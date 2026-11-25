"""A first-time payee is a question, not a detail."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest

from mandate import core, report

POLICY = {"version": 1, "default": "deny",
          "effects": {"payment.send": {"risk": "high", "new_payee": "deny"}}}


def keypair(td: str, name: str) -> str:
    path = os.path.join(td, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name,
                    "-N", ""], check=True)
    return path


class NewPayee(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.key = keypair(self.dir, "approver")
        self.signers = os.path.join(self.dir, "allowed_signers")
        open(self.signers, "w").write(
            'approver namespaces="mandate" %s\n' % open(self.key + ".pub").read().strip())
        self.ledger = os.path.join(self.dir, "ledger.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def intent(self, target: str, nonce: str) -> dict:
        return core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": "payment.send", "target": target,
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": nonce,
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})

    def grant(self, item: dict) -> dict:
        gc = core.build_grant_core(core.intent_commitment(item), "approver",
                                   ttl_s=600, render_hash=core.render_hash(item),
                                   agent="bank-agent")
        return core.make_grant(gc, self.key)

    def test_a_first_time_payee_is_refused_under_that_policy(self) -> None:
        item = self.intent("New Supplier", "n1")
        with self.assertRaises(core.PolicyDenied):
            core.enforce_new_payee(item, POLICY, self.ledger)

    def test_after_one_payment_the_same_payee_passes(self) -> None:
        first = self.intent("Known Supplier", "n1")
        core.redeem(first, self.grant(first), self.signers, self.ledger)
        second = self.intent("Known Supplier", "n2")
        core.enforce_new_payee(second, POLICY, self.ledger)      # must not raise

    def test_the_default_policy_does_not_gate(self) -> None:
        item = self.intent("Anyone", "n1")
        core.enforce_new_payee(item, core.load_policy(), self.ledger)

    def test_history_counts_payments_to_that_target_only(self) -> None:
        for name, nonce in (("A", "n1"), ("A", "n2"), ("B", "n3")):
            item = self.intent(name, nonce)
            core.redeem(item, self.grant(item), self.signers, self.ledger)
        history = report.payee_history(self.ledger, "A", "payment.send")
        self.assertEqual(history["payments"], 2)
        self.assertFalse(history["first_time"])
        self.assertTrue(report.payee_history(self.ledger, "C")["first_time"])


if __name__ == "__main__":
    unittest.main()
