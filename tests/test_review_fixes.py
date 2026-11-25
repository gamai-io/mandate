"""Regressions from the external review: audience, governance, ledger integrity."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest

from mandate import core, governance


def keypair(td: str, name: str) -> str:
    path = os.path.join(td, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name,
                    "-N", ""], check=True)
    return path


POLICY = {"version": 1, "default": "deny",
          "effects": {"payment.send": {"risk": "high",
                                       "require_data_ref": ["target", "amount"]}}}


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.key = keypair(self.dir, "approver")
        self.signers = os.path.join(self.dir, "allowed_signers")
        open(self.signers, "w").write(
            'approver namespaces="mandate" %s\n' % open(self.key + ".pub").read().strip())
        self.intent = core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": "payment.send", "target": "X",
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n-1",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def grant(self, audience: str = "") -> dict:
        item = self.intent
        gc = core.build_grant_core(core.intent_commitment(item), "approver",
                                   ttl_s=600, render_hash=core.render_hash(item),
                                   agent="bank-agent", audience=audience)
        return core.make_grant(gc, self.key)


class Audience(Base):
    def test_a_bound_grant_needs_the_caller_to_name_the_audience(self) -> None:
        grant = self.grant("local-broker")
        with self.assertRaises(core.GrantInvalid):
            core.redeem(self.intent, grant, self.signers,
                        os.path.join(self.dir, "l.jsonl"), audience=None)

    def test_the_right_audience_is_accepted(self) -> None:
        grant = self.grant("local-broker")
        entry = core.redeem(self.intent, grant, self.signers,
                            os.path.join(self.dir, "l.jsonl"),
                            audience="local-broker")
        self.assertEqual(entry["body"]["decision"], "executed")

    def test_an_unbound_grant_still_works_from_the_cli(self) -> None:
        grant = self.grant("")
        entry = core.redeem(self.intent, grant, self.signers,
                            os.path.join(self.dir, "l.jsonl"))
        self.assertTrue(entry["hash"])


class Limits(Base):
    def test_the_pending_amount_counts_against_the_cap(self) -> None:
        ledger = os.path.join(self.dir, "l.jsonl")
        limits = {"max_amount": 1000, "currency": "BAM"}
        verdict = governance.check(ledger, limits, pending={"value": 5000,
                                                            "currency": "BAM"})
        self.assertFalse(verdict["allow"])
        self.assertEqual(verdict["code"], "limit_amount")

    def test_a_small_pending_amount_is_allowed(self) -> None:
        ledger = os.path.join(self.dir, "l.jsonl")
        verdict = governance.check(ledger, {"max_amount": 1000},
                                   pending={"value": 10, "currency": "BAM"})
        self.assertTrue(verdict["allow"])

    def test_an_unreadable_limits_file_is_not_unlimited(self) -> None:
        policy = os.path.join(self.dir, "policy.json")
        open(policy, "w").write("{broken")
        with self.assertRaises(governance.MandateError):
            governance.load_limits(policy)


if __name__ == "__main__":
    unittest.main()
