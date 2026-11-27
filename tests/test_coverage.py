"""COVERAGE_V1: each receipt says how the effect was captured.

The class is the honest part of the evidence: `enforced` means the gate could
refuse it, `observed` means something watched but could not block, and
`self_reported` means only the agent says so. A policy can demand a minimum.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from mandate import core, coverage


def intent_factory(**over):
    intent = {
        "v": 1,
        "actor": {"agent": "agent@example", "session": "s1"},
        "effect": {
            "kind": "payment.send",
            "target": "Example Supplier",
            "amount": {"value": 1170.0, "currency": "BAM"},
            "params": {"ref": "faktura-77"},
        },
        "requested_by": "approver",
        "nonce": "n-fixed-1",
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1",
                        "covers": ["target", "amount"]}],
    }
    intent.update(over)
    return intent


class CoverageModule(unittest.TestCase):
    def test_norm_and_rank(self):
        self.assertEqual(coverage.norm("Enforced"), "enforced")
        self.assertEqual(coverage.norm("self-reported"), "self_reported")
        self.assertEqual(coverage.rank("observed"), 1)
        self.assertTrue(coverage.meets("enforced", "observed"))
        self.assertFalse(coverage.meets("observed", "enforced"))
        self.assertEqual(coverage.weakest("enforced", "self_reported"), "self_reported")

    def test_unknown_value_is_rejected_with_code(self):
        for bad in ("", None, "enforced-ish", 3):
            with self.assertRaises(coverage.CoverageError) as ctx:
                coverage.norm(bad)
            self.assertEqual(ctx.exception.code, "E_COVERAGE")


class ReceiptCoverage(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n'
            % pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")

    def tearDown(self):
        self.td.cleanup()

    def _grant(self, intent, ttl_s=900):
        proposal = core.propose(intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=ttl_s,
            render_hash=proposal["render_hash"], agent="agent@example")
        return core.make_grant(grant_core, self.key)

    def _entries(self):
        if not os.path.exists(self.ledger):
            return []
        return [json.loads(line) for line in
                pathlib.Path(self.ledger).read_text(encoding="utf-8").splitlines() if line]

    def test_receipt_is_enforced_by_default(self):
        intent = intent_factory()
        receipt = core.redeem(intent, self._grant(intent), self.signers, self.ledger)
        self.assertEqual(receipt["body"]["coverage"], "enforced")

    def test_observe_marks_observed(self):
        intent = intent_factory()
        receipt = core.redeem(intent, self._grant(intent), self.signers, self.ledger,
                              observe=True)
        self.assertEqual(receipt["body"]["coverage"], "observed")
        self.assertEqual(receipt["body"]["decision"], "observe")

    def test_explicit_class_is_recorded(self):
        intent = intent_factory()
        receipt = core.redeem(intent, self._grant(intent), self.signers, self.ledger,
                              coverage="self_reported")
        self.assertEqual(receipt["body"]["coverage"], "self_reported")

    def test_policy_minimum_refuses_weaker_class(self):
        intent = intent_factory()
        policy = dict(core.load_policy())
        policy["require_coverage"] = "enforced"
        with self.assertRaises(core.PolicyDenied):
            core.redeem(intent, self._grant(intent), self.signers, self.ledger,
                        policy=policy, coverage="observed")
        # odbijanje je dokaz: mora biti u ledgeru
        refusals = [e for e in self._entries()
                    if (e.get("body") or {}).get("action") == "refuse"]
        self.assertTrue(refusals, self._entries())
        self.assertIn("coverage", json.dumps(refusals[-1]).lower())

    def test_explicit_require_coverage_also_works(self):
        intent = intent_factory()
        with self.assertRaises(core.PolicyDenied):
            core.redeem(intent, self._grant(intent), self.signers, self.ledger,
                        coverage="self_reported", require_coverage="observed")

    def test_bad_coverage_value_is_refused(self):
        intent = intent_factory()
        with self.assertRaises(coverage.CoverageError):
            core.redeem(intent, self._grant(intent), self.signers, self.ledger,
                        coverage="trust_me")

    def test_verify_receipt_checks_coverage(self):
        intent = intent_factory()
        grant = self._grant(intent)
        core.redeem(intent, grant, self.signers, self.ledger)
        entry = [e for e in self._entries()
                 if (e.get("body") or {}).get("type") == "receipt"][-1]
        self.assertTrue(core.verify_receipt(entry, intent, grant, self.signers,
                                            require_coverage=True))
        # receipt bez coverage prolazi u kompat modu, pada u strogom
        body = dict(entry["body"])
        body.pop("coverage")
        bare = dict(entry)
        bare["body"] = body
        bare["hash"] = core.sha256(core.jcs(body))
        self.assertTrue(core.verify_receipt(bare, intent, grant, self.signers))
        self.assertFalse(core.verify_receipt(bare, intent, grant, self.signers,
                                             require_coverage=True))
        # neispravna vrijednost pada uvijek
        body2 = dict(entry["body"])
        body2["coverage"] = "trust_me"
        bad = dict(entry)
        bad["body"] = body2
        bad["hash"] = core.sha256(core.jcs(body2))
        self.assertFalse(core.verify_receipt(bad, intent, grant, self.signers))


if __name__ == "__main__":
    unittest.main()
