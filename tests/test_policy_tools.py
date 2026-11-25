"""Policy review: lint, explain, diff, and the observe summary."""
from __future__ import annotations

import copy
import os
import tempfile
import unittest

from mandate import policy_tools, report
from mandate.core import append_receipt

POLICY = {
    "version": 1,
    "default": "deny",
    "effects": {
        "payment.send": {"risk": "high", "max_auto": 0, "purpose": "pay an invoice",
                         "require_data_ref": ["target", "amount"]},
        "quote.create": {"risk": "medium", "max_auto": 100, "purpose": "prepare a quote"},
        "read.lookup": {"risk": "low", "purpose": "read a record"},
    },
    "require_revert": {"payment.send": True},
}


class Lint(unittest.TestCase):
    def test_the_shipped_default_policy_is_clean(self) -> None:
        from mandate.core import load_policy
        res = policy_tools.lint(load_policy())
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["warnings"], [], res["warnings"])

    def test_missing_purpose_is_a_warning_not_a_blocker(self) -> None:
        policy = copy.deepcopy(POLICY)
        del policy["effects"]["quote.create"]["purpose"]
        res = policy_tools.lint(policy)
        self.assertTrue(res["ok"])
        self.assertTrue(any("purpose" in w for w in res["warnings"]), res["warnings"])

    def test_default_allow_is_blocking(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["default"] = "allow"
        res = policy_tools.lint(policy)
        self.assertFalse(res["ok"])
        self.assertTrue(any("default" in p for p in res["problems"]))

    def test_unknown_risk_is_blocking(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["effects"]["read.lookup"]["risk"] = "harmless"
        self.assertFalse(policy_tools.lint(policy)["ok"])

    def test_unknown_key_is_reported_because_check_ignores_it(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["effects"]["quote.create"]["max_ammount"] = 10
        res = policy_tools.lint(policy)
        self.assertTrue(any("max_ammount" in w for w in res["warnings"]), res["warnings"])

    def test_low_risk_with_max_auto_is_pointless(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["effects"]["read.lookup"]["max_auto"] = 5
        self.assertTrue(any("risk=low" in w for w in policy_tools.lint(policy)["warnings"]))

    def test_require_revert_must_name_a_real_effect(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["require_revert"]["refund.send"] = True
        self.assertFalse(policy_tools.lint(policy)["ok"])


class Explain(unittest.TestCase):
    def test_low_risk_runs_without_a_human(self) -> None:
        res = policy_tools.explain(POLICY, "read.lookup")
        self.assertEqual(res["decision"], "allow")
        self.assertIn("risk=low", res["because"])

    def test_amount_within_max_auto_is_allowed(self) -> None:
        self.assertEqual(policy_tools.explain(POLICY, "quote.create", 80)["decision"], "allow")

    def test_amount_above_max_auto_asks(self) -> None:
        self.assertEqual(policy_tools.explain(POLICY, "quote.create", 500)["decision"], "ask")

    def test_high_risk_always_asks(self) -> None:
        res = policy_tools.explain(POLICY, "payment.send", 1)
        self.assertEqual(res["decision"], "ask")
        self.assertTrue(res["revert_required"])
        self.assertEqual(res["provenance_required"], ["target", "amount"])

    def test_unknown_effect_is_denied(self) -> None:
        self.assertEqual(policy_tools.explain(POLICY, "payroll.run")["decision"], "deny")


class Diff(unittest.TestCase):
    def test_digest_changes_when_anything_changes(self) -> None:
        new = copy.deepcopy(POLICY)
        new["effects"]["quote.create"]["max_auto"] = 50
        res = policy_tools.diff(POLICY, new)
        self.assertNotEqual(res["old_digest"], res["new_digest"])
        self.assertIn("quote.create", res["changed"])
        self.assertTrue(any("max_auto lowered" in b for b in res["breaking"]))

    def test_risk_raise_is_breaking(self) -> None:
        new = copy.deepcopy(POLICY)
        new["effects"]["quote.create"]["risk"] = "high"
        res = policy_tools.diff(POLICY, new)
        self.assertTrue(any("risk raised" in b for b in res["breaking"]))

    def test_removed_effect_is_breaking_and_added_is_not(self) -> None:
        new = copy.deepcopy(POLICY)
        del new["effects"]["read.lookup"]
        new["effects"]["refund.send"] = {"risk": "high", "purpose": "refund a customer"}
        res = policy_tools.diff(POLICY, new)
        self.assertEqual(res["removed"], ["read.lookup"])
        self.assertEqual(res["added"], ["refund.send"])
        self.assertTrue(any("removed" in b for b in res["breaking"]))


class ObserveSummary(unittest.TestCase):
    def _body(self, kind: str, nonce: str, decision: str) -> dict:
        return {"v": 1, "type": "receipt", "decision": decision,
                "grant_nonce": nonce, "agent": "bank-agent", "ts": 1,
                "binding": decision != "observe",
                "intent": {"effect": {"kind": kind,
                                      "amount": {"value": 10.0, "currency": "BAM"}}}}

    def test_observed_but_never_executed_is_listed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "ledger.jsonl")
            append_receipt(ledger, self._body("payment.send", "n1", "observe"))
            append_receipt(ledger, self._body("payment.send", "n1", "executed"))
            append_receipt(ledger, self._body("quote.create", "n2", "observe"))
            res = report.observe_summary(ledger)
            self.assertEqual(res["observations"], 2)
            self.assertEqual(res["executions"], 1)
            self.assertEqual(list(res["observed_not_executed"]), ["n2"])
            self.assertEqual(res["by_kind"]["payment.send"]["observe"], 1)


if __name__ == "__main__":
    unittest.main()
