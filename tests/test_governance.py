"""Governance tests: limits, halt/resume, separation of duties, chain integrity."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from mandate import governance
from mandate.core import append_receipt, verify_chain


def receipt(path: str, value: float, ts: float, currency: str = "BAM") -> None:
    append_receipt(path, {
        "v": 1, "type": "receipt", "ts": ts,
        "render": {"amount": {"value": value, "currency": currency}},
    })


class Limits(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")
        self.limits = dict(governance.DEFAULTS, window_seconds=3600, max_effects=3,
                           max_amount=500, currency="BAM")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_effect_budget(self) -> None:
        for i in range(3):
            self.assertTrue(governance.check(self.ledger, self.limits, now=1000 + i)["allow"])
            receipt(self.ledger, 10, ts=1000 + i)
        blocked = governance.check(self.ledger, self.limits, now=1010)
        self.assertFalse(blocked["allow"])
        self.assertEqual(blocked["code"], "limit_effects")

    def test_amount_budget(self) -> None:
        limits = dict(self.limits, max_effects=0)
        for i in range(4):
            receipt(self.ledger, 200, ts=1000 + i)
        blocked = governance.check(self.ledger, limits, now=1010)
        self.assertEqual(blocked["code"], "limit_amount")

    def test_currency_mismatch(self) -> None:
        receipt(self.ledger, 1, ts=1000, currency="EUR")
        blocked = governance.check(self.ledger, self.limits, now=1001)
        self.assertEqual(blocked["code"], "limit_currency")

    def test_window_expiry_frees_budget(self) -> None:
        for i in range(3):
            receipt(self.ledger, 1, ts=1000 + i)
        self.assertFalse(governance.check(self.ledger, self.limits, now=1010)["allow"])
        self.assertTrue(governance.check(self.ledger, self.limits, now=5000)["allow"])

    def test_unlimited_by_default(self) -> None:
        for i in range(50):
            receipt(self.ledger, 1_000_000, ts=1000 + i)
        self.assertTrue(governance.check(self.ledger, governance.DEFAULTS, now=1100)["allow"])


class KillSwitch(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_halt_blocks_and_is_recorded(self) -> None:
        governance.halt(self.ledger, "runaway agent", actor="ops")
        state = governance.check(self.ledger, governance.DEFAULTS)
        self.assertFalse(state["allow"])
        self.assertEqual(state["code"], "halted")
        control = governance.last_control(self.ledger)
        self.assertEqual(control["action"], "halt")
        self.assertEqual(control["actor"], "ops")
        self.assertTrue(verify_chain(self.ledger))

    def test_resume_allows_again(self) -> None:
        governance.halt(self.ledger, "incident")
        governance.resume(self.ledger, "post-mortem done")
        self.assertTrue(governance.check(self.ledger, governance.DEFAULTS)["allow"])
        self.assertEqual(governance.last_control(self.ledger)["action"], "resume")

    def test_resume_does_not_reset_the_budget(self) -> None:
        limits = dict(governance.DEFAULTS, window_seconds=3600, max_effects=1)
        receipt(self.ledger, 10, ts=1000)
        governance.halt(self.ledger, "stop")
        governance.resume(self.ledger, "resume")
        state = governance.check(self.ledger, limits, now=1001)
        self.assertEqual(state["code"], "limit_effects")


class SeparationOfDuties(unittest.TestCase):
    def test_agent_cannot_approve_itself(self) -> None:
        intent = {"actor": {"agent": "agent@bank"}}
        self.assertFalse(governance.check_separation_of_duties(intent, "agent@bank")["allow"])
        self.assertFalse(governance.check_separation_of_duties(intent, "agent")["allow"])

    def test_human_approver_passes(self) -> None:
        intent = {"actor": {"agent": "agent@bank"}}
        self.assertTrue(governance.check_separation_of_duties(intent, "renato")["allow"])


class LimitsFromPolicy(unittest.TestCase):
    def test_policy_block_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "policy.json")
            json.dump({"version": 1, "default": "deny",
                       "limits": {"max_effects": 2, "max_amount": 100, "currency": "EUR"}},
                      open(p, "w"))
            lim = governance.load_limits(p)
        self.assertEqual(lim["max_effects"], 2)
        self.assertEqual(lim["max_amount"], 100)
        self.assertEqual(lim["currency"], "EUR")
        self.assertEqual(lim["window_seconds"], governance.DEFAULTS["window_seconds"])


if __name__ == "__main__":
    unittest.main()
