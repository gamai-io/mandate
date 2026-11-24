"""Runtime detection over the ledger: human credentials, velocity, scope, hours."""
from __future__ import annotations

import os
import tempfile
import time
import unittest

from mandate import detect
from mandate.core import append_receipt


def receipt(path: str, agent: str, approver: str, kind: str = "payment.send",
            amount: float = 100.0, ts: float | None = None) -> None:
    append_receipt(path, {
        "v": 1, "type": "receipt", "agent": agent, "approver": approver,
        "grant_nonce": f"n-{time.time_ns()}",
        "ts": time.time() if ts is None else ts,
        "render": {"fields": {"kind": kind, "amount": {"value": amount,
                                                      "currency": "BAM"}}},
    })


class Detection(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def cfg(self, **kw) -> dict:
        return dict(detect.DEFAULTS, **kw)

    def test_clean_ledger_has_no_findings(self) -> None:
        receipt(self.ledger, "bank-agent", "renato")
        res = detect.detect(self.ledger, self.cfg(business_hours_utc=[0, 24]))
        self.assertTrue(res["ok"])
        self.assertEqual(res["findings"], [])

    def test_agent_approving_itself(self) -> None:
        receipt(self.ledger, "bank-agent", "bank-agent")
        res = detect.detect(self.ledger, self.cfg())
        self.assertFalse(res["ok"])
        self.assertEqual(res["by_rule"]["sod_ledger"], 1)

    def test_agent_using_a_human_identity(self) -> None:
        receipt(self.ledger, "renato", "ops")
        res = detect.detect(self.ledger, self.cfg(human_principals=["renato"]))
        self.assertEqual(res["by_rule"]["human_credential"], 1)
        self.assertFalse(res["ok"])

    def test_velocity_spike(self) -> None:
        now = time.time()
        for i in range(6):
            receipt(self.ledger, "bank-agent", "renato", ts=now - i)
        res = detect.detect(self.ledger, self.cfg(max_effects_per_hour=5), now=now)
        self.assertEqual(res["by_rule"]["velocity"], 1)
        self.assertEqual(res["findings"][0]["evidence"]["effects"], 6)

    def test_amount_above_ceiling(self) -> None:
        receipt(self.ledger, "bank-agent", "renato", amount=9000)
        res = detect.detect(self.ledger, self.cfg(max_amount=5000))
        self.assertEqual(res["by_rule"]["amount"], 1)
        self.assertEqual(res["findings"][0]["severity"], "medium")

    def test_effect_outside_business_hours(self) -> None:
        ts = time.mktime(time.strptime("2026-11-24 03:00:00", "%Y-%m-%d %H:%M:%S"))
        receipt(self.ledger, "bank-agent", "renato", ts=ts)
        res = detect.detect(self.ledger, self.cfg(business_hours_utc=[6, 20]), now=ts + 60)
        self.assertEqual(res["by_rule"]["off_hours"], 1)

    def test_scope_not_granted_in_any_token(self) -> None:
        receipt(self.ledger, "bank-agent", "renato", kind="wire.transfer")
        token = {"payload": {"sub": "bank-agent", "scopes": ["payment.send"]}}
        res = detect.detect(self.ledger, self.cfg(), tokens=[token])
        self.assertEqual(res["by_rule"]["scope_unknown"], 1)

    def test_findings_are_not_written_unless_asked(self) -> None:
        receipt(self.ledger, "bank-agent", "bank-agent")
        detect.detect(self.ledger, self.cfg())
        entries = open(self.ledger).read().strip().splitlines()
        self.assertEqual(len(entries), 1, "detect must be read-only by default")


if __name__ == "__main__":
    unittest.main()
