"""Detection over the new evidence fields: taint and coverage.

Blue team needs alerts, not just proofs. These rules read what the gate already
recorded, so they work offline and without a model.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from mandate import core, detect


def _receipt(**over):
    body = {
        "v": 1, "type": "receipt", "proposal_id": "m1", "approver": "approver",
        "agent": "agent@example", "grant_nonce": "n-1", "decision": "executed",
        "coverage": "enforced", "result_hash": "sha256:bb", "ts": 1000,
        "render": {"fields": {"kind": "payment.send", "target": "Example",
                              "amount": {"value": 10, "currency": "BAM"}}},
    }
    body.update(over)
    return body


class Rules(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.td.name, "ledger.jsonl")

    def tearDown(self):
        self.td.cleanup()

    def _write(self, *bodies):
        for body in bodies:
            core.append_receipt(self.ledger, body)

    def _rules(self, **cfg):
        cfg.setdefault("human_principals", [])
        cfg.setdefault("business_hours_utc", [0, 24])
        cfg.setdefault("max_effects_per_hour", 0)
        cfg.setdefault("max_amount", 0)
        out = detect.detect(self.ledger, cfg)
        return [f["rule"] for f in out["findings"]], out

    def test_clean_receipt_has_no_findings(self):
        self._write(_receipt())
        rules, out = self._rules()
        self.assertEqual(rules, [])
        self.assertTrue(out["ok"])

    def test_untrusted_input_is_high(self):
        self._write(_receipt(taint={"material_untrusted": ["target"],
                                    "untrusted_fields": ["target"], "tainted": True}))
        rules, out = self._rules()
        self.assertIn("untrusted_input", rules)
        self.assertFalse(out["ok"])            # high severity flips ok to False
        finding = [f for f in out["findings"] if f["rule"] == "untrusted_input"][0]
        self.assertEqual(finding["evidence"]["fields"], ["target"])

    def test_weak_coverage_is_reported(self):
        self._write(_receipt(coverage="observed"))
        rules, _ = self._rules()
        self.assertIn("weak_coverage", rules)

    def test_floor_can_be_lowered(self):
        self._write(_receipt(coverage="observed"))
        rules, _ = self._rules(min_coverage="observed")
        self.assertNotIn("weak_coverage", rules)

    def test_missing_coverage_is_informational(self):
        body = _receipt()
        body.pop("coverage")
        self._write(body)
        rules, out = self._rules(report_coverage_missing=True)
        self.assertIn("coverage_missing", rules)
        self.assertTrue(out["ok"])             # low severity does not block

    def test_taint_block_absent_is_fine(self):
        self._write(_receipt())
        rules, _ = self._rules()
        self.assertNotIn("untrusted_input", rules)


if __name__ == "__main__":
    unittest.main()
