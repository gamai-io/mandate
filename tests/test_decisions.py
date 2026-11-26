"""Decision latency: from the request to the human's answer."""
from __future__ import annotations

import os
import tempfile
import unittest

from mandate import report
from mandate.core import append_receipt


def approval(decision: str, waited: float) -> dict:
    return {"v": 1, "type": "approval", "decision": decision, "waited_s": waited,
            "approver": "approver", "commitment": "sha256:" + "0" * 64, "ts": 1}


class Decisions(unittest.TestCase):
    def test_median_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "l.jsonl")
            for decision, waited in (("approved", 12.0), ("approved", 30.0),
                                     ("rejected", 90.0)):
                append_receipt(ledger, approval(decision, waited))
            result = report.decisions(ledger)
            self.assertEqual(result["approved"], 2)
            self.assertEqual(result["rejected"], 1)
            self.assertEqual(result["median_wait_s"], 30.0)
            self.assertEqual(result["max_wait_s"], 90.0)

    def test_the_pack_carries_the_latency_summary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "l.jsonl")
            append_receipt(ledger, approval("approved", 20.0))
            out = os.path.join(td, "pack")
            result = report.pack(ledger, out)
            import json
            data = json.load(open(os.path.join(out, "decisions.json")))
            self.assertEqual(data["approved"], 1)
            self.assertEqual(data["median_wait_s"], 20.0)
            self.assertIn("decisions.json", result.get("files") or {})

    def test_an_empty_ledger_reports_nothing_rather_than_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = report.decisions(os.path.join(td, "l.jsonl"))
            self.assertEqual(result["decisions"], 0)
            self.assertIsNone(result["median_wait_s"])


if __name__ == "__main__":
    unittest.main()


class PackArtefacts(unittest.TestCase):
    def test_grants_and_intents_are_archived_in_the_pack(self) -> None:
        import json as _json
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "l.jsonl")
            append_receipt(ledger, approval("approved", 5.0))
            grant = os.path.join(td, "grant.json")
            intent = os.path.join(td, "intent.json")
            _json.dump({"grant": {"v": 1}, "sig": "x"}, open(grant, "w"))
            _json.dump({"v": 1}, open(intent, "w"))
            out = os.path.join(td, "pack")
            result = report.pack(ledger, out, grants=[grant], intents=[intent])
            self.assertTrue(os.path.isdir(os.path.join(out, "grants")))
            self.assertTrue(os.path.isdir(os.path.join(out, "intents")))
            names = [name for name in (result.get("files") or {}) if "grants/" in name]
            self.assertTrue(names, result.get("files"))

    def test_a_missing_grant_is_refused_rather_than_silently_skipped(self) -> None:
        from mandate.core import MandateError
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "l.jsonl")
            append_receipt(ledger, approval("approved", 5.0))
            with self.assertRaises(MandateError):
                report.pack(ledger, os.path.join(td, "pack"),
                            grants=[os.path.join(td, "nope.json")])
