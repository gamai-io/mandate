"""Appending must not cost the length of the ledger."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from mandate import core


def body(nonce: str) -> dict:
    return {"v": 1, "type": "receipt", "grant_nonce": nonce, "decision": "executed",
            "commitment": "sha256:" + "0" * 64, "ts": 1}


class Append(unittest.TestCase):
    def test_append_cost_does_not_grow_with_the_ledger(self) -> None:
        """Doubling the ledger must not double the cost of one more append."""
        def time_appends(n: int) -> float:
            with tempfile.TemporaryDirectory() as td:
                ledger = os.path.join(td, "ledger.jsonl")
                start = time.perf_counter()
                for i in range(n):
                    core.append_receipt(ledger, body("n%d" % i))
                elapsed = time.perf_counter() - start
                self.assertTrue(core.verify_chain(ledger, anchor=True))
                self.assertEqual(len(core.read_ledger(ledger)), n)
                return elapsed

        small = time_appends(400)
        large = time_appends(1600)
        # Linear append: 4x the rows costs about 4x; a quadratic implementation
        # costs ~16x. The 6x/10s envelope absorbs a stalled disk (fsync latency
        # spikes under CI load) while still failing a quadratic change.
        self.assertLess(large, 6 * small + 10.0,
                        "append looks quadratic: %.1fs vs %.1fs" % (large, small))

    def test_a_tampered_tail_is_refused_not_repaired(self) -> None:
        """Silently rewriting .head after a bad tail would hide deleted entries."""
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "ledger.jsonl")
            core.append_receipt(ledger, body("n1"))
            core.append_receipt(ledger, body("n2"))
            lines = open(ledger, encoding="utf-8").read().strip().splitlines()
            last = json.loads(lines[-1])
            last["body"]["decision"] = "allowed"          # hash no longer matches
            lines[-1] = json.dumps(last, sort_keys=True)
            open(ledger, "w", encoding="utf-8").write("\n".join(lines) + "\n")
            with self.assertRaises(core.MandateError):
                core.append_receipt(ledger, body("n3"))

    def test_a_truncated_ledger_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "ledger.jsonl")
            for i in range(5):
                core.append_receipt(ledger, body("n%d" % i))
            lines = open(ledger, encoding="utf-8").read().strip().splitlines()
            open(ledger, "w", encoding="utf-8").write("\n".join(lines[:3]) + "\n")
            with self.assertRaises(core.MandateError):
                core.append_receipt(ledger, body("n6"))

    def test_a_missing_head_falls_back_to_a_full_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "ledger.jsonl")
            core.append_receipt(ledger, body("n1"))
            os.remove(ledger + ".head")
            core.append_receipt(ledger, body("n2"))
            entries = core.read_ledger(ledger)
            self.assertEqual(entries[0]["hash"], entries[1]["body"]["prev"])

    def test_the_chain_still_links_every_entry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "ledger.jsonl")
            for i in range(50):
                core.append_receipt(ledger, body("n%d" % i))
            self.assertTrue(core.verify_chain(ledger, anchor=True))


if __name__ == "__main__":
    unittest.main()


class Diagnosis(unittest.TestCase):
    def test_a_healthy_chain_says_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "l.jsonl")
            for i in range(3):
                core.append_receipt(ledger, body("n%d" % i))
            diag = core.diagnose_chain(ledger)
            self.assertTrue(diag["valid"])
            self.assertEqual(diag["code"], "ok")

    def test_truncation_is_named(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "l.jsonl")
            for i in range(3):
                core.append_receipt(ledger, body("n%d" % i))
            lines = open(ledger).read().strip().splitlines()
            open(ledger, "w").write("\n".join(lines[:2]) + "\n")
            diag = core.diagnose_chain(ledger)
            self.assertFalse(diag["valid"])
            self.assertEqual(diag["code"], "truncated_or_head_edited")

    def test_an_edited_entry_is_named(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "l.jsonl")
            for i in range(2):
                core.append_receipt(ledger, body("n%d" % i))
            lines = open(ledger).read().strip().splitlines()
            last = json.loads(lines[-1])
            last["body"]["decision"] = "allowed"
            lines[-1] = json.dumps(last, sort_keys=True)
            open(ledger, "w").write("\n".join(lines) + "\n")
            diag = core.diagnose_chain(ledger)
            self.assertEqual(diag["code"], "entry_tampered")
