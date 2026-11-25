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
        # linear append: 4x the rows costs about 4x, quadratic would cost ~16x
        self.assertLess(large, 4 * small + 5.0,
                        "append looks quadratic: %.1fs vs %.1fs" % (large, small))

    def test_a_tampered_tail_falls_back_to_a_full_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "ledger.jsonl")
            core.append_receipt(ledger, body("n1"))
            core.append_receipt(ledger, body("n2"))
            lines = open(ledger, encoding="utf-8").read().strip().splitlines()
            last = json.loads(lines[-1])
            last["body"]["decision"] = "allowed"          # hash no longer matches
            lines[-1] = json.dumps(last, sort_keys=True)
            open(ledger, "w", encoding="utf-8").write("\n".join(lines) + "\n")
            core.append_receipt(ledger, body("n3"))
            self.assertFalse(core.verify_chain(ledger, anchor=False))

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
