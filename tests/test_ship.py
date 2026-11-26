"""Shipping to a SIEM must not lose records, and must not mix two ledgers."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from mandate import core, ship


def body(nonce: str, ts: int = 1) -> dict:
    return {"v": 1, "type": "receipt", "grant_nonce": nonce, "decision": "executed",
            "commitment": "sha256:" + "0" * 64, "ts": ts}


class Ship(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.ledger = os.path.join(self.dir, "a.jsonl")
        for i in range(5):
            core.append_receipt(self.ledger, body("n%d" % i))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_a_dry_run_counts_without_writing_state(self) -> None:
        result = ship.ship(self.ledger, "https://siem.example/services/collector",
                           dry_run=True)
        self.assertEqual(result["sent"], 5)
        self.assertFalse(os.path.exists(self.ledger + ".shipstate"))

    def test_two_ledgers_get_their_own_state_by_default(self) -> None:
        other = os.path.join(self.dir, "b.jsonl")
        core.append_receipt(other, body("m0"))
        posted = []
        original = ship._post
        ship._post = lambda url, token, payload, timeout=20: posted.append(len(payload))
        try:
            ship.ship(self.ledger, "https://siem.example/x")
            ship.ship(other, "https://siem.example/x")
        finally:
            ship._post = original
        self.assertTrue(os.path.exists(self.ledger + ".shipstate"))
        self.assertTrue(os.path.exists(other + ".shipstate"))
        self.assertEqual(sum(posted), 6)

    def test_a_shared_state_file_keys_by_ledger(self) -> None:
        other = os.path.join(self.dir, "b.jsonl")
        core.append_receipt(other, body("m0"))
        shared = os.path.join(self.dir, "ship.state")
        posted = []
        original = ship._post
        ship._post = lambda url, token, payload, timeout=20: posted.append(len(payload))
        try:
            ship.ship(self.ledger, "https://siem.example/x", offset_path=shared)
            ship.ship(other, "https://siem.example/x", offset_path=shared)
            state = json.load(open(shared))
        finally:
            ship._post = original
        self.assertEqual(len(state["offsets"]), 2)
        self.assertEqual(sum(posted), 6)

    def test_a_second_run_sends_nothing_new(self) -> None:
        posted = []
        original = ship._post
        ship._post = lambda url, token, payload, timeout=20: posted.append(len(payload))
        try:
            ship.ship(self.ledger, "https://siem.example/x")
            second = ship.ship(self.ledger, "https://siem.example/x")
        finally:
            ship._post = original
        self.assertEqual(second["records"], 0)
        self.assertEqual(sum(posted), 5)

    def test_a_rotated_ledger_is_detected_and_restarts(self) -> None:
        posted = []
        original = ship._post
        ship._post = lambda url, token, payload, timeout=20: posted.append(len(payload))
        try:
            ship.ship(self.ledger, "https://siem.example/x")
            open(self.ledger, "w").write("")           # rotation
            core.append_receipt(self.ledger, body("after-rotation"))
            result = ship.ship(self.ledger, "https://siem.example/x")
        finally:
            ship._post = original
        self.assertTrue(result["rotated"])
        self.assertEqual(result["sent"], 1)

    def test_a_rejected_batch_does_not_advance_the_offset(self) -> None:
        def boom(url, token, payload, timeout=20):
            raise ship.ShipError("SIEM rejected batch: HTTP 500")
        original = ship._post
        ship._post = boom
        try:
            with self.assertRaises(ship.ShipError):
                ship.ship(self.ledger, "https://siem.example/x")
        finally:
            ship._post = original
        state = self.ledger + ".shipstate"
        if os.path.exists(state):
            self.assertEqual(json.load(open(state))["offsets"].get(
                os.path.abspath(self.ledger), 0), 0)


if __name__ == "__main__":
    unittest.main()
