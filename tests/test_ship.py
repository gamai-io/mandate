"""SIEM shipping: batches, offset state, no silent loss."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from mandate import ship
from mandate.core import append_receipt


class Collector(BaseHTTPRequestHandler):
    got: list[dict] = []
    fail = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode()
        if Collector.fail:
            self.send_response(500); self.end_headers(); return
        for line in body.strip().splitlines():
            Collector.got.append(json.loads(line))
        self.send_response(200); self.end_headers()

    def log_message(self, *args):
        pass


class Shipping(unittest.TestCase):
    def setUp(self) -> None:
        Collector.got = []
        Collector.fail = False
        self.server = HTTPServer(("127.0.0.1", 0), Collector)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/services/collector"
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")
        self.state = os.path.join(self.tmp.name, "ship.state")
        for i in range(3):
            append_receipt(self.ledger, {"v": 1, "type": "receipt", "ts": 1000 + i,
                                         "agent": "a", "approver": "b"})

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_ships_once_then_resumes_from_offset(self) -> None:
        first = ship.ship(self.ledger, self.url, "tok", self.state)
        self.assertEqual(first["sent"], 3)
        self.assertEqual(len(Collector.got), 3)
        second = ship.ship(self.ledger, self.url, "tok", self.state)
        self.assertEqual(second["sent"], 0, "offset must prevent resending")
        append_receipt(self.ledger, {"v": 1, "type": "receipt", "ts": 2000,
                                     "agent": "a", "approver": "b"})
        third = ship.ship(self.ledger, self.url, "tok", self.state)
        self.assertEqual(third["sent"], 1)
        self.assertEqual(len(Collector.got), 4)

    def test_rejected_batch_does_not_advance_the_offset(self) -> None:
        Collector.fail = True
        with self.assertRaises(ship.ShipError):
            ship.ship(self.ledger, self.url, "tok", self.state)
        self.assertFalse(os.path.exists(self.state), "offset must not move on failure")
        Collector.fail = False
        res = ship.ship(self.ledger, self.url, "tok", self.state)
        self.assertEqual(res["sent"], 3)

    def test_dry_run_does_not_send(self) -> None:
        res = ship.ship(self.ledger, self.url, "tok", self.state, dry_run=True)
        self.assertEqual(res["sent"], 3)
        self.assertEqual(Collector.got, [])
        self.assertFalse(os.path.exists(self.state))


if __name__ == "__main__":
    unittest.main()
