"""DETECT_SIEM_V1: what a bank's SOC needs — tool-level sequences and a SIEM line.

Per-receipt rules cannot see `web_fetch` → `pay` inside 20 seconds; that gap is the one an
injection exploits. These tests cover the three sequence rules, the DORA proposal, and the
two SIEM formats (including the escaping that keeps a target with `|` from breaking a row).
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

from mandate import detect

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _event(ts, tool="read", **over):
    body = {"v": 1, "type": "control", "action": "call", "tool": tool,
            "decision": "allow", "audience": "mcp:fake", "ts": ts}
    body.update(over)
    return body


class Sequences(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        pathlib.Path(self.ledger).write_text(
            json.dumps({"v": 1, "body": {"type": "control", "action": "x"}, "hash": "aa",
                        "prev": "GENESIS"}) + "\n", encoding="utf-8")
        self.mcp = os.path.join(self.dir, "mcp.jsonl")
        self.now = int(time.time())

    def tearDown(self):
        self.td.cleanup()

    def _write(self, *events):
        pathlib.Path(self.mcp).write_text(
            "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    def _rules(self):
        out = detect.detect(self.ledger, {"human_principals": [], "max_effects_per_hour": 0,
                                          "max_amount": 0, "business_hours_utc": [0, 24],
                                          "min_coverage": ""}, mcp_ledger=self.mcp)
        return [f["rule"] for f in out["findings"]], out

    def test_fetch_then_pay(self):
        self._write(_event(self.now - 60, "web_fetch"), _event(self.now - 40, "pay"))
        rules, _ = self._rules()
        self.assertIn("fetch_then_pay", rules)

    def test_a_slow_pair_is_not_a_sequence(self):
        self._write(_event(self.now - 900, "web_fetch"), _event(self.now - 60, "pay"))
        rules, _ = self._rules()
        self.assertNotIn("fetch_then_pay", rules)

    def test_pay_after_a_blocked_response(self):
        self._write(_event(self.now - 200, "read", code="ResponseBlocked", action="refuse"),
                    _event(self.now - 100, "pay"))
        rules, _ = self._rules()
        self.assertIn("pay_after_block", rules)

    def test_tool_loop(self):
        self._write(*[_event(self.now - 50 + i, "read") for i in range(6)])
        rules, _ = self._rules()
        self.assertIn("tool_loop", rules)

    def test_four_calls_are_not_a_loop(self):
        self._write(*[_event(self.now - 50 + i, "read") for i in range(4)])
        rules, _ = self._rules()
        self.assertNotIn("tool_loop", rules)

    def test_every_finding_carries_a_dora_proposal(self):
        self._write(_event(self.now - 60, "web_fetch"), _event(self.now - 40, "pay"))
        _, out = self._rules()
        for finding in out["findings"]:
            self.assertIn(finding["dora"]["class"], ("major", "incident"))
            self.assertIn("proposal", finding["dora"]["basis"])


class Siem(unittest.TestCase):
    def setUp(self):
        self.finding = {"rule": "untrusted_input", "severity": "high", "agent": "agent@x",
                        "evidence": {"fields": ["target"], "target": "A|B=C"}}

    def test_cef_shape_and_escaping(self):
        line = detect.to_cef(self.finding)
        self.assertTrue(line.startswith("CEF:0|gamai|mandate|1.0|untrusted_input|"))
        self.assertIn("|8|", line)                      # severity high
        self.assertIn("src=agent@x", line)
        self.assertIn("A\\|B\\=C", line)                 # delimiter escaped
        self.assertEqual(line.count("\n"), 0)

    def test_leef_shape(self):
        line = detect.to_leef(self.finding)
        self.assertTrue(line.startswith("LEEF:2.0|gamai|mandate|1.0|untrusted_input|"))
        self.assertIn("sev=8", line)
        self.assertIn("\t", line)
        self.assertEqual(line.count("\n"), 0)

    def test_cli_formats(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "ledger.jsonl")
            pathlib.Path(ledger).write_text(
                json.dumps({"v": 1, "body": {"type": "receipt", "approver": "approver",
                                             "agent": "approver", "ts": 1,
                                             "render": {"fields": {"kind": "payment.send",
                                                                   "target": "X"}}}}) + "\n",
                encoding="utf-8")
            for fmt, prefix in (("cef", "CEF:0|"), ("leef", "LEEF:2.0|"),
                                ("jsonl", "{")):
                done = subprocess.run([sys.executable, "-m", "mandate", "detect",
                                       "--ledger", ledger, "--format", fmt],
                                      cwd=str(ROOT), capture_output=True, text=True)
                lines = [line for line in done.stdout.splitlines() if line]
                self.assertTrue(lines, (fmt, done.stdout, done.stderr))
                self.assertTrue(lines[0].startswith(prefix), (fmt, lines[0]))


if __name__ == "__main__":
    unittest.main()
