"""Behavioural detection of an inbound agent: the Jesta/OpenCode timeline as a test."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from mandate import agentwatch

NOW = 1795558000.0
DESKTOP = "Mozilla/5.0 (Macintosh) Chrome/157.0"
PHONE = "Mozilla/5.0 (Linux; Android 15; Pixel 10) Chrome/157.0 Mobile"
CURL = "curl/8.7.1"


def line(ts, ua, path, status=200, method="GET", auth="none", referer="", platform=None):
    return {"ts": ts, "ip": "81.2.3.4", "ua": ua, "method": method, "path": path,
            "status": status, "auth": auth, "referer": referer,
            "ua_platform": platform or ("mobile" if "Mobile" in ua else "desktop")}


def jesta_like() -> list[dict]:
    t = NOW - 400
    rows = [
        line(t, DESKTOP, "/", 403),
        line(t + 6, PHONE, "/", 403),
        line(t + 11, DESKTOP, "/api/openapi.json", 403),
        line(t + 16, DESKTOP, "/decoy/openapi.md", 200),
        line(t + 29, DESKTOP, "/api/v1/transactions", 200, referer="/decoy/openapi.md"),
        line(t + 40, CURL, "/api/v1/transactions", 401, auth="key-A"),
        line(t + 42, CURL, "/api/v1/transactions", 401, auth="none"),
        line(t + 44, CURL, "/api/v1/transactions", 401, auth="made-up"),
        line(t + 60, CURL, "/api/v1/transactions/read", 405),
        line(t + 70, CURL, "/api/v1/transactions/read", 405),
    ]
    return rows


def benign() -> list[dict]:
    t = NOW - 300
    return [line(t + i * 20, DESKTOP, "/pricing", 200) for i in range(5)]


class JestaTimeline(unittest.TestCase):
    def test_incident_is_high(self) -> None:
        res = agentwatch.analyse(jesta_like(), now=NOW)
        session = res["sessions"]["81.2.3.4"]
        rules = {f["rule"] for f in session["findings"]}
        self.assertEqual(session["level"], "high", session)
        for expected in ("tool_switch", "ua_flip", "docs_link_follow", "key_probing",
                         "read_after_submit"):
            self.assertIn(expected, rules)
        self.assertGreaterEqual(session["points"], 10)

    def test_benign_visitor_is_low(self) -> None:
        res = agentwatch.analyse(benign(), now=NOW)
        self.assertEqual(res["sessions"]["81.2.3.4"]["level"], "low")

    def test_old_requests_fall_outside_the_window(self) -> None:
        res = agentwatch.analyse(jesta_like(), window=60, now=NOW)
        session = res["sessions"].get("81.2.3.4")
        if session:  # only the tail of the session remains
            self.assertLess(session["requests"], len(jesta_like()))

    def test_cli_writes_an_alert_to_the_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "access.jsonl")
            with open(log, "w") as fh:
                for row in jesta_like():
                    row = dict(row)
                    row["ts"] = time.time() - 60
                    fh.write(json.dumps(row) + "\n")
            ledger = os.path.join(td, "ledger.jsonl")
            res = agentwatch.watch(log, ledger=ledger)
            self.assertEqual(res["flagged"], 1)
            last = json.loads(open(ledger).read().strip().splitlines()[-1])["body"]
            self.assertEqual(last["type"], "control")
            self.assertEqual(last["action"], "alert")

    def test_quiet_log_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "access.jsonl")
            with open(log, "w") as fh:
                for row in benign():
                    row = dict(row)
                    row["ts"] = time.time() - 30
                    fh.write(json.dumps(row) + "\n")
            ledger = os.path.join(td, "ledger.jsonl")
            agentwatch.watch(log, ledger=ledger)
            self.assertFalse(os.path.exists(ledger))


if __name__ == "__main__":
    unittest.main()
