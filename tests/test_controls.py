"""CONTROLS_V1 + ANCHOR_STATUS_V1: the two things a bank asks first.

  "which control does this satisfy, and what is missing?"   -> mandate controls
  "how old is your last anchor, and does it cover the head?" -> mandate anchor --status

Both are answerable without a customer, which is the point: a supplier questionnaire can be
filled from data, and a stale anchor is reported as stale instead of being called sealed.
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

from mandate import anchor, controls

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Matrix(unittest.TestCase):
    def test_twelve_rows_with_blunt_statuses(self):
        out = controls.summary()
        self.assertEqual(out["rows"], 12)
        self.assertEqual(out["have"] + out["partial"] + out["gap"], 12)
        self.assertGreaterEqual(out["partial"], 1)      # honesty: most rows are partial
        self.assertIn("tamper-proof", " ".join(out["not_claimed"]))

    def test_every_row_names_an_artifact(self):
        for row in controls.rows():
            self.assertTrue(row["artifact"], row)
            self.assertIn(row["status"], ("have", "partial", "gap"), row)

    def test_status_filter(self):
        have = controls.rows(status="have")
        self.assertTrue(have)
        self.assertTrue(all(r["status"] == "have" for r in have))

    def test_dora_hooks_are_reachable_by_alias(self):
        out = controls.summary("dora")
        self.assertTrue(any("12(2)(d)" in h for h in out["hooks"]))

    def test_unknown_framework_is_refused(self):
        with self.assertRaises(ValueError):
            controls.rows(framework="pci-dss")

    def test_render_mentions_the_limit(self):
        text = controls.render()
        self.assertIn("Not claimed", text)
        self.assertIn("tamper-evident", text)

    def test_cli(self):
        done = subprocess.run([sys.executable, "-m", "mandate", "controls", "--summary"],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(json.loads(done.stdout)["rows"], 12)


class AnchorStatus(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        pathlib.Path(self.ledger).write_text(
            json.dumps({"v": 1, "body": {"type": "control", "action": "x"}, "hash": "aa",
                        "prev": "GENESIS"}) + "\n", encoding="utf-8")
        self.anchors = os.path.join(self.dir, "anchors")
        os.makedirs(self.anchors, exist_ok=True)

    def tearDown(self):
        self.td.cleanup()

    def _write_anchor(self, head: str, when: float) -> None:
        side = {"head": head, "tsa": "https://freetsa.org/tsr", "gen_time_ms": when * 1000,
                "anchors": [{"ok": True}]}
        path = os.path.join(self.anchors, "a%s.tsr.json" % int(when))
        pathlib.Path(path).write_text(json.dumps(side), encoding="utf-8")

    def test_no_anchor_is_reported_as_no_anchor(self):
        out = anchor.status(self.ledger, self.anchors)
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "no_anchor")
        self.assertIn("disk", out["message"])

    def test_fresh_anchor_covering_the_head_is_ok(self):
        self._write_anchor("aa", time.time() - 60)
        out = anchor.status(self.ledger, self.anchors)
        self.assertTrue(out["ok"], out)
        self.assertTrue(out["covers_current_head"])
        self.assertLess(out["age_hours"], 1)

    def test_old_anchor_is_stale(self):
        self._write_anchor("aa", time.time() - 48 * 3600)
        out = anchor.status(self.ledger, self.anchors, max_age_hours=24)
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "stale")

    def test_anchor_behind_the_head_is_reported(self):
        self._write_anchor("bb", time.time() - 60)
        out = anchor.status(self.ledger, self.anchors)
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "behind")
        self.assertFalse(out["covers_current_head"])

    def test_cli_exit_codes(self):
        done = subprocess.run([sys.executable, "-m", "mandate", "anchor", "--ledger",
                               self.ledger, "--out", self.anchors, "--status"],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(done.returncode, 4)
        self.assertEqual(json.loads(done.stdout)["code"], "no_anchor")


if __name__ == "__main__":
    unittest.main()
