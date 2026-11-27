"""WORM_VERIFY_V1 + EGRESS_RULES_V1: an outsider can check the pack, and the proxy cannot be walked around."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import anchor, egress

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WormVerify(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        pathlib.Path(self.ledger).write_text(
            json.dumps({"v": 1, "body": {"type": "control", "action": "a"}, "hash": "aa",
                        "prev": "GENESIS"}) + "\n", encoding="utf-8")
        pathlib.Path(self.ledger + ".head").write_text("aa\n", encoding="utf-8")
        self.out = os.path.join(self.dir, "exports")
        res = anchor.worm_export(self.ledger, self.out, 180)
        self.pack = res["path"]

    def tearDown(self):
        self.td.cleanup()

    def test_a_clean_pack_verifies(self):
        out = anchor.worm_verify(self.pack)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["files_checked"], out["files_listed"])
        self.assertEqual(out["problems"], [])

    def test_a_changed_ledger_is_caught(self):
        with open(os.path.join(self.pack, "ledger.jsonl"), "a", encoding="utf-8") as fh:
            fh.write('{"v":1,"body":{"type":"control","action":"b"},"hash":"bb","prev":"aa"}\n')
        out = anchor.worm_verify(self.pack)
        self.assertFalse(out["ok"])
        self.assertIn("sha256 mismatch: ledger.jsonl", " ".join(out["problems"]))

    def test_a_missing_file_is_caught(self):
        os.remove(os.path.join(self.pack, "ledger.jsonl"))
        out = anchor.worm_verify(self.pack)
        self.assertFalse(out["ok"])
        self.assertIn("missing: ledger.jsonl", " ".join(out["problems"]))

    def test_a_file_outside_the_manifest_is_caught(self):
        pathlib.Path(os.path.join(self.pack, "extra.txt")).write_text("x", encoding="utf-8")
        out = anchor.worm_verify(self.pack)
        self.assertFalse(out["ok"])
        self.assertIn("not in manifest: extra.txt", " ".join(out["problems"]))

    def test_no_manifest(self):
        empty = os.path.join(self.dir, "empty")
        os.makedirs(empty)
        out = anchor.worm_verify(empty)
        self.assertEqual(out["code"], "no_manifest")

    def test_cli_exit_codes(self):
        good = subprocess.run([sys.executable, "-m", "mandate", "worm-verify", "--dir", self.pack],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        with open(os.path.join(self.pack, "ledger.jsonl"), "a", encoding="utf-8") as fh:
            fh.write("{}\n")
        bad = subprocess.run([sys.executable, "-m", "mandate", "worm-verify", "--dir", self.pack],
                             cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(bad.returncode, 4)


class Rules(unittest.TestCase):
    def test_rules_leave_one_path(self):
        text = egress.nft_rules(1001, "127.0.0.1:3128", ["10.0.0.0/8", "8.8.8.8:53"])
        self.assertIn("meta skuid 1001", text)
        self.assertIn("tcp dport 3128 accept", text)
        self.assertIn("ip daddr 10.0.0.0/8 accept", text)
        self.assertIn("udp dport 53 accept", text)      # DNS je UDP
        self.assertIn("meta skuid 1001 drop", text)
        self.assertEqual(text.count("tcp dport 3128 accept"), 1)   # bez duplikata

    def test_rule_text_says_its_scope(self):
        text = egress.nft_rules(7)
        self.assertIn("requires root", text)
        self.assertIn("containers and network namespaces", text)

    def test_cli_generates_and_checks(self):
        done = subprocess.run([sys.executable, "-m", "mandate", "egress", "rules",
                               "--uid", "1001", "--allow", "8.8.8.8:53", "--check"],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertIn(done.returncode, (0, 4))
        payload = json.loads(done.stdout)
        self.assertIn("skuid 1001", payload["text"])
        if payload["check"]:
            self.assertIn(payload["check"]["code"], ("ok", "nft_not_available", "nft_check_failed"))

    def test_cli_requires_uid(self):
        done = subprocess.run([sys.executable, "-m", "mandate", "egress", "rules"],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)


if __name__ == "__main__":
    unittest.main()
