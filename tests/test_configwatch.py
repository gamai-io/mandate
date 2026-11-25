"""What the agent reads before it acts must not change behind your back."""
from __future__ import annotations

import os
import tempfile
import unittest

from mandate import configwatch


class Config(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.settings = os.path.join(self.dir, "settings.json")
        self.mcp = os.path.join(self.dir, ".mcp.json")
        open(self.settings, "w").write('{"model": "x"}')
        open(self.mcp, "w").write('{"servers": ["erp"]}')
        self.store = os.path.join(self.dir, "configs.json")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_locking_records_hashes_not_contents(self) -> None:
        result = configwatch.lock([self.settings], self.store)
        self.assertEqual(result["files"], 1)
        stored = open(self.store, encoding="utf-8").read()
        self.assertNotIn("model", stored)
        self.assertIn("sha256", stored)

    def test_a_directory_lock_finds_the_usual_suspects(self) -> None:
        result = configwatch.lock([], self.store, [self.dir])
        self.assertIn(self.settings, result["paths"])
        self.assertIn(self.mcp, result["paths"])

    def test_an_unchanged_set_is_ok(self) -> None:
        configwatch.lock([self.settings, self.mcp], self.store)
        self.assertTrue(configwatch.check(self.store)["ok"])

    def test_an_edited_file_is_drift(self) -> None:
        configwatch.lock([self.settings, self.mcp], self.store)
        open(self.settings, "w").write('{"model": "x", "approve": "everything"}')
        result = configwatch.check(self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["drift"][0]["path"], self.settings)

    def test_a_deleted_file_is_missing(self) -> None:
        configwatch.lock([self.settings, self.mcp], self.store)
        os.remove(self.mcp)
        result = configwatch.check(self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing"][0]["path"], self.mcp)

    def test_the_check_is_recorded_in_the_ledger(self) -> None:
        ledger = os.path.join(self.dir, "ledger.jsonl")
        configwatch.lock([self.settings], self.store)
        configwatch.check(self.store, ledger)
        body = __import__("json").loads(
            open(ledger, encoding="utf-8").read().strip().splitlines()[-1])["body"]
        self.assertEqual((body["type"], body["action"]), ("control", "config_check"))
        self.assertTrue(body["ok"])

    def test_a_missing_lock_is_an_error_not_a_pass(self) -> None:
        with self.assertRaises(configwatch.ConfigError):
            configwatch.check(os.path.join(self.dir, "nope.json"))


if __name__ == "__main__":
    unittest.main()
