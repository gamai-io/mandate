"""Every attack in tools/attack_eval.py must stay caught.

A record that stops catching one of these is not tamper-evident any more, so the list is
run as a test rather than kept as a document.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import attack_eval  # noqa: E402


class Attacks(unittest.TestCase):
    def test_every_attack_is_caught(self):
        work = tempfile.mkdtemp(prefix="mandate-attacks-test-")
        env = attack_eval.build(work)
        rows = attack_eval.attacks(env)
        missed = [row["attack"] for row in rows if not row["caught"]]
        self.assertEqual(missed, [], f"not caught: {missed}")
        self.assertGreaterEqual(len(rows), 11)

    def test_the_baseline_verifies(self):
        work = tempfile.mkdtemp(prefix="mandate-attacks-test-")
        env = attack_eval.build(work)
        rows = attack_eval.attacks(env)
        self.assertTrue(rows[0]["caught"], rows[0])


if __name__ == "__main__":
    unittest.main()
