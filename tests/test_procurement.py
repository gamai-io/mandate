"""ROW11_V1: procurement answers that cannot drift from the code.

A supplier questionnaire is where a PDF goes to die. These three files are generated from the
same data as `mandate controls` and shipped inside `mandate pack`, so an answer that no longer
matches the code fails a test instead of being discovered by a bank.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import controls, report

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Answers(unittest.TestCase):
    def test_dd_answers_mirror_the_matrix(self):
        out = controls.dd_answers("1.0.4", now=1700000000)
        matrix = controls.summary()
        self.assertEqual(out["controls"]["rows"], matrix["rows"])
        self.assertEqual(out["controls"]["have"], matrix["have"])
        self.assertEqual(len(out["rows"]), matrix["rows"])
        self.assertEqual(out["answered_at"], 1700000000)
        self.assertTrue(any("tamper-proof" in x for x in out["not_claimed"]))

    def test_every_row_carries_what_is_missing(self):
        for row in controls.dd_answers("1.0.4")["rows"]:
            self.assertTrue(row["artifact"], row)
            self.assertTrue(row["missing"], row)

    def test_how_to_verify_names_real_commands(self):
        cmds = controls.dd_answers("1.0.4")["how_to_verify"]
        self.assertTrue(any("worm-verify" in c for c in cmds))
        self.assertTrue(any("replay" in c for c in cmds))

    def test_subprocessors_say_there_is_no_hosted_service(self):
        out = controls.subprocessors()
        self.assertIn("no subprocessors", out["statement"])
        self.assertTrue(all(c["sees_your_data"] is not True for c in out["categories"]))

    def test_every_clause_has_a_proof(self):
        out = controls.contract_clauses()
        self.assertGreaterEqual(len(out["clauses"]), 8)
        for clause in out["clauses"]:
            self.assertTrue(clause["text"].strip(), clause)
            self.assertTrue(clause["evidence"].strip(), clause)
        self.assertIn("does not certify compliance",
                      " ".join(c["text"] for c in out["clauses"]))


class Pack(unittest.TestCase):
    def test_pack_carries_the_three_procurement_files(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = os.path.join(td, "ledger.jsonl")
            pathlib.Path(ledger).write_text(
                json.dumps({"v": 1, "type": "control", "action": "x", "hash": "aa",
                            "prev": "GENESIS"}) + "\n", encoding="utf-8")
            out = os.path.join(td, "pack")
            res = report.pack(ledger, out)
            names = sorted(os.listdir(out))
            for name in ("dd_answers.json", "subprocessors.json", "contract_clauses.json"):
                self.assertIn(name, names)
                self.assertIn(name, (res.get("files") or []))
            index = json.loads(pathlib.Path(os.path.join(out, "index.json")).read_text())
            for name in ("dd_answers.json", "subprocessors.json", "contract_clauses.json"):
                self.assertIn(name, index["files"])
                self.assertEqual(len(index["files"][name]["sha256"]), 64)

    def test_cli(self):
        done = subprocess.run([sys.executable, "-m", "mandate", "controls", "--summary"],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
