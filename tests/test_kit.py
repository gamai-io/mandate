"""The conformance kit must pass our verifier and fail a lying one."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
KIT = ROOT / "tools" / "kit.py"
# the {bundle}/{signers}/{log_signers} placeholders belong to the kit, not to str.format
VERIFIER = (sys.executable + " -m mandate --signers {signers} audit verify "
            "--bundle {bundle} --log-signers {log_signers} "
            "--witness-signers {witness_signers}")


class Kit(unittest.TestCase):
    def run_kit(self, verifier: str):
        done = subprocess.run([sys.executable, str(KIT), "--verifier", verifier, "--json"],
                              cwd=ROOT, capture_output=True, text=True, timeout=180)
        return done, json.loads(done.stdout)

    def test_our_verifier_passes_every_case(self):
        done, report = self.run_kit(VERIFIER)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(report["failed"], 0, report)
        self.assertGreaterEqual(report["total"], 11)

    def test_a_verifier_that_always_says_yes_fails(self):
        liar = f'{sys.executable} -c "print(\'{{\\"valid\\": true}}\')"'
        done, report = self.run_kit(liar)
        self.assertEqual(done.returncode, 1)
        self.assertGreaterEqual(report["failed"], 5, report)

    def test_badge_record_matches_the_run(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            record = pathlib.Path(td) / "conformance.json"
            done = subprocess.run([sys.executable, str(KIT), "--verifier", VERIFIER,
                                   "--badge", str(record), "--name", "tests"],
                                  cwd=ROOT, capture_output=True, text=True, timeout=180)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertIn("shields.io/badge", done.stdout)
            data = json.loads(record.read_text(encoding="utf-8"))
            self.assertEqual(data["format"], "mandate-conformance/1")
            self.assertTrue(data["ok"])
            self.assertEqual(data["failed"], 0)
            self.assertEqual(data["total"], len(data["cases"]))
            self.assertEqual(data["verifier"], "tests")

    def test_the_case_list_is_complete(self):
        manifest = json.loads((ROOT / "spec" / "kit" / "cases.json").read_text())
        names = {case["name"] for case in manifest["cases"]}
        for required in ("valid", "tampered_signature", "sth_bad_signature",
                         "proof_tampered", "witness_claim_only",
                         "coverage_missing", "coverage_invalid", "taint_mismatch",
                         "witness_note_forged", "unknown_signer"):
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
