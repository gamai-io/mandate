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
        self.assertGreaterEqual(report["total"], 7)

    def test_a_verifier_that_always_says_yes_fails(self):
        liar = f'{sys.executable} -c "print(\'{{\\"valid\\": true}}\')"'
        done, report = self.run_kit(liar)
        self.assertEqual(done.returncode, 1)
        self.assertGreaterEqual(report["failed"], 5, report)

    def test_the_case_list_is_complete(self):
        manifest = json.loads((ROOT / "spec" / "kit" / "cases.json").read_text())
        names = {case["name"] for case in manifest["cases"]}
        for required in ("valid", "tampered_signature", "sth_bad_signature",
                         "proof_tampered", "witness_claim_only",
                         "witness_note_forged", "unknown_signer"):
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
