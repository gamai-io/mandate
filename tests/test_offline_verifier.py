"""The independent verifier must pass the vectors and fail the tampered ones."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "spec", "verify_offline.py")
V = os.path.join(ROOT, "spec", "vectors")


def run(*args):
    proc = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout)


class Vectors(unittest.TestCase):
    def test_the_published_vector_verifies(self) -> None:
        code, out = run("--grant", os.path.join(V, "grant.json"),
                        "--intent", os.path.join(V, "intent.json"),
                        "--signers", os.path.join(V, "allowed_signers"),
                        "--receipt", os.path.join(V, "receipt.json"))
        self.assertEqual(code, 0, out)
        self.assertTrue(out["ok"])
        names = {c["check"] for c in out["checks"]}
        self.assertTrue({"grant_signature", "signer_authorised",
                         "commitment_matches_intent", "receipt_hash",
                         "receipt_bound_to_grant"} <= names, names)

    def test_a_changed_amount_fails(self) -> None:
        code, out = run("--grant", os.path.join(V, "grant.json"),
                        "--intent", os.path.join(V, "intent-tampered.json"),
                        "--signers", os.path.join(V, "allowed_signers"))
        self.assertEqual(code, 1)
        self.assertFalse(out["ok"])
        self.assertTrue(any("commitment" in e for e in out["errors"]), out["errors"])

    def test_a_forged_receipt_fails(self) -> None:
        code, out = run("--grant", os.path.join(V, "grant.json"),
                        "--intent", os.path.join(V, "intent.json"),
                        "--signers", os.path.join(V, "allowed_signers"),
                        "--receipt", os.path.join(V, "receipt-tampered.json"))
        self.assertEqual(code, 1)
        self.assertTrue(any("receipt hash" in e for e in out["errors"]), out["errors"])

    def test_an_unknown_signer_fails(self) -> None:
        empty = os.path.join(V, "allowed_signers.empty")
        open(empty, "w").close()
        try:
            code, out = run("--grant", os.path.join(V, "grant.json"),
                            "--signers", empty)
        finally:
            os.remove(empty)
        self.assertEqual(code, 1)
        self.assertTrue(any("not authorised" in e for e in out["errors"]), out["errors"])

    def test_the_verifier_imports_no_project_code(self) -> None:
        source = open(SCRIPT, encoding="utf-8").read()
        for forbidden in ("import mandate", "from mandate"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
