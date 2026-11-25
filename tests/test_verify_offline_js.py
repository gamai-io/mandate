"""A second verifier in another language, on another crypto library."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "spec", "verify_offline.js")
VECTORS = os.path.join(ROOT, "spec", "vectors")
NODE = shutil.which("node")


def run(*args):
    proc = subprocess.run([NODE, SCRIPT, *args], capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout)


@unittest.skipUnless(NODE, "node is not installed")
class NodeVerifier(unittest.TestCase):
    def test_the_published_vector_verifies(self) -> None:
        code, out = run("--grant", os.path.join(VECTORS, "grant.json"),
                        "--intent", os.path.join(VECTORS, "intent.json"),
                        "--signers", os.path.join(VECTORS, "allowed_signers"),
                        "--receipt", os.path.join(VECTORS, "receipt.json"))
        self.assertEqual(code, 0, out)
        names = {c["check"] for c in out["checks"]}
        self.assertTrue({"grant_signature", "signer_authorised",
                         "commitment_matches_intent", "receipt_hash",
                         "receipt_bound_to_grant"} <= names, names)

    def test_a_changed_amount_fails(self) -> None:
        code, out = run("--grant", os.path.join(VECTORS, "grant.json"),
                        "--intent", os.path.join(VECTORS, "intent-tampered.json"),
                        "--signers", os.path.join(VECTORS, "allowed_signers"))
        self.assertEqual(code, 1)
        self.assertFalse(out["ok"])

    def test_a_forged_receipt_fails(self) -> None:
        code, out = run("--grant", os.path.join(VECTORS, "grant.json"),
                        "--intent", os.path.join(VECTORS, "intent.json"),
                        "--signers", os.path.join(VECTORS, "allowed_signers"),
                        "--receipt", os.path.join(VECTORS, "receipt-tampered.json"))
        self.assertEqual(code, 1)
        self.assertTrue(any("receipt hash" in e for e in out["errors"]), out["errors"])

    def test_the_two_verifiers_agree(self) -> None:
        import sys
        py = subprocess.run([sys.executable, os.path.join(ROOT, "spec", "verify_offline.py"),
                             "--grant", os.path.join(VECTORS, "grant.json"),
                             "--intent", os.path.join(VECTORS, "intent.json"),
                             "--signers", os.path.join(VECTORS, "allowed_signers"),
                             "--receipt", os.path.join(VECTORS, "receipt.json")],
                            capture_output=True, text=True)
        js = subprocess.run([NODE, SCRIPT, "--grant", os.path.join(VECTORS, "grant.json"),
                             "--intent", os.path.join(VECTORS, "intent.json"),
                             "--signers", os.path.join(VECTORS, "allowed_signers"),
                             "--receipt", os.path.join(VECTORS, "receipt.json")],
                            capture_output=True, text=True)
        self.assertEqual(py.returncode, 0)
        self.assertEqual(js.returncode, 0)
        self.assertTrue(json.loads(py.stdout)["ok"])
        self.assertTrue(json.loads(js.stdout)["ok"])

    def test_the_js_verifier_does_not_import_our_package(self) -> None:
        source = open(SCRIPT, encoding="utf-8").read()
        for forbidden in ("require(\"mandate", "mandate/", "verify_offline.py"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
