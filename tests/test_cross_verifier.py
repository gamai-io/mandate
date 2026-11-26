"""The two offline verifiers must agree, including on the cases we ship.

The README says two implementations (Python and Node) must give the same answer on
the same vectors. This test runs both and compares exit codes; a divergence is a
finding, not a style difference.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec" / "vectors"
NODE = shutil.which("node")


def run(cmd):
    done = subprocess.run(cmd, capture_output=True, text=True)
    payload = {}
    try:
        payload = json.loads(done.stdout)
    except ValueError:
        pass
    return done.returncode, payload


@unittest.skipUnless(NODE, "node is not installed")
class CrossVerifier(unittest.TestCase):
    def _both(self, intent="intent.json", receipt="receipt.json",
              signers=None):
        signers = signers or str(VECTORS / "allowed_signers")
        py = run([sys.executable, str(ROOT / "spec" / "verify_offline.py"),
                  "--grant", str(VECTORS / "grant.json"),
                  "--intent", str(VECTORS / intent),
                  "--signers", signers,
                  "--receipt", str(VECTORS / receipt)])
        js = run([NODE, str(ROOT / "spec" / "verify_offline.js"),
                  "--grant", str(VECTORS / "grant.json"),
                  "--intent", str(VECTORS / intent),
                  "--signers", signers,
                  "--receipt", str(VECTORS / receipt)])
        return py, js

    def test_the_published_vector_passes_in_both(self):
        (py_code, py), (js_code, js) = self._both()
        self.assertEqual(py_code, 0, py)
        self.assertEqual(js_code, 0, js)
        self.assertEqual(bool(py.get("ok")), bool(js.get("ok")))

    def test_a_tampered_intent_fails_in_both(self):
        (py_code, py), (js_code, js) = self._both(intent="intent-tampered.json")
        self.assertEqual(py_code, 1, py)
        self.assertEqual(js_code, 1, js)
        self.assertEqual(bool(py.get("ok")), bool(js.get("ok")))

    def test_a_tampered_receipt_fails_in_both(self):
        (py_code, py), (js_code, js) = self._both(receipt="receipt-tampered.json")
        self.assertEqual(py_code, 1, py)
        self.assertEqual(js_code, 1, js)
        self.assertEqual(bool(py.get("ok")), bool(js.get("ok")))

    def test_a_namespace_restricted_line_fails_in_both(self):
        with tempfile.TemporaryDirectory() as td:
            signers = os.path.join(td, "signers")
            lines = (VECTORS / "allowed_signers").read_text(encoding="utf-8")
            signers_text = lines.replace('namespaces="mandate"',
                                         'namespaces="other"')
            with open(signers, "w", encoding="utf-8") as fh:
                fh.write(signers_text)
            (py_code, py), (js_code, js) = self._both(signers=signers)
        self.assertEqual(py_code, 1, py)
        self.assertEqual(js_code, 1, js)
        self.assertEqual(bool(py.get("ok")), bool(js.get("ok")))


if __name__ == "__main__":
    unittest.main()
