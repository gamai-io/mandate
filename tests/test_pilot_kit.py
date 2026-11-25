"""The folder we send must be complete and checkable."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Kit(unittest.TestCase):
    def build(self) -> str:
        out = tempfile.mkdtemp(prefix="kit-")
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_pilot_kit.py"),
                        "--out", out], check=True, capture_output=True)
        return out

    def test_the_kit_has_the_documents_and_a_manifest(self) -> None:
        out = self.build()
        names = set(os.listdir(out))
        for expected in ("00-one-page.html", "01-pilot-sow.md", "02-control-matrix.md",
                         "03-procurement-answers.md", "07-dora-supplier-pack.md",
                         "README.md", "MANIFEST.sha256"):
            self.assertIn(expected, names)
        manifest = open(os.path.join(out, "MANIFEST.sha256")).read().strip().splitlines()
        self.assertGreaterEqual(len(manifest), 8)
        for line in manifest:
            digest, name = line.split("  ", 1)
            with open(os.path.join(out, name), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest)

    def test_no_internal_paths_leak_into_the_kit(self) -> None:
        out = self.build()
        for name in os.listdir(out):
            text = open(os.path.join(out, name), encoding="utf-8", errors="replace").read()
            internal = "/" + "root" + "/"
            self.assertNotIn(internal, text, "%s carries an internal path" % name)
            self.assertNotIn("ghp_", text)


if __name__ == "__main__":
    unittest.main()
