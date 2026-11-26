"""The build backend pin is part of the reproducibility claim.

`docs/REPRODUCIBLE.md` says the published artefacts were built with a pinned
setuptools. A dependabot bump of that pin silently invalidated the claim once; this
test makes the pin explicit, so changing it has to be a deliberate change here too.
"""
from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PIN = "78.1.0"


class BuildPin(unittest.TestCase):
    def test_setuptools_pin(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        requires = re.search(r'^requires\s*=\s*\[(.*?)\]', text, re.M | re.S).group(1)
        self.assertIn(f'setuptools=={PIN}', requires,
                      "build backend pin changed: update docs/REPRODUCIBLE.md and "
                      "re-verify an artefact before touching this")

    def test_documentation_names_the_same_pin(self):
        text = (ROOT / "docs" / "REPRODUCIBLE.md").read_text(encoding="utf-8")
        self.assertIn(f"setuptools=={PIN}", text)

    def test_dependabot_ignores_the_build_backend(self):
        text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn('dependency-name: "setuptools"', text)


if __name__ == "__main__":
    unittest.main()
