"""`tools/published_versions.json` must not claim a version older than what ships.

The nightly `published-smoke` job installs from PyPI and fails when PyPI serves something
older than this file records (a yank, a rollback, or a mis-tagged release). This test
keeps the file in step with the package version when a release is cut.
"""
from __future__ import annotations

import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PublishedVersions(unittest.TestCase):
    def test_file_is_valid(self):
        data = json.loads((ROOT / "tools" / "published_versions.json").read_text(encoding="utf-8"))
        self.assertIn("gama-mandate", data)
        for name, version in data.items():
            self.assertRegex(version, r"^\d+\.\d+\.\d+$", name)

    def test_this_package_is_not_ahead_of_the_record(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        version = [l.split('"')[1] for l in text.splitlines() if l.startswith("version = ")][0]
        recorded = json.loads((ROOT / "tools" / "published_versions.json")
                              .read_text(encoding="utf-8"))["gama-mandate"]
        self.assertEqual(recorded, version,
                         "bump tools/published_versions.json in the same release commit")


if __name__ == "__main__":
    unittest.main()
