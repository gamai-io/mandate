"""A verifier must refuse what a second parser could read differently.

Each case below is a document that `json.loads` accepts and that a JavaScript or Go
verifier can interpret differently, which would let a signature cover one thing and an
auditor read another.
"""
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from mandate.strictjson import StrictJSONError, loads_strict

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Rejections(unittest.TestCase):
    def assertCode(self, text, code):
        with self.assertRaises(StrictJSONError) as ctx:
            loads_strict(text)
        self.assertEqual(ctx.exception.code, code)

    def test_duplicate_key(self):
        self.assertCode('{"a": 1, "a": 2}', "duplicate_key")

    def test_nan_and_infinity(self):
        self.assertCode('{"a": NaN}', "non_finite")
        self.assertCode('{"a": -Infinity}', "non_finite")

    def test_integer_beyond_ieee754(self):
        self.assertCode('{"a": 9007199254740993}', "int_range")
        self.assertCode('{"a": 12345678901234567890}', "int_range")

    def test_lone_surrogate(self):
        self.assertCode('{"a": "\\ud800"}', "lone_surrogate")

    def test_depth(self):
        self.assertCode("[" * 130 + "]" * 130, "depth")

    def test_syntax(self):
        self.assertCode("{", "syntax")

    def test_non_utf8(self):
        with self.assertRaises(StrictJSONError) as ctx:
            loads_strict(b'{"a": "\xff"}')
        self.assertEqual(ctx.exception.code, "invalid_utf8")


class Accepts(unittest.TestCase):
    def test_ordinary_document(self):
        value = loads_strict('{"a": 1, "b": [true, null, "č"], "c": 1.5}')
        self.assertEqual(value["b"][2], "č")

    def test_the_shipped_vectors_parse(self):
        for path in (ROOT / "spec" / "vectors").glob("*.json"):
            with self.subTest(vector=path.name):
                loads_strict(path.read_bytes())

    def test_core_loader_is_strict(self):
        from mandate.core import load_json
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "dup.json"
            path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaises(StrictJSONError):
                load_json(str(path))

    def test_bundle_round_trip_still_valid(self):
        # a normal bundle produced by the CLI must still parse
        from mandate import export
        bundle = export.build_bundle({"id": "r1"}, {"op": "echo"}, {"grant": {}})
        self.assertEqual(loads_strict(json.dumps(bundle))["v"], 1)


if __name__ == "__main__":
    unittest.main()
