"""PROVENANCE_V1: "who built the wheel" is a server-side fact, so it is checked, not assumed.

The tests inject PyPI responses instead of trusting the network: a version with attestations,
a version uploaded with a token (none), a partial, an offline host and an unknown version.
"""
from __future__ import annotations

import json
import unittest

from mandate import provenance


def _meta(*names: str) -> bytes:
    return json.dumps({"urls": [{"filename": n, "digests": {"sha256": "a" * 64}} for n in names]}
                      ).encode()


def _attested(repo: str = "gamai-io/mandate") -> bytes:
    return json.dumps({"version": 1, "attestation_bundles": [{
        "publisher": {"kind": "GitHub", "repository": repo, "workflow": "release.yml",
                      "environment": None},
        "attestations": [{"verification_material": {}}]}]}).encode()


class Check(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.responses = {}
        self._orig = provenance._fetch

        def fake(url, timeout=15):
            self.calls.append(url)
            for key, value in self.responses.items():
                if url.endswith(key):
                    return value
            return 404, b""
        provenance._fetch = fake

    def tearDown(self):
        provenance._fetch = self._orig

    def test_every_file_attested(self):
        self.responses = {"/json": (200, _meta("a.whl", "a.tar.gz")),
                          "/provenance": (200, _attested())}
        out = provenance.check("1.0.7")
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["attested"], 2)
        self.assertEqual(out["files"][0]["publishers"][0]["repository"], "gamai-io/mandate")

    def test_a_token_upload_has_no_attestation(self):
        self.responses = {"/json": (200, _meta("a.whl"))}      # integrity 404
        out = provenance.check("1.0.6")
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "none")
        self.assertEqual(out["missing"], ["a.whl"])

    def test_one_attested_one_not_is_partial(self):
        self.responses = {"/json": (200, _meta("a.whl", "a.tar.gz"))}

        def fake(url, timeout=15):
            self.calls.append(url)
            if url.endswith("/json"):
                return 200, _meta("a.whl", "a.tar.gz")
            if url.endswith("a.whl/provenance"):
                return 200, _attested()
            return 404, b""
        provenance._fetch = fake
        out = provenance.check("1.0.7")
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "partial")
        self.assertEqual(out["missing"], ["a.tar.gz"])

    def test_unknown_version(self):
        out = provenance.check("9.9.9")
        self.assertEqual(out["code"], "no_version")

    def test_offline_says_offline_instead_of_claiming_anything(self):
        self.responses = {"/json": (0, b"")}
        out = provenance.check("1.0.7")
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "network")
        self.assertIn("cannot be checked offline", out["message"])

    def test_summary_names_the_builder(self):
        self.responses = {"/json": (200, _meta("a.whl")),
                          "/provenance": (200, _attested())}
        text = provenance.summary(provenance.check("1.0.7"))
        self.assertIn("1/1 files attested", text)
        self.assertIn("GitHub gamai-io/mandate release.yml", text)


if __name__ == "__main__":
    unittest.main()
