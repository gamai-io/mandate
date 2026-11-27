"""DISCLOSURE_V1: show the record, hide the supplier.

The redacted view binds to the original receipt hash (the thing the log anchors)
and every hidden field carries a salted commitment that a later reveal must
match. It does *not* inherit the original signer's signature — the signer signed
the values — so the party producing the view signs it, and the document says so.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import disclose
from mandate.jcs import canonicalize

ROOT = pathlib.Path(__file__).resolve().parents[1]

RECEIPT = {
    "v": 1, "type": "receipt", "proposal_id": "m1", "approver": "approver",
    "decision": "executed", "coverage": "enforced",
    "render": {"fields": {"kind": "payment.send", "target": "Example Supplier",
                          "amount": {"value": 1170.0, "currency": "BAM"}}},
}


def body_hash(body):
    return hashlib.sha256(canonicalize(body).encode("utf-8")).hexdigest()


class Commitments(unittest.TestCase):
    def test_commit_and_verify(self):
        d = disclose.commit("Example Supplier")
        self.assertTrue(disclose.verify_commit("Example Supplier", d))
        self.assertFalse(disclose.verify_commit("Other Supplier", d))

    def test_salt_changes_the_hash(self):
        a = disclose.commit("x", b"a" * 16)
        b = disclose.commit("x", b"b" * 16)
        self.assertNotEqual(a["hash"], b["hash"])

    def test_bad_salt_is_refused(self):
        with self.assertRaises(disclose.DisclosureError) as ctx:
            disclose.verify_commit("x", {"salt": "!!!", "hash": "aa"})
        self.assertEqual(ctx.exception.code, "E_SALT")


class RedactReveal(unittest.TestCase):
    def setUp(self):
        self.hash = body_hash(RECEIPT)
        self.view = disclose.redact(RECEIPT, ["render.fields.target",
                                              "render.fields.amount"],
                                    expect_hash=self.hash)

    def test_redacted_view_hides_values(self):
        fields = self.view["receipt"]["render"]["fields"]
        self.assertEqual(set(fields["target"]), {"__redacted__"})
        self.assertNotIn("Example Supplier", json.dumps(self.view))
        self.assertEqual(self.view["receipt_hash"], self.hash)

    def test_structure_check_passes(self):
        out = disclose.check_view(self.view)
        self.assertTrue(out["ok"])
        self.assertEqual(sorted(out["redacted"]),
                         ["render.fields.amount", "render.fields.target"])

    def test_reveal_restores_the_original_hash(self):
        out = disclose.reveal(self.view,
                              ["render.fields.target", "render.fields.amount"],
                              {"render.fields.target": "Example Supplier",
                               "render.fields.amount": {"value": 1170.0, "currency": "BAM"}})
        self.assertEqual(out["hash"], self.hash)
        self.assertEqual(out["receipt"], RECEIPT)

    def test_wrong_value_is_refused(self):
        with self.assertRaises(disclose.DisclosureError) as ctx:
            disclose.reveal(self.view, ["render.fields.target"],
                            {"render.fields.target": "Other Supplier"})
        self.assertEqual(ctx.exception.code, "E_COMMITMENT")

    def test_missing_disclosure_is_refused(self):
        with self.assertRaises(disclose.DisclosureError) as ctx:
            disclose.reveal(self.view, ["render.fields.kind"], {"render.fields.kind": "x"})
        self.assertEqual(ctx.exception.code, "E_NODISCLOSURE")

    def test_redaction_of_another_record_is_refused(self):
        with self.assertRaises(disclose.DisclosureError) as ctx:
            disclose.redact(RECEIPT, ["render.fields.target"], expect_hash="00" * 32)
        self.assertEqual(ctx.exception.code, "E_HASH")

    def test_unknown_path_is_refused(self):
        with self.assertRaises(disclose.DisclosureError) as ctx:
            disclose.redact(RECEIPT, ["render.fields.nope"])
        self.assertEqual(ctx.exception.code, "E_PATH")

    def test_tampering_with_a_commitment_is_caught(self):
        view = json.loads(json.dumps(self.view))
        view["disclosures"][0]["hash"] = "00" * 32
        with self.assertRaises(disclose.DisclosureError) as ctx:
            disclose.check_view(view)
        self.assertEqual(ctx.exception.code, "E_COMMITMENT")


class Cli(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.receipt = os.path.join(d, "receipt.json")
        pathlib.Path(self.receipt).write_text(json.dumps(RECEIPT), encoding="utf-8")
        self.view = os.path.join(d, "view.json")
        self.hash = body_hash(RECEIPT)

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "mandate", "disclose", *args],
                              cwd=str(ROOT), capture_output=True, text=True)

    def test_redact_then_verify(self):
        done = self._run("redact", "--receipt", self.receipt,
                         "--fields", "render.fields.target",
                         "--expect-hash", self.hash, "-o", self.view)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = self._run("verify", "--view", self.view)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(json.loads(done.stdout)["ok"])

    def test_wrong_value_exits_non_zero_with_a_code(self):
        self._run("redact", "--receipt", self.receipt, "--fields", "render.fields.target",
                  "-o", self.view)
        vals = os.path.join(self.dir, "v.json")
        pathlib.Path(vals).write_text(json.dumps({"render.fields.target": "nope"}),
                                      encoding="utf-8")
        done = self._run("reveal", "--view", self.view, "--fields",
                         "render.fields.target", "--values", vals)
        self.assertEqual(done.returncode, 1)
        self.assertEqual(json.loads(done.stdout)["error"], "E_COMMITMENT")


if __name__ == "__main__":
    unittest.main()
