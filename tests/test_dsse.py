"""DSSE_V1: standard envelopes over our receipts, verified by our keys.

The point is interoperability without vendoring: any DSSE implementation can
rebuild the signed bytes from `pae()`, and any in-toto consumer can read the
statement shape.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import dsse
from mandate.jcs import canonicalize as jcs_canon

ROOT = pathlib.Path(__file__).resolve().parents[1]

RECEIPT = {
    "v": 1, "type": "receipt", "proposal_id": "m1abc", "commitment": "sha256:aa",
    "approver": "approver", "agent": "agent@example", "grant_nonce": "n-1",
    "decision": "executed", "coverage": "enforced", "result_hash": "sha256:bb",
    "ts": 1794184500, "render": {"summary": "payment.send | Example | 10 BAM"},
}


class Pae(unittest.TestCase):
    def test_spec_vector(self):
        # the example from the DSSE spec
        self.assertEqual(dsse.pae("http://example.com/HelloWorld", b"hello world"),
                         b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")

    def test_rejects_bad_input(self):
        with self.assertRaises(dsse.DsseError):
            dsse.pae("", b"x")
        with self.assertRaises(dsse.DsseError):
            dsse.pae("t", "not bytes")


class SignVerify(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n'
            % pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def test_roundtrip(self):
        env = dsse.envelope_for_receipt(RECEIPT, self.key, "approver")
        self.assertEqual(env["payloadType"], dsse.RECEIPT_TYPE)
        self.assertTrue(dsse.verify(env, self.signers))
        self.assertEqual(dsse.payload_json(env), RECEIPT)

    def test_statement_roundtrip(self):
        env = dsse.envelope_for_receipt(RECEIPT, self.key, "approver", as_statement=True)
        self.assertEqual(env["payloadType"], "application/vnd.in-toto+json")
        self.assertTrue(dsse.verify(env, self.signers))
        st = dsse.payload_json(env)
        self.assertEqual(st["_type"], dsse.INTOTO_STATEMENT)
        self.assertEqual(st["predicateType"], dsse.PREDICATE_TYPE)
        self.assertEqual(st["predicate"], RECEIPT)
        self.assertEqual(st["subject"][0]["digest"]["sha256"],
                         __import__("hashlib").sha256(
                             jcs_canon(RECEIPT).encode("utf-8")).hexdigest())

    def test_tampered_payload_fails(self):
        env = dsse.envelope_for_receipt(RECEIPT, self.key, "approver")
        body = dict(RECEIPT, decision="refused")
        env["payload"] = base64.b64encode(
            jcs_canon(body).encode("utf-8")).decode()
        self.assertFalse(dsse.verify(env, self.signers))

    def test_tampered_type_fails(self):
        env = dsse.envelope_for_receipt(RECEIPT, self.key, "approver")
        env["payloadType"] = "application/json"
        self.assertFalse(dsse.verify(env, self.signers))

    def test_unknown_signer_fails(self):
        env = dsse.envelope_for_receipt(RECEIPT, self.key, "approver")
        env["signatures"][0]["keyid"] = "someone-else"
        self.assertFalse(dsse.verify(env, self.signers))
        self.assertFalse(dsse.verify(env, self.signers, require_keyid="approver"))

    def test_shape_errors_carry_codes(self):
        env = dsse.envelope_for_receipt(RECEIPT, self.key, "approver")
        broken = dict(env, extra=1)
        with self.assertRaises(dsse.DsseError) as ctx:
            dsse.verify(broken, self.signers)
        self.assertEqual(ctx.exception.code, "E_FIELDS")
        with self.assertRaises(dsse.DsseError) as ctx:
            dsse.verify({"payloadType": "t", "payload": "", "signatures": []},
                        self.signers)
        self.assertEqual(ctx.exception.code, "E_NOSIG")
        with self.assertRaises(dsse.DsseError) as ctx:
            dsse.verify({"payloadType": "t", "payload": "!!!", "signatures": []},
                        self.signers)
        self.assertEqual(ctx.exception.code, "E_BASE64")

    def test_sig_entry_fields_are_checked(self):
        env = dsse.envelope_for_receipt(RECEIPT, self.key, "approver")
        env["signatures"][0]["note"] = "hi"
        with self.assertRaises(dsse.DsseError) as ctx:
            dsse.verify(env, self.signers)
        self.assertEqual(ctx.exception.code, "E_FIELDS")


class StrictLoading(unittest.TestCase):
    def test_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "env.json")
            pathlib.Path(path).write_text(
                '{"payloadType": "t", "payload": "", "payload": ""}', encoding="utf-8")
            with self.assertRaises(Exception):
                dsse.load_envelope(path)


class Cli(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.key = os.path.join(d, "k")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(d, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n'
            % pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.receipt = os.path.join(d, "r.json")
        pathlib.Path(self.receipt).write_text(json.dumps(RECEIPT), encoding="utf-8")
        self.env = os.path.join(d, "env.json")

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "mandate", "--signers", self.signers,
                               "dsse", *args], cwd=str(ROOT), capture_output=True, text=True)

    def test_sign_then_verify(self):
        done = self._run("sign", "--receipt", self.receipt, "--key", self.key,
                         "--signer", "approver", "-o", self.env)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = self._run("verify", "--file", self.env)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(json.loads(done.stdout)["ok"])

    def test_tampered_envelope_exits_nonzero(self):
        self._run("sign", "--receipt", self.receipt, "--key", self.key,
                  "--signer", "approver", "-o", self.env)
        data = json.loads(pathlib.Path(self.env).read_text(encoding="utf-8"))
        data["payload"] = base64.b64encode(b"{}").decode()
        pathlib.Path(self.env).write_text(json.dumps(data), encoding="utf-8")
        done = self._run("verify", "--file", self.env)
        self.assertEqual(done.returncode, 1)
        self.assertFalse(json.loads(done.stdout)["ok"])


class StatementGuards(unittest.TestCase):
    def test_only_receipts_become_statements(self):
        with self.assertRaises(dsse.DsseError) as ctx:
            dsse.statement({"type": "control"})
        self.assertEqual(ctx.exception.code, "E_RECEIPT")


if __name__ == "__main__":
    unittest.main()
