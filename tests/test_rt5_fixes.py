"""Regressions from RT5: offline verifier options, bundle STH, claims rows."""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from mandate import core, export, sign

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec" / "vectors"


def offline(*args):
    return subprocess.run([sys.executable, str(ROOT / "spec" / "verify_offline.py"),
                           *args], capture_output=True, text=True)


class OfflineVerifierOptions(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)
        for name in ("grant.json", "intent.json", "receipt.json",
                     "allowed_signers"):
            shutil.copy(VECTORS / name, self.dir / name)
        self.signers = self.dir / "allowed_signers"

    def tearDown(self):
        self.td.cleanup()

    def run_base(self, *extra):
        return offline("--grant", str(self.dir / "grant.json"),
                       "--intent", str(self.dir / "intent.json"),
                       "--signers", str(self.signers),
                       "--receipt", str(self.dir / "receipt.json"), *extra)

    def test_the_baseline_vector_still_verifies(self):
        done = self.run_base()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(json.loads(done.stdout)["ok"])

    def test_a_namespace_restricted_line_does_not_authorise(self):
        lines = self.signers.read_text(encoding="utf-8").splitlines()
        lines = [line.replace('namespaces="mandate"', 'namespaces="other"')
                 for line in lines]
        self.signers.write_text("\n".join(lines) + "\n", encoding="utf-8")
        done = self.run_base()
        self.assertEqual(done.returncode, 1)
        self.assertFalse(json.loads(done.stdout)["ok"])

    def test_a_revoked_key_does_not_authorise(self):
        lines = [line for line in
                 self.signers.read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.startswith("#")]
        tokens = lines[0].split()
        key_index = next(i for i, t in enumerate(tokens)
                         if t.startswith(("ssh-", "sk-", "ecdsa-")))
        blob = tokens[key_index + 1]
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(blob + "=" * (-len(blob) % 4))).digest()
        ).decode().rstrip("=")
        revoked = self.dir / "revoked"
        revoked.write_text(fingerprint.replace("SHA256:", "").lower() + "\n",
                           encoding="utf-8")
        done = self.run_base("--revoked", str(revoked))
        self.assertEqual(done.returncode, 1)
        self.assertFalse(json.loads(done.stdout)["ok"])


class BundleUsesSignedHead(unittest.TestCase):
    def test_inclusion_is_checked_against_the_sth_root_not_the_proof(self):
        receipt = {"body": {}, "hash": "x"}
        bundle = {"receipt": receipt, "intent": {}, "grant": {},
                  "signature": {"alg": "ssh-ed25519", "signer": "approver",
                                "value": "sig"},
                  "inclusion_proof": {"root_hash": "aa", "leaf_hash": "bb"},
                  "sth": {"sth": {"root_hash": "cc", "tree_size": 7}}}
        seen = {}

        def fake_proof(entry, proof, root=None, size=None):
            seen["root"], seen["size"] = root, size
            return True

        with mock.patch.object(export.sign, "verify", return_value=True), \
                mock.patch.object(export.core, "verify_receipt", return_value=True), \
                mock.patch.object(export.mlog, "verify_inclusion_proof",
                                  side_effect=fake_proof):
            result = export.verify_bundle(bundle, "signers")
        self.assertTrue(result["valid"])
        self.assertEqual(seen, {"root": "cc", "size": 7},
                         "the proof was checked against its own root")

    def test_a_proof_without_a_signed_head_is_refused(self):
        bundle = {"receipt": {}, "intent": {}, "grant": {},
                  "signature": {"alg": "ssh-ed25519", "signer": "a", "value": "s"},
                  "inclusion_proof": {"root_hash": "aa"}}
        with mock.patch.object(export.sign, "verify", return_value=True), \
                mock.patch.object(export.core, "verify_receipt", return_value=True):
            result = export.verify_bundle(bundle, "signers")
        self.assertFalse(result["valid"])
        self.assertFalse(result["inclusion"])


class SignerLineOptions(unittest.TestCase):
    def test_a_comment_cannot_grant_a_namespace(self):
        line = ('approver # namespaces="mandate" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5'
                'AAAAIGZha2U= fake@example\n')
        entry = sign._parse_line(line)
        self.assertEqual(entry["namespaces"], [])

    def test_revoked_fingerprints_are_normalised(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "revoked"
            path.write_text("SHA256:AbCd\n", encoding="utf-8")
            self.assertEqual(sign.load_revoked(str(path)), {"abcd"})


class HardwareKeyUsesTheSigningLine(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)
        self.keys = {}
        for name in ("revoked", "signer"):
            path = self.dir / name
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(path)], check=True)
            self.keys[name] = path
        self.signers = self.dir / "signers"
        revoked_blob = (self.dir / "revoked.pub").read_text(
            encoding="utf-8").split()[1]
        signer_line = "approver namespaces=\"mandate\" %s\n" % (
            self.dir / "signer.pub").read_text(encoding="utf-8").strip()
        self.signers.write_text(
            'approver namespaces="mandate" sk-ssh-ed25519@openssh.com %s\n%s'
            % (revoked_blob, signer_line), encoding="utf-8")
        self.revoked = self.dir / "revoked.txt"
        self.revoked.write_text(sign.fingerprint(revoked_blob) + "\n",
                                encoding="utf-8")
        self.intent = {"v": 1, "actor": {"agent": "agent@example"},
                       "effect": {"kind": "payment.send", "target": "X",
                                  "amount": {"value": 1.0, "currency": "BAM"}},
                       "requested_by": "ops", "nonce": "n-1",
                       "provenance": [{"type": "data_ref", "source": "erp:x"}]}

    def tearDown(self):
        self.td.cleanup()

    def test_a_revoked_sk_line_does_not_satisfy_the_hardware_policy(self):
        policy = core.load_policy()
        policy["effects"]["payment.send"] = dict(
            policy["effects"]["payment.send"], require_hardware_key=True)
        proposal = core.propose(self.intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=600,
            render_hash=proposal["render_hash"], agent="agent@example",
            policy_fingerprint=core.policy_digest(policy))
        grant = core.make_grant(grant_core, str(self.keys["signer"]))
        with self.assertRaises(core.HardwareKeyRequired):
            core.verify_authorization(self.intent, grant, str(self.signers),
                                      policy=policy, revoked_path=str(self.revoked))


if __name__ == "__main__":
    unittest.main()
