"""AP2_SIDECAR_V1: reference their authorisation by hash, never pretend to be it.

The tests build a real ES256 JWS (ECDSA P-256) so the verification path is exercised, and they
assert the limits too: an unsigned JWS is reported as unsecured, an unknown curve is refused, and
the sidecar carries a `not_claimed` block that says we are not AP2-compatible.
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

from mandate import ap2, core
from mandate.core import MandateError

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _jws(claims: dict, key=None, header: dict | None = None) -> str:
    head = {"alg": "ES256" if key else "none", "typ": "JWT", "kid": "ap2-test"}
    head.update(header or {})
    first = _b64(json.dumps(head, separators=(",", ":")).encode())
    second = _b64(json.dumps(claims, separators=(",", ":")).encode())
    if key is None:
        return first + "." + second + "."
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    der = key.sign((first + "." + second).encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return first + "." + second + "." + _b64(raw)


CLAIMS = {
    "iss": "https://credential-provider.example",
    "aud": "https://merchant.example",
    "iat": 1795800000,
    "exp": 1795803600,
    "type": "payment-mandate",
    "merchant": {"name": "Example Supplier", "id": "vendor-1"},
    "payment_amount": {"value": 1170.0, "currency": "BAM"},
    "constraints": {"max_amount": 1200.0},
}


class Decode(unittest.TestCase):
    def test_an_unsigned_jws_is_unsecured_not_verified(self):
        token = _jws(CLAIMS)
        out = ap2.decode(token)
        self.assertFalse(out["signature_verified"])
        self.assertIn("unsecured", out["why_unverified"])
        self.assertTrue(out["hash"].startswith("sha256:"))
        self.assertEqual(out["claims"]["iss"], CLAIMS["iss"])

    def test_garbage_is_refused(self):
        with self.assertRaises(MandateError):
            ap2.decode("not-a-jws")
        with self.assertRaises(MandateError):
            ap2.decode("a.b")


class Verify(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def test_es256_verifies_with_the_right_key(self):
        token = _jws(CLAIMS, self.key)
        self.assertTrue(ap2.verify(token, self.pem))

    def test_a_changed_claim_breaks_the_signature(self):
        token = _jws(CLAIMS, self.key)
        first, second, third = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(second + "=="))
        payload["payment_amount"]["value"] = 99999.0
        forged = first + "." + _b64(json.dumps(payload).encode()) + "." + third
        with self.assertRaises(Exception):
            ap2.verify(forged, self.pem)

    def test_a_non_p256_key_is_refused_by_name(self):
        jwk = {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}
        with self.assertRaises(MandateError):
            ap2._pem_key(json.dumps(jwk))


class Mapping(unittest.TestCase):
    def test_the_intent_carries_amount_target_and_the_hash_as_provenance(self):
        decoded = ap2.decode(_jws(CLAIMS))
        intent = ap2.to_intent(decoded, approver="approver")
        self.assertEqual(intent["effect"]["kind"], "payment.send")
        self.assertEqual(intent["effect"]["target"], "Example Supplier")
        self.assertEqual(intent["effect"]["amount"]["value"], 1170.0)
        self.assertEqual(intent["effect"]["amount"]["currency"], "BAM")
        self.assertEqual(intent["provenance"][0]["type"], "data_ref")
        self.assertEqual(intent["provenance"][0]["source"], "ap2:" + decoded["hash"][:0] +
                         decoded["hash"])
        core.normalize_intent(intent)              # must be a legal intent

    def test_unknown_claims_are_not_copied_into_the_intent(self):
        decoded = ap2.decode(_jws({"type": "payment-mandate", "secret_internal": {"x": 1}}))
        intent = ap2.to_intent(decoded)
        self.assertNotIn("secret_internal", json.dumps(intent))


class Sidecar(unittest.TestCase):
    def test_sidecar_binds_a_receipt_to_the_ap2_hash(self):
        with tempfile.TemporaryDirectory() as td:
            key = os.path.join(td, "k")
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key],
                           check=True, capture_output=True)
            signers = os.path.join(td, "signers")
            pathlib.Path(signers).write_text(
                'approver namespaces="mandate" %s\n'
                % pathlib.Path(key + ".pub").read_text().strip(), encoding="utf-8")
            decoded = ap2.decode(_jws(CLAIMS))
            intent = ap2.to_intent(decoded, approver="approver")
            proposal = core.propose(intent)
            grant_core = core.build_grant_core(proposal["commitment"], "approver",
                                               render_hash=proposal["render_hash"],
                                               agent="agent@ap2")
            grant = core.make_grant(grant_core, key)
            ledger = os.path.join(td, "ledger.jsonl")
            receipt = core.redeem(intent, grant, signers, ledger)
            out = ap2.sidecar(decoded, grant, receipt)
            self.assertEqual(out["format"], "mandate-ap2-sidecar/1")
            self.assertEqual(out["ap2"]["hash"], decoded["hash"])
            self.assertEqual(out["mandate"]["commitment"], proposal["commitment"])
            self.assertEqual(out["mandate"]["receipt_hash"], receipt["hash"])
            self.assertFalse(out["ap2"]["signature_verified"])
            joined = " ".join(out["not_claimed"])
            self.assertIn("AP2 compatibility", joined)


class Cli(unittest.TestCase):
    def test_inspect_and_intent(self):
        with tempfile.TemporaryDirectory() as td:
            token = os.path.join(td, "token.jwt")
            pathlib.Path(token).write_text(_jws(CLAIMS), encoding="utf-8")
            done = subprocess.run([sys.executable, "-m", "mandate", "ap2", "inspect",
                                   "--token", token], cwd=str(ROOT),
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertFalse(json.loads(done.stdout)["signature_verified"])
            done = subprocess.run([sys.executable, "-m", "mandate", "ap2", "intent",
                                   "--token", token, "--approver", "approver"],
                                  cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            intent = json.loads(done.stdout)
            self.assertEqual(intent["effect"]["amount"]["value"], 1170.0)


if __name__ == "__main__":
    unittest.main()
