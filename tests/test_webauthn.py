"""WebAuthn verification, exercised by a software authenticator."""
from __future__ import annotations

import hashlib
import json
import struct
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from mandate import webauthn as wa

RP_ID = "127.0.0.1"
ORIGIN = "http://127.0.0.1:8898"


def cbor(value) -> bytes:
    """Enough CBOR for a test authenticator."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        if n < 256:
            return bytes([major << 5 | 24, n])
        if n < 65536:
            return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(value)


def client_data(kind: str, challenge: str, origin: str = ORIGIN) -> bytes:
    return json.dumps({"type": kind, "challenge": challenge, "origin": origin},
                      separators=(",", ":")).encode()


def cose_p256(key) -> bytes:
    numbers = key.public_key().public_numbers()
    return cbor({1: 2, 3: -7, -1: 1,
                 -2: numbers.x.to_bytes(32, "big"),
                 -3: numbers.y.to_bytes(32, "big")})


def cose_ed25519(pub) -> bytes:
    return cbor({1: 1, 3: -8, -1: 6, -2: pub.public_bytes_raw()})


class SoftwareAuthenticator:
    def __init__(self, kind="p256", sign_count=0, origin=ORIGIN):
        self.kind = kind
        self.origin = origin
        self.sign_count = sign_count
        if kind == "p256":
            self.key = ec.generate_private_key(ec.SECP256R1())
            self.cose = cose_p256(self.key)
        else:
            self.key = ed25519.Ed25519PrivateKey.generate()
            self.cose = cose_ed25519(self.key.public_key())
        self.credential_id = b"\x11" * 16

    def _auth(self, flags: int, attested: bool) -> bytes:
        data = hashlib.sha256(RP_ID.encode()).digest() + bytes([flags])
        data += struct.pack(">I", self.sign_count)
        if attested:
            data += b"\x00" * 16 + struct.pack(">H", len(self.credential_id))
            data += self.credential_id + self.cose
        return data

    def register(self, challenge: str) -> dict:
        flags = 0x41 | 0x04          # attested credential + user verified
        raw = self._auth(flags, attested=True)
        return {"attestation": wa.b64e(cbor({"fmt": "none", "attStmt": {},
                                             "authData": raw})),
                "client_data": wa.b64e(client_data("webauthn.create", challenge,
                                                   self.origin))}

    def assert_(self, challenge: str) -> dict:
        flags = 0x01 | 0x04
        raw = self._auth(flags, attested=False)
        message = raw + hashlib.sha256(client_data("webauthn.get", challenge,
                                                   self.origin)).digest()
        if self.kind == "p256":
            der = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der)
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")   # WebAuthn is raw
        else:
            sig = self.key.sign(message)
        self.sign_count += 1
        return {"auth_data": wa.b64e(raw), "signature": wa.b64e(sig),
                "client_data": wa.b64e(client_data("webauthn.get", challenge,
                                                   self.origin))}


class Registration(unittest.TestCase):
    def test_a_p256_passkey_registers(self) -> None:
        auth = SoftwareAuthenticator("p256")
        out = wa.register(**auth.register("chal-1"), challenge="chal-1",
                          rp_id=RP_ID, origin=ORIGIN)
        self.assertEqual(out["cose"], "ES256")
        self.assertTrue(out["uv"])

    def test_an_ed25519_passkey_registers(self) -> None:
        auth = SoftwareAuthenticator("ed25519")
        out = wa.register(**auth.register("chal-2"), challenge="chal-2",
                          rp_id=RP_ID, origin=ORIGIN)
        self.assertEqual(out["cose"], "EdDSA")

    def test_a_different_challenge_is_refused(self) -> None:
        auth = SoftwareAuthenticator()
        with self.assertRaises(wa.WebAuthnError):
            wa.register(**auth.register("chal-3"), challenge="chal-other",
                        rp_id=RP_ID, origin=ORIGIN)

    def test_a_different_origin_is_refused(self) -> None:
        auth = SoftwareAuthenticator()
        with self.assertRaises(wa.WebAuthnError):
            wa.register(**auth.register("chal-4"), challenge="chal-4",
                        rp_id=RP_ID, origin="https://evil.example")

    def test_another_relying_party_is_refused(self) -> None:
        auth = SoftwareAuthenticator()
        with self.assertRaises(wa.WebAuthnError):
            wa.register(**auth.register("chal-5"), challenge="chal-5",
                        rp_id="bank.example", origin=ORIGIN)

    def test_a_packed_attestation_is_not_accepted(self) -> None:
        auth = SoftwareAuthenticator()
        reg = auth.register("chal-6")
        blob = wa.cbor_decode(wa.b64d(reg["attestation"]))
        blob["fmt"] = "packed"
        with self.assertRaises(wa.WebAuthnError):
            wa.register(wa.b64e(cbor(blob)), reg["client_data"], "chal-6",
                        RP_ID, ORIGIN)


class Assertion(unittest.TestCase):
    def _registered(self, kind="p256"):
        auth = SoftwareAuthenticator(kind)
        credential = wa.register(**auth.register("r"), challenge="r",
                                 rp_id=RP_ID, origin=ORIGIN)
        return auth, credential

    def test_a_valid_assertion_passes_and_moves_the_counter(self) -> None:
        auth, credential = self._registered()
        out = wa.assert_valid(credential, **auth.assert_("a"), challenge="a",
                              rp_id=RP_ID, origin=ORIGIN)
        self.assertEqual(out["sign_count"], 0)
        credential["sign_count"] = out["sign_count"]
        second = wa.assert_valid(credential, **auth.assert_("a1"), challenge="a1",
                                 rp_id=RP_ID, origin=ORIGIN)
        self.assertEqual(second["sign_count"], 1)

    def test_ed25519_assertion_passes(self) -> None:
        auth, credential = self._registered("ed25519")
        wa.assert_valid(credential, **auth.assert_("a2"), challenge="a2",
                        rp_id=RP_ID, origin=ORIGIN)

    def test_the_wrong_challenge_is_refused(self) -> None:
        auth, credential = self._registered()
        with self.assertRaises(wa.WebAuthnError):
            wa.assert_valid(credential, **auth.assert_("b"), challenge="c",
                            rp_id=RP_ID, origin=ORIGIN)

    def test_a_tampered_signature_is_refused(self) -> None:
        auth, credential = self._registered()
        payload = auth.assert_("b2")
        sig = bytearray(wa.b64d(payload["signature"]))
        sig[10] ^= 0xFF
        payload["signature"] = wa.b64e(bytes(sig))
        with self.assertRaises(wa.WebAuthnError):
            wa.assert_valid(credential, **payload, challenge="b2",
                            rp_id=RP_ID, origin=ORIGIN)

    def test_a_cloned_authenticator_is_detected(self) -> None:
        auth, credential = self._registered()
        first = wa.assert_valid(credential, **auth.assert_("c1"), challenge="c1",
                                rp_id=RP_ID, origin=ORIGIN)
        credential["sign_count"] = first["sign_count"] + 5   # the real device is ahead
        with self.assertRaises(wa.WebAuthnError) as caught:
            wa.assert_valid(credential, **auth.assert_("c2"), challenge="c2",
                            rp_id=RP_ID, origin=ORIGIN)
        self.assertIn("counter", str(caught.exception))

    def test_a_zero_counter_is_tolerated(self) -> None:
        auth, credential = self._registered()
        credential["sign_count"] = 0
        auth.sign_count = 0
        wa.assert_valid(credential, **auth.assert_("c3"), challenge="c3",
                        rp_id=RP_ID, origin=ORIGIN)


if __name__ == "__main__":
    unittest.main()
