"""Hybrid signatures: Ed25519 (classic) plus ML-DSA-65 (FIPS 204), both required.

Why: an Ed25519 signature collected today can be forged later by a large quantum
computer ("harvest now, decrypt later"). A hybrid signature means an attacker must break
*two* schemes. ML-DSA-65 is the FIPS 204 standard; it comes from `cryptography` and needs
no extra dependency.

Wire format (canonical JSON, then signed as usual):

    {"alg": "ed25519+ml-dsa-65",
     "ed25519": "<SSHSIG block>",
     "ml-dsa-65": {"public_key": "<b64>", "signature": "<b64>"}}

`verify_hybrid` requires both, and never silently downgrades to one.
"""
from __future__ import annotations

import base64

try:                                            # cryptography >= 45
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mldsa
    PQ_AVAILABLE = True
except Exception:                               # pragma: no cover - old install
    mldsa = None
    InvalidSignature = Exception
    PQ_AVAILABLE = False

from . import core, sign

ALG = "ed25519+ml-dsa-65"


class HybridError(core.MandateError):
    pass


def pq_keygen(path: str) -> str:
    """Write a raw ML-DSA-65 private key (0600) and return the public key, base64."""
    if not PQ_AVAILABLE:
        raise HybridError("ML-DSA is not available in this Python environment")
    key = mldsa.MLDSA65PrivateKey.generate()
    raw = key.private_bytes_raw()
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def pq_sign(path: str, message: str) -> dict:
    if not PQ_AVAILABLE:
        raise HybridError("ML-DSA is not available in this Python environment")
    raw = open(path, "rb").read()
    key = mldsa.MLDSA65PrivateKey.from_seed_bytes(raw)
    sig = key.sign(message.encode("utf-8"))
    return {"public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
            "signature": base64.b64encode(sig).decode()}


def pq_verify(public_key_b64: str, signature_b64: str, message: str) -> bool:
    if not PQ_AVAILABLE:
        return False
    try:
        pub = mldsa.MLDSA65PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), message.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_note(message: str, ed_key_path: str, ed_signer: str,
              pq_key_path: str) -> dict:
    return {"alg": ALG,
            "ed25519": sign.sign(message, ed_key_path, "mandate-witness"),
            "ed25519_signer": ed_signer,
            "ml-dsa-65": pq_sign(pq_key_path, message)}


def verify_note(message: str, hybrid: dict, ed_signers_path: str,
                pq_keys: list[str], revoked_path: str | None = None) -> dict:
    """Both halves must verify; `pq_keys` is the list of allowed ML-DSA public keys."""
    result = {"valid": False, "ed25519": False, "ml_dsa": False, "alg": ""}
    if not isinstance(hybrid, dict):
        return result
    result["alg"] = str(hybrid.get("alg") or "")
    if result["alg"] != ALG:
        return result
    result["ed25519"] = bool(sign.verify(message, str(hybrid.get("ed25519_signer") or ""),
                                         str(hybrid.get("ed25519") or ""),
                                         ed_signers_path, "mandate-witness",
                                         revoked_path=revoked_path))
    pq = hybrid.get("ml-dsa-65") or {}
    pub = str(pq.get("public_key") or "")
    result["ml_dsa"] = (pub in set(pq_keys)
                        and pq_verify(pub, str(pq.get("signature") or ""), message))
    result["valid"] = bool(result["ed25519"] and result["ml_dsa"])
    return result
