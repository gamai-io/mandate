"""AP2 / Verifiable Intent sidecar: point at their authorisation, do not pretend to be it.

AP2 signs a *mandate* (checkout or payment) as an SD-JWT VC and the network/processor issues a
receipt. Mastercard's Verifiable Intent is a signed record of what the user asked for. Those are
authorisation objects for the payment rail; they are not an evidence chain a bank's auditor can
keep, and they are not ours.

What we add is the second half: a specific human's Ed25519 grant over the exact effect, kept in a
hash chain that a third party verifies offline. The sidecar makes the link explicit and one-way —
our receipt commits to the AP2 mandate's hash, so their record can be cited from ours, and ours
from theirs.

Deliberate limits, stated here because a supplier will otherwise assume more:

  * we do not verify the AP2 signature unless `cryptography` is installed and a key is supplied;
    without that we report `signature_verified: false` and the hash only;
  * we never call an AP2 mandate "our mandate" and never claim AP2 compatibility;
  * ES256 only — AP2 uses ECDSA P-256, so anything else is reported as unsupported, not guessed.
"""
from __future__ import annotations

import base64
import hashlib
import json

from .core import MandateError


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def decode(token: str) -> dict:
    """Parse a compact JWS without trusting it: header, claims, and the hash of the raw bytes."""
    raw = str(token or "").strip()
    parts = raw.split(".")
    if len(parts) not in (2, 3):
        raise MandateError("not a compact JWS: expected 2 or 3 dot-separated parts")
    try:
        header = json.loads(_b64url(parts[0]).decode("utf-8"))
        claims = json.loads(_b64url(parts[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise MandateError("not a JWS: %s" % str(exc)[:120]) from exc
    return {
        "format": "mandate-ap2/1",
        "alg": str(header.get("alg") or ""),
        "kid": str(header.get("kid") or ""),
        "typ": str(header.get("typ") or ""),
        "claims": claims,
        "hash": "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "signature_verified": False,
        "signature_present": bool(len(parts) == 3 and parts[2].strip()),
        "why_unverified": ("no key supplied; the AP2 artefact is referenced by hash only"
                           if (len(parts) == 3 and parts[2].strip())
                           else "unsecured JWS: there is no signature to verify"),
    }


def _pem_key(jwk_or_pem: str) -> object:
    """Accept a PEM public key or a JWK (EC) and return a cryptography key object."""
    from cryptography.hazmat.primitives import serialization
    text = str(jwk_or_pem or "").strip()
    if text.startswith("-----BEGIN"):
        return serialization.load_pem_public_key(text.encode("utf-8"))
    try:
        jwk = json.loads(text)
    except ValueError as exc:
        raise MandateError("key is neither PEM nor JSON JWK") from exc
    if str(jwk.get("kty")) != "EC" or str(jwk.get("crv")) != "P-256":
        raise MandateError("only EC P-256 (ES256) keys are supported")
    from cryptography.hazmat.primitives.asymmetric import ec
    x = int.from_bytes(_b64url(str(jwk.get("x"))), "big")
    y = int.from_bytes(_b64url(str(jwk.get("y"))), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify(token: str, key_text: str) -> bool:
    """Verify an ES256 signature. Optional dependency: cryptography."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError as exc:                       # pragma: no cover - env dependent
        raise MandateError("verifying AP2 signatures needs the optional 'cryptography' package") \
            from exc
    parts = str(token or "").strip().split(".")
    if len(parts) != 3:
        raise MandateError("unsigned JWS: nothing to verify")
    header = json.loads(_b64url(parts[0]).decode("utf-8"))
    if str(header.get("alg")) != "ES256":
        raise MandateError("only ES256 is supported, got %r" % header.get("alg"))
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    der = _b64url(parts[2])
    if len(der) == 64:                               # raw r||s, the JWS form
        half = 32
        r = int.from_bytes(der[:half], "big")
        s = int.from_bytes(der[half:], "big")
        der = encode_dss_signature(r, s)
    key = _pem_key(key_text)
    key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    return True


def _first(claims: dict, *names: str):
    for name in names:
        value = claims.get(name)
        if value not in (None, "", {}, []):
            return value
    return None


def _amount(claims: dict) -> dict | None:
    for candidate in ("payment_amount", "amount", "total", "transaction_amount"):
        value = claims.get(candidate)
        if isinstance(value, dict):
            number = _first(value, "value", "amount", "total")
            currency = _first(value, "currency", "currency_code")
        elif isinstance(value, (int, float)):
            number, currency = value, _first(claims, "currency", "currency_code")
        else:
            continue
        if number is None:
            continue
        try:
            number = float(number)
        except (TypeError, ValueError):
            continue
        return {"value": number, "currency": str(currency or "EUR")}
    constraints = claims.get("constraints")
    if isinstance(constraints, dict):
        return _amount(constraints)
    return None


def to_intent(decoded: dict, approver: str = "", agent: str = "agent@ap2",
              kind: str = "payment.send") -> dict:
    """Map the parts a bank actually cares about into our intent, keeping the hash as provenance.

    Unknown claims are not copied into the intent: an intent is a narrow, signed object, and
    carrying an unbounded third-party payload inside it would make the approval unreadable.
    """
    claims = decoded.get("claims") or {}
    effect: dict = {"kind": kind, "params": {"ap2_hash": decoded.get("hash", "")}}
    target = _first(claims, "merchant", "payee", "merchant_name", "aud", "audience")
    if isinstance(target, dict):
        target = _first(target, "name", "id", "domain")
    if target is not None:
        effect["target"] = str(target)
    amount = _amount(claims)
    if amount:
        effect["amount"] = amount
    issuer = _first(claims, "iss", "issuer")
    effect["params"]["ap2_issuer"] = str(issuer or "")
    intent = {
        "v": 1,
        "actor": {"agent": agent, "session": "ap2"},
        "nonce": "ap2-" + str(decoded.get("hash", "")).replace("sha256:", "")[:16],
        "effect": effect,
        "requested_by": approver or "operator",
        "provenance": [{"type": "data_ref", "source": "ap2:" + str(decoded.get("hash", ""))}],
    }
    return intent


def sidecar(decoded: dict, grant_obj: dict, receipt_entry: dict | None = None) -> dict:
    """The one-way link: our signed grant/receipt commits to the AP2 mandate's hash."""
    grant = (grant_obj or {}).get("grant") or {}
    body = (receipt_entry or {}).get("body") or {}
    return {
        "format": "mandate-ap2-sidecar/1",
        "ap2": {
            "hash": decoded.get("hash", ""),
            "alg": decoded.get("alg", ""),
            "kid": decoded.get("kid", ""),
            "signature_verified": bool(decoded.get("signature_verified")),
            "claims": {k: decoded.get("claims", {}).get(k) for k in
                       ("iss", "aud", "sub", "iat", "exp", "type") if
                       decoded.get("claims", {}).get(k) is not None},
        },
        "mandate": {
            "commitment": grant.get("commitment", ""),
            "approver": grant.get("approver", ""),
            "grant_nonce": grant.get("nonce", ""),
            "receipt_hash": receipt_entry.get("hash", "") if receipt_entry else "",
            "approver_signed_effect": body.get("render_hash", grant.get("render_hash", "")),
        },
        "meaning": ("AP2 authorises the rail; this binds that authorisation to one named human's "
                    "signature over the exact effect. Verify the mandate receipt offline with "
                    "mandate verify-receipt or verify.html; verify the AP2 signature with the "
                    "credential provider's key."),
        "not_claimed": [
            "AP2 compatibility of our record format",
            "verification of the AP2 signature unless signature_verified is true",
            "that the AP2 mandate is valid on any rail",
        ],
    }
