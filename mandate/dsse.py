"""DSSE envelopes and in-toto statements: let other toolchains read our receipts.

A mandate receipt is useful on its own, but an auditor's pipeline rarely speaks
only our format. Two thin, standard wrappers are enough to plug in without
vendoring anyone's code:

  * **DSSE** (Dead Simple Signing Envelope): `{payloadType, payload, signatures}`
    over the exact pre-authentication encoding from the spec, so the signature is
    verifiable by any DSSE implementation.
  * **in-toto Statement v1**: the receipt becomes a `predicate`, the receipt hash
    becomes the `subject` digest, and `predicateType` names our schema. SLSA and
    Chainloop-style tools consume that shape.

Deliberate limits (stated so nobody assumes more):
  * We sign with the same SSH keys as the rest of mandate; `keyid` carries the
    signer name and the signature bytes are an SSHSIG blob. DSSE treats
    signatures as opaque, so this is conformant — but a verifier that insists on
    raw Ed25519 bytes must call our `sign.verify`, not its own ssh parser.
  * Full SCITT uses COSE/CBOR; that is not implemented here. The in-toto
    statement produced by `statement()` is the thing a SCITT service would wrap.

Nothing here is on the critical path: a receipt still verifies with
`mandate audit verify` if this module is deleted.
"""
from __future__ import annotations

import base64
import hashlib
import json

from . import sign as _sign
from . import strictjson
from .jcs import canonicalize as _canonicalize

RECEIPT_TYPE = "application/vnd.gamai.mandate.receipt.v1+json"
INTOTO_STATEMENT = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://gamai.io/mandate/receipt/v1"
CODE = "E_DSSE"


class DsseError(ValueError):
    """Malformed envelope or bad signature. Carries a machine code."""

    code = CODE

    def __init__(self, message: str, code: str = CODE):
        super().__init__(message)
        self.code = code


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding (the exact bytes that get signed).

    "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload — lengths are the
    decimal ASCII byte counts, so a verifier in another language can rebuild it
    without guessing.
    """
    if not isinstance(payload_type, str) or not payload_type:
        raise DsseError("payloadType must be a non-empty string")
    t = payload_type.encode("utf-8")
    if not isinstance(payload, (bytes, bytearray)):
        raise DsseError("payload must be bytes")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), bytes(payload))


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise DsseError("payload/sig must be base64 strings")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise DsseError("not valid base64: %s" % str(exc)[:60], "E_BASE64") from exc


def envelope(payload_type: str, payload: bytes, key_path: str, signer: str,
             namespace: str = _sign.DEFAULT_NAMESPACE) -> dict:
    """Sign `payload` and return a DSSE envelope (dict, ready for JSON)."""
    pre = pae(payload_type, payload)
    signature = _sign.sign(pre.decode("utf-8", "surrogateescape"), key_path, namespace)
    return {
        "payloadType": payload_type,
        "payload": _b64e(payload),
        "signatures": [{"keyid": str(signer), "sig": _b64e(signature.encode("utf-8"))}],
    }


def verify(env: dict, signers_path: str,
           namespace: str = _sign.DEFAULT_NAMESPACE,
           revoked_path: str | None = None,
           require_keyid: str | None = None) -> bool:
    """Verify every signature over the PAE. Unknown extra fields are rejected."""
    if not isinstance(env, dict):
        raise DsseError("envelope must be an object")
    extra = set(env) - {"payloadType", "payload", "signatures"}
    if extra:
        raise DsseError("unknown envelope fields: %s" % sorted(extra), "E_FIELDS")
    payload_type = env.get("payloadType")
    payload = _b64d(env.get("payload"))
    sigs = env.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise DsseError("envelope has no signatures", "E_NOSIG")
    pre = pae(payload_type, payload).decode("utf-8", "surrogateescape")
    ok = False
    for entry in sigs:
        if not isinstance(entry, dict):
            raise DsseError("signatures must be objects")
        extra_sig = set(entry) - {"keyid", "sig"}
        if extra_sig:
            raise DsseError("unknown signature fields: %s" % sorted(extra_sig), "E_FIELDS")
        keyid = str(entry.get("keyid") or "")
        if require_keyid and keyid != require_keyid:
            continue
        try:
            name = _sign.verify(pre, keyid, _b64d(entry.get("sig")).decode("utf-8"),
                                signers_path, namespace, revoked_path=revoked_path)
        except Exception:  # noqa: BLE001
            name = False
        ok = ok or bool(name)
    return ok


def load_envelope(path: str) -> dict:
    """Read an envelope with the strict parser (no duplicate keys, no NaN)."""
    return strictjson.load_strict(path)


def statement(receipt_body: dict) -> dict:
    """Wrap a receipt body as an in-toto Statement v1."""
    if not isinstance(receipt_body, dict) or receipt_body.get("type") != "receipt":
        raise DsseError("statement() needs a receipt body", "E_RECEIPT")
    digest = hashlib.sha256(_canonicalize(receipt_body).encode("utf-8")).hexdigest()
    return {
        "_type": INTOTO_STATEMENT,
        "subject": [{"name": "mandate-receipt:%s" % (receipt_body.get("proposal_id") or ""),
                     "digest": {"sha256": digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": receipt_body,
    }


def envelope_for_receipt(receipt_body: dict, key_path: str, signer: str,
                         namespace: str = _sign.DEFAULT_NAMESPACE,
                         as_statement: bool = False) -> dict:
    """DSSE envelope over a receipt (or over its in-toto statement)."""
    payload_obj = statement(receipt_body) if as_statement else receipt_body
    payload = _canonicalize(payload_obj).encode("utf-8")
    payload_type = ("application/vnd.in-toto+json" if as_statement else RECEIPT_TYPE)
    return envelope(payload_type, payload, key_path, signer, namespace)


def payload_json(env: dict):
    """Decode the payload back to JSON (strict)."""
    return strictjson.loads_strict(_b64d(env.get("payload")).decode("utf-8"))
