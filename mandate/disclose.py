"""Selective disclosure: show that a record exists without showing every value.

An auditor often needs "the payment to *some* supplier was 1170 BAM and was
approved", not the supplier's name. Two facts must stay verifiable:

  1. the redacted view is provably a redaction **of that receipt** — its hash
     matches the original, which is what the log anchors;
  2. each hidden value can be revealed later and must match its commitment.

What this does **not** do, stated plainly: the original signer signed the full
values, so a redacted view is not covered by that signature. It binds to the
original receipt hash, and the party producing it should sign the view
(`--key`), so a reader knows *who* chose what to hide. Do not present a redacted
view as "what the approver signed"; present it as "this is what we disclose of
receipt X, and here is our signature".

Commitment: `sha256("salt:" || salt_bytes || ":" || jcs(value))`. The salt keeps a
dictionary attack on a supplier name from working, and travels with the
disclosure (not with the redacted record).
"""
from __future__ import annotations

import base64
import hashlib
import os

from . import strictjson
from .jcs import canonicalize as _canonicalize

CODE = "E_DISCLOSURE"
REDACTED = "__redacted__"


class DisclosureError(ValueError):
    code = CODE

    def __init__(self, message: str, code: str = CODE):
        super().__init__(message)
        self.code = code


def _canon(value) -> bytes:
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return _canonicalize(value).encode("utf-8")
    raise DisclosureError("cannot commit a value of type %s" % type(value).__name__)


def commit(value, salt: bytes | None = None) -> dict:
    """A salted commitment for one value."""
    if salt is None:
        salt = os.urandom(16)
    if not isinstance(salt, (bytes, bytearray)):
        raise DisclosureError("salt must be bytes")
    return {
        "salt": base64.b64encode(bytes(salt)).decode("ascii"),
        "hash": hashlib.sha256(b"salt:" + bytes(salt) + b":" + _canon(value)).hexdigest(),
    }


def verify_commit(value, disclosure: dict) -> bool:
    try:
        salt = base64.b64decode(str(disclosure.get("salt") or "").encode("ascii"),
                                validate=True)
    except Exception:  # noqa: BLE001
        raise DisclosureError("salt is not base64", "E_SALT") from None
    return commit(value, salt)["hash"] == str(disclosure.get("hash") or "")


def _get(body: dict, path: str):
    node = body
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            raise DisclosureError("path not found: %s" % path, "E_PATH")
    return node


def _set(body: dict, path: str, value) -> None:
    parts = path.split(".")
    node = body
    for part in parts[:-1]:
        if isinstance(node, list):
            node = node[int(part)]
        else:
            node = node[part]
    if isinstance(node, list):
        node[int(parts[-1])] = value
    else:
        node[parts[-1]] = value


def receipt_hash(body: dict) -> str:
    return hashlib.sha256(_canonicalize(body).encode("utf-8")).hexdigest()


def redact(body: dict, paths: list[str], expect_hash: str | None = None) -> dict:
    """Return a redacted copy plus the disclosures needed to re-hash it.

    `expect_hash` is the hash of the *full* body; when given, redaction refuses to
    run on anything else, so a view cannot be attached to the wrong record.
    """
    if not isinstance(body, dict):
        raise DisclosureError("body must be an object")
    full_hash = receipt_hash(body)
    if expect_hash and str(expect_hash) != full_hash:
        raise DisclosureError("body does not match the expected hash", "E_HASH")
    out = strictjson.loads_strict(_canonicalize(body))
    disclosures = []
    for path in paths:
        value = _get(out, path)
        if isinstance(value, dict) and REDACTED in value:
            continue
        entry = commit(value)
        _set(out, path, {REDACTED: entry["hash"]})
        disclosures.append({"path": path, "salt": entry["salt"],
                            "hash": entry["hash"],
                            "type": type(value).__name__})
    return {"receipt": out, "disclosures": disclosures,
            "receipt_hash": full_hash, "redacted": [d["path"] for d in disclosures]}


def reveal(view: dict, paths: list[str], values: dict) -> dict:
    """Put disclosed values back and prove the result is the original record."""
    body = strictjson.loads_strict(_canonicalize(view["receipt"]))
    by_path = {d["path"]: d for d in view.get("disclosures") or []}
    for path in paths:
        if path not in by_path:
            raise DisclosureError("no disclosure for %s" % path, "E_NODISCLOSURE")
        if path not in values:
            raise DisclosureError("no value supplied for %s" % path, "E_NOVALUE")
        if not verify_commit(values[path], by_path[path]):
            raise DisclosureError("value for %s does not match its commitment" % path,
                                  "E_COMMITMENT")
        _set(body, path, values[path])
    got = receipt_hash(body)
    if got != str(view.get("receipt_hash") or ""):
        raise DisclosureError("revealed record does not hash to the original", "E_HASH")
    return {"receipt": body, "hash": got, "ok": True}


def check_view(view: dict) -> dict:
    """Structural checks that need no secrets: every redaction has a commitment."""
    body = (view or {}).get("receipt")
    if not isinstance(body, dict):
        raise DisclosureError("view has no receipt", "E_SHAPE")
    disclosures = view.get("disclosures")
    if not isinstance(disclosures, list) or not disclosures:
        raise DisclosureError("view has no disclosures", "E_SHAPE")
    for entry in disclosures:
        if not isinstance(entry, dict) or "path" not in entry or "hash" not in entry:
            raise DisclosureError("malformed disclosure entry", "E_SHAPE")
        found = _get(body, entry["path"])
        if not isinstance(found, dict) or found.get(REDACTED) != entry["hash"]:
            raise DisclosureError("commitment mismatch at %s" % entry["path"], "E_COMMITMENT")
    return {"ok": True, "redacted": [d["path"] for d in disclosures],
            "receipt_hash": str(view.get("receipt_hash") or "")}
