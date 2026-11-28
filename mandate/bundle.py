"""A portable bundle: everything a human needs to check one approval offline.

A receipt alone proves a hash exists in a chain. To answer "who approved what", a verifier also
needs the intent, the signed grant and the approver's public key. This packages the four in one
JSON file that `verify.html` (or any independent implementation) can check without our servers.

    mandate export-bundle --intent intent.json --grant grant.json --ledger ledger.jsonl \
        --signers signers --out bundle.json
"""
from __future__ import annotations

import os

from . import core, sign


class BundleError(Exception):
    pass


def _receipt_for(ledger_path: str, nonce: str) -> dict:
    if not os.path.exists(ledger_path):
        raise BundleError("ledger not found: %s" % ledger_path)
    for entry in core.read_ledger(ledger_path):
        body = entry.get("body") or {}
        if body.get("type") == "receipt" and str(body.get("grant_nonce") or "") == nonce:
            return entry
    raise BundleError("no receipt in %s for grant nonce %s" % (ledger_path, nonce))


def export_bundle(intent: dict, grant_obj: dict, ledger_path: str,
                  signers_path: str = "") -> dict:
    grant = (grant_obj or {}).get("grant") or {}
    nonce = str(grant.get("nonce") or "")
    if not nonce:
        raise BundleError("grant has no nonce")
    approver = str(grant.get("approver") or "")
    if not approver:
        raise BundleError("grant has no approver")
    receipt = _receipt_for(ledger_path, nonce)
    public_key = sign.public_key_for(approver, signers_path) if signers_path else ""
    bundle = {
        "format": "mandate-bundle/1",
        "receipt": receipt,
        "intent": core.normalize_intent(intent),
        "grant": grant_obj,
        "public_key": public_key or "",
        "how_to_verify": [
            "Otvorite verify.html, zalijepite ovaj JSON i kliknite 'Provjeri lokalno'.",
            "Ili: mandate verify-receipt --bundle ovaj.json --signers signers",
        ],
    }
    if not public_key:
        bundle["warning"] = ("no public key for %r in %s: a verifier cannot check the signature "
                             "without it" % (approver, signers_path or "no signers file"))
    return bundle
