"""Portable receipt envelope (JOSE-style, OpenSSH signature).

This is a custom profile, not strict JWS/C2PA: the signature is an OpenSSH
SSHSIG (`ssh-keygen -Y sign`) in namespace `mandate-export`, so verifiers use
OpenSSH tooling. The envelope carries the intent, the signed grant, the
hash-chained receipt, and an optional Merkle inclusion proof.
"""
from __future__ import annotations

from . import core, sign
from . import log as mlog

EXPORT_NAMESPACE = "mandate-export"
FORMAT = "mandate-receipt/1"


def _key_id(key_path: str) -> str:
    path = str(key_path) + ".pub"
    try:
        with open(path, encoding="utf-8") as fh:
            tokens = fh.read().split()
    except OSError:
        return ""
    for idx, token in enumerate(tokens):
        if token.startswith(("ssh-", "ecdsa-", "sk-")) and idx + 1 < len(tokens):
            return sign.fingerprint(tokens[idx + 1])
    return ""


def build_bundle(receipt_entry: dict, intent: dict, grant_obj: dict,
                 proof: dict | None = None, key_path: str | None = None,
                 signer: str | None = None, sth: dict | None = None,
                 witness_state: dict | None = None) -> dict:
    body = {
        "v": 1,
        "format": FORMAT,
        "receipt": receipt_entry,
        "intent": intent,
        "grant": grant_obj,
    }
    if proof:
        body["inclusion_proof"] = proof
    if sth:
        body["sth"] = sth
    if witness_state:
        body["witness_state"] = witness_state
    signature = {"alg": "ssh-ed25519", "namespace": EXPORT_NAMESPACE,
                 "key_id": _key_id(key_path) if key_path else "",
                 "signer": str(signer or (grant_obj or {}).get("grant", {})
                               .get("approver") or ""),
                 "value": ""}
    if key_path:
        signature["value"] = sign.sign(core.jcs(body), key_path,
                                       EXPORT_NAMESPACE)
    bundle = dict(body)
    bundle["signature"] = signature
    return bundle


def verify_bundle(bundle: dict, signers_path: str,
                  revoked_path: str | None = None) -> dict:
    result = {"valid": False, "signature": False, "receipt": False,
              "inclusion": None}
    signature = (bundle or {}).get("signature") or {}
    if signature.get("alg") != "ssh-ed25519":
        return result
    body = {key: value for key, value in bundle.items() if key != "signature"}
    try:
        result["signature"] = sign.verify(
            core.jcs(body), str(signature.get("signer") or ""),
            str(signature.get("value") or ""), signers_path, EXPORT_NAMESPACE,
            revoked_path=revoked_path)
    except (OSError, ValueError):
        result["signature"] = False
    if not result["signature"]:
        return result
    receipt = bundle.get("receipt") or {}
    intent = bundle.get("intent") or {}
    grant = bundle.get("grant") or {}
    try:
        result["receipt"] = core.verify_receipt(
            receipt, intent, grant, signers_path, revoked_path=revoked_path)
    except (core.MandateError, OSError, ValueError):
        result["receipt"] = False
    proof = bundle.get("inclusion_proof")
    if isinstance(proof, dict):
        result["inclusion"] = mlog.verify_inclusion_proof(receipt, proof)
    result["valid"] = bool(result["signature"] and result["receipt"]
                           and (result["inclusion"] is not False))
    return result


def verify_bundle_file(path: str, signers_path: str,
                       revoked_path: str | None = None) -> dict:
    return verify_bundle(core.load_json(path), signers_path,
                         revoked_path=revoked_path)


def key_id_for(key_path: str) -> str:
    return _key_id(key_path)


__all__ = ["EXPORT_NAMESPACE", "FORMAT", "build_bundle", "verify_bundle",
           "verify_bundle_file", "key_id_for"]
