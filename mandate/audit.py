"""Auditor bundle verification: envelope + STH + inclusion + witness pin."""
from __future__ import annotations

from . import core, export
from . import log as mlog


class AuditError(core.MandateError):
    pass


def verify_bundle(bundle: dict, signers_path: str, log_signers_path: str,
                  revoked_path: str | None = None,
                  witness_signers_path: str | None = None,
                  pq_witness_keys: list[str] | None = None) -> dict:
    envelope = export.verify_bundle(bundle, signers_path,
                                    revoked_path=revoked_path)
    receipt = (bundle or {}).get("receipt") or {}
    result = {
        "valid": False,
        "envelope": envelope,
        "sth": False,
        "inclusion": False,
        "witness": False,
        "decision": (receipt.get("body") or {}).get("decision"),
    }
    sth = (bundle or {}).get("sth")
    if not isinstance(sth, dict):
        return result
    payload = sth.get("sth") or {}
    result["sth"] = mlog.verify_sth(sth, log_signers_path,
                                    revoked_path=revoked_path)
    proof = (bundle or {}).get("inclusion_proof")
    if isinstance(proof, dict):
        result["inclusion"] = mlog.verify_inclusion_proof(
            receipt, proof, root=payload.get("root_hash"),
            size=payload.get("tree_size"))
    state = (bundle or {}).get("witness_state")
    note = (bundle or {}).get("witness_note")
    result["witness_signed"] = False
    if isinstance(note, dict) and witness_signers_path:
        from . import witness_note
        checked = witness_note.verify(note, witness_signers_path,
                                      (bundle or {}).get("sth"),
                                      revoked_path=revoked_path,
                                      pq_keys=pq_witness_keys)
        result["witness"] = bool(checked["valid"])
        result["witness_signed"] = bool(checked["note"])
        result["witness_note"] = checked
    elif isinstance(state, dict):
        # a state file only claims the pin; it is not a signature by the witness
        try:
            result["witness"] = (
                str(state.get("root_hash")) == str(payload.get("root_hash"))
                and int(state.get("tree_size")) == int(payload.get("tree_size")))
        except (TypeError, ValueError):
            result["witness"] = False
    result["valid"] = bool(envelope.get("valid") and result["sth"]
                           and result["inclusion"] and result["witness"])
    decision = result.get("decision")
    result["executed"] = bool(result["valid"] and decision == "executed")
    result["observed"] = bool(result["valid"] and decision == "observe")
    return result


def verify_bundle_file(path: str, signers_path: str, log_signers_path: str,
                       revoked_path: str | None = None,
                       witness_signers_path: str | None = None,
                  pq_witness_keys: list[str] | None = None) -> dict:
    return verify_bundle(core.load_json(path), signers_path,
                         log_signers_path, revoked_path=revoked_path,
                         witness_signers_path=witness_signers_path)
