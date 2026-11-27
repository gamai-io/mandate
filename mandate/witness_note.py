"""A witness note the witness host signs, instead of a JSON file that merely claims a pin.

Before this module the bundle carried `witness_state`: a plain JSON file. A verifier could
only check that it *matched* the signed tree head, not that another machine produced it —
so a bundle builder could fabricate one and re-sign the bundle. That limit is stated in
`docs/AUDITOR_BUNDLE.md`; this is the fix.

The note is short canonical text, signed with the witness host's own Ed25519 key through
SSHSIG (the same mechanism as grants and the bundle envelope), so an auditor needs no new
library and no new key format:

    mandate witness note v1
    log: log1
    log_id: abc…
    tree_size: 4
    root_hash: 9f…
    pinned_at: 1795733000000

Verification checks the signature against a witness signers file **and** that the fields
match the STH the bundle carries.
"""
from __future__ import annotations

import time

from . import core, sign

FORMAT = "mandate-witness-note/1"
NAMESPACE = "mandate-witness"


class WitnessNoteError(core.MandateError):
    pass


def text_for(payload: dict, pinned_at: int) -> str:
    try:
        return ("mandate witness note v1\n"
                f"log: {payload['log_name']}\n"
                f"log_id: {payload['log_id']}\n"
                f"tree_size: {int(payload['tree_size'])}\n"
                f"root_hash: {payload['root_hash']}\n"
                f"pinned_at: {int(pinned_at)}\n")
    except (KeyError, TypeError, ValueError) as exc:
        raise WitnessNoteError("STH payload invalid") from exc


def make(sth: dict, key_path: str, signer: str, pinned_at: int | None = None,
         pq_key_path: str | None = None) -> dict:
    payload = (sth or {}).get("sth") or {}
    when = int(pinned_at if pinned_at is not None else time.time() * 1000)
    text = text_for(payload, when)
    note = {"format": FORMAT, "signer": str(signer), "text": text,
            "signature": sign.sign(text, key_path, NAMESPACE)}
    if pq_key_path:
        from . import hybrid
        note["hybrid"] = hybrid.sign_note(text, key_path, str(signer), pq_key_path)
    return note


def parse(text: str) -> dict:
    lines = (text or "").strip("\n").split("\n")
    if not lines or lines[0] != "mandate witness note v1":
        raise WitnessNoteError("unknown note format")
    fields = {}
    for line in lines[1:]:
        if ": " not in line:
            raise WitnessNoteError("malformed note line")
        key, value = line.split(": ", 1)
        fields[key] = value
    for required in ("log", "log_id", "tree_size", "root_hash", "pinned_at"):
        if required not in fields:
            raise WitnessNoteError(f"note missing {required}")
    try:
        fields["tree_size"] = int(fields["tree_size"])
        fields["pinned_at"] = int(fields["pinned_at"])
    except ValueError as exc:
        raise WitnessNoteError("note numbers invalid") from exc
    return fields


def verify(note: dict, signers_path: str, sth: dict,
           revoked_path: str | None = None,
           pq_keys: list[str] | None = None) -> dict:
    """Return {'valid': bool, 'note': bool, 'matches_sth': bool, 'signer': str}."""
    result = {"valid": False, "note": False, "matches_sth": False, "signer": "",
              "hybrid": False, "no_downgrade": True}
    if not isinstance(note, dict) or note.get("format") != FORMAT:
        return result
    text = str(note.get("text") or "")
    result["signer"] = str(note.get("signer") or "")
    try:
        result["note"] = bool(sign.verify(text, result["signer"],
                                          str(note.get("signature") or ""),
                                          signers_path, NAMESPACE,
                                          revoked_path=revoked_path))
        fields = parse(text)
    except (OSError, ValueError, WitnessNoteError):
        return result
    payload = (sth or {}).get("sth") or {}
    if isinstance(note.get("hybrid"), dict):
        # a hybrid note must verify as hybrid: an auditor without the PQ key gets "no",
        # not a silently downgraded Ed25519-only "yes"
        from . import hybrid
        checked = hybrid.verify_note(text, note["hybrid"], signers_path,
                                     list(pq_keys or []), revoked_path=revoked_path)
        result["hybrid"] = bool(checked["valid"])
        result["no_downgrade"] = bool(checked["ed25519"])
        if not checked["valid"]:
            result["valid"] = False
            return result
    result["matches_sth"] = (
        str(fields["log"]) == str(payload.get("log_name"))
        and str(fields["log_id"]) == str(payload.get("log_id"))
        and int(fields["tree_size"]) == int(payload.get("tree_size") or -1)
        and str(fields["root_hash"]) == str(payload.get("root_hash")))
    result["valid"] = bool(result["note"] and result["matches_sth"]
                           and (result["hybrid"] if isinstance(note.get("hybrid"), dict)
                                else True))
    return result
