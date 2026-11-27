"""Witness quorum: two independent hosts agreeing beats one host saying "I saw it".

A witness note is signed by one host. That is already stronger than a JSON state
file, but it still leaves one machine — and one operator — as the single point
that decides what the log contained. A quorum fixes that: the bundle must carry
notes from **N distinct witnesses**, all attesting the **same** tree head.

Two failures matter and are reported separately:

  E_QUORUM      fewer than N distinct valid witnesses
  E_SPLIT_VIEW  valid notes for *different* root hashes or tree sizes — someone is
                running two logs, or a note was replayed from another tree

Distinct means distinct signer name **after** signature verification; the same key
listed twice counts once, and a revoked signer does not count at all.
"""
from __future__ import annotations

from . import witness_note

CODE = "E_QUORUM"
SPLIT = "E_SPLIT_VIEW"


def _identity(fields: dict) -> tuple:
    return (str(fields.get("log_id") or ""), int(fields.get("tree_size") or 0),
            str(fields.get("root_hash") or ""))


def evaluate(notes: list[dict], sth: dict, signers_path: str, min_witnesses: int = 2,
             revoked_path: str | None = None,
             pq_keys: list[str] | None = None) -> dict:
    """Count distinct witnesses whose note verifies against `sth`."""
    required = int(min_witnesses)
    if required < 1:
        raise ValueError("min_witnesses must be at least 1")
    seen: dict[str, dict] = {}
    rejected: list[dict] = []
    for note in notes or []:
        if not isinstance(note, dict):
            rejected.append({"reason": "not a note"})
            continue
        checked = witness_note.verify(note, signers_path, sth,
                                      revoked_path=revoked_path, pq_keys=pq_keys)
        signer = str(checked.get("signer") or "")
        if not checked.get("valid"):
            rejected.append({"signer": signer,
                             "reason": "signature" if not checked.get("note") else "sth_mismatch"})
            continue
        if not signer:
            rejected.append({"reason": "no signer"})
            continue
        # one key, one vote
        seen.setdefault(signer, {"signer": signer, "hybrid": bool(checked.get("hybrid"))})
    witnesses = sorted(seen)
    ok = len(witnesses) >= required
    out = {
        "ok": ok,
        "count": len(witnesses),
        "required": required,
        "witnesses": witnesses,
        "rejected": rejected,
    }
    if not ok:
        out["code"] = CODE
        out["message"] = ("%d of %d required witnesses attested this tree head"
                          % (len(witnesses), required))
    return out


def split_view(notes: list[dict], signers_path: str,
               revoked_path: str | None = None,
               pq_keys: list[str] | None = None, sth: dict | None = None) -> dict:
    """Detect valid notes that point at different trees.

    Signatures are checked against a dummy STH so only the signature and the note
    fields are trusted here; the grouping is what matters.
    """
    groups: dict[tuple, list[str]] = {}
    for note in notes or []:
        if not isinstance(note, dict):
            continue
        checked = witness_note.verify(note, signers_path, sth or {}, revoked_path=revoked_path,
                                      pq_keys=pq_keys)
        if not checked.get("note"):
            continue
        try:
            fields = witness_note.parse(str(note.get("text") or ""))
        except Exception:  # noqa: BLE001
            continue
        groups.setdefault(_identity(fields), []).append(str(checked.get("signer") or ""))
    if len(groups) <= 1:
        return {"split": False, "trees": len(groups),
                "groups": [{"tree_size": k[1], "root_hash": k[2], "witnesses": sorted(set(v))}
                           for k, v in groups.items()]}
    return {"split": True, "code": SPLIT, "trees": len(groups),
            "groups": [{"tree_size": k[1], "root_hash": k[2], "witnesses": sorted(set(v))}
                       for k, v in groups.items()]}
