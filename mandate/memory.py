"""Signed provenance for instructions an agent keeps.

You cannot stop a model from believing something — the 2026 incidents show a
planted instruction surviving weeks and being defended when questioned. What you
can do is refuse to let a *belief* authorise an effect unless a named human signed
that instruction, for a scope, with an expiry.

So an instruction is a record: text, scope (which effect kinds and targets it may
influence), the human who accepted it, and a signature over the whole thing. An
intent may cite an instruction in its provenance; the broker checks that the
citation is signed, unexpired and in scope before the grant is spent.

  mandate memory add --text "pay Acme invoices under 5000" \
      --scope payment.send:Acme --approver alice --key ~/.ssh/alice --ttl 30d
  mandate memory list
  mandate memory verify --id m-1
"""
from __future__ import annotations

import json
import os
import secrets
import time

from . import core, sign


class MemoryError(core.MandateError):
    pass


def _path_list(path: str) -> list[dict]:
    if not path or not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError as exc:
            raise MemoryError("instruction store is corrupt: %s" % exc) from exc
    return out


def _append(path: str, body: dict) -> dict:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    core.append_receipt(path, body)          # the same hash chain as receipts
    return body


def _payload(record: dict) -> dict:
    return {k: record.get(k) for k in
            ("id", "text", "scope", "created_by", "approver", "created",
             "expires", "revoked")}


def add(path: str, text: str, scope: list[str], approver: str, key_path: str,
        ttl_s: int = 30 * 86400, created_by: str = "agent") -> dict:
    text = str(text or "").strip()
    if not text:
        raise MemoryError("instruction text is required")
    if not approver or not key_path:
        raise MemoryError("an instruction needs --approver and --key: a belief "
                          "without a signature is what the incidents exploit")
    scope = [str(item) for item in (scope or [])]
    if not scope:
        raise MemoryError("an instruction needs a scope, e.g. payment.send:Acme")
    now = int(time.time())
    record = {"v": 1, "type": "instruction", "id": "m-" + secrets.token_hex(5),
              "text": text, "scope": scope, "created_by": str(created_by),
              "approver": str(approver), "created": now,
              "expires": now + max(60, int(ttl_s)), "revoked": False}
    record["sig"] = sign.sign(core.jcs(_payload(record)), key_path)
    _append(path, record)
    return record


def load(path: str) -> list[dict]:
    return [r for r in _path_list(path)
            if r.get("body", {}).get("type") == "instruction"
            for r in [r["body"]]]


def get(path: str, instruction_id: str) -> dict | None:
    found = None
    for record in load(path):
        if record.get("id") == instruction_id:
            found = record          # the last write wins: revoke appends a new one
    return found


def revoke(path: str, instruction_id: str, reason: str = "") -> dict:
    record = get(path, instruction_id)
    if record is None:
        raise MemoryError("no such instruction: %s" % instruction_id)
    body = {k: record.get(k) for k in ("id", "text", "scope", "created_by",
                                       "approver", "created", "expires")}
    body.update({"v": 1, "type": "instruction", "revoked": True,
                 "reason": reason, "revoked_at": int(time.time())})
    _append(path, body)
    return body


def verify(record: dict, signers_path: str, now: float | None = None) -> bool:
    moment = time.time() if now is None else float(now)
    if not record or record.get("revoked"):
        return False
    if int(record.get("expires") or 0) <= moment:
        return False
    signature = str(record.get("sig") or "")
    approver = str(record.get("approver") or "")
    if not signature or not approver:
        return False
    return sign.verify(core.jcs(_payload(record)), approver, signature,
                       signers_path, "mandate")


def scope_covers(scope: list[str], kind: str, target: str) -> bool:
    for item in scope or []:
        entry = str(item)
        if entry == "*" or entry == "*:*":
            return True
        if ":" not in entry:
            if entry == str(kind):
                return True
            continue
        scope_kind, _, scope_target = entry.partition(":")
        if scope_kind not in ("*", str(kind)):
            continue
        if scope_target in ("*", str(target)):
            return True
    return False


def check_provenance(intent: dict, store_path: str, signers_path: str,
                     now: float | None = None) -> list[str]:
    """Refuse an intent that leans on an instruction nobody signed correctly."""
    cited = [p for p in (intent.get("provenance") or [])
             if isinstance(p, dict) and p.get("type") == "instruction"]
    if not cited:
        return []
    effect = intent.get("effect") or {}
    kind, target = str(effect.get("kind") or ""), str(effect.get("target") or "")
    checked = []
    for entry in cited:
        instruction_id = str(entry.get("source") or "")
        record = get(store_path, instruction_id)
        if record is None:
            raise MemoryError("instruction %r is cited but not in the store"
                              % instruction_id)
        if not verify(record, signers_path, now):
            raise MemoryError("instruction %r is unsigned, revoked or expired"
                              % instruction_id)
        if not scope_covers(record.get("scope") or [], kind, target):
            raise MemoryError("instruction %r does not cover %s:%s"
                              % (instruction_id, kind, target))
        checked.append(instruction_id)
    return checked
