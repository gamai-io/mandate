"""Containment that expires unless a human extends it.

A defence that can only act permanently is a defence nobody lets act. So a
containment here carries a deadline: when it passes, a sweep releases the process
and records that it did. Extending is a human act with its own signature, because
"keep this stopped" is a decision, not a timeout.

Safe direction: if the sweep never runs, the process stays stopped. Nothing is
released by accident.
"""
from __future__ import annotations

import time

from . import core, sign, warden

CONTROL = "containment"


def contain(pid: int | None = None, uid: int | None = None, minutes: int = 15,
            ledger_path: str = "ledger.jsonl", reason: str = "",
            actor: str = "ops", by_pgid: bool = False) -> dict:
    """Stop now, with a deadline. Returns the record that was written."""
    minutes = max(1, min(int(minutes), 24 * 60))
    target = int(pid) if pid is not None else _pid_for_uid(uid)
    stopped = warden.stop(target, by_pgid=by_pgid, ledger_path=ledger_path,
                          reason=reason or "containment", actor=actor)
    until = int(time.time()) + minutes * 60
    record = {"v": 1, "type": CONTROL, "action": "contain", "pid": target,
              "by_pgid": bool(by_pgid), "until": until, "minutes": minutes,
              "reason": reason, "actor": actor, "ts": int(time.time()),
              "stop": stopped}
    core.append_receipt(ledger_path, record)
    return record


def _pid_for_uid(uid: int | None) -> int:
    if uid is None:
        raise ValueError("pid or uid is required")
    raise ValueError("uid containment is not implemented in this version; pass --pid")


def extend(ledger_path: str, pid: int, minutes: int = 15, approver: str = "",
           key_path: str = "", reason: str = "extended") -> dict:
    """A human decides to keep it stopped. The decision is signed."""
    if not approver or not key_path:
        raise core.MandateError("extending containment needs --approver and --key")
    minutes = max(1, min(int(minutes), 24 * 60))
    until = int(time.time()) + minutes * 60
    decision = {"pid": int(pid), "until": until, "minutes": minutes,
                "reason": reason, "approver": approver,
                "decided_at": int(time.time())}
    signature = sign.sign(core.jcs(decision), key_path)
    body = {"v": 1, "type": CONTROL, "action": "extend", "pid": int(pid),
            "until": until, "minutes": minutes, "reason": reason,
            "approver": approver, "ts": decision["decided_at"],
            "decision": decision, "sig": signature}
    entry = core.append_receipt(ledger_path, body)
    return {"ok": True, "pid": int(pid), "until": until, "signed": True,
            "entry": entry}


def verify_extend(entry: dict, signers_path: str, namespace: str = "mandate") -> bool:
    body = (entry or {}).get("body") or {}
    decision = body.get("decision") or {}
    signature = str(body.get("sig") or "")
    approver = str(decision.get("approver") or "")
    if not decision or not signature or not approver:
        return False
    return sign.verify(core.jcs(decision), approver, signature, signers_path,
                       namespace)


def release(ledger_path: str, pid: int, approver: str, key_path: str,
            reason: str = "released by a human") -> dict:
    """End containment early. This is a decision, so it is signed."""
    if not approver or not key_path:
        raise core.MandateError("releasing early needs --approver and --key")
    decision = {"pid": int(pid), "action": "release", "approver": approver,
                "reason": reason, "decided_at": int(time.time())}
    signature = sign.sign(core.jcs(decision), key_path)
    entry = core.append_receipt(ledger_path, {
        "v": 1, "type": CONTROL, "action": "release", "pid": int(pid),
        "reason": reason, "actor": approver, "ts": decision["decided_at"],
        "decision": decision, "sig": signature})
    return {"ok": True, "pid": int(pid), "entry": entry}


def verify_release(entry: dict, signers_path: str) -> bool:
    body = (entry or {}).get("body") or {}
    decision = body.get("decision") or {}
    if body.get("action") != "release" or not decision:
        return False
    return sign.verify(core.jcs(decision), str(decision.get("approver") or ""),
                       str(body.get("sig") or ""), signers_path, "mandate")


def sweep(ledger_path: str, now: float | None = None,
          signers_path: str = "") -> dict:
    """Release everything whose deadline passed, and record that it was released."""
    moment = time.time() if now is None else float(now)
    entries = core.read_ledger(ledger_path) if ledger_path else []
    state: dict[int, dict] = {}
    for entry in entries:
        body = entry.get("body") or {}
        if body.get("type") != CONTROL:
            continue
        pid = int(body.get("pid") or 0)
        if body.get("action") in ("contain", "extend"):
            state[pid] = body
        elif body.get("action") == "release":
            # an unsigned release from anywhere is ignored: it would otherwise stop
            # the deadline from ever firing and leave the process stopped forever
            if body.get("actor") == "containment-sweep":
                state.pop(pid, None)
            elif signers_path and verify_release(entry, signers_path):
                state.pop(pid, None)
    released = []
    for pid, body in state.items():
        if int(body.get("until") or 0) <= moment:
            try:
                warden.resume(pid, by_pgid=bool(body.get("by_pgid")),
                              ledger_path=ledger_path)
            except ValueError:
                pass          # already gone
            core.append_receipt(ledger_path, {
                "v": 1, "type": CONTROL, "action": "release", "pid": pid,
                "reason": "deadline passed", "actor": "containment-sweep",
                "ts": int(moment)})
            released.append(pid)
    return {"released": released, "still_contained": len(state) - len(released)}
