"""Warden: stop an agent from outside, prove that it stopped.

A kill switch that only *sends* a signal is a promise. A warden is a switch that
(a) stops the target through the kernel, (b) polls until the stop is observable
(``/proc`` state ``T`` for freeze, process gone for kill), (c) measures
time-to-halt, and (d) writes the stop — with that evidence — into the same
hash-chained ledger as the receipts.

Scope, stated honestly: this stops processes on the host where the warden runs.
It is not a hypervisor control plane, it cannot stop an agent that holds a
credential the warden does not control, and a ``SIGSTOP`` freeze is not a
security boundary (the process keeps its memory and can be resumed by anyone who
can signal it). For Firecracker/gVisor pause, see the roadmap in
``docs/BANK_CONTROL_MATRIX.md``.
"""
from __future__ import annotations

import json
import os
import signal
import time

from .core import append_receipt

FREEZE_STATES = ("T", "t")
GONE_STATES = ("Z", "X", "x")


def _stat(pid: int) -> dict | None:
    try:
        raw = open(f"/proc/{pid}/stat", encoding="utf-8").read()
    except OSError:
        return None
    rest = raw.rsplit(")", 1)[1].split()
    return {"pid": pid, "state": rest[0], "ppid": int(rest[1]), "pgid": int(rest[2])}


def pids_in_pgid(pgid: int) -> list[int]:
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        st = _stat(int(name))
        if st and st["pgid"] == pgid:
            out.append(st["pid"])
    return sorted(out)


def states(pids: list[int]) -> dict[int, str]:
    out = {}
    for pid in pids:
        st = _stat(pid)
        out[pid] = st["state"] if st else "-"
    return out


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


def stop(target: int, method: str = "freeze", by_pgid: bool = False,
         timeout_ms: int = 3000, ledger_path: str | None = None,
         reason: str = "", actor: str = "ops") -> dict:
    """Stop a pid or process group and wait until the stop is observable."""
    pids = pids_in_pgid(target) if by_pgid else [target]
    pids = [pid for pid in pids if _stat(pid) is not None]
    if not pids:
        raise ValueError(f"no processes for {'pgid' if by_pgid else 'pid'} {target}")

    sig = signal.SIGSTOP if method == "freeze" else signal.SIGKILL
    t0 = _now_ms()
    if by_pgid:
        os.killpg(target, sig)
    else:
        for pid in pids:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass

    want = FREEZE_STATES if method == "freeze" else GONE_STATES
    deadline = t0 + timeout_ms
    seen: dict[int, str] = {}
    while _now_ms() < deadline:
        seen = states(pids)
        if all(state in want or state == "-" for state in seen.values()):
            break
        time.sleep(0.005)
    halted_ms = round(_now_ms() - t0, 1)
    remaining = [pid for pid, state in seen.items() if state not in want and state != "-"]

    evidence = {
        "action": "halt",
        "method": method,
        "target": target,
        "by_pgid": by_pgid,
        "pids": pids,
        "states_after": {str(pid): state for pid, state in seen.items()},
        "time_to_halt_ms": halted_ms,
        "verified": not remaining,
        "reason": reason,
        "actor": actor,
    }
    entry = None
    if ledger_path:
        entry = append_receipt(ledger_path, {"v": 1, "type": "control", **evidence})
        evidence["ledger_head"] = entry["hash"]
    evidence["entry"] = entry
    return evidence


def resume(target: int, by_pgid: bool = False, ledger_path: str | None = None,
           reason: str = "", actor: str = "ops") -> dict:
    pids = pids_in_pgid(target) if by_pgid else [target]
    if not pids:
        raise ValueError("no processes to resume")
    if by_pgid:
        os.killpg(target, signal.SIGCONT)
    else:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
    time.sleep(0.01)
    seen = states(pids)
    evidence = {
        "action": "resume",
        "target": target,
        "by_pgid": by_pgid,
        "pids": pids,
        "states_after": {str(pid): state for pid, state in seen.items()},
        "reason": reason,
        "actor": actor,
    }
    entry = None
    if ledger_path:
        entry = append_receipt(ledger_path, {"v": 1, "type": "control", **evidence})
        evidence["ledger_head"] = entry["hash"]
    evidence["entry"] = entry
    return evidence


def last_stop(ledger_path: str) -> dict | None:
    if not os.path.exists(ledger_path):
        return None
    last = None
    for line in open(ledger_path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        body = (json.loads(line) or {}).get("body") or {}
        if body.get("type") == "control" and body.get("action") in ("halt", "resume"):
            last = body
    return last
