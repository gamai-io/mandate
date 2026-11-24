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
import shutil
import signal
import subprocess
import time

from .core import append_receipt

FREEZE_STATES = ("T", "t")
GONE_STATES = ("Z", "X", "x")
CGROUP_ROOT = os.environ.get("MANDATE_CGROUP_ROOT", "/sys/fs/cgroup")
QUARANTINE_CHAIN = "MANDATE_QUARANTINE"


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


# --- cgroup v2 freezer: the kernel observes the freeze, not us -----------------


def cgroup_available() -> bool:
    return os.path.exists(os.path.join(CGROUP_ROOT, "cgroup.controllers"))


def attach(pid: int, name: str, root: str | None = None) -> str:
    """Put a process into its own cgroup so it can be frozen as a unit."""
    root = root or CGROUP_ROOT
    base = os.path.join(root, "mandate")
    path = os.path.join(base, name)
    os.makedirs(path, exist_ok=True)
    procs = os.path.join(path, "cgroup.procs")
    with open(procs, "w", encoding="utf-8") as fh:
        fh.write(str(pid))
    time.sleep(0.02)
    members = open(procs, encoding="utf-8").read().split()
    if str(pid) not in members:
        raise ValueError(f"pid {pid} is not in {path} (cgroup delegation may be restricted)")
    return path


def cgroup_state(path: str) -> dict:
    events = {}
    try:
        for line in open(os.path.join(path, "cgroup.events"), encoding="utf-8"):
            key, _, value = line.strip().partition(" ")
            events[key] = value
    except OSError:
        pass
    return {"frozen": events.get("frozen") == "1", "events": events}


def freeze_cgroup(path: str, timeout_ms: int = 3000) -> dict:
    t0 = _now_ms()
    with open(os.path.join(path, "cgroup.freeze"), "w", encoding="utf-8") as fh:
        fh.write("1")
    deadline = t0 + timeout_ms
    state = cgroup_state(path)
    while _now_ms() < deadline and not state["frozen"]:
        time.sleep(0.005)
        state = cgroup_state(path)
    return {"frozen": state["frozen"], "time_to_halt_ms": round(_now_ms() - t0, 1),
            "cgroup": path, "events": state["events"]}


def thaw_cgroup(path: str) -> dict:
    with open(os.path.join(path, "cgroup.freeze"), "w", encoding="utf-8") as fh:
        fh.write("0")
    time.sleep(0.02)
    return cgroup_state(path)


def kill_cgroup(path: str) -> dict:
    with open(os.path.join(path, "cgroup.kill"), "w", encoding="utf-8") as fh:
        fh.write("1")
    return {"killed": True, "cgroup": path}


def cgroup_pids(path: str) -> list[int]:
    try:
        return sorted(int(x) for x in open(os.path.join(path, "cgroup.procs")).read().split())
    except OSError:
        return []


# --- network quarantine by uid (the agent must run under its own uid) --------


def _nft(*args: str) -> dict:
    out = subprocess.run(["nft", *args], capture_output=True, text=True, timeout=30)
    return {"ok": out.returncode == 0,
            "out": (out.stdout + out.stderr).strip()[:300]}


def _nft_init() -> None:
    _nft("add", "table", "inet", "mandate")
    _nft("add", "set", "inet", "mandate", "q_uids", "{", "type", "uid;", "}")
    _nft("add", "chain", "inet", "mandate", "out",
         "{", "type", "filter", "hook", "output", "priority", "0;", "}")
    rules = subprocess.run(["nft", "list", "chain", "inet", "mandate", "out"],
                           capture_output=True, text=True, timeout=30).stdout
    if "@q_uids" not in rules:
        _nft("add", "rule", "inet", "mandate", "out", "meta", "skuid", "@q_uids", "drop")


def quarantine_members() -> list[int]:
    out = subprocess.run(["nft", "list", "set", "inet", "mandate", "q_uids"],
                         capture_output=True, text=True, timeout=30)
    members = []
    for token in out.stdout.replace("{", " ").replace("}", " ").split():
        if token.isdigit():
            members.append(int(token))
    return sorted(members)


def quarantine(uid: int, undo: bool = False) -> dict:
    """Cut every packet from one uid (the agent must run under its own uid).

    Implemented with nftables so it works without the iptables owner module:
    a single set of quarantined uids and one drop rule on the output hook.
    """
    if not shutil.which("nft"):
        return {"action": "quarantine" if not undo else "quarantine_undo", "uid": uid,
                "ok": False, "out": "nft not installed"}
    _nft_init()
    if undo:
        res = _nft("delete", "element", "inet", "mandate", "q_uids", "{", str(uid), "}")
    else:
        res = _nft("add", "element", "inet", "mandate", "q_uids", "{", str(uid), "}")
    return {"action": "quarantine" if not undo else "quarantine_undo", "uid": uid,
            "ok": res["ok"], "out": res["out"], "members": quarantine_members()}


def quarantine_active(uid: int) -> bool:
    return uid in quarantine_members()


# --- signed stop evidence ----------------------------------------------------


SIGN_EXCLUDE = ("v", "type", "prev", "entry", "signature", "signed", "signer", "ledger_head")


def _signable(evidence: dict) -> dict:
    return {k: v for k, v in evidence.items() if k not in SIGN_EXCLUDE}


def sign_evidence(evidence: dict, key_path: str, signer: str) -> dict:
    from . import sign
    from .jcs import canonicalize
    body = _signable(evidence)
    signature = sign.sign(canonicalize(body), key_path)
    return {"signer": signer, "signature": signature, "signed": True}


def verify_evidence(evidence: dict, signers_path: str) -> dict:
    from . import sign
    from .jcs import canonicalize
    body = _signable(evidence)
    ok = sign.verify(canonicalize(body), evidence.get("signer") or "",
                     evidence.get("signature") or "", signers_path,
                     sign.DEFAULT_NAMESPACE)
    return {"valid": bool(ok), "signer": evidence.get("signer")}


# --- Firecracker microVM pause (needs a KVM host; code is host-agnostic) ------


def fc_call(socket_path: str, method: str, path: str, payload: dict | None = None,
            timeout: int = 10) -> dict:
    """Minimal Firecracker API client over its unix socket (via curl)."""
    cmd = ["curl", "-s", "-X", method, "--unix-socket", socket_path,
           f"http://localhost{path}"]
    if payload is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(payload)]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    try:
        body = json.loads(out.stdout) if out.stdout.strip() else {}
    except ValueError:
        body = {"raw": out.stdout[:200]}
    return {"ok": out.returncode == 0, "status": out.returncode, "body": body}


def vm_state(socket_path: str) -> str | None:
    """Firecracker 1.17 answers GET / with {"state": "Running"|"Paused"}."""
    res = fc_call(socket_path, "GET", "/")
    if res["ok"] and isinstance(res["body"], dict) and res["body"].get("state"):
        return res["body"]["state"]
    res = fc_call(socket_path, "GET", "/vm")  # older builds
    if res["ok"] and isinstance(res["body"], dict):
        return res["body"].get("state")
    return None


def vm_pause(socket_path: str, timeout_ms: int = 3000) -> dict:
    t0 = _now_ms()
    before = vm_state(socket_path)
    res = fc_call(socket_path, "PATCH", "/vm", {"state": "Paused"})
    deadline = t0 + timeout_ms
    state = vm_state(socket_path)
    while _now_ms() < deadline and state != "Paused":
        time.sleep(0.01)
        state = vm_state(socket_path)
    return {"method": "vm-pause", "socket": socket_path, "state_before": before,
            "state_after": state, "verified": state == "Paused",
            "time_to_halt_ms": round(_now_ms() - t0, 1), "api": res["body"]}


def vm_resume(socket_path: str, timeout_ms: int = 3000) -> dict:
    res = fc_call(socket_path, "PATCH", "/vm", {"state": "Resumed"})
    deadline = _now_ms() + timeout_ms
    state = vm_state(socket_path)
    while _now_ms() < deadline and state != "Running":
        time.sleep(0.01)
        state = vm_state(socket_path)
    return {"method": "vm-resume", "socket": socket_path, "state_after": state,
            "verified": state == "Running", "api": res["body"]}


def kvm_available(path: str = "/dev/kvm") -> bool:
    return os.path.exists(path) and os.access(path, os.R_OK | os.W_OK)
