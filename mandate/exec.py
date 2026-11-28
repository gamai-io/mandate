"""`mandate exec`: an effect that only happens with a signed grant.

Why a wrapper and not a kernel module: a bank's agent already runs somewhere. A wrapper is the one
control a team can adopt in an afternoon, and it makes the approval *per command*, not per session.
What it does not do is stated in the output: a child process that forks its own work, or a command
run outside the wrapper, is not covered.

The flow is the same as any other effect:

    intent   = {kind: process.exec, target: <binary>, params: {argv: [...]}, revert: irreversible}
    create   -> refuse unless a grant for *this* argv exists (one-shot nonce, bound agent)
    run      -> the process starts only after redeem() succeeded
    outcome  -> exit code, duration and a hash of stdout are appended to the chain

The outcome record is separate from the authorisation receipt on purpose: "was allowed" and "did
run, with this result" are two different claims, and an auditor will ask for both.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time

from . import core


class ExecError(Exception):
    pass


def build_intent(argv: list[str], agent: str = "agent@exec", approver: str = "operator",
                 session: str = "", cwd: str = "", env_names: list[str] | None = None) -> dict:
    if not argv:
        raise ExecError("no command given")
    binary = shutil.which(argv[0]) or argv[0]
    effect = {
        "kind": "process.exec",
        "target": os.path.basename(argv[0]),
        "params": {
            "argv": list(argv),
            "resolved": binary,
            "cwd": os.path.abspath(cwd or os.getcwd()),
            "env_names": sorted(env_names or []),
        },
        "revert": "irreversible",
    }
    return {
        "v": 1,
        "actor": {"agent": agent, "session": session or "exec"},
        "nonce": "exec-" + hashlib.sha256((" ".join(argv) + str(time.time())).encode()
                                          ).hexdigest()[:16],
        "effect": effect,
        "requested_by": approver,
        "provenance": [
            {"type": "data_ref", "source": "cli:argv", "covers": ["target", "params"]},
            {"type": "user_pref", "source": "operator:%s" % approver},
        ],
    }


def check_allowed(intent: dict, policy: dict) -> dict:
    """Ask the policy, not the model. A missing effect entry means deny."""
    decision = core.check(intent, policy)
    return decision


def run(argv: list[str], intent: dict, grant_obj: dict, signers_path: str,
        ledger_path: str, policy: dict, timeout_s: int = 0,
        cwd: str = "", env: dict | None = None) -> dict:
    """Redeem first, execute second, record the outcome third. Any failure stops before exec."""
    # The approver signed an intent, not a function call: refuse to run anything the intent does
    # not name. Without this check a grant for `echo ok` would execute whatever argv the caller
    # passed next to it — the signature would be on a document nobody looked at.
    signed = ((intent.get("effect") or {}).get("params") or {}).get("argv")
    if signed is not None and list(signed) != list(argv):
        raise ExecError("refusing: the grant was approved for %r, not %r"
                        % (list(signed), list(argv)))
    decision = check_allowed(intent, policy)
    if decision.get("decision") == "deny":
        raise ExecError("policy denied: %s" % decision.get("reason", "denied"))
    receipt = core.redeem(intent, grant_obj, signers_path, ledger_path, policy=policy)
    started = time.time()
    try:
        proc = subprocess.run(argv, cwd=cwd or None, env=env,
                              stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=timeout_s or None)
    except FileNotFoundError as exc:
        raise ExecError("command not found: %s" % argv[0]) from exc
    duration_ms = int((time.time() - started) * 1000)
    outcome = {
        "v": 1,
        "type": "control",
        "action": "outcome",
        "grant_nonce": str(((grant_obj or {}).get("grant") or {}).get("nonce") or ""),
        "argv": list(argv),
        "exit_code": int(proc.returncode),
        "duration_ms": duration_ms,
        "stdout_sha256": hashlib.sha256(proc.stdout or b"").hexdigest(),
        "stdout_bytes": len(proc.stdout or b""),
        "stderr_sha256": hashlib.sha256(proc.stderr or b"").hexdigest(),
        "receipt_hash": receipt.get("hash", ""),
        "ts": int(time.time()),
    }
    entry = core.append_receipt(ledger_path, outcome)
    return {"receipt": receipt, "outcome": entry, "exit_code": proc.returncode,
            "stdout": proc.stdout, "stderr": proc.stderr, "duration_ms": duration_ms}


def describe(argv: list[str], intent: dict) -> dict:
    """What the approver is being asked to sign, in one object, without running anything."""
    return {
        "would_run": argv,
        "intent": intent,
        "commitment": core.intent_commitment(intent),
        "render": core.render(intent),
        "note": ("approve this intent (mandate grant), then re-run with --intent/--grant; "
                 "a grant for different argv will not match the commitment"),
    }
