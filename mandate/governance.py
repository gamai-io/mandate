"""Governance for long-running agent fleets: limits, halt/resume, separation of duties.

Banks now treat agents like employees: credentials, permissions, limits, and a
kill switch whose use is on the record. Mandate already proves *who authorised
which effect*; this module adds the "how much may it do" and "who stopped it,
when, and why" parts.

Everything here is written to the same hash-chained ledger as receipts, so
limits and stops are auditable with the same tooling (`mandate chain`,
`mandate audit bundle`).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

from .core import append_receipt, read_ledger

CONTROL_TYPE = "control"

DEFAULTS = {
    "window_seconds": 3600,      # rolling window for the counters below
    "max_effects": 0,            # 0 = unlimited
    "max_amount": 0,             # 0 = unlimited, in the policy currency
    "currency": "BAM",
    "max_total_seconds": 0,      # 0 = unlimited; wall clock since first effect
}


def load_limits(policy_path: str | None) -> dict:
    """Read the optional "limits" block from the policy file."""
    limits = dict(DEFAULTS)
    if not policy_path or not os.path.exists(policy_path):
        return limits
    try:
        data = json.load(open(policy_path, encoding="utf-8"))
    except (OSError, ValueError):
        return limits
    block = (data or {}).get("limits") or {}
    if isinstance(block, dict):
        for key in DEFAULTS:
            if key in block:
                limits[key] = block[key]
    return limits


def last_control(ledger_path: str) -> dict | None:
    """Return the most recent halt/resume record, if any."""
    if not os.path.exists(ledger_path):
        return None
    for entry in reversed(read_ledger(ledger_path)):
        body = entry.get("body") or {}
        if body.get("type") == CONTROL_TYPE and body.get("action") in ("halt", "resume"):
            return body
    return None


def _append_control(ledger_path: str, action: str, reason: str, actor: str) -> dict:
    body = {
        "v": 1,
        "type": CONTROL_TYPE,
        "action": action,
        "reason": reason,
        "actor": actor,
        "ts": time.time(),
    }
    return append_receipt(ledger_path, body)


def halt(ledger_path: str, reason: str, actor: str = "owner") -> dict:
    return _append_control(ledger_path, "halt", reason, actor)


def resume(ledger_path: str, reason: str, actor: str = "owner") -> dict:
    return _append_control(ledger_path, "resume", reason, actor)


def _receipts(ledger_path: str) -> list[dict]:
    if not os.path.exists(ledger_path):
        return []
    out = []
    for entry in read_ledger(ledger_path):
        body = entry.get("body") or {}
        if body.get("type") == "receipt":
            out.append(body)
    return out


def _amount(body: dict) -> tuple[float, str]:
    render = body.get("render") or {}
    amount = render.get("amount") or {}
    if isinstance(amount, dict):
        try:
            return float(amount.get("value") or 0.0), str(amount.get("currency") or "")
        except (TypeError, ValueError):
            return 0.0, str(amount.get("currency") or "")
    return 0.0, ""


def check(ledger_path: str, limits: dict, now: float | None = None) -> dict:
    """Return {"allow": bool, "code": str, "detail": {...}} for the next effect."""
    now = time.time() if now is None else now
    control = last_control(ledger_path)
    if control and control.get("action") == "halt":
        return {"allow": False, "code": "halted",
                "detail": {"reason": control.get("reason"), "since": control.get("ts")}}

    receipts = _receipts(ledger_path)
    window = float(limits.get("window_seconds") or 0)
    in_window = [r for r in receipts if window <= 0 or now - float(r.get("ts") or 0) <= window]

    max_effects = int(limits.get("max_effects") or 0)
    if max_effects and len(in_window) >= max_effects:
        return {"allow": False, "code": "limit_effects",
                "detail": {"used": len(in_window), "max": max_effects, "window_seconds": window}}

    max_amount = float(limits.get("max_amount") or 0)
    if max_amount:
        currency = str(limits.get("currency") or "")
        total = 0.0
        for r in in_window:
            value, cur = _amount(r)
            if cur and currency and cur != currency:
                return {"allow": False, "code": "limit_currency",
                        "detail": {"seen": cur, "expected": currency}}
            total += value
        if total >= max_amount:
            return {"allow": False, "code": "limit_amount",
                    "detail": {"used": total, "max": max_amount, "currency": currency}}

    max_total = float(limits.get("max_total_seconds") or 0)
    if max_total and receipts:
        first = min(float(r.get("ts") or now) for r in receipts)
        if now - first >= max_total:
            return {"allow": False, "code": "limit_runtime",
                    "detail": {"running_for": now - first, "max": max_total}}

    return {"allow": True, "code": "ok",
            "detail": {"effects_in_window": len(in_window), "limits": limits}}


def check_separation_of_duties(intent: dict, approver: str) -> dict:
    """An agent may not approve its own effect (four-eyes principle)."""
    actor = str(((intent or {}).get("actor") or {}).get("agent") or "").strip().lower()
    who = str(approver or "").strip().lower()
    if actor and who and (actor == who or actor.split("@")[0] == who.split("@")[0]):
        return {"allow": False, "code": "sod_violation",
                "detail": {"agent": actor, "approver": who}}
    return {"allow": True, "code": "ok", "detail": {}}


def summary(ledger_path: str, limits: dict) -> dict[str, Any]:
    return {"control": last_control(ledger_path), "state": check(ledger_path, limits),
            "receipts": len(_receipts(ledger_path))}
