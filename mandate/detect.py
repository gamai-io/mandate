"""Detection rules over the ledger: what a bank actually asks for at runtime.

Reuters (23 Nov 2026) lists the checks banks added: detect an agent using a
human employee's credentials, watch unusual tool sequences and volume spikes,
and know which systems an agent reached. This module turns the ledger and the
agent tokens into findings — deterministic rules, each with the evidence that
triggered it.

Rules (all offline, no model):
  human_credential  — a principal that appears as approver also acts as the agent
  sod_ledger        — receipt exists where approver == agent
  velocity          — more than N effects per agent per hour
  amount            — single effect above the configured ceiling
  off_hours         — effect outside the configured window
  scope_unknown     — effect kind never granted in any supplied agent token

Each finding: {"rule", "severity", "agent", "evidence"}.
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict

DEFAULTS = {
    "max_effects_per_hour": 10,
    "max_amount": 5000,
    "business_hours_utc": [6, 20],
    "human_principals": ["renato", "ops", "owner", "approver"],
    "window_seconds": 3600,
}


def load_config(policy_path: str | None) -> dict:
    cfg = dict(DEFAULTS)
    if policy_path and os.path.exists(policy_path):
        try:
            data = json.load(open(policy_path, encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        block = (data or {}).get("detect") or {}
        if isinstance(block, dict):
            cfg.update(block)
    return cfg


def _receipts(ledger_path: str) -> list[dict]:
    if not os.path.exists(ledger_path):
        return []
    out = []
    for line in open(ledger_path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        body = (json.loads(line) or {}).get("body") or {}
        if body.get("type") == "receipt":
            out.append(body)
    return out


def _agent(receipt: dict) -> str:
    render = receipt.get("render") or {}
    fields = render.get("fields") or {}
    return str(receipt.get("agent") or fields.get("actor") or render.get("agent") or "?")


def _kind(receipt: dict) -> str:
    return str(((receipt.get("render") or {}).get("fields") or {}).get("kind") or "?")


def _amount(receipt: dict) -> float:
    amount = ((receipt.get("render") or {}).get("fields") or {}).get("amount") or {}
    try:
        return float((amount or {}).get("value") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _ts(receipt: dict) -> float:
    try:
        return float(receipt.get("ts") or 0)
    except (TypeError, ValueError):
        return 0.0


def _is_human(name: str, humans: list[str]) -> bool:
    base = str(name or "").split("@")[0].strip().lower()
    return base in {h.lower() for h in humans}


def detect(ledger_path: str, config: dict | None = None,
           tokens: list[dict] | None = None, now: float | None = None) -> dict:
    cfg = dict(DEFAULTS, **(config or {}))
    now = time.time() if now is None else now
    receipts = _receipts(ledger_path)
    findings: list[dict] = []

    # 1. the same principal approves and acts
    for r in receipts:
        approver = str(r.get("approver") or "")
        agent = _agent(r)
        if approver and agent and approver.split("@")[0] == agent.split("@")[0]:
            findings.append({"rule": "sod_ledger", "severity": "high", "agent": agent,
                             "evidence": {"approver": approver, "ts": _ts(r),
                                          "grant_nonce": r.get("grant_nonce")}})

    # 2. an agent using an identity that belongs to a human
    humans = list(cfg.get("human_principals") or [])
    for r in receipts:
        agent = _agent(r)
        if _is_human(agent, humans):
            findings.append({"rule": "human_credential", "severity": "high", "agent": agent,
                             "evidence": {"ts": _ts(r), "kind": _kind(r),
                                          "why": "agent identity matches a human principal"}})

    # 3. velocity per agent inside the rolling window
    window = float(cfg.get("window_seconds") or 3600)
    limit = int(cfg.get("max_effects_per_hour") or 0)
    if limit:
        buckets: dict[str, list[float]] = defaultdict(list)
        for r in receipts:
            if now - _ts(r) <= window:
                buckets[_agent(r)].append(_ts(r))
        for agent, stamps in buckets.items():
            if len(stamps) > limit:
                findings.append({"rule": "velocity", "severity": "high", "agent": agent,
                                 "evidence": {"effects": len(stamps), "limit": limit,
                                              "window_seconds": window}})

    # 4. single effect above the ceiling
    ceiling = float(cfg.get("max_amount") or 0)
    if ceiling:
        for r in receipts:
            value = _amount(r)
            if value > ceiling:
                findings.append({"rule": "amount", "severity": "medium", "agent": _agent(r),
                                 "evidence": {"amount": value, "max": ceiling,
                                              "kind": _kind(r), "ts": _ts(r)}})

    # 5. outside the configured hours
    hours = cfg.get("business_hours_utc") or [0, 24]
    start, end = int(hours[0]), int(hours[1])
    for r in receipts:
        hour = time.gmtime(_ts(r)).tm_hour
        if not (start <= hour < end):
            findings.append({"rule": "off_hours", "severity": "low", "agent": _agent(r),
                             "evidence": {"hour_utc": hour, "window": [start, end],
                                          "ts": _ts(r)}})

    # 6. effect kind never seen in any supplied agent token
    if tokens:
        granted = set()
        for t in tokens:
            granted.update(((t.get("payload") or {}).get("scopes") or []))
        if granted:
            for r in receipts:
                kind = _kind(r)
                if kind and kind not in granted and "*" not in granted:
                    findings.append({"rule": "scope_unknown", "severity": "medium",
                                     "agent": _agent(r),
                                     "evidence": {"kind": kind, "granted": sorted(granted)}})

    by_rule: dict[str, int] = defaultdict(int)
    for f in findings:
        by_rule[f["rule"]] += 1
    return {"ok": not any(f["severity"] == "high" for f in findings),
            "receipts": len(receipts), "findings": findings,
            "by_rule": dict(by_rule),
            "checked_at": now}
