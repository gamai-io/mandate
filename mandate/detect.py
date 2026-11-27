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
  untrusted_input   — the receipt says the effect rested on untrusted input
  weak_coverage     — the receipt was not enforced (observed / self_reported)
  coverage_missing  — older receipt without a coverage class (informational)

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
    "min_coverage": "enforced",
    # stare trake nemaju coverage; javljaj to samo ako korisnik traži
    "report_coverage_missing": False,
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


SEQUENCE_FETCH = ("read", "web_fetch", "fetch", "browse", "search", "scrape", "http_get")
SEQUENCE_PAY = ("pay", "transfer", "send", "wire", "refund", "payout")


def _mcp_events(path: str) -> list[dict]:
    if not path or not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        body = entry.get("body") if isinstance(entry.get("body"), dict) else entry
        if not isinstance(body, dict):
            continue
        body.setdefault("_ts", body.get("ts") or 0)
        out.append(body)
    return out


def sequences(mcp_ledger: str, window_s: float = 120.0,
              repeat_window_s: float = 60.0, repeats: int = 5) -> list[dict]:
    """Tool-level anomalies a per-receipt view cannot see.

    fetch -> pay inside the window is the shape of an injected instruction that reached the
    agent and was acted on; pay right after a blocked response is the same attempt with the
    firewall already firing; the same tool five times in a minute is a loop, not work.
    """
    events = [e for e in _mcp_events(mcp_ledger) if e.get("ts")]
    events.sort(key=lambda e: float(e["ts"]))
    findings: list[dict] = []
    for i, event in enumerate(events):
        tool = str(event.get("tool") or "").lower()
        if tool in SEQUENCE_FETCH:
            for later in events[i + 1:]:
                if float(later["ts"]) - float(event["ts"]) > window_s:
                    break
                if str(later.get("tool") or "").lower() in SEQUENCE_PAY:
                    findings.append({
                        "rule": "fetch_then_pay", "severity": "high",
                        "agent": str(later.get("audience") or event.get("audience") or ""),
                        "evidence": {"fetch": tool, "pay": str(later.get("tool")),
                                     "gap_s": round(float(later["ts"]) - float(event["ts"]), 1)}})
                    break
        # pay_after_block se gleda za SVAKI pay događaj, ne samo kad je prethodni fetch
        if tool in SEQUENCE_PAY:
            blockers = [e for e in events[:i] if e.get("code") == "ResponseBlocked"
                        and float(event["ts"]) - float(e["ts"]) <= 300]
            if blockers:
                findings.append({
                    "rule": "pay_after_block", "severity": "high",
                    "agent": str(event.get("audience") or ""),
                    "evidence": {"tool": tool, "blocked_s_before":
                                 round(float(event["ts"]) - float(blockers[-1]["ts"]), 1)}})
    buckets: dict[tuple, list[float]] = defaultdict(list)
    for event in events:
        buckets[(str(event.get("tool") or ""), str(event.get("audience") or ""))].append(
            float(event["ts"]))
    for (tool, audience), stamps in buckets.items():
        stamps.sort()
        for start in range(len(stamps)):
            inside = [t for t in stamps[start:] if t - stamps[start] <= repeat_window_s]
            if len(inside) >= repeats:
                findings.append({"rule": "tool_loop", "severity": "medium", "agent": audience,
                                 "evidence": {"tool": tool, "calls": len(inside),
                                              "window_s": repeat_window_s}})
                break
    return findings


def classify(finding: dict) -> dict:
    """A proposed DORA Art. 18 classification; the bank decides, we do not."""
    severity = str(finding.get("severity") or "")
    return {"class": "major" if severity == "high" else "incident",
            "basis": "severity=%s; proposal only, the bank classifies" % severity}


def to_cef(finding: dict) -> str:
    """ArcSight CEF line. Escapes the delimiters so a target with '|' cannot break the row."""
    def esc(value) -> str:
        return (str(value).replace("\\", "\\\\").replace("|", "\\|")
                .replace("=", "\\=").replace("\n", " "))

    evidence = finding.get("evidence") or {}
    severity = {"high": 8, "medium": 5, "low": 2}.get(str(finding.get("severity")), 3)
    return ("CEF:0|gamai|mandate|1.0|%s|%s|%d|src=%s cs1Label=rule cs1=%s "
            "cs2Label=evidence cs2=%s" % (
                esc(finding.get("rule")), esc(finding.get("rule")), severity,
                esc(finding.get("agent") or "-"), esc(finding.get("rule")),
                esc(json.dumps(evidence, ensure_ascii=False, sort_keys=True)[:400])))


def to_leef(finding: dict) -> str:
    """QRadar LEEF 2.0 line: tab-separated, values tab-escaped."""
    evidence = finding.get("evidence") or {}
    severity = {"high": 8, "medium": 5, "low": 2}.get(str(finding.get("severity")), 3)
    def esc(value) -> str:
        return str(value).replace("\t", " ").replace("\n", " ")
    return "LEEF:2.0|gamai|mandate|1.0|%s|^|devTimeFormat=unix\tsev=%d\tcat=%s\tsrc=%s\tevidence=%s" % (
        esc(finding.get("rule")), severity, esc(finding.get("rule")),
        esc(finding.get("agent") or "-"),
        esc(json.dumps(evidence, ensure_ascii=False, sort_keys=True)[:400]))


def detect(ledger_path: str, config: dict | None = None,
           tokens: list[dict] | None = None, now: float | None = None,
           mcp_ledger: str = "") -> dict:
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

    # 7. the effect rested on input we do not trust (prompt-injection shape)
    for r in receipts:
        taint = r.get("taint") or {}
        bad = [f for f in (taint.get("material_untrusted") or []) if f]
        if bad:
            findings.append({"rule": "untrusted_input", "severity": "high",
                             "agent": _agent(r),
                             "evidence": {"fields": bad, "kind": _kind(r),
                                          "target": ((r.get("render") or {}).get("fields") or {})
                                                     .get("target"),
                                          "ts": _ts(r),
                                          "grant_nonce": r.get("grant_nonce")}})

    # 8. evidence weaker than the configured floor
    floor = str(cfg.get("min_coverage") or "").strip().lower()
    order = {"self_reported": 0, "observed": 1, "enforced": 2}
    if floor in order:
        for r in receipts:
            cov = str(r.get("coverage") or "").strip().lower()
            if cov and order.get(cov, -1) < order[floor]:
                findings.append({"rule": "weak_coverage", "severity": "medium",
                                 "agent": _agent(r),
                                 "evidence": {"coverage": cov, "floor": floor,
                                              "kind": _kind(r), "ts": _ts(r)}})
            elif not cov and cfg.get("report_coverage_missing"):
                findings.append({"rule": "coverage_missing", "severity": "low",
                                 "agent": _agent(r),
                                 "evidence": {"kind": _kind(r), "ts": _ts(r),
                                              "why": "receipt has no coverage class"}})

    if mcp_ledger:
        findings.extend(sequences(mcp_ledger,
                                  float(cfg.get("sequence_window_s") or 120),
                                  float(cfg.get("repeat_window_s") or 60),
                                  int(cfg.get("repeats") or 5)))

    for finding in findings:
        finding["dora"] = classify(finding)

    by_rule: dict[str, int] = defaultdict(int)
    for f in findings:
        by_rule[f["rule"]] += 1
    return {"ok": not any(f["severity"] == "high" for f in findings),
            "receipts": len(receipts), "findings": findings,
            "by_rule": dict(by_rule),
            "checked_at": now}
