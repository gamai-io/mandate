"""Behavioural detector for an inbound agent.

The Jesta/OpenCode incident (24 Nov 2026) is the design brief: no blocklist
matched the address, so detection has to come from *what the visitor did* —
desktop browser then a fake phone UA, then curl, from the same address within
minutes; following a link that only existed inside an API document; probing the
same key, no key and a fabricated key within seconds; giving up after 5m44s.

This module reads a JSONL access log (nginx/Envoy/our egress proxy) and scores
each source address over a sliding window. Deterministic, no model in the decision
path; an optional judge model may explain a finding but cannot lower the score.

Log line:
  {"ts": 1795558000.1, "ip": "1.2.3.4", "ua": "Mozilla/5.0 ... Chrome/157",
   "method": "GET", "path": "/api/v1/invoices", "status": 200,
   "ua_platform": "desktop|mobile", "auth": "key-A|none|invalid",
   "referer": "/docs/api.md", "bytes": 1234}

Rules (points):
  tool_switch        3  browser then a CLI HTTP client (curl/wget/python-requests) within 15 min
  ua_flip            2  same address claims desktop and mobile within 5 min
  docs_link_follow   3  request whose Referer is an API/spec document, not a page
  key_probing        4  >=3 distinct auth values (or none) on the same path within 60 s
  read_after_submit  2  GET on an endpoint that only accepts submissions (status 403/405 twice)
  velocity           1  >= 15 distinct paths per minute
  low_and_slow_scan  2  >= 10 distinct paths with 4xx in 10 min, single UA

Levels: >=6 high, >=3 medium, else low. A finding is written to the ledger as a
`control/alert` record (same chain as receipts) when `--ledger` is given.
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict

BROWSER = ("mozilla", "chrome", "safari", "firefox", "edge", "opera")
CLI_CLIENTS = ("curl", "wget", "python-requests", "httpx", "go-http-client", "libwww")

WINDOW = 600          # seconds scanned per IP
THRESHOLDS = {"high": 6, "medium": 3}


def _kind(ua: str) -> str:
    ua = (ua or "").lower()
    if any(c in ua for c in CLI_CLIENTS):
        return "cli"
    if any(b in ua for b in BROWSER):
        return "browser"
    return "other"


def _is_doc(referer: str) -> bool:
    r = (referer or "").lower()
    return any(token in r for token in ("/docs", "/api-docs", "openapi", "swagger", ".md",
                                        "/spec", "/redoc"))


def load(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _session(rows: list[dict]) -> dict:
    rows = sorted(rows, key=lambda r: float(r.get("ts") or 0))
    findings: list[dict] = []
    points = 0

    kinds = defaultdict(list)          # kind -> timestamps
    platforms = defaultdict(list)      # platform -> timestamps
    for r in rows:
        kinds[_kind(str(r.get("ua") or ""))].append(float(r.get("ts") or 0))
        platform = str(r.get("ua_platform") or "").lower()
        if platform:
            platforms[platform].append(float(r.get("ts") or 0))

    # tool switch: browser then cli
    if kinds["browser"] and kinds["cli"]:
        first_browser = min(kinds["browser"])
        first_cli = min(kinds["cli"])
        if 0 <= first_cli - first_browser <= 900 or 0 <= first_browser - first_cli <= 900:
            findings.append({"rule": "tool_switch", "points": 3,
                             "detail": "browser and CLI HTTP client from one address"})
            points += 3

    # ua flip between desktop and mobile
    if platforms.get("desktop") and platforms.get("mobile"):
        gap = abs(min(platforms["desktop"]) - min(platforms["mobile"]))
        if gap <= 300:
            findings.append({"rule": "ua_flip", "points": 2,
                             "detail": "same address claims desktop and mobile within %ds" % int(gap)})
            points += 2

    # following a link that only exists in a document
    docs = [r for r in rows if _is_doc(str(r.get("referer") or ""))]
    if docs:
        findings.append({"rule": "docs_link_follow", "points": 3,
                         "detail": "%d request(s) came from an API/spec document" % len(docs)})
        points += 3

    # key probing: several auth values (or none) on one path in under a minute
    by_path = defaultdict(list)
    for r in rows:
        by_path[str(r.get("path") or "")].append((float(r.get("ts") or 0), str(r.get("auth") or "none")))
    for path, hits in by_path.items():
        hits.sort()
        for i in range(len(hits)):
            window = [h for h in hits if 0 <= h[0] - hits[i][0] <= 60]
            distinct = {v for _t, v in window}
            if len(distinct) >= 3:
                findings.append({"rule": "key_probing", "points": 4,
                                 "detail": "%d auth values on %s within 60s" % (len(distinct), path)})
                points += 4
                break

    # reading an endpoint that only accepts submissions
    blocked = [r for r in rows if int(r.get("status") or 0) in (403, 405)
               and str(r.get("method") or "").upper() == "GET"]
    if len(blocked) >= 2:
        findings.append({"rule": "read_after_submit", "points": 2,
                         "detail": "%d GET requests refused by submit-only endpoints" % len(blocked)})
        points += 2

    # velocity: distinct paths per minute
    per_minute = defaultdict(set)
    for r in rows:
        per_minute[int(float(r.get("ts") or 0) // 60)].add(str(r.get("path") or ""))
    busiest = max((len(v) for v in per_minute.values()), default=0)
    if busiest >= 15:
        findings.append({"rule": "velocity", "points": 1,
                         "detail": "%d distinct paths in one minute" % busiest})
        points += 1

    # low and slow scan: many 4xx across many paths, single UA
    fourxx = {str(r.get("path")) for r in rows if 400 <= int(r.get("status") or 0) < 500}
    uas = {str(r.get("ua") or "") for r in rows}
    if len(fourxx) >= 10 and len(uas) <= 1:
        findings.append({"rule": "low_and_slow_scan", "points": 2,
                         "detail": "%d distinct paths answered 4xx with a single UA" % len(fourxx)})
        points += 2

    level = "high" if points >= THRESHOLDS["high"] else (
        "medium" if points >= THRESHOLDS["medium"] else "low")
    return {"points": points, "level": level, "findings": findings,
            "requests": len(rows),
            "first_ts": rows[0].get("ts") if rows else None,
            "last_ts": rows[-1].get("ts") if rows else None}


def analyse(rows: list[dict], window: int = WINDOW, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    by_ip = defaultdict(list)
    for r in rows:
        ts = float(r.get("ts") or 0)
        if window and now - ts > window:
            continue
        by_ip[str(r.get("ip") or "?")].append(r)
    sessions = {ip: _session(items) for ip, items in by_ip.items()}
    flagged = {ip: s for ip, s in sessions.items() if s["level"] != "low"}
    return {"window_s": window, "sources": len(sessions), "flagged": len(flagged),
            "sessions": sessions,
            "highest": max((s["points"] for s in sessions.values()), default=0)}


def watch(log_path: str, window: int = WINDOW, ledger=None) -> dict:
    result = analyse(load(log_path), window)
    if ledger:
        alerts = [{"ip": ip, **s} for ip, s in result["sessions"].items()
                  if s["level"] != "low"]
        if alerts:
            from .core import append_receipt
            append_receipt(ledger, {"v": 1, "type": "control", "action": "alert",
                                    "actor": "agentwatch", "reason": "inbound agent behaviour",
                                    "ts": time.time(), "findings": alerts})
    return result
