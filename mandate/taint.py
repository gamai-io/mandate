"""The bridge between "something suspicious came in" and "this effect may not happen".

A firewall that only warns is a firewall people turn off. The chain this module
closes is:

    a tool response or a document is flagged  ->  a taint mark in the ledger
    ->  the next intent cites that source as provenance  ->  `require_trusted`
    refuses the effect because the field rests on untrusted input

The mark is a `control` entry, not a hidden state file: an auditor can see when the
taint started, what triggered it and which session it belongs to. Marks are never
deleted — `clear()` writes a release entry, so "it was tainted until 14:20" stays
visible.

Honest scope: this does not prove that a given intent *used* the tainted text. It
says the source was flagged and the caller declared that source. The declaration is
the part a human reviews; the gate is what makes ignoring it expensive.
"""
from __future__ import annotations

import json
import os
import time
import uuid

FORMAT = "mandate-taint/1"
TRUST = "untrusted"


def _append(ledger_path: str, body: dict) -> dict:
    body.setdefault("v", 1)
    body.setdefault("type", "control")
    body.setdefault("format", FORMAT)
    body.setdefault("ts", int(time.time()))
    body.setdefault("nonce", uuid.uuid4().hex[:12])
    os.makedirs(os.path.dirname(os.path.abspath(ledger_path)), exist_ok=True)
    with open(ledger_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(body, ensure_ascii=False, sort_keys=True) + "\n")
    return body


def mark(ledger_path: str, session: str, source: str, kind: str = "data_ref",
         reason: str = "", findings: list[str] | None = None,
         now: float | None = None) -> dict:
    """Record that `source` put something untrustworthy into `session`."""
    if not str(session or "").strip():
        raise ValueError("session is required")
    if not str(source or "").strip():
        raise ValueError("source is required")
    return _append(ledger_path, {
        "action": "taint", "session": str(session), "source": str(source),
        "kind": str(kind), "trust": TRUST, "reason": str(reason)[:200],
        "findings": list(findings or [])[:8],
        "ts": int(now if now is not None else time.time()),
    })


def clear(ledger_path: str, session: str, source: str, reason: str = "",
          now: float | None = None) -> dict:
    """Release a mark. The history stays: a release is an entry, not a deletion."""
    return _append(ledger_path, {
        "action": "untaint", "session": str(session), "source": str(source),
        "reason": str(reason)[:200],
        "ts": int(now if now is not None else time.time()),
    })


def _entries(ledger_path: str) -> list[dict]:
    if not ledger_path or not os.path.exists(ledger_path):
        return []
    out = []
    for line in open(ledger_path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def active(ledger_path: str, session: str | None = None) -> list[dict]:
    """Sources currently tainted, latest action per (session, source) wins."""
    state: dict[tuple, dict] = {}
    for entry in _entries(ledger_path):
        if entry.get("format") != FORMAT:
            continue
        if session is not None and str(entry.get("session")) != str(session):
            continue
        key = (str(entry.get("session")), str(entry.get("source")))
        if entry.get("action") == "taint":
            state[key] = entry
        elif entry.get("action") == "untaint":
            state.pop(key, None)
    return sorted(state.values(), key=lambda e: (str(e.get("session")), str(e.get("source"))))


def provenance_for(ledger_path: str, session: str,
                   covers: list[str] | None = None) -> list[dict]:
    """Provenance entries a caller should put on an intent that used this session.

    Every active source becomes `trust: untrusted`, so a policy with
    `require_trusted` refuses an effect whose material fields rest on it.
    """
    out = []
    for entry in active(ledger_path, session):
        item = {"type": str(entry.get("kind") or "data_ref"),
                "source": str(entry.get("source")), "trust": TRUST}
        if covers:
            item["covers"] = list(covers)
        out.append(item)
    return out
