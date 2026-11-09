#!/usr/bin/env python3
"""Minimal MCP (stdio) adapter exposing Mandate tools to any agent."""
from __future__ import annotations

import json
import os
import sys

from . import core

SIGNERS = os.environ.get("MANDATE_SIGNERS", "trust/allowed_signers")
LEDGER = os.environ.get("MANDATE_LEDGER", "ledger.jsonl")
SERVER_INFO = {"name": "mandate", "version": "0.4.0"}

TOOLS = [
    {
        "name": "mandate_check",
        "description": "Decide allow/ask/deny for an intent effect.",
        "inputSchema": {"type": "object", "properties": {"intent": {"type": "object"}},
                        "required": ["intent"]},
    },
    {
        "name": "mandate_propose",
        "description": "Create a canonical commitment proposal.",
        "inputSchema": {"type": "object", "properties": {"intent": {"type": "object"}},
                        "required": ["intent"]},
    },
    {
        "name": "mandate_redeem",
        "description": "Redeem a human-signed grant (one-shot).",
        "inputSchema": {"type": "object", "required": ["intent", "grant"],
                        "properties": {"intent": {"type": "object"},
                                       "grant": {"type": "object"}}},
    },
    {
        "name": "mandate_verify",
        "description": "Verify a receipt against intent and grant offline.",
        "inputSchema": {"type": "object", "required": ["receipt", "intent", "grant"],
                        "properties": {"receipt": {"type": "object"},
                                       "intent": {"type": "object"},
                                       "grant": {"type": "object"}}},
    },
]


def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _call(name: str, args: dict) -> dict:
    if name == "mandate_check":
        return core.check(args["intent"])
    if name == "mandate_propose":
        return core.propose(args["intent"])
    if name == "mandate_redeem":
        return core.redeem(args["intent"], args["grant"], SIGNERS, LEDGER)
    if name == "mandate_verify":
        return {"valid": core.verify_receipt(
            args["receipt"], args["intent"], args["grant"], SIGNERS)}
    raise ValueError("unknown tool")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05",
                      "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                out = _call(str(params.get("name")), params.get("arguments") or {})
                result = {"content": [{"type": "text",
                                       "text": json.dumps(out, ensure_ascii=False)}],
                          "isError": False}
            except Exception as exc:
                result = {"content": [{"type": "text", "text": str(exc)}],
                          "isError": True}
        elif mid is None:
            continue
        else:
            _send({"jsonrpc": "2.0", "id": mid,
                   "error": {"code": -32601, "message": "method not found"}})
            continue
        _send({"jsonrpc": "2.0", "id": mid, "result": result})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
