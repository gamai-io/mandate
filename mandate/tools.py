"""Pin what an approved tool actually is.

An approval of "erp.read" says nothing about what `erp.read` will do tomorrow. The
Deadbugz incident is exactly that shape: a server approved once, its tool metadata
changed afterwards, and every agent that trusted the earlier review inherited the
change.

So a tool is pinned by the JCS hash of its schema, the intent commits to that hash,
and the broker re-reads the file before executing. Drift is a refusal, not a
warning: the approval was for the version that was read.
"""
from __future__ import annotations

import hashlib
import json
import os

from . import core
from .jcs import canonicalize


class ToolError(core.MandateError):
    pass


def schema_hash(path: str) -> str:
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ToolError("tool schema unreadable: %s: %s" % (path, exc)) from exc
    return hashlib.sha256(canonicalize(data).encode()).hexdigest()


def load(path: str) -> dict:
    if not os.path.exists(path):
        return {"version": 1, "tools": {}}
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ToolError("tool registry unreadable: %s" % exc) from exc
    if not isinstance(data, dict) or not isinstance(data.get("tools"), dict):
        raise ToolError("tool registry has no tools object")
    return data


def save(path: str, data: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def lock(name: str, schema_path: str, registry_path: str) -> dict:
    data = load(registry_path)
    digest = schema_hash(schema_path)
    data["tools"][str(name)] = {"path": os.path.abspath(schema_path),
                                "sha256": digest}
    save(registry_path, data)
    return {"tool": name, "sha256": digest, "path": os.path.abspath(schema_path)}


def verify(intent: dict, registry_path: str) -> dict:
    """Compare the tool on disk with the registry and with what was approved."""
    params = (intent.get("effect") or {}).get("params") or {}
    name = str(params.get("tool") or "")
    if not name:
        return {"ok": True, "checked": [], "drift": [], "skipped": "no tool named"}
    registry = load(registry_path)
    entry = (registry.get("tools") or {}).get(name)
    if not entry:
        return {"ok": False, "checked": [], "drift": [{
            "tool": name, "reason": "not in the tool registry"}]}
    live = schema_hash(str(entry.get("path") or ""))
    approved = str(params.get("schema_sha256") or "")
    drift = []
    if live != entry.get("sha256"):
        drift.append({"tool": name, "reason": "schema changed since it was locked",
                      "locked": entry.get("sha256"), "live": live})
    if approved and approved != live:
        drift.append({"tool": name, "reason": "the approval names a different schema",
                      "approved": approved, "live": live})
    return {"ok": not drift, "checked": [name], "drift": drift}


def enforce(intent: dict, registry_path: str) -> None:
    if not registry_path:
        return
    result = verify(intent, registry_path)
    if not result["ok"]:
        raise core.PolicyDenied("tool schema drift: %s"
                                % "; ".join(item["reason"] for item in result["drift"]))
