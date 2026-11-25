"""Integrity of the files an agent trusts before it does anything.

The 2025-2026 supply-chain worms (Mini Shai-Hulud, Miasma) did not attack a model.
They edited the configuration files that AI coding assistants read to decide what
to trust: settings, MCP server lists, instruction files. An agent cannot tell a
backdoored dependency from a real one if the only thing checking is the agent.

So the files are pinned by hash, in the same ledger as receipts, and checked before
the agent starts. Drift is reported with the file and the reason; nothing is
rewritten silently.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import time

from . import core

WATCHED = (
    ".mcp.json", "mcp.json", "settings.json", "settings.local.json",
    "CLAUDE.md", "AGENTS.md", ".claude/settings.json", ".cursor/mcp.json",
    ".cursorrules", ".windsurf/mcp.json", ".continue/config.json",
)


class ConfigError(core.MandateError):
    pass


def _digest(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def expand(paths: list[str], directories: list[str] | None = None) -> list[str]:
    """Paths given explicitly, plus the usual suspects inside each directory."""
    found: list[str] = []
    for item in paths or []:
        found.extend(sorted(glob.glob(os.path.expanduser(str(item)))))
    for directory in directories or []:
        base = os.path.expanduser(str(directory))
        for name in WATCHED:
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate):
                found.append(candidate)
        for pattern in ("*/SKILL.md", "skills/*/SKILL.md", ".claude/skills/*/SKILL.md"):
            found.extend(sorted(glob.glob(os.path.join(base, pattern))))
    seen, unique = set(), []
    for path in found:
        absolute = os.path.abspath(path)
        if absolute not in seen and os.path.isfile(absolute):
            seen.add(absolute)
            unique.append(absolute)
    return unique


def lock(paths: list[str], store: str, directories: list[str] | None = None) -> dict:
    files = {}
    for path in expand(paths, directories):
        files[path] = {"sha256": _digest(path), "size": os.path.getsize(path)}
    if not files:
        raise ConfigError("no files to lock (nothing matched)")
    data = {"version": 1, "locked": int(time.time()), "files": files}
    directory = os.path.dirname(os.path.abspath(store))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = store + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    os.replace(tmp, store)
    return {"store": store, "files": len(files), "paths": sorted(files)}


def load(store: str) -> dict:
    if not os.path.exists(store):
        raise ConfigError("no config lock at %s; run 'mandate config lock' first"
                          % store)
    try:
        data = json.load(open(store, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError("config lock unreadable: %s" % exc) from exc
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise ConfigError("config lock has no files object")
    return data


def check(store: str, ledger: str | None = None) -> dict:
    data = load(store)
    drift, missing, ok = [], [], 0
    for path, entry in sorted((data.get("files") or {}).items()):
        if not os.path.isfile(path):
            missing.append({"path": path, "reason": "file is gone"})
            continue
        live = _digest(path)
        if live != entry.get("sha256"):
            drift.append({"path": path, "reason": "hash changed",
                          "locked": entry.get("sha256"), "live": live})
            continue
        ok += 1
    result = {"ok": not drift and not missing, "unchanged": ok,
              "drift": drift, "missing": missing, "checked": len(data.get("files") or {})}
    if ledger:
        core.append_receipt(ledger, {
            "v": 1, "type": "control", "action": "config_check",
            "ok": result["ok"], "unchanged": ok,
            "drift": [d["path"] for d in drift],
            "missing": [m["path"] for m in missing], "ts": int(time.time())})
    return result
