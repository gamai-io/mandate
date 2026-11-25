"""Per-agent credentials for the broker, so one token does not mean one identity.

Today the broker takes a single bearer token: every caller is "the agent" and the
ledger can only tell them apart by the grant they present. With this store each
agent gets its own token, the broker maps the token to a name, and a grant signed
for agent A cannot be redeemed with agent B's token.

The file keeps SHA-256 of each token, never the token, so a copy of the store does
not hand anyone a working credential. Tokens are printed once when created.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time


class AgentStoreError(Exception):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load(path: str, strict: bool = True) -> dict:
    if not path:
        return {"version": 1, "agents": []}
    if not os.path.exists(path):
        if strict:
            raise AgentStoreError("agent store %s does not exist" % path)
        return {"version": 1, "agents": []}
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AgentStoreError("agent store %s is unreadable: %s" % (path, exc)) from exc
    if not isinstance(data, dict) or not isinstance(data.get("agents"), list):
        raise AgentStoreError("agent store %s has no agents list" % path)
    for entry in data["agents"]:
        if not isinstance(entry, dict) or "name" not in entry or "sha256" not in entry:
            raise AgentStoreError("agent store %s has a malformed entry" % path)
    return data


def save(path: str, data: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def add(path: str, name: str, note: str = "") -> dict:
    name = str(name or "").strip()
    if not name:
        raise AgentStoreError("agent name is required")
    data = load(path, strict=False)
    for entry in data["agents"]:
        if entry["name"] == name:
            raise AgentStoreError("agent %r already has a token; revoke it first" % name)
    token = "mb_" + secrets.token_urlsafe(32)
    data["agents"].append({"name": name, "sha256": _hash(token), "note": note,
                           "created": int(time.time()), "revoked": False})
    save(path, data)
    return {"name": name, "token": token, "path": path,
            "warning": "shown once: only its sha256 is stored"}


def revoke(path: str, name: str) -> dict:
    data = load(path, strict=True)
    found = 0
    for entry in data["agents"]:
        if entry["name"] == name:
            entry["revoked"] = True
            found += 1
    save(path, data)
    return {"revoked": found, "name": name}


def resolve(path: str, token: str) -> str | None:
    """Token -> agent name, or None. Compared in constant time per entry."""
    if not token:
        return None
    try:
        data = load(path, strict=True)
    except AgentStoreError:
        return None
    for entry in data["agents"]:
        if entry.get("revoked"):
            continue
        if hmac.compare_digest(entry["sha256"], _hash(token)):
            return str(entry["name"])
    return None


def list_store(path: str) -> dict:
    """Strict load, for the CLI: a corrupt store must fail, not look empty."""
    return load(path, strict=True)


def names(path: str) -> list[dict]:
    data = load(path, strict=False)
    return [{"name": e["name"], "note": e.get("note", ""),
             "created": e.get("created"), "revoked": bool(e.get("revoked"))}
            for e in data["agents"]]
