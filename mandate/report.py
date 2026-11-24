"""Audit reporting: agent inventory, change records, and a DORA-style evidence pack.

Rows 1, 10 and 11 of the control matrix are not runtime controls — they are the
documents an auditor asks for. They are generated from the ledger, so they cannot
drift away from what actually happened.

  mandate inventory --ledger L --out inventory.json      # row 1: who exists
  mandate change record --ledger L --file policy.json \
      --approver ops --key ops_key --reason "limit raise"  # row 10: what changed
  mandate pack --ledger L --out audit-pack               # row 11: what an auditor gets
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import time
from collections import defaultdict

from . import sign
from .core import append_receipt, read_ledger
from .jcs import canonicalize


def _entries(ledger_path: str) -> list[dict]:
    if not os.path.exists(ledger_path):
        return []
    return read_ledger(ledger_path)


def _receipts(entries: list[dict]) -> list[dict]:
    return [e["body"] for e in entries if (e.get("body") or {}).get("type") == "receipt"]


def _scopes(tokens: list[dict] | None) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for token in tokens or []:
        payload = (token or {}).get("payload") or {}
        subject = payload.get("sub")
        if subject:
            out[subject].update(payload.get("scopes") or [])
    return out


def inventory(ledger_path: str, tokens: list[dict] | None = None,
              owners: dict[str, str] | None = None) -> dict:
    """Row 1: one record per agent, derived from what the ledger shows."""
    receipts = _receipts(_entries(ledger_path))
    scopes = _scopes(tokens)
    agents: dict[str, dict] = {}
    for r in receipts:
        agent = str(r.get("agent") or "unknown")
        rec = agents.setdefault(agent, {
            "agent": agent, "owner": (owners or {}).get(agent, ""),
            "effects": 0, "kinds": set(), "approvers": set(),
            "first_seen": None, "last_seen": None, "amount_total": 0.0})
        rec["effects"] += 1
        fields = (r.get("render") or {}).get("fields") or {}
        kind = fields.get("kind")
        if kind:
            rec["kinds"].add(str(kind))
        if r.get("approver"):
            rec["approvers"].add(str(r["approver"]))
        ts = float(r.get("ts") or 0)
        rec["first_seen"] = ts if rec["first_seen"] is None else min(rec["first_seen"], ts)
        rec["last_seen"] = ts if rec["last_seen"] is None else max(rec["last_seen"], ts)
        amount = (fields.get("amount") or {}).get("value")
        try:
            rec["amount_total"] += float(amount or 0)
        except (TypeError, ValueError):
            pass
    rows = []
    for agent, rec in sorted(agents.items()):
        rows.append({
            **rec,
            "kinds": sorted(rec["kinds"]),
            "approvers": sorted(rec["approvers"]),
            "scopes": sorted(scopes.get(agent, [])),
            "first_seen": rec["first_seen"],
            "last_seen": rec["last_seen"],
            "amount_total": round(rec["amount_total"], 2),
        })
    return {"generated_at": int(time.time()), "agents": rows, "count": len(rows),
            "receipts": len(receipts)}


def write_inventory_csv(inv: dict, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["agent", "owner", "effects", "kinds", "approvers",
                         "scopes", "first_seen", "last_seen", "amount_total"])
        for a in inv["agents"]:
            writer.writerow([a["agent"], a["owner"], a["effects"], ";".join(a["kinds"]),
                             ";".join(a["approvers"]), ";".join(a["scopes"]),
                             a["first_seen"], a["last_seen"], a["amount_total"]])


def change_record(ledger_path: str, path: str, approver: str, key_path: str,
                  reason: str) -> dict:
    """Row 10: a change to a control file, hashed and signed by its approver."""
    raw = open(path, "rb").read()
    body = {
        "v": 1,
        "type": "control",
        "action": "change",
        "actor": approver,
        "reason": reason,
        "file": os.path.basename(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "ts": int(time.time()),
    }
    body["signature"] = sign.sign(canonicalize(body), key_path)
    body["signer"] = approver
    entry = append_receipt(ledger_path, body)
    return {"entry": entry["hash"], **body}


def changes(ledger_path: str, signers_path: str | None = None) -> dict:
    found = []
    for e in _entries(ledger_path):
        body = e.get("body") or {}
        if body.get("type") == "control" and body.get("action") == "change":
            item = {k: body.get(k) for k in
                    ("file", "sha256", "bytes", "actor", "reason", "ts", "signer")}
            item["entry"] = e.get("hash")
            if signers_path and body.get("signature"):
                signed = {k: v for k, v in body.items()
                          if k not in ("prev", "signature", "signer")}
                item["signature_valid"] = bool(
                    sign.verify(canonicalize(signed), body.get("signer") or "",
                                body.get("signature") or "", signers_path,
                                sign.DEFAULT_NAMESPACE))
            found.append(item)
    return {"count": len(found), "changes": found}


DORA_ROI = {
    "service": "Agent authorisation and evidence layer (gama-mandate)",
    "provider": "GAMA TRADE d.o.o. / gamAI, Usora, Bosnia and Herzegovina",
    "data_location": "on-premises at the client; no data leaves the client environment",
    "subcontracting": "none",
    "reliance": "important",
    "exit_plan": "Apache-2.0 code and published format; the client can keep running the ledger "
                 "and verifier without the provider",
    "audit_rights": "offline verification with the published verifier; full source access",
    "security_evidence": "hash-chained ledger, RFC 3161 anchors, signed change records",
}


def pack(ledger_path: str, out_dir: str, tokens: list[dict] | None = None,
         owners: dict[str, str] | None = None,
         controls_path: str | None = None) -> dict:
    """Row 11: everything an auditor asks for, generated from the ledger."""
    os.makedirs(out_dir, exist_ok=True)
    inv = inventory(ledger_path, tokens, owners)
    with open(os.path.join(out_dir, "inventory.json"), "w", encoding="utf-8") as fh:
        json.dump(inv, fh, indent=1, sort_keys=True)
    write_inventory_csv(inv, os.path.join(out_dir, "inventory.csv"))

    chg = changes(ledger_path)
    with open(os.path.join(out_dir, "changes.json"), "w", encoding="utf-8") as fh:
        json.dump(chg, fh, indent=1, sort_keys=True)

    with open(os.path.join(out_dir, "dora_roi.json"), "w", encoding="utf-8") as fh:
        json.dump(DORA_ROI, fh, indent=1, sort_keys=True)

    head = ""
    head_path = ledger_path + ".head"
    if os.path.exists(head_path):
        head = open(head_path).read().strip()

    if controls_path and os.path.exists(controls_path):
        text = open(controls_path, encoding="utf-8").read()
        open(os.path.join(out_dir, "controls.md"), "w", encoding="utf-8").write(text)

    files = {}
    for name in sorted(os.listdir(out_dir)):
        full = os.path.join(out_dir, name)
        if os.path.isfile(full) and name != "index.json":
            files[name] = {"sha256": hashlib.sha256(open(full, "rb").read()).hexdigest(),
                           "bytes": os.path.getsize(full)}

    index = {
        "generated_at": int(time.time()),
        "ledger_head": head,
        "ledger_entries": len(_entries(ledger_path)),
        "agents": inv["count"],
        "changes": chg["count"],
        "files": files,
        "how_to_verify": [
            "mandate chain --ledger <ledger.jsonl>",
            "mandate anchor-verify --ledger <ledger.jsonl> --token <anchors/*.tsr>",
            "sha256sum -c <index.json hashes>",
        ],
        "note": ("this pack is generated from the ledger, not written by hand; if a number "
                 "here disagrees with the ledger, the ledger wins"),
    }
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1, sort_keys=True)
    return {"path": out_dir, "index": os.path.join(out_dir, "index.json"), **index}
