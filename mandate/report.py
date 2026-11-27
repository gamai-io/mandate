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
import fnmatch
import hashlib
import json
import os
import re
import shutil
import time
from collections import defaultdict

from . import sign
from .core import MandateError, append_receipt, read_ledger
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


TICKET_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,15}-[0-9]{1,9}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}(@[A-Za-z0-9._:/-]{1,80})?$")


def _ticket_problem(ticket: str) -> str:
    """A change without a ticket is an unrecorded change; a ticket that is not a ticket is a note."""
    if not ticket:
        return "ticket required: a change with no ticket id cannot be traced to an approval"
    if not TICKET_RE.match(ticket):
        return ("ticket %r does not look like PROJECT-123; a free-form string is not a ticket" % ticket)
    return ""


def change_record(ledger_path: str, path: str, approver: str, key_path: str,
                  reason: str, signer_cmd: str | None = None, ticket: str = "",
                  model: str = "", model_digest: str = "",
                  require_ticket: bool = False) -> dict:
    """Row 10: a change to a control file, hashed and signed by its approver.

    Carries the ticket that authorised it and, optionally, the model versions the change
    pins (`--model gpt-x@2026-11-01 --model-digest sha256:...`). Without a ticket the record
    proves *that* something changed, never *who asked for it* — so `--require-ticket` turns
    the warning into a refusal.
    """
    problem = _ticket_problem(ticket)
    if problem and require_ticket:
        raise MandateError(problem)
    if model and not MODEL_RE.match(model):
        raise MandateError("model %r is not name or name@version" % model)
    if model_digest and not (model_digest.startswith("sha256:") and len(model_digest) == 71):
        raise MandateError("model digest must be sha256:<64 hex>")
    raw = open(path, "rb").read()
    body = {
        "v": 1,
        "type": "control",
        "action": "change",
        "actor": approver,
        "reason": reason,
        "file": os.path.basename(path),
        "path": os.path.normpath(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "ts": int(time.time()),
        "ticket": ticket,
    }
    if problem:
        body["ticket_problem"] = problem
    if model:
        body["model"] = model
    if model_digest:
        body["model_digest"] = model_digest
    if signer_cmd:
        from . import signing as _signing
        signed = _signing.sign_with(signer_cmd, canonicalize(body))
        body["signature"] = signed["sig"]
        body["signer"] = signed["signer"] or approver
        body["signer_backend"] = "external"
    else:
        body["signature"] = sign.sign(canonicalize(body), key_path)
        body["signer"] = approver
    entry = append_receipt(ledger_path, body)
    return {"entry": entry["hash"], **body}


def changes(ledger_path: str, signers_path: str | None = None,
            ticket: str = "") -> dict:
    found = []
    for e in _entries(ledger_path):
        body = e.get("body") or {}
        if body.get("type") == "control" and body.get("action") == "change":
            if ticket and body.get("ticket") != ticket:
                continue
            item = {k: body.get(k) for k in
                    ("file", "path", "sha256", "bytes", "actor", "reason", "ts", "signer",
                     "ticket", "ticket_problem", "model", "model_digest")}
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


def drift(ledger_path: str, root: str, signers_path: str | None = None,
          include: tuple[str, ...] = ("*.json", "*.yaml", "*.yml", "*.toml", "*.ini", "*.conf",
                                      "*.cfg", "*.py")) -> dict:
    """Is the control file on disk still the one someone signed for?

    Change control fails quietly in one way: a file gets edited and nobody records it. This
    compares the newest signed change per file against the bytes on disk and calls the
    difference `unrecorded_change`. A file that was never recorded is reported separately
    (`untracked`) — that is a gap in the process, not a tamper.
    """
    latest: dict[str, dict] = {}
    for item in changes(ledger_path, signers_path)["changes"]:
        key = item.get("path") or item.get("file")
        if not key:
            continue
        # `>=`: two records in the same second are decided by ledger order, and the later
        # entry is the later decision. `>` silently kept the older one and reported drift
        # right after a correct re-record.
        if key not in latest or float(item.get("ts") or 0) >= float(latest[key].get("ts") or 0):
            latest[key] = item
    rows, problems = [], []
    for key, item in sorted(latest.items()):
        candidate = key if os.path.isabs(key) else os.path.join(root, os.path.basename(key))
        if not os.path.exists(candidate):
            rows.append({"file": os.path.basename(key), "state": "missing",
                         "recorded": item.get("sha256")})
            problems.append("missing: %s" % os.path.basename(key))
            continue
        now = hashlib.sha256(open(candidate, "rb").read()).hexdigest()
        state = "ok" if now == item.get("sha256") else "unrecorded_change"
        rows.append({"file": os.path.basename(key), "state": state,
                     "recorded": item.get("sha256"), "current": now,
                     "ticket": item.get("ticket"), "actor": item.get("actor")})
        if state != "ok":
            problems.append("unrecorded change: %s (recorded %s, now %s)" % (
                os.path.basename(key), str(item.get("sha256"))[:12], now[:12]))
    untracked = []
    if os.path.isdir(root):
        known = {os.path.basename(key) for key in latest}
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if not os.path.isfile(full) or name in known or name.startswith("."):
                continue
            # samo konfiguracioni fajlovi: ključevi i ledger nisu "zaboravljeni", oni nisu kontrola
            if include and not any(fnmatch.fnmatch(name, pat) for pat in include):
                continue
            untracked.append(name)
    return {"ok": not problems, "code": "ok" if not problems else "drift",
            "checked": len(rows), "files": rows, "problems": problems[:10],
            "untracked": untracked[:20],
            "note": ("untracked files are a process gap, not a tamper; recorded files are the "
                     "ones whose bytes were signed")}


def pinned_models(ledger_path: str) -> dict:
    """What model versions the change records pin, newest first per model."""
    out: dict[str, dict] = {}
    for item in changes(ledger_path)["changes"]:
        name = item.get("model")
        if not name:
            continue
        # jedan model, jedna linija: verzija je vrijednost, ne ključ
        key = name.split("@")[0]
        stamp = float(item.get("ts") or 0)
        if key not in out or stamp >= out[key]["ts"]:
            out[key] = {"model": name, "digest": item.get("model_digest") or "",
                         "ts": int(stamp), "ticket": item.get("ticket") or "",
                         "file": item.get("file") or "", "actor": item.get("actor") or ""}
    return {"count": len(out), "models": sorted(out.values(), key=lambda m: -m["ts"])}


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
         controls_path: str | None = None,
         signers_path: str | None = None,
         anchors_dir: str | None = None,
         sign_key: str | None = None, signer: str | None = None,
         grants: list[str] | None = None,
         intents: list[str] | None = None) -> dict:
    """Row 11: everything an auditor asks for, generated from the ledger.

    The pack now carries the ledger itself, the anchors, and (optionally) a
    signature over its own index — otherwise the index is just a text file that
    anyone could rewrite.
    """
    os.makedirs(out_dir, exist_ok=True)
    for stale in os.listdir(out_dir):   # never bless a file we did not generate now
        path = os.path.join(out_dir, stale)
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    inv = inventory(ledger_path, tokens, owners)
    with open(os.path.join(out_dir, "inventory.json"), "w", encoding="utf-8") as fh:
        json.dump(inv, fh, indent=1, sort_keys=True)
    write_inventory_csv(inv, os.path.join(out_dir, "inventory.csv"))

    chg = changes(ledger_path, signers_path)
    with open(os.path.join(out_dir, "changes.json"), "w", encoding="utf-8") as fh:
        json.dump(chg, fh, indent=1, sort_keys=True)

    # the evidence the pack talks about, so a reviewer does not have to trust us
    if os.path.exists(ledger_path):
        shutil.copy2(ledger_path, os.path.join(out_dir, "ledger.jsonl"))
        if os.path.exists(ledger_path + ".head"):
            shutil.copy2(ledger_path + ".head", os.path.join(out_dir, "ledger.jsonl.head"))
    if anchors_dir and os.path.isdir(anchors_dir):
        target = os.path.join(out_dir, "anchors")
        os.makedirs(target, exist_ok=True)
        for name in sorted(os.listdir(anchors_dir)):
            src = os.path.join(anchors_dir, name)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(target, name))

    # the artefacts behind the receipts: an auditor asks "who approved X", which a
    # hash in a chain cannot answer without the grant that carries the signature
    for folder, paths in (("grants", grants or []), ("intents", intents or [])):
        if not paths:
            continue
        target = os.path.join(out_dir, folder)
        os.makedirs(target, exist_ok=True)
        for index, path in enumerate(paths, start=1):
            if not os.path.isfile(path):
                raise MandateError("pack: %s is missing" % path)
            shutil.copy2(path, os.path.join(target, "%02d-%s" % (index,
                                                                 os.path.basename(path))))

    dec = decisions(ledger_path)
    with open(os.path.join(out_dir, "decisions.json"), "w", encoding="utf-8") as fh:
        json.dump(dec, fh, indent=1, sort_keys=True)

    with open(os.path.join(out_dir, "dora_roi.json"), "w", encoding="utf-8") as fh:
        json.dump(DORA_ROI, fh, indent=1, sort_keys=True)

    # row 11: the three things a supplier questionnaire asks for that are not the ledger
    from . import controls as _controls
    try:
        version = __import__("mandate").__version__
    except Exception:  # noqa: BLE001
        version = ""
    for name, payload in (
            ("subprocessors.json", _controls.subprocessors()),
            ("contract_clauses.json", _controls.contract_clauses()),
            ("dd_answers.json", _controls.dd_answers(version))):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True, ensure_ascii=False)

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
    anchors_dir_out = os.path.join(out_dir, "anchors")
    if os.path.isdir(anchors_dir_out):
        for name in sorted(os.listdir(anchors_dir_out)):
            full = os.path.join(anchors_dir_out, name)
            if os.path.isfile(full):
                files["anchors/" + name] = {
                    "sha256": hashlib.sha256(open(full, "rb").read()).hexdigest(),
                    "bytes": os.path.getsize(full)}

    for folder in ("grants", "intents"):
        full_dir = os.path.join(out_dir, folder)
        if not os.path.isdir(full_dir):
            continue
        for name in sorted(os.listdir(full_dir)):
            full = os.path.join(full_dir, name)
            if os.path.isfile(full):
                files["%s/%s" % (folder, name)] = {
                    "sha256": hashlib.sha256(open(full, "rb").read()).hexdigest(),
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
    if sign_key:
        from . import sign as _sign
        index["signature"] = _sign.sign(canonicalize(index), sign_key)
        index["signer"] = signer or ""
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1, sort_keys=True)
    return {"path": out_dir, "index": os.path.join(out_dir, "index.json"), **index}


def backup(ledger_path: str, out_dir: str, anchors_dir: str | None = "anchors") -> dict:
    """A restorable copy of the evidence: ledger, head, anchors + a hash manifest."""
    import tarfile
    os.makedirs(out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    name = f"mandate-backup-{stamp}.tar.gz"
    archive = os.path.join(out_dir, name)
    members = [p for p in (ledger_path, ledger_path + ".head") if os.path.exists(p)]
    if anchors_dir and os.path.isdir(anchors_dir):
        members += [os.path.join(anchors_dir, f) for f in sorted(os.listdir(anchors_dir))
                    if os.path.isfile(os.path.join(anchors_dir, f))]
    with tarfile.open(archive, "w:gz") as tf:
        for path in members:
            tf.add(path, arcname=os.path.basename(path) if not path.startswith(anchors_dir or "")
                   else os.path.join("anchors", os.path.basename(path)))
    manifest = {
        "created_at": int(time.time()),
        "ledger": os.path.basename(ledger_path),
        "ledger_head": open(ledger_path + ".head").read().strip()
        if os.path.exists(ledger_path + ".head") else "",
        "members": {os.path.basename(p): hashlib.sha256(open(p, "rb").read()).hexdigest()
                    for p in members},
        "archive_name": name,
        "archive_sha256": hashlib.sha256(open(archive, "rb").read()).hexdigest(),
    }
    manifest_path = os.path.join(out_dir, name.replace(".tar.gz", ".manifest.json"))
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    return {"archive": archive, "manifest": manifest_path, **manifest}


def restore(archive_path: str, out_dir: str) -> dict:
    """Extract a backup and verify every hash and the chain before reporting ok."""
    import tarfile
    manifest_path = archive_path.replace(".tar.gz", ".manifest.json")
    manifest = json.load(open(manifest_path, encoding="utf-8")) if os.path.exists(manifest_path) else {}
    os.makedirs(out_dir, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as tf:
        members = []
        for member in tf.getmembers():
            name = member.name.replace("\\", "/")
            if os.path.isabs(name) or ".." in name.split("/"):
                raise MandateError("archive member escapes the target: %r" % member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise MandateError("archive member is a link or device: %r"
                                   % member.name)
            members.append(member)
        tf.extractall(out_dir, members=members)
    problems = []
    for name, want in (manifest.get("members") or {}).items():
        found = None
        for root, _dirs, files in os.walk(out_dir):
            if name in files:
                found = os.path.join(root, name)
                break
        if not found:
            problems.append(f"missing: {name}")
            continue
        got = hashlib.sha256(open(found, "rb").read()).hexdigest()
        if got != want:
            problems.append(f"hash mismatch: {name}")
    ledger = None
    for root, _dirs, files in os.walk(out_dir):
        if (manifest.get("ledger") or "ledger.jsonl") in files:
            ledger = os.path.join(root, manifest.get("ledger") or "ledger.jsonl")
    chain_ok = bool(ledger) and _verify_chain(ledger)
    return {"ok": not problems and chain_ok, "restored_to": out_dir, "ledger": ledger,
            "chain_valid": chain_ok, "problems": problems}


def _verify_chain(path: str) -> bool:
    from .core import verify_chain
    try:
        return bool(verify_chain(path))
    except Exception:
        return False


def sbom(app_version: str = "", out_path: str = "sbom.json") -> dict:
    """Minimal CycloneDX SBOM: one component, zero runtime dependencies."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = {}
    for name in ("LICENSE", "README.md", "pyproject.toml"):
        path = os.path.join(here, name)
        if os.path.exists(path):
            files[name] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "component": {"type": "library", "name": "gama-mandate",
                                   "version": app_version or "unknown",
                                   "licenses": [{"license": {"id": "MIT"}}],
                                   "purl": f"pkg:pypi/gama-mandate@{app_version or 'unknown'}"}},
        "components": [],
        "properties": [{"name": "runtime_dependencies", "value": "0"}],
        "files": [{"name": n, "hashes": [{"alg": "SHA-256", "content": h}]}
                  for n, h in files.items()],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    return {"path": out_path, "component": "gama-mandate", "dependencies": 0,
            "files": len(files)}


def payee_history(ledger_path: str, target: str, kind: str = "") -> dict:
    """Has this bank ever paid this beneficiary before?

    A first-time payee approved by a human is the shape of the memory-poisoning
    incidents: the instruction is planted weeks earlier, so the approver signs a
    payee that looks ordinary. Counting prior payments turns that into a question
    the human can answer.
    """
    from . import normalize as _normalize
    want = _normalize.fold(target)
    first = last = None
    count = 0
    aliases = set()
    for entry in _entries(ledger_path):
        body = entry.get("body") or {}
        if body.get("type") != "receipt":
            continue
        # receipts carry the rendered effect; older ones carry the intent
        fields = ((body.get("render") or {}).get("fields")
                  or ((body.get("intent") or {}).get("effect")) or {})
        seen = str(fields.get("target") or "")
        # NORMALIZE_V1: „Аpple" (ćirilično А) i „Apple\u200b" su isti primalac
        if _normalize.fold(seen) != want:
            continue
        if seen != str(target):
            aliases.add(seen)
        if kind and str(fields.get("kind") or "") != str(kind):
            continue
        count += 1
        ts = int(body.get("ts") or 0)
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
    return {"target": str(target), "kind": kind or "", "payments": count,
            "first_ts": first, "last_ts": last, "first_time": count == 0}


def decisions(ledger_path: str) -> dict:
    """How long a human took to decide. The number nobody can produce in minutes."""
    waited = []
    approved = rejected = 0
    for entry in _entries(ledger_path):
        body = entry.get("body") or {}
        if body.get("type") != "approval":
            continue
        if body.get("decision") == "approved":
            approved += 1
        else:
            rejected += 1
        if body.get("waited_s") is not None:
            waited.append(float(body["waited_s"]))
    waited.sort()

    def percentile(values: list[float], q: float) -> float | None:
        if not values:
            return None
        index = min(len(values) - 1, max(0, int(round(q * (len(values) - 1)))))
        return round(values[index], 1)

    return {"ledger": ledger_path, "approved": approved, "rejected": rejected,
            "decisions": approved + rejected,
            "median_wait_s": percentile(waited, 0.5),
            "p95_wait_s": percentile(waited, 0.95),
            "max_wait_s": round(max(waited), 1) if waited else None,
            "note": "wait is measured from the request arriving to the decision"}


def observe_summary(ledger_path: str) -> dict:
    """What would have run: observe-mode receipts against real executions.

    Observation is free and does not spend a grant, so the same grant may appear
    as observed and later as executed. The useful number for a risk committee is
    how often the observe mode would have allowed something nobody then executed.
    """
    by_kind: dict[str, dict[str, int]] = defaultdict(lambda: {"observe": 0, "executed": 0,
                                                              "other": 0})
    observed: dict[str, dict] = {}
    executed: set[str] = set()
    for body in _receipts(_entries(ledger_path)):
        kind = str(((body.get("intent") or {}).get("effect") or {}).get("kind") or "?")
        decision = str(body.get("decision") or "")
        nonce = str(body.get("grant_nonce") or "")
        if decision == "observe" or body.get("binding") is False:
            by_kind[kind]["observe"] += 1
            if nonce and nonce not in observed:
                observed[nonce] = {"kind": kind, "ts": body.get("ts"),
                                   "amount": ((body.get("intent") or {}).get("effect")
                                              or {}).get("amount"),
                                   "agent": body.get("agent")}
        elif decision in ("", "executed", "allowed"):
            by_kind[kind]["executed"] += 1
            if nonce:
                executed.add(nonce)
        else:
            by_kind[kind]["other"] += 1
    unexecuted = {nonce: item for nonce, item in observed.items() if nonce not in executed}
    total_observe = sum(v["observe"] for v in by_kind.values())
    total_executed = sum(v["executed"] for v in by_kind.values())
    return {
        "ledger": ledger_path,
        "observations": total_observe,
        "executions": total_executed,
        "by_kind": dict(sorted(by_kind.items())),
        "observed_not_executed": unexecuted,
        "note": ("observation does not spend a grant; a grant seen only as observed was "
                 "never executed in this ledger"),
    }
