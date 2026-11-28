"""A SIEM connector that a bank can test, not just read about.

A CEF line is not a connector. What a SOC checks is: does the event arrive in the platform's schema,
does a failure retry instead of dropping, and can a gap be replayed without duplicating what was
already sent. This module does those three things:

  * **schema**: ECS (Elastic) and OCSF-style detection findings, plus the CEF/LEEF lines `detect`
    already produced;
  * **transport**: file (for tests and air-gapped relays), or HTTP with a Splunk HEC envelope;
  * **delivery**: retries with backoff, and a checkpoint of event ids so a re-run resumes instead of
    duplicating. `--resend` deliberately ignores the checkpoint for backfill.

The event id is the SHA-256 of the finding itself: the same alert has the same id across formats and
across runs, which is what makes deduplication possible on the receiving side too.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request

from . import detect

SEVERITY_ECS = {"high": 73, "medium": 47, "low": 21}
SEVERITY_OCSF = {"high": 4, "medium": 3, "low": 2}


def event_id(finding: dict) -> str:
    return hashlib.sha256(json.dumps(finding, sort_keys=True, ensure_ascii=False).encode()
                          ).hexdigest()


def to_ecs(finding: dict, agent: str = "") -> dict:
    """Elastic Common Schema: the fields a bank's saved searches already filter on."""
    evidence = finding.get("evidence") or {}
    return {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "ecs.version": "8.11",
        "event": {"kind": "alert", "category": ["iam"], "type": ["info"],
                  "action": str(finding.get("rule") or ""),
                  "severity": SEVERITY_ECS.get(str(finding.get("severity")), 30),
                  "id": event_id(finding)},
        "rule": {"name": str(finding.get("rule") or ""),
                 "ruleset": "mandate"},
        "message": json.dumps(evidence, ensure_ascii=False, sort_keys=True)[:900],
        "user": {"name": str(finding.get("agent") or agent or "unknown")},
        "mandate": {"severity": str(finding.get("severity") or ""),
                    "dora_class": (finding.get("dora") or {}).get("class", ""),
                    "evidence": evidence},
    }


def to_ocsf(finding: dict, agent: str = "") -> dict:
    """OCSF Detection Finding (class_uid 2004), the shape a lake expects."""
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "severity_id": SEVERITY_OCSF.get(str(finding.get("severity")), 1),
        "time": int(time.time() * 1000),
        "metadata": {"version": "1.3.0", "product": {"name": "gama-mandate", "vendor_name": "gamai"}},
        "finding_info": {"uid": event_id(finding), "title": str(finding.get("rule") or ""),
                         "types": ["agent_authorisation"]},
        "actor": {"user": {"name": str(finding.get("agent") or agent or "unknown")}},
        "unmapped": {"evidence": finding.get("evidence") or {},
                     "dora_class": (finding.get("dora") or {}).get("class", "")},
    }


def render(finding: dict, fmt: str = "jsonl", agent: str = "") -> str:
    if fmt == "cef":
        return detect.to_cef(finding)
    if fmt == "leef":
        return detect.to_leef(finding)
    if fmt == "ecs":
        return json.dumps(to_ecs(finding, agent), ensure_ascii=False, sort_keys=True)
    if fmt == "ocsf":
        return json.dumps(to_ocsf(finding, agent), ensure_ascii=False, sort_keys=True)
    return json.dumps(finding, ensure_ascii=False, sort_keys=True)


def collect(ledger_path: str, mcp_ledger: str = "", config: dict | None = None) -> list[dict]:
    """Findings from the ledger, through the same rules `mandate detect` uses."""
    res = detect.detect(ledger_path, config or detect.load_config(None),
                        tokens=[], mcp_ledger=mcp_ledger)
    return res.get("findings") or []


def load_checkpoint(path: str) -> set[str]:
    if not path or not os.path.exists(path):
        return set()
    out = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.add(line)
    return out


def append_checkpoint(path: str, ids: list[str]) -> None:
    if not path or not ids:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for item in ids:
            fh.write(item + "\n")


def _post(url: str, payload: bytes, token: str, headers: dict | None = None,
          timeout: int = 15) -> tuple[int, str]:
    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Splunk " + token)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, resp.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(400).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return 0, str(exc)[:200]


def send(events: list[str], url: str, token: str = "", batch: int = 50,
         retries: int = 3, index: str = "main", sourcetype: str = "mandate:alert",
         backoff: float = 1.0, dry_run: bool = False) -> dict:
    """POST in batches wrapped in a HEC envelope; retry 5xx and network errors, never 4xx."""
    sent, failed = 0, []
    batches = [events[i:i + batch] for i in range(0, len(events), max(1, batch))]
    for number, group in enumerate(batches):
        envelope = json.dumps({"index": index, "sourcetype": sourcetype,
                               "event": [json.loads(line) if line.lstrip().startswith("{")
                                         else line for line in group]}).encode("utf-8")
        if dry_run:
            sent += len(group)
            continue
        for attempt in range(max(1, retries)):
            status, body = _post(url, envelope, token)
            if 200 <= status < 300:
                sent += len(group)
                break
            if 400 <= status < 500:
                failed.append({"batch": number, "status": status, "body": body[:200]})
                break
            if attempt + 1 < retries:
                time.sleep(backoff * (2 ** attempt))
        else:
            failed.append({"batch": number, "status": "retries exhausted"})
    return {"batches": len(batches), "events": len(events), "sent": sent, "failed": failed}


def deliver(ledger_path: str, mcp_ledger: str = "", fmt: str = "jsonl", url: str = "",
            token: str = "", checkpoint: str = "", out: str = "", batch: int = 50,
            resend: bool = False, dry_run: bool = False) -> dict:
    findings = collect(ledger_path, mcp_ledger)
    lines = [render(finding, fmt) for finding in findings]
    ids = [event_id(finding) for finding in findings]
    already = set() if resend else load_checkpoint(checkpoint)
    fresh = [(line, ident) for line, ident in zip(lines, ids) if ident not in already]
    report = {"findings": len(findings), "already_sent": len(findings) - len(fresh),
              "to_send": len(fresh), "format": fmt}
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            for line, _ in fresh:
                fh.write(line + "\n")
        report["file"] = out
    if url:
        result = send([line for line, _ in fresh], url, token, batch=batch, dry_run=dry_run)
        report.update(result)
        if not dry_run and result["sent"]:
            append_checkpoint(checkpoint, [ident for _, ident in fresh][:result["sent"]])
    return report
