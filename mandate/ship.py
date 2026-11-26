"""Ship ledger records to a SIEM (Splunk HEC or any JSON HTTP endpoint).

The bank's SIEM is where incidents are actually seen; a ledger nobody reads is
not monitoring. This is deliberately small:

  mandate ship --ledger L --url https://splunk:8088/services/collector \
      --token "$HEC" [--offset ship.state] [--batch 200]

- sends one JSON object per record (`{"event": <body>, "sourcetype": "mandate"}`);
- keeps a byte offset in a state file so a restart does not re-send or skip;
- refuses to advance the offset when the endpoint does not accept the batch
  (no silent loss, same fail-closed rule as the rest).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class ShipError(RuntimeError):
    pass


def _read(path: str, offset: int) -> tuple[list[dict], int]:
    if not os.path.exists(path):
        return [], offset
    out = []
    with open(path, "rb") as fh:
        fh.seek(offset)
        for line in fh:
            line = line.strip()
            if not line:
                offset += 1
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                raise ShipError("ledger line is not JSON at offset %d" % offset)
            offset += len(line) + 1
    return out, offset


def _post(url: str, token: str, payload: list[dict], timeout: int = 20) -> None:
    from .net import require_http
    url = require_http(url, "SIEM endpoint")
    body = "\n".join(json.dumps({"event": rec.get("body", rec),
                                 "sourcetype": "mandate",
                                 "time": rec.get("body", {}).get("ts")}, sort_keys=True)
                     for rec in payload).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Splunk " + token
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status >= 300:
                raise ShipError("SIEM answered %s" % resp.status)
    except urllib.error.HTTPError as exc:
        raise ShipError("SIEM rejected batch: HTTP %s" % exc.code) from exc
    except OSError as exc:
        raise ShipError("SIEM unreachable: %s" % str(exc)[:120]) from exc


def _load_offsets(path: str) -> dict:
    """State is per ledger: two ledgers must never share one byte counter."""
    if not path or not os.path.exists(path):
        return {}
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if isinstance(data, dict) and isinstance(data.get("offsets"), dict):
        return {str(k): int(v) for k, v in data["offsets"].items()}
    return {}


def _save_offsets(path: str, offsets: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "offsets": offsets}, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def ship(ledger_path: str, url: str, token: str = "", offset_path: str | None = None,
         batch: int = 200, dry_run: bool = False) -> dict:
    ledger_key = os.path.abspath(ledger_path)
    state_path = offset_path or (ledger_path + ".shipstate")
    offsets = _load_offsets(state_path)
    offset = offsets.get(ledger_key, 0)
    rotated = False
    if os.path.exists(ledger_path) and offset and \
            os.path.getsize(ledger_path) < offset:
        offset = 0          # the file was rotated or replaced: start from the top
        rotated = True
    records, new_offset = _read(ledger_path, offset)
    sent = 0
    for start in range(0, len(records), max(1, batch)):
        chunk = records[start:start + batch]
        if dry_run:
            sent += len(chunk)
            continue
        _post(url, token, chunk)
        sent += len(chunk)
    if not dry_run:
        offsets[ledger_key] = new_offset
        _save_offsets(state_path, offsets)
    return {"ledger": ledger_key, "records": len(records), "sent": sent,
            "offset": new_offset, "rotated": rotated, "state": state_path,
            "dry_run": dry_run}
