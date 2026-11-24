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


def ship(ledger_path: str, url: str, token: str = "", offset_path: str | None = None,
         batch: int = 200, dry_run: bool = False) -> dict:
    offset = 0
    if offset_path and os.path.exists(offset_path):
        try:
            offset = int(open(offset_path).read().strip() or 0)
        except ValueError:
            offset = 0
    records, new_offset = _read(ledger_path, offset)
    sent = 0
    for start in range(0, len(records), max(1, batch)):
        chunk = records[start:start + batch]
        if dry_run:
            sent += len(chunk)
            continue
        _post(url, token, chunk)
        sent += len(chunk)
    if offset_path and not dry_run:
        os.makedirs(os.path.dirname(os.path.abspath(offset_path)), exist_ok=True)
        with open(offset_path, "w") as fh:
            fh.write(str(new_offset))
    return {"records": len(records), "sent": sent, "offset": new_offset,
            "dry_run": dry_run}
