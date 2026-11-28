#!/usr/bin/env python3
"""Publish our release log: entries from PyPI, a signed checkpoint, proofs, and a browser page.

Every artifact we ship is a leaf: tag, filename, sha256, size, upload time. The log is rebuilt from
PyPI's own metadata, so an entry cannot disagree with what the registry serves without the hash
changing. The checkpoint is signed with a log key kept at ~/.mandate_tlog_key (0600) and is
later timestamped by an RFC 3161 authority, which is what stops us from rewriting history quietly.

    python3 tools/publish_tlog.py --site-dir /opt/gama-harness/site/tlog --versions 1.0.7 1.0.8 1.0.9 1.0.10 1.0.11
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from mandate import core, tlog  # noqa: E402

KEY = os.environ.get("MANDATE_TLOG_KEY", os.path.expanduser("~/.mandate_tlog_key"))


def fetch(version: str) -> list[dict]:
    url = "https://pypi.org/pypi/gama-mandate/%s/json" % version
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.load(resp)
    rows = []
    for item in data.get("urls") or []:
        rows.append({
            "release": version,
            "file": item["filename"],
            "sha256": item["digests"]["sha256"],
            "bytes": int(item["size"]),
            "uploaded": item.get("upload_time_iso_8601") or "",
            "url": item["url"],
        })
    return rows


def ensure_key() -> str:
    if not os.path.exists(KEY):
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "mandate-tlog", "-f", KEY],
                       check=True, capture_output=True)
        os.chmod(KEY, 0o600)
    return KEY


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-dir", default="/opt/gama-harness/site/tlog")
    ap.add_argument("--versions", nargs="+", required=True)
    ap.add_argument("--out-json", default=None, help="also write the log here")
    args = ap.parse_args()
    entries = []
    for version in args.versions:
        rows = fetch(version)
        if not rows:
            print("no files for %s (skipped)" % version, file=sys.stderr)
        entries.extend(rows)
    if not entries:
        print("nothing to publish", file=sys.stderr)
        return 2
    payloads = [core.jcs(e).encode() for e in entries]
    key = ensure_key()
    log = tlog.build(payloads, sign_key=key, signer="mandate-log")
    proofs = {"format": "mandate-tlog-proofs/1", "size": log["size"], "root": log["root"],
              "proofs": {str(i): tlog.inclusion_proof(payloads, i)
                         for i in range(len(payloads))}}
    site = pathlib.Path(args.site_dir)
    site.mkdir(parents=True, exist_ok=True)
    (site / "log.json").write_text(json.dumps(log, indent=1, sort_keys=True), encoding="utf-8")
    (site / "proofs.json").write_text(json.dumps(proofs, indent=1, sort_keys=True),
                                      encoding="utf-8")
    (site / "checkpoint.json").write_text(json.dumps(log["checkpoint"], indent=1, sort_keys=True),
                                          encoding="utf-8")
    anchors = site / "anchors"
    if anchors.is_dir():
        index = []
        for side in sorted(anchors.glob("*.json")):
            try:
                data = json.loads(side.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if data.get("root") == log["root"]:
                index.append({"token": data.get("token"), "tsa": data.get("tsa"),
                              "gen_time": data.get("gen_time"), "digest": data.get("digest")})
        (site / "anchors.json").write_text(json.dumps({"anchors": index}, indent=1,
                                                      sort_keys=True), encoding="utf-8")
    if args.out_json:
        pathlib.Path(args.out_json).write_text(json.dumps(log, indent=1, sort_keys=True),
                                               encoding="utf-8")
    print(json.dumps({"entries": log["size"], "root": log["root"],
                      "checkpoint": site / "checkpoint.json",
                      "public_key": log["checkpoint"]["public_key"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
