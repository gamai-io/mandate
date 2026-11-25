#!/usr/bin/env python3
"""Reproduce the ledger numbers in docs/PERFORMANCE.md.

    python3 tools/bench_ledger.py            # 10,000 receipts
    python3 tools/bench_ledger.py --count 2000

Measures append (flat cost is the point), chain verification and pack building on
this machine. Nothing is mocked: it uses the same core functions the broker uses.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mandate import core, report  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10000)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    directory = tempfile.mkdtemp(prefix="mandate-bench-")
    key = os.path.join(directory, "k")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key],
                   check=True)
    ledger = os.path.join(directory, "ledger.jsonl")
    intent = core.normalize_intent({
        "v": 1, "actor": {"agent": "bench", "session": "s"},
        "effect": {"kind": "payment.send", "target": "X",
                   "amount": {"value": 10.0, "currency": "BAM"}},
        "requested_by": "ops", "nonce": "n0",
        "provenance": [{"type": "data_ref", "source": "erp:x"}]})
    grant_core = core.build_grant_core(
        core.intent_commitment(intent), "approver", ttl_s=600,
        render_hash=core.render_hash(intent), agent="bench", audience="b")
    start = time.perf_counter()
    for i in range(args.count):
        intent["nonce"] = "n%d" % i
        core.append_receipt(ledger, core.build_receipt(
            intent, grant_core, "sha256:" + core.sha256(str(i)),
            core.sha256(str(i)), ts=1795600000 + i))
    append = time.perf_counter() - start
    size = os.path.getsize(ledger)
    start = time.perf_counter()
    chain_ok = core.verify_chain(ledger, anchor=True)
    chain = time.perf_counter() - start
    start = time.perf_counter()
    pack = report.pack(ledger, os.path.join(directory, "pack"))
    pack_s = time.perf_counter() - start
    print(json.dumps({
        "receipts": args.count,
        "append_s": round(append, 1),
        "ms_per_receipt": round(append / max(args.count, 1) * 1000, 2),
        "ledger_mb": round(size / 1e6, 1),
        "chain_ok": chain_ok,
        "chain_s": round(chain, 2),
        "pack_s": round(pack_s, 2),
        "pack_files": len(pack.get("files") or []),
        "directory": directory if args.keep else "(removed)",
    }, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
