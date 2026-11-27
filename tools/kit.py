#!/usr/bin/env python3
"""Score any verifier against the conformance cases.

An auditor who writes their own verifier should not have to trust ours. This runs the
cases in `spec/kit/cases.json` through a verifier of their choosing and reports, per case,
whether the verdict is right and — for a rejection — which check failed first.

    python3 tools/kit.py --verifier "mandate --signers spec/kit/signers audit verify \
        --bundle {bundle} --log-signers spec/kit/log_signers"

Placeholders: {bundle} {signers} {log_signers}. The verifier must print one JSON object
on stdout; `valid` is required, and the per-check booleans (`envelope`, `sth`,
`inclusion`, `witness`) are used when present. Exit 0 = every case correct, 1 = mismatch,
2 = the kit itself could not run.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def failing_check(result: dict) -> str:
    """The first check that is not true, in the order a verifier performs it.

    The envelope reports its own parts (signature, receipt, inclusion), so a broken
    seal is named `signature` rather than the whole envelope.
    """
    envelope = result.get("envelope")
    if isinstance(envelope, dict):
        for name in ("signature", "receipt", "inclusion"):
            if envelope.get(name) is False:
                return name
    for name in ("sth", "inclusion", "witness"):
        value = result.get(name)
        if isinstance(value, dict):
            value = value.get("valid")
        if value is False:
            return name
    return "none"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verifier", required=True,
                    help="command template with {bundle} {signers} {log_signers}")
    ap.add_argument("--cases", default=str(ROOT / "spec" / "kit" / "cases.json"))
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("--badge", default=None,
                    help="write a conformance record (JSON) for a badge page")
    ap.add_argument("--name", default="", help="verifier name for the badge record")
    args = ap.parse_args(argv[1:])
    manifest = json.loads(pathlib.Path(args.cases).read_text(encoding="utf-8"))
    signers = str((ROOT / manifest["signers"]).resolve())
    log_signers = str((ROOT / manifest["log_signers"]).resolve())
    witness_signers = str((ROOT / manifest.get("witness_signers", manifest["log_signers"])).resolve())

    rows, failures = [], 0
    for case in manifest["cases"]:
        bundle = str((ROOT / case["bundle"]).resolve())
        command = (args.verifier.replace("{bundle}", bundle)
                   .replace("{signers}", signers)
                   .replace("{log_signers}", log_signers)
                   .replace("{witness_signers}", witness_signers))
        done = subprocess.run(shlex.split(command), capture_output=True, text=True,
                              timeout=120)
        try:
            result = json.loads(done.stdout.strip() or "{}")
        except json.JSONDecodeError:
            rows.append({"case": case["name"], "ok": False,
                         "why": "verifier did not print one JSON object",
                         "stdout": done.stdout[-200:], "stderr": done.stderr[-200:]})
            failures += 1
            continue
        valid = bool(result.get("valid"))
        expect_valid = bool(case.get("valid"))
        ok = valid == expect_valid
        why = ""
        if ok and not expect_valid and case.get("fails"):
            first = failing_check(result)
            ok = first == case["fails"]
            why = f"first failing check {first}, expected {case['fails']}"
        rows.append({"case": case["name"], "ok": ok, "valid": valid,
                     "expected": expect_valid, "why": why})
        failures += 0 if ok else 1

    if args.badge:
        import time as _time
        record = {
            "format": "mandate-conformance/1",
            "verifier": args.name or " ".join(shlex.split(args.verifier)[:2]),
            "passed": len(rows) - failures,
            "failed": failures,
            "total": len(rows),
            "ok": failures == 0,
            "checked_at": int(_time.time()),
            "cases": [{"case": r["case"], "ok": r["ok"]} for r in rows],
        }
        pathlib.Path(args.badge).write_text(json.dumps(record, indent=1), encoding="utf-8")
        colour = "brightgreen" if record["ok"] else "red"
        label = "mandate%20conformance"
        value = "%d%%2F%d" % (record["passed"], record["total"])
        print("![%s](https://img.shields.io/badge/%s-%s-%s)"
              % ("mandate conformance", label, value, colour))
        print("record: %s  (%d/%d)" % (args.badge, record["passed"], record["total"]))

    if args.json:
        print(json.dumps({"cases": rows, "failed": failures,
                          "total": len(rows)}, indent=1))
    else:
        width = max(len(r["case"]) for r in rows) + 2
        for row in rows:
            mark = "ok  " if row["ok"] else "FAIL"
            detail = "" if row["ok"] else row.get("why") or row.get("stderr", "")
            print(f"{mark} {row['case']:<{width}} valid={row.get('valid')} {detail}".rstrip())
        print(f"\n{len(rows) - failures}/{len(rows)} cases correct")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
