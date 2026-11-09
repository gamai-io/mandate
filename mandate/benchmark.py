"""Intent Divergence Benchmark (IDB) — deterministic gate evaluation.

Each scenario carries a proposed intent and the expected gate outcome
(`block`, `grant`, `allow`). The benchmark verifies that the Mandate policy +
provenance rules produce the expected decision. A model can be added later to
generate the intents at scale.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import core

EXPECTED = {"block": "deny", "grant": "ask", "allow": "allow"}


class BenchmarkError(core.MandateError):
    pass


def load_scenarios(path: str) -> list[dict]:
    scenarios = []
    try:
        fh = open(path, encoding="utf-8")
    except OSError as exc:
        raise BenchmarkError("cannot read scenarios: %s" % str(exc)[:120]) from exc
    with fh:
        for index, line in enumerate(fh):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise BenchmarkError("invalid scenario line %d" % (index + 1)) from exc
            if not isinstance(row, dict) or not isinstance(row.get("intent"), dict):
                raise BenchmarkError("scenario %d has no intent" % (index + 1))
            row.setdefault("id", "s%d" % (index + 1))
            row.setdefault("category", "general")
            if row.get("expected") not in EXPECTED:
                raise BenchmarkError("scenario %s has invalid expected" % row["id"])
            scenarios.append(row)
    return scenarios


def evaluate(scenario: dict, policy: dict) -> dict:
    expected = str(scenario["expected"])
    want = EXPECTED[expected]
    try:
        decision = core.check(scenario["intent"], policy)
        outcome = decision.get("decision")
        reason = decision.get("reason") or ""
        missing = decision.get("missing") or []
    except core.MandateError as exc:
        outcome = "deny"
        reason = type(exc).__name__
        missing = []
    return {
        "id": scenario.get("id"),
        "category": scenario.get("category"),
        "expected": expected,
        "decision": outcome,
        "reason": reason,
        "missing": missing,
        "ok": outcome == want,
    }


def run(scenarios: list[dict], policy: dict) -> dict:
    results = [evaluate(scenario, policy) for scenario in scenarios]
    by_category: dict[str, dict] = {}
    false_allow = 0
    false_block = 0
    injection_total = 0
    injection_false_allow = 0
    for row in results:
        category = str(row["category"])
        bucket = by_category.setdefault(category, {"total": 0, "ok": 0})
        bucket["total"] += 1
        if row["ok"]:
            bucket["ok"] += 1
        if row["expected"] == "block" and row["decision"] in ("allow", "ask"):
            false_allow += 1
            if category == "prompt_injection":
                injection_false_allow += 1
        if row["expected"] in ("allow", "grant") and row["decision"] == "deny":
            false_block += 1
        if category == "prompt_injection":
            injection_total += 1
    total = len(results)
    ok = sum(1 for row in results if row["ok"])
    metrics = {
        "total": total,
        "ok": ok,
        "failed": total - ok,
        "false_allow": false_allow,
        "false_block": false_block,
        "injection_total": injection_total,
        "pi_asr": (injection_false_allow / injection_total)
        if injection_total else 0.0,
        "by_category": by_category,
    }
    return {"metrics": metrics, "results": results}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mandate.benchmark")
    parser.add_argument("--scenarios", default="bench/scenarios/idb_v0.jsonl")
    parser.add_argument("--policy", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    try:
        scenarios = load_scenarios(args.scenarios)
        report = run(scenarios, core.load_policy(args.policy))
    except (core.MandateError, OSError, ValueError) as exc:
        print(json.dumps({"error": type(exc).__name__,
                          "message": str(exc)[:200]}, ensure_ascii=False))
        return 3
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 0 if report["metrics"]["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
