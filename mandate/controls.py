"""The control matrix, as data a procurement person can paste.

`docs/BANK_CONTROL_MATRIX.md` is the reasoning; this module is the same twelve rows in a
shape that can be printed, filtered and quoted in a supplier questionnaire. Each row says
what exists, what is still missing and who owns the next step — because "we have it" with no
named artifact is the answer that gets a vendor thrown out.

Status values are deliberately blunt:

    have     shipped and tested; an auditor can look at it today
    partial  exists, but not to the standard a supervisor would accept
    gap      not built

The matrix is research, not legal advice; article numbers must be checked with counsel
before they appear in a customer document.
"""
from __future__ import annotations

import json
import os

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "controls.json")
ALIASES = {"dora": "dora_level2_rts_2024_1774", "ai-act": "ai_act", "aiact": "ai_act"}


def _key(framework: str) -> str:
    return ALIASES.get(framework, framework)


def load() -> dict:
    with open(DATA, encoding="utf-8") as fh:
        return json.load(fh)


def rows(framework: str = "", status: str = "") -> list[dict]:
    data = load()
    out = data["rows"]
    if status:
        out = [r for r in out if r["status"] == status]
    if framework and framework not in ("all", ""):
        if _key(framework) not in data.get("hooks", {}):
            raise ValueError("unknown framework: %s (have: %s)"
                             % (framework, ", ".join(data.get("hooks", {}))))
    return out


def summary(framework: str = "") -> dict:
    data = load()
    counts: dict[str, int] = {}
    for row in data["rows"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {
        "format": data["format"],
        "rows": len(data["rows"]),
        "have": counts.get("have", 0),
        "partial": counts.get("partial", 0),
        "gap": counts.get("gap", 0),
        "hooks": data.get("hooks", {}).get(_key(framework), []) if framework else [],
        "not_claimed": data.get("not_claimed", []),
    }


def load_file(name: str) -> dict:
    path = os.path.join(os.path.dirname(DATA), name)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def subprocessors() -> dict:
    return load_file("subprocessors.json")


def contract_clauses() -> dict:
    return load_file("contract_clauses.json")


def dd_answers(version: str = "", now: int | None = None) -> dict:
    """The due-diligence answers, dated, with the command that proves each one.

    Generated from the same data as `mandate controls`, so a questionnaire cannot be
    answered from a document that drifted: if a row changes, this changes with it.
    """
    import time as _time
    data = load()
    matrix = summary()
    return {
        "format": "mandate-dd-answers/1",
        "product": "gama-mandate",
        "version": version,
        "answered_at": int(now if now is not None else _time.time()),
        "controls": {"rows": matrix["rows"], "have": matrix["have"],
                     "partial": matrix["partial"], "gap": matrix["gap"]},
        "rows": [{"n": r["n"], "control": r["control"], "status": r["status"],
                  "artifact": r["artifact"], "missing": r["missing"]} for r in data["rows"]],
        "not_claimed": data.get("not_claimed", []),
        "subprocessors": "see subprocessors.json in this pack",
        "clauses": "see contract_clauses.json in this pack",
        "how_to_verify": [
            "mandate audit verify --bundle <bundle> --log-signers <f> --witness-signers <f>",
            "mandate replay --bundle <bundle>",
            "mandate worm-verify --dir <export>",
            "python3 tools/kit.py --verifier '<your verifier>'",
        ],
    }


def render(framework: str = "", status: str = "") -> str:
    data = load()
    lines = []
    if framework and _key(framework) in data.get("hooks", {}):
        lines.append("Hooks for %s:" % framework)
        for item in data["hooks"][_key(framework)]:
            lines.append("  - %s" % item)
        lines.append("")
    width = max(len(r["control"]) for r in data["rows"]) + 2
    lines.append("%-3s %-*s %-8s %s" % ("#", width, "control", "status", "artifact"))
    for row in rows(framework, status):
        lines.append("%-3d %-*s %-8s %s" % (row["n"], width, row["control"],
                                            row["status"], row["artifact"]))
        if row.get("missing"):
            lines.append("    missing: %s (owner: %s)" % (row["missing"], row.get("owner", "")))
    lines.append("")
    lines.append("Not claimed: " + "; ".join(data.get("not_claimed", [])))
    return "\n".join(lines)
