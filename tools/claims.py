#!/usr/bin/env python3
"""Make the repository's own claims mechanically true.

Three failures end an evaluation in the first ten minutes: a version in the
README that is not the version on PyPI, a SECURITY.md that supports a release
nobody can install, and a test count that does not match the suite. This script
reads the version from `pyproject.toml` and refuses to pass if any anchor in the
documentation disagrees, or if CHANGELOG.md has no section for the release.

    python3 tools/claims.py --check     # CI gate, exit 1 on drift
    python3 tools/claims.py --write     # regenerate CLAIMS.md

Zero dependencies. It does not prove a claim is useful, only that it is the same
claim everywhere and can be reproduced by the command next to it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STRICT = [False]

ANCHORS = [
    ("README.md", r"\*\*v(?P<v>\d+\.\d+\.\d+)\*\*", "status line"),
    ("SECURITY.md", r"\| (?P<v>\d+\.\d+)\.x\s+\| yes", "supported version table"),
    ("docs/PROCUREMENT_ANSWERS.md", r"`gama-mandate` (?P<v>\d+\.\d+\.\d+)", "product line"),
    ("docs/REFERENCE_ARCHITECTURE.md", r"`gama-mandate` (?P<v>\d+\.\d+\.\d+)", "status line"),
    ("CHANGELOG.md", r"## (?P<v>\d+\.\d+\.\d+) —", "release section"),
]

TEST_COUNT_ANCHORS = [
    ("README.md", r"(?P<n>\d+) tests"),
    ("README.md", r"(?P<n>\d+) testova"),
]


def version() -> str:
    text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    match = re.search(r'^version = "(?P<v>[^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml has no version")
    return match.group("v")


def module_version() -> str:
    out = subprocess.run([sys.executable, "-c",
                          "import mandate; print(mandate.__version__)"],
                         cwd=ROOT, capture_output=True, text=True)
    return out.stdout.strip() or "unknown"


def check_versions() -> list[str]:
    current = version()
    problems = []
    for path, pattern, label in ANCHORS:
        full = os.path.join(ROOT, path)
        if not os.path.exists(full):
            problems.append("%s: missing (%s)" % (path, label))
            continue
        text = open(full, encoding="utf-8").read()
        found = list(re.finditer(pattern, text))
        if path == "CHANGELOG.md":
            found = found[:1]        # only the newest section has to match
        matches = {m.group("v") for m in found}
        expected = current
        if path == "SECURITY.md":
            expected = ".".join(current.split(".")[:2])
        if not matches:
            problems.append("%s: no %s found" % (path, label))
        elif expected not in matches:
            problems.append("%s: %s says %s, pyproject says %s"
                            % (path, label, ", ".join(sorted(matches)), current))
        elif len(matches) > 1:
            problems.append("%s: %s mentions several versions: %s"
                            % (path, label, ", ".join(sorted(matches))))
    installed = module_version()
    if installed != current:
        line = ("installed distribution is %s, pyproject says %s"
                % (installed, current))
        if STRICT[0]:
            problems.append(line)
        else:
            print("warn: %s (fine in a checkout, a problem in a release)" % line)
    return problems


def count_tests() -> int:
    """pytest when available, otherwise count the unittest methods.

    CI installs only ruff/build/twine for the unittest job, so a hard dependency
    on pytest made the gate fail on "could not collect" instead of on drift.
    """
    out = subprocess.run([sys.executable, "-m", "pytest", "-q", "--collect-only",
                          "tests/"], cwd=ROOT, capture_output=True, text=True)
    match = re.search(r"(\d+) tests? collected", out.stdout + out.stderr)
    if match:
        return int(match.group(1))
    total = 0
    for name in sorted(os.listdir(os.path.join(ROOT, "tests"))):
        if not name.startswith("test_") or not name.endswith(".py"):
            continue
        text = open(os.path.join(ROOT, "tests", name), encoding="utf-8").read()
        total += len(re.findall(r"^\s+def test_", text, re.M))
    return total or -1


def check_tests() -> list[str]:
    actual = count_tests()
    if actual < 0:
        return ["could not collect the test suite"]
    problems = []
    for path, pattern in TEST_COUNT_ANCHORS:
        full = os.path.join(ROOT, path)
        if not os.path.exists(full):
            continue
        for match in re.finditer(pattern, open(full, encoding="utf-8").read()):
            claimed = int(match.group("n"))
            if claimed != actual:
                problems.append("%s: claims %d tests, suite has %d"
                                % (path, claimed, actual))
    return problems


def write_claims() -> str:
    current = version()
    rows = ["# Claims and how to check them", "",
            "Generated by `tools/claims.py --write`. A claim without a command that",
            "reproduces it does not belong in a sales conversation.", "",
            "| claim | value | command |", "|---|---|---|",
            "| version | %s | `python3 tools/claims.py --version` |" % current,
            "| tests | %d | `python3 -m pytest -q tests/` |" % count_tests(),
            "| runtime dependencies | 0 | `grep -A2 '^dependencies' pyproject.toml` |",
            "| policy lints clean | yes | `mandate policy lint` |",
            "| supported python | %s | `grep requires-python pyproject.toml` |"
            % _requires_python(),
            "", "## Not proven here", "",
            "- Independent pentest: not done.",
            "- Second implementation of the verifier: not written.",
            "- HA / RTO / RPO for the nonce authority: not defined by this repository.",
            "- PI/cyber insurance: not in place.",
            "", "These are listed, not hidden: a questionnaire that answers yes to",
            "everything is the first thing a reviewer distrusts.", ""]
    text = "\n".join(rows)
    with open(os.path.join(ROOT, "CLAIMS.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    return text


def _requires_python() -> str:
    text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    match = re.search(r'requires-python = "([^"]+)"', text)
    return match.group(1) if match else "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="also require the installed distribution to match")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args()
    STRICT[0] = args.strict
    if args.version:
        print(version())
        return 0
    if args.write:
        print(write_claims())
        return 0
    problems = check_versions() + check_tests()
    if problems:
        for problem in problems:
            print("DRIFT:", problem)
        print("\n%d claim(s) disagree with the code. Fix the document, not the check."
              % len(problems))
        return 1
    print(json.dumps({"version": version(), "tests": count_tests(),
                      "claims": "consistent"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
