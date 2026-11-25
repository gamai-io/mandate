#!/usr/bin/env python3
"""Pre-publish scan for Python distributions (sdist/wheel).

Blocks a release when the artifact contains secrets, internal host paths, or
customer data. Usage:

    python3 tools/prepublish_scan.py dist/*.tar.gz dist/*.whl
    python3 tools/prepublish_scan.py --staged .        # scan a source tree

Exit code 1 on any BLOCK finding, 0 otherwise. Only the standard library.
"""
from __future__ import annotations

import argparse
import re
import sys
import tarfile
import zipfile

HIGH = "BLOCK"
MED = "WARN"

RULES = [
    (HIGH, "private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (HIGH, "openai/anthropic key", re.compile(r"\bsk-(ant-)?[A-Za-z0-9_-]{20,}")),
    (HIGH, "github token", re.compile(r"\b(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})")),
    (HIGH, "huggingface token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    (HIGH, "aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (HIGH, "google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    (HIGH, "slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    (HIGH, "assigned secret literal",
     # a name is not a value: env:PAY_TOKEN, $PAY_TOKEN and "token_env" are fine
     re.compile(r"(?i)\b(api_key|apikey|secret|password|passwd|token)\b\s*[:=]\s*"
                r"[\"'](?!env:|\$)[^\"'\s]{12,}[\"']")),
    (HIGH, "internal absolute path", re.compile(r"/(root|home/[a-z0-9._-]+)/")),
    (HIGH, "internal host name",
     re.compile(r"(?i)\b(contabo|oracle-vps|linux3|vmlab|dispecer|podrum|kuca|vastvm)\b")),
    (HIGH, "customer schema", re.compile(r"(?i)\b(vp2026|mp2026|kupdob)\b")),
    (MED, "customer word", re.compile(r"(?i)\bkupac\b")),
    (MED, "non-example email", re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.)[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    (MED, "private ip", re.compile(r"\b(192\.168\.\d+\.\d+|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")),
    (MED, "hpc/lab marker", re.compile(r"(?i)(lumi-multitorch|Local-LAIF|/project/project_\d+|firecracker pool)")),
]

SKIP_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".whl", ".gz", ".zip", ".so", ".pyc")


def files_from_artifact(path: str):
    if path.endswith((".tar.gz", ".tgz")):
        with tarfile.open(path) as tf:
            for m in tf.getmembers():
                if m.isfile() and not m.name.endswith(SKIP_SUFFIX):
                    yield m.name, tf.extractfile(m).read()
    elif path.endswith(".whl"):
        with zipfile.ZipFile(path) as zf:
            for n in zf.namelist():
                if not n.endswith(SKIP_SUFFIX):
                    yield n, zf.read(n)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifacts", nargs="+")
    args = ap.parse_args()
    blocks = warns = 0
    for art in args.artifacts:
        for name, raw in files_from_artifact(art):
            try:
                text = raw.decode("utf-8", "ignore")
            except Exception:
                continue
            is_test = "/tests/" in name or name.startswith("tests/")
            is_meta = any(k in name for k in ("pyproject.toml", "PKG-INFO", "METADATA", ".dist-info/", "setup.cfg"))
            for sev, label, rx in RULES:
                if label == "non-example email" and is_meta:
                    continue
                for m in rx.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    snippet = m.group(0)[:80].replace("\n", " ")
                    eff = MED if (is_test and label == "assigned secret literal") else sev
                    print(f"{eff:5} {art}:{name}:{line} [{label}] {snippet}")
                    if eff == HIGH:
                        blocks += 1
                    else:
                        warns += 1
                    break
    print(f"\nsummary: {blocks} blocking, {warns} warnings")
    return 1 if blocks else 0


if __name__ == "__main__":
    sys.exit(main())
