#!/usr/bin/env python3
"""Rebuild this checkout and compare the bytes with what PyPI serves.

    python3 tools/verify_pypi.py            # current pyproject version
    python3 tools/verify_pypi.py --tag v0.68.7

Exit 0 only when every published file is byte-identical to a  rebuild of the
tagged source with SOURCE_DATE_EPOCH set to the commit time (the sdist is
normalized first, see tools/normalize_sdist.py). This checks the *contents* of
the artifact; the PEP 740 attestation checks who built it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def project_name() -> str:
    for line in open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8"):
        if line.startswith("name = "):
            return line.split('"')[1]
    raise SystemExit("pyproject.toml has no name")


def project_version() -> str:
    for line in open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8"):
        if line.startswith("version = "):
            return line.split('"')[1]
    raise SystemExit("pyproject.toml has no version")


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pypi_files(name: str, version: str) -> dict[str, str]:
    url = "https://pypi.org/pypi/%s/%s/json" % (name, version)
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.loads(response.read())
    return {item["filename"]: item["digests"]["sha256"]
            for item in data.get("urls") or []}


def build(source: str, out: str, when: str) -> None:
    env = dict(os.environ, SOURCE_DATE_EPOCH=when, PYTHONHASHSEED="0")
    subprocess.run([sys.executable, "-m", "build", "--outdir", out],
                   cwd=source, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run([sys.executable,
                    os.path.join(source, "tools", "normalize_sdist.py"),
                    *[os.path.join(out, f) for f in os.listdir(out)
                      if f.endswith((".tar.gz", ".tgz"))]],
                   cwd=source, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default=None, help="git tag to build (default: worktree)")
    ap.add_argument("--version", default=None)
    args = ap.parse_args()
    name, version = project_name(), args.version or project_version()
    if args.tag:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, check=True).stdout.strip()
        tagged = subprocess.run(["git", "rev-list", "-n", "1", args.tag], cwd=ROOT,
                                capture_output=True, text=True, check=True).stdout.strip()
        if head != tagged:
            print("HEAD is not %s; check out the tag first" % args.tag)
            return 2
    when = subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout.strip()
    remote = pypi_files(name, version)
    if not remote:
        print("PyPI has no files for %s %s" % (name, version))
        return 1
    with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as sd:
        # Gradi se iz `git archive <tag>`, ne iz radnog stabla: tako u build ne mogu ući
        # necommitovani fajlovi, a redoslijed fajlova je isti kao u tools/build_release.sh.
        source = ROOT
        if args.tag:
            source = sd
            archive = subprocess.run(["git", "archive", args.tag], cwd=ROOT,
                                     capture_output=True, check=True).stdout
            subprocess.run(["tar", "-x", "-C", source], input=archive, check=True)
        build(source, td, when)
        local = {f: sha256(os.path.join(td, f)) for f in sorted(os.listdir(td))}
    bad = 0
    for filename in sorted(set(local) | set(remote)):
        here, there = local.get(filename), remote.get(filename)
        status = "ok" if here and there and here == there else "MISMATCH"
        if status != "ok":
            bad += 1
        print("%-8s %s\n         local %s\n         pypi  %s"
              % (status, filename, here or "-", there or "-"))
    print("\n%s %s: %d file(s) differ" % (name, version, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
