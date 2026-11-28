#!/usr/bin/env python3
"""Normalize an sdist so the same source produces the same bytes.

`python -m build` honours SOURCE_DATE_EPOCH for the wheel, but the sdist's tar
entries (directories, PKG-INFO) and the gzip header still carry the build time.
This rewrites both with a fixed timestamp, uid/gid and empty owner names, which
makes the archive reproducible without changing what is inside it.

    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python3 tools/normalize_sdist.py dist/*.tar.gz
"""
from __future__ import annotations

import argparse
import gzip
import io
import os
import subprocess
import sys
import tarfile


def epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH")
    if value and value.isdigit():
        return int(value)
    try:
        return int(subprocess.run(["git", "log", "-1", "--format=%ct"],
                                  capture_output=True, text=True, check=True
                                  ).stdout.strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        raise SystemExit("set SOURCE_DATE_EPOCH or run inside git")


def normalize(path: str, when: int) -> bool:
    original = open(path, "rb").read()
    raw = gzip.decompress(original)
    out = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source, \
            tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as target:
        for member in source.getmembers():
            data = source.extractfile(member).read() if member.isfile() else None
            member.mtime = when
            # i mode: `git archive` izvučen pod umask 0002 daje 0664, a checkout u CI daje
            # 0644. Bez ovoga se sdist razlikuje samo po bitovima dozvole i reproducibilnost
            # pada na stvari koja ne mijenja sadržaj.
            # izvršni bit se ČUVA (skripte u examples/ moraju ostati 0755); normalizuje se
            # samo razlika 0644/0664 koja dolazi od umask-a pri izvlačenju arhive
            executable = bool(member.mode & 0o111)
            member.mode = (0o755 if (member.isdir() or executable) else 0o644)
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.pax_headers = {}
            target.addfile(member, io.BytesIO(data) if data is not None else None)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=when, filename="") as gz:
        gz.write(out.getvalue())
    normalized = buffer.getvalue()
    if normalized != original:
        with open(path, "wb") as fh:
            fh.write(normalized)
    return normalized == original


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help=".tar.gz sdists")
    ap.add_argument("--check", action="store_true",
                    help="do not write; fail if a file is not normalized")
    args = ap.parse_args()
    when = epoch()
    bad = 0
    for path in args.files:
        if not path.endswith((".tar.gz", ".tgz")):
            continue
        if args.check:
            tmp = path + ".check"
            with open(tmp, "wb") as fh:
                fh.write(open(path, "rb").read())
            already = normalize(tmp, when)
            os.unlink(tmp)
            if not already:
                print("%s is not normalized" % path)
                bad += 1
            continue
        normalize(path, when)
        print("normalized", path)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
