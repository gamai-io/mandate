"""PEP 740 provenance, checked from the outside.

A hash on PyPI proves the file did not change after upload. It does not prove *who built it,
from which repository and which commit* — that is what an attestation adds. PyPI exposes one
per file at `https://pypi.org/integrity/<project>/<version>/<file>/provenance`, so this module
answers the question a customer actually has: "was the wheel I installed built by the tagged
repository, or by whoever held an API token?"

It is deliberately online-only: the answer lives on PyPI. On an air-gapped host it says
`network` and refuses to imply anything.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

API = "https://pypi.org"
PROJECT = "gama-mandate"


def _fetch(url: str, timeout: int = 15) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError):
        return 0, b""


def _publishers(payload: bytes) -> list[dict]:
    try:
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []
    out = []
    for bundle in data.get("attestation_bundles") or []:
        pub = bundle.get("publisher") or {}
        out.append({"kind": pub.get("kind") or "", "repository": pub.get("repository") or "",
                    "workflow": pub.get("workflow") or "",
                    "environment": pub.get("environment") or "",
                    "attestations": len(bundle.get("attestations") or [])})
    return out


def check(version: str, project: str = PROJECT, timeout: int = 15) -> dict:
    """Per-file attestation status for one version, as PyPI reports it."""
    status, raw = _fetch("%s/pypi/%s/%s/json" % (API, project, version), timeout)
    if status == 404:
        return {"ok": False, "code": "no_version", "project": project, "version": version,
                "message": "%s %s is not on PyPI" % (project, version)}
    if status != 200:
        return {"ok": False, "code": "network", "project": project, "version": version,
                "message": ("could not reach PyPI (status %s): provenance is a server-side fact "
                            "and cannot be checked offline" % status)}
    try:
        meta = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"ok": False, "code": "network", "project": project, "version": version,
                "message": "PyPI returned something that is not JSON"}
    rows, missing = [], []
    for item in meta.get("urls") or []:
        name = item.get("filename") or ""
        status, payload = _fetch("%s/integrity/%s/%s/%s/provenance" % (
            API, project, version, name), timeout)
        publishers = _publishers(payload) if status == 200 else []
        row = {"file": name, "sha256": (item.get("digests") or {}).get("sha256", ""),
               "attested": bool(publishers), "publishers": publishers}
        if not publishers:
            missing.append(name)
        rows.append(row)
    attested = [r for r in rows if r["attested"]]
    code = ("ok" if rows and not missing else
            ("none" if not attested else "partial"))
    return {"ok": code == "ok", "code": code, "project": project, "version": version,
            "files": rows, "attested": len(attested), "files_total": len(rows),
            "missing": missing,
            "note": ("an attestation says which repository and workflow built the file; a hash "
                     "alone only says the file did not change after upload")}


def summary(result: dict) -> str:
    if result.get("code") in ("network", "no_version"):
        return result.get("message") or result.get("code", "")
    lines = ["%s %s: %d/%d files attested" % (result["project"], result["version"],
                                              result["attested"], result["files_total"])]
    for row in result.get("files") or []:
        where = ""
        if row.get("publishers"):
            pub = row["publishers"][0]
            where = " <- %s %s %s" % (pub.get("kind"), pub.get("repository"), pub.get("workflow"))
        lines.append("  %-52s %s%s" % (row["file"], "yes" if row["attested"] else "no", where))
    return "\n".join(lines)
