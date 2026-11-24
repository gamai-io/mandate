"""External anchoring (RFC 3161) and WORM export for the ledger.

A hash chain proves internal consistency. It does not prove that the chain you
are shown is the chain that existed at time T — whoever holds the file can
rewrite the whole chain and the head file together. An RFC 3161 timestamp from a
third party fixes the head in time. Without one, an auditor is entitled to treat
receipts as an informative log.

This module is deliberately small and offline-verifiable:

  mandate anchor --ledger ledger.jsonl --tsa https://freetsa.org/tsr
  mandate anchor-verify --ledger ledger.jsonl --token anchors/<...>.tsr
  mandate worm-export --ledger ledger.jsonl --out ./worm --retention-days 180

Signature-chain verification of the token is delegated to ``openssl ts -verify``
when a CA file is supplied; otherwise we verify the message imprint, the status
and the time, and say so explicitly instead of implying more.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.request

DEFAULT_TSA = "https://freetsa.org/tsr"
SHA256_OID = bytes.fromhex("0609608648016503040201")  # DER OID 2.16.840.1.101.3.4.2.1


def cms_structure_ok(raw: bytes) -> tuple[bool, str]:
    """Parse the token with openssl (deep ASN.1), not just match an OID.

    Returns (ok, detail). If openssl is missing we fall back to the OID scan and
    say so — never silently claim more than we checked.
    """
    import shutil as _shutil
    import tempfile as _tempfile
    if not _shutil.which("openssl"):
        oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" in raw
        return oid, "openssl not installed: OID scan only"
    with _tempfile.NamedTemporaryFile(suffix=".tsr") as fh:
        fh.write(raw)
        fh.flush()
        out = subprocess.run(["openssl", "ts", "-reply", "-in", fh.name, "-text"],
                             capture_output=True, text=True, timeout=30)
    text = out.stdout + out.stderr
    ok = out.returncode == 0 and "TST info" in text and "Status: Granted" in text
    return ok, text.strip()[-300:]


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = [40 * parts[0] + parts[1]]
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        out += chunk[::-1]
    return _der(0x06, bytes(out))


def build_request(digest_hex: str, algorithm: str = "sha256", cert_req: bool = True) -> bytes:
    oid = {
        "sha256": "2.16.840.1.101.3.4.2.1",
        "sha512": "2.16.840.1.101.3.4.2.3",
    }[algorithm]
    alg = _der(0x30, _der_oid(oid) + _der(0x05, b""))
    imprint = _der(0x30, alg + _der(0x04, bytes.fromhex(digest_hex)))
    body = _der(0x02, b"\x01") + imprint
    if cert_req:
        body += _der(0x01, b"\xff")
    return _der(0x30, body)


def _children(data: bytes, start: int, end: int):
    i = start
    while i < end:
        tag = data[i]
        i += 1
        length = data[i]
        i += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[i:i + n], "big")
            i += n
        yield tag, data[i:i + length]
        i += length


def parse_response(raw: bytes) -> dict:
    """Extract status, message imprint, generation time and whether a cert is present."""
    out = {"status": None, "imprint_sha256": None, "gen_time": None,
           "has_certificate": False, "der_bytes": len(raw)}
    try:
        outer = list(_children(raw, 0, len(raw)))
    except Exception:
        return out
    if not outer or outer[0][0] != 0x30:
        return out
    top = list(_children(outer[0][1], 0, len(outer[0][1])))
    if not top:
        return out
    status_info, token = top[0], (top[1] if len(top) > 1 else None)
    if status_info[0] == 0x30:
        parts = list(_children(status_info[1], 0, len(status_info[1])))
        if parts and parts[0][0] == 0x02:
            out["status"] = int.from_bytes(parts[0][1], "big")
    if not token:
        return out
    blob = token[1]
    idx = blob.find(SHA256_OID)
    if idx != -1:
        window = blob[idx:idx + 48]
        marker = window.find(b"\x04\x20")
        if marker != -1:
            start = idx + marker + 2
            out["imprint_sha256"] = blob[start:start + 32].hex()
    import re as _re
    m = _re.search(rb"(\d{12})Z", blob)
    if m:
        out["gen_time"] = m.group(0).decode("ascii")
    out["has_certificate"] = b"\x30\x82" in blob and len(blob) > 1500
    out["has_cms_signed_data"] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" in blob
    return out


def ledger_head(path: str) -> str:
    head = path + ".head"
    if os.path.exists(head):
        return open(head).read().strip()
    entries = [json.loads(line) for line in open(path) if line.strip()]
    return str(entries[-1]["hash"]) if entries else ""


def request_token(head_hex: str, tsa: str = DEFAULT_TSA, timeout: int = 40) -> bytes:
    req = build_request(head_hex)
    r = urllib.request.Request(tsa, data=req,
                               headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return resp.read()


def anchor(ledger_path: str, tsa: str | None = None, out_dir: str | None = None,
           ca_path: str | None = None, tsas: list[str] | None = None) -> dict:
    head = ledger_head(ledger_path)
    if not head:
        raise ValueError("empty ledger: nothing to anchor")
    digest = hashlib.sha256(head.encode()).hexdigest()
    servers = [t for t in (tsas or [tsa or DEFAULT_TSA]) if t]
    entries = []
    for server in servers:
        try:
            raw = request_token(digest, server)
        except Exception as exc:      # one TSA down must not lose the others
            entries.append({"tsa": server, "error": str(exc)[:160], "ok": False})
            continue
        info = parse_response(raw)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        token_path = os.path.join(out_dir or "anchors",
                                  "%s-%s.tsr" % (head[:16], stamp + "-" + str(len(entries))))
        entries.append({"tsa": server, "token": os.path.basename(token_path),
                        "token_sha256": hashlib.sha256(raw).hexdigest(),
                        "imprint_ok": info.get("imprint_sha256") == digest,
                        "gen_time": info.get("gen_time"), "status": info.get("status"),
                        "ok": info.get("imprint_sha256") == digest and info.get("status") == 0,
                        "_raw": raw, "_path": token_path})
    # first successful token keeps the legacy top-level fields
    ok_entries = [e for e in entries if e.get("ok")]
    if not ok_entries:
        raise ValueError("no TSA returned a usable token: %s"
                         % [e.get("tsa") for e in entries])
    raw = ok_entries[0]["_raw"]
    tsa = ok_entries[0]["tsa"]
    info = parse_response(raw)
    info = parse_response(raw)
    out_dir = out_dir or "anchors"
    os.makedirs(out_dir, exist_ok=True)
    token_path = ok_entries[0]["_path"]
    for entry in entries:
        if entry.get("_raw"):
            with open(entry["_path"], "wb") as fh:
                fh.write(entry["_raw"])
    anchors = [{k: v for k, v in e.items() if not k.startswith("_")} for e in entries]
    sidecar = {"head": head, "head_sha256": digest, "tsa": tsa, "anchors": anchors,
               "token": os.path.basename(token_path),
               "token_sha256": hashlib.sha256(raw).hexdigest(), **info}
    if ca_path:
        sidecar["openssl_verify"] = _openssl_verify(token_path, ledger_path, ca_path)
    with open(token_path + ".json", "w", encoding="utf-8") as fh:
        json.dump(sidecar, fh, indent=1, sort_keys=True)
    sidecar["token_path"] = token_path
    sidecar["imprint_matches_head"] = info.get("imprint_sha256") == digest
    return sidecar


def extract_token(raw: bytes) -> bytes:
    """Return the CMS TimeStampToken (second child of TimeStampResp) as raw DER."""
    outer = list(_children(raw, 0, len(raw)))
    if not outer or outer[0][0] != 0x30:
        return b""
    body = outer[0][1]
    top = []
    i = 0
    while i < len(body):
        tag = body[i]
        length = body[i + 1]
        header = 2
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(body[i + 2:i + 2 + n], "big")
            header = 2 + n
        top.append((tag, body[i:i + header + length]))
        i += header + length
    return top[1][1] if len(top) > 1 else b""


def _openssl_verify(token_path: str, ledger_path: str, ca_path: str) -> dict:
    """Full CMS verification with openssl; the token covers the ledger HEAD bytes."""
    raw = open(token_path, "rb").read()
    token = extract_token(raw)
    if not token:
        return {"verified": False, "error": "no CMS token in this file"}
    import tempfile
    head = ledger_head(ledger_path)
    with tempfile.TemporaryDirectory() as td:
        tok = os.path.join(td, "token.der")
        data = os.path.join(td, "head.txt")
        open(tok, "wb").write(token)
        open(data, "wb").write(head.encode())
        try:
            out = subprocess.run(
                ["openssl", "ts", "-verify", "-in", tok, "-data", data,
                 "-CAfile", ca_path, "-token_in"],
                capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"verified": False, "error": str(exc)[:200]}
    text = (out.stdout + out.stderr).strip()
    return {"verified": "Verification: OK" in text, "openssl": text[-400:]}


def verify_anchor(ledger_path: str, token_path: str, ca_path: str | None = None) -> dict:
    """A token is only 'valid' when the CMS signature is verified with a CA.

    Without --ca we can check the imprint, the status and the time — but an
    attacker can fabricate those fields in a 1 KB blob. Reporting that as valid
    would be the same mistake as calling a log "tamper-proof".
    """
    raw = open(token_path, "rb").read()
    info = parse_response(raw)
    head = ledger_head(ledger_path)
    digest = hashlib.sha256(head.encode()).hexdigest()
    imprint_ok = info.get("imprint_sha256") == digest and info.get("status") == 0
    result = {"token": token_path, "tsa_head": head, "head_sha256": digest, **info,
              "imprint_matches_head": info.get("imprint_sha256") == digest,
              "imprint_ok": bool(imprint_ok), "valid": False}
    structure_ok, detail = cms_structure_ok(raw)
    result["cms_parsed"] = structure_ok
    if not (info.get("has_cms_signed_data") and structure_ok):
        result["code"] = "no_cms_token"
        result["note"] = "not a parseable CMS timestamp token: " + str(detail)[:160]
        return result
    if not ca_path:
        result["code"] = "cms_unverified"
        result["note"] = ("imprint/status/time checked, but the CMS signature was NOT verified; "
                          "pass --ca <tsa-ca.pem> to make this evidence")
        return result
    result["openssl_verify"] = _openssl_verify(token_path, ledger_path, ca_path)
    result["valid"] = bool(imprint_ok and result["openssl_verify"].get("verified"))
    result["code"] = "ok" if result["valid"] else "cms_failed"
    return result


def _clock_evidence() -> dict:
    ev = {"system_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    for cmd in (["chronyc", "tracking"], ["timedatectl", "show", "--property=NTPSynchronized"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                ev[cmd[0]] = out.stdout.strip()[:600]
        except (OSError, subprocess.SubprocessError):
            continue
    ev["note"] = "captured at export time; not attested by a third party"
    return ev


def worm_export(ledger_path: str, out_dir: str, retention_days: int = 180,
                anchor_dir: str | None = None) -> dict:
    """Copy ledger + head + anchors into a dated, read-only directory with a manifest."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    target = os.path.join(out_dir, stamp)
    os.makedirs(target, exist_ok=True)
    files = []
    for src in (ledger_path, ledger_path + ".head"):
        if os.path.exists(src):
            dst = os.path.join(target, os.path.basename(src))
            shutil.copy2(src, dst)
            files.append(dst)
    if anchor_dir and os.path.isdir(anchor_dir):
        for name in sorted(os.listdir(anchor_dir)):
            src = os.path.join(anchor_dir, name)
            if os.path.isfile(src):
                dst = os.path.join(target, "anchors", name)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
                files.append(dst)
    manifest = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "retention_days": retention_days,
        "retention_until": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + retention_days * 86400)),
        "ledger_head": ledger_head(ledger_path),
        "files": {os.path.relpath(f, target): {
            "sha256": hashlib.sha256(open(f, "rb").read()).hexdigest(),
            "bytes": os.path.getsize(f)} for f in files},
        "clock": _clock_evidence(),
        "note": ("directory is chmod 0444/0555 as a local safeguard only; for real WORM "
                 "use object lock (S3 Object Lock / Azure immutable blob) or a WORM appliance"),
    }
    path = os.path.join(target, "manifest.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    for root, dirs, names in os.walk(target):
        for name in names:
            try:
                os.chmod(os.path.join(root, name), 0o444)
            except OSError:
                pass
        for name in dirs:
            try:
                os.chmod(os.path.join(root, name), 0o555)
            except OSError:
                pass
    manifest["path"] = target
    manifest["manifest_path"] = path
    return manifest
