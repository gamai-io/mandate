from __future__ import annotations

import base64
import fnmatch
import hashlib
import os
import re
import shlex
import subprocess
import tempfile
import time

DEFAULT_NAMESPACE = "mandate"
_KEYTYPE = re.compile(r"^(ssh-|ecdsa-|sk-)")


class SignError(Exception):
    pass


def fingerprint(key_b64: str) -> str:
    data = str(key_b64)
    blob = base64.b64decode(data + "=" * (-len(data) % 4))
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode().rstrip("=")


def _parse_line(line: str) -> dict | None:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    try:
        tokens = shlex.split(raw)
    except ValueError:
        return None
    if len(tokens) < 3:
        return None
    idx = next((i for i, tok in enumerate(tokens) if _KEYTYPE.match(tok)), None)
    if idx is None or idx + 1 >= len(tokens):
        return None
    ns = re.search(r'namespaces\s*=\s*"([^"]*)"', raw)
    va = re.search(r'valid-after\s*=\s*"([^"]*)"', raw)
    vb = re.search(r'valid-before\s*=\s*"([^"]*)"', raw)
    try:
        fp = fingerprint(tokens[idx + 1])
    except (ValueError, TypeError):
        return None
    return {
        "principal": tokens[0],
        "keytype": tokens[idx],
        "key": tokens[idx + 1],
        "namespaces": ([x.strip() for x in ns.group(1).split(",") if x.strip()]
                       if ns else []),
        "valid_after": va.group(1) if va else None,
        "valid_before": vb.group(1) if vb else None,
        "fingerprint": fp,
    }


def list_signers(signers_path: str) -> list[dict]:
    out = []
    try:
        fh = open(signers_path, encoding="utf-8")
    except OSError:
        return out
    with fh:
        for line in fh:
            entry = _parse_line(line)
            if entry:
                out.append(entry)
    return out


def _principal_match(principal_field: str, name: str) -> bool:
    for pattern in str(principal_field).split(","):
        pattern = pattern.strip()
        if pattern and fnmatch.fnmatchcase(str(name), pattern):
            return True
    return False


def _norm_time(value) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) == 8:
        text += "000000"
    elif len(text) == 12:
        text += "00"
    return text if len(text) == 14 and text.isdigit() else "invalid"


def _validity_ok(entry: dict, now: float) -> bool:
    moment = time.strftime("%Y%m%d%H%M%S", time.gmtime(now))
    after = _norm_time(entry.get("valid_after"))
    before = _norm_time(entry.get("valid_before"))
    if after == "invalid" or before == "invalid":
        return False
    if after and moment < after:
        return False
    if before and moment >= before:
        return False
    return True


def load_revoked(revoked_path: str | None) -> set[str]:
    out: set[str] = set()
    if not revoked_path:
        return out
    try:
        with open(revoked_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.add(line.split()[0])
    except OSError:
        pass
    return out


def authorize_signer(name: str, signers_path: str, namespace: str,
                     now: float | None = None, revoked_path: str | None = None,
                     require_namespace: bool = True) -> bool:
    moment = time.time() if now is None else float(now)
    revoked = load_revoked(revoked_path)
    try:
        fh = open(signers_path, encoding="utf-8")
    except OSError:
        return False
    with fh:
        for line in fh:
            entry = _parse_line(line)
            if not entry:
                continue
            if not _principal_match(entry["principal"], name):
                continue
            if require_namespace:
                if namespace not in entry["namespaces"]:
                    continue
            elif entry["namespaces"] and namespace not in entry["namespaces"]:
                continue
            if not _validity_ok(entry, moment):
                continue
            if entry["fingerprint"] in revoked:
                continue
            return True
    return False


def sign(payload: str, key_path: str, namespace: str = DEFAULT_NAMESPACE) -> str:
    path = str(key_path or "").strip()
    if not path or not os.path.exists(path):
        raise SignError("private key not found")
    with tempfile.TemporaryDirectory() as td:
        data = os.path.join(td, "payload")
        with open(data, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        try:
            proc = subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f", path, "-n", namespace, data],
                capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SignError("sign failed: %s" % str(exc)[:160]) from exc
        if proc.returncode != 0:
            raise SignError("sign failed: %s" % (proc.stderr or "")[:200])
        with open(data + ".sig", encoding="utf-8") as fh:
            return fh.read()


def verify(payload: str, name: str, signature: str, signers_path: str,
           namespace: str = DEFAULT_NAMESPACE,
           revoked_path: str | None = None, now: float | None = None,
           require_namespace: bool = True) -> bool:
    if not signature or not signers_path or not os.path.exists(signers_path):
        return False
    if not authorize_signer(name, signers_path, namespace, now, revoked_path,
                            require_namespace):
        return False
    with tempfile.TemporaryDirectory() as td:
        sig = os.path.join(td, "payload.sig")
        with open(sig, "w", encoding="utf-8") as fh:
            fh.write(signature)
        try:
            proc = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", signers_path, "-I", str(name),
                 "-n", namespace, "-s", sig],
                input=payload + "\n", capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            return False
    return proc.returncode == 0


def public_key_for(name: str, signers_path: str) -> str | None:
    for entry in list_signers(signers_path):
        if _principal_match(entry["principal"], name):
            return "%s %s" % (entry["keytype"], entry["key"])
    return None


def keytype_for(name: str, signers_path: str,
                namespace: str = DEFAULT_NAMESPACE) -> str:
    try:
        fh = open(signers_path, encoding="utf-8")
    except OSError:
        return ""
    with fh:
        for line in fh:
            entry = _parse_line(line)
            if not entry or not _principal_match(entry["principal"], name):
                continue
            if namespace in entry["namespaces"]:
                return entry["keytype"]
    return ""


def is_hardware_key(keytype: str) -> bool:
    return str(keytype or "").startswith("sk-")
