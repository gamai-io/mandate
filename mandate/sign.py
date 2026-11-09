from __future__ import annotations

import os
import subprocess
import tempfile

DEFAULT_NAMESPACE = "mandate"


class SignError(Exception):
    pass


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
           namespace: str = DEFAULT_NAMESPACE) -> bool:
    if not signature or not signers_path or not os.path.exists(signers_path):
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
    try:
        with open(signers_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if parts and parts[0] == name:
                    return " ".join(parts[1:])
    except OSError:
        return None
    return None
