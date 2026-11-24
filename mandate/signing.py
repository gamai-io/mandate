"""External signer hook: let an HSM/KMS sign, keep the verification story.

A bank will not hand a private key to a process. The common shape is a signing
service (PKCS#11 gateway, Vault Transit, cloud KMS) that takes bytes and returns
a signature. This module defines that contract for receipts and change records:

    <command>  receives the canonical payload on stdin
               returns JSON: {"sig": "<ssh-armored signature>", "signer": "name"}
               exit 0 on success

The command is the bank's adapter; we never see the key. Verification stays the
same as for file keys (`allowed_signers`), because the adapter must produce an
SSH-armored signature — anything else would silently change the format.

  mandate redeem ... --signer-cmd /usr/local/bin/hsm-sign --signer approver-hsm
"""
from __future__ import annotations

import json
import shlex
import subprocess


class SignerError(RuntimeError):
    pass


def sign_with(command: str, payload: str, timeout: int = 30) -> dict:
    """Run the external signer and return {"sig": ..., "signer": ...}."""
    argv = shlex.split(command)
    if not argv:
        raise SignerError("empty signer command")
    # The library signs payload + "\n" (ssh-keygen convention); the adapter must
    # receive exactly the bytes that will be verified.
    if not payload.endswith("\n"):
        payload += "\n"
    try:
        out = subprocess.run(argv, input=payload, capture_output=True, text=True,
                             timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SignerError("signer failed to run: %s" % str(exc)[:160]) from exc
    if out.returncode != 0:
        raise SignerError("signer exited %s: %s"
                          % (out.returncode, (out.stderr or out.stdout).strip()[:200]))
    text = out.stdout.strip()
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise SignerError("signer must print JSON {sig, signer}") from exc
    sig = str(data.get("sig") or "")
    if not sig:
        raise SignerError("signer returned no signature")
    if "BEGIN SSH SIGNATURE" not in sig:
        raise SignerError("signer must return an SSH-armored signature; got %r"
                          % sig[:40])
    return {"sig": sig, "signer": str(data.get("signer") or ""),
            "backend": "external"}
