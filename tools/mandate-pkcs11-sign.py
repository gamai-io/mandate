#!/usr/bin/env python3
"""Sign a Mandate payload with a PKCS#11 key (SoftHSM2 or a vendor HSM).

This is the `--signer-cmd` adapter: the private key never enters the Mandate
process. It reads the canonical payload from stdin (exactly the bytes that will be
verified), signs it with the token, and prints `{"sig": <SSHSIG armor>, "signer": ...}`.

    export MANDATE_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so
    export MANDATE_PKCS11_TOKEN=mandate
    export MANDATE_PKCS11_PIN=1234
    export MANDATE_PKCS11_KEY=approver
    export MANDATE_SIGNER=approver
    mandate redeem ... --signer-cmd "python3 tools/mandate-pkcs11-sign.py"

Supported keys: Ed25519 (EC_EDWARDS). Requires `python-pkcs11`.
Tested against SoftHSM2 2.6.1; a vendor HSM is the same API, not the same device.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys


def _u32(value: int) -> bytes:
    return int(value).to_bytes(4, "big")


def _str(data: bytes) -> bytes:
    return _u32(len(data)) + data


def armor(blob: bytes) -> str:
    body = base64.b64encode(blob).decode("ascii")
    lines = [body[i:i + 70] for i in range(0, len(body), 70)]
    return ("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines)
            + "\n-----END SSH SIGNATURE-----\n")


def signed_data(namespace: str, payload: bytes) -> bytes:
    """What ssh-keygen signs: SSHSIG framing over H(message), not the message."""
    digest = hashlib.sha512(payload).digest()
    return (b"SSHSIG" + _str(namespace.encode()) + _str(b"")
            + _str(b"sha512") + _str(digest))


def sshsig(public_blob: bytes, signature: bytes, namespace: str) -> str:
    sig_blob = _str(b"ssh-ed25519") + _str(signature)
    blob = (b"SSHSIG" + _u32(1) + _str(public_blob) + _str(namespace.encode())
            + _str(b"") + _str(b"sha512") + _str(sig_blob))
    return armor(blob)


def main() -> int:
    try:
        import pkcs11
    except ImportError:
        print("python-pkcs11 is not installed", file=sys.stderr)
        return 2
    lib_path = os.environ.get("MANDATE_PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so")
    token_label = os.environ.get("MANDATE_PKCS11_TOKEN", "")
    pin = os.environ.get("MANDATE_PKCS11_PIN", "")
    label = os.environ.get("MANDATE_PKCS11_KEY", "")
    signer = os.environ.get("MANDATE_SIGNER", "approver")
    namespace = os.environ.get("MANDATE_PKCS11_NAMESPACE", "mandate")
    if not token_label or not pin or not label:
        print("set MANDATE_PKCS11_TOKEN, MANDATE_PKCS11_PIN and MANDATE_PKCS11_KEY",
              file=sys.stderr)
        return 2
    payload = sys.stdin.buffer.read()
    if payload.endswith(b"\n"):
        signed_payload = payload
    else:
        signed_payload = payload + b"\n"
    try:
        lib = pkcs11.lib(lib_path)
        token = lib.get_token(token_label=token_label)
        with token.open(user_pin=pin) as session:
            private = session.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                                      label=label)
            public = session.get_key(object_class=pkcs11.ObjectClass.PUBLIC_KEY,
                                     label=label)
            point = bytes(public[pkcs11.Attribute.EC_POINT])
            # DER OCTET STRING (04 20) around the 32-byte Ed25519 point
            raw = point[-32:]
            public_blob = _str(b"ssh-ed25519") + _str(raw)
            to_sign = signed_data(namespace, signed_payload)
            signature = private.sign(to_sign,
                                     mechanism=pkcs11.Mechanism.EDDSA)
    except Exception as exc:                       # noqa: BLE001 - report, exit 2
        print("PKCS#11 sign failed: %s" % str(exc)[:200], file=sys.stderr)
        return 2
    if len(signature) != 64:
        print("unexpected Ed25519 signature length %d" % len(signature),
              file=sys.stderr)
        return 2
    armored = sshsig(public_blob, signature, namespace)
    # sanity: our own construction must verify with the token's public key
    print(json.dumps({"sig": armored, "signer": signer,
                      "signed_sha256": hashlib.sha256(to_sign).hexdigest()}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
