"""A local CA for TLS interception, and the honest terms of using one.

`egress.py` judges the destination: a CONNECT to `bank.example:443` is allowed or
refused, and the bytes inside are invisible to us. That is the right default. When a
customer needs the *content* of an HTTPS call inspected (a secret leaving, an
instruction coming back), something has to terminate the TLS — and that something
has to present a certificate the client trusts.

This module builds that certificate authority. It does **not** pretend the trade-off
away:

  * the CA private key can impersonate **any** host for any client that trusts it —
    it is generated on the machine that runs the proxy, `0600`, and never leaves it;
  * the client must be told to trust it (a system store, a browser profile, a
    container image) — that is a deployment decision, not a switch;
  * interception breaks certificate pinning by design, so a pinned client will
    (correctly) refuse;
  * everything decrypted is scanned in memory and not written to disk; the ledger
    records the decision and the finding kinds, never the payload.

Generated with the `openssl` binary rather than a Python dependency, because a
monitoring tool that cannot be installed without a crypto stack is a monitoring tool
nobody installs.
"""
from __future__ import annotations

import os
import re
import shutil
import ssl
import subprocess
import tempfile

CA_CERT = "ca.pem"
CA_KEY = "ca.key"
LEAF_DIR = "leaves"
_HASH = re.compile(r"^[a-f0-9]{12}$")


class CaError(RuntimeError):
    pass


def _openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise CaError("openssl is not installed; TLS interception needs it")
    return path


def _run(args: list[str]) -> str:
    done = subprocess.run([_openssl()] + args, capture_output=True, text=True)
    if done.returncode != 0:
        raise CaError("openssl failed: %s" % (done.stderr or done.stdout)[-300:])
    return done.stdout


def _chmod600(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def init_ca(directory: str, days: int = 3650, common_name: str = "") -> dict:
    """Create the CA (idempotent: an existing CA is reused, not replaced)."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    cert = os.path.join(directory, CA_CERT)
    key = os.path.join(directory, CA_KEY)
    if not (os.path.exists(cert) and os.path.exists(key)):
        name = common_name or "Mandate Local Inspection CA"
        _run(["req", "-x509", "-newkey", "rsa:2048", "-nodes",
              "-keyout", key, "-out", cert, "-days", str(days),
              "-subj", "/CN=%s" % name,
              "-addext", "basicConstraints=critical,CA:TRUE",
              "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        _chmod600(key)
    return {"cert": cert, "key": key, "fingerprint": fingerprint(cert)}


def fingerprint(cert_path: str) -> str:
    out = _run(["x509", "-in", cert_path, "-noout", "-fingerprint", "-sha256"])
    return out.strip().split("=", 1)[-1].replace(":", "")[-32:]


def leaf_for(directory: str, host: str, days: int = 90) -> tuple[str, str]:
    """Certificate for one host, signed by our CA, cached per host.

    An IP destination needs `IP:` in the SAN, a name needs `DNS:`; getting this wrong
    produces a certificate the client rejects with a clear error, which is at least
    honest, but wasteful.
    """
    cert = os.path.join(directory, CA_CERT)
    key = os.path.join(directory, CA_KEY)
    if not (os.path.exists(cert) and os.path.exists(key)):
        raise CaError("no CA in %s: run `mandate egress ca init` first" % directory)
    leaves = os.path.join(directory, LEAF_DIR)
    os.makedirs(leaves, mode=0o700, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", host)[:80] or "host"
    stem = os.path.join(leaves, safe)
    if os.path.exists(stem + ".pem") and os.path.exists(stem + ".key"):
        return stem + ".pem", stem + ".key"

    is_ip = bool(re.match(r"^[0-9.]+$", host)) or ":" in host
    san = ("IP:%s" if is_ip else "DNS:%s") % host
    with tempfile.TemporaryDirectory() as td:
        csr = os.path.join(td, "leaf.csr")
        ext = os.path.join(td, "leaf.ext")
        with open(ext, "w", encoding="utf-8") as fh:
            fh.write("subjectAltName=%s\nbasicConstraints=CA:FALSE\n"
                     "keyUsage=critical,digitalSignature,keyEncipherment\n"
                     "extendedKeyUsage=serverAuth\n" % san)
        _run(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", stem + ".key",
              "-out", csr, "-subj", "/CN=%s" % host])
        _run(["x509", "-req", "-in", csr, "-CA", cert, "-CAkey", key,
              "-CAcreateserial", "-out", stem + ".pem", "-days", str(days),
              "-extfile", ext])
    _chmod600(stem + ".key")
    return stem + ".pem", stem + ".key"


def server_context(directory: str, host: str,
                   alpn: list[str] | None = None) -> ssl.SSLContext:
    """Server-side context that presents a certificate for `host`."""
    cert, key = leaf_for(directory, host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    try:
        ctx.set_alpn_protocols(alpn or ["http/1.1"])
    except NotImplementedError:
        pass
    return ctx


def client_context(cafile: str | None = None) -> ssl.SSLContext:
    """Context for the upstream leg: verification stays on.

    `cafile` adds a trust anchor (a private origin with an internal CA); it never turns
    verification off, because a proxy that does not verify the origin is a proxy that
    can be pointed anywhere by whoever controls DNS.
    """
    ctx = ssl.create_default_context()
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    return ctx


def trust_hint(cert_path: str) -> str:
    return (
        "Trust this CA only on the machines you choose to inspect:\n"
        "  Linux (system):  sudo cp {0} /usr/local/share/ca-certificates/mandate-ca.crt "
        "&& sudo update-ca-certificates\n"
        "  curl/wget:       --cacert {0}\n"
        "  Python:          ssl.create_default_context(cafile='{0}')\n"
        "  Node:            NODE_EXTRA_CA_CERTS={0}\n"
        "Remove it when you stop inspecting: an unused CA is a standing impersonation "
        "capability.".format(cert_path))
