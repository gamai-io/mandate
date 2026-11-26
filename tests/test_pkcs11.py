"""The PKCS#11 adapter must sign what ssh-keygen verifies.

Skipped unless SoftHSM2, opensc's pkcs11-tool and python-pkcs11 are installed.
This is the HSM path a bank would use (its adapter, its token); SoftHSM proves the
protocol, not the vendor device.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tools" / "mandate-pkcs11-sign.py"
SOFTHSM = shutil.which("softhsm2-util")
PKCS11_TOOL = shutil.which("pkcs11-tool")
MODULE = "/usr/lib/softhsm/libsofthsm2.so"


def _have() -> bool:
    if not (SOFTHSM and PKCS11_TOOL and os.path.exists(MODULE)):
        return False
    try:
        import pkcs11  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(_have(), "SoftHSM2 / pkcs11-tool / python-pkcs11 not available")
class Pkcs11Signer(unittest.TestCase):
    def test_a_token_signature_verifies_with_ssh_keygen(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            conf = os.path.join(td, "softhsm2.conf")
            tokens = os.path.join(td, "tokens")
            os.makedirs(tokens)
            with open(conf, "w", encoding="utf-8") as fh:
                fh.write("directories.tokendir = %s\nobjectstore.backend = file\n"
                         "log.level = ERROR\n" % tokens)
            env = dict(os.environ, SOFTHSM2_CONF=conf)
            subprocess.run([SOFTHSM, "--init-token", "--free", "--label",
                            "mandate", "--so-pin", "1234", "--pin", "1234"],
                           check=True, capture_output=True, env=env)
            subprocess.run([PKCS11_TOOL, "--module", MODULE, "-l", "-p", "1234",
                            "--keypairgen", "--key-type", "EC:edwards25519",
                            "--label", "approver", "--id", "01"],
                           check=True, capture_output=True, env=env)
            payload = b'{"v":1,"test":"pkcs11"}\n'
            run_env = dict(env, MANDATE_PKCS11_TOKEN="mandate",
                           MANDATE_PKCS11_PIN="1234",
                           MANDATE_PKCS11_KEY="approver",
                           MANDATE_SIGNER="approver")
            done = subprocess.run([sys.executable, str(ADAPTER)], input=payload,
                                  capture_output=True, env=run_env)
            self.assertEqual(done.returncode, 0, done.stderr)
            signature = json.loads(done.stdout)["sig"]

            raw = base64.b64decode("".join(
                line for line in signature.splitlines()
                if not line.startswith("-----")))
            offset = 10

            def take(data, at):
                size = int.from_bytes(data[at:at + 4], "big")
                return data[at + 4:at + 4 + size], at + 4 + size

            public, _ = take(raw, offset)
            signers = os.path.join(td, "signers")
            with open(signers, "w", encoding="utf-8") as fh:
                fh.write('approver namespaces="mandate" ssh-ed25519 %s\n'
                         % base64.b64encode(public).decode())
            sig_path = os.path.join(td, "p.sig")
            with open(sig_path, "w", encoding="utf-8") as fh:
                fh.write(signature)
            verified = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", signers, "-I", "approver",
                 "-n", "mandate", "-s", sig_path],
                input=payload, capture_output=True)
            self.assertEqual(verified.returncode, 0,
                             verified.stderr + verified.stdout)


if __name__ == "__main__":
    unittest.main()
