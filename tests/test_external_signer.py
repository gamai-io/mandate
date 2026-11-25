"""HSM/KMS path: the signature comes from an external command, verification is unchanged."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest

from mandate import signing
from mandate.core import (
    build_grant_core,
    intent_commitment,
    make_grant,
    normalize_intent,
    redeem,
    verify_receipt,
)

SIGNER = """#!/bin/sh
# Emulates a bank adapter: takes the payload on stdin, signs it with a key that
# lives outside this process, prints {sig, signer}.
tmp=$(mktemp); cat > "$tmp"; rm -f "$tmp.sig"
ssh-keygen -Y sign -f "$HSM_KEY" -n mandate "$tmp" > /dev/null 2>&1
python3 - "$tmp.sig" <<'PY'
import json, sys
print(json.dumps({"sig": open(sys.argv[1]).read(), "signer": "approver-hsm"}))
PY
rm -f "$tmp" "$tmp.sig"
"""


class ExternalSigner(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.key = os.path.join(self.dir, "hsm_key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", self.key,
                        "-C", "approver-hsm", "-N", ""], check=True)
        self.signers = os.path.join(self.dir, "allowed_signers")
        open(self.signers, "w").write(
            f'approver-hsm namespaces="mandate" {open(self.key + ".pub").read().strip()}\n')
        self.command = os.path.join(self.dir, "hsm-sign")
        open(self.command, "w").write(SIGNER)
        os.chmod(self.command, 0o755)
        self.intent = normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": "payment.send", "target": "X",
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n-hsm-1",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})
        gc = build_grant_core(intent_commitment(self.intent), "approver-hsm", ttl_s=600,
                              render_hash=__import__("mandate.core", fromlist=["render_hash"]).render_hash(self.intent),
                              agent="bank-agent", audience="")
        self.grant = make_grant(gc, self.key)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_receipt_signed_by_external_command_verifies(self) -> None:
        os.environ["HSM_KEY"] = self.key
        try:
            ledger = os.path.join(self.dir, "l.jsonl")
            entry = redeem(self.intent, self.grant, self.signers, ledger,
                           signer_cmd=self.command)
        finally:
            os.environ.pop("HSM_KEY", None)
        self.assertIn("signature", entry["body"])
        self.assertEqual(entry["body"]["signer"], "approver-hsm")
        self.assertEqual(entry["body"]["signer_backend"], "external")
        # verification path is unchanged: the armor is checked against allowed_signers
        from mandate.core import verify_receipt_signature
        self.assertTrue(verify_receipt_signature(entry["body"], self.signers))
        self.assertTrue(verify_receipt(entry, self.intent, self.grant, self.signers))

    def test_bad_command_is_refused_before_writing(self) -> None:
        ledger = os.path.join(self.dir, "l2.jsonl")
        with self.assertRaises(signing.SignerError):
            signing.sign_with("/bin/false", "payload")
        with self.assertRaises(Exception):
            redeem(self.intent, self.grant, self.signers, ledger,
                   signer_cmd="/bin/false")

    def test_non_ssh_output_is_rejected(self) -> None:
        bad = os.path.join(self.dir, "bad-sign")
        open(bad, "w").write("#!/bin/sh\necho '{\"sig\": \"deadbeef\", \"signer\": \"x\"}'\n")
        os.chmod(bad, 0o755)
        with self.assertRaises(signing.SignerError):
            signing.sign_with(bad, "payload")


if __name__ == "__main__":
    unittest.main()
