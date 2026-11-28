"""SIGNING_CONVENTION_V1: sign the canonical bytes, verify the old convention too.

Until 1.0.10 `sign()` wrote `payload + "\\n"` to the file handed to `ssh-keygen -Y sign`, so every
signature covered an extra byte that is not part of RFC 8785. An independent implementation (our
own browser verifier) had to discover that by trial, and a third party would have hit it as a
"signature invalid" on a clean record. New signatures cover the exact bytes; verification still
accepts the legacy newline so records issued before 1.0.10 keep verifying.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

from mandate import sign


class Convention(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "k")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n'
            % pathlib.Path(self.key + ".pub").read_text().strip(), encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def test_signature_covers_the_exact_bytes(self):
        payload = '{"a":1,"b":"ž"}'
        sig = sign.sign(payload, self.key)
        self.assertTrue(sign.verify(payload, "approver", sig, self.signers))
        self.assertFalse(sign.verify(payload + "\n", "approver", sig, self.signers))

    def test_a_legacy_signature_still_verifies(self):
        payload = '{"legacy":true}'
        data = os.path.join(self.dir, "payload")
        pathlib.Path(data).write_text(payload + "\n", encoding="utf-8")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", self.key, "-n", "mandate", data],
                       check=True, capture_output=True)
        legacy = pathlib.Path(data + ".sig").read_text(encoding="utf-8")
        self.assertTrue(sign.verify(payload, "approver", legacy, self.signers))

    def test_wrong_namespace_is_still_refused(self):
        payload = '{"a":2}'
        sig = sign.sign(payload, self.key)
        self.assertFalse(sign.verify(payload, "approver", sig, self.signers,
                                     namespace="other"))


if __name__ == "__main__":
    unittest.main()
