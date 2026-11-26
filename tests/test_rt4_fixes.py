"""Regressions from the fourth review (RT4) of mandate.

The important one: a revoked key used to verify if the same principal had a
second, valid key, because ssh-keygen reads the whole signers file.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import approval_page, core, sign
from mandate import approver as mapprover

ROOT = pathlib.Path(__file__).resolve().parents[1]


def intent_factory():
    return {"v": 1, "actor": {"agent": "agent@example", "session": "s1"},
            "effect": {"kind": "payment.send", "target": "Example Supplier",
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n-1",
            "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}]}


def keypair(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path],
                   check=True)
    return path


class RevokedKeyAmongTwo(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.old = keypair(self.dir, "old")
        self.new = keypair(self.dir, "new")
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\napprover namespaces="mandate" %s\n'
            % (pathlib.Path(self.old + ".pub").read_text(encoding="utf-8").strip(),
               pathlib.Path(self.new + ".pub").read_text(encoding="utf-8").strip()),
            encoding="utf-8")
        self.revoked = os.path.join(self.dir, "revoked")
        pathlib.Path(self.revoked).write_text(
            sign.fingerprint(pathlib.Path(self.old + ".pub").read_text(
                encoding="utf-8").split()[1]) + "\n", encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def test_the_revoked_key_cannot_sign_even_with_a_second_key_present(self):
        payload = "hello"
        old_sig = sign.sign(payload, self.old)
        self.assertFalse(sign.verify(payload, "approver", old_sig, self.signers,
                                     revoked_path=self.revoked),
                         "a revoked key verified because the principal has another key")
        new_sig = sign.sign(payload, self.new)
        self.assertTrue(sign.verify(payload, "approver", new_sig, self.signers,
                                    revoked_path=self.revoked))


class ApproverValidatesBeforeApproval(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = keypair(self.dir, "k")

    def tearDown(self):
        self.td.cleanup()

    def test_a_broken_policy_fails_before_the_human_is_asked(self):
        asked = []
        approver = mapprover.Approver(
            self.key, "approver", audience_default="local-broker",
            confirm=lambda *a: asked.append(True) or True,
            policy_path=os.path.join(self.dir, "missing.json"))
        with self.assertRaises((OSError, core.MandateError)):
            approver.request(intent_factory())
        self.assertEqual(asked, [], "the human was asked before the policy was read")

    def test_the_page_refuses_a_broken_policy_at_startup(self):
        with self.assertRaises((OSError, core.MandateError)):
            approval_page.serve(self.key, "approver", port=0,
                                policy_path=os.path.join(self.dir, "missing.json"))


class TamperedReceiptIsNotExecuted(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = keypair(self.dir, "k")
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.intent = intent_factory()

    def tearDown(self):
        self.td.cleanup()

    def test_a_tampered_receipt_does_not_report_executed(self):
        proposal = core.propose(self.intent)
        gc = core.build_grant_core(proposal["commitment"], "approver", ttl_s=600,
                                   render_hash=proposal["render_hash"],
                                   agent="agent@example", audience="local-broker",
                                   policy_fingerprint=core.policy_digest(
                                       core.load_policy()))
        grant = core.make_grant(gc, self.key)
        receipt = core.redeem(self.intent, grant, self.signers,
                              os.path.join(self.dir, "l.jsonl"),
                              policy=core.load_policy(), audience="local-broker")
        receipt["body"]["ts"] = 1                 # hash no longer matches
        paths = {}
        for name, value in (("r", receipt), ("i", self.intent), ("g", grant)):
            paths[name] = os.path.join(self.dir, name + ".json")
            pathlib.Path(paths[name]).write_text(json.dumps(value), encoding="utf-8")
        done = subprocess.run([sys.executable, str(ROOT / "bin" / "mandate"),
                               "verify", "--receipt", paths["r"], "--intent",
                               paths["i"], "--grant", paths["g"], "--signers",
                               self.signers], capture_output=True, text=True)
        payload = json.loads(done.stdout)
        self.assertFalse(payload["valid"])
        self.assertFalse(payload["executed"])


if __name__ == "__main__":
    unittest.main()
