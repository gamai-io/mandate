"""Round-2 security fixes: cross-ledger nonce (H2), delegation subject (H4), signed receipts (H9)."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest

from mandate import core, svid


def keypair(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name, "-N", ""],
                   check=True)
    return path


class CrossLedgerNonce(unittest.TestCase):
    """One grant must not be redeemable into a second ledger."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.approver = keypair(self.dir, "approver")
        self.agent = keypair(self.dir, "agent")
        self.signers = os.path.join(self.dir, "allowed_signers")
        with open(self.signers, "w") as fh:
            for name, key in (("approver", self.approver), ("bank-agent", self.agent)):
                fh.write(f'{name} namespaces="mandate" {open(key + ".pub").read().strip()}\n')
        self.intent = core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": "payment.send", "target": "X",
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n-cross-1",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})
        grant_core = core.build_grant_core(core.intent_commitment(self.intent),
                                          "approver", ttl_s=600,
                                          render_hash=core.render_hash(self.intent),
                                          agent="bank-agent", audience="")
        self.grant = core.make_grant(grant_core, self.approver)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_second_ledger_is_refused(self) -> None:
        first = os.path.join(self.dir, "a.jsonl")
        second = os.path.join(self.dir, "b.jsonl")
        core.redeem(self.intent, self.grant, self.signers, first)
        with self.assertRaises(core.GrantReplayed):
            core.redeem(self.intent, self.grant, self.signers, second)


class DelegationSubject(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.parent_key = keypair(self.dir, "parent")
        self.child_key = keypair(self.dir, "child")
        self.signers = os.path.join(self.dir, "allowed_signers")
        with open(self.signers, "w") as fh:
            for name, key in (("parent", self.parent_key), ("child", self.child_key)):
                fh.write(f'{name} namespaces="mandate" {open(key + ".pub").read().strip()}\n')
        self.parent = svid.issue("parent", self.parent_key, "parent", "local-broker",
                                 ["payment.send"], 300)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def child(self, declared_parent: str, sub: str = "child", key: str | None = None) -> dict:
        token = svid.issue(sub, key or self.child_key, sub, "local-broker",
                           ["payment.send"], 120, parent=self.parent["payload"])
        token["payload"]["parent_sub"] = declared_parent
        # re-sign after editing, as an attacker with the child key could
        from mandate import sign
        from mandate.jcs import canonicalize
        body = {k: v for k, v in token["payload"].items()}
        token["sig"] = sign.sign(canonicalize(body), key or self.child_key)
        return token

    def test_wrong_declared_parent_is_rejected(self) -> None:
        res = svid.verify_chain(self.child("someone-else"), [self.parent], self.signers)
        self.assertFalse(res["valid"])
        self.assertEqual(res["code"], "parent_subject_mismatch")

    def test_correct_parent_passes(self) -> None:
        res = svid.verify_chain(self.child("parent"), [self.parent], self.signers)
        self.assertTrue(res["valid"], res)

    def test_self_delegation_with_null_parent_sub_is_rejected(self) -> None:
        token = self.child("parent", sub="parent", key=self.parent_key)
        res = svid.verify_chain(token, [self.parent], self.signers)
        self.assertFalse(res["valid"])
        self.assertIn(res["code"], ("self_delegation", "parent_subject_mismatch"))


class SignedReceipts(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.approver = keypair(self.dir, "approver")
        self.broker = keypair(self.dir, "broker")
        self.signers = os.path.join(self.dir, "allowed_signers")
        with open(self.signers, "w") as fh:
            for name, key in (("approver", self.approver), ("broker", self.broker)):
                fh.write(f'{name} namespaces="mandate" {open(key + ".pub").read().strip()}\n')
        self.intent = core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": "payment.send", "target": "X",
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n-signed-1",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})
        grant_core = core.build_grant_core(core.intent_commitment(self.intent),
                                          "approver", ttl_s=600,
                                          render_hash=core.render_hash(self.intent),
                                          agent="bank-agent", audience="")
        self.grant = core.make_grant(grant_core, self.approver)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_signed_receipt_verifies_and_tamper_fails(self) -> None:
        ledger = os.path.join(self.dir, "l.jsonl")
        entry = core.redeem(self.intent, self.grant, self.signers, ledger,
                            sign_key=self.broker, signer="broker")
        self.assertIn("signature", entry["body"])
        self.assertTrue(core.verify_receipt_signature(entry["body"], self.signers))
        self.assertTrue(core.verify_receipt(entry, self.intent, self.grant, self.signers))
        tampered = json.loads(json.dumps(entry))
        tampered["body"]["ts"] = int(tampered["body"]["ts"]) + 1
        self.assertFalse(core.verify_receipt_signature(tampered["body"], self.signers))

    def test_policy_can_require_signatures(self) -> None:
        ledger = os.path.join(self.dir, "l2.jsonl")
        with self.assertRaises(core.MandateError):
            core.redeem(self.intent, self.grant, self.signers, ledger,
                        policy={"effects": {"payment.send": {"risk": "high"}},
                                "require_signed_receipts": True})

    def test_unsigned_receipt_still_verifies_when_policy_allows(self) -> None:
        ledger = os.path.join(self.dir, "l3.jsonl")
        entry = core.redeem(self.intent, self.grant, self.signers, ledger)
        self.assertNotIn("signature", entry["body"])
        self.assertTrue(core.verify_receipt(entry, self.intent, self.grant, self.signers))


if __name__ == "__main__":
    unittest.main()
