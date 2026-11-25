"""Policy digest (change after approval), observe mode, revert field."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest

from mandate.core import (
    MandateError,
    PolicyDenied,
    build_grant_core,
    intent_commitment,
    make_grant,
    normalize_intent,
    policy_digest,
    redeem,
    render_hash,
)


def keypair(td: str, name: str) -> str:
    path = os.path.join(td, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name, "-N", ""],
                   check=True)
    return path


POLICY = {"version": 1, "default": "deny", "effects": {"payment.send": {"risk": "high"}}}


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.key = keypair(self.dir, "approver")
        self.signers = os.path.join(self.dir, "allowed_signers")
        open(self.signers, "w").write(
            f'approver namespaces="mandate" {open(self.key + ".pub").read().strip()}\n')
        self.intent = normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": "payment.send", "target": "X",
                       "amount": {"value": 10.0, "currency": "BAM"},
                       "revert": "reverse_transfer"},
            "requested_by": "ops", "nonce": "n-pol-1",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def grant(self, policy: dict) -> dict:
        core = build_grant_core(intent_commitment(self.intent), "approver", ttl_s=600,
                                render_hash=render_hash(self.intent), agent="bank-agent",
                                audience="local-broker",
                                policy_fingerprint=policy_digest(policy))
        return make_grant(core, self.key)


class PolicyDigest(Base):
    def test_changed_policy_blocks_redeem(self) -> None:
        grant = self.grant(POLICY)
        stricter = json.loads(json.dumps(POLICY))
        stricter["effects"]["payment.send"]["max_auto"] = 0
        with self.assertRaises(PolicyDenied):
            redeem(self.intent, grant, self.signers, os.path.join(self.dir, "l.jsonl"),
                   policy=stricter)

    def test_same_policy_passes_and_digest_is_recorded(self) -> None:
        grant = self.grant(POLICY)
        entry = redeem(self.intent, grant, self.signers,
                       os.path.join(self.dir, "l.jsonl"), policy=POLICY)
        self.assertEqual(entry["body"]["policy_digest"], policy_digest(POLICY))


class Observe(Base):
    def test_observe_does_not_spend_the_grant(self) -> None:
        grant = self.grant(POLICY)
        ledger = os.path.join(self.dir, "l.jsonl")
        first = redeem(self.intent, grant, self.signers, ledger, policy=POLICY, observe=True)
        self.assertFalse(first["body"]["binding"])
        self.assertEqual(first["body"]["decision"], "observe")
        # the same grant can still be executed for real afterwards
        second = redeem(self.intent, grant, self.signers, ledger, policy=POLICY)
        self.assertTrue(second["body"]["binding"])
        self.assertEqual(second["body"]["decision"], "executed")


class Revert(Base):
    def test_revert_is_recorded(self) -> None:
        grant = self.grant(POLICY)
        entry = redeem(self.intent, grant, self.signers,
                       os.path.join(self.dir, "l.jsonl"), policy=POLICY)
        self.assertEqual(entry["body"]["revert"], "reverse_transfer")

    def test_missing_revert_is_refused_when_policy_requires_it(self) -> None:
        policy = json.loads(json.dumps(POLICY))
        policy["require_revert"] = {"payment.send": True}
        intent = normalize_intent({**self.intent,
                                   "effect": {k: v for k, v in self.intent["effect"].items()
                                              if k != "revert"}})
        core = build_grant_core(intent_commitment(intent), "approver", ttl_s=600,
                                render_hash=render_hash(intent), agent="bank-agent",
                                audience="local-broker",
                                policy_fingerprint=policy_digest(policy))
        grant = make_grant(core, self.key)
        with self.assertRaises(MandateError):
            redeem(intent, grant, self.signers, os.path.join(self.dir, "l.jsonl"),
                   policy=policy)


if __name__ == "__main__":
    unittest.main()
