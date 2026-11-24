"""Round-4: identity cannot be skipped, claim callback can't double-spend, fail-closed governance,
wildcard scope refused, anchor imprint comes from the TSA's own parse."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from mandate import anchor, governance, svid
from mandate.core import (
    GrantReplayed,
    build_grant_core,
    intent_commitment,
    make_grant,
    normalize_intent,
    redeem,
    render_hash,
)

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
TSR = os.path.join(FIX, "tsa_freetsa_2026-11-24.tsr")
SIDECAR = os.path.join(FIX, "tsa_freetsa_2026-11-24.json")


def keypair(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name, "-N", ""],
                   check=True)
    return path


class Flow(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.approver = keypair(self.dir, "approver")
        self.signers = os.path.join(self.dir, "allowed_signers")
        with open(self.signers, "w") as fh:
            fh.write(f'approver namespaces="mandate" '
                     f'{open(self.approver + ".pub").read().strip()}\n')
        self.intent = normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": "payment.send", "target": "X",
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n-r4",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})
        gc = build_grant_core(intent_commitment(self.intent), "approver", ttl_s=600,
                              render_hash=render_hash(self.intent),
                              agent="bank-agent", audience="local-broker")
        self.grant = make_grant(gc, self.approver)

    def tearDown(self) -> None:
        self.tmp.cleanup()


class ClaimCallback(Flow):
    def test_custom_claim_cannot_double_spend(self) -> None:
        a = os.path.join(self.dir, "a.jsonl")
        b = os.path.join(self.dir, "b.jsonl")
        redeem(self.intent, self.grant, self.signers, a, claim=lambda n: True)
        with self.assertRaises(GrantReplayed):
            redeem(self.intent, self.grant, self.signers, b, claim=lambda n: True)


class FailClosedGovernance(unittest.TestCase):
    def test_broker_denies_when_limits_cannot_be_checked(self) -> None:
        from mandate import broker
        with mock.patch.object(governance, "check", side_effect=RuntimeError("boom")):
            b = broker.Broker.__new__(broker.Broker)
            b.ledger_path = "/tmp/x.jsonl"
            b.policy_path = None
            b.policy = {"effects": {"payment.send": {"risk": "high"}}}
            b.erp = None
            b.signers = "/dev/null"
            b.journal = None
            b.lease_s = 60
            with self.assertRaises(Exception) as ctx:
                broker.Broker.execute(b, {"v": 1, "actor": {"agent": "a", "session": "s"},
                                          "effect": {"kind": "payment.send", "target": "X",
                                                     "amount": {"value": 1, "currency": "BAM"}},
                                          "requested_by": "ops", "nonce": "n",
                                          "provenance": [{"type": "data_ref", "source": "e"}]},
                                      {"grant": {}, "sig": ""})
            self.assertIn("governance", str(ctx.exception).lower())


class WildcardScope(unittest.TestCase):
    def test_wildcard_requires_explicit_permission(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            key = keypair(td, "k")
            with self.assertRaises(ValueError):
                svid.issue("agent", key, "agent", "aud", ["*"], 60)
            token = svid.issue("agent", key, "agent", "aud", ["*"], 60, allow_wildcard=True)
            self.assertEqual(token["payload"]["scopes"], ["*"])


class AnchorParse(unittest.TestCase):
    def test_imprint_comes_from_openssl_parse(self) -> None:
        side = json.load(open(SIDECAR))
        raw = open(TSR, "rb").read()
        ok, detail = anchor.cms_structure_ok(raw)
        self.assertTrue(ok)
        parsed = anchor.imprint_from_openssl_text(detail)
        self.assertEqual(parsed, side["head_sha256"])


class SvidRequired(unittest.TestCase):
    def test_redeem_without_token_is_refused_when_policy_requires_it(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(__file__)))
            subprocess.run([subprocess.sys.executable, "-m", "mandate", "init", "--dir", "."],
                           check=True, capture_output=True, env=env)
            policy = json.load(open("mandate/policy.json"))
            policy["require_svid"] = True
            json.dump(policy, open("mandate/policy.json", "w"))
            # no keys needed: the CLI must refuse before touching the grant
            out = subprocess.run([subprocess.sys.executable, "-m", "mandate", "redeem",
                                  "--intent", "examples/intent.json",
                                  "--grant", "grant.json", "--ledger", "l.jsonl",
                                  "--policy", "mandate/policy.json"],
                                 capture_output=True, text=True, env=env)
            self.assertEqual(out.returncode, 6, out.stdout + out.stderr)
            self.assertIn("SvidRequired", out.stdout)


if __name__ == "__main__":
    unittest.main()
