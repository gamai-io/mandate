"""Regression tests for the red-team findings (2026-11-24).

Each test reproduces a reported issue and fails if it comes back.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import unittest

from mandate import core, egress, governance, report, svid, warden


def keypair(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name, "-N", ""],
                   check=True)
    return path


def signers(directory: str, mapping: dict[str, str]) -> str:
    path = os.path.join(directory, "allowed_signers")
    with open(path, "w", encoding="utf-8") as fh:
        for name, key in mapping.items():
            fh.write(f'{name} namespaces="mandate" {open(key + ".pub").read().strip()}\n')
    return path


class SvidSubjectBinding(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.agent_key = keypair(self.tmp.name, "agent")
        self.rogue_key = keypair(self.tmp.name, "rogue")
        self.signers = signers(self.tmp.name, {"bank-agent": self.agent_key,
                                               "rogue": self.rogue_key})

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_rogue_key_cannot_mint_another_agents_token(self) -> None:
        token = svid.issue("bank-agent", self.rogue_key, "rogue", "local-broker",
                           ["payment.send"], 60)
        res = svid.verify(token, self.signers, audience="local-broker")
        self.assertFalse(res["valid"], "any key must not be able to mint any subject")
        self.assertEqual(res["code"], "issuer_subject_mismatch")

    def test_own_key_still_works(self) -> None:
        token = svid.issue("bank-agent", self.agent_key, "bank-agent", "local-broker",
                           ["payment.send"], 60)
        self.assertTrue(svid.verify(token, self.signers, audience="local-broker")["valid"])


class CommitmentBindsActor(unittest.TestCase):
    def setUp(self) -> None:
        self.base = {
            "v": 1,
            "actor": {"agent": "bank-agent", "session": "s1"},
            "effect": {"kind": "payment.send", "target": "X",
                       "amount": {"value": 10, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n-1",
            "provenance": [{"type": "data_ref", "source": "erp:x"}],
        }

    def test_actor_and_nonce_change_the_commitment(self) -> None:
        a = core.intent_commitment(core.normalize_intent(dict(self.base)))
        evil = json.loads(json.dumps(self.base))
        evil["actor"]["agent"] = "EVIL-bot"
        b = core.intent_commitment(core.normalize_intent(evil))
        self.assertNotEqual(a, b, "the approver must sign who may execute, not only what")
        other_nonce = json.loads(json.dumps(self.base))
        other_nonce["nonce"] = "n-2"
        c = core.intent_commitment(core.normalize_intent(other_nonce))
        self.assertNotEqual(a, c)


class SpendLimitsUseReceiptShape(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_amount_is_read_from_render_fields(self) -> None:
        core.append_receipt(self.ledger, {
            "v": 1, "type": "receipt", "ts": time.time(), "agent": "a", "approver": "b",
            "render": {"fields": {"kind": "payment.send",
                                  "amount": {"value": 4000.0, "currency": "BAM"}}}})
        limits = dict(governance.DEFAULTS, max_effects=0, max_amount=5000,
                      currency="BAM", window_seconds=3600)
        first = governance.check(self.ledger, limits)
        self.assertTrue(first["allow"], first)
        core.append_receipt(self.ledger, {
            "v": 1, "type": "receipt", "ts": time.time(), "agent": "a", "approver": "b",
            "render": {"fields": {"kind": "payment.send",
                                  "amount": {"value": 4000.0, "currency": "BAM"}}}})
        second = governance.check(self.ledger, limits)
        self.assertFalse(second["allow"], "2 x 4000 BAM must exceed a 5000 BAM ceiling")
        self.assertEqual(second["code"], "limit_amount")


class EgressPrivateDestinations(unittest.TestCase):
    def policy(self, allow: list[str]) -> dict:
        return {"version": 1, "default": "deny", "allow": allow,
                "token_env": "MANDATE_EGRESS_TOKEN"}

    def test_hostname_allowlist_does_not_grant_loopback(self) -> None:
        verdict = egress.decide(self.policy(["localhost:80"]), "localhost", 80)
        self.assertFalse(verdict["allow"], "a hostname entry must not open 127.0.0.1")
        self.assertEqual(verdict["code"], "private_destination")

    def test_rfc1918_172_16_is_private(self) -> None:
        self.assertTrue(egress._is_private("172.20.5.5"))

    def test_ipv6_reserved_ranges(self) -> None:
        for ip in ("2001:db8::1", "64:ff9b::1", "::", "::1", "fe80::1"):
            self.assertTrue(egress._is_private(ip), ip)

    def test_allow_decision_returns_the_validated_ip(self) -> None:
        verdict = egress.decide(self.policy(["127.0.0.1:80"]), "127.0.0.1", 80)
        self.assertTrue(verdict["allow"])
        self.assertEqual(verdict.get("ip"), "127.0.0.1",
                         "the proxy must connect to the IP it validated")

    def test_metadata_still_denied(self) -> None:
        self.assertEqual(egress.decide(self.policy([]), "169.254.169.254", 80)["code"],
                         "metadata_endpoint")


class PackHygiene(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")
        core.append_receipt(self.ledger, {
            "v": 1, "type": "receipt", "agent": "a", "approver": "b", "ts": time.time(),
            "render": {"fields": {"kind": "payment.send",
                                  "amount": {"value": 1, "currency": "BAM"}}}})

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_stale_files_are_not_blessed(self) -> None:
        out = os.path.join(self.tmp.name, "pack")
        os.makedirs(out)
        open(os.path.join(out, "planted.json"), "w").write('{"evil": true}')
        report.pack(self.ledger, out)
        self.assertFalse(os.path.exists(os.path.join(out, "planted.json")))
        index = json.load(open(os.path.join(out, "index.json")))
        self.assertNotIn("planted.json", index["files"])


class WardenEvidenceShape(unittest.TestCase):
    def test_stop_evidence_has_state_time_and_timestamp(self) -> None:
        proc = subprocess.Popen(["sleep", "60"], start_new_session=True)
        try:
            res = warden.stop(proc.pid, method="freeze", by_pgid=True,
                              reason="red-team regression")
            self.assertTrue(res["verified"])
            self.assertIn("ts", res)
            self.assertIn("time_to_halt_ms", res)
            self.assertEqual(res["states_after"][str(proc.pid)], "T")
        finally:
            proc.kill()
            proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
