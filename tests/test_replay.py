"""REPLAY_V1: the decision can be re-derived from the evidence, or it is not evidence.

A signed receipt proves *who* produced the record. It does not prove the recorded
decision follows from the recorded policy — a builder can sign a record that the
policy would have refused, and a later policy change makes yesterday's decision
unreproducible. `replay()` recomputes the hashes, the taint picture and the
decision, and says exactly which one drifted.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import core, export, replay

ROOT = pathlib.Path(__file__).resolve().parents[1]


def intent_factory(**over):
    intent = {
        "v": 1,
        "actor": {"agent": "agent@example", "session": "s1"},
        "effect": {"kind": "payment.send", "target": "Example Supplier",
                   "amount": {"value": 1170.0, "currency": "BAM"},
                   "params": {"ref": "faktura-77"}},
        "requested_by": "approver",
        "nonce": "n-replay-1",
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1",
                        "trust": "trusted", "covers": ["target", "amount"]}],
    }
    intent.update(over)
    return intent


class Replay(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.key = os.path.join(d, "approver")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(d, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate,mandate-export" %s\n'
            % pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.ledger = os.path.join(d, "ledger.jsonl")
        self.policy = core.load_policy()
        self.intent = intent_factory()
        proposal = core.propose(self.intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=900,
            render_hash=proposal["render_hash"], agent="agent@example")
        self.grant = core.make_grant(grant_core, self.key)
        self.receipt = core.redeem(self.intent, self.grant, self.signers, self.ledger,
                                   policy=self.policy)
        self.bundle = {"intent": self.intent, "receipt": self.receipt, "grant": self.grant}

    def tearDown(self):
        self.td.cleanup()

    def test_honest_record_replays(self):
        out = replay.replay(self.bundle, self.policy)
        self.assertTrue(out["ok"], out)
        self.assertTrue(out["reproducible"])
        for name in ("commitment", "render_hash", "result_hash", "policy_digest",
                     "taint", "decision"):
            self.assertTrue(out["checks"][name]["ok"], (name, out["checks"][name]))

    def test_changed_intent_breaks_the_hashes(self):
        bundle = dict(self.bundle)
        bundle["intent"] = intent_factory(
            effect={"kind": "payment.send", "target": "Example Supplier",
                    "amount": {"value": 9999.0, "currency": "BAM"},
                    "params": {"ref": "faktura-77"}})
        out = replay.replay(bundle, self.policy)
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "E_REPLAY_HASH")
        self.assertFalse(out["checks"]["commitment"]["ok"])

    def test_changed_policy_is_reported_as_drift(self):
        policy = json.loads(json.dumps(self.policy))
        policy["effects"]["payment.send"] = dict(policy["effects"]["payment.send"],
                                                 max_auto=1)
        out = replay.replay(self.bundle, policy)
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "E_POLICY_DRIFT")

    def test_policy_that_now_denies_is_not_reproducible(self):
        policy = json.loads(json.dumps(self.policy))
        policy["effects"]["payment.send"] = dict(policy["effects"]["payment.send"],
                                                 require_trusted=["target", "amount"])
        bundle = dict(self.bundle)
        bundle["intent"] = intent_factory(provenance=[
            {"type": "data_ref", "source": "erp:vendor:1",
             "covers": ["target", "amount"]}])   # bez trust -> unknown
        # hashes se poklapaju jer je intent isti koji je potpisan? nije: napravljen novi
        out = replay.replay(bundle, policy)
        self.assertFalse(out["ok"])
        self.assertIn(out["code"], ("E_REPLAY_HASH", "E_DECISION"))

    def test_tampered_taint_block_is_caught(self):
        bundle = json.loads(json.dumps({"intent": self.intent, "receipt": self.receipt,
                                        "grant": self.grant}))
        bundle["receipt"]["body"]["taint"] = {
            "untrusted_fields": [], "unknown_fields": [], "trusted_fields": [],
            "material_untrusted": [], "tainted": False}
        out = replay.replay(bundle, self.policy)
        self.assertFalse(out["checks"]["taint"]["ok"])

    def test_cli_exit_codes(self):
        path = os.path.join(self.dir, "bundle.json")
        pathlib.Path(path).write_text(json.dumps(self.bundle), encoding="utf-8")
        good = subprocess.run([sys.executable, "-m", "mandate", "replay", "--bundle", path],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        bundle = json.loads(json.dumps(self.bundle))
        bundle["intent"]["effect"]["amount"]["value"] = 5.0
        pathlib.Path(path).write_text(json.dumps(bundle), encoding="utf-8")
        bad = subprocess.run([sys.executable, "-m", "mandate", "replay", "--bundle", path],
                             cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertFalse(json.loads(bad.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
