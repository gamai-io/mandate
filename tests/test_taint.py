"""TAINT_V1: an effect that rests on untrusted input can be refused by policy.

The attack this addresses is the one that actually works in the wild: a document,
an email or a web page carries an instruction, the agent follows it, and every
step is "authorized" because a human approved a well-formed intent. Provenance
alone does not help — the intent looks complete. `trust` on each provenance entry
turns "where did this come from" into a decision the gate can make:

    trusted    ERP/bank file/signed export
    untrusted  document, email, web page, model output
    unknown    nobody said (default)

A field is tainted when an untrusted source covers it and no trusted source does.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from mandate import core


def intent_factory(**over):
    intent = {
        "v": 1,
        "actor": {"agent": "agent@example", "session": "s1"},
        "effect": {
            "kind": "payment.send",
            "target": "Example Supplier",
            "amount": {"value": 1170.0, "currency": "BAM"},
            "params": {"ref": "faktura-77"},
        },
        "requested_by": "approver",
        "nonce": "n-taint-1",
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1",
                        "trust": "trusted", "covers": ["target", "amount"]}],
    }
    intent.update(over)
    return intent


class TaintReport(unittest.TestCase):
    def test_trusted_input_is_clean(self):
        rep = core.taint_report(intent_factory())
        self.assertEqual(rep["untrusted_fields"], [])
        self.assertFalse(rep["tainted"])
        self.assertIn("target", rep["trusted_fields"])

    def test_email_source_taints_target(self):
        intent = intent_factory(provenance=[
            {"type": "data_ref", "source": "email:from-supplier", "trust": "untrusted",
             "covers": ["target"]},
            {"type": "data_ref", "source": "erp:amount", "trust": "trusted",
             "covers": ["amount"]},
        ])
        rep = core.taint_report(intent)
        self.assertEqual(rep["untrusted_fields"], ["target"])
        self.assertEqual(rep["material_untrusted"], ["target"])
        self.assertTrue(rep["tainted"])

    def test_trusted_beats_untrusted_for_the_same_field(self):
        intent = intent_factory(provenance=[
            {"type": "data_ref", "source": "email:x", "trust": "untrusted",
             "covers": ["target"]},
            {"type": "data_ref", "source": "erp:vendor:1", "trust": "trusted",
             "covers": ["target"]},
        ])
        self.assertEqual(core.taint_report(intent)["untrusted_fields"], [])

    def test_missing_trust_is_unknown_not_trusted(self):
        intent = intent_factory(provenance=[
            {"type": "data_ref", "source": "erp:vendor:1", "covers": ["target"]}])
        rep = core.taint_report(intent)
        self.assertIn("target", rep["unknown_fields"])
        self.assertTrue(rep["tainted"])

    def test_model_inference_is_not_evidence_of_trust(self):
        intent = intent_factory(provenance=[
            {"type": "model_inference", "source": "summary-model",
             "trust": "untrusted", "covers": ["target", "amount"]}])
        self.assertEqual(sorted(core.taint_report(intent)["material_untrusted"]),
                         ["amount", "target"])

    def test_unknown_trust_label_is_rejected(self):
        with self.assertRaises(core.MandateError):
            core.normalize_intent(intent_factory(provenance=[
                {"type": "data_ref", "source": "erp:x", "trust": "maybe"}]))


class PolicyGate(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.key = os.path.join(d, "approver")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(d, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n'
            % pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.ledger = os.path.join(d, "ledger.jsonl")
        self.policy = dict(core.load_policy())
        self.policy["effects"] = dict(self.policy["effects"])
        self.policy["effects"]["payment.send"] = dict(
            self.policy["effects"]["payment.send"], require_trusted=["target"])

    def tearDown(self):
        self.td.cleanup()

    def _grant(self, intent):
        proposal = core.propose(intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=900,
            render_hash=proposal["render_hash"], agent="agent@example")
        return core.make_grant(grant_core, self.key)

    def test_check_denies_untrusted_target(self):
        intent = intent_factory(provenance=[
            {"type": "data_ref", "source": "email:planted", "trust": "untrusted",
             "covers": ["target", "amount"]}])
        decision = core.check(intent, self.policy)
        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(decision["reason"], "untrusted_input")
        self.assertEqual(decision["fields"], ["target"])

    def test_check_allows_trusted_target(self):
        intent = intent_factory()
        self.assertNotEqual(core.check(intent, self.policy)["decision"], "deny")

    def test_unknown_blocks_when_policy_requires_trust(self):
        intent = intent_factory(provenance=[
            {"type": "data_ref", "source": "erp:vendor:1",
             "covers": ["target", "amount"]}])
        decision = core.check(intent, self.policy)
        self.assertEqual(decision["reason"], "untrusted_input")

    def test_redeem_records_the_refusal(self):
        intent = intent_factory(provenance=[
            {"type": "data_ref", "source": "email:planted", "trust": "untrusted",
             "covers": ["target", "amount"]}])
        with self.assertRaises(core.PolicyDenied):
            core.redeem(intent, self._grant(intent), self.signers, self.ledger,
                        policy=self.policy)
        entries = [json.loads(x) for x in
                   pathlib.Path(self.ledger).read_text(encoding="utf-8").splitlines() if x] \
            if os.path.exists(self.ledger) else []
        self.assertTrue(entries, "odbijanje mora ostaviti zapis")
        self.assertIn("untrusted_input", json.dumps(entries[-1]))

    def test_receipt_carries_taint_block(self):
        intent = intent_factory()
        receipt = core.redeem(intent, self._grant(intent), self.signers, self.ledger,
                              policy=self.policy)
        taint = receipt["body"]["taint"]
        self.assertEqual(taint["untrusted_fields"], [])
        self.assertIn("target", taint["trusted_fields"])


if __name__ == "__main__":
    unittest.main()
