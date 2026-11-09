import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import approver as mapprover
from mandate import core
from mandate import export as mexport
from mandate import log as mlog

ROOT = pathlib.Path(__file__).resolve().parents[1]


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
        "nonce": "n-1",
    }
    intent.update(over)
    return intent


class NotifyExportTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate,mandate-export" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.intent = intent_factory()
        proposal = core.propose(self.intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=900,
            render_hash=proposal["render_hash"],
            agent=str(self.intent["actor"]["agent"]))
        self.grant = core.make_grant(grant_core, self.key)
        self.receipt = core.redeem(self.intent, self.grant, self.signers,
                                   self.ledger, policy=core.load_policy())
        leaves = mlog.leaves_from_ledger(self.ledger)
        self.proof = mlog.inclusion_proof(leaves, 0)

    def tearDown(self):
        self.td.cleanup()

    def test_bundle_verifies(self):
        bundle = mexport.build_bundle(self.receipt, self.intent, self.grant,
                                      self.proof, key_path=self.key,
                                      signer="approver")
        result = mexport.verify_bundle(bundle, self.signers)
        self.assertTrue(result["valid"], result)
        self.assertTrue(result["signature"])
        self.assertTrue(result["receipt"])
        self.assertTrue(result["inclusion"])

    def test_tampered_intent_fails(self):
        bundle = mexport.build_bundle(self.receipt, self.intent, self.grant,
                                      None, key_path=self.key,
                                      signer="approver")
        bundle["intent"]["effect"]["amount"]["value"] = 1.0
        self.assertFalse(mexport.verify_bundle(bundle, self.signers)["valid"])

    def test_tampered_receipt_fails(self):
        bundle = mexport.build_bundle(self.receipt, self.intent, self.grant,
                                      None, key_path=self.key,
                                      signer="approver")
        bundle["receipt"]["body"]["decision"] = "forged"
        self.assertFalse(mexport.verify_bundle(bundle, self.signers)["valid"])

    def test_wrong_signer_fails(self):
        other = os.path.join(self.dir, "other")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", other],
                       check=True, capture_output=True)
        bundle = mexport.build_bundle(self.receipt, self.intent, self.grant,
                                      None, key_path=other, signer="approver")
        self.assertFalse(mexport.verify_bundle(bundle, self.signers)["signature"])

    def test_revoked_signer_fails(self):
        from mandate import sign
        fp = sign.fingerprint(pathlib.Path(self.key + ".pub")
                              .read_text(encoding="utf-8").split()[1])
        revoked = os.path.join(self.dir, "revoked")
        pathlib.Path(revoked).write_text(fp + "\n", encoding="utf-8")
        bundle = mexport.build_bundle(self.receipt, self.intent, self.grant,
                                      None, key_path=self.key,
                                      signer="approver")
        result = mexport.verify_bundle(bundle, self.signers,
                                       revoked_path=revoked)
        self.assertFalse(result["signature"])

    def test_notifier_receives_advisory_text(self):
        sent = []

        class Fake:
            def send(self, text):
                sent.append(text)
                return True

        approver = mapprover.Approver(self.key, "approver",
                                      confirm=lambda *args: True,
                                      notifier=Fake())
        result = approver.request(intent_factory())
        self.assertTrue(result["ok"])
        self.assertEqual(len(sent), 1)
        self.assertIn("MANDATE approval requested", sent[0])
        self.assertIn("Example Supplier", sent[0])
        self.assertIn(result["commitment"], sent[0])
        self.assertIn("advisory only", sent[0])

    def test_notifier_failure_does_not_block(self):
        class Boom:
            def send(self, text):
                raise RuntimeError("telegram down")

        approver = mapprover.Approver(self.key, "approver",
                                      confirm=lambda *args: True,
                                      notifier=Boom())
        self.assertTrue(approver.request(intent_factory())["ok"])

    def test_telegram_without_config_is_noop(self):
        from mandate.notify import TelegramNotifier
        self.assertFalse(TelegramNotifier("", "").send("x"))

    def test_cli_export_and_verify(self):
        env = dict(os.environ)
        receipt_path = os.path.join(self.dir, "receipt.json")
        intent_path = os.path.join(self.dir, "intent.json")
        grant_path = os.path.join(self.dir, "grant.json")
        proof_path = os.path.join(self.dir, "proof.json")
        bundle_path = os.path.join(self.dir, "bundle.json")
        pathlib.Path(receipt_path).write_text(json.dumps(self.receipt),
                                              encoding="utf-8")
        pathlib.Path(intent_path).write_text(json.dumps(self.intent),
                                             encoding="utf-8")
        pathlib.Path(grant_path).write_text(json.dumps(self.grant),
                                            encoding="utf-8")
        pathlib.Path(proof_path).write_text(json.dumps(self.proof),
                                            encoding="utf-8")
        out = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"), "export",
             "--receipt", receipt_path, "--intent", intent_path,
             "--grant", grant_path, "--proof", proof_path,
             "--key", self.key, "--signer", "approver", "--out", bundle_path],
            capture_output=True, text=True, env=env)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        check = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"),
             "--signers", self.signers, "export-verify",
             "--bundle", bundle_path],
            capture_output=True, text=True, env=env)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertTrue(json.loads(check.stdout)["valid"])


if __name__ == "__main__":
    unittest.main()
