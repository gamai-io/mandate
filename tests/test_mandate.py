import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from mandate import broker, core

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
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}],
    }
    intent.update(over)
    return intent


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen missing")
class MandateTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "id_ed25519")
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "t", "-f", self.key],
            check=True, capture_output=True)
        pub = pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip()
        self.signers = os.path.join(self.dir, "allowed_signers")
        pathlib.Path(self.signers).write_text("approver %s\n" % pub, encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")

    def tearDown(self):
        self.td.cleanup()

    def _grant(self, intent, approver="approver", ttl=900, key=None,
               render_hash=None):
        proposal = core.propose(intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], approver, ttl_s=ttl,
            render_hash=(proposal["render_hash"] if render_hash is None
                         else render_hash))
        return core.make_grant(grant_core, key or self.key)

    def test_check_risky_requires_grant(self):
        decision = core.check(intent_factory())
        self.assertEqual(decision["decision"], "ask")
        self.assertEqual(decision["risk"], "high")

    def test_check_unknown_effect_denied(self):
        decision = core.check(intent_factory(effect={"kind": "rm.rf", "target": "/"}))
        self.assertEqual(decision["decision"], "deny")

    def test_check_low_risk_allowed(self):
        decision = core.check(intent_factory(effect={"kind": "read.lookup",
                                                     "target": "customers"}))
        self.assertEqual(decision["decision"], "allow")

    def test_commitment_is_stable_and_render_is_human(self):
        a = core.propose(intent_factory())
        b = core.propose(intent_factory())
        self.assertEqual(a["commitment"], b["commitment"])
        self.assertIn("payment.send", a["render"]["summary"])
        self.assertIn("1170.00 BAM", a["render"]["summary"])

    def test_redeem_success_and_chain(self):
        intent = intent_factory()
        grant = self._grant(intent)
        receipt = core.redeem(intent, grant, self.signers, self.ledger)
        self.assertEqual(receipt["body"]["decision"], "executed")
        self.assertTrue(core.verify_chain(self.ledger))
        self.assertTrue(core.verify_receipt(receipt, intent, grant, self.signers))

    def test_tampered_amount_is_rejected(self):
        intent = intent_factory()
        grant = self._grant(intent)
        tampered = intent_factory()
        tampered["effect"] = dict(tampered["effect"])
        tampered["effect"]["amount"] = {"value": 1.0, "currency": "BAM"}
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(tampered, grant, self.signers, self.ledger)

    def test_replay_is_rejected(self):
        intent = intent_factory()
        grant = self._grant(intent)
        core.redeem(intent, grant, self.signers, self.ledger)
        with self.assertRaises(core.GrantReplayed):
            core.redeem(intent, grant, self.signers, self.ledger)

    def test_agent_cannot_approve_itself(self):
        intent = intent_factory(actor={"agent": "approver", "session": "s"})
        grant = self._grant(intent, approver="approver")
        pathlib.Path(self.signers).write_text(
            "approver %s\n" % pathlib.Path(self.key + ".pub").read_text().strip(),
            encoding="utf-8")
        with self.assertRaises(core.SelfApproval):
            core.redeem(intent, grant, self.signers, self.ledger)

    def test_expired_grant_rejected(self):
        intent = intent_factory()
        grant = self._grant(intent, ttl=1)
        with self.assertRaises(core.GrantExpired):
            core.redeem(intent, grant, self.signers, self.ledger,
                        now=time.time() + 10)

    def test_unknown_signer_rejected(self):
        intent = intent_factory()
        other = os.path.join(self.dir, "other")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", other],
                       check=True, capture_output=True)
        grant = self._grant(intent, key=other)
        with self.assertRaises(core.GrantInvalid):
            core.redeem(intent, grant, self.signers, self.ledger)

    def test_render_hash_is_bound(self):
        intent = intent_factory()
        grant = self._grant(intent, render_hash="deadbeef")
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(intent, grant, self.signers, self.ledger)

    def test_render_includes_all_params(self):
        intent = intent_factory()
        intent["effect"]["params"] = {"ref": "x", "supplier": "Example", "extra": "Z"}
        summary = core.render(intent)["summary"]
        self.assertIn("supplier=Example", summary)
        self.assertIn("extra=Z", summary)

    def _start_broker(self):
        b = broker.Broker(
            os.path.join(ROOT, "policy.json"), self.signers, self.ledger,
            os.path.join(self.dir, "used.sqlite"),
            effects_dir=os.path.join(self.dir, "effects"),
            outbox=os.path.join(self.dir, "outbox"))
        srv = broker.make_server("127.0.0.1", 0, b)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def _post(self, port, intent, grant):
        data = json.dumps({"intent": intent, "grant": grant}).encode()
        request = urllib.request.Request(
            "http://127.0.0.1:%d/execute" % port, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_broker_executes_once(self):
        intent = intent_factory()
        grant = self._grant(intent)
        port = self._start_broker()
        status, body = self._post(port, intent, grant)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["effect"], "payment.send")
        status2, body2 = self._post(port, intent, grant)
        self.assertEqual(status2, 409, body2)
        self.assertEqual(body2["error"], "GrantReplayed")

    def test_broker_rejects_tampered_amount(self):
        intent = intent_factory()
        grant = self._grant(intent)
        port = self._start_broker()
        tampered = intent_factory()
        tampered["effect"] = dict(tampered["effect"])
        tampered["effect"]["amount"] = {"value": 1.0, "currency": "BAM"}
        status, body = self._post(port, tampered, grant)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], "CommitmentMismatch")

    def test_broker_rejects_unknown_effect(self):
        intent = intent_factory(effect={"kind": "rm.rf", "target": "/"})
        port = self._start_broker()
        status, body = self._post(port, intent, {})
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], "PolicyDenied")

    def test_cli_end_to_end(self):
        env = dict(os.environ)
        intent_path = os.path.join(self.dir, "intent.json")
        pathlib.Path(intent_path).write_text(json.dumps(intent_factory()),
                                             encoding="utf-8")
        prop = os.path.join(self.dir, "proposal.json")
        grant = os.path.join(self.dir, "grant.json")
        subprocess.run([sys.executable, str(ROOT / "bin" / "mandate"),
                        "propose", "--intent", intent_path, "--out", prop],
                       check=True, capture_output=True, env=env)
        subprocess.run([sys.executable, str(ROOT / "bin" / "mandate"),
                        "grant", "--proposal", prop, "--approver", "approver",
                        "--key", self.key, "--out", grant],
                       check=True, capture_output=True, env=env)
        out = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"), "redeem",
             "--intent", intent_path, "--grant", grant,
             "--ledger", self.ledger, "--signers", self.signers],
            capture_output=True, text=True, env=env)
        self.assertEqual(out.returncode, 0, out.stderr + out.stdout)
        receipt = json.loads(out.stdout)
        self.assertEqual(receipt["body"]["decision"], "executed")


if __name__ == "__main__":
    unittest.main()