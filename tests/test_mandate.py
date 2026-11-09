import json
import os
import pathlib
import shutil
import sqlite3
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
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n' % pub, encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")

    def tearDown(self):
        self.td.cleanup()

    def _grant(self, intent, approver="approver", ttl=900, key=None,
               render_hash=None, agent=None, audience="gama-broker"):
        proposal = core.propose(intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], approver, ttl_s=ttl,
            render_hash=(proposal["render_hash"] if render_hash is None
                         else render_hash),
            agent=(agent if agent is not None
                   else str(intent.get("actor", {}).get("agent") or "")),
            audience=audience)
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
            'approver namespaces="mandate" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
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

    def test_namespace_required_and_scoped(self):
        from mandate import sign as msign
        pub = pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip()
        path = os.path.join(self.dir, "no_ns")
        pathlib.Path(path).write_text("approver %s\n" % pub, encoding="utf-8")
        self.assertFalse(msign.authorize_signer("approver", path, "mandate"))
        pathlib.Path(path).write_text(
            'approver namespaces="other" %s\n' % pub, encoding="utf-8")
        self.assertFalse(msign.authorize_signer("approver", path, "mandate"))

    def test_validity_window_enforced(self):
        from mandate import sign as msign
        pub = pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip()
        path = os.path.join(self.dir, "window")
        pathlib.Path(path).write_text(
            'approver namespaces="mandate" valid-before="20200101" %s\n' % pub,
            encoding="utf-8")
        self.assertFalse(msign.authorize_signer("approver", path, "mandate"))
        pathlib.Path(path).write_text(
            'approver namespaces="mandate" valid-after="20990101" %s\n' % pub,
            encoding="utf-8")
        self.assertFalse(msign.authorize_signer("approver", path, "mandate"))
        pathlib.Path(path).write_text(
            'approver namespaces="mandate" %s\n' % pub, encoding="utf-8")
        self.assertTrue(msign.authorize_signer("approver", path, "mandate"))

    def test_revoked_key_rejected(self):
        from mandate import sign as msign
        intent = intent_factory()
        grant = self._grant(intent)
        fp = msign.fingerprint(
            pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").split()[1])
        revoked = os.path.join(self.dir, "revoked")
        pathlib.Path(revoked).write_text(fp + "\n", encoding="utf-8")
        self.assertFalse(msign.authorize_signer(
            "approver", self.signers, "mandate", revoked_path=revoked))
        with self.assertRaises(core.GrantInvalid):
            core.redeem(intent, grant, self.signers, self.ledger,
                        revoked_path=revoked)

    def test_revoke_cli(self):
        revoked = os.path.join(self.dir, "revoked_cli")
        out = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"), "--revoked", revoked,
             "revoke", "--pub", self.key + ".pub", "--reason", "test"],
            capture_output=True, text=True, env=dict(os.environ))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        data = json.loads(out.stdout)
        self.assertTrue(data["added"])
        self.assertIn(data["fingerprint"],
                      pathlib.Path(revoked).read_text(encoding="utf-8"))

    def test_render_hash_is_bound(self):
        intent = intent_factory()
        grant = self._grant(intent, render_hash="deadbeef")
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(intent, grant, self.signers, self.ledger)

    def test_render_includes_all_params(self):
        intent = intent_factory()
        intent["effect"]["params"] = {"ref": "x", "supplier": "Example", "extra": "Z"}
        summary = core.render(intent)["summary"]
        self.assertIn('supplier="Example"', summary)
        self.assertIn('extra="Z"', summary)

    def test_hidden_effect_field_rejected(self):
        intent = intent_factory()
        intent["effect"]["iban"] = "XX99"
        with self.assertRaises(core.MandateError):
            core.normalize_intent(intent)

    def test_nan_amount_rejected(self):
        intent = intent_factory()
        intent["effect"]["amount"] = {"value": float("nan"), "currency": "BAM"}
        with self.assertRaises(core.MandateError):
            core.normalize_intent(intent)

    def test_max_uses_clamped_to_one(self):
        grant = core.build_grant_core("sha256:x", "approver", max_uses=5)
        self.assertEqual(grant["scope"]["max_uses"], 1)

    def test_actor_swap_rejected(self):
        intent = intent_factory()
        grant = self._grant(intent)
        swapped = intent_factory(actor={"agent": "other@test", "session": "s"})
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(swapped, grant, self.signers, self.ledger)

    def test_unknown_effect_redeem_denied(self):
        intent = intent_factory(effect={"kind": "rm.rf", "target": "/"})
        grant = self._grant(intent)
        with self.assertRaises(core.PolicyDenied):
            core.redeem(intent, grant, self.signers, self.ledger)

    def test_erp_nan_blocked(self):
        from mandate.adapters import ErpChecker
        erp = ErpChecker(self._make_erp())
        result = erp.check({"effect": {
            "kind": "payment.send", "target": "Example Supplier",
            "amount": {"value": float("nan")}}})
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "invalid_amount")

    def test_concurrent_redeem_single_success(self):
        intent = intent_factory()
        grant = self._grant(intent)
        ok, failed = [], []

        def worker():
            try:
                core.redeem(intent, grant, self.signers, self.ledger)
                ok.append(1)
            except core.MandateError:
                failed.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(ok), 1)
        self.assertTrue(core.verify_chain(self.ledger))

    def test_verify_chain_empty_and_truncated(self):
        self.assertFalse(core.verify_chain(os.path.join(self.dir, "missing.jsonl")))
        first = intent_factory(nonce="chain-1")
        second = intent_factory(nonce="chain-2")
        core.redeem(first, self._grant(first), self.signers, self.ledger)
        core.redeem(second, self._grant(second), self.signers, self.ledger)
        self.assertTrue(core.verify_chain(self.ledger))
        lines = pathlib.Path(self.ledger).read_text(encoding="utf-8").splitlines()
        pathlib.Path(self.ledger).write_text(lines[0] + "\n", encoding="utf-8")
        self.assertFalse(core.verify_chain(self.ledger))

    def test_proposal_mismatch_cli(self):
        intent_path = os.path.join(self.dir, "intent.json")
        pathlib.Path(intent_path).write_text(json.dumps(intent_factory()),
                                             encoding="utf-8")
        prop = os.path.join(self.dir, "proposal.json")
        subprocess.run([sys.executable, str(ROOT / "bin" / "mandate"),
                        "propose", "--intent", intent_path, "--out", prop],
                       check=True, capture_output=True, env=dict(os.environ))
        data = json.loads(pathlib.Path(prop).read_text(encoding="utf-8"))
        data["commitment"] = "sha256:deadbeef"
        pathlib.Path(prop).write_text(json.dumps(data), encoding="utf-8")
        out = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"), "grant",
             "--proposal", prop, "--approver", "approver", "--key", self.key],
            capture_output=True, text=True, env=dict(os.environ))
        self.assertEqual(out.returncode, 3, out.stdout + out.stderr)
        self.assertIn("ProposalMismatch", out.stdout)

    def _make_erp(self):
        path = os.path.join(self.dir, "erp.sqlite")
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE vendors(name TEXT, invoice_total REAL, currency TEXT)")
        con.execute("INSERT INTO vendors VALUES ('Example Supplier', 1170.0, 'BAM')")
        con.commit()
        con.close()
        return {
            "db": path,
            "checks": {"payment.send": {
                "query": "SELECT invoice_total FROM vendors WHERE name = :target",
                "amount_field": "invoice_total", "tolerance_pct": 0.5}},
            "derive": {"payment.send": {
                "query": "SELECT name, invoice_total, currency FROM vendors"
                         " WHERE name = :target",
                "fields": {"counterparty": "name", "amount": "invoice_total",
                           "currency": "currency"},
                "tolerance_pct": 0.5}},
        }

    def _start_broker(self, smtp=None, erp=None, receipt_key="",
                      broker_name="gama-broker"):
        b = broker.Broker(
            os.path.join(ROOT, "policy.json"), self.signers, self.ledger,
            os.path.join(self.dir, "used.sqlite"),
            receipt_key=receipt_key, broker_name=broker_name,
            effects_dir=os.path.join(self.dir, "effects"),
            outbox=os.path.join(self.dir, "outbox"),
            smtp=smtp, erp=erp)
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

    def test_erp_precondition_blocks_unknown_target(self):
        intent = intent_factory()
        intent["effect"]["target"] = "Beta d.o.o."
        grant = self._grant(intent)
        port = self._start_broker(erp=self._make_erp())
        status, body = self._post(port, intent, grant)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], "PreconditionFailed")

    def test_erp_amount_mismatch_blocks(self):
        intent = intent_factory()
        intent["effect"]["amount"] = {"value": 1.0, "currency": "BAM"}
        grant = self._grant(intent)
        port = self._start_broker(erp=self._make_erp())
        status, body = self._post(port, intent, grant)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], "PreconditionFailed")

    def test_precondition_failure_does_not_consume_grant(self):
        erp = self._make_erp()
        intent = intent_factory()
        intent["effect"]["target"] = "Beta d.o.o."
        grant = self._grant(intent)
        port = self._start_broker(erp=erp)
        status, _body = self._post(port, intent, grant)
        self.assertEqual(status, 409)
        con = sqlite3.connect(erp["db"])
        con.execute("INSERT INTO vendors VALUES ('Beta d.o.o.', 1170.0, 'BAM')")
        con.commit()
        con.close()
        status2, body2 = self._post(port, intent, grant)
        self.assertEqual(status2, 200, body2)

    def test_audience_mismatch_rejected(self):
        intent = intent_factory()
        grant = self._grant(intent)
        port = self._start_broker(broker_name="other-broker")
        status, body = self._post(port, intent, grant)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], "GrantInvalid")

    def test_unbound_grant_rejected(self):
        intent = intent_factory()
        grant = self._grant(intent, audience="")
        port = self._start_broker()
        status, body = self._post(port, intent, grant)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], "GrantInvalid")

    def test_derive_currency_mismatch_blocked(self):
        intent = intent_factory()
        intent["effect"]["amount"] = {"value": 1170.0, "currency": "EUR"}
        grant = self._grant(intent)
        port = self._start_broker(erp=self._make_erp())
        status, body = self._post(port, intent, grant)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], "PreconditionFailed")
        self.assertIn("derivation", body["message"])

    def test_smtp_dry_run_message(self):
        intent = intent_factory(effect={
            "kind": "message.send", "target": "kupac@example.com",
            "params": {"subject": "Ponuda", "body": "Dobar dan"}})
        grant = self._grant(intent)
        outbox = os.path.join(self.dir, "outbox-smtp")
        port = self._start_broker(smtp={"mode": "dry_run", "outbox": outbox})
        status, body = self._post(port, intent, grant)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["result"]["dry_run"])
        self.assertTrue(os.path.exists(body["result"]["path"]))

    def test_broker_result_signature_verifiable(self):
        broker_key = os.path.join(self.dir, "broker_key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", broker_key],
                       check=True, capture_output=True)
        broker_signers = os.path.join(self.dir, "broker_signers")
        pathlib.Path(broker_signers).write_text(
            'gama-broker namespaces="mandate-broker" %s\n' % pathlib.Path(
                broker_key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        intent = intent_factory()
        grant = self._grant(intent)
        port = self._start_broker(receipt_key=broker_key,
                                  broker_name="gama-broker")
        status, body = self._post(port, intent, grant)
        self.assertEqual(status, 200, body)
        entry = body["result_entry"]
        self.assertTrue(core.verify_result_entry(entry, broker_signers))
        forged = json.loads(json.dumps(entry))
        forged["body"]["status"] = "ok-forged"
        self.assertFalse(core.verify_result_entry(forged, broker_signers))

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