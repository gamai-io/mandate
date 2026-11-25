"""Crash recovery must not charge twice, and single-use must cross deployments."""
from __future__ import annotations

import json
import os
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

from mandate import core
from test_broker_custody import PROVIDER_SECRET, FakeProvider, free_port

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Recovery(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        shutil.copy(os.path.join(ROOT, "policy.json"), self.dir)
        os.makedirs(os.path.join(self.dir, "trust"), exist_ok=True)
        self.key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True)
        with open(os.path.join(self.dir, "trust", "allowed_signers"), "w") as fh:
            fh.write('approver namespaces="mandate" %s\n'
                     % open(self.key + ".pub").read().strip())
        self.provider = FakeProvider()
        self.port = free_port()
        self.journal = os.path.join(self.dir, "journal.sqlite")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        config = {
            "host": "127.0.0.1", "port": self.port,
            "policy": os.path.join(self.dir, "policy.json"),
            "signers": os.path.join(self.dir, "trust", "allowed_signers"),
            "ledger": self.ledger,
            "nonce_db": os.path.join(self.dir, "used.sqlite"),
            "journal_db": self.journal,
            "effects_dir": os.path.join(self.dir, "effects"),
            "outbox": os.path.join(self.dir, "outbox"),
            "broker_name": "gama-broker",
            "lease_s": 0.05,
            "payment": {"provider": "http",
                        "url": "http://127.0.0.1:%d" % self.provider.port,
                        "token_env": "PAY_TOKEN"},
        }
        cfg = os.path.join(self.dir, "broker.json")
        json.dump(config, open(cfg, "w"))
        env = {k: v for k, v in os.environ.items() if k != "PAY_TOKEN"}
        env.update({"PAY_TOKEN": PROVIDER_SECRET, "PYTHONPATH": ROOT})
        self.broker = subprocess.Popen(
            [sys.executable, "-m", "mandate.broker", "--config", cfg],
            cwd=self.dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(120):
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/health" % self.port,
                                       timeout=0.2).read()
                break
            except OSError:
                time.sleep(0.05)

    def tearDown(self) -> None:
        self.broker.terminate()
        try:
            self.broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.broker.kill()
        self.provider.stop()
        self.tmp.cleanup()

    def _grant(self, nonce: str) -> dict:
        intent = core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s1"},
            "effect": {"kind": "payment.send", "target": "Example Supplier",
                       "amount": {"value": 1170.0, "currency": "BAM"},
                       "params": {"ref": "f-1"}},
            "requested_by": "ops", "nonce": nonce,
            "provenance": [{"type": "data_ref", "source": "erp:vendor:1"},
                           {"type": "data_ref", "source": "Example Supplier"},
                           {"type": "data_ref", "source": "1170.0"}]})
        grant_core = core.build_grant_core(
            core.intent_commitment(intent), "approver", ttl_s=600,
            render_hash=core.render_hash(intent), agent="bank-agent",
            audience="gama-broker")
        return {"intent": intent, "grant": core.make_grant(grant_core, self.key)}

    def _post(self, payload: dict):
        request = urllib.request.Request(
            "http://127.0.0.1:%d/execute" % self.port,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_an_expired_lease_recovers_without_charging_again(self) -> None:
        payload = self._grant("n-rec-1")
        status, body = self._post(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.provider.charges), 1)

        grant_nonce = payload["grant"]["grant"]["nonce"]
        # pretend the worker died after charging but before writing the receipt
        con = sqlite3.connect(self.journal)
        con.execute("UPDATE effect_journal SET state='executing', lease_until=0 "
                    "WHERE idem_key=?", (grant_nonce,))
        con.commit()
        con.close()

        status, body = self._post(payload)
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("recovered"), body)
        self.assertEqual(len(self.provider.charges), 1, "the provider saw one charge")

    def test_a_nonce_claimed_elsewhere_is_refused(self) -> None:
        payload = self._grant("n-rec-2")
        # another deployment (or another ledger) already spent this nonce
        self.assertTrue(core.claim_nonce_db(payload["grant"]["grant"]["nonce"],
                                           self.ledger))
        status, body = self._post(payload)
        self.assertEqual(status, 409, body)
        self.assertIn("nonce", json.dumps(body).lower())
        self.assertEqual(len(self.provider.charges), 0)


if __name__ == "__main__":
    unittest.main()
