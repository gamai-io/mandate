"""Per-agent tokens: one broker, several agents, no shared identity."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from test_broker_custody import PROVIDER_SECRET, FakeProvider, free_port

from mandate import agents, core

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def intent(nonce: str, agent: str):
    return core.normalize_intent({
        "v": 1, "actor": {"agent": agent, "session": "s1"},
        "effect": {"kind": "payment.send", "target": "Example Supplier",
                   "amount": {"value": 1170.0, "currency": "BAM"},
                   "params": {"ref": "f-1"}},
        "requested_by": "ops", "nonce": nonce,
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1"},
                       {"type": "data_ref", "source": "Example Supplier"},
                       {"type": "data_ref", "source": "1170.0"}]})


class Store(unittest.TestCase):
    def test_a_token_is_shown_once_and_stored_as_a_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "agents.json")
            created = agents.add(path, "bank-agent", "ops")
            self.assertNotIn(created["token"], open(path).read())
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(agents.resolve(path, created["token"]), "bank-agent")

    def test_an_unknown_token_resolves_to_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "agents.json")
            agents.add(path, "bank-agent")
            self.assertIsNone(agents.resolve(path, "mb_nope"))

    def test_a_revoked_token_stops_working(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "agents.json")
            token = agents.add(path, "bank-agent")["token"]
            agents.revoke(path, "bank-agent")
            self.assertIsNone(agents.resolve(path, token))

    def test_a_duplicate_name_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "agents.json")
            agents.add(path, "bank-agent")
            with self.assertRaises(agents.AgentStoreError):
                agents.add(path, "bank-agent")

    def test_a_corrupt_store_is_an_error_not_an_empty_store(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "agents.json")
            open(path, "w").write("{broken")
            with self.assertRaises(agents.AgentStoreError):
                agents.list_store(path)


class Broker(unittest.TestCase):
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
        self.store = os.path.join(self.dir, "agents.json")
        self.token_a = agents.add(self.store, "agent-a")["token"]
        self.token_b = agents.add(self.store, "agent-b")["token"]
        self.provider = FakeProvider()
        self.port = free_port()
        config = {
            "host": "127.0.0.1", "port": self.port,
            "policy": os.path.join(self.dir, "policy.json"),
            "signers": os.path.join(self.dir, "trust", "allowed_signers"),
            "ledger": os.path.join(self.dir, "ledger.jsonl"),
            "nonce_db": os.path.join(self.dir, "used.sqlite"),
            "journal_db": os.path.join(self.dir, "journal.sqlite"),
            "effects_dir": os.path.join(self.dir, "effects"),
            "outbox": os.path.join(self.dir, "outbox"),
            "broker_name": "gama-broker",
            "agents": self.store,
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
        for _ in range(100):
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

    def grant(self, agent: str, nonce: str) -> dict:
        item = intent(nonce, agent)
        grant_core = core.build_grant_core(
            core.intent_commitment(item), "approver", ttl_s=600,
            render_hash=core.render_hash(item), agent=agent,
            audience="gama-broker")
        return {"intent": item, "grant": core.make_grant(grant_core, self.key)}

    def post(self, payload, token):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            "http://127.0.0.1:%d/execute" % self.port,
            data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_agent_a_executes_and_is_charged_once(self) -> None:
        status, body = self.post(self.grant("agent-a", "n-a-1"), self.token_a)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.provider.charges), 1)

    def test_agent_bs_token_cannot_redeem_agent_as_grant(self) -> None:
        status, body = self.post(self.grant("agent-a", "n-a-2"), self.token_b)
        self.assertEqual(status, 409, body)
        self.assertIn("belongs to", json.dumps(body))
        self.assertEqual(len(self.provider.charges), 0)

    def test_an_unknown_token_is_refused(self) -> None:
        status, body = self.post(self.grant("agent-a", "n-a-3"), "mb_unknown")
        self.assertEqual(status, 401, body)

    def test_a_revoked_agent_is_refused(self) -> None:
        agents.revoke(self.store, "agent-a")
        status, body = self.post(self.grant("agent-a", "n-a-4"), self.token_a)
        self.assertEqual(status, 401, body)

    def test_health_counts_agents_without_naming_tokens(self) -> None:
        with urllib.request.urlopen("http://127.0.0.1:%d/health" % self.port) as resp:
            health = json.loads(resp.read())
        self.assertEqual(health["agents"], 2)
        self.assertNotIn("mb_", json.dumps(health))


if __name__ == "__main__":
    unittest.main()
