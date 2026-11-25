"""Credential custody: the agent can execute an effect without ever holding the key.

This is the claim the whole broker exists for, so it is tested end to end with
three processes: a fake payment provider (holds nothing), the broker (holds the
provider credential), and an "agent" that only has the broker token.
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from mandate import core

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROVIDER_SECRET = "provider-secret-value"
AGENT_TOKEN = "agent-only-token"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeProvider:
    """Requires the bearer token; records one charge per idempotency key."""

    def __init__(self) -> None:
        self.charges: dict[str, dict] = {}
        self.port = free_port()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _auth(self) -> bool:
                return self.headers.get("Authorization", "") == "Bearer " + PROVIDER_SECRET

            def _json(self, code: int, obj: dict) -> None:
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if not self._auth():
                    self._json(401, {"error": "no token"})
                    return
                key = self.path.strip("/")
                charge = outer.charges.get(key)
                self._json(200 if charge else 404, charge or {"error": "not found"})

            def do_POST(self):
                if not self._auth():
                    self._json(401, {"error": "no token"})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                key = str(payload.get("idempotency_key"))
                if key not in outer.charges:
                    outer.charges[key] = {"idem_key": key, "status": "captured",
                                          "target": payload.get("target"),
                                          "amount": payload.get("amount")}
                self._json(200, outer.charges[key])

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()


class Custody(unittest.TestCase):
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
            "payment": {"provider": "http", "url": "http://127.0.0.1:%d" % self.provider.port,
                        "token_env": "PAY_TOKEN"},
        }
        self.config_path = os.path.join(self.dir, "broker.json")
        with open(self.config_path, "w") as fh:
            json.dump(config, fh)
        env = {k: v for k, v in os.environ.items() if k != "PAY_TOKEN"}
        env.update({"PAY_TOKEN": PROVIDER_SECRET, "MANDATE_BROKER_TOKEN": AGENT_TOKEN,
                    "PYTHONPATH": ROOT})
        self.broker = subprocess.Popen(
            [sys.executable, "-m", "mandate.broker", "--config", self.config_path],
            cwd=self.dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._wait()

    def tearDown(self) -> None:
        self.broker.terminate()
        try:
            self.broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.broker.kill()
        self.provider.stop()
        self.tmp.cleanup()

    def _wait(self) -> None:
        for _ in range(100):
            try:
                urllib.request.urlopen(
                    "http://127.0.0.1:%d/health" % self.port, timeout=0.2).read()
                return
            except OSError:
                time.sleep(0.05)
        raise AssertionError("broker did not start")

    def _grant(self) -> dict:
        intent = core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s1"},
            "effect": {"kind": "payment.send", "target": "Example Supplier",
                       "amount": {"value": 1170.0, "currency": "BAM"},
                       "params": {"ref": "f-1"}},
            "requested_by": "ops", "nonce": "n-custody-1",
            "provenance": [{"type": "data_ref", "source": "erp:vendor:1"},
                           {"type": "data_ref", "source": "Example Supplier"},
                           {"type": "data_ref", "source": "1170.0"}],
        })
        grant_core = core.build_grant_core(
            core.intent_commitment(intent), "approver", ttl_s=600,
            render_hash=core.render_hash(intent), agent="bank-agent",
            audience="gama-broker")
        return {"intent": intent, "grant": core.make_grant(grant_core, self.key)}

    def _post(self, payload: dict, token: str | None = AGENT_TOKEN):
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

    # ------------------------------------------------------------------ tests
    def test_the_agent_has_no_provider_credential_but_the_effect_runs(self) -> None:
        self.assertNotIn("PAY_TOKEN", os.environ, "the test process must not hold it")
        payload = self._grant()
        status, body = self._post(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.provider.charges), 1, "one charge, made by the broker")
        charge = list(self.provider.charges.values())[0]
        self.assertEqual(charge["amount"], 1170.0)

    def test_an_agent_cannot_call_the_provider_itself(self) -> None:
        request = urllib.request.Request(
            "http://127.0.0.1:%d/" % self.provider.port, method="POST",
            data=b'{"idempotency_key":"x","amount":1}')
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 401)

    def test_an_unauthenticated_request_to_the_broker_is_refused(self) -> None:
        status, body = self._post(self._grant(), token=None)
        self.assertEqual(status, 401, body)

    def test_a_replayed_grant_does_not_charge_twice(self) -> None:
        payload = self._grant()
        first, _ = self._post(payload)
        second, body = self._post(payload)
        self.assertEqual(first, 200)
        self.assertIn(second, (200, 409), body)
        self.assertEqual(len(self.provider.charges), 1, "the provider saw one charge")

    def test_health_reports_the_secret_by_name_only(self) -> None:
        with urllib.request.urlopen("http://127.0.0.1:%d/health" % self.port) as resp:
            health = json.loads(resp.read())
        custody = health["custody"]
        self.assertEqual(custody["payment"]["secret"], "env:PAY_TOKEN")
        self.assertTrue(custody["payment"]["present"])
        self.assertNotIn(PROVIDER_SECRET, json.dumps(health))


if __name__ == "__main__":
    unittest.main()
