"""mTLS: the agent's identity is its certificate, and the grant must match it."""
from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

from test_broker_custody import PROVIDER_SECRET, FakeProvider, free_port

from mandate import agents, core

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def make_pki(directory: str) -> dict:
    ca_key = os.path.join(directory, "ca.key")
    ca_crt = os.path.join(directory, "ca.crt")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-keyout", ca_key, "-out", ca_crt, "-subj", "/CN=test-ca")
    server_key = os.path.join(directory, "server.key")
    server_crt = os.path.join(directory, "server.crt")
    csr = os.path.join(directory, "server.csr")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", server_key,
            "-out", csr, "-subj", "/CN=127.0.0.1")
    ext = os.path.join(directory, "san.ext")
    open(ext, "w").write("subjectAltName=IP:127.0.0.1\n")
    openssl("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
            "-CAcreateserial", "-out", server_crt, "-days", "2", "-extfile", ext)
    clients = {}
    for name in ("agent-a", "agent-b", "agent-c"):
        key = os.path.join(directory, name + ".key")
        crt = os.path.join(directory, name + ".crt")
        csr = os.path.join(directory, name + ".csr")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                "-out", csr, "-subj", "/CN=" + name)
        openssl("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
                "-CAcreateserial", "-out", crt, "-days", "2")
        clients[name] = (crt, key)
    return {"ca": ca_crt, "server_crt": server_crt, "server_key": server_key,
            "clients": clients, "ca_key": ca_key}


class MTLS(unittest.TestCase):
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
        self.pki = make_pki(self.dir)
        self.store = os.path.join(self.dir, "agents.json")
        for name in ("agent-a", "agent-b"):
            agents.ensure_name(self.store, name)
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
            [sys.executable, "-m", "mandate.broker", "--config", cfg,
             "--tls-cert", self.pki["server_crt"],
             "--tls-key", self.pki["server_key"],
             "--client-ca", self.pki["ca"]],
            cwd=self.dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(120):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
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

    def _grant(self, agent: str, nonce: str) -> dict:
        intent = core.normalize_intent({
            "v": 1, "actor": {"agent": agent, "session": "s1"},
            "effect": {"kind": "payment.send", "target": "Example Supplier",
                       "amount": {"value": 1170.0, "currency": "BAM"},
                       "params": {"ref": "f-1"}},
            "requested_by": "ops", "nonce": nonce,
            "provenance": [{"type": "data_ref", "source": "erp:vendor:1"},
                           {"type": "data_ref", "source": "Example Supplier"},
                           {"type": "data_ref", "source": "1170.0"}]})
        grant_core = core.build_grant_core(
            core.intent_commitment(intent), "approver", ttl_s=600,
            render_hash=core.render_hash(intent), agent=agent,
            audience="gama-broker")
        return {"intent": intent, "grant": core.make_grant(grant_core, self.key)}

    def _context(self, client: str | None) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=self.pki["ca"])
        context.check_hostname = False            # the SAN is IP; keep the test simple
        if client:
            crt, key = self.pki["clients"][client]
            context.load_cert_chain(crt, key)
        return context

    def _post(self, payload: dict, client: str | None):
        context = self._context(client)
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=10,
                                                context=context)
        try:
            connection.request("POST", "/execute", body=json.dumps(payload),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read() or b"{}")
        finally:
            connection.close()

    def test_agent_a_certificate_executes_its_own_grant(self) -> None:
        status, body = self._post(self._grant("agent-a", "n-mtls-1"), "agent-a")
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.provider.charges), 1)

    def test_agent_bs_certificate_cannot_redeem_agent_as_grant(self) -> None:
        status, body = self._post(self._grant("agent-a", "n-mtls-2"), "agent-b")
        self.assertEqual(status, 409, body)
        self.assertIn("belongs to", json.dumps(body))
        self.assertEqual(len(self.provider.charges), 0)

    def test_an_unregistered_certificate_is_refused(self) -> None:
        status, body = self._post(self._grant("agent-c", "n-mtls-3"), "agent-c")
        self.assertEqual(status, 403, body)
        self.assertEqual(body.get("error"), "unknown_agent")

    def test_no_certificate_means_no_connection(self) -> None:
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            self._post(self._grant("agent-a", "n-mtls-4"), None)


if __name__ == "__main__":
    unittest.main()
