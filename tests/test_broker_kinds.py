"""Non-payment effects: a SQL write and a registry publish, both owned by the broker."""
from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = "registry-token"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeRegistry:
    def __init__(self) -> None:
        self.published: dict[str, dict] = {}
        self.port = free_port()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _auth(self) -> bool:
                return self.headers.get("Authorization", "") == "Bearer " + TOKEN

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
                found = outer.published.get(key)
                self._json(200 if found else 404, found or {"error": "missing"})

            def do_POST(self):
                if not self._auth():
                    self._json(401, {"error": "no token"})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                key = self.headers.get("Idempotency-Key") or payload.get("idempotency_key")
                if key not in outer.published:
                    outer.published[key] = {"artefact": payload.get("artefact"),
                                            "status": "accepted"}
                self._json(200, outer.published[key])

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()


class Kinds(unittest.TestCase):
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
        self.registry = FakeRegistry()
        self.db = os.path.join(self.dir, "app.sqlite")
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE invoices(id TEXT PRIMARY KEY, paid INT)")
        con.commit()
        con.close()
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
            "sql": {"db": self.db},
            "publish": {"url": "http://127.0.0.1:%d" % self.registry.port,
                        "token_env": "REGISTRY_TOKEN"},
        }
        cfg = os.path.join(self.dir, "broker.json")
        json.dump(config, open(cfg, "w"))
        env = {k: v for k, v in os.environ.items() if k != "REGISTRY_TOKEN"}
        env.update({"REGISTRY_TOKEN": TOKEN, "PYTHONPATH": ROOT})
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
        self.registry.stop()
        self.tmp.cleanup()

    def grant(self, kind: str, target: str, params: dict, nonce: str) -> dict:
        intent = core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": kind, "target": target, "params": params},
            "requested_by": "ops", "nonce": nonce,
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})
        gc = core.build_grant_core(core.intent_commitment(intent), "approver",
                                   ttl_s=600, render_hash=core.render_hash(intent),
                                   agent="bank-agent", audience="gama-broker")
        return {"intent": intent, "grant": core.make_grant(gc, self.key)}

    def post(self, payload: dict):
        request = urllib.request.Request(
            "http://127.0.0.1:%d/execute" % self.port,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_a_sql_write_applies_once(self) -> None:
        payload = self.grant("sql.write", "invoices",
                             {"sql": "INSERT INTO invoices(id, paid) VALUES(:id, 1)",
                              "args": {"id": "inv-1"}}, "n-sql-1")
        status, body = self.post(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["result"]["rows_changed"], 1)
        con = sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM invoices").fetchone()[0], 1)
        con.close()
        status, body = self.post(payload)
        self.assertEqual(status, 200, body)
        con = sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM invoices").fetchone()[0], 1,
                         "a replay must not write twice")
        con.close()

    def test_a_delete_is_refused(self) -> None:
        payload = self.grant("sql.write", "invoices",
                             {"sql": "DELETE FROM invoices", "args": {}}, "n-sql-2")
        status, body = self.post(payload)
        self.assertEqual(status, 409, body)
        self.assertIn("INSERT and UPDATE", json.dumps(body))

    def test_a_publish_goes_out_once_with_the_broker_token(self) -> None:
        payload = self.grant("package.publish", "pypi:internal",
                             {"artefact": "pkg-1.0.0.whl"}, "n-pub-1")
        status, body = self.post(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.registry.published), 1)
        status, body = self.post(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.registry.published), 1, "one publish, not two")


if __name__ == "__main__":
    unittest.main()
