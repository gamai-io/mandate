import json
import os
import pathlib
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from mandate import approver as mapprover
from mandate import broker, core
from mandate import witness as mwit

ROOT = pathlib.Path(__file__).resolve().parents[1]


def intent_factory(**over):
    intent = {
        "v": 1,
        "actor": {"agent": "agent@example"},
        "effect": {
            "kind": "payment.send",
            "target": "Example Supplier",
            "amount": {"value": 1170.0, "currency": "BAM"},
            "params": {"ref": "f-1"},
        },
        "requested_by": "approver",
        "nonce": "n-1",
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}],
    }
    intent.update(over)
    return intent


class OpsTests(unittest.TestCase):
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

    def tearDown(self):
        self.td.cleanup()

    def _grant(self, intent):
        proposal = core.propose(intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=900,
            render_hash=proposal["render_hash"],
            agent=str(intent["actor"]["agent"]), audience="gama-broker")
        return core.make_grant(grant_core, self.key)

    def test_broker_rate_limit_and_metrics(self):
        intent = intent_factory()
        grant = self._grant(intent)
        b = broker.Broker(
            os.path.join(ROOT, "policy.json"), self.signers,
            os.path.join(self.dir, "ledger.jsonl"),
            os.path.join(self.dir, "used.sqlite"),
            journal_db=os.path.join(self.dir, "journal.sqlite"),
            effects_dir=os.path.join(self.dir, "effects"),
            rate_per_min=60, rate_burst=1, recover_on_start=False)
        server = broker.make_server("127.0.0.1", 0, b)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:%d" % server.server_address[1]

        def post():
            request = urllib.request.Request(
                base + "/execute",
                data=json.dumps({"intent": intent, "grant": grant}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=10) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                return exc.code

        self.assertEqual(post(), 200)
        self.assertEqual(post(), 429)
        with urllib.request.urlopen(base + "/metrics", timeout=5) as resp:
            text = resp.read().decode()
        self.assertIn("mandate_broker_requests_total", text)
        self.assertIn("mandate_broker_rate_limited_total", text)

    def test_approver_rate_limit_and_metrics(self):
        approver = mapprover.Approver(self.key, "approver",
                                      confirm=lambda *args: True,
                                      rate_per_min=60, rate_burst=1)
        server = mapprover.make_server("127.0.0.1", 0, approver)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:%d" % server.server_address[1]

        def post():
            request = urllib.request.Request(
                base + "/request",
                data=json.dumps({"intent": intent_factory()}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=10) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                return exc.code

        self.assertEqual(post(), 200)
        self.assertEqual(post(), 429)
        with urllib.request.urlopen(base + "/metrics", timeout=5) as resp:
            text = resp.read().decode()
        self.assertIn("mandate_approver_requests_total", text)

    def test_witness_rate_limit_and_metrics(self):
        state = os.path.join(self.dir, "witness.json")
        server = mwit.make_server("127.0.0.1", 0, state, self.signers, "tok",
                                  rate_per_min=60, rate_burst=1)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:%d" % server.server_address[1]

        def post():
            request = urllib.request.Request(
                base + "/sth", data=b"{}",
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer tok"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=10) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                return exc.code

        self.assertEqual(post(), 409)
        self.assertEqual(post(), 429)
        request = urllib.request.Request(
            base + "/metrics", headers={"Authorization": "Bearer tok"})
        with urllib.request.urlopen(request, timeout=5) as resp:
            text = resp.read().decode()
        self.assertIn("mandate_witness_reject_total", text)


if __name__ == "__main__":
    unittest.main()
