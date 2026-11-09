import json
import os
import pathlib
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from mandate import approver as mapprover
from mandate import core

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


class ApproverTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "id_ed25519")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")

    def tearDown(self):
        self.td.cleanup()

    def _approver(self, confirm=None):
        return mapprover.Approver(self.key, "approver",
                                  audience_default="gama-broker",
                                  confirm=confirm or (lambda *args: True))

    def test_request_signs_redeemable_grant(self):
        approver = self._approver()
        intent = intent_factory()
        result = approver.request(intent)
        self.assertTrue(core.verify_grant(result["grant"], self.signers))
        self.assertEqual(result["commitment"], core.intent_commitment(intent))
        self.assertEqual(result["render_hash"], core.render_hash(intent))
        receipt = core.redeem(
            intent, result["grant"], self.signers, self.ledger,
            policy=core.load_policy(), audience="gama-broker",
            require_audience=True)
        self.assertEqual(receipt["body"]["decision"], "executed")

    def test_rejection_returns_error(self):
        approver = self._approver(confirm=lambda *args: False)
        with self.assertRaises(mapprover.ApprovalRejected):
            approver.request(intent_factory())

    def test_no_tty_refuses(self):
        approver = mapprover.Approver(self.key, "approver")
        with mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(mapprover.NoTTY):
                approver.request(intent_factory())

    def test_grant_is_bound_to_intent(self):
        approver = self._approver()
        grant = approver.request(intent_factory())["grant"]
        tampered = intent_factory()
        tampered["effect"] = dict(tampered["effect"])
        tampered["effect"]["amount"] = {"value": 1.0, "currency": "BAM"}
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(tampered, grant, self.signers, self.ledger)

    def test_grant_is_bound_to_agent(self):
        approver = self._approver()
        grant = approver.request(intent_factory())["grant"]
        swapped = intent_factory(actor={"agent": "other@test", "session": "s"})
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(swapped, grant, self.signers, self.ledger)

    def test_http_request_and_auth(self):
        token = "approver-token"
        approver = self._approver()
        server = mapprover.make_server("127.0.0.1", 0, approver, token=token)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        base = "http://127.0.0.1:%d" % port

        def post(body, bearer=token):
            request = urllib.request.Request(
                base + "/request", data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + bearer}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=10) as resp:
                    return resp.status, json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode())

        status, body = post({"intent": intent_factory(), "audience": "gama-broker"})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        status, _body = post({"intent": intent_factory()}, bearer="wrong")
        self.assertEqual(status, 401)

    def test_http_body_cap(self):
        approver = self._approver()
        server = mapprover.make_server("127.0.0.1", 0, approver, token="")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        request = urllib.request.Request(
            "http://127.0.0.1:%d/request" % port,
            data=b"x" * (mapprover.MAX_BODY + 1),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        self.assertEqual(status, 413)


if __name__ == "__main__":
    unittest.main()
