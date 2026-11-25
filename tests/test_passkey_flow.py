"""The full ceremony through the approval server, with a software authenticator."""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from test_webauthn import SoftwareAuthenticator

from mandate import approval_page, core, sign


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def intent(nonce="n-pk-1"):
    return core.normalize_intent({
        "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
        "effect": {"kind": "payment.send", "target": "Example Supplier",
                   "amount": {"value": 1170.0, "currency": "BAM"},
                   "params": {"ref": "f-1"}, "revert": "reverse_transfer"},
        "requested_by": "ops", "nonce": nonce,
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1"},
                       {"type": "data_ref", "source": "Example Supplier"},
                       {"type": "data_ref", "source": "1170.0"}]})


class Flow(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True)
        self.signers = os.path.join(self.dir, "allowed_signers")
        with open(self.signers, "w") as fh:
            fh.write('approver namespaces="mandate" %s\n'
                     % open(self.key + ".pub").read().strip())
        self.passkeys = os.path.join(self.dir, "passkeys.json")
        self.port = free_port()
        self.origin = "http://127.0.0.1:%d" % self.port
        self.server = approval_page.serve(
            self.key, "approver", port=self.port, audience="local-broker",
            wait_s=20, passkeys_path=self.passkeys, rp_id="127.0.0.1",
            origin=self.origin)
        self.base = self.origin
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def get_json(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as resp:
            return json.loads(resp.read())

    def post_json(self, path, payload):
        request = urllib.request.Request(
            self.base + path, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def start_request(self, payload):
        holder = {}

        def worker():
            holder["status"], holder["body"] = self.post_json("/request", payload)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        return holder, thread

    def pending_id(self):
        for _ in range(100):
            with urllib.request.urlopen(self.base + "/") as resp:
                match = re.search(r'name="id" value="([^"]+)"', resp.read().decode())
            if match:
                return match.group(1)
            threading.Event().wait(0.05)
        raise AssertionError("no pending request")

    def test_register_then_approve_end_to_end(self) -> None:
        auth = SoftwareAuthenticator("p256", origin=self.origin)
        challenge = self.get_json("/passkey/challenge?purpose=register")["challenge"]
        reg = auth.register(challenge)
        status, body = self.post_json("/passkey/register",
                                      {**reg, "challenge": challenge,
                                       "label": "YubiKey 5"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cose"], "ES256")
        self.assertEqual(os.stat(self.passkeys).st_mode & 0o777, 0o600)

        holder, thread = self.start_request({"intent": intent()})
        pid = self.pending_id()
        challenge = self.get_json("/passkey/challenge?purpose=approve&id=" + pid)["challenge"]
        assertion = auth.assert_(challenge)
        cred_id = list(json.load(open(self.passkeys))["credentials"])[0]
        status, body = self.post_json("/approve", {"id": pid, "credential_id": cred_id,
                                                   **assertion, "challenge": challenge})
        self.assertEqual(status, 200, body)
        thread.join(5)
        self.assertEqual(holder["status"], 200, holder)
        self.assertTrue(holder["body"]["passkey"]["user_verified"])
        self.assertTrue(sign.verify(core.jcs(holder["body"]["grant"]["grant"]),
                                    "approver", holder["body"]["grant"]["sig"],
                                    self.signers))

    def test_a_form_button_cannot_approve_once_a_passkey_exists(self) -> None:
        auth = SoftwareAuthenticator(origin=self.origin)
        challenge = self.get_json("/passkey/challenge?purpose=register")["challenge"]
        self.post_json("/passkey/register", {**auth.register(challenge),
                                             "challenge": challenge})
        holder, thread = self.start_request({"intent": intent("n-pk-2")})
        pid = self.pending_id()
        with urllib.request.urlopen(self.base + "/") as resp:
            page_html = resp.read().decode()
        token = re.search(r'name="token" value="([^"]+)"', page_html).group(1)
        form = urllib.parse.urlencode({"id": pid, "token": token}).encode()
        request = urllib.request.Request(
            self.base + "/approve", data=form, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            urllib.request.urlopen(request, timeout=5)
            self.fail("form approval should be refused")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 403)
            self.assertIn("passkey", json.loads(exc.read())["error"])
        self.server.page.reject(pid, "test cleanup")     # type: ignore[attr-defined]
        thread.join(5)

    def test_an_assertion_for_another_request_is_refused(self) -> None:
        auth = SoftwareAuthenticator(origin=self.origin)
        challenge = self.get_json("/passkey/challenge?purpose=register")["challenge"]
        self.post_json("/passkey/register", {**auth.register(challenge),
                                             "challenge": challenge})
        holder, thread = self.start_request({"intent": intent("n-pk-3")})
        pid = self.pending_id()
        other = self.get_json("/passkey/challenge?purpose=approve&id=other")["challenge"]
        assertion = auth.assert_(other)
        cred_id = list(json.load(open(self.passkeys))["credentials"])[0]
        status, body = self.post_json("/approve", {"id": pid, "credential_id": cred_id,
                                                   **assertion, "challenge": other})
        self.assertEqual(status, 403, body)
        thread.join(5)

    def test_an_unknown_credential_is_refused(self) -> None:
        holder, thread = self.start_request({"intent": intent("n-pk-4")})
        pid = self.pending_id()
        status, body = self.post_json("/approve", {"id": pid,
                                                   "credential_id": "nope",
                                                   "auth_data": "", "signature": "",
                                                   "client_data": "", "challenge": "x"})
        self.assertEqual(status, 403, body)
        self.assertIn("unknown credential", json.dumps(body))
        thread.join(5)


if __name__ == "__main__":
    unittest.main()
