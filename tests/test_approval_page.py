"""The approval page: what the human sees is what gets signed."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from mandate import approval_page, core, sign


def intent(nonce="n-page-1", amount=1170.0):
    return core.normalize_intent({
        "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
        "effect": {"kind": "payment.send", "target": "Example Supplier",
                   "amount": {"value": amount, "currency": "BAM"},
                   "params": {"ref": "f-1"}, "revert": "reverse_transfer"},
        "requested_by": "ops", "nonce": nonce,
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1"},
                       {"type": "data_ref", "source": "Example Supplier"},
                       {"type": "data_ref", "source": "1170.0"}]})


class Page(unittest.TestCase):
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
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.server = approval_page.serve(self.key, "approver", port=0,
                                          audience="local-broker", wait_s=20,
                                          ledger=self.ledger)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as resp:
            return resp.status, resp.read().decode()

    def post_form(self, path, data):
        body = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(self.base + path, data=body, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def start_request(self, payload):
        holder = {}

        def worker():
            request = urllib.request.Request(
                self.base + "/request", data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=30) as resp:
                    holder["status"], holder["body"] = resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                holder["status"], holder["body"] = exc.code, json.loads(exc.read() or b"{}")

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        return holder, thread

    def _wait_for_form(self):
        for _ in range(100):
            status, page = self.get("/")
            found = re.search(r'name="id" value="([^"]+)"', page)
            token = re.search(r'name="token" value="([^"]+)"', page)
            if found and token:
                return page, found.group(1), token.group(1)
            threading.Event().wait(0.05)
        raise AssertionError("no pending form appeared")

    def test_the_page_shows_the_effect_and_approval_signs_it(self) -> None:
        holder, thread = self.start_request({"intent": intent()})
        page, pid, token = self._wait_for_form()
        self.assertIn("1170.00 BAM", page)
        self.assertIn("Example Supplier", page)
        self.assertIn("bank-agent", page)
        status, body = self.post_form("/approve", {"id": pid, "token": token})
        self.assertEqual(status, 200, body)
        thread.join(5)
        self.assertEqual(holder["status"], 200, holder)
        grant = holder["body"]["grant"]
        self.assertTrue(sign.verify(core.jcs(grant["grant"]), "approver",
                                    grant["sig"], self.signers))
        last = json.loads(open(self.ledger).read().strip().splitlines()[-1])["body"]
        self.assertEqual((last["type"], last["decision"]), ("approval", "approved"))

    def test_rejection_reaches_the_waiting_agent(self) -> None:
        holder, thread = self.start_request({"intent": intent(nonce="n-page-2")})
        page, pid, token = self._wait_for_form()
        status, body = self.post_form("/reject", {"id": pid, "token": token,
                                                  "reason": "wrong supplier"})
        self.assertEqual(status, 200, body)
        thread.join(5)
        self.assertEqual(holder["status"], 409, holder)
        self.assertIn("rejected", json.dumps(holder["body"]).lower())

    def test_a_guessed_form_token_cannot_approve(self) -> None:
        holder, thread = self.start_request({"intent": intent(nonce="n-page-3")})
        page, pid, _token = self._wait_for_form()
        status, body = self.post_form("/approve", {"id": pid, "token": "0" * 64})
        self.assertEqual(status, 403, body)
        self.assertIn("form token", body.get("error", ""))

    def test_a_request_changed_after_display_is_refused(self) -> None:
        holder, thread = self.start_request({"intent": intent(nonce="n-page-4")})
        page, pid, token = self._wait_for_form()
        pending = self.server.page.pending[pid]        # type: ignore[attr-defined]
        pending.intent["effect"]["amount"]["value"] = 9999.0   # tamper behind the page
        status, body = self.post_form("/approve", {"id": pid, "token": token})
        self.assertEqual(status, 409, body)
        self.assertIn("changed after it was displayed", json.dumps(body))
        thread.join(5)

    def test_the_page_refuses_to_bind_a_public_interface_by_default(self) -> None:
        with self.assertRaises(SystemExit):
            approval_page.serve(self.key, "approver", host="0.0.0.0", port=0)

    def test_health_counts_pending(self) -> None:
        holder, thread = self.start_request({"intent": intent(nonce="n-page-5")})
        self._wait_for_form()
        status, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(json.loads(body)["pending"], 1)
        page, pid, token = self._wait_for_form()
        self.post_form("/reject", {"id": pid, "token": token})
        thread.join(5)


if __name__ == "__main__":
    unittest.main()
