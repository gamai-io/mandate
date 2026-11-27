"""RESPONSE_GATE_V1: what an MCP tool returns is scanned before the model sees it.

The proxy already locked the tool list and gated effects. This covers the other
direction: a tool result carrying an instruction (or a key) must not reach the client,
and the refusal must leave a `control` entry.
"""
from __future__ import annotations

import json
import os
import pathlib
import select
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fixtures" / "fake_mcp.py"


class ResponseGate(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate,mandate-mcp" %s\n'
            % pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.cmd = "%s %s" % (sys.executable, FAKE)
        self.lock = os.path.join(self.dir, "lock.json")
        self.ledger = os.path.join(self.dir, "mcp.jsonl")
        done = subprocess.run([sys.executable, str(ROOT / "bin" / "mandate"), "mcp", "lock",
                               "--cmd", self.cmd, "--server", "fake", "--key", self.key,
                               "--signer", "approver", "--out", self.lock],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def tearDown(self):
        self.td.cleanup()

    def _proxy(self, mode: str):
        env = dict(os.environ, FAKE_MODE=mode)
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "bin" / "mandate"), "--signers", self.signers,
             "mcp", "proxy", "--lock", self.lock, "--cmd", self.cmd,
             "--mcp-ledger", self.ledger],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env)
        self.addCleanup(proc.terminate)
        return proc

    @staticmethod
    def _rpc(proc, obj, timeout=8):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if not ready:
            raise AssertionError("proxy response timeout")
        return json.loads(proc.stdout.readline())

    def _call(self, proc, mid, name="read", arguments=None):
        return self._rpc(proc, {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                                "params": {"name": name, "arguments": arguments or {}}})

    def test_clean_response_passes(self):
        proc = self._proxy("")
        self._rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        res = self._call(proc, 2)
        self.assertIn("ok:read", res["result"]["content"][0]["text"])

    def test_injected_response_is_blocked_and_recorded(self):
        proc = self._proxy("inject")
        self._rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        res = self._call(proc, 2)
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32005)
        self.assertIn("blocked", res["error"]["message"])
        entries = [json.loads(x).get("body", {}) for x in
                   pathlib.Path(self.ledger).read_text(encoding="utf-8").splitlines() if x]
        blocked = [e for e in entries if e.get("code") == "ResponseBlocked"]
        self.assertTrue(blocked, entries)
        self.assertIn("ignore_previous", blocked[0]["findings"])

    def test_secret_in_a_response_is_blocked(self):
        proc = self._proxy("secret")
        self._rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        res = self._call(proc, 2)
        self.assertEqual(res["error"]["code"], -32005)
        self.assertIn("aws_access_key", res["error"]["message"])


if __name__ == "__main__":
    unittest.main()
