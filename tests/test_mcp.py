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


class McpTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "publisher")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'publisher namespaces="mandate-mcp" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.cmd = "%s %s" % (sys.executable, FAKE)
        self.lock = os.path.join(self.dir, "mandate.lock.json")

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"), *args],
            capture_output=True, text=True, env=env or dict(os.environ))

    def _lock(self, env=None):
        result = self._run("mcp", "lock", "--cmd", self.cmd,
                           "--server", "fake", "--key", self.key,
                           "--signer", "publisher", "--out", self.lock,
                           env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lock_and_verify(self):
        self._lock()
        result = self._run("--signers", self.signers, "mcp", "verify",
                           "--lock", self.lock, "--cmd", self.cmd)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data["valid"])
        self.assertEqual(data["tools"], ["pay", "read", "web_fetch"])

    def test_poisoned_manifest_rejected(self):
        self._lock()
        env = dict(os.environ)
        env["FAKE_MODE"] = "poison"
        result = self._run("--signers", self.signers, "mcp", "verify",
                           "--lock", self.lock, "--cmd", self.cmd, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_wrong_signer_rejected(self):
        self._lock()
        other = os.path.join(self.dir, "other")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", other],
                       check=True, capture_output=True)
        lock = self._run("mcp", "lock", "--cmd", self.cmd, "--server", "fake",
                         "--key", other, "--signer", "publisher",
                         "--out", self.lock)
        self.assertEqual(lock.returncode, 0, lock.stdout + lock.stderr)
        result = self._run("--signers", self.signers, "mcp", "verify",
                           "--lock", self.lock, "--cmd", self.cmd)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def _proxy(self, env=None):
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "bin" / "mandate"),
             "--signers", self.signers, "mcp", "proxy",
             "--lock", self.lock, "--cmd", self.cmd],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
            env=env or dict(os.environ))
        self.addCleanup(proc.terminate)
        return proc

    @staticmethod
    def _rpc(proc, obj, timeout=5):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if not ready:
            raise AssertionError("proxy response timeout")
        return json.loads(proc.stdout.readline())

    def test_proxy_forwards_locked_tools(self):
        self._lock()
        proc = self._proxy()
        init = self._rpc(proc, {"jsonrpc": "2.0", "id": 1,
                                "method": "initialize", "params": {}})
        self.assertEqual(init["id"], 1)
        listing = self._rpc(proc, {"jsonrpc": "2.0", "id": 2,
                                   "method": "tools/list"})
        names = [tool["name"] for tool in listing["result"]["tools"]]
        self.assertEqual(sorted(names), ["pay", "read", "web_fetch"])
        call = self._rpc(proc, {"jsonrpc": "2.0", "id": 3,
                                "method": "tools/call",
                                "params": {"name": "pay", "arguments": {}}})
        self.assertIn("ok:pay", call["result"]["content"][0]["text"])

    def test_proxy_blocks_poisoned_manifest(self):
        self._lock()
        env = dict(os.environ)
        env["FAKE_MODE"] = "poison"
        proc = self._proxy(env=env)
        self._rpc(proc, {"jsonrpc": "2.0", "id": 1,
                         "method": "initialize", "params": {}})
        listing = self._rpc(proc, {"jsonrpc": "2.0", "id": 2,
                                   "method": "tools/list"})
        self.assertIn("error", listing)
        self.assertIn("manifest mismatch", listing["error"]["message"])

    def test_proxy_blocks_tool_not_in_lock(self):
        env = dict(os.environ)
        env["FAKE_MODE"] = "readonly"
        self._lock(env=env)
        proc = self._proxy()
        self._rpc(proc, {"jsonrpc": "2.0", "id": 1,
                         "method": "initialize", "params": {}})
        call = self._rpc(proc, {"jsonrpc": "2.0", "id": 2,
                                "method": "tools/call",
                                "params": {"name": "pay", "arguments": {}}})
        self.assertIn("error", call)
        self.assertIn("tool not in lock", call["error"]["message"])


if __name__ == "__main__":
    unittest.main()
