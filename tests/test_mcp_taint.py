import json
import os
import pathlib
import select
import subprocess
import sys
import tempfile
import unittest

from mandate import core

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fixtures" / "fake_mcp.py"


class TaintTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate,mandate-mcp" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.cmd = "%s %s" % (sys.executable, FAKE)
        self.lock = os.path.join(self.dir, "mandate.lock.json")
        self.taint = os.path.join(self.dir, "taint.json")
        pathlib.Path(self.taint).write_text(json.dumps({
            "sources": ["web_fetch"], "effects": ["pay"],
            "require_grant": True}), encoding="utf-8")
        self.ledger = os.path.join(self.dir, "mcp_ledger.jsonl")
        result = self._run("mcp", "lock", "--cmd", self.cmd,
                           "--server", "fake", "--key", self.key,
                           "--signer", "approver", "--out", self.lock)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"), *args],
            capture_output=True, text=True, env=dict(os.environ))

    def _grant(self, arguments, provenance=None):
        args_sha = core.sha256(core.jcs(arguments))
        intent = {
            "v": 1,
            "actor": {"agent": "agent@example"},
            "effect": {"kind": "mcp.call", "target": "pay",
                       "params": {"args_sha256": args_sha}},
            "requested_by": "approver",
            "nonce": "mcp-%s" % args_sha[:8],
            "provenance": provenance if provenance is not None else [
                {"type": "data_ref", "source": "erp:vendor:1"}],
        }
        proposal = core.propose(intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=900,
            render_hash=proposal["render_hash"], agent="agent@example",
            audience="mcp:fake")
        return {"intent": intent,
                "grant": core.make_grant(grant_core, self.key)}

    def _proxy(self):
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "bin" / "mandate"),
             "--signers", self.signers, "mcp", "proxy",
             "--lock", self.lock, "--cmd", self.cmd,
             "--taint", self.taint, "--mcp-ledger", self.ledger,
             "--mcp-audience", "mcp:fake"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
            env=dict(os.environ))
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

    def _call(self, proc, mid, name, arguments):
        return self._rpc(proc, {"jsonrpc": "2.0", "id": mid,
                                "method": "tools/call",
                                "params": {"name": name,
                                           "arguments": arguments}})

    def test_taint_requires_grant_and_data_ref(self):
        proc = self._proxy()
        self._rpc(proc, {"jsonrpc": "2.0", "id": 1,
                         "method": "initialize", "params": {}})
        source = self._call(proc, 2, "web_fetch", {"url": "https://x"})
        self.assertIn("ok:web_fetch", source["result"]["content"][0]["text"])
        no_grant = self._call(proc, 3, "pay", {"amount": 1})
        self.assertIn("grant required", no_grant["error"]["message"])
        no_ref = self._grant({"amount": 1}, provenance=[])
        denied = self._call(proc, 4, "pay",
                            {"amount": 1, "_mandate": no_ref})
        self.assertIn("data_ref required", denied["error"]["message"])
        valid = self._grant({"amount": 1})
        allowed = self._call(proc, 5, "pay",
                             {"amount": 1, "_mandate": valid})
        self.assertIn("ok:pay", allowed["result"]["content"][0]["text"])
        self.assertNotIn("_mandate", allowed["result"].get("echo") or {})
        replay = self._call(proc, 6, "pay",
                            {"amount": 1, "_mandate": valid})
        self.assertIn("grant rejected", replay["error"]["message"])
        neutral = self._call(proc, 7, "read", {"path": "/x"})
        self.assertIn("ok:read", neutral["result"]["content"][0]["text"])

    def test_wrong_arguments_rejected(self):
        proc = self._proxy()
        self._rpc(proc, {"jsonrpc": "2.0", "id": 1,
                         "method": "initialize", "params": {}})
        self._call(proc, 2, "web_fetch", {"url": "https://x"})
        grant = self._grant({"amount": 2})
        response = self._call(proc, 3, "pay",
                              {"amount": 1, "_mandate": grant})
        self.assertIn("arguments do not match", response["error"]["message"])


if __name__ == "__main__":
    unittest.main()
