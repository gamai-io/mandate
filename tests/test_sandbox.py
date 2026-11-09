import json
import os
import pathlib
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

from mandate.sandbox import DockerRunner, LocalRunner, SandboxError, TemplateRunner, build_runner

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fixtures" / "fake_mcp.py"


def docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    check = subprocess.run(["docker", "image", "inspect", "python:3.12-slim"],
                           capture_output=True)
    return check.returncode == 0


class SandboxUnitTests(unittest.TestCase):
    def test_local_runner(self):
        self.assertEqual(LocalRunner().wrap("python3 s.py"), ["python3", "s.py"])

    def test_docker_argv_hardened(self):
        runner = DockerRunner(image="python:3.12-slim",
                              mounts=["/host:/work:ro"], workdir="/work")
        argv = runner.wrap("python3 s.py")
        self.assertEqual(argv[0], "docker")
        self.assertIn("--read-only", argv)
        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--security-opt", argv)
        self.assertIn("no-new-privileges", argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--memory", argv)
        self.assertIn("/host:/work:ro", argv)
        self.assertIn("python:3.12-slim", argv)
        self.assertEqual(argv[-2:], ["python3", "s.py"])

    def test_gvisor_runtime(self):
        argv = DockerRunner(runtime="runsc").wrap("python3 s.py")
        self.assertIn("--runtime", argv)
        self.assertIn("runsc", argv)

    def test_template_runner(self):
        runner = TemplateRunner("/usr/local/bin/mandate-firecracker --")
        self.assertEqual(runner.wrap("python3 s.py")[:3],
                         ["/usr/local/bin/mandate-firecracker", "--", "python3"])

    def test_firecracker_requires_template(self):
        with self.assertRaises(SandboxError):
            build_runner("firecracker")

    def test_unknown_mode(self):
        with self.assertRaises(SandboxError):
            build_runner("bogus")


@unittest.skipUnless(docker_ready(), "docker/python image unavailable")
class DockerSandboxIntegrationTests(unittest.TestCase):
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
        self.lock = os.path.join(self.dir, "lock.json")
        self.mount = "%s:/work:ro" % (ROOT / "tests" / "fixtures")

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"), *args],
            capture_output=True, text=True, env=dict(os.environ),
            timeout=60)

    def _sandbox(self):
        return ["--sandbox", "docker", "--sandbox-image", "python:3.12-slim",
                "--sandbox-mount", self.mount, "--sandbox-workdir", "/work"]

    def test_lock_verify_and_proxy_in_docker(self):
        cmd = "python3 fake_mcp.py"
        result = self._run("mcp", "lock", "--cmd", cmd, "--server", "fake",
                           "--key", self.key, "--signer", "approver",
                           "--out", self.lock, *self._sandbox())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self._run("--signers", self.signers, "mcp", "verify",
                           "--lock", self.lock, "--cmd", cmd, *self._sandbox())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["valid"])

        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "bin" / "mandate"),
             "--signers", self.signers, "mcp", "proxy",
             "--lock", self.lock, "--cmd", cmd, *self._sandbox()],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
            env=dict(os.environ))
        self.addCleanup(proc.terminate)

        def rpc(obj, timeout=20):
            proc.stdin.write(json.dumps(obj) + "\n")
            proc.stdin.flush()
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if not ready:
                raise AssertionError("docker proxy timeout")
            return json.loads(proc.stdout.readline())

        init = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {}})
        self.assertEqual(init["id"], 1)
        listing = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [tool["name"] for tool in listing["result"]["tools"]]
        self.assertIn("read", names)
        call = rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "read", "arguments": {"path": "/x"}}})
        self.assertIn("ok:read", call["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
