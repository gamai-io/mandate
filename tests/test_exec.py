"""EXEC_V1: the process starts only after redeem() succeeded, and the outcome is evidence too.

The test that matters most is the negative one: a grant approved for `echo ok` must not allow
`rm -rf`. It is checked by running a command whose only observable effect is a file it creates, so
"refused" is proven by the file not existing.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import core
from mandate import exec as exec_mod

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Guard(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "k")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'operator namespaces="mandate" %s\n'
            % pathlib.Path(self.key + ".pub").read_text().strip(), encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        core.append_receipt(self.ledger, {"v": 1, "type": "control", "action": "init"})
        self.policy = core.load_policy()

    def tearDown(self):
        self.td.cleanup()

    def _grant(self, argv: list[str]) -> tuple[dict, dict]:
        intent = exec_mod.build_intent(argv, "agent@exec", "operator")
        proposal = core.propose(intent, salted=True)
        grant_core = core.build_grant_core(
            proposal["commitment"], "operator", render_hash=proposal["render_hash"],
            agent="agent@exec", commitment_alg=proposal["commitment_alg"],
            commitment_salt=proposal["commitment_salt"],
            policy_fingerprint=core.policy_digest(self.policy))
        return intent, core.make_grant(grant_core, self.key)

    def test_policy_asks_for_a_grant_on_every_command(self):
        intent = exec_mod.build_intent(["echo", "hi"])
        decision = exec_mod.check_allowed(intent, self.policy)
        self.assertEqual(decision["decision"], "ask")

    def test_a_valid_grant_runs_the_command_and_records_the_outcome(self):
        marker = os.path.join(self.dir, "ran.txt")
        argv = [sys.executable, "-c", "open(%r,'w').write('x')" % marker]
        intent, grant = self._grant(argv)
        res = exec_mod.run(argv, intent, grant, self.signers, self.ledger, self.policy)
        self.assertEqual(res["exit_code"], 0)
        self.assertTrue(os.path.exists(marker))
        bodies = [e["body"] for e in core.read_ledger(self.ledger)]
        self.assertTrue(any(b.get("type") == "receipt" for b in bodies))
        outcome = [b for b in bodies if b.get("action") == "outcome"][0]
        self.assertEqual(outcome["exit_code"], 0)
        self.assertEqual(len(outcome["stdout_sha256"]), 64)
        self.assertNotIn("stdout", outcome)          # a hash, not the content

    def test_a_grant_for_another_command_is_refused_and_nothing_runs(self):
        allowed = os.path.join(self.dir, "allowed.txt")
        forbidden = os.path.join(self.dir, "forbidden.txt")
        intent, grant = self._grant([sys.executable, "-c",
                                     "open(%r,'w').write('ok')" % allowed])
        other = [sys.executable, "-c", "open(%r,'w').write('bad')" % forbidden]
        with self.assertRaises((core.MandateError, exec_mod.ExecError)):
            exec_mod.run(other, intent, grant, self.signers, self.ledger, self.policy)
        self.assertFalse(os.path.exists(allowed))
        self.assertFalse(os.path.exists(forbidden))

    def test_the_same_grant_does_not_run_twice(self):
        argv = [sys.executable, "-c", "print('once')"]
        intent, grant = self._grant(argv)
        exec_mod.run(argv, intent, grant, self.signers, self.ledger, self.policy)
        with self.assertRaises(core.MandateError):
            exec_mod.run(argv, intent, grant, self.signers, self.ledger, self.policy)

    def test_an_unknown_effect_is_denied(self):
        policy = json.loads(json.dumps(self.policy))
        policy["effects"].pop("process.exec")
        intent = exec_mod.build_intent(["echo", "hi"])
        decision = exec_mod.check_allowed(intent, policy)
        self.assertEqual(decision["decision"], "deny")
        with self.assertRaises(exec_mod.ExecError):
            exec_mod.run(["echo", "hi"], intent, {"grant": {}}, self.signers, self.ledger, policy)

    def test_describe_shows_what_would_run_without_running_it(self):
        marker = os.path.join(self.dir, "never.txt")
        argv = [sys.executable, "-c", "open(%r,'w').write('x')" % marker]
        described = exec_mod.describe(argv, exec_mod.build_intent(argv))
        self.assertEqual(described["would_run"], argv)
        self.assertEqual(described["commitment"][:7], "sha256:")
        self.assertFalse(os.path.exists(marker))


class Cli(unittest.TestCase):
    def test_check_exits_three_and_writes_the_intent(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "intent.json")
            done = subprocess.run([sys.executable, "-m", "mandate", "exec", "--check",
                                   "--out", out, "--", "echo", "hi"],
                                  cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(done.returncode, 3, done.stderr)
            payload = json.loads(done.stdout)
            self.assertTrue(payload["needs_grant"])
            self.assertTrue(os.path.exists(out))
            intent = json.loads(pathlib.Path(out).read_text(encoding="utf-8"))
            self.assertEqual(intent["effect"]["kind"], "process.exec")


if __name__ == "__main__":
    unittest.main()
