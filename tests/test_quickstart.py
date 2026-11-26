"""The README quickstart must run exactly as written.

It is the first thing a reader executes, so a stale flag or a missing
`--audience` is a broken front door. This test copies the commands from
README.md ("Quickstart") and runs them through the CLI in a fresh directory.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Quickstart(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        shutil.copytree(ROOT / "examples", self.dir / "examples")
        self.env = dict(os.environ, PYTHONPATH=str(ROOT))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "mandate", *args],
                              cwd=str(self.dir), env=self.env,
                              capture_output=True, text=True)

    def ok(self, *args: str) -> str:
        proc = self.run_cli(*args)
        self.assertEqual(proc.returncode, 0,
                         "%s failed: %s%s" % (args[0], proc.stdout,
                                              proc.stderr))
        return proc.stdout

    def test_readme_quickstart_runs_and_the_grant_is_one_shot(self) -> None:
        self.ok("init", "--dir", ".")
        key = self.dir / "approver_key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(key),
                        "-C", "mandate", "-N", ""], check=True)
        with open(self.dir / "trust" / "allowed_signers", "a",
                  encoding="utf-8") as fh:
            fh.write('approver namespaces="mandate" %s\n'
                     % (self.dir / "approver_key.pub").read_text(
                         encoding="utf-8").strip())

        self.ok("propose", "--intent", "examples/intent.json",
                "--out", "proposal.json")
        self.ok("grant", "--proposal", "proposal.json",
                "--approver", "approver", "--key", "./approver_key",
                "--audience", "local-broker", "--out", "grant.json")
        receipt = self.ok("redeem", "--intent", "examples/intent.json",
                          "--grant", "grant.json", "--ledger", "ledger.jsonl",
                          "--audience", "local-broker")
        (self.dir / "receipt.json").write_text(receipt, encoding="utf-8")

        verified = json.loads(self.ok(
            "verify", "--receipt", "receipt.json",
            "--intent", "examples/intent.json", "--grant", "grant.json",
            "--signers", "trust/allowed_signers"))
        self.assertIs(verified.get("valid"), True, verified)

        replay = self.run_cli("redeem", "--intent", "examples/intent.json",
                              "--grant", "grant.json", "--ledger",
                              "ledger.jsonl", "--audience", "local-broker")
        self.assertEqual(replay.returncode, 3, replay.stdout)
        self.assertEqual(json.loads(replay.stdout).get("error"),
                         "GrantReplayed")

    def test_a_bound_grant_requires_the_broker_to_identify_itself(self) -> None:
        self.ok("init", "--dir", ".")
        key = self.dir / "approver_key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(key),
                        "-C", "mandate", "-N", ""], check=True)
        with open(self.dir / "trust" / "allowed_signers", "a",
                  encoding="utf-8") as fh:
            fh.write('approver namespaces="mandate" %s\n'
                     % (self.dir / "approver_key.pub").read_text(
                         encoding="utf-8").strip())
        self.ok("propose", "--intent", "examples/intent.json",
                "--out", "proposal.json")
        self.ok("grant", "--proposal", "proposal.json",
                "--approver", "approver", "--key", "./approver_key",
                "--audience", "local-broker", "--out", "grant.json")

        silent = self.run_cli("redeem", "--intent", "examples/intent.json",
                              "--grant", "grant.json",
                              "--ledger", "ledger.jsonl")
        self.assertEqual(silent.returncode, 3, silent.stdout)
        self.assertEqual(json.loads(silent.stdout).get("error"),
                         "GrantInvalid")


if __name__ == "__main__":
    unittest.main()
