"""GLOBAL_FLAGS_V1: `mandate --signers X ...` must not be overwritten by the subcommand.

The bug this guards: the subparsers re-declared `--signers` with a default, so
`mandate --signers /tmp/signers redeem ...` silently used `trust/allowed_signers`
and failed with "grant signature invalid". A quickstart that follows the docs hit it
on the first run.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

INTENT = {
    "v": 1, "actor": {"agent": "agent@example", "session": "s1"},
    "effect": {"kind": "payment.send", "target": "Example Supplier",
               "amount": {"value": 1170.0, "currency": "BAM"},
               "params": {"ref": "faktura-77"}},
    "requested_by": "approver", "nonce": "cli-1",
    "provenance": [{"type": "data_ref", "source": "erp:vendor:1", "trust": "trusted",
                    "covers": ["target", "amount"]}],
}


class GlobalSigners(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.key = os.path.join(d, "approver")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(d, "allowed_signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate,mandate-export" %s\n'
            % pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.intent = os.path.join(d, "intent.json")
        pathlib.Path(self.intent).write_text(json.dumps(INTENT), encoding="utf-8")
        self.proposal = os.path.join(d, "proposal.json")
        self.grant = os.path.join(d, "grant.json")
        self.ledger = os.path.join(d, "ledger.jsonl")

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "mandate", *args], cwd=str(ROOT),
                              capture_output=True, text=True)

    def test_signers_before_the_subcommand_is_honoured(self):
        # bez globalnog --signers ovo bi palo: putanja trust/allowed_signers ne postoji
        done = self._run("--signers", self.signers, "propose", "--intent", self.intent,
                         "--out", self.proposal)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = self._run("--signers", self.signers, "grant", "--proposal", self.proposal,
                         "--approver", "approver", "--key", self.key, "--out", self.grant)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = self._run("--signers", self.signers, "redeem", "--intent", self.intent,
                         "--grant", self.grant, "--ledger", self.ledger)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        receipt = json.loads(done.stdout)
        self.assertEqual(receipt["body"]["decision"], "executed")
        self.assertEqual(receipt["body"]["coverage"], "enforced")

    def test_flag_after_the_subcommand_still_wins(self):
        # propose/grant ne verifikuju potpise; samo redeem prima --signers poslije komande
        self._run("propose", "--intent", self.intent, "--out", self.proposal)
        done = self._run("grant", "--proposal", self.proposal, "--approver", "approver",
                         "--key", self.key, "--out", self.grant)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = self._run("redeem", "--intent", self.intent, "--grant", self.grant,
                         "--ledger", self.ledger, "--signers", self.signers)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(json.loads(done.stdout)["body"]["decision"], "executed")


if __name__ == "__main__":
    unittest.main()
