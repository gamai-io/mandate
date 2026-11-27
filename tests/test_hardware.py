"""HARDWARE_V1: which keys are FIDO2 security keys, and what the gate does with that.

The gate itself (`require_hardware_key`) already existed; these tests cover the
inspection command and make the *evidence* explicit: a refused approval leaves a control
entry behind, so "we required hardware" is visible in the ledger.
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

ROOT = pathlib.Path(__file__).resolve().parents[1]


class SignersFile(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.soft = os.path.join(d, "soft")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.soft],
                       check=True, capture_output=True)
        self.signers = os.path.join(d, "signers")
        pathlib.Path(self.signers).write_text(
            'soft namespaces="mandate" %s\n'
            'hard namespaces="mandate" sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIBfake\n'
            % pathlib.Path(self.soft + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "mandate", "--signers", self.signers,
                               "hardware", *args], cwd=str(ROOT),
                              capture_output=True, text=True)

    def test_list_counts_hardware_and_software(self):
        done = self._run("list")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        out = json.loads(done.stdout)
        self.assertEqual(out["hardware"], 1)
        self.assertEqual(out["software"], 1)
        kinds = {row["name"]: row["keytype"] for row in out["signers"]}
        self.assertEqual(kinds["soft"], "ssh-ed25519")
        self.assertTrue(kinds["hard"].startswith("sk-"))

    def test_check_reports_the_signing_key_not_the_first_line(self):
        msg = os.path.join(self.dir, "msg")
        pathlib.Path(msg).write_text("payload", encoding="utf-8")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-n", "mandate", "-f", self.soft, msg],
                       check=True, capture_output=True)
        done = self._run("check", "--name", "soft", "--signature", msg + ".sig")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)   # nije hardver
        out = json.loads(done.stdout)
        self.assertEqual(out["signing_keytype"], "ssh-ed25519")
        self.assertFalse(out["hardware"])

    def test_unknown_signer_is_not_reported_as_hardware(self):
        done = self._run("check", "--name", "nobody")
        self.assertEqual(json.loads(done.stdout)["software"], 0)


class GateLeavesEvidence(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.key = os.path.join(d, "approver")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(d, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n'
            % pathlib.Path(self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.ledger = os.path.join(d, "ledger.jsonl")
        self.intent = {
            "v": 1, "actor": {"agent": "agent@example", "session": "s1"},
            "effect": {"kind": "payment.send", "target": "Example",
                       "amount": {"value": 10.0, "currency": "BAM"}, "params": {}},
            "requested_by": "approver", "nonce": "hw-1",
            "provenance": [{"type": "data_ref", "source": "erp:1", "trust": "trusted",
                            "covers": ["target", "amount"]}],
        }
        proposal = core.propose(self.intent)
        grant_core = core.build_grant_core(proposal["commitment"], "approver", ttl_s=900,
                                           render_hash=proposal["render_hash"],
                                           agent="agent@example")
        self.grant = core.make_grant(grant_core, self.key)
        self.policy = core.load_policy()
        self.policy["effects"] = dict(self.policy["effects"])
        self.policy["effects"]["payment.send"] = dict(
            self.policy["effects"]["payment.send"], require_hardware_key=True)

    def tearDown(self):
        self.td.cleanup()

    def test_software_key_is_refused_and_recorded(self):
        with self.assertRaises(core.HardwareKeyRequired):
            core.redeem(self.intent, self.grant, self.signers, self.ledger,
                        policy=self.policy)
        entries = [json.loads(line) for line in
                   pathlib.Path(self.ledger).read_text(encoding="utf-8").splitlines() if line]
        self.assertTrue(entries, "odbijanje mora ostaviti zapis")
        self.assertIn("HardwareKeyRequired", json.dumps(entries[-1]))
        self.assertIn("hardware", json.dumps(entries[-1]).lower())


if __name__ == "__main__":
    unittest.main()
