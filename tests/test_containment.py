"""Containment stops now, expires on its own, and a human can extend it."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest

from mandate import containment, core, warden


class Containment(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.proc = subprocess.Popen(["sleep", "120"])

    def tearDown(self) -> None:
        try:
            self.proc.kill()
        except OSError:
            pass
        self.proc.wait(timeout=5)
        self.tmp.cleanup()

    def state(self) -> str:
        return warden.states([self.proc.pid]).get(self.proc.pid, "?")

    def test_contain_stops_the_process_and_sets_a_deadline(self) -> None:
        record = containment.contain(self.proc.pid, minutes=5, ledger_path=self.ledger)
        self.assertEqual(self.state(), "T")
        self.assertGreater(record["until"], int(time.time()))
        self.assertTrue(core.verify_chain(self.ledger))

    def test_the_sweep_leaves_it_alone_before_the_deadline(self) -> None:
        containment.contain(self.proc.pid, minutes=5, ledger_path=self.ledger)
        result = containment.sweep(self.ledger)
        self.assertEqual(result["released"], [])
        self.assertEqual(self.state(), "T")

    def test_the_sweep_releases_it_after_the_deadline(self) -> None:
        record = containment.contain(self.proc.pid, minutes=1, ledger_path=self.ledger)
        result = containment.sweep(self.ledger, now=record["until"] + 1)
        self.assertEqual(result["released"], [self.proc.pid])
        time.sleep(0.2)
        self.assertNotEqual(self.state(), "T")
        self.assertTrue(core.verify_chain(self.ledger))

    def test_extending_needs_a_signed_decision(self) -> None:
        containment.contain(self.proc.pid, minutes=1, ledger_path=self.ledger)
        with self.assertRaises(core.MandateError):
            containment.extend(self.ledger, self.proc.pid, minutes=10)

    def test_a_signed_extension_verifies(self) -> None:
        key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key],
                       check=True)
        signers = os.path.join(self.dir, "allowed_signers")
        open(signers, "w").write('approver namespaces="mandate" %s\n'
                                 % open(key + ".pub").read().strip())
        containment.contain(self.proc.pid, minutes=1, ledger_path=self.ledger)
        result = containment.extend(self.ledger, self.proc.pid, minutes=10,
                                    approver="approver", key_path=key)
        self.assertTrue(result["signed"])
        self.assertTrue(containment.verify_extend(result["entry"], signers))

    def test_a_tampered_extension_does_not_verify(self) -> None:
        key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key],
                       check=True)
        signers = os.path.join(self.dir, "allowed_signers")
        open(signers, "w").write('approver namespaces="mandate" %s\n'
                                 % open(key + ".pub").read().strip())
        containment.contain(self.proc.pid, minutes=1, ledger_path=self.ledger)
        result = containment.extend(self.ledger, self.proc.pid, minutes=10,
                                    approver="approver", key_path=key)
        entry = result["entry"]
        entry["body"]["decision"]["minutes"] = 999
        self.assertFalse(containment.verify_extend(entry, signers))


if __name__ == "__main__":
    unittest.main()


class EarlyRelease(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.key = os.path.join(self.dir, "approver")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True)
        self.signers = os.path.join(self.dir, "allowed_signers")
        open(self.signers, "w").write('approver namespaces="mandate" %s\n'
                                      % open(self.key + ".pub").read().strip())
        self.proc = subprocess.Popen(["sleep", "120"])
        containment.contain(self.proc.pid, minutes=30, ledger_path=self.ledger)

    def tearDown(self) -> None:
        try:
            self.proc.kill()
        except OSError:
            pass
        self.proc.wait(timeout=5)
        self.tmp.cleanup()

    def test_an_unsigned_release_record_is_ignored(self) -> None:
        core.append_receipt(self.ledger, {"v": 1, "type": "containment",
                                          "action": "release", "pid": self.proc.pid,
                                          "actor": "someone", "ts": 1})
        result = containment.sweep(self.ledger, now=int(time.time()) + 10 ** 6,
                                   signers_path=self.signers)
        self.assertEqual(result["released"], [self.proc.pid])

    def test_an_unsigned_extend_does_not_hold_it_frozen(self) -> None:
        core.append_receipt(self.ledger, {"v": 1, "type": "containment",
                                          "action": "extend", "pid": self.proc.pid,
                                          "until": int(time.time()) + 10 ** 8,
                                          "ts": 1})
        # without a signature the extension is ignored, so the deadline fires
        containment.contain(self.proc.pid, minutes=1, ledger_path=self.ledger)
        result = containment.sweep(self.ledger, now=int(time.time()) + 120,
                                   signers_path=self.signers)
        self.assertIn(self.proc.pid, result["released"])

    def test_the_sweep_actor_name_is_not_a_bypass(self) -> None:
        core.append_receipt(self.ledger, {"v": 1, "type": "containment",
                                          "action": "release", "pid": self.proc.pid,
                                          "actor": "containment-sweep", "ts": 1})
        result = containment.sweep(self.ledger, now=int(time.time()) + 10 ** 6,
                                   signers_path=self.signers)
        self.assertEqual(result["released"], [self.proc.pid])
        self.assertNotEqual(warden.states([self.proc.pid])[self.proc.pid], "T")

    def test_a_signed_release_ends_it_early(self) -> None:
        result = containment.release(self.ledger, self.proc.pid, "approver", self.key)
        self.assertTrue(result["ok"])
        out = containment.sweep(self.ledger, now=int(time.time()) + 10 ** 6,
                                signers_path=self.signers)
        self.assertEqual(out["released"], [])
