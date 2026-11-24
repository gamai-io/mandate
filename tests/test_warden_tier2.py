"""Warden tier 2: cgroup freezer (kernel-observed), network quarantine, signed stops."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from mandate import warden

CHILD = """
import sys, time
path = sys.argv[1]
i = 0
while True:
    i += 1
    open(path, "w").write(str(i))
    time.sleep(0.01)
"""


def spawn(counter: str) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", CHILD, counter],
                            start_new_session=True, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def value(path: str) -> int:
    try:
        return int(open(path).read() or 0)
    except (OSError, ValueError):
        return 0


@unittest.skipUnless(os.geteuid() == 0 and warden.cgroup_available(), "needs root + cgroup v2")
class CgroupFreezer(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.counter = os.path.join(self.tmp.name, "c")
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")
        self.proc = spawn(self.counter)
        deadline = time.time() + 5
        while value(self.counter) < 3 and time.time() < deadline:
            time.sleep(0.02)
        self.name = f"t-{os.getpid()}-{int(time.time() * 1000) % 100000}"
        self.path = warden.attach(self.proc.pid, self.name)

    def tearDown(self) -> None:
        try:
            os.killpg(self.proc.pid, 9)
        except ProcessLookupError:
            pass
        self.proc.wait(timeout=5)
        shutil.rmtree(self.path, ignore_errors=True)
        self.tmp.cleanup()

    def test_attach_puts_pid_in_cgroup(self) -> None:
        self.assertIn(self.proc.pid, warden.cgroup_pids(self.path))

    def test_freeze_is_observed_by_the_kernel(self) -> None:
        res = warden.freeze_cgroup(self.path)
        self.assertTrue(res["frozen"])
        self.assertEqual(res["events"].get("frozen"), "1")
        self.assertLess(res["time_to_halt_ms"], 2000)
        frozen = value(self.counter)
        time.sleep(0.3)
        self.assertEqual(value(self.counter), frozen, "frozen cgroup kept working")

    def test_thaw_restarts_work(self) -> None:
        warden.freeze_cgroup(self.path)
        before = value(self.counter)
        warden.thaw_cgroup(self.path)
        deadline = time.time() + 3
        while value(self.counter) <= before and time.time() < deadline:
            time.sleep(0.02)
        self.assertGreater(value(self.counter), before, "thawed cgroup did not resume")

    def test_cgroup_kill(self) -> None:
        warden.kill_cgroup(self.path)
        time.sleep(0.2)
        self.assertIsNotNone(self.proc.poll(), "process survived cgroup.kill")
        self.assertEqual(warden.cgroup_pids(self.path), [])


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("nft"), "needs root + nft")
class Quarantine(unittest.TestCase):
    UID = 65534  # nobody

    def tearDown(self) -> None:
        warden.quarantine(self.UID, undo=True)

    def test_quarantine_and_undo(self) -> None:
        res = warden.quarantine(self.UID)
        self.assertTrue(res["ok"], res)
        self.assertIn(self.UID, res["members"])
        self.assertTrue(warden.quarantine_active(self.UID))

        undo = warden.quarantine(self.UID, undo=True)
        self.assertTrue(undo["ok"], undo)
        self.assertFalse(warden.quarantine_active(self.UID))


class SignedStop(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.key = os.path.join(self.tmp.name, "ops_key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", self.key,
                        "-C", "ops", "-N", ""], check=True)
        self.signers = os.path.join(self.tmp.name, "allowed_signers")
        with open(self.signers, "w", encoding="utf-8") as fh:
            fh.write(f'ops namespaces="mandate" {open(self.key + ".pub").read().strip()}\n')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def evidence(self) -> dict:
        return {"action": "halt", "method": "cgroup-freeze", "pids": [1],
                "time_to_halt_ms": 3.1, "verified": True, "reason": "test", "actor": "ops"}

    def test_signature_roundtrip(self) -> None:
        ev = self.evidence()
        ev.update(warden.sign_evidence(ev, self.key, "ops"))
        self.assertTrue(warden.verify_evidence(ev, self.signers)["valid"])

    def test_tampered_evidence_fails(self) -> None:
        ev = self.evidence()
        ev.update(warden.sign_evidence(ev, self.key, "ops"))
        ev["time_to_halt_ms"] = 0.1
        self.assertFalse(warden.verify_evidence(ev, self.signers)["valid"])


if __name__ == "__main__":
    unittest.main()
