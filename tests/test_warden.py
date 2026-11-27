"""Warden: stop from outside, verify the stop, record it. Real processes, no mocks."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from mandate import warden

CHILD = """
import os, sys, time
path = sys.argv[1]
i = 0
while True:
    i += 1
    with open(path, "w") as fh:
        fh.write(str(i))
    time.sleep(0.01)
"""


def spawn(counter_path: str) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", CHILD, counter_path],
                            start_new_session=True, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def counter(path: str) -> int:
    try:
        return int(open(path).read() or 0)
    except (OSError, ValueError):
        return 0


class Warden(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.counter = os.path.join(self.tmp.name, "counter")
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")
        # On a loaded runner the child process can take seconds to reach its loop; give it
        # room, retry once, and say what happened instead of just "0".
        for attempt in (1, 2):
            self.proc = spawn(self.counter)
            deadline = time.time() + 20
            while counter(self.counter) < 3 and time.time() < deadline:
                time.sleep(0.02)
            if counter(self.counter) >= 3:
                break
            exit_code = self.proc.poll()
            if attempt == 1 and exit_code is None:
                continue
            self.fail(f"child did not start (attempt {attempt}, exit={exit_code}, "
                      f"counter={counter(self.counter)})")

    def tearDown(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.proc.wait(timeout=5)
        self.tmp.cleanup()

    def test_freeze_is_verified_and_stops_work(self) -> None:
        res = warden.stop(self.proc.pid, method="freeze", by_pgid=True,
                          ledger_path=self.ledger, reason="test freeze", actor="ops")
        self.assertTrue(res["verified"])
        self.assertEqual(res["states_after"][str(self.proc.pid)], "T")
        # Prag je liveness, ne performansa: pod punim suite-om mašina je zauzeta i
        # 6 ms iz README-a nije garant. 3 s hvata „nije se zaustavio", bez flake-a.
        self.assertLess(res["time_to_halt_ms"], 3000)

        frozen_at = counter(self.counter)
        time.sleep(0.3)
        self.assertEqual(counter(self.counter), frozen_at, "frozen process kept working")

        entry = json.loads(open(self.ledger).read().splitlines()[-1])
        self.assertEqual(entry["body"]["action"], "halt")
        self.assertEqual(entry["body"]["actor"], "ops")
        self.assertTrue(entry["body"]["verified"])

    def test_resume_restarts_work_and_is_recorded(self) -> None:
        warden.stop(self.proc.pid, by_pgid=True, ledger_path=self.ledger)
        before = counter(self.counter)
        warden.resume(self.proc.pid, by_pgid=True, ledger_path=self.ledger,
                      reason="fixed", actor="ops")
        deadline = time.time() + 5
        while counter(self.counter) <= before and time.time() < deadline:
            time.sleep(0.02)
        self.assertGreater(counter(self.counter), before, "resumed process did not run")
        last = warden.last_stop(self.ledger)
        self.assertEqual(last["action"], "resume")

    def test_kill_makes_the_process_gone(self) -> None:
        res = warden.stop(self.proc.pid, method="kill", by_pgid=True,
                          ledger_path=self.ledger, reason="hard stop")
        self.assertTrue(res["verified"])
        time.sleep(0.2)
        self.assertNotEqual(self.proc.poll(), None, "process still alive after kill")
        self.assertIsNone(warden._stat(self.proc.pid))

    def test_unknown_pid_is_an_error(self) -> None:
        # 999_999 could be reused on a busy host; pick something outside the
        # default pid range instead of relying on a specific number being free.
        unknown = 2 ** 22 + 4242
        if os.path.exists("/proc/%d" % unknown):
            self.skipTest("pid %d exists on this host" % unknown)
        with self.assertRaises(ValueError):
            warden.stop(unknown, by_pgid=False)

    def test_pids_in_pgid_finds_the_child(self) -> None:
        self.assertIn(self.proc.pid, warden.pids_in_pgid(self.proc.pid))

    def test_ledger_chain_stays_valid(self) -> None:
        from mandate.core import verify_chain
        warden.stop(self.proc.pid, by_pgid=True, ledger_path=self.ledger)
        warden.resume(self.proc.pid, by_pgid=True, ledger_path=self.ledger)
        self.assertTrue(verify_chain(self.ledger))


if __name__ == "__main__":
    unittest.main()
