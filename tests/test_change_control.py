"""ROW10_V1: a change is traceable, and the file on disk is still the one that was signed.

Two failure modes make change control theatre: a record with no ticket (who asked?), and a
record that was true last month (nobody recorded today's edit). `change record --require-ticket`
refuses the first; `change verify` catches the second by comparing the newest signed hash with
the bytes on disk.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import report
from mandate.core import MandateError

ROOT = pathlib.Path(__file__).resolve().parents[1]
KEY = None
SIGNERS = None


def setUpModule():
    global KEY, SIGNERS, _td
    _td = tempfile.TemporaryDirectory()
    KEY = os.path.join(_td.name, "key")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", KEY],
                   check=True, capture_output=True)
    SIGNERS = os.path.join(_td.name, "signers")
    pathlib.Path(SIGNERS).write_text(
        "approver %s\n" % pathlib.Path(KEY + ".pub").read_text().strip(), encoding="utf-8")


def tearDownModule():
    _td.cleanup()


class Tickets(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.file = os.path.join(self.dir, "policy.json")
        pathlib.Path(self.file).write_text('{"limits": {"max_amount": 10}}\n', encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def _record(self, **kw):
        return report.change_record(self.ledger, self.file, "approver", KEY,
                                    kw.pop("reason", "r"), **kw)

    def test_a_record_without_a_ticket_is_flagged(self):
        out = self._record()
        self.assertEqual(out["ticket"], "")
        self.assertIn("ticket required", out["ticket_problem"])

    def test_require_ticket_refuses(self):
        with self.assertRaises(MandateError):
            self._record(require_ticket=True)

    def test_a_shape_that_is_not_a_ticket_is_refused(self):
        with self.assertRaises(MandateError):
            self._record(ticket="fixed the thing", require_ticket=True)

    def test_a_real_ticket_is_accepted_and_filterable(self):
        self._record(ticket="SEC-142")
        self._record(ticket="OPS-7")
        listed = report.changes(self.ledger, ticket="SEC-142")
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["changes"][0]["ticket"], "SEC-142")

    def test_model_pinning_validates_its_shape(self):
        self._record(ticket="SEC-142", model="gpt-x@2026-11-01")
        with self.assertRaises(MandateError):
            self._record(ticket="SEC-143", model="two words")
        with self.assertRaises(MandateError):
            self._record(ticket="SEC-144", model_digest="sha256:short")

    def test_models_view_reports_the_newest_pin(self):
        self._record(ticket="SEC-142", model="gpt-x@1")
        self._record(ticket="SEC-143", model="gpt-x@2")
        out = report.pinned_models(self.ledger)
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["models"][0]["model"], "gpt-x@2")
        self.assertEqual(out["models"][0]["ticket"], "SEC-143")


class Drift(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.file = os.path.join(self.dir, "policy.json")
        pathlib.Path(self.file).write_text('{"limits": {"max_amount": 10}}\n', encoding="utf-8")
        report.change_record(self.ledger, self.file, "approver", KEY, "limit", ticket="SEC-1")

    def tearDown(self):
        self.td.cleanup()

    def test_the_signed_bytes_verify(self):
        out = report.drift(self.ledger, self.dir)
        self.assertTrue(out["ok"], out)
        self.assertEqual([f["state"] for f in out["files"]], ["ok"])

    def test_an_unrecorded_edit_is_caught(self):
        pathlib.Path(self.file).write_text('{"limits": {"max_amount": 999}}\n', encoding="utf-8")
        out = report.drift(self.ledger, self.dir)
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "drift")
        self.assertIn("unrecorded change: policy.json", " ".join(out["problems"]))

    def test_a_deleted_file_is_caught(self):
        os.remove(self.file)
        out = report.drift(self.ledger, self.dir)
        self.assertFalse(out["ok"])
        self.assertIn("missing: policy.json", " ".join(out["problems"]))

    def test_an_untracked_config_file_is_a_gap_not_a_tamper(self):
        pathlib.Path(os.path.join(self.dir, "other.json")).write_text("{}", encoding="utf-8")
        pathlib.Path(os.path.join(self.dir, "notes.txt")).write_text("x", encoding="utf-8")
        out = report.drift(self.ledger, self.dir)
        self.assertTrue(out["ok"])                       # nothing recorded changed
        self.assertEqual(out["untracked"], ["other.json"])   # .txt is not a control file

    def test_a_newer_record_wins(self):
        pathlib.Path(self.file).write_text('{"limits": {"max_amount": 50}}\n', encoding="utf-8")
        report.change_record(self.ledger, self.file, "approver", KEY, "raise", ticket="SEC-2")
        out = report.drift(self.ledger, self.dir)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["files"][0]["ticket"], "SEC-2")

    def test_cli_exit_codes(self):
        ok = subprocess.run([sys.executable, "-m", "mandate", "change", "verify",
                             "--ledger", self.ledger, "--dir", self.dir],
                            cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        pathlib.Path(self.file).write_text("{}", encoding="utf-8")
        bad = subprocess.run([sys.executable, "-m", "mandate", "change", "verify",
                              "--ledger", self.ledger, "--dir", self.dir],
                             cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(bad.returncode, 4)
        self.assertEqual(json.loads(bad.stdout)["code"], "drift")


if __name__ == "__main__":
    unittest.main()
