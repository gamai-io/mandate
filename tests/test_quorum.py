"""QUORUM_V1: N independent witnesses on the same tree head, or it fails."""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

from mandate import log as mlog
from mandate import quorum, witness_note


def keypair(dirpath, name):
    path = os.path.join(dirpath, name)
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", path],
                   check=True, capture_output=True)
    return path


class Quorum(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.keys = {n: keypair(d, n) for n in ("w1", "w2", "w3", "evil")}
        self.signers = os.path.join(d, "signers")
        pathlib.Path(self.signers).write_text("".join(
            '%s namespaces="mandate-witness" %s\n'
            % (n, pathlib.Path(self.keys[n] + ".pub").read_text(encoding="utf-8").strip())
            for n in ("w1", "w2", "w3")), encoding="utf-8")   # „evil" nije dozvoljen
        self.sth = {"sth": mlog.sth_payload("log1", "abc", 4, "9f" * 32)}
        self.notes = {n: witness_note.make(self.sth, self.keys[n], n, pinned_at=1000)
                      for n in ("w1", "w2", "w3")}

    def tearDown(self):
        self.td.cleanup()

    def test_two_of_three_is_enough(self):
        res = quorum.evaluate([self.notes["w1"], self.notes["w2"]], self.sth,
                              self.signers, 2)
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 2)
        self.assertEqual(res["witnesses"], ["w1", "w2"])

    def test_one_is_not_enough(self):
        res = quorum.evaluate([self.notes["w1"]], self.sth, self.signers, 2)
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "E_QUORUM")
        self.assertIn("1 of 2", res["message"])

    def test_same_witness_twice_counts_once(self):
        res = quorum.evaluate([self.notes["w1"], dict(self.notes["w1"])], self.sth,
                              self.signers, 2)
        self.assertFalse(res["ok"])
        self.assertEqual(res["count"], 1)

    def test_note_for_another_tree_is_rejected(self):
        other = {"sth": mlog.sth_payload("log1", "abc", 5, "aa" * 32)}
        stale = witness_note.make(other, self.keys["w3"], "w3", pinned_at=1001)
        res = quorum.evaluate([self.notes["w1"], stale], self.sth, self.signers, 2)
        self.assertFalse(res["ok"])
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["rejected"][0]["reason"], "sth_mismatch")

    def test_unknown_witness_key_does_not_count(self):
        forged = witness_note.make(self.sth, self.keys["evil"], "evil", pinned_at=1002)
        res = quorum.evaluate([self.notes["w1"], forged], self.sth, self.signers, 2)
        self.assertFalse(res["ok"])
        self.assertEqual(res["count"], 1)

    def test_split_view_is_detected(self):
        other = {"sth": mlog.sth_payload("log1", "abc", 5, "aa" * 32)}
        other_note = witness_note.make(other, self.keys["w2"], "w2", pinned_at=1003)
        res = quorum.split_view([self.notes["w1"], other_note], self.signers,
                                sth=self.sth)
        self.assertTrue(res["split"])
        self.assertEqual(res["code"], "E_SPLIT_VIEW")
        self.assertEqual(res["trees"], 2)

    def test_same_tree_is_not_a_split(self):
        res = quorum.split_view([self.notes["w1"], self.notes["w2"]], self.signers,
                                sth=self.sth)
        self.assertFalse(res["split"])


class InAuditVerify(unittest.TestCase):
    """`audit verify --witness-quorum` must fail the bundle when the quorum fails."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.keys = {n: keypair(d, n) for n in ("w1", "w2")}
        self.signers = os.path.join(d, "signers")
        pathlib.Path(self.signers).write_text("".join(
            '%s namespaces="mandate-witness" %s\n'
            % (n, pathlib.Path(self.keys[n] + ".pub").read_text(encoding="utf-8").strip())
            for n in self.keys), encoding="utf-8")
        self.sth = {"sth": mlog.sth_payload("log1", "abc", 4, "9f" * 32)}
        self.notes = [witness_note.make(self.sth, self.keys[n], n, pinned_at=1000)
                      for n in self.keys]

    def tearDown(self):
        self.td.cleanup()

    def _verify(self, quorum_n, notes):
        from mandate import audit
        bundle = {"receipt": {}, "sth": self.sth, "witness_notes": notes,
                  "envelope": {}, "inclusion_proof": None}
        return audit.verify_bundle(bundle, self.signers, self.signers,
                                   witness_signers_path=self.signers,
                                   witness_quorum=quorum_n)

    def test_two_notes_meet_a_quorum_of_two(self):
        res = self._verify(2, self.notes)
        self.assertTrue(res["witness_quorum"]["ok"])
        self.assertTrue(res["witness"])

    def test_one_note_misses_a_quorum_of_two(self):
        res = self._verify(2, self.notes[:1])
        self.assertFalse(res["witness_quorum"]["ok"])
        self.assertFalse(res["witness"])
        self.assertEqual(res.get("quorum_error"), "E_QUORUM")

    def test_split_view_fails_even_with_enough_notes(self):
        other = {"sth": mlog.sth_payload("log1", "abc", 9, "bb" * 32)}
        extra = witness_note.make(other, self.keys["w1"], "w1", pinned_at=1001)
        res = self._verify(2, self.notes + [extra])
        self.assertTrue(res.get("witness_split_view"))
        self.assertFalse(res["witness"])


if __name__ == "__main__":
    unittest.main()
