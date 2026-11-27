"""A witness pin is only evidence if the witness host signed it."""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

from mandate import witness_note as wn

STH = {"sth": {"log_name": "log1", "log_id": "id-1", "tree_size": 4,
               "root_hash": "9f" * 32}}


class Note(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = self.make_key("witness")
        self.other = self.make_key("other")
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'witness1 namespaces="mandate-witness" %s\n' % self.pub(self.key),
            encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def make_key(self, name):
        path = os.path.join(self.dir, name)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path],
                       check=True)
        return path

    def pub(self, path):
        return pathlib.Path(path + ".pub").read_text().strip()

    def test_note_verifies_and_matches_the_sth(self):
        note = wn.make(STH, self.key, "witness1", pinned_at=1795733000000)
        result = wn.verify(note, self.signers, STH)
        self.assertTrue(result["valid"], result)
        self.assertTrue(result["note"])
        self.assertTrue(result["matches_sth"])

    def test_edited_note_is_refused(self):
        note = wn.make(STH, self.key, "witness1")
        note["text"] = note["text"].replace("tree_size: 4", "tree_size: 5")
        self.assertFalse(wn.verify(note, self.signers, STH)["valid"])

    def test_a_different_key_is_refused(self):
        note = wn.make(STH, self.other, "witness1", pinned_at=1)
        self.assertFalse(wn.verify(note, self.signers, STH)["note"])

    def test_note_for_another_log_is_refused(self):
        note = wn.make(STH, self.key, "witness1")
        other_sth = {"sth": dict(STH["sth"], root_hash="00" * 32)}
        result = wn.verify(note, self.signers, other_sth)
        self.assertFalse(result["valid"])
        self.assertTrue(result["note"])
        self.assertFalse(result["matches_sth"])

    def test_unknown_format_is_refused(self):
        self.assertFalse(wn.verify({"format": "x", "text": "", "signature": ""},
                                   self.signers, STH)["valid"])


if __name__ == "__main__":
    unittest.main()
