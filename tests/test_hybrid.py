"""Hybrid witness notes: Ed25519 plus ML-DSA-65, and no silent downgrade."""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

from mandate import hybrid
from mandate import witness_note as wn

STH = {"sth": {"log_name": "log1", "log_id": "id-1", "tree_size": 3,
               "root_hash": "ab" * 32}}


@unittest.skipUnless(hybrid.PQ_AVAILABLE, "ML-DSA is not available here")
class Hybrid(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ed = self.ed_key("witness")
        self.pq = os.path.join(self.dir, "pq.key")
        self.pq_pub = hybrid.pq_keygen(self.pq)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'witness1 namespaces="mandate-witness" %s\n'
            % pathlib.Path(self.ed + ".pub").read_text().strip(), encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def ed_key(self, name):
        path = os.path.join(self.dir, name)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path],
                       check=True)
        return path

    def note(self):
        return wn.make(STH, self.ed, "witness1", pinned_at=1, pq_key_path=self.pq)

    def test_private_key_is_0600(self):
        self.assertEqual(os.stat(self.pq).st_mode & 0o777, 0o600)

    def test_hybrid_note_verifies_with_both_keys(self):
        result = wn.verify(self.note(), self.signers, STH, pq_keys=[self.pq_pub])
        self.assertTrue(result["valid"], result)
        self.assertTrue(result["hybrid"])

    def test_without_the_pq_key_it_is_refused_not_downgraded(self):
        result = wn.verify(self.note(), self.signers, STH, pq_keys=[])
        self.assertFalse(result["valid"])
        self.assertFalse(result["hybrid"])
        self.assertTrue(result["no_downgrade"],
                        "the Ed25519 half verified; the note must still be refused")

    def test_a_wrong_pq_key_is_refused(self):
        self.assertFalse(wn.verify(self.note(), self.signers, STH,
                                   pq_keys=["AAAA"])["valid"])

    def test_a_tampered_pq_signature_is_refused(self):
        note = self.note()
        sig = note["hybrid"]["ml-dsa-65"]["signature"]
        note["hybrid"]["ml-dsa-65"]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        self.assertFalse(wn.verify(note, self.signers, STH, pq_keys=[self.pq_pub])["valid"])

    def test_a_tampered_text_breaks_both_halves(self):
        note = self.note()
        note["text"] = note["text"].replace("tree_size: 3", "tree_size: 4")
        result = wn.verify(note, self.signers, STH, pq_keys=[self.pq_pub])
        self.assertFalse(result["note"])
        self.assertFalse(result["hybrid"])

    def test_ed25519_only_note_still_verifies(self):
        note = wn.make(STH, self.ed, "witness1", pinned_at=1)
        result = wn.verify(note, self.signers, STH, pq_keys=[self.pq_pub])
        self.assertTrue(result["valid"], result)
        self.assertFalse(result["hybrid"])


if __name__ == "__main__":
    unittest.main()
