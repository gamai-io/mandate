"""A backup archive must not write outside the directory we restore into."""
from __future__ import annotations

import os
import tarfile
import tempfile
import unittest

from mandate import report
from mandate.core import MandateError


def make_tar(path: str, member: str, payload: bytes = b"x") -> None:
    with tarfile.open(path, "w:gz") as tf:
        import io
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))


class RestoreSafety(unittest.TestCase):
    def test_a_path_traversal_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            archive = os.path.join(td, "backup.tar.gz")
            make_tar(archive, "../../etc/evil")
            with self.assertRaises(MandateError):
                report.restore(archive, os.path.join(td, "out"))

    def test_an_absolute_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            archive = os.path.join(td, "backup.tar.gz")
            make_tar(archive, "/etc/evil")
            with self.assertRaises(MandateError):
                report.restore(archive, os.path.join(td, "out"))

    def test_a_clean_archive_still_restores(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            archive = os.path.join(td, "backup.tar.gz")
            make_tar(archive, "ledger.jsonl", b"")
            result = report.restore(archive, os.path.join(td, "out"))
            self.assertIn("restored_to", result)


if __name__ == "__main__":
    unittest.main()
