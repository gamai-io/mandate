"""SDIST_REPRO_V1: the same source has to produce the same sdist bytes from any checkout.

`git archive` extracted under umask 0002 gives 0664, a CI checkout gives 0644. That difference
does not change a single byte of content, but it changes the archive hash — and a hash mismatch
is what a customer sees. The normalizer therefore fixes the mode too, while keeping the
executable bit, because `examples/*.sh` must stay runnable.
"""
from __future__ import annotations

import gzip
import importlib.util
import io
import os
import pathlib
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("normalize_sdist",
                                              ROOT / "tools" / "normalize_sdist.py")
normalize_sdist = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalize_sdist)


def _tar(path: str, mode: int, exe_mode: int, when: int = 1700000000) -> None:
    with tarfile.open(path, "w:gz") as tf:
        for name, content, perm in (("pkg/data.txt", b"x", mode),
                                    ("pkg/run.sh", b"#!/bin/sh\n", exe_mode)):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = perm
            info.mtime = when
            info.uid = info.gid = 1000
            info.uname = info.gname = "builder"
            tf.addfile(info, io.BytesIO(content))


class SameBytes(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name

    def tearDown(self):
        self.td.cleanup()

    def _hash(self, path: str) -> bytes:
        return pathlib.Path(path).read_bytes()

    def test_umask_and_checkout_permissions_normalize_to_one_archive(self):
        a = os.path.join(self.dir, "a.tar.gz")
        b = os.path.join(self.dir, "b.tar.gz")
        _tar(a, 0o664, 0o775)
        _tar(b, 0o644, 0o755)
        self.assertNotEqual(self._hash(a), self._hash(b))
        normalize_sdist.normalize(a, 1700000000)
        normalize_sdist.normalize(b, 1700000000)
        self.assertEqual(self._hash(a), self._hash(b))

    def test_the_executable_bit_survives(self):
        a = os.path.join(self.dir, "a.tar.gz")
        _tar(a, 0o664, 0o775)
        normalize_sdist.normalize(a, 1700000000)
        raw = gzip.decompress(pathlib.Path(a).read_bytes())
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            modes = {m.name: m.mode for m in tf.getmembers()}
        self.assertEqual(modes["pkg/run.sh"], 0o755)
        self.assertEqual(modes["pkg/data.txt"], 0o644)

    def test_uid_and_owner_names_are_stripped(self):
        a = os.path.join(self.dir, "a.tar.gz")
        _tar(a, 0o644, 0o755)
        normalize_sdist.normalize(a, 1700000000)
        raw = gzip.decompress(pathlib.Path(a).read_bytes())
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            for member in tf.getmembers():
                self.assertEqual((member.uid, member.gid), (0, 0))
                self.assertEqual((member.uname, member.gname), ("", ""))
                self.assertEqual(member.mtime, 1700000000)

    def test_normalize_is_idempotent(self):
        a = os.path.join(self.dir, "a.tar.gz")
        _tar(a, 0o664, 0o775)
        normalize_sdist.normalize(a, 1700000000)
        once = self._hash(a)
        normalize_sdist.normalize(a, 1700000000)
        self.assertEqual(once, self._hash(a))

    def test_normalize_reports_whether_it_had_to_write(self):
        a = os.path.join(self.dir, "a.tar.gz")
        _tar(a, 0o664, 0o775)
        self.assertFalse(normalize_sdist.normalize(a, 1700000000))   # changed -> False
        self.assertTrue(normalize_sdist.normalize(a, 1700000000))    # already normalized


if __name__ == "__main__":
    unittest.main()
