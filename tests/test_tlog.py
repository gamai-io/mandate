"""TLOG_V1: an append-only release log a stranger can check, in RFC 6962 shape.

The tests avoid trusting the implementation with itself: the root is cross-checked by a second,
deliberately naive construction, and every leaf's inclusion proof is verified for tree sizes 1–17
(the sizes where the split rule actually bends). A proof that only verifies for powers of two is
the classic audit-path bug, and it was a real one here — walking the sibling subtree produced
proofs that verified against nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import tlog

ROOT = pathlib.Path(__file__).resolve().parents[1]


def entries(n: int) -> list[bytes]:
    return [json.dumps({"release": "1.0.%d" % i, "sha256": "%064x" % (i + 1)},
                       sort_keys=True).encode() for i in range(n)]


def naive_root(leaves: list[bytes]) -> bytes:
    """Second implementation: size-based split, written independently of the module."""
    level = [tlog.leaf_hash(e) for e in leaves]
    if not level:
        return hashlib.sha256(b"").digest()
    if len(level) == 1:
        return level[0]
    size = len(level)
    power = 1
    while power * 2 < size:
        power *= 2
    return hashlib.sha256(b"\x01" + naive_root_bytes(level[:power])
                          + naive_root_bytes(level[power:])).digest()


def naive_root_bytes(level: list[bytes]) -> bytes:
    if len(level) == 1:
        return level[0]
    size = len(level)
    power = 1
    while power * 2 < size:
        power *= 2
    return hashlib.sha256(b"\x01" + naive_root_bytes(level[:power])
                          + naive_root_bytes(level[power:])).digest()


class Hashing(unittest.TestCase):
    def test_empty_tree_is_sha256_of_nothing(self):
        self.assertEqual(tlog.merkle_root([]), hashlib.sha256(b"").digest())

    def test_domains_are_separated(self):
        data = b"x"
        self.assertNotEqual(tlog.leaf_hash(data), tlog.node_hash(data, data))
        self.assertEqual(tlog.leaf_hash(data), hashlib.sha256(b"\x00" + data).digest())

    def test_root_matches_a_second_implementation(self):
        for n in range(1, 18):
            batch = entries(n)
            self.assertEqual(tlog.tree_hash(batch), naive_root(batch), "size %d" % n)


class Proofs(unittest.TestCase):
    def test_every_leaf_is_provable_for_sizes_one_to_seventeen(self):
        for n in range(1, 18):
            batch = entries(n)
            root = tlog.tree_hash(batch).hex()
            for index in range(n):
                proof = tlog.inclusion_proof(batch, index)
                self.assertTrue(tlog.verify_inclusion(batch[index], index, n, proof, root),
                                "size %d index %d" % (n, index))

    def test_a_changed_leaf_does_not_verify(self):
        batch = entries(9)
        root = tlog.tree_hash(batch).hex()
        proof = tlog.inclusion_proof(batch, 4)
        self.assertFalse(tlog.verify_inclusion(b'{"release":"9.9.9"}', 4, 9, proof, root))

    def test_a_proof_from_another_index_does_not_verify(self):
        batch = entries(9)
        root = tlog.tree_hash(batch).hex()
        proof = tlog.inclusion_proof(batch, 3)
        self.assertFalse(tlog.verify_inclusion(batch[4], 4, 9, proof, root))

    def test_a_wrong_index_is_refused(self):
        with self.assertRaises(ValueError):
            tlog.inclusion_proof(entries(3), 3)
        self.assertFalse(tlog.verify_inclusion(b"x", 5, 3, [], "00" * 32))


class Append(unittest.TestCase):
    def test_append_only_is_enforced(self):
        old = entries(3)
        self.assertEqual(tlog.append(old, old + [b"x"]), old + [b"x"])
        with self.assertRaises(ValueError):
            tlog.append(old, entries(2))

    def test_a_rewritten_prefix_is_detected(self):
        old = entries(3)
        rewritten = [old[0], b'{"release":"0.0.1"}', old[2], b"x"]
        with self.assertRaises(ValueError):
            tlog.append(old, rewritten)
        self.assertFalse(tlog.consistency(old, rewritten))

    def test_a_longer_log_is_consistent(self):
        old = entries(4)
        self.assertTrue(tlog.consistency(old, old + [b"y"]))


class Checkpoint(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.key = os.path.join(self.td.name, "logkey")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.other = os.path.join(self.td.name, "other")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.other],
                       check=True, capture_output=True)
        self.batch = entries(5)
        self.root = tlog.tree_hash(self.batch)

    def tearDown(self):
        self.td.cleanup()

    def test_a_signed_head_verifies(self):
        ckpt = tlog.checkpoint(len(self.batch), self.root, self.key, "log")
        out = tlog.verify_checkpoint(ckpt)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["size"], 5)

    def test_a_changed_size_breaks_the_signature(self):
        ckpt = tlog.checkpoint(len(self.batch), self.root, self.key, "log")
        ckpt["size"] = 6
        self.assertEqual(tlog.verify_checkpoint(ckpt)["code"], "bad_signature")

    def test_the_wrong_key_does_not_verify(self):
        ckpt = tlog.checkpoint(len(self.batch), self.root, self.other, "log")
        from mandate import sign
        wrong = tlog.verify_checkpoint(ckpt, sign.public_key_of_keyfile(self.key))
        self.assertFalse(wrong["ok"])

    def test_build_embeds_a_checkpoint(self):
        log = tlog.build(self.batch, sign_key=self.key, signer="log")
        self.assertEqual(log["size"], 5)
        self.assertEqual(log["root"], self.root.hex())
        self.assertTrue(tlog.verify_checkpoint(log["checkpoint"])["ok"])


class Cli(unittest.TestCase):
    def test_build_prove_verify_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            key = os.path.join(td, "logkey")
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key],
                           check=True, capture_output=True)
            manifest = os.path.join(td, "manifest.json")
            items = [json.loads(e.decode()) for e in entries(5)]
            pathlib.Path(manifest).write_text(json.dumps(items), encoding="utf-8")
            log = os.path.join(td, "log.json")
            done = subprocess.run([sys.executable, "-m", "mandate", "tlog", "build",
                                   "--manifest", manifest, "--key", key, "--out", log],
                                  cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            payload = json.loads(pathlib.Path(log).read_text(encoding="utf-8"))
            ckpt = os.path.join(td, "ckpt.json")
            pathlib.Path(ckpt).write_text(json.dumps(payload["checkpoint"]), encoding="utf-8")
            proof = os.path.join(td, "proof.json")
            done = subprocess.run([sys.executable, "-m", "mandate", "tlog", "prove",
                                   "--log", log, "--index", "2", "--out", proof],
                                  cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            entry = os.path.join(td, "entry.json")
            pathlib.Path(entry).write_text(json.dumps(items[2], sort_keys=True,
                                                      ensure_ascii=False), encoding="utf-8")
            ok = subprocess.run([sys.executable, "-m", "mandate", "tlog", "verify",
                                 "--entry", entry, "--proof", proof, "--checkpoint", ckpt],
                                cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertTrue(json.loads(ok.stdout)["ok"])
            pathlib.Path(entry).write_text(json.dumps({"release": "never"}, sort_keys=True),
                                           encoding="utf-8")
            bad = subprocess.run([sys.executable, "-m", "mandate", "tlog", "verify",
                                  "--entry", entry, "--proof", proof, "--checkpoint", ckpt],
                                 cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(bad.returncode, 4)
            self.assertFalse(json.loads(bad.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
