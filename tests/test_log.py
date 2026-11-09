import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import core, sign
from mandate import log as mlog

ROOT = pathlib.Path(__file__).resolve().parents[1]


class MerkleTests(unittest.TestCase):
    def setUp(self):
        self.leaves = [hashlib.sha256(bytes([i])).digest() for i in range(30)]

    def test_empty_root(self):
        self.assertEqual(mlog.mth([]), hashlib.sha256(b"").digest())

    def test_inclusion_all_indices(self):
        for n in range(1, 25):
            root = mlog.mth(self.leaves[:n])
            for index in range(n):
                path = mlog.inclusion_path(index, self.leaves[:n])
                self.assertTrue(mlog.verify_inclusion(
                    self.leaves[index], index, n, root, path), (n, index))
                if path:
                    bad = list(path)
                    bad[0] = b"\x00" * 32
                    self.assertFalse(mlog.verify_inclusion(
                        self.leaves[index], index, n, root, bad))
            self.assertFalse(mlog.verify_inclusion(
                b"\x11" * 32, 0, n, root,
                mlog.inclusion_path(0, self.leaves[:n])))

    def test_inclusion_proof_dict(self):
        entry = {"body": {"v": 1, "i": 0}, "hash": "h0"}
        leaves = [mlog.leaf_hash(entry),
                  mlog.leaf_hash({"body": {"i": 1}, "hash": "h1"})]
        proof = mlog.inclusion_proof(leaves, 0)
        self.assertTrue(mlog.verify_inclusion_proof(entry, proof))
        self.assertFalse(mlog.verify_inclusion_proof(
            {"body": {"i": 9}, "hash": "h9"}, proof))

    def test_consistency_all_pairs(self):
        for n in range(1, 25):
            for m in range(0, n + 1):
                proof = mlog.consistency_proof(self.leaves[:n], m, n)
                first_root = mlog.mth(self.leaves[:m])
                second_root = mlog.mth(self.leaves[:n])
                path = [bytes.fromhex(p) for p in proof["path"]]
                self.assertTrue(mlog.verify_consistency(
                    m, n, first_root, second_root, path), (m, n))
                if path:
                    bad = list(path)
                    bad[0] = b"\x00" * 32
                    self.assertFalse(mlog.verify_consistency(
                        m, n, first_root, second_root, bad), (m, n))

    def test_consistency_edges(self):
        self.assertFalse(mlog.verify_consistency(3, 2, b"a", b"b", [b"c"]))
        self.assertTrue(mlog.verify_consistency(2, 2, b"a", b"a", []))
        self.assertFalse(mlog.verify_consistency(2, 2, b"a", b"b", []))
        self.assertTrue(mlog.verify_consistency(0, 5,
                                                mlog.empty_root(), b"x", []))


class LedgerLogTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        for i in range(3):
            core.append_receipt(self.ledger, {"v": 1, "type": "receipt",
                                              "i": i, "decision": "executed"})
        self.key = os.path.join(self.dir, "log_key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "log_signers")
        pathlib.Path(self.signers).write_text(
            'log1 namespaces="mandate-log" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def test_leaves_and_invalid_ledger(self):
        leaves = mlog.leaves_from_ledger(self.ledger)
        self.assertEqual(len(leaves), 3)
        lines = pathlib.Path(self.ledger).read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1].replace('"i":1', '"i":99')
        pathlib.Path(self.ledger).write_text("\n".join(lines) + "\n",
                                             encoding="utf-8")
        with self.assertRaises(mlog.LogError):
            mlog.leaves_from_ledger(self.ledger)

    def test_sth_sign_and_verify(self):
        leaves = mlog.leaves_from_ledger(self.ledger)
        payload = mlog.sth_payload("log1", mlog.log_id_from_key(self.key),
                                   len(leaves), mlog.root_hex(leaves))
        sth = mlog.sign_sth(payload, self.key)
        self.assertTrue(mlog.verify_sth(sth, self.signers))
        wrong_ns = os.path.join(self.dir, "wrong_ns")
        pathlib.Path(wrong_ns).write_text(
            'log1 namespaces="mandate" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.assertFalse(mlog.verify_sth(sth, wrong_ns))
        tampered = json.loads(json.dumps(sth))
        tampered["sth"]["root_hash"] = "00" * 32
        self.assertFalse(mlog.verify_sth(tampered, self.signers))
        fp = sign.fingerprint(pathlib.Path(self.key + ".pub")
                              .read_text(encoding="utf-8").split()[1])
        revoked = os.path.join(self.dir, "revoked")
        pathlib.Path(revoked).write_text(fp + "\n", encoding="utf-8")
        self.assertFalse(mlog.verify_sth(sth, self.signers,
                                         revoked_path=revoked))

    def test_cli_end_to_end(self):
        env = dict(os.environ)
        sth = os.path.join(self.dir, "sth.json")
        proof = os.path.join(self.dir, "proof.json")
        entry = os.path.join(self.dir, "entry.json")
        cons = os.path.join(self.dir, "cons.json")
        old_sth = os.path.join(self.dir, "old_sth.json")

        def run(*args):
            return subprocess.run(
                [sys.executable, str(ROOT / "bin" / "mandate"), *args],
                capture_output=True, text=True, env=env)

        result = run("log", "head", "--ledger", self.ledger,
                     "--log-name", "log1", "--log-key", self.key,
                     "--out", sth)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        result = run("--signers", self.signers, "log", "sth-verify", "--sth", sth)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(json.loads(result.stdout)["valid"])

        result = run("log", "proof", "--ledger", self.ledger,
                     "--index", "1", "--out", proof)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        entries = core.read_ledger(self.ledger)
        pathlib.Path(entry).write_text(json.dumps(entries[1]), encoding="utf-8")
        result = run("log", "verify-inclusion", "--entry", entry,
                     "--proof", proof, "--sth", sth)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(json.loads(result.stdout)["valid"])

        lines = pathlib.Path(self.ledger).read_text(encoding="utf-8").splitlines()
        old_ledger = os.path.join(self.dir, "old.jsonl")
        pathlib.Path(old_ledger).write_text("\n".join(lines[:2]) + "\n",
                                            encoding="utf-8")
        result = run("log", "head", "--ledger", old_ledger,
                     "--log-name", "log1", "--log-key", self.key,
                     "--out", old_sth)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        result = run("log", "consistency", "--ledger", self.ledger,
                     "--first", "2", "--second", "3", "--out", cons)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        result = run("log", "verify-consistency", "--old", old_sth,
                     "--new", sth, "--proof", cons)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(json.loads(result.stdout)["valid"])

    def test_cli_rejects_invalid_ledger(self):
        lines = pathlib.Path(self.ledger).read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"i":0', '"i":42')
        bad = os.path.join(self.dir, "bad.jsonl")
        pathlib.Path(bad).write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "mandate"), "log", "head",
             "--ledger", bad, "--log-name", "log1", "--log-key", self.key],
            capture_output=True, text=True, env=dict(os.environ))
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
