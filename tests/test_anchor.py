"""External anchoring (RFC 3161) and WORM export, tested offline.

The fixture is a real FreeTSA token taken 2026-11-24 over a 64-hex ledger head,
together with its sidecar. No network is used in these tests.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest

from mandate import anchor

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
TSR = os.path.join(FIX, "tsa_freetsa_2026-11-24.tsr")
SIDECAR = os.path.join(FIX, "tsa_freetsa_2026-11-24.json")
CA = os.path.join(FIX, "tsa_freetsa_ca.pem")


def write_ledger(directory: str, head_hex: str) -> str:
    path = os.path.join(directory, "ledger.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"body": {"v": 1, "type": "receipt"}, "hash": head_hex}) + "\n")
    with open(path + ".head", "w", encoding="utf-8") as fh:
        fh.write(head_hex + "\n")
    return path


class TokenParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.side = json.load(open(SIDECAR))
        self.raw = open(TSR, "rb").read()

    def test_status_and_time(self) -> None:
        info = anchor.parse_response(self.raw)
        self.assertEqual(info["status"], 0)
        self.assertTrue(info["gen_time"].endswith("Z"), info["gen_time"])
        self.assertEqual(len(info["gen_time"]), 13)

    def test_imprint_is_sha256_of_head(self) -> None:
        info = anchor.parse_response(self.raw)
        expected = hashlib.sha256(self.side["head"].encode()).hexdigest()
        self.assertEqual(info["imprint_sha256"], expected)
        self.assertEqual(info["imprint_sha256"], self.side["head_sha256"])

    def test_cms_token_is_extractable(self) -> None:
        token = anchor.extract_token(self.raw)
        self.assertGreater(len(token), 1000)
        self.assertNotEqual(token, self.raw, "token must be the CMS, not the whole response")
        self.assertIn(bytes.fromhex("0609608648016503040201"), token, "sha256 imprint inside the token")


class Verification(unittest.TestCase):
    def setUp(self) -> None:
        self.side = json.load(open(SIDECAR))

    def test_valid_only_with_a_ca(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = write_ledger(td, self.side["head"])
            weak = anchor.verify_anchor(ledger, TSR)
            strong = anchor.verify_anchor(ledger, TSR, CA)
        self.assertFalse(weak["valid"], "without a CA this must not be called valid")
        self.assertEqual(weak["code"], "cms_unverified")
        self.assertTrue(weak["imprint_ok"])
        self.assertTrue(strong["valid"], strong)
        self.assertTrue(strong["openssl_verify"]["verified"])

    def test_forged_blob_is_rejected(self) -> None:
        """A hand-made blob with status 0 + imprint must not pass verification."""
        import hashlib as _h
        head = self.side["head"]
        digest = _h.sha256(head.encode()).digest()
        oid = bytes.fromhex("0609608648016503040201")
        inner = b"\x30\x00" + oid + b"\x04\x20" + digest
        blob = b"\x30" + bytes([len(inner) + 2]) + b"\x30\x03\x02\x01\x00" + inner
        with tempfile.TemporaryDirectory() as td:
            token = os.path.join(td, "forged.tsr")
            open(token, "wb").write(blob)
            ledger = write_ledger(td, head)
            res = anchor.verify_anchor(ledger, token, CA)
        self.assertFalse(res["valid"], res)
        self.assertIn(res["code"], ("no_cms_token", "cms_failed"))

    def test_invalid_when_ledger_moved_on_or_was_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = write_ledger(td, "0" * 64)
            res = anchor.verify_anchor(ledger, TSR, CA)
        self.assertFalse(res["valid"])
        self.assertFalse(res["imprint_matches_head"])

    def test_empty_ledger_cannot_be_anchored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "empty.jsonl")
            open(path, "w").close()
            with self.assertRaises(ValueError):
                anchor.anchor(path, out_dir=td)


class WormExport(unittest.TestCase):
    def test_export_is_read_only_with_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            head = "a" * 64
            ledger = write_ledger(td, head)
            anchors = os.path.join(td, "anchors")
            os.makedirs(anchors)
            open(os.path.join(anchors, "x.tsr"), "wb").write(b"token")
            res = anchor.worm_export(ledger, os.path.join(td, "worm"), 180, anchors)

            self.assertTrue(os.path.isdir(res["path"]))
            manifest = json.load(open(res["manifest_path"]))
            self.assertEqual(manifest["ledger_head"], head)
            self.assertEqual(manifest["retention_days"], 180)
            self.assertIn("clock", manifest)
            self.assertEqual(len(manifest["files"]), 3)  # ledger, head, anchor

            for rel in manifest["files"]:
                full = os.path.join(res["path"], rel)
                mode = stat.S_IMODE(os.stat(full).st_mode)
                self.assertEqual(mode & 0o222, 0, "exported files must not be writable")
                self.assertEqual(
                    manifest["files"][rel]["sha256"],
                    hashlib.sha256(open(full, "rb").read()).hexdigest())

    def test_retention_is_in_the_future(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ledger = write_ledger(td, "b" * 64)
            res = anchor.worm_export(ledger, os.path.join(td, "worm"), 30)
            manifest = json.load(open(res["manifest_path"]))
        self.assertGreater(manifest["retention_until"], manifest["exported_at"])


class RequestEncoding(unittest.TestCase):
    def test_request_is_valid_der(self) -> None:
        req = anchor.build_request("f" * 64)
        self.assertEqual(req[0], 0x30)
        self.assertIn(bytes.fromhex("0609608648016503040201"), req)


if __name__ == "__main__":
    unittest.main()
