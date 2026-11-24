"""Ops round: backup/restore, SBOM, multi-TSA anchoring, signed pack index."""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest

from mandate import anchor, report
from mandate.core import append_receipt

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
TSR = os.path.join(FIX, "tsa_freetsa_2026-11-24.tsr")
SIDECAR = os.path.join(FIX, "tsa_freetsa_2026-11-24.json")


def keypair(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name, "-N", ""],
                   check=True)
    return path


def ledger_with_one_receipt(path: str, head: str | None = None) -> str:
    entry = append_receipt(path, {"v": 1, "type": "receipt", "agent": "a", "approver": "b",
                                  "ts": time.time(),
                                  "render": {"fields": {"kind": "payment.send",
                                                        "amount": {"value": 1,
                                                                   "currency": "BAM"}}}})
    if head:   # tests that need a specific head (e.g. matching a TSA fixture)
        with open(path + ".head", "w") as fh:
            fh.write(head + "\n")
    return entry["hash"]


class BackupRestore(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        ledger_with_one_receipt(self.ledger)
        os.makedirs(os.path.join(self.dir, "anchors"))
        open(os.path.join(self.dir, "anchors", "a.tsr"), "wb").write(b"token")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_roundtrip_verifies_every_hash(self) -> None:
        b = report.backup(self.ledger, os.path.join(self.dir, "backup"),
                          os.path.join(self.dir, "anchors"))
        r = report.restore(b["archive"], os.path.join(self.dir, "restored"))
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["chain_valid"])
        self.assertEqual(r["problems"], [])

    def test_tampered_manifest_is_detected(self) -> None:
        b = report.backup(self.ledger, os.path.join(self.dir, "backup"),
                          os.path.join(self.dir, "anchors"))
        manifest = json.load(open(b["manifest"]))
        key = next(iter(manifest["members"]))
        manifest["members"][key] = "0" * 64
        json.dump(manifest, open(b["manifest"], "w"))
        r = report.restore(b["archive"], os.path.join(self.dir, "restored2"))
        self.assertFalse(r["ok"])
        self.assertTrue(any("hash mismatch" in p for p in r["problems"]))


class Sbom(unittest.TestCase):
    def test_cyclonedx_shape_and_zero_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "sbom.json")
            report.sbom("9.9.9", path)
            doc = json.load(open(path))
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertEqual(doc["metadata"]["component"]["version"], "9.9.9")
        self.assertEqual(doc["components"], [])
        self.assertEqual(doc["properties"][0]["value"], "0")
        self.assertTrue(doc["files"])


class SignedPack(unittest.TestCase):
    def test_index_signature_and_embedded_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            key = keypair(td, "ops_key")
            signers = os.path.join(td, "allowed_signers")
            open(signers, "w").write(
                f'ops namespaces="mandate" {open(key + ".pub").read().strip()}\n')
            ledger = os.path.join(td, "ledger.jsonl")
            ledger_with_one_receipt(ledger)
            out = os.path.join(td, "pack")
            res = report.pack(ledger, out, sign_key=key, signer="ops")
            index = json.load(open(res["index"]))
            self.assertTrue(os.path.exists(os.path.join(out, "ledger.jsonl")))
            self.assertIn("signature", index)
            from mandate import sign
            from mandate.jcs import canonicalize
            body = {k: v for k, v in index.items() if k not in ("signature", "signer")}
            self.assertTrue(sign.verify(canonicalize(body), "ops", index["signature"],
                                        signers, sign.DEFAULT_NAMESPACE))


class StubTsa(http.server.BaseHTTPRequestHandler):
    body = b""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        pass


class MultiTsa(unittest.TestCase):
    def test_two_tsas_both_stored(self) -> None:
        StubTsa.body = open(TSR, "rb").read()
        head = json.load(open(SIDECAR))["head"]
        servers = []
        for _ in range(2):
            srv = http.server.HTTPServer(("127.0.0.1", 0), StubTsa)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            servers.append((srv, f"http://127.0.0.1:{srv.server_address[1]}/tsr"))
        try:
            with tempfile.TemporaryDirectory() as td:
                ledger = os.path.join(td, "ledger.jsonl")
                ledger_with_one_receipt(ledger, head)
                out = os.path.join(td, "anchors")
                res = anchor.anchor(ledger, servers[0][1], out,
                                    tsas=[url for _s, url in servers])
                tokens = [f for f in os.listdir(out) if f.endswith(".tsr")]
        finally:
            for srv, _url in servers:
                srv.shutdown()
                srv.server_close()
        self.assertEqual(len(tokens), 2, tokens)
        self.assertEqual(len(res["anchors"]), 2)
        self.assertTrue(all(a["ok"] for a in res["anchors"]), res["anchors"])


if __name__ == "__main__":
    unittest.main()
