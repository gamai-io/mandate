"""OFFLINE_VERIFIER_V1: the bundle verifies with zero network calls, in a second implementation.

The point of the browser verifier is that it does not trust us. A test that only calls our own
Python would prove nothing, so this one runs the *JavaScript* verifier under Node against a bundle
produced by the CLI, and compares the canonicaliser with Python's on a corpus:

  * jcs(intent) must be byte-identical in both implementations (otherwise a verifier "fails" on
    a clean record, which is worse than passing a tampered one);
  * a clean bundle verifies;
  * a changed amount fails, and fails on the commitment check specifically;
  * a receipt whose body was edited fails on the receipt hash.

Node is optional: without it the tests are skipped, not silently passed.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from mandate import bundle as bundle_mod
from mandate import core

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "web" / "mandate-verify.js"
NODE = shutil.which("node")


def intent(**over) -> dict:
    body = {
        "v": 1,
        "actor": {"agent": "agent@example", "session": "s1"},
        "effect": {"kind": "payment.send", "target": "Example Supplier",
                   "amount": {"value": 1170.0, "currency": "BAM"},
                   "params": {"ref": "faktura-77", "note": "žurba — 17% PDV"}},
        "requested_by": "approver",
        "nonce": "n-1",
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1"},
                       {"type": "user_pref", "source": "chat:42"}],
    }
    body.update(over)
    return body


@unittest.skipUnless(NODE, "node is not installed")
class JavaScript(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "k")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n'
            % pathlib.Path(self.key + ".pub").read_text().strip(), encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.bundle = self._make_bundle()

    def tearDown(self):
        self.td.cleanup()

    def _make_bundle(self) -> dict:
        proposal = core.propose(intent(), salted=True)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", render_hash=proposal["render_hash"],
            agent="agent@example", commitment_alg=proposal["commitment_alg"],
            commitment_salt=proposal["commitment_salt"])
        grant = core.make_grant(grant_core, self.key)
        core.redeem(intent(), grant, self.signers, self.ledger)
        return bundle_mod.export_bundle(intent(), grant, self.ledger, self.signers)

    def _run(self, payload: str, script: str) -> str:
        path = os.path.join(self.dir, "payload.json")
        pathlib.Path(path).write_text(payload, encoding="utf-8")
        js = os.path.join(self.dir, "check.js")
        pathlib.Path(js).write_text(
            "global.crypto = require('node:crypto').webcrypto;\n"
            "require(%s);\n"
            "const fs = require('node:fs');\n"
            "const b = JSON.parse(fs.readFileSync(%s, 'utf8'));\n"
            "(async () => { %s })();\n" % (json.dumps(str(VERIFIER)), json.dumps(path), script),
            encoding="utf-8")
        done = subprocess.run([NODE, js], capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr[:400])
        return done.stdout.strip()

    def test_a_clean_bundle_verifies(self):
        out = self._run(json.dumps(self.bundle),
                        "const r = await MandateVerify.verifyBundle(b);"
                        "console.log(JSON.stringify(r));")
        result = json.loads(out)
        self.assertTrue(result["ok"], result)
        self.assertTrue(all(c["ok"] for c in result["checks"]), result)

    def test_a_changed_amount_fails_on_the_commitment(self):
        tampered = json.loads(json.dumps(self.bundle))
        tampered["intent"]["effect"]["amount"]["value"] = 1171.0
        out = self._run(json.dumps(tampered),
                        "const r = await MandateVerify.verifyBundle(b);"
                        "console.log(JSON.stringify(r));")
        result = json.loads(out)
        self.assertFalse(result["ok"])
        failed = [c["name"] for c in result["checks"] if not c["ok"]]
        self.assertIn("commitment (intent → grant)", failed)

    def test_an_edited_receipt_body_fails_on_the_hash(self):
        tampered = json.loads(json.dumps(self.bundle))
        tampered["receipt"]["body"]["approver"] = "someone-else"
        out = self._run(json.dumps(tampered),
                        "const r = await MandateVerify.verifyBundle(b);"
                        "console.log(JSON.stringify(r));")
        result = json.loads(out)
        self.assertFalse(result["ok"])
        self.assertIn("receipt sha256(jcs(body))",
                      [c["name"] for c in result["checks"] if not c["ok"]])

    def test_javascript_canonicalisation_matches_python(self):
        corpus = [
            intent(),
            intent(nonce="n-2", effect={"kind": "read.lookup", "target": "Customer 7"}),
            intent(effect={"kind": "price.change", "target": "Artikel Ä",
                           "amount": {"value": 0.1, "currency": "EUR"},
                           "params": {"levels": [1, 2.5, "x"], "flag": True, "none": None}}),
            intent(requested_by="Šuster", actor={"agent": "agent@example", "session": None}),
        ]
        expected = [core.jcs(core.normalize_intent(item)) for item in corpus]
        out = self._run(json.dumps({"items": corpus}),
                        "console.log(JSON.stringify(b.items.map(x => MandateVerify.jcs(x))));")
        self.assertEqual(json.loads(out), expected)


class Cli(unittest.TestCase):
    def test_missing_signers_is_a_warning_not_a_crash(self):
        with tempfile.TemporaryDirectory() as td:
            key = os.path.join(td, "k")
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key],
                           check=True, capture_output=True)
            ledger = os.path.join(td, "ledger.jsonl")
            proposal = core.propose(intent())
            grant_core = core.build_grant_core(proposal["commitment"], "approver",
                                               render_hash=proposal["render_hash"])
            grant = core.make_grant(grant_core, key)
            signers = os.path.join(td, "signers")
            pathlib.Path(signers).write_text(
                'approver namespaces="mandate" %s\n'
                % pathlib.Path(key + ".pub").read_text().strip(), encoding="utf-8")
            core.redeem(intent(), grant, signers, ledger)
            out = bundle_mod.export_bundle(intent(), grant, ledger, "")
            self.assertEqual(out["format"], "mandate-bundle/1")
            self.assertIn("warning", out)
            self.assertIn("cannot check the signature", out["warning"])

    def test_bundle_has_the_four_parts(self):
        with tempfile.TemporaryDirectory() as td:
            key = os.path.join(td, "k")
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key],
                           check=True, capture_output=True)
            signers = os.path.join(td, "signers")
            pathlib.Path(signers).write_text(
                'approver namespaces="mandate" %s\n'
                % pathlib.Path(key + ".pub").read_text().strip(), encoding="utf-8")
            ledger = os.path.join(td, "ledger.jsonl")
            proposal = core.propose(intent(), salted=True)
            grant_core = core.build_grant_core(
                proposal["commitment"], "approver", render_hash=proposal["render_hash"],
                commitment_alg=proposal["commitment_alg"],
                commitment_salt=proposal["commitment_salt"])
            grant = core.make_grant(grant_core, key)
            core.redeem(intent(), grant, signers, ledger)
            out = bundle_mod.export_bundle(intent(), grant, ledger, signers)
            for part in ("receipt", "intent", "grant", "public_key"):
                self.assertIn(part, out)
            self.assertNotIn("warning", out)
            self.assertTrue(out["public_key"].startswith("ssh-ed25519 "))


if __name__ == "__main__":
    unittest.main()
