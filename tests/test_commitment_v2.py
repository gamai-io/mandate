"""COMMITMENT_V2: a salted commitment, because AP2 says deterministic binding is guessable.

AP2's specification forbids signing the checkout hash with a deterministic scheme "to prevent
rainbow table attacks". Our v1 commitment is sha256(jcs(core)) — a low-entropy intent (pay 1.00
to X) is guessable in principle, so a signature over it can be matched offline. v2 prepends a
fixed domain and 16 random bytes that travel inside the signed grant:

    sha256(b"mandate/commitment/v2\\x00" || salt[16] || jcs(intent_core))

These tests hold the line between the two schemes: v1 still verifies (frozen 1.0 format), v2
refuses to work without its salt, and a changed amount still fails on both.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import core
from mandate.core import MandateError

ROOT = pathlib.Path(__file__).resolve().parents[1]


def intent(**over) -> dict:
    body = {
        "v": 1,
        "actor": {"agent": "agent@example", "session": "s1"},
        "effect": {"kind": "payment.send", "target": "Example Supplier",
                   "amount": {"value": 1170.0, "currency": "BAM"},
                   "params": {"ref": "faktura-77"}},
        "requested_by": "approver",
        "nonce": "n-1",
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}],
    }
    body.update(over)
    return body


class Commitment(unittest.TestCase):
    def test_v2_differs_from_v1_and_from_another_salt(self):
        one = core.intent_commitment(intent())
        a = core.intent_commitment(intent(), "00" * 16)
        b = core.intent_commitment(intent(), "11" * 16)
        self.assertNotEqual(one, a)
        self.assertNotEqual(a, b)
        self.assertEqual(a, core.intent_commitment(intent(), "00" * 16))   # deterministic given salt

    def test_short_salt_is_refused(self):
        with self.assertRaises(MandateError):
            core.intent_commitment(intent(), "00" * 8)

    def test_non_hex_salt_is_refused(self):
        with self.assertRaises(MandateError):
            core.intent_commitment(intent(), "zz" * 16)

    def test_propose_carries_the_salt_and_the_algorithm(self):
        plain = core.propose(intent())
        salted = core.propose(intent(), salted=True)
        self.assertNotIn("commitment_salt", plain)
        self.assertEqual(salted["commitment_alg"], core.COMMITMENT_V2)
        self.assertEqual(len(bytes.fromhex(salted["commitment_salt"])), core.SALT_BYTES)
        self.assertEqual(salted["commitment"],
                         core.intent_commitment(salted["intent"], salted["commitment_salt"]))

    def test_a_grant_that_claims_v2_without_a_salt_is_refused(self):
        granter = {"grant": {"commitment": "sha256:" + "0" * 64,
                             "commitment_alg": core.COMMITMENT_V2,
                             "render_hash": core.render_hash(intent()),
                             "approver": "approver", "nonce": "n-1",
                             "scope": {"max_uses": 1, "not_after": 9999999999}}}
        with self.assertRaises(MandateError):
            core._grant_salt(granter["grant"])


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "k")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate,mandate-mcp" %s\n'
            % pathlib.Path(self.key + ".pub").read_text().strip(), encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")

    def tearDown(self):
        self.td.cleanup()

    def _grant(self, salted: bool) -> dict:
        proposal = core.propose(intent(), salted=salted)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", render_hash=proposal["render_hash"],
            agent="agent@example", commitment_alg=proposal.get("commitment_alg", ""),
            commitment_salt=proposal.get("commitment_salt", ""))
        return core.make_grant(grant_core, self.key)

    def test_salted_grant_redeems(self):
        receipt = core.redeem(intent(), self._grant(True), self.signers, self.ledger)
        self.assertEqual(receipt["body"]["type"], "receipt")
        self.assertEqual(receipt["body"]["commitment"],
                         core.intent_commitment(intent(), core._grant_salt(receipt["body"]))
                         if "commitment_salt" in receipt["body"]
                         else receipt["body"]["commitment"])

    def test_v1_grant_still_redeems(self):
        receipt = core.redeem(intent(), self._grant(False), self.signers, self.ledger)
        self.assertEqual(receipt["body"]["type"], "receipt")

    def test_a_changed_amount_fails_on_the_salted_scheme(self):
        grant = self._grant(True)
        changed = intent(effect={"kind": "payment.send", "target": "Example Supplier",
                                 "amount": {"value": 1171.0, "currency": "BAM"},
                                 "params": {"ref": "faktura-77"}})
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(changed, grant, self.signers, self.ledger)

    def test_the_receipt_verifies_with_the_salted_commitment(self):
        grant = self._grant(True)
        receipt = core.redeem(intent(), grant, self.signers, self.ledger)
        self.assertTrue(core.verify_receipt(receipt, intent(), grant, self.signers))

    def test_cli_propose_salted(self):
        path = os.path.join(self.dir, "intent.json")
        pathlib.Path(path).write_text(json.dumps(intent()), encoding="utf-8")
        done = subprocess.run([sys.executable, "-m", "mandate", "propose", "--intent", path,
                               "--salted"], cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        payload = json.loads(done.stdout)
        self.assertEqual(payload["commitment_alg"], core.COMMITMENT_V2)
        self.assertIn("commitment_salt", payload)


if __name__ == "__main__":
    unittest.main()
