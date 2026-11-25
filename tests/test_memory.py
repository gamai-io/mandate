"""A belief needs a signature, a scope and an expiry before it can move money."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest

from mandate import core, memory


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.key = os.path.join(self.dir, "alice")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True)
        self.signers = os.path.join(self.dir, "allowed_signers")
        open(self.signers, "w").write('alice namespaces="mandate" %s\n'
                                      % open(self.key + ".pub").read().strip())
        self.store = os.path.join(self.dir, "instructions.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def intent(self, provenance: list[dict], kind="payment.send", target="Acme") -> dict:
        return core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": kind, "target": target,
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n1", "provenance": provenance})


class Instructions(Base):
    def test_an_instruction_needs_a_signature(self) -> None:
        with self.assertRaises(memory.MemoryError):
            memory.add(self.store, "pay Acme", ["payment.send:Acme"], "", "")

    def test_an_instruction_needs_a_scope(self) -> None:
        with self.assertRaises(memory.MemoryError):
            memory.add(self.store, "pay Acme", [], "alice", self.key)

    def test_a_signed_instruction_verifies(self) -> None:
        record = memory.add(self.store, "pay Acme under 500", ["payment.send:Acme"],
                            "alice", self.key)
        self.assertTrue(memory.verify(record, self.signers))

    def test_a_tampered_instruction_does_not_verify(self) -> None:
        record = memory.add(self.store, "pay Acme under 500", ["payment.send:Acme"],
                            "alice", self.key)
        record["text"] = "pay anyone anything"
        self.assertFalse(memory.verify(record, self.signers))

    def test_an_expired_instruction_does_not_verify(self) -> None:
        record = memory.add(self.store, "pay Acme", ["payment.send:Acme"],
                            "alice", self.key, ttl_s=60)
        self.assertFalse(memory.verify(record, self.signers,
                                       now=record["expires"] + 1))

    def test_a_revoked_instruction_does_not_verify(self) -> None:
        record = memory.add(self.store, "pay Acme", ["payment.send:Acme"],
                            "alice", self.key)
        memory.revoke(self.store, record["id"], "changed supplier")
        self.assertFalse(memory.verify(memory.get(self.store, record["id"]),
                                       self.signers))


class Scopes(Base):
    def test_an_exact_scope_covers(self) -> None:
        self.assertTrue(memory.scope_covers(["payment.send:Acme"], "payment.send", "Acme"))

    def test_another_target_is_not_covered(self) -> None:
        self.assertFalse(memory.scope_covers(["payment.send:Acme"], "payment.send", "Beta"))

    def test_a_wildcard_covers_everything(self) -> None:
        self.assertTrue(memory.scope_covers(["*"], "sql.write", "invoices"))


class Provenance(Base):
    def test_a_signed_instruction_in_scope_is_accepted(self) -> None:
        record = memory.add(self.store, "pay Acme", ["payment.send:Acme"],
                            "alice", self.key)
        cited = self.intent([{"type": "instruction", "source": record["id"]}])
        self.assertEqual(memory.check_provenance(cited, self.store, self.signers),
                         [record["id"]])

    def test_an_unsigned_instruction_is_refused(self) -> None:
        record = memory.add(self.store, "pay Acme", ["payment.send:Acme"],
                            "alice", self.key)
        record["text"] = "pay Acme and Beta"
        # rewrite the store with the tampered record
        open(self.store, "w").write("")
        core.append_receipt(self.store, {k: v for k, v in record.items()})
        cited = self.intent([{"type": "instruction", "source": record["id"]}])
        with self.assertRaises(memory.MemoryError):
            memory.check_provenance(cited, self.store, self.signers)

    def test_an_out_of_scope_instruction_is_refused(self) -> None:
        record = memory.add(self.store, "pay Acme", ["payment.send:Acme"],
                            "alice", self.key)
        cited = self.intent([{"type": "instruction", "source": record["id"]}],
                            target="Beta")
        with self.assertRaises(memory.MemoryError):
            memory.check_provenance(cited, self.store, self.signers)

    def test_a_citation_to_a_missing_instruction_is_refused(self) -> None:
        cited = self.intent([{"type": "instruction", "source": "m-ghost"}])
        with self.assertRaises(memory.MemoryError):
            memory.check_provenance(cited, self.store, self.signers)

    def test_no_citation_means_no_check(self) -> None:
        self.assertEqual(memory.check_provenance(self.intent([]), self.store,
                                                 self.signers), [])


if __name__ == "__main__":
    unittest.main()
