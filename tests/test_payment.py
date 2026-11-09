import os
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

from mandate import broker, core
from mandate.adapters.erp import ErpChecker
from mandate.adapters.payment import PaymentAdapter, SandboxProvider

ROOT = pathlib.Path(__file__).resolve().parents[1]


def intent_factory(**over):
    intent = {
        "v": 1,
        "actor": {"agent": "agent@example", "session": "s1"},
        "effect": {
            "kind": "payment.send",
            "target": "Example Supplier",
            "amount": {"value": 1170.0, "currency": "BAM"},
            "params": {"ref": "faktura-77"},
        },
        "requested_by": "approver",
        "nonce": "n-1",
    }
    intent.update(over)
    return intent


class SandboxPaymentTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.td.name, "payments.sqlite")

    def tearDown(self):
        self.td.cleanup()

    def test_idempotent_charge(self):
        adapter = PaymentAdapter({"provider": "sandbox", "db": self.db})
        intent = intent_factory()
        first = adapter.execute(intent, "nonce-1")
        second = adapter.execute(intent, "nonce-1")
        self.assertTrue(first["ok"])
        self.assertFalse(first["recovered"])
        self.assertTrue(second["recovered"])
        self.assertEqual(first["charge"]["charge_id"],
                         second["charge"]["charge_id"])
        con = sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM charges")
                         .fetchone()[0], 1)
        con.close()

    def test_distinct_keys_create_distinct_charges(self):
        adapter = PaymentAdapter({"provider": "sandbox", "db": self.db})
        one = adapter.execute(intent_factory(), "nonce-1")
        two = adapter.execute(intent_factory(), "nonce-2")
        self.assertNotEqual(one["charge"]["charge_id"],
                            two["charge"]["charge_id"])

    def test_provider_timeout_after_charge_is_recovered(self):
        class AfterCharge(SandboxProvider):
            def charge(self, *args, **kwargs):
                super().charge(*args, **kwargs)
                raise TimeoutError("timeout")

        adapter = PaymentAdapter({"provider": "sandbox", "db": self.db})
        adapter.provider = AfterCharge(self.db)
        result = adapter.execute(intent_factory(), "nonce-1")
        self.assertTrue(result["recovered"])
        self.assertTrue(result["ok"])
        con = sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM charges")
                         .fetchone()[0], 1)
        con.close()


class BrokerPaymentTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.payment_db = os.path.join(self.dir, "payments.sqlite")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")

    def tearDown(self):
        self.td.cleanup()

    def _grant(self, intent):
        proposal = core.propose(intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=900,
            render_hash=proposal["render_hash"],
            agent=str(intent["actor"]["agent"]), audience="gama-broker")
        return core.make_grant(grant_core, self.key)

    def _broker(self):
        return broker.Broker(
            os.path.join(ROOT, "policy.json"), self.signers, self.ledger,
            os.path.join(self.dir, "used.sqlite"),
            journal_db=os.path.join(self.dir, "journal.sqlite"),
            effects_dir=os.path.join(self.dir, "effects"),
            payment={"provider": "sandbox", "db": self.payment_db},
            lease_s=0, recover_on_start=False)

    def _charge_count(self):
        con = sqlite3.connect(self.payment_db)
        try:
            return con.execute("SELECT COUNT(*) FROM charges").fetchone()[0]
        finally:
            con.close()

    def test_broker_payment_duplicate_is_receipted_once(self):
        intent = intent_factory()
        grant = self._grant(intent)
        b = self._broker()
        first = b.execute(intent, grant)
        self.assertTrue(first["ok"])
        self.assertEqual(self._charge_count(), 1)
        second = b.execute(intent, grant)
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["receipt"]["hash"], first["receipt"]["hash"])
        self.assertEqual(self._charge_count(), 1)

    def test_recovery_after_charge_before_receipt(self):
        intent = intent_factory()
        grant = self._grant(intent)
        b = self._broker()
        with mock.patch.object(b.journal, "mark_executed",
                               side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                b.execute(intent, grant)
        self.assertEqual(self._charge_count(), 1)
        b2 = self._broker()
        actions = b2.recover()
        self.assertTrue(any(a["action"] == "receipted" for a in actions))
        duplicate = b2.execute(intent, grant)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(self._charge_count(), 1)

    def test_erp_rejects_non_select(self):
        db = os.path.join(self.dir, "erp.sqlite")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE vendors(name TEXT)")
        con.commit()
        con.close()
        erp = ErpChecker({"db": db, "checks": {
            "payment.send": {"query": "DELETE FROM vendors"}}})
        result = erp.check(intent_factory())
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "invalid_query")

    def test_erp_derive_rejects_non_select(self):
        db = os.path.join(self.dir, "erp.sqlite")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE vendors(name TEXT)")
        con.commit()
        con.close()
        erp = ErpChecker({"db": db, "derive": {
            "payment.send": {"query": "UPDATE vendors SET name='x'"}}})
        result = erp.derive_expected(intent_factory())
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "invalid_query")


if __name__ == "__main__":
    unittest.main()
