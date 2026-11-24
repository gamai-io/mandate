"""Audit reporting: inventory, signed change records, and the evidence pack."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest

from mandate import report
from mandate.core import append_receipt


def receipt(path: str, agent: str, approver: str, kind: str = "payment.send",
            amount: float = 100.0, ts: float | None = None) -> None:
    append_receipt(path, {
        "v": 1, "type": "receipt", "agent": agent, "approver": approver,
        "ts": time.time() if ts is None else ts, "grant_nonce": f"n-{time.time_ns()}",
        "render": {"fields": {"kind": kind, "amount": {"value": amount,
                                                      "currency": "BAM"}}},
    })


class Inventory(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_one_row_per_agent_with_counts(self) -> None:
        now = time.time()
        receipt(self.ledger, "bank-agent", "renato", amount=50, ts=now - 60)
        receipt(self.ledger, "bank-agent", "renato", amount=70, ts=now)
        receipt(self.ledger, "other-agent", "ops", kind="order.create", ts=now)
        inv = report.inventory(self.ledger, owners={"bank-agent": "ops-team"})
        self.assertEqual(inv["count"], 2)
        row = {a["agent"]: a for a in inv["agents"]}["bank-agent"]
        self.assertEqual(row["effects"], 2)
        self.assertEqual(row["amount_total"], 120.0)
        self.assertEqual(row["owner"], "ops-team")
        self.assertEqual(row["approvers"], ["renato"])
        self.assertLess(row["first_seen"], row["last_seen"])

    def test_scopes_come_from_tokens(self) -> None:
        receipt(self.ledger, "bank-agent", "renato")
        token = {"payload": {"sub": "bank-agent", "scopes": ["payment.send"]}}
        inv = report.inventory(self.ledger, tokens=[token])
        self.assertEqual(inv["agents"][0]["scopes"], ["payment.send"])

    def test_csv_has_a_header_and_rows(self) -> None:
        receipt(self.ledger, "bank-agent", "renato")
        inv = report.inventory(self.ledger)
        path = os.path.join(self.tmp.name, "inv.csv")
        report.write_inventory_csv(inv, path)
        lines = open(path).read().strip().splitlines()
        self.assertTrue(lines[0].startswith("agent,owner,effects"))
        self.assertEqual(len(lines), 2)


class ChangeControl(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")
        self.policy = os.path.join(self.tmp.name, "policy.json")
        open(self.policy, "w").write('{"version": 1, "default": "deny"}')
        self.key = os.path.join(self.tmp.name, "ops_key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", self.key,
                        "-C", "ops", "-N", ""], check=True)
        self.signers = os.path.join(self.tmp.name, "allowed_signers")
        open(self.signers, "w").write(
            f'ops namespaces="mandate" {open(self.key + ".pub").read().strip()}\n')

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_record_is_signed_and_verified(self) -> None:
        res = report.change_record(self.ledger, self.policy, "ops", self.key, "raise limit")
        self.assertEqual(res["file"], "policy.json")
        out = report.changes(self.ledger, self.signers)
        self.assertEqual(out["count"], 1)
        self.assertTrue(out["changes"][0]["signature_valid"])
        self.assertEqual(out["changes"][0]["sha256"],
                         hashlib.sha256(open(self.policy, "rb").read()).hexdigest())

    def test_tampered_record_is_detected(self) -> None:
        report.change_record(self.ledger, self.policy, "ops", self.key, "raise limit")
        lines = open(self.ledger).read().splitlines()
        entry = json.loads(lines[-1])
        entry["body"]["reason"] = "something else"
        lines[-1] = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        open(self.ledger, "w").write("\n".join(lines) + "\n")
        out = report.changes(self.ledger, self.signers)
        self.assertFalse(out["changes"][0]["signature_valid"])

    def test_change_lands_in_the_chain(self) -> None:
        from mandate.core import verify_chain
        report.change_record(self.ledger, self.policy, "ops", self.key, "x")
        self.assertTrue(verify_chain(self.ledger))


class Pack(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")
        receipt(self.ledger, "bank-agent", "renato")
        self.out = os.path.join(self.tmp.name, "pack")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pack_contents_and_hashes(self) -> None:
        res = report.pack(self.ledger, self.out)
        for name in ("inventory.json", "inventory.csv", "changes.json",
                     "dora_roi.json", "index.json"):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)
        index = json.load(open(res["index"]))
        self.assertEqual(index["agents"], 1)
        self.assertTrue(index["ledger_head"])
        for name, meta in index["files"].items():
            full = os.path.join(self.out, name)
            self.assertEqual(meta["sha256"],
                             hashlib.sha256(open(full, "rb").read()).hexdigest())

    def test_dora_row_has_the_required_fields(self) -> None:
        report.pack(self.ledger, self.out)
        roi = json.load(open(os.path.join(self.out, "dora_roi.json")))
        for key in ("service", "provider", "data_location", "subcontracting",
                    "exit_plan", "audit_rights"):
            self.assertIn(key, roi)


if __name__ == "__main__":
    unittest.main()
