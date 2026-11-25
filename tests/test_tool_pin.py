"""A tool approval must be an approval of a specific schema, not of a name."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from mandate import core, tools

SCHEMA = {"name": "erp.read", "input": {"type": "object",
                                        "properties": {"invoice": {"type": "string"}}}}


class ToolPin(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.schema = os.path.join(self.dir, "erp-read.json")
        self.registry = os.path.join(self.dir, "tools.json")
        json.dump(SCHEMA, open(self.schema, "w"))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def intent(self, digest: str) -> dict:
        return core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": {"kind": "mcp.call", "target": "invoices",
                       "params": {"tool": "erp.read", "schema_sha256": digest}},
            "requested_by": "ops", "nonce": "n1",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})

    def test_locking_records_the_hash_and_not_the_schema(self) -> None:
        entry = tools.lock("erp.read", self.schema, self.registry)
        stored = json.load(open(self.registry))["tools"]["erp.read"]
        self.assertEqual(stored["sha256"], entry["sha256"])
        self.assertNotIn("properties", json.dumps(stored))

    def test_a_matching_schema_verifies(self) -> None:
        entry = tools.lock("erp.read", self.schema, self.registry)
        result = tools.verify(self.intent(entry["sha256"]), self.registry)
        self.assertTrue(result["ok"], result)

    def test_a_changed_schema_is_drift(self) -> None:
        entry = tools.lock("erp.read", self.schema, self.registry)
        changed = json.loads(json.dumps(SCHEMA))
        changed["input"]["properties"]["transfer_to"] = {"type": "string"}
        json.dump(changed, open(self.schema, "w"))
        result = tools.verify(self.intent(entry["sha256"]), self.registry)
        self.assertFalse(result["ok"])
        self.assertTrue(any("changed since it was locked" in d["reason"]
                            for d in result["drift"]))

    def test_an_approval_for_another_schema_is_drift(self) -> None:
        tools.lock("erp.read", self.schema, self.registry)
        result = tools.verify(self.intent("b" * 64), self.registry)
        self.assertFalse(result["ok"])
        self.assertTrue(any("approval names a different schema" in d["reason"]
                            for d in result["drift"]))

    def test_an_unknown_tool_is_refused(self) -> None:
        item = core.normalize_intent({
            "v": 1, "actor": {"agent": "a", "session": "s"},
            "effect": {"kind": "mcp.call", "target": "x",
                       "params": {"tool": "ghost.tool", "schema_sha256": "a" * 64}},
            "requested_by": "ops", "nonce": "n2",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})
        result = tools.verify(item, self.registry)
        self.assertFalse(result["ok"])
        self.assertIn("not in the tool registry", result["drift"][0]["reason"])

    def test_enforce_raises_a_policy_denial_on_drift(self) -> None:
        entry = tools.lock("erp.read", self.schema, self.registry)
        changed = json.loads(json.dumps(SCHEMA))
        changed["input"]["properties"]["transfer_to"] = {"type": "string"}
        json.dump(changed, open(self.schema, "w"))
        with self.assertRaises(core.PolicyDenied):
            tools.enforce(self.intent(entry["sha256"]), self.registry)

    def test_an_intent_without_a_tool_is_skipped_not_failed(self) -> None:
        item = core.normalize_intent({
            "v": 1, "actor": {"agent": "a", "session": "s"},
            "effect": {"kind": "payment.send", "target": "X",
                       "amount": {"value": 1.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n3",
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})
        self.assertTrue(tools.verify(item, self.registry)["ok"])


if __name__ == "__main__":
    unittest.main()
