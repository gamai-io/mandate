import json
import os
import pathlib
import unittest

from mandate import benchmark, core

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "bench" / "scenarios" / "idb_v0.jsonl"


class BenchmarkTests(unittest.TestCase):
    def test_repo_scenarios_pass(self):
        scenarios = benchmark.load_scenarios(str(SCENARIOS))
        self.assertGreater(len(scenarios), 5)
        report = benchmark.run(scenarios, core.load_policy())
        self.assertEqual(report["metrics"]["failed"], 0,
                         [row for row in report["results"] if not row["ok"]])
        self.assertEqual(report["metrics"]["false_allow"], 0)
        self.assertEqual(report["metrics"]["pi_asr"], 0.0)
        self.assertIn("prompt_injection", report["metrics"]["by_category"])
        self.assertIn("benign", report["metrics"]["by_category"])

    def test_false_allow_is_detected(self):
        scenario = {
            "id": "bad-expectation",
            "category": "test",
            "expected": "block",
            "intent": {
                "v": 1,
                "actor": {"agent": "agent@example"},
                "effect": {"kind": "read.lookup", "target": "customers"},
                "requested_by": "approver",
                "nonce": "x-1",
                "provenance": [],
            },
        }
        report = benchmark.run([scenario], core.load_policy())
        self.assertEqual(report["metrics"]["failed"], 1)
        self.assertEqual(report["metrics"]["false_allow"], 1)

    def test_invalid_scenario_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"id": "x"}) + "\n")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.load_scenarios(path)


if __name__ == "__main__":
    unittest.main()
