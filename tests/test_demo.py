"""`mandate demo` must prove the four things it claims, on a fresh directory."""
from __future__ import annotations

import tempfile
import unittest

from mandate import demo


class Demo(unittest.TestCase):
    def test_the_demo_passes_every_step(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = demo.run(td)
        self.assertTrue(result["ok"], result)
        steps = {s["step"]: s for s in result["steps"]}
        self.assertEqual(steps["policy"]["decision"], "ask")
        self.assertEqual(steps["redeem"]["decision"], "executed")
        self.assertIn("refused", steps["replay"]["result"])
        self.assertEqual(steps["changed_amount"]["result"], "CommitmentMismatch")
        self.assertTrue(steps["verify"]["ok"])
        self.assertTrue(steps["verify"]["chain"])
        self.assertGreaterEqual(steps["pack"]["files"], 3)

    def test_the_demo_writes_its_result(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            demo.run(td)
            self.assertTrue(__import__("os").path.exists(td + "/demo.json"))


if __name__ == "__main__":
    unittest.main()
