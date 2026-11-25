"""The sandbox claim must be a result, not a setting."""
from __future__ import annotations

import shutil
import unittest

from mandate import sandbox


class Probe(unittest.TestCase):
    def test_the_probe_reports_every_tier_and_proves_the_network_one(self) -> None:
        result = sandbox.probe()
        for key in ("bwrap", "docker", "kvm", "network_isolated"):
            self.assertIn(key, result)
        if shutil.which("bwrap"):
            self.assertTrue(result["network_isolated"],
                            "bwrap is installed but egress was not isolated: %s"
                            % result.get("detail"))

    def test_without_bwrap_the_claim_is_not_made(self) -> None:
        if shutil.which("bwrap"):
            self.skipTest("bwrap is installed here")
        self.assertIsNone(sandbox.probe()["network_isolated"])


if __name__ == "__main__":
    unittest.main()
