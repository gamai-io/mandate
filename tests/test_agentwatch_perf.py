"""A single address must not make the window scan quadratic."""
from __future__ import annotations

import time
import unittest

from mandate import agentwatch


class WindowScan(unittest.TestCase):
    def test_50k_requests_on_one_path_finish_quickly(self) -> None:
        base = 1_795_000_000.0
        rows = [{"ts": base + i * 0.01, "ip": "8.8.4.4", "ua": "curl/8.7.1",
                 "method": "GET", "path": "/api/v1/invoices", "status": 401,
                 "auth": "k%d" % (i % 3)} for i in range(50_000)]
        start = time.perf_counter()
        result = agentwatch.analyse(rows, window=10 ** 9, now=base + 600)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 10.0, "quadratic behaviour is back: %.1fs" % elapsed)
        self.assertIn(result["sessions"]["8.8.4.4"]["level"], ("medium", "high"))
        self.assertGreaterEqual(result["sessions"]["8.8.4.4"]["points"], 4)


if __name__ == "__main__":
    unittest.main()
