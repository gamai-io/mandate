"""Outbound URLs are http(s) with a host, or they are refused."""
from __future__ import annotations

import unittest

from mandate.core import MandateError
from mandate.net import require_http


class RequireHttp(unittest.TestCase):
    def test_https_is_allowed(self) -> None:
        self.assertEqual(require_http("https://bank.example/api"), "https://bank.example/api")

    def test_local_http_is_allowed_for_loopback_brokers(self) -> None:
        self.assertEqual(require_http("http://127.0.0.1:8899"), "http://127.0.0.1:8899")

    def test_file_scheme_is_refused(self) -> None:
        with self.assertRaises(MandateError):
            require_http("file:///etc/passwd", "payment provider url")

    def test_a_bare_path_is_refused(self) -> None:
        with self.assertRaises(MandateError):
            require_http("/etc/passwd")

    def test_a_url_without_a_host_is_refused(self) -> None:
        with self.assertRaises(MandateError):
            require_http("http:///nohost")


if __name__ == "__main__":
    unittest.main()
