"""Nothing leaves the broker unless the egress policy names the destination."""
from __future__ import annotations

import unittest

from mandate import egress
from mandate.adapters.payment import PaymentAdapter, PaymentError
from mandate.adapters.publish import Publisher, PublishError


class Guard(unittest.TestCase):
    def test_a_loopback_destination_needs_an_explicit_entry(self) -> None:
        policy = {"version": 1, "default": "deny", "allow": []}
        with self.assertRaises(ValueError):
            egress.guard("http://127.0.0.1:9/", policy, "test")

    def test_an_allowlisted_ip_and_port_passes(self) -> None:
        policy = {"version": 1, "default": "deny", "allow": ["127.0.0.1:9"]}
        self.assertTrue(egress.guard("http://127.0.0.1:9/", policy)["allow"])

    def test_the_wrong_port_is_not_allowlisted(self) -> None:
        policy = {"version": 1, "default": "deny", "allow": ["127.0.0.1:9"]}
        with self.assertRaises(ValueError):
            egress.guard("http://127.0.0.1:10/", policy)

    def test_a_metadata_address_is_refused_even_when_named(self) -> None:
        policy = {"version": 1, "default": "deny",
                  "allow": ["169.254.169.254:80"]}
        with self.assertRaises(ValueError) as caught:
            egress.guard("http://169.254.169.254/latest/meta-data/", policy)
        self.assertIn("denied", str(caught.exception))


class Adapters(unittest.TestCase):
    def test_the_publisher_refuses_a_destination_outside_the_policy(self) -> None:
        publisher = Publisher({"url": "http://127.0.0.1:9",
                               "egress": {"version": 1, "default": "deny",
                                          "allow": []}})
        with self.assertRaises(PublishError):
            publisher.lookup("k")

    def test_the_payment_adapter_refuses_too(self) -> None:
        adapter = PaymentAdapter({"provider": "http", "url": "http://127.0.0.1:9",
                                  "egress": {"version": 1, "default": "deny",
                                             "allow": []}})
        with self.assertRaises(PaymentError):
            adapter.recover("k")

    def test_without_a_policy_the_adapter_behaves_as_before(self) -> None:
        publisher = Publisher({"url": "http://127.0.0.1:9"})
        with self.assertRaises(PublishError):        # connection refused, not egress
            publisher.lookup("k")


if __name__ == "__main__":
    unittest.main()
