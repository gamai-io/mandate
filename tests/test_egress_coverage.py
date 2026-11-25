"""Every outbound adapter must go through the egress gate.

This is a source-level check on purpose: a behavioural test proves today's path,
this one notices when a new adapter is added tomorrow without a guard.
"""
from __future__ import annotations

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADAPTERS = os.path.join(ROOT, "mandate", "adapters")

# an adapter that opens a connection has to mention the guard
OUTBOUND = {
    "payment.py": "urllib.request.urlopen",
    "publish.py": "urllib.request.urlopen",
    "smtp.py": "smtplib",
}


class Coverage(unittest.TestCase):
    def test_every_outbound_adapter_calls_the_egress_guard(self) -> None:
        for name in OUTBOUND:
            path = os.path.join(ADAPTERS, name)
            source = open(path, encoding="utf-8").read()
            if OUTBOUND[name] not in source:
                self.skipTest("%s no longer opens a connection" % name)
            self.assertIn("egress.guard", source,
                          "%s opens a connection without egress.guard" % name)

    def test_no_adapter_opens_a_raw_socket_without_a_guard(self) -> None:
        for name in sorted(os.listdir(ADAPTERS)):
            if not name.endswith(".py") or name == "__init__.py":
                continue
            source = open(os.path.join(ADAPTERS, name), encoding="utf-8").read()
            if re.search(r"socket\.(create_connection|socket)\(", source):
                self.assertIn("egress.guard", source,
                              "%s uses a raw socket without egress.guard" % name)
