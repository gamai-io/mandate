"""Shared (cross-host) nonce store: one authority, fail closed."""
from __future__ import annotations

import os
import tempfile
import threading
import unittest

from mandate import nonce


class SharedStore(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "nonces.sqlite")
        self.server = nonce.serve("127.0.0.1", 0, self.db, token="s3cret")
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.env = {"MANDATE_NONCE_URL": f"http://127.0.0.1:{self.port}",
                    "MANDATE_NONCE_TOKEN": "s3cret"}
        self._saved = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_second_claim_from_another_host_is_refused(self) -> None:
        a = os.path.join(self.tmp.name, "host-a", "ledger.jsonl")
        b = os.path.join(self.tmp.name, "host-b", "ledger.jsonl")
        os.makedirs(os.path.dirname(a))
        os.makedirs(os.path.dirname(b))
        self.assertTrue(nonce.claim("g-1", a))
        self.assertFalse(nonce.claim("g-1", b),
                         "a second host must not spend the same grant")

    def test_health_endpoint(self) -> None:
        import json
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=5) as r:
            body = json.loads(r.read())
        self.assertTrue(body["ok"])
        self.assertEqual(body["backend"], "sqlite")


class FailClosed(unittest.TestCase):
    def test_unreachable_store_raises(self) -> None:
        saved = os.environ.get("MANDATE_NONCE_URL")
        os.environ["MANDATE_NONCE_URL"] = "http://127.0.0.1:9"
        try:
            with self.assertRaises(nonce.NonceUnavailable):
                nonce.claim("g-2")
        finally:
            if saved is None:
                os.environ.pop("MANDATE_NONCE_URL", None)
            else:
                os.environ["MANDATE_NONCE_URL"] = saved

    def test_wrong_token_raises(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        server = nonce.serve("127.0.0.1", 0, os.path.join(tmp.name, "n.sqlite"), token="right")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        saved = {k: os.environ.get(k) for k in ("MANDATE_NONCE_URL", "MANDATE_NONCE_TOKEN")}
        os.environ["MANDATE_NONCE_URL"] = f"http://127.0.0.1:{server.server_address[1]}"
        os.environ["MANDATE_NONCE_TOKEN"] = "wrong"
        try:
            with self.assertRaises(nonce.NonceUnavailable):
                nonce.claim("g-3")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            server.shutdown()
            server.server_close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
