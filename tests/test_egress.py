"""Egress control: deny by default, authenticate, record every decision."""
from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import tempfile
import threading
import time
import unittest

from mandate import egress


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Origin(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        body = b"origin-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_origin() -> tuple[socketserver.TCPServer, int]:
    port = free_port()
    server = socketserver.TCPServer(("127.0.0.1", port), Origin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def start_proxy(policy: dict, ledger: str | None) -> tuple[egress.ProxyServer, int]:
    port = free_port()
    server = egress.serve(policy, "127.0.0.1", port, ledger)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def request_via_proxy(proxy_port: int, target: str, token: str | None) -> int:
    req = [f"GET {target} HTTP/1.1", f"Host: {target.split('//')[-1].split('/')[0]}"]
    if token:
        req.append(f"Proxy-Authorization: Bearer {token}")
    payload = ("\r\n".join(req) + "\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as s:
        s.sendall(payload)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(1024)
            if not chunk:
                break
            head += chunk
    return int(head.split(b" ")[1])


class Decisions(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = {"version": 1, "default": "deny", "allow": ["127.0.0.1:9"],
                       "token_env": "MANDATE_EGRESS_TOKEN"}

    def test_allowlisted_host(self) -> None:
        v = egress.decide(self.policy, "127.0.0.1", 9)
        self.assertTrue(v["allow"])
        self.assertEqual(v["code"], "allowlist_host")

    def test_not_allowlisted_external(self) -> None:
        v = egress.decide(self.policy, "pypi.org", 443)
        self.assertFalse(v["allow"])
        self.assertEqual(v["code"], "not_allowlisted")

    def test_metadata_endpoint_refused_even_if_private(self) -> None:
        v = egress.decide(self.policy, "169.254.169.254", 80)
        self.assertFalse(v["allow"])
        self.assertEqual(v["code"], "metadata_endpoint")

    def test_private_destination_refused(self) -> None:
        v = egress.decide(self.policy, "127.0.0.1", 22)
        self.assertFalse(v["allow"])
        self.assertIn(v["code"], ("private_destination", "not_allowlisted"))

    def test_dns_failure_is_denied(self) -> None:
        v = egress.decide(self.policy, "no-such-host.invalid", 443)
        self.assertFalse(v["allow"])
        self.assertEqual(v["code"], "dns_failure")


class Proxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.origin, cls.origin_port = start_origin()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ledger = os.path.join(cls.tmp.name, "egress.jsonl")
        cls.policy = {"version": 1, "default": "deny",
                      "allow": [f"127.0.0.1:{cls.origin_port}"],
                      "token_env": "MANDATE_EGRESS_TOKEN"}
        cls.proxy, cls.proxy_port = start_proxy(cls.policy, cls.ledger)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.shutdown()
        cls.proxy.server_close()
        cls.origin.shutdown()
        cls.origin.server_close()
        cls.tmp.cleanup()

    def setUp(self) -> None:
        os.environ["MANDATE_EGRESS_TOKEN"] = "test-token"

    def test_allowed_request(self) -> None:
        code = request_via_proxy(self.proxy_port,
                                 f"http://127.0.0.1:{self.origin_port}/x", "test-token")
        self.assertEqual(code, 200)

    def test_missing_token_is_407(self) -> None:
        code = request_via_proxy(self.proxy_port,
                                 f"http://127.0.0.1:{self.origin_port}/x", None)
        self.assertEqual(code, 407)

    def test_wrong_token_is_407(self) -> None:
        code = request_via_proxy(self.proxy_port,
                                 f"http://127.0.0.1:{self.origin_port}/x", "nope")
        self.assertEqual(code, 407)

    def test_unlisted_destination_is_403(self) -> None:
        code = request_via_proxy(self.proxy_port, "http://127.0.0.1:9/x", "test-token")
        self.assertEqual(code, 403)

    def test_decisions_are_recorded(self) -> None:
        request_via_proxy(self.proxy_port,
                          f"http://127.0.0.1:{self.origin_port}/recorded", "test-token")
        request_via_proxy(self.proxy_port, "http://127.0.0.1:9/blocked", "test-token")
        time.sleep(0.05)
        summary = egress.summary(self.ledger)
        self.assertGreaterEqual(summary["records"], 2)
        self.assertIn("allow:allowlist_host", summary["by_code"])
        self.assertTrue(any(k.startswith("deny:") for k in summary["by_code"]))
        for line in open(self.ledger):
            body = json.loads(line)["body"]
            self.assertEqual(body["type"], "control")
            self.assertEqual(body["action"], "egress")


if __name__ == "__main__":
    unittest.main()
