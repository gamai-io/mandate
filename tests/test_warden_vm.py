"""Firecracker VM pause: exercised against a stub unix-socket API.

The real Firecracker needs /dev/kvm. This host may not have it, so the client is
tested against a socket that speaks the same two calls (GET /vm, PATCH /vm).
"""
from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import unittest

from mandate import warden


class StubFc(threading.Thread):
    def __init__(self, path: str):
        super().__init__(daemon=True)
        self.path = path
        self.state = "Running"
        self.calls: list[tuple[str, str]] = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)

    def run(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                head, _, body = data.partition(b"\r\n\r\n")
                lines = head.decode("latin-1").split("\r\n")
                method, path, _ = lines[0].split(" ", 2)
                length = 0
                for line in lines[1:]:
                    if line.lower().startswith("content-length:"):
                        length = int(line.split(":")[1])
                if length > len(body):
                    body += conn.recv(length - len(body))
                self.calls.append((method, path))
                if method == "PATCH" and path == "/vm":
                    payload = json.loads(body or b"{}")
                    wanted = payload.get("state", self.state)
                    # real Firecracker reports "Running" after a "Resumed" PATCH
                    self.state = "Running" if wanted == "Resumed" else wanted
                    response = b"HTTP/1.1 204 No Content\r\n\r\n"
                else:
                    payload = json.dumps({"state": self.state}).encode()
                    response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                b"Content-Length: " + str(len(payload)).encode() +
                                b"\r\n\r\n" + payload)
                conn.sendall(response)

    def stop(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class VmPause(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "fc.sock")
        self.stub = StubFc(self.path)
        self.stub.start()

    def tearDown(self) -> None:
        self.stub.stop()
        self.tmp.cleanup()

    def test_pause_is_confirmed_by_state(self) -> None:
        res = warden.vm_pause(self.path)
        self.assertTrue(res["verified"], res)
        self.assertEqual(res["state_before"], "Running")
        self.assertEqual(res["state_after"], "Paused")
        self.assertLess(res["time_to_halt_ms"], 2000)

    def test_resume_returns_to_running(self) -> None:
        warden.vm_pause(self.path)
        res = warden.vm_resume(self.path)
        self.assertTrue(res["verified"], res)
        self.assertEqual(res["state_after"], "Running")

    def test_state_is_readable(self) -> None:
        self.assertEqual(warden.vm_state(self.path), "Running")
        self.assertTrue(any(m == "GET" and p in ("/", "/vm") for m, p in self.stub.calls), self.stub.calls)

    def test_missing_socket_is_reported(self) -> None:
        res = warden.vm_pause(os.path.join(self.tmp.name, "nope.sock"))
        self.assertFalse(res["verified"])


class KvmCheck(unittest.TestCase):
    def test_reports_absence_honestly(self) -> None:
        self.assertEqual(warden.kvm_available("/nonexistent/kvm"), False)


if __name__ == "__main__":
    unittest.main()
