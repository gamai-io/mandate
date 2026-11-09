"""Approver daemon: the human's separate signer host.

The agent sends an intent; the daemon recomputes the commitment and render
itself, shows it on the approver's terminal, and signs a grant only after the
human confirms. The private key never leaves this host.
"""
from __future__ import annotations

import hmac
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import core

MAX_BODY = 256 * 1024


class ApproverError(core.MandateError):
    pass


class ApprovalRejected(ApproverError):
    pass


class NoTTY(ApproverError):
    pass


def tty_confirm(summary: str, commitment: str, agent: str,
                audience: str) -> bool:
    if not sys.stdin.isatty():
        raise NoTTY("approver has no TTY; refusing to auto-approve")
    print("\n=== MANDATE APPROVAL REQUEST ===", file=sys.stderr)
    print("effect:     " + summary, file=sys.stderr)
    print("agent:      " + (agent or "-"), file=sys.stderr)
    print("broker:     " + (audience or "(unbound)"), file=sys.stderr)
    print("commitment: " + commitment, file=sys.stderr)
    print("Approve? [y/N] ", end="", file=sys.stderr, flush=True)
    answer = sys.stdin.readline().strip().lower()
    return answer in ("y", "yes", "da", "d")


class Approver:
    def __init__(self, key_path: str, approver_name: str,
                 audience_default: str = "", ttl_default: int = 900,
                 confirm=None):
        self.key_path = key_path
        self.approver_name = approver_name
        self.audience_default = audience_default
        self.ttl_default = int(ttl_default)
        self.confirm = confirm or tty_confirm
        self._lock = threading.Lock()

    def request(self, intent: dict, audience: str | None = None,
                ttl: int | None = None) -> dict:
        with self._lock:
            intent = core.normalize_intent(intent)
            proposal = core.propose(intent)
            agent = str(intent["actor"].get("agent") or "")
            bound_audience = str(
                audience if audience is not None else self.audience_default or "")
            ttl_s = min(max(int(ttl if ttl is not None else self.ttl_default), 30),
                        3600)
            approved = self.confirm(proposal["render"]["summary"],
                                    proposal["commitment"], agent,
                                    bound_audience)
            if not approved:
                raise ApprovalRejected("approver rejected the request")
            grant_core = core.build_grant_core(
                proposal["commitment"], self.approver_name, ttl_s=ttl_s,
                render_hash=proposal["render_hash"], agent=agent,
                audience=bound_audience)
            grant = core.make_grant(grant_core, self.key_path)
            return {
                "ok": True,
                "grant": grant,
                "intent": intent,
                "commitment": proposal["commitment"],
                "render_hash": proposal["render_hash"],
                "render": proposal["render"],
                "agent": agent,
                "audience": bound_audience,
            }

    def status(self) -> dict:
        return {"ok": True, "service": "mandate-approver",
                "approver": self.approver_name,
                "key_present": bool(self.key_path and os.path.exists(self.key_path)),
                "audience_default": self.audience_default}


def make_handler(approver: Approver, token: str = ""):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "mandate-approver/0.1"

        def log_message(self, fmt, *args):
            if os.environ.get("MANDATE_APPROVER_LOG") == "1":
                super().log_message(fmt, *args)

        def _send(self, code: int, obj: dict):
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            if not token:
                return True
            header = self.headers.get("Authorization", "")
            return (header.lower().startswith("bearer ")
                    and hmac.compare_digest(header[7:].strip(), token))

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path == "/health":
                self._send(200, approver.status())
                return
            self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path != "/request":
                self._send(404, {"error": "not found"})
                return
            if not self._authorized():
                self._send(401, {"ok": False, "error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length < 0 or length > MAX_BODY:
                    self.close_connection = True
                    self._send(413, {"ok": False, "error": "payload_too_large"})
                    return
                body = json.loads((self.rfile.read(length) if length else b"{}")
                                  .decode("utf-8"))
                result = approver.request(body.get("intent") or {},
                                          audience=body.get("audience"),
                                          ttl=body.get("ttl"))
                self._send(200, result)
            except NoTTY as exc:
                self._send(503, {"ok": False, "error": type(exc).__name__,
                                 "message": str(exc)})
            except ApprovalRejected as exc:
                self._send(403, {"ok": False, "error": type(exc).__name__,
                                 "message": str(exc)})
            except core.MandateError as exc:
                self._send(409, {"ok": False, "error": type(exc).__name__,
                                 "message": str(exc)})
            except (ValueError, TypeError) as exc:
                self._send(400, {"ok": False, "error": "bad_request",
                                 "message": str(exc)[:200]})

    return Handler


def make_server(host: str, port: int, approver: Approver,
                token: str = "") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, int(port)),
                                 make_handler(approver, token))
    server.daemon_threads = True
    server.approver = approver
    return server
