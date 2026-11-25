"""Grant-nonce store that can be shared across hosts.

One host is easy: SQLite next to the ledger. Several hosts redeeming against the
same grant need one authority, otherwise each host's local file says "unused" and
the grant is spent twice. Two deployments, no dependencies:

  local (default)   SQLite in the deployment directory
  shared            one `mandate nonce serve` instance, reached over HTTP

Failing to reach the shared store is a refusal, not a pass: an unreachable
authority must not turn into a double spend.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_ENV = "MANDATE_NONCE_DB"
URL_ENV = "MANDATE_NONCE_URL"
TOKEN_ENV = "MANDATE_NONCE_TOKEN"


class NonceUnavailable(RuntimeError):
    """The shared authority could not answer; callers must fail closed."""


def _db_path(ledger_path: str | None) -> str:
    if os.environ.get(DB_ENV):
        return os.environ[DB_ENV]
    if ledger_path:
        return os.path.join(os.path.dirname(os.path.abspath(ledger_path)),
                            ".mandate-nonces.sqlite")
    return os.path.expanduser("~/.mandate/nonces.sqlite")


def claim_local(nonce: str, ledger_path: str | None = None) -> bool:
    path = _db_path(ledger_path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    con = sqlite3.connect(path, timeout=10)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS used (nonce TEXT PRIMARY KEY, ts REAL)")
        cur = con.execute("INSERT OR IGNORE INTO used (nonce, ts) VALUES (?, ?)",
                          (str(nonce), time.time()))
        con.commit()
        return cur.rowcount == 1
    finally:
        con.close()


def claim_remote(nonce: str) -> bool:
    from .net import require_http
    url = require_http(os.environ.get(URL_ENV, "").rstrip("/"),
                       "MANDATE_NONCE_URL").rstrip("/")
    token = os.environ.get(TOKEN_ENV, "")
    body = json.dumps({"nonce": str(nonce)}).encode()
    req = urllib.request.Request(url + "/claim", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode() or "{}")
            return bool(data.get("claimed"))
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return False
        raise NonceUnavailable("nonce store refused: HTTP %s" % exc.code) from exc
    except (OSError, ValueError) as exc:
        raise NonceUnavailable("nonce store unreachable: %s" % str(exc)[:120]) from exc


def claim(nonce: str, ledger_path: str | None = None) -> bool:
    """True if this nonce is now claimed. Raises NonceUnavailable if it cannot tell."""
    if os.environ.get(URL_ENV):
        return claim_remote(nonce)
    return claim_local(nonce, ledger_path)


class _Handler(BaseHTTPRequestHandler):
    server_version = "mandate-nonce/1"

    def _auth_ok(self) -> bool:
        token = getattr(self.server, "token", "")
        if not token:
            return True
        return self.headers.get("Authorization", "") == "Bearer " + token

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True, "backend": "sqlite",
                                    "db": getattr(self.server, "db_path", "")})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/claim":
            return self._json(404, {"error": "not found"})
        if not self._auth_ok():
            return self._json(401, {"error": "unauthorized"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json(400, {"error": "invalid json"})
        nonce = str(payload.get("nonce") or "")
        if not nonce:
            return self._json(400, {"error": "nonce required"})
        with self.server.lock:  # type: ignore[attr-defined]
            ok = claim_local(nonce, getattr(self.server, "db_path", None))
        self._json(200 if ok else 409, {"claimed": ok, "nonce": nonce})

    def log_message(self, *args):  # keep the cron log quiet
        pass


def serve(host: str = "127.0.0.1", port: int = 8899, db_path: str | None = None,
          token: str = "") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.db_path = db_path or os.path.expanduser("~/.mandate/nonces.sqlite")  # type: ignore[attr-defined]
    server.token = token  # type: ignore[attr-defined]
    server.lock = threading.Lock()  # type: ignore[attr-defined]
    os.makedirs(os.path.dirname(server.db_path), exist_ok=True)  # type: ignore[attr-defined]
    return server
