"""Off-host STH witness for the Mandate transparency log.

The witness stores only the latest signed tree head (STH) it has accepted and
refuses rollback or split-view. Growth requires a valid consistency proof from
the pinned root to the new root.
"""
from __future__ import annotations

import hmac
import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import core
from . import log as mlog

_LOCK = threading.Lock()
MAX_BODY = 256 * 1024


class WitnessError(core.MandateError):
    pass


def load_state(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise WitnessError("witness state unreadable") from exc
    if not isinstance(state, dict) or not state.get("root_hash"):
        raise WitnessError("witness state invalid")
    return state


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(core.jcs(state))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def accept(sth: dict, proof: dict | None, signers_path: str, state_path: str,
           revoked_path: str | None = None, dry_run: bool = False) -> dict:
    with _LOCK:
        return _accept(sth, proof, signers_path, state_path, revoked_path,
                       dry_run)


def _accept(sth: dict, proof: dict | None, signers_path: str, state_path: str,
            revoked_path: str | None = None, dry_run: bool = False) -> dict:
    if not mlog.verify_sth(sth, signers_path, revoked_path=revoked_path):
        raise WitnessError("STH signature invalid")
    payload = (sth or {}).get("sth") or {}
    try:
        log_name = str(payload["log_name"])
        log_id = str(payload["log_id"])
        size = int(payload["tree_size"])
        root = str(payload["root_hash"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WitnessError("STH payload invalid") from exc
    state = load_state(state_path)
    if state is None:
        new_state = {"v": 1, "log_name": log_name, "log_id": log_id,
                     "tree_size": size, "root_hash": root, "sth": sth,
                     "pinned_at": int(time.time() * 1000)}
        if not dry_run:
            save_state(state_path, new_state)
        return {"ok": True, "first": True, "state": new_state}
    if state.get("log_id") != log_id or state.get("log_name") != log_name:
        raise WitnessError("log identity mismatch")
    old_size = int(state["tree_size"])
    old_root = str(state["root_hash"])
    if size < old_size:
        raise WitnessError("rollback rejected (new tree is smaller)")
    if size == old_size:
        if root != old_root:
            raise WitnessError("split-view rejected (same size, different root)")
        return {"ok": True, "unchanged": True, "state": state}
    if not proof:
        raise WitnessError("consistency proof required for growth")
    try:
        proof_first = int(proof["first_size"])
        proof_second = int(proof["second_size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WitnessError("consistency proof invalid") from exc
    if proof_first != old_size or proof_second != size:
        raise WitnessError("consistency proof range mismatch")
    if not mlog.verify_consistency_proof(
            proof, first_root=old_root, second_root=root,
            first=old_size, second=size):
        raise WitnessError("consistency proof invalid")
    new_state = {"v": 1, "log_name": log_name, "log_id": log_id,
                 "tree_size": size, "root_hash": root, "sth": sth,
                 "pinned_at": int(time.time() * 1000)}
    if not dry_run:
        save_state(state_path, new_state)
    return {"ok": True, "advanced": True, "from": old_size, "to": size,
            "state": new_state}


def make_handler(state_path: str, signers_path: str, token: str,
                 revoked_path: str | None = None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "mandate-witness/0.1"

        def log_message(self, fmt, *args):
            if os.environ.get("MANDATE_WITNESS_LOG") == "1":
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
            header = self.headers.get("Authorization", "")
            if not header.lower().startswith("bearer "):
                return False
            return hmac.compare_digest(header[7:].strip(), token)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path == "/health":
                self._send(200, {"ok": True, "service": "mandate-witness"})
                return
            if path == "/state":
                if not self._authorized():
                    self._send(401, {"ok": False, "error": "unauthorized"})
                    return
                state = load_state(state_path)
                if state is None:
                    self._send(404, {"ok": False, "error": "empty"})
                    return
                self._send(200, {"ok": True, "state": state})
                return
            self._send(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path != "/sth":
                self._send(404, {"ok": False, "error": "not found"})
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
                result = accept(body.get("sth") or {}, body.get("proof"),
                                signers_path, state_path,
                                revoked_path=revoked_path)
                self._send(200, result)
            except WitnessError as exc:
                self._send(409, {"ok": False, "error": type(exc).__name__,
                                 "message": str(exc)})
            except (ValueError, TypeError) as exc:
                self._send(400, {"ok": False, "error": "bad_request",
                                 "message": str(exc)[:200]})

    return Handler


def make_server(host: str, port: int, state_path: str, signers_path: str,
                token: str, revoked_path: str | None = None
                ) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, int(port)),
                                 make_handler(state_path, signers_path, token,
                                              revoked_path))
    server.daemon_threads = True
    return server
