from __future__ import annotations

import argparse
import json
import os
import sqlite3
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import core, sign
from .adapters import ErpChecker, SmtpSender

BROKER_NAMESPACE = "mandate-broker"


class PreconditionFailed(core.MandateError):
    pass


class NonceStore:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        self._con = sqlite3.connect(path, check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute(
            "CREATE TABLE IF NOT EXISTS used(nonce TEXT PRIMARY KEY, ts REAL)")
        self._con.commit()

    def consume(self, nonce: str) -> bool:
        with self._lock:
            try:
                self._con.execute("INSERT INTO used(nonce, ts) VALUES(?, ?)",
                                  (str(nonce), time.time()))
                self._con.commit()
                return True
            except sqlite3.IntegrityError:
                return False


class Broker:
    def __init__(self, policy: str, signers: str, ledger: str, nonce_db: str,
                 receipt_key: str = "", broker_name: str = "gama-broker",
                 effects_dir: str = "effects", outbox: str = "outbox",
                 smtp: dict | None = None, erp: dict | None = None):
        self.policy_path = policy
        self.policy = core.load_policy(policy)
        self.signers = signers
        self.ledger = ledger
        self.receipt_key = receipt_key
        self.broker_name = broker_name
        self.effects_dir = effects_dir
        self.outbox = outbox
        self.smtp = SmtpSender(smtp) if smtp else None
        self.erp = ErpChecker(erp) if erp else None
        self.nonces = NonceStore(nonce_db)

    def _run(self, kind: str, intent: dict) -> dict:
        if kind == "message.send" and self.smtp is not None:
            return self.smtp.send(intent)
        stamp = int(time.time() * 1000)
        record = {"effect": intent["effect"], "nonce": intent["nonce"],
                  "actor": intent.get("actor"), "requested_by": intent.get("requested_by"),
                  "ts": int(time.time())}
        if kind == "message.send":
            target_dir = self.outbox
        else:
            target_dir = self.effects_dir
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, "%s-%s-%s.json" % (
            kind.replace(".", "_"), intent["nonce"], stamp))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(core.jcs(record) + "\n")
        return {"ok": True, "sandbox": True, "effect": kind, "record": path}

    def _sign_result(self, body: dict) -> dict:
        if not self.receipt_key or not os.path.exists(self.receipt_key):
            return body
        unsigned = {k: v for k, v in body.items() if k != "broker_sig"}
        body["broker_sig"] = sign.sign(core.jcs(unsigned), self.receipt_key,
                                       BROKER_NAMESPACE)
        return body

    def execute(self, intent: dict, grant_obj: dict) -> dict:
        intent = core.normalize_intent(intent)
        decision = core.check(intent, self.policy)
        kind = str(intent["effect"]["kind"])
        if decision["decision"] == "deny":
            raise core.PolicyDenied("policy denied: %s" % decision.get("reason"))
        if not grant_obj:
            raise core.GrantInvalid("a signed grant is required")
        if self.erp is not None:
            pre = self.erp.check(intent)
            if not pre.get("ok"):
                raise PreconditionFailed(
                    "erp precondition failed: %s" % pre.get("reason"))
        receipt = core.redeem(intent, grant_obj, self.signers, self.ledger,
                              claim=self.nonces.consume)
        try:
            result = self._run(kind, intent)
            status = "ok"
        except Exception as exc:
            result = {"ok": False, "error": str(exc)[:200]}
            status = "error"
        body = {
            "v": core.VERSION,
            "type": "result",
            "receipt_hash": receipt["hash"],
            "grant_nonce": receipt["body"]["grant_nonce"],
            "effect": kind,
            "status": status,
            "result_hash": core.sha256(core.jcs(result)),
            "broker": self.broker_name,
            "ts": int(time.time()),
        }
        entry = core.append_receipt(self.ledger, self._sign_result(body))
        return {"ok": status == "ok", "effect": kind, "receipt": receipt,
                "result": result, "result_entry": entry}

    def status(self) -> dict:
        return {"ok": True, "broker": self.broker_name,
                "policy": self.policy_path, "effects": sorted(self.policy["effects"]),
                "signers": bool(os.path.exists(self.signers)),
                "receipt_key": bool(self.receipt_key and os.path.exists(self.receipt_key)),
                "smtp": bool(self.smtp), "erp": bool(self.erp)}


def make_handler(broker: Broker):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "mandate-broker/0.2"

        def log_message(self, fmt, *args):
            if os.environ.get("MANDATE_BROKER_LOG") == "1":
                super().log_message(fmt, *args)

        def _send(self, code: int, obj: dict):
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path == "/health":
                self._send(200, broker.status())
                return
            self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path != "/execute":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                payload = json.loads(raw.decode("utf-8"))
                result = broker.execute(payload.get("intent") or {},
                                        payload.get("grant") or {})
                self._send(200, result)
            except core.MandateError as exc:
                self._send(409, {"ok": False, "error": type(exc).__name__,
                                 "message": str(exc)})
            except (ValueError, TypeError) as exc:
                self._send(400, {"ok": False, "error": "bad_request",
                                 "message": str(exc)[:200]})

    return Handler


def make_server(host: str, port: int, broker: Broker) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, int(port)), make_handler(broker))
    server.daemon_threads = True
    server.broker = broker
    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mandate-broker")
    parser.add_argument("--host", default=os.environ.get("MANDATE_BROKER_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MANDATE_BROKER_PORT", "8899")))
    parser.add_argument("--policy", default=os.environ.get("MANDATE_POLICY", "policy.json"))
    parser.add_argument("--signers", default=os.environ.get("MANDATE_SIGNERS", "trust/allowed_signers"))
    parser.add_argument("--ledger", default=os.environ.get("MANDATE_LEDGER", "ledger.jsonl"))
    parser.add_argument("--nonce-db", default=os.environ.get("MANDATE_NONCE_DB", "broker/used.sqlite"))
    parser.add_argument("--receipt-key", default=os.environ.get("MANDATE_RECEIPT_KEY", ""))
    parser.add_argument("--broker-name", default=os.environ.get("MANDATE_BROKER_NAME", "gama-broker"))
    parser.add_argument("--effects-dir", default=os.environ.get("MANDATE_EFFECTS_DIR", "effects"))
    parser.add_argument("--outbox", default=os.environ.get("MANDATE_OUTBOX", "outbox"))
    parser.add_argument("--config", default=os.environ.get("MANDATE_BROKER_CONFIG", ""))
    parser.add_argument("--allow-remote", action="store_true")
    args = parser.parse_args(argv)

    cfg = {}
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
        for key in ("host", "port", "policy", "signers", "ledger", "nonce_db",
                    "receipt_key", "broker_name", "effects_dir", "outbox"):
            if key in cfg:
                setattr(args, key, cfg[key])

    if args.host not in ("127.0.0.1", "::1", "localhost") and not args.allow_remote:
        print("refusing to bind non-loopback host without --allow-remote", flush=True)
        return 2

    broker = Broker(args.policy, args.signers, args.ledger, args.nonce_db,
                    receipt_key=args.receipt_key, broker_name=args.broker_name,
                    effects_dir=args.effects_dir, outbox=args.outbox,
                    smtp=cfg.get("smtp"), erp=cfg.get("erp"))
    server = make_server(args.host, args.port, broker)
    host, port = server.server_address[:2]
    print("mandate-broker listening on http://%s:%s" % (host, port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
