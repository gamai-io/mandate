from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import agents as agent_store
from . import core, sign
from .adapters import ErpChecker, PaymentAdapter, Publisher, SmtpSender, SqlWriter, WriteAdapter
from .journal import Journal
from .metrics import Registry
from .ratelimit import RateLimiter

BROKER_NAMESPACE = "mandate-broker"
MAX_BODY = 256 * 1024


class PreconditionFailed(core.MandateError):
    pass


class ReplayBusy(core.MandateError):
    pass


class Broker:
    def __init__(self, policy: str, signers: str, ledger: str,
                 nonce_db: str = "broker/used.sqlite",
                 receipt_key: str = "", broker_name: str = "gama-broker",
                 effects_dir: str = "effects", outbox: str = "outbox",
                 smtp: dict | None = None, erp: dict | None = None,
                 write: dict | None = None, payment: dict | None = None,
                 require_audience: bool = True, revoked_path: str = "",
                 journal_db: str | None = None, lease_s: float = 60,
                 recover_on_start: bool = True, token: str = "",
                 rate_per_min: float = 0, rate_burst: float = 0,
                 agents_path: str = "", tls_client_ca: str = "",
                 tools_path: str = "", sql: dict | None = None,
                 publish: dict | None = None):
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
        self.payment = PaymentAdapter(payment) if payment else None
        self.payment_cfg = dict(payment or {})
        self.smtp_cfg = dict(smtp or {})
        self.require_audience = require_audience
        self.revoked_path = revoked_path
        self.token = token
        self.agents_path = agents_path
        self.tls_client_ca = tls_client_ca
        self.tools_path = tools_path
        self.sql = SqlWriter(sql) if sql else None
        self.publisher = Publisher(publish) if publish else None
        self.metrics = Registry("mandate_broker")
        self.limiter = (RateLimiter(rate_per_min, rate_burst)
                        if rate_per_min and float(rate_per_min) > 0 else None)
        write_cfg = dict(write or {})
        write_cfg.setdefault("effects_dir", effects_dir)
        self.writer = WriteAdapter(write_cfg)
        self.journal = Journal(journal_db or (nonce_db + ".journal"),
                               lease_s=lease_s)
        self._finalize_lock = threading.Lock()
        if recover_on_start:
            self.recover()

    def _store(self, kind: str):
        if kind == "payment.send" and self.payment is not None:
            return self.payment
        if kind == "sql.write" and self.sql is not None:
            return self.sql
        if kind == "package.publish" and self.publisher is not None:
            return self.publisher
        if kind == "message.send" and self.smtp is not None:
            return None
        return self.writer

    def _run(self, kind: str, intent: dict, idem_key: str) -> dict:
        if kind == "message.send" and self.smtp is not None:
            return self.smtp.send(intent)
        store = self._store(kind)
        return store.execute(intent, idem_key)

    def _sign_result(self, body: dict) -> dict:
        if not self.receipt_key or not os.path.exists(self.receipt_key):
            return body
        body["broker_sig"] = sign.sign(
            core.jcs(core.result_signing_payload(body)), self.receipt_key,
            BROKER_NAMESPACE)
        return body

    def _result_entry(self, receipt: dict, result: dict,
                      result_hash: str) -> dict:
        kind = str(((receipt.get("body") or {}).get("render") or {})
                   .get("fields", {}).get("kind") or "")
        body = {
            "v": core.VERSION,
            "type": "result",
            "receipt_hash": receipt["hash"],
            "grant_nonce": receipt["body"]["grant_nonce"],
            "effect": kind,
            "status": "ok" if result.get("ok", True) else "error",
            "result_hash": result_hash,
            "broker": self.broker_name,
            "ts": int(time.time()),
        }
        return core.append_receipt(self.ledger, self._sign_result(body))

    def _finalize(self, nonce: str, intent: dict, grant_core: dict,
                  commitment: str, result: dict, result_hash: str):
        with self._finalize_lock:
            row = self.journal.get(nonce) or {}
            if row.get("receipt_entry"):
                return (json.loads(row["receipt_entry"]),
                        json.loads(row["result_entry"])
                        if row.get("result_entry") else None)
            receipt = core.append_receipt(
                self.ledger,
                core.build_receipt(intent, grant_core, commitment, result_hash))
            entry = self._result_entry(receipt, result, result_hash)
            self.journal.mark_receipted(nonce, core.jcs(receipt),
                                        core.jcs(entry))
            return receipt, entry

    def _duplicate(self, nonce: str) -> dict:
        row = self.journal.get(nonce) or {}
        if row.get("state") == "executed" and not row.get("receipt_entry"):
            try:
                intent = json.loads(row["payload"])
                grant_core = json.loads(row["grant_core"])
                result = json.loads(row["result_json"] or "{}")
                self._finalize(nonce, intent, grant_core,
                               core.intent_commitment(intent), result,
                               core.sha256(core.jcs(result)))
            except (TypeError, ValueError):
                self.recover()
            row = self.journal.get(nonce) or {}
        receipt = json.loads(row["receipt_entry"]) if row.get("receipt_entry") else None
        entry = json.loads(row["result_entry"]) if row.get("result_entry") else None
        result = json.loads(row["result_json"]) if row.get("result_json") else None
        return {"ok": True, "duplicate": True, "effect": row.get("kind"),
                "receipt": receipt, "result": result, "result_entry": entry}

    def recover(self) -> list[dict]:
        actions = []
        for row in self.journal.recoverable():
            nonce = str(row["idem_key"])
            if row["state"] == "intent":
                self.journal.mark_abandoned(nonce, "grant expired before execution")
                actions.append({"nonce": nonce, "action": "abandoned"})
                continue
            if row["state"] == "executing":
                store = self._store(str(row.get("kind") or ""))
                if store is not None and store.has_effect(nonce):
                    result = store.result_for(nonce) or {
                        "ok": True, "recovered": True}
                    self.journal.mark_executed(nonce, core.jcs(result),
                                               external_ref=nonce)
                    row = self.journal.get(nonce) or {}
                    actions.append({"nonce": nonce, "action": "effect_found"})
                else:
                    self.journal.mark_abandoned(nonce, "lease expired before effect")
                    actions.append({"nonce": nonce, "action": "abandoned"})
                    continue
            if row.get("state") == "executed" and not row.get("receipt_entry"):
                try:
                    intent = json.loads(row["payload"])
                    grant_core = json.loads(row["grant_core"])
                    result = json.loads(row["result_json"] or "{}")
                except (TypeError, ValueError):
                    self.journal.mark_failed(nonce, "journal payload corrupt")
                    actions.append({"nonce": nonce, "action": "corrupt"})
                    continue
                result_hash = core.sha256(core.jcs(result))
                self._finalize(nonce, intent, grant_core,
                               core.intent_commitment(intent), result,
                               result_hash)
                actions.append({"nonce": nonce, "action": "receipted"})
        return actions

    def execute(self, intent: dict, grant_obj: dict, caller: str | None = None) -> dict:
        intent = core.normalize_intent(intent)
        # limits and halt apply to every execution path, not only the CLI
        try:
            from .governance import check as governance_check
            from .governance import load_limits
            ledger = getattr(self, "ledger", None) or getattr(self, "ledger_path", None)
            amount = intent.get("effect", {}).get("amount") or {}
            pending = {"value": float(amount.get("value") or 0),
                       "currency": str(amount.get("currency") or "")}
            gov = governance_check(ledger,
                                   load_limits(getattr(self, "policy_path", None)),
                                   pending=pending)
            if not gov["allow"]:
                raise core.PolicyDenied("governance: %s" % gov["code"])
        except core.MandateError:
            raise
        except Exception as exc:      # fail closed: if limits cannot be checked, do not run
            raise core.PolicyDenied("governance unavailable: %s" % str(exc)[:120])
        kind = str(intent["effect"]["kind"])
        decision = core.check(intent, self.policy)
        if decision["decision"] == "deny":
            raise core.PolicyDenied("policy denied: %s" % decision.get("reason"))
        if not grant_obj:
            raise core.GrantInvalid("a signed grant is required")
        core.enforce_new_payee(intent, self.policy, self.ledger)
        if self.tools_path:
            from . import tools as tool_registry
            tool_registry.enforce(intent, self.tools_path)
        if self.erp is not None:
            pre = self.erp.check(intent)
            if not pre.get("ok"):
                raise PreconditionFailed(
                    "erp precondition failed: %s" % pre.get("reason"))
            derived = self.erp.derive_expected(intent)
            if not derived.get("ok"):
                raise PreconditionFailed(
                    "erp derivation failed: %s" % derived.get("reason"))
        verified = core.verify_authorization(
            intent, grant_obj, self.signers, policy=self.policy,
            audience=self.broker_name, require_audience=self.require_audience,
            revoked_path=self.revoked_path or None)
        intent = verified["intent"]
        grant_core = verified["grant"]
        if caller and str(grant_core.get("agent") or "") and \
                str(grant_core.get("agent")) != str(caller):
            raise core.GrantInvalid(
                "this token belongs to %r but the grant is for %r"
                % (str(caller), str(grant_core.get("agent"))))
        nonce = str(grant_core.get("nonce") or "")
        intent_hash = core.sha256(core.jcs(intent))
        begin = self.journal.begin(
            nonce, intent_hash, kind, core.jcs(intent), core.jcs(grant_core),
            (grant_core.get("scope") or {}).get("not_after"))
        status = begin["status"]
        if status == "payload_mismatch":
            raise core.GrantInvalid("same nonce used for a different intent")
        if status == "terminal":
            raise core.GrantInvalid("grant already failed or abandoned")
        if status == "busy":
            raise ReplayBusy("execution in progress")
        if status == "done":
            return self._duplicate(nonce)
        if status == "retry":
            # A previous worker held the lease and vanished. Never re-run an
            # effect blindly: ask the provider whether it already happened.
            recovered = None
            if kind == "payment.send" and self.payment is not None:
                recovered = self.payment.recover(nonce)
            if recovered is None:
                raise ReplayBusy(
                    "a previous attempt did not finish; whether the effect "
                    "happened cannot be proven, so it is not repeated")
            self.journal.claim(nonce, self.broker_name)
            self.journal.mark_executed(nonce, core.jcs(recovered),
                                       external_ref=recovered.get("idem_key"))
            receipt, entry = self._finalize(
                nonce, intent, grant_core, verified["commitment"], recovered,
                core.sha256(core.jcs(recovered)))
            return {"ok": True, "effect": kind, "receipt": receipt,
                    "result": recovered, "result_entry": entry, "recovered": True}
        if status == "new":
            # one-shot across deployments, not only inside this journal
            if not core.claim_nonce_db(nonce, self.ledger):
                raise core.GrantReplayed("grant already used (nonce store)")
        if not self.journal.claim(nonce, self.broker_name):
            row = self.journal.get(nonce) or {}
            if row.get("state") in ("executed", "receipted"):
                return self._duplicate(nonce)
            raise ReplayBusy("execution in progress")
        try:
            result = self._run(kind, intent, nonce)
        except Exception as exc:
            self.journal.mark_failed(nonce, str(exc))
            raise
        result_json = core.jcs(result)
        result_hash = core.sha256(result_json)
        self.journal.mark_executed(
            nonce, result_json,
            external_ref=result.get("path") or result.get("idem_key"))
        receipt, entry = self._finalize(
            nonce, intent, grant_core, verified["commitment"], result,
            result_hash)
        return {"ok": True, "effect": kind, "receipt": receipt,
                "result": result, "result_entry": entry}

    def custody(self) -> dict:
        """Named secrets the broker holds. Presence only, never the value."""
        payment = self.payment.custody() if self.payment is not None else None
        smtp_env = str(self.smtp_cfg.get("password_env") or "") or None
        return {"broker": self.broker_name, "payment": payment,
                "smtp": {"secret": ("env:" + smtp_env) if smtp_env else None,
                         "present": bool(smtp_env and os.environ.get(smtp_env))}}

    def status(self) -> dict:
        return {"ok": True, "broker": self.broker_name,
                "policy": self.policy_path, "effects": sorted(self.policy["effects"]),
                "signers": bool(os.path.exists(self.signers)),
                "receipt_key": bool(self.receipt_key and os.path.exists(self.receipt_key)),
                "smtp": bool(self.smtp), "erp": bool(self.erp),
                "payment": bool(self.payment),
                "custody": self.custody(),
                "agents": (len(agent_store.names(self.agents_path))
                           if self.agents_path else 0),
                "writer": self.writer.mode, "auth": bool(self.token),
                "journal": self.journal.counts()}


def make_handler(broker: Broker):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "mandate-broker/0.25.0"

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

        def _client_cert_name(self) -> str | None:
            try:
                cert = self.connection.getpeercert() or {}
            except AttributeError:
                return None
            for field in cert.get("subject", ()):
                for key, value in field:
                    if key in ("commonName", "CN"):
                        return str(value)
            return None

        def _client_ip(self) -> str:
            return str(self.client_address[0]) if self.client_address else "?"

        def _send_text(self, code: int, text: str):
            data = text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path == "/health":
                self._send(200, broker.status())
                return
            if path == "/metrics":
                if broker.token:
                    header = self.headers.get("Authorization", "")
                    ok = (header.lower().startswith("bearer ")
                          and hmac.compare_digest(header[7:].strip(),
                                                  broker.token))
                    if not ok:
                        self._send(401, {"ok": False, "error": "unauthorized"})
                        return
                for state, count in broker.journal.counts().items():
                    broker.metrics.set("journal_entries", count, state=state)
                self._send_text(200, broker.metrics.render())
                return
            self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if path != "/execute":
                self._send(404, {"error": "not found"})
                return
            if broker.limiter is not None:
                allowed, retry = broker.limiter.allow(self._client_ip())
                if not allowed:
                    broker.metrics.inc("rate_limited", action="execute")
                    self._send_text(429, "rate limited\n")
                    return
            caller = None
            header = self.headers.get("Authorization", "")
            presented = header[7:].strip() if header.lower().startswith("bearer ") else ""
            if broker.tls_client_ca:
                caller = self._client_cert_name()
                if not caller:
                    self._send(403, {"ok": False, "error": "no_client_certificate"})
                    return
                if broker.agents_path and not agent_store.is_registered(
                        broker.agents_path, caller):
                    self._send(403, {"ok": False, "error": "unknown_agent",
                                     "message": "certificate %r is not registered"
                                                % caller})
                    return
            elif broker.agents_path:
                caller = agent_store.resolve(broker.agents_path, presented)
                if caller is None:
                    self._send(401, {"ok": False, "error": "unauthorized",
                                     "message": "a per-agent token is required"})
                    return
            elif broker.token:
                if not (presented and hmac.compare_digest(presented, broker.token)):
                    self._send(401, {"ok": False, "error": "unauthorized"})
                    return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length < 0 or length > MAX_BODY:
                    self.close_connection = True
                    self._send(413, {"ok": False, "error": "payload_too_large"})
                    return
                raw = self.rfile.read(length) if length else b"{}"
                payload = json.loads(raw.decode("utf-8"))
                result = broker.execute(payload.get("intent") or {},
                                        payload.get("grant") or {},
                                        caller=caller)
                broker.metrics.inc("requests", action="execute",
                                   result="duplicate" if result.get("duplicate")
                                   else "ok")
                if result.get("duplicate"):
                    broker.metrics.inc("executions", result="duplicate")
                else:
                    broker.metrics.inc("executions", result="ok")
                self._send(200, result)
            except core.MandateError as exc:
                broker.metrics.inc("requests", action="execute",
                                   result=type(exc).__name__)
                self._send(409, {"ok": False, "error": type(exc).__name__,
                                 "message": str(exc)})
            except (ValueError, TypeError) as exc:
                broker.metrics.inc("requests", action="execute",
                                   result="bad_request")
                self._send(400, {"ok": False, "error": "bad_request",
                                 "message": str(exc)[:200]})

    return Handler


def make_server(host: str, port: int, broker: Broker) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, int(port)), make_handler(broker))
    server.daemon_threads = True
    server.broker = broker
    return server


def agent_cli(argv: list[str]) -> int:
    """`mandate-broker agent add|list|revoke --store FILE`"""
    ap = argparse.ArgumentParser(prog="mandate-broker agent")
    ap.add_argument("action", choices=("add", "list", "revoke", "register"))
    ap.add_argument("--store", required=True)
    ap.add_argument("--name", default="")
    ap.add_argument("--note", default="")
    args = ap.parse_args(argv)
    try:
        if args.action == "add":
            if not args.name:
                ap.error("--name is required for add")
            print(json.dumps(agent_store.add(args.store, args.name, args.note), indent=1))
        elif args.action == "register":
            if not args.name:
                ap.error("--name is required for register")
            print(json.dumps(agent_store.ensure_name(args.store, args.name), indent=1))
        elif args.action == "list":
            print(json.dumps({"agents": agent_store.names(args.store)}, indent=1))
        else:
            if not args.name:
                ap.error("--name is required for revoke")
            print(json.dumps(agent_store.revoke(args.store, args.name), indent=1))
    except agent_store.AgentStoreError as exc:
        print(json.dumps({"error": "AgentStoreError", "message": str(exc)}))
        return 2
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "agent":
        return agent_cli(argv[1:])
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
    parser.add_argument("--journal-db", default=os.environ.get("MANDATE_JOURNAL_DB", ""))
    parser.add_argument("--lease", type=float,
                        default=float(os.environ.get("MANDATE_LEASE_S", "60")))
    parser.add_argument("--no-recover", action="store_true")
    parser.add_argument("--rate-limit-per-min", type=float,
                        default=float(os.environ.get("MANDATE_RATE_PER_MIN", "0")))
    parser.add_argument("--rate-burst", type=float,
                        default=float(os.environ.get("MANDATE_RATE_BURST", "0")))
    parser.add_argument("--config", default=os.environ.get("MANDATE_BROKER_CONFIG", ""))
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--token", default=os.environ.get("MANDATE_BROKER_TOKEN", ""))
    parser.add_argument("--tls-cert", default=os.environ.get("MANDATE_TLS_CERT", ""),
                        help="server certificate (PEM); enables HTTPS")
    parser.add_argument("--tls-key", default=os.environ.get("MANDATE_TLS_KEY", ""))
    parser.add_argument("--client-crl", default=os.environ.get("MANDATE_CLIENT_CRL", ""),
                        help="PEM revocation list; a revoked certificate cannot connect")
    parser.add_argument("--client-ca", default=os.environ.get("MANDATE_CLIENT_CA", ""),
                        help="require a client certificate signed by this CA; the "
                             "certificate commonName becomes the agent identity")
    parser.add_argument("--tools", default=os.environ.get("MANDATE_TOOLS", ""),
                        help="JSON registry pinning tool schema hashes")
    parser.add_argument("--agents", default=os.environ.get("MANDATE_AGENTS", ""),
                        help="JSON store of per-agent tokens (see 'mandate broker agent')")
    parser.add_argument("--allow-any-audience", action="store_true")
    parser.add_argument("--revoked", default=os.environ.get(
        "MANDATE_REVOKED", "trust/revoked_signers"))
    args = parser.parse_args(argv)

    cfg = {}
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
        for key in ("host", "port", "policy", "signers", "ledger", "nonce_db", "agents",
                    "receipt_key", "broker_name", "effects_dir", "outbox",
                    "revoked", "journal_db"):
            if key in cfg:
                setattr(args, key, cfg[key])
        if "lease_s" in cfg:
            args.lease = float(cfg["lease_s"])
        if "rate_limit_per_min" in cfg:
            args.rate_limit_per_min = float(cfg["rate_limit_per_min"])
        if "rate_burst" in cfg:
            args.rate_burst = float(cfg["rate_burst"])

    if args.host not in ("127.0.0.1", "::1", "localhost"):
        if not args.allow_remote or not args.token:
            print("refusing non-loopback bind without --allow-remote and a "
                  "bearer token (--token / MANDATE_BROKER_TOKEN)", flush=True)
            return 2

    if args.policy == "policy.json" and not os.path.exists(args.policy):
        args.policy = core.DEFAULT_POLICY

    broker = Broker(args.policy, args.signers, args.ledger, args.nonce_db,
                    receipt_key=args.receipt_key, broker_name=args.broker_name,
                    effects_dir=args.effects_dir, outbox=args.outbox,
                    smtp=cfg.get("smtp"), erp=cfg.get("erp"),
                    write=cfg.get("write"), payment=cfg.get("payment"),
                    sql=cfg.get("sql"), publish=cfg.get("publish"),
                    require_audience=not args.allow_any_audience,
                    revoked_path=args.revoked,
                    journal_db=args.journal_db or None,
                    lease_s=args.lease,
                    agents_path=getattr(args, "agents", "") or "",
                    tls_client_ca=getattr(args, "client_ca", "") or "",
                    tools_path=getattr(args, "tools", "") or "",
                    recover_on_start=not args.no_recover,
                    token=args.token,
                    rate_per_min=args.rate_limit_per_min,
                    rate_burst=args.rate_burst)
    server = make_server(args.host, args.port, broker)
    if args.tls_cert and args.tls_key:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        if args.client_ca:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(args.client_ca)
        if args.client_crl:
            context.load_verify_locations(cafile=args.client_crl)   # holds the CRL
            context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        server.socket = context.wrap_socket(server.socket, server_side=True)
    host, port = server.server_address[:2]
    scheme = "https" if args.tls_cert and args.tls_key else "http"
    print("mandate-broker listening on %s://%s:%s%s"
          % (scheme, host, port,
             " (client certificate required)" if args.client_ca else ""), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
