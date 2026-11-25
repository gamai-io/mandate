"""A browser page a human can actually use to approve an effect.

The JSON approver needs a terminal on the approver host: fine for an engineer,
useless for treasury operations. This page shows the **rendered effect** (what,
to whom, how much, which agent, which broker), and signs the same snapshot the
human saw.

Three properties it enforces, each with a test:

1. **The snapshot is the signature.** The intent is frozen when the request
   arrives; approval signs that object, not whatever the agent sends later.
   A recomputed `render_hash` that no longer matches the stored one is refused.
2. **The form is bound to the server.** Every button carries an HMAC over the
   pending id with a per-process secret, so a page from another origin cannot
   approve by guessing an id.
3. **It says what it is.** The page states, in the page, that the signature is
   made by the key on this host via `ssh-keygen`, and that it is not WebAuthn.

Loopback only by default; `--host 0.0.0.0` is refused unless `--allow-remote`.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import secrets
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import core

MAX_BODY = 64 * 1024
PAGE_TTL = 900


class Pending:
    def __init__(self, intent: dict, proposal: dict, audience: str, ttl: int,
                 wait_s: float):
        self.id = uuid.uuid4().hex[:16]
        self.intent = intent
        self.proposal = proposal
        self.audience = audience
        self.ttl = ttl
        self.created = time.time()
        self.expires = time.time() + min(wait_s, 3600)
        self.event = threading.Event()
        self.result: dict | None = None
        self.error: str | None = None
        self.decision: str | None = None


class ApprovalPage:
    def __init__(self, key_path: str, approver_name: str, audience: str = "",
                 ttl: int = 900, wait_s: float = 300, token: str = "",
                 ledger: str = "", signers: str = ""):
        self.key_path = key_path
        self.approver_name = approver_name
        self.audience = audience
        self.ttl = int(ttl)
        self.wait_s = float(wait_s)
        self.token = token
        self.ledger = ledger
        self.signers = signers
        self.secret = secrets.token_bytes(32)
        self.pending: dict[str, Pending] = {}
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ forms
    def form_token(self, pending_id: str) -> str:
        return hmac.new(self.secret, pending_id.encode(), hashlib.sha256).hexdigest()

    def form_ok(self, pending_id: str, token: str) -> bool:
        return hmac.compare_digest(self.form_token(pending_id), str(token or ""))

    # --------------------------------------------------------------- requests
    def submit(self, intent: dict, audience: str | None = None,
               ttl: int | None = None) -> dict:
        intent = core.normalize_intent(intent)
        proposal = core.propose(intent)
        item = Pending(intent, proposal,
                       str(audience if audience is not None else self.audience),
                       int(ttl if ttl is not None else self.ttl), self.wait_s)
        with self.lock:
            self._prune()
            self.pending[item.id] = item
        if not item.event.wait(self.wait_s):
            with self.lock:
                self.pending.pop(item.id, None)
            raise core.MandateError("approval timed out after %ds" % self.wait_s)
        with self.lock:
            self.pending.pop(item.id, None)
        if item.result is not None:
            return item.result
        raise core.PolicyDenied(item.error or "rejected")

    def _prune(self) -> None:
        now = time.time()
        for pid in [p for p, item in self.pending.items() if item.expires < now]:
            item = self.pending.pop(pid)
            item.error = "expired before approval"
            item.event.set()

    def list_pending(self) -> list[dict]:
        with self.lock:
            self._prune()
            items = list(self.pending.values())
        return [{"id": item.id, "token": self.form_token(item.id),
                 "summary": item.proposal["render"]["summary"],
                 "fields": item.proposal["render"]["fields"],
                 "commitment": item.proposal["commitment"],
                 "agent": str(item.intent["actor"].get("agent") or ""),
                 "audience": item.audience, "age_s": int(time.time() - item.created),
                 "expires_in_s": max(0, int(item.expires - time.time()))}
                for item in sorted(items, key=lambda i: i.created)]

    # --------------------------------------------------------------- decisions
    def approve(self, pending_id: str) -> dict:
        with self.lock:
            item = self.pending.get(pending_id)
        if item is None:
            raise core.GrantInvalid("no such pending request")
        # the snapshot is what gets signed; if it no longer renders the same, stop
        recomputed = core.render_hash(item.intent)
        if recomputed != item.proposal["render_hash"]:
            item.error = "the request changed after it was displayed"
            item.event.set()
            raise core.CommitmentMismatch(item.error)
        grant_core = core.build_grant_core(
            item.proposal["commitment"], self.approver_name, ttl_s=item.ttl,
            render_hash=item.proposal["render_hash"],
            agent=str(item.intent["actor"].get("agent") or ""),
            audience=item.audience,
            policy_fingerprint=core.policy_digest(core.load_policy()))
        grant = core.make_grant(grant_core, self.key_path)
        item.decision = "approved"
        item.result = {"ok": True, "grant": grant, "intent": item.intent,
                       "commitment": item.proposal["commitment"],
                       "render_hash": item.proposal["render_hash"],
                       "render": item.proposal["render"],
                       "approver": self.approver_name,
                       "audience": item.audience,
                       "approved_at": int(time.time())}
        self._record(item, "approved")
        item.event.set()
        return item.result

    def reject(self, pending_id: str, reason: str = "") -> dict:
        with self.lock:
            item = self.pending.get(pending_id)
        if item is None:
            raise core.GrantInvalid("no such pending request")
        item.decision = "rejected"
        item.error = "approver rejected the request" + (
            ": " + reason if reason else "")
        self._record(item, "rejected", reason)
        item.event.set()
        return {"ok": False, "decision": "rejected", "reason": reason}

    def _record(self, item: Pending, decision: str, reason: str = "") -> None:
        if not self.ledger:
            return
        body = {"v": 1, "type": "approval", "decision": decision,
                "approver": self.approver_name,
                "commitment": item.proposal["commitment"],
                "render_hash": item.proposal["render_hash"],
                "render": item.proposal["render"],
                "agent": str(item.intent["actor"].get("agent") or ""),
                "audience": item.audience, "ts": int(time.time())}
        if reason:
            body["reason"] = str(reason)[:200]
        try:
            core.append_receipt(self.ledger, body)
        except OSError:
            pass


# ------------------------------------------------------------------- HTML
STYLE = """
body{font:16px/1.5 system-ui,sans-serif;background:#0f1115;color:#e7e9ee;margin:0}
.wrap{max-width:760px;margin:0 auto;padding:28px 20px}
h1{font-size:22px;margin:0 0 6px}
.note{color:#9aa3b2;font-size:13px}
.card{background:#171a21;border:1px solid #262b36;border-radius:10px;padding:18px;margin:16px 0}
.amount{font-size:26px;font-weight:600;color:#fff}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
button{font:inherit;padding:10px 16px;border-radius:8px;border:1px solid #2c3240;
background:#232936;color:#e7e9ee;cursor:pointer}
.ok{background:#1f6f43;border-color:#2a8a55}
.no{background:#3a2226;border-color:#6b2f37}
code{background:#0b0d12;padding:2px 6px;border-radius:5px;font-size:13px}
.empty{color:#9aa3b2}
"""


def _page(rows: list[dict]) -> str:
    if not rows:
        body = ('<p class="empty">Nema zahtjeva na čekanju. Stranica se sama '
                'osvježava svakih 5 s.</p>')
    else:
        cards = []
        for row in rows:
            fields = row["fields"] or {}
            amount = fields.get("amount") or {}
            cards.append("""
<div class="card">
  <div class="amount">{amount}</div>
  <div><strong>{summary}</strong></div>
  <p class="note">agent <code>{agent}</code> &middot; broker <code>{audience}</code>
     &middot; čeka {age}s &middot; ističe za {expires}s</p>
  <p class="note">commitment <code>{commitment}</code></p>
  <form method="post" action="/approve">
    <input type="hidden" name="id" value="{id}">
    <input type="hidden" name="token" value="{token}">
    <div class="row">
      <button class="ok" type="submit">Odobri</button>
      <button class="no" type="submit" name="decision" value="reject"
              formaction="/reject">Odbij</button>
    </div>
  </form>
</div>""".format(amount=html.escape(
                ("%.2f %s" % (amount.get("value"), amount.get("currency")))
                if amount.get("value") is not None else "—"),
                summary=html.escape(row["summary"]),
                agent=html.escape(row["agent"] or "-"),
                audience=html.escape(row["audience"] or "(unbound)"),
                age=row["age_s"], expires=row["expires_in_s"],
                commitment=html.escape(row["commitment"]),
                id=html.escape(row["id"]), token=html.escape(row["token"])))
        body = "".join(cards)
    return """<!doctype html><html lang="bs"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mandate — odobrenje</title>
<style>%s</style>
<div class="wrap">
  <h1>Odobrenje efekta</h1>
  <p class="note">Potpisuje se <strong>tačno ono što vidite</strong>: iznos, primalac,
  agent i broker ulaze u commitment. Ako se zahtjev promijeni poslije prikaza,
  odobrenje se odbija.</p>
  <p class="note">Potpis ide sa ključem na <em>ovom</em> hostu preko <code>ssh-keygen</code>
  (radi i sa <code>sk-</code> hardverskim ključem). Ovo nije WebAuthn/passkey.</p>
  %s
  <p class="note">Ova stranica poslužuje samo <code>127.0.0.1</code>.</p>
</div>
<script>setTimeout(function(){location.reload()},5000)</script>
</html>""" % (STYLE, body)


def make_handler(page: ApprovalPage):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "mandate-approval/1"

        def log_message(self, *args):
            pass

        def _json(self, code: int, obj: dict) -> None:
            data = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _html(self, code: int, text: str) -> None:
            data = text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            if not page.token:
                return True
            header = self.headers.get("Authorization", "")
            return (header.lower().startswith("bearer ")
                    and hmac.compare_digest(header[7:].strip(), page.token))

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if not self._authorized():
                self._json(401, {"ok": False, "error": "unauthorized"})
                return
            if path in ("/", "/pending"):
                self._html(200, _page(page.list_pending()))
                return
            if path == "/health":
                self._json(200, {"ok": True, "approver": page.approver_name,
                                 "pending": len(page.pending)})
                return
            self._json(404, {"error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
            if not self._authorized():
                self._json(401, {"ok": False, "error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length < 0 or length > MAX_BODY:
                    self.close_connection = True
                    self._json(413, {"ok": False, "error": "payload_too_large"})
                    return
                raw = self.rfile.read(length) if length else b"{}"
                if path == "/request":
                    payload = json.loads(raw.decode())
                    result = page.submit(payload.get("intent") or {},
                                         audience=payload.get("audience"),
                                         ttl=payload.get("ttl"))
                    self._json(200, result)
                    return
                form = urllib.parse.parse_qs(raw.decode())
                pending_id = (form.get("id") or [""])[0]
                token = (form.get("token") or [""])[0]
                if not page.form_ok(pending_id, token):
                    self._json(403, {"ok": False, "error": "bad form token"})
                    return
                if path == "/approve":
                    self._json(200, page.approve(pending_id))
                elif path == "/reject":
                    reason = (form.get("reason") or [""])[0]
                    self._json(200, page.reject(pending_id, reason))
                else:
                    self._json(404, {"error": "not found"})
            except core.MandateError as exc:
                self._json(409, {"ok": False, "error": type(exc).__name__,
                                 "message": str(exc)})
            except (ValueError, TypeError) as exc:
                self._json(400, {"ok": False, "error": "bad_request",
                                 "message": str(exc)[:200]})

    return Handler


def serve(key_path: str, approver_name: str, host: str = "127.0.0.1",
          port: int = 8898, audience: str = "", ttl: int = 900,
          wait_s: float = 300, token: str = "", ledger: str = "",
          allow_remote: bool = False) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
        raise SystemExit("refusing to bind %s: the approval page is loopback-only "
                         "unless --allow-remote is given" % host)
    page = ApprovalPage(key_path, approver_name, audience, ttl, wait_s, token,
                        ledger)
    server = ThreadingHTTPServer((host, int(port)), make_handler(page))
    server.daemon_threads = True
    server.page = page          # type: ignore[attr-defined]
    return server
