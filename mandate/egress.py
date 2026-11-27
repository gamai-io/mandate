"""Egress control: deny by default, allow by name, authenticate every request.

In July 2026 the escape route was not a clever model — it was a reachable
network path (a package-registry cache proxy with a zero-day, then stolen
credentials), and in October a "firewall-approved connection" was reused. A
sandbox without an egress policy is half a control.

This module is deliberately dependency-free:

  mandate egress policy --allow 127.0.0.1:18080 --out egress.json
  mandate egress proxy --policy egress.json --port 3128 --ledger egress.jsonl
  mandate egress check --policy egress.json example.com:443

Design:
  * default deny;
  * allowlist entries are host:port (host may be a DNS name or an IP literal);
  * every request needs `Proxy-Authorization: Bearer <token>` (token from env or
    the policy file's token_env);
  * destinations resolving to loopback, link-local, private or metadata addresses
    are refused unless that IP is allowlisted explicitly (SSRF / metadata guard);
  * HTTP CONNECT (TLS) and plain HTTP are both proxied;
  * every decision — allow and deny — is a `control` record in the ledger.

Honest scope: this is an application-level proxy. An agent that can bypass the
proxy (raw socket, its own resolver, host networking) is not contained by it;
pair it with network namespaces/VM egress rules, which is the bank tier.
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
import time

from .core import append_receipt

PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "169.254.", "0.", "100.64.", "100.65.",
                    "100.66.", "100.67.", "100.68.", "100.69.", "100.70.", "100.71.",
                    "100.72.", "100.73.", "100.74.", "100.75.", "100.76.", "100.77.",
                    "100.78.", "100.79.", "100.80.", "100.81.", "100.82.", "100.83.",
                    "100.84.", "100.85.", "100.86.", "100.87.", "100.88.", "100.89.",
                    "100.90.", "100.91.", "100.92.", "100.93.", "100.94.", "100.95.",
                    "100.96.", "100.97.", "100.98.", "100.99.", "100.100.", "100.101.",
                    "100.102.", "100.103.", "100.104.", "100.105.", "100.106.", "100.107.",
                    "100.108.", "100.109.", "100.110.", "100.111.", "100.112.", "100.113.",
                    "100.114.", "100.115.", "100.116.", "100.117.", "100.118.", "100.119.",
                    "100.120.", "100.121.", "100.122.", "100.123.", "100.124.", "100.125.",
                    "100.126.", "100.127.")

METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "100.100.100.200"}


def default_policy() -> dict:
    return {"version": 1, "default": "deny", "allow": [], "token_env": "MANDATE_EGRESS_TOKEN"}


def load_policy(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return default_policy()
    data = json.load(open(path, encoding="utf-8"))
    if not isinstance(data, dict) or data.get("default", "deny") != "deny":
        raise ValueError("egress policy must be an object with default=deny")
    data.setdefault("allow", [])
    data.setdefault("token_env", "MANDATE_EGRESS_TOKEN")
    return data


def _is_private(ip: str) -> bool:
    ip = (ip or "").lower()
    if ip.startswith("::ffff:"):        # IPv4-mapped IPv6
        ip = ip.split("::ffff:")[-1]
    if ip in METADATA_HOSTS:
        return True
    if ip.startswith(PRIVATE_PREFIXES):
        return True
    try:
        first, second = (int(x) for x in ip.split(".")[:2])
        if first == 172 and 16 <= second <= 31:   # RFC1918 172.16/12
            return True
        if first == 169 and second == 254:        # link-local
            return True
    except (TypeError, ValueError):
        pass
    if ip in ("::", "::1") or ip.startswith("fc") or ip.startswith("fd"):
        return True
    if ip.startswith("fe80") or ip.startswith("2001:db8") or ip.startswith("64:ff9b"):
        return True     # link-local, documentation, NAT64
    return False


def _split(entry: str) -> tuple[str, int]:
    if entry.startswith("["):
        host, _, port = entry.partition("]")
        return host[1:], int(port.lstrip(":"))
    host, _, port = entry.rpartition(":")
    if not host:
        return entry, 443
    return host, int(port)


def decide(policy: dict, host: str, port: int) -> dict:
    host = (host or "").strip().lower()
    allow = policy.get("allow") or []
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return {"allow": False, "code": "dns_failure", "detail": str(exc)[:120]}
    ips = sorted({info[4][0] for info in infos})
    allowed_host = False
    allowed_ips: set[str] = set()
    for entry in allow:
        ahost, aport = _split(str(entry))
        if aport != int(port):
            continue
        if ahost.lower() == host:
            allowed_host = True
        if ahost in ips:
            allowed_ips.add(ahost)

    # SSRF and metadata guards run BEFORE the allowlist: a hostname entry must not
    # become a way to reach loopback or a cloud metadata service.
    if any(ip in METADATA_HOSTS for ip in ips) and not (set(ips) & allowed_ips):
        return {"allow": False, "code": "metadata_endpoint", "ips": ips}
    private = [ip for ip in ips if _is_private(ip) and ip not in allowed_ips]
    if private:
        return {"allow": False, "code": "private_destination", "ips": private}

    if allowed_host:
        return {"allow": True, "code": "allowlist_host", "ip": ips[0]}
    if allowed_ips:
        return {"allow": True, "code": "allowlist_ip", "ip": sorted(allowed_ips)[0]}
    return {"allow": False, "code": "not_allowlisted", "ips": ips}


def guard(url: str, policy: dict | None, what: str = "outbound call") -> dict:
    """Check a destination before connecting. Denied is an exception, not a warning.

    Called by the adapters on every request, not only at construction, because a
    hostname can resolve differently the second time (DNS rebinding).
    """
    from urllib.parse import urlsplit
    pol = policy if isinstance(policy, dict) else default_policy()
    parts = urlsplit(str(url or ""))
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if not host:
        raise ValueError("%s has no host" % what)
    decision = decide(pol, host, port)
    if decision.get("allow") and not pol.get("allow_metadata"):
        ips = decision.get("ips") or ([decision["ip"]] if decision.get("ip") else [])
        if any(str(ip) in METADATA_HOSTS for ip in ips):
            raise ValueError("egress denied for %s (%s): metadata address"
                             % (what, host))
    if not decision.get("allow"):
        raise ValueError("egress denied for %s (%s): %s"
                         % (what, host, decision.get("code")))
    return decision


def _record(policy: dict, ledger_path: str | None, body: dict) -> None:
    if ledger_path:
        append_receipt(ledger_path, {"v": 1, "type": "control", **body})


def _read_n(sock, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(min(65536, size - len(data)))
        if not chunk:
            break
        data += chunk
    return data


class _Handler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self) -> None:
        policy = self.server.policy  # type: ignore[attr-defined]
        ledger = self.server.ledger_path  # type: ignore[attr-defined]

        head = b""
        while b"\r\n\r\n" not in head and len(head) < 65536:
            chunk = self.rfile.read(1)
            if not chunk:
                return
            head += chunk
        try:
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
        except ValueError:
            self.wfile.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        expected = os.environ.get(policy.get("token_env") or "MANDATE_EGRESS_TOKEN", "")
        offered = headers.get("proxy-authorization", "")
        if offered.lower().startswith("bearer "):
            offered = offered[7:].strip()
        if not expected:
            body = {"action": "egress", "decision": "deny", "code": "no_token_configured",
                    "method": method, "target": target, "ts": time.time()}
            _record(policy, ledger, body)
            self.wfile.write(b"HTTP/1.1 503 No Token Configured\r\n\r\n")
            return
        if offered != expected:
            body = {"action": "egress", "decision": "deny", "code": "unauthenticated",
                    "method": method, "target": target, "ts": time.time()}
            _record(policy, ledger, body)
            self.wfile.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                             b"Proxy-Authenticate: Bearer\r\n\r\n")
            return

        if method.upper() == "CONNECT":
            host, _, port_s = target.partition(":")
            port = int(port_s or 443)
        else:
            # absolute-form request target, e.g. http://example.com/path
            rest = target.split("://", 1)[-1]
            hostport, _, path = rest.partition("/")
            host, _, port_s = hostport.partition(":")
            port = int(port_s or 80)
            target = "/" + path if path else "/"

        verdict = decide(policy, host, port)
        if not verdict["allow"]:
            _record(policy, ledger, {"action": "egress", "decision": "deny",
                                     "code": verdict["code"], "host": host, "port": port,
                                     "method": method, "ts": time.time()})
            self.wfile.write(("HTTP/1.1 403 Forbidden\r\nX-Egress-Reason: %s\r\n\r\n"
                              % verdict["code"]).encode())
            return

        # Connect to the IP we validated, not to the name we validated: a DNS
        # answer that changes between decide() and connect() must not matter.
        target_ip = verdict.get("ip") or host
        try:
            upstream = socket.create_connection((target_ip, port), timeout=15)
        except OSError as exc:
            _record(policy, ledger, {"action": "egress", "decision": "deny",
                                     "code": "connect_failed", "host": host, "port": port,
                                     "error": str(exc)[:120], "ts": time.time()})
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        _record(policy, ledger, {"action": "egress", "decision": "allow",
                                 "code": verdict["code"], "host": host, "port": port,
                                 "method": method, "ts": time.time()})
        ca_dir = str(policy.get("intercept_ca") or "")
        if method.upper() == "CONNECT" and policy.get("intercept") and ca_dir:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            try:
                self._intercept(upstream, host, port, ca_dir, ledger)
            finally:
                upstream.close()
            return
        try:
            if method.upper() == "CONNECT":
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                host_header = headers.get("host") or host
                out = ["%s %s HTTP/1.1" % (method, target), "Host: %s" % host_header]
                for k, v in headers.items():
                    if k in ("proxy-authorization", "proxy-connection", "host"):
                        continue
                    out.append("%s: %s" % (k, v))
                upstream.sendall(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
            self._pipe(upstream)
        finally:
            upstream.close()

    # --- TLS interception (opt-in per policy) ------------------------------
    def _intercept(self, upstream: socket.socket, host: str, port: int,
                   ca_dir: str, ledger_path: str | None) -> None:
        """Terminate TLS for one request, scan both directions, relay the verdict.

        One request per connection, no keep-alive, `Content-Length` bodies only
        (chunked bodies are passed through unscanned and recorded as such). Everything
        is scanned in memory; nothing decrypted is written to disk.
        """
        from . import egress_tls, firewall
        try:
            ctx = egress_tls.server_context(ca_dir, host)
            client = ctx.wrap_socket(self.connection, server_side=True)
        except Exception as exc:  # noqa: BLE001
            _record(self.server.policy, ledger_path,
                    {"action": "egress", "decision": "deny", "code": "tls_handshake",
                     "host": host, "error": str(exc)[:120], "ts": time.time()})
            return
        try:
            head = self._read_until(client, b"\r\n\r\n")
            if not head:
                return
            text = head.decode("latin-1")
            lines = text.split("\r\n")
            try:
                method, path, _ = lines[0].split(" ", 2)
            except ValueError:
                self._respond(client, 400, "bad request")
                return
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            chunked = "chunked" in headers.get("transfer-encoding", "").lower()
            body = b""
            if chunked:
                body = self._read_chunked(client)
            elif headers.get("content-length", "").isdigit():
                body = self._read_exact(client, min(int(headers["content-length"]), 2_000_000))

            request_text = body.decode("utf-8", "replace")
            scan = firewall.scan_outbound(request_text)
            if not scan["ok"]:
                kinds = [f["kind"] for f in scan["findings"] if f["action"] == "block"]
                _record(self.server.policy, ledger_path,
                        {"action": "egress", "decision": "deny", "code": "request_blocked",
                         "host": host, "port": port, "method": method,
                         "findings": kinds[:8], "ts": time.time()})
                self._respond(client, 403, "blocked by mandate: %s" % ", ".join(kinds[:3]))
                return
            forwarded, replacements = firewall.redact(request_text) if scan["redactable"] \
                else (request_text, 0)
            if replacements:
                _record(self.server.policy, ledger_path,
                        {"action": "egress", "decision": "allow", "code": "redacted",
                         "host": host, "port": port, "replacements": replacements,
                         "ts": time.time()})

            out = ["%s %s HTTP/1.1" % (method, path)]
            for key, value in headers.items():
                if key in ("proxy-authorization", "proxy-connection"):
                    continue
                out.append("%s: %s" % (key, value))
            if "content-length" in headers:
                out = [line for line in out if not line.lower().startswith("content-length:")]
                out.append("Content-Length: %d" % len(forwarded.encode("utf-8")))
            out.append("Connection: close")
            payload = ("\r\n".join(out) + "\r\n\r\n").encode("latin-1") \
                + forwarded.encode("utf-8")
            policy_obj = self.server.policy
            want_tls = policy_obj.get("intercept_upstream_tls")
            if want_tls is None:
                want_tls = port in (443, 8443)
            if want_tls:
                try:
                    upstream = egress_tls.client_context(
                        policy_obj.get("upstream_ca")).wrap_socket(
                            upstream, server_hostname=host)
                except Exception as exc:  # noqa: BLE001
                    _record(policy_obj, ledger_path,
                            {"action": "egress", "decision": "deny",
                             "code": "upstream_tls", "host": host,
                             "error": str(exc)[:120], "ts": time.time()})
                    self._respond(client, 502, "upstream TLS failed")
                    return
            upstream.sendall(payload)

            resp_head = self._read_until(upstream, b"\r\n\r\n")
            if not resp_head:
                self._respond(client, 502, "no response")
                return
            resp_text = resp_head.decode("latin-1")
            resp_headers = {}
            for line in resp_text.split("\r\n")[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    resp_headers[key.strip().lower()] = value.strip()
            resp_body = b""
            if "chunked" in resp_headers.get("transfer-encoding", "").lower():
                resp_body = self._read_chunked(upstream)
            elif resp_headers.get("content-length", "").isdigit():
                resp_body = self._read_exact(upstream,
                                             min(int(resp_headers["content-length"]),
                                                 2_000_000))
            inbound = firewall.scan_inbound(resp_body.decode("utf-8", "replace"))
            if not inbound["ok"]:
                kinds = [f["kind"] for f in inbound["findings"] if f["action"] == "block"]
                _record(self.server.policy, ledger_path,
                        {"action": "egress", "decision": "deny",
                         "code": "response_blocked", "host": host, "port": port,
                         "findings": kinds[:8], "ts": time.time()})
                self._respond(client, 502, "response blocked by mandate: %s"
                              % ", ".join(kinds[:3]))
                return
            status_line = resp_text.split("\r\n")[0]
            keep = ["content-type", "content-encoding", "cache-control", "date"]
            out = [status_line]
            for key in keep:
                if key in resp_headers:
                    out.append("%s: %s" % (key, resp_headers[key]))
            out.append("Content-Length: %d" % len(resp_body))
            out.append("Connection: close")
            client.sendall(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + resp_body)
        finally:
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _read_until(sock, marker: bytes, limit: int = 65536) -> bytes:
        data = b""
        while marker not in data and len(data) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    @staticmethod
    def _read_exact(sock, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = sock.recv(min(65536, size - len(data)))
            if not chunk:
                break
            data += chunk
        return data

    @staticmethod
    def _read_chunked(sock, limit: int = 2_000_000) -> bytes:
        data = b""
        while len(data) < limit:
            line = b""
            while not line.endswith(b"\r\n"):
                chunk = sock.recv(1)
                if not chunk:
                    return data
                line += chunk
            try:
                size = int(line.strip().split(b";")[0], 16)
            except ValueError:
                return data
            if size == 0:
                sock.recv(2)
                return data
            data += _read_n(sock, size)
            sock.recv(2)
        return data

    def _respond(self, sock, status: int, message: str) -> None:
        body = message.encode("utf-8")
        sock.sendall(("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"
                      "Content-Length: %d\r\nConnection: close\r\n\r\n"
                      % (status, "Blocked" if status >= 400 else "OK", len(body))
                      ).encode("latin-1") + body)

    def _pipe(self, upstream: socket.socket) -> None:
        self.connection.settimeout(30)
        upstream.settimeout(30)
        stop = threading.Event()

        def pump(src, dst):
            try:
                while not stop.is_set():
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                stop.set()

        t = threading.Thread(target=pump, args=(self.connection, upstream), daemon=True)
        t.start()
        pump(upstream, self.connection)
        t.join(timeout=2)


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(policy: dict, host: str = "127.0.0.1", port: int = 3128,
          ledger_path: str | None = None) -> ProxyServer:
    server = ProxyServer((host, port), _Handler)
    server.policy = policy  # type: ignore[attr-defined]
    server.ledger_path = ledger_path  # type: ignore[attr-defined]
    return server


def run_forever(policy: dict, host: str, port: int, ledger_path: str | None) -> None:
    server = serve(policy, host, port, ledger_path)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def summary(ledger_path: str) -> dict:
    if not os.path.exists(ledger_path):
        return {"records": 0}
    counts: dict[str, int] = {}
    for line in open(ledger_path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        body = (json.loads(line) or {}).get("body") or {}
        if body.get("action") != "egress":
            continue
        key = body.get("decision", "?") + ":" + str(body.get("code"))
        counts[key] = counts.get(key, 0) + 1
    return {"records": sum(counts.values()), "by_code": counts}
