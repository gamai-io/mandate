"""MCP manifest pinning and a gating stdio proxy (Phase 1).

The lock records a signed hash of every tool description/schema. A changed
manifest (tool poisoning, rug-pull) is denied before tools are exposed or calls
are forwarded.
"""
from __future__ import annotations

import json
import select
import shlex
import subprocess
import sys
import threading
import time

from . import core, sign

MCP_NAMESPACE = "mandate-mcp"


class McpError(core.MandateError):
    pass


def tool_fingerprint(tool: dict) -> str:
    return core.sha256(core.jcs({
        "name": tool.get("name"),
        "description": tool.get("description") or "",
        "inputSchema": tool.get("inputSchema") or {},
    }))


def manifest_from_tools(server: str, tools: list[dict], version: str = "") -> dict:
    return {
        "v": 1,
        "server": str(server),
        "version": str(version),
        "tools": {str(t.get("name")): tool_fingerprint(t) for t in tools
                  if isinstance(t, dict) and t.get("name")},
    }


def manifest_hash(manifest: dict) -> str:
    return core.sha256(core.jcs({
        "v": 1,
        "server": manifest.get("server"),
        "version": manifest.get("version") or "",
        "tools": manifest.get("tools") or {},
    }))


def build_lock(manifest: dict, key_path: str, signer: str) -> dict:
    body = {
        "v": 1,
        "server": manifest["server"],
        "version": manifest.get("version") or "",
        "manifest_hash": manifest_hash(manifest),
        "tools": manifest["tools"],
    }
    signature = {
        "alg": "ssh-ed25519",
        "namespace": MCP_NAMESPACE,
        "signer": str(signer),
        "key_id": sign.fingerprint(_pubkey_blob(key_path)),
        "value": sign.sign(core.jcs(body), key_path, MCP_NAMESPACE),
    }
    lock = dict(body)
    lock["signature"] = signature
    return lock


def _pubkey_blob(key_path: str) -> str:
    try:
        with open(str(key_path) + ".pub", encoding="utf-8") as fh:
            tokens = fh.read().split()
    except OSError as exc:
        raise McpError("public key not found") from exc
    for idx, token in enumerate(tokens):
        if token.startswith(("ssh-", "ecdsa-", "sk-")) and idx + 1 < len(tokens):
            return tokens[idx + 1]
    raise McpError("invalid public key")


def verify_lock(lock: dict, signers_path: str,
                revoked_path: str | None = None) -> bool:
    signature = (lock or {}).get("signature") or {}
    if signature.get("alg") != "ssh-ed25519":
        return False
    body = {key: value for key, value in lock.items() if key != "signature"}
    if not sign.verify(core.jcs(body), str(signature.get("signer") or ""),
                       str(signature.get("value") or ""), signers_path,
                       MCP_NAMESPACE, revoked_path=revoked_path):
        return False
    expected = manifest_hash({"server": body.get("server"),
                              "version": body.get("version"),
                              "tools": body.get("tools") or {}})
    return expected == body.get("manifest_hash")


def check_manifest(lock: dict, manifest: dict) -> bool:
    return (str(lock.get("server")) == str(manifest.get("server"))
            and str(lock.get("manifest_hash"))
            == manifest_hash(manifest)
            and (lock.get("tools") or {}) == (manifest.get("tools") or {}))


def _read_response(proc, want_id, timeout: float) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [],
                                    max(0.05, deadline - time.time()))
        if not ready:
            continue
        line = proc.stdout.readline()
        if not line:
            raise McpError("MCP server closed the stream")
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get("id") == want_id:
            return message
    raise McpError("MCP server response timeout")


def probe(cmd: str, timeout: float = 10, server: str = "") -> dict:
    args = shlex.split(str(cmd))
    if not args:
        raise McpError("empty MCP command")
    try:
        proc = subprocess.Popen(args, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except OSError as exc:
        raise McpError("cannot start MCP server: %s" % str(exc)[:120]) from exc
    try:
        init = {"jsonrpc": "2.0", "id": "mandate-init",
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05",
                           "capabilities": {},
                           "clientInfo": {"name": "mandate",
                                          "version": core.VERSION}}}
        proc.stdin.write(json.dumps(init) + "\n")
        proc.stdin.flush()
        response = _read_response(proc, "mandate-init", timeout)
        if "error" in response:
            raise McpError("initialize failed")
        proc.stdin.write(json.dumps({"jsonrpc": "2.0",
                                     "method": "notifications/initialized"})
                         + "\n")
        proc.stdin.flush()
        request = {"jsonrpc": "2.0", "id": "mandate-tools",
                   "method": "tools/list"}
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()
        response = _read_response(proc, "mandate-tools", timeout)
        if "error" in response:
            raise McpError("tools/list failed")
        tools = (response.get("result") or {}).get("tools") or []
        return manifest_from_tools(server, tools)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def proxy(lock: dict, cmd: str, signers_path: str,
          verify_calls: bool = False, revoked_path: str | None = None,
          in_stream=None, out_stream=None, taint: dict | None = None,
          mcp_policy: dict | None = None, ledger: str | None = None,
          audience: str = "") -> int:
    if not verify_lock(lock, signers_path, revoked_path=revoked_path):
        raise McpError("MCP lock signature invalid")
    in_stream = in_stream or sys.stdin
    out_stream = out_stream or sys.stdout
    taint = taint or {}
    sources = {str(item) for item in (taint.get("sources") or [])}
    effects = {str(item) for item in (taint.get("effects") or [])}
    require_grant = bool(taint.get("require_grant", True))
    ledger_path = ledger or "mcp_ledger.jsonl"
    tainted = False
    args = shlex.split(str(cmd))
    proc = subprocess.Popen(args, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=None,
                            text=True, bufsize=1)
    pending: dict = {}
    lock_tools = lock.get("tools") or {}

    def deny(mid, message_text: str) -> None:
        if mid is not None:
            out_stream.write(json.dumps({
                "jsonrpc": "2.0", "id": mid,
                "error": {"code": -32003, "message": message_text}}) + "\n")
            out_stream.flush()

    def authorize_effect(name: str, arguments: dict, mandate) -> str:
        if not isinstance(mandate, dict):
            return "mandate: grant required for effect tool '%s'" % name
        intent = mandate.get("intent") or {}
        grant = mandate.get("grant") or {}
        try:
            intent = core.normalize_intent(intent)
        except core.MandateError:
            return "mandate: invalid intent"
        effect = intent.get("effect") or {}
        if str(effect.get("kind")) != "mcp.call":
            return "mandate: grant is not for mcp.call"
        if str(effect.get("target")) != name:
            return "mandate: grant target does not match tool"
        args_sha = core.sha256(core.jcs(arguments))
        if str((effect.get("params") or {}).get("args_sha256")) != args_sha:
            return "mandate: grant arguments do not match"
        if tainted and not any(
                entry.get("type") == "data_ref"
                and str(entry.get("source") or "").strip()
                for entry in (intent.get("provenance") or [])):
            return "mandate: data_ref required after untrusted content"
        try:
            core.redeem(intent, grant, signers_path, ledger_path,
                        policy=mcp_policy, audience=audience or None,
                        require_audience=bool(audience),
                        revoked_path=revoked_path)
        except core.MandateError as exc:
            return "mandate: grant rejected (%s)" % type(exc).__name__
        return ""

    def reader() -> None:
        for line in proc.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                out_stream.write(line)
                out_stream.flush()
                continue
            method = pending.pop(message.get("id"), None)
            if method == "tools/list" and "result" in message:
                manifest = manifest_from_tools(
                    str(lock.get("server")),
                    (message["result"] or {}).get("tools") or [],
                    str(lock.get("version") or ""))
                if not check_manifest(lock, manifest):
                    message = {
                        "jsonrpc": "2.0", "id": message.get("id"),
                        "error": {"code": -32001,
                                  "message": "mandate: MCP manifest mismatch "
                                             "(possible rug-pull)"}}
            out_stream.write(json.dumps(message, ensure_ascii=False) + "\n")
            out_stream.flush()

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    try:
        for line in in_stream:
            text = line.strip()
            if not text:
                continue
            try:
                message = json.loads(text)
            except ValueError:
                continue
            method = message.get("method")
            mid = message.get("id")
            if method == "tools/call":
                params = message.get("params") or {}
                name = str(params.get("name") or "")
                arguments = params.get("arguments")
                if not isinstance(arguments, dict):
                    arguments = {}
                mandate = arguments.pop("_mandate", None)
                if name not in lock_tools:
                    deny(mid, "mandate: tool not in lock: %s" % name)
                    continue
                if name in sources:
                    tainted = True
                if name in effects and require_grant:
                    reason = authorize_effect(name, arguments, mandate)
                    if reason:
                        deny(mid, reason)
                        continue
                params["arguments"] = arguments
                message["params"] = params
                if verify_calls:
                    try:
                        manifest = probe(cmd, server=str(lock.get("server") or ""))
                        if not check_manifest(lock, manifest):
                            raise McpError("manifest mismatch")
                    except Exception as exc:
                        if mid is not None:
                            out_stream.write(json.dumps({
                                "jsonrpc": "2.0", "id": mid,
                                "error": {"code": -32001,
                                          "message": "mandate: verify failed: %s"
                                                     % str(exc)[:120]}}) + "\n")
                            out_stream.flush()
                        continue
            if mid is not None and method == "tools/list":
                pending[mid] = method
            proc.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
            proc.stdin.flush()
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    return 0
