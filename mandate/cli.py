from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from . import (
    agentwatch,
    anchor,
    approval_page,
    containment,
    core,
    demo,
    detect,
    egress,
    governance,
    policy_tools,
    sign,
    svid,
    warden,
)
from . import report as audit_report
from . import ship as ship_mod


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _emit(obj, out: str | None) -> None:
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)


def _read(path: str):
    return core.load_json(path)


def _cmd_init(args) -> int:
    base = os.path.abspath(args.dir)
    for sub in ("mandate", "trust", "examples"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)
    created = []
    policy_target = os.path.join(base, "mandate", "policy.json")
    if not os.path.exists(policy_target):
        with open(core.DEFAULT_POLICY, encoding="utf-8") as src, \
                open(policy_target, "w", encoding="utf-8") as dst:
            dst.write(src.read())
        created.append(policy_target)
    signers_target = os.path.join(base, "trust", "allowed_signers")
    if not os.path.exists(signers_target):
        with open(signers_target, "w", encoding="utf-8") as fh:
            fh.write('# <name> namespaces="mandate" ssh-ed25519 AAAAC3Nza... comment\n')
        created.append(signers_target)
    revoked_target = os.path.join(base, "trust", "revoked_signers")
    if not os.path.exists(revoked_target):
        with open(revoked_target, "w", encoding="utf-8") as fh:
            fh.write("# SHA256:<fingerprint>  reason\n")
        created.append(revoked_target)
    example = os.path.join(base, "examples", "intent.json")
    if not os.path.exists(example):
        demo = {
            "v": 1,
            "actor": {"agent": "opencode@host", "session": "demo"},
            "effect": {"kind": "payment.send", "target": "Example Supplier",
                       "amount": {"value": 1170.0, "currency": "BAM"},
                       "params": {"ref": "faktura-1"}},
            "requested_by": "owner", "nonce": "demo-1",
            "provenance": [{"type": "data_ref", "source": "erp:vendors:1"}],
        }
        with open(example, "w", encoding="utf-8") as fh:
            json.dump(demo, fh, indent=2)
            fh.write("\n")
        created.append(example)
    config = {
        "host": "127.0.0.1", "port": 8899,
        "policy": policy_target, "signers": signers_target,
        "revoked": revoked_target,
        "ledger": os.path.join(base, "ledger.jsonl"),
        "nonce_db": os.path.join(base, "broker", "used.sqlite"),
        "effects_dir": os.path.join(base, "effects"),
        "outbox": os.path.join(base, "outbox"),
        "broker_name": "local-broker",
        "smtp": {"mode": "dry_run", "outbox": os.path.join(base, "outbox")},
    }
    config_path = os.path.join(base, "mandate", "config.json")
    if not os.path.exists(config_path):
        with open(config_path, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)
            fh.write("\n")
        created.append(config_path)
    _emit({"ok": True, "dir": base, "created": created}, None)
    return 0


def _cmd_doctor(args) -> int:
    import shutil
    out = {
        "python": sys.version.split()[0],
        "ssh_keygen": bool(shutil.which("ssh-keygen")),
        "policy": args.policy,
        "signers": args.signers,
        "signers_present": os.path.exists(args.signers),
    }
    try:
        policy = core.load_policy(args.policy)
        out["policy_ok"] = True
        out["effects"] = len(policy["effects"])
    except (core.MandateError, OSError, ValueError) as exc:
        out["policy_ok"] = False
        out["policy_error"] = str(exc)[:160]
    _emit(out, None)
    return 0 if (out["ssh_keygen"] and out.get("policy_ok")
                 and out["signers_present"]) else 1


def _cmd_log(args) -> int:
    from . import log as mlog
    cmd = getattr(args, "log_cmd", None)
    try:
        if cmd == "head":
            leaves = mlog.leaves_from_ledger(args.ledger)
            log_id = args.log_id or mlog.log_id_from_key(args.log_key)
            payload = mlog.sth_payload(args.log_name, log_id, len(leaves),
                                       mlog.root_hex(leaves))
            _emit(mlog.sign_sth(payload, args.log_key), args.out)
            return 0
        if cmd == "sth-verify":
            ok = mlog.verify_sth(_read(args.sth), args.signers,
                                 revoked_path=args.revoked)
            _emit({"valid": ok}, None)
            return 0 if ok else 1
        if cmd == "proof":
            leaves = mlog.leaves_from_ledger(args.ledger)
            _emit(mlog.inclusion_proof(leaves, args.index), args.out)
            return 0
        if cmd == "verify-inclusion":
            # an inclusion proof is only meaningful against a *signed* tree
            # head; verifying against the proof's own root proves nothing
            if not args.sth:
                _emit({"valid": False, "error": "SthRequired",
                       "note": "pass a signed --sth; a proof checked against its "
                               "own root is self-consistent, not evidence"}, None)
                return 2
            try:
                sth = _read(args.sth)
                entry = _read(args.entry)
                proof = _read(args.proof)
            except (OSError, ValueError) as exc:
                _emit({"valid": False, "error": "Unreadable",
                       "message": str(exc)[:200]}, None)
                return 2
            signature_ok = mlog.verify_sth(sth, args.signers,
                                           revoked_path=args.revoked)
            payload = sth.get("sth") if isinstance(sth, dict) else {}
            root = (payload or {}).get("root_hash")
            size = (payload or {}).get("tree_size")
            if not isinstance(root, str) or not isinstance(size, int):
                _emit({"valid": False, "error": "SthIncomplete",
                       "message": "the signed tree head has no root_hash/tree_size",
                       "sth_verified": signature_ok}, None)
                return 1
            inclusion = mlog.verify_inclusion_proof(entry, proof,
                                                    root=root, size=size)
            _emit({"valid": bool(signature_ok and inclusion),
                   "inclusion": inclusion, "sth_verified": signature_ok}, None)
            return 0 if (signature_ok and inclusion) else 1
        if cmd == "consistency":
            leaves = mlog.leaves_from_ledger(args.ledger)
            _emit(mlog.consistency_proof(leaves, args.first, args.second),
                  args.out)
            return 0
        if cmd == "verify-consistency":
            old = _read(args.old)
            new = _read(args.new)
            proof = _read(args.proof)
            old_sth = old.get("sth") or {}
            new_sth = new.get("sth") or {}
            ok = mlog.verify_consistency_proof(
                proof, first_root=old_sth.get("root_hash"),
                second_root=new_sth.get("root_hash"),
                first=old_sth.get("tree_size"),
                second=new_sth.get("tree_size"))
            _emit({"valid": ok}, None)
            return 0 if ok else 1
    except (core.MandateError, OSError, ValueError) as exc:
        _emit({"error": type(exc).__name__, "message": str(exc)[:200]}, None)
        return 3
    _emit({"error": "unknown_log_command"}, None)
    return 2


def _pq_keys(path):
    """Read allowed ML-DSA public keys: one base64 key per line, optional `name key`."""
    if not path:
        return None
    keys = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            keys.append(line.split()[-1])
    return keys


def _cmd_witness(args) -> int:
    from . import witness as mwit
    cmd = getattr(args, "witness_cmd", None)
    try:
        if cmd in ("accept", "verify"):
            sth = _read(args.sth)
            proof = _read(args.proof) if args.proof else None
            out = mwit.accept(sth, proof, args.signers, args.state,
                              revoked_path=args.revoked,
                              dry_run=(cmd == "verify"),
                              key_path=getattr(args, "key", None),
                              signer=getattr(args, "signer", "witness"),
                              pq_key_path=getattr(args, "pq_key", None))
            _emit(out, None)
            return 0
        if cmd == "show":
            state = mwit.load_state(args.state)
            _emit({"state": state}, None)
            return 0 if state else 1
        if cmd == "push":
            payload = json.dumps({
                "sth": _read(args.sth),
                "proof": _read(args.proof) if args.proof else None,
            }).encode("utf-8")
            request = urllib.request.Request(
                args.url.rstrip("/") + "/sth", data=payload,
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + args.token},
                method="POST")
            try:
                with urllib.request.urlopen(request, timeout=30) as resp:
                    _emit(json.loads(resp.read().decode("utf-8")), None)
                    return 0
            except urllib.error.HTTPError as exc:
                try:
                    _emit(json.loads(exc.read().decode("utf-8")), None)
                except ValueError:
                    _emit({"error": "http", "status": exc.code}, None)
                return 1
        if cmd == "serve":
            if not args.token:
                _emit({"error": "token_required"}, None)
                return 2
            if args.host not in ("127.0.0.1", "::1", "localhost") and \
                    not args.allow_remote:
                _emit({"error": "remote_requires_allow_remote"}, None)
                return 2
            server = mwit.make_server(args.host, args.port, args.state,
                                      args.signers, args.token,
                                      revoked_path=args.revoked,
                                      rate_per_min=args.rate_limit_per_min,
                                      rate_burst=args.rate_burst)
            host, port = server.server_address[:2]
            print("mandate-witness listening on http://%s:%s" % (host, port),
                  flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
    except (core.MandateError, OSError, ValueError) as exc:
        _emit({"error": type(exc).__name__, "message": str(exc)[:200]}, None)
        return 3
    _emit({"error": "unknown_witness_command"}, None)
    return 2


def _cmd_approver(args) -> int:
    from . import approver as mapprover
    from . import notify as mnotify
    if getattr(args, "approver_cmd", None) != "serve":
        _emit({"error": "unknown_approver_command"}, None)
        return 2
    if not os.path.exists(args.key):
        _emit({"error": "key_not_found", "key": args.key}, None)
        return 2
    if args.host not in ("127.0.0.1", "::1", "localhost") and not args.token:
        _emit({"error": "remote_requires_token"}, None)
        return 2
    if args.host not in ("127.0.0.1", "::1", "localhost") and \
            not args.allow_remote:
        _emit({"error": "remote_requires_allow_remote"}, None)
        return 2
    if getattr(args, "page", False):
        server = approval_page.serve(
            args.key, args.approver, args.host, args.port,
            audience=args.audience, ttl=args.ttl, wait_s=args.wait,
            token=args.token, ledger=getattr(args, "ledger", "") or "",
            allow_remote=getattr(args, "allow_remote", False),
            passkeys_path=getattr(args, "passkeys", "") or "",
            rp_id=getattr(args, "rp_id", "127.0.0.1"),
            origin=getattr(args, "origin", "") or
                   "http://127.0.0.1:%d" % args.port,
            require_passkey=getattr(args, "require_passkey", False),
            policy_path=getattr(args, "policy", None))
        host, port = server.server_address[:2]
        print("mandate approval page on http://%s:%s (approver=%s) - open it in a "
              "browser on this host" % (host, port, args.approver), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    token = os.environ.get(args.telegram_token_env, "") \
        if args.telegram_token_env else ""
    chat = args.telegram_chat or os.environ.get("TELEGRAM_CHAT_ID", "")
    notifier = mnotify.TelegramNotifier(token, chat) if token and chat else None
    approver = mapprover.Approver(args.key, args.approver,
                                  audience_default=args.audience,
                                  ttl_default=args.ttl,
                                  notifier=notifier,
                                  rate_per_min=args.rate_limit_per_min,
                                  rate_burst=args.rate_burst,
                                  policy_path=getattr(args, "policy", None))
    server = mapprover.make_server(args.host, args.port, approver,
                                   token=args.token)
    host, port = server.server_address[:2]
    print("mandate-approver listening on http://%s:%s (approver=%s, notify=%s)"
          % (host, port, args.approver, bool(notifier)), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _cmd_request(args) -> int:
    body = json.dumps({
        "intent": _read(args.intent),
        "audience": args.audience,
        "ttl": args.ttl,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = "Bearer " + args.token
    request = urllib.request.Request(
        args.approver.rstrip("/") + "/request", data=body, headers=headers,
        method="POST")
    try:
        with urllib.request.urlopen(request, timeout=3600) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            _emit(json.loads(exc.read().decode("utf-8")), None)
        except ValueError:
            _emit({"error": "http", "status": exc.code}, None)
        return 1
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result.get("grant") or {}, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    _emit(result, None)
    return 0


def _cmd_export(args) -> int:
    from . import export as mexport
    if args.cmd == "export":
        if args.proof and not args.sth:
            _emit({"error": "SthRequired",
                   "message": "a proof must be checked against a signed tree "
                              "head; pass --sth"}, None)
            return 2
        bundle = mexport.build_bundle(
            _read(args.receipt), _read(args.intent), _read(args.grant),
            _read(args.proof) if args.proof else None,
            key_path=args.key, signer=args.signer,
            sth=_read(args.sth) if args.sth else None,
            witness_state=(_read(args.witness_state)
                           if args.witness_state else None))
        _emit(bundle, args.out)
        return 0
    result = mexport.verify_bundle_file(args.bundle, args.signers,
                                        revoked_path=args.revoked)
    _emit(result, None)
    return 0 if result.get("valid") else 1


def _add_sandbox_args(parser) -> None:
    parser.add_argument("--sandbox",
                        choices=("local", "docker", "gvisor", "firecracker"),
                        default="local")
    parser.add_argument("--sandbox-image", default="python:3.12-slim")
    parser.add_argument("--sandbox-mount", action="append", default=[])
    parser.add_argument("--sandbox-workdir", default="")
    parser.add_argument("--sandbox-net", action="store_true")
    parser.add_argument("--sandbox-cmd-template", default="")


def _cmd_mcp(args) -> int:
    from . import mcp as mmcp
    from . import sandbox as msandbox
    cmd = getattr(args, "mcp_cmd", None)
    server_cmd = getattr(args, "mcp_server_cmd", "")
    try:
        runner = msandbox.build_runner(
            getattr(args, "sandbox", "local"),
            getattr(args, "sandbox_image", "python:3.12-slim"),
            getattr(args, "sandbox_mount", None),
            getattr(args, "sandbox_workdir", ""),
            getattr(args, "sandbox_net", False),
            getattr(args, "sandbox_cmd_template", ""))
        if cmd == "lock":
            manifest = mmcp.probe(server_cmd, server=args.server, runner=runner)
            lock = mmcp.build_lock(manifest, args.key, args.signer)
            _emit(lock, args.out)
            return 0
        if cmd == "verify":
            lock = _read(args.lock)
            manifest = mmcp.probe(server_cmd,
                                  server=str(lock.get("server") or ""),
                                  runner=runner)
            valid = (mmcp.verify_lock(lock, args.signers,
                                      revoked_path=args.revoked)
                     and mmcp.check_manifest(lock, manifest))
            _emit({"valid": valid, "server": lock.get("server"),
                   "tools": sorted((lock.get("tools") or {}).keys())}, None)
            return 0 if valid else 1
        if cmd == "proxy":
            taint = _read(args.taint) if args.taint else {}
            return mmcp.proxy(
                _read(args.lock), server_cmd, args.signers,
                verify_calls=args.verify_calls, revoked_path=args.revoked,
                taint=taint, mcp_policy=core.load_policy(args.policy),
                ledger=args.mcp_ledger, audience=args.mcp_audience,
                runner=runner)
    except (core.MandateError, OSError, ValueError) as exc:
        if cmd == "proxy":
            print("mandate mcp proxy: %s" % str(exc)[:200], file=sys.stderr)
        else:
            _emit({"error": type(exc).__name__, "message": str(exc)[:200]},
                  None)
        return 3
    _emit({"error": "unknown_mcp_command"}, None)
    return 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mandate")
    parser.add_argument("--policy", default=None)
    parser.add_argument("--signers", default=os.environ.get(
        "MANDATE_SIGNERS", "trust/allowed_signers"))
    parser.add_argument("--revoked", default=os.environ.get(
        "MANDATE_REVOKED", "trust/revoked_signers"))
    sub = parser.add_subparsers(dest="cmd")

    p_check = sub.add_parser("check")
    p_check.add_argument("--intent", required=True)

    p_prop = sub.add_parser("propose")
    p_prop.add_argument("--intent", required=True)
    p_prop.add_argument("--out", default=None)

    p_grant = sub.add_parser("grant")
    p_grant.add_argument("--proposal", required=True)
    p_grant.add_argument("--approver", required=True)
    p_grant.add_argument("--key", required=True)
    p_grant.add_argument("--ttl", type=int, default=900)
    p_grant.add_argument("--audience", default="",
                         help="broker name this grant is bound to")
    p_grant.add_argument("--out", default=None)

    p_redeem = sub.add_parser("redeem")
    p_redeem.add_argument("--intent", required=True)
    p_redeem.add_argument("--grant", required=True)
    p_redeem.add_argument("--ledger", default="ledger.jsonl")
    p_redeem.add_argument("--allow-self", action="store_true")
    p_redeem.add_argument("--svid", action="append", default=None,
                          help="agent token (repeatable: child first, then parents)")
    p_redeem.add_argument("--svid-audience", dest="svid_audience", default=None)
    p_redeem.add_argument("--audience", default=None,
                          help="name of this broker; required when the grant is bound "
                               "to an audience (grant --audience)")
    p_redeem.add_argument("--key", default=None, help="sign the receipt")
    p_redeem.add_argument("--signer", default=None)
    p_redeem.add_argument("--instructions", default=None,
                          help="store of signed instructions the intent may cite")
    p_redeem.add_argument("--observe", action="store_true",
                          help="record what would happen without spending the grant")
    p_redeem.add_argument("--signer-cmd", dest="signer_cmd", default=None,
                          help="external HSM/KMS adapter that prints {sig, signer}")

    p_halt = sub.add_parser("halt")
    p_halt.add_argument("--reason", required=True)
    p_halt.add_argument("--actor", default="owner")
    p_halt.add_argument("--ledger", default="ledger.jsonl")

    p_resume = sub.add_parser("resume")
    p_resume.add_argument("--reason", required=True)
    p_resume.add_argument("--actor", default="owner")
    p_resume.add_argument("--ledger", default="ledger.jsonl")

    p_limits = sub.add_parser("limits")
    p_limits.add_argument("--ledger", default="ledger.jsonl")
    p_limits.add_argument("--policy", default=argparse.SUPPRESS)

    p_inv = sub.add_parser("inventory")
    p_inv.add_argument("--ledger", default="ledger.jsonl")
    p_inv.add_argument("--out", default=None)
    p_inv.add_argument("--csv", default=None)
    p_inv.add_argument("--svid", action="append", default=None)
    p_inv.add_argument("--owner", action="append", default=None, help="agent=owner")

    p_chg = sub.add_parser("change")
    p_chg.add_argument("action", choices=("record", "list", "verify", "models"))
    p_chg.add_argument("--ledger", default="ledger.jsonl")
    p_chg.add_argument("--file", default=None)
    p_chg.add_argument("--approver", default=None)
    p_chg.add_argument("--key", default=None)
    p_chg.add_argument("--reason", default="")
    p_chg.add_argument("--signers", default=argparse.SUPPRESS)
    p_chg.add_argument("--signer-cmd", dest="signer_cmd", default=None)
    p_chg.add_argument("--ticket", default="", help="PROJECT-123 that authorised the change")
    p_chg.add_argument("--require-ticket", dest="require_ticket", action="store_true",
                       help="refuse a change record that has no valid ticket id")
    p_chg.add_argument("--model", default="", help="model version this change pins (name@ver)")
    p_chg.add_argument("--model-digest", dest="model_digest", default="",
                       help="sha256:<64 hex> of the pinned model artefact")
    p_chg.add_argument("--dir", default=".", help="root for action=verify")

    p_watch = sub.add_parser("watch")
    p_watch.add_argument("--log", required=True, help="JSONL access log")
    p_watch.add_argument("--window", type=int, default=agentwatch.WINDOW)
    p_watch.add_argument("--ledger", default=None, help="write alerts into this ledger")
    p_watch.add_argument("--min-level", dest="min_level", choices=("low", "medium", "high"),
                         default="medium")

    p_ship = sub.add_parser("ship")
    p_ship.add_argument("--ledger", default="ledger.jsonl")
    p_ship.add_argument("--url", required=True)
    p_ship.add_argument("--token", default="")
    p_ship.add_argument("--offset", default="ship.state")
    p_ship.add_argument("--batch", type=int, default=200)
    p_ship.add_argument("--dry-run", dest="dry_run", action="store_true")

    p_taint = sub.add_parser("taint", help="flagged input becomes provenance the policy refuses")
    p_taint.add_argument("action", choices=["mark", "clear", "show", "provenance"])
    p_taint.add_argument("--session", default="")
    p_taint.add_argument("--source", default="")
    p_taint.add_argument("--kind", default="data_ref")
    p_taint.add_argument("--reason", default="")
    p_taint.add_argument("--covers", default="", help="comma-separated fields")
    p_taint.add_argument("--ledger", default="ledger.jsonl")

    p_fw = sub.add_parser("firewall", help="content gate: secrets out, injections in")
    p_fw.add_argument("action", choices=["scan", "redact", "decide", "selftest"])
    p_fw.add_argument("--text", default=None)
    p_fw.add_argument("--file", default=None)
    p_fw.add_argument("--response", default=None, help="inbound text to scan as well")
    p_fw.add_argument("--out", "-o", default=None)

    p_hw = sub.add_parser("hardware", help="which signing keys are hardware-backed")
    p_hw.add_argument("action", choices=["list", "check"], nargs="?", default="list")
    p_hw.add_argument("--signers", default=argparse.SUPPRESS)
    p_hw.add_argument("--name", default=None)
    p_hw.add_argument("--signature", default=None, help="SSHSIG file: check the key that signed")

    p_cap = sub.add_parser("cap", help="capability tokens that can only narrow")
    p_cap.add_argument("action", choices=["mint", "attenuate", "verify", "check"])
    p_cap.add_argument("--kinds", default="", help="comma-separated effect kinds")
    p_cap.add_argument("--max-amount", dest="max_amount", type=float, default=None)
    p_cap.add_argument("--currency", default=None)
    p_cap.add_argument("--targets", default="", help="comma-separated targets")
    # bez --ttl: mint uzima 3600 s, attenuate nasljeđuje preostali rok roditelja
    p_cap.add_argument("--ttl", type=int, default=None)
    p_cap.add_argument("--max-uses", dest="max_uses", type=int, default=1)
    p_cap.add_argument("--issuer", default=None)
    p_cap.add_argument("--subject", default=None)
    p_cap.add_argument("--parent", default=None)
    p_cap.add_argument("--token", default=None)
    p_cap.add_argument("--chain", default="", help="comma-separated token files, root first")
    p_cap.add_argument("--intent", default=None)
    p_cap.add_argument("--key", default=None)
    p_cap.add_argument("--signers", default=argparse.SUPPRESS)
    p_cap.add_argument("--out", "-o", default=None)

    p_disc = sub.add_parser("disclose", help="redacted view of a receipt (selective disclosure)")
    p_disc.add_argument("action", choices=["redact", "verify", "reveal"])
    p_disc.add_argument("--receipt", default=None)
    p_disc.add_argument("--view", default=None)
    p_disc.add_argument("--fields", default="", help="comma-separated paths, e.g. render.fields.target")
    p_disc.add_argument("--values", default=None, help="JSON object path -> value (reveal)")
    p_disc.add_argument("--expect-hash", dest="expect_hash", default=None)
    p_disc.add_argument("--key", default=None, help="sign the redacted view (who discloses)")
    p_disc.add_argument("--signer", default=None)
    p_disc.add_argument("--signers", default=argparse.SUPPRESS)
    p_disc.add_argument("--out", "-o", default=None)

    p_replay = sub.add_parser("replay", help="re-derive the decision from a bundle")
    p_replay.add_argument("--bundle", required=True)
    p_replay.add_argument("--policy", default=argparse.SUPPRESS)

    p_dsse = sub.add_parser("dsse", help="DSSE envelope over a receipt (interop)")
    p_dsse.add_argument("action", choices=["sign", "verify"])
    p_dsse.add_argument("--receipt", default=None, help="receipt body JSON (sign)")
    p_dsse.add_argument("--file", default=None, help="envelope JSON (verify)")
    p_dsse.add_argument("--key", default=None, help="signing key (sign)")
    p_dsse.add_argument("--signer", default=None, help="signer name (sign)")
    p_dsse.add_argument("--keyid", default=None, help="require this keyid (verify)")
    p_dsse.add_argument("--statement", action="store_true",
                        help="wrap as in-toto Statement v1 instead of a bare receipt")
    p_dsse.add_argument("--out", "-o", default=None)

    p_nonce = sub.add_parser("nonce")
    p_nonce.add_argument("action", choices=("serve", "check"))
    p_nonce.add_argument("--host", default="127.0.0.1")
    p_nonce.add_argument("--port", type=int, default=8899)
    p_nonce.add_argument("--db", default=None)
    p_nonce.add_argument("--token", default="")
    p_nonce.add_argument("--value", default=None, help="nonce to test with action=check")

    p_backup = sub.add_parser("backup")
    p_backup.add_argument("--ledger", default="ledger.jsonl")
    p_backup.add_argument("--out", default="backup")
    p_backup.add_argument("--anchors", default="anchors")

    p_restore = sub.add_parser("restore")
    p_restore.add_argument("--in", dest="archive", required=True)
    p_restore.add_argument("--out", default="restored")

    p_sbom = sub.add_parser("sbom")
    p_sbom.add_argument("--out", default="sbom.json")
    p_sbom.add_argument("--version", default="")

    p_pack = sub.add_parser("pack")
    p_pack.add_argument("--ledger", default="ledger.jsonl")
    p_pack.add_argument("--out", default="audit-pack")
    p_pack.add_argument("--svid", action="append", default=None)
    p_pack.add_argument("--owner", action="append", default=None)
    p_pack.add_argument("--controls", default=None)
    p_pack.add_argument("--signers", default=argparse.SUPPRESS)
    p_pack.add_argument("--anchors", default="anchors")
    p_pack.add_argument("--grant", action="append", default=None,
                        help="archive this grant in the pack (repeatable)")
    p_pack.add_argument("--intent", action="append", default=None,
                        help="archive this intent in the pack (repeatable)")
    p_pack.add_argument("--key", default=None)
    p_pack.add_argument("--signer", default=None)

    p_detect = sub.add_parser("detect")
    p_detect.add_argument("--ledger", default="ledger.jsonl")
    p_detect.add_argument("--policy", default=argparse.SUPPRESS)
    p_detect.add_argument("--svid", action="append", default=None)
    p_detect.add_argument("--write", action="store_true",
                          help="append findings as control records (type=alert)")
    p_detect.add_argument("--mcp-ledger", dest="mcp_ledger", default=None,
                          help="MCP proxy ledger: enables tool-sequence rules")
    p_detect.add_argument("--format", dest="fmt", default="json",
                          choices=("json", "cef", "leef", "jsonl"),
                          help="output format for the findings (SIEM: cef/leef)")

    p_svid = sub.add_parser("svid")
    p_svid.add_argument("action", choices=("issue", "verify", "delegate"))
    p_svid.add_argument("--token", default=None)
    p_svid.add_argument("--parent", default=None)
    p_svid.add_argument("--sub", default=None)
    p_svid.add_argument("--issuer", default=None)
    p_svid.add_argument("--key", default=None)
    p_svid.add_argument("--audience", default="local-broker")
    p_svid.add_argument("--scope", action="append", default=None)
    p_svid.add_argument("--ttl", type=int, default=300)
    p_svid.add_argument("--out", default=None)
    p_svid.add_argument("--allow-wildcard", dest="allow_wildcard", action="store_true")
    p_svid.add_argument("--signers", default=argparse.SUPPRESS)

    p_egress = sub.add_parser("egress")
    p_egress.add_argument("action", choices=("policy", "proxy", "check", "summary",
                                             "ca", "trust", "rules"))
    p_egress.add_argument("target", nargs="?", default=None, help="host:port for action=check")
    p_egress.add_argument("--policy", default=argparse.SUPPRESS)
    p_egress.add_argument("--allow", action="append", default=None)
    p_egress.add_argument("--out", default=None)
    p_egress.add_argument("--host", default="127.0.0.1")
    p_egress.add_argument("--port", type=int, default=3128)
    p_egress.add_argument("--ledger", default=None)
    p_egress.add_argument("--token-env", dest="token_env", default=None)
    p_egress.add_argument("--intercept", action="store_true",
                          help="terminate TLS and scan bodies (needs --ca-dir)")
    p_egress.add_argument("--ca-dir", dest="ca_dir", default=None)
    p_egress.add_argument("--upstream-ca", dest="upstream_ca", default=None,
                          help="extra trust anchor for the real origin")
    p_egress.add_argument("--uid", type=int, default=None, help="uid for action=rules")
    p_egress.add_argument("--proxy", dest="proxy_addr", default="127.0.0.1:3128")
    p_egress.add_argument("--check", action="store_true",
                          help="validate the ruleset with `nft -c` without applying it")
    p_egress.add_argument("--target", dest="target_opt", default=None,
                          help="host:port to test (same as the positional, avoids argparse ambiguity)")

    p_warden = sub.add_parser("warden")
    p_warden.add_argument("--pid", type=int, default=None)
    p_warden.add_argument("--pgid", type=int, default=None)
    p_warden.add_argument("--method", choices=("freeze", "kill", "vm-pause", "vm-resume"),
                          default="freeze")
    p_warden.add_argument("--vm-socket", dest="vm_socket", default=None)
    p_warden.add_argument("--timeout-ms", dest="timeout_ms", type=int, default=3000)
    p_warden.add_argument("--reason", default="")
    p_warden.add_argument("--actor", default="ops")
    p_warden.add_argument("--ledger", default=None)
    p_warden.add_argument("--resume", action="store_true")
    p_warden.add_argument("--cgroup", default=None)
    p_warden.add_argument("--attach", default=None)
    p_warden.add_argument("--quarantine", action="store_true")
    p_warden.add_argument("--uid", type=int, default=None)
    p_warden.add_argument("--undo", action="store_true")
    p_warden.add_argument("--key", default=None)
    p_warden.add_argument("--signer", default=None)
    p_warden.add_argument("--verify", action="store_true")
    p_warden.add_argument("--signers", default=argparse.SUPPRESS)

    p_ctl = sub.add_parser("controls", help="the twelve-row control matrix, as data")
    p_ctl.add_argument("--framework", default="", choices=("", "dora", "ai_act", "all"))
    p_ctl.add_argument("--status", default="", choices=("", "have", "partial", "gap"))
    p_ctl.add_argument("--summary", action="store_true")
    p_ctl.add_argument("--out", "-o", default=None)

    p_prov = sub.add_parser("provenance",
                            help="check PEP 740 attestations for a published version")
    p_prov.add_argument("--version", default=None, help="defaults to the installed version")
    p_prov.add_argument("--project", default="gama-mandate")
    p_prov.add_argument("--text", action="store_true", help="human summary instead of JSON")

    p_wv = sub.add_parser("worm-verify", help="verify an exported evidence pack offline")
    p_wv.add_argument("--dir", required=True)

    p_anchor = sub.add_parser("anchor")
    p_anchor.add_argument("--ledger", default="ledger.jsonl")
    p_anchor.add_argument("--tsa", action="append", default=None)
    p_anchor.add_argument("--out", default="anchors")
    p_anchor.add_argument("--ca", default=None)
    p_anchor.add_argument("--status", action="store_true",
                          help="report anchor age and whether it covers the current head")
    p_anchor.add_argument("--max-age-hours", dest="max_age_hours", type=float, default=24.0)

    p_anchor_verify = sub.add_parser("anchor-verify")
    p_anchor_verify.add_argument("--ledger", default="ledger.jsonl")
    p_anchor_verify.add_argument("--token", required=True)
    p_anchor_verify.add_argument("--ca", default=None)

    p_worm = sub.add_parser("worm-export")
    p_worm.add_argument("--ledger", default="ledger.jsonl")
    p_worm.add_argument("--out", default="worm")
    p_worm.add_argument("--retention-days", dest="retention_days", type=int, default=180)
    p_worm.add_argument("--anchors", default="anchors")

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--receipt", required=True)
    p_verify.add_argument("--intent", required=True)
    p_verify.add_argument("--grant", required=True)

    p_chain = sub.add_parser("chain")
    p_chain.add_argument("--ledger", default="ledger.jsonl")
    p_chain.add_argument("--signers", default=argparse.SUPPRESS, help="verify receipt signatures")
    p_chain.add_argument("--broker-signers", dest="broker_signers", default=None,
                         help="verify broker result entries")

    p_vr = sub.add_parser("verify-result")
    p_vr.add_argument("--entry", required=True)
    p_vr.add_argument("--broker-signers", dest="broker_signers", required=True)

    p_exec = sub.add_parser("execute")
    p_exec.add_argument("--broker", required=True)
    p_exec.add_argument("--intent", required=True)
    p_exec.add_argument("--grant", required=True)
    p_exec.add_argument("--allow-remote", action="store_true")

    p_policy = sub.add_parser("policy")
    p_policy.add_argument("action", nargs="?", default="show",
                          choices=("show", "lint", "explain", "diff"))
    p_policy.add_argument("--policy", default=argparse.SUPPRESS)
    p_policy.add_argument("--against", default=None, help="previous policy for diff")
    p_policy.add_argument("--effect", default=None, help="effect kind for explain")
    p_policy.add_argument("--amount", type=float, default=None)
    p_policy.add_argument("--currency", default=None)

    p_sandbox = sub.add_parser("sandbox")
    p_sandbox.add_argument("action", choices=("check",))

    p_cfg = sub.add_parser("config")
    p_cfg.add_argument("action", choices=("lock", "check", "list"))
    p_cfg.add_argument("--path", action="append", default=None,
                       help="file or glob to pin (repeatable)")
    p_cfg.add_argument("--dir", action="append", default=None,
                       help="directory whose usual agent config files are pinned")
    p_cfg.add_argument("--store", default="configs.json")
    p_cfg.add_argument("--ledger", default=None)

    p_mem = sub.add_parser("memory")
    p_mem.add_argument("action", choices=("add", "list", "verify", "revoke"))
    p_mem.add_argument("--store", default="instructions.jsonl")
    p_mem.add_argument("--text", default="")
    p_mem.add_argument("--scope", action="append", default=None,
                       help="kind:target, e.g. payment.send:Acme (repeatable)")
    p_mem.add_argument("--approver", default="")
    p_mem.add_argument("--key", default=None)
    p_mem.add_argument("--ttl", type=int, default=30 * 86400)
    p_mem.add_argument("--id", default=None)
    p_mem.add_argument("--reason", default="")
    p_mem.add_argument("--signers", default=os.environ.get("MANDATE_SIGNERS",
                                                           "trust/allowed_signers"))

    p_tool = sub.add_parser("tool")
    p_tool.add_argument("action", choices=("lock", "list", "verify"))
    p_tool.add_argument("--registry", default="tools.json")
    p_tool.add_argument("--name", default="")
    p_tool.add_argument("--file", default=None, help="schema file (lock)")
    p_tool.add_argument("--intent", default=None, help="intent to verify against")

    p_cont = sub.add_parser("contain")
    p_cont.add_argument("--pid", type=int, default=None)
    p_cont.add_argument("--minutes", type=int, default=15)
    p_cont.add_argument("--reason", default="")
    p_cont.add_argument("--ledger", default="ledger.jsonl")
    p_cont.add_argument("--extend", type=int, default=None, metavar="PID")
    p_cont.add_argument("--approver", default="")
    p_cont.add_argument("--key", default=None)
    p_cont.add_argument("--release", type=int, default=None, metavar="PID")
    p_cont.add_argument("--signers", default=os.environ.get("MANDATE_SIGNERS",
                                                           "trust/allowed_signers"))
    p_cont.add_argument("--sweep", action="store_true")

    p_dec = sub.add_parser("decisions")
    p_dec.add_argument("--ledger", default="ledger.jsonl")

    p_obs = sub.add_parser("observe-summary")
    p_obs.add_argument("--ledger", default="ledger.jsonl")
    p_obs.add_argument("--out", default=None)

    p_demo = sub.add_parser("demo")
    p_demo.add_argument("--dir", default=None, help="use this directory instead of a temp one")
    p_demo.add_argument("--keep", action="store_true", help="keep the temp directory")

    sub.add_parser("version")

    p_init = sub.add_parser("init")
    p_init.add_argument("--dir", default=".")

    p_doctor = sub.add_parser("doctor")
    p_doctor.add_argument("--policy", default=None)
    p_doctor.add_argument("--signers", default=os.environ.get(
        "MANDATE_SIGNERS", "trust/allowed_signers"))

    p_revoke = sub.add_parser("revoke")
    p_revoke.add_argument("--pub", required=True)
    p_revoke.add_argument("--reason", default="")

    sub.add_parser("signers")

    p_log = sub.add_parser("log")
    log_sub = p_log.add_subparsers(dest="log_cmd")
    p_lh = log_sub.add_parser("head")
    p_lh.add_argument("--ledger", required=True)
    p_lh.add_argument("--log-name", required=True)
    p_lh.add_argument("--log-key", required=True)
    p_lh.add_argument("--log-id", default=None)
    p_lh.add_argument("--out", default=None)
    p_ls = log_sub.add_parser("sth-verify")
    p_ls.add_argument("--sth", required=True)
    p_lp = log_sub.add_parser("proof")
    p_lp.add_argument("--ledger", required=True)
    p_lp.add_argument("--index", type=int, required=True)
    p_lp.add_argument("--out", default=None)
    p_li = log_sub.add_parser("verify-inclusion")
    p_li.add_argument("--entry", required=True)
    p_li.add_argument("--proof", required=True)
    p_li.add_argument("--sth", default=None)
    p_lc = log_sub.add_parser("consistency")
    p_lc.add_argument("--ledger", required=True)
    p_lc.add_argument("--first", type=int, required=True)
    p_lc.add_argument("--second", type=int, required=True)
    p_lc.add_argument("--out", default=None)
    p_lv = log_sub.add_parser("verify-consistency")
    p_lv.add_argument("--old", required=True)
    p_lv.add_argument("--new", required=True)
    p_lv.add_argument("--proof", required=True)

    p_wit = sub.add_parser("witness")
    wit_sub = p_wit.add_subparsers(dest="witness_cmd")
    p_wa = wit_sub.add_parser("accept")
    p_wa.add_argument("--state", required=True)
    p_wa.add_argument("--sth", required=True)
    p_wa.add_argument("--proof", default=None)
    p_wa.add_argument("--key", default=None,
                      help="witness signing key; without it the state is a claim, not a note")
    p_wa.add_argument("--signer", default="witness")
    p_wa.add_argument("--pq-key", dest="pq_key", default=None,
                      help="ML-DSA-65 key; makes the note hybrid (Ed25519 + ML-DSA)")
    p_wv = wit_sub.add_parser("verify")
    p_wv.add_argument("--state", required=True)
    p_wv.add_argument("--sth", required=True)
    p_wv.add_argument("--proof", default=None)
    p_ws = wit_sub.add_parser("show")
    p_ws.add_argument("--state", required=True)
    p_pq = sub.add_parser("pq")
    pq_sub = p_pq.add_subparsers(dest="pq_cmd")
    p_pqk = pq_sub.add_parser("keygen")
    p_pqk.add_argument("--out", required=True)
    p_wserve = wit_sub.add_parser("serve")
    p_wserve.add_argument("--state", required=True)
    p_wserve.add_argument("--token", default=os.environ.get(
        "MANDATE_WITNESS_TOKEN", ""))
    p_wserve.add_argument("--host", default="127.0.0.1")
    p_wserve.add_argument("--port", type=int, default=8898)
    p_wserve.add_argument("--allow-remote", action="store_true")
    p_wserve.add_argument("--rate-limit-per-min", type=float,
                          default=float(os.environ.get("MANDATE_RATE_PER_MIN", "0")))
    p_wserve.add_argument("--rate-burst", type=float,
                          default=float(os.environ.get("MANDATE_RATE_BURST", "0")))
    p_wpush = wit_sub.add_parser("push")
    p_wpush.add_argument("--url", required=True)
    p_wpush.add_argument("--sth", required=True)
    p_wpush.add_argument("--proof", default=None)
    p_wpush.add_argument("--token", default=os.environ.get(
        "MANDATE_WITNESS_TOKEN", ""))

    p_appr = sub.add_parser("approver")
    appr_sub = p_appr.add_subparsers(dest="approver_cmd")
    p_as = appr_sub.add_parser("serve")
    p_as.add_argument("--key", required=True)
    p_as.add_argument("--approver", required=True)
    p_as.add_argument("--audience", default="",
                      help="broker name a grant is bound to (a label the redeem "
                           "caller must repeat; it is not a credential)")
    p_as.add_argument("--policy", default=None,
                      help="policy file whose digest is bound into every grant")
    p_as.add_argument("--ttl", type=int, default=900)
    p_as.add_argument("--host", default="127.0.0.1")
    p_as.add_argument("--port", type=int, default=8897)
    p_as.add_argument("--token", default=os.environ.get(
        "MANDATE_APPROVER_TOKEN", ""))
    p_as.add_argument("--telegram-chat", default=os.environ.get(
        "TELEGRAM_CHAT_ID", ""))
    p_as.add_argument("--page", action="store_true",
                      help="serve a browser approval page instead of a terminal prompt")
    p_as.add_argument("--wait", type=float, default=300,
                      help="seconds a pending request waits for a human")
    p_as.add_argument("--ledger", default="", help="append approval decisions here")
    p_as.add_argument("--passkeys", default="", help="passkey registry (JSON, 0600)")
    p_as.add_argument("--rp-id", dest="rp_id", default="127.0.0.1")
    p_as.add_argument("--origin", default="", help="browser origin, e.g. http://127.0.0.1:8898")
    p_as.add_argument("--require-passkey", dest="require_passkey", action="store_true")
    p_as.add_argument("--telegram-token-env", default="TELEGRAM_BOT_TOKEN")
    p_as.add_argument("--rate-limit-per-min", type=float,
                      default=float(os.environ.get("MANDATE_RATE_PER_MIN", "0")))
    p_as.add_argument("--rate-burst", type=float,
                      default=float(os.environ.get("MANDATE_RATE_BURST", "0")))
    p_as.add_argument("--allow-remote", action="store_true")

    p_exp = sub.add_parser("export")
    p_exp.add_argument("--receipt", required=True)
    p_exp.add_argument("--intent", required=True)
    p_exp.add_argument("--grant", required=True)
    p_exp.add_argument("--proof", default=None)
    p_exp.add_argument("--sth", default=None,
                       help="signed tree head; required with --proof, because a "
                            "proof checked against its own root proves nothing")
    p_exp.add_argument("--witness-state", dest="witness_state", default=None)
    p_exp.add_argument("--key", required=True)
    p_exp.add_argument("--signer", default=None)
    p_exp.add_argument("--out", default=None)

    p_ev = sub.add_parser("export-verify")
    p_ev.add_argument("--bundle", required=True)

    p_mcp = sub.add_parser("mcp")
    mcp_sub = p_mcp.add_subparsers(dest="mcp_cmd")
    p_ml = mcp_sub.add_parser("lock")
    p_ml.add_argument("--cmd", dest="mcp_server_cmd", required=True)
    p_ml.add_argument("--server", required=True)
    p_ml.add_argument("--key", required=True)
    p_ml.add_argument("--signer", required=True)
    p_ml.add_argument("--out", default="mandate.lock.json")
    _add_sandbox_args(p_ml)
    p_mv = mcp_sub.add_parser("verify")
    p_mv.add_argument("--lock", required=True)
    p_mv.add_argument("--cmd", dest="mcp_server_cmd", required=True)
    _add_sandbox_args(p_mv)
    p_mp = mcp_sub.add_parser("proxy")
    p_mp.add_argument("--lock", required=True)
    p_mp.add_argument("--cmd", dest="mcp_server_cmd", required=True)
    p_mp.add_argument("--verify-calls", action="store_true")
    p_mp.add_argument("--taint", default=None)
    p_mp.add_argument("--mcp-ledger", default="mcp_ledger.jsonl")
    p_mp.add_argument("--mcp-audience", default="")
    _add_sandbox_args(p_mp)

    p_req = sub.add_parser("request")
    p_req.add_argument("--approver", required=True)
    p_req.add_argument("--intent", required=True)
    p_req.add_argument("--audience", default=None)
    p_req.add_argument("--ttl", type=int, default=None)
    p_req.add_argument("--token", default=os.environ.get(
        "MANDATE_APPROVER_TOKEN", ""))
    p_req.add_argument("--out", default=None)

    p_bench = sub.add_parser("bench")
    p_bench.add_argument("--scenarios", default="bench/scenarios/idb_v0.jsonl")
    p_bench.add_argument("--out", default=None)
    p_bench.add_argument("--model-url", default="")
    p_bench.add_argument("--model", default="")
    p_bench.add_argument("--api-key-env", default="")

    p_audit = sub.add_parser("audit")
    audit_sub = p_audit.add_subparsers(dest="audit_cmd")
    p_ab = audit_sub.add_parser("bundle")
    p_ab.add_argument("--receipt", required=True)
    p_ab.add_argument("--intent", required=True)
    p_ab.add_argument("--grant", required=True)
    p_ab.add_argument("--proof", default=None)
    p_ab.add_argument("--sth", default=None)
    p_ab.add_argument("--witness-state", dest="witness_state", default=None)
    p_ab.add_argument("--key", required=True)
    p_ab.add_argument("--signer", default=None)
    p_ab.add_argument("--out", default=None)
    p_av = audit_sub.add_parser("verify")
    p_av.add_argument("--bundle", required=True)
    p_av.add_argument("--log-signers", dest="log_signers", required=True)
    p_av.add_argument("--witness-signers", dest="witness_signers", default=None,
                      help="allowed witness keys; without it a witness state is only a claim")
    p_av.add_argument("--pq-witness-keys", dest="pq_witness_keys", default=None,
                      help="file with allowed ML-DSA-65 witness public keys (one per line)")
    p_av.add_argument("--require-coverage", dest="require_coverage",
                      action="store_true", help="reject receipts without a coverage class")
    p_av.add_argument("--witness-quorum", dest="witness_quorum", type=int, default=0,
                      help="require N distinct witnesses on the same tree head (0 = off)")

    # GLOBAL_FLAGS_V1: subparser default mora biti SUPPRESS, inače pregazi
    # `mandate --signers X redeem ...` sa podrazumijevanom putanjom.
    for _sp in (p_check, p_prop, p_grant, p_redeem):
        _sp.add_argument("--policy", default=argparse.SUPPRESS)
    for _sp in (p_check, p_redeem, p_verify):
        _sp.add_argument("--signers", default=argparse.SUPPRESS)
    p_verify.add_argument("--ledger", default=None,
                          help="check an unsigned receipt against this ledger")

    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help(sys.stderr)
        return 2

    try:
        if args.cmd == "check":
            result = core.check(_read(args.intent), core.load_policy(args.policy))
            _emit(result, None)
            return {"allow": 0, "ask": 10, "deny": 20}.get(result["decision"], 2)

        if args.cmd == "propose":
            _emit(core.propose(_read(args.intent)), args.out)
            return 0

        if args.cmd == "grant":
            proposal = _read(args.proposal)
            intent = core.normalize_intent(proposal.get("intent") or {})
            commitment = core.intent_commitment(intent)
            rhash = core.render_hash(intent)
            if (commitment != proposal.get("commitment")
                    or rhash != proposal.get("render_hash")
                    or core.proposal_id(intent) != proposal.get("proposal_id")):
                _emit({"error": "ProposalMismatch",
                       "message": "proposal does not match its intent"}, None)
                return 3
            sod = governance.check_separation_of_duties(intent, args.approver)
            if not sod["allow"]:
                _emit({"error": "SeparationOfDuties", "message":
                       "approver must differ from the agent that proposed the effect",
                       "detail": sod["detail"]}, None)
                return 3
            grant_core = core.build_grant_core(
                commitment, args.approver, ttl_s=args.ttl,
                render_hash=rhash,
                agent=str(intent["actor"]["agent"]),
                audience=args.audience,
                policy_fingerprint=core.policy_digest(core.load_policy(args.policy)))
            _emit(core.make_grant(grant_core, args.key), args.out)
            return 0

        if args.cmd == "redeem":
            _pol = core.load_policy(args.policy) or {}
            if _pol.get("require_svid") and not args.svid:
                _emit({"error": "SvidRequired", "code": "missing_svid",
                       "message": "policy requires an agent token: pass --svid"},
                      None)
                return 6
            if args.svid:
                intent_obj = _read(args.intent)
                tokens = [svid.load(p) for p in args.svid]
                child, parents = tokens[0], tokens[1:]
                chk = svid.verify_chain(child, parents, args.signers,
                                        audience=args.svid_audience,
                                        revoked_path=args.revoked)
                if not chk["valid"]:
                    _emit({"error": "SvidInvalid", "code": chk["code"]}, None)
                    return 6
                cov = svid.covers(child, str(((intent_obj.get("effect") or {}).get("kind")) or ""),
                                  subject=str(((intent_obj.get("actor") or {}).get("agent")) or ""))
                if not cov["ok"]:
                    _emit({"error": "SvidScope", "code": cov["code"],
                           "detail": {k: v for k, v in cov.items() if k != "ok"}}, None)
                    return 6
            gov = governance.check(args.ledger, governance.load_limits(args.policy))
            if not gov["allow"]:
                _emit({"error": "Governance", "code": gov["code"],
                       "message": "the effect is not allowed right now",
                       "detail": gov["detail"]}, None)
                return 4
            _intent = _read(args.intent)
            core.enforce_new_payee(_intent, core.load_policy(args.policy), args.ledger)
            receipt = core.redeem(
                _intent, _read(args.grant), args.signers,
                args.ledger, allow_self=args.allow_self,
                audience=getattr(args, "audience", None),
                policy=core.load_policy(args.policy),
                revoked_path=args.revoked,
                sign_key=getattr(args, "key", None),
                signer=getattr(args, "signer", None),
                signer_cmd=getattr(args, "signer_cmd", None),
                observe=getattr(args, "observe", False),
                instruction_store=getattr(args, "instructions", None) or "")
            _emit(receipt, None)
            return 0

        if args.cmd == "inventory":
            tokens = [svid.load(t) for t in (args.svid or [])]
            owners = dict(pair.split("=", 1) for pair in (args.owner or []) if "=" in pair)
            inv = audit_report.inventory(args.ledger, tokens, owners)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(inv, fh, indent=1, sort_keys=True)
            if args.csv:
                audit_report.write_inventory_csv(inv, args.csv)
            _emit({"count": inv["count"], "agents": [a["agent"] for a in inv["agents"]],
                   "out": args.out, "csv": args.csv}, None)
            return 0

        if args.cmd == "change":
            if args.action == "record":
                if not (args.file and args.approver and args.key):
                    _emit({"error": "Usage",
                           "message": "change record --file F --approver A --key K --reason R"}, None)
                    return 2
                res = audit_report.change_record(
                    args.ledger, args.file, args.approver, args.key, args.reason,
                    getattr(args, "signer_cmd", None), ticket=args.ticket,
                    model=args.model, model_digest=args.model_digest,
                    require_ticket=args.require_ticket)
                out = {k: res[k] for k in ("entry", "file", "sha256", "actor", "reason", "ticket")}
                if res.get("ticket_problem"):
                    out["ticket_problem"] = res["ticket_problem"]
                _emit(out, None)
                return 0
            if args.action == "verify":
                res = audit_report.drift(args.ledger, args.dir,
                                         getattr(args, "signers", None))
                _emit(res, None)
                return 0 if res.get("ok") else 4
            if args.action == "models":
                res = audit_report.pinned_models(args.ledger)
                _emit(res, None)
                return 0 if res.get("count") else 4
            res = audit_report.changes(args.ledger, args.signers, ticket=args.ticket)
            _emit(res, None)
            return 0

        if args.cmd == "watch":
            res = agentwatch.watch(args.log, args.window, args.ledger)
            order = {"low": 0, "medium": 1, "high": 2}
            floor = order[args.min_level]
            flagged = {ip: s for ip, s in res["sessions"].items()
                       if order[s["level"]] >= floor}
            _emit({"sources": res["sources"], "flagged": len(flagged),
                   "highest_points": res["highest"],
                   "sessions": flagged}, None)
            return 0 if not flagged else 1

        if args.cmd == "ship":
            try:
                res = ship_mod.ship(args.ledger, args.url, args.token, args.offset,
                                    args.batch, args.dry_run)
            except ship_mod.ShipError as exc:
                _emit({"error": "ShipError", "message": str(exc)}, None)
                return 4
            _emit(res, None)
            return 0

        if args.cmd == "taint":
            from . import taint as taint_mod
            covers = [c.strip() for c in (args.covers or "").split(",") if c.strip()]
            if args.action == "mark":
                out = taint_mod.mark(args.ledger, args.session, args.source,
                                     kind=args.kind, reason=args.reason)
            elif args.action == "clear":
                out = taint_mod.clear(args.ledger, args.session, args.source,
                                      reason=args.reason)
            elif args.action == "show":
                out = {"active": taint_mod.active(args.ledger, args.session or None)}
            else:
                out = {"provenance": taint_mod.provenance_for(args.ledger, args.session,
                                                              covers or None)}
            _emit(out, None)
            return 0

        if args.cmd == "firewall":
            from . import firewall as fw
            if args.action == "selftest":
                # bez subprocess-a i bez repo fajlova: korpus je u paketu
                corpus = json.loads((pathlib.Path(__file__).resolve().parent
                                     / "data" / "firewall_corpus.json").read_text(encoding="utf-8"))
                tp = fn = fp = tn = 0
                for case in corpus["outbound"]:
                    r = fw.scan_outbound(fw.expand_fixture(case["text"]))
                    hit = (not r["ok"]) or bool(r["redactable"])
                    tp += hit and case["expect"]
                    fn += (not hit) and case["expect"]
                    fp += hit and not case["expect"]
                    tn += (not hit) and not case["expect"]
                for case in corpus["inbound"]:
                    r = fw.scan_inbound(fw.expand_fixture(case["text"]))
                    hit = (not r["ok"]) or bool(r["flagged"])
                    tp += hit and case["expect"]
                    fn += (not hit) and case["expect"]
                    fp += hit and not case["expect"]
                    tn += (not hit) and not case["expect"]
                report = {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "total": tp + fn + fp + tn,
                          "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
                          "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0}
                _emit({"ok": fn == 0 and fp == 0, "report": report}, None)
                return 0 if (fn == 0 and fp == 0) else 1
            text = args.text
            if text is None and args.file:
                text = pathlib.Path(args.file).read_text(encoding="utf-8", errors="replace")
            if text is None:
                _emit({"error": "usage", "message": "firewall scan --text ... | --file F"}, None)
                return 2
            if args.action == "scan":
                out = {"outbound": fw.scan_outbound(text)}
                if args.response is not None:
                    out["inbound"] = fw.scan_inbound(args.response)
                _emit(out, None)
                return 0 if out["outbound"]["ok"] else 1
            if args.action == "decide":
                res = fw.decide(text, args.response or "")
                _emit(res, None)
                return 0 if res["allow"] else 1
            cleaned, count = fw.redact(text)
            if args.out:
                pathlib.Path(args.out).write_text(cleaned, encoding="utf-8")
                _emit({"ok": True, "out": args.out, "replacements": count}, None)
            else:
                _emit({"ok": True, "text": cleaned, "replacements": count}, None)
            return 0

        if args.cmd == "hardware":
            from . import sign as sign_mod
            rows = []
            path = args.signers
            try:
                text = open(path, encoding="utf-8").read()
            except OSError as exc:
                _emit({"error": "io", "message": str(exc)}, None)
                return 2
            for line in text.splitlines():
                parts = line.split()
                if not parts or line.strip().startswith("#"):
                    continue
                name = parts[0]
                alg = next((p for p in parts if p.startswith(("ssh-", "ecdsa-", "sk-"))), "")
                rows.append({"name": name, "keytype": alg,
                             "hardware": sign_mod.is_hardware_key(alg)})
            if args.name:
                rows = [r for r in rows if r["name"] == args.name]
            if args.signature:
                try:
                    sig = open(args.signature, encoding="utf-8").read()
                except OSError as exc:
                    _emit({"error": "io", "message": str(exc)}, None)
                    return 2
                name = args.name or (rows[0]["name"] if rows else "")
                keytype = sign_mod.keytype_for_signature(
                    name, sig, path, sign_mod.DEFAULT_NAMESPACE, revoked_path=args.revoked)
                _emit({"ok": True, "signer": name, "signing_keytype": keytype,
                       "hardware": sign_mod.is_hardware_key(keytype)}, None)
                return 0 if sign_mod.is_hardware_key(keytype) else 1
            hardware = [r for r in rows if r["hardware"]]
            _emit({"ok": True, "signers": rows, "hardware": len(hardware),
                   "software": len(rows) - len(hardware)}, None)
            return 0

        if args.cmd == "cap":
            from . import capability as cap_mod
            def _scopes():
                return {
                    "kinds": ([k.strip() for k in args.kinds.split(",") if k.strip()]
                              or None),
                    "max_amount": args.max_amount,
                    "currency": args.currency,
                    "targets": ([t.strip() for t in args.targets.split(",") if t.strip()]
                                or None),
                }
            try:
                if args.action == "mint":
                    if not (args.key and args.subject):
                        _emit({"error": "usage",
                               "message": "cap mint --subject S --key K [--kinds ...]"}, None)
                        return 2
                    token = cap_mod.mint(_scopes(), args.key,
                                         args.issuer or args.subject, args.subject,
                                         ttl_s=(args.ttl or 3600), max_uses=args.max_uses)
                elif args.action == "attenuate":
                    if not (args.parent and args.key and args.subject):
                        _emit({"error": "usage",
                               "message": "cap attenuate --parent F --subject S --key K"}, None)
                        return 2
                    parent = core.load_json(args.parent)
                    token = cap_mod.attenuate(parent, _scopes(), args.key, args.subject,
                                              ttl_s=args.ttl, max_uses=args.max_uses,
                                              signers_path=args.signers)
                elif args.action == "verify":
                    files = [f.strip() for f in (args.chain or args.token or "").split(",")
                             if f.strip()]
                    chain = [core.load_json(f) for f in files]
                    out = cap_mod.verify_chain(chain, args.signers)
                    _emit(out, None)
                    return 0
                else:                                   # check
                    token = core.load_json(args.token)
                    intent = core.load_json(args.intent) if args.intent else {}
                    cap_mod.verify(token, args.signers)
                    out = cap_mod.allows(token, intent)
                    _emit(out, None)
                    return 0 if out.get("ok") else 1
                if args.out:
                    with open(args.out, "w", encoding="utf-8") as fh:
                        json.dump(token, fh, ensure_ascii=False, indent=2, sort_keys=True)
                        fh.write("\n")
                    _emit({"ok": True, "out": args.out, "digest": cap_mod.digest(token),
                           "scopes": token["scopes"]}, None)
                else:
                    _emit(token, None)
                return 0
            except cap_mod.CapabilityError as exc:
                _emit({"ok": False, "error": exc.code, "message": str(exc)}, None)
                return 1

        if args.cmd == "disclose":
            from . import disclose as disc
            if args.action == "redact":
                if not args.receipt:
                    _emit({"error": "usage", "message": "disclose redact --receipt F --fields a,b"}, None)
                    return 2
                paths = [p.strip() for p in (args.fields or "").split(",") if p.strip()]
                if not paths:
                    _emit({"error": "usage", "message": "--fields render.fields.target,..."}, None)
                    return 2
                body = _read(args.receipt)
                if isinstance(body, dict) and isinstance(body.get("body"), dict):
                    body = body["body"]
                view = disc.redact(body, paths, expect_hash=args.expect_hash)
                if args.key:
                    from . import sign as sign_mod
                    payload = core.jcs({k: v for k, v in view.items()
                                        if k not in ("signature", "signer")})
                    view["signature"] = sign_mod.sign(payload, args.key,
                                                      "mandate-disclosure")
                    view["signer"] = str(args.signer or "")
                if args.out:
                    with open(args.out, "w", encoding="utf-8") as fh:
                        json.dump(view, fh, ensure_ascii=False, indent=2, sort_keys=True)
                        fh.write("\n")
                    _emit({"ok": True, "out": args.out, "redacted": view["redacted"],
                           "receipt_hash": view["receipt_hash"],
                           "signed": bool(args.key)}, None)
                else:
                    _emit(view, None)
                return 0
            if args.action == "verify":
                view = core.load_json(args.view) if args.view else None
                if not view:
                    _emit({"error": "usage", "message": "disclose verify --view F"}, None)
                    return 2
                out = disc.check_view(view)
                if view.get("signature"):
                    from . import sign as sign_mod
                    payload = core.jcs({k: v for k, v in view.items()
                                        if k not in ("signature", "signer")})
                    out["view_signature"] = bool(sign_mod.verify(
                        payload, str(view.get("signer") or ""), str(view["signature"]),
                        args.signers, "mandate-disclosure", revoked_path=args.revoked))
                _emit(out, None)
                return 0
            # reveal
            view = core.load_json(args.view) if args.view else None
            values = core.load_json(args.values) if args.values else {}
            paths = [p.strip() for p in (args.fields or "").split(",") if p.strip()]
            if not (view and paths):
                _emit({"error": "usage",
                       "message": "disclose reveal --view F --fields a,b --values vals.json"}, None)
                return 2
            res = disc.reveal(view, paths, values)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(res, fh, ensure_ascii=False, indent=2, sort_keys=True)
                    fh.write("\n")
                _emit({"ok": True, "out": args.out, "hash": res["hash"]}, None)
            else:
                _emit(res, None)
            return 0

        if args.cmd == "replay":
            from . import replay as replay_mod
            pol = (core.load_json(args.policy) if args.policy else None)
            out = replay_mod.replay(core.load_json(args.bundle), pol)
            _emit(out, None)
            return 0 if out.get("ok") else 1

        if args.cmd == "dsse":
            from . import dsse as dsse_mod
            if args.action == "sign":
                if not (args.receipt and args.key and args.signer):
                    _emit({"error": "usage",
                           "message": "dsse sign --receipt F --key K --signer NAME [--statement]"}, None)
                    return 2
                body = _read(args.receipt)
                if isinstance(body, dict) and isinstance(body.get("body"), dict):
                    body = body["body"]          # prihvati i cijeli ledger entry
                env = dsse_mod.envelope_for_receipt(
                    body, args.key, args.signer, as_statement=args.statement)
                if args.out:
                    with open(args.out, "w", encoding="utf-8") as fh:
                        json.dump(env, fh, ensure_ascii=False, indent=2, sort_keys=True)
                        fh.write("\n")
                    _emit({"ok": True, "out": args.out,
                           "payloadType": env["payloadType"]}, None)
                else:
                    _emit(env, None)
                return 0
            try:
                env = dsse_mod.load_envelope(args.file) if args.file else None
                if env is None:
                    _emit({"error": "usage", "message": "dsse verify --file env.json"}, None)
                    return 2
                ok = dsse_mod.verify(env, args.signers, revoked_path=args.revoked,
                                     require_keyid=args.keyid)
            except dsse_mod.DsseError as exc:
                _emit({"ok": False, "error": exc.code, "message": str(exc)}, None)
                return 1
            _emit({"ok": bool(ok), "envelope": bool(ok),
                   "keyid": (env.get("signatures") or [{}])[0].get("keyid")}, None)
            return 0 if ok else 1

        if args.cmd == "nonce":
            from . import nonce as nonce_mod
            if args.action == "check":
                if not args.value:
                    _emit({"error": "Usage", "message": "nonce check --value N"}, None)
                    return 2
                try:
                    ok = nonce_mod.claim(args.value, args.db)
                except nonce_mod.NonceUnavailable as exc:
                    _emit({"error": "NonceUnavailable", "message": str(exc)}, None)
                    return 4
                _emit({"nonce": args.value, "claimed": ok}, None)
                return 0 if ok else 1
            server = nonce_mod.serve(args.host, args.port, args.db, args.token)
            _emit({"serving": f"http://{args.host}:{args.port}", "db": server.db_path}, None)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0

        if args.cmd == "backup":
            res = audit_report.backup(args.ledger, args.out, args.anchors)
            _emit({k: res[k] for k in ("archive", "manifest", "ledger_head")}, None)
            return 0

        if args.cmd == "restore":
            res = audit_report.restore(args.archive, args.out)
            _emit(res, None)
            return 0 if res["ok"] else 1

        if args.cmd == "sbom":
            res = audit_report.sbom(args.version or __import__("mandate").__version__, args.out)
            _emit(res, None)
            return 0

        if args.cmd == "pack":
            tokens = [svid.load(t) for t in (args.svid or [])]
            owners = dict(pair.split("=", 1) for pair in (args.owner or []) if "=" in pair)
            res = audit_report.pack(args.ledger, args.out, tokens, owners, args.controls,
                                    getattr(args, "signers", None),
                                    getattr(args, "anchors", None),
                                    getattr(args, "key", None),
                                    getattr(args, "signer", None),
                                    grants=args.grant, intents=args.intent)
            _emit({"path": res["path"], "files": sorted(res["files"]),
                   "agents": res["agents"], "changes": res["changes"],
                   "ledger_head": res["ledger_head"]}, None)
            return 0

        if args.cmd == "detect":
            tokens = [svid.load(p) for p in (args.svid or [])]
            res = detect.detect(args.ledger,
                                detect.load_config(getattr(args, "policy", None)),
                                tokens=tokens, mcp_ledger=args.mcp_ledger or "")
            if args.write and res["findings"]:
                core.append_receipt(args.ledger, {"v": 1, "type": "control",
                                                  "action": "alert",
                                                  "actor": "detect",
                                                  "reason": "runtime detection",
                                                  "ts": res["checked_at"],
                                                  "findings": res["findings"]})
            fmt = getattr(args, "fmt", "json")
            if fmt in ("cef", "leef"):
                # SIEM-ovi čitaju linije, ne JSON: jedno nalaz = jedan red
                render = detect.to_cef if fmt == "cef" else detect.to_leef
                for finding in res["findings"]:
                    print(render(finding))
                return 0 if res["ok"] else 1
            if fmt == "jsonl":
                for finding in res["findings"]:
                    print(json.dumps(finding, ensure_ascii=False, sort_keys=True))
                return 0 if res["ok"] else 1
            _emit(res, None)
            return 0 if res["ok"] else 1

        if args.cmd == "svid":
            signers_path = getattr(args, "signers", None) or getattr(args, "signers_path", None)
            if args.action == "issue":
                if not (args.sub and args.key):
                    _emit({"error": "Usage", "message": "svid issue --sub NAME --key KEY [--scope ...]"}, None)
                    return 2
                try:
                    token = svid.issue(args.sub, args.key, args.issuer or args.sub,
                                       args.audience, args.scope or [], args.ttl,
                                       allow_wildcard=args.allow_wildcard)
                except ValueError as exc:
                    _emit({"error": "SvidInvalid", "message": str(exc)}, None)
                    return 2
                if args.out:
                    svid.save(token, args.out)
                _emit({"jti": token["payload"]["jti"], "sub": args.sub,
                       "exp": token["payload"]["exp"], "out": args.out}, None)
                return 0
            if args.action == "delegate":
                if not (args.parent and args.sub and args.key):
                    _emit({"error": "Usage", "message": "svid delegate --parent T --sub S --key K --scope ..."}, None)
                    return 2
                parent_tok = svid.load(args.parent)
                parent_payload = parent_tok["payload"]
                scopes = args.scope or parent_payload.get("scopes") or []
                token = svid.issue(args.sub, args.key, args.issuer or args.sub,
                                   parent_payload.get("aud"), scopes,
                                   min(args.ttl, parent_payload["exp"] - int(time.time())),
                                   parent=parent_payload)
                if args.out:
                    svid.save(token, args.out)
                _emit({"jti": token["payload"]["jti"], "sub": args.sub,
                       "parent_jti": parent_payload["jti"], "out": args.out}, None)
                return 0
            if not args.token:
                _emit({"error": "Usage", "message": "svid verify --token T"}, None)
                return 2
            token = svid.load(args.token)
            res = svid.verify(token, signers_path, args.audience)
            _emit(res, None)
            return 0 if res["valid"] else 6

        if args.cmd == "egress":
            if args.action in ("ca", "trust"):
                from . import egress_tls
                ca_dir = args.ca_dir or "egress-ca"
                if args.action == "trust":
                    cert = str(pathlib.Path(ca_dir) / egress_tls.CA_CERT)
                    _emit({"ca": cert, "hint": egress_tls.trust_hint(cert)}, None)
                    return 0
                try:
                    info = egress_tls.init_ca(ca_dir)
                except egress_tls.CaError as exc:
                    _emit({"ok": False, "error": "E_CA", "message": str(exc)}, None)
                    return 1
                _emit({"ok": True, **info,
                       "next": "mandate egress trust --ca-dir %s" % ca_dir}, None)
                return 0
            if args.action == "rules":
                if args.uid is None:
                    _emit({"error": "usage", "message": "egress rules --uid N [--allow h:p]"}, None)
                    return 2
                text = egress.nft_rules(args.uid, args.proxy_addr,
                                        [a for a in (args.allow or []) if a])
                if args.out:
                    pathlib.Path(args.out).write_text(text, encoding="utf-8")
                checked = None
                if args.check:
                    import shutil as _shutil
                    nft = _shutil.which("nft")
                    if not nft:
                        checked = {"ok": False, "code": "nft_not_available"}
                    else:
                        import subprocess as _sp
                        done = _sp.run([nft, "-c", "-f", "-"], input=text,
                                       capture_output=True, text=True)
                        checked = {"ok": done.returncode == 0,
                                   "code": "ok" if done.returncode == 0 else "nft_check_failed",
                                   "stderr": (done.stderr or "")[-200:]}
                _emit({"ok": True, "rules": len(text.splitlines()), "out": args.out,
                       "check": checked, "text": None if args.out else text}, None)
                if checked is not None and not checked.get("ok") and checked.get("code") != "nft_not_available":
                    return 4
                return 0

            if args.action == "policy":
                pol = egress.default_policy()
                pol["allow"] = list(args.allow or [])
                if args.token_env:
                    pol["token_env"] = args.token_env
                target = args.out or "egress.json"
                with open(target, "w", encoding="utf-8") as fh:
                    json.dump(pol, fh, indent=1)
                _emit({"written": target, **pol}, None)
                return 0
            policy_path = getattr(args, "policy", None)
            target = args.target_opt or args.target
            if args.action == "check":
                if not target:
                    _emit({"error": "Usage", "message": "egress check host:port"}, None)
                    return 2
                host, _, port_s = target.partition(":")
                verdict = egress.decide(egress.load_policy(policy_path), host, int(port_s or 443))
                _emit({"target": target, **verdict}, None)
                return 0 if verdict["allow"] else 4
            if args.action == "summary":
                _emit(egress.summary(args.ledger or "egress.jsonl"), None)
                return 0
            pol = egress.load_policy(policy_path)
            if args.intercept:
                if not args.ca_dir:
                    _emit({"ok": False, "error": "E_CA",
                           "message": "TLS interception needs --ca-dir "
                                      "(run `mandate egress ca init` first)"}, None)
                    return 2
                pol = dict(pol, intercept=True, intercept_ca=args.ca_dir)
                if args.upstream_ca:
                    pol["upstream_ca"] = args.upstream_ca
            try:
                egress.run_forever(pol, args.host, args.port, args.ledger)
            except KeyboardInterrupt:
                return 0
            return 0

        if args.cmd == "warden":
            if args.verify:
                ledger = args.ledger or "ledger.jsonl"
                signers_path = args.signers or args.signers_path
                results = []
                for line in open(ledger, encoding="utf-8") if os.path.exists(ledger) else []:
                    body = ((json.loads(line) or {}).get("body") or {})
                    if body.get("type") == "control" and body.get("signature"):
                        results.append({"action": body.get("action"),
                                        **warden.verify_evidence(body, signers_path)})
                _emit({"signed_controls": len(results), "results": results}, None)
                if not results:
                    return 6   # nothing to verify is not a pass
                return 0 if all(r["valid"] for r in results) else 6

            if args.quarantine:
                if args.uid is None:
                    _emit({"error": "Usage", "message": "warden --quarantine --uid N [--undo]"}, None)
                    return 2
                res = warden.quarantine(args.uid, undo=args.undo)
                if args.ledger:
                    body = {"v": 1, "type": "control", "target": args.uid,
                            "method": "quarantine", "reason": args.reason, "actor": args.actor,
                            **{k: v for k, v in res.items() if k != "action"},
                            "action": "halt" if not args.undo else "resume"}
                    core.append_receipt(args.ledger, body)
                _emit(res, None)
                return 0 if res.get("ok") else 5

            if args.method in ("vm-pause", "vm-resume"):
                if not args.vm_socket:
                    _emit({"error": "Usage", "message": "--method vm-pause needs --vm-socket"}, None)
                    return 2
                if not warden.kvm_available():
                    _emit({"error": "NoKvm", "message":
                           "/dev/kvm is not available on this host: Firecracker cannot run here",
                           "hint": "use a KVM-capable host (nested virt / bare metal)"}, None)
                    return 4
                res = (warden.vm_pause(args.vm_socket) if args.method == "vm-pause"
                       else warden.vm_resume(args.vm_socket))
                evidence = {"action": "halt" if args.method == "vm-pause" else "resume",
                            "cgroup": None, "target": args.vm_socket,
                            "reason": args.reason, "actor": args.actor, **res}
                if args.key:
                    evidence.update(warden.sign_evidence(evidence, args.key,
                                                         args.signer or args.actor))
                if args.ledger:
                    entry = core.append_receipt(args.ledger,
                                                {"v": 1, "type": "control", **evidence})
                    evidence["ledger_head"] = entry["hash"]
                _emit(evidence, None)
                return 0 if res.get("verified") else 5

            if args.attach or args.cgroup:
                path = args.cgroup
                if args.attach:
                    if args.pid is None:
                        _emit({"error": "Usage", "message": "warden --attach NAME --pid N"}, None)
                        return 2
                    path = warden.attach(args.pid, args.attach)
                try:
                    if args.resume:
                        state = warden.thaw_cgroup(path)
                        evidence = {"action": "resume", "method": "cgroup", "cgroup": path,
                                    "pids": warden.cgroup_pids(path), "states_after": state,
                                    "reason": args.reason, "actor": args.actor}
                    elif args.method == "kill":
                        out = warden.kill_cgroup(path)
                        evidence = {"action": "halt", "method": "cgroup-kill", "cgroup": path,
                                    **out, "reason": args.reason, "actor": args.actor,
                                    "verified": True}
                    else:
                        frozen = warden.freeze_cgroup(path, args.timeout_ms)
                        evidence = {"action": "halt", "method": "cgroup-freeze",
                                    "cgroup": path, "pids": warden.cgroup_pids(path),
                                    "states_after": frozen.get("events"),
                                    "time_to_halt_ms": frozen["time_to_halt_ms"],
                                    "verified": bool(frozen["frozen"]),
                                    "reason": args.reason, "actor": args.actor}
                except (OSError, ValueError) as exc:
                    _emit({"error": type(exc).__name__, "message": str(exc)}, None)
                    return 4
                if args.key:
                    evidence.update(warden.sign_evidence(evidence, args.key,
                                                         args.signer or args.actor))
                if args.ledger:
                    entry = core.append_receipt(args.ledger, {"v": 1, "type": "control", **evidence})
                    evidence["ledger_head"] = entry["hash"]
                _emit(evidence, None)
                return 0 if evidence.get("verified", True) else 5

            target = args.pgid if args.pgid is not None else args.pid
            if target is None:
                _emit({"error": "Usage", "message": "pass --pid or --pgid"}, None)
                return 2
            by_pgid = args.pgid is not None
            try:
                if args.resume:
                    res = warden.resume(target, by_pgid=by_pgid, ledger_path=args.ledger,
                                        reason=args.reason, actor=args.actor)
                else:
                    res = warden.stop(target, method=args.method, by_pgid=by_pgid,
                                      timeout_ms=args.timeout_ms, ledger_path=args.ledger,
                                      reason=args.reason, actor=args.actor)
            except (ValueError, PermissionError, ProcessLookupError) as exc:
                _emit({"error": type(exc).__name__, "message": str(exc)}, None)
                return 4
            res.pop("entry", None)
            _emit(res, None)
            return 0 if res.get("verified", True) else 5

        if args.cmd == "controls":
            from . import controls as controls_mod
            if args.summary:
                _emit(controls_mod.summary(args.framework), None)
                return 0
            text = controls_mod.render(args.framework, args.status)
            if args.out:
                pathlib.Path(args.out).write_text(text + "\n", encoding="utf-8")
                _emit({"ok": True, "out": args.out,
                       **controls_mod.summary(args.framework)}, None)
            else:
                print(text)
            return 0

        if args.cmd == "anchor":
            if getattr(args, "status", False):
                res = anchor.status(args.ledger, args.out, args.max_age_hours)
                _emit(res, None)
                return 0 if res.get("ok") else 4
            servers = args.tsa or [anchor.DEFAULT_TSA]
            res = anchor.anchor(args.ledger, servers[0], args.out, args.ca, tsas=servers)
            _emit(res, None)
            return 0 if res.get("imprint_matches_head") else 4

        if args.cmd == "anchor-verify":
            res = anchor.verify_anchor(args.ledger, args.token, args.ca)
            _emit(res, None)
            return 0 if res.get("valid") else 4

        if args.cmd == "provenance":
            from . import provenance as prov
            version = args.version or __import__("mandate").__version__
            res = prov.check(version, args.project)
            if args.text:
                print(prov.summary(res))
            else:
                _emit(res, None)
            return 0 if res.get("ok") else 4

        if args.cmd == "worm-verify":
            res = anchor.worm_verify(args.dir)
            _emit(res, None)
            return 0 if res.get("ok") else 4

        if args.cmd == "worm-export":
            res = anchor.worm_export(args.ledger, args.out, args.retention_days, args.anchors)
            _emit({"path": res["path"], "manifest": res["manifest_path"],
                   "retention_until": res["retention_until"],
                   "files": len(res["files"])}, None)
            return 0

        if args.cmd == "halt":
            entry = governance.halt(args.ledger, args.reason, args.actor)
            _emit({"halted": True, "reason": args.reason, "head": entry["hash"]}, None)
            return 0

        if args.cmd == "resume":
            entry = governance.resume(args.ledger, args.reason, args.actor)
            _emit({"resumed": True, "reason": args.reason, "head": entry["hash"]}, None)
            return 0

        if args.cmd == "limits":
            _emit(governance.summary(args.ledger,
                                     governance.load_limits(args.policy)), None)
            return 0

        if args.cmd == "verify":
            receipt = _read(args.receipt)
            ok = core.verify_receipt(
                receipt, _read(args.intent), _read(args.grant),
                args.signers, revoked_path=args.revoked)
            body = receipt.get("body") or {}
            decision = str(body.get("decision") or "")
            signed = bool(body.get("signature"))
            authentic = signed
            if not signed and getattr(args, "ledger", None):
                try:
                    authentic = any(entry.get("hash") == receipt.get("hash")
                                    for entry in core.read_ledger(args.ledger))
                except (OSError, core.MandateError):
                    authentic = False
            _emit({"valid": ok, "authentic": bool(ok and authentic),
                   "decision": decision or None,
                   # a tampered receipt must not look executed just because its
                   # body still says so
                   "executed": bool(ok and decision == "executed"),
                   "observed": bool(ok and decision == "observe"),
                   "signed": bool(body.get("signature"))}, None)
            return 0 if ok else 1

        if args.cmd == "chain":
            entries = core.read_ledger(args.ledger)
            ok = core.verify_chain(args.ledger)
            report = {"valid": ok, "entries": len(entries),
                      "diagnosis": core.diagnose_chain(args.ledger)}
            if args.signers:
                signed = [e for e in entries
                          if (e.get("body") or {}).get("signature")]
                bad = [e["hash"] for e in signed
                       if not core.verify_receipt_signature(e["body"], args.signers,
                                                            revoked_path=args.revoked)]
                report.update({"signed_receipts": len(signed), "bad_signatures": bad})
                ok = ok and not bad
            if args.broker_signers:
                results = [e for e in entries
                           if (e.get("body") or {}).get("type") == "result"]
                bad = [e["hash"] for e in results
                       if not core.verify_result_entry(e, args.broker_signers,
                                                       revoked_path=args.revoked)]
                report.update({"broker_results": len(results), "bad_results": bad})
                ok = ok and not bad
            report["valid"] = ok
            _emit(report, None)
            return 0 if ok else 1

        if args.cmd == "verify-result":
            ok = core.verify_result_entry(_read(args.entry), args.broker_signers,
                                          revoked_path=args.revoked)
            _emit({"valid": ok}, None)
            return 0 if ok else 1

        if args.cmd == "signers":
            _emit({"signers": sign.list_signers(args.signers)}, None)
            return 0

        if args.cmd == "log":
            return _cmd_log(args)

        if args.cmd == "witness":
            return _cmd_witness(args)

        if args.cmd == "pq":
            from . import hybrid
            if getattr(args, "pq_cmd", None) == "keygen":
                public = hybrid.pq_keygen(args.out)
                _emit({"ok": True, "alg": hybrid.ALG, "public_key": public,
                       "private_key": args.out}, None)
                return 0
            _emit({"error": "unknown_pq_command"}, None)
            return 2

        if args.cmd == "approver":
            return _cmd_approver(args)

        if args.cmd == "request":
            return _cmd_request(args)

        if args.cmd in ("export", "export-verify"):
            return _cmd_export(args)

        if args.cmd == "mcp":
            return _cmd_mcp(args)
        if args.cmd == "bench":
            from . import benchmark as mbench
            try:
                policy = core.load_policy(args.policy)
                if args.model_url:
                    scenarios = mbench.load_prompts(args.scenarios)
                    api_key = os.environ.get(args.api_key_env, "") \
                        if args.api_key_env else ""
                    report = mbench.run_model(
                        scenarios,
                        mbench.model_agent(args.model_url, args.model, api_key),
                        policy)
                    ok = report["metrics"]["unsafe_execution"] == 0
                else:
                    report = mbench.run(
                        mbench.load_scenarios(args.scenarios), policy)
                    ok = report["metrics"]["failed"] == 0
            except (core.MandateError, OSError, ValueError) as exc:
                _emit({"error": type(exc).__name__,
                       "message": str(exc)[:200]}, None)
                return 3
            _emit(report, args.out)
            return 0 if ok else 1

        if args.cmd == "audit":
            from . import audit as maudit
            from . import export as mexport
            try:
                if getattr(args, "audit_cmd", None) == "bundle":
                    bundle = mexport.build_bundle(
                        _read(args.receipt), _read(args.intent),
                        _read(args.grant),
                        _read(args.proof) if args.proof else None,
                        key_path=args.key, signer=args.signer,
                        sth=_read(args.sth) if args.sth else None,
                        witness_state=(_read(args.witness_state)
                                       if args.witness_state else None))
                    _emit(bundle, args.out)
                    return 0
                if getattr(args, "audit_cmd", None) == "verify":
                    result = maudit.verify_bundle_file(
                        args.bundle, args.signers, args.log_signers,
                        revoked_path=args.revoked,
                        witness_signers_path=getattr(args, "witness_signers", None),
                        pq_witness_keys=_pq_keys(getattr(args, "pq_witness_keys", None)),
                        witness_quorum=int(getattr(args, "witness_quorum", 0) or 0),
                        require_coverage=bool(getattr(args, "require_coverage", False)))
                    _emit(result, None)
                    return 0 if result.get("valid") else 1
            except (core.MandateError, OSError, ValueError) as exc:
                _emit({"error": type(exc).__name__,
                       "message": str(exc)[:200]}, None)
                return 3
            _emit({"error": "unknown_audit_command"}, None)
            return 2

        if args.cmd == "revoke":
            try:
                text = open(args.pub, encoding="utf-8").read()
            except OSError as exc:
                _emit({"error": "io", "message": str(exc)}, None)
                return 2
            tokens = text.split()
            idx = next((i for i, tok in enumerate(tokens)
                        if tok.startswith(("ssh-", "ecdsa-", "sk-"))), None)
            if idx is None or idx + 1 >= len(tokens):
                _emit({"error": "bad_pubkey"}, None)
                return 2
            fp = sign.fingerprint(tokens[idx + 1])
            target = args.revoked
            os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
            added = fp not in sign.load_revoked(target)
            if added:
                with open(target, "a", encoding="utf-8") as fh:
                    fh.write(fp + ("  # " + args.reason if args.reason else "") + "\n")
            _emit({"ok": True, "fingerprint": fp, "added": added,
                   "revoked_file": target}, None)
            return 0

        if args.cmd == "policy":
            policy = core.load_policy(args.policy)
            action = getattr(args, "action", "show")
            if action == "show":
                _emit(policy, None)
                return 0
            if action == "lint":
                res = policy_tools.lint(policy)
                _emit(res, None)
                return 0 if res["ok"] else 1
            if action == "explain":
                if not args.effect:
                    _emit({"error": "Usage", "message": "policy explain --effect KIND"}, None)
                    return 2
                _emit(policy_tools.explain(policy, args.effect, args.amount), None)
                return 0
            if not args.against:
                _emit({"error": "Usage", "message": "policy diff --against OLD.json"}, None)
                return 2
            old = core.load_policy(args.against)
            _emit(policy_tools.diff(old, policy), None)
            return 0

        if args.cmd == "sandbox":
            from . import sandbox as sandbox_mod
            res = sandbox_mod.probe()
            _emit(res, None)
            return 0 if res.get("network_isolated") else 1

        if args.cmd == "config":
            from . import configwatch
            if args.action == "lock":
                _emit(configwatch.lock(args.path or [], args.store, args.dir,
                                       args.ledger), None)
                return 0
            if args.action == "list":
                _emit(configwatch.load(args.store), None)
                return 0
            res = configwatch.check(args.store, args.ledger)
            _emit(res, None)
            return 0 if res["ok"] else 1

        if args.cmd == "memory":
            from . import memory as memory_store
            if args.action == "add":
                _emit(memory_store.add(args.store, args.text, args.scope or [],
                                       args.approver, args.key or "", args.ttl), None)
                return 0
            if args.action == "list":
                records = memory_store.load(args.store)
                _emit({"count": len(records),
                       "instructions": [{"id": r.get("id"), "text": r.get("text"),
                                         "scope": r.get("scope"),
                                         "expires": r.get("expires"),
                                         "revoked": r.get("revoked")}
                                        for r in records]}, None)
                return 0
            if args.action == "verify":
                if not args.id:
                    _emit({"error": "Usage", "message": "memory verify --id m-..."}, None)
                    return 2
                record = memory_store.get(args.store, args.id)
                ok = bool(record) and memory_store.verify(record, args.signers)
                _emit({"id": args.id, "ok": ok}, None)
                return 0 if ok else 1
            if not args.id:
                _emit({"error": "Usage", "message": "memory revoke --id m-..."}, None)
                return 2
            _emit(memory_store.revoke(args.store, args.id, args.approver,
                                      args.key or "", args.reason), None)
            return 0

        if args.cmd == "tool":
            from . import tools as tool_registry
            if args.action == "lock":
                if not (args.name and args.file):
                    _emit({"error": "Usage", "message": "tool lock --name X --file schema.json"}, None)
                    return 2
                _emit(tool_registry.lock(args.name, args.file, args.registry), None)
                return 0
            if args.action == "list":
                _emit(tool_registry.load(args.registry), None)
                return 0
            if not args.intent:
                _emit({"error": "Usage", "message": "tool verify --intent intent.json"}, None)
                return 2
            res = tool_registry.verify(_read(args.intent), args.registry)
            _emit(res, None)
            return 0 if res["ok"] else 1

        if args.cmd == "contain":
            if args.sweep:
                _emit(containment.sweep(args.ledger, signers_path=args.signers), None)
                return 0
            if args.release is not None:
                _emit(containment.release(args.ledger, args.release, args.approver,
                                          args.key or "", args.reason or "released"),
                      None)
                return 0
            if args.extend is not None:
                res = containment.extend(args.ledger, args.extend, args.minutes,
                                         approver=args.approver,
                                         key_path=args.key or "",
                                         reason=args.reason or "extended")
                _emit(res, None)
                return 0
            if args.pid is None:
                _emit({"error": "Usage", "message": "contain --pid N --minutes M"}, None)
                return 2
            _emit(containment.contain(pid=args.pid, minutes=args.minutes,
                                      ledger_path=args.ledger, reason=args.reason), None)
            return 0

        if args.cmd == "decisions":
            _emit(audit_report.decisions(args.ledger), None)
            return 0

        if args.cmd == "observe-summary":
            res = audit_report.observe_summary(args.ledger)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(res, fh, indent=1, sort_keys=True)
            _emit(res, None)
            return 0

        if args.cmd == "demo":
            res = demo.run(args.dir, keep=args.keep)
            _emit(res, None)
            return 0 if res["ok"] else 1

        if args.cmd == "version":
            from . import __version__
            _emit({"name": "gama-mandate", "version": __version__}, None)
            return 0

        if args.cmd == "init":
            return _cmd_init(args)

        if args.cmd == "doctor":
            return _cmd_doctor(args)

        if args.cmd == "execute":
            parsed = urllib.parse.urlsplit(args.broker)
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in ("http", "https"):
                _emit({"error": "BadBrokerUrl"}, None)
                return 2
            if host not in ("127.0.0.1", "::1", "localhost") and not args.allow_remote:
                _emit({"error": "RemoteBrokerRefused",
                       "message": "non-loopback broker requires --allow-remote"}, None)
                return 2
            payload = json.dumps({
                "intent": _read(args.intent),
                "grant": _read(args.grant),
            }).encode("utf-8")
            request = urllib.request.Request(
                args.broker.rstrip("/") + "/execute", data=payload,
                headers={"Content-Type": "application/json"}, method="POST")
            opener = urllib.request.build_opener(_NoRedirect)
            try:
                with opener.open(request, timeout=30) as resp:
                    _emit(json.loads(resp.read().decode("utf-8")), None)
                    return 0
            except urllib.error.HTTPError as exc:
                try:
                    _emit(json.loads(exc.read().decode("utf-8")), None)
                except ValueError:
                    _emit({"error": "http", "status": exc.code}, None)
                return 1
    except core.MandateError as exc:
        _emit({"error": type(exc).__name__, "message": str(exc)}, None)
        return 3
    except (OSError, ValueError) as exc:
        # greške koje nose mašinski kod (E_*) se prijavljuju kao takve, ne kao „io"
        code = getattr(exc, "code", None)
        _emit({"error": code or "io", "message": str(exc)}, None)
        return 1 if code else 2
    parser.print_help(sys.stderr)
    return 2
