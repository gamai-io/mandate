from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from . import core, sign


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
            sth = _read(args.sth) if args.sth else None
            root = size = None
            if sth:
                root = (sth.get("sth") or {}).get("root_hash")
                size = (sth.get("sth") or {}).get("tree_size")
            ok = mlog.verify_inclusion_proof(
                _read(args.entry), _read(args.proof), root=root, size=size)
            _emit({"valid": ok}, None)
            return 0 if ok else 1
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


def _cmd_witness(args) -> int:
    from . import witness as mwit
    cmd = getattr(args, "witness_cmd", None)
    try:
        if cmd in ("accept", "verify"):
            sth = _read(args.sth)
            proof = _read(args.proof) if args.proof else None
            out = mwit.accept(sth, proof, args.signers, args.state,
                              revoked_path=args.revoked,
                              dry_run=(cmd == "verify"))
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
    token = os.environ.get(args.telegram_token_env, "") \
        if args.telegram_token_env else ""
    chat = args.telegram_chat or os.environ.get("TELEGRAM_CHAT_ID", "")
    notifier = mnotify.TelegramNotifier(token, chat) if token and chat else None
    approver = mapprover.Approver(args.key, args.approver,
                                  audience_default=args.audience,
                                  ttl_default=args.ttl,
                                  notifier=notifier,
                                  rate_per_min=args.rate_limit_per_min,
                                  rate_burst=args.rate_burst)
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
        bundle = mexport.build_bundle(
            _read(args.receipt), _read(args.intent), _read(args.grant),
            _read(args.proof) if args.proof else None,
            key_path=args.key, signer=args.signer)
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

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--receipt", required=True)
    p_verify.add_argument("--intent", required=True)
    p_verify.add_argument("--grant", required=True)

    p_chain = sub.add_parser("chain")
    p_chain.add_argument("--ledger", default="ledger.jsonl")

    p_vr = sub.add_parser("verify-result")
    p_vr.add_argument("--entry", required=True)
    p_vr.add_argument("--broker-signers", dest="broker_signers", required=True)

    p_exec = sub.add_parser("execute")
    p_exec.add_argument("--broker", required=True)
    p_exec.add_argument("--intent", required=True)
    p_exec.add_argument("--grant", required=True)
    p_exec.add_argument("--allow-remote", action="store_true")

    sub.add_parser("policy")
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
    p_wv = wit_sub.add_parser("verify")
    p_wv.add_argument("--state", required=True)
    p_wv.add_argument("--sth", required=True)
    p_wv.add_argument("--proof", default=None)
    p_ws = wit_sub.add_parser("show")
    p_ws.add_argument("--state", required=True)
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
    p_as.add_argument("--audience", default="")
    p_as.add_argument("--ttl", type=int, default=900)
    p_as.add_argument("--host", default="127.0.0.1")
    p_as.add_argument("--port", type=int, default=8897)
    p_as.add_argument("--token", default=os.environ.get(
        "MANDATE_APPROVER_TOKEN", ""))
    p_as.add_argument("--telegram-chat", default=os.environ.get(
        "TELEGRAM_CHAT_ID", ""))
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

    for _sp in (p_check, p_prop, p_grant, p_redeem):
        _sp.add_argument("--policy", default=None)
    for _sp in (p_check, p_redeem, p_verify):
        _sp.add_argument("--signers", default=os.environ.get(
            "MANDATE_SIGNERS", "trust/allowed_signers"))

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
            grant_core = core.build_grant_core(
                commitment, args.approver, ttl_s=args.ttl,
                render_hash=rhash,
                agent=str(intent["actor"]["agent"]),
                audience=args.audience)
            _emit(core.make_grant(grant_core, args.key), args.out)
            return 0

        if args.cmd == "redeem":
            receipt = core.redeem(
                _read(args.intent), _read(args.grant), args.signers,
                args.ledger, allow_self=args.allow_self,
                policy=core.load_policy(args.policy),
                revoked_path=args.revoked)
            _emit(receipt, None)
            return 0

        if args.cmd == "verify":
            ok = core.verify_receipt(
                _read(args.receipt), _read(args.intent), _read(args.grant),
                args.signers, revoked_path=args.revoked)
            _emit({"valid": ok}, None)
            return 0 if ok else 1

        if args.cmd == "chain":
            entries = core.read_ledger(args.ledger)
            ok = core.verify_chain(args.ledger)
            _emit({"valid": ok, "entries": len(entries)}, None)
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

        if args.cmd == "approver":
            return _cmd_approver(args)

        if args.cmd == "request":
            return _cmd_request(args)

        if args.cmd in ("export", "export-verify"):
            return _cmd_export(args)

        if args.cmd == "mcp":
            return _cmd_mcp(args)

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
            _emit(core.load_policy(args.policy), None)
            return 0

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
        _emit({"error": "io", "message": str(exc)}, None)
        return 2
    parser.print_help(sys.stderr)
    return 2
