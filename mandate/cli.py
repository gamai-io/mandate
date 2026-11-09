from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from . import core


def _emit(obj, out: str | None) -> None:
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)


def _read(path: str):
    return core.load_json(path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mandate")
    parser.add_argument("--policy", default=None)
    parser.add_argument("--signers", default=os.environ.get(
        "MANDATE_SIGNERS", "trust/allowed_signers"))
    parser.add_argument("--json", action="store_true")
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
    p_grant.add_argument("--max-uses", type=int, default=1)
    p_grant.add_argument("--ttl", type=int, default=900)
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

    p_exec = sub.add_parser("execute")
    p_exec.add_argument("--broker", required=True)
    p_exec.add_argument("--intent", required=True)
    p_exec.add_argument("--grant", required=True)

    sub.add_parser("policy")

    for _sp in (p_check, p_prop, p_grant, p_redeem, p_verify, p_chain):
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
            grant_core = core.build_grant_core(
                proposal["commitment"], args.approver,
                max_uses=args.max_uses, ttl_s=args.ttl,
                render_hash=proposal.get("render_hash", ""))
            _emit(core.make_grant(grant_core, args.key), args.out)
            return 0

        if args.cmd == "redeem":
            receipt = core.redeem(
                _read(args.intent), _read(args.grant), args.signers,
                args.ledger, allow_self=args.allow_self)
            _emit(receipt, None)
            return 0

        if args.cmd == "verify":
            ok = core.verify_receipt(
                _read(args.receipt), _read(args.intent), _read(args.grant),
                args.signers)
            _emit({"valid": ok}, None)
            return 0 if ok else 1

        if args.cmd == "chain":
            entries = core.read_ledger(args.ledger)
            ok = core.verify_chain(args.ledger)
            _emit({"valid": ok, "entries": len(entries)}, None)
            return 0 if ok else 1

        if args.cmd == "policy":
            _emit(core.load_policy(args.policy), None)
            return 0

        if args.cmd == "execute":
            payload = json.dumps({
                "intent": _read(args.intent),
                "grant": _read(args.grant),
            }).encode("utf-8")
            request = urllib.request.Request(
                args.broker.rstrip("/") + "/execute", data=payload,
                headers={"Content-Type": "application/json"}, method="POST")
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
    except core.MandateError as exc:
        _emit({"error": type(exc).__name__, "message": str(exc)}, None)
        return 3
    except (OSError, ValueError) as exc:
        _emit({"error": "io", "message": str(exc)}, None)
        return 2
    parser.print_help(sys.stderr)
    return 2
