#!/usr/bin/env python3
"""Eight ways to make a Mandate record lie, and what stops each one.

Each attack is performed against a freshly built, fully valid record; the table says
whether the attack was caught and by which check. Run it to reproduce:

    python3 tools/attack_eval.py            # table
    python3 tools/attack_eval.py --json     # machine-readable
    python3 tools/attack_eval.py --write docs/ATTACKS.md
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from mandate import audit, core, export  # noqa: E402
from mandate import log as mlog  # noqa: E402
from mandate import witness as mwit  # noqa: E402

INTENT = {
    "v": 1,
    "actor": {"agent": "agent@example"},
    "effect": {"kind": "payment.send", "target": "Supplier",
               "amount": {"value": 10.0, "currency": "BAM"}, "params": {}},
    "requested_by": "approver",
    "nonce": "attack-1",
    "provenance": [{"type": "data_ref", "source": "erp:vendor:1",
                    "covers": ["target", "amount"]}],
}


def keys(directory: str) -> dict:
    out = {}
    for name in ("approver", "logkey", "attacker", "witness"):
        path = os.path.join(directory, name)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path],
                       check=True)
        out[name] = path
    return out


def write_signers(path: str, k: dict) -> None:
    def pub(name):
        return pathlib.Path(k[name] + ".pub").read_text().strip()
    pathlib.Path(path).write_text(
        f'approver namespaces="mandate,mandate-export" {pub("approver")}\n'
        f'log1 namespaces="mandate-log" {pub("logkey")}\n'
        f'witness1 namespaces="mandate-witness" {pub("witness")}\n', encoding="utf-8")


def build(work: str) -> dict:
    k = keys(work)
    signers = os.path.join(work, "signers")
    write_signers(signers, k)
    log_signers = os.path.join(work, "log_signers")
    pathlib.Path(log_signers).write_text(
        'log1 namespaces="mandate-log" %s\n'
        % pathlib.Path(k["logkey"] + ".pub").read_text().strip(), encoding="utf-8")
    witness_signers = os.path.join(work, "witness_signers")
    pathlib.Path(witness_signers).write_text(
        'witness1 namespaces="mandate-witness" %s\n'
        % pathlib.Path(k["witness"] + ".pub").read_text().strip(), encoding="utf-8")

    ledger = os.path.join(work, "ledger.jsonl")
    proposal = core.propose(INTENT)
    grant_core = core.build_grant_core(proposal["commitment"], "approver", ttl_s=900,
                                       render_hash=proposal["render_hash"],
                                       agent="agent@example")
    grant = core.make_grant(grant_core, k["approver"])
    receipt = core.redeem(INTENT, grant, signers, ledger, policy=core.load_policy())
    leaves = mlog.leaves_from_ledger(ledger)
    proof = mlog.inclusion_proof(leaves, 0)
    payload = mlog.sth_payload("log1", mlog.log_id_from_key(k["logkey"]),
                               len(leaves), mlog.root_hex(leaves))
    sth = mlog.sign_sth(payload, k["logkey"])
    state_path = os.path.join(work, "witness.json")
    mwit.accept(sth, None, signers, state_path, key_path=k["witness"], signer="witness1")
    state = mwit.load_state(state_path)

    def clone(value):
        return json.loads(json.dumps(value))

    def bundle(**over):
        proof_value = over.pop("proof", clone(proof))
        kwargs = dict(key_path=k["approver"], signer="approver", sth=clone(sth),
                      witness_state=clone(state))
        kwargs.update(over)
        return export.build_bundle(clone(receipt), clone(INTENT), clone(grant),
                                   proof_value, **kwargs)

    return {"keys": k, "signers": signers, "log_signers": log_signers,
            "witness_signers": witness_signers, "ledger": ledger,
            "receipt": receipt, "intent": INTENT, "grant": grant, "sth": sth,
            "proof": proof, "state": state, "bundle": bundle,
            "state_path": state_path, "work": work}


def verify(env: dict, bundle: dict) -> dict:
    return audit.verify_bundle(bundle, env["signers"], env["log_signers"],
                               witness_signers_path=env["witness_signers"])


def first_failure(result: dict) -> str:
    envelope = result.get("envelope") or {}
    for name in ("signature", "receipt", "inclusion"):
        if envelope.get(name) is False:
            return name
    for name in ("sth", "inclusion", "witness"):
        value = result.get(name)
        if isinstance(value, dict):
            value = value.get("valid")
        if value is False:
            return name
    return "none"


def attacks(env: dict) -> list[dict]:
    out = []

    def record(name, caught, by, detail):
        out.append({"attack": name, "caught": bool(caught), "by": by, "detail": detail})

    base = env["bundle"]()
    result = verify(env, base)
    record("baseline: an untouched record", result["valid"], "—",
           "the record verifies before any attack")

    # 1
    b = env["bundle"]()
    b["receipt"]["body"]["decision"] = "observe"
    r = verify(env, b)
    record("1. edit the receipt (decision executed -> observe)", not r["valid"],
           first_failure(r), "envelope signature covers the receipt")

    # 2
    b = env["bundle"]()
    b["intent"]["effect"]["amount"]["value"] = 999.0
    r = verify(env, b)
    record("2. change the amount the approver saw", not r["valid"], first_failure(r),
           "the signed grant binds the intent commitment")

    # 3
    b = env["bundle"]()
    b["inclusion_proof"]["leaf_hash"] = "00" * 32
    b = env["bundle"](proof=b["inclusion_proof"])
    r = verify(env, b)
    record("3. swap the inclusion proof (then re-sign as approver)", not r["valid"],
           first_failure(r), "proof must reach the signed root")

    # 4
    b = env["bundle"]()
    b["witness_note"]["text"] = b["witness_note"]["text"].replace("tree_size: ", "tree_size: 9")
    b = env["bundle"](witness_note=b["witness_note"])
    r = verify(env, b)
    record("4. forge the witness pin (re-signed bundle)", not r["valid"],
           first_failure(r), "the note is signed by the witness key, not by the builder")

    # 5
    b = env["bundle"]()
    b["witness_state"].pop("note", None)
    b["witness_state"]["tree_size"] = 99
    b = env["bundle"](witness_state=b["witness_state"])
    r = verify(env, b)
    record("5. ship a witness state without a note", not r["valid"],
           first_failure(r), "a claim is not a proof when witness signers are required")

    # 6
    b = env["bundle"](key_path=env["keys"]["attacker"])
    r = verify(env, b)
    record("6. re-sign the whole bundle with another key", not r["valid"],
           first_failure(r), "the signer must be in the allowed signers file")

    # 7
    try:
        core.redeem(env["intent"], env["grant"], env["signers"], env["ledger"],
                    policy=core.load_policy())
        caught, detail = False, "second redemption succeeded"
    except core.MandateError as exc:
        caught, detail = True, f"{type(exc).__name__}: {exc}"
    record("7. redeem the same grant twice (replay)", caught, "core.redeem", detail)

    lines = pathlib.Path(env["ledger"]).read_text(encoding="utf-8").splitlines()
    last_hash = json.loads(lines[-1])["hash"]
    head_path = env["ledger"] + ".head"
    pathlib.Path(head_path).write_text(last_hash + "\n", encoding="utf-8")

    # 8 edit the record inside the hashed body
    ledger_copy = os.path.join(env["work"], "ledger-attacked.jsonl")
    attacked = []
    for line in lines:
        entry = json.loads(line)
        entry["body"]["decision"] = "observe"
        attacked.append(json.dumps(entry))
    pathlib.Path(ledger_copy).write_text("\n".join(attacked) + "\n", encoding="utf-8")
    pathlib.Path(ledger_copy + ".head").write_text(last_hash + "\n", encoding="utf-8")
    try:
        caught = not core.verify_chain(ledger_copy)
        detail = "each entry must hash to its own body"
    except Exception as exc:                       # noqa: BLE001
        caught, detail = True, f"{type(exc).__name__}: {exc}"
    record("8. edit a record inside the hash-chained log", caught,
           "core.verify_chain", detail)

    # 9 drop the last entry but keep the sealed head
    truncated = os.path.join(env["work"], "ledger-truncated.jsonl")
    pathlib.Path(truncated).write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    pathlib.Path(truncated + ".head").write_text(last_hash + "\n", encoding="utf-8")
    try:
        caught = not core.verify_chain(truncated)
        detail = "the sealed head no longer matches the last entry"
    except Exception as exc:                       # noqa: BLE001
        caught, detail = True, f"{type(exc).__name__}: {exc}"
    record("9. drop the last entry (sealed head kept)", caught,
           "core.verify_chain", detail)

    # 10 rewrite an entry, rebuild the chain and re-sign the STH with a stolen log key.
    # The builder also holds the approver key in this scenario; only the witness, on
    # another host, still disagrees about the root.
    rewritten = os.path.join(env["work"], "ledger-rewritten.jsonl")
    # rewrite the first entry and keep only it: a single-entry chain must start at GENESIS
    entry = json.loads(lines[0])
    entry["body"]["decision"] = "observe"
    entry["hash"] = core.sha256(core.jcs(entry["body"]))
    pathlib.Path(rewritten).write_text(json.dumps(entry) + "\n", encoding="utf-8")
    leaves = mlog.leaves_from_ledger(rewritten)
    payload = mlog.sth_payload("log1", mlog.log_id_from_key(env["keys"]["logkey"]),
                               len(leaves), mlog.root_hex(leaves))
    new_sth = mlog.sign_sth(payload, env["keys"]["logkey"])
    new_proof = mlog.inclusion_proof(leaves, 0)
    b = env["bundle"](sth=new_sth, proof=new_proof)
    r = verify(env, b)
    record("10. rewrite an entry and re-sign the STH with a stolen log key",
           not r["valid"], first_failure(r),
           "the receipt does not sit under the rewritten root (inclusion); the witness "
           "note also still pins the original root")

    # 11 plant an instruction in a document and claim it as a data source
    tainted = dict(INTENT)
    tainted = json.loads(json.dumps(INTENT))
    tainted["nonce"] = "attack-taint"
    tainted["provenance"] = [{"type": "data_ref", "source": "email:supplier.pdf",
                             "trust": "untrusted", "covers": ["target", "amount"]}]
    pol = core.load_policy()
    pol["effects"] = dict(pol["effects"])
    pol["effects"]["payment.send"] = dict(pol["effects"]["payment.send"],
                                          require_trusted=["target", "amount"])
    decision = core.check(tainted, pol)
    caught = decision.get("reason") == "untrusted_input"
    record("11. plant the payee in an email and cite it as data",
           caught, "core.check", f"{decision.get('decision')}: {decision.get('reason')}"
           f" fields={decision.get('fields')}")

    # 12 same effect, but the source is the ERP: the gate must not block honest work
    trusted = json.loads(json.dumps(tainted))
    trusted["provenance"][0].update({"source": "erp:vendor:1", "trust": "trusted"})
    ok = core.check(trusted, pol).get("reason") != "untrusted_input"
    record("12. control: the same effect from the ERP is allowed", ok, "core.check",
           "trust labels must not turn into a blanket ban")

    # 13 write a known payee with a cyrillic letter so it looks new (or a blocked one
    #    so it looks allowed)
    from mandate import normalize, report
    payee = "Apple Inc"
    lookalike = "\u0410pple Inc"          # cyrillic A
    core.append_receipt(env["ledger"], {
        "v": 1, "type": "receipt", "decision": "executed", "ts": 1,
        "render": {"fields": {"kind": "payment.send", "target": payee,
                              "amount": {"value": 1, "currency": "BAM"}}}})
    hist = report.payee_history(env["ledger"], lookalike, "payment.send")
    record("13. spell a known payee with a homoglyph", not hist["first_time"],
           "report.payee_history", f"payments={hist['payments']} for {lookalike!r}; "
           f"fold={normalize.fold(lookalike)!r}")

    # 14 zero-width characters in the payee
    zw = "Apple\u200b Inc"
    hist = report.payee_history(env["ledger"], zw, "payment.send")
    record("14. hide a zero-width character in the payee", not hist["first_time"],
           "report.payee_history", f"payments={hist['payments']} for {zw!r}")

    # 15 claim the effect was only self-reported while the policy wants enforced
    b = env["bundle"]()
    b["receipt"]["body"]["coverage"] = "self_reported"
    r = verify(env, b)
    record("15. downgrade the coverage class inside a re-signed bundle", not r["valid"],
           first_failure(r), "the coverage class is inside the signed receipt")

    # 16 ship one witness where the policy asks for two
    from mandate import quorum as _quorum
    q = _quorum.evaluate([env["bundle"]()["witness_note"]], env["bundle"]()["sth"],
                         env["signers"], 2)
    record("16. ship a single witness when the policy asks for two", not q["ok"],
           "quorum.evaluate", q.get("message") or "ok")

    # 17 the record is signed, but the policy it claims to follow has changed since
    from mandate import replay as replay_mod
    b = env["bundle"]()
    other_policy = json.loads(json.dumps(core.load_policy()))
    other_policy["effects"]["payment.send"] = dict(
        other_policy["effects"]["payment.send"], max_auto=1)
    rep = replay_mod.replay(b, other_policy)
    record("17. replay the record under a policy that now says no", not rep["ok"],
           "mandate.replay", f"{rep.get('code')}: {rep.get('message', '')[:70]}")

    # 18 hide a value in a redacted view and then swap it on reveal
    from mandate import disclose as disc
    body = b["receipt"]["body"] if isinstance(b, dict) and isinstance(b.get("receipt"), dict) else None
    if body:
        view = disc.redact(body, ["render.fields.target"])
        try:
            disc.reveal(view, ["render.fields.target"], {"render.fields.target": "Attacker Ltd"})
            caught, detail = False, "swapped value was accepted"
        except disc.DisclosureError as exc:
            caught, detail = True, f"{getattr(exc, 'code', 'E_DISCLOSURE')}: {exc}"
        record("18. swap a value in a redacted view", caught, "mandate.disclose", detail)

    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write", default=None, help="write a Markdown report to this path")
    args = ap.parse_args(argv[1:])
    work = tempfile.mkdtemp(prefix="mandate-attacks-")
    env = build(work)
    rows = attacks(env)
    failed = [r for r in rows if not r["caught"]]
    if args.json:
        print(json.dumps({"attacks": rows, "caught": len(rows) - len(failed),
                          "total": len(rows)}, indent=1))
    else:
        width = max(len(r["attack"]) for r in rows) + 2
        for row in rows:
            print(f"{'caught' if row['caught'] else 'MISSED':<7} {row['attack']:<{width}}"
                  f" by {row['by']}")
        print(f"\n{len(rows) - len(failed)}/{len(rows)} attacks caught")
    if args.write:
        lines = ["# Attack evaluation", "",
                 f"Generated by `python3 tools/attack_eval.py --write {args.write}`.", "",
                 "| Attack | Caught | By | Why it is caught |", "|---|---|---|---|"]
        for row in rows:
            lines.append(f"| {row['attack']} | {'yes' if row['caught'] else '**no**'} "
                         f"| `{row['by']}` | {row['detail']} |")
        lines += ["", f"**{len(rows) - len(failed)}/{len(rows)} attacks caught.**",
                  "", "The tests in `tests/test_attacks.py` run this list; a case that stops",
                  "being caught fails CI."]
        pathlib.Path(args.write).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
