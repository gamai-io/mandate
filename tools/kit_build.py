#!/usr/bin/env python3
"""Build the conformance cases for `tools/kit.py`.

One valid bundle and one bundle per failure mode. Keys are generated per build, so the
committed cases are regenerated with `python3 tools/kit_build.py`; the case list
(`spec/kit/cases.json`) names the expected verdict and, for a rejection, which check must
be the first to fail.

    python3 tools/kit_build.py            # writes spec/kit/cases/
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from mandate import core, export  # noqa: E402
from mandate import log as mlog  # noqa: E402
from mandate import witness as mwit  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
KIT = ROOT / "spec" / "kit"
INTENT = {
    "v": 1,
    "actor": {"agent": "agent@example", "session": "kit"},
    "effect": {"kind": "payment.send", "target": "Supplier",
               "amount": {"value": 10.0, "currency": "BAM"}},
    "requested_by": "approver",
    "nonce": "kit-nonce-1",
    "provenance": [{"type": "data_ref", "source": "erp:vendor:1",
                    "covers": ["target", "amount"]}],
}


def keys(directory: str):
    approver = os.path.join(directory, "approver")
    logkey = os.path.join(directory, "logkey")
    other = os.path.join(directory, "other")
    wkey = os.path.join(directory, "witness")
    for path in (approver, logkey, other, wkey):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path],
                       check=True)
    signers = os.path.join(directory, "signers")
    pathlib.Path(signers).write_text(
        'approver namespaces="mandate,mandate-export" {}\n'
        'log1 namespaces="mandate-log" {}\n'.format(
            pathlib.Path(approver + ".pub").read_text().strip(),
            pathlib.Path(logkey + ".pub").read_text().strip()), encoding="utf-8")
    log_signers = os.path.join(directory, "log_signers")
    pathlib.Path(log_signers).write_text(
        'log1 namespaces="mandate-log" {}\n'.format(
            pathlib.Path(logkey + ".pub").read_text().strip()), encoding="utf-8")
    witness_signers = os.path.join(directory, "witness_signers")
    pathlib.Path(witness_signers).write_text(
        'witness1 namespaces="mandate-witness" {}\n'.format(
            pathlib.Path(wkey + ".pub").read_text().strip()), encoding="utf-8")
    return approver, logkey, other, wkey, signers, log_signers, witness_signers


def build(work: str):
    approver, logkey, other, wkey, signers, log_signers, witness_signers = keys(work)
    ledger = os.path.join(work, "ledger.jsonl")
    proposal = core.propose(INTENT)
    grant_core = core.build_grant_core(proposal["commitment"], "approver", ttl_s=900,
                                       render_hash=proposal["render_hash"],
                                       agent="agent@example")
    grant = core.make_grant(grant_core, approver)
    receipt = core.redeem(INTENT, grant, signers, ledger, policy=core.load_policy())
    leaves = mlog.leaves_from_ledger(ledger)
    proof = mlog.inclusion_proof(leaves, 0)
    payload = mlog.sth_payload("log1", mlog.log_id_from_key(logkey), len(leaves),
                               mlog.root_hex(leaves))
    sth = mlog.sign_sth(payload, logkey)
    state_path = os.path.join(work, "witness.json")
    mwit.accept(sth, None, signers, state_path, key_path=wkey, signer="witness1")
    state = mwit.load_state(state_path)

    def clone(value):
        return json.loads(json.dumps(value))

    def bundle(**over):
        # deep copies: each case is mutated independently, and a shared nested dict would
        # silently change the bundle the signature was made over
        proof_value = over.pop("proof", clone(proof))
        receipt_value = over.pop("receipt", clone(receipt))
        if receipt_value is not clone(receipt):
            # izmijenjen receipt mora imati svoj hash, inače prvi padne "receipt" provjera
            receipt_value["hash"] = core.sha256(core.jcs(receipt_value["body"]))
        kwargs = dict(key_path=approver, signer="approver", sth=clone(sth),
                      witness_state=clone(state))
        kwargs.update(over)
        return export.build_bundle(clone(receipt_value), clone(INTENT), clone(grant),
                                   proof_value, **kwargs)

    _case_no = [0]

    def relogged(body):
        """Zapiši izmijenjeni body kroz append_receipt i napravi novi STH/proof/note.

        Ručno sastavljanje JSON-a nije dovoljno: leaf hash pokriva i ono što append_receipt
        upiše (prev/hash), pa inclusion padne prije provjere koja se testira.
        """
        _case_no[0] += 1
        no = _case_no[0]
        ledger2 = os.path.join(work, "ledger-case-%d.jsonl" % no)
        entry = core.append_receipt(ledger2, body)
        leaves2 = mlog.leaves_from_ledger(ledger2)
        payload2 = mlog.sth_payload("log1", mlog.log_id_from_key(logkey),
                                    len(leaves2), mlog.root_hex(leaves2))
        sth2 = mlog.sign_sth(payload2, logkey)
        state_path2 = os.path.join(work, "witness-case-%d.json" % no)
        mwit.accept(sth2, None, signers, state_path2, key_path=wkey, signer="witness1")
        return {"receipt": entry, "sth": sth2,
                "proof": mlog.inclusion_proof(leaves2, 0),
                "witness_state": mwit.load_state(state_path2)}

    cases = {}

    def resigned(**over):
        """Build, apply a tamper, then sign again: this tests the CHECK, not the seal."""
        return bundle(**over)

    cases["valid"] = dict(bundle=bundle(), expect={"valid": True})

    # tampering with the signed content is caught by the envelope signature
    tampered = bundle()
    tampered["receipt"]["body"]["decision"] = "observe"
    cases["tampered_receipt"] = dict(bundle=tampered, expect={"valid": False, "fails": "signature"})

    bad_sig = bundle()
    value = bad_sig["signature"]["value"]
    bad_sig["signature"]["value"] = value[:-40] + ("A" if value[-40] != "A" else "B") + value[-39:]
    cases["tampered_signature"] = dict(bundle=bad_sig, expect={"valid": False, "fails": "signature"})

    cases["unknown_signer"] = dict(bundle=bundle(key_path=other),
                                   expect={"valid": False, "fails": "signature"})

    # the checks below need a valid seal, otherwise the signature fails first and the
    # check under test is never reached: tamper, then sign again with the approver key
    bad_sth = bundle()
    bad_sth["sth"]["sig"] = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
    cases["sth_bad_signature"] = dict(bundle=resigned(sth=bad_sth["sth"]),
                                      expect={"valid": False, "fails": "sth"})

    bad_proof = bundle()
    bad_proof["inclusion_proof"]["leaf_hash"] = "00" * 32
    cases["proof_tampered"] = dict(bundle=resigned(proof=bad_proof["inclusion_proof"]),
                                   expect={"valid": False, "fails": "inclusion"})

    # a state file with no signed note is only a claim: an auditor who requires witness
    # signatures must refuse it, and must refuse it at the witness check
    claim_only = clone(state)
    claim_only.pop("note", None)
    claim_only["tree_size"] = 999
    cases["witness_claim_only"] = dict(bundle=resigned(witness_state=claim_only),
                                       expect={"valid": False, "fails": "witness"})

    forged = bundle()
    note = dict(forged["witness_note"])
    note["text"] = note["text"].replace(f"tree_size: {int(payload['tree_size'])}",
                                        f"tree_size: {int(payload['tree_size']) + 1}")
    forged["witness_note"] = note
    cases["witness_note_forged"] = dict(bundle=resigned(witness_note=note),
                                        expect={"valid": False, "fails": "witness"})

    # COVERAGE_V1: receipt bez klase prolazi samo u kompat modu; sa --require-coverage pada
    no_cov_body = clone(receipt)["body"]
    no_cov_body.pop("coverage", None)
    cases["coverage_missing"] = dict(
        bundle=resigned(**relogged(no_cov_body)),
        expect={"valid": False, "fails": "coverage"},
        extra=["--require-coverage"])

    # ... a klasa koja ne postoji je laž i pada bez ikakvog flaga
    bad_cov_body = clone(receipt)["body"]
    bad_cov_body["coverage"] = "trust_me"
    cases["coverage_invalid"] = dict(bundle=resigned(**relogged(bad_cov_body)),
                                     expect={"valid": False, "fails": "coverage"})

    # TAINT_V1: taint blok mora odgovarati intentu iz bundlea
    bad_taint_body = clone(receipt)["body"]
    bad_taint_body["taint"] = {
        "untrusted_fields": [], "unknown_fields": [], "trusted_fields": [],
        "material_untrusted": [], "tainted": False}
    cases["taint_mismatch"] = dict(bundle=resigned(**relogged(bad_taint_body)),
                                   expect={"valid": False, "fails": "taint"})

    return cases, wkey, signers, log_signers, witness_signers


def main() -> int:
    work = tempfile.mkdtemp(prefix="mandate-kit-")
    try:
        cases, wkey, signers, log_signers, witness_signers = build(work)
        if KIT.exists():
            shutil.rmtree(KIT)
        (KIT / "cases").mkdir(parents=True)
        shutil.copyfile(signers, KIT / "signers")
        shutil.copyfile(log_signers, KIT / "log_signers")
        shutil.copyfile(witness_signers, KIT / "witness_signers")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    manifest = []
    for name, case in cases.items():
        path = KIT / "cases" / f"{name}.json"
        path.write_text(json.dumps(case["bundle"], indent=1, sort_keys=True) + "\n",
                        encoding="utf-8")
        entry = {"name": name, "bundle": str(path.relative_to(ROOT)), **case["expect"]}
        if case.get("extra"):
            entry["extra"] = case["extra"]
        manifest.append(entry)
    (KIT / "cases.json").write_text(json.dumps(
        {"format": "mandate-conformance-kit/1",
         "signers": str((KIT / "signers").relative_to(ROOT)),
         "log_signers": str((KIT / "log_signers").relative_to(ROOT)),
         "witness_signers": str((KIT / "witness_signers").relative_to(ROOT)),
         "cases": manifest}, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(manifest)} cases to {KIT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
