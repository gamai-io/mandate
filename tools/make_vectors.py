#!/usr/bin/env python3
"""Write the published test vectors for spec/verify_offline.py.

These keys are generated for the vectors and are worthless: they exist so anyone
can run the independent verifier and see a pass and a fail.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile

from mandate import core

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "spec", "vectors")


def keypair(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name,
                    "-f", path], check=True)
    return path


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        key = keypair(td, "approver")
        signers = os.path.join(OUT, "allowed_signers")
        with open(signers, "w", encoding="utf-8") as fh:
            fh.write('approver namespaces="mandate" %s\n'
                     % open(key + ".pub", encoding="utf-8").read().strip())

        intent = core.normalize_intent({
            "v": 1,
            "actor": {"agent": "bank-agent", "session": "s-42"},
            "effect": {"kind": "payment.send", "target": "Example Supplier",
                       "amount": {"value": 1170.0, "currency": "BAM"},
                       "params": {"ref": "faktura-77"},
                       "revert": "reverse_transfer"},
            "requested_by": "ops",
            "nonce": "n-vector-1",
            "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}],
        })
        grant_core = core.build_grant_core(
            core.intent_commitment(intent), "approver", ttl_s=86400,
            render_hash=core.render_hash(intent), agent="bank-agent",
            audience="local-broker",
            policy_fingerprint=core.policy_digest(core.load_policy()))
        grant = core.make_grant(grant_core, key)
        body = core.build_receipt(intent, grant_core,
                                  core.intent_commitment(intent),
                                  core.sha256(core.jcs(intent)), ts=1795560000)
        ledger = os.path.join(td, "ledger.jsonl")
        core.append_receipt(ledger, body)
        receipt = json.loads(open(ledger, encoding="utf-8").read().strip().splitlines()[-1])

        def dump(name: str, obj) -> None:
            with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
                json.dump(obj, fh, indent=1, sort_keys=True)
                fh.write("\n")

        dump("intent.json", intent)
        dump("grant.json", grant)
        dump("receipt.json", receipt)

        # a tampered intent: the amount the approver never saw
        tampered = json.loads(json.dumps(intent))
        tampered["effect"]["amount"]["value"] = 9999.0
        dump("intent-tampered.json", tampered)

        # a tampered receipt: body changed, hash left as it was
        forged = json.loads(json.dumps(receipt))
        forged["body"]["decision"] = "allowed"
        dump("receipt-tampered.json", forged)

    print("vectors written to %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
