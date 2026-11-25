"""`mandate demo`: the whole chain in one command, on a throwaway directory.

Nothing here is a mock of the product: it generates a real Ed25519 key, signs a
real grant, executes it through the same `redeem` path the broker uses, verifies
the receipt offline, and writes an audit pack. It exists so a room can see the
claim in sixty seconds instead of reading a README.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from . import core, report


def _keypair(directory: str) -> tuple[str, str]:
    key = os.path.join(directory, "approver")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "approver",
                    "-f", key], check=True)
    signers = os.path.join(directory, "allowed_signers")
    with open(signers, "w", encoding="utf-8") as fh:
        fh.write('approver namespaces="mandate" %s\n'
                 % open(key + ".pub", encoding="utf-8").read().strip())
    return key, signers


def run(directory: str | None = None, keep: bool = False) -> dict:
    directory = directory or tempfile.mkdtemp(prefix="mandate-demo-")
    os.makedirs(directory, exist_ok=True)
    steps = []

    def step(name: str, **detail) -> None:
        steps.append({"step": name, **detail})

    key, signers = _keypair(directory)
    policy = core.load_policy()
    step("keys", approver="approver", signers=os.path.relpath(signers, directory),
         policy_effects=len(policy["effects"]))

    intent = core.normalize_intent({
        "v": 1,
        "actor": {"agent": "demo-agent", "session": "demo-" + str(int(time.time()))},
        "effect": {"kind": "payment.send", "target": "Example Supplier",
                   "amount": {"value": 1170.0, "currency": "BAM"},
                   "params": {"ref": "faktura-77"},
                   "revert": "reverse_transfer"},
        "requested_by": "ops",
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1"},
                       {"type": "data_ref", "source": "Example Supplier"},
                       {"type": "data_ref", "source": "1170.00 BAM"}],
    })
    proposal = core.propose(intent)
    step("propose", commitment=proposal["commitment"][:24] + "…",
         render=proposal["render"]["summary"])

    decision = core.check(intent, policy)
    step("policy", decision=decision["decision"], risk=decision.get("risk"))

    grant_core = core.build_grant_core(
        proposal["commitment"], "approver", ttl_s=600,
        render_hash=proposal["render_hash"], agent="demo-agent",
        audience="demo-broker",
        policy_fingerprint=core.policy_digest(policy))
    grant = core.make_grant(grant_core, key)
    step("grant", signed_by="approver", max_uses=1)

    ledger = os.path.join(directory, "ledger.jsonl")
    receipt = core.redeem(intent, grant, signers, ledger, policy=policy,
                          audience="demo-broker")
    step("redeem", receipt_hash=receipt["hash"][:24] + "…",
         decision=receipt["body"].get("decision"),
         revert=receipt["body"].get("revert"))

    replay = None
    try:
        core.redeem(intent, grant, signers, ledger, policy=policy,
                    audience="demo-broker")
    except core.GrantReplayed:
        replay = "refused (grant already used)"
    step("replay", result=replay or "NOT REFUSED")

    changed = json.loads(json.dumps(intent))
    changed["effect"]["amount"]["value"] = 9999.0
    refused = None
    try:
        core.redeem(changed, grant, signers, ledger + ".2", policy=policy,
                    audience="demo-broker")
    except core.MandateError as exc:
        refused = type(exc).__name__
    step("changed_amount", result=refused or "NOT REFUSED")

    verified = core.verify_receipt(receipt, intent, grant, signers)
    step("verify", ok=bool(verified), chain=core.verify_chain(ledger, anchor=False))

    pack = report.pack(ledger, os.path.join(directory, "audit-pack"))
    step("pack", files=len(pack.get("files") or []), out="audit-pack")

    ok = bool(verified) and replay is not None and refused is not None
    result = {"ok": ok, "directory": directory, "steps": steps,
              "kept": bool(keep)}
    with open(os.path.join(directory, "demo.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
    return result
