"""Replay: can a third party re-derive the decision from the evidence alone?

Verification today answers "was this record produced by someone we trust and is
it intact". It does not answer "would this policy really have allowed it". A
receipt can be perfectly signed and still describe a decision the recorded policy
would have refused — because the policy changed afterwards, or because the
builder ran a different one.

`replay()` recomputes everything the decision depended on and says what matches:

    commitment   intent -> intent_commitment (what the approver signed)
    render_hash  what the human saw
    result_hash  the exact bytes that were executed
    policy       recorded policy_digest vs the policy supplied now
    taint        the trust picture recorded in the receipt
    decision     recorded executed/observe vs a fresh `check()`

Outcome codes:
    E_REPLAY_HASH   a hash does not match the recorded bytes  (tampering)
    E_POLICY_DRIFT  the policy now differs from the recorded one (not tampering,
                    but the decision is no longer reproducible with this policy)
    E_DECISION      the recorded decision differs from what the policy says now
"""
from __future__ import annotations

from . import core

CODE_HASH = "E_REPLAY_HASH"
CODE_POLICY = "E_POLICY_DRIFT"
CODE_DECISION = "E_DECISION"


def replay(bundle: dict, policy: dict | None = None) -> dict:
    receipt = ((bundle or {}).get("receipt") or {}).get("body") or {}
    intent = (bundle or {}).get("intent") or {}
    checks: dict[str, dict] = {}

    def check(name, expected, actual):
        checks[name] = {"ok": expected == actual, "recorded": expected, "recomputed": actual}

    try:
        normalized = core.normalize_intent(intent)
    except core.MandateError as exc:
        return {"ok": False, "code": CODE_HASH, "checks": checks,
                "message": "intent does not normalise: %s" % exc}

    check("commitment", receipt.get("commitment"), core.intent_commitment(normalized))
    check("render_hash", receipt.get("render_hash"), core.render_hash(normalized))
    check("result_hash", receipt.get("result_hash"),
          core.sha256(core.jcs(normalized)))
    check("taint", receipt.get("taint"), core.taint_report(normalized))

    pol = policy if isinstance(policy, dict) else core.load_policy()
    recorded_digest = receipt.get("policy_digest")
    check("policy_digest", recorded_digest, core.policy_digest(pol) if recorded_digest else None)

    decided = core.check(normalized, pol)
    recorded_decision = str(receipt.get("decision") or "")
    recomputed = str(decided.get("decision") or "")
    # „ask" znaci da je odluka isla coveku — a covek je potpisao grant, pa je
    # executed/observe kompatibilno i sa allow i sa ask. Samo „deny" nije.
    if recorded_decision in ("executed", "observe"):
        decision_ok = recomputed in ("allow", "ask")
    elif recorded_decision == "refused":
        decision_ok = recomputed == "deny"
    else:
        decision_ok = recomputed == recorded_decision
    checks["decision"] = {"ok": decision_ok,
                          "recorded": recorded_decision,
                          "recomputed": recomputed,
                          "policy_reason": decided.get("reason")}

    hash_ok = all(checks[k]["ok"] for k in ("commitment", "render_hash", "result_hash", "taint"))
    policy_ok = checks["policy_digest"]["ok"]
    decision_ok = checks["decision"]["ok"]

    out = {"ok": hash_ok and policy_ok and decision_ok, "checks": checks,
           "reproducible": hash_ok and decision_ok}
    if not hash_ok:
        out["code"] = CODE_HASH
        out["message"] = "recorded bytes do not match the hashes in the receipt"
    elif not policy_ok:
        out["code"] = CODE_POLICY
        out["message"] = ("the policy now has a different digest than the receipt "
                          "recorded; the decision cannot be reproduced with it")
    elif not decision_ok:
        out["code"] = CODE_DECISION
        out["message"] = ("recorded decision %r but the policy says %r"
                          % (recorded_decision, decided.get("decision")))
    return out
