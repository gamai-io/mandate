from __future__ import annotations

import hashlib
import json
import os
import time
import uuid

from . import sign

VERSION = 1
DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "data", "policy.json")


class MandateError(Exception):
    pass


class PolicyDenied(MandateError):
    pass


class CommitmentMismatch(MandateError):
    pass


class GrantInvalid(MandateError):
    pass


class GrantExpired(MandateError):
    pass


class GrantReplayed(MandateError):
    pass


class SelfApproval(MandateError):
    pass


def jcs(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_policy(path: str | None = None) -> dict:
    p = path or os.environ.get("MANDATE_POLICY") or DEFAULT_POLICY
    data = load_json(p)
    if not isinstance(data, dict) or not isinstance(data.get("effects"), dict):
        raise MandateError("invalid policy")
    return data


def normalize_intent(intent: dict) -> dict:
    if not isinstance(intent, dict):
        raise MandateError("intent must be an object")
    if int(intent.get("v", 0)) != VERSION:
        raise MandateError("unsupported intent version")
    effect = intent.get("effect")
    if not isinstance(effect, dict) or not effect.get("kind"):
        raise MandateError("intent.effect.kind is required")
    actor = intent.get("actor")
    if not isinstance(actor, dict) or not actor.get("agent"):
        raise MandateError("intent.actor.agent is required")
    if not intent.get("requested_by"):
        raise MandateError("intent.requested_by is required")
    out = dict(intent)
    out["nonce"] = str(intent.get("nonce") or uuid.uuid4().hex)
    out.setdefault("provenance", [])
    return out


def intent_core(intent: dict) -> dict:
    return {
        "v": VERSION,
        "effect": intent["effect"],
        "requested_by": intent.get("requested_by"),
        "render_hash": render_hash(intent),
    }


def intent_commitment(intent: dict) -> str:
    return "sha256:" + sha256(jcs(intent_core(intent)))


def proposal_id(intent: dict) -> str:
    return "m1" + sha256(jcs(intent))[:24]


def _amount(intent: dict):
    amount = (intent.get("effect") or {}).get("amount")
    if not isinstance(amount, dict):
        return None, None
    try:
        return float(amount.get("value")), str(amount.get("currency") or "BAM")
    except (TypeError, ValueError):
        return None, None


def render(intent: dict) -> dict:
    effect = intent.get("effect") or {}
    parts = [str(effect.get("kind") or "?")]
    if effect.get("target"):
        parts.append(str(effect["target"]))
    value, currency = _amount(intent)
    if value is not None:
        parts.append(f"{value:.2f} {currency}")
    params = effect.get("params") or {}
    for key in sorted(params):
        parts.append(f"{key}={params[key]}")
    evidence = sorted({
        str(p.get("source"))
        for p in (intent.get("provenance") or [])
        if isinstance(p, dict) and p.get("type") == "data_ref" and p.get("source")
    })
    if evidence:
        parts.append("evidence=" + ",".join(evidence))
    return {
        "summary": " | ".join(parts),
        "fields": {
            "kind": effect.get("kind"),
            "target": effect.get("target"),
            "amount": ({"value": value, "currency": currency}
                       if value is not None else None),
            "params": params,
            "evidence": evidence,
        },
    }


def render_hash(intent: dict) -> str:
    return sha256(jcs(render(intent)))


def check(intent: dict, policy: dict | None = None) -> dict:
    intent = normalize_intent(intent)
    pol = policy if isinstance(policy, dict) else load_policy()
    kind = str(intent["effect"]["kind"])
    spec = pol["effects"].get(kind)
    if not isinstance(spec, dict):
        return {"decision": "deny", "reason": "unknown effect", "kind": kind}
    risk = str(spec.get("risk") or "high")
    value, _currency = _amount(intent)
    if risk == "low":
        decision = "allow"
    else:
        max_auto = spec.get("max_auto") or 0
        if max_auto and value is not None and value <= float(max_auto):
            decision = "allow"
        else:
            decision = "ask"
    return {
        "decision": decision,
        "risk": risk,
        "kind": kind,
        "amount": value,
        "render": render(intent),
    }


def propose(intent: dict) -> dict:
    intent = normalize_intent(intent)
    return {
        "v": VERSION,
        "proposal_id": proposal_id(intent),
        "commitment": intent_commitment(intent),
        "render_hash": render_hash(intent),
        "render": render(intent),
        "intent": intent,
    }


def build_grant_core(commitment: str, approver: str, max_uses: int = 1,
                     ttl_s: int = 900, nonce: str | None = None,
                     render_hash: str = "") -> dict:
    now = int(time.time())
    return {
        "v": VERSION,
        "commitment": str(commitment),
        "render_hash": str(render_hash or ""),
        "approver": str(approver),
        "scope": {"max_uses": max(1, int(max_uses)),
                  "not_after": now + max(1, int(ttl_s))},
        "nonce": nonce or uuid.uuid4().hex,
    }


def make_grant(core: dict, key_path: str, namespace: str = "mandate") -> dict:
    signature = sign.sign(jcs(core), key_path, namespace)
    return {"grant": core, "sig": signature}


def read_ledger(path: str) -> list[dict]:
    entries = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except OSError:
        return []
    return entries


def append_receipt(path: str, body: dict) -> dict:
    entries = read_ledger(path)
    prev = entries[-1]["hash"] if entries else "GENESIS"
    body = dict(body, prev=prev)
    entry = {"body": body, "hash": sha256(jcs(body))}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(jcs(entry) + "\n")
    return entry


def _used_nonces(path: str) -> set[str]:
    return {str(e.get("body", {}).get("grant_nonce")) for e in read_ledger(path)}


def verify_chain(path: str) -> bool:
    prev = "GENESIS"
    for entry in read_ledger(path):
        body = entry.get("body") or {}
        if body.get("prev") != prev:
            return False
        if sha256(jcs(body)) != entry.get("hash"):
            return False
        prev = entry.get("hash")
    return True


def verify_grant(grant_obj: dict, signers_path: str,
                 namespace: str = "mandate") -> bool:
    core = (grant_obj or {}).get("grant") or {}
    return sign.verify(jcs(core), str(core.get("approver") or ""),
                       str((grant_obj or {}).get("sig") or ""),
                       signers_path, namespace)


def redeem(intent: dict, grant_obj: dict, signers_path: str,
           ledger_path: str, namespace: str = "mandate",
           allow_self: bool = False, now: float | None = None,
           claim=None) -> dict:
    intent = normalize_intent(intent)
    core = (grant_obj or {}).get("grant") or {}
    signature = str((grant_obj or {}).get("sig") or "")
    commitment = intent_commitment(intent)
    if core.get("commitment") != commitment:
        raise CommitmentMismatch("grant commitment does not match intent")
    if core.get("render_hash") != render_hash(intent):
        raise CommitmentMismatch("grant render hash does not match intent")
    if not sign.verify(jcs(core), str(core.get("approver") or ""), signature,
                       signers_path, namespace):
        raise GrantInvalid("grant signature invalid")
    moment = time.time() if now is None else float(now)
    if float((core.get("scope") or {}).get("not_after") or 0) <= moment:
        raise GrantExpired("grant expired")
    approver = str(core.get("approver") or "")
    if not allow_self and approver == str(intent["actor"].get("agent") or ""):
        raise SelfApproval("agent cannot approve its own effect")
    nonce = str(core.get("nonce") or "")
    if claim is not None:
        if not claim(nonce):
            raise GrantReplayed("grant already used")
    elif nonce in _used_nonces(ledger_path):
        raise GrantReplayed("grant already used")
    receipt = {
        "v": VERSION,
        "type": "receipt",
        "proposal_id": proposal_id(intent),
        "commitment": commitment,
        "render_hash": render_hash(intent),
        "approver": approver,
        "grant_nonce": nonce,
        "decision": "executed",
        "result_hash": sha256(jcs(intent)),
        "ts": int(moment),
        "render": render(intent),
    }
    return append_receipt(ledger_path, receipt)


def verify_receipt(receipt_entry: dict, intent: dict, grant_obj: dict,
                   signers_path: str, namespace: str = "mandate") -> bool:
    body = (receipt_entry or {}).get("body") or {}
    if sha256(jcs(body)) != (receipt_entry or {}).get("hash"):
        return False
    if body.get("commitment") != intent_commitment(intent):
        return False
    if body.get("render_hash") != render_hash(intent):
        return False
    if not verify_grant(grant_obj, signers_path, namespace):
        return False
    core = (grant_obj or {}).get("grant") or {}
    if body.get("grant_nonce") != core.get("nonce"):
        return False
    if core.get("render_hash") != render_hash(intent):
        return False
    return True
