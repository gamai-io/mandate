from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import time
import uuid

from . import sign

try:
    import fcntl
except ImportError:
    fcntl = None

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
    if not isinstance(intent.get("v"), int) or intent.get("v") != VERSION:
        raise MandateError("unsupported intent version")
    effect = intent.get("effect")
    if not isinstance(effect, dict) or not isinstance(effect.get("kind"), str) \
            or not effect.get("kind"):
        raise MandateError("intent.effect.kind is required")
    extra = set(effect) - {"kind", "target", "amount", "params"}
    if extra:
        raise MandateError("unknown effect fields: %s" % sorted(extra))
    if effect.get("target") is not None and not isinstance(effect["target"], str):
        raise MandateError("effect.target must be a string")
    amount = effect.get("amount")
    if amount is not None:
        if not isinstance(amount, dict):
            raise MandateError("effect.amount must be an object")
        if set(amount) - {"value", "currency"}:
            raise MandateError("unknown amount fields")
        value = amount.get("value")
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or not math.isfinite(float(value)):
            raise MandateError("amount.value must be a finite number")
        if amount.get("currency") is not None and \
                not isinstance(amount["currency"], str):
            raise MandateError("amount.currency must be a string")
    params = effect.get("params") or {}
    if not isinstance(params, dict):
        raise MandateError("effect.params must be an object")
    for key, value in params.items():
        if not isinstance(key, str):
            raise MandateError("params keys must be strings")
        if isinstance(value, (dict, list)):
            raise MandateError("params values must be scalars")
        if isinstance(value, float) and not math.isfinite(value):
            raise MandateError("params values must be finite")
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
    if effect.get("target") is not None:
        parts.append("target=" + json.dumps(effect["target"], ensure_ascii=False))
    value, currency = _amount(intent)
    if value is not None:
        parts.append("amount=%.2f %s" % (value, currency))
    params = effect.get("params") or {}
    for key in sorted(params):
        parts.append("%s=%s" % (key, json.dumps(params[key], ensure_ascii=False)))
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
                     render_hash: str = "", agent: str = "",
                     audience: str = "") -> dict:
    now = int(time.time())
    return {
        "v": VERSION,
        "commitment": str(commitment),
        "render_hash": str(render_hash or ""),
        "agent": str(agent or ""),
        "audience": str(audience or ""),
        "approver": str(approver),
        "scope": {"max_uses": 1, "not_after": now + max(1, int(ttl_s))},
        "nonce": nonce or uuid.uuid4().hex,
    }


def make_grant(core: dict, key_path: str, namespace: str = "mandate") -> dict:
    try:
        signature = sign.sign(jcs(core), key_path, namespace)
    except sign.SignError as exc:
        raise MandateError("signing failed: %s" % str(exc)[:160]) from exc
    return {"grant": core, "sig": signature}


@contextlib.contextmanager
def _ledger_lock(path: str):
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(lock_path)), exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def read_ledger(path: str) -> list[dict]:
    entries = []
    try:
        fh = open(path, encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise MandateError("ledger unreadable: %s" % str(exc)[:120]) from exc
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError as exc:
                raise MandateError("ledger corrupt") from exc
    return entries


def _append_locked(path: str, body: dict) -> dict:
    entries = read_ledger(path)
    prev = entries[-1]["hash"] if entries else "GENESIS"
    body = dict(body, prev=prev)
    entry = {"body": body, "hash": sha256(jcs(body))}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(jcs(entry) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    head_path = path + ".head"
    tmp = head_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(entry["hash"])
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, head_path)
    return entry


def append_receipt(path: str, body: dict) -> dict:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with _ledger_lock(path):
        return _append_locked(path, body)


def _used_nonces(path: str) -> set[str]:
    return {str(e.get("body", {}).get("grant_nonce")) for e in read_ledger(path)}


def verify_chain(path: str, anchor: bool = True) -> bool:
    entries = read_ledger(path)
    if not entries:
        return False
    prev = "GENESIS"
    for entry in entries:
        body = entry.get("body") or {}
        if body.get("prev") != prev:
            return False
        if sha256(jcs(body)) != entry.get("hash"):
            return False
        prev = entry.get("hash")
    if anchor:
        head_path = path + ".head"
        if os.path.exists(head_path):
            try:
                with open(head_path, encoding="utf-8") as fh:
                    want = fh.read().strip()
            except OSError:
                return False
            if want != prev:
                return False
    return True


def verify_grant(grant_obj: dict, signers_path: str,
                 namespace: str = "mandate",
                 revoked_path: str | None = None,
                 now: float | None = None) -> bool:
    core = (grant_obj or {}).get("grant") or {}
    return sign.verify(jcs(core), str(core.get("approver") or ""),
                       str((grant_obj or {}).get("sig") or ""),
                       signers_path, namespace, revoked_path=revoked_path,
                       now=now)


def redeem(intent: dict, grant_obj: dict, signers_path: str,
           ledger_path: str, namespace: str = "mandate",
           allow_self: bool = False, now: float | None = None,
           claim=None, policy: dict | None = None,
           audience: str | None = None,
           require_audience: bool = False,
           revoked_path: str | None = None) -> dict:
    intent = normalize_intent(intent)
    policy_obj = policy if isinstance(policy, dict) else load_policy()
    decision = check(intent, policy_obj)
    if decision["decision"] == "deny":
        raise PolicyDenied("policy denied: %s" % decision.get("reason"))
    moment = time.time() if now is None else float(now)
    core = (grant_obj or {}).get("grant") or {}
    signature = str((grant_obj or {}).get("sig") or "")
    commitment = intent_commitment(intent)
    if core.get("commitment") != commitment:
        raise CommitmentMismatch("grant commitment does not match intent")
    if core.get("render_hash") != render_hash(intent):
        raise CommitmentMismatch("grant render hash does not match intent")
    bound_agent = str(core.get("agent") or "")
    if bound_agent and bound_agent != str(intent["actor"].get("agent") or ""):
        raise CommitmentMismatch("grant is bound to a different agent")
    if audience is not None:
        bound_audience = str(core.get("audience") or "")
        if require_audience and not bound_audience:
            raise GrantInvalid("grant is not bound to a broker audience")
        if bound_audience and bound_audience != str(audience):
            raise GrantInvalid("grant audience does not match this broker")
    if not sign.verify(jcs(core), str(core.get("approver") or ""), signature,
                       signers_path, namespace, revoked_path=revoked_path,
                       now=moment):
        raise GrantInvalid("grant signature invalid")
    if float((core.get("scope") or {}).get("not_after") or 0) <= moment:
        raise GrantExpired("grant expired")
    approver = str(core.get("approver") or "")
    if not allow_self and approver == str(intent["actor"].get("agent") or ""):
        raise SelfApproval("agent cannot approve its own effect")
    nonce = str(core.get("nonce") or "")
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
    if claim is not None:
        if not claim(nonce):
            raise GrantReplayed("grant already used")
        return append_receipt(ledger_path, receipt)
    os.makedirs(os.path.dirname(os.path.abspath(ledger_path)), exist_ok=True)
    with _ledger_lock(ledger_path):
        if nonce in _used_nonces(ledger_path):
            raise GrantReplayed("grant already used")
        return _append_locked(ledger_path, receipt)


def verify_receipt(receipt_entry: dict, intent: dict, grant_obj: dict,
                   signers_path: str, namespace: str = "mandate",
                   revoked_path: str | None = None) -> bool:
    body = (receipt_entry or {}).get("body") or {}
    if sha256(jcs(body)) != (receipt_entry or {}).get("hash"):
        return False
    if body.get("commitment") != intent_commitment(intent):
        return False
    if body.get("render_hash") != render_hash(intent):
        return False
    if not verify_grant(grant_obj, signers_path, namespace,
                        revoked_path=revoked_path):
        return False
    core = (grant_obj or {}).get("grant") or {}
    if body.get("grant_nonce") != core.get("nonce"):
        return False
    if core.get("render_hash") != render_hash(intent):
        return False
    return True


RESULT_SIGNED_FIELDS = ("v", "type", "receipt_hash", "grant_nonce", "effect",
                        "status", "result_hash", "broker", "ts")


def result_signing_payload(body: dict) -> dict:
    return {key: body.get(key) for key in RESULT_SIGNED_FIELDS}


def verify_result_entry(entry: dict, broker_signers: str,
                        revoked_path: str | None = None) -> bool:
    body = (entry or {}).get("body") or {}
    if sha256(jcs(body)) != (entry or {}).get("hash"):
        return False
    return sign.verify(jcs(result_signing_payload(body)),
                       str(body.get("broker") or ""),
                       str(body.get("broker_sig") or ""), broker_signers,
                       "mandate-broker", revoked_path=revoked_path)
