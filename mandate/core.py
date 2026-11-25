from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import time
import uuid

from . import sign
from .jcs import canonicalize as _canonicalize

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


class ProvenanceMissing(MandateError):
    pass


class HardwareKeyRequired(MandateError):
    pass


def jcs(obj) -> str:
    return _canonicalize(obj)


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
    extra = set(effect) - {"kind", "target", "amount", "params", "revert"}
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
    provenance = intent.get("provenance") or []
    if not isinstance(provenance, list):
        raise MandateError("intent.provenance must be a list")
    for entry in provenance:
        if not isinstance(entry, dict):
            raise MandateError("provenance entries must be objects")
        kind = entry.get("type")
        if kind not in ("user_pref", "data_ref", "model_inference"):
            raise MandateError("provenance type must be user_pref, data_ref "
                               "or model_inference")
        if kind == "data_ref" and not str(entry.get("source") or "").strip():
            raise MandateError("data_ref provenance requires a source")
        covers = entry.get("covers")
        if covers is not None and (
                not isinstance(covers, list)
                or any(not isinstance(item, str) for item in covers)):
            raise MandateError("provenance covers must be a list of strings")
    out = dict(intent)
    out["nonce"] = str(intent.get("nonce") or uuid.uuid4().hex)
    out["provenance"] = provenance
    return out


def intent_core(intent: dict) -> dict:
    """What the approver signs: the effect AND who is allowed to execute it."""
    actor = intent.get("actor") or {}
    effect = dict(intent["effect"])
    effect["revert"] = str(effect.get("revert") or "irreversible")
    return {
        "v": VERSION,
        "actor": {"agent": actor.get("agent"), "session": actor.get("session")},
        "nonce": intent.get("nonce"),
        "effect": effect,
        "requested_by": intent.get("requested_by"),
        "render_hash": render_hash(intent),
        "provenance_hash": provenance_hash(intent),
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


def provenance_hash(intent: dict) -> str:
    return sha256(jcs(intent.get("provenance") or []))


def missing_provenance(intent: dict, spec: dict) -> list[str]:
    required = spec.get("require_data_ref") or []
    if not required:
        return []
    refs = [entry for entry in (intent.get("provenance") or [])
            if entry.get("type") == "data_ref"
            and str(entry.get("source") or "").strip()]
    missing = []
    for field in required:
        covered = any((not entry.get("covers"))
                      or field in entry.get("covers") for entry in refs)
        if not covered:
            missing.append(str(field))
    return missing


def policy_digest(policy: dict | None) -> str:
    """Stable fingerprint of the policy that authorised an effect."""
    return sha256(jcs(policy or {}))[:32]


def check(intent: dict, policy: dict | None = None) -> dict:
    intent = normalize_intent(intent)
    pol = policy if isinstance(policy, dict) else load_policy()
    kind = str(intent["effect"]["kind"])
    spec = pol["effects"].get(kind)
    if not isinstance(spec, dict):
        return {"decision": "deny", "reason": "unknown effect", "kind": kind}
    missing = missing_provenance(intent, spec)
    if missing:
        return {"decision": "deny", "reason": "missing_data_ref",
                "missing": missing, "provenance_ok": False,
                "risk": spec.get("risk"), "kind": kind,
                "render": render(intent)}
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
        "provenance_ok": True,
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
                     audience: str = "", policy_fingerprint: str = "") -> dict:
    now = int(time.time())
    return {
        "v": VERSION,
        "commitment": str(commitment),
        "render_hash": str(render_hash or ""),
        "agent": str(agent or ""),
        "audience": str(audience or ""),
        "policy_digest": str(policy_fingerprint or ""),
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


def _tail_entry(path: str) -> dict | None:
    """Read only the last line of the ledger.

    The previous append wrote `.head`, so a cheap check suffices: if the last line
    parses and its hash equals `.head`, the whole file does not need reading.
    Anything unexpected falls back to a full read.
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            if size == 0:
                return None
            window = min(65536, size)
            fh.seek(size - window)
            tail = fh.read()
    except OSError:
        return None
    line = tail.rstrip().split(b"\n")[-1]
    try:
        entry = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(entry, dict) or "body" not in entry or "hash" not in entry:
        return None
    if sha256(jcs(entry["body"])) != entry["hash"]:
        raise MandateError("the last ledger entry does not match its own hash: "
                           "the file was edited; refusing to append")
    try:
        head = open(path + ".head", encoding="utf-8").read().strip()
    except OSError:
        return None
    return entry if entry["hash"] == head else None


def _append_locked(path: str, body: dict) -> dict:
    tail = _tail_entry(path)
    if tail is not None:
        prev = tail["hash"]
    else:
        entries = read_ledger(path)
        if entries:
            last = entries[-1]
            if sha256(jcs(last.get("body") or {})) != last.get("hash"):
                raise MandateError("the last ledger entry does not match its own "
                                   "hash: the file was edited; refusing to append")
        head_path = path + ".head"
        if entries and os.path.exists(head_path):
            try:
                head = open(head_path, encoding="utf-8").read().strip()
            except OSError:
                head = ""
            if head and head != entries[-1]["hash"]:
                raise MandateError(
                    "ledger head does not match the last entry: the file was "
                    "truncated or tampered with; refusing to append")
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


def claim_nonce_db(nonce: str, ledger_path: str | None = None) -> bool:
    """Atomically claim a grant nonce. False = already used, raises = cannot tell."""
    from . import nonce as _nonce
    try:
        return _nonce.claim(nonce, ledger_path)
    except _nonce.NonceUnavailable as exc:
        raise MandateError("nonce store unavailable: %s" % str(exc)[:120]) from exc


def _used_nonces(path: str) -> set[str]:
    used = set()
    for entry in read_ledger(path):
        body = entry.get("body") or {}
        if body.get("binding") is False or body.get("decision") == "observe":
            continue          # observation must not consume the grant
        used.add(str(body.get("grant_nonce")))
    return used


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


def verify_authorization(intent: dict, grant_obj: dict, signers_path: str,
                         namespace: str = "mandate",
                         allow_self: bool = False, now: float | None = None,
                         policy: dict | None = None,
                         audience: str | None = None,
                         require_audience: bool = False,
                         revoked_path: str | None = None) -> dict:
    intent = normalize_intent(intent)
    policy_obj = policy if isinstance(policy, dict) else load_policy()
    decision = check(intent, policy_obj)
    approved_digest = str(((grant_obj or {}).get("grant") or {}).get("policy_digest") or "")
    if approved_digest and approved_digest != policy_digest(policy_obj):
        raise PolicyDenied("policy changed since approval: %s != %s"
                           % (approved_digest, policy_digest(policy_obj)))
    if decision["decision"] == "deny":
        if decision.get("missing"):
            raise ProvenanceMissing(
                "missing data_ref for: %s" % ", ".join(decision["missing"]))
        raise PolicyDenied("policy denied: %s" % decision.get("reason"))
    moment = time.time() if now is None else float(now)
    grant_core = (grant_obj or {}).get("grant") or {}
    signature = str((grant_obj or {}).get("sig") or "")
    commitment = intent_commitment(intent)
    if grant_core.get("commitment") != commitment:
        raise CommitmentMismatch("grant commitment does not match intent")
    if grant_core.get("render_hash") != render_hash(intent):
        raise CommitmentMismatch("grant render hash does not match intent")
    bound_agent = str(grant_core.get("agent") or "")
    if bound_agent and bound_agent != str(intent["actor"].get("agent") or ""):
        raise CommitmentMismatch("grant is bound to a different agent")
    bound_audience = str(grant_core.get("audience") or "")
    if bound_audience and audience is None:
        raise GrantInvalid("grant is bound to audience %r; this caller did not "
                           "identify itself" % bound_audience)
    if audience is not None:
        if require_audience and not bound_audience:
            raise GrantInvalid("grant is not bound to a broker audience")
        if bound_audience and bound_audience != str(audience):
            raise GrantInvalid("grant audience does not match this broker")
    if not sign.verify(jcs(grant_core), str(grant_core.get("approver") or ""),
                       signature, signers_path, namespace,
                       revoked_path=revoked_path, now=moment):
        raise GrantInvalid("grant signature invalid")
    spec = (policy_obj.get("effects") or {}).get(
        str(intent["effect"]["kind"])) or {}
    if isinstance(spec, dict) and spec.get("require_hardware_key"):
        keytype = sign.keytype_for(str(grant_core.get("approver") or ""),
                                   signers_path, namespace)
        if not sign.is_hardware_key(keytype):
            raise HardwareKeyRequired(
                "approver key is not a hardware key (sk-ssh-ed25519)")
    if float((grant_core.get("scope") or {}).get("not_after") or 0) <= moment:
        raise GrantExpired("grant expired")
    approver = str(grant_core.get("approver") or "")
    if not allow_self and approver == str(intent["actor"].get("agent") or ""):
        raise SelfApproval("agent cannot approve its own effect")
    return {"intent": intent, "grant": grant_core,
            "commitment": commitment, "render_hash": render_hash(intent),
            "moment": moment}


RECEIPT_SIGN_EXCLUDE = ("prev", "signature", "signer", "signer_backend",
                        "signer_command", "ledger_head")


def _receipt_signable(body: dict) -> dict:
    return {k: v for k, v in body.items() if k not in RECEIPT_SIGN_EXCLUDE}


def sign_receipt(body: dict, key_path: str, signer: str) -> dict:
    body = dict(body)
    body["signature"] = sign.sign(jcs(_receipt_signable(body)), key_path)
    body["signer"] = signer
    return body


def sign_receipt_external(body: dict, command: str) -> dict:
    """Sign the receipt with an external HSM/KMS adapter (no key in our process)."""
    from . import signing as _signing
    payload = jcs(_receipt_signable(body))
    result = _signing.sign_with(command, payload)
    body = dict(body)
    body["signature"] = result["sig"]
    body["signer"] = result["signer"]
    body["signer_backend"] = "external"
    body["signer_command"] = command.split()[0] if command else ""
    return body


def verify_receipt_signature(body: dict, signers_path: str,
                             revoked_path: str | None = None) -> bool:
    if not body.get("signature"):
        return False
    return bool(sign.verify(jcs(_receipt_signable(body)), str(body.get("signer") or ""),
                            str(body["signature"]), signers_path,
                            sign.DEFAULT_NAMESPACE, revoked_path=revoked_path))


def build_receipt(intent: dict, grant_core: dict, commitment: str,
                  result_hash: str, decision: str = "executed",
                  ts: float | None = None) -> dict:
    return {
        "v": VERSION,
        "type": "receipt",
        "proposal_id": proposal_id(intent),
        "commitment": commitment,
        "render_hash": render_hash(intent),
        "approver": str(grant_core.get("approver") or ""),
        "agent": str((intent.get("actor") or {}).get("agent") or ""),
        "session": str((intent.get("actor") or {}).get("session") or ""),
        "grant_nonce": str(grant_core.get("nonce") or ""),
        "decision": decision,
        "result_hash": result_hash,
        "ts": int(time.time() if ts is None else ts),
        "render": render(intent),
    }


def enforce_new_payee(intent: dict, policy: dict, ledger_path: str) -> None:
    """A policy can require that a beneficiary has been paid before.

    `effects.<kind>.new_payee` accepts "allow" (default), "ask" or "deny". It is a
    check on the past, so it needs the ledger; the broker and the CLI both call it
    before the grant is spent.
    """
    from . import report as _report
    effect = intent.get("effect") or {}
    spec = ((policy or {}).get("effects") or {}).get(str(effect.get("kind") or "")) or {}
    mode = str(spec.get("new_payee") or "allow").lower()
    if mode == "allow":
        return
    target = str(effect.get("target") or "")
    if not target:
        return
    history = _report.payee_history(ledger_path, target, str(effect.get("kind") or ""))
    if history["first_time"]:
        raise PolicyDenied("first-time payee %r: policy says new_payee=%s"
                           % (target, mode))


def redeem(intent: dict, grant_obj: dict, signers_path: str,
           ledger_path: str, namespace: str = "mandate",
           allow_self: bool = False, now: float | None = None,
           claim=None, policy: dict | None = None,
           audience: str | None = None,
           require_audience: bool = False,
           revoked_path: str | None = None,
           sign_key: str | None = None, signer: str | None = None,
           signer_cmd: str | None = None, observe: bool = False) -> dict:
    verified = verify_authorization(
        intent, grant_obj, signers_path, namespace, allow_self, now, policy,
        audience, require_audience, revoked_path)
    intent = verified["intent"]
    grant_core = verified["grant"]
    nonce = str(grant_core.get("nonce") or "")
    receipt = build_receipt(intent, grant_core, verified["commitment"],
                            sha256(jcs(intent)), ts=verified["moment"],
                            decision="observe" if observe else "executed")
    if policy is not None:
        receipt["policy_digest"] = policy_digest(policy)
    receipt["binding"] = not observe
    effect = intent.get("effect") or {}
    receipt["revert"] = str(effect.get("revert") or ("irreversible" if not effect.get("revert") else ""))
    if policy is not None and (policy.get("require_revert") or {}).get(str(effect.get("kind"))):
        if not effect.get("revert"):
            raise MandateError("policy requires a revert step for %s" % effect.get("kind"))
    if observe:      # observation must not spend the grant
        return append_receipt(ledger_path, receipt)
    if (policy or {}).get("require_signed_receipts") and not (sign_key or signer_cmd):
        raise MandateError("policy requires signed receipts: pass --key/--signer "
                           "or --signer-cmd")
    if sign_key:
        receipt = sign_receipt(receipt, sign_key, signer or str(grant_core.get("approver") or ""))
    elif signer_cmd:
        receipt = sign_receipt_external(receipt, signer_cmd)
    if claim is not None:
        if not claim(nonce):
            raise GrantReplayed("grant already used")
        if not claim_nonce_db(nonce):     # a custom callback must not skip the cross-ledger check
            raise GrantReplayed("grant already used (nonce seen in another ledger)")
        return append_receipt(ledger_path, receipt)
    os.makedirs(os.path.dirname(os.path.abspath(ledger_path)), exist_ok=True)
    with _ledger_lock(ledger_path):
        if nonce in _used_nonces(ledger_path):
            raise GrantReplayed("grant already used")
        if not claim_nonce_db(nonce, ledger_path):
            raise GrantReplayed("grant already used (nonce seen in another ledger)")
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
    if body.get("policy_digest") and core.get("policy_digest") and \
            body["policy_digest"] != core["policy_digest"]:
        return False
    if body.get("signature") and not verify_receipt_signature(
            body, signers_path, revoked_path=revoked_path):
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
