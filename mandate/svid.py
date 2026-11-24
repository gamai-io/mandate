"""Short-lived agent identity (SVID) and delegation chains.

Why: a long-lived key file in the agent's filesystem is a shared credential. Banks
now require per-agent identity, short lifetime, and a delegation chain that can
only narrow ("agent acts for a named human, sub-agent for the agent").

A token is a signed, canonical JSON payload:

    {"v":1,"typ":"mandate-svid","sub":"bank-agent","iss":"bank-agent",
     "aud":"local-broker","scopes":["payment.send"],"iat":...,"exp":...,
     "jti":"...","parent_jti":null,"parent_sub":null}

Signature: the same SSH/Ed25519 mechanism as grants (`sign.sign(payload, key)`,
verified against `allowed_signers`), so there is one key story, not two.

Delegation: a child token names the parent's `jti`, and verification enforces
that the child's scopes are a subset, its expiry is not later, and its audience
is identical. A chain is only as wide as its narrowest link.
"""
from __future__ import annotations

import json
import secrets
import time

from . import sign
from .jcs import canonicalize as _jcs

TTL_MAX = 3600


def _payload_json(payload: dict) -> str:
    return _jcs(payload)


def _new_jti() -> str:
    return secrets.token_hex(8)


def issue(sub: str, key_path: str, issuer: str, audience: str,
          scopes: list[str], ttl: int = 300, parent: dict | None = None,
          now: float | None = None) -> dict:
    if not sub or not issuer:
        raise ValueError("sub and issuer are required")
    if ttl <= 0 or ttl > TTL_MAX:
        raise ValueError(f"ttl must be 1..{TTL_MAX} seconds")
    now = time.time() if now is None else now
    payload = {
        "v": 1,
        "typ": "mandate-svid",
        "sub": sub,
        "iss": issuer,
        "aud": audience,
        "scopes": sorted(set(scopes or [])),
        "iat": int(now),
        "exp": int(now) + int(ttl),
        "jti": _new_jti(),
        "parent_jti": None,
        "parent_sub": None,
    }
    if parent:
        payload["parent_jti"] = parent["jti"]
        payload["parent_sub"] = parent["sub"]
    signature = sign.sign(_payload_json(payload), key_path)
    return {"payload": payload, "sig": signature, "issuer": issuer}


def verify(token: dict, signers_path: str, audience: str | None = None,
           now: float | None = None, revoked_path: str | None = None) -> dict:
    now = time.time() if now is None else now
    payload = (token or {}).get("payload") or {}
    signature = (token or {}).get("sig") or ""
    issuer = (token or {}).get("issuer") or payload.get("iss") or ""
    result = {"valid": False, "code": None, "payload": payload}

    if payload.get("typ") != "mandate-svid" or payload.get("v") != 1:
        return {**result, "code": "not_a_svid"}
    # The subject must be the principal that signed: otherwise any key in
    # allowed_signers could mint a token for any agent.
    if str(payload.get("sub") or "") != str(payload.get("iss") or "") or issuer != payload.get("iss"):
        return {**result, "code": "issuer_subject_mismatch",
                "sub": payload.get("sub"), "iss": payload.get("iss"), "signer": issuer}
    if not sign.verify(_payload_json(payload), issuer, signature, signers_path,
                       sign.DEFAULT_NAMESPACE, revoked_path=revoked_path):
        return {**result, "code": "bad_signature"}
    if int(payload.get("exp") or 0) <= int(now):
        return {**result, "code": "expired", "exp": payload.get("exp")}
    if int(payload.get("iat") or 0) > int(now) + 60:
        return {**result, "code": "issued_in_the_future"}
    if audience and payload.get("aud") != audience:
        return {**result, "code": "wrong_audience", "aud": payload.get("aud")}
    return {**result, "valid": True, "code": "ok"}


def verify_chain(child: dict, parents: list[dict], signers_path: str,
                 audience: str | None = None, now: float | None = None,
                 revoked_path: str | None = None) -> dict:
    """Verify a child token and every parent it names; scopes may only narrow."""
    now = time.time() if now is None else now
    res = verify(child, signers_path, audience, now, revoked_path)
    if not res["valid"]:
        return res
    by_jti = {p.get("payload", {}).get("jti"): p for p in parents or []}
    current = child
    depth = 0
    while current.get("payload", {}).get("parent_jti"):
        depth += 1
        if depth > 8:
            return {**res, "valid": False, "code": "chain_too_deep"}
        parent = by_jti.get(current["payload"]["parent_jti"])
        if parent is None:
            return {**res, "valid": False, "code": "parent_missing",
                    "parent_jti": current["payload"]["parent_jti"]}
        pres = verify(parent, signers_path, audience, now, revoked_path)
        if not pres["valid"]:
            return {**res, "valid": False, "code": "parent_" + str(pres["code"])}
        cp, pp = current["payload"], parent["payload"]
        if not set(cp.get("scopes") or []).issubset(set(pp.get("scopes") or [])):
            return {**res, "valid": False, "code": "scope_widened",
                    "child": cp.get("scopes"), "parent": pp.get("scopes")}
        if int(cp.get("exp") or 0) > int(pp.get("exp") or 0):
            return {**res, "valid": False, "code": "expiry_extended"}
        if cp.get("aud") != pp.get("aud"):
            return {**res, "valid": False, "code": "audience_changed"}
        if cp.get("parent_sub") and cp.get("sub") == pp.get("sub"):
            return {**res, "valid": False, "code": "self_delegation"}
        current = parent
    return {**res, "valid": True, "code": "ok", "depth": depth}


def covers(token: dict, effect_kind: str, subject: str | None = None) -> dict:
    payload = (token or {}).get("payload") or {}
    if subject and payload.get("sub") != subject:
        return {"ok": False, "code": "subject_mismatch",
                "token_sub": payload.get("sub"), "expected": subject}
    scopes = payload.get("scopes") or []
    if effect_kind not in scopes and "*" not in scopes:
        return {"ok": False, "code": "scope_not_granted", "scopes": scopes,
                "effect": effect_kind}
    return {"ok": True, "code": "ok"}


def load(path: str) -> dict:
    return json.load(open(path, encoding="utf-8"))


def save(token: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(token, fh, indent=1, sort_keys=True)
