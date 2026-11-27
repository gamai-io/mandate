"""Capability tokens: authority that can only get narrower.

A grant authorises **one** effect; it does not say whether the agent was allowed to
ask in the first place. A capability token is that standing authority, and the one
property that makes delegation safe is **attenuation**: a child token can only
narrow what the parent allows.

    ops mints    kinds=[payment.send], max_amount=5000, targets=[A, B], ttl 8h
    team lead    attenuates -> max_amount=500, targets=[A]                 ok
    an agent     attenuates -> max_amount=9000                            refused

Rules enforced here (each with a code, each with a test):
    E_SIG          signature missing or not from an allowed signer
    E_EXPIRED      outside not_before/not_after
    E_CHAIN        parent hash does not match the token it claims
    E_WIDEN        the child allows something the parent does not
    E_SHAPE        malformed token

Not implemented, and not claimed: revocation of individual capability tokens lives in
`mandate revoke` for signing keys; per-token revocation lists and budget consumption
across a fleet are a ledger problem, not a token problem.
"""
from __future__ import annotations

import hashlib
import time
import uuid

from . import core, sign

FORMAT = "mandate-capability/1"
NAMESPACE = "mandate-capability"
CODE_SIG = "E_SIG"
CODE_EXPIRED = "E_EXPIRED"
CODE_CHAIN = "E_CHAIN"
CODE_WIDEN = "E_WIDEN"
CODE_SHAPE = "E_SHAPE"


class CapabilityError(ValueError):
    def __init__(self, message: str, code: str = CODE_SHAPE):
        super().__init__(message)
        self.code = code


def _payload(token: dict) -> str:
    return core.jcs({k: v for k, v in token.items() if k not in ("sig", "signer")})


def digest(token: dict) -> str:
    return "sha256:" + hashlib.sha256(_payload(token).encode("utf-8")).hexdigest()


def _scope(value) -> dict:
    if not isinstance(value, dict):
        raise CapabilityError("scopes must be an object", CODE_SHAPE)
    kinds = value.get("kinds")
    if kinds is not None and (not isinstance(kinds, list)
                              or any(not isinstance(k, str) for k in kinds)):
        raise CapabilityError("scopes.kinds must be a list of strings", CODE_SHAPE)
    targets = value.get("targets")
    if targets is not None and (not isinstance(targets, list)
                               or any(not isinstance(t, str) for t in targets)):
        raise CapabilityError("scopes.targets must be a list of strings", CODE_SHAPE)
    amount = value.get("max_amount")
    if amount is not None and (isinstance(amount, bool)
                               or not isinstance(amount, (int, float)) or amount < 0):
        raise CapabilityError("scopes.max_amount must be a non-negative number", CODE_SHAPE)
    currency = value.get("currency")
    if currency is not None and not isinstance(currency, str):
        raise CapabilityError("scopes.currency must be a string", CODE_SHAPE)
    return {"kinds": kinds, "max_amount": amount, "currency": currency, "targets": targets}


def mint(scopes: dict, key_path: str, issuer: str, subject: str,
         ttl_s: int = 3600, max_uses: int = 1, parent: str | None = None,
         now: float | None = None, not_before: float | None = None) -> dict:
    start = float(now if now is not None else time.time())
    token = {
        "v": 1,
        "type": "mandate-capability",
        "format": FORMAT,
        "issuer": str(issuer),
        "subject": str(subject),
        "scopes": _scope(scopes),
        "not_before": int(not_before if not_before is not None else start),
        "not_after": int(start + int(ttl_s)),
        "max_uses": int(max_uses),
        "parent": str(parent or ""),
        "nonce": uuid.uuid4().hex,
    }
    token["sig"] = sign.sign(_payload(token), key_path, NAMESPACE)
    token["signer"] = str(issuer)
    return token


def verify(token: dict, signers_path: str, now: float | None = None,
           revoked_path: str | None = None) -> dict:
    """Signature and validity window. Does not look at the parent."""
    if not isinstance(token, dict) or token.get("format") != FORMAT:
        raise CapabilityError("not a capability token", CODE_SHAPE)
    if not sign.verify(_payload(token), str(token.get("signer") or ""),
                       str(token.get("sig") or ""), signers_path, NAMESPACE,
                       revoked_path=revoked_path):
        raise CapabilityError("capability signature invalid", CODE_SIG)
    moment = float(now if now is not None else time.time())
    if moment < int(token.get("not_before") or 0):
        raise CapabilityError("capability not valid yet", CODE_EXPIRED)
    if moment > int(token.get("not_after") or 0):
        raise CapabilityError("capability expired", CODE_EXPIRED)
    return {"ok": True, "subject": str(token.get("subject") or ""),
            "issuer": str(token.get("issuer") or ""),
            "scopes": token.get("scopes") or {}, "digest": digest(token)}


def narrower(child: dict, parent: dict) -> None:
    """Raise E_WIDEN when the child allows anything the parent does not."""
    c, p = child.get("scopes") or {}, parent.get("scopes") or {}
    pk = p.get("kinds")
    if pk is not None and "*" not in pk:
        for kind in (c.get("kinds") or []):
            if kind != "*" and kind not in pk:
                raise CapabilityError("child allows kind %r, parent does not" % kind,
                                      CODE_WIDEN)
    if c.get("kinds") is None and pk is not None:
        raise CapabilityError("child dropped the kind list, which allows everything",
                              CODE_WIDEN)
    pc, cc = p.get("max_amount"), c.get("max_amount")
    if pc is not None and (cc is None or float(cc) > float(pc)):
        raise CapabilityError("child max_amount %s exceeds parent %s" % (cc, pc),
                              CODE_WIDEN)
    pcur, ccur = p.get("currency"), c.get("currency")
    if pcur is not None and ccur is not None and ccur != pcur:
        raise CapabilityError("child currency %r differs from parent %r" % (ccur, pcur),
                              CODE_WIDEN)
    if pcur is not None and ccur is None:
        raise CapabilityError("child dropped the currency restriction", CODE_WIDEN)
    pt = p.get("targets")
    if pt is not None:
        if c.get("targets") is None:
            raise CapabilityError("child dropped the target list, which allows any payee",
                                  CODE_WIDEN)
        for target in c["targets"]:
            if target not in pt:
                raise CapabilityError("child allows target %r, parent does not" % target,
                                      CODE_WIDEN)
    # max_uses i not_after su na nivou tokena, ne u scopes
    pmu = int(parent.get("max_uses") or 0)          # 0 = neograničeno
    cmu = int(child.get("max_uses") or 0)
    if pmu and (cmu == 0 or cmu > pmu):
        raise CapabilityError("child max_uses %s exceeds parent %s" % (cmu, pmu), CODE_WIDEN)
    if int(child.get("not_after") or 0) > int(parent.get("not_after") or 0):
        raise CapabilityError("child lives longer than the parent", CODE_WIDEN)


def attenuate(parent: dict, scopes: dict, key_path: str, subject: str,
              ttl_s: int | None = None, max_uses: int | None = None,
              now: float | None = None, signers_path: str | None = None) -> dict:
    """Mint a child token that can only narrow the parent."""
    if signers_path:
        verify(parent, signers_path, now=now)
    # potpisuje onaj ko prenosi (parent.subject); novi nosilac je `subject`
    child = mint(scopes, key_path, str(parent.get("subject") or ""), subject,
                 ttl_s=(ttl_s if ttl_s is not None
                        else int(parent.get("not_after") or 0) - int(now or time.time())),
                 max_uses=(max_uses if max_uses is not None
                           else int(parent.get("max_uses") or 1)),
                 parent=digest(parent), now=now)
    narrower(child, parent)
    return child


def verify_chain(chain: list[dict], signers_path: str, now: float | None = None,
                 revoked_path: str | None = None) -> dict:
    """Verify root -> leaf, each link signed and each child narrower than its parent."""
    if not chain:
        raise CapabilityError("empty chain", CODE_SHAPE)
    for index, token in enumerate(chain):
        verify(token, signers_path, now=now, revoked_path=revoked_path)
        if index == 0:
            if token.get("parent"):
                raise CapabilityError("root token claims a parent", CODE_CHAIN)
            continue
        parent = chain[index - 1]
        if str(token.get("parent") or "") != digest(parent):
            raise CapabilityError("token %d does not chain to its parent" % index,
                                  CODE_CHAIN)
        narrower(token, parent)
    return {"ok": True, "length": len(chain),
            "subject": str(chain[-1].get("subject") or ""),
            "digest": digest(chain[-1]),
            "scopes": chain[-1].get("scopes") or {}}


def allows(token: dict, intent: dict) -> dict:
    """Does this token permit the *request*? (The grant still authorises the effect.)"""
    effect = (intent or {}).get("effect") or {}
    kind = str(effect.get("kind") or "")
    amount = effect.get("amount") or {}
    scopes = token.get("scopes") or {}
    kinds = scopes.get("kinds")
    if kinds is not None and "*" not in kinds and kind not in kinds:
        return {"ok": False, "why": "kind %r is not in the token" % kind}
    targets = scopes.get("targets")
    target = str(effect.get("target") or "")
    if targets is not None and target and target not in targets:
        return {"ok": False, "why": "target %r is not in the token" % target}
    cap = scopes.get("max_amount")
    value = amount.get("value")
    if cap is not None and value is not None and float(value) > float(cap):
        return {"ok": False, "why": "amount %s exceeds %s" % (value, cap)}
    cur = scopes.get("currency")
    if cur is not None and amount.get("currency") not in (None, cur):
        return {"ok": False, "why": "currency %r is not %r" % (amount.get("currency"), cur)}
    return {"ok": True, "why": "", "scopes": scopes}
