"""Policy review without running anything: lint, explain, diff.

A policy is the document that decides what an agent may do without a human. It
deserves the same review as code: a stable digest, a reason per rule, and a diff
an approver can read before signing.

  mandate policy lint
  mandate policy explain --effect payment.send --amount 500 --currency BAM
  mandate policy diff --against previous-policy.json
"""
from __future__ import annotations

from . import core

RISKS = ("low", "medium", "high")
KNOWN_FIELDS = {"risk", "max_auto", "require_data_ref", "require_hardware_key",
                "purpose", "max_amount", "currency", "notes"}


def lint(policy: dict) -> dict:
    problems: list[str] = []
    warnings: list[str] = []
    if not isinstance(policy, dict):
        return {"ok": False, "problems": ["policy is not an object"], "warnings": []}
    if policy.get("default") not in (None, "deny"):
        problems.append("default must be 'deny' (found %r)" % policy.get("default"))
    effects = policy.get("effects")
    if not isinstance(effects, dict) or not effects:
        problems.append("effects must be a non-empty object")
        effects = {}
    for kind, spec in effects.items():
        if not isinstance(spec, dict):
            problems.append("%s: spec must be an object" % kind)
            continue
        risk = spec.get("risk")
        if risk not in RISKS:
            problems.append("%s: risk must be one of %s (found %r)"
                            % (kind, "/".join(RISKS), risk))
        for field in sorted(set(spec) - KNOWN_FIELDS):
            warnings.append("%s: unknown field %r is ignored by check()" % (kind, field))
        if not str(spec.get("purpose") or "").strip():
            warnings.append("%s: no purpose - an approver cannot tell why this may "
                            "run without a human" % kind)
        max_auto = spec.get("max_auto")
        if max_auto is not None:
            try:
                if float(max_auto) < 0:
                    problems.append("%s: max_auto must not be negative" % kind)
            except (TypeError, ValueError):
                problems.append("%s: max_auto is not a number" % kind)
        if risk == "low" and max_auto:
            warnings.append("%s: risk=low ignores max_auto (everything is auto)" % kind)
        if risk == "high" and max_auto:
            warnings.append("%s: risk=high with max_auto=%s auto-approves up to that "
                            "amount" % (kind, max_auto))
    for kind in (policy.get("require_revert") or {}):
        if kind not in effects:
            problems.append("require_revert names %r which is not an effect" % kind)
    return {"ok": not problems, "problems": problems, "warnings": warnings,
            "effects": sorted(effects), "digest": core.policy_digest(policy)}


def explain(policy: dict, kind: str, amount: float | None = None) -> dict:
    effects = policy.get("effects") or {}
    spec = effects.get(kind)
    if not isinstance(spec, dict):
        return {"kind": kind, "decision": "deny", "reason": "unknown effect",
                "digest": core.policy_digest(policy)}
    risk = str(spec.get("risk") or "high")
    max_auto = spec.get("max_auto") or 0
    decision = "ask"
    because = "risk=%s needs a human signature" % risk
    if risk == "low":
        decision, because = "allow", "risk=low runs without a human"
    elif max_auto and amount is not None and float(amount) <= float(max_auto):
        decision, because = "allow", ("%.2f <= max_auto %s" % (amount, max_auto))
    return {
        "kind": kind, "decision": decision, "because": because, "risk": risk,
        "amount": amount,
        "auto_above": None if risk == "low" else max_auto or None,
        "provenance_required": list(spec.get("require_data_ref") or []),
        "hardware_key_required": bool(spec.get("require_hardware_key")),
        "revert_required": bool((policy.get("require_revert") or {}).get(kind)),
        "purpose": spec.get("purpose") or "",
        "digest": core.policy_digest(policy),
    }


def diff(old: dict, new: dict) -> dict:
    old_effects = (old.get("effects") or {})
    new_effects = (new.get("effects") or {})
    added = sorted(set(new_effects) - set(old_effects))
    removed = sorted(set(old_effects) - set(new_effects))
    changed = {}
    breaking = []
    for kind in sorted(set(old_effects) & set(new_effects)):
        a, b = old_effects[kind] or {}, new_effects[kind] or {}
        fields = {}
        for field in sorted(set(a) | set(b)):
            if a.get(field) != b.get(field):
                fields[field] = {"from": a.get(field), "to": b.get(field)}
        if fields:
            changed[kind] = fields
            order = {"low": 0, "medium": 1, "high": 2}
            if order.get(str(b.get("risk")), 2) > order.get(str(a.get("risk")), 2):
                breaking.append("%s: risk raised to %s" % (kind, b.get("risk")))
            if "max_auto" in fields and (b.get("max_auto") or 0) < (a.get("max_auto") or 0):
                breaking.append("%s: max_auto lowered (existing grants keep their own "
                                "digest, new ones are narrower)" % kind)
            if b.get("require_hardware_key") and not a.get("require_hardware_key"):
                breaking.append("%s: hardware key now required" % kind)
    for kind in removed:
        breaking.append("%s: effect removed" % kind)
    revert_added = sorted(set(new.get("require_revert") or {}) - set(old.get("require_revert") or {}))
    return {"added": added, "removed": removed, "changed": changed,
            "require_revert_added": revert_added,
            "old_digest": core.policy_digest(old), "new_digest": core.policy_digest(new),
            "breaking": breaking,
            "approver_note": ("stricter: existing grants keep working, new approvals "
                             "must be signed again" if breaking else "no narrowing detected")}
