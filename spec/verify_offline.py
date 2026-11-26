#!/usr/bin/env python3
"""Verify a Mandate grant and receipt with nothing but the Python standard library.

This file is deliberately independent of the `mandate` package: it imports no
project code and never calls `ssh-keygen`. If the vendor disappears, this script
and the vectors next to it are enough to check that a receipt was signed by the
key named in an `allowed_signers` file, that the grant authorises exactly the
effect in the intent, and that a ledger entry is the hash of its own body.

    python3 spec/verify_offline.py \
        --grant spec/vectors/grant.json \
        --intent spec/vectors/intent.json \
        --signers spec/vectors/allowed_signers \
        --receipt spec/vectors/receipt.json

Exit 0 = every check passed, 1 = at least one failed, 2 = usage.

Limits, stated here rather than discovered later: this checks signatures,
commitments and the hash chain. It does not check that a nonce was claimed once
(that needs the ledger) and it does not check a timestamp authority token.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import time
from decimal import Decimal

MAX_SAFE = 2 ** 53 - 1


# --------------------------------------------------------------------------- JCS
def _utf16_key(text):
    data = text.encode("utf-16-be")
    return tuple(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))


def _escape(text):
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError("lone surrogate")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value):
    if isinstance(value, bool):
        raise TypeError("bool is not a number")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE:
            raise ValueError("integer outside the safe range")
        return str(value)
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite number")
    if number == 0:
        return "0"
    sign = "-" if number < 0 else ""
    decimal = Decimal(repr(abs(number)))
    digits = list(decimal.as_tuple().digits)
    exponent = decimal.as_tuple().exponent
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    count = len(digits)
    position = exponent + count
    text = "".join(str(d) for d in digits)
    if count <= position <= 21:
        rendered = text + "0" * (position - count)
    elif 0 < position <= 21:
        rendered = text[:position] + "." + text[position:]
    elif -6 < position <= 0:
        rendered = "0." + "0" * (-position) + text
    else:
        exp = position - 1
        mantissa = text[0] + ("." + text[1:] if count > 1 else "")
        rendered = mantissa + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))
    return sign + rendered


# ---------------------------------------------------------------- strict JSON
# This file must run on its own: an auditor copies one script and nothing else. The
# strictness rules are therefore duplicated here instead of imported from the package.
MAX_DEPTH = 128
MAX_INT = 2 ** 53 - 1


class StrictJSONError(ValueError):
    def __init__(self, code, detail=""):
        self.code = code
        super().__init__(code + (": " + detail if detail else ""))


def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise StrictJSONError("duplicate_key", key)
        obj[key] = value
    return obj


def _no_constants(token):
    raise StrictJSONError("non_finite", token)


def _int_guard(token):
    if len(token.lstrip("-")) > 16 or abs(int(token)) > MAX_INT:
        raise StrictJSONError("int_range", token)
    return int(token)


def _walk(value, depth=0):
    if depth > MAX_DEPTH:
        raise StrictJSONError("depth", str(depth))
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise StrictJSONError("lone_surrogate", value[:20]) from None
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    raise StrictJSONError("lone_surrogate", key[:20]) from None
            _walk(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _walk(item, depth + 1)


def _load(path):
    """Read a document that may be signed; refuse anything a second parser could read differently."""
    raw = open(path, "rb").read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise StrictJSONError("invalid_utf8") from None
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates,
                           parse_constant=_no_constants, parse_int=_int_guard)
    except StrictJSONError:
        raise
    except json.JSONDecodeError as exc:
        raise StrictJSONError("syntax", str(exc)[:80]) from None
    _walk(value)
    return value


def jcs(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("object keys must be strings")
        keys = sorted(value.keys(), key=_utf16_key)
        return "{" + ",".join(_escape(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise TypeError("unsupported type: %r" % type(value))


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------- Ed25519
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493   # group order
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)   # sqrt(-1) mod p


def _xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * SQRT_M1) % P
    if x % 2 != 0:
        x = P - x
    return x


_By = 4 * pow(5, P - 2, P) % P
_B = (_xrecover(_By) % P, _By)


def _edwards_add(p, q):
    x1, y1 = p
    x2, y2 = q
    k = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + k, P - 2, P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - k, P - 2, P)
    return (x3 % P, y3 % P)


def _scalar_mult(point, scalar):
    result = (0, 1)
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


def _decode_point(data):
    if len(data) != 32:
        raise ValueError("bad point length")
    value = int.from_bytes(data, "little")
    y = value & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (value >> 255) & 1:
        x = P - x
    if (-x * x + y * y - 1 - D * x * x * y * y) % P != 0:
        raise ValueError("point is not on the curve")
    return (x, y)


def ed25519_verify(public_key, signature, message):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        a = _decode_point(public_key)
        r = _decode_point(signature[:32])
        s = int.from_bytes(signature[32:], "little")
    except ValueError:
        return False
    if s >= L:                     # reject a non-canonical scalar
        return False
    h = int.from_bytes(hashlib.sha512(
        signature[:32] + public_key + message).digest(), "little") % L
    left = _scalar_mult(_B, s)
    right = _edwards_add(r, _scalar_mult(a, h))
    return left == right


# ---------------------------------------------------------------------- SSHSIG
BEGIN = "-----BEGIN SSH SIGNATURE-----"
END = "-----END SSH SIGNATURE-----"


def _read_string(blob, offset):
    if offset + 4 > len(blob):
        raise ValueError("truncated")
    length = int.from_bytes(blob[offset:offset + 4], "big")
    start = offset + 4
    if start + length > len(blob):
        raise ValueError("truncated")
    return blob[start:start + length], start + length


def _ssh_string(data):
    return len(data).to_bytes(4, "big") + data


def parse_sshsig(armored):
    lines = [line.strip() for line in armored.strip().splitlines()]
    if not lines or lines[0] != BEGIN:
        raise ValueError("not an SSH signature")
    body = "".join(line for line in lines if not line.startswith("-----"))
    blob = base64.b64decode(body)
    if not blob.startswith(b"SSHSIG"):
        raise ValueError("bad magic")
    offset = 6
    version = int.from_bytes(blob[offset:offset + 4], "big")
    if version != 1:
        raise ValueError("unsupported SSHSIG version")
    offset += 4
    public_key, offset = _read_string(blob, offset)
    namespace, offset = _read_string(blob, offset)
    reserved, offset = _read_string(blob, offset)
    hash_algorithm, offset = _read_string(blob, offset)
    signature_blob, offset = _read_string(blob, offset)
    key_type, _ = _read_string(public_key, 0)
    key_bytes, _ = _read_string(public_key, 4 + len(key_type))
    sig_type, _ = _read_string(signature_blob, 0)
    sig_bytes, _ = _read_string(signature_blob, 4 + len(sig_type))
    if key_type != b"ssh-ed25519" or sig_type != b"ssh-ed25519":
        raise ValueError("only ssh-ed25519 is checked by this script")
    return {"public_key": key_bytes, "public_blob": public_key,
            "namespace": namespace.decode(), "reserved": reserved,
            "hash": hash_algorithm.decode(), "signature": sig_bytes}


def sshsig_verify(armored, payload, namespace="mandate"):
    parsed = parse_sshsig(armored)
    if parsed["namespace"] != namespace:
        return False, "namespace is %r, expected %r" % (parsed["namespace"], namespace)
    digest = hashlib.new(parsed["hash"], payload.encode("utf-8")).digest()
    to_sign = (b"SSHSIG" + _ssh_string(parsed["namespace"].encode())
               + _ssh_string(parsed["reserved"])
               + _ssh_string(parsed["hash"].encode())
               + _ssh_string(digest))
    if not ed25519_verify(parsed["public_key"], parsed["signature"], to_sign):
        return False, "signature does not verify"
    return True, "signature verifies"


# ------------------------------------------------------------------ Mandate-1
def provenance_hash(intent):
    return sha256_hex(jcs(intent.get("provenance") or []))


def intent_core(intent):
    """Exactly what the approver signs: the effect, who may execute it, and the
    hash of every provenance entry that must be present at redemption."""
    effect = dict(intent["effect"])
    effect["revert"] = str(effect.get("revert") or "irreversible")
    actor = intent.get("actor") or {}
    return {"v": intent.get("v", 1),
            "actor": {"agent": actor.get("agent"), "session": actor.get("session")},
            "nonce": intent.get("nonce"),
            "effect": effect,
            "requested_by": intent.get("requested_by"),
            "render_hash": render_hash(intent),
            "provenance_hash": provenance_hash(intent)}


def render(intent):
    effect = intent.get("effect") or {}
    parts = [str(effect.get("kind") or "?")]
    if effect.get("target") is not None:
        parts.append("target=" + json.dumps(effect["target"], ensure_ascii=False))
    amount = effect.get("amount")
    value = currency = None
    if isinstance(amount, dict):
        try:
            value = float(amount.get("value"))
        except (TypeError, ValueError):
            value = None
        currency = amount.get("currency")
    if value is not None:
        parts.append("amount=%.2f %s" % (value, currency))
    params = effect.get("params") or {}
    for key in sorted(params):
        parts.append("%s=%s" % (key, json.dumps(params[key], ensure_ascii=False)))
    evidence = sorted({str(p.get("source")) for p in (intent.get("provenance") or [])
                       if isinstance(p, dict) and p.get("type") == "data_ref"
                       and p.get("source")})
    if evidence:
        parts.append("evidence=" + ",".join(evidence))
    return {"summary": " | ".join(parts),
            "fields": {"kind": effect.get("kind"), "target": effect.get("target"),
                       "amount": ({"value": value, "currency": currency}
                                  if value is not None else None),
                       "params": params, "evidence": evidence}}


def render_hash(intent):
    return sha256_hex(jcs(render(intent)))


def commitment_of(intent):
    return "sha256:" + sha256_hex(jcs(intent_core(intent)))


def _norm_time(text):
    text = str(text or "").strip()
    if len(text) == 8:
        text += "000000"
    elif len(text) == 12:
        text += "00"
    return text if len(text) == 14 and text.isdigit() else None


def _valid_now(entry, now):
    moment = time.strftime("%Y%m%d%H%M%S", time.gmtime(now))
    after, before = _norm_time(entry.get("after")), _norm_time(entry.get("before"))
    if entry.get("after") and after is None:
        return False
    if entry.get("before") and before is None:
        return False
    if after and moment < after:
        return False
    if before and moment >= before:
        return False
    return True


def allowed_keys(path):
    """Every authorised line, with its namespace and validity options."""
    import re
    entries = []
    for line in open(path, encoding="utf-8"):
        raw = line.strip()
        if len(raw) < 3 or raw.startswith("#"):
            continue
        tokens = raw.split()
        principal = tokens[0]
        key_type = next((t for t in tokens if t.startswith(("ssh-", "ecdsa-", "sk-"))), None)
        if key_type is None:
            continue
        idx = tokens.index(key_type)
        if idx + 1 >= len(tokens):
            continue
        options = " ".join(tokens[:idx])
        blob = tokens[idx + 1]
        ns = re.search(r'namespaces\s*=\s*"([^"]*)"', options)
        va = re.search(r'valid-after\s*=\s*"([^"]*)"', options)
        vb = re.search(r'valid-before\s*=\s*"([^"]*)"', options)
        entries.append({
            "principal": principal,
            "patterns": [p.strip() for p in principal.split(",") if p.strip()],
            "namespaces": ([x.strip() for x in ns.group(1).split(",") if x.strip()]
                           if ns else []),
            "after": va.group(1) if va else None,
            "before": vb.group(1) if vb else None,
            "key": base64.b64decode(blob + "=" * (-len(blob) % 4)),
        })
    return entries


def fingerprint(blob):
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def authorised(entries, principal, blob, namespace, revoked, now):
    """True only if this exact key is allowed for the principal right now."""
    import fnmatch
    stamp = fingerprint(blob).replace("SHA256:", "").lower()
    if stamp in revoked:
        return False, "key is revoked"
    for entry in entries:
        if not any(fnmatch.fnmatchcase(principal, p) for p in entry["patterns"]):
            continue
        if entry["key"] != blob:
            continue
        if namespace not in entry["namespaces"]:
            continue
        if not _valid_now(entry, now):
            continue
        return True, "signature key is authorised for %r" % principal
    return False, "signature key is not authorised for %r (namespace/validity/revocation)" % principal


# ------------------------------------------------------------------------- CLI
def verify(grant_path, intent_path, signers_path, receipt_path,
           namespace="mandate", revoked_path=None, revoke_now=None):
    grant_obj = _load(grant_path)
    checks, errors = [], []
    core = grant_obj.get("grant") or {}
    signature = str(grant_obj.get("sig") or "")

    ok, why = sshsig_verify(signature, jcs(core) + "\n", namespace)
    checks.append({"check": "grant_signature", "ok": ok, "detail": why})
    if not ok:
        errors.append(why)

    entries = allowed_keys(signers_path)
    approver = str(core.get("approver") or "")
    entries_all = entries
    revoked = set()
    if revoked_path:
        try:
            for line in open(revoked_path, encoding="utf-8"):
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    revoked.add(line.split()[0].replace("sha256:", ""))
        except OSError:
            revoked = set()
    try:
        embedded = parse_sshsig(signature)["public_blob"]
    except ValueError:
        embedded = b""
    ok, why = authorised(entries_all, approver, embedded, namespace, revoked,
                         time.time() if revoke_now is None else revoke_now)
    checks.append({"check": "signer_authorised", "ok": ok, "detail": why})
    if not ok:
        errors.append(why)

    if intent_path:
        intent = _load(intent_path)
        computed = commitment_of(intent)
        same = computed == core.get("commitment")
        checks.append({"check": "commitment_matches_intent", "ok": same,
                       "detail": "computed %s, grant says %s"
                                 % (computed, core.get("commitment"))})
        if not same:
            errors.append("grant commitment does not match the intent")
        rhash = core.get("render_hash")
        same_hash = (not rhash) or rhash == render_hash(intent)
        checks.append({"check": "render_hash_matches_intent", "ok": same_hash,
                       "detail": "approver saw %s" % render(intent)["summary"]})
        if not same_hash:
            errors.append("render hash does not match the intent")

    if receipt_path:
        receipt = _load(receipt_path)
        body = receipt.get("body") or {}
        recomputed = sha256_hex(jcs(body))
        same = recomputed == receipt.get("hash")
        checks.append({"check": "receipt_hash", "ok": same,
                       "detail": "recomputed %s" % recomputed})
        if not same:
            errors.append("receipt hash does not match its body")
        bound = body.get("commitment") == core.get("commitment")
        checks.append({"check": "receipt_bound_to_grant", "ok": bound,
                       "detail": "commitment %s" % body.get("commitment")})
        if not bound:
            errors.append("receipt is for a different commitment")

    return {"ok": not errors, "checks": checks, "errors": errors}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify a Mandate grant and receipt offline.")
    ap.add_argument("--grant", required=True)
    ap.add_argument("--signers", required=True)
    ap.add_argument("--revoked", default=None,
                    help="revoked key fingerprints (one per line)")
    ap.add_argument("--intent", default=None)
    ap.add_argument("--receipt", default=None)
    ap.add_argument("--namespace", default="mandate")
    args = ap.parse_args(argv)
    try:
        result = verify(args.grant, args.intent, args.signers, args.receipt,
                        namespace=args.namespace, revoked_path=args.revoked)
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"ok": False, "errors": [str(exc)]}, indent=1))
        return 1
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
