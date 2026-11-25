"""WebAuthn assertion verification with the standard library.

Approving with a key file on the host proves possession of a key. A bank asks a
harder question: *which device, unlocked by which human, with which user
verification?* That is what a passkey answers, and this module verifies the
answer without pulling in a WebAuthn library.

Supported: `ES256` (P-256, what platform passkeys use) and `EdDSA` (Ed25519).
Attestation is accepted as `none` only — we register a credential, we do not
claim to know what hardware made it. Verification covers:

- `clientDataJSON.type`, `challenge` and `origin`
- `rpIdHash` against the expected relying-party id
- the signature over `authData || sha256(clientDataJSON)`
- the signature counter never going backwards (cloned-authenticator signal)

Not covered, stated so nobody assumes it: attestation trust (which vendor made
the key), user-verification *policy* beyond the UV flag, and backup eligibility.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct

ORIGIN_DEFAULT = "http://127.0.0.1:8898"
UV_FLAG = 0x04
AT_FLAG = 0x40


class WebAuthnError(Exception):
    pass


# ------------------------------------------------------------------ base64url
def b64d(text: str) -> bytes:
    if isinstance(text, bytes):
        data = text
    else:
        data = text.encode()
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# ----------------------------------------------------------------------- CBOR
def cbor_decode(data: bytes):
    value, offset = _cbor(data, 0)
    if offset != len(data):
        raise WebAuthnError("trailing bytes after CBOR value")
    return value


def _cbor(data: bytes, offset: int):
    if offset >= len(data):
        raise WebAuthnError("truncated CBOR")
    initial = data[offset]
    offset += 1
    major, info = initial >> 5, initial & 0x1F
    if info < 24:
        length = info
    elif info == 24:
        length = data[offset]
        offset += 1
    elif info == 25:
        length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
    elif info == 26:
        length = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
    elif info == 27:
        length = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
    else:
        raise WebAuthnError("indefinite or reserved CBOR length")
    if major == 0:
        return length, offset
    if major == 1:
        return -1 - length, offset
    if major == 2:
        return data[offset:offset + length], offset + length
    if major == 3:
        return data[offset:offset + length].decode("utf-8"), offset + length
    if major == 4:
        items = []
        for _ in range(length):
            item, offset = _cbor(data, offset)
            items.append(item)
        return items, offset
    if major == 5:
        out = {}
        for _ in range(length):
            key, offset = _cbor(data, offset)
            item, offset = _cbor(data, offset)
            out[key] = item
        return out, offset
    if major == 6:                       # tag: decode the tagged value
        return _cbor(data, offset)
    if major == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info in (22, 23):
            return None, offset
    raise WebAuthnError("unsupported CBOR major type %d" % major)


# ------------------------------------------------------------------- Ed25519
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _SQRT_M1) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_B = (_xrecover(_BY) % _P, _BY)


def _add(p, q):
    x1, y1 = p
    x2, y2 = q
    k = _D * x1 * x2 * y1 * y2 % _P
    return ((x1 * y2 + x2 * y1) * pow(1 + k, _P - 2, _P) % _P,
            (y1 * y2 + x1 * x2) * pow(1 - k, _P - 2, _P) % _P)


def _mul(point, scalar: int):
    result = (0, 1)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _decode_point(data: bytes):
    value = int.from_bytes(data, "little")
    y = value & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (value >> 255) & 1:
        x = _P - x
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _P != 0:
        raise WebAuthnError("point is not on the curve")
    return (x, y)


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        a = _decode_point(public)
        r = _decode_point(signature[:32])
    except WebAuthnError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(),
                       "little") % _L
    return _mul(_B, s) == _add(r, _mul(a, h))


# -------------------------------------------------------------------- P-256
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _p256_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P256_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + P256_A) * pow(2 * p[1], P256_P - 2, P256_P) % P256_P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], P256_P - 2, P256_P) % P256_P
    x = (lam * lam - p[0] - q[0]) % P256_P
    return (x, (lam * (p[0] - x) - p[1]) % P256_P)


def p256_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    if len(public) != 64 or len(signature) != 64:
        return False
    try:
        point = (int.from_bytes(public[:32], "big"), int.from_bytes(public[32:], "big"))
    except ValueError:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    digest = hashlib.sha256(message).digest()
    e = int.from_bytes(digest, "big")
    w = pow(s, P256_N - 2, P256_N)
    u1 = e * w % P256_N
    u2 = r * w % P256_N
    left = _p256_add(_p256_mul(P256_G, u1), _p256_mul(point, u2))
    return left is not None and left[0] % P256_N == r


def _p256_mul(point, scalar: int):
    result = None
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        scalar >>= 1
    return result


# ------------------------------------------------------------------ COSE key
def parse_cose_key(blob: bytes) -> dict:
    cose = cbor_decode(blob)
    if not isinstance(cose, dict):
        raise WebAuthnError("COSE key is not a map")
    kty = cose.get(1)
    alg = cose.get(3)
    if kty == 2 and cose.get(-1) == 1:            # EC2 / P-256
        x, y = cose.get(-2), cose.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise WebAuthnError("EC2 key without coordinates")
        return {"alg": alg or -7, "cose": "ES256", "public": x + y}
    if kty == 1 and cose.get(-1) == 6:            # OKP / Ed25519
        x = cose.get(-2)
        if not isinstance(x, bytes):
            raise WebAuthnError("OKP key without x")
        return {"alg": alg or -8, "cose": "EdDSA", "public": x}
    raise WebAuthnError("unsupported COSE key type %r" % (kty,))


def verify_signature(key: dict, signature: bytes, message: bytes) -> bool:
    if key.get("cose") == "ES256":
        return p256_verify(key["public"], signature, message)
    if key.get("cose") == "EdDSA":
        return ed25519_verify(key["public"], signature, message)
    return False


# ------------------------------------------------------------------ ceremony
def _client_data(raw: bytes, expected_type: str, challenge: str,
                 origin: str) -> dict:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise WebAuthnError("clientDataJSON is not JSON") from exc
    if data.get("type") != expected_type:
        raise WebAuthnError("ceremony is %r, expected %r"
                            % (data.get("type"), expected_type))
    if data.get("challenge") != challenge:
        raise WebAuthnError("challenge does not match")
    if origin and data.get("origin") != origin:
        raise WebAuthnError("origin is %r, expected %r" % (data.get("origin"), origin))
    return data


def _auth_data(raw: bytes, rp_id: str, need_attested: bool):
    if len(raw) < 37:
        raise WebAuthnError("authData too short")
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    if raw[:32] != rp_hash:
        raise WebAuthnError("rpIdHash does not match %s" % rp_id)
    flags = raw[32]
    sign_count = struct.unpack(">I", raw[33:37])[0]
    rest = raw[37:]
    attested = None
    if flags & AT_FLAG:
        if len(rest) < 18:
            raise WebAuthnError("attested credential data truncated")
        aaguid = rest[:16]
        cred_len = struct.unpack(">H", rest[16:18])[0]
        cred_id = rest[18:18 + cred_len]
        key_blob = rest[18 + cred_len:]
        attested = {"aaguid": aaguid.hex(), "credential_id": cred_id,
                    "cose": parse_cose_key(key_blob)}
    elif need_attested:
        raise WebAuthnError("registration without attested credential data")
    return {"flags": flags, "sign_count": sign_count, "attested": attested,
            "uv": bool(flags & UV_FLAG)}


def register(attestation: str, client_data: str, challenge: str,
             rp_id: str, origin: str) -> dict:
    """Verify a `navigator.credentials.create()` response (attestation `none`)."""
    decoded = cbor_decode(b64d(attestation))
    if not isinstance(decoded, dict):
        raise WebAuthnError("attestationObject is not a map")
    fmt = decoded.get("fmt")
    if fmt not in ("none", None):
        raise WebAuthnError("attestation format %r is not accepted; this server "
                            "records the key, it does not judge the hardware" % fmt)
    raw_client = b64d(client_data)
    _client_data(raw_client, "webauthn.create", challenge, origin)
    auth = _auth_data(decoded.get("authData") or b"", rp_id, need_attested=True)
    attested = auth["attested"]
    return {"credential_id": b64e(attested["credential_id"]),
            "public": b64e(attested["cose"]["public"]),
            "cose": attested["cose"]["cose"],
            "sign_count": auth["sign_count"], "uv": auth["uv"],
            "aaguid": attested["aaguid"]}


def assert_valid(credential: dict, auth_data: str, signature: str,
                 client_data: str, challenge: str, rp_id: str,
                 origin: str) -> dict:
    """Verify a `navigator.credentials.get()` response for a stored credential."""
    raw_client = b64d(client_data)
    _client_data(raw_client, "webauthn.get", challenge, origin)
    raw_auth = b64d(auth_data)
    auth = _auth_data(raw_auth, rp_id, need_attested=False)
    message = raw_auth + hashlib.sha256(raw_client).digest()
    key = {"cose": credential.get("cose"), "public": b64d(credential.get("public", ""))}
    if not verify_signature(key, b64d(signature), message):
        raise WebAuthnError("assertion signature does not verify")
    previous = int(credential.get("sign_count") or 0)
    if auth["sign_count"] and previous and auth["sign_count"] <= previous:
        raise WebAuthnError("signature counter did not advance (%d -> %d): a "
                            "cloned authenticator looks like this"
                            % (previous, auth["sign_count"]))
    return {"sign_count": auth["sign_count"], "uv": auth["uv"]}
