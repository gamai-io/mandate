"""RFC 6962/9162-style Merkle transparency log over the Mandate ledger.

Leaf  = SHA256(0x00 || utf8(JCS(ledger_entry)))
Node  = SHA256(0x01 || left || right)
Root  = MTH([]) = SHA256("") ; MTH([d]) = LeafHash(d)
        MTH(D[0:n]) = Node(MTH(D[0:k]), MTH(D[k:n])), k = largest 2^x < n
"""
from __future__ import annotations

import hashlib
import os
import time

from . import core, sign

LOG_NAMESPACE = "mandate-log"


class LogError(core.MandateError):
    pass


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(entry: dict) -> bytes:
    return _sha(b"\x00" + core.jcs(entry).encode("utf-8"))


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)


def empty_root() -> bytes:
    return _sha(b"")


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return empty_root()
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def leaves_from_ledger(ledger_path: str) -> list[bytes]:
    entries = core.read_ledger(ledger_path)
    if entries and not core.verify_chain(ledger_path):
        raise LogError("ledger hash chain is invalid")
    return [leaf_hash(entry) for entry in entries]


def root_hex(leaves: list[bytes]) -> str:
    return mth(leaves).hex()


def inclusion_path(index: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return inclusion_path(index, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_path(index - k, leaves[k:]) + [mth(leaves[:k])]


def inclusion_proof(leaves: list[bytes], index: int) -> dict:
    if index < 0 or index >= len(leaves):
        raise LogError("leaf index out of range")
    path = inclusion_path(index, leaves)
    return {
        "v": 1,
        "tree_size": len(leaves),
        "leaf_index": index,
        "leaf_hash": leaves[index].hex(),
        "path": [p.hex() for p in path],
        "root_hash": mth(leaves).hex(),
    }


def verify_inclusion(leaf: bytes, index: int, size: int, root: bytes,
                     path: list[bytes]) -> bool:
    if index < 0 or index >= size or size <= 0:
        return False
    fn = index
    sn = size - 1
    r = leaf
    for sibling in path:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = node_hash(sibling, r)
            if not (fn & 1):
                while fn and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_inclusion_proof(entry: dict, proof: dict, root: str | None = None,
                           size: int | None = None) -> bool:
    try:
        leaf = leaf_hash(entry)
        index = int(proof["leaf_index"])
        proof_size = int(proof["tree_size"])
        path = [bytes.fromhex(p) for p in proof.get("path") or []]
        expected_root = bytes.fromhex(root or proof.get("root_hash") or "")
    except (KeyError, TypeError, ValueError):
        return False
    if size is not None and proof_size != int(size):
        return False
    if leaf.hex() != str(proof.get("leaf_hash") or ""):
        return False
    return verify_inclusion(leaf, index, proof_size, expected_root, path)


def _subproof(m: int, leaves: list[bytes], base: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if base else [mth(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], base) + [mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def consistency_proof(leaves: list[bytes], first: int, second: int) -> dict:
    if first < 0 or second < first or second > len(leaves):
        raise LogError("invalid consistency range")
    path = [] if first == 0 else _subproof(first, leaves[:second], True)
    return {
        "v": 1,
        "first_size": first,
        "second_size": second,
        "first_root": mth(leaves[:first]).hex(),
        "second_root": mth(leaves[:second]).hex(),
        "path": [p.hex() for p in path],
    }


def verify_consistency(first: int, second: int, first_root: bytes,
                       second_root: bytes, path: list[bytes]) -> bool:
    if first == second:
        return not path and first_root == second_root
    if first == 0:
        return not path
    if first > second or not path:
        return False
    if first & (first - 1) == 0:
        path = [first_root] + path
    fn = first - 1
    sn = second - 1
    if fn & 1:
        while fn & 1:
            fn >>= 1
            sn >>= 1
    fr = path[0]
    sr = path[0]
    for node in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = node_hash(node, fr)
            sr = node_hash(node, sr)
            if not (fn & 1):
                while fn and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, node)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


def verify_consistency_proof(proof: dict, first_root: str | None = None,
                             second_root: str | None = None,
                             first: int | None = None,
                             second: int | None = None) -> bool:
    try:
        first_size = int(first if first is not None else proof["first_size"])
        second_size = int(second if second is not None else proof["second_size"])
        fr = bytes.fromhex(first_root or proof["first_root"])
        sr = bytes.fromhex(second_root or proof["second_root"])
        path = [bytes.fromhex(p) for p in proof.get("path") or []]
    except (KeyError, TypeError, ValueError):
        return False
    return verify_consistency(first_size, second_size, fr, sr, path)


def sth_payload(log_name: str, log_id: str, tree_size: int, root: str,
                timestamp_ms: int | None = None) -> dict:
    return {
        "v": 1,
        "log_name": str(log_name),
        "log_id": str(log_id),
        "tree_size": int(tree_size),
        "root_hash": str(root),
        "timestamp": int(timestamp_ms if timestamp_ms is not None
                         else time.time() * 1000),
    }


def sign_sth(payload: dict, key_path: str) -> dict:
    return {"sth": payload, "sig": sign.sign(core.jcs(payload), key_path,
                                              LOG_NAMESPACE)}


def verify_sth(sth: dict, signers_path: str,
               revoked_path: str | None = None) -> bool:
    payload = (sth or {}).get("sth") or {}
    return sign.verify(core.jcs(payload), str(payload.get("log_name") or ""),
                       str((sth or {}).get("sig") or ""), signers_path,
                       LOG_NAMESPACE, revoked_path=revoked_path)


def log_id_from_key(key_path: str) -> str:
    path = str(key_path) + ".pub"
    if not os.path.exists(path):
        raise LogError("log public key not found: %s" % path)
    with open(path, encoding="utf-8") as fh:
        tokens = fh.read().split()
    for idx, token in enumerate(tokens):
        if token.startswith(("ssh-", "ecdsa-", "sk-")) and idx + 1 < len(tokens):
            return sign.fingerprint(tokens[idx + 1])
    raise LogError("invalid log public key")
