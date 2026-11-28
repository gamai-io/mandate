"""A transparency log for our own releases, in the shape of RFC 6962.

A hash on PyPI proves a file did not change after upload; a signed release tag proves we meant it.
Neither proves *when* we published it, and neither survives us quietly re-cutting a release. A
public, append-only log does: each entry is a leaf, the tree head is a named size and root, and a
checkpoint signs that head. Anyone who kept an earlier checkpoint can prove we never rewrote it
(consistency), and anyone holding one entry can prove it is in the tree (inclusion) without asking
us for anything.

What a log run by one party can and cannot prove is stated in `docs/TLOG.md`: it is
tamper-*evident* against a party who kept the old checkpoint, not against us rewriting history
before anyone looked. The mitigation is the checkpoint being timestamped externally
(`mandate anchor` on the checkpoint file) and mirrored by someone else.

Hashing follows RFC 6962 §2.1 exactly, so an independent implementation can check it:

    leaf_hash(d)      = SHA-256(0x00 || d)
    node_hash(l, r)   = SHA-256(0x01 || l || r)
    MTH(empty)        = SHA-256("")
"""
from __future__ import annotations

import hashlib
import json
import time

FORMAT = "mandate-tlog/1"
CHECKPOINT_FORMAT = "mandate-checkpoint/1"


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return _sha(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)


def empty_root() -> bytes:
    return _sha(b"")


def _split(size: int) -> int:
    """Largest power of two strictly smaller than size (RFC 6962)."""
    power = 1
    while power * 2 < size:
        power *= 2
    return power


def merkle_root(leaves: list[bytes]) -> bytes:
    """MTH over already-hashed leaves, recursive as the RFC defines it."""
    if not leaves:
        return empty_root()
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def tree_hash(entries: list[bytes]) -> bytes:
    return merkle_root([leaf_hash(e) for e in entries])


def inclusion_proof(entries: list[bytes], index: int) -> list[dict]:
    """Audit path for one entry: siblings from the leaf upward, each with its side.

    Only the path down to `index` may contribute steps; a sibling subtree is summarised by its
    Merkle root. Getting this wrong is subtle — an early version walked the sibling subtree as
    well and produced a proof that verified against nothing.
    """
    if not 0 <= index < len(entries):
        raise ValueError("index %d outside 0..%d" % (index, len(entries) - 1))
    leaves = [leaf_hash(e) for e in entries]
    path: list[dict] = []

    def root(start: int, end: int) -> bytes:
        return merkle_root(leaves[start:end])

    def walk(start: int, end: int) -> None:
        if end - start == 1:
            return
        k = _split(end - start)
        mid = start + k
        if index < mid:
            walk(start, mid)
            path.append({"side": "right", "hash": root(mid, end).hex()})
        else:
            walk(mid, end)
            path.append({"side": "left", "hash": root(start, mid).hex()})

    walk(0, len(leaves))
    return path


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[dict],
                     root_hex: str) -> bool:
    """Rebuild the root from a leaf and its audit path; independent of how the proof was made."""
    if index < 0 or index >= size or size <= 0:
        return False
    node = leaf_hash(leaf)
    for step in proof:
        sibling = bytes.fromhex(str(step.get("hash") or ""))
        if len(sibling) != 32:
            return False
        if step.get("side") == "left":
            node = node_hash(sibling, node)
        elif step.get("side") == "right":
            node = node_hash(node, sibling)
        else:
            return False
    return node.hex() == str(root_hex)


def build(entries: list[bytes], sign_key: str = "", signer: str = "",
          created: int | None = None) -> dict:
    """The log file itself: entries with their leaf hashes, the head, and an optional checkpoint."""
    if not entries:
        raise ValueError("a log needs at least one entry")
    leaves = [leaf_hash(e) for e in entries]
    size = len(leaves)
    root = merkle_root(leaves)
    out = {
        "format": FORMAT,
        "created": int(created if created is not None else time.time()),
        "size": size,
        "root": root.hex(),
        "entries": [{"index": i, "leaf": leaves[i].hex(),
                     "entry": json.loads(e.decode("utf-8")) if _looks_json(e) else
                     {"raw_sha256": hashlib.sha256(e).hexdigest()}}
                    for i, e in enumerate(entries)],
    }
    if sign_key:
        out["checkpoint"] = checkpoint(size, root, sign_key, signer)
    return out


def _looks_json(data: bytes) -> bool:
    try:
        json.loads(data.decode("utf-8"))
        return True
    except (ValueError, UnicodeDecodeError):
        return False


def checkpoint(size: int, root: bytes, sign_key: str, signer: str = "") -> dict:
    """A signed statement of the head; this is the object a third party keeps."""
    from . import sign as sign_mod
    body = {"format": CHECKPOINT_FORMAT, "size": int(size), "root": root.hex(),
            "created": int(time.time()), "signer": signer or "log"}
    body["public_key"] = sign_mod.public_key_of_keyfile(sign_key)
    body["signature"] = sign_mod.sign(_canonical(body), sign_key)
    return body


def _canonical(body: dict) -> str:
    from .core import jcs
    return jcs({k: v for k, v in body.items() if k != "signature"})


def verify_checkpoint(ckpt: dict, public_key: str = "") -> dict:
    """Verify the signature over the head; returns the object, never raises on a bad signature."""
    import os
    import tempfile

    from . import sign as sign_mod
    if not isinstance(ckpt, dict) or ckpt.get("format") != CHECKPOINT_FORMAT:
        return {"ok": False, "code": "bad_format"}
    key = public_key or str(ckpt.get("public_key") or "")
    if not key:
        return {"ok": False, "code": "no_key"}
    signer = str(ckpt.get("signer") or "log")
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "signers")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('%s namespaces="mandate" %s\n' % (signer, key))
        ok = sign_mod.verify(_canonical(ckpt), signer, str(ckpt.get("signature") or ""), path)
    return {"ok": bool(ok), "code": "ok" if ok else "bad_signature",
            "size": ckpt.get("size"), "root": ckpt.get("root")}


def append(entries: list[bytes], new_entries: list[bytes]) -> list[bytes]:
    """Append-only, enforced: a shorter log is a rewrite, not an update."""
    if len(new_entries) < len(entries):
        raise ValueError("new log has %d entries, old had %d: that is a rewrite"
                         % (len(new_entries), len(entries)))
    for index, old in enumerate(entries):
        if new_entries[index] != old:
            raise ValueError("entry %d changed: the log was rewritten" % index)
    return list(new_entries)


def consistency(old: list[bytes], new: list[bytes]) -> bool:
    """Cheap check anyone can run: the old log must be a prefix of the new one."""
    return len(old) <= len(new) and all(old[i] == new[i] for i in range(len(old)))
