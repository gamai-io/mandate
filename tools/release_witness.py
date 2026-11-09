#!/usr/bin/env python3
"""Build a witness-ready STH over release artifacts and verify all proofs.

Leaves are the existing ledger receipts plus one leaf per artifact
(SHA256 of the file).  Emits sth.json, artifacts.json (with inclusion
proofs) and consistency.json (from the previous tree size).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os

from mandate import log as mlog


def artifact_entry(path: str) -> dict:
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    return {"kind": "release.artifact", "name": os.path.basename(path),
            "sha256": digest}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="release_witness")
    parser.add_argument("--artifacts", nargs="+", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--log-key", required=True)
    parser.add_argument("--log-name", default="log1")
    parser.add_argument("--signers", required=True)
    parser.add_argument("--out-dir", default="release")
    args = parser.parse_args(argv)

    old = mlog.leaves_from_ledger(args.ledger)
    entries = [artifact_entry(path) for path in args.artifacts]
    leaves = old + [mlog.leaf_hash(entry) for entry in entries]
    size = len(leaves)
    root = mlog.root_hex(leaves)
    payload = mlog.sth_payload(args.log_name,
                               mlog.log_id_from_key(args.log_key),
                               size, root)
    sth = mlog.sign_sth(payload, args.log_key)
    if not mlog.verify_sth(sth, args.signers):
        raise SystemExit("STH signature invalid")

    proofs = []
    for index, entry in enumerate(entries):
        proof = mlog.inclusion_proof(leaves, len(old) + index)
        if not mlog.verify_inclusion_proof(entry, proof, root):
            raise SystemExit("inclusion proof invalid for %s" % entry["name"])
        proofs.append(proof)

    consistency = mlog.consistency_proof(leaves, len(old), size)
    if not mlog.verify_consistency_proof(
            consistency, first_root=mlog.root_hex(old),
            second_root=root, first=len(old), second=size):
        raise SystemExit("consistency proof invalid")

    os.makedirs(args.out_dir, exist_ok=True)

    def dump(name: str, obj) -> None:
        with open(os.path.join(args.out_dir, name), "w",
                  encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    dump("sth.json", sth)
    dump("artifacts.json", {"artifacts": entries, "proofs": proofs})
    dump("consistency.json", consistency)
    print(json.dumps({"tree_size": size, "root_hash": root,
                      "old_size": len(old),
                      "artifacts": [entry["name"] for entry in entries]},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
