# Release witness

Every release artifact is appended as a leaf to the Mandate transparency log;
the resulting STH is pinned by three independent witnesses (vast, oracle,
linux3). The witnesses only accept growth with a valid consistency proof, so a
rollback or split view of the release history is rejected.

## Build the release STH

`tools/release_witness.py` takes the existing ledger, adds one leaf per
artifact (`SHA256(file)`), signs the new STH with the log key and verifies:

- the STH signature;
- the inclusion proof of every artifact;
- the consistency proof from the previous tree size.

```bash
PYTHONPATH=. python3 tools/release_witness.py \
  --artifacts dist/*.whl dist/*.tar.gz \
  --ledger ledger.jsonl --log-key ~/.ssh/mandate-log \
  --signers trust/log_signers --out-dir release/0.25.0
```

Outputs `sth.json`, `artifacts.json` (hashes + inclusion proofs) and
`consistency.json`.

## Pin on the witnesses

On each witness host (state already at the previous tree size):

```bash
mandate --signers log_signers witness accept \
  --state witness.json --sth sth.json --proof consistency.json
```

For 0.25.0 all three returned `advanced: true, from: 1, to: 3`; the state now
contains `tree_size=3` and
`root_hash=5d472d19d44c5370b90038392f3d0cb1f2ae983e695c4d7d76f135a5159f3e80`.

## Verification

`release/0.25.0/witnesses.json` records the artifact hashes, the STH, the
per-host pin (timestamp) and the proof results. Validate with:

```bash
mandate witness show --state witness.json
mandate witness verify --state witness.json --sth sth.json
```

The witness states are currently at `/tmp/witness.json` on the three hosts;
move them to persistent storage before production use.
