# Auditor bundle

An auditor bundle is one portable JSON that proves a single business action:

- the exact **intent** and the human-signed **grant**,
- the hash-chained **receipt**,
- a Merkle **inclusion proof**,
- the signed tree head (**STH**),
- the **witness state** that pinned that STH on another host.

The bundle is signed by the approver (OpenSSH SSHSIG, namespace
`mandate-export`). Verification checks the envelope signature, the receipt/grant
binding, the STH signature, the inclusion proof against the STH root/size, and
that the witness state matches the STH.

## Build

```bash
mandate audit bundle \
  --receipt receipt.json --intent intent.json --grant grant.json \
  --proof proof.json --sth sth.json --witness-state witness.json \
  --key ~/.ssh/mandate --signer approver --out bundle.json
```

## Verify (offline, any host)

```bash
mandate --signers trust/allowed_signers audit verify \
  --bundle bundle.json --log-signers trust/log_signers
```

`--signers` must contain the approver key with
`namespaces="mandate,mandate-export"` (the grant is `mandate`, the bundle
envelope is `mandate-export`); `--log-signers` must contain the log key
(`namespaces="mandate-log"`).

Output: `{valid, envelope, sth, inclusion, witness}` — `valid` is true only if
all four checks pass.

## Cross-host flow

1. On the log host: `mandate log head`, `mandate log proof`, and `mandate export`.
2. On the witness host: `mandate witness accept --state witness.json --sth sth.json`.
3. Copy `witness.json` to the log host and build the bundle.
4. An auditor verifies the bundle offline with the two signer files above.

No network, database or host access is required at verification time.

## Verified on a second host (2026-11-09)

A real two-host pin was performed without using oracle, linux3 or LUMI:

- contabo produced the keys, intent, grant, receipt and signed STH
  (`tree_size=1`, `root_hash=266f308b...`);
- only the public `signers` file and `sth.json` were transferred to a second
  host (vast, `ebe88a874e2e`);
- on vast, `mandate --signers signers witness accept --state witness.json --sth
  sth.json` returned `ok=true, first=true` (first pin);
- the witness state was copied back and
  `mandate --signers signers audit verify --bundle bundle.json --log-signers
  signers` returned `valid=true, witness=true`.

This shows the witness host needs only public keys and the STH, and the bundle
can be pinned and verified across machines.

The same pin was repeated on **oracle** and **linux3** on 2026-11-09; both
witness states produced `valid=true, witness=true`. Three independent hosts
(vast, oracle, linux3) now hold the same `root_hash` and `tree_size`.
