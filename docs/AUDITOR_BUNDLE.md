# Auditor bundle

An auditor bundle is one portable JSON that *records* a single business action,
and one signature that binds those records together:

- the exact **intent** and the human-signed **grant**,
- the hash-chained **receipt**,
- a Merkle **inclusion proof**,
- the signed tree head (**STH**),
- the **witness state** that *claims* the STH was pinned on another host (a
  claim, see the honest limit below).

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

Output: `{valid, envelope, sth, inclusion, witness, decision, executed, observed}`
— `valid` is true only if the envelope, STH, inclusion and witness checks pass.

**Honest limit:** `witness_state` is a JSON file, not a signature by the witness
host. `audit verify` checks that it matches the STH, not that another machine
produced it. If the bundle builder fabricates a state and re-signs the bundle,
`witness` is still true. A witness you do not trust is not a witness: the
independent check is running `mandate witness verify` on the witness host against
its own state file.

## Cross-host flow

1. On the log host: `mandate log head`, `mandate log proof`, and `mandate export`.
2. On the witness host: `mandate witness accept --state witness.json --sth sth.json`.
3. Copy `witness.json` to the log host and build the bundle.
4. An auditor verifies the bundle offline with the two signer files above.

No network, database or host access is required at verification time.

## Verified on a second host (2026-11-09)

A real two-host pin was performed on two independent machines (host A, host B):

- host A produced the keys, intent, grant, receipt and signed STH
  (`tree_size=1`, example `root_hash=266f308b...`);
- only the public `signers` file and `sth.json` were transferred to a second
  host (host B);
- on host B, `mandate --signers signers witness accept --state witness.json --sth
  sth.json` returned `ok=true, first=true` (first pin);
- the witness state was copied back and
  `mandate --signers signers audit verify --bundle bundle.json --log-signers
  signers` returned `valid=true, witness=true`.

This shows the witness host needs only public keys and the STH, and the bundle
can be pinned and verified across machines.

The same pin was repeated on two further hosts on 2026-11-09; both
witness states produced `valid=true, witness=true`. Three independent hosts
(vast, host D, host C) now hold the same `root_hash` and `tree_size`.
