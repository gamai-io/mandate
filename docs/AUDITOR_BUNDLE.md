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

`--signers` must contain the approver key (`namespaces="mandate"`); `--log-signers`
must contain the log key (`namespaces="mandate-log"`).

Output: `{valid, envelope, sth, inclusion, witness}` — `valid` is true only if
all four checks pass.

## Cross-host flow

1. On the log host: `mandate log head`, `mandate log proof`, and `mandate export`.
2. On the witness host: `mandate witness accept --state witness.json --sth sth.json`.
3. Copy `witness.json` to the log host and build the bundle.
4. An auditor verifies the bundle offline with the two signer files above.

No network, database or host access is required at verification time.
