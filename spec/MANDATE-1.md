# MANDATE-1

## Canonicalization
All objects are canonicalised per **RFC 8785 (JCS)**: UTF-16 code-unit key
ordering, ECMAScript number serialization (`1170.0` → `1170`, `1e-7` → `1e-7`),
minimal string escaping, UTF-8 output. Non-finite numbers, lone surrogates,
non-string keys and integers outside `[-(2^53-1), 2^53-1]` are rejected.
Hashes are `sha256` over those bytes.

## Intent
```json
{
  "v": 1,
  "actor": {"agent": "opencode@host", "session": "abc"},
  "effect": {
    "kind": "payment.send",
    "target": "Example Supplier",
    "amount": {"value": 1170.0, "currency": "BAM"},
    "params": {"ref": "faktura-77"}
  },
  "requested_by": "approver",
  "nonce": "n-1",
  "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}]
}
```

## Commitment
```
render_hash = sha256(jcs(render(intent)))
commitment  = "sha256:" + sha256(jcs({v, effect, requested_by, render_hash}))
```
The commitment covers **what** is authorised (including the exact human-readable
render the approver sees), never **who executes it**.

## Proposal
```
proposal = {v, proposal_id, commitment, render, intent}
proposal_id = "m1" + sha256(jcs(intent))[:24]
```

## Grant
```json
{
  "grant": {
    "v": 1,
    "commitment": "sha256:...",
    "render_hash": "sha256:...",
    "approver": "approver",
    "scope": {"max_uses": 1, "not_after": 1794185400},
    "nonce": "uuid"
  },
  "sig": "-----BEGIN SSH SIGNATURE-----\n..."
}
```
`sig` is an OpenSSH signature over `jcs(grant) + "\n"` with namespace `mandate`
and principal = `approver`.

## Receipt
```json
{
  "body": {
    "v": 1, "type": "receipt", "proposal_id": "m1...",
    "commitment": "sha256:...", "render_hash": "sha256:...",
    "approver": "approver",
    "grant_nonce": "uuid", "decision": "executed",
    "coverage": "enforced",
    "result_hash": "sha256:...", "ts": 1794184500,
    "render": {"summary": "payment.send | Example Supplier | 1170.00 BAM"},
    "prev": "GENESIS"
  },
  "hash": "sha256..."
}
```
`hash = sha256(jcs(body))`, `body.prev` = previous entry hash (or `GENESIS`).

### `coverage` — how the effect was captured
Every receipt states the strength of the evidence, in this order:

| value | meaning |
|---|---|
| `enforced` | the effect could not happen without passing `redeem`; the gate refused anything unauthorised |
| `observed` | a hook or adapter saw the call but could not block it |
| `self_reported` | only the agent says it happened; nothing enforced it |

Rules:
- A receipt produced by `redeem` is `enforced` unless the caller states otherwise;
  `observe=True` records `observed`.
- `verify` accepts a missing `coverage` only in compatibility mode. With
  `require_coverage` (library) or a policy that sets `require_coverage`, a missing or
  weaker class is refused — the refusal is written to the ledger as a `control` entry.
- An unknown value is refused everywhere (`E_COVERAGE`).

## Decision codes (`check`)
- `0` allow (low risk, or under `max_auto`)
- `10` ask (a grant is required)
- `20` deny (unknown effect / policy deny)
- `2` malformed input
- `3` mandate error (expired, replayed, invalid signature)

## Broker preconditions
Before the nonce is claimed, the broker may run read-only checks (ERP master
data). A failed precondition aborts with `PreconditionFailed` and leaves the
grant unconsumed. Preconditions never mutate external state.

## Independent verification

`spec/verify_offline.py` checks a grant and a receipt using nothing but the
Python standard library: it imports no project code and never calls `ssh-keygen`.
It re-implements JCS (RFC 8785), the SSHSIG container and Ed25519 from the RFCs,
so every step that decides the answer is readable in one file.

```bash
python3 spec/verify_offline.py --grant spec/vectors/grant.json \
    --intent spec/vectors/intent.json \
    --signers spec/vectors/allowed_signers \
    --receipt spec/vectors/receipt.json
# ok: true, exit 0
```

A **second implementation** in another language and on another crypto library:
`spec/verify_offline.js` (Node standard library, OpenSSL Ed25519) performs the same
checks and is run against the same vectors in the test suite.

The vectors in `spec/vectors/` include a tampered intent (amount changed after
approval) and a forged receipt, each of which must fail. This is a **second
implementation by the same author**, not an independent third party: it lowers
the cost of an audit and of a re-implementation, and it is not a substitute for
one. The distinction is stated so nobody has to discover it.
