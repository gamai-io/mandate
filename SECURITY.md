# Security policy

## Supported versions

Only the latest released version receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.10.x  | yes       |
| < 0.10  | no        |

## Reporting a vulnerability

Do **not** open a public issue for a security problem. Report privately to
`security@example.com` with:

- affected version and component (core, broker, witness, log, adapters),
- a reproducer or a precise description,
- impact and any suggested fix.

You will get an acknowledgement within 72 hours. We will coordinate a fix and a
disclosure date. Please give us a reasonable window before publishing details.

## Scope

In scope: signature verification, canonicalization, nonce/replay handling,
journal/recovery, broker auth and body limits, witness rollback/split-view
handling, key scoping and revocation.

Out of scope (by design, see `docs/THREAT_MODEL.md`): an agent that holds the
target system's credentials can bypass Mandate; running the harness as root on
the same host as the approver's key; denial of service by simply not acting.

## Hardening already implemented

- default-deny policy for unknown effects,
- off-host Ed25519 grants with namespace-scoped `allowed_signers`,
- validity windows and SHA256 fingerprint revocation,
- one-shot grants and idempotent effects (grant nonce),
- receipt only after the effect commits, with crash recovery,
- loopback-only defaults, bearer token for non-loopback broker,
- request body caps on broker and witness,
- signed tree heads + off-host witness (rollback/split-view rejection).
