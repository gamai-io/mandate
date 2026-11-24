# Security policy

## Supported versions

Only the latest released version receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.34.x  | yes       |
| < 0.33  | no        |

## Reporting a vulnerability

Do **not** open a public issue for a security problem. Report privately to
`renato@gamatrade.ba` with:

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

## Adversarial review 2026-11-24 — fixed in 0.35.0

An external-style red-team pass found real defects. Fixed, each with a regression
test in `tests/test_redteam_fixes.py`:

- **SVID subject binding.** `verify()` now requires `iss == sub == signing key`;
  previously any key in `allowed_signers` could mint a token for any agent.
- **Spend limits were dead code.** `_amount()` read `render.amount` while receipts
  write `render.fields.amount`, so the ceiling never triggered. Fixed, and the
  broker now calls governance before executing (halt/limits apply to `/execute` too).
- **`anchor-verify` without `--ca` was forgeable.** It now refuses a token without
  CMS SignedData and reports `cms_unverified` unless the signature is checked with
  a CA; a hand-made 1 KB blob is rejected in the test suite.
- **Commitment binds the actor.** `intent_core()` now covers `actor.agent`,
  `session` and `nonce`, so a grant cannot be replayed by a different agent.
- **Egress SSRF guard order.** Private/metadata checks run before the allowlist; a
  hostname entry no longer opens loopback; `172.16/12` and IPv4-mapped IPv6 added.
- **Audit pack hygiene.** `pack` deletes stale files in the output directory and
  verifies change-record signatures when `--signers` is given.
- **Warden evidence** carries a timestamp; `warden --verify` fails when there is
  nothing to verify.

## Known limitations (open, not hidden)

- **One-shot is enforced across ledgers** since 0.36.0: a nonce is claimed in a
  SQLite store (`MANDATE_NONCE_DB`, default `~/.mandate/nonces.sqlite`) before the
  receipt is appended, so the same grant cannot be redeemed into a second ledger.
- **Receipts are signed only when asked.** `mandate redeem --key/--signer` signs the
  receipt and `verify_receipt` checks it; a policy can require it with
  `"require_signed_receipts": true`. `mandate chain --signers` verifies every
  signature present, and `--broker-signers` verifies broker result entries.
  Unsigned receipts remain valid unless the policy says otherwise (compatibility).
- **`SIGSTOP` freeze is not a security boundary**; use the cgroup or microVM path.
- **Pack contents include the ledger and anchors** (0.37.0), so a reviewer does not
  have to trust the summary; sign the index to bind it.

## Ops commands (0.37.0)

`mandate backup` / `mandate restore` (tar + per-file sha256 + chain check on restore),
`mandate sbom` (CycloneDX 1.5, zero runtime dependencies).
- **Anchoring is multi-TSA since 0.37.0** (`--tsa` repeatable): each server's token is
  stored and its imprint checked, so one dishonest TSA cannot fake existence alone.
  Timestamps between anchors are still self-asserted.
- **The audit pack index can be signed** (`pack --key/--signer`); unsigned packs are
  still generated so old flows keep working.
