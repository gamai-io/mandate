# Plan

## Phase 1 — Core (done, v0.1)
- [x] Canonical commitment (JCS), stable ids
- [x] Intent / Grant / Receipt objects
- [x] Ed25519 grant signing via OpenSSH (`ssh-keygen -Y sign`)
- [x] One-shot redeem with nonce, replay detection
- [x] Hash-chained ledger + offline verification
- [x] Agent cannot self-approve
- [x] Fail-closed policy (unknown effect = deny)
- [x] Bypass tests: tamper, replay, wrong signer, expiry, self-approval

## Phase 2 — Effect broker (core done, v0.2)
- [x] Broker is the only executor; agent never runs the effect itself
- [x] HTTP `/execute` + `/health`, loopback-only by default
- [x] Atomic nonce claim (SQLite UNIQUE) → no double execution under concurrency
- [x] `render_hash`: the human signs the rendered summary, bound into the commitment
- [x] Signed result entry chained after the authorisation receipt
- [x] Read-only ERP precondition (SQLite, fail-closed target + amount check)
- [x] SMTP adapter (`dry_run` default; `live` reads password from env)
- [ ] Move write credentials (SQL write, payment, WA) into the broker
- [ ] Per-effect adapters + integration tests against a fake ERP

## Phase 3 — Transparency + interop
- [x] Merkle transparency log (RFC 6962/9162 style) with inclusion + consistency proofs
- [x] Signed tree head via Ed25519 (`mandate-log` namespace)
- [x] Off-host witness/anchor for the STH (rules out split-view)
- [ ] Export receipt as JWS / C2PA-style manifest
- [ ] OIDC/WebAuthn co-sign (passkeys) alongside Ed25519
- [ ] Provenance enforcement: `data_ref` required for every choice parameter

## Phase 4 — Ecosystem
- [ ] MCP server packaged for Claude Code / opencode / Cursor
- [ ] Shell shim + GitHub Action for CI bypass tests
- [ ] Policy packs per domain (trade, finance, ops)
- [ ] `mandate audit` diff of policy and trust-root changes

## Definition of done for v1.0
An agent with no credentials to the target system cannot cause a consequential
effect without a valid, single-use, human-signed grant, and an auditor can prove
that offline.
