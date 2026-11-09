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

## Phase 2 — Effect broker (the milestone that removes theater)
- [ ] Credentials live only in the broker (SQL write, SMTP, payment, WA)
- [ ] Agent calls broker over HTTP/MCP; broker requires a valid grant
- [ ] `render_hash`: the human signs the rendered summary, not opaque args
- [ ] Per-effect adapters + integration tests against a fake ERP

## Phase 3 — Transparency + interop
- [ ] Append-only transparency log (SCITT-style) for receipts
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
