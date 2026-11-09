# Changelog

## 0.6.0 — 2026-11-09
- `allowed_signers` now requires an explicit `namespaces="mandate"` scope
  (`namespaces="mandate-broker"` for broker result keys). A key without a scope
  is rejected, so a grant key cannot sign broker receipts and vice versa.
- Validity windows (`valid-after` / `valid-before`) are enforced in Mandate's
  own check and by OpenSSH.
- Key revocation: `mandate revoke --pub key.pub` writes the SHA256 fingerprint to
  `trust/revoked_signers`; `redeem`, `verify`, and `verify-result` reject revoked
  keys. Configurable via `--revoked` / `MANDATE_REVOKED`.
- `mandate signers` lists parsed principals, namespaces, validity, and fingerprints.
- 37 tests (namespace scope, validity window, revocation, revoke CLI).

## 0.5.0 — 2026-11-09
- Grant `audience`: a grant can be bound to one broker (`mandate grant --audience <broker>`).
  The broker verifies `audience == broker_name` and rejects unbound grants by default
  (`--allow-any-audience` to opt out). Closes cross-broker replay.
- Broker-side re-derivation: `erp.derive` re-reads counterparty/amount/currency from the
  source of truth and rejects the effect if the agent's intent diverges
  (`derivation_mismatch`), not just at the precondition amount check.
- 33 tests (audience mismatch, unbound grant, currency derivation mismatch).

## 0.4.0 — 2026-11-09
Security fixes from an independent multi-agent audit (Claude + subagent + web):
- `mandate grant` recomputes commitment/render_hash/proposal_id from the intent and rejects a mismatched proposal (approval-confusion fix).
- `redeem` enforces policy (unknown effects denied) and binds the grant to the agent (`agent` field), closing the actor-swap self-approval bypass.
- CLI/MCP redeem now performs the nonce check and append under one file lock; ledger append is fsync'd and anchored with `<ledger>.head`; `verify_chain` rejects empty or truncated ledgers.
- Intent schema validation: unknown effect/amount fields and non-finite amounts are rejected; `params` must be flat scalars.
- `render` quotes every value (no `|` injection) and includes all params.
- ERP: NaN/non-dict amounts rejected; only `bind_params` can fill query placeholders.
- `execute` refuses non-loopback brokers (unless `--allow-remote`) and does not follow redirects.
- MCP adapter moved into the package and shipped as `mandate-mcp`; `verify-result` validates the signed broker result entry.
- `doctor` fails when signers are missing; `max_uses` is honestly fixed at 1.

## 0.3.0 — 2026-11-09
- Read-only ERP precondition (SQLite `mode=ro`, named-param query, amount tolerance).
- SMTP adapter for `message.send` (`dry_run` default, `live` reads password from env).
- Broker `--config`, `/health` reports `smtp` and `erp`.
- Preconditions run before the nonce claim, so a failed check does not consume the grant.
- Packaging: `pyproject.toml`, console scripts `mandate` / `mandate-broker`,
  `mandate init`, `mandate doctor`, `mandate version`.

## 0.2.0 — 2026-11-09
- Effect broker: `/execute` + `/health`, loopback by default.
- Atomic nonce claim (SQLite `UNIQUE`) prevents double execution.
- `render_hash` bound into commitment and grant (approver signs the rendered summary).
- Signed result entry chained after the authorisation receipt.

## 0.1.0 — 2026-11-09
- Canonical commitment (JCS), stable ids.
- Intent / Grant / Receipt objects.
- Off-host Ed25519 grant via `ssh-keygen -Y sign`.
- One-shot redeem, replay detection, hash-chained ledger, offline verification.
- Agent cannot self-approve; unknown effects denied.
- MCP adapter and agent skill.
