# Changelog

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
