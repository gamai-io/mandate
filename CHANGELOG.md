# Changelog

## 0.16.1 — 2026-11-09
- pymssql ERP driver: configurable `tds_version` (default `7.0` for older
  servers). A live read-only MSSQL check against `master`/`sys.tables` passed
  through the adapter (no business data).
- `STATUS.md` handover/state document; sdist includes it.
- No behavior change for SQLite/pyodbc; 106 tests.

## 0.16.0 — 2026-11-09
- **OIDC trusted publishing** path in the release workflow (dual path). Set the
  repo variable `PYPI_OIDC=true` after configuring the PyPI trusted publisher;
  the token secret is then unused.
- **Hardware-backed approver keys** (WebAuthn substitute): policy
  `require_hardware_key` rejects software Ed25519 grants; the approver key must
  be `sk-ssh-ed25519` (FIDO2, `ssh-keygen -t ed25519-sk -O verify-required`).
  Full WebAuthn/passkeys still requires a browser/CBOR stack.
- ERP `driver=pymssql` (FreeTDS; no ODBC driver needed) alongside `mssql`
  (pyodbc) and `sqlite`; `:name` binds are converted to positional parameters.
- 106 tests.

## 0.15.1 — 2026-11-09
- **Automated release**: pushing a `v*` tag now builds, tests, `twine check`s,
  publishes to PyPI (`PYPI_API_TOKEN` secret) and creates a GitHub release via
  `.github/workflows/release.yml`.
- No code changes; 103 tests.

## 0.15.0 — 2026-11-09
- **Operations**: `/metrics` (Prometheus text) on the broker, approver daemon and
  witness: request/execution/rejection counters, rate-limit hits, journal gauges,
  uptime.
- **Per-IP rate limiting** on `/execute`, `/request` and `/sth`
  (`--rate-limit-per-min`, `--rate-burst`, or `MANDATE_RATE_PER_MIN` /
  `MANDATE_RATE_BURST`); excess returns `429`. Disabled by default.
- Metrics require the bearer token when one is configured.
- 103 tests.

## 0.14.0 — 2026-11-09
- **Provenance enforcement (sycophancy firewall)**: policy effects declare
  `require_data_ref` fields (`payment.send`: `["target","amount"]`, etc.). A
  consequential intent must carry a `data_ref` provenance entry covering each
  required field; `user_pref` and `model_inference` never satisfy it. A
  `data_ref` without `covers` covers all required fields. Missing evidence is
  denied (`ProvenanceMissing` / `missing_data_ref`).
- Provenance is **hashed into the commitment**, so it cannot be swapped after the
  grant. Provenance entries are schema-validated.
- **Breaking:** commitment/receipt hashes change (provenance hash added).
- 100 tests.

## 0.13.0 — 2026-11-09
- **Advisory Telegram notification** in the approver daemon
  (`--telegram-chat`, token from `TELEGRAM_BOT_TOKEN`). The message carries only
  the summary/commitment; it has no approve button or link. The decision still
  happens on the approver host's TTY, so the security property is unchanged.
- **Portable receipt envelope** (`mandate export` / `export-verify`): intent,
  signed grant, hash-chained receipt, optional Merkle inclusion proof, signed
  with an OpenSSH SSHSIG in namespace `mandate-export`. This is a custom
  JOSE-style profile (not strict JWS/C2PA); verifiers use OpenSSH tooling.
- 94 tests.

## 0.12.0 — 2026-11-09
- **Payment adapter**: `provider=sandbox` (SQLite) or `provider=http`. Strict
  idempotency key = grant nonce, `lookup` before charging, and reconciliation on
  timeout. The broker's recovery uses the provider lookup, so a committed charge
  without a receipt is finalized without charging twice; a crash before the
  charge abandons the grant.
- **ERP driver `mssql`** (optional `pyodbc`, `pip install gama-mandate[mssql]`):
  only `SELECT`/`WITH` queries are accepted; SQLite stays `mode=ro`, MSSQL runs
  read-only and rolls back.
- 85 tests.

## 0.11.1 — 2026-11-09
- Privacy: repository is now **private**; example names, vendor names, and local
  domains were removed from the tree and from the package metadata. No personal,
  customer, or vendor data is included. Code unchanged; 78 tests.

## 0.11.0 — 2026-11-09
- **Approver daemon** (`mandate approver serve`): runs on the approver's host,
  recomputes the commitment and render from the intent (it does not trust the
  agent's proposal), shows the summary on its terminal, and signs a grant only
  after the human types `y`. The private key never leaves the approver host.
- **`mandate request --approver URL --intent ...`** client: gets the signed
  grant back (or a rejection). Loopback by default, bearer token for remote,
  256 KiB body cap.
- 7 approver tests + 78 total.

## 0.10.4 — 2026-11-09
- `mandate version` reports the distribution name `gama-mandate`.
- Published to PyPI: https://pypi.org/project/gama-mandate/

## 0.10.3 — 2026-11-09
- PyPI distribution name is **`gama-mandate`**. `agent-mandate` was rejected by
  PyPI as too similar to an existing project (`agentmandate`). Import package and
  console scripts are unchanged (`mandate`, `mandate-broker`, `mandate-mcp`).
- Code identical to 0.10.2.

## 0.10.2 — 2026-11-09
- Published to GitHub: https://github.com/gamai-io/mandate (public, CI green on
  Python 3.9–3.12). Release v0.10.1 with wheel, sdist, and checksums.
- Correct project URLs, README CI/license badges, install-from-git instructions.

## 0.10.1 — 2026-11-09
- Security: the broker requires a bearer token for non-loopback binds
  (`--token` / `MANDATE_BROKER_TOKEN`); broker and witness reject request bodies
  over 256 KiB (413).
- Lint: `ruff` config, clean `ruff check .`, CI lint + build/`twine check`.
- Packaging: `py.typed`, sdist/README install instructions, governance files
  (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `AUTHORS`,
  `RELEASE.md`).
- PyPI name `agent-mandate` verified available (2026-11-09).
- 71 tests.

## 0.10.0 — 2026-11-09
- **Off-host STH witness**: pins the latest signed tree head, rejects rollback
  (smaller tree), rejects split-view (same size, different root), and requires a
  valid consistency proof for growth. State is written atomically (0600).
- CLI: `mandate witness accept | verify | show | serve | push`.
- Loopback HTTP witness with a bearer token (`/sth`, `/state`, `/health`);
  `--allow-remote` required to bind elsewhere.
- 8 witness tests + 68 total.

## 0.9.0 — 2026-11-09
- **Merkle transparency log** over ledger entries (RFC 6962/9162 style):
  `Leaf=SHA256(0x00||JCS(entry))`, `Node=SHA256(0x01||L||R)`, MTH, inclusion
  proofs, consistency proofs.
- **Signed tree head** via `ssh-keygen -Y sign` in namespace `mandate-log`;
  `log_id` is the log key SHA256 fingerprint.
- CLI: `mandate log head | sth-verify | proof | verify-inclusion | consistency |
  verify-consistency`.
- Refuses to build a log over an invalid ledger hash chain.
- 9 Merkle tests + 60 total. Off-host **witness/anchor** is still required to
  rule out split-view; tracked in PLAN.md.

## 0.8.0 — 2026-11-09
- **Effect journal** (SQLite) with a lease-based state machine:
  `intent → executing → executed → receipted`, plus `failed` / `abandoned`.
- **Idempotent write adapter**: `mode=file` or `mode=sqlite` (a trusted SQL
  statement runs in the same transaction as the idempotency insert). The
  idempotency key is the **grant nonce**.
- The authorisation receipt is now appended **after** the effect commits,
  fixing the old "ledger says executed but no effect happened" crash window.
- **Crash recovery on start**: `executing` with a committed effect → finish the
  receipt; without an effect → abandoned; `executed` without a receipt →
  receipted. Duplicate `execute` returns the same receipt/result instead of an
  error.
- Config: `write`, `journal_db`, `lease_s`; `/health` reports journal counts.
- 43 tests (crash-after-effect recovery, crash-before-effect abandon, writer
  failure, concurrent single effect, journal payload mismatch).

## 0.7.0 — 2026-11-09
- Canonicalization is now **RFC 8785 (JCS)**: UTF-16 code-unit key ordering,
  ECMAScript number serialization, minimal string escaping, and strict rejection
  of non-finite numbers, lone surrogates, non-string keys, and integers outside
  the IEEE-754 safe range. Passes the RFC 8785 reference vector.
- **Breaking:** commitment/receipt hashes change (e.g. `1170.0` serializes as
  `1170`). Regenerate grants and ledgers from earlier versions.
- CI: GitHub Actions test matrix on Python 3.9–3.12.

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
