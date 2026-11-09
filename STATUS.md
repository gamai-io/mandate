# Status / handover

**Mandate** — signed, verifiable business commitments for AI agents.

- Distribution: `gama-mandate` (PyPI), import package `mandate`.
- CLI: `mandate`, `mandate-broker`, `mandate-mcp`.
- Repository: https://github.com/gamai-io/mandate (public, MIT).
- Current release: **v0.24.0**, CI green on Python 3.9–3.12, 137 tests.

## What works now

- RFC 8785 (JCS) canonical commitment; provenance hashed into the commitment.
- Provenance enforcement: policy `require_data_ref` per effect; `user_pref` and
  `model_inference` never satisfy it.
- Off-host Ed25519 grant bound to the agent and broker audience; one-shot
  redeem; namespace-scoped signers, validity windows, revocation.
- Idempotent effect journal; write adapter; payment adapter (sandbox/HTTP) with
  provider idempotency and reconciliation; SMTP (dry-run/live).
- Read-only ERP checks: SQLite, MSSQL (pyodbc), MSSQL via pymssql/FreeTDS
  (`tds_version`, default 7.0 for older servers); only SELECT/WITH.
- Merkle transparency log (RFC 6962/9162 style) + signed tree head + off-host
  witness (rollback/split-view rejection).
- Approver daemon on the approver host (TTY confirm, key never leaves);
  advisory Telegram notification.
- Portable receipt envelope (`mandate export`) with OpenSSH SSHSIG.
- Operations: `/metrics` (Prometheus text) and per-IP rate limiting.
- MCP manifest gate: signed lock, rug-pull/poisoned-manifest deny, stdio proxy.
- MCP taint gate: untrusted source → effect requires a grant + `data_ref`.
- Sandbox runner: hardened Docker (verified), gVisor (verified end-to-end on a
  lab VM with `runsc`), Firecracker (verified end-to-end via
  `mandate-fc-bridge` and a KVM microVM).
- Intent Divergence Benchmark: deterministic 12-scenario corpus (12/12,
  `pi_asr=0`) and a 20-prompt model corpus; LUMI comparison of qwen25-7b and
  qwen25vl7b (`unsafe_execution=0` for both); LUMI batch templates.
- Auditor bundle: intent + grant + receipt + Merkle proof + STH + witness pin in
  one signed JSON, verified offline.
- Automated release on `v*` tags; OIDC trusted-publishing path.

## Known limitations / open items

- Full WebAuthn/passkeys are not implemented (browser/CBOR stack). Use FIDO2
  `sk-ssh-ed25519` keys with `require_hardware_key`.
- PyPI releases **0.10.3, 0.10.4, 0.11.0** contain old example identifiers in
  their sdists/metadata; a deletion request was sent to PyPI support. Do not
  treat those releases as current.
- OIDC publishing needs the one-time PyPI trusted-publisher configuration and
  `PYPI_OIDC=true`; until then the `PYPI_API_TOKEN` secret is used.
- One live MSSQL check passed with pymssql/FreeTDS; ODBC Driver 18 failed TLS
  negotiation against an older server. Use `driver=pymssql` there.
- A single transparency log cannot prevent split-view by its operator; pin the
  STH with the witness on a separate host.

## Test / release

```bash
make test          # 106 tests
ruff check .
# release: bump version, update CHANGELOG, then
git tag -a v<ver> -m "Mandate <ver>" && git push origin main --tags
# the release workflow builds, tests, publishes to PyPI and creates the GitHub release
```
