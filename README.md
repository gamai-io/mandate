# Mandate

[![tests](https://github.com/gamai-io/mandate/actions/workflows/test.yml/badge.svg)](https://github.com/gamai-io/mandate/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Signed, verifiable business commitments for AI agents.**

Most agent safety tools answer *"is this tool allowed?"*. Mandate answers the
question that actually matters: **"who ordered this exact payment, to this
supplier, for this amount?"** A tool permission is not a business mandate.

Every consequential effect becomes a canonical **Commitment** object. An agent
signs the intent; a human co-signs a **Grant** with an Ed25519 key; execution
produces a hash-chained **Receipt**. Anyone can verify the whole chain offline.

> Approval workflows are ephemeral events. A Mandate is a durable, portable,
> cryptographically bound artifact — a commit, not a log line.

## Why it is not another approval gate

| Approval gate | Mandate |
|---|---|
| Asks "may this tool run?" | Asks "is this exact effect authorised?" |
| Identity is a self-asserted field | Approver proves possession of an off-host key |
| Approval is a mutable DB row | Grant + receipt are signed, content-addressed |
| Logs what happened | Lets anyone prove what was authorised |

## Install

CLI + broker + MCP adapter. There is **no web UI** by design: Mandate is a
local trust primitive you embed in your own stack.

```bash
python3 -m pip install gama-mandate
# or from source / git
python3 -m pip install "git+https://github.com/gamai-io/mandate.git"

mandate doctor                      # checks python, ssh-keygen, policy
mandate init --dir ./my-deployment  # policy, allowed_signers, config, example
```

## Quickstart

```bash
export PYTHONPATH=$PWD

# 1. on the approver's device (never on the agent host)
ssh-keygen -t ed25519 -f ~/.ssh/mandate -C mandate
# append the PUBLIC key to trust/allowed_signers as: approver ssh-ed25519 AAAA... mandate

# 2. agent proposes
./bin/mandate propose --intent examples/intent.json --out /tmp/proposal.json

# 3. human grants (signs the commitment, bound to one broker + the agent)
./bin/mandate grant --proposal /tmp/proposal.json --approver approver \
  --key ~/.ssh/mandate --audience local-broker --out /tmp/grant.json

# 4. agent redeems exactly once
./bin/mandate redeem --intent examples/intent.json --grant /tmp/grant.json \
  --ledger ledger.jsonl

# 5. or let the effect broker execute it (credentials stay in the broker)
./bin/mandate-broker --port 8899 --signers trust/allowed_signers \
  --ledger ledger.jsonl --nonce-db broker/used.sqlite &
./bin/mandate execute --broker http://127.0.0.1:8899 \
  --intent examples/intent.json --grant /tmp/grant.json

# 5. anyone verifies offline
./bin/mandate verify --receipt ... --intent examples/intent.json --grant /tmp/grant.json
./bin/mandate verify-result --entry /tmp/result.json --broker-signers trust/broker_signers
./bin/mandate chain --ledger ledger.jsonl
```

Exit codes for `check`: `0` allow · `10` ask (grant required) · `20` deny.

## Effect broker (Phase 2)

`bin/mandate-broker` is the only component that executes effects. It verifies
the grant, **atomically claims the nonce** (SQLite `UNIQUE`, so two concurrent
requests cannot both succeed), runs the effect handler, and appends a signed
result entry to the hash-chained ledger. The agent calls it over loopback; the
agent never holds the effect credentials.

The shipped handlers are a sandbox (they record the effect under `effects/` or
`outbox/`). Wiring real credentials (SQL write, SMTP, payment) is Phase 2
completion — see `PLAN.md`.

### Adapters

**ERP precondition (read-only).** Before a grant is consumed, the broker runs a
named-parameter SQLite query against master data. No row → `counterparty_not_found`;
amount outside `tolerance_pct` → `amount_mismatch`. The grant is **not**
consumed when a precondition fails, so a corrected request can retry safely.

**SMTP (`message.send`).** `mode=dry_run` writes an `.eml` to the outbox;
`mode=live` sends via SMTP. The password is read from the env var named in
`password_env` and never logged or returned.

```json
"erp": {"db": "erp.sqlite", "checks": {"payment.send": {
  "query": "SELECT invoice_total FROM vendors WHERE name = :target",
  "amount_field": "invoice_total", "tolerance_pct": 0.5}}},
"smtp": {"mode": "dry_run", "host": "", "user": "",
         "password_env": "MANDATE_SMTP_PASSWORD", "from": "noreply@example.com"}
```

## Key scoping and revocation

An `allowed_signers` line **must** declare its namespace scope:

```
approver namespaces="mandate" ssh-ed25519 AAAAC3Nza... mandate
gama-broker namespaces="mandate-broker" ssh-ed25519 AAAAC3Nza... broker
```

Optional validity: `valid-after="YYYYMMDD" valid-before="YYYYMMDD"`.
Revoke a key by fingerprint:

```bash
mandate revoke --pub key.pub --reason "laptop lost"
mandate --signers trust/allowed_signers signers   # inspect scopes + fingerprints
```

### Idempotent writes and recovery

The broker keeps a SQLite **effect journal** (`journal_db`). The flow is
`intent → executing → executed → receipted`; the authorisation receipt is
written only **after** the effect commits. On startup the broker recovers:
a committed effect without a receipt gets one; a claimed grant with no effect is
abandoned; a duplicate `execute` returns the original receipt and result.

`write.mode=sqlite` runs a trusted configured statement together with an
idempotency insert in **one transaction**, keyed by the grant nonce:

```json
"write": {"mode": "sqlite", "db": "erp.sqlite",
          "statement": "INSERT INTO payments(nonce,vendor,amount) VALUES(:nonce,:target,:amount)"}
```

## Transparency log

Every ledger entry is a leaf in an RFC 6962/9162-style Merkle tree
(`Leaf=SHA256(0x00||JCS(entry))`, `Node=SHA256(0x01||L||R)`). A signed tree
head (STH) fixes the root and size; inclusion and consistency proofs verify
offline:

```bash
mandate log head  --ledger ledger.jsonl --log-name log1 --log-key ~/.ssh/mandate-log --out sth.json
mandate --signers trust/allowed_signers log sth-verify --sth sth.json
mandate log proof --ledger ledger.jsonl --index 3 --out proof.json
mandate log verify-inclusion --entry entry.json --proof proof.json --sth sth.json
mandate log consistency --ledger ledger.jsonl --first 2 --second 3 --out cons.json
mandate log verify-consistency --old old_sth.json --new sth.json --proof cons.json
```

A single log cannot prevent **split-view** by its operator; pin the STH on a
second machine (witness/anchor). The STH signer needs
`namespaces="mandate-log"` in `allowed_signers`.

### Off-host witness

```bash
# on the second machine
mandate --signers log_signers witness serve --state witness.json \
  --token "$WITNESS_TOKEN" --port 8898

# on the log host
mandate witness push --url http://witness:8898 --sth sth.json --token "$WITNESS_TOKEN"
mandate witness push --url http://witness:8898 --sth sth_new.json --proof cons.json --token "$WITNESS_TOKEN"
mandate witness show --state witness.json
```

The witness pins the latest STH and rejects rollback or a same-size different
root (split-view). Growth requires a consistency proof from the pinned root.
`witness verify` checks without pinning; `witness accept` pins locally.

## Co-sign on the approver's host

The agent never holds the private key. The approver runs a small daemon on
their own machine; it recomputes the commitment/render from the intent (it does
not trust the agent's proposal), prints the summary, and signs only after `y`:

```bash
# approver's host
mandate approver serve --key ~/.ssh/mandate --approver approver \
  --audience local-broker --port 8897

# agent host
mandate request --approver http://approver-host:8897 --intent intent.json \
  --audience local-broker --out grant.json
mandate execute --broker http://127.0.0.1:8899 --intent intent.json --grant grant.json
```

Loopback by default; a non-loopback daemon requires `--token` /
`MANDATE_APPROVER_TOKEN`. Without a TTY the daemon refuses to auto-approve
(`503`). A Telegram notification channel can be added in front of the same
signer without changing the security property.

### Telegram notification (advisory)

```bash
TELEGRAM_BOT_TOKEN=... mandate approver serve --key ~/.ssh/mandate \
  --approver approver --telegram-chat 6402195499
```
The message contains only the summary, agent, broker and commitment. It has no
approve button or link; the human still confirms on the approver host's TTY.
Notification failures are logged and never auto-approve.

### Portable receipt export (JOSE-style)

```bash
mandate export --receipt receipt.json --intent intent.json --grant grant.json \
  --proof proof.json --key ~/.ssh/mandate --signer approver --out bundle.json
mandate --signers trust/allowed_signers export-verify --bundle bundle.json
```
The envelope carries the intent, the signed grant, the hash-chained receipt and
an optional Merkle inclusion proof, signed with an OpenSSH SSHSIG in namespace
`mandate-export`. Add `mandate-export` to the approver's `namespaces="..."` in
`allowed_signers`. This is a custom profile, not strict JWS/C2PA; verifiers use
OpenSSH tooling.

### Payments

```json
"payment": {"provider": "sandbox", "db": "payments.sqlite"}
```
or a generic HTTP provider:
```json
"payment": {"provider": "http", "url": "https://provider.example/charges",
            "token_env": "PAYMENT_TOKEN"}
```
The provider must be idempotent on `idempotency_key` and expose a lookup by that
key. The broker looks up before charging and reconciles on timeout; recovery
never charges twice.

### ERP (SQLite or MSSQL, read-only)

```json
"erp": {"driver": "sqlite", "db": "erp.sqlite", "checks": { ... }}
```
For MSSQL: `"driver": "mssql"`, `"dsn": "...", "user_env": "...",
"password_env": "..."` and `pip install gama-mandate[mssql]`. For FreeTDS without
an ODBC driver use `"driver": "pymssql"`, `"server": "...", "database": "...",
"tds_version": "7.0"` (default; raise it only if the server supports it),
`"user_env": "...", "password_env": "..."`. Only `SELECT`/`WITH` queries are
accepted; SQLite opens `mode=ro`, MSSQL runs read-only and rolls back.

## Provenance (sycophancy firewall)

A consequential intent must justify its choices with data, not with a stated
preference. Policy declares the required fields:

```json
"payment.send": {"risk": "high", "require_data_ref": ["target", "amount"]}
```

The intent carries typed provenance:

```json
"provenance": [
  {"type": "data_ref", "source": "erp:vendor:1", "covers": ["target", "amount"]}
]
```

- `data_ref` without `covers` covers all required fields.
- `user_pref` and `model_inference` **never** satisfy a required field.
- Missing evidence is denied (`missing_data_ref` / `ProvenanceMissing`).
- The provenance is hashed into the commitment, so it cannot be swapped after
  the grant.

## Operations

- **Metrics:** Prometheus text at `/metrics` on the broker, approver daemon and
  witness (bearer token required if one is configured). Counters for requests,
  executions, rejections, rate-limit hits, journal gauges and uptime.
- **Rate limiting:** per-IP token bucket on `/execute`, `/request` and `/sth`.
  Enable with `--rate-limit-per-min N --rate-burst M` (or
  `MANDATE_RATE_PER_MIN` / `MANDATE_RATE_BURST`). Excess returns `429`.
  Disabled by default (`0`).

## Hardware-backed approver keys (WebAuthn substitute)

Mandate does not implement browser WebAuthn (it needs a CBOR/COSE stack and a
browser UI). A phishing-resistant FIDO2 key works with the same verification:

```bash
ssh-keygen -t ed25519-sk -O verify-required -f ~/.ssh/mandate
# allowed_signers: approver namespaces="mandate,mandate-export" sk-ssh-ed25519 AAAA...
```

Set `"require_hardware_key": true` on an effect to reject software Ed25519
grants; the approver key must then be `sk-ssh-ed25519`.

## MCP manifest gate (Phase 1)

Pin the tools an agent may use and detect tool poisoning/rug-pull:

```bash
mandate mcp lock --cmd "python3 my_mcp_server.py" --server my-server \
  --key ~/.ssh/publisher --signer publisher --out mandate.lock.json
mandate --signers trust/allowed_signers mcp verify \
  --lock mandate.lock.json --cmd "python3 my_mcp_server.py"
mandate --signers trust/allowed_signers mcp proxy \
  --lock mandate.lock.json --cmd "python3 my_mcp_server.py"
```

The lock hashes every tool name, description and input schema and is signed
with an OpenSSH SSHSIG in namespace `mandate-mcp` (`namespaces="mandate-mcp"` in
`allowed_signers`). The proxy denies a changed manifest and any tool not in the
lock; `--verify-calls` re-probes before each call.

## Taint gate (Phase 2)

After an untrusted source (web, email, RAG, MCP output) is read, an effect tool
requires a Mandate grant and a `data_ref`:

```json
{"sources": ["web_fetch"], "effects": ["pay"], "require_grant": true}
```

The agent attaches the grant to the call; the proxy verifies it, requires a
`data_ref` provenance entry when the session is tainted, consumes it (replay
denied) and strips `_mandate` before forwarding:

```json
{"name": "pay", "arguments": {"amount": 1,
  "_mandate": {"intent": {"effect": {"kind": "mcp.call", "target": "pay",
     "params": {"args_sha256": "…"}}, "provenance": [{"type": "data_ref",
     "source": "erp:vendor:1"}]}, "grant": {…}}}}
```

Run with `mandate mcp proxy --taint taint.json --mcp-ledger ledger.jsonl`.

## Sandbox untrusted MCP servers (Phase 3)

Run the MCP server itself in a hardened container:

```bash
mandate mcp proxy --lock mandate.lock.json --cmd "python3 fake_mcp.py" \
  --sandbox docker --sandbox-image python:3.12-slim \
  --sandbox-mount "$PWD/tests/fixtures:/work:ro" --sandbox-workdir /work
```

- `docker` (runc) and `gvisor` (`--runtime runsc`): read-only root, `--network
  none`, `--cap-drop ALL`, `no-new-privileges`, pids/memory/cpu limits, 16 MiB
  tmpfs, explicit read-only mounts.
- `firecracker` uses `--sandbox-cmd-template "<launcher> --"` so a VMLab
  Firecracker runner can be plugged in without changing the proxy.
- `local` is for trusted development only.

## Intent Divergence Benchmark

Measure whether the gate rejects actions that diverge from the user's intent:

```bash
mandate bench --scenarios bench/scenarios/idb_v0.jsonl --out idb-report.json
```

Scenarios cover prompt injection, sycophancy-to-action, partial/invalid
provenance, hidden fields, unknown effects and benign effects. Metrics:
`failed`, `false_allow`, `false_block`, `pi_asr`, per-category totals. The
deterministic run is CPU-only; `bench/lumi_idb.sbatch` runs it inside the LUMI
container.

A model-generated corpus measures the model itself:

```bash
mandate bench --scenarios bench/scenarios/model_prompts.jsonl \
  --model-url http://127.0.0.1:8000 --model <served-model>
```

Metrics: `bad_proposals`, `bad_proposal_rate`, `unsafe_execution`
(target 0). `bench/lumi_idb_model.sbatch` runs it against a vLLM server on LUMI.

## Design invariants

1. **Effect, not tool.** The registry keys on `payment.send`, not on
   `gama_sql`. The same effect is the same commitment regardless of executor.
2. **Canonical bytes.** **RFC 8785 (JCS)** canonical JSON; the commitment is the
   hash of `{v, effect, requested_by, render_hash}`. Same content ⇒ same id, in
   any RFC 8785 implementation.
3. **Off-host key.** The approver's private key never lives where the agent
   runs. The host stores only public keys (`trust/allowed_signers`).
4. **One-shot, nonce-bound.** A grant is redeemable once; replays fail.
5. **Agent cannot self-approve.** Enforced in code, not by convention.
6. **Fail closed.** Unknown effects are denied. Missing signer ⇒ invalid.

## Layout

```
spec/       MANDATE-1 data model
mandate/    stdlib-only reference implementation
bin/        CLI
adapters/   MCP server
tests/      unit + bypass tests (red-team)
docs/       THREAT_MODEL, NON_GOALS, PLAN
skills/     agent skill instructions
```

## Status

**Alpha** — reference implementation v0.16.1: canonical commitment, Ed25519
grant bound to the executing agent, one-shot redeem under a file lock,
hash-chained receipts with a `.head` anchor, provenance enforcement, idempotent
effect journal + write adapter, payment adapter with provider idempotency and
reconciliation, read-only ERP (SQLite/MSSQL/pymssql) checks, SMTP, Merkle
transparency log with an off-host witness, approver daemon with advisory
Telegram notification, hardware-backed `sk-` keys, portable JOSE-style receipt
export, MCP server (`mandate-mcp`), `/metrics`, rate limiting, and a red-team
test suite. See `STATUS.md` and `docs/THREAT_MODEL.md` for limits.

## Honest limitation

Cryptography proves *who authorised what*. It does **not** isolate
credentials. Until the credentials that cause the effect (SQL write, payment
API, mail) live only in an effect broker, a compromised agent can bypass
Mandate entirely. That broker is the next milestone — see `PLAN.md`.
