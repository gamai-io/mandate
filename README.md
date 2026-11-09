# Mandate

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
python3 -m pip wheel . -w dist --no-deps
python3 -m pip install dist/agent_mandate-0.3.0-py3-none-any.whl

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

# 3. human grants (signs the commitment)
./bin/mandate grant --proposal /tmp/proposal.json --approver approver \
  --key ~/.ssh/mandate --out /tmp/grant.json

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

## Design invariants

1. **Effect, not tool.** The registry keys on `payment.send`, not on
   `gama_sql`. The same effect is the same commitment regardless of executor.
2. **Canonical bytes.** JCS-style canonical JSON; the commitment is the hash of
   `{v, effect, requested_by}`. Same content ⇒ same id, any language.
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

Reference implementation v0.4: canonical commitment, Ed25519 grant bound to the
executing agent, one-shot redeem under a file lock, hash-chained receipts with a
`.head` anchor, effect broker with signed result entries, read-only ERP
preconditions, SMTP adapter, MCP server (`mandate-mcp`), and a red-team test
suite. See `PLAN.md` for the roadmap.

## Honest limitation

Cryptography proves *who authorised what*. It does **not** isolate
credentials. Until the credentials that cause the effect (SQL write, payment
API, mail) live only in an effect broker, a compromised agent can bypass
Mandate entirely. That broker is the next milestone — see `PLAN.md`.
