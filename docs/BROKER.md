# The broker: where the credential lives

The README says the honest thing: *cryptography proves who authorised what; it
does not isolate credentials.* This document is the line between those two, and
what is on each side of it.

## The claim, tested

> An agent with no payment credential can cause a payment **only** by presenting
> a signed, one-shot grant to the broker; a replayed grant charges once.

`tests/test_broker_custody.py` proves it with three processes:

| process | holds | can do |
|---|---|---|
| fake payment provider | nothing | records a charge per idempotency key, requires a bearer token |
| **broker** | `PAY_TOKEN` (env), receipt key, nonce db, journal | charge, append receipt |
| agent | `MANDATE_BROKER_TOKEN` only | `POST /execute` with intent + grant |

Measured in the suite (5 tests, ~3.5 s):

- the agent's environment does **not** contain `PAY_TOKEN`, yet the effect runs;
- the agent calling the provider directly gets **401**;
- an unauthenticated `/execute` gets **401**;
- the same grant presented twice produces **one** charge;
- `/health` reports `custody.payment.secret = "env:PAY_TOKEN"` and `present: true`,
  and never the value.

```bash
python3 -m pytest -q tests/test_broker_custody.py -v
```

## What this boundary does and does not buy

**Buys:** a compromised agent cannot pay by reading its own environment, because
the credential is not there. It can only ask the broker, and the broker requires
a grant whose commitment covers kind, target, amount, agent, session and nonce.

**Does not buy:** protection from a host-level compromise. If the agent runs as
the same uid as the broker, or can ptrace it, or read `/proc/<pid>/environ`, the
boundary is gone. `packaging/mandate-broker.service` exists for that reason:
separate user, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`RestrictAddressFamilies`, `MemoryDenyWriteExecute`, and a `0400` environment
file. Verify it, do not trust it:

```bash
systemctl show mandate-broker -p User -p ProtectSystem -p NoNewPrivileges
ls -l /etc/mandate/broker.env          # must be 0400, owner mandate-broker
tr '\0' '\n' < /proc/$(pgrep -f mandate-broker | head -1)/environ | grep -c PAY_TOKEN
```

## Deploying it

1. `useradd --system --home /opt/mandate mandate-broker`
2. `/etc/mandate/broker.env` — `0400`, owner `mandate-broker`, holds only secrets.
3. `broker/config.json` — no secret values, only `token_env` names.
4. `systemctl enable --now mandate-broker`
5. Agent side: `MANDATE_BROKER_URL=http://127.0.0.1:8899` and
   `MANDATE_BROKER_TOKEN=...`; no provider token, no signing key.
6. The approver key never touches the broker or the agent: `mandate grant`
   runs where the human is.

## Recovery

The journal is `executing → executed → receipted`. On start the broker recovers:
a committed effect without a receipt gets one; a claimed grant with no effect is
abandoned; a duplicate `execute` returns the original receipt instead of charging
again. `mandate broker recover` runs the same pass by hand.

## Open gaps, named

- **No mTLS.** Loopback plus a bearer token; a bank that wants mutual TLS puts a
  sidecar in front or asks us to add it (small change, not built).
- **No per-agent tokens.** One broker token today; every caller shares it, so the
  ledger distinguishes them by grant, not by credential.
- **Host compromise** is out of scope, as above. So is a malicious broker admin.
- **The broker is still our code.** The offline verifier covers the evidence, not
  the execution path.
