# The broker: where the credential lives

The README says the honest thing: *cryptography proves who authorised what; it
does not isolate credentials.* This document is the line between those two, and
what is on each side of it.

## The claim, tested

> An agent with no payment credential can cause a payment **only** by presenting
> a signed, one-shot grant to the broker; a replayed grant charges once.
> ("One-shot" is per nonce store: two hosts or two ledgers without a shared
> `MANDATE_NONCE_URL` are two stores.)

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

## The `--audience` label is not a credential

A grant can be bound to a broker name (`grant --audience local-broker`). The
redeeming caller must repeat that name (`redeem --audience local-broker` or, in
code, `audience=`). This is a **label, not authentication**: any process that can
run `redeem` can type the same string. What makes the binding matter is that the
broker is the only place with the payment credential; the agent has nothing to
redeem *with* unless the operator runs `redeem` on the broker host.

If you need the caller's identity to be proven, use the agent token (`--svid`)
or mTLS — those are checked cryptographically. Do not rely on `--audience` for
that; it prevents a grant meant for broker A from being presented to broker B by
accident, not by an attacker who already runs your CLI.

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
again. `mandate-broker` runs the same pass by hand on start (it has no separate recover verb).

## Several agents, one broker

`--agents /etc/mandate/agents.json` switches the broker from one shared token to
per-agent tokens. Each token maps to a name, and a grant signed for `agent-a`
cannot be redeemed with `agent-b`'s token (tested). The store keeps SHA-256 only;
`mandate-broker agent add|list|revoke` manages it, tokens are printed once, and
the file is written `0600`.

## Certificates

`--tls-cert/--tls-key` serve HTTPS; `--client-ca` additionally requires a client
certificate and uses its **CN** as the agent name. The CN must be registered in
the agent store (`mandate-broker agent register`), and the grant's `agent` must
equal it — a valid certificate for the wrong agent is a 409, not a 401, because
the identity is known and the authorisation is wrong.

Tested end to end with a throwaway CA: own grant executes, another agent's grant
is refused, an unregistered CN is refused, no certificate means no handshake
(`tests/test_mtls.py`).

### Revocation

`--client-crl revoked.pem` turns on `VERIFY_CRL_CHECK_LEAF`: a certificate that
appears in the list cannot complete the TLS handshake, so the grant is never read.
The list is loaded at start; replacing it needs a restart today.

## Open gaps, named

- **Rotation needs a restart.** The certificate, CA and CRL are loaded at start;
  there is no live reload and no OCSP.
- **Per-agent tokens exist, per-agent *keys* do not.** The token identifies the
  caller; the grant still carries the approver's signature, not the agent's.
- **Host compromise** is out of scope, as above. So is a malicious broker admin.
- **The broker is still our code.** The offline verifier covers the evidence, not
  the execution path.
