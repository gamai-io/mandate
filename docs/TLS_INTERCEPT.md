# TLS interception — what it buys, what it costs

`egress.py` judges the destination: a CONNECT to `bank.example:443` is allowed or refused and the
bytes inside are invisible. That is the default, and it is the right one. Content inspection of
an HTTPS call needs something to terminate the TLS.

```bash
mandate egress ca init --ca-dir /etc/mandate/ca     # CA key + cert, key 0600
mandate egress trust --ca-dir /etc/mandate/ca       # how to make a client trust it
mandate egress policy --allow bank.example:443 --out egress.json
mandate egress proxy --policy egress.json --intercept --ca-dir /etc/mandate/ca \
        --port 3128 --ledger egress.jsonl
```

## The honest trade-off

| you get | you pay |
|---|---|
| request bodies scanned: a secret leaving is refused (`request_blocked`), redactable identifiers are masked | **the CA key can impersonate any host** for any client that trusts it |
| response bodies scanned: an instruction coming back is refused (`response_blocked`) | every inspected client must be configured to trust it — a deployment decision, not a flag |
| every decision in the same hash-chained ledger as grants and receipts | a client with **certificate pinning** will correctly refuse to connect through it |
| nothing decrypted is written to disk | the proxy becomes a high-value target: it sees plaintext |

If a pinned client breaks, that is the control working, not a bug to route around.

## Key custody

```
/etc/mandate/ca/ca.key     0600, owned by the proxy user, never copied
/etc/mandate/ca/ca.pem     the certificate clients trust
/etc/mandate/ca/leaves/    per-host certs, cached, 0600 keys, 90 days
```

- Generate it **on the machine that runs the proxy**; do not sync it to workstations.
- Remove it from clients when you stop inspecting: an unused CA is a standing impersonation
  capability, exactly like an unused signing key.
- Rotating the CA means re-trusting it everywhere; that is why `init_ca()` reuses an existing
  CA instead of silently replacing it.

## What is scanned

The same lexer as `mandate firewall` — 31 outbound and 18 inbound patterns, matched after
`normalize.fold` (see `docs/FIREWALL_COMPARE.md`):

| direction | blocked | redacted |
|---|---|---|
| request body | cloud keys, private-key blocks, JWTs, credentials in URLs, bearer headers | emails, IBANs, card numbers (Luhn), phones, JMBG |
| response body | instruction override, prompt reveal, role override, chat-template markers, hidden instructions | — |

A blocked request returns `403` to the agent; a blocked response returns `502` — the agent
never sees the content, and the reason is in the ledger.

## Limits, stated so nobody assumes more

- **One request per connection**, no keep-alive, no HTTP/2, no WebSocket.
- **`Content-Length` bodies**; a chunked body is read but an oversized one (>2 MB) is passed
  through and recorded as unscanned.
- **No content inspection of requests already in flight** — the policy is evaluated at CONNECT
  *and* at the request, but a connection opened before a policy change keeps its verdict.
- **Upstream verification stays on.** `--upstream-ca` adds a trust anchor for a private origin;
  there is no flag to turn verification off, because a proxy that does not verify its upstream
  can be pointed anywhere by whoever controls DNS.

## Proof

`tests/test_egress_tls.py` runs a real TLS origin signed by our CA and asserts:

- the CA key is `0600` and a leaf verifies against it (`openssl verify`);
- an IP destination gets an `IP:` SAN, a name gets `DNS:` (a wrong SAN is a rejected handshake);
- a clean POST passes end to end through the proxy;
- a request body with an AWS key returns **403** and leaves `request_blocked`;
- a response containing an instruction returns **502** and leaves `response_blocked`.
