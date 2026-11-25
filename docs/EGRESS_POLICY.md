# What to put on the egress allowlist

The broker refuses every outbound connection that is not on the list. That is the
point, and it means the list is a configuration a bank has to fill in once.

## The shape

```json
{
  "version": 1,
  "default": "deny",
  "allow": [
    "api.payment-provider.example:443",
    "registry.internal.example:443",
    "smtp.example:587"
  ],
  "allow_metadata": false
}
```

Rules the code enforces, in this order:

1. **default deny** — a policy without `"default": "deny"` is rejected at load;
2. **host:port** — the port must match; `host:443` does not open `host:8443`;
3. **private and link-local addresses** are refused unless that exact IP is
   allowlisted;
4. **metadata addresses** (`169.254.169.254`, `fd00:ec2::254`) are refused even
   when someone allowlists them; only `"allow_metadata": true` says otherwise, and
   that should be a deliberate, documented exception;
5. the check runs **on every request**, so a hostname that resolves differently the
   second time is caught.

## Starting set for a bank

| purpose | entry | note |
|---|---|---|
payment provider | `api.<provider>:443` | one host, not the provider's whole domain |
package registry | `<registry>:443` | internal mirror preferred |
SMTP relay | `<relay>:587` | only if `message.send` is a live effect |
SIEM | `<siem>:443` | for `mandate ship` |
TSA | one qualified TSA host:443 | only if anchoring is on |

Everything else starts closed: DNS, package indexes the agent might want, generic
`https://` — none of it is allowed by default, and that is what breaks the "agent
fetches a fake API doc and pays" chain.

## What this does not do

- It is an **application-level** control: an agent with raw sockets and host
  networking bypasses it. Pair it with network namespaces, a VM egress rule or a
  Kubernetes NetworkPolicy; that is the bank tier.
- It does not inspect content, only destinations.
- It does not cover the agent's own package manager unless that traffic is forced
  through the proxy.

## Checking it

```bash
mandate egress check --policy egress.json api.payment-provider.example:443
mandate egress check --policy egress.json 169.254.169.254:80      # refused
```

`tests/test_egress_coverage.py` also fails when an adapter is added that opens a
connection without calling the guard, so the list cannot be quietly bypassed in
code.
