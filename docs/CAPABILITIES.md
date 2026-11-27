# Capability tokens — authority that can only narrow

A grant authorises **one** effect. It does not answer "was the agent allowed to ask at
all", and it cannot be handed to a team. A capability token is that standing authority,
and the rule that makes delegation safe is **attenuation**: a child token may only narrow
its parent.

```bash
# ops: payments up to 5000 BAM, two payees, 8h, 5 uses
mandate --signers signers cap mint \
  --kinds payment.send --max-amount 5000 --currency BAM \
  --targets "Example Supplier,Other Ltd" --ttl 28800 --max-uses 5 \
  --issuer ops --subject ops --key ops -o root.json

# the team lead takes a slice: one payee, 2000 BAM
mandate --signers signers cap attenuate --parent root.json \
  --kinds payment.send --max-amount 2000 --currency BAM \
  --targets "Example Supplier" --ttl 7200 --max-uses 3 \
  --subject lead --key ops -o lead.json

# the agent gets less again
mandate --signers signers cap attenuate --parent lead.json \
  --kinds payment.send --max-amount 500 --currency BAM \
  --targets "Example Supplier" --ttl 3600 --max-uses 1 \
  --subject agent@example --key lead -o agent.json

mandate --signers signers cap verify --chain root.json,lead.json,agent.json
# {"ok": true, "length": 3, "subject": "agent@example", "scopes": {...}}
```

Ask the leaf what it permits:

```bash
mandate --signers signers cap check --token agent.json --intent intent.json
# {"ok": true}   or   {"ok": false, "why": "amount 900.0 exceeds 500.0"}
```

## What cannot happen (tested, with codes)

| attempt | code |
|---|---|
| raise `max_amount` above the parent | `E_WIDEN` |
| add a kind the parent does not have, or drop the kind list | `E_WIDEN` |
| drop the target list (which would allow any payee) | `E_WIDEN` |
| extend `not_after` or `max_uses` beyond the parent | `E_WIDEN` |
| change the currency restriction | `E_WIDEN` |
| present a child whose `parent` hash is not its parent | `E_CHAIN` |
| forge a scope (the signature covers the whole token) | `E_SIG` |
| use it outside its window | `E_EXPIRED` |

`scope` completeness matters more than it looks: *dropping* a restriction is how a
delegation widens. That is why an absent `targets` list is refused when the parent had one.

## What this does not do

- **It does not authorise the effect.** A capability token says the agent may ask; the
  grant still binds one specific effect, and `redeem` is what executes it.
- **It does not consume a budget across a fleet.** `max_uses` is a claim; counting uses
  needs the ledger, and the ledger already records them.
- **It does not revoke individual tokens.** `mandate revoke` removes a *signing key*; a
  per-token revocation list is a registry problem, not solved here.

Root of trust is the same SSH signer list as everything else, namespace
`mandate-capability`.
