# AP2 / Verifiable Intent: a sidecar, not a competitor

AP2 (Agent Payments Protocol, Google, Sept 2025, now under FIDO) defines a **mandate**: a signed
SD-JWT VC in which a user authorises an agent to do a specific checkout or payment, and receipts
issued by whoever verified it. Mastercard's **Verifiable Intent** is the same idea in the card
network's words: a signed, tamper-resistant record of what the person asked for.

Those objects answer *"may this agent pay this merchant, within these constraints"* on a rail.
They do not answer the question a bank's auditor asks afterwards: **which named human approved
this exact effect, once, and can I prove it without the vendor?** That is what `gama-mandate`
adds, and the two are composable.

## What the sidecar does

```bash
# 1. look at the mandate (no signature check without a key)
mandate ap2 inspect --token mandate.jwt --key issuer.pem
# → {"alg":"ES256","hash":"sha256:d2810c07…","signature_verified":true,"claims":{…}}

# 2. turn it into our intent — amount, merchant, and the hash as provenance
mandate ap2 intent --token mandate.jwt --approver approver --out intent.json

# 3. approve it like any other effect
mandate propose --intent intent.json --salted --out p.json
mandate grant --proposal p.json --approver approver --key approver_key
mandate redeem --intent intent.json --grant grant.json --ledger ledger.jsonl

# 4. emit the link for their log and ours
mandate ap2 sidecar --token mandate.jwt --grant grant.json --ledger ledger.jsonl
```

The sidecar contains the AP2 hash, the few claims that matter, our commitment, the grant nonce,
the receipt hash and the render hash the human actually saw. It is one-way by design: **our
receipt commits to their mandate's hash**, so citing either record cites the other.

## What we do and do not verify

| claim | status |
|---|---|
| the AP2 mandate is referenced by hash | **yes**, always (SHA-256 over the raw JWS) |
| the AP2 signature is valid | **only if** `cryptography` is installed, a key is supplied and `alg` is ES256; otherwise `signature_verified: false` and a stated reason |
| our grant belongs to a named human and one effect | **yes**, Ed25519 over the canonical intent, one-shot nonce |
| our record is independently verifiable offline | **yes** — `verify.html`, `mandate verify-receipt`, `spec/verify_offline.py` |
| we are AP2-compatible | **no** — our object is not an SD-JWT VC with `cnf`; the sidecar says so in `not_claimed` |
| the mandate is valid on a rail | **no** — that is the network's and the issuer's decision |

## Why a sidecar and not a re-implementation

AP2 solves reach: issuers, processors and merchants already agree on the object. Re-implementing
it would mean asking a bank to replace a standard with ours — the objection that kills small
vendors. Referencing it costs one hash and wins the argument that matters: their mandate says
*what was allowed*; our receipt says *who signed, over what, and here is the chain an auditor can
check in 2033 with our servers switched off*.

## Limits worth stating in a supplier questionnaire

- A sidecar without a receipt hash (`--ledger` omitted) proves the link to the grant, not that the
  effect was redeemed. Provide the ledger.
- `signature_verified: false` is not an error; it is the truthful state when no issuer key is
  available. Do not describe such a record as "verified mandate".
- ES256 only. P-384, RS256 and `alg: none` are refused by name rather than guessed at.
- Claim mapping is intentionally narrow (amount, merchant/payee, issuer). Unknown claims are not
  copied into the intent, because an intent is signed and must stay readable.
