# The commitment: why a salt, and what it defends against

A grant signs a *commitment* to an intent, not the intent text. The verifier recomputes it from
the intent it is given; if the bytes differ, the grant does not apply. Two schemes exist:

| scheme | value | where it is used |
|---|---|---|
| `sha256-jcs` (v1, frozen in 1.0) | `"sha256:" + hex(sha256(jcs(intent_core)))` | existing records; still verifies |
| `sha256-jcs-salt-v1` (v2) | `"sha256:" + hex(sha256(DOMAIN ‖ salt[16] ‖ jcs(intent_core)))` | `mandate propose --salted` |

```
DOMAIN = b"mandate/commitment/v2\x00"      (23 bytes, fixed)
salt   = 16 random bytes, hex-encoded, carried in the signed grant core
```

`intent_core` is the intent without `provenance` and without display-only fields; the JCS
canonicalisation is RFC 8785. The render hash is a separate binding to what the approver saw.

## Why v2 exists

AP2 (Agent Payments Protocol) says, in the specification of the payment mandate:

> "To prevent rainbow table attacks, the Checkout JWT MUST be signed using a digital signature
> scheme (e.g., ECDSA) and not a deterministic signature (e.g., Ed25519)."
> — https://ap2-protocol.org/ap2/specification/

The concern is real and applies to *any* deterministic signature over a low-entropy message:
`Ed25519` is deterministic (RFC 8032), and our commitment is a hash of a payload an attacker may
be able to guess — "pay 1.00 to X" for a handful of X is a small space. Given a signature seen in
the wild and the public key, an attacker can enumerate candidate payloads, compute the same hash,
and learn which one was approved. No private key is needed for that inference; it is a
confidentiality leak, not a forgery.

Three defences, and we use all three:

1. **Domain separation** — the prefix makes a mandate commitment unusable as any other hash in the
   system (and vice versa).
2. **A 128-bit salt inside the signed grant** — the attacker must know the salt to test a guess,
   and the salt never appears in the intent, the receipt, or the digest. Enumerating 2^128 salts
   is not a shortcut; it is the security level of the hash itself.
3. **A nonce per intent** — already part of the signed core, so even a repeated payment differs
   between approvals.

v1 remains valid because 1.0 froze the record format: removing it would break verification of
records already issued. New records can opt into v2; a verifier must honour `commitment_alg` from
the *signed* grant, never from the receipt alone — the grant is what the approver signed.

## Test vectors (for an independent verifier)

Input intent (canonical core, after normalisation):

```json
{"actor":{"agent":"agent@example","session":"s1"},
 "effect":{"amount":{"currency":"BAM","value":1170.0},"kind":"payment.send",
           "params":{"ref":"faktura-77"},"revert":"irreversible",
           "target":"Example Supplier"},
 "nonce":"n-1","requested_by":"approver","v":1}
```

| check | value |
|---|---|
| `sha256(jcs(core))` (v1) | `sha256:a8cb346e55c5f1a4ccac3f9eee610e1aa3e674129515e0c580b720e9c6c804bf` |
| v2, salt `00…00` (16 B) | `sha256:aa02112be1fdc9fbefa7ed2803c912c305c8637b15ac548ea15bf22c04def547` |
| v2, salt `11…11` (16 B) | `sha256:55076bbddd9c7b4a7c9d8494e0c4e94d1d690849ff3c80b8675d0c17456c5258` |
| render hash | `e26b7052ee91994c4c7e53bdf8402be1abc4cc1343cd9f7c33828904f0f4c2eb` |

(The `revert` field appears because normalisation adds it; a verifier must normalise the same way,
which is why the canonicalisation and the normalisation rules are part of `spec/MANDATE-1.md`.)

## Costs and limits

- The salt is not a secret kept by anyone; it is *inside the signed grant*. Its job is to raise the
  cost of guessing, not to be hidden from the verifier.
- A leaked salt lets an attacker test guesses for **that one** record; it does not weaken any other.
- Salt does not fix a weak nonce. If an integrator reuses a nonce across intents, that is a
  separate defect and `mandate` refuses reuse through the ledger.
- v2 does not make the commitment post-quantum. A future scheme will need its own `commitment_alg`
  string, and that is exactly why the algorithm is a named field rather than an assumption.
