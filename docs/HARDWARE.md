# Hardware-rooted signing — what is verified, and what is not

Two different questions often get the same answer, and they should not:

1. **Was the approval signed by a key that lives in hardware** (a FIDO2 security key, a
   TPM-backed key)? — key type, checked by the gate.
2. **Which device, unlocked by which human, with which user verification?** — that is a
   WebAuthn assertion, verified by `mandate/webauthn.py`.

## 1. Requiring a hardware key at approval

```json
{"effects": {"payment.send": {"require_hardware_key": true}}}
```

With that in the policy, `redeem` reads the key type of the key that **actually produced
the grant signature** — not the first line in the signers file — and refuses a software
key with `HardwareKeyRequired`. The refusal is written to the ledger as a control entry, so
"we required hardware and it was refused" is evidence, not a claim.

```bash
mandate --signers signers hardware list
# {"ok": true, "signers": [{"name": "soft", "keytype": "ssh-ed25519", "hardware": false},
#                          {"name": "hard", "keytype": "sk-ssh-ed25519@openssh.com", "hardware": true}],
#  "hardware": 1, "software": 1}

mandate --signers signers hardware check --name approver --signature grant.sig
# {"ok": true, "signer": "approver", "signing_keytype": "ssh-ed25519", "hardware": false}
```

Exit code is 0 only when the signing key is hardware-backed.

### Making a hardware key

```bash
ssh-keygen -t ed25519-sk -O resident -O verify-required   # FIDO2 security key or TPM-backed
```

`ed25519-sk` keys are what `is_hardware_key()` recognises (`sk-…`). A TPM that is not
exposed through OpenSSH needs the external-signer path instead: `redeem --signer-cmd` runs a
command on the host that holds the key, and the key never enters this process
(`mandate/signing.py`).

## 2. Per-approval WebAuthn (device, human, user verification)

`mandate/webauthn.py` verifies an assertion with the standard library: `ES256` (P-256) and
`EdDSA` (Ed25519), `clientDataJSON.type/challenge/origin`, `rpIdHash`, the signature over
`authData || sha256(clientDataJSON)`, and a non-decreasing signature counter (a cloned
authenticator signal).

It accepts attestation `none` only. That means:

| verified | not verified |
|---|---|
| the signature, challenge, origin and relying-party id | **which vendor made the key** (no attestation chain) |
| the user-verification flag was set | that the human was not coerced |
| the counter never goes backwards | backup eligibility of the passkey |

So: "a passkey on this device approved this challenge" is proven. "This is a YubiKey
manufactured on date X" is not, and we do not claim it.

## What hardware does not fix

- A hardware key signs **what is on screen**. If the rendered text is wrong, the signature
  is still valid — that is why `render_hash` exists and why the approval page shows the
  rendered effect, not the raw JSON.
- A stolen unlocked security key is a stolen key. The counter and user verification narrow
  that window; they do not close it.
- The signers file is trusted configuration: whoever edits it decides which keys count. Its
  own integrity is a deployment question (and `configwatch` watches it).
