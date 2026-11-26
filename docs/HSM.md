# HSM / PKCS#11 signer

The private key never has to enter the Mandate process. `--signer-cmd` runs an
adapter that receives the canonical payload on stdin and prints
`{"sig": "<SSHSIG armor>", "signer": "<name>"}`.

`tools/mandate-pkcs11-sign.py` is that adapter for a PKCS#11 token:

```bash
export MANDATE_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so
export MANDATE_PKCS11_TOKEN=mandate
export MANDATE_PKCS11_PIN=1234
export MANDATE_PKCS11_KEY=approver
export MANDATE_SIGNER=approver

mandate redeem --intent intent.json --grant grant.json --ledger ledger.jsonl \
  --audience local-broker --signer-cmd "python3 tools/mandate-pkcs11-sign.py"
```

The token's public key must be in `allowed_signers`:

```
approver namespaces="mandate" ssh-ed25519 <base64 of the token public key>
```

## What is proven, and where

`tests/test_pkcs11.py` creates a **SoftHSM2** token, generates an Ed25519 key that
cannot be exported, signs through the adapter and verifies with `ssh-keygen -Y
verify`. That proves the protocol and the adapter; it is **not** a vendor HSM
test. A bank's HSM exposes the same PKCS#11 API and usually adds PIN policies,
audit logs and FIPS validation that this repository cannot exercise.

Notes:

- Ed25519 (`EC_EDWARDS`) is the supported key type. ECDSA tokens are not wired yet.
- The adapter reads `CKA_EC_POINT`, strips the DER OCTET STRING and builds the
  SSH public key blob itself; no private material leaves the token.
- SoftHSM2 is a development token: the file-backed store is only as protected as
  the directory it lives in.
