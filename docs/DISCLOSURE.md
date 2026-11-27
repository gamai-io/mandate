# Selective disclosure — hide the supplier, keep the proof

An auditor needs "a payment of 1170 BAM was approved and executed", not the supplier's
name. `mandate disclose` produces a **redacted view** of a receipt in which hidden fields
are replaced by salted commitments:

```bash
mandate disclose redact --receipt receipt.json \
  --fields render.fields.target,render.fields.amount \
  --expect-hash <sha256 of jcs(receipt body)> \
  --key approver --signer approver -o view.json
```

```json
{"ok": true, "redacted": ["render.fields.target", "render.fields.amount"],
 "receipt_hash": "556c96cb…", "signed": true}
```

Anybody can check the structure without any secret:

```bash
mandate disclose verify --view view.json --signers signers
# {"ok": true, "redacted": [...], "receipt_hash": "556c96cb…", "view_signature": true}
```

and a value can be revealed later — it must hash back to the original record:

```bash
mandate disclose reveal --view view.json \
  --fields render.fields.target,render.fields.amount --values vals.json
# {"receipt": {...}, "hash": "556c96cb…", "ok": true}      # hash == receipt_hash
```

A wrong value is refused with `E_COMMITMENT`, not silently accepted.

## What the commitments are

`sha256("salt:" || salt || ":" || jcs(value))` — canonical JSON from RFC 8785, so a
verifier in another language computes the same bytes. The 16-byte salt keeps a dictionary
attack on a supplier name from working; it travels with the disclosure entry, never with
the redacted record.

## What this proves — and what it does not

| proves | does not prove |
|---|---|
| the view is a redaction of **that** receipt (`receipt_hash` matches `sha256(jcs(body))`) | that the original signer approved the **redacted form** — they signed the values |
| every hidden field has a commitment, and each redaction path is filled with it | that the discloser hid nothing else (they choose the paths) |
| a revealed value is the one that was committed | that a value is true — only that it is what the record said |

Because the original signature covers the values, a redacted view is **not** covered by it.
Whoever produces the view signs it (`--key`, namespace `mandate-disclosure`, policy code
`E_DISCLOSURE` on malformed input), so a reader sees *who* chose what to hide. Present a
redacted view as "this is what we disclose of receipt X, signed by us", never as "this is
what the approver signed".

The right way to get signer-level privacy is to commit at creation time (`coverage` +
hashed fields in the receipt); that is a change to the receipt schema, not to this tool,
and it is not claimed here.

## Failure codes

| code | meaning |
|---|---|
| `E_PATH` | the field path does not exist in the record |
| `E_HASH` | the record does not hash to `--expect-hash` / the reveal does not restore it |
| `E_COMMITMENT` | the value does not match its commitment, or a redaction lost its hash |
| `E_NODISCLOSURE` | no disclosure entry for the requested path |
| `E_SALT` | the salt is not base64 |
