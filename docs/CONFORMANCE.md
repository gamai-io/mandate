# Conformance — run the kit against *your* verifier

An auditor should not have to trust our verifier. `spec/kit/` contains eight records with
known outcomes; `tools/kit.py` runs them through any command that prints one JSON object:

```bash
python3 tools/kit.py --verifier "mandate --signers {signers} audit verify \
  --bundle {bundle} --log-signers {log_signers} --witness-signers {witness_signers}"
```

```
ok   valid                 valid=True
ok   tampered_receipt      valid=False
ok   tampered_signature    valid=False
ok   unknown_signer        valid=False
ok   sth_bad_signature     valid=False
ok   proof_tampered        valid=False
ok   witness_claim_only    valid=False
ok   witness_note_forged   valid=False

8/8 cases correct
```

## Why four "must fail" cases matter

A verifier that returns `{"valid": true}` for everything scores 5/8 — not 8/8. The kit also
checks **why** a case fails: for `proof_tampered` it expects the first failing check to be
`inclusion`, not `signature`. That is what separates "this bundle is broken" from "this
verifier is checking the wrong thing".

## Badge

```bash
python3 tools/kit.py --verifier "<cmd>" --badge conformance.json --name "Ours"
# ![mandate conformance](https://img.shields.io/badge/mandate%20conformance-8%2F8-brightgreen)
```

`conformance.json` is a record, not a sticker:

```json
{"format": "mandate-conformance/1", "verifier": "Ours",
 "passed": 8, "failed": 0, "total": 8, "ok": true,
 "checked_at": 1795805000, "cases": [{"case": "valid", "ok": true}, "..."]}
```

Publish it next to the badge. A badge without the record is a claim; with the record it is
reproducible.

## Certified verifiers

| verifier | kit | record |
|---|---|---|
| `mandate` reference (`audit verify`) | **8/8** | reproducible: run the command above |
| *yours* | — | send the `conformance.json` + the command; it goes in this table |

We do not certify verifiers we did not run. To be listed, the record must be produced by a
command a third party can run against `spec/kit/` unchanged.

## What the kit does and does not prove

- **Does**: the verifier rejects a tampered receipt, a swapped inclusion proof, an unknown
  signer, a forged witness note, and a claim without a signature — and accepts the honest
  record.
- **Does not**: prove the verifier checks *everything your threat model needs*. Add your own
  cases: the format is a JSON manifest of bundles plus expected outcomes, and the tool does
  not care where they came from.

## Adding a case

1. Put the bundle under `spec/kit/` (or anywhere the manifest points to).
2. Add an entry to `spec/kit/cases.json`:
   `{"name": "...", "bundle": "...", "valid": false, "fails": "inclusion"}`.
3. Run the kit. A new case that your verifier fails is either a bug in the verifier or a
   missing check — both worth knowing before an auditor finds them.
