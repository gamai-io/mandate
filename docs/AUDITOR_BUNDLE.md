# Auditor bundle

An auditor bundle is one portable JSON that *records* a single business action,
and one signature that binds those records together:

- the exact **intent** and the human-signed **grant**,
- the hash-chained **receipt**,
- a Merkle **inclusion proof**,
- the signed tree head (**STH**),
- the **witness state** that *claims* the STH was pinned on another host (a
  claim, see the honest limit below).

The bundle is signed by the approver (OpenSSH SSHSIG, namespace
`mandate-export`). Verification checks the envelope signature, the receipt/grant
binding, the STH signature, the inclusion proof against the STH root/size, and
that the witness state matches the STH.

## Build

```bash
mandate audit bundle \
  --receipt receipt.json --intent intent.json --grant grant.json \
  --proof proof.json --sth sth.json --witness-state witness.json \
  --key ~/.ssh/mandate --signer approver --out bundle.json
```

## Verify (offline, any host)

```bash
mandate --signers trust/allowed_signers audit verify \
  --bundle bundle.json --log-signers trust/log_signers
```

`--signers` must contain the approver key with
`namespaces="mandate,mandate-export"` (the grant is `mandate`, the bundle
envelope is `mandate-export`); `--log-signers` must contain the log key
(`namespaces="mandate-log"`).

Output: `{valid, envelope, sth, inclusion, witness, decision, executed, observed}`
— `valid` is true only if the envelope, STH, inclusion and witness checks pass.

**Witness note (2026-11-27).** When the witness host accepts an STH with `--key`, it
stores a **note it signed** with its own Ed25519 key (SSHSIG, namespace
`mandate-witness`):

```bash
mandate witness accept --state witness.json --sth sth.json \
    --signers trust/log_signers --key ~/.ssh/witness --signer witness1

mandate --signers trust/allowed_signers audit verify --bundle bundle.json \
    --log-signers trust/log_signers --witness-signers trust/witness_signers
```

The note is short canonical text (`log`, `log_id`, `tree_size`, `root_hash`,
`pinned_at`). Verification checks the signature against the witness signers file **and**
that every field matches the STH in the bundle, so a bundle builder can no longer
fabricate a pin: it does not hold the witness key.

If `--witness-signers` is not supplied — or the bundle only carries `witness_state` —
`witness` still means "the state file matches the STH", which is a claim, not a proof.
`audit verify` reports `witness_signed: true|false` so the difference is visible in the
output rather than only in this document.

## Cross-host flow

1. On the log host: `mandate log head`, `mandate log proof`, and `mandate export`.
2. On the witness host: `mandate witness accept --state witness.json --sth sth.json`.
3. Copy `witness.json` to the log host and build the bundle.
4. An auditor verifies the bundle offline with the two signer files above.

No network, database or host access is required at verification time.

## Verified on a second host (2026-11-09)

A real two-host pin was performed on two independent machines (host A, host B):

- host A produced the keys, intent, grant, receipt and signed STH
  (`tree_size=1`, example `root_hash=266f308b...`);
- only the public `signers` file and `sth.json` were transferred to a second
  host (host B);
- on host B, `mandate --signers signers witness accept --state witness.json --sth
  sth.json` returned `ok=true, first=true` (first pin);
- the witness state was copied back and
  `mandate --signers signers audit verify --bundle bundle.json --log-signers
  signers` returned `valid=true, witness=true`.

This shows the witness host needs only public keys and the STH, and the bundle
can be pinned and verified across machines.

The same pin was repeated on two further hosts on 2026-11-09; both
witness states produced `valid=true, witness=true`. Three independent hosts
(vast, host D, host C) now hold the same `root_hash` and `tree_size`.

## Strict parsing (2026-11-27)

A bundle is only as good as the parser that reads it. `{"a": 1, "a": 2}` parses to
`{"a": 2}` in Python, JavaScript and Go, so a signer and an auditor can disagree about
what was signed while both report success. Both verifiers therefore refuse, before any
hash is computed:

| Rejected | Error code |
|---|---|
| a key twice in one object | `duplicate_key` |
| `NaN`, `Infinity`, `-Infinity` | `non_finite` |
| an integer outside ±2^53−1, or a token longer than 16 digits | `int_range` |
| a string with a lone UTF-16 surrogate | `lone_surrogate` |
| nesting deeper than 128 | `depth` |
| bytes that are not UTF-8 | `invalid_utf8` |

`mandate/strictjson.py` is the package implementation; `spec/verify_offline.py` carries
its own copy because that script must run standalone (`tests/test_offline_verifier.py`
enforces it), and `spec/verify_offline.js` implements the same rules for Node. A
differential test feeds each rejected document to both verifiers and requires the same
error code from each.

The idea and the rule list follow Tracekit's `format.canon.loads_strict` (MIT); the
implementation here is ours.

## Conformance kit (2026-11-27)

An auditor who writes their own verifier should not have to take ours on trust. The kit runs
a fixed set of bundles through **any** verifier command and reports whether each verdict,
and the first failing check, is right:

```bash
python3 tools/kit.py --verifier "python3 -m mandate --signers {signers} audit verify \
    --bundle {bundle} --log-signers {log_signers}"
```

```
ok   valid                valid=True
ok   tampered_receipt     valid=False
ok   tampered_signature   valid=False
ok   unknown_signer       valid=False
ok   sth_bad_signature    valid=False
ok   proof_tampered       valid=False
ok   witness_mismatch     valid=False

7/7 cases correct
```

`{bundle}`, `{signers}` and `{log_signers}` are substituted. The verifier prints one JSON
object; `valid` is required, and `envelope.signature`, `envelope.receipt`,
`envelope.inclusion`, `sth`, `inclusion`, `witness` are used to name the first failure.
`--json` gives the same report machine-readable; exit 0 means every case is correct.

The cases live in `spec/kit/` and are rebuilt with `python3 tools/kit_build.py` (fresh
keys per build). Three of them tamper **and then sign again** with the approver key:
that is what isolates the `sth`, `inclusion` and `witness` checks, because otherwise the
envelope signature fails first and the check under test is never reached.
