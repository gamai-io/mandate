# Quickstart — 30 minutes, one real record

Everything below was run on 2026-11-27 with `mandate 0.68.13`; the outputs are copied
from that run, not written by hand. If a step prints something different, that is a bug —
open an issue with the command and the output.

You need: Python 3.9+, `ssh-keygen` (present on macOS/Linux/Git Bash on Windows), and a
directory you can write to.

---

## 1. Install (1 min)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install gama-mandate
mandate version
```

## 2. Keys (1 min)

Mandate deliberately uses the keys you already have — SSH Ed25519 — so an auditor needs no
new library and no new key format.

```bash
ssh-keygen -q -t ed25519 -N '' -f approver      # the human who approves
ssh-keygen -q -t ed25519 -N '' -f logkey        # the log that seals the ledger
printf 'approver namespaces="mandate,mandate-export" %s\nlog1 namespaces="mandate-log" %s\n' \
  "$(cat approver.pub)" "$(cat logkey.pub)" > signers
```

`signers` is the allow-list. A signature from a key that is not in it verifies nowhere.

## 3. The intent — what the agent wants to do (2 min)

```json
{"v":1,"actor":{"agent":"agent@example","session":"s1"},
 "effect":{"kind":"payment.send","target":"Example Supplier",
           "amount":{"value":1170.0,"currency":"BAM"},"params":{"ref":"faktura-77"}},
 "requested_by":"approver","nonce":"qs-2",
 "provenance":[{"type":"data_ref","source":"erp:vendor:1","trust":"trusted",
                "covers":["target","amount"]}]}
```

`provenance` says where the fields came from and how much you trust that source. Drop
`trust` and the field becomes `unknown`, which a strict policy treats as untrusted.

## 4. Check → propose → approve (2 min)

```bash
mandate check   --intent intent.json
mandate --signers signers propose --intent intent.json --out proposal.json
mandate --signers signers grant \
  --proposal proposal.json --approver approver --key approver --ttl 900 --out grant.json
```

`check` decides **ask / allow / deny** before anything is signed. `grant` is the human
signature over the commitment — not over a copy of the intent, so the intent cannot be
edited afterwards.

## 5. Execute once (1 min)

```bash
mandate --signers signers redeem \
  --intent intent.json --grant grant.json --ledger ledger.jsonl
```

Prints the receipt. Useful fields, in order of what an auditor asks:

| field | meaning |
|---|---|
| `commitment` | the intent the approver signed |
| `render_hash` | what the human saw |
| `decision` | `executed` / `observe` |
| `coverage` | **how** it was captured: `enforced`, `observed`, `self_reported` |
| `taint` | which fields rested on untrusted input |
| `policy_digest` | the policy that was in force |

Run it a second time — the grant is one-shot:

```
{"error": "GrantReplayed", "message": "grant already used"}
```

## 6. Check the log and look for trouble (1 min)

```bash
mandate chain  --ledger ledger.jsonl      # {"valid": true, "entries": 1}
mandate detect --ledger ledger.jsonl      # {"ok": true, "findings": []}
```

## 7. Bundle, replay, and export (3 min)

```bash
mandate audit bundle --receipt receipt.json --intent intent.json --grant grant.json \
  --key approver --signer approver --out bundle.json

mandate replay --bundle bundle.json
# ok true, every check true: commitment, render_hash, result_hash, taint,
# policy_digest, decision

mandate dsse sign --receipt receipt.json --key approver --signer approver -o env.json
mandate dsse verify --file env.json          # {"ok": true, "keyid": "approver"}
```

`replay` is the interesting one: feed it a policy that now refuses the record and it says
so instead of silently trusting the signature.

```bash
mandate replay --bundle bundle.json --policy tighter-policy.json
# ok false, code E_POLICY_DRIFT
```

## 8. Prove your verifier is honest (2 min)

```bash
python3 tools/kit.py --verifier "<your verifier with {bundle} {signers} {log_signers} {witness_signers}>"
```

Eight cases, four of which **must fail** — a verifier that always says "valid" scores 4/8
at best. See [`CONFORMANCE.md`](CONFORMANCE.md).

---

## What this quickstart does not give you

- **A production policy.** `mandate/data/policy.json` is an example. Your effect kinds and
  limits are your risk decision, not ours.
- **A witness host.** A note signed on the same machine as the log proves less; run
  `mandate witness` somewhere else and require a quorum.
- **A promise that the agent is safe.** Mandate records and refuses; it does not make a
  model honest.
