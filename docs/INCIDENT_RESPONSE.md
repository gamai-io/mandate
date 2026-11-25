# Incident response runbook

What to do when `mandate detect` raises an alert, or when someone reports an
agent doing something it should not. Written for an on-call engineer who has this
repository and the ledger, nothing else.

## 0. First 5 minutes

1. **Stop accepting new effects** (does not stop the process):
   ```bash
   mandate halt --reason "incident <id>: investigating" --actor oncall --ledger ledger.jsonl
   ```
   Any new `redeem` now exits 4 with `code=halted`. In-flight work is not killed.
2. **Stop the agent itself** if it is still acting:
   ```bash
   mandate warden --cgroup /sys/fs/cgroup/mandate/<agent> --reason "incident <id>" \
     --actor oncall --key <ops-key> --signer ops --ledger ledger.jsonl
   ```
   Or `--pgid <pgid> --method freeze`, or `--method kill` for the hard stop.
   The record contains pids, states and `time_to_halt_ms`.
3. **Preserve evidence before touching anything else**:
   ```bash
   mandate pack --ledger ledger.jsonl --out /evidence/<incident-id> \
     --signers trust/allowed_signers --anchors anchors --key <ops-key> --signer ops
   ```
   The pack contains the ledger, anchors and per-file hashes. Copy it off the host.

## 1. Classify

| Alert rule | Meaning | First question |
|---|---|---|
| `human_credential` | the acting identity is a human principal | did a person run the agent under their own account? |
| `sod_ledger` | approver == agent in a receipt | was the four-eyes rule bypassed, or is it an old record? |
| `velocity` | effects above the ceiling for that agent | legitimate batch, or a loop? |
| `amount` | single effect above the ceiling | wrong parameter, or a compromised input? |
| `off_hours` | effect outside the business window | scheduled job, or an unauthorised actor? |
| `scope_unknown` | effect kind never granted to that token | stale token, or a widened scope? |

Record the classification in the incident ticket; it drives notification duties.

## 2. Contain

- Network: `mandate warden --quarantine --uid <agent-uid>` (nftables drop for that
  uid), and remove the explicit allowlist entry from the egress policy.
- Credentials: revoke the approver key in `trust/revoked_signers`; stop issuing
  SVIDs for the affected agent; rotate the broker's effect credentials (they were
  never in the agent, but rotate anyway if the broker host is suspect).
- Tokens: they expire within one hour by design; do not wait for that — revoke.

## 3. Establish what actually happened

```bash
mandate chain --ledger ledger.jsonl --signers trust/allowed_signers
mandate detect --ledger ledger.jsonl --policy mandate/policy.json
mandate inventory --ledger ledger.jsonl --csv /evidence/<id>/inventory.csv
```

Answer three questions before closing:

1. Which effects were **authorised** (grant + receipt) and which were only
   **claimed** (no receipt)?
2. Did any effect reach the target system without a receipt? (Compare with the
   target's own logs — this is the one check the ledger cannot do alone.)
3. Was the approver key used by the approver? (Check signer name, timestamp,
   and whether the key was on the expected device.)

## 4. Notify

| Trigger | Who | Deadline |
|---|---|---|
| Personal data affected | DPO | immediately, per the bank's GDPR process |
| Material ICT incident (DORA) | regulator via the bank's incident process | initial notification within the bank's DORA timeline |
| Customer-visible outage | account owner | within the bank's SLA |
| Key compromise | security team + approver | immediately |

We supply the pack and the timeline; the notification itself is the bank's act.

## 5. Recover

```bash
mandate resume --reason "incident <id> closed: <cause>" --actor oncall --ledger ledger.jsonl
```
Resume does **not** reset budgets — that is deliberate. If the budget must change,
do it as a recorded change:
```bash
mandate change record --ledger ledger.jsonl --file mandate/policy.json \
  --approver <name> --key <key> --reason "post-incident limit change for <id>"
```

Verify the restored environment before re-enabling:
1. `mandate chain` valid; 2. `anchor-verify` with the TSA CA; 3. one dry-run effect
through the broker; 4. the agent's cgroup no longer contains the stopped pids.

## 6. Post-mortem (within 5 business days)

- Timeline from ledger timestamps (they are the record; do not reconstruct from
  memory).
- Root cause: input, credential, policy, or implementation.
- Which detection rule fired, and how long after the first bad effect.
- One change with an owner and a date. If the answer is "add a rule", the rule
  goes in `detect.py` with a test that reproduces the incident.

## Contacts and artefacts

- Ledger, anchors, packs: `/var/lib/mandate/` (deployment-specific).
- Verifier: `mandate chain`, `mandate anchor-verify`, `mandate detect`.
- This repository at the tag of the deployed version (`git tag --list 'v*'`).
- No vendor access is required for any step above; that is the point.
