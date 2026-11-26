# Runbook — first action for each alert

Written for the person on call at 03:00. Every entry answers four things: what the
alert means, what to check first, what to do, and what to keep as evidence. If a
step says "stop and escalate", stop — do not improvise on a production gate.

Two sources produce alerts:

- `gama-mandate` writes `control` records into the ledger (`refuse`, `alert`,
  `config_check`, `config_lock`, `containment`, `approval`).
- `gamai-tripwire` writes `control/alert` for inbound behaviour.

Read the ledger with `mandate log --ledger L` or `grep '"action":"refuse"'`.

---

## 1. `PolicyDenied` — the broker refused an effect

**Means:** the effect did not run. The reason is in the record (`code` and
`message`): unknown effect kind, missing provenance, policy deny, first-time payee,
tool schema drift, unsigned instruction, egress denied.

**First:** `mandate log --ledger L | grep refuse | tail -5`

**Do:**
- `first-time payee` → confirm with the business that the supplier is real, then
  either pay once under a smaller amount with a second approver, or raise the payee
  into history by an approved payment.
- `tool schema drift` → `mandate tool verify --intent I --registry tools.json`;
  if the tool changed on purpose, re-lock it: `mandate tool lock ...`.
- `instruction ... revoked/expired` → the agent is citing a stale belief. Ask the
  approver to issue a new instruction (`mandate memory add`), never to edit the
  store by hand.
- `egress denied` → the destination is not on the allowlist. Check who added it and
  why; do not widen the allowlist without a policy diff.

**Evidence:** the `refuse` record itself (code, kind, target, nonce, approver).

---

## 2. Instruction expired or revoked mid-workflow

**Means:** an effect cites a signed instruction that is no longer valid.

**First:** `mandate memory list --store instructions.jsonl | grep <id>`

**Do:** the business owner decides. A new instruction is `mandate memory add` with
the same scope and a new expiry; a revocation is `mandate memory revoke --approver
... --key ...`. Never re-append an old record — the store's chain will break and
`check_provenance` will refuse the whole store.

**Evidence:** the old and new instruction records, both signed.

---

## 3. Tool schema drift

**Means:** the tool the agent wanted to use is not the one that was approved.

**First:** `mandate tool verify --intent I --registry tools.json` (exit 1 = drift).

**Do:** treat it as an incident until proven otherwise: compare the schema diff,
find who changed the file, and check whether the agent's last successful calls were
made with the changed version. Re-lock only after the change is understood.

**Evidence:** registry entry (hash), current file, and the refusal record.

---

## 4. Config drift — `config_check` says `ok: false`

**Means:** a file the agent trusts (`.mcp.json`, `settings.json`, `CLAUDE.md`,
`AGENTS.md`, a skill) changed since it was pinned. This is the Shai-Hulud shape.

**First:** `mandate config check --store configs.json --ledger L` and read `drift`
and `missing` (paths only).

**Do:** diff the file against the last known content (version control if the file is
in git, otherwise a copy from the pack). If the change was not made by a person,
contain first: `mandate contain --pid <agent> --minutes 15`. Re-lock only after the
diff is understood.

**Evidence:** `config_check` record with the drift list, plus the new hash after
re-locking.

---

## 5. Containment expired and the process was released

**Means:** the deadline passed. `sweep` resumed the process and recorded
`action: release` with `reason: deadline passed`.

**First:** check whether a human extended it (`action: extend`, signed) or not.

**Do:** if the incident is unresolved, contain again with a fresh window and a named
owner. Do not re-extend silently: an unsigned extend is ignored by design.

**Evidence:** contain → (extend) → release chain for that pid.

---

## 6. Ledger head mismatch

**Means:** `mandate chain` exits non-zero. Three different things produce it and the
tool now says which:

| message | meaning |
|---|---|
`truncated: N entries but head says ...` | records were removed from the end |
`head does not match the last entry` | the `.head` file was changed |
`entry N hash mismatch` | an entry's body was edited |

**First:** stop appends. `mandate chain --ledger L` prints the diagnosis.

**Do:** restore from the last backup (`mandate restore --in backup.tar.gz --out
restored`) and compare `verify_chain` on both. Never delete the suspicious file —
copy it aside and escalate. If the head was edited from a different host, treat it
as a compromise of the ledger, not a bug.

**Evidence:** the original file, the backup, both chain outputs.

---

## 7. Nonce authority unreachable

**Means:** `nonce store unavailable` — the shared authority did not answer. The
broker fails **closed**: the effect did not run.

**First:** `curl -s http://<authority>/health`. Then check which deployments point
at it (`MANDATE_NONCE_URL`).

**Do:** restore the authority first. Do not switch a deployment to the local SQLite
store to "unblock" the payment: that is how a nonce gets spent twice.

**Evidence:** the refusal records with `NonceUnavailable`, and the authority's
health timeline.

---

## 8. Egress denied

**Means:** an adapter tried to reach a destination outside the allowlist.

**First:** the refusal record contains host and code (`not_allowlisted`,
`private_destination`, `metadata_endpoint`).

**Do:** `metadata_endpoint` and `private_destination` are incident-grade: something
is trying to reach the cloud metadata service or an internal address. Contain the
agent first (`mandate contain`), then investigate the intent that requested it. A
plain `not_allowlisted` is usually a configuration gap — fix it through a policy
diff, not an inline edit.

**Evidence:** `egress denied` record, the egress policy in force, and the intent.

---

## 9. Records were not shipped to the SIEM

**Means:** `mandate ship` exits 4 (`SIEM rejected batch`), or the state file has no
entry for this ledger. The offset only advances when the SIEM accepted the batch,
so a failure is repeated, not lost.

**First:** `mandate ship --ledger L --url ... --dry-run` prints how many records are
pending: `{"records": N, "sent": N, "dry_run": true}`.

**Do:** check the SIEM token and reachability. If the ledger was rotated, the next
run reports `"rotated": true` and starts from the top of the new file — that is
expected, not a duplicate. Never delete the `.shipstate` file to "restart": it would
re-send history.

**Evidence:** the ship result JSON per run, and the SIEM's own ingest timestamps.

## Tripwire: inbound behaviour

| alert | first action |
|---|---|
`critical` (canary used) | a planted key was sent. Suspend that key, read the request path, then check whether the document containing it is still served |
`high` | read the findings; if `auth_failure_streak` or `key_probing` is present, treat as an active attempt and add the address to the deny list with a TTL |
`medium` | look at the rules; `ua_flip` + `velocity` is often a scanner. Deny only if identity evidence is also present (the tool refuses otherwise) |
`path_anomaly` | a path is being walked from many addresses. Check the endpoint's owner before blocking anything: this is deliberately not an address-level alarm |

An exception for a scanner is `{"ip": "...", "until": <epoch>, "approver": "...",
"reason": "..."}` in the exceptions file. Without `until` and `approver` it is
ignored — a permanent, unattributable whitelist is how a control rots.

---

## Escalation

- Effect refused, business impact **now** → incident commander + DPO if personal
  data is involved; DORA Art. 19 clock starts at classification.
- Ledger integrity or key compromise → CISO immediately; the evidence pack is the
  first artefact they will ask for.
- Anything you cannot classify in 15 minutes → escalate, keep the artefacts, do not
  retry the effect.
