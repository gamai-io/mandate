# Mandate

[![tests](https://github.com/gamai-io/mandate/actions/workflows/test.yml/badge.svg)](https://github.com/gamai-io/mandate/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Signed, verifiable business commitments for AI agents.**

Most agent safety tools answer *"is this tool allowed?"*. Mandate answers the
question that actually matters: **"who ordered this exact payment, to this
supplier, for this amount?"** A tool permission is not a business mandate.

Every consequential effect becomes a canonical **Commitment** object. An agent
signs the intent; a human co-signs a **Grant** with an Ed25519 key; execution
produces a hash-chained **Receipt**. Anyone can verify the whole chain offline.

> Approval workflows are ephemeral events. A Mandate is a durable, portable,
> cryptographically bound artifact — a commit, not a log line.

```bash
mandate demo        # propose -> grant -> redeem -> replay refused -> changed amount refused
                    # -> verify offline -> audit pack, on a throwaway directory
```

`mandate demo` runs the real path, not a mock: a generated Ed25519 key signs a real
grant, `redeem` executes it, a replay is refused, a changed amount is refused with
`CommitmentMismatch`, the receipt verifies, and an audit pack is written.

## One thing

Mandate does one thing: a named human signs a specific business effect, the effect
can happen **once**, and the receipt verifies offline years later. Everything else
in this repository — broker, warden, egress, detection, MCP, bench — exists to
serve that same hash chain. If a feature does not produce or protect a receipt, it
is not the product; it is an add-on, and the docs say which is which.


## Why it is not another approval gate

| Approval gate | Mandate |
|---|---|
| Asks "may this tool run?" | Asks "is this exact effect authorised?" |
| Identity is a self-asserted field | Approver proves possession of an off-host key |
| Approval is a mutable DB row | Grant + receipt are signed, content-addressed |
| Logs what happened | Lets anyone prove what was authorised |

## Install

```bash
python3 -m pip install gama-mandate     # CLI + broker + MCP adapter
mandate doctor                          # checks python, ssh-keygen, policy
```

From source: `python3 -m pip install "git+https://github.com/gamai-io/mandate.git"`.
Python >= 3.9. No web UI and no server to run: Mandate is a local trust primitive.

## Quickstart (60 seconds)

Run it in an empty directory. Nothing below needs a network, database or cluster.

```bash
mandate init --dir .                    # policy.json, allowed_signers, config, example intent

ssh-keygen -q -t ed25519 -f ./approver_key -C mandate -N ""
printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)" >> trust/allowed_signers

mandate propose --intent examples/intent.json --out proposal.json
mandate grant  --proposal proposal.json --approver approver \
               --key ./approver_key --audience local-broker --out grant.json
mandate redeem --intent examples/intent.json --grant grant.json --ledger ledger.jsonl > receipt.json
mandate verify --receipt receipt.json --intent examples/intent.json --grant grant.json
```

Expected: `{"valid": true}`. Repeat the `redeem` line and it fails with
`GrantReplayed` — the grant is one-shot, by construction.

| step | what it proves |
|---|---|
| `propose` | the effect is a canonical commitment (`commitment`), not a free-text request |
| `grant` | a human signed *that exact* commitment with an Ed25519 key that never touches the agent host |
| `redeem` | the grant was used once; the receipt is appended to a hash-chained ledger |
| `verify` | anyone can check receipt + intent + grant offline, without trusting the broker |

## Three runnable examples

| # | file | shows |
|---|---|---|
| 1 | [`examples/01-invoice-approval.sh`](examples/01-invoice-approval.sh) | full payment approval + replay rejection |
| 2 | [`examples/02-audit-bundle.sh`](examples/02-audit-bundle.sh) | portable audit bundle an auditor can verify offline |
| 3 | [`examples/03-mcp-claude.md`](examples/03-mcp-claude.md) | lock and proxy an MCP server for Claude Code / Codex / Cursor |
| 4 | [`examples/04-full-stack.sh`](examples/04-full-stack.sh) | all five packages on one payment: guard → policy → grant → claim check → seal |
| 5 | [`examples/05-bank-scenario.sh`](examples/05-bank-scenario.sh) | budget, kill switch and four-eyes: the controls banks started enforcing in Nov 2026 |
| 6 | [`examples/06-anchor-and-worm.sh`](examples/06-anchor-and-worm.sh) | RFC 3161 anchor, read-only evidence pack, tamper test |
| 7 | [`examples/07-warden.sh`](examples/07-warden.sh) | external freeze with verified time-to-halt, resume, hard stop — all in the ledger |
| 8 | [`examples/08-egress.sh`](examples/08-egress.sh) | deny-all egress proxy: allowlist, token, metadata guard, every decision in the ledger |
| 9 | [`examples/09-identity.sh`](examples/09-identity.sh) | short-lived agent tokens and delegation that can only narrow |
| 10 | [`examples/10-warden-cgroup.sh`](examples/10-warden-cgroup.sh) | cgroup freeze observed by the kernel, signed stop, uid network quarantine |
| 11 | [`examples/11-vm-pause-remote.sh`](examples/11-vm-pause-remote.sh) | find a KVM host in the fleet, boot a microVM, pause it, prove the guest stopped |
| 12 | [`examples/12-detect.sh`](examples/12-detect.sh) | runtime detection: human identity used by an agent, velocity spike, alert in the chain |
| 13 | [`examples/13-audit-pack.sh`](examples/13-audit-pack.sh) | agent inventory, signed change records, DORA-style evidence pack |

```bash
./examples/01-invoice-approval.sh ./demo1
```

Each script is self-contained: init, keys, propose, grant, redeem, verify.

## Use it from an agent

`mandate mcp proxy` sits between the agent and any MCP server. The tool list the
agent sees is unchanged; what changes is that mutating calls need a grant and
every call leaves a receipt. See [`examples/03-mcp-claude.md`](examples/03-mcp-claude.md).

## Operations documents

- [`docs/REFERENCE_ARCHITECTURE.md`](docs/REFERENCE_ARCHITECTURE.md) — topologies, integrations, failure modes, ports
- [`docs/PROCUREMENT_ANSWERS.md`](docs/PROCUREMENT_ANSWERS.md) — ~40 questionnaire answers, including the honest "no"s
- [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md) — first 5 minutes, classification, containment, notification, post-mortem
- [`docs/PILOT_SOW_TEMPLATE.md`](docs/PILOT_SOW_TEMPLATE.md) — 6-week pilot scope, acceptance criteria, exit
- [`docs/BANK_CONTROL_MATRIX.md`](docs/BANK_CONTROL_MATRIX.md) — 12 controls vs what we can prove

## The documents an auditor asks for

Three controls are paperwork, not runtime. They are generated from the ledger so
they cannot drift from what happened:

```bash
mandate inventory --ledger L --owner bank-agent=payments-ops --out inv.json --csv inv.csv
# one row per agent: effects, kinds, approvers, scopes, first/last seen, amount total

mandate change record --ledger L --file mandate/policy.json \
  --approver approver --key ./approver_key --reason "raise effect budget to 5/h"
mandate change list --ledger L --signers trust/allowed_signers
# sha256 of the file + Ed25519 signature + entry hash; verified on demand

mandate pack --ledger L --out audit-pack --controls docs/BANK_CONTROL_MATRIX.md
# inventory.json/.csv, changes.json, dora_roi.json, controls.md, index.json with sha256 of each
```

`index.json` also carries `ledger_head` and the three commands an auditor runs
(`chain`, `anchor-verify`, `sha256sum`). The DORA row (service, provider, data
location, subcontracting, reliance, exit plan, audit rights, security evidence)
is in `dora_roi.json` — the fields a register-of-information entry needs.

## Shared nonce store (multi-host)

A grant is one-shot per nonce store. One host needs nothing; several hosts need
one authority, or each host's local file will say "unused":

```bash
mandate nonce serve --host 0.0.0.0 --port 8899 --token "$TOKEN" --db /var/lib/mandate/nonces.sqlite
export MANDATE_NONCE_URL=http://nonce.internal:8899 MANDATE_NONCE_TOKEN="$TOKEN"
```

Unreachable authority = refusal (`NonceUnavailable`), not a pass.

## Detect an inbound agent (behaviour, not blocklists)

The Nov 2026 incident that used OpenCode + Chrome + curl matched no blocklist; the
signal was behaviour. `mandate watch` scores each source address from an access log:

```bash
mandate watch --log access.jsonl --window 600 --ledger alerts.jsonl
```

| rule | points | what it sees |
|---|---|---|
| `tool_switch` | 3 | browser then curl/wget/httpx from one address within 15 min |
| `ua_flip` | 2 | same address claims desktop and mobile within 5 min |
| `docs_link_follow` | 3 | request whose Referer is an API/spec document |
| `key_probing` | 4 | 3+ distinct auth values on one path within 60 s |
| `read_after_submit` | 2 | repeated GETs refused by submit-only endpoints |
| `velocity` | 1 | 15+ distinct paths in one minute |
| `low_and_slow_scan` | 2 | 10+ paths answering 4xx with a single UA |

`>=6` high, `>=3` medium; alerts go into the ledger as `control/alert`. No model
is in the decision path — a judge may explain a finding, it cannot lower it.

## Detection: what a bank watches at runtime

Reuters reports banks adding detection for "agents using human employee
credentials", unusual volume and unusual tool use. `mandate detect` runs
deterministic rules over the ledger and the agent tokens:

```bash
mandate detect --ledger ledger.jsonl --policy policy.json            # read-only
mandate detect --ledger ledger.jsonl --policy policy.json --write    # alert into the chain
```

| rule | what it catches |
|---|---|
| `sod_ledger` | a receipt where approver == agent |
| `human_credential` | the acting identity is a human principal (`renato`, `ops`, …) |
| `velocity` | more than N effects per agent per hour |
| `amount` | single effect above the ceiling |
| `off_hours` | effect outside the configured UTC window |
| `scope_unknown` | effect kind never granted in any supplied agent token |

Receipts now carry `agent` and `session`, so an auditor can see *who acted*, not
only who approved. `--write` appends one `control`/`alert` record with the full
findings — same hash chain, same `mandate chain` verification.

## Warden, tier 2: kernel-observed freeze, signed stops, quarantine

```bash
mandate warden --attach agent-1 --pid 4242 --reason "runaway loop" --actor ops --ledger L.jsonl
# method=cgroup-freeze frozen=True events={"populated":"1","frozen":"1"} time_to_halt_ms=0.3

mandate warden --cgroup /sys/fs/cgroup/mandate/agent-1 --resume --actor ops --ledger L.jsonl
mandate warden --cgroup /sys/fs/cgroup/mandate/agent-1 --method kill --key ./ops_key \
  --signer ops --ledger L.jsonl          # stop signed by the operator
mandate warden --verify --ledger L.jsonl --signers allowed_signers   # all signed controls valid

mandate warden --quarantine --uid 65534 --reason "network isolation" --ledger L.jsonl
mandate warden --quarantine --uid 65534 --undo --ledger L.jsonl
```

- **cgroup v2 freezer** (`cgroup.freeze` + `cgroup.events`): the evidence is the
  kernel saying `frozen 1`, not our claim; `cgroup.kill` for the hard stop.
- **signed stops**: with `--key/--signer` the stop evidence is Ed25519-signed and
  `warden --verify` re-checks it, so "ops stopped it at 14:32" is non-repudiable.
- **quarantine by uid** through an nftables set (`meta skuid @q_uids drop`), which
  works where the iptables `owner` module is missing. The agent must run under its
  own uid for this to mean anything.

**MicroVM pause** is implemented against the Firecracker API and tested against a
stub, but it needs `/dev/kvm`:

```bash
mandate warden --method vm-pause --vm-socket /tmp/fc.sock --ledger L.jsonl
# without KVM: exit 4, {"error": "NoKvm", "message": "/dev/kvm is not available on this host"}
```

Verified 2026-11-24: the lab node `gama-lab-fra` (Vultr FRA, 8 vCPU / 31 GB,
20 containers) has **no** `/dev/kvm` and no `kvm` module, so Firecracker and VM
pause cannot run there. MicroVM work needs a KVM-capable host (nested virt or
bare metal); the client code is host-agnostic and ready for it.

Honest limits: a cgroup freeze keeps memory and can be thawed by anyone with
write access to that cgroup; quarantine is per-uid, not per-process; neither is a
hypervisor boundary. VM pause is code-ready but not yet demonstrated on real
Firecracker; "safe state" remains the bank's definition, not ours (row 5).

## One broker, several agents

One bearer token means every caller is "the agent". Per-agent tokens give each
agent its own credential and make the grant binding real:

```bash
mandate-broker agent add --store /etc/mandate/agents.json --name bank-agent
# prints the token once; the store keeps only its sha256 (0600)
mandate-broker --agents /etc/mandate/agents.json --config broker/config.json
```

The broker resolves the token to a name and refuses a grant signed for another
agent (`grant.agent` must equal the caller). Revoking one agent leaves the others
working: `mandate-broker agent revoke --store ... --name bank-agent`.

## Identity from a certificate, not a header

A bearer token proves possession of a string; a client certificate proves control
of a key and survives a sloppy proxy. With `--client-ca` the broker requires a
certificate signed by your CA and takes the **commonName as the agent**:

```bash
mandate-broker --agents /etc/mandate/agents.json \
    --tls-cert /etc/mandate/server.crt --tls-key /etc/mandate/server.key \
    --client-ca /etc/mandate/agents-ca.crt
mandate-broker agent register --store /etc/mandate/agents.json --name bank-agent
```

Add `--client-crl revoked.pem` and a revoked certificate cannot complete the
handshake at all (tested with a real CRL). A grant signed for `agent-a` is refused with `agent-b`'s certificate; a
certificate whose CN is not registered is refused before the grant is even read;
a client with no certificate cannot complete the handshake. Tokens and
certificates are separate mechanisms and can be used independently.

## Approve in a browser, not a terminal

```bash
mandate approver serve --page --key ~/.ssh/approver --approver "Amina H." \
    --audience local-broker --ledger ledger.jsonl
# then open http://127.0.0.1:8898 on that machine
```

**With a passkey** (WebAuthn), the signature comes from the device, not a file:

```bash
mandate approver serve --page --passkeys ~/.mandate/passkeys.json \
    --rp-id 127.0.0.1 --require-passkey --key ~/.ssh/approver --approver "Amina H."
```

The server verifies the assertion itself — `clientDataJSON` (type, challenge,
origin), `rpIdHash`, the signature over `authData || sha256(clientData)`, and a
signature counter that must advance. `ES256` and `EdDSA` are both accepted;
attestation is `none` only, so we register the key without judging the hardware.
Once a passkey exists, a form button **cannot** approve: the request is refused.
The browser JavaScript is not covered by CI — the verification it calls is
(12 WebAuthn tests plus 4 end-to-end ceremony tests with a software authenticator).

The page shows the **rendered effect** — amount, supplier, agent, broker — and
the button signs that exact snapshot. If the request changes after it was shown,
approval is refused (`render_hash` no longer matches). Every decision is appended
to the ledger as an `approval` record. The page binds to loopback and says, in
the page, that it signs with the key on this host via `ssh-keygen` and that this
is **not** WebAuthn: an honest limitation, not a hidden one.

## Verify without our code

`spec/verify_offline.py` checks a grant and a receipt with the Python standard
library only — no `import mandate`, no `ssh-keygen`. It re-implements JCS, the
SSHSIG container and Ed25519, so a reviewer can read every step:

```bash
python3 spec/verify_offline.py --grant spec/vectors/grant.json \
    --intent spec/vectors/intent.json --signers spec/vectors/allowed_signers \
    --receipt spec/vectors/receipt.json     # ok: true, exit 0
```

`spec/vectors/` also contains a tampered intent and a forged receipt, both of
which must fail.

**A second implementation in another language**: `spec/verify_offline.js` does the
same checks with Node's standard library and OpenSSL's Ed25519, not our Python:

```bash
node spec/verify_offline.js --grant spec/vectors/grant.json \
    --intent spec/vectors/intent.json --signers spec/vectors/allowed_signers \
    --receipt spec/vectors/receipt.json     # ok: true, exit 0
```

Both verifiers run in the same test suite on the same vectors and must agree. They
are written by the same author: that lowers the cost of an audit, it does not
replace an independent review.

## Review the policy like code

```bash
mandate policy lint                      # default must be deny, risk known, purpose written
mandate policy explain --effect payment.send --amount 500 --currency BAM
mandate policy diff --against policy.last-month.json
mandate observe-summary --ledger ledger.jsonl
```

`lint` blocks on a missing `default: deny`, an unknown `risk`, a negative
`max_auto`, or `require_revert` naming an effect that does not exist; it warns
when a rule has no `purpose` (an approver cannot tell why it may run without a
human) and when `max_auto` is set on `risk: low`, where it does nothing.
`explain` answers one question for one amount. `diff` names what got stricter,
so an approver reads a change, not a file. `observe-summary` reports which
observations were never executed.

## Policy digest, observe mode, revert

Approval binds the policy it was granted under; a changed policy invalidates old
grants. Observation is free, execution spends the grant, and every receipt says
what would undo the effect.

```bash
mandate grant ...            # records policy_digest of the policy the approver saw
mandate redeem ... --observe # receipt with binding=false, grant NOT spent
mandate redeem ...           # real execution; if the policy changed -> PolicyDenied
```

- `policy.json` may declare `"require_revert": {"payment.send": true}`; a missing
  `revert` step then blocks the effect.
- Receipts carry `policy_digest`, `binding` and `revert` (`irreversible` when none).

## Short-lived identity and delegation

An agent should not hold a long-lived key in its filesystem, and a sub-agent
should never be able to do more than its parent.

```bash
mandate svid issue --sub bank-agent --issuer bank-agent --key agent_key \
  --ttl 120 --audience local-broker --scope payment.send --out token.json

mandate redeem ... --svid token.json --svid-audience local-broker
# exit 6 + code=scope_not_granted | expired | subject_mismatch | bad_signature

mandate svid delegate --parent token.json --sub sub-agent --issuer sub-agent \
  --key sub_key --ttl 30 --scope payment.send --out child.json
mandate redeem ... --svid child.json --svid token.json --svid-audience local-broker
```

Enforced on every redeem that passes `--svid`:

- signature against `allowed_signers` (same key story as grants — no second PKI);
- `exp` and `iat` (no tokens from the future), TTL capped at one hour;
- **audience** must equal the broker;
- `sub` must equal `intent.actor.agent`;
- scope must contain the effect kind (`payment.send`, `order.create`, `*`);
- **chain**: child scopes ⊆ parent scopes, child `exp` ≤ parent `exp`, same
  audience, parent token must be supplied, self-delegation refused.

Honest limits: tokens are bearer credentials — whoever holds the file can use it
until it expires; that is why the TTL is short and why revocation is next
(`trust/revoked_signers` already exists for grants). A real deployment should
issue these from the bank's IdP/SPIFFE rather than from `svid issue`.

## Egress: deny by default

The July 2026 incident used a reachable network path, not a clever model. The
proxy refuses anything not named, refuses unauthenticated callers, and refuses
the cloud metadata endpoint:

```bash
mandate egress policy --allow 127.0.0.1:8080 --out egress.json
export MANDATE_EGRESS_TOKEN=...
mandate egress proxy --policy egress.json --port 3128 --ledger egress.jsonl

mandate egress check --policy egress.json --target pypi.org:443   # deny: not_allowlisted
mandate egress summary --ledger egress.jsonl                      # counts per decision
```

- **default deny**, allowlist by `host:port` or by IP;
- **bearer token required** (`407` otherwise), token read from the env var named
  in the policy;
- **SSRF/metadata guard**: destinations resolving to loopback, private,
  link-local or metadata addresses are refused unless the IP itself is listed;
- **every decision** — allow and deny — is a `control` record in the same hash
  chain, so "the agent could not reach X at 14:32" is provable;
- works for `CONNECT` (TLS) and plain HTTP.

Honest scope: an application-level proxy does not contain an agent that opens raw
sockets or has host networking. Pair it with network-namespace or VM egress rules
— that is the bank tier and it is on the roadmap, not in this release.

## Warden: a stop you can prove

`halt` stops the *ledger* (no new grants are honoured). `warden` stops the
*process*, from outside, and waits until the kernel confirms it:

```bash
mandate warden --pgid 4242 --reason "runaway loop" --actor ops --ledger ledger.jsonl
# {"verified": true, "states_after": {"4242": "T"}, "time_to_halt_ms": 6.0}

mandate warden --pgid 4242 --resume --reason "fixed" --actor ops --ledger ledger.jsonl
mandate warden --pgid 4242 --method kill --reason "credential misuse" --ledger ledger.jsonl
```

- **freeze** = `SIGSTOP` to the process group, then poll `/proc/<pid>/stat` until
  every pid reports `T`; **verified** is false if any pid is still running when
  the timeout expires (`exit 5`).
- **kill** = `SIGKILL`, verified by the process disappearing.
- Every stop, resume and hard stop is a `control` record in the same hash chain
  as receipts — actor, reason, pids, states, time-to-halt.

Honest limits: this is a host-level stop, not a hypervisor control plane; a
`SIGSTOP` freeze keeps memory and can be resumed by anyone who can signal the
process; an agent holding credentials the warden does not control is out of
scope. VM pause and network quarantine are the next tier (see
`docs/BANK_CONTROL_MATRIX.md`, row 5).

## Anchoring and evidence export

A hash chain is tamper-*evident* only relative to itself; whoever holds the file
can rewrite chain and head together. An RFC 3161 timestamp from a third party
fixes the head in time:

```bash
mandate anchor --ledger ledger.jsonl --tsa https://freetsa.org/tsr
# {"tsa": ..., "gen_time": "261124212228Z", "imprint_matches_head": true}

mandate anchor-verify --ledger ledger.jsonl --token anchors/<...>.tsr
# offline: status + imprint + genTime
mandate anchor-verify ... --ca tsa-ca.pem     # full CMS check via `openssl ts -verify`

mandate worm-export --ledger ledger.jsonl --out worm --retention-days 180 --anchors anchors
# dated directory, files chmod 0444, manifest with sha256 + retention_until + clock snapshot
```

Verified in `examples/06-anchor-and-worm.sh` against FreeTSA: imprint matches the
head, `openssl ts -verify` returns `Verification: OK`, the export is read-only,
and editing one byte of the ledger breaks `mandate chain`.

Honest limits: the timestamp proves *when a head existed*, not that the ledger is
complete; the local chmod is not WORM (use object lock for that); the signing key
is still a file on disk — HSM/PKCS#11 is the next step.

## Governance: budget, kill switch, four-eyes

Banks now treat agents like employees: credentials, permissions, **limits**, and
a kill switch whose use is on the record. Three additions cover that:

```bash
# policy.json
"limits": {"window_seconds": 3600, "max_effects": 3,
           "max_amount": 5000, "currency": "BAM"}

mandate redeem ...            # exit 4, code=limit_effects once the budget is spent
mandate halt --reason "runaway loop detected" --actor ops
mandate redeem ...            # exit 4, code=halted
mandate resume --reason "root cause fixed" --actor ops
mandate redeem ...            # still exit 4: resume does not reset the budget
mandate limits --ledger ledger.jsonl   # current state and last control record
```

- **Four-eyes:** `mandate grant` refuses when the approver equals the agent in
  the intent (`exit 3`, `SeparationOfDuties`).
- **Kill switch is evidence:** `halt`/`resume` are written into the same
  hash-chained ledger as receipts, so "we stopped it at 14:32, because X" is
  provable with `mandate chain` and survives the agent being deleted.
- **Limits are policy, not code:** an operator can raise a budget deliberately
  (and that change is a human act, with its own authorisation trail).

Run [`examples/05-bank-scenario.sh`](examples/05-bank-scenario.sh) to see all of
it in one pass: self-approval refused → three effects allowed → fourth refused →
halt → resume keeps the budget → raised limit → audit re-check.

## Effect broker (Phase 2)

`bin/mandate-broker` is the only component that executes effects. It verifies
the grant, **atomically claims the nonce** (SQLite `UNIQUE`, so two concurrent
requests cannot both succeed), runs the effect handler, and appends a signed
result entry to the hash-chained ledger. The agent calls it over loopback; the
agent never holds the effect credentials.

The shipped handlers are a sandbox (they record the effect under `effects/` or
`outbox/`). Wiring real credentials (SQL write, SMTP, payment) is Phase 2
completion — see `PLAN.md`.

### Adapters

**ERP precondition (read-only).** Before a grant is consumed, the broker runs a
named-parameter SQLite query against master data. No row → `counterparty_not_found`;
amount outside `tolerance_pct` → `amount_mismatch`. The grant is **not**
consumed when a precondition fails, so a corrected request can retry safely.

**SMTP (`message.send`).** `mode=dry_run` writes an `.eml` to the outbox;
`mode=live` sends via SMTP. The password is read from the env var named in
`password_env` and never logged or returned.

```json
"erp": {"db": "erp.sqlite", "checks": {"payment.send": {
  "query": "SELECT invoice_total FROM vendors WHERE name = :target",
  "amount_field": "invoice_total", "tolerance_pct": 0.5}}},
"smtp": {"mode": "dry_run", "host": "", "user": "",
         "password_env": "MANDATE_SMTP_PASSWORD", "from": "noreply@example.com"}
```

## Key scoping and revocation

An `allowed_signers` line **must** declare its namespace scope:

```
approver namespaces="mandate" ssh-ed25519 AAAAC3Nza... mandate
gama-broker namespaces="mandate-broker" ssh-ed25519 AAAAC3Nza... broker
```

Optional validity: `valid-after="YYYYMMDD" valid-before="YYYYMMDD"`.
Revoke a key by fingerprint:

```bash
mandate revoke --pub key.pub --reason "laptop lost"
mandate --signers trust/allowed_signers signers   # inspect scopes + fingerprints
```

### Idempotent writes and recovery

The broker keeps a SQLite **effect journal** (`journal_db`). The flow is
`intent → executing → executed → receipted`; the authorisation receipt is
written only **after** the effect commits. On startup the broker recovers:
a committed effect without a receipt gets one; a claimed grant with no effect is
abandoned; a duplicate `execute` returns the original receipt and result.

`write.mode=sqlite` runs a trusted configured statement together with an
idempotency insert in **one transaction**, keyed by the grant nonce:

```json
"write": {"mode": "sqlite", "db": "erp.sqlite",
          "statement": "INSERT INTO payments(nonce,vendor,amount) VALUES(:nonce,:target,:amount)"}
```

## Transparency log

Every ledger entry is a leaf in an RFC 6962/9162-style Merkle tree
(`Leaf=SHA256(0x00||JCS(entry))`, `Node=SHA256(0x01||L||R)`). A signed tree
head (STH) fixes the root and size; inclusion and consistency proofs verify
offline:

```bash
mandate log head  --ledger ledger.jsonl --log-name log1 --log-key ~/.ssh/mandate-log --out sth.json
mandate --signers trust/allowed_signers log sth-verify --sth sth.json
mandate log proof --ledger ledger.jsonl --index 3 --out proof.json
mandate log verify-inclusion --entry entry.json --proof proof.json --sth sth.json
mandate log consistency --ledger ledger.jsonl --first 2 --second 3 --out cons.json
mandate log verify-consistency --old old_sth.json --new sth.json --proof cons.json
```

A single log cannot prevent **split-view** by its operator; pin the STH on a
second machine (witness/anchor). The STH signer needs
`namespaces="mandate-log"` in `allowed_signers`.

### Off-host witness

```bash
# on the second machine
mandate --signers log_signers witness serve --state witness.json \
  --token "$WITNESS_TOKEN" --port 8898

# on the log host
mandate witness push --url http://witness:8898 --sth sth.json --token "$WITNESS_TOKEN"
mandate witness push --url http://witness:8898 --sth sth_new.json --proof cons.json --token "$WITNESS_TOKEN"
mandate witness show --state witness.json
```

The witness pins the latest STH and rejects rollback or a same-size different
root (split-view). Growth requires a consistency proof from the pinned root.
`witness verify` checks without pinning; `witness accept` pins locally.

## Co-sign on the approver's host

The agent never holds the private key. The approver runs a small daemon on
their own machine; it recomputes the commitment/render from the intent (it does
not trust the agent's proposal), prints the summary, and signs only after `y`:

```bash
# approver's host
mandate approver serve --key ~/.ssh/mandate --approver approver \
  --audience local-broker --port 8897

# agent host
mandate request --approver http://approver-host:8897 --intent intent.json \
  --audience local-broker --out grant.json
mandate execute --broker http://127.0.0.1:8899 --intent intent.json --grant grant.json
```

Loopback by default; a non-loopback daemon requires `--token` /
`MANDATE_APPROVER_TOKEN`. Without a TTY the daemon refuses to auto-approve
(`503`). A Telegram notification channel can be added in front of the same
signer without changing the security property.

### Telegram notification (advisory)

```bash
TELEGRAM_BOT_TOKEN=... mandate approver serve --key ~/.ssh/mandate \
  --approver approver --telegram-chat 6402195499
```
The message contains only the summary, agent, broker and commitment. It has no
approve button or link; the human still confirms on the approver host's TTY.
Notification failures are logged and never auto-approve.

### Portable receipt export (JOSE-style)

```bash
mandate export --receipt receipt.json --intent intent.json --grant grant.json \
  --proof proof.json --key ~/.ssh/mandate --signer approver --out bundle.json
mandate --signers trust/allowed_signers export-verify --bundle bundle.json
```
The envelope carries the intent, the signed grant, the hash-chained receipt and
an optional Merkle inclusion proof, signed with an OpenSSH SSHSIG in namespace
`mandate-export`. Add `mandate-export` to the approver's `namespaces="..."` in
`allowed_signers`. This is a custom profile, not strict JWS/C2PA; verifiers use
OpenSSH tooling.

### Payments

```json
"payment": {"provider": "sandbox", "db": "payments.sqlite"}
```
or a generic HTTP provider:
```json
"payment": {"provider": "http", "url": "https://provider.example/charges",
            "token_env": "PAYMENT_TOKEN"}
```
The provider must be idempotent on `idempotency_key` and expose a lookup by that
key. The broker looks up before charging and reconciles on timeout; recovery
never charges twice.

### ERP (SQLite or MSSQL, read-only)

```json
"erp": {"driver": "sqlite", "db": "erp.sqlite", "checks": { ... }}
```
For MSSQL: `"driver": "mssql"`, `"dsn": "...", "user_env": "...",
"password_env": "..."` and `pip install gama-mandate[mssql]`. For FreeTDS without
an ODBC driver use `"driver": "pymssql"`, `"server": "...", "database": "...",
"tds_version": "7.0"` (default; raise it only if the server supports it),
`"user_env": "...", "password_env": "..."`. Only `SELECT`/`WITH` queries are
accepted; SQLite opens `mode=ro`, MSSQL runs read-only and rolls back.

## Provenance (sycophancy firewall)

A consequential intent must justify its choices with data, not with a stated
preference. Policy declares the required fields:

```json
"payment.send": {"risk": "high", "require_data_ref": ["target", "amount"]}
```

The intent carries typed provenance:

```json
"provenance": [
  {"type": "data_ref", "source": "erp:vendor:1", "covers": ["target", "amount"]}
]
```

- `data_ref` without `covers` covers all required fields.
- `user_pref` and `model_inference` **never** satisfy a required field.
- Missing evidence is denied (`missing_data_ref` / `ProvenanceMissing`).
- The provenance is hashed into the commitment, so it cannot be swapped after
  the grant.

## Operations

- **Metrics:** Prometheus text at `/metrics` on the broker, approver daemon and
  witness (bearer token required if one is configured). Counters for requests,
  executions, rejections, rate-limit hits, journal gauges and uptime.
- **Rate limiting:** per-IP token bucket on `/execute`, `/request` and `/sth`.
  Enable with `--rate-limit-per-min N --rate-burst M` (or
  `MANDATE_RATE_PER_MIN` / `MANDATE_RATE_BURST`). Excess returns `429`.
  Disabled by default (`0`).

## Hardware-backed approver keys (WebAuthn substitute)

Mandate does not implement browser WebAuthn (it needs a CBOR/COSE stack and a
browser UI). A phishing-resistant FIDO2 key works with the same verification:

```bash
ssh-keygen -t ed25519-sk -O verify-required -f ~/.ssh/mandate
# allowed_signers: approver namespaces="mandate,mandate-export" sk-ssh-ed25519 AAAA...
```

Set `"require_hardware_key": true` on an effect to reject software Ed25519
grants; the approver key must then be `sk-ssh-ed25519`.

## MCP manifest gate (Phase 1)

Pin the tools an agent may use and detect tool poisoning/rug-pull:

```bash
mandate mcp lock --cmd "python3 my_mcp_server.py" --server my-server \
  --key ~/.ssh/publisher --signer publisher --out mandate.lock.json
mandate --signers trust/allowed_signers mcp verify \
  --lock mandate.lock.json --cmd "python3 my_mcp_server.py"
mandate --signers trust/allowed_signers mcp proxy \
  --lock mandate.lock.json --cmd "python3 my_mcp_server.py"
```

The lock hashes every tool name, description and input schema and is signed
with an OpenSSH SSHSIG in namespace `mandate-mcp` (`namespaces="mandate-mcp"` in
`allowed_signers`). The proxy denies a changed manifest and any tool not in the
lock; `--verify-calls` re-probes before each call.

## Taint gate (Phase 2)

After an untrusted source (web, email, RAG, MCP output) is read, an effect tool
requires a Mandate grant and a `data_ref`:

```json
{"sources": ["web_fetch"], "effects": ["pay"], "require_grant": true}
```

The agent attaches the grant to the call; the proxy verifies it, requires a
`data_ref` provenance entry when the session is tainted, consumes it (replay
denied) and strips `_mandate` before forwarding:

```json
{"name": "pay", "arguments": {"amount": 1,
  "_mandate": {"intent": {"effect": {"kind": "mcp.call", "target": "pay",
     "params": {"args_sha256": "…"}}, "provenance": [{"type": "data_ref",
     "source": "erp:vendor:1"}]}, "grant": {…}}}}
```

Run with `mandate mcp proxy --taint taint.json --mcp-ledger ledger.jsonl`.

## Sandbox untrusted MCP servers (Phase 3)

Run the MCP server itself in a hardened container:

```bash
mandate mcp proxy --lock mandate.lock.json --cmd "python3 fake_mcp.py" \
  --sandbox docker --sandbox-image python:3.12-slim \
  --sandbox-mount "$PWD/tests/fixtures:/work:ro" --sandbox-workdir /work
```

- `docker` (runc) and `gvisor` (`--runtime runsc`): read-only root, `--network
  none`, `--cap-drop ALL`, `no-new-privileges`, pids/memory/cpu limits, 16 MiB
  tmpfs, explicit read-only mounts.
- `firecracker` uses `--sandbox-cmd-template "<launcher> --"` so a lab VM
  Firecracker runner can be plugged in without changing the proxy.
- `local` is for trusted development only.

## Intent Divergence Benchmark

Measure whether the gate rejects actions that diverge from the user's intent:

```bash
mandate bench --scenarios bench/scenarios/idb_v0.jsonl --out idb-report.json
```

Scenarios cover prompt injection, sycophancy-to-action, partial/invalid
provenance, hidden fields, unknown effects and benign effects. Metrics:
`failed`, `false_allow`, `false_block`, `pi_asr`, per-category totals. The
deterministic run is CPU-only; `bench/lumi_idb.sbatch` runs it inside the LUMI
container.

A model-generated corpus measures the model itself:

```bash
mandate bench --scenarios bench/scenarios/model_prompts.jsonl \
  --model-url http://127.0.0.1:8000 --model <served-model>
```

Metrics: `bad_proposals`, `bad_proposal_rate`, `unsafe_execution`
(target 0). `bench/lumi_idb_model.sbatch` runs it against a vLLM server on LUMI.

## Auditor bundle

One signed JSON proves a single action end-to-end (intent, grant, receipt,
Merkle proof, signed tree head, witness pin):

```bash
mandate audit bundle --receipt R --intent I --grant G --proof P \
  --sth sth.json --witness-state witness.json \
  --key ~/.ssh/mandate --signer approver --out bundle.json
mandate --signers trust/allowed_signers audit verify \
  --bundle bundle.json --log-signers trust/log_signers
```

`valid` is true only if the envelope signature, receipt/grant, STH signature,
inclusion proof and witness state all check out. Details: `docs/AUDITOR_BUNDLE.md`.

## The stack

Five packages, one purpose: an agent's "done" should be provable.

| Package | Job | Start with |
|---|---|---|
| **`gama-mandate`** | who authorised this exact effect: commitment → Ed25519 grant → receipt | `pip install gama-mandate` |
| [`gamai-trust`](https://pypi.org/project/gamai-trust/) | is the claim true against observed evidence (`confirmed` / `refuted` / `unverified`) | `gamai-trust verify claims.json` |
| [`gamai-guard`](https://pypi.org/project/gamai-guard/) | block prompt injection, multilingual, with a false-positive brake | `gamai-guard text "..."` |
| [`gamai-plugins`](https://pypi.org/project/gamai-plugins/) | policy evaluation (deny wins), sandbox leases, team coordination | `gamai-plugins list` |
| [`gama-l`](https://pypi.org/project/gama-l/) | small language with `prove`/`verify` and hash-chained receipts | `gama-l run proof.gm` |

Mandate is the entry point: it is the piece that decides *whether* an effect may
happen. The other four answer the questions around it — was the claim true
(`trust`), was the input hostile (`guard`), is the tool allowed (`plugins`), and
can the computation be proven (`gama-l`).

## Bank control matrix

`docs/BANK_CONTROL_MATRIX.md` maps the twelve controls a bank needs (DORA Level 2
RTS 2024/1774, AI Act where in scope, NIST agent-identity tenets) to what this
repository can prove today, what is partial, and what is missing — with effort
estimates. Short version: rows 4, 6 and 7 are done; row 9 (tamper-evident,
independently verifiable evidence) is partial and is also the row with no
credible vendor in the market.

## Design invariants

1. **Effect, not tool.** The registry keys on `payment.send`, not on
   `gama_sql`. The same effect is the same commitment regardless of executor.
2. **Canonical bytes.** **RFC 8785 (JCS)** canonical JSON; the commitment is the
   hash of `{v, effect, requested_by, render_hash}`. Same content ⇒ same id, in
   any RFC 8785 implementation.
3. **Off-host key.** The approver's private key never lives where the agent
   runs. The host stores only public keys (`trust/allowed_signers`).
4. **One-shot, nonce-bound.** A grant is redeemable once; replays fail.
5. **Agent cannot self-approve.** Enforced in code, not by convention.
6. **Fail closed.** Unknown effects are denied. Missing signer ⇒ invalid.

## Layout

```
spec/       MANDATE-1 data model
mandate/    stdlib-only reference implementation
bin/        CLI
adapters/   MCP server
tests/      unit + bypass tests (red-team)
docs/       THREAT_MODEL, NON_GOALS, PLAN
skills/     agent skill instructions
```

## Status

**v0.51.0** — canonical commitment, Ed25519
grant bound to the executing agent, one-shot redeem under a file lock,
hash-chained receipts with a `.head` anchor, provenance enforcement, idempotent
effect journal + write adapter, payment adapter with provider idempotency and
reconciliation, read-only ERP (SQLite/MSSQL/pymssql) checks, SMTP, Merkle
transparency log with an off-host witness, approver daemon with advisory
Telegram notification, hardware-backed `sk-` keys, portable JOSE-style receipt
export, MCP server (`mandate-mcp`), `/metrics`, rate limiting, and a red-team
test suite. See `STATUS.md` and `docs/THREAT_MODEL.md` for limits.

## Honest limitation

Cryptography proves *who authorised what*. It does **not** isolate
credentials. Until the credentials that cause the effect (SQL write, payment
API, mail) live only in an effect broker, a compromised agent can bypass
Mandate entirely. That broker is the next milestone — see `PLAN.md`.

## Where a signed commitment actually matters (asked on AI Lounge, 24 Nov 2026)

Not for every message. Exactly when an agent agrees a **price or a delivery date** on the company's
behalf: that is the claim someone disputes three weeks later, and the only one worth signing.
Everything else is chatter and should stay unsigned.
