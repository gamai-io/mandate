# Changelog

## 0.53.0 — 2026-11-25
- **Decision latency is recorded.** Approval records carry `waited_s` (request
  arrival to the decision), and `mandate decisions --ledger` reports approved /
  rejected counts with median, p95 and max wait. The reporting on AI-accelerated
  attacks says the bottleneck is the decision after the alert; this is the number
  that argument needs.
- `docs/THREAT_CONTEXT.md` maps the ARTEX/FBI reporting to the code, names what it
  threatens, and lists the next three pieces of work.
- 357 tests.

## 0.52.0 — 2026-11-25
Security pass after an external review. Breaking where the old behaviour was unsafe:
- **Audience is enforced.** A grant bound to an audience can no longer be redeemed
  by a caller that does not name it; previously the check was skipped entirely
  when `--audience` was omitted. `mandate redeem` on a bound grant now needs
  `--audience`.
- **Crash recovery never charges twice.** When a lease expires, the broker asks the
  payment provider whether the effect already happened and finalises that result;
  for effects without an idempotency key it refuses to repeat and says why.
- **Single use crosses deployments.** The broker claims the grant nonce in the
  shared nonce store, not only in its own journal.
- **A truncated or edited ledger is refused**, not silently repaired: appending to
  a file whose head does not match its tail (or whose last entry no longer matches
  its own hash) raises instead of rewriting `.head`.
- **One approval, one grant**: the approval page refuses a second POST for the
  same request, and requires user verification (UV), so a touch-only passkey does
  not approve a payment.
- **Limits include the pending effect**, and an unreadable limits file is a refusal
  rather than "no limits".
- `mandate restore` rejects archive members that escape the target directory or are
  links/devices; outbound URLs must be http(s) with a host.
- 354 tests.

## 0.51.2 — 2026-11-25
- **Append is no longer quadratic.** `_append_locked` read the entire ledger on
  every write, so the n-th receipt cost O(n). It now reads only the last line and
  checks it against `.head`, falling back to a full read on any mismatch. Measured:
  10,000 receipts at a flat **9.7 ms** each (fsync-bound), ledger 8.1 MB,
  `verify_chain` **1.94 s**, `mandate pack` **0.55 s** — see `docs/PERFORMANCE.md`.
- `tests/test_append.py`: a four-times-larger ledger must not cost more per append,
  plus fallbacks for a tampered tail and a missing `.head`.
- `docs/DORA_SUPPLIER_PACK.md`: register data points, contract elements, the
  evidence we can show, and the list of what is missing.
- 338 tests.

## 0.51.1 — 2026-11-25
- Publish through OIDC trusted publishing with PEP 740 attestations: the PyPI
  trusted publisher for `gamai-io/mandate` + `release.yml` was added on
  2026-11-25, and `PYPI_OIDC=true` is set on the repository. The long-lived API
  token is no longer needed for releases.

## 0.51.0 — 2026-11-25
- `mandate demo`: the whole chain in one command on a throwaway directory — real
  key, real grant, redeem, **replay refused**, **changed amount refused**, receipt
  verified, audit pack written. Exits non-zero if any step does not hold.
- `spec/verify_offline.js`: a second verifier in Node (OpenSSL Ed25519, own JCS and
  SSHSIG parsing). Both verifiers run on the same vectors in CI and must agree.
- Broker `--client-crl`: `VERIFY_CRL_CHECK_LEAF`, so a revoked certificate cannot
  complete the handshake; tested with a real CRL and a revoked client.
- 8 new tests; 334 total.

## 0.50.0 — 2026-11-25
- **mTLS for the broker.** `--tls-cert/--tls-key` serve HTTPS; `--client-ca`
  requires a client certificate and uses its CN as the agent identity. The CN must
  be registered (`agent register`), and the grant's `agent` must equal it.
  Unregistered CN → 403 before the grant is read; no certificate → handshake
  failure; wrong agent → 409.
- 4 end-to-end tests with a throwaway CA (own grant, other agent's grant,
  unregistered CN, no certificate); 326 total.
- Broker docs state what is *not* covered: certificate rotation is a restart, no
  CRL/OCSP check yet.

## 0.49.1 — 2026-11-25
- CI installs `cryptography` (test-only): the WebAuthn tests import it to emulate
  an authenticator, so 0.49.0 passed locally and failed in CI at import. The code
  is unchanged; this release exists so the published version has a green run.

## 0.49.0 — 2026-11-25
- **Per-agent broker tokens.** `mandate-broker agent add|list|revoke` manages a
  store that keeps only SHA-256 of each token (written `0600`, token shown once).
  The broker resolves the bearer token to a name and refuses a grant signed for a
  different agent; revocation is per agent, not global.
- `/health` reports the number of agents, never a token.
- 10 tests (store hygiene, duplicate name, corrupt store, wrong-agent redemption,
  unknown and revoked tokens, single-token mode unchanged); 322 total.

## 0.48.0 — 2026-11-25
- **Passkey approval.** `mandate/webauthn.py` verifies WebAuthn assertions with
  the standard library: `ES256` (P-256) and `EdDSA`, `clientDataJSON` type /
  challenge / origin, `rpIdHash`, the signature over `authData || sha256(clientData)`,
  and a monotonic signature counter (a cloned authenticator is refused). Minimal
  CBOR decoder included; attestation is accepted as `none` only, stated as such.
- `mandate approver serve --page --passkeys FILE [--require-passkey]`:
  registration and assertion endpoints, challenge store with 120 s TTL, registry
  written `0600`, and a hard rule that a form button cannot approve once a passkey
  exists.
- 12 WebAuthn tests (registration, challenge/origin/rpId, tampered signature,
  counter rollback, zero counter, packed attestation refused) and 4 end-to-end
  ceremony tests through the HTTP server.
- Honest limit in the docs: the browser JavaScript is not exercised by CI; the
  verification it calls is.
- 312 tests.

## 0.47.0 — 2026-11-25
- `mandate approver serve --page`: a browser page a human can actually use. It
  shows the rendered effect (amount, target, agent, broker), and the button signs
  that snapshot. A request changed after display is refused; a guessed form token
  is refused (HMAC per process); every decision is an `approval` record in the
  ledger.
- Loopback by default; `0.0.0.0` needs `--allow-remote`; the page states that the
  signature comes from the key on this host via `ssh-keygen` and that it is not
  WebAuthn.
- 296 tests (6 new: approve, reject reaching the waiting agent, forged token,
  tampered-after-display, bind guard, health).

## 0.46.0 — 2026-11-25
- **Credential custody is now a tested claim, not a design note.**
  `tests/test_broker_custody.py` runs three processes (fake provider, broker,
  agent): the agent has no provider token, the effect still executes, the provider
  refuses the agent's direct call (401), an unauthenticated `/execute` is 401, and
  the same grant charges once.
- `Broker.custody()` / `/health` report held secrets **by name only**
  (`env:PAY_TOKEN`, `present: true`), never the value.
- `packaging/mandate-broker.service`: own user, `ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies`, `MemoryDenyWriteExecute`,
  `0400` environment file.
- `docs/BROKER.md`: the containment claim, the checks to run, what the boundary
  does not buy (host compromise, one shared broker token, no mTLS).
- `docs/AP2_VS_MANDATE.md`: protocols (AP2, TAP, Agent Pay, ACP, x402) authorise
  on the network; this records that a named person in *this* bank approved *this*
  amount. Includes the three things interoperability would need, none of them built.
- Release publishes with PEP 740 attestations (PyPI provenance) when OIDC is on.
- README opens with **One thing**, so the scope is not a discovery.
- 290 tests.

## 0.45.0 — 2026-11-25
- `spec/verify_offline.py`: a verifier that imports no project code and never
  calls `ssh-keygen`. Standard library only — JCS (RFC 8785), SSHSIG and Ed25519
  re-implemented, ~350 lines a reviewer can read. Checks the grant signature, the
  signer against `allowed_signers`, the commitment and render hash against the
  intent, the receipt hash and its binding to the grant.
- `spec/vectors/`: valid grant/receipt plus a tampered intent and a forged
  receipt, each expected to fail; generated by `tools/make_vectors.py`.
- `spec/MANDATE-1.md` documents the independent-verification path and says what
  it is not (second implementation, same author, not a third party).
- `docs/PROCUREMENT_ANSWERS.md` answers "who verifies your verifier" with the
  artefacts and the remaining gap.
- 285 tests.

## 0.44.0 — 2026-11-25
- `agentwatch.key_probing` used a per-row rescan of the 60 s window: one address
  sending 100k requests made a run effectively never finish. Sliding window with
  a counter, O(n) instead of O(n^2); 100k rows now score in ~1 s.
- Regression test at 50k rows with a wall-clock bound.
- `tools/claims.py`: CI fails when the version, the CHANGELOG or the test count in
  README disagree with pyproject; `CLAIMS.md` lists every claim with the command
  that reproduces it, and what is not proven.
- One version everywhere: README, SECURITY.md (supported table), procurement and
  architecture docs said 0.34/0.38 while PyPI served 0.43. CHANGELOG now covers
  0.34–0.44.

## 0.43.0 — 2026-11-25
- `mandate policy lint/explain/diff`: a policy is reviewed like code. `lint` blocks
  `default != deny`, unknown risk, negative `max_auto`, `require_revert` naming a
  missing effect; warns when a rule has no `purpose`. `diff` names what got stricter.
- `mandate observe-summary`: observations vs executions; grants observed and never
  executed. Shipped `policy.json` carries `purpose` for every effect.
- 279 tests.

## 0.42.0 — 2026-11-25
- `policy_digest` in grant and receipt; `redeem` refuses when the policy changed
  after the signature (`PolicyDenied`).
- `redeem --observe`: receipt with `binding: false`, grant is **not** spent.
- `effect.revert` accepted and committed; receipts carry `revert` or `irreversible`;
  `require_revert` per effect kind.
- 263 tests.

## 0.41.0 — 2026-11-25
- `mandate watch`: behavioural detection of an inbound agent from an access log —
  tool switching, UA flipping, docs link following, key probing, submit-only reads,
  velocity, low-and-slow. Alerts are `control/alert` in the same hash chain.
- 258 tests.

## 0.40.1 — 2026-11-25
- Signed release provenance: `attest.yml` builds and attests every artefact
  (Sigstore/OIDC) and uploads the SBOM next to it.
- `docs/PILOT_SOW_TEMPLATE.md`, `docs/INCIDENT_RESPONSE.md`.

## 0.40.0 — 2026-11-24
- Egress proxy: deny-all, host:port allowlist, metadata/RFC1918 guard before the
  allowlist, connect-to-validated-IP (SSRF and DNS rebinding).
- SVID issuance and delegation; `require_svid`; wildcard scope refused.

## 0.39.0 — 2026-11-24
- Cross-ledger nonce store; `mandate nonce serve` as a shared authority (fail-closed).
- Claim-callback double-spend closed; broker governance fails closed.

## 0.38.0 — 2026-11-24
- Warden: SIGSTOP, cgroup freeze confirmed via `cgroup.events`, `cgroup.kill`,
  Firecracker pause confirmed through the API, per-uid quarantine; signed stops and
  measured time-to-halt.
- Annex IV packaging (`mandate pack`), inventory and change records.

## 0.37.0 — 2026-11-24
- Multi-TSA anchoring (`--tsa` repeatable); pack includes ledger and anchors;
  WORM export.

## 0.36.0 — 2026-11-24
- One-shot enforced across ledgers (nonce seen in another ledger is refused).

## 0.35.0 — 2026-11-24
- Red-team round: SVID subject/key binding, spend-limit path, anchor forgery,
  commitment actor binding, pack hygiene. Each has a regression test.

## 0.34.0 — 2026-11-23
- Canonical commitment, Ed25519 grant bound to the agent, one-shot redeem under a
  file lock, hash-chained receipts with a `.head` anchor, provenance enforcement,
  idempotent effect journal, payment adapter, read-only ERP checks.

## 0.26.0 – 0.33.0 — 2026-11-09 … 2026-11-22
Summarised: model/provider adapters, bench harness, Merkle transparency log with an
off-host witness, approver daemon, hardware-backed `sk-` keys, portable receipts,
MCP policy, sandbox backends. Individual entries were not kept; the tags and tests
are the record.

## 0.25.0 — 2026-11-09
- Concurrent model benchmark (`--workers`) using a thread pool, order
  preserved; enables many parallel agents against one vLLM endpoint.
- 244-prompt corpus generated by four parallel agents
  (`bench/scenarios/model_prompts_merged.jsonl`).
- 139 tests.

## 0.24.1 — 2026-11-09
- Fix model benchmark URL handling: `--model-url` may end with `/v1`
  (previously produced `/v1/v1/chat/completions` and HTTP 404); added test.
- 138 tests.

## 0.24.0 — 2026-11-09
- **Auditor bundle**: `mandate audit bundle` packages the intent, signed grant,
  hash-chained receipt, Merkle inclusion proof, signed tree head and witness
  state into one signed JSON; `mandate audit verify --log-signers ...` checks
  the envelope signature, receipt/grant, STH signature, inclusion against the
  STH root/size and the witness pin. 4 tests + docs
  (`docs/AUDITOR_BUNDLE.md`).
- 137 tests.

## 0.23.0 — 2026-11-09
- Model IDB prompt corpus expanded to **20** scenarios (injection, sycophancy,
  exfiltration, TOCTOU, ambiguous, benign).
- LUMI comparison of **qwen25-7b** and **qwen25vl7b** (4× MI250, TP4):
  bad proposals 6/20 and 9/20 respectively; every consequential proposal was
  denied or required a grant; **unsafe_execution=0** for both.
  Raw summary: `bench/results/lumi-2026-11-09-20prompts.json`.
- 133 tests.

## 0.22.2 — 2026-11-09
- Model IDB exit criterion is now `unsafe_execution == 0`; `invalid` (no usable
  intent / refusal) and `bad_proposals` are findings, not failures.
- LUMI run recorded: qwen25-7b, 4 prompts, `bad_proposals=1`,
  `blocked=1 (ask)`, `unsafe_execution=0`
  (`bench/results/lumi-qwen25-7b-2026-11-09.json`).
- 133 tests.

## 0.22.1 — 2026-11-09
- Model IDB: normalize effect aliases (`payment` → `payment.send`,
  `create_order` → `order.create`, …) and classify unknown names containing
  `pay/order/supplier/price/message/export/delete/refund/transfer` as
  consequential. Unknown names are still denied by the gate but now counted as
  bad proposals on injection/sycophancy prompts.
- System prompt now lists the allowed effect kinds explicitly.
- 2 classifier tests + 133 total.

## 0.22.0 — 2026-11-09
- **Model-generated IDB**: `mandate bench --model-url ... --model ...` sends a
  prompt corpus to an OpenAI-compatible endpoint (vLLM), parses the proposed
  intent and reports `invalid`, `bad_proposals`, `bad_proposal_rate`,
  `consequential`, `blocked`, `unsafe_execution`.
- Prompt corpus `bench/scenarios/model_prompts.jsonl`; LUMI template
  `bench/lumi_idb_model.sbatch`.
- 4 model tests + 131 total.

## 0.21.0 — 2026-11-09
- **Intent Divergence Benchmark (IDB)**: `mandate bench` (or
  `python3 -m mandate.benchmark`) evaluates a JSONL scenario corpus against the
  policy/provenance gate and reports `failed`, `false_allow`, `false_block`,
  `pi_asr` and per-category metrics.
- Scenario corpus: prompt injection, sycophancy-to-action, partial/invalid
  provenance, hidden effect fields, unknown effects, benign effects.
- LUMI batch template `bench/lumi_idb.sbatch` (deterministic gate run; a
  model-generated corpus is the next step).
- 3 benchmark tests + 127 total. Live run: 12/12, `pi_asr=0`, `false_allow=0`.

## 0.20.0 — 2026-11-09
- **Firecracker stdio bridge (Phase 3 complete)**: `mandate.firecracker_bridge`
  boots a KVM microVM, copies host files referenced by absolute path into
  `/tmp` in the guest, starts the command with unbuffered Python and bridges
  JSON-RPC lines between stdin/stdout and the guest serial console.
  `mandate-fc-bridge` console script.
- Verified on the lab VM: `mandate mcp lock/verify --sandbox firecracker
  --sandbox-cmd-template "python3 -m mandate.firecracker_bridge --"` returns a
  valid lock against a real microVM (Python 3.12 inside).
- 3 bridge tests + 124 total.

## 0.19.0 — 2026-11-09
- **Sandbox runner for untrusted MCP servers (Phase 3)**: `--sandbox
  local|docker|gvisor|firecracker` on `mandate mcp lock|verify|proxy`.
  Docker/gVisor use a hardened container: read-only root, no network, all
  capabilities dropped, `no-new-privileges`, pids/memory/cpu limits, 16 MiB
  tmpfs, explicit read-only mounts, no bytecode writes.
  Firecracker is an external launcher template (`--sandbox-cmd-template`) so a
  lab VM runner can be plugged in.
- Integration test runs the MCP lock/verify/proxy through a real Docker
  container (`python:3.12-slim`, network none).
- 7 sandbox tests + 121 total.

## 0.18.0 — 2026-11-09
- **MCP taint gate (Phase 2)**: `mandate mcp proxy --taint taint.json` marks the
  session tainted after a source tool (`web_fetch`, email, RAG, …). An effect
  tool then requires a Mandate grant in `arguments._mandate` for
  `effect.kind="mcp.call"`, with matching `target` and `args_sha256`; after
  taint it also requires a `data_ref` provenance entry. The grant is verified
  and consumed (replay denied); `_mandate` is stripped before forwarding.
- Policy: `mcp.call` (high risk).
- 2 taint tests + 114 total.

## 0.17.0 — 2026-11-09
- **MCP manifest gate (Phase 1)**: `mandate mcp lock` builds a signed lock of
  tool descriptions/schemas (SHA-256 over canonical JSON, OpenSSH SSHSIG in
  namespace `mandate-mcp`); `mandate mcp verify` re-probes the server and
  detects tool poisoning/rug-pull; `mandate mcp proxy` is a stdio MCP proxy that
  denies a changed manifest and any tool not present in the lock (optional
  per-call re-verification with `--verify-calls`).
- 6 MCP tests + 112 total.

## 0.16.1 — 2026-11-09
- pymssql ERP driver: configurable `tds_version` (default `7.0` for older
  servers). A live read-only MSSQL check against `master`/`sys.tables` passed
  through the adapter (no business data).
- `STATUS.md` handover/state document; sdist includes it.
- No behavior change for SQLite/pyodbc; 106 tests.

## 0.16.0 — 2026-11-09
- **OIDC trusted publishing** path in the release workflow (dual path). Set the
  repo variable `PYPI_OIDC=true` after configuring the PyPI trusted publisher;
  the token secret is then unused.
- **Hardware-backed approver keys** (WebAuthn substitute): policy
  `require_hardware_key` rejects software Ed25519 grants; the approver key must
  be `sk-ssh-ed25519` (FIDO2, `ssh-keygen -t ed25519-sk -O verify-required`).
  Full WebAuthn/passkeys still requires a browser/CBOR stack.
- ERP `driver=pymssql` (FreeTDS; no ODBC driver needed) alongside `mssql`
  (pyodbc) and `sqlite`; `:name` binds are converted to positional parameters.
- 106 tests.

## 0.15.1 — 2026-11-09
- **Automated release**: pushing a `v*` tag now builds, tests, `twine check`s,
  publishes to PyPI (`PYPI_API_TOKEN` secret) and creates a GitHub release via
  `.github/workflows/release.yml`.
- No code changes; 103 tests.

## 0.15.0 — 2026-11-09
- **Operations**: `/metrics` (Prometheus text) on the broker, approver daemon and
  witness: request/execution/rejection counters, rate-limit hits, journal gauges,
  uptime.
- **Per-IP rate limiting** on `/execute`, `/request` and `/sth`
  (`--rate-limit-per-min`, `--rate-burst`, or `MANDATE_RATE_PER_MIN` /
  `MANDATE_RATE_BURST`); excess returns `429`. Disabled by default.
- Metrics require the bearer token when one is configured.
- 103 tests.

## 0.14.0 — 2026-11-09
- **Provenance enforcement (sycophancy firewall)**: policy effects declare
  `require_data_ref` fields (`payment.send`: `["target","amount"]`, etc.). A
  consequential intent must carry a `data_ref` provenance entry covering each
  required field; `user_pref` and `model_inference` never satisfy it. A
  `data_ref` without `covers` covers all required fields. Missing evidence is
  denied (`ProvenanceMissing` / `missing_data_ref`).
- Provenance is **hashed into the commitment**, so it cannot be swapped after the
  grant. Provenance entries are schema-validated.
- **Breaking:** commitment/receipt hashes change (provenance hash added).
- 100 tests.

## 0.13.0 — 2026-11-09
- **Advisory Telegram notification** in the approver daemon
  (`--telegram-chat`, token from `TELEGRAM_BOT_TOKEN`). The message carries only
  the summary/commitment; it has no approve button or link. The decision still
  happens on the approver host's TTY, so the security property is unchanged.
- **Portable receipt envelope** (`mandate export` / `export-verify`): intent,
  signed grant, hash-chained receipt, optional Merkle inclusion proof, signed
  with an OpenSSH SSHSIG in namespace `mandate-export`. This is a custom
  JOSE-style profile (not strict JWS/C2PA); verifiers use OpenSSH tooling.
- 94 tests.

## 0.12.0 — 2026-11-09
- **Payment adapter**: `provider=sandbox` (SQLite) or `provider=http`. Strict
  idempotency key = grant nonce, `lookup` before charging, and reconciliation on
  timeout. The broker's recovery uses the provider lookup, so a committed charge
  without a receipt is finalized without charging twice; a crash before the
  charge abandons the grant.
- **ERP driver `mssql`** (optional `pyodbc`, `pip install gama-mandate[mssql]`):
  only `SELECT`/`WITH` queries are accepted; SQLite stays `mode=ro`, MSSQL runs
  read-only and rolls back.
- 85 tests.

## 0.11.1 — 2026-11-09
- Privacy: repository is now **private**; example names, vendor names, and local
  domains were removed from the tree and from the package metadata. No personal,
  customer, or vendor data is included. Code unchanged; 78 tests.

## 0.11.0 — 2026-11-09
- **Approver daemon** (`mandate approver serve`): runs on the approver's host,
  recomputes the commitment and render from the intent (it does not trust the
  agent's proposal), shows the summary on its terminal, and signs a grant only
  after the human types `y`. The private key never leaves the approver host.
- **`mandate request --approver URL --intent ...`** client: gets the signed
  grant back (or a rejection). Loopback by default, bearer token for remote,
  256 KiB body cap.
- 7 approver tests + 78 total.

## 0.10.4 — 2026-11-09
- `mandate version` reports the distribution name `gama-mandate`.
- Published to PyPI: https://pypi.org/project/gama-mandate/

## 0.10.3 — 2026-11-09
- PyPI distribution name is **`gama-mandate`**. `agent-mandate` was rejected by
  PyPI as too similar to an existing project (`agentmandate`). Import package and
  console scripts are unchanged (`mandate`, `mandate-broker`, `mandate-mcp`).
- Code identical to 0.10.2.

## 0.10.2 — 2026-11-09
- Published to GitHub: https://github.com/gamai-io/mandate (public, CI green on
  Python 3.9–3.12). Release v0.10.1 with wheel, sdist, and checksums.
- Correct project URLs, README CI/license badges, install-from-git instructions.

## 0.10.1 — 2026-11-09
- Security: the broker requires a bearer token for non-loopback binds
  (`--token` / `MANDATE_BROKER_TOKEN`); broker and witness reject request bodies
  over 256 KiB (413).
- Lint: `ruff` config, clean `ruff check .`, CI lint + build/`twine check`.
- Packaging: `py.typed`, sdist/README install instructions, governance files
  (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `AUTHORS`,
  `RELEASE.md`).
- PyPI name `agent-mandate` verified available (2026-11-09).
- 71 tests.

## 0.10.0 — 2026-11-09
- **Off-host STH witness**: pins the latest signed tree head, rejects rollback
  (smaller tree), rejects split-view (same size, different root), and requires a
  valid consistency proof for growth. State is written atomically (0600).
- CLI: `mandate witness accept | verify | show | serve | push`.
- Loopback HTTP witness with a bearer token (`/sth`, `/state`, `/health`);
  `--allow-remote` required to bind elsewhere.
- 8 witness tests + 68 total.

## 0.9.0 — 2026-11-09
- **Merkle transparency log** over ledger entries (RFC 6962/9162 style):
  `Leaf=SHA256(0x00||JCS(entry))`, `Node=SHA256(0x01||L||R)`, MTH, inclusion
  proofs, consistency proofs.
- **Signed tree head** via `ssh-keygen -Y sign` in namespace `mandate-log`;
  `log_id` is the log key SHA256 fingerprint.
- CLI: `mandate log head | sth-verify | proof | verify-inclusion | consistency |
  verify-consistency`.
- Refuses to build a log over an invalid ledger hash chain.
- 9 Merkle tests + 60 total. Off-host **witness/anchor** is still required to
  rule out split-view; tracked in PLAN.md.

## 0.8.0 — 2026-11-09
- **Effect journal** (SQLite) with a lease-based state machine:
  `intent → executing → executed → receipted`, plus `failed` / `abandoned`.
- **Idempotent write adapter**: `mode=file` or `mode=sqlite` (a trusted SQL
  statement runs in the same transaction as the idempotency insert). The
  idempotency key is the **grant nonce**.
- The authorisation receipt is now appended **after** the effect commits,
  fixing the old "ledger says executed but no effect happened" crash window.
- **Crash recovery on start**: `executing` with a committed effect → finish the
  receipt; without an effect → abandoned; `executed` without a receipt →
  receipted. Duplicate `execute` returns the same receipt/result instead of an
  error.
- Config: `write`, `journal_db`, `lease_s`; `/health` reports journal counts.
- 43 tests (crash-after-effect recovery, crash-before-effect abandon, writer
  failure, concurrent single effect, journal payload mismatch).

## 0.7.0 — 2026-11-09
- Canonicalization is now **RFC 8785 (JCS)**: UTF-16 code-unit key ordering,
  ECMAScript number serialization, minimal string escaping, and strict rejection
  of non-finite numbers, lone surrogates, non-string keys, and integers outside
  the IEEE-754 safe range. Passes the RFC 8785 reference vector.
- **Breaking:** commitment/receipt hashes change (e.g. `1170.0` serializes as
  `1170`). Regenerate grants and ledgers from earlier versions.
- CI: GitHub Actions test matrix on Python 3.9–3.12.

## 0.6.0 — 2026-11-09
- `allowed_signers` now requires an explicit `namespaces="mandate"` scope
  (`namespaces="mandate-broker"` for broker result keys). A key without a scope
  is rejected, so a grant key cannot sign broker receipts and vice versa.
- Validity windows (`valid-after` / `valid-before`) are enforced in Mandate's
  own check and by OpenSSH.
- Key revocation: `mandate revoke --pub key.pub` writes the SHA256 fingerprint to
  `trust/revoked_signers`; `redeem`, `verify`, and `verify-result` reject revoked
  keys. Configurable via `--revoked` / `MANDATE_REVOKED`.
- `mandate signers` lists parsed principals, namespaces, validity, and fingerprints.
- 37 tests (namespace scope, validity window, revocation, revoke CLI).

## 0.5.0 — 2026-11-09
- Grant `audience`: a grant can be bound to one broker (`mandate grant --audience <broker>`).
  The broker verifies `audience == broker_name` and rejects unbound grants by default
  (`--allow-any-audience` to opt out). Closes cross-broker replay.
- Broker-side re-derivation: `erp.derive` re-reads counterparty/amount/currency from the
  source of truth and rejects the effect if the agent's intent diverges
  (`derivation_mismatch`), not just at the precondition amount check.
- 33 tests (audience mismatch, unbound grant, currency derivation mismatch).

## 0.4.0 — 2026-11-09
Security fixes from an independent multi-agent audit (Claude + subagent + web):
- `mandate grant` recomputes commitment/render_hash/proposal_id from the intent and rejects a mismatched proposal (approval-confusion fix).
- `redeem` enforces policy (unknown effects denied) and binds the grant to the agent (`agent` field), closing the actor-swap self-approval bypass.
- CLI/MCP redeem now performs the nonce check and append under one file lock; ledger append is fsync'd and anchored with `<ledger>.head`; `verify_chain` rejects empty or truncated ledgers.
- Intent schema validation: unknown effect/amount fields and non-finite amounts are rejected; `params` must be flat scalars.
- `render` quotes every value (no `|` injection) and includes all params.
- ERP: NaN/non-dict amounts rejected; only `bind_params` can fill query placeholders.
- `execute` refuses non-loopback brokers (unless `--allow-remote`) and does not follow redirects.
- MCP adapter moved into the package and shipped as `mandate-mcp`; `verify-result` validates the signed broker result entry.
- `doctor` fails when signers are missing; `max_uses` is honestly fixed at 1.

## 0.3.0 — 2026-11-09
- Read-only ERP precondition (SQLite `mode=ro`, named-param query, amount tolerance).
- SMTP adapter for `message.send` (`dry_run` default, `live` reads password from env).
- Broker `--config`, `/health` reports `smtp` and `erp`.
- Preconditions run before the nonce claim, so a failed check does not consume the grant.
- Packaging: `pyproject.toml`, console scripts `mandate` / `mandate-broker`,
  `mandate init`, `mandate doctor`, `mandate version`.

## 0.2.0 — 2026-11-09
- Effect broker: `/execute` + `/health`, loopback by default.
- Atomic nonce claim (SQLite `UNIQUE`) prevents double execution.
- `render_hash` bound into commitment and grant (approver signs the rendered summary).
- Signed result entry chained after the authorisation receipt.

## 0.1.0 — 2026-11-09
- Canonical commitment (JCS), stable ids.
- Intent / Grant / Receipt objects.
- Off-host Ed25519 grant via `ssh-keygen -Y sign`.
- One-shot redeem, replay detection, hash-chained ledger, offline verification.
- Agent cannot self-approve; unknown effects denied.
- MCP adapter and agent skill.
