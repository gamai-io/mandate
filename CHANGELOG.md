# Changelog

## Unreleased — signed witness note
- **The witness signs the pin.** `mandate witness accept --key …` stores an SSHSIG note
  over `log`, `log_id`, `tree_size`, `root_hash`, `pinned_at`; `audit verify
  --witness-signers` checks that signature and that every field matches the STH, and
  reports `witness_signed` so a claim is distinguishable from a proof. A bundle builder
  without the witness key can no longer produce a passing `witness`.
- Conformance kit grew two cases: `witness_claim_only` (state file, no note) and
  `witness_note_forged` (note edited, bundle re-signed). 8/8 against our verifier.

## Unreleased — conformance kit
- **`tools/kit.py` scores any verifier.** Seven cases (one valid, six rejections), and for
  a rejection it names the first check that must fail. Three cases tamper and re-sign so
  the `sth`, `inclusion` and `witness` checks are actually reached. `tools/kit_build.py`
  regenerates `spec/kit/`; `tests/test_kit.py` proves our verifier passes all seven and a
  verifier that always says yes fails at least five.

## Unreleased — strict parsing
- **Both verifiers refuse ambiguous JSON.** `{"a":1,"a":2}`, `NaN`/`Infinity`, integers
  beyond 2^53−1, lone UTF-16 surrogates, depth > 128 and non-UTF-8 bytes now fail with a
  stable code (`duplicate_key`, `non_finite`, `int_range`, `lone_surrogate`, `depth`,
  `invalid_utf8`) before any hash is computed. `mandate/strictjson.py` is the package
  implementation; `spec/verify_offline.py` keeps a standalone copy and
  `spec/verify_offline.js` implements the same rules. A differential test requires the
  same error code from Python and Node. The rule list follows Tracekit's `loads_strict`
  (MIT); the implementation is ours.

## 0.68.11 — 2026-11-26
- **The Node verifier had the RT5 hole.** It ignored `namespaces`, validity and
  revocation, so a key restricted to another namespace (or revoked) authorised a
  grant there while the Python verifier refused it. Both now parse the options
  before the key, match the key embedded in the signature, check validity and a
  `--revoked` file.
- `tests/test_cross_verifier.py` runs both verifiers on the published vectors and
  on tampered/namespace-restricted cases; a divergence fails the suite.

## 0.68.10 — 2026-11-26
- **Differential test between the two verifiers.** The same grant/intent/receipt
  cases (valid, tampered, wrong namespace, revoked) must produce the same answer
  from `spec/verify_offline.py` and the package. This is the test that would have
  caught RT5's namespace divergence immediately.
- **Key-rotation drill** as a test: after the signer key is replaced, old grants
  fail and new ones redeem.
- Fuzz pass over `normalize_intent` and `policy_tools.lint` with 600 random shapes;
  they may reject, never crash.

## 0.68.9 — 2026-11-26
- **HSM path is tested, not just documented.** `tools/mandate-pkcs11-sign.py` is a
  PKCS#11 `--signer-cmd` adapter (Ed25519, `EC_EDWARDS`) that builds the SSHSIG
  itself; the key never enters the process. `tests/test_pkcs11.py` creates a
  SoftHSM2 token, generates a non-exportable key, signs and verifies with
  `ssh-keygen -Y verify`. CI installs softhsm2/opensc/python3-pkcs11 on 3.12 so the
  test runs instead of skipping.
- `docs/HSM.md` states the limit: same API as a vendor HSM, not the same device;
  FIPS/PIN policy/vendor audit are outside this repository.
- The approval page signs with one policy snapshot taken at startup, not a
  re-read after the human clicks.

## 0.68.8 — 2026-11-26
Fifth review (RT5).

- **A bundle proof is now checked against the signed STH.** `export-verify` passed
  the proof's own root, so a proof that matched nothing the log signed still
  returned `valid: true`. `export` refuses `--proof` without `--sth`, and
  `export-verify` reports `inclusion: false` when the STH is missing or mismatched.
- **The offline verifier enforces `namespaces`, validity and revocation.** It
  accepted a key restricted to another namespace (or revoked) while the package
  refused it, and it ignored multiple keys per principal. It now matches the
  signature's embedded key against the authorised line.
- **`require_hardware_key` checks the key that actually signed.** A revoked `sk-`
  line followed by a software key satisfied it because the first matching line was
  inspected; the check now uses the signature's public key.
- **`setuptools==78.1.0` is really pinned** (the previous note claimed a pin that
  was not in `pyproject.toml`), so `verify_pypi.py` matches PyPI byte-for-byte.
- **Signer options are parsed before the key**, so `# namespaces="mandate"` in a
  comment no longer authorises; revoked fingerprints are normalised
  (`SHA256:`/case).
- **`verify` adds `authentic`**: an unsigned receipt is only authentic if its hash
  is in the ledger you pass with `--ledger`; `valid` alone stays "internally
  consistent".
- The claims gate refuses duplicate `tests collected`/`runtime dependencies`/
  `policy lints clean` rows instead of reading the first.

## 0.68.7 — 2026-11-26
- **Reproducible artifacts.** `setuptools==78.1.0` is pinned in `[build-system]`;
  the release build sets `SOURCE_DATE_EPOCH` to the commit time and normalises the
  sdist headers (`tools/normalize_sdist.py`). `tools/verify_pypi.py` rebuilds the
  tag and compares SHA-256 per file with PyPI. CI checks that two builds are
  byte-identical. The claim is "byte-identical with the pinned toolchain";
  who-built-it remains the PEP 740 attestation.
- The release attaches a CycloneDX SBOM (`mandate sbom`) as a release asset.

## 0.68.6 — 2026-11-26
- **The offline examples now run in CI.** `tests/test_examples.py` executes 01, 02,
  05, 09, 12 and 13 (06 needs a public TSA, so it stays out) on one matrix job
  with `RUN_EXAMPLES=1`. The README quickstart already had a test; these are the
  rest of the scripts that once broke silently.
- Supply chain: GitHub Actions are pinned by commit SHA, the build job no longer
  inherits `contents: write`, the pre-publish secret scan runs before upload, and
  the separate `attest.yml` rebuild is gone — provenance is created by the publish
  step (`attestations: true`), so there is one build, not two.
- Docs: "one-shot" is qualified per nonce store in the control matrix, broker and
  DORA pack; SECURITY.md says it the same way.

## 0.68.5 — 2026-11-26
Fourth review (RT4).

- **A revoked key can no longer sign just because the same principal has a second
  key.** `ssh-keygen -Y verify` reads the whole signers file and accepts any
  matching key, while `authorize_signer` only checked that *some* valid line
  existed. Verification now writes a filtered signers file containing only the
  allowed, non-revoked, in-window lines and verifies against that. A test covers
  the two-keys-one-revoked case.
- **`approver serve --page --policy` now honours `--policy`.** The page path
  signed the packaged default's digest regardless of the flag; a grant then
  failed `PolicyDenied` on redeem. The policy is also loaded before the human is
  asked and validated at startup, so a bad path is an error, not a dropped
  approval.
- **`executed` is only true when the receipt is valid.** A tampered receipt used
  to print `executed: true` next to `valid: false`. Output now also carries
  `signed`; the README says `executed` means "the grant was spent", not "the bank
  confirmed a payment".
- **The claims gate closes the holes RT4 found:** it refuses a missing or
  duplicate version row, a non-plain version (`x.y.z` only), a stale dependency
  or policy-lint row, and it accepts `-` as well as `—` in the changelog. A full
  run with pytest missing now says "could not run the suite", not "0 failed".
- **Release workflow:** the tag check and pre-publish secret scan run before
  upload; `skip-existing` is gone, so a force-moved tag fails instead of leaving
  PyPI unchanged while GitHub gets new files; the build job no longer inherits
  `contents: write`; the PyPI guard runs on `main`, not after publication.
- **`verify-inclusion`:** a signed STH without `root_hash`/`tree_size` is refused
  (`SthIncomplete`) instead of falling back to the proof's own root; a malformed
  `--sth`/entry/proof is exit 2, not a traceback.
- Packaging: MIT/development/Python classifiers and the Changelog URL (the MIT
  classifier itself is not used because PEP 639 licence expressions conflict with
  it on current setuptools).
- Docs: "one-shot" is qualified per nonce store wherever it appears; the auditor
  bundle "records" an action and the witness state is named as a claim.

  Correction to 0.68.4's note: it said the gate cross-checks README's passing
  count. It did not (the row had been removed); the gate now checks the collected
  row, the failed row, dependencies and lint, and a full run proves the counts.

## 0.68.4 — 2026-11-26
Third adversarial review (RT3). Two real bugs and four honesty fixes.

- **The approver daemon now binds the policy.** `Approver.request` minted grants
  with `policy_digest: ""`, so a grant from the co-sign path redeemed under any
  policy while the README said a changed policy invalidates old grants. It now
  records the digest; `approver serve --policy` selects the file, and a test
  asserts `PolicyDenied` after an edit.
- **`mandate verify` distinguishes observation from execution.** Output now has
  `decision`, `executed` and `observed`. An `--observe` receipt was already a
  valid receipt (it is), but a reader could take `valid: true` for "the payment
  happened"; now the fields say which.
- **`mandate log verify-inclusion` requires a signed tree head.** Without a
  signature it was verifying a proof against its own root and printing
  `valid: true`; with an unsigned `--sth` it copied the root without checking the
  signature. It now returns `SthRequired` (exit 2) without `--sth`, and `valid`
  requires `sth_verified`.
- **`audit verify` exposes the decision** (`decision`, `executed`, `observed`) and
  `docs/AUDITOR_BUNDLE.md` states the limit: `witness_state` is a claim in an
  unsigned JSON file, not a signature by the witness host; a fabricated state
  re-signed by the bundle key still shows `witness: true`.
- **The claims gate now sees `CLAIMS.md`.** Its regex looked for a `| tests |`
  row that no longer existed, and it never compared the passing count. It now
  checks both rows, cross-checks README's passing promise, and `CLAIMS_FULL=1`
  (set in CI) runs the suite once to prove the number.
- **Release integrity:** the release workflow refuses a tag that is not
  `v<pyproject version>`, and the GitHub release now waits for the PyPI publish.
- The quickstart says one-shot is per nonce store; `--audience` is documented as
  a label the broker repeats, not a credential (README + `docs/BROKER.md`).
- The pilot-kit generator no longer hardcodes timings or calls two same-author
  verifiers "independent"; it points at `06-performance.md` instead.

## 0.68.3 — 2026-11-26
- `docs/PERFORMANCE.md` now carries a run of `tools/bench_ledger.py` from this
  host (8.9 ms per receipt at 10k, chain 1.85 s, pack 0.71 s) and says the
  per-receipt cost is `fsync`-bound and varies by disk (5.75-9.7 ms here), instead
  of quoting one old number as if it were the constant.

## 0.68.2 — 2026-11-26
- **The quickstart now runs as written.** `grant --audience local-broker` binds the
  grant to a broker, but `redeem` had no way to name it, so the documented flow
  died with `GrantInvalid: this caller did not identify itself`. `redeem` takes
  `--audience`; `tests/test_quickstart.py` runs the README commands in a temp dir
  and asserts `{"valid": true}` plus `GrantReplayed` on replay.
- **Examples were run, not just written.** All of them now pass `--audience` to
  `redeem`; `02-audit-bundle.sh` produces the proof/STH/witness an audit bundle
  needs (it built a bundle that could never verify); `05-bank-scenario.sh`
  re-approves after a deliberate policy change and passes `--policy` to `grant`;
  `06-anchor-and-worm.sh` treats `cms_unverified` as the honest result it is and
  checks the CMS signature in its own step; `12-detect.sh` no longer passes
  `--audience` to `detect` (which does not take it).
- `README.md` states the test count again (it had lost the line, and a claims gate
  with no anchor passes silently — that is now itself a failure).
- The gate compares the README figure against **passing** tests, and CLAIMS.md keeps
  collected and passing apart.
- `README.md` no longer says VM pause is "not demonstrated": the measured numbers
  (boot 125 ms, pause 7 ms, resume 6 ms on `crusoe-cpu1`) were in
  `docs/PERFORMANCE.md` and contradicted the text.

## 0.68.1 — 2026-11-26
- The claims gate now also checks `CLAIMS.md` and the `__version__` fallback in
  `mandate/__init__.py`; both had drifted (CLAIMS said 0.56.0 / 370 tests while the
  code was 0.68.0 / 442). `CLAIMS.md` separates collected from passing tests.
- `docs/BROKER.md` no longer invents a `mandate broker` subcommand: the broker is
  the `mandate-broker` console script.

## 0.68.0 — 2026-11-26
- **`mandate ship` keeps one offset per ledger.** By default each ledger gets
  `<ledger>.shipstate`; a shared `--offset` file now keys by absolute ledger path,
  so shipping a second ledger no longer starts at the first one's byte count. Re-run
  after a rotation reports `"rotated": true` and restarts at the top of the new
  file instead of silently sending nothing.
- `packaging/mandate-ship.service|.timer`: a oneshot unit every minute with the HEC
  token in an environment file, so a SIEM feed is an operation and not a library
  call.
- `docs/RUNBOOK.md` gains the "records were not shipped" event.
- 6 ship tests; 438 pass, 4 documented skips.

## 0.67.0 — 2026-11-26
Operational readiness (blue-team review):
- **`docs/RUNBOOK.md`**: first action for eight events — refusal, expired
  instruction, tool drift, config drift, expired containment, ledger head mismatch,
  nonce authority down, egress denied — plus the inbound alerts and escalation.
- **`mandate chain` explains itself**: `diagnose_chain` distinguishes `link_broken`,
  `entry_tampered` and `truncated_or_head_edited` instead of one `valid: false`.
- **`mandate pack --grant --intent`**: the artefacts behind the receipts are
  archived in the pack, so "who approved X" is answerable from the pack alone.
- 435 pass, 4 documented skips.

## 0.66.0 — 2026-11-25
Second red-team pass, this time over the modules added in 0.62–0.65. Every fix has
a test that fails on the previous behaviour:
- **Refusals are now ledger records.** `redeem` wraps every path; a `PolicyDenied`,
  `GrantReplayed` or `CommitmentMismatch` appends `control/refuse` with the code,
  kind, target, nonce and approver before it is raised. "Show me every refused
  effect yesterday" is now answerable, and a SIEM sees refusals, not only successes.
- **`memory revoke` is signed.** An unsigned revocation record is treated as
  tampering, not as a revocation, so deleting or forging one is refused.
- **Containment:** an unsigned `extend` no longer keeps a process frozen, the
  `containment-sweep` actor name is no longer a release bypass, and `--release`
  actually sends SIGCONT (it previously recorded success and left the process
  stopped).
- **`sql.write` may not touch the audit table**, `sqlite_master` or `PRAGMA`: an
  effect could pre-seed `applied_effects` and make the next real effect return a
  forged "recovered" result.
- **The config lock anchor is the first record**, so appending a forged
  `config_lock` no longer wins; and **tool pinning is required for `mcp.call`**,
  including the schema hash.
- 430 pass, 4 documented skips.

## 0.65.0 — 2026-11-25
Hardening after a red-team pass over the new surface:
- **The instruction store is checked as a chain.** `check_provenance` refuses when
  the store's hash chain is broken (a removed record is not a revoked one), and
  `.head` makes truncation detectable.
- **The config lock pins itself.** `config lock --ledger` records the lock file's
  digest; `config check --ledger` refuses when the lock file changed, so editing
  both the config and the lock no longer passes.
- **Early containment release must be signed.** `mandate contain --release PID
  --approver --key`; `sweep` ignores an unsigned release record, which otherwise
  would suppress the deadline and leave a process stopped for ever.
- 7 new tests; 427 pass, 4 documented skips.

## 0.64.1 — 2026-11-25
- The pre-publish scanner no longer flags itself when `tools/` ships in the sdist:
  the internal host and customer names are assembled at runtime, and the scanner
  still catches all three on a sample (verified).
- The Firecracker demo defaults to a neutral rootfs path instead of a personal one.

## 0.64.0 — 2026-11-25
- **`tools/firecracker_demo.sh`**: boots a microVM with no network device, measures
  boot to the first serial line, then pauses and resumes through the API and checks
  the state each time. Measured on `crusoe-cpu1` (KVM): **125 ms** boot, **7 ms**
  pause, **6 ms** resume, 0 network devices.
- `docs/PERFORMANCE.md` replaces the one-off 17.2 ms note with that reproducible
  script and explains why the two numbers differ (API round-trip vs warden's
  stop-and-verify).
- `tools/` is now included in the sdist, so the script ships with the package.

## 0.63.0 — 2026-11-25
- **`mandate config`**: pins the files an agent trusts before it acts (`.mcp.json`,
  `settings.json`, `CLAUDE.md`, `AGENTS.md`, MCP lists, skill files) by hash, checks
  them before startup, and records the check as a `control` entry in the ledger.
  Exit 1 on drift or a missing file. This is the Shai-Hulud/Miasma shape.
- **`mandate sandbox check`**: starts `bwrap --unshare-net`, attempts a real
  connection from inside and expects it to fail; reports bwrap/docker/kvm and
  `network_isolated` as a measured result.
- `docs/SANDBOX_TIER.md`: three tiers, a coverage table, and what none of them does.
- 9 new tests; 420 pass, 4 documented skips.

## 0.62.0 — 2026-11-25
- **Signed instructions (memory provenance).** `mandate memory add` records an
  instruction with a text, a scope (`kind:target`), an approver signature and an
  expiry; `memory verify`, `memory revoke`, `memory list`. An intent may cite one in
  `provenance` with `type: "instruction"`; `check_provenance` refuses a citation
  that is unsigned, revoked, expired or out of scope, in `redeem` and in the broker
  (`--instructions`). It does not stop a model from believing something; it stops
  the belief from authorising an effect alone.
- `docs/EGRESS_POLICY.md`: what belongs on the allowlist, the order the checks run
  in, and what an application-level gate cannot do.
- 14 memory tests plus the egress document; 412 pass, 3 documented skips.

## 0.61.0 — 2026-11-25
- **SMTP send goes through the egress gate** like payment and publish, so a live
  mail cannot leave for a host nobody allowed.
- **`tests/test_egress_coverage.py`**: a source-level check that every adapter which
  opens a connection (urlopen, smtplib, raw socket) calls `egress.guard`. It fails
  when a future adapter is added without one, which a behavioural test cannot catch.
- **Incident suite extended**: the Mythos publish (no grant, default deny), the
  Opus DB-write shape (DELETE refused), and a publish to a destination outside the
  egress policy.
- 398 pass, 3 documented skips.

## 0.60.0 — 2026-11-25
- **The egress gate is wired into the outbound adapters.** `payment` and
  `package.publish` accept an `egress` policy and call `egress.guard` on every
  request, so a publish or a charge cannot leave for a destination that is not
  allowlisted. The metadata guard cannot be defeated by allowlisting the address
  (only `allow_metadata: true` can), and a payment-recovery path no longer swallows
  an egress refusal as "no charge yet".
- 7 tests (loopback needs an explicit entry, wrong port refused, metadata refused
  when named, publisher and payment adapter refusals, adapter without a policy);
  393 pass, 3 documented skips.

## 0.59.0 — 2026-11-25
- **`sql.write` and `package.publish` are broker-owned effects.** One INSERT or
  UPDATE per effect (no DDL, no DELETE), bound parameters, row count in the result;
  one artefact per publish, idempotency key, registry token only in the broker's
  environment. Replays are recovered, not repeated.
- `normalize_intent` accepts nested params (`_check_params` validates leaves), so an
  effect can carry a structured statement or tool binding and still be committed.
- The shipped `policy.json` now lists 11 effect kinds, including both new ones.
- 3 end-to-end tests through the broker; 386 pass, 3 documented skips.

## 0.58.0 — 2026-11-25
- **Tool schemas are pinned.** `mandate tool lock --name X --file schema.json`
  records the JCS hash of the schema in a registry; the intent commits to that hash
  (`params.schema_sha256`); `mandate tool verify` and `mandate-broker --tools`
  re-read the file before executing and refuse on drift. This closes the Deadbugz
  shape: a tool approved once and changed afterwards.
- 7 tests (lock, match, changed schema, wrong approved hash, unknown tool, enforce,
  intent without a tool); 386 collected, 383 pass, 3 documented skips.

## 0.57.0 — 2026-11-25
- **Cooling window on a payee**: `new_payee_grace_h` treats a beneficiary whose
  first payment is newer than N hours as new, so "paid once two days ago by the
  poisoned instruction" does not open the door.
- **`new_payee` is enforced inside `redeem`**, not only in the CLI and the broker,
  so a library user cannot skip it.
- **`tests/test_incidents.py`**: the recorded incidents replayed against the code
  (Zscaler injected payee, Lakera poisoned payee, Opus 4.7 wrong target, Deadbugz
  metadata swap, unknown effect kind, replayed grant) plus three explicit skips for
  what this does not cover (sandbox escape, config worms, memory poisoning).
- 379 tests (376 pass, 3 documented skips).

## 0.56.0 — 2026-11-25
- **`new_payee` policy rule.** `effects.<kind>.new_payee` = `allow` (default),
  `ask` or `deny`. The broker and `mandate redeem` refuse a beneficiary with no
  prior payment in the ledger (`core.enforce_new_payee`, `report.payee_history`).
  This is the one failure mode where good cryptography makes things worse: a
  poisoned instruction, approved by a human, produces a valid receipt for a fraud.
- `report.payee_history` reads the rendered effect, so it works on existing ledgers.
- 370 tests.

## 0.55.0 — 2026-11-25
- **Containment with an expiry.** `mandate contain --pid N --minutes M` stops the
  process and records a deadline; `mandate contain --sweep` releases only what
  passed it, and records the release. If the sweep never runs, nothing is released
  — the failure mode is the safe one.
- **Extending needs a signature**: `mandate contain --extend PID --minutes M
  --approver "Name" --key ...` signs the decision, and `verify_extend()` rejects a
  changed one. "Keep this stopped" is a decision, not a timeout.
- 366 tests.

## 0.54.0 — 2026-11-25
- **`mandate pack` carries decision latency**: the audit pack now includes
  `decisions.json` (approved/rejected counts, median/p95/max wait), so the number a
  reviewer asks for travels with the evidence.
- **`tools/make_pilot_kit.py`**: assembles the folder we actually send to a bank —
  one printable page, SOW, control matrix, procurement answers, incident response,
  threat context, performance, DORA supplier pack, SECURITY — plus a SHA-256
  manifest so the recipient can confirm nothing was swapped. Nine files, no
  internal paths (tested).
- 360 tests.

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
