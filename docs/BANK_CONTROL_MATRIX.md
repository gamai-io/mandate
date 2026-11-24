# Bank control matrix — what we can prove, what we cannot (yet)

Status: 24 Nov 2026. Basis: the twelve control rows in the internal research
dossier (83 sources with URLs, each claim dated).
**Legal statements here are research, not legal advice — verify with counsel before
putting any article number in a customer document.**

## Corrections that change the pitch

| Common assumption | Reality (verified in research) |
|---|---|
| "SR 11-7 model risk applies to agents" | SR 11-7 was superseded in Apr 2026 (SR 26-2 / OCC 2026-13 / FDIC FIL-15-2026) **and generative/agentic AI is expressly out of its scope**. Do not pitch SR 11-7 to a US bank. |
| "AI Act Art. 12/14/26 apply from Aug 2026" | High-risk duties were postponed by Reg. (EU) 2026/1744 (Digital Omnibus, in force 27 Jul 2026) to **2 Dec 2027** for Annex III. |
| "Every bank agent is high-risk AI" | Annex III 5(b)/(c) is creditworthiness scoring of natural persons and life/health insurance pricing. A payments-reconciliation or fraud-triage agent is **out of scope of the AI Act**; **DORA is the binding hook**. |
| "SOC 2 covers agents" | The current TSC contains **no AI criterion**; the 2027 exposure draft adds AI only as points of focus. |

**The hook to quote instead:** DORA Level 2 RTS (Reg. 2024/1774)
— Art. 12(2)(d): logs protected against tampering, deletion and unauthorised
access; Art. 21(2)(c): no shared accounts, users identifiable for actions "at all
times"; Art. 23(3): anomaly records protected against tampering. Plus AI Act
Art. 26(5)/(6) and 72(4) let a financial institution fold AI monitoring and log
retention into its existing financial-sector documentation.

## Matrix

Legend: **have** = shipped and tested; **partial** = exists but not to the standard
an auditor would accept; **gap** = not built.

| # | Control | Our artifact today | Status | What is missing | Effort |
|---|---|---|---|---|---|
| 1 | Agent inventory, owner, model version | `mandate init` creates config; receipts carry agent, commit, version | partial | a register export: agent → owner → scopes → last seen, reconciled with IdP | 3 d |
| 2 | Unique non-human identity, no shared creds | grant binds a named approver; agent key separate (`examples/05`) | partial | short-lived workload identity (SPIFFE/JWT) instead of a local key file | 3 d |
| 3 | Delegation chain, attenuated scopes | intent records `actor.agent`; grant binds one agent + one audience | partial | signed chain originator → agent → sub-agent, scopes only narrow | 4 d |
| 4 | **Human approval of a specific effect, attributable** | **have**: Ed25519 grant over the canonical commitment, one-shot nonce, receipt with approver + render hash; four-eyes refused (exit 3) | **have** | approval over a *human-readable render* is there; add WebAuthn/FIDO2 for the approver device | 3 d |
| 5 | Kill switch, tested time-to-halt, safe state | **`mandate warden` (freeze/kill from outside, polls `/proc` until `T`, measures time-to-halt, writes a control record) + `halt`/`resume` in the ledger** | **have (partial)** | cgroup-freezer path by default, VM pause (Firecracker), network quarantine, proof of a *safe state* beyond "process not running" | 6 d |
| 6 | Policy outside the model, deterministic | `gamai-plugins` trust plugin: deny wins, fail-closed, exit codes | **have** | joined decision log per tool call with policy version | 1 d |
| 7 | Software-enforced limits (spend, velocity, volume) | `limits` in policy: effects/hour, amount, runtime, currency — enforced at redeem, refusals in the ledger | **have** | per-tool data-volume caps; cost accounting | 2 d |
| 8 | Egress control | **`mandate egress` (deny-all proxy, token, allowlist, metadata/SSRF guard, every decision in the ledger) + red-team demo** | **have (partial)** | enforcement at network layer (namespace/VM rules) so a raw socket cannot bypass the proxy; DNS pinning | 4 d |
| 9 | **Tamper-evident, agent-inaccessible log, retention, clock** | hash chain + `.head` + `mandate chain`; **`mandate anchor` (RFC 3161, verified with `openssl ts`, FreeTSA OK); `mandate worm-export` (0444 + manifest + retention + clock snapshot)** | **have (partial)** | bank-held key (HSM/PKCS#11), object-lock storage instead of local chmod, clock attested by a third party | 5 d |
| 10 | Change control over prompts/models/permissions | receipts carry commitment + render hash, so a changed prompt changes the hash | partial | tie diffs to change tickets and approvals; model version pinning | 3 d |
| 11 | Third-party register / due diligence | Apache-2.0 code, published artifact, spec, `CITATION.cff` | partial | DORA RoI row, subprocessor list, exit/transition plan, DD pack | 3 d docs |
| 12 | Detection & reporting of agent incidents | `gamai-trust` claim-vs-evidence; `crossnode-bench` false-success rate | partial | agent-specific detection rules (credential switching, unusual tool sequences, volume spikes) | 4 d |

## What the market research says about the wedge

- Agent gateways (Okta, Google, Auth0, Datawiza, Solo, TrueFoundry) all shipped
  between Mar and Oct 2026 — **do not build another gateway**.
- The closest product to row 4 is HYPR AgentPass (18 Nov 2026): FIDO2 passkey
  signs the exact action on a separate device. It closes the "specific human
  authorised this effect" half; whether its export is a standard receipt is
  undisclosed.
- **Row 9 (tamper-evident, third-party-verifiable evidence) has no credible
  vendor.** NIST's 27 Oct 2026 agent-identity tenets name signed mandates and
  immutable evidence as "not immediately fulfilled by the current state of
  standards and technology".

## What we must not say

- "DORA / AI Act compliant" or "certified" — compliance is the bank's obligation.
- "Tamper-proof" — the chain is tamper-*evident*; whoever holds the key and the
  log can rewrite the whole chain unless an external anchor exists.
- "Prevents sandbox escape" or "prevents prompt injection".
- "Kill switch guarantees the agent stops" — only for calls routed through us.
- "SR 11-7 compliant" (see corrections above).
- Reuters reports as proof that our product works.

## Next four builds, in order

1. `mandate anchor` — RFC 3161 timestamp over the ledger head, verified offline (**2 d**).
2. WORM export + retention schedule + clock evidence (**2 d**).
3. Limits and allowed-systems **inside the grant**, not only in policy (**3 d**).
4. Register export (`mandate inventory`) + agent-specific detection rules (**4 d**).

Together they move rows 9, 5, 7 and 12 from *partial* to *auditable*, which is the
only thing a supervisor actually accepts.
