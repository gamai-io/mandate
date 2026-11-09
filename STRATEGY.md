# Strategy — what to build next

**Decision:** build the **Mandate Agent Firewall** on top of the existing Mandate
core: an MCP/agent gateway that enforces the *decision boundary*, pins tool
artifacts, tracks taint, runs untrusted tools in a sandbox and emits the same
signed receipts. Prove it with an **Intent Divergence Benchmark** at scale.

## Why (gap map)

Research across incidents, model-failure taxonomies and market analysis shows
the same eight gaps:

1. Deterministic taint/dataflow: untrusted content (web, email, RAG, MCP output)
   can reach a privileged tool (the "lethal trifecta").
2. MCP/tool manifest integrity: tool poisoning and rug-pull after approval.
3. Approval bound to the exact effect (TOCTOU: approved ≠ executed).
4. Agent identity and ephemeral, attenuating capabilities.
5. Provenance of artifacts: `SKILL.md`, MCP manifests, packages.
6. Memory/RAG integrity and per-record revocation.
7. Cross-agent trust and capability attenuation.
8. Tamper-evident audit and a kill switch outside the model.

Incumbents solve model policy, network egress or workload identity. **Nobody
owns the semantic decision boundary** — the moment an agent proposes a
consequential action (pay, send, delete, deploy, sign). That is where Mandate
already sits.

## Architecture

```
agent / MCP client
        │
  Mandate Agent Firewall
   ├─ manifest gate      signed MCP/skill manifest, hash pin, rug-pull deny
   ├─ taint gate         untrusted source → effect requires data_ref + co-sign
   ├─ sandbox runner     untrusted MCP server/tool in Firecracker or gVisor
   ├─ effect broker      Mandate grant, idempotent journal, payment/SMTP/ERP
   └─ evidence           receipt, hash-chain, Merkle log + off-host witness
```

- **Manifest gate**: `mandate.lock` (issuer, version, hash of tool descriptions
  and binaries). Any change is a diff and a deny until re-approved.
- **Taint gate**: every value carries a source class (`untrusted`, `data_ref`,
  `model_inference`). `untrusted` never reaches `payment.send`,
  `message.send` or `file.export` without a covering `data_ref` and a grant.
- **Sandbox**: untrusted MCP servers and tools run in the lab's Firecracker or
  gVisor sandboxes; the gateway talks to them over a narrow RPC.
- **Evidence**: every effect still produces a grant + receipt + Merkle log entry;
  a second host pins the signed tree head.

## Evidence / moat: Intent Divergence Benchmark

Measure whether an agent's *actions* match the user's *intent* when adversarial
content is present:

- prompt injection → effect, sycophancy → action, TOCTOU, cross-agent
  propagation, rug-pull, memory poisoning.
- generate and execute thousands of scenarios in a batch GPU cluster; publish
  the harness, the scenarios and the results.
- metrics: PI-ASR (0% on irreversible effects), taint violations (0),
  manifest tamper (100% deny), overhead (<5 ms/call), receipt coverage (100%).

## Phases

1. **MCP proxy + manifest pinning** (local): hash/sign tool manifests, detect
   rug-pull, emit a deny. Acceptance: tool-poisoning PoC blocked; <5 ms overhead.
2. **Taint gate** + Mandate effects: untrusted source → consequential effect is
   denied unless a covering `data_ref` and co-sign exist. Acceptance: injection
   suite cannot trigger a payment/message/export.
3. **Sandbox runner**: execute untrusted MCP servers in Firecracker/gVisor;
   acceptance: escape suite fails, no host access.
4. **Intent Divergence Benchmark**: 2k scenarios locally, then 10k on a
   LUMI-class batch GPU cluster; publish results and the harness.
5. **Off-host witness + auditor bundle**; ephemeral capability tokens.

## Non-goals

- Another LLM judge or regex filter as the primary control.
- Full browser WebAuthn (FIDO2 `sk-ssh-ed25519` is the substitute).
- Blockchain, compliance scores without adversarial tests.
- Approval for every low-risk action (alert fatigue).
