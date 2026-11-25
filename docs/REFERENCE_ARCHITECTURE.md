# Reference architecture

Status: 2026-11-25, `gama-mandate` 0.56.0. This document describes how the pieces
fit in a bank, what is shipped, and what is a gap. It is written for a platform
team that has to schedule work, not for a quickstart reader.

## Principles

1. **No runtime dependencies.** The library is standard-library Python; the only
   external programs it calls are `ssh-keygen`, `openssl`, `nft` and `curl` (for
   the Firecracker API). That is deliberate: an auditor can rebuild it.
2. **Fail closed.** Missing policy, unreachable nonce authority, unparsable
   anchor, absent token — each is a refusal, not a pass.
3. **Evidence outlives the vendor.** Apache-2.0/MIT code, a published format,
   an offline verifier, and a pack that contains the ledger it describes.
4. **The agent is not trusted.** Every consequential effect passes through a
   broker or proxy that holds the credential; the agent holds a short-lived token.

## Topology A — single host (pilot / lab)

```
 agent ──(SVID, 1h)──► mandate broker ──► effect (dry-run dir / SMTP / ERP check)
                          │  │
                          │  └── ledger.jsonl (+ .head) ──► mandate pack
                          └── anchors/ (RFC 3161, ≥2 TSAs)
 nonce: SQLite next to the ledger
 stop:  mandate warden --pgid / --cgroup
 egress: mandate egress proxy (:3128, bearer token)
```

Sizing: 2 vCPU / 2 GB is enough for the pilot; the ledger is append-only JSONL
(~1 KB per effect).

## Topology B — bank-grade

```
                    ┌──────────── IdP (Entra ID / Okta) ────────────┐
                    │  human approver authenticates + MFA           │
                    └───────────────┬───────────────────────────────┘
                                    │ (1) approval
   agent ──SVID──► [ broker / mcp proxy ] ──► effect system (ERP, payment, mail)
      │                    │        │
      │                    │        └── egress proxy (deny-all + allowlist)
      │                    │
      │                    ├── ledger (append-only, WORM via object lock)
      │                    ├── anchors ──► 2–3 external TSAs (+ local TSA if air-gapped)
      │                    └── alerts ────► SIEM (Splunk HEC / Sentinel DCR)  [gap]
      │
      └── short-lived token issued by [ SVID issuer ]  [gap: today `mandate svid issue`]

 nonce authority: `mandate nonce serve` (single instance, HA via shared DB) [shipped 0.38]
 approver keys: HSM / PKCS#11                                  [gap: file keys today]
 stop: cgroup freeze on the agent's unit, or Firecracker pause  [shipped, proven on KVM]
```

### Integration points, and the honest status

| Integration | Shipped | Gap / what the bank must add |
|---|---|---|
| **Approver identity** | Ed25519 key signs the commitment; principal name in `allowed_signers` | Bind the key to an IdP session (OIDC `sub`, MFA method, device). Today the receipt names a key, not a verified person. |
| **Key custody** | `ssh-keygen` keys, `sk-` hardware keys, **and `--signer-cmd`**: the bank's HSM/KMS adapter receives the canonical payload on stdin and returns `{sig, signer}` with an SSH-armored signature. Verification is unchanged (`allowed_signers`); we never see the key. | A native PKCS#11 provider inside the process (the adapter is a separate binary today). |
| **Agent identity** | `mandate svid issue/delegate` (TTL ≤ 1 h, audience, scopes) | Issue from the bank IdP/SPIFFE instead of a local key; wire `revoked_signers`. |
| **Nonce authority** | `mandate nonce serve` + `MANDATE_NONCE_URL` | HA (shared Postgres/Redis behind the same HTTP contract). |
| **Log shipping** | `mandate ship` → Splunk HEC style endpoint, offset state, fail-closed on rejection | Sentinel needs a small relay (Logic App / DCR) in front of the same endpoint |
| **WORM** | `worm-export` (0444 + manifest) | Object lock (S3 Object Lock, Azure immutable blob) or WORM appliance. |
| **Anchoring** | `anchor --tsa` (repeatable), `anchor-verify --ca` | A second, independent TSA the bank trusts; air-gapped deployments need a local TSA. |
| **Stop** | `warden` (SIGSTOP, cgroup, cgroup.kill, VM pause, uid quarantine) | Map to the bank's own unit names; cgroup delegation (`Delegate=yes`) on the agent's systemd unit. |
| **Detection** | `mandate detect` rules over the ledger | Tool-level events (which tool, which host) for sequence anomalies; SIEM correlation rules. |
| **Policy** | `policy.json` (`effects`, `limits`, `detect`) | Policy authoring/review workflow; the file is hashed and signed by `change record`. |

## Failure modes

| Failure | Behaviour | What the operator sees |
|---|---|---|
| Nonce authority down | redemption refused (`NonceUnavailable`) | `exit 3`, message names the store |
| All TSAs down | ledger still valid, no new anchor | `anchor` returns an error; chain stays verifiable |
| Anchor file lost | verifiable only up to the next anchor | `anchor-verify` says `cms_unverified`/`missing` |
| Ledger `.head` deleted | truncation is not detectable from the file alone | `chain --signers` reports; anchors catch it |
| Broker killed mid-effect | journal replays or marks failed | broker log + `mandate log` |
| Approver key compromised | revoke in `trust/revoked_signers` | future grants fail verification |
| Agent escapes its cgroup | not contained (documented) | quarantine by uid + network segmentation |

## Firewall / ports

| From | To | Port | Why |
|---|---|---|---|
| broker host | nonce authority | 8899 (configurable) | grant nonce claim |
| broker host | TSA (e.g. freetsa.org, DigiCert) | 443 | RFC 3161 |
| agent | egress proxy | 3128 | all outbound traffic |
| broker | ERP / SMTP / payment | as required | the effect itself |
| platform team | broker metrics | `/metrics` | Prometheus |

## Air-gapped variant

Everything works offline except RFC 3161. Options, in order of preference:
1. a local TSA the bank already runs (same `anchor --tsa` API);
2. anchor only at export time on a connected host, verify offline (`--ca` bundle
   shipped with the pack);
3. no anchors, and accept that the claim is "chain integrity since creation",
   not "existed at time T" — state that in the pack.

## What this architecture does not do

- It does not contain a compromised agent; it stops and records what we route.
- It does not replace IAM, SIEM, DLP or the bank's incident process.
- It does not make receipts signed unless the deployment asks for it.
