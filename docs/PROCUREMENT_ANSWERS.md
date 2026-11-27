# Procurement answers

Pre-filled answers to the questions a bank's security/procurement process asks.
Every "no" is a real gap with a plan; a questionnaire that answers "yes" to
everything is the first thing a reviewer distrusts.

Product: `gama-mandate` 0.74.0 and the four companion packages (`gamai-trust`,
`gamai-guard`, `gamai-plugins`, `gama-l`). Vendor: GAMA TRADE d.o.o. / gamAI,
Usora, Bosnia and Herzegovina.

## Company

| Question | Answer |
|---|---|
| Legal entity | GAMA TRADE d.o.o., Bosnia and Herzegovina (registration documents on request) |
| Headcount | 1 (founder) + contract collaborators |
| ISO 27001 / SOC 2 | **No.** No certification and no audit report. We do not claim one. |
| Insurance (PI / cyber) | **Not in place yet.** Quotes requested; this is on the critical path for a pilot SOW. |
| Customer references | **None in banking.** Published artifact + preprint only. |
| Financial standing | Small company; the mitigation is exit, not balance sheet — see "Exit" below. |

## Data and privacy

| Question | Answer |
|---|---|
| Where is data processed? | Entirely in the customer's environment. The software has no telemetry, no phone-home and no vendor-side service. |
| Data leaving the customer | Only outbound calls the customer configures: TSA requests (hash of ledger head only) and optional SIEM export. No effect data is sent to us. |
| Personal data in the ledger | Receipts contain the effect (target, amount), the approver **name** and the agent identity. Customer names/payments can be present — this is why `pack` supports a hash-only variant and crypto-shredding is on the roadmap. |
| DPIA support | A DPIA template and a data-flow description are available; we are not a processor by default. |
| Retention | Configurable at export (`worm-export --retention-days`); default 180 days in the demo. Bank sets the real schedule (EU AI Act Art. 19/26: ≥ 6 months; financial-sector rules usually longer). |
| Third-country transfer | None by default (on-prem). If we run a hosted pilot, it is on an EU provider; Bosnia's adequacy status must be confirmed by the bank's DPO. |

## Cryptography

| Question | Answer |
|---|---|
| Algorithms | Ed25519 signatures (SSH key format), SHA-256, RFC 8785 canonical JSON, RFC 3161 timestamps. |
| Key generation / storage | `ssh-keygen` file keys or `sk-` hardware keys; **HSM/KMS through `--signer-cmd`** — the bank's adapter signs the canonical payload, our process never holds the key. A PKCS#11 adapter ships (`tools/mandate-pkcs11-sign.py`) and is tested against **SoftHSM2** Ed25519; a vendor HSM has the same API but is not tested here. |
| Key rotation | `allowed_signers` supports multiple keys; remove the old one, add the new one, record it with `change record`. No automated rotation tooling. |
| Where are private keys? | Never in the repository or the ledger; the approver's environment only. We never see them. |
| Crypto library | None — the code calls `ssh-keygen`/`openssl`. No home-grown primitives in the signing path (Ed25519 comes from OpenSSH); the offline verifier does implement Ed25519 in pure Python, and that is stated where it matters. |

## Access and identity

| Question | Answer |
|---|---|
| Approver authentication | A signature over the canonical commitment, one-shot nonce, four-eyes rule (agent cannot approve itself). Binding to an IdP session (MFA method, device) is a **gap**. |
| Agent identity | Short-lived Ed25519 token (`iss == sub == signer`, TTL ≤ 1 h, audience, scopes); delegation chains can only narrow. |
| Privileged access | The agent never holds the effect credential when the broker executes: it holds a grant, the broker holds the secret. |
| Revocation | `trust/revoked_signers` for grants; for tokens the path must be passed to `svid verify`/`redeem`. No central revocation service. |

## Logging, monitoring, detection

| Question | Answer |
|---|---|
| Log format | Append-only JSONL, one record per line, hash-chained; each record is canonical JSON. |
| Tamper evidence | Hash chain + `.head`; external proof via RFC 3161 anchors (multi-TSA). Unsigned receipts are the default. |
| Integrity of the log store | `worm-export` writes a read-only directory with per-file SHA-256 and a retention date. **Real WORM needs object lock** — bank-provided. |
| SIEM integration | `mandate ship` posts each record as `{"event": …}` to a Splunk HEC-style endpoint, keeps a byte offset (no resend, no skip), and refuses to advance the offset when the endpoint rejects a batch. Generic JSON endpoint works for Sentinel via a Logic App/Data Collector. |
| Detection content | Six deterministic rules over the ledger (self-approval, human identity used by an agent, velocity, amount ceiling, off-hours, scope not granted). Tool-sequence anomalies are a gap. |
| Clock | Timestamps from the host clock; external time only comes from anchors. Clock-sync evidence is captured at export, not attested. |

## Resilience and operations

| Question | Answer |
|---|---|
| Backup / restore | `mandate backup` (tar + per-file SHA-256 manifest) and `mandate restore` (verifies every hash and the chain). |
| RPO / RTO | Not defined by us; the ledger is a file — RPO is your backup interval, RTO is a restore of seconds for the file plus your platform start-up. |
| HA | The nonce authority is a single HTTP service; HA requires a shared database behind it. The ledger is a single-writer file per broker. |
| Multi-host | `MANDATE_NONCE_URL` shares the one-shot authority; without it, two hosts can double-spend (documented). |
| Kill switch | `warden`: SIGSTOP, cgroup v2 freeze (kernel-confirmed), `cgroup.kill`, Firecracker pause, per-uid nftables quarantine. It stops what we route; it is not containment. |
| Upgrade path | Semantic versions, changelog, published tags; no service to upgrade — the bank controls deployment. |

## Supply chain

| Question | Answer |
|---|---|
| Dependencies | **Zero runtime dependencies.** `sbom` emits CycloneDX 1.5 with empty `components`. |
| SBOM | `mandate sbom` (shipped). |
| Signed releases | **Gap.** Wheels are published to PyPI with hashes; Sigstore build attestation and PyPI PEP 740 provenance are both live. Tags exist per release. |
| Vulnerability handling | `SECURITY.md` with a contact; fixes are released as patch versions and listed in `SECURITY.md`. No formal CVE process, no bounty. |
| Pentest | **Not done.** Booked as a prerequisite for a pilot; the red-team review we ran internally is public in spirit (findings and fixes are in `SECURITY.md`). |

## Exit and continuity

| Question | Answer |
|---|---|
| What if the vendor disappears? | Apache-2.0/MIT code, published data format, offline verifier, and `pack` contains the ledger it describes. The bank keeps running the verifier and the ledger without us. |
| Source escrow | Not needed: source is already public. |
| Data export | JSONL + `pack` (inventory, changes, DORA row, ledger, anchors, signed index). |
| Contract termination | No licence to revoke (permissive open source). Support and warranty would end; the software keeps working. |

## Claims we will not make

- "DORA/AI Act compliant" or "certified" — compliance is the bank's obligation.
- "Tamper-proof" or "immutable" — tamper-*evident* relative to the last anchor.
- "Containment" or "cannot escape" — we stop and record what we route.
- "SOC 2 / ISO 27001 equivalent" — no certificate exists.
- Any customer reference or bank pilot that has not happened.

### "Who verifies your verifier?"

- **Published format**: `spec/MANDATE-1.md` — canonicalisation, commitment, grant,
  receipt, hash chain.
- **Test vectors**: `spec/vectors/` — a valid grant and receipt, plus a tampered
  intent and a forged receipt that must fail.
- **A verifier that is not our package**: `spec/verify_offline.py` — standard
  library only, no `import mandate`, no `ssh-keygen`. It re-implements JCS, SSHSIG
  and Ed25519 so every deciding step is readable in one file.
- **Honest limit**: it is a second implementation by the same author, not an
  independent third party. An external implementation or a funded review is still
  open, and `CLAIMS.md` lists it as unproven.

### Release provenance (PEP 740)

Releases use OIDC trusted publishing with `attestations: true`. The trusted
publisher for `gamai-io/mandate` + `release.yml` exists and `PYPI_OIDC=true` is
set, so every artefact carries a PyPI provenance attestation. Check it without
trusting us:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  https://pypi.org/integrity/gama-mandate/<version>/\
gama_mandate-<version>-py3-none-any.whl/provenance    # 200 = attestation exists
```
