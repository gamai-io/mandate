# DORA supplier pack — what we can hand a bank

DORA (Regulation (EU) 2022/2554) applies to the bank, not to us. What the bank
needs from a supplier is evidence it can put in its register of information and
its contract file. This document lists what exists, what is a template, and what
is genuinely missing. Nothing here is a certification.

## 1. Register of information (Art. 28(3), RTS on the register)

| data point the bank must record | what we provide |
|---|---|
| legal name, LEI, address | GAMA TRADE d.o.o., Usora, Bosnia and Herzegovina — extract on request; no LEI |
| contract type, start/end, governing law | template in `PILOT_SOW_TEMPLATE.md` (pilot), MSA to be signed |
| services provided, business functions supported | "software for signed approval of business effects and audit evidence", not a payment service |
| data locations and processing | on-premise at the bank; we receive no production data by default |
| sub-outsourcers | **none** |
| reliance on ICT third parties by us | PyPI (distribution), GitHub (source and CI). No runtime dependency: the package has zero runtime dependencies and runs air-gapped |
| exit strategy | `mandate pack` exports the ledger, receipts and anchors; `spec/verify_offline.py` and `verify_offline.js` verify without us |
| level of reliance | the bank decides; the tool is not on the payment path, it authorises the effect |

## 2. Contractual elements (Art. 30)

| element | status |
|---|---|
| service description, SLAs | pilot describes deliverables; **no SLA yet** — open item |
| audit and access rights | accepted; source is MIT and readable |
| participation in security training / awareness | we can provide a one-hour session per year |
| incident notification timelines | `INCIDENT_RESPONSE.md`; contract wording still to be drafted |
| data return and deletion on exit | `mandate pack` + documented deletion of our copies (we hold none by default) |
| termination and transition | export + offline verification, no licence server to shut down |
| liability cap and indemnity | **open** — legal, with counsel |
| insurance (PI/cyber) | **not in place** — open |

## 3. Security evidence we can show today

| control | artefact | how the bank checks it |
|---|---|---|
| integrity of the audit trail | hash chain + optional Ed25519 receipts + RFC 3161 anchors | `mandate chain`, `mandate anchor-verify --ca` |
| authorisation is one-shot (per nonce store) | nonce store, cross-ledger refusal | `tests/`, `mandate demo` |
| approval is bound to the effect | commitment over kind/target/amount/agent/session/nonce | `mandate verify`, `spec/verify_offline.py` |
| the agent holds no payment credential | broker custody test with three processes | `tests/test_broker_custody.py` |
| agent identity | per-agent tokens, mTLS with CN, CRL | `tests/test_agents.py`, `tests/test_mtls.py` |
| approval device | passkey (WebAuthn) or host key | `tests/test_webauthn.py`, `tests/test_passkey_flow.py` |
| release integrity | PyPI provenance (PEP 740) + Sigstore attestation | `https://pypi.org/integrity/<project>/<version>/<file>/provenance` |
| third-party verifiability | two implementations, published vectors | `spec/verify_offline.py`, `spec/verify_offline.js` |

## 4. What is genuinely missing (so the bank is not surprised)

- **No ISO 27001, no SOC 2, no independent pentest yet.** A pentest engagement is
  the next external item; until then the honest answer is "not done".
- **No SLA, no 24/7 support contract, no insurance.** All three are commercial,
  not technical.
- **RTO/RPO for the bank's own deployment** are the bank's to set; we provide the
  export and verification path, not an HA design.
- **We are a small vendor.** A bank should assess concentration risk and require
  the source escrow that MIT already gives it.

## 5. What the bank must do on its side

1. Run the broker as its own user, with the credential only in that environment
   (`packaging/mandate-broker.service`).
2. Keep the approver key off the agent host, on a hardware token or passkey.
3. Decide the retention period and where the ledger copies live; anchors make
   deletion detectable, which is the point.
4. Put the effect kinds it authorises into `policy.json` and review the diff each
   time it changes (`mandate policy diff`).

## 6. How to verify the claims in this document

Every row in section 3 names a command or a test file. `CLAIMS.md` carries the
same table generated from the repository, and CI fails when the version, the
changelog or the test count disagree with the code.
