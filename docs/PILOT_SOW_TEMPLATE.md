# Pilot statement of work — template

Six weeks, fixed fee, one workflow. Fill the bracketed fields; the structure is
deliberately narrow so a change board can approve it.

---

## 1. Parties

- **Customer:** [bank / insurer legal name, registered address]
- **Supplier:** GAMA TRADE d.o.o., Usora, Bosnia and Herzegovina
- **Effective date:** [date] · **Term:** 6 weeks from kickoff

## 2. Scope

One business workflow chosen by the Customer, for example:

- accounts-payable payment approval (invoice → approval → payment instruction), or
- customer-onboarding data change (request → four-eyes → system update), or
- [Customer-specific workflow, max 3 systems]

In scope:

1. Deploy `gama-mandate` (and, where relevant, `gamai-guard`, `gamai-plugins`) in
   the Customer's environment, in a non-production segment.
2. Route the workflow's consequential effects through the broker/proxy.
3. Configure: policy (allowed effects, limits), approver identity, nonce
   authority, anchors (the Customer's TSA), SIEM shipping, stop procedure.
4. Produce an evidence pack per week (`mandate pack`) and one post-pilot pack.
5. Run a stop drill (freeze + record + restore) with the Customer's operators.

Out of scope: production rollout, HSM procurement, IdP changes, model selection,
custom application development, legal or compliance advice.

## 3. Deliverables and acceptance

| # | Deliverable | Acceptance criterion |
|---|---|---|
| D1 | Running pilot in the non-production segment | 20 consecutive effects processed; `mandate chain` valid |
| D2 | Policy and limits for the workflow | Customer security signs the policy file; `change record` present |
| D3 | Evidence pack | `index.json` hashes match; one effect verified offline by the Customer *without our help* |
| D4 | Stop drill | Time-to-halt measured and recorded; restart procedure documented |
| D5 | Handover | Customer operator performs one full cycle (propose → approve → execute → verify) unaided |
| D6 | Findings report | False-success and refusal counts for the pilot window, with numbers |

Acceptance is per deliverable, within 5 business days of handover.

## 4. Responsibilities

**Supplier:** configuration, documentation, two training sessions (2 h each),
weekly 30-minute review, response within one business day during the pilot.

**Customer:** named technical contact and named approver, non-production
environment, network path to the TSA, SIEM endpoint credentials, and a decision
on which workflow is in scope by week 1 day 3.

## 5. Fees and payment

- Fixed fee: **€[amount]** for the 6 weeks (suggested band: €9,000–€18,000 for a
  single-workflow pilot; founding-customer discount at the Supplier's discretion).
- Payment: 40% at kickoff, 60% at D5 acceptance. Invoiced in EUR, 15 days.
- Expenses: none expected; travel only if agreed in writing.

## 6. Data and confidentiality

- The software runs in the Customer's environment; the Supplier receives no
  production data.
- Any sample the Customer shares is limited to what is necessary and deleted
  within 30 days of the pilot.
- Mutual NDA to be signed before kickoff (Customer's template preferred).

## 7. Evidence and audit rights

- All artifacts (code, ledger, packs) remain the Customer's property.
- The Customer may audit the Supplier's work with 5 business days' notice; the
  code and the verifier are public, so most audit work is reading them.
- No certification is claimed. The Supplier supports controls; compliance remains
  the Customer's obligation.

## 8. Exit

- The Customer may terminate for convenience with 10 business days' notice;
  fees are pro-rated to delivered items.
- On exit the Customer keeps every artifact and the offline verifier; no licence
  to revoke (Apache-2.0 / MIT).
- Transition assistance: 5 business days of handover at no extra cost.

## 9. Liability

- Cap: fees paid under this SOW.
- Excluded: indirect and consequential loss.
- The Supplier carries [PI/cyber insurance — insert policy once bound] or states
  explicitly that it does not.

## 10. Signatures

Customer: ______________________  Date: __________

Supplier: ______________________  Date: __________
