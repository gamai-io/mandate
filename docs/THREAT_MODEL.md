# Threat model

## Assets
- The authority to cause a consequential effect (pay, order, change supplier/price, send).
- The integrity of the authorisation record (who approved what, unaltered).
- The approver's signing key.

## Adversaries
- **Sycophantic agent**: turns a user preference into a "fact" and executes.
- **Compromised agent**: prompt injection or a malicious tool steers the effect.
- **Malicious operator of the host**: has root where the agent runs.
- **Replay attacker**: reuses an old approval for a new effect.
- **Insider collusion**: proposer approves their own request.

## Invariants
1. No effect executes without a grant whose commitment equals the intent.
2. A grant is valid only if the approver's signature verifies against a public
   key in `trust/allowed_signers`.
3. A grant is single-use (nonce consumed in the ledger).
4. Approver != executing agent.
5. Unknown effect kinds are denied.
6. Every executed effect appends a receipt whose hash chains to the previous one.

## What Mandate does NOT protect against (yet)
- **Credential bypass**: if the agent holds the DB/mail/payment credential, it
  can act without calling Mandate. Mitigation: effect broker (Phase 2).
- **Root on the host**: root can read the ledger and may read a key if one is
  stored there. Mitigation: never store the private key on the host; move the
  broker to a separate host/user.
- **Semantic deception upstream**: a correct grant over a wrong premise (e.g.,
  the supplier price itself was tampered in the source data). Mitigation:
  provenance (`data_ref`) + alternative checks in the policy pack.
- **Denial of service**: the agent simply does nothing. Out of scope.

## Bypass test suite (must always fail)
- Redeem with no grant.
- Redeem with a grant for a different amount/target.
- Redeem the same grant twice.
- Redeem with a grant signed by a key not in `allowed_signers`.
- Redeem after `not_after`.
- Approve as the same identity as the agent.
- Execute an effect kind absent from policy.
