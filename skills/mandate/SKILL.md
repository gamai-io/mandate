---
name: mandate
description: Use when an AI agent is about to perform a consequential business effect (payment, order, supplier or price change, outbound message/commitment). Produces a canonical Commitment, requires a human-signed Grant, and emits a verifiable Receipt so no business decision happens that nobody ordered.
---

# Mandate — signed business commitments for agents

## When to use
Use Mandate **before** any effect that commits money, inventory, a supplier, a
price, a deadline, or an outbound promise. Do **not** use it for reads.

Effect kinds (from `policy.json`): `payment.send`, `order.create`,
`supplier.change`, `price.change`, `quote.create`, `message.send`,
`file.export`, `read.lookup`.

## Rules for the agent
1. Never execute a consequential effect you were not explicitly asked to do.
2. A user preference ("I like supplier X") is **not** a decision. Record it as
   provenance `user_pref`; it cannot justify a commitment.
3. Build an Intent with `provenance`. Every choice parameter must have a
   `data_ref` (SQL row, document id), not a `model_inference`.
4. Run `mandate check`. If the decision is `ask`, STOP and request a grant.
5. Execute only after `mandate redeem` succeeds. Redeem exactly once.
6. Never ask for, store, or use the approver's private key.

## Commands
```bash
mandate check   --intent intent.json            # 0 allow / 10 ask / 20 deny
mandate propose --intent intent.json --out proposal.json
mandate grant   --proposal proposal.json --approver <name> --key <priv> --out grant.json   # human only
mandate redeem  --intent intent.json --grant grant.json --ledger ledger.jsonl
mandate verify  --receipt receipt.json --intent intent.json --grant grant.json
mandate chain   --ledger ledger.jsonl
```

## Intent template
```json
{
  "v": 1,
  "actor": {"agent": "opencode@host", "session": "abc"},
  "effect": {
    "kind": "payment.send",
    "target": "Example Supplier",
    "amount": {"value": 1170.0, "currency": "BAM"},
    "params": {"ref": "faktura-77"}
  },
  "requested_by": "approver",
  "nonce": "unique-1",
  "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}]
}
```

## Hard fail conditions (do not retry with a workaround)
- `CommitmentMismatch`: the grant is for a different effect. Re-propose.
- `GrantExpired`: ask the human for a new grant.
- `GrantReplayed`: this grant was already used. Never reuse.
- `SelfApproval`: the agent tried to approve itself. Escalate to a human.
- `GrantInvalid`: signature does not match `trust/allowed_signers`.

## Anti-patterns
- Editing the intent after the grant to "fix" a field.
- Looping `redeem` until it passes.
- Using a host-held key to self-sign.
- Treating `check` exit 10 as success.
