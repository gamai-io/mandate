# Why this exists: the attack got faster than the decision

Source: Moran Regev, "No coding skills required: the AI tool that worries the
FBI", Ynetnews, 25 November 2026 —
<https://www.ynetnews.com/tech-and-digital/article/sjqkg3z1ql>

The article reports an FBI warning about **ARTEX**, an open-source
penetration-testing framework that was forked and reused as a multi-agent attack
tool. What it says, in the parts that matter to a bank:

- A central system coordinates several agents; almost any model can be plugged in.
  Once a tool like this is published, taking it down does not remove it.
- The cost and skill of an attack fall: "people with lower skill levels
  successfully carry out cyberattacks".
- Recorded cases: elevated access in under three hours; 27 attack events in 23
  seconds and access within 15 minutes (Google figures quoted in the article);
  one campaign touched 200+ organisations, another attempted connections to
  2,250 organisations through a shared software provider (attempts, not breaches).
- The bottleneck is **after** the alert: "security systems aren't collapsing;
  they're issuing alerts. The problem is what happens after the alert."
- Defence needs three properties, per the interviewee: act only with high
  confidence, make the intervention **as targeted as possible**, and make it
  **reversible**. When unsure, stop and hand the decision to a human.
- Attackers already disguise activity as routine and inject instructions into data
  to confuse defensive systems.

We do not claim to stop ARTEX or anything like it. What we take from the article
is narrower and checkable.

## What it validates in this repository

| the article's principle | where it is implemented | how to check |
|---|---|---|
"when unsure, stop and pass to a human" | an effect with `risk != low` requires a signature; `mandate policy explain` shows the decision and why | `mandate policy explain --effect payment.send --amount 500` |
"as targeted as possible" | one grant authorises **one** effect, one amount, one target, one agent, one nonce | `mandate verify`, `tests/test_mandate.py` |
"reversible if necessary" | every receipt carries `revert` or `irreversible`; policy can refuse an effect that has no revert step | `tests/test_policy_observe.py` |
"alerts are not the problem; the decision is" | the broker refuses what cannot be proven and records why; `mandate demo` shows a replay and a changed amount refused | `mandate demo` |
"disguise activity as routine / inject instructions" | the judge model is deliberately **not** in the decision path; a canary or a rejected credential is identity evidence, behaviour is not | `docs/FALSE_POSITIVES.md` in tripwire |

## What it threatens

- **Detection alone is not a product.** If the article is right that the alert
  fires but nobody can decide in minutes, then a detector without a decision path
  is a bill, not a control. Our answer is not "more alerts": it is that the effect
  cannot happen without a human signature, so speed buys the attacker nothing at
  the money step.
- **Broad auto-blocking will hurt the bank.** The article's own example — blocking
  an executive on holiday — is why tripwire denies only on identity evidence
  (canary, probed keys), never on behaviour, and why every block expires.
- **A model in the loop is an attack surface.** An agent that decides approvals is
  the thing ARTEX-style tooling would try to talk into approving. Hence: signature
  by a named person, offline verification, no LLM in the decision.

## What we should build next because of this

1. **Time-boxed containment with proof** — `warden` already stops and measures;
   the missing piece is a policy that says "when confidence is X, contain for N
   minutes, then require a human to extend". Containment that expires is reversible
   by construction.
2. **Decision latency as a metric** — record time from alert to decision
   (signature or explicit refusal) in the ledger, and report the median. That is
   the number the article says nobody has.
3. **Canary coverage as a first-class control** — the one signal that needs no
   corroboration and no model. Plant them where an agent-shaped intruder reads.

None of these are claimed above; they are the next work.
