# Where agent-payment protocols end and this starts

Four protocols compete for the same wire: Google's **AP2** (donated to the FIDO
Alliance), Visa's **Trusted Agent Protocol**, Mastercard's **Agent Pay**, and the
Stripe/OpenAI **ACP** with Coinbase's **x402**. They define how an agent, a
merchant and a network *talk* to each other. None of them is what a bank's DORA
reviewer asks for on a Tuesday afternoon.

> **Attribution.** The description of AP2 and its partners below is the summary
> given to us by an external reviewer. We have not independently verified the
> current status of any competing specification, and we do not claim to.

## The two questions

| question | who answers it today |
|---|---|
| "May this agent pay this merchant, up to this amount, in this protocol?" | AP2 / TAP / Agent Pay / ACP |
| "Who in *our* bank approved *this* payment, on which device, under which policy, and can we prove it offline in seven years?" | nobody with a shipping artefact — this is the row our own control matrix marks as having no credible vendor |

The first is a protocol. The second is a control with an evidence trail. A bank
does not choose between them; it buys the protocol from the network and needs the
control for its own supervisor.

## Mapping

| layer | protocol side | Mandate | where they meet |
|---|---|---|---|
| intent | the protocol's mandate/authorisation object | `intent.json`: effect kind, target, amount, agent, session, nonce, provenance | map the protocol object into our intent; the commitment then covers it |
| authorisation | signed by the user's wallet or the agent platform | Ed25519 grant over `jcs(intent)` signed by a **named human** key held off the agent host | a grant can cite the protocol's authorisation hash as provenance |
| execution | the network moves the money | broker executes, claims the nonce once, appends a receipt | the broker is the only holder of the payment credential |
| evidence | protocol logs, network reports | hash-chained receipts, optional RFC 3161 anchors, `mandate pack` (inventory, changes, DORA row) | the protocol receipt becomes a `data_ref`; our pack is what an auditor reads |
| verification | the network's API | `spec/verify_offline.py` — stdlib only, no vendor needed | an auditor verifies without either party |

## What we would have to build to interoperate

1. **An importer** for the protocol's mandate object → our `intent`
   (a day, once someone publishes a stable JSON schema we can read).
2. **A verifier for their signature format** inside the grant's provenance, not
   inside our receipt chain (their key, their algorithm, our pointer).
3. **A field map** from their settlement reference to our `result_hash` input, so
   the receipt names the same transaction they do.

None of this is built. Saying so is cheaper than discovering it in a pilot.

## The one sentence

> Protocols decide whether an agent may pay on the network; Mandate records that
> a named person in *this* bank approved *this* amount, and proves it offline
> when the network's logs are long gone.
