# Firewall — content gate, compared honestly

`mandate firewall` looks at what `egress.py` already let through. The connection is
allowed or refused by the proxy; the **content** is scanned here:

| direction | what is looked for | actions |
|---|---|---|
| outbound (agent → world) | 17 patterns: AWS/GitHub/GitLab/Slack/OpenAI/Anthropic/Google/Stripe keys, private-key blocks, JWTs, credentials in URLs and connection strings, bearer headers, emails, IBANs, card numbers (Luhn-checked), BH mobile numbers, plus a high-entropy-token catch | `block`, `redact`, `flag` |
| inbound (world → agent) | 10 patterns: “ignore previous instructions”, new/system prompt, reveal-prompt, role override, tool-directive-payment, credential request, urgency+payment, invisible characters, hidden HTML comments, long base64 blobs | `block`, `flag` |

Matching happens **after folding** (`mandate/normalize.py`): zero-width characters,
homoglyphs and compatibility forms cannot walk past a pattern written in Latin.

## Numbers, from the corpus in this repo

```
python3 tools/firewall_eval.py
caught 27, missed 0, false positives 0 of 45 cases
recall 100.0%  precision 100.0%
```

45 cases: 27 attacks/leaks and 18 benign texts, and CI fails if one flips
(`tests/test_firewall.py::Corpus`). The corpus is ours and small — it says what these
patterns do, not that prompt injection is solved. `docs/FIREWALL.md` lists every case.

## What a record looks like

```bash
mandate firewall scan --text "key AKIAIOSFODNN7EXAMPLE"
# {"outbound": {"ok": false, "findings": [{"kind": "aws_access_key", "action": "block",
#  "masked": "AKIA…LE (20 chars)"}], "blocked": 1, ...}}
```

The finding keeps a **masked** value (first four characters, length), never the secret:
writing it into a ledger would make the ledger the leak.

```bash
mandate firewall redact --file request.txt -o clean.txt
# mail <email:redacted> card <card_number:redacted>
```

## Compared with `pipelock` (1,025★), the strongest open firewall for agents

| | pipelock | mandate firewall (today) |
|---|---|---|
| DLP patterns | **74** | 17 |
| injection patterns | **34**, 6-pass normalisation | 10, folding via `normalize.py` |
| TLS interception | yes (CONNECT contents) | **no** — CONNECT is tunneled, only the destination is judged |
| MCP / A2A mediation | yes (request and response) | **no** — `mandate/mcp.py` is a server, not a mediator |
| redaction | yes, typed placeholders | yes, `<kind:redacted>` |
| receipts for decisions | yes | yes — `control` entries in the same ledger as grants |
| feeds a policy decision | policy per route | **yes**: a flagged response can be labelled untrusted and `require_trusted` then refuses the effect it influences |
| corpus / proof | public benchmark | **45 cases, 0 misses, 0 false positives, run in CI** |

Honest verdict: **pipelock is the stronger firewall; mandate is the stronger evidence
layer.** The gap is deliberate for now — a data plane needs TLS interception and MCP
mediation to be worth deploying, and that is a bigger build than a lexer. What mandate
adds on top is the thing pipelock does not do: the firewall's judgement becomes part of
the signed record, and an untrusted response can *taint* the effect it tries to cause.

## Next, in order

1. **MCP response mediation** — scan tool results and model answers on the way in, not
   only egress text.
2. **Pattern breadth** — the missing 50+ DLP and 20+ injection patterns, each with a
   corpus case (no pattern lands without a test).
3. **Taint bridge** — a flagged response writes `trust=untrusted` provenance for the
   next intent, so `require_trusted` refuses the payment instead of only warning.
4. TLS interception only if a customer needs it; it costs a dependency and a CA.
