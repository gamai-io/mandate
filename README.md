# Mandate

[![tests](https://github.com/gamai-io/mandate/actions/workflows/test.yml/badge.svg)](https://github.com/gamai-io/mandate/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Signed, verifiable business commitments for AI agents.**

Most agent safety tools answer *"is this tool allowed?"*. Mandate answers the
question that actually matters: **"who ordered this exact payment, to this
supplier, for this amount?"** A tool permission is not a business mandate.

Every consequential effect becomes a canonical **Commitment** object. An agent
signs the intent; a human co-signs a **Grant** with an Ed25519 key; execution
produces a hash-chained **Receipt**. Anyone can verify the whole chain offline.

> Approval workflows are ephemeral events. A Mandate is a durable, portable,
> cryptographically bound artifact — a commit, not a log line.

```bash
mandate demo        # propose -> grant -> redeem -> replay refused -> changed amount refused
                    # -> verify offline -> audit pack, on a throwaway directory
```

`mandate demo` runs the real path, not a mock: a generated Ed25519 key signs a real
grant, `redeem` executes it, a replay is refused, a changed amount is refused with
`CommitmentMismatch`, the receipt verifies, and an audit pack is written.

New here? [`docs/QUICKSTART.md`](docs/QUICKSTART.md) is the 30-minute path from install to a
verified record. [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) is how to run the kit against
*your* verifier and publish the record behind the badge. [`docs/DISCLOSURE.md`](docs/DISCLOSURE.md)
is how to hand an auditor a redacted record that still proves it is the same record.
[`docs/CAPABILITIES.md`](docs/CAPABILITIES.md) is delegated authority that can only narrow.
[`docs/HARDWARE.md`](docs/HARDWARE.md) says exactly what a security key proves and what it does not.
[`docs/FIREWALL_COMPARE.md`](docs/FIREWALL_COMPARE.md) is the content gate (secrets out, instructions in)
and an honest comparison with the strongest open agent firewall; [`docs/TLS_INTERCEPT.md`](docs/TLS_INTERCEPT.md)
is the optional TLS interception, including what a local CA costs you.

**v1.0.4** — canonical commitment, Ed25519 grant, one-shot redeem, hash-chained receipt.

**Status:** 675 tests collected; 0 failed. On a host with Node and bubblewrap 670
pass; the rest skip with a stated reason, and CI skips more where those tools are
absent. `python3 -m pytest -q tests/`.

Rebuilds are reproducible: `docs/REPRODUCIBLE.md` and `tools/verify_pypi.py`.
`tools/claims.py` fails CI when the version, the changelog section, the collected
and passing test counts, or any figure in `CLAIMS.md` disagrees with the code. The
benchmark numbers are not constants: each one names the script that reproduces it,
because `fsync` and the host change the absolute value.

## One thing

Mandate does one thing: a named human signs a specific business effect, the effect
can happen **once**, and the receipt verifies offline years later. Everything else
in this repository — broker, warden, egress, detection, MCP, bench — exists to
serve that same hash chain. If a feature does not produce or protect a receipt, it
is not the product; it is an add-on, and the docs say which is which.


## Why it is not another approval gate

| Approval gate | Mandate |
|---|---|
| Asks "may this tool run?" | Asks "is this exact effect authorised?" |
| Identity is a self-asserted field | Approver proves possession of an off-host key |
| Approval is a mutable DB row | Grant + receipt are signed, content-addressed |
| Logs what happened | Lets anyone prove what was authorised |

## Install

```bash
python3 -m pip install gama-mandate     # CLI + broker + MCP adapter
mandate doctor                          # checks python, ssh-keygen, policy
```

From source: `python3 -m pip install "git+https://github.com/gamai-io/mandate.git"`.
Python >= 3.9. No web UI and no server to run: Mandate is a local trust primitive.

## Quickstart (60 seconds)

Run it in an empty directory. Nothing below needs a network, database or cluster.

```bash
mandate init --dir .                    # policy.json, allowed_signers, config, example intent

ssh-keygen -q -t ed25519 -f ./approver_key -C mandate -N ""
printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)" >> trust/allowed_signers

mandate propose --intent examples/intent.json --out proposal.json
mandate grant  --proposal proposal.json --approver approver \
               --key ./approver_key --audience local-broker --out grant.json
mandate redeem --intent examples/intent.json --grant grant.json --ledger ledger.jsonl \
    --audience local-broker > receipt.json
mandate verify --receipt receipt.json --intent examples/intent.json --grant grant.json
```

Expected:
`{"valid": true, "decision": "executed", "executed": true, "observed": false, "signed": false}`.
`valid` is the cryptographic check; `executed` says the **grant was spent** and
the receipt records it. It is not a bank confirmation: the broker executes and
reports, and without `--key` on `redeem` the receipt is unsigned (tamper-evident
only through the ledger). Repeat the `redeem` line and it fails with
`GrantReplayed` — the grant is one-shot per nonce store, by construction (the
shared store section below covers multiple hosts or directories).

| step | what it proves |
|---|---|
| `propose` | the effect is a canonical commitment (`commitment`), not a free-text request |
| `grant` | a human signed *that exact* commitment with an Ed25519 key that never touches the agent host |
| `redeem` | the grant was used once; the receipt is appended to a hash-chained ledger |
| `verify` | anyone can check receipt + intent + grant offline, without trusting the broker |

## What else is in the box

Each of these produces or protects the same receipt; none of them is a second product.

| piece | what it adds | doc |
|---|---|---|
| **broker** | the agent never holds the payment credential | [`docs/BROKER.md`](docs/BROKER.md) |
| **warden** | an external freeze you can prove (cgroup/VM), signed stops, quarantine | `mandate warden --help` |
| **egress + firewall** | deny-by-default proxy; secrets do not leave, instructions do not enter (31+18 patterns, 75-case corpus) | [`docs/FIREWALL_COMPARE.md`](docs/FIREWALL_COMPARE.md) |
| **TLS interception** | optional: scan HTTPS bodies with a local CA | [`docs/TLS_INTERCEPT.md`](docs/TLS_INTERCEPT.md) |
| **taint bridge** | a flagged input becomes `trust=untrusted`, and `require_trusted` refuses the effect | `mandate taint --help` |
| **capability tokens** | delegated authority that can only narrow | [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md) |
| **MCP gate** | lock the tool list, gate effects, scan tool responses | [`docs/BROKER.md`](docs/BROKER.md) |
| **disclosure** | a redacted receipt that still proves it is the same receipt | [`docs/DISCLOSURE.md`](docs/DISCLOSURE.md) |
| **hardware keys** | what a security key proves, and what it does not | [`docs/HARDWARE.md`](docs/HARDWARE.md) |
| **conformance kit** | run 11 cases against *your* verifier | [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) |
| **bank pack** | procurement answers, control matrix, pilot SOW, DORA evidence | [`docs/PROCUREMENT_ANSWERS.md`](docs/PROCUREMENT_ANSWERS.md) |

Everything else — examples, operations, the transparency log, the effect broker,
the MCP gates, the bank control matrix, design invariants, layout — is in
[`docs/REFERENCE.md`](docs/REFERENCE.md).

## What it does not do

- **It does not isolate credentials.** Cryptography proves *who authorised what*; a
  compromised agent that holds the payment key can bypass Mandate entirely. That is
  why the broker exists, and why `docs/NON_GOALS.md` names the line.
- **It is not a compliance certificate.** Evidence only; the obligation stays with the bank.
- **It is not tamper-proof.** Tamper-*evident* relative to the last anchor and the witness.
- **It is not independently audited.** Both verifiers are written by the same author; the
  conformance kit and the attack corpus are there so an outsider can check us cheaply.

## Install order

```bash
pip install gama-mandate      # the product: commitments, grants, receipts, verification
```

The other packages are layers around it, not alternatives: `gamai-tripwire` (inbound
detection), `gamai-guard` (policy/injection), `sigil-profile` (receipt profile over MCP/A2A),
`proofgate-runtime` (claim/receipt core), `gama-l` (a small language with proofs). Start with
`mandate`; add a layer only when you need what it does.

## License

MIT. No network, no database, no cluster: `mandate doctor` tells you what your host can do.
