# Three tiers of isolation, and what this host proves

The incident record has two failures this repository cannot fix with a signature:
agents escaping a sandbox (Hugging Face: code on 41 production dataset workers;
OpenAI Artifactory) and worms editing the configuration an assistant trusts
(Mini Shai-Hulud, Miasma). Both are answered by *where the code runs* and *what it
may reach*, not by an approval.

## What is proven, on this machine, now

```bash
mandate sandbox check
{"bwrap": true, "docker": true, "kvm": false, "network_isolated": true}
```

`network_isolated` is not a setting, it is a result: the command starts
`bwrap --unshare-net`, then tries to connect to `1.1.1.1:80` from inside, and
expects the connect to fail. Exit 1 from the probe means the namespace did its job.

`kvm: false` on this host is honest and matters: without `/dev/kvm` there is no
microVM tier here. The Firecracker pause measurement in `docs/PERFORMANCE.md` was
taken on `crusoe-cpu1`, the only host with KVM, and CI cannot reproduce it.

## Tier 1 — bubblewrap (works on any Linux host)

```bash
bwrap --unshare-net --ro-bind / / --dev /dev --proc /proc -- python3 agent.py
```

- no network namespace, so no egress at all; the egress proxy is not needed inside
- read-only root, so the agent cannot rewrite the configuration it trusts
- no capabilities; the process cannot `mount`, `ptrace` or open raw sockets
- cheapest to deploy and the one verified above

## Tier 2 — container with a hardened profile

`mandate/sandbox.py` builds `docker`/`runsc` (gVisor) runners: read-only root, no
network by default, capabilities dropped, `no-new-privileges`. gVisor adds a user
space kernel, which is the right answer when the workload is untrusted code rather
than an LLM calling tools.

## Tier 3 — microVM (Firecracker)

The strongest boundary and the one a bank's red team will ask about. It needs
`/dev/kvm`, a kernel image and a launcher; `mandate warden` can pause the VM and
measure the stop. Not available on this host; verified on `crusoe-cpu1`.

## What each tier is for

| threat | tier 1 | tier 2 | tier 3 |
|---|---|---|---|
agent fetches a fake API doc and pays | mandate: broker holds the key | same | same |
agent escapes into the host | bwrap user namespace + ro root | gVisor syscall boundary | hardware boundary |
worm edits `settings.json` / `.mcp.json` | ro root + `mandate config check` | same | same |
agent scans 9,000 external hosts | no network namespace | no network | no network |

## The config half, which is cheap and usually missing

```bash
mandate config lock --dir . --dir ~/.claude --store configs.json
mandate config check --store configs.json --ledger ledger.jsonl   # exit 1 on drift
```

It pins `.mcp.json`, `settings.json`, `CLAUDE.md`, `AGENTS.md`, MCP server lists and
skill files by hash, records the check as a `control` entry in the same ledger as
receipts, and exits non-zero on a changed or missing file. Put it in the wrapper
that starts the agent:

```bash
mandate config check --store /etc/mandate/configs.json || exit 1
exec claude "$@"
```

## What none of this does

- It does not stop a malicious model from *deciding* something; it stops the effect.
- Tier 1 and 2 are not a hardware boundary. If the host kernel is compromised, the
  boundary is gone; that is what tier 3 exists for.
- No tier is claimed to be tested against ARTEX-style tooling. That requires a
  red-team engagement, which is listed as open in `PROCUREMENT_ANSWERS.md`.
