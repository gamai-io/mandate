# Sandbox verification

Three isolation levels were exercised. No host names, addresses or internal data
are recorded here.

## Docker (runc) — automated

`tests/test_sandbox.py` runs the full MCP lock/verify/proxy through a real
container:

- image `python:3.12-slim`
- `--read-only`, `--network none`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, pids/memory/cpu limits, 16 MiB tmpfs
- fixture directory mounted read-only at `/work`

Result: `lock`, `verify` and `proxy` (initialize, tools/list, tools/call) pass.

## gVisor (runsc) — lab VM, manual

On a lab VM with Docker + `runsc`:

```bash
mandate mcp lock --cmd "python3 fake_mcp.py" --server fake \
  --key /tmp/k --signer approver --out /tmp/lock.json \
  --sandbox gvisor --sandbox-image python:3.12-slim \
  --sandbox-mount /tmp:/work:ro --sandbox-workdir /work

mandate --signers /tmp/signers mcp verify --lock /tmp/lock.json \
  --cmd "python3 fake_mcp.py" --sandbox gvisor \
  --sandbox-image python:3.12-slim \
  --sandbox-mount /tmp:/work:ro --sandbox-workdir /work
```

Result: `{"valid": true, "tools": ["pay","read","web_fetch"]}` — the runner
built a `runsc` container with the same hardening flags, and the MCP handshake
and tools/list succeeded inside it.

## Firecracker — lab VM, manual

The lab VM has Firecracker 1.17 and a KVM microVM pool with Python 3.12 inside.
A real microVM boot + command execution succeeded:

```
fc-ok
Python 3.12.7
Linux ubuntu-fc-uvm 4.14.174 ... x86_64
```

The runtime is verified. A stdio bridge that exposes an MCP server inside a
Firecracker microVM to the proxy (`--sandbox firecracker
--sandbox-cmd-template`) is the next step; the proxy already supports an
external launcher template.

## Recommendation

- Use `docker`/`gvisor` for MCP servers that must be reachable as stdio today.
- Use the Firecracker template path when a serial-console-to-stdio launcher is
  available.
- Keep `local` only for trusted development.
