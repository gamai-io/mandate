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

## Firecracker — lab VM, manual + Mandate bridge

The lab VM has Firecracker 1.17 and a KVM microVM pool with Python 3.12 inside.
A real microVM boot + command execution succeeded:

```
fc-ok
Python 3.12.7
Linux ubuntu-fc-uvm 4.14.174 ... x86_64
```

`mandate.firecracker_bridge` (console script `mandate-fc-bridge`) boots a
microVM, copies host files referenced by absolute path into `/tmp` in the guest,
starts the command with unbuffered Python and bridges JSON-RPC lines between
stdin/stdout and the guest serial console:

```bash
mandate mcp verify --lock /tmp/fclock.json --cmd "python3 /tmp/fake_mcp.py" \
  --sandbox firecracker \
  --sandbox-cmd-template "python3 -m mandate.firecracker_bridge --"
```

Result: `{"valid": true, "tools": ["pay","read","web_fetch"]}` against a real
KVM microVM; `lock` and `verify` both pass.

## Recommendation

- Use `docker`/`gvisor` for MCP servers that must be reachable as stdio today.
- Use `firecracker` with `mandate-fc-bridge` for a KVM microVM boundary.
- Keep `local` only for trusted development.
