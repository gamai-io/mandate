# Put Mandate in front of an MCP server (Claude Code, Codex, Cursor)

`mandate mcp` wraps any MCP server: it locks the server command, then proxies
`tools/call` through the same commitment → grant → receipt path as the CLI.

## 1. Lock the server command

Locking records exactly which command and arguments are allowed to run. Change
the command later and the lock no longer matches.

```bash
mandate init --dir ./agent-side >/dev/null
ssh-keygen -q -t ed25519 -f ./agent-side/approver_key -C mandate -N ""
printf 'approver namespaces="mandate" %s\n' "$(cat agent-side/approver_key.pub)" \
  >> agent-side/trust/allowed_signers

mandate mcp lock \
  --cmd "python3 -m my_mcp_server --read-only" \
  --server "my-mcp" \
  --key agent-side/approver_key \
  --signer approver \
  --out lock.json
```

## 2. Run the proxy

```bash
mandate mcp proxy \
  --lock lock.json \
  --cmd "python3 -m my_mcp_server --read-only" \
  --verify-calls \
  --mcp-ledger mcp-ledger.jsonl
```

Every `tools/call` that mutates state (`order.create`, `payment.send`, …) needs
a grant; read-only calls can pass through if your policy allows it. Each call
lands in `mcp-ledger.jsonl` with the same hash-chained receipt format.

Optional sandboxing of the MCP server itself:

```bash
mandate mcp proxy --lock lock.json --cmd "python3 -m my_mcp_server" \
  --sandbox docker --sandbox-image python:3.12-slim --sandbox-net
```

`--sandbox` accepts `local`, `docker`, `gvisor`, `firecracker`.

## 3. Point your agent at the proxy

Claude Code (`~/.claude/settings.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "my-mcp": {
      "command": "mandate",
      "args": ["mcp", "proxy", "--lock", "/abs/path/lock.json",
               "--cmd", "python3 -m my_mcp_server --read-only",
               "--verify-calls", "--mcp-ledger", "/abs/path/mcp-ledger.jsonl"]
    }
  }
}
```

Codex CLI (`~/.codex/config.toml`):

```toml
[mcp_servers.my-mcp]
command = "mandate"
args = ["mcp", "proxy", "--lock", "/abs/path/lock.json",
        "--cmd", "python3 -m my_mcp_server --read-only", "--verify-calls"]
```

## 4. What the agent sees

The tool list is unchanged — the agent does not know Mandate is there. What
changes is what happens on a mutating call:

- no grant → the call is refused with a reason the agent can act on;
- grant for a different amount/target → refused (the commitment hash differs);
- the same grant twice → `GrantReplayed`;
- everything that did run → one receipt, verifiable offline.

## 5. Verify a call later

```bash
grep '"mcp.call"' mcp-ledger.jsonl | tail -1 > receipt.json
mandate audit verify --bundle receipt.json --log-signers agent-side/trust/allowed_signers
```

If your MCP server is not ready, the same flow works with the CLI demo in
`examples/01-invoice-approval.sh`.
