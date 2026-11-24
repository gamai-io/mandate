# Examples

| # | file | needs | shows |
|---|---|---|---|
| 1 | `01-invoice-approval.sh` | `pip install gama-mandate`, `ssh-keygen` | propose → grant → redeem → verify, then a replay is rejected |
| 2 | `02-audit-bundle.sh` | same | portable audit bundle + offline verification |
| 3 | `03-mcp-claude.md` | same | `mandate mcp lock` / `proxy` for Claude Code, Codex, Cursor |
| 4 | `04-full-stack.sh` | all five packages installed | guard → plugins policy → mandate grant → trust claims → gama-l seal |

Run 1 and 2 in a throwaway directory:

```bash
./examples/01-invoice-approval.sh /tmp/demo1
./examples/02-audit-bundle.sh /tmp/demo2
```

Both scripts print each step and fail loudly if any step stops working — they
are executable documentation, not pseudocode.

`intent.json` is the minimal input: actor, effect (kind/target/amount), nonce and
provenance. Change `amount` or `target` and the commitment hash changes, which is
why a grant for one amount cannot authorise another.
