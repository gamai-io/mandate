# Contributing

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
make test          # all unit + bypass tests
ruff check .       # lint
```

`ssh-keygen` (OpenSSH >= 8.0) must be on `PATH`; the test suite generates
throwaway keys and skips the crypto tests if it is missing.

## Rules

- No third-party runtime dependencies. Standard library only.
- No LLM call in the decision path. Decisions are deterministic.
- Every security-relevant change needs a test that **fails before the fix**.
- Do not weaken a default (default-deny, loopback-only, off-host key,
  explicit namespace scope) without a documented reason and a test.
- Keep secrets out of the repo and out of logs.

## Commits and PRs

- One logical change per commit; imperative subject line.
- Include the command you ran and its result in the PR description.
- CI must be green (Python 3.9–3.12, tests and `ruff check .`).
- By contributing you agree to the Developer Certificate of Origin
  (https://developercertificate.org/): sign off with `git commit -s`.

## Security

Please read `SECURITY.md` before reporting a vulnerability.
