# Release checklist

## 1. Preconditions

- [ ] `git status` clean; you are on the release branch.
- [ ] `CHANGELOG.md` has an entry for the new version.
- [ ] Version bumped in **all** of:
      `pyproject.toml`, `mandate/__init__.py`, `mandate/mcp_server.py`,
      `mandate/broker.py` (`server_version`).

## 2. Verify

```bash
make test                 # unit + bypass tests
ruff check .              # lint
python3 -m unittest discover -s tests -p 'test_*.py'
```

Expected: all green. Do not tag on a red suite.

## 3. Build

```bash
python3 -m venv .venv-build
. .venv-build/bin/activate
pip install build twine
python3 -m build                    # wheel + sdist
twine check dist/*
```

Verify a clean install from the **sdist** and the wheel:

```bash
python3 -m venv /tmp/rel && /tmp/rel/bin/pip install dist/agent_mandate-<ver>-py3-none-any.whl
/tmp/rel/bin/mandate version
/tmp/rel/bin/mandate doctor
```

## 4. Tag and publish to git

```bash
git tag -a v<ver> -m "Mandate <ver>"
git push origin main --tags
```

Create the GitHub release and attach `dist/*.whl`, `dist/*.tar.gz` and
`dist/*.sha256` (`sha256sum dist/*`).

## 5. PyPI

```bash
twine upload dist/*
```

`gama-mandate` is the PyPI distribution name (verified available 2026-11-09).
`agent-mandate` was rejected by PyPI as too similar to the existing
`agentmandate`; `mandate` and `agentmandate` are taken.

## 6. Post-release

- [ ] `pip install agent-mandate==<ver>` in a clean venv works.
- [ ] `mandate doctor` passes.
- [ ] Announce with the threat model and the known limitations
      (`docs/THREAT_MODEL.md`, `docs/NON_GOALS.md`).
