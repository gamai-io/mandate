# Reproducible builds

The published wheel and sdist can be rebuilt byte-for-byte from the tagged
source, given the pinned build toolchain and the commit timestamp.

## How

```bash
git checkout v0.68.7
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
python -m build
python3 tools/normalize_sdist.py dist/*.tar.gz
```

`pyproject.toml` pins `setuptools==78.1.0` in `[build-system]`, so an isolated
build installs the same backend. `tools/normalize_sdist.py` rewrites the sdist's
tar/gzip headers with that timestamp (build backends still stamp directories and
`PKG-INFO` with the wall clock).

## Check against PyPI

```bash
python3 tools/verify_pypi.py --tag v0.68.7
```

It rebuilds, normalizes, downloads the PyPI JSON and compares SHA-256 per file.
Exit 0 means every published file is byte-identical to this rebuild.

## What this does and does not prove

- Proves: the artifact on PyPI matches this source tree, not just its version.
- Does not prove who built it: that is the PEP 740 attestation
  (`https://pypi.org/integrity/<project>/<version>/<file>/provenance`).
- A different Python or setuptools version can still change the bytes; the pin
  and the documented command are the contract.
