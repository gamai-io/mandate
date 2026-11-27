#!/usr/bin/env bash
# Build a release that a third party can rebuild byte for byte.
#
#   tools/build_release.sh v0.69.0 [outdir]
#
# Why a script: `python -m build` alone embeds the current time in the wheel and in the
# sdist's tar/gzip headers, so two builds of the same source differ. This builds from the
# **tag's archive** (uncommitted edits cannot leak in), pins SOURCE_DATE_EPOCH to the tag
# commit, normalises the sdist and refuses to leave artifacts that fail `twine check`.
#
# It does not upload. Verify first:
#   SOURCE_DATE_EPOCH=... python3 tools/verify_pypi.py --tag <tag>   (after `twine upload`)
set -euo pipefail

tag="${1:?usage: tools/build_release.sh <tag> [outdir]}"
out="${2:-dist}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

commit="$(git rev-list -n1 "$tag")"
epoch="$(git show -s --format=%ct "$commit")"
export SOURCE_DATE_EPOCH="$epoch"
echo "tag $tag -> commit ${commit:0:12}, SOURCE_DATE_EPOCH=$epoch"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git archive "$tag" | tar -x -C "$work"

mkdir -p "$out"
rm -f "$out"/*.whl "$out"/*.tar.gz
( cd "$work" && python3 -m build --outdir "$out" >/dev/null )
python3 tools/normalize_sdist.py "$out"/*.tar.gz
python3 -m twine check "$out"/*
sha256sum "$out"/*
