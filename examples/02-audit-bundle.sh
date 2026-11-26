#!/usr/bin/env bash
# Offline audit: build a portable bundle for one effect and verify it without
# network, database or the Mandate installation that produced it.
#
#   ./examples/02-audit-bundle.sh ./demo2
#
# The bundle carries the intent, the signed grant, the receipt, a Merkle
# inclusion proof, a signed tree head (STH) and the witness state that pinned
# that STH. `audit verify` requires all of them, so this script produces all of
# them; a bundle without an STH is not an audit bundle.
set -euo pipefail

D=${1:-./mandate-audit}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

mandate init --dir . >/dev/null
ssh-keygen -q -t ed25519 -f ./approver_key -C mandate -N ""
ssh-keygen -q -t ed25519 -f ./log_key -C log1 -N ""
# the approver signs grants (namespace "mandate") and bundle envelopes
# ("mandate-export"); the log key only signs tree heads ("mandate-log")
printf 'approver namespaces="mandate,mandate-export" %s\nlog1 namespaces="mandate-log" %s\n' \
  "$(cat approver_key.pub)" "$(cat log_key.pub)" >> trust/allowed_signers

mandate propose --intent examples/intent.json --out proposal.json
mandate grant --proposal proposal.json --approver approver --key ./approver_key \
  --audience local-broker --out grant.json >/dev/null
mandate redeem --intent examples/intent.json --grant grant.json --ledger ledger.jsonl \
  --audience local-broker > receipt.json

echo "ledger (hash-chained, one line per redeemed effect):"
wc -l < ledger.jsonl | sed 's/^/  entries: /'

echo "log: Merkle proof for the receipt and a signed tree head"
mandate log proof --ledger ledger.jsonl --index 0 --out proof.json >/dev/null
mandate log head --ledger ledger.jsonl --log-name log1 --log-key ./log_key \
  --out sth.json >/dev/null
mandate witness accept --state witness.json --sth sth.json >/dev/null
python3 - <<'PY'
import json
sth = json.load(open('sth.json'))['sth']
print('  tree_size=%s root=%s...' % (sth['tree_size'], sth['root_hash'][:16]))
PY

echo "build the audit bundle (receipt + intent + grant + proof + STH + witness)"
mandate audit bundle --receipt receipt.json --intent examples/intent.json \
  --grant grant.json --proof proof.json --sth sth.json \
  --witness-state witness.json --key ./approver_key --signer approver \
  --out bundle.json
python3 - <<'PY'
import hashlib, json
b = open('bundle.json','rb').read()
print('  bundle size:', len(b), 'bytes')
print('  bundle sha256:', hashlib.sha256(b).hexdigest()[:32] + '...')
json.loads(b)
print('  bundle is valid JSON')
PY

echo "verify the bundle with only the public signer file"
mandate --signers trust/allowed_signers audit verify \
  --bundle bundle.json --log-signers trust/allowed_signers
