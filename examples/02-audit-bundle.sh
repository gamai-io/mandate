#!/usr/bin/env bash
# Offline audit: build a portable bundle for one effect and verify it without
# network, database or the Mandate installation that produced it.
#
#   ./examples/02-audit-bundle.sh ./demo2
set -euo pipefail

D=${1:-./mandate-audit}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

mandate init --dir . >/dev/null
ssh-keygen -q -t ed25519 -f ./approver_key -C mandate -N ""
printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)" >> trust/allowed_signers

mandate propose --intent examples/intent.json --out proposal.json
mandate grant --proposal proposal.json --approver approver --key ./approver_key \
  --audience local-broker --out grant.json >/dev/null
mandate redeem --intent examples/intent.json --grant grant.json --ledger ledger.jsonl > receipt.json

echo "ledger (hash-chained, one line per redeemed effect):"
wc -l < ledger.jsonl | sed 's/^/  entries: /'

echo "build the audit bundle (receipt + intent + grant + signatures)"
mandate audit bundle --receipt receipt.json --intent examples/intent.json \
  --grant grant.json --key ./approver_key --signer approver --out bundle.json
python3 - <<'PY'
import hashlib, json
b = open('bundle.json','rb').read()
print('  bundle size:', len(b), 'bytes')
print('  bundle sha256:', hashlib.sha256(b).hexdigest()[:32] + '...')
json.loads(b)
print('  bundle is valid JSON')
PY

echo "verify the bundle with only the public signer file"
mandate audit verify --bundle bundle.json --log-signers trust/allowed_signers | tail -5

echo
echo "OK. bundle.json can be mailed to an auditor; verification needs no secrets."
