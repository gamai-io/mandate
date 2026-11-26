#!/usr/bin/env bash
# 60-second demo: agent proposes a payment, a human approves it off-host,
# the agent redeems it exactly once, anyone verifies the receipt.
#
#   ./examples/01-invoice-approval.sh ./demo1
# Requires: gama-mandate installed (pip install gama-mandate), ssh-keygen.
set -euo pipefail

D=${1:-./mandate-demo}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

echo "1) init (policy, allowed_signers, config, example intent)"
mandate init --dir . >/dev/null

echo "2) approver key lives on the approver's device, never on the agent host"
ssh-keygen -q -t ed25519 -f ./approver_key -C mandate -N ""
printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)" >> trust/allowed_signers

echo "3) agent proposes (writes a canonical commitment, not a request string)"
mandate propose --intent examples/intent.json --out proposal.json
python3 -c "import json;p=json.load(open('proposal.json'));print('   proposal_id:',p['proposal_id']);print('   commitment :',p['commitment'][:24]+'...')"

echo "4) human grants: signs the commitment with the ed25519 key, bound to one broker"
mandate grant --proposal proposal.json --approver approver --key ./approver_key \
  --audience local-broker --out grant.json

echo "5) agent redeems once (receipt goes to stdout, hash-chained ledger on disk)"
mandate redeem --intent examples/intent.json --grant grant.json --ledger ledger.jsonl \
  --audience local-broker > receipt.json
python3 -c "import json;r=json.load(open('receipt.json'));print('   receipt hash:',r.get('hash','?')[:24]+'...')"

echo "6) verify offline: receipt + intent + grant, no network, no database"
mandate verify --receipt receipt.json --intent examples/intent.json --grant grant.json

echo "7) replay the same grant (must be rejected)"
if mandate redeem --intent examples/intent.json --grant grant.json --ledger ledger.jsonl \
    --audience local-broker >/dev/null 2>&1; then
  echo "FAIL: replay was accepted"; exit 1
else
  echo "   rejected as expected (GrantReplayed)"
fi

echo
echo "OK. Everything is in $PWD: grant.json, receipt.json, ledger.jsonl, trust/allowed_signers"
