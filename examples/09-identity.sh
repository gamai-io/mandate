#!/usr/bin/env bash
# Short-lived identity and delegation that can only narrow.
#
#   ./examples/09-identity.sh ./identity-demo
#
# The agent gets a token, not a long-lived key in its filesystem. Sub-agents get
# a child token whose scopes are a subset of the parent's and whose expiry cannot
# be longer. Redeeming an effect requires the token to match the acting agent,
# the audience, the scope and the clock.
set -euo pipefail

D=${1:-./identity-demo}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

mandate init --dir . >/dev/null
ssh-keygen -q -t ed25519 -f approver_key -C mandate -N ""
ssh-keygen -q -t ed25519 -f agent_key -C bank-agent -N ""
ssh-keygen -q -t ed25519 -f sub_key -C sub-agent -N ""
{
  printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)"
  printf 'bank-agent namespaces="mandate" %s\n' "$(cat agent_key.pub)"
  printf 'sub-agent namespaces="mandate" %s\n' "$(cat sub_key.pub)"
} >> trust/allowed_signers

intent () { # session nonce agent
  python3 - "$1" "$2" "$3" > "intent_$1.json" <<'PY'
import json, sys
session, nonce, agent = sys.argv[1:4]
json.dump({"v": 1, "actor": {"agent": agent, "session": session},
           "effect": {"kind": "payment.send", "target": "Example Supplier",
                      "amount": {"value": 100.0, "currency": "BAM"},
                      "params": {"ref": "inv-1"}},
           "requested_by": "ops", "nonce": nonce,
           "provenance": [{"type": "data_ref", "source": "erp:vendors:1"}]}, sys.stdout)
PY
}

approved () { # session -> proposal+grant for that intent
  mandate propose --intent "intent_$1.json" --out "prop_$1.json" >/dev/null
  mandate grant --proposal "prop_$1.json" --approver approver --key ./approver_key \
    --audience local-broker --out "grant_$1.json" >/dev/null
}

echo "1) agent gets a 120-second token for one effect kind"
mandate svid issue --sub bank-agent --issuer bank-agent --key agent_key \
  --ttl 120 --audience local-broker --scope payment.send --out token.json
intent main n-1 bank-agent
approved main
mandate redeem --intent intent_main.json --grant grant_main.json --ledger ledger.jsonl \
  --svid token.json --audience local-broker --svid-audience local-broker \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('   redeemed with token, receipt %s...' % d['hash'][:12])"

echo "2) a token for a different effect kind is refused"
mandate svid issue --sub bank-agent --issuer bank-agent --key agent_key \
  --ttl 120 --audience local-broker --scope order.create --out token_scope.json >/dev/null
intent scope n-2 bank-agent
approved scope
set +e
mandate redeem --intent intent_scope.json --grant grant_scope.json --ledger ledger2.jsonl \
  --svid token_scope.json --audience local-broker --svid-audience local-broker > scope.json 2>&1
set -e
python3 -c "
import json;d=json.load(open('scope.json'));print('   refused: %s / %s' % (d['error'], d['code']))
assert d['code'] == 'scope_not_granted'"

echo "3) an expired token is refused"
mandate svid issue --sub bank-agent --issuer bank-agent --key agent_key \
  --ttl 1 --audience local-broker --scope payment.send --out token_exp.json >/dev/null
sleep 2
set +e
mandate redeem --intent intent_main.json --grant grant_main.json --ledger ledger3.jsonl \
  --svid token_exp.json --audience local-broker --svid-audience local-broker > exp.json 2>&1
set -e
python3 -c "
import json;d=json.load(open('exp.json'));print('   refused: %s / %s' % (d['error'], d['code']))
assert d['code'] == 'expired'"

echo "4) sub-agent gets a narrower child token (same scope, shorter life)"
mandate svid delegate --parent token.json --sub sub-agent --issuer sub-agent \
  --key sub_key --ttl 30 --scope payment.send --out child.json
python3 -c "
import json;c=json.load(open('child.json'))['payload'];print('   child exp <= parent exp:', c['exp'])
assert c['parent_sub'] == 'bank-agent'"
intent sub n-3 sub-agent
approved sub
mandate redeem --intent intent_sub.json --grant grant_sub.json --ledger ledger4.jsonl \
  --svid child.json --svid token.json --audience local-broker --svid-audience local-broker \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('   child redeemed, receipt %s...' % d['hash'][:12])"

echo "5) a child that tries to widen its scope is refused"
mandate svid delegate --parent token.json --sub sub-agent --issuer sub-agent \
  --key sub_key --ttl 30 --scope payment.send --scope order.create --out child_wide.json >/dev/null
set +e
mandate redeem --intent intent_sub.json --grant grant_sub.json --ledger ledger5.jsonl \
  --svid child_wide.json --svid token.json --audience local-broker --svid-audience local-broker > wide.json 2>&1
set -e
python3 -c "
import json;d=json.load(open('wide.json'));print('   refused: %s / %s' % (d['error'], d['code']))
assert d['code'] == 'scope_widened'"

echo
echo "OK: token required, scope and clock enforced, delegation can only narrow."
echo "Files: token.json, child.json, ledger.jsonl (receipts), ledger4.jsonl (delegated effect)"
