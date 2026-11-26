#!/usr/bin/env bash
# Bank scenario: an agent with a budget, a kill switch, and four-eyes approval.
# Mirrors what US banks started doing in Nov 2026: limit runtime and volume,
# keep evidence out of the agent's reach, record a human approval, and make the
# stop itself auditable.
#
#   ./examples/05-bank-scenario.sh ./bank-demo
#
# Exit codes used by the CLI: 3 = separation-of-duties, 4 = governance (limits/halt).
set -euo pipefail

D=${1:-./bank-demo}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

mandate init --dir . >/dev/null
python3 - <<'PY'
import json
p = json.load(open("mandate/policy.json"))
p["limits"] = {"window_seconds": 3600, "max_effects": 3, "max_amount": 5000,
               "currency": "BAM", "max_total_seconds": 0}
json.dump(p, open("mandate/policy.json", "w"), indent=1)
print("limits: 3 effects / 5000 BAM per hour")
PY

ssh-keygen -q -t ed25519 -f ./approver_key -C mandate -N ""
printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)" >> trust/allowed_signers
ssh-keygen -q -t ed25519 -f ./agent_key -C agent -N ""
printf 'bank-agent namespaces="mandate" %s\n' "$(cat agent_key.pub)" >> trust/allowed_signers

intent () { # n amount
  python3 - "$1" "$2" > "intent$1.json" <<'PY'
import json, sys
n, amount = sys.argv[1], float(sys.argv[2])
json.dump({"v": 1, "actor": {"agent": "bank-agent", "session": "run-1"},
           "effect": {"kind": "payment.send", "target": "Example Supplier",
                      "amount": {"value": amount, "currency": "BAM"},
                      "params": {"ref": "inv-%s" % n}},
           "requested_by": "ops", "nonce": "n-%s" % n,
           "provenance": [{"type": "data_ref", "source": "erp:vendors:1"}]},
          sys.stdout)
PY
}

propose_grant () { # n
  mandate propose --intent "intent$1.json" --out "prop$1.json" >/dev/null
  mandate grant --proposal "prop$1.json" --approver approver --key ./approver_key \
    --policy mandate/policy.json \
    --audience local-broker --out "grant$1.json" >/dev/null
}

redeem () { # n
  mandate redeem --intent "intent$1.json" --grant "grant$1.json" \
    --ledger ledger.jsonl --policy mandate/policy.json --audience local-broker
}

echo "1) four-eyes: the agent tries to approve its own payment"
intent 1 100
mandate propose --intent intent1.json --out prop1.json >/dev/null
set +e
mandate grant --proposal prop1.json --approver bank-agent --key ./approver_key \
  --audience local-broker --out x.json > sod.json 2>&1
rc=$?
set -e
python3 - <<'PY'
import json
d = json.load(open("sod.json"))
print("   refused: %s (%s vs %s)" % (d["error"], d["detail"]["agent"], d["detail"]["approver"]))
assert d["error"] == "SeparationOfDuties"
PY
[ "$rc" = "3" ] || { echo "FAIL: expected exit 3, got $rc"; exit 1; }

echo "2) three approved payments go through"
for n in 2 3 4; do
  intent "$n" 100
  propose_grant "$n"
  redeem "$n" > "receipt$n.json"
  echo "   effect $n: ok"
done

echo "3) fourth effect is refused by the budget"
intent 5 100
propose_grant 5
set +e
redeem 5 > five.json 2>&1
rc=$?
set -e
python3 - <<'PY'
import json
d = json.load(open("five.json"))
print("   refused: %s used=%s max=%s" % (d["code"], d["detail"]["used"], d["detail"]["max"]))
assert d["code"] == "limit_effects"
PY
[ "$rc" = "4" ] || { echo "FAIL: expected exit 4, got $rc"; exit 1; }

echo "4) kill switch: ops halts the agent, the stop is on the record"
mandate halt --reason "runaway loop detected in run-1" --actor ops --ledger ledger.jsonl > halt.json
python3 - <<'PY'
import json
h = json.load(open("halt.json"))
print("   halted, ledger head %s..." % h["head"][:12])
PY
set +e
redeem 5 > halted.json 2>&1
set -e
python3 - <<'PY'
import json
d = json.load(open("halted.json"))
print("   redeem while halted: %s (%s)" % (d["code"], d["detail"]["reason"]))
assert d["code"] == "halted"
PY

echo "5) resume does NOT reset the budget"
mandate resume --reason "root cause fixed" --actor ops --ledger ledger.jsonl >/dev/null
set +e
redeem 5 > after.json 2>&1
set -e
python3 - <<'PY'
import json
d = json.load(open("after.json"))
print("   still refused: %s (used=%s)" % (d["code"], d["detail"]["used"]))
assert d["code"] == "limit_effects"
PY

echo "6) ops raises the budget deliberately; the next effect passes"
python3 - <<'PY'
import json
p = json.load(open("mandate/policy.json"))
p["limits"]["max_effects"] = 10
json.dump(p, open("mandate/policy.json", "w"), indent=1)
print("   limit raised to 10 for this investigation")
PY
# the policy digest is part of the grant: changing the policy invalidates the
# old grant, so the human approves the effect again under the new policy
propose_grant 5
redeem 5 > receipt5.json
python3 -c "import json;d=json.load(open('receipt5.json'));print('   effect 5: ok, receipt %s...' % d['hash'][:12])"

echo "7) the whole record verifies offline, including the halt/resume events"
mandate chain --ledger ledger.jsonl | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('   chain valid=%s entries=%s' % (d['valid'], d['entries']))
assert d['valid'] is True
"

echo "8) an auditor re-checks the approved effect offline"
mandate verify --receipt receipt2.json --intent intent2.json --grant grant2.json \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('   receipt for effect 2 valid=%s' % d['valid'])
assert d['valid'] is True
"

echo
echo "OK: four-eyes enforced, budget enforced, halt recorded, resume keeps the budget, chain valid."
echo "Files: ledger.jsonl (receipts + halt/resume), mandate/policy.json"
