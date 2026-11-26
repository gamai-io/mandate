#!/usr/bin/env bash
# The three documents an auditor asks for, generated from the ledger:
#   row 1  agent inventory        row 10 change records        row 11 evidence pack
#
#   ./examples/13-audit-pack.sh ./audit-demo
set -euo pipefail

D=${1:-./audit-demo}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

mandate init --dir . >/dev/null
ssh-keygen -q -t ed25519 -f approver_key -C approver -N ""
ssh-keygen -q -t ed25519 -f agent_key -C bank-agent -N ""
{
  printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)"
  printf 'bank-agent namespaces="mandate" %s\n' "$(cat agent_key.pub)"
} >> trust/allowed_signers

effect () { # n agent amount
  python3 - "$1" "$2" "$3" > "intent$1.json" <<'PY'
import json, sys
n, agent, amount = sys.argv[1], sys.argv[2], float(sys.argv[3])
json.dump({"v": 1, "actor": {"agent": agent, "session": "run-1"},
           "effect": {"kind": "payment.send", "target": "Example Supplier",
                      "amount": {"value": amount, "currency": "BAM"},
                      "params": {"ref": "inv-%s" % n}},
           "requested_by": "ops", "nonce": "n-%s" % n,
           "provenance": [{"type": "data_ref", "source": "erp:vendors:1"}]}, sys.stdout)
PY
  mandate propose --intent "intent$1.json" --out "prop$1.json" >/dev/null
  mandate grant --proposal "prop$1.json" --approver approver --key ./approver_key \
    --policy mandate/policy.json \
    --audience local-broker --out "grant$1.json" >/dev/null
  mandate redeem --intent "intent$1.json" --grant "grant$1.json" \
    --ledger ledger.jsonl --policy mandate/policy.json --audience local-broker >/dev/null
}

echo "1) some real activity"
effect 1 bank-agent 100
effect 2 bank-agent 250
effect 3 bank-agent 90

echo "2) row 10: a control change, hashed and signed by its approver"
python3 - <<'PY'
import json
p = json.load(open("mandate/policy.json"))
p["limits"] = {"max_effects": 5, "max_amount": 1000, "currency": "BAM",
               "window_seconds": 3600}
json.dump(p, open("mandate/policy.json", "w"), indent=1)
PY
mandate change record --ledger ledger.jsonl --file mandate/policy.json \
  --approver approver --key ./approver_key --reason "raise effect budget to 5/hour" > change.json
mandate change list --ledger ledger.jsonl --signers trust/allowed_signers \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
c=d['changes'][0]
print('   change: %s sha=%s signed=%s' % (c['file'], c['sha256'][:12], c['signature_valid']))
assert d['count'] == 1 and c['signature_valid'] is True
"

echo "3) row 1: agent inventory derived from the ledger"
mandate inventory --ledger ledger.jsonl --owner bank-agent=payments-ops \
  --out inventory.json --csv inventory.csv
column -s, -t < inventory.csv | cut -c1-100

echo "4) row 11: the evidence pack"
mandate pack --ledger ledger.jsonl --out audit-pack --owner bank-agent=payments-ops \
  --controls ../docs/BANK_CONTROL_MATRIX.md > pack.json 2>/dev/null || \
mandate pack --ledger ledger.jsonl --out audit-pack --owner bank-agent=payments-ops > pack.json
python3 - <<'PY'
import hashlib, json, os
index = json.load(open("audit-pack/index.json"))
print("   files:", ", ".join(sorted(index["files"])))
print("   agents=%s changes=%s entries=%s head=%s..."
      % (index["agents"], index["changes"], index["ledger_entries"],
         index["ledger_head"][:12]))
for name, meta in index["files"].items():
    full = os.path.join("audit-pack", name)
    digest = hashlib.sha256(open(full, "rb").read()).hexdigest()
    assert digest == meta["sha256"], "hash mismatch for " + name
print("   every file hash in index.json matches")
roi = json.load(open("audit-pack/dora_roi.json"))
for key in ("service", "provider", "data_location", "exit_plan", "audit_rights"):
    assert key in roi, key
print("   DORA row fields present:", ", ".join(roi))
PY

echo "5) the pack is traceable to the chain"
mandate chain --ledger ledger.jsonl | tr -d '\n'; echo

echo
echo "OK: inventory, signed change records and a DORA pack, all generated from the ledger."
echo "Files: inventory.csv, change.json, audit-pack/ (5 files + index.json)"
