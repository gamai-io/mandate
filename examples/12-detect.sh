#!/usr/bin/env bash
# Runtime detection: agent using a human identity, velocity spike, and the alert
# landing in the same hash chain as the receipts.
#
#   ./examples/12-detect.sh ./detect-demo
set -euo pipefail

D=${1:-./detect-demo}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

mandate init --dir . >/dev/null
python3 - <<'PY'
import json
p = json.load(open("mandate/policy.json"))
p["detect"] = {"max_effects_per_hour": 3, "max_amount": 5000,
               "business_hours_utc": [0, 24],
               "human_principals": ["renato", "ops"]}
json.dump(p, open("mandate/policy.json", "w"), indent=1)
PY

ssh-keygen -q -t ed25519 -f approver_key -C approver -N ""
ssh-keygen -q -t ed25519 -f agent_key -C bank-agent -N ""
ssh-keygen -q -t ed25519 -f human_key -C renato -N ""
{
  printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)"
  printf 'bank-agent namespaces="mandate" %s\n' "$(cat agent_key.pub)"
  printf 'renato namespaces="mandate" %s\n' "$(cat human_key.pub)"
} >> trust/allowed_signers

effect () { # n agent
  python3 - "$1" "$2" > "intent$1.json" <<'PY'
import json, sys
n, agent = sys.argv[1], sys.argv[2]
json.dump({"v": 1, "actor": {"agent": agent, "session": "run-1"},
           "effect": {"kind": "payment.send", "target": "Example Supplier",
                      "amount": {"value": 100.0, "currency": "BAM"},
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

echo "1) one legitimate effect by the agent"
effect 1 bank-agent

echo "2) an effect where the acting identity is a human principal"
effect 2 renato

echo "3) a velocity spike (limit is 3 per hour)"
for n in 3 4 5; do effect "$n" bank-agent; done

echo "4) detect (read-only)"
mandate detect --ledger ledger.jsonl --policy mandate/policy.json > findings.json || true
python3 - <<'PY'
import json
d = json.load(open("findings.json"))
print("   ok=%s receipts=%s by_rule=%s" % (d["ok"], d["receipts"], d["by_rule"]))
assert d["ok"] is False
assert d["by_rule"].get("human_credential") == 1
assert d["by_rule"].get("velocity") == 1
for f in d["findings"]:
    if f["rule"] in ("human_credential", "velocity"):
        print("   %-16s %-6s %s %s" % (f["rule"], f["severity"], f["agent"], f["evidence"]))
PY

echo "5) write the alert into the same hash chain"
before=$(wc -l < ledger.jsonl)
mandate detect --ledger ledger.jsonl --policy mandate/policy.json --write >/dev/null || true
after=$(wc -l < ledger.jsonl)
echo "   ledger entries $before -> $after"
mandate chain --ledger ledger.jsonl | tr -d '\n'; echo
python3 - <<'PY'
import json
last = [json.loads(l)["body"] for l in open("ledger.jsonl")][-1]
print("   last record: type=%s action=%s findings=%s"
      % (last["type"], last["action"], len(last["findings"])))
assert last["type"] == "control" and last["action"] == "alert"
PY

echo
echo "OK: human identity and velocity detected, alert appended to the chain."
