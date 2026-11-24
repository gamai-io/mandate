#!/usr/bin/env bash
# Warden: stop an agent from outside, prove it stopped, record the stop.
#
#   ./examples/07-warden.sh ./warden-demo
#
# The child process below stands in for an agent loop: it writes a heartbeat
# every 10 ms. Freezing it must stop the heartbeat, and the stop must land in the
# hash-chained ledger with the evidence (pids, states, time-to-halt).
set -euo pipefail

D=${1:-./warden-demo}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

cat > agent.py <<'PY'
import sys, time
path = sys.argv[1]
i = 0
while True:
    i += 1
    open(path, "w").write(str(i))
    time.sleep(0.01)
PY

setsid python3 agent.py heartbeat >/dev/null 2>&1 &
AGENT=$!
disown 2>/dev/null || true
trap 'kill -9 $AGENT 2>/dev/null || true' EXIT
sleep 0.4
echo "agent pid=$AGENT heartbeat=$(cat heartbeat) (runs in its own session)"

echo "1) freeze from outside and wait until the kernel says stopped"
mandate warden --pgid "$AGENT" --method freeze --reason "runaway loop" --actor ops \
  --ledger ledger.jsonl > freeze.json
python3 - <<'PY'
import json
d = json.load(open("freeze.json"))
print("   verified=%s states=%s time_to_halt_ms=%s"
      % (d["verified"], d["states_after"], d["time_to_halt_ms"]))
assert d["verified"] is True
assert list(d["states_after"].values()) == ["T"]
assert d["time_to_halt_ms"] < 1000
PY

frozen=$(cat heartbeat); sleep 0.5; after=$(cat heartbeat)
echo "   heartbeat frozen at $frozen, still $after after 500 ms"
[ "$frozen" = "$after" ] || { echo "FAIL: process kept working while frozen"; exit 1; }

echo "2) the stop is in the ledger, and the chain is still valid"
mandate chain --ledger ledger.jsonl | python3 -c "
import json,sys
d=json.load(sys.stdin); print('   chain valid=%s entries=%s' % (d['valid'], d['entries']))
assert d['valid'] is True
"

echo "3) resume: the heartbeat moves again, and that is recorded too"
mandate warden --pgid "$AGENT" --resume --reason "root cause fixed" --actor ops \
  --ledger ledger.jsonl > resume.json
before=$(cat heartbeat); sleep 0.3; moved=$(cat heartbeat)
echo "   heartbeat $before -> $moved"
[ "$moved" != "$before" ] || { echo "FAIL: resume did not restart work"; exit 1; }

echo "4) hard stop for a compromised agent"
mandate warden --pgid "$AGENT" --method kill --reason "credential misuse" --actor ops \
  --ledger ledger.jsonl > kill.json
python3 - <<'PY'
import json
d = json.load(open("kill.json"))
print("   verified=%s states=%s" % (d["verified"], d["states_after"]))
assert d["verified"] is True
PY
sleep 0.2
if kill -0 "$AGENT" 2>/dev/null; then echo "FAIL: process survived kill"; exit 1; fi
echo "   process is gone"

echo "5) both stops and the resume are audit events with actors and reasons"
python3 - <<'PY'
import collections, json
actions = collections.Counter()
for line in open("ledger.jsonl"):
    body = json.loads(line)["body"]
    if body.get("type") == "control":
        actions[(body["action"], body["actor"], body["reason"])] += 1
for key, n in actions.items():
    print("   %-6s by %-4s: %s" % key)
assert sum(actions.values()) == 3
PY

echo
echo "OK: freeze verified by kernel state, time-to-halt measured, kill confirmed, all recorded."
echo "Files: ledger.jsonl (control records), freeze.json, resume.json, kill.json"
