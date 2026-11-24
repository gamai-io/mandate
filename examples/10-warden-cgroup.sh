#!/usr/bin/env bash
# Warden tier 2: cgroup freezer observed by the kernel, network quarantine,
# and a stop signed by the operator so it cannot be repudiated.
#
#   sudo ./examples/10-warden-cgroup.sh ./warden-cgroup-demo
#
# Needs root (cgroup v2 + nftables). Delegation must allow creating a cgroup
# under /sys/fs/cgroup; if it does not, the script says so and stops.
set -euo pipefail

D=${1:-./warden-cgroup-demo}
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
trap 'kill -9 $AGENT 2>/dev/null || true; [ -n "${CG:-}" ] && rmdir "$CG" 2>/dev/null || true' EXIT
sleep 0.4
echo "agent pid=$AGENT heartbeat=$(cat heartbeat)"

NAME="demo-$$"
set +e
mandate warden --attach "$NAME" --pid "$AGENT" --reason "runaway loop" --actor ops \
  --ledger ledger.jsonl > freeze.json 2>freeze.err
rc=$?
set -e
if [ "$rc" != 0 ]; then
  echo "   cgroup attach failed (rc=$rc): $(head -2 freeze.err | tr '\n' ' ')"
  echo "   falling back to SIGSTOP warden (tier 1) is documented in README; stopping demo"
  exit 0
fi
CG=/sys/fs/cgroup/mandate/$NAME
python3 - <<'PY'
import json
d = json.load(open("freeze.json"))
print("   method=%s frozen=%s events=%s time_to_halt_ms=%s"
      % (d["method"], d["verified"], d.get("states_after"), d["time_to_halt_ms"]))
assert d["verified"] is True
assert (d.get("states_after") or {}).get("frozen") == "1"
PY

frozen=$(cat heartbeat); sleep 0.4; after=$(cat heartbeat)
echo "   heartbeat $frozen -> $after while frozen"
[ "$frozen" = "$after" ] || { echo "FAIL: cgroup freeze did not stop the work"; exit 1; }

echo "2) kernel state is the evidence, not our word"
grep -q "frozen 1" "$CG/cgroup.events"
echo "   $(tr '\n' ' ' < "$CG/cgroup.events")"

echo "3) resume (thaw) restarts the work"
mandate warden --cgroup "$CG" --resume --reason "root cause fixed" --actor ops \
  --ledger ledger.jsonl > thaw.json
before=$(cat heartbeat); sleep 0.3; moved=$(cat heartbeat)
echo "   heartbeat $before -> $moved"
[ "$moved" != "$before" ] || { echo "FAIL: thaw did not restart work"; exit 1; }

echo "4) a stop signed by the operator"
ssh-keygen -q -t ed25519 -f ops_key -C ops -N ""
printf 'ops namespaces="mandate" %s\n' "$(cat ops_key.pub)" > allowed_signers
mandate warden --cgroup "$CG" --method kill --reason "credential misuse" --actor ops \
  --key ./ops_key --signer ops --ledger ledger.jsonl > kill.json
python3 - <<'PY'
import json
d = json.load(open("kill.json"))
print("   killed, signed=%s signer=%s" % (d.get("signed"), d.get("signer")))
assert d.get("signed") is True
PY
mandate warden --verify --ledger ledger.jsonl --signers allowed_signers | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('   signed control records: %s, all valid: %s' % (d['signed_controls'], all(r['valid'] for r in d['results'])))
assert d['signed_controls'] >= 1 and all(r['valid'] for r in d['results'])
"

echo "5) network quarantine for one uid (the agent must run under its own uid)"
if [ "$(id -u)" = 0 ] && command -v nft >/dev/null; then
  mkdir -p site && echo origin-ok > site/index.html
  (cd site && setsid python3 -m http.server 18097 --bind 127.0.0.1 >/dev/null 2>&1) &
  ORIGIN=$!
  trap 'kill $ORIGIN 2>/dev/null || true; kill -9 $AGENT 2>/dev/null || true; rmdir "$CG" 2>/dev/null || true' EXIT
  sleep 1
  as_nobody () { setpriv --reuid=65534 --regid=65534 --clear-groups curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:18097/ || true; }
  echo "   before quarantine: $(as_nobody)"
  mandate warden --quarantine --uid 65534 --reason "network isolation" --actor ops \
    --ledger ledger.jsonl > q.json
  blocked=$(as_nobody)
  echo "   after quarantine:  ${blocked:-blocked}"
  [ "${blocked:-000}" = "000" ] || { echo "FAIL: uid still reachable"; exit 1; }
  mandate warden --quarantine --uid 65534 --undo --reason "restored" --actor ops \
    --ledger ledger.jsonl >/dev/null
  echo "   after undo:        $(as_nobody)"
else
  echo "   skipped (needs root + nftables)"
fi

echo
echo "OK: freeze observed by the kernel, stop signed by the operator, uid quarantined."
echo "Files: ledger.jsonl (controls incl. signature), freeze.json, kill.json, q.json"
