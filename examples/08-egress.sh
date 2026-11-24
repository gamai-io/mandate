#!/usr/bin/env bash
# Egress control: deny by default, allow by name, authenticate, record everything.
#
#   ./examples/08-egress.sh ./egress-demo
#
# The July 2026 escape used a reachable network path, not a clever model. This
# demo shows the proxy refusing what is not on the list, refusing unauthenticated
# callers, and refusing the cloud metadata endpoint - with every decision written
# into the hash-chained ledger.
set -euo pipefail

D=${1:-./egress-demo}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

free_port () { python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()"; }
ORIGIN_PORT=$(free_port); PROXY_PORT=$(free_port)
echo "origin 127.0.0.1:$ORIGIN_PORT, proxy 127.0.0.1:$PROXY_PORT"

mkdir -p site && printf 'origin-ok\n' > site/index.html
(cd site && setsid python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
ORIGIN=$!
PROXY=0
cleanup () { [ "$PROXY" != 0 ] && kill "$PROXY" 2>/dev/null || true; kill "$ORIGIN" 2>/dev/null || true; }
trap cleanup EXIT
sleep 1

mandate egress policy --allow "127.0.0.1:$ORIGIN_PORT" --out egress.json >/dev/null
export MANDATE_EGRESS_TOKEN="demo-token-$RANDOM"
setsid mandate egress proxy --policy egress.json --port "$PROXY_PORT" --ledger egress.jsonl > proxy.log 2>&1 &
PROXY=$!
sleep 1.5

call () { # label expected_url expected_code extra_curl_args...
  local label=$1 url=$2 want=$3; shift 3
  local got
  got=$(curl -s -o /dev/null -w '%{http_code}' --noproxy '' -x "http://127.0.0.1:$PROXY_PORT" "$@" "$url" || true)
  printf '   %-22s %s (want %s)\n' "$label" "$got" "$want"
  [ "$got" = "$want" ] || { echo "FAIL: $label returned $got"; exit 1; }
}

echo "1) allowlisted destination, authenticated"
body=$(curl -s --noproxy '' -x "http://127.0.0.1:$PROXY_PORT" -H "Proxy-Authorization: Bearer $MANDATE_EGRESS_TOKEN" "http://127.0.0.1:$ORIGIN_PORT/")
echo "   body: $body"
[ "$body" = "origin-ok" ] || { echo "FAIL: body"; exit 1; }

echo "2) no token"
call "unauthenticated" "http://127.0.0.1:$ORIGIN_PORT/" 407

echo "3) wrong token"
call "wrong-token" "http://127.0.0.1:$ORIGIN_PORT/" 407 -H "Proxy-Authorization: Bearer wrong"

echo "4) destination that is not on the list"
call "not-allowlisted" "http://127.0.0.1:9/" 403 -H "Proxy-Authorization: Bearer $MANDATE_EGRESS_TOKEN"

echo "5) cloud metadata endpoint"
call "metadata" "http://169.254.169.254/latest/meta-data/" 403 -H "Proxy-Authorization: Bearer $MANDATE_EGRESS_TOKEN"

echo "6) the public internet, not on the list"
call "public-host" "http://pypi.org/" 403 -H "Proxy-Authorization: Bearer $MANDATE_EGRESS_TOKEN"

echo "7) every decision is in the ledger"
mandate egress summary --ledger egress.jsonl
mandate chain --ledger egress.jsonl | python3 -c "
import json,sys
d=json.load(sys.stdin); print('   chain valid=%s entries=%s' % (d['valid'], d['entries']))
assert d['valid'] is True
"
python3 - <<'PY'
import collections, json
c = collections.Counter()
for line in open("egress.jsonl"):
    b = json.loads(line)["body"]
    if b.get("action") == "egress":
        c[(b["decision"], b["code"])] += 1
print("   decisions:", dict(c))
assert c[("deny", "unauthenticated")] == 2
assert c[("deny", "metadata_endpoint")] == 1
PY

echo
echo "OK: only the allowlisted origin was reachable; everything else denied and recorded."
echo "Files: egress.json, egress.jsonl (control records), proxy.log"
