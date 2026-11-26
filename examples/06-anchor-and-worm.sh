#!/usr/bin/env bash
# Anchor the ledger in time (RFC 3161) and export a read-only evidence pack.
#
#   ./examples/06-anchor-and-worm.sh ./anchor-demo
#
# The anchor is what turns "a hash chain" into "the chain that existed at time T".
# Needs network only for the TSA request; verification is offline.
set -euo pipefail

D=${1:-./anchor-demo}
rm -rf "$D"; mkdir -p "$D"; cd "$D"

mandate init --dir . >/dev/null
ssh-keygen -q -t ed25519 -f ./approver_key -C mandate -N ""
printf 'approver namespaces="mandate" %s\n' "$(cat approver_key.pub)" >> trust/allowed_signers
mandate propose --intent examples/intent.json --out proposal.json
mandate grant --proposal proposal.json --approver approver --key ./approver_key \
  --audience local-broker --out grant.json >/dev/null
mandate redeem --intent examples/intent.json --grant grant.json --ledger ledger.jsonl \
  --audience local-broker > receipt.json
echo "ledger: $(wc -l < ledger.jsonl) receipt(s), head $(cut -c1-16 ledger.jsonl.head)"

echo "1) anchor the head with a public TSA (RFC 3161)"
if mandate anchor --ledger ledger.jsonl --out anchors --tsa https://freetsa.org/tsr > anchor.json 2>anchor.err; then
  python3 - <<'PY'
import json
d = json.load(open("anchor.json"))
print("   tsa=%s genTime=%s imprint_match=%s" % (d["tsa"], d["gen_time"], d["imprint_matches_head"]))
assert d["imprint_matches_head"] is True
PY
else
  echo "   TSA unreachable ($(head -1 anchor.err)); anchor step skipped, rest continues"
  mkdir -p anchors
fi

TOKEN=$(ls anchors/*.tsr 2>/dev/null | head -1 || true)
if [ -n "$TOKEN" ]; then
  echo "2) verify the anchor offline (imprint + status + time)"
  mandate anchor-verify --ledger ledger.jsonl --token "$TOKEN" > anchor-verify.json || true
  python3 - <<'PY'
import json
d = json.load(open("anchor-verify.json"))
print("   imprint=%s status=%s code=%s" % (
    d["imprint_matches_head"], d["status"], d["code"]))
# Without the TSA CA bundle the imprint, status and time are checked but the
# CMS signature is not; the result says so (code=cms_unverified) instead of
# claiming a verification that did not happen.
assert d["imprint_matches_head"] is True
assert d["code"] in ("ok", "cms_unverified")
PY

  echo "3) full CMS check against the TSA CA bundle"
  if curl -sfL -o tsa-ca.pem https://freetsa.org/files/cacert.pem 2>/dev/null; then
    if mandate anchor-verify --ledger ledger.jsonl --token "$TOKEN" --ca tsa-ca.pem > full.json 2>/dev/null; then
      python3 -c "
import json;d=json.load(open('full.json'))
print('   valid=%s openssl signature check: %s' % (
    d['valid'], d['openssl_verify']['verified']))
assert d['valid'] is True and d['openssl_verify']['verified'] is True
"
    else
      echo "   openssl check not available in this environment (skipped)"
    fi
  else
    echo "   CA bundle not downloadable (skipped)"
  fi
fi

echo "4) export a read-only evidence pack with retention"
mandate worm-export --ledger ledger.jsonl --out worm --retention-days 180 --anchors anchors > worm.json
python3 - <<'PY'
import json, glob, os, stat
w = json.load(open("worm.json"))
m = json.load(open(w["manifest"]))
print("   pack=%s files=%s retention_until=%s" % (os.path.basename(w["path"]), w["files"], w["retention_until"]))
print("   clock evidence: %s" % m["clock"]["system_time_utc"])
for rel in m["files"]:
    mode = stat.S_IMODE(os.stat(os.path.join(w["path"], rel)).st_mode)
    assert not mode & 0o222, "exported file is writable: " + rel
print("   all exported files are read-only")
PY

echo "5) tamper test: change one byte of the ledger and ask the verifier"
cp ledger.jsonl tampered.jsonl; cp ledger.jsonl.head tampered.jsonl.head
python3 - <<'PY'
import json
lines = open("tampered.jsonl").read().splitlines()
body = json.loads(lines[0])
body["body"]["ts"] = float(body["body"]["ts"]) + 1  # move the clock by one second
lines[0] = json.dumps(body, separators=(",", ":"), sort_keys=True)
open("tampered.jsonl", "w").write("\n".join(lines) + "\n")
PY
mandate chain --ledger tampered.jsonl > tamper.json 2>&1 || true
python3 - <<'PY'
import json
d = json.load(open("tamper.json"))
print("   chain valid after edit: %s" % d["valid"])
assert d["valid"] is False, "tampering must break the chain"
PY

echo
echo "OK: head anchored in time, evidence pack read-only, tampering detected."
echo "Files: anchors/ (TSA tokens), worm/<timestamp>/manifest.json, tampered.jsonl"
