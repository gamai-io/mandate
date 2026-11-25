#!/usr/bin/env python3
"""Assemble the folder we actually send to a bank.

    python3 tools/make_pilot_kit.py --out pilot-kit

Copies the documents that exist (no duplicates, no rewrites), writes an index that
says what each one answers, a one-page summary for the person who will not read
the rest, and a manifest of SHA-256 hashes so the recipient can check that nothing
was swapped in transit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOCS = [
    ("01-pilot-sow.md", "docs/PILOT_SOW_TEMPLATE.md",
     "the offer: six weeks, one workflow, deliverables D1-D6, fee band, exit"),
    ("02-control-matrix.md", "docs/BANK_CONTROL_MATRIX.md",
     "12 controls against the evidence this repository produces, and the gaps"),
    ("03-procurement-answers.md", "docs/PROCUREMENT_ANSWERS.md",
     "the questionnaire answers, including the honest no's"),
    ("04-incident-response.md", "docs/INCIDENT_RESPONSE.md",
     "the first five minutes when something goes wrong"),
    ("05-threat-context.md", "docs/THREAT_CONTEXT.md",
     "why this exists, against the ARTEX/FBI reporting"),
    ("06-performance.md", "docs/PERFORMANCE.md",
     "measured numbers and the method, with what is not measured"),
    ("07-dora-supplier-pack.md", "docs/DORA_SUPPLIER_PACK.md",
     "register data points, contract elements, and what is missing"),
    ("08-security.md", "SECURITY.md",
     "supported versions, how releases are signed, what we do not claim"),
]

ONE_PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<title>Mandate - one page</title>
<style>
body{{font:16px/1.55 system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 20px;color:#111}}
h1{{font-size:26px;margin:0 0 4px}} .sub{{color:#555;margin:0 0 24px}}
h2{{font-size:17px;margin:26px 0 6px}} table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #ddd;padding:6px 4px;text-align:left;vertical-align:top;font-size:14px}}
code{{background:#f3f3f3;padding:1px 5px;border-radius:4px;font-size:13px}}
.note{{color:#555;font-size:13px}}
</style>
<h1>Who approved this exact payment?</h1>
<p class="sub">Signed approval of a business effect, one-shot, verifiable offline.
Open source (MIT), on your infrastructure.</p>

<h2>What it does</h2>
<table>
<tr><th>Step</th><th>What happens</th></tr>
<tr><td>1. Intent</td><td>the agent states the effect: kind, target, amount, reference, evidence</td></tr>
<tr><td>2. Commitment</td><td>a canonical hash over that exact content, including agent, session and nonce</td></tr>
<tr><td>3. Grant</td><td>a named person signs it with their own Ed25519 key; the key is not on the agent host</td></tr>
<tr><td>4. Redeem</td><td>the broker verifies, spends the grant once, executes, appends a receipt to a hash chain</td></tr>
<tr><td>5. Verify</td><td>anyone checks the receipt offline, without the vendor: two independent verifiers</td></tr>
</table>

<h2>What a bank gets</h2>
<table>
<tr><td>Evidence</td><td>hash-chained receipts, optional RFC 3161 anchors, audit pack with inventory and changes</td></tr>
<tr><td>Containment of the effect</td><td>the agent never holds the payment credential; the broker does</td></tr>
<tr><td>Approval a human can actually do</td><td>browser page with a passkey, bound to the rendered amount</td></tr>
<tr><td>Numbers</td><td>10,000 receipts: 9.7 ms each to write, 1.94 s to verify, 0.55 s to pack</td></tr>
</table>

<h2>What it is not</h2>
<p class="note">Not a certificate. Not tamper-proof (tamper-evident against the last
anchor). Not containment of a compromised host. Not a payment protocol - it is the
control and the evidence underneath one. No independent pentest yet; that is stated
in the procurement answers, not hidden.</p>

<h2>How to check us</h2>
<p class="note"><code>mandate demo</code> runs the whole chain in about a minute.
<code>spec/verify_offline.py</code> and <code>spec/verify_offline.js</code> verify a
receipt without our package. PyPI artefacts carry provenance:
<code>https://pypi.org/integrity/gama-mandate/{version}/</code>.</p>

<p class="note">GAMA TRADE d.o.o. / gamAI - gamai.io - generated {stamp}</p>
</html>
"""


def build(out: str) -> dict:
    os.makedirs(out, exist_ok=True)
    for stale in os.listdir(out):
        path = os.path.join(out, stale)
        if os.path.isfile(path):
            os.remove(path)
    copied = []
    rows = []
    for target, source, purpose in DOCS:
        src = os.path.join(ROOT, source)
        if not os.path.exists(src):
            continue
        shutil.copy2(src, os.path.join(out, target))
        copied.append(target)
        rows.append("| `%s` | %s |" % (target, purpose))
    version = _version()
    page = ONE_PAGE.format(version=version,
                           stamp=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
    open(os.path.join(out, "00-one-page.html"), "w", encoding="utf-8").write(page)
    copied.insert(0, "00-one-page.html")

    index = "\n".join([
        "# Mandate — pilot kit",
        "",
        "Send this folder as one file. It answers, in order: what the offer is, what",
        "we control and prove, what we do **not**, what happens in an incident, why",
        "the work exists, and how fast it is.",
        "",
        "| file | answers |",
        "|---|---|",
        "| `00-one-page.html` | the whole thing on one printable page |",
    ] + rows + [
        "",
        "`MANIFEST.sha256` lists a hash per file, so the recipient can confirm that",
        "nothing was changed in transit.",
        "",
        "Version: `%s`. Everything here is generated from the repository by" % version,
        "`tools/make_pilot_kit.py`; the claims inside are checked by `tools/claims.py`.",
        "",
    ])
    open(os.path.join(out, "README.md"), "w", encoding="utf-8").write(index)

    digests = {}
    for name in sorted(copied):
        with open(os.path.join(out, name), "rb") as fh:
            digests[name] = hashlib.sha256(fh.read()).hexdigest()
    with open(os.path.join(out, "MANIFEST.sha256"), "w", encoding="utf-8") as fh:
        for name, digest in digests.items():
            fh.write("%s  %s\n" % (digest, name))
    return {"out": out, "version": version, "files": len(digests),
            "names": sorted(digests)}


def _version() -> str:
    for line in open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8"):
        if line.startswith("version = "):
            return line.split('"')[1]
    return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="pilot-kit")
    args = ap.parse_args()
    result = build(args.out)
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
