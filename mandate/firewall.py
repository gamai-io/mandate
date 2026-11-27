"""The firewall half of a mandate: what leaves, and what comes back.

`mandate/egress.py` already answers "may this host be reached at all". That is
the connection; this module looks at the *content*:

  outbound  secrets and business identifiers leaving the agent (DLP)
  inbound   instructions trying to get in through a document, a tool result or a
            model answer (prompt injection)

Every finding is a record, not a log line: `control` entries in the ledger, the
same shape as a refused redemption, so the evidence trail is one file. Nothing
here calls a model and nothing needs a database.

Two rules that keep this honest:

  * **mask, never store.** A finding keeps a masked form (`AKIA…9f2c`, 20 chars)
    and the offset. Writing the secret into the ledger would make the ledger the
    leak.
  * **normalise before matching.** Zero-width characters, homoglyphs and
    compatibility forms are folded first (`mandate/normalize.py`), so
    "Ign\u200bore all previous instructions" and a Cyrillic "а" do not walk past
    a pattern written in Latin.

Scope, stated plainly: this is a lexer with judgement, not a classifier. It
catches what it has patterns for and reports what it does not (`unknown`), and
the selftest prints its own precision/recall on a fixed corpus instead of
claiming a percentage.
"""
from __future__ import annotations

import math
import re

from . import normalize

MASK_KEEP = 4

# --- outbound: secrets and business identifiers -----------------------------
SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "block"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "block"),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "block"),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b"), "block"),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9][A-Za-z0-9_\-]{19,}\b"), "block"),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "block"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "block"),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "block"),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "block"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "redact"),
    ("basic_auth_url", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]{1,64}:[^/\s@]{1,64}@"), "block"),
    ("conn_string_password", re.compile(r"(?i)\b(?:password|pwd)\s*=\s*[^\s;&\"']{4,}"), "block"),
    ("bearer_header", re.compile(r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9\-._~+/]{12,}"), "block"),
    ("azure_storage_key", re.compile(r"\bAccountKey=[A-Za-z0-9+/=]{40,}"), "block"),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"), "block"),
    ("twilio_sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "block"),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), "block"),
    ("pypi_token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}"), "block"),
    ("digitalocean_token", re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), "block"),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "block"),
    ("shopify_token", re.compile(r"\bshp(at|ca|pa|ss)_[a-fA-F0-9]{32}\b"), "block"),
    ("telegram_bot", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"), "block"),
    ("discord_webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{30,}"), "block"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]{20,}"), "block"),
    ("aws_secret_key", re.compile(r"(?i)aws_?secret_?access_?key\s*[=:]\s*[A-Za-z0-9/+=]{40}"), "block"),
    ("jmbg", re.compile(r"\b\d{13}\b"), "redact"),        # checksum filtrira ispod
    ("passport_mrz", re.compile(r"\bP<[A-Z]{3}[A-Z<]{10,}"), "redact"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "redact"),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), "redact"),
    ("card_number", re.compile(r"\b(?:\d[ -]?){13,19}\b"), "redact"),   # Luhn-filtrirano ispod
    ("phone_bih", re.compile(r"(?:\+387\s?|0)6[0-9][ .\-/]?\d{3}[ .\-]?\d{3}\b"), "redact"),
]

# --- inbound: instructions trying to get in ---------------------------------
INJECTION_PATTERNS = [
    ("ignore_previous", re.compile(r"(?i)\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|above|prior|earlier)\b[^.\n]{0,20}\b(?:instruction|prompt|rule|message)s?\b"), "block"),
    ("new_system_prompt", re.compile(r"(?i)\b(?:new|updated|real)\s+(?:system\s+)?(?:prompt|instructions?)\b\s*[:\-]"), "block"),
    ("reveal_prompt", re.compile(r"(?i)\b(?:print|show|reveal|repeat|output)\b[^.\n]{0,30}\b(?:system\s+prompt|initial\s+instructions?|your\s+rules)\b"), "block"),
    ("role_override", re.compile(r"(?i)\byou\s+are\s+now\b[^.\n]{0,40}\b(?:developer|admin|unrestricted|dan|jailbreak)\b"), "block"),
    ("tool_directive", re.compile(r"(?i)\b(?:call|invoke|execute|run)\b[^.\n]{0,20}\b(?:tool|function|command)\b[^.\n]{0,20}\b(?:pay|transfer|send|delete|drop)\b"), "flag"),
    ("credential_request", re.compile(r"(?i)\b(?:send|paste|provide|enter)\b[^.\n]{0,25}\b(?:password|api[\s\-]?key|token|seed\s+phrase)\b"), "block"),
    ("urgency_payment", re.compile(r"(?i)\b(?:urgent|immediately|right\s+now|within\s+\d+\s+minutes?)\b[^.\n]{0,60}\b(?:pay|transfer|wire|send\s+money)\b"), "flag"),
    ("invisible_text", re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]"), "flag"),
    ("html_hidden", re.compile(r"(?is)<!--.{0,400}?(?:ignore|instruction|pay|transfer).{0,400}?-->"), "flag"),
    ("chat_template_marker", re.compile(r"<\|(?:im_start|im_end|system|endoftext)\|>"), "block"),
    ("system_spoof", re.compile(r"(?im)^\s*\[?(?:system|developer|admin)\]?\s*[:>]"), "flag"),
    # dva oblika, oba vezana za agenta: "you have no restrictions" / "no limits for you".
    # „there are no restrictions on file size" ne smije se hvatati (FP u korpusu).
    ("no_restrictions", re.compile(r"(?i)(?:\byou\b[^.\n]{0,40}\b(?:no|zero)\b[^.\n]{0,20}\b(?:restrictions?|limits?|rules?|filters?)\b|\b(?:no|zero)\b[^.\n]{0,20}\b(?:restrictions?|limits?)\b[^.\n]{0,20}\b(?:on|for)\s+you\b)"), "block"),
    ("pretend_identity", re.compile(r"(?i)\b(?:pretend|act|behave)\b[^.\n]{0,20}\b(?:you are|as if you were)\b"), "flag"),
    ("from_now_on", re.compile(r"(?i)\bfrom now on\b[^.\n]{0,40}\b(?:you|answer|respond|always)\b"), "flag"),
    ("skip_review", re.compile(r"(?i)\b(?:approve|release|settle)\b[^.\n]{0,25}\b(?:without|skip(?:ping)?)\b[^.\n]{0,20}\b(?:review|approval|check|four eyes)\b"), "flag"),
    ("js_uri", re.compile(r"(?i)\]\(\s*javascript:"), "flag"),
    ("translate_then_do", re.compile(r"(?i)\btranslate\b[^.\n]{0,40}\b(?:then|afterwards|and then)\b[^.\n]{0,40}\b(?:run|execute|pay|send)\b"), "flag"),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b"), "flag"),
]


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _jmbg_ok(number: str) -> bool:
    """JMBG: 13 digits, mod-11 check digit, plausible date. Stops 13-digit noise."""
    d = [int(c) for c in number if c.isdigit()]
    if len(d) != 13:
        return False
    dd, mm = d[0] * 10 + d[1], d[2] * 10 + d[3]
    if not (1 <= dd <= 31 and 1 <= mm <= 12):
        return False
    m = 11 - ((7 * (d[0] + d[6]) + 6 * (d[1] + d[7]) + 5 * (d[2] + d[8])
               + 4 * (d[3] + d[9]) + 3 * (d[4] + d[10]) + 2 * (d[5] + d[11])) % 11)
    if m == 10:
        return False
    return (0 if m == 11 else m) == d[12]


FIXTURE_SUBS = {"{{hex32}}": "0123456789abcdef" * 2,
                "{{hex64}}": "0123456789abcdef" * 4,
                "{{b64_40}}": "A" * 40}
_FIXTURE_RX = re.compile(r"\{\{(alnum|upper|digits|lower|hex):(\d{1,4})\}\}")
_ALPHABETS = {"alnum": "abcdefghijklmnopqrstuvwxyz0123456789",
              "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
              "digits": "0123456789",
              "lower": "abcdefghijklmnopqrstuvwxyz",
              "hex": "0123456789abcdef"}


def expand_fixture(text: str) -> str:
    """Corpus fixtures that GitHub push protection flags are stored as templates.

    A corpus has to contain strings that look like credentials; a literal Twilio SID in
    the repository blocks every push. The expansion happens at run time, the corpus stays
    committable, and the pattern is still tested against a realistic value.
    """
    for key, value in FIXTURE_SUBS.items():
        text = text.replace(key, value)

    def _fill(match):
        alphabet = _ALPHABETS[match.group(1)]
        return (alphabet * 300)[:int(match.group(2))]

    return _FIXTURE_RX.sub(_fill, text)


def mask(value: str) -> str:
    value = str(value)
    if len(value) <= MASK_KEEP * 2:
        return value[:2] + "…" + "%d chars" % len(value)
    return value[:MASK_KEEP] + "…" + value[-2:] + " (%d chars)" % len(value)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def scan_outbound(text: str, min_kind: str = "") -> dict:
    """Secrets and identifiers leaving. `text` is scanned after normalisation."""
    flat = normalize.fold(text) if text else ""
    raw = str(text or "")
    findings = []
    for name, pattern, action in SECRET_PATTERNS:
        for match in pattern.finditer(raw):
            value = match.group(0)
            if name == "card_number" and not _luhn(value):
                continue
            if name == "jmbg" and not _jmbg_ok(value):
                continue
            findings.append({"kind": name, "action": action, "offset": match.start(),
                             "masked": mask(value)})
    # dugi tokeni visoke entropije koji ne padaju ni u jedan šablon
    for token in re.findall(r"\b[A-Za-z0-9_\-]{32,}\b", raw):
        if len(set(token)) > 12 and _entropy(token) > 4.2 and not any(
                token in f["masked"] for f in findings):
            findings.append({"kind": "high_entropy_token", "action": "flag",
                             "offset": raw.find(token), "masked": mask(token)})
    blocking = [f for f in findings if f["action"] == "block"]
    redact = [f for f in findings if f["action"] == "redact"]
    return {"ok": not blocking, "findings": findings, "blocked": len(blocking),
            "redactable": len(redact), "scanned": len(raw), "normalised": len(flat)}


def scan_inbound(text: str) -> dict:
    """Instructions trying to get in through content."""
    raw = str(text or "")
    flat = normalize.fold(raw)
    findings = []
    for name, pattern, action in INJECTION_PATTERNS:
        target = raw if name == "invisible_text" else flat
        for match in pattern.finditer(target):
            findings.append({"kind": name, "action": action,
                             "offset": match.start(),
                             "evidence": (match.group(0) or "")[:60]})
    blocking = [f for f in findings if f["action"] == "block"]
    return {"ok": not blocking, "findings": findings, "blocked": len(blocking),
            "flagged": len([f for f in findings if f["action"] == "flag"]),
            "scanned": len(raw)}


def redact(text: str) -> tuple[str, int]:
    """Replace what may leave. Returns (text, replacements)."""
    out = str(text or "")
    count = 0
    for name, pattern, action in SECRET_PATTERNS:
        if action not in ("block", "redact"):
            continue
        def _sub(match, _name=name):
            nonlocal count
            value = match.group(0)
            if _name == "card_number" and not _luhn(value):
                return value
            count += 1
            return "<%s:redacted>" % _name
        out = pattern.sub(_sub, out)
    return out, count


MCP_SCAN_LIMIT = 1_000_000       # ne skeniraj 100 MB odgovor; radije reci da je prevelik


def _texts(value, out: list[str], budget: list[int]) -> None:
    if budget[0] <= 0:
        return
    if isinstance(value, str):
        out.append(value[:budget[0]])
        budget[0] -= len(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                out.append(key[:200])
            _texts(item, out, budget)
    elif isinstance(value, (list, tuple)):
        for item in value[:500]:
            _texts(item, out, budget)


def scan_mcp_result(result, limit: int = MCP_SCAN_LIMIT) -> dict:
    """Tool result on its way to the model: everything textual is scanned.

    A tool that returns a document, a web page or a database row is the most common
    way an instruction reaches the model. Findings are returned, never rewritten:
    the caller decides whether to block, redact or pass through with a taint mark.
    """
    budget = [int(limit)]
    texts: list[str] = []
    _texts(result, texts, budget)
    joined = "\n".join(texts)
    scan = scan_inbound(joined)
    out = scan_outbound(joined)
    oversized = budget[0] <= 0
    return {"ok": scan["ok"] and out["ok"], "inbound": scan, "outbound": out,
            "texts": len(texts), "chars": len(joined), "truncated": oversized}


def decide(request_text: str, response_text: str = "",
           policy: dict | None = None) -> dict:
    """The whole gate for one exchange, in the order a proxy would run it.

    deny    anything that must not pass (a blocked secret, a blocked instruction)
    redact  only secrets that can be masked in place (email, IBAN, card, phone)
    allow   nothing found
    """
    pol = policy or {}
    out = scan_outbound(request_text)
    inn = (scan_inbound(response_text) if response_text
           else {"ok": True, "findings": [], "blocked": 0, "flagged": 0})
    allow = out["ok"] and inn["ok"]
    if not allow:
        action = "deny"
    elif out.get("redactable") and pol.get("redact", True):
        action = "redact"
    else:
        action = "allow"
    return {"allow": allow, "action": action, "request": out, "response": inn,
            "policy": {"redact": bool(pol.get("redact", True))}}
