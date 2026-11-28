"""Compile a sentence into a policy fragment — deterministically, and refuse when unsure.

Why not an LLM: the output of this module becomes `max_auto`, the amount below which an agent acts
without a human. A model that "understands" could quietly widen a limit, and no test would catch it
because the sentence is the specification. So the grammar is small, explicit and bilingual, and
anything it does not parse is **refused with the reason**, never guessed.

Understood shape (Bosnian or English):

    allow  <kind phrase>  [up to <amount> <CUR>]  [only if provenance <source>]
    deny   <kind phrase>
    allow  <kind phrase>  always

    allow  pay  up to 500 EUR  only if provenance erp:vendor
    dozvoli plaćanje do 500 EUR samo ako provenijencija sadrži erp:vendor
    zabrani izvoz fajlova

Every compiled effect keeps the sentence in `purpose`, so a reviewer reads the rule and its source
next to each other. `risk` is taken from the base policy when the effect already exists, never
invented; a new effect is `high` with `max_auto: 0` unless the sentence explicitly grants a limit.
"""
from __future__ import annotations

import re

KINDS = [
    (("pay", "payment", "plati", "plat", "plaćanj", "placanj", "uplati", "isplati", "isplat"),
     "payment.send"),
    (("quote", "ponud"), "quote.create"),
    (("order", "narudž", "narudz", "poruč", "poruc"), "order.create"),
    (("email", "mail", "message", "poruk", "pošalji", "posalji", "obavijest"), "message.send"),
    (("export", "izvoz", "izvezi", "download", "preuzmi"), "file.export"),
    (("exec", "shell", "command", "komand", "pokreni", "izvrši", "izvrsi"), "process.exec"),
    (("sql", "update", "insert", "baza", "updatuj"), "sql.write"),
    (("publish", "objavi", "release", "objavljivanj"), "package.publish"),
    (("read", "lookup", "čitaj", "citaj", "čitanje", "citanje", "pretraž", "pretraz"),
     "read.lookup"),
    (("price", "cijen", "cijen", "cjenovnik"), "price.change"),
    (("supplier", "dobavlja", "vendor", "bank details", "račun dobavljača"), "supplier.change"),
    (("mcp", "tool", "alat"), "mcp.call"),
]

DENY_WORDS = ("deny", "zabran", "ne smije", "ne smij", "blokiraj", "forbid", "must not")
ALLOW_WORDS = ("allow", "dozvoli", "smije", "može", "moze", "dopusti", "permit")
ALWAYS_WORDS = ("always", "uvijek", "uvjek", "bez odobrenja", "without approval")
CURRENCIES = ("BAM", "EUR", "USD", "GBP", "CHF", "RSD", "HRK")
LIMIT_WORDS = ("up to", "do", "max", "maks", "najviše", "najvise", "<=", "najviše do")


LOW_RISK = {"read.lookup"}


class CompileError(Exception):
    pass


PROVENANCE_CLAUSE = re.compile(r"(?i)(only if provenance|samo ako provenijencij\w*|"
                               r"samo uz izvor|only when source).*$")


def _kind(text: str) -> tuple[str, str]:
    # the provenance source is data, not an effect name: "erp:vendor" must not read as
    # "supplier.change", which is how the first version refused a perfectly clear sentence
    body = PROVENANCE_CLAUSE.sub("", text)
    lowered = body.lower()
    hits = []
    for phrases, kind in KINDS:
        for phrase in phrases:
            # left boundary only: Bosnian inflects ("ponudu", "cijene", "emaila"), and a right
            # boundary made every inflected sentence unrecognisable
            if re.search(r"(?<![a-zčćšđž])" + re.escape(phrase.strip()), lowered):
                hits.append((len(phrase.strip()), phrase, kind))
    if not hits:
        raise CompileError("I do not recognise an effect in %r. Known effects: %s"
                           % (body.strip(), ", ".join(sorted({k for _, k in KINDS}))))
    kinds = {kind for _, _, kind in hits}
    if len(kinds) > 1:
        raise CompileError("the sentence names more than one effect (%s); one rule, one effect"
                           % ", ".join(sorted(kinds)))
    longest = max(hit[0] for hit in hits)
    phrase, kind = [(p, k) for length, p, k in hits if length == longest][0]
    return phrase, kind


def _amount(text: str) -> tuple[float | None, str]:
    match = re.search(r"(?i)(?:up to|do|max|maks|najviše|najvise|<=)?\s*"
                      r"(\d[\d.,]*)\s*(%s)\b" % "|".join(CURRENCIES), text)
    if not match:
        return None, ""
    raw = match.group(1).replace(".", "").replace(",", ".")
    try:
        return float(raw), match.group(2).upper()
    except ValueError as exc:
        raise CompileError("cannot read the amount %r" % match.group(0)) from exc


SOURCE_STOPWORDS = {"sadrži", "sadrzi", "contains", "includes", "sadrz", "with", "from"}

SOURCE_WORDS = (r"(?:only if provenance|samo ako provenijencij\w*|from source|iz izvora|"
                r"izvor\w*|source|provenijencij\w*|provenance)")


def _source(text: str) -> str:
    """The data source named after the provenance keyword; a token with ':' is required.

    A bare word here would swallow the tail of another word ("vendor" -> "or"), which is how the
    first version required a source called "or" and denied every correct intent.
    """
    after = re.search(r"(?i)" + SOURCE_WORDS, text)
    if not after:
        return ""
    tail = text[after.end():after.end() + 80]
    namespaced = re.search(r"([a-z0-9][a-z0-9_.-]*(?::[a-z0-9_.-]+)+)", tail)
    if namespaced:
        return namespaced.group(1)
    for word in re.findall(r"[a-z0-9_.-]{3,64}", tail):
        if word.lower() not in SOURCE_STOPWORDS:
            return word
    return ""


def compile_rule(sentence: str, base: dict | None = None) -> dict:
    """One sentence → one effect rule. Raises CompileError rather than guessing."""
    text = " ".join(str(sentence or "").split())
    if not text:
        raise CompileError("empty rule")
    lowered = text.lower()
    deny = any(word in lowered for word in DENY_WORDS)
    allow = any(word in lowered for word in ALLOW_WORDS)
    if deny and allow:
        raise CompileError("the sentence both allows and denies; write two rules")
    if not deny and not allow:
        raise CompileError("no decision word (allow/deny, dozvoli/zabrani) in %r" % text)
    _, kind = _kind(text)
    existing = ((base or {}).get("effects") or {}).get(kind) or {}
    amount, currency = _amount(text)
    source = _source(text)
    if deny:
        rule = {"risk": existing.get("risk", "high"), "max_auto": 0,
                "purpose": text, "deny": True}
        return {kind: rule}
    rule = {"risk": existing.get("risk", "high"), "purpose": text}
    always = any(word in lowered for word in ALWAYS_WORDS)
    if amount is None and not always:
        # no limit and no "always": the safe reading is "approval required"
        rule["max_auto"] = 0
    elif amount is not None:
        rule["max_auto"] = amount
        if currency:
            rule["max_auto_currency"] = currency
    elif kind in LOW_RISK or str(existing.get("risk") or "") == "low":
        # a read has no amount; auto-allowing it is the sentence's plain meaning
        rule["always"] = True
        rule["max_auto"] = 0
        rule["risk"] = "low"
    else:
        raise CompileError("'always' without an amount would auto-allow every %s; refuse to "
                           "compile that from one sentence" % kind)
    if source:
        rule["require_data_ref"] = ["target", "amount"] if kind == "payment.send" else ["target"]
        rule["source_required"] = source
    return {kind: rule}


def compile_text(text: str, base: dict | None = None) -> dict:
    """Compile a whole document; report every line separately so a refusal is visible."""
    out = {"compiled": {}, "refused": [], "lines": 0}
    for number, line in enumerate(str(text or "").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out["lines"] += 1
        try:
            rule = compile_rule(line, base)
        except CompileError as exc:
            out["refused"].append({"line": number, "text": line, "why": str(exc)})
            continue
        out["compiled"].update(rule)
    return out


def merge_policy(base: dict, compiled: dict) -> dict:
    """Apply compiled rules on top of a base policy, keeping `default: deny` unless told otherwise."""
    policy = {
        "version": base.get("version", 1),
        "default": base.get("default", "deny"),
        "effects": dict(base.get("effects") or {}),
    }
    for kind, rule in compiled.items():
        current = dict(policy["effects"].get(kind) or {})
        current.update(rule)
        policy["effects"][kind] = current
    return policy


def explain(compiled: dict) -> list[str]:
    lines = []
    for kind, rule in sorted(compiled.items()):
        if rule.get("deny"):
            lines.append("DENY  %-16s %s" % (kind, rule.get("purpose", "")))
            continue
        limit = rule.get("max_auto")
        if limit:
            lines.append("ALLOW %-16s up to %s %s without approval  | %s"
                         % (kind, limit, rule.get("max_auto_currency", ""), rule.get("purpose", "")))
        else:
            lines.append("ALLOW %-16s with approval on every call      | %s"
                         % (kind, rule.get("purpose", "")))
    return lines
