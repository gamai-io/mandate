"""Identifier folding for policy decisions (not for display).

The cheapest way around a name-based control is to change the name without
changing the meaning:

  * zero-width and bidi characters ("Apple\\u200b Inc")
  * homoglyphs ("Аpple" with Cyrillic А, "РаyPal" with Cyrillic Р/а)
  * compatibility forms (fullwidth "Ａｐｐｌｅ", ligatures)
  * diacritics on the same person ("Šuster" vs "Suster")

`fold()` maps both sides of a comparison to one canonical identifier, so a
payee that is already known cannot look new (or a blocked name cannot look
allowed) just by swapping a character. It is deliberately aggressive: it is
used for matching only, never to rewrite what gets stored or signed — the
receipt keeps the original bytes, and the audit trail stays truthful.

No dependencies outside the standard library.
"""
from __future__ import annotations

import unicodedata

# Zero-width, bidi controls, soft hyphen, word joiner — invisible in a UI,
# meaningful to a comparison.
_INVISIBLE = {
    0x00AD, 0x061C, 0x180E, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060, 0x2061, 0x2062,
    0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF,
}

# Confusables that matter for names of people, companies and currencies.
# Only unambiguous pairs (a letter that looks like exactly one Latin letter).
# Written as escapes on purpose: a literal Cyrillic "а" next to a Latin "a" is
# indistinguishable in an editor, and a silent mix-up turns this map into a no-op.
_CONFUSABLE_PAIRS = [
    # Cyrillic
    ("\u0430", "a"), ("\u0432", "b"), ("\u0435", "e"), ("\u043a", "k"),
    ("\u043c", "m"), ("\u043d", "h"), ("\u043e", "o"), ("\u0440", "p"),
    ("\u0441", "c"), ("\u0442", "t"), ("\u0443", "y"), ("\u0445", "x"),
    ("\u0456", "i"), ("\u0458", "j"), ("\u0455", "s"), ("\u0501", "d"),
    ("\u04bb", "h"), ("\u04cf", "l"), ("\u0261", "g"), ("\u051b", "q"),
    ("\u051d", "w"), ("\u0475", "v"), ("\u04af", "y"), ("\u04bd", "e"),
    ("\u04c0", "l"),
    # Armenian
    ("\u0561", "w"), ("\u0585", "o"), ("\u0581", "g"), ("\u057d", "u"),
    ("\u0578", "n"), ("\u0570", "h"), ("\u0566", "q"),
    # Greek
    ("\u03b1", "a"), ("\u03b2", "b"), ("\u03b3", "y"), ("\u03b5", "e"),
    ("\u03b7", "n"), ("\u03b9", "i"), ("\u03ba", "k"), ("\u03bb", "l"),
    ("\u03bc", "u"), ("\u03bd", "v"), ("\u03bf", "o"), ("\u03c1", "p"),
    ("\u03c2", "o"), ("\u03c3", "o"), ("\u03c4", "t"), ("\u03c5", "u"),
    ("\u03c7", "x"), ("\u03c9", "w"), ("\u03b6", "z"), ("\u03b8", "o"),
    ("\u03c0", "n"), ("\u03c6", "o"),
]
_CONFUSABLES = {ord(src): dst for src, dst in _CONFUSABLE_PAIRS}

# Letters that NFKD does not decompose into base + combining mark.
_SPECIAL = {ord("\u0111"): "dj", ord("\u0142"): "l", ord("\u00f8"): "o",
            ord("\u00e6"): "ae", ord("\u0153"): "oe", ord("\u00fe"): "th",
            ord("\u00f0"): "d", ord("\u0131"): "i"}


def _strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if ord(ch) not in _INVISIBLE
                   and unicodedata.category(ch) != "Cf")


def fold(text) -> str:
    """Canonical comparison form: lowercase, no invisible chars, no diacritics
    (via NFKD), compatibility forms unified, confusables mapped, whitespace
    collapsed."""
    if text is None:
        return ""
    s = str(text)
    s = _strip_invisible(s)
    s = s.casefold()                       # mora prije mape: „А" (U+0410) ≠ „а" (U+0430)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = unicodedata.normalize("NFKC", s)
    s = s.translate(_CONFUSABLES).translate(_SPECIAL)
    s = unicodedata.normalize("NFKC", s)
    s = " ".join(s.split())
    return s


def same(a, b) -> bool:
    """True when two identifiers fold to the same value."""
    return fold(a) == fold(b)


def differs_only_by_formatting(a, b) -> bool:
    """True when the raw strings differ but the folded identifiers match.

    Policy can use this to note "matched after normalization" in a refusal,
    so an auditor sees why a name that looks different was treated as the same.
    """
    return str(a) != str(b) and same(a, b)
