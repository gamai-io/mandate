"""How strongly was an effect captured? The honesty field of a receipt.

Three classes, from weakest to strongest:

  self_reported  — the agent says it happened; nothing enforced it. Anyone can
                   write this, so it proves intent, not execution.
  observed       — a hook or adapter saw the call but could not block it
                   (framework callback, passive telemetry, log tail).
  enforced       — the effect could not happen without passing `redeem`; the
                   gate refused everything that was not authorized.

Why a separate field: a receipt that does not say *how* it was captured invites
the reader to assume the strongest case. That is the same class of error as a
capability list that advertises a command nobody implemented. Policy may also
demand a minimum class for a given effect kind (`require_coverage`), which is
how a bank says "payments must be enforced, not observed".

Code stays dependency-free so it can be imported by the verifier, the broker and
third-party tools without pulling the rest of mandate in.
"""
from __future__ import annotations

# weakest -> strongest
ORDER = ("self_reported", "observed", "enforced")
RANK = {name: i for i, name in enumerate(ORDER)}
CODE = "E_COVERAGE"


class CoverageError(ValueError):
    """Raised for an unknown coverage value. Carries a machine code."""

    code = CODE

    def __init__(self, message: str):
        super().__init__(message)
        self.code = CODE


def norm(value) -> str:
    """Validate and canonicalise a coverage value."""
    if not isinstance(value, str):
        raise CoverageError("coverage must be a string, one of: %s" % ", ".join(ORDER))
    key = value.strip().lower().replace("-", "_").replace(" ", "_")
    if key not in RANK:
        raise CoverageError("coverage must be one of %s, got %r"
                            % (", ".join(ORDER), value))
    return key


def rank(value) -> int:
    return RANK[norm(value)]


def meets(actual, required) -> bool:
    """True when `actual` is at least as strong as `required`."""
    return rank(actual) >= rank(required)


def weakest(*values) -> str:
    """The weakest of the given classes (used when merging several sources)."""
    vals = [norm(v) for v in values if v is not None]
    if not vals:
        raise CoverageError("no coverage value given")
    return min(vals, key=lambda v: RANK[v])


def describe(value) -> str:
    return {
        "enforced": "enforced by the gate (could not happen without redeem)",
        "observed": "observed by a hook; not blocked",
        "self_reported": "self-reported by the agent; not enforced",
    }.get(norm(value), "unknown")
