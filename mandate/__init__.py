"""Mandate: signed, verifiable business commitments for AI agents."""

from .core import (  # noqa: F401
    CommitmentMismatch,
    GrantExpired,
    GrantInvalid,
    GrantReplayed,
    HardwareKeyRequired,
    MandateError,
    PolicyDenied,
    ProvenanceMissing,
    SelfApproval,
    append_receipt,
    build_grant_core,
    build_receipt,
    check,
    intent_commitment,
    jcs,
    load_policy,
    make_grant,
    normalize_intent,
    proposal_id,
    propose,
    read_ledger,
    redeem,
    render,
    render_hash,
    sha256,
    verify_authorization,
    verify_chain,
    verify_grant,
    verify_receipt,
    verify_result_entry,
)

try:  # single source of truth: installed distribution metadata
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("gama-mandate")
except Exception:  # running from a source tree without an installed dist
    __version__ = "1.0.18"
