"""DORA pack: the three documents a bank's ICT third-party file actually needs.

DORA (Regulation (EU) 2022/2554) puts the obligation on the financial entity, so a supplier can only
supply material, not compliance. This module produces that material:

  * a **register row** for Art. 28(3) — the register of information the entity maintains;
  * the **Art. 30(2) contractual points** and the Art. 30(3) access/audit rights, each mapped to an
    artefact we actually ship and the command that proves it;
  * an **incident notification timeline** under the reporting RTS.

Two honest notes that are part of the output, because they are the ones that get misquoted:

  1. **There is no DORA certification.** "DORA compliant" is not a thing a vendor can be; the
     entity's competent authority supervises the entity.
  2. **The deadlines are 4 hours, 24 hours and one month**, counted from classification as major
     under the reporting RTS. The often-quoted "72 hours" belongs to NIS2/GDPR-style regimes, not
     to DORA incident reporting. Getting this wrong in a template is how a supplier loses credibility
     in the first meeting.

Everything here is a template to be adapted by counsel; `to_verify_with_counsel` says so in the data.
"""
from __future__ import annotations

import os
import time

from . import controls

FORMAT = "mandate-dora-pack/1"
CLAUSE = "mandate-dora-clauses/1"


def _version() -> str:
    """Prefer the source tree's pyproject (running from a checkout), then the installed metadata."""
    pyproject = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "pyproject.toml")
    if os.path.exists(pyproject):
        import re
        match = re.search(r'^version = "([^"]+)"', open(pyproject, encoding="utf-8").read(),
                          re.M)
        if match:
            return match.group(1)
    try:
        import mandate
        return str(mandate.__version__)
    except Exception:  # noqa: BLE001
        return ""


def register_row(provider: str = "GAMA TRADE d.o.o. / gamAI",
                 product: str = "gama-mandate", lei: str = "",
                 contract_ref: str = "", version: str = "") -> dict:
    """One row of the Art. 28(3) register, with the fields we cannot fill left visibly empty."""
    summary = controls.summary()
    return {
        "format": FORMAT,
        "section": "register_of_information",
        "provider": {
            "name": provider,
            "lei": lei,
            "lei_note": ("" if lei else "LEI is the provider's legal entity identifier; the buyer "
                         "records it from the GLEIF register, not from the supplier's word"),
            "country": "BA",
            "contact_for_ict_incidents": "security contact in SECURITY.md",
        },
        "service": {
            "name": product,
            "version": version or _version(),
            "description": ("software library and CLI that binds a named human's signature to a "
                            "specific agent effect and keeps a hash-chained, externally timestamped "
                            "evidence record"),
            "ict_service_type": "software licence (on-premises), not a hosted service",
            "is_critical_or_important_function": "the buyer decides; the software is not on the "
                                                 "payment path by itself",
            "data_processed": "none by the provider; the buyer's records stay on the buyer's hosts",
            "data_locations": "buyer's infrastructure (the provider operates no service)",
            "subcontractors": "none for customer data (see subprocessors.json)",
            "integration_type": "library + CLI; optional MCP proxy and egress proxy",
            "reliance_on_other_ict_providers": ("PyPI and GitHub for distribution only; no runtime "
                                                "dependency (standard library)"),
            "exit_plan": ("MIT licence: the buyer may fork and maintain the source; records are "
                          "exported with mandate worm-export / mandate pack"),
            "audit_rights": "the buyer verifies evidence offline without the provider (mandate "
                            "verify-receipt, verify.html, spec/verify_offline.py)",
            "controls_have": summary["have"], "controls_partial": summary["partial"],
            "controls_gap": summary["gap"],
            "evidence_checked_on": int(time.time()),
        },
        "not_claimed": controls.load().get("not_claimed", []),
        "to_verify_with_counsel": [
            "the register schema version used by the buyer's competent authority",
            "whether the buyer classifies this as an ICT third-party service supporting a critical "
            "or important function",
        ],
    }


def clauses() -> dict:
    """Art. 30(2) points a–e and Art. 30(3) rights, each with the artefact that proves it."""
    rows = [
        {"ref": "Art. 30(2)(a)", "point": "clear and complete description of the services",
         "text": "The Supplier provides the software described in Annex A (version, functionality, "
                 "supported interfaces) and states what the software does not do.",
         "evidence": ["README.md (What it does not do)", "mandate controls",
                      "docs/REFERENCE.md"]},
        {"ref": "Art. 30(2)(b)", "point": "locations where data are processed and stored",
         "text": "The Supplier operates no service and processes no customer data. All records are "
                 "created and stored on the Customer's infrastructure; the Supplier has no remote "
                 "access by default.",
         "evidence": ["mandate doctor", "subprocessors.json", "docs/PROCUREMENT_ANSWERS.md"]},
        {"ref": "Art. 30(2)(c)", "point": "data protection provisions",
         "text": "The software transmits no customer data to the Supplier. Where the Customer "
                 "enables an adapter (payments, ERP, mail), the Customer is the controller of that "
                 "flow; no subprocessor is engaged by the Supplier.",
         "evidence": ["subprocessors.json", "SECURITY.md"]},
        {"ref": "Art. 30(2)(d)", "point": "availability, authenticity, integrity, confidentiality",
         "text": "Integrity and authenticity are the product: Ed25519 signatures over canonical "
                 "intents, a hash chain with .head, and RFC 3161 anchors. Availability of the "
                 "Customer's own infrastructure is outside the Supplier's control and stated as such.",
         "evidence": ["mandate chain", "mandate anchor --status", "mandate worm-verify",
                      "docs/TLOG.md"]},
        {"ref": "Art. 30(2)(e)", "point": "access, recovery and return of data on termination",
         "text": "Records remain the Customer's data in open formats; export and verification do not "
                 "stop with the contract. The MIT licence removes the escrow question.",
         "evidence": ["mandate export", "mandate worm-export", "mandate pack", "LICENSE"]},
        {"ref": "Art. 30(3)(a)", "point": "access, inspection and audit rights",
         "text": "The Customer may verify the Supplier's evidence at any time without the Supplier's "
                 "cooperation, using the published verification commands; the Supplier's release "
                 "process is auditable from the public log.",
         "evidence": ["spec/verify_offline.py", "verify.html", "tlog.html",
                      "tools/verify_pypi.py"]},
        {"ref": "Art. 30(3)(b)", "point": "cooperation with competent authorities",
         "text": "The Supplier answers a supervisory questionnaire with the shipped control matrix "
                 "and names what is missing instead of answering 'yes'.",
         "evidence": ["mandate controls --summary --framework dora", "docs/BANK_CONTROL_MATRIX.md"]},
        {"ref": "Art. 30(3)(e)", "point": "termination and exit",
         "text": "On termination the Customer keeps every artefact it exported; the Supplier deletes "
                 "any copy it holds and certifies the deletion in writing.",
         "evidence": ["contract_clauses.json (C2)", "docs/AP2.md"]},
    ]
    return {"format": CLAUSE, "clauses": rows,
            "note": "Template, not legal advice. Counsel adapts wording to the governing law and the "
                    "entity's policy; the references are to Regulation (EU) 2022/2554."}


def incident_timeline() -> dict:
    """The reporting clock, with the 72-hour myth corrected in the data itself."""
    return {
        "format": FORMAT,
        "section": "incident_reporting",
        "trigger": "classification as a major ICT-related incident by the financial entity",
        "deadlines": [
            {"when": "4 hours after classification", "what":
             "initial notification: incident type, affected services, start time, impact, "
             "cross-border effects, containment measures"},
            {"when": "24 hours after classification", "what":
             "intermediate report: updated impact, root cause direction, recovery measures, "
             "estimated restoration"},
            {"when": "within 1 month after classification (final report)", "what":
             "final report: root cause, actual impact, permanence measures, lessons learned"},
        ],
        "common_mistake": ("'72 hours' is not a DORA incident-reporting deadline; it belongs to "
                           "NIS2/GDPR-style regimes. Using it in a DORA template signals that the "
                           "template was copied, not read."),
        "supplier_commitment": ("the Supplier notifies the Customer without undue delay and within "
                               "24 hours of becoming aware of a security incident affecting the "
                               "software, with affected versions, failure mode, fix and a signed "
                               "advisory (contract clause C3)"),
        "what_the_supplier_can_evidence": [
            "the incident-detection records the software produced (detect --write)",
            "the tamper-evident chain that shows nothing was removed after the fact",
            "the release that fixed it, in the public log with an external timestamp",
        ],
        "to_verify_with_counsel": [
            "the buyer's incident classification procedure and reporting channel",
            "whether the entity reports to a competent authority or a lead overseer",
        ],
    }


def pack(provider: str = "", contract_ref: str = "", lei: str = "") -> dict:
    return {
        "format": FORMAT,
        "generated": int(time.time()),
        "register": register_row(provider or "GAMA TRADE d.o.o. / gamAI", lei=lei,
                                 contract_ref=contract_ref),
        "contract": clauses(),
        "incident": incident_timeline(),
        "not_claimed": [
            "DORA compliance or certification (there is no DORA certification; the entity is "
            "supervised, not the supplier)",
            "that the buyer's register schema is satisfied without adaptation",
            "legal advice",
        ],
    }


def render_markdown(pack_obj: dict) -> str:
    reg = pack_obj["register"]
    lines = ["# DORA pack — %s %s" % (reg["service"]["name"], reg["service"]["version"]),
             "",
             "Generated %s. Template, not legal advice; article references must be checked with "
             "counsel." % time.strftime("%Y-%m-%d", time.gmtime(pack_obj["generated"])),
             "",
             "## Register of information (Art. 28(3))", ""]
    for key, value in reg["provider"].items():
        lines.append("- **provider.%s**: %s" % (key, value or "—"))
    for key, value in reg["service"].items():
        if key.startswith("controls_"):
            continue
        lines.append("- **service.%s**: %s" % (key, value))
    svc = reg["service"]
    lines.append("- **controls**: %d have, %d partial, %d gap"
                 % (svc["controls_have"], svc["controls_partial"], svc["controls_gap"]))
    lines += ["", "## Contract (Art. 30)", ""]
    for row in pack_obj["contract"]["clauses"]:
        lines.append("### %s — %s" % (row["ref"], row["point"]))
        lines.append(row["text"])
        lines.append("")
        lines.append("Evidence: " + ", ".join("`%s`" % e for e in row["evidence"]))
        lines.append("")
    lines += ["## Incident reporting", "", pack_obj["incident"]["trigger"] + ":", ""]
    for item in pack_obj["incident"]["deadlines"]:
        lines.append("- **%s** — %s" % (item["when"], item["what"]))
    lines += ["", "> " + pack_obj["incident"]["common_mistake"], "",
              "## Not claimed", ""]
    for item in pack_obj["not_claimed"]:
        lines.append("- " + item)
    return "\n".join(lines) + "\n"
