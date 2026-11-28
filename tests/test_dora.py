"""DORA_V1: the three documents a bank's ICT third-party file needs, with the myths removed.

The tests check the content a reviewer would challenge: are the Art. 30(2) points a–e all present
with an artefact behind each, is the audit right (Art. 30(3)) stated as something the customer can
exercise without us, and does the incident timeline avoid the "72 hours" that belongs to NIS2. A
template that repeats that mistake is worse than no template.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest

from mandate import dora

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Register(unittest.TestCase):
    def test_the_row_has_what_art_28_3_asks_for(self):
        row = dora.register_row(version="9.9.9")
        svc = row["service"]
        for key in ("name", "version", "description", "ict_service_type", "data_locations",
                    "subcontractors", "exit_plan", "audit_rights", "reliance_on_other_ict_providers"):
            self.assertTrue(svc.get(key), key)
        self.assertEqual(svc["version"], "9.9.9")
        self.assertIn("none", str(svc["subcontractors"]).lower())

    def test_the_lei_is_not_invented(self):
        row = dora.register_row()
        self.assertEqual(row["provider"]["lei"], "")
        self.assertIn("GLEIF", row["provider"]["lei_note"])

    def test_control_counts_come_from_the_matrix(self):
        row = dora.register_row()
        self.assertEqual(row["service"]["controls_have"]
                         + row["service"]["controls_partial"]
                         + row["service"]["controls_gap"], 12)

    def test_not_claimed_is_shipped(self):
        row = dora.register_row()
        joined = " ".join(row["not_claimed"])
        self.assertIn("tamper-proof", joined)
        self.assertIn("compliant or certified", joined)


class Contract(unittest.TestCase):
    def test_every_art_30_2_point_is_present_with_evidence(self):
        rows = dora.clauses()["clauses"]
        refs = [row["ref"] for row in rows]
        for point in ("(a)", "(b)", "(c)", "(d)", "(e)"):
            self.assertTrue(any(ref.endswith(point) for ref in refs), point)
        for row in rows:
            self.assertTrue(row["evidence"], row["ref"])
            self.assertTrue(row["text"].strip(), row["ref"])

    def test_the_audit_right_is_exercisable_without_us(self):
        rows = {row["ref"]: row for row in dora.clauses()["clauses"]}
        audit = rows["Art. 30(3)(a)"]
        joined = " ".join(audit["evidence"])
        self.assertIn("verify_offline.py", joined)
        self.assertIn("without the Supplier", audit["text"])

    def test_the_note_says_template(self):
        self.assertIn("not legal advice", dora.clauses()["note"])


class Incident(unittest.TestCase):
    def test_the_clock_is_4_24_and_one_month(self):
        when = [item["when"] for item in dora.incident_timeline()["deadlines"]]
        self.assertTrue(any(w.startswith("4 hours") for w in when), when)
        self.assertTrue(any(w.startswith("24 hours") for w in when), when)
        self.assertTrue(any("1 month" in w for w in when), when)

    def test_the_72_hour_myth_is_corrected_in_the_data(self):
        text = dora.incident_timeline()["common_mistake"]
        self.assertIn("72 hours", text)
        self.assertIn("not a DORA", text)
        self.assertIn("NIS2", text)

    def test_the_supplier_commitment_is_24_hours(self):
        self.assertIn("24 hours", dora.incident_timeline()["supplier_commitment"])


class Pack(unittest.TestCase):
    def test_pack_has_three_sections_and_denies_certification(self):
        pack = dora.pack()
        for key in ("register", "contract", "incident", "not_claimed"):
            self.assertIn(key, pack)
        joined = " ".join(pack["not_claimed"]).lower()
        self.assertIn("no dora certification", joined)

    def test_markdown_contains_the_sections_and_the_warning(self):
        text = dora.render_markdown(dora.pack())
        for heading in ("Register of information", "Contract (Art. 30)", "Incident reporting",
                        "Not claimed"):
            self.assertIn(heading, text)
        self.assertIn("not legal advice", text)
        self.assertIn("72 hours", text)


class Cli(unittest.TestCase):
    def test_json(self):
        done = subprocess.run([sys.executable, "-m", "mandate", "dora"], cwd=str(ROOT),
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        payload = json.loads(done.stdout)
        self.assertEqual(len(payload["contract"]["clauses"]), 8)

    def test_markdown_to_a_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "dora.md"
            done = subprocess.run([sys.executable, "-m", "mandate", "dora", "--format", "md",
                                   "--out", str(out)], cwd=str(ROOT), capture_output=True,
                                  text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("Art. 30(2)(a)", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
