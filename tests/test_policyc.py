"""POLICYC_V1: a sentence becomes a limit, or it is refused — never guessed.

The dangerous compiler is the one that "understands". If a model turned "agents can pay suppliers"
into an auto-allow, no test would notice, because the sentence is the specification. These tests
therefore check both directions: the sentences that must compile, the sentences that must be
refused, and — most importantly — how the compiled policy actually decides sample intents,
including the currency and provenance cases that a careless compile would wave through.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest

from mandate import core, policyc

ROOT = pathlib.Path(__file__).resolve().parents[1]


def intent(kind: str, value: float = 0.0, currency: str = "EUR",
           source: str = "erp:vendor") -> dict:
    body = {"v": 1, "actor": {"agent": "a", "session": "s"}, "nonce": "n",
            "requested_by": "o", "effect": {"kind": kind, "target": "X"},
            "provenance": [{"type": "data_ref", "source": source}]}
    if kind not in ("read.lookup", "file.export", "process.exec"):
        body["effect"]["amount"] = {"value": value, "currency": currency}
    return body


class Compile(unittest.TestCase):
    def test_english_limit(self):
        rule = policyc.compile_rule("allow pay up to 500 EUR")["payment.send"]
        self.assertEqual(rule["max_auto"], 500.0)
        self.assertEqual(rule["max_auto_currency"], "EUR")

    def test_bosnian_limit_and_source(self):
        rule = policyc.compile_rule("dozvoli plaćanje do 300 BAM samo ako provenijencija "
                                    "sadrži erp:vendor")["payment.send"]
        self.assertEqual(rule["max_auto"], 300.0)
        self.assertEqual(rule["source_required"], "erp:vendor")

    def test_the_source_is_not_mistaken_for_an_effect(self):
        rule = policyc.compile_rule("allow pay up to 500 EUR only if provenance erp:vendor")
        self.assertEqual(list(rule), ["payment.send"])

    def test_deny(self):
        rule = policyc.compile_rule("zabrani izvoz fajlova")["file.export"]
        self.assertTrue(rule["deny"])

    def test_without_approval_is_refused_for_a_medium_risk_effect(self):
        with self.assertRaises(policyc.CompileError):
            policyc.compile_rule("dozvoli ponudu bez odobrenja")

    def test_always_is_allowed_only_for_a_read(self):
        rule = policyc.compile_rule("dozvoli čitanje uvijek")["read.lookup"]
        self.assertTrue(rule["always"])
        with self.assertRaises(policyc.CompileError):
            policyc.compile_rule("allow payment always")

    def test_a_sentence_with_two_effects_is_refused(self):
        with self.assertRaises(policyc.CompileError) as ctx:
            policyc.compile_rule("allow pay and export")
        self.assertIn("more than one effect", str(ctx.exception))

    def test_no_decision_word_is_refused(self):
        with self.assertRaises(policyc.CompileError):
            policyc.compile_rule("agents should probably be careful with payments")

    def test_unknown_effect_is_refused_with_the_known_list(self):
        with self.assertRaises(policyc.CompileError) as ctx:
            policyc.compile_rule("allow teleportation")
        self.assertIn("payment.send", str(ctx.exception))

    def test_allow_and_deny_in_one_sentence_is_refused(self):
        with self.assertRaises(policyc.CompileError):
            policyc.compile_rule("allow but also deny payment.send")

    def test_no_limit_means_approval_every_time(self):
        rule = policyc.compile_rule("allow send email")["message.send"]
        self.assertEqual(rule["max_auto"], 0)


class Decisions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = ("allow pay up to 500 EUR only if provenance erp:vendor\n"
                "zabrani izvoz fajlova\n"
                "dozvoli čitanje uvijek\n")
        compiled = policyc.compile_text(text, core.load_policy())
        cls.policy = policyc.merge_policy(core.load_policy(), compiled["compiled"])
        assert not compiled["refused"], compiled["refused"]

    def decision(self, kind, value=0.0, currency="EUR", source="erp:vendor"):
        return core.check(intent(kind, value, currency, source), self.policy)["decision"]

    def test_under_the_limit_with_the_right_source_is_allowed(self):
        self.assertEqual(self.decision("payment.send", 400.0), "allow")

    def test_over_the_limit_asks(self):
        self.assertEqual(self.decision("payment.send", 600.0), "ask")

    def test_a_currency_mismatch_asks(self):
        self.assertEqual(self.decision("payment.send", 400.0, currency="BAM"), "ask")

    def test_a_wrong_source_is_denied(self):
        self.assertEqual(self.decision("payment.send", 400.0, source="other:db"), "deny")

    def test_the_denied_effect_stays_denied(self):
        self.assertEqual(self.decision("file.export"), "deny")

    def test_the_read_is_allowed(self):
        self.assertEqual(self.decision("read.lookup"), "allow")

    def test_the_default_stays_deny_for_everything_unmentioned(self):
        self.assertEqual(self.decision("unknown.side_effect"), "deny")


class Corpus(unittest.TestCase):
    CASES = [
        ("allow pay up to 100 BAM", "payment.send"),
        ("dozvoli isplatu do 1.000,00 EUR", "payment.send"),
        ("allow create quote", "quote.create"),
        ("dozvoli ponudu do 5.000 EUR", "quote.create"),
        ("forbid sql writes", "sql.write"),
        ("zabrani slanje emaila", "message.send"),
        ("allow run command up to 0 EUR", "process.exec"),
        ("allow publish release", "package.publish"),
        ("dozvoli promjenu cijene do 50 EUR", "price.change"),
    ]

    def test_corpus_compiles_or_refuses_cleanly(self):
        base = core.load_policy()
        for sentence, expected in self.CASES:
            with self.subTest(sentence=sentence):
                rule = policyc.compile_rule(sentence, base)
                self.assertIn(expected, rule)
                self.assertTrue(rule[expected]["purpose"])

    def test_whole_documents_report_each_refusal(self):
        out = policyc.compile_text("allow pay up to 10 EUR\nnonsense\nallow export\n",
                                   core.load_policy())
        self.assertEqual(len(out["refused"]), 1)
        self.assertEqual(out["refused"][0]["line"], 2)
        self.assertEqual(out["lines"], 3)


class Cli(unittest.TestCase):
    def test_compile_writes_a_policy_and_explains_it(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rules = pathlib.Path(td) / "rules.txt"
            rules.write_text("allow pay up to 50 EUR\nzabrani izvoz\n", encoding="utf-8")
            out = pathlib.Path(td) / "policy.json"
            done = subprocess.run([sys.executable, "-m", "mandate", "policy", "compile",
                                   "--file", str(rules), "--out", str(out)],
                                  cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            payload = json.loads(done.stdout)
            self.assertEqual(payload["refused"], [])
            policy = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(policy["effects"]["payment.send"]["max_auto"], 50.0)
            self.assertTrue(policy["effects"]["file.export"]["deny"])
            self.assertEqual(policy["default"], "deny")

    def test_a_refusal_exits_four(self):
        done = subprocess.run([sys.executable, "-m", "mandate", "policy", "compile",
                               "--text", "please be reasonable with payments"],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(done.returncode, 4)
        payload = json.loads(done.stdout)
        self.assertEqual(len(payload["refused"]), 1)


if __name__ == "__main__":
    unittest.main()
