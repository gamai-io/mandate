"""NORMALIZE_V1: a name cannot change meaning by changing characters.

Zero-width spaces, Cyrillic/Greek homoglyphs, fullwidth forms and diacritics are
the cheapest way to make a known payee look new (or a blocked one look fine).
`fold()` maps both sides to one identifier; receipts keep the original bytes.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from mandate import core, normalize, report


class Fold(unittest.TestCase):
    def test_homoglyphs(self):
        self.assertTrue(normalize.same("\u0410pple", "Apple"))      # cyrillic A
        self.assertTrue(normalize.same("\u0420\u0430yPal", "PayPal"))  # cyrillic P/a
        self.assertTrue(normalize.same("\u03bfPen", "oPen"))        # greek omicron

    def test_invisible_characters(self):
        self.assertTrue(normalize.same("App\u200ble", "Apple"))
        self.assertTrue(normalize.same("Ap\u00adple", "Apple"))      # soft hyphen
        self.assertTrue(normalize.same("\ufeffApple", "Apple"))      # BOM

    def test_compatibility_forms(self):
        self.assertTrue(normalize.same("\uff21\uff50\uff50\uff4c\uff45", "Apple"))  # fullwidth
        self.assertTrue(normalize.same("APPLE", "apple"))

    def test_diacritics_fold_to_same_person(self):
        self.assertTrue(normalize.same("Šuster", "Suster"))
        self.assertTrue(normalize.same("Đorđe", "Djordje"))

    def test_whitespace(self):
        self.assertTrue(normalize.same("  Apple   Inc  ", "apple inc"))
        self.assertTrue(normalize.same("Apple\tInc\n", "Apple Inc"))

    def test_different_names_stay_different(self):
        self.assertFalse(normalize.same("Apple Inc", "Apple Incorporated"))
        self.assertFalse(normalize.same("ACME", "ACME2"))

    def test_fold_is_idempotent(self):
        for raw in ("\u0410pple\u200b", "Šuster", "  A  B ", "\uff21\uff50"):
            once = normalize.fold(raw)
            self.assertEqual(once, normalize.fold(once))

    def test_differs_only_by_formatting(self):
        self.assertTrue(normalize.differs_only_by_formatting("\u0410pple", "Apple"))
        self.assertFalse(normalize.differs_only_by_formatting("Apple", "Apple"))
        self.assertFalse(normalize.differs_only_by_formatting("Apple", "Pear"))

    def test_empty_values(self):
        self.assertEqual(normalize.fold(None), "")
        self.assertEqual(normalize.fold(""), "")
        self.assertFalse(normalize.same(None, "x"))


class PayeeHistoryUsesFold(unittest.TestCase):
    """A payee paid as "Apple Inc" must be recognized when written "Аpple Inc"."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.td.name, "ledger.jsonl")
        core.append_receipt(self.ledger, {
            "v": 1, "type": "receipt", "decision": "executed", "ts": 1000,
            "render": {"fields": {"kind": "payment.send", "target": "Apple Inc",
                                  "amount": {"value": 10, "currency": "BAM"}}},
        })

    def tearDown(self):
        self.td.cleanup()

    def test_homoglyph_payee_is_not_new(self):
        hist = report.payee_history(self.ledger, "\u0410pple Inc", "payment.send")
        self.assertEqual(hist["payments"], 1)
        self.assertFalse(hist["first_time"])

    def test_zero_width_payee_is_not_new(self):
        hist = report.payee_history(self.ledger, "Apple\u200b Inc", "payment.send")
        self.assertEqual(hist["payments"], 1)

    def test_unrelated_payee_is_new(self):
        hist = report.payee_history(self.ledger, "Pear Ltd", "payment.send")
        self.assertEqual(hist["payments"], 0)
        self.assertTrue(hist["first_time"])

    def test_diacritics_variant_is_the_same_payee(self):
        hist = report.payee_history(self.ledger, "\u0160uster", "payment.send")
        self.assertEqual(hist["payments"], 0)      # nije placen, ali...
        core.append_receipt(self.ledger, {
            "v": 1, "type": "receipt", "decision": "executed", "ts": 1001,
            "render": {"fields": {"kind": "payment.send", "target": "Suster",
                                  "amount": {"value": 5, "currency": "BAM"}}},
        })
        hist = report.payee_history(self.ledger, "\u0160uster", "payment.send")
        self.assertEqual(hist["payments"], 1)      # ...sada jeste, kroz fold


if __name__ == "__main__":
    unittest.main()
