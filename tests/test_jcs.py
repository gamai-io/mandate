import unittest

from mandate.jcs import canonicalize


class JcsTests(unittest.TestCase):
    def test_rfc8785_reference_vector(self):
        value = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3,
                        0.000000000000000000000000001],
            "string": "\u20ac$\u000f\u0010\nA'B\"\\\\\"/",
            "literals": [None, True, False],
        }
        expected = (
            '{"literals":[null,true,false],'
            '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
            '"string":"\u20ac$\\u000f\\u0010\\nA\'B\\"\\\\\\\\\\"/"}'
        )
        self.assertEqual(canonicalize(value), expected)

    def test_number_formatting(self):
        cases = [
            (1170.0, "1170"),
            (1170, "1170"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (1e21, "1e+21"),
            (4.5, "4.5"),
            (-0.0, "0"),
            (100.0, "100"),
            (0.000123, "0.000123"),
            (-2.5, "-2.5"),
        ]
        for value, expected in cases:
            self.assertEqual(canonicalize(value), expected, repr(value))

    def test_utf16_key_order(self):
        self.assertEqual(canonicalize({"\uffff": 1, "\U00010000": 2}),
                         '{"\U00010000":2,"\uffff":1}')

    def test_minimal_escaping(self):
        self.assertEqual(canonicalize("/"), '"/"')
        self.assertEqual(canonicalize("\u0000"), '"\\u0000"')
        self.assertEqual(canonicalize("\r"), '"\\r"')

    def test_rejects_non_finite(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                canonicalize(value)

    def test_rejects_unsafe_integer(self):
        with self.assertRaises(ValueError):
            canonicalize(2 ** 53)

    def test_rejects_lone_surrogate(self):
        with self.assertRaises(ValueError):
            canonicalize("\ud800")

    def test_rejects_non_string_keys(self):
        with self.assertRaises(TypeError):
            canonicalize({1: 2})


if __name__ == "__main__":
    unittest.main()
