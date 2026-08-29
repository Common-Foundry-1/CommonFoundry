from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from production_v4_poseidon import MODULUS, DuplexChallenger, Extension


class ExtensionFieldTests(unittest.TestCase):
    def test_x4_equals_three(self) -> None:
        x = Extension((0, 1, 0, 0))
        self.assertEqual(x**4, Extension.from_base(3))

    def test_coefficient_first_multiplication(self) -> None:
        left = Extension((1, 2, 3, 4))
        right = Extension((5, 6, 7, 8))
        self.assertEqual(left * right, Extension((188, 172, 130, 60)))

    def test_inverse(self) -> None:
        value = Extension((7, 11, 13, 17))
        self.assertEqual(value * value.inverse(), Extension.one())
        with self.assertRaises(ZeroDivisionError):
            Extension.zero().inverse()

    def test_coefficients_are_canonicalized(self) -> None:
        self.assertEqual(
            Extension((MODULUS, -1, 0, 0)).coefficients, (0, MODULUS - 1, 0, 0)
        )


class ChallengerVectorTests(unittest.TestCase):
    def test_pinned_rust_challenger_vector(self) -> None:
        challenger = DuplexChallenger()
        challenger.observe_bytes(bytes(range(32)))
        first = challenger.sample_ext()
        challenger.observe_ext(first)
        second = challenger.sample_ext()
        bits = challenger.sample_bits(17)
        third = challenger.sample_ext()

        self.assertEqual(
            first.coefficients, (2072054569, 1667143315, 1060284628, 1940132924)
        )
        self.assertEqual(
            second.coefficients, (29929288, 1332930300, 2040675319, 1961178542)
        )
        self.assertEqual(bits, 17104)
        self.assertEqual(
            third.coefficients, (7203716, 404656108, 344185242, 1401671596)
        )


if __name__ == "__main__":
    unittest.main()
