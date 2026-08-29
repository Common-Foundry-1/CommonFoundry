from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from production_v4_poseidon import DuplexChallenger, Extension
from production_v4_transcript import (
    Sumcheck,
    TranscriptVerificationError,
    _polynomial_evaluate,
    _poseidon_compress,
    _poseidon_hash,
    _reverse_bits,
    _verify_sumcheck,
    _zero_plus_one,
)


class SumcheckTranscriptTests(unittest.TestCase):
    @staticmethod
    def valid_sumcheck() -> Sumcheck:
        prover = DuplexChallenger()
        first = (Extension.from_base(3), Extension.from_base(5))
        for coefficient in first:
            prover.observe_ext(coefficient)
        first_challenge = prover.sample_ext()
        previous_evaluation = _polynomial_evaluate(first, first_challenge)
        second = (Extension.zero(), previous_evaluation)
        for coefficient in second:
            prover.observe_ext(coefficient)
        second_challenge = prover.sample_ext()
        return Sumcheck(
            (first, second),
            _zero_plus_one(first),
            (second_challenge, first_challenge),
            _polynomial_evaluate(second, second_challenge),
        )

    def test_point_is_encoded_in_front_insertion_order(self) -> None:
        _verify_sumcheck(self.valid_sumcheck(), DuplexChallenger(), "fixture")

    def test_sampling_order_is_rejected_as_encoded_point_order(self) -> None:
        valid = self.valid_sumcheck()
        mutated = Sumcheck(
            valid.polynomials,
            valid.claimed_sum,
            tuple(reversed(valid.point)),
            valid.evaluation,
        )
        with self.assertRaisesRegex(TranscriptVerificationError, "encoded point"):
            _verify_sumcheck(mutated, DuplexChallenger(), "fixture")

    def test_mutated_round_is_rejected(self) -> None:
        valid = self.valid_sumcheck()
        changed_second = (
            valid.polynomials[1][0],
            valid.polynomials[1][1] + Extension.one(),
        )
        mutated = Sumcheck(
            (valid.polynomials[0], changed_second),
            valid.claimed_sum,
            valid.point,
            valid.evaluation,
        )
        with self.assertRaisesRegex(
            TranscriptVerificationError, "inconsistent sumcheck round"
        ):
            _verify_sumcheck(mutated, DuplexChallenger(), "fixture")


class MerklePrimitiveTests(unittest.TestCase):
    def test_pinned_rust_poseidon_merkle_vector(self) -> None:
        root = _poseidon_hash(list(range(10)))
        metadata = _poseidon_hash([0, 10])
        self.assertEqual(
            root,
            (
                47_251_751,
                553_575_958,
                1_345_488_649,
                498_318_952,
                809_293_257,
                806_094_821,
                1_113_971_194,
                130_894_578,
            ),
        )
        self.assertEqual(
            _poseidon_compress(root, metadata),
            (
                1_127_114_543,
                883_611_560,
                1_138_804_829,
                1_396_197_074,
                817_678_494,
                924_635_742,
                440_606_442,
                267_639_023,
            ),
        )

    def test_bit_reversal_is_width_bounded(self) -> None:
        self.assertEqual(_reverse_bits(0b001, 3), 0b100)
        self.assertEqual(_reverse_bits(0b101, 3), 0b101)


if __name__ == "__main__":
    unittest.main()
