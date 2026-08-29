"""Independent ProductionV4 Fiat-Shamir and algebraic verification.

This module parses the pinned transparent-proof topology without importing or
calling the Common Foundry Rust verifier.  It verifies all relation sumchecks,
their terminal identities, opening-claim routing, opening-reduction sumchecks,
and the non-Merkle BaseFold transcript checks.  Merkle authentication and the
FRI query-fold equations remain a separate final slice.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path

import blake3
from production_v4_poseidon import MODULUS, DuplexChallenger, Extension
from production_v4_wire import (
    BANK_BYTES,
    BANKS,
    DIGEST_BYTES,
    FINAL_ACTIVATION_BYTES,
    OPENING_BYTES,
    OPENING_HEADER_BYTES,
    OUTER_HEADER_BYTES,
    RELATION_REPETITION_BYTES,
    RELATION_REPETITIONS,
)

FIXED_COLUMNS = 256
DYNAMIC_COLUMNS = 16
ROW_VARIABLES = 23
BASEFOLD_QUERIES = 270
BASEFOLD_LOG_BLOWUP = 1
BASEFOLD_POW_BITS = 16
BASEFOLD_BATCH_POW_BITS = 5
LAYER_VARIABLES = 7
BATCH_VARIABLES = 7
DIMENSION_VARIABLES = 12

COMMITMENTS_DOMAIN = b"CommonFoundry/ForgeMatrix/V4/Commitments/v1"
MATRIX_POINT_DOMAIN = b"CommonFoundry/ForgeMatrix/V4/MatrixPoint/v1"
MATRIX_PROOF_DOMAIN = b"CommonFoundry/ForgeMatrix/V4/MatrixProof/v1"
SHIFT_PROOF_DOMAIN = b"CommonFoundry/ForgeMatrix/V4/ShiftProof/v1"
CUBIC_POINT_DOMAIN = b"CommonFoundry/ForgeMatrix/V4/CubicPoint/v1"
CUBIC_PROOF_DOMAIN = b"CommonFoundry/ForgeMatrix/V4/CubicProof/v1"
FINAL_POINT_DOMAIN = b"CommonFoundry/ForgeMatrix/V4/FinalPoint/v1"
OPENING_REDUCTION_DOMAIN = b"CommonFoundry/ForgeMatrix/V4/OpeningReduction/v2"
MASK_DOMAIN = "CMFD/FORGEMATRIX/MASKCOEFF/V2"


class TranscriptVerificationError(ValueError):
    """Raised when an independent transcript or algebraic check fails."""


@dataclass(frozen=True)
class Sumcheck:
    polynomials: tuple[tuple[Extension, ...], ...]
    claimed_sum: Extension
    point: tuple[Extension, ...]
    evaluation: Extension


@dataclass(frozen=True)
class MatrixRelation:
    sumcheck: Sumcheck
    preactivation: Extension
    weight: Extension
    input_value: Extension


@dataclass(frozen=True)
class ShiftRelation:
    sumcheck: Sumcheck
    boundary: Extension
    next_activation: Extension


@dataclass(frozen=True)
class CubicRelation:
    sumcheck: Sumcheck
    preactivation: Extension
    next_activation: Extension


@dataclass(frozen=True)
class Relation:
    matrix: MatrixRelation
    shift: ShiftRelation
    cubic: CubicRelation


@dataclass(frozen=True)
class Opening:
    sumcheck: Sumcheck
    fixed_evaluations: tuple[Extension, ...]
    dynamic_evaluations: tuple[Extension, ...]
    univariate_messages: tuple[tuple[Extension, Extension], ...]
    fri_commitments: tuple[tuple[int, ...], ...]
    final_poly: Extension
    pow_witness: int
    batch_grinding_witness: int


@dataclass(frozen=True)
class Bank:
    dynamic_commitment: tuple[int, ...]
    relations: tuple[Relation, ...]
    opening: Opening


@dataclass(frozen=True)
class Claim:
    commitment: int
    column_point: tuple[Extension, ...]
    row_point: tuple[Extension, ...]
    value: Extension


class Reader:
    def __init__(self, data: bytes, position: int, end: int) -> None:
        self.data = data
        self.position = position
        self.end = end

    def take(self, count: int) -> bytes:
        end = self.position + count
        if count < 0 or end > self.end:
            raise TranscriptVerificationError(
                "proof reader crossed a pinned section boundary"
            )
        value = self.data[self.position : end]
        self.position = end
        return value

    def field(self) -> int:
        value = struct.unpack("<I", self.take(4))[0]
        if value >= MODULUS:
            raise TranscriptVerificationError(
                "proof contains a noncanonical KoalaBear value"
            )
        return value

    def extension(self) -> Extension:
        return Extension(tuple(self.field() for _ in range(4)))

    def digest(self) -> tuple[int, ...]:
        return tuple(self.field() for _ in range(8))

    def sumcheck(self, variables: int, degree: int) -> Sumcheck:
        polynomials = tuple(
            tuple(self.extension() for _ in range(degree + 1)) for _ in range(variables)
        )
        claimed_sum = self.extension()
        point = tuple(self.extension() for _ in range(variables))
        evaluation = self.extension()
        return Sumcheck(polynomials, claimed_sum, point, evaluation)


def _parse_relation(reader: Reader) -> Relation:
    matrix = MatrixRelation(
        reader.sumcheck(19, 3),
        reader.extension(),
        reader.extension(),
        reader.extension(),
    )
    shift = ShiftRelation(reader.sumcheck(7, 2), reader.extension(), reader.extension())
    cubic = CubicRelation(
        reader.sumcheck(26, 4), reader.extension(), reader.extension()
    )
    return Relation(matrix, shift, cubic)


def _parse_opening(data: bytes, start: int) -> Opening:
    end = start + OPENING_BYTES
    if data[start : start + 8] != b"CMV4BF01":
        raise TranscriptVerificationError("opening has the wrong magic")
    version, claims = struct.unpack(
        "<II", data[start + 8 : start + OPENING_HEADER_BYTES]
    )
    if version != 1 or claims != 16:
        raise TranscriptVerificationError(
            "opening has the wrong version or claim count"
        )
    reader = Reader(data, start + OPENING_HEADER_BYTES, end)
    sumcheck = reader.sumcheck(ROW_VARIABLES, 2)
    fixed = tuple(reader.extension() for _ in range(FIXED_COLUMNS))
    dynamic = tuple(reader.extension() for _ in range(DYNAMIC_COLUMNS))
    messages = tuple(
        (reader.extension(), reader.extension()) for _ in range(ROW_VARIABLES)
    )
    commitments = tuple(reader.digest() for _ in range(ROW_VARIABLES))
    final_reader = Reader(data, end - 24, end)
    final_poly = final_reader.extension()
    pow_witness = final_reader.field()
    batch_witness = final_reader.field()
    if reader.position > end - 24:
        raise TranscriptVerificationError("opening metadata overlaps its final fields")
    return Opening(
        sumcheck,
        fixed,
        dynamic,
        messages,
        commitments,
        final_poly,
        pow_witness,
        batch_witness,
    )


def parse_proof(path: Path) -> tuple[bytes, tuple[Bank, ...]]:
    data = path.read_bytes()
    banks: list[Bank] = []
    first_bank = OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES
    for bank_index in range(BANKS):
        bank_start = first_bank + bank_index * BANK_BYTES
        reader = Reader(data, bank_start, bank_start + BANK_BYTES)
        dynamic = reader.digest()
        relations = tuple(_parse_relation(reader) for _ in range(RELATION_REPETITIONS))
        opening_start = (
            bank_start + DIGEST_BYTES + RELATION_REPETITIONS * RELATION_REPETITION_BYTES
        )
        if reader.position != opening_start:
            raise TranscriptVerificationError(
                "relation parser did not end at the opening boundary"
            )
        banks.append(Bank(dynamic, relations, _parse_opening(data, opening_start)))
    return data, tuple(banks)


def parse_fixed_commitments(
    record_path: Path, expected_proof_system: bytes, expected_manifest: bytes
) -> tuple[tuple[int, ...], ...]:
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TranscriptVerificationError(
            f"failed to load fixed artifact record: {error}"
        ) from error
    if not isinstance(record, dict) or record.get("record_version") != 1:
        raise TranscriptVerificationError("fixed artifact record has the wrong version")

    def byte_array(name: str) -> bytes:
        value = record.get(name)
        if (
            not isinstance(value, list)
            or len(value) != 32
            or any(
                isinstance(item, bool)
                or not isinstance(item, int)
                or item < 0
                or item > 255
                for item in value
            )
        ):
            raise TranscriptVerificationError(
                f"fixed artifact record {name} is malformed"
            )
        return bytes(value)

    if byte_array("proof_system_digest") != expected_proof_system:
        raise TranscriptVerificationError(
            "fixed artifact record proof-system digest mismatch"
        )
    if byte_array("manifest_digest") != expected_manifest:
        raise TranscriptVerificationError(
            "fixed artifact record manifest digest mismatch"
        )
    bank_values = record.get("banks")
    if not isinstance(bank_values, list) or len(bank_values) != BANKS:
        raise TranscriptVerificationError(
            "fixed artifact record must contain exactly three banks"
        )
    commitments: list[tuple[int, ...]] = []
    for index, bank in enumerate(bank_values):
        if not isinstance(bank, dict) or bank.get("bank") != index:
            raise TranscriptVerificationError(
                "fixed artifact record bank ordering mismatch"
            )
        values = bank.get("commitment")
        if (
            not isinstance(values, list)
            or len(values) != 8
            or any(
                isinstance(item, bool)
                or not isinstance(item, int)
                or item < 0
                or item >= MODULUS
                for item in values
            )
        ):
            raise TranscriptVerificationError(
                f"fixed artifact record bank {index} commitment is malformed"
            )
        commitments.append(tuple(values))
    return tuple(commitments)


def _polynomial_evaluate(
    polynomial: tuple[Extension, ...], point: Extension
) -> Extension:
    result = Extension.zero()
    for coefficient in reversed(polynomial):
        result = result * point + coefficient
    return result


def _zero_plus_one(polynomial: tuple[Extension, ...]) -> Extension:
    return polynomial[0] + sum(polynomial, Extension.zero())


def _verify_sumcheck(
    sumcheck: Sumcheck, challenger: DuplexChallenger, label: str
) -> None:
    if not sumcheck.polynomials:
        raise TranscriptVerificationError(f"{label}: empty sumcheck")
    first = sumcheck.polynomials[0]
    if _zero_plus_one(first) != sumcheck.claimed_sum:
        raise TranscriptVerificationError(
            f"{label}: first round does not match claimed sum"
        )
    for coefficient in first:
        challenger.observe_ext(coefficient)
    sampled: list[Extension] = []
    previous = first
    for polynomial in sumcheck.polynomials[1:]:
        challenge = challenger.sample_ext()
        sampled.append(challenge)
        if _polynomial_evaluate(previous, challenge) != _zero_plus_one(polynomial):
            raise TranscriptVerificationError(f"{label}: inconsistent sumcheck round")
        for coefficient in polynomial:
            challenger.observe_ext(coefficient)
        previous = polynomial
    final_challenge = challenger.sample_ext()
    sampled.append(final_challenge)
    # slop Point::add_dimension inserts each sampled coordinate at the front.
    if tuple(reversed(sampled)) != sumcheck.point:
        raise TranscriptVerificationError(
            f"{label}: encoded point differs from transcript challenges"
        )
    if _polynomial_evaluate(previous, final_challenge) != sumcheck.evaluation:
        raise TranscriptVerificationError(
            f"{label}: final polynomial evaluation mismatch"
        )


def _equality(left: tuple[Extension, ...], right: tuple[Extension, ...]) -> Extension:
    if len(left) != len(right):
        raise TranscriptVerificationError("equality points have different dimensions")
    result = Extension.one()
    one = Extension.one()
    for left_value, right_value in zip(left, right):
        result = result * (
            (one - left_value) * (one - right_value) + left_value * right_value
        )
    return result


def _equality_at_boolean(point: tuple[Extension, ...], index: int) -> Extension:
    if index < 0 or index >= 1 << len(point):
        raise TranscriptVerificationError("Boolean equality index is out of range")
    result = Extension.one()
    one = Extension.one()
    for coordinate, value in enumerate(point):
        bit = (index >> (len(point) - coordinate - 1)) & 1
        result = result * (value if bit else one - value)
    return result


def _partial_lagrange(point: tuple[Extension, ...]) -> list[Extension]:
    weights = [Extension.one()]
    one = Extension.one()
    for coordinate in point:
        weights = [
            value
            for weight in weights
            for value in (weight * (one - coordinate), weight * coordinate)
        ]
    return weights


def _mask_coefficients(challenge: bytes, layer: int) -> tuple[int, ...]:
    hasher = blake3.blake3(derive_key_context=MASK_DOMAIN)
    hasher.update(challenge)
    hasher.update(struct.pack("<I", layer))
    coefficients: list[int] = []
    offset = 0
    while len(coefficients) < 20:
        end = offset + 64
        chunk = hasher.digest(length=end)[offset:end]
        coefficients.extend(value for value in chunk if value <= 250)
        offset = end
    return tuple(coefficients[:20])


def _mask_evaluation(
    challenge: bytes,
    bank: int,
    layer_point: tuple[Extension, ...],
    batch_point: tuple[Extension, ...],
    output_point: tuple[Extension, ...],
) -> Extension:
    layer_weights = _partial_lagrange(layer_point)
    result = Extension.zero()
    for local_layer, layer_weight in enumerate(layer_weights):
        coefficients = _mask_coefficients(challenge, bank * 128 + local_layer)
        value = Extension.from_base(coefficients[0])
        for coefficient, coordinate in zip(coefficients[1:8], reversed(batch_point)):
            value = value + Extension.from_base(coefficient) * coordinate
        for coefficient, coordinate in zip(coefficients[8:], reversed(output_point)):
            value = value + Extension.from_base(coefficient) * coordinate
        result = result + layer_weight * value
    return result


def _sample_point(
    challenger: DuplexChallenger,
    domain: bytes,
    bank: int,
    repetition: int,
    variables: int,
) -> tuple[Extension, ...]:
    challenger.observe_bytes(domain)
    challenger.observe(bank)
    challenger.observe(repetition)
    return tuple(challenger.sample_ext() for _ in range(variables))


def _split_point(
    point: tuple[Extension, ...], columns: int
) -> tuple[tuple[Extension, ...], tuple[Extension, ...]]:
    return point[:columns], point[columns:]


def _dynamic_claim(
    kind: int,
    layer: tuple[Extension, ...],
    batch: tuple[Extension, ...],
    output: tuple[Extension, ...],
    value: Extension,
) -> Claim:
    column, row = _split_point((Extension.from_base(kind),) + layer + batch + output, 4)
    return Claim(1, column, row, value)


def _last_activation_claim(
    batch: tuple[Extension, ...], output: tuple[Extension, ...], value: Extension
) -> Claim:
    return _dynamic_claim(1, (Extension.one(),) * LAYER_VARIABLES, batch, output, value)


def _verify_relation(
    challenge: bytes,
    bank: int,
    repetition: int,
    relation: Relation,
    challenger: DuplexChallenger,
) -> tuple[list[Claim], tuple[Extension, ...], tuple[Extension, ...], Extension]:
    matrix_point = _sample_point(challenger, MATRIX_POINT_DOMAIN, bank, repetition, 26)
    layer = matrix_point[:7]
    batch = matrix_point[7:14]
    output = matrix_point[14:]
    mask = _mask_evaluation(challenge, bank, layer, batch, output)
    challenger.observe_bytes(MATRIX_PROOF_DOMAIN)
    challenger.observe_ext(relation.matrix.preactivation)
    challenger.observe_ext(mask)
    if relation.matrix.sumcheck.claimed_sum != relation.matrix.preactivation - mask:
        raise TranscriptVerificationError(
            f"bank {bank} repetition {repetition}: matrix claim mismatch"
        )
    _verify_sumcheck(
        relation.matrix.sumcheck,
        challenger,
        f"bank {bank} repetition {repetition} matrix",
    )
    terminal_layer = relation.matrix.sumcheck.point[:7]
    terminal_common = relation.matrix.sumcheck.point[7:]
    expected_matrix = (
        relation.matrix.weight
        * relation.matrix.input_value
        * _equality(layer, terminal_layer)
    )
    if relation.matrix.sumcheck.evaluation != expected_matrix:
        raise TranscriptVerificationError(
            f"bank {bank} repetition {repetition}: matrix terminal mismatch"
        )
    challenger.observe_ext(relation.matrix.weight)
    challenger.observe_ext(relation.matrix.input_value)

    challenger.observe_bytes(SHIFT_PROOF_DOMAIN)
    challenger.observe_ext(relation.matrix.input_value)
    challenger.observe_ext(relation.shift.boundary)
    expected_shift_claim = (
        relation.matrix.input_value
        - _equality_at_boolean(terminal_layer, 0) * relation.shift.boundary
    )
    if relation.shift.sumcheck.claimed_sum != expected_shift_claim:
        raise TranscriptVerificationError(
            f"bank {bank} repetition {repetition}: shift claim mismatch"
        )
    _verify_sumcheck(
        relation.shift.sumcheck,
        challenger,
        f"bank {bank} repetition {repetition} shift",
    )
    terminal_weights = _partial_lagrange(relation.shift.sumcheck.point)
    shift_coefficient = sum(
        (
            _equality_at_boolean(terminal_layer, source + 1) * terminal_weights[source]
            for source in range(127)
        ),
        Extension.zero(),
    )
    if (
        relation.shift.sumcheck.evaluation
        != relation.shift.next_activation * shift_coefficient
    ):
        raise TranscriptVerificationError(
            f"bank {bank} repetition {repetition}: shift terminal mismatch"
        )
    challenger.observe_ext(relation.shift.next_activation)

    weight_column, weight_row = _split_point(
        terminal_layer + terminal_common + output, 8
    )
    claims = [
        Claim(0, weight_column, weight_row, relation.matrix.weight),
        _dynamic_claim(0, layer, batch, output, relation.matrix.preactivation),
        _dynamic_claim(
            1,
            relation.shift.sumcheck.point,
            batch,
            terminal_common,
            relation.shift.next_activation,
        ),
    ]
    boundary_batch = batch
    boundary_output = terminal_common

    cubic_point = _sample_point(challenger, CUBIC_POINT_DOMAIN, bank, repetition, 26)
    challenger.observe_bytes(CUBIC_PROOF_DOMAIN)
    if relation.cubic.sumcheck.claimed_sum != Extension.zero():
        raise TranscriptVerificationError(
            f"bank {bank} repetition {repetition}: cubic claim is not zero"
        )
    _verify_sumcheck(
        relation.cubic.sumcheck,
        challenger,
        f"bank {bank} repetition {repetition} cubic",
    )
    expected_cubic = _equality(cubic_point, relation.cubic.sumcheck.point) * (
        relation.cubic.next_activation - relation.cubic.preactivation**3
    )
    if relation.cubic.sumcheck.evaluation != expected_cubic:
        raise TranscriptVerificationError(
            f"bank {bank} repetition {repetition}: cubic terminal mismatch"
        )
    challenger.observe_ext(relation.cubic.preactivation)
    challenger.observe_ext(relation.cubic.next_activation)
    cubic_terminal = relation.cubic.sumcheck.point
    claims.extend(
        [
            _dynamic_claim(
                0,
                cubic_terminal[:7],
                cubic_terminal[7:14],
                cubic_terminal[14:],
                relation.cubic.preactivation,
            ),
            _dynamic_claim(
                1,
                cubic_terminal[:7],
                cubic_terminal[7:14],
                cubic_terminal[14:],
                relation.cubic.next_activation,
            ),
        ]
    )
    return claims, boundary_batch, boundary_output, relation.shift.boundary


def _evaluate_columns(
    evaluations: tuple[Extension, ...], point: tuple[Extension, ...]
) -> Extension:
    return sum(
        (
            value * weight
            for value, weight in zip(evaluations, _partial_lagrange(point))
        ),
        Extension.zero(),
    )


def _verify_opening(
    bank: int,
    fixed: tuple[int, ...],
    dynamic: tuple[int, ...],
    claims: list[Claim],
    opening: Opening,
    challenger: DuplexChallenger,
) -> None:
    if len(claims) != 12:
        raise TranscriptVerificationError(
            f"bank {bank}: expected 12 routed claims before padding"
        )
    claims.extend([claims[-1]] * 4)
    challenger.observe_bytes(OPENING_REDUCTION_DOMAIN)
    challenger.observe_digest(fixed)
    challenger.observe_digest(dynamic)
    challenger.observe(len(claims))
    for claim in claims:
        challenger.observe(claim.commitment)
        for coordinate in claim.column_point:
            challenger.observe_ext(coordinate)
        for coordinate in claim.row_point:
            challenger.observe_ext(coordinate)
        challenger.observe_ext(claim.value)

    lambda_value = challenger.sample_ext()
    powers = [Extension.one()] * len(claims)
    for index in range(len(claims) - 2, -1, -1):
        powers[index] = powers[index + 1] * lambda_value
    expected_claim = sum(
        (claim.value * power for claim, power in zip(claims, powers)), Extension.zero()
    )
    if opening.sumcheck.claimed_sum != expected_claim:
        raise TranscriptVerificationError(
            f"bank {bank}: opening-reduction claim mismatch"
        )
    _verify_sumcheck(opening.sumcheck, challenger, f"bank {bank} opening reduction")
    expected_terminal = Extension.zero()
    for claim, power in zip(claims, powers):
        evaluations = (
            opening.fixed_evaluations
            if claim.commitment == 0
            else opening.dynamic_evaluations
        )
        expected_terminal = expected_terminal + power * _evaluate_columns(
            evaluations, claim.column_point
        ) * _equality(claim.row_point, opening.sumcheck.point)
    if opening.sumcheck.evaluation != expected_terminal:
        raise TranscriptVerificationError(
            f"bank {bank}: opening-reduction terminal mismatch"
        )

    challenger.observe(opening.batch_grinding_witness)
    if challenger.sample_bits(BASEFOLD_BATCH_POW_BITS) != 0:
        raise TranscriptVerificationError(
            f"bank {bank}: invalid BaseFold batch-grinding witness"
        )
    batching_point = tuple(challenger.sample_ext() for _ in range(9))
    batching_weights = _partial_lagrange(batching_point)
    all_evaluations = opening.fixed_evaluations + opening.dynamic_evaluations
    evaluation_claim = sum(
        (value * weight for value, weight in zip(all_evaluations, batching_weights)),
        Extension.zero(),
    )
    reversed_point = tuple(reversed(opening.sumcheck.point))
    challenger.observe(ROW_VARIABLES)
    betas: list[Extension] = []
    for message, commitment in zip(
        opening.univariate_messages, opening.fri_commitments
    ):
        challenger.observe_ext(message[0])
        challenger.observe_ext(message[1])
        challenger.observe_digest(commitment)
        betas.append(challenger.sample_ext())
    first = opening.univariate_messages[0]
    if (
        evaluation_claim
        != (Extension.one() - reversed_point[0]) * first[0]
        + reversed_point[0] * first[1]
    ):
        raise TranscriptVerificationError(
            f"bank {bank}: first BaseFold message mismatch"
        )
    expected = first[0] + betas[0] * first[1]
    for index, (message, beta) in enumerate(
        zip(opening.univariate_messages[1:], betas[1:]), start=1
    ):
        if (
            expected
            != (Extension.one() - reversed_point[index]) * message[0]
            + reversed_point[index] * message[1]
        ):
            raise TranscriptVerificationError(
                f"bank {bank}: BaseFold round {index} mismatch"
            )
        expected = message[0] + beta * message[1]
    if opening.final_poly != expected:
        raise TranscriptVerificationError(
            f"bank {bank}: BaseFold final polynomial mismatch"
        )
    challenger.observe_ext(opening.final_poly)
    challenger.observe(opening.pow_witness)
    if challenger.sample_bits(BASEFOLD_POW_BITS) != 0:
        raise TranscriptVerificationError(
            f"bank {bank}: invalid BaseFold proof-of-work witness"
        )
    for _ in range(BASEFOLD_QUERIES):
        challenger.sample_bits(ROW_VARIABLES + BASEFOLD_LOG_BLOWUP)


def _multilinear_evaluate_base(
    values: list[int], point: tuple[Extension, ...]
) -> Extension:
    if len(values) != 1 << len(point):
        raise TranscriptVerificationError(
            "multilinear input length does not match point dimension"
        )
    coordinate = point[-1]
    current = [
        Extension.from_base(left) + Extension.from_base(right - left) * coordinate
        for left, right in zip(values[::2], values[1::2])
    ]
    for coordinate in reversed(point[:-1]):
        current = [
            left + (right - left) * coordinate
            for left, right in zip(current[::2], current[1::2])
        ]
    return current[0]


def verify_transcript_and_algebra(
    proof_path: Path,
    statement_digest: bytes,
    challenge_digest: bytes,
    fixed_commitments: tuple[tuple[int, ...], ...],
) -> dict[str, object]:
    data, banks = parse_proof(proof_path)
    if len(fixed_commitments) != BANKS:
        raise TranscriptVerificationError(
            "exactly three fixed commitments are required"
        )
    challenger = DuplexChallenger()
    challenger.observe_bytes(statement_digest)
    challenger.observe_bytes(COMMITMENTS_DOMAIN)
    for fixed, bank in zip(fixed_commitments, banks):
        challenger.observe_digest(fixed)
        challenger.observe_digest(bank.dynamic_commitment)

    claims: list[list[Claim]] = [[] for _ in range(BANKS)]
    relation_count = 0
    opening_count = 0
    for bank_index, bank in enumerate(banks):
        for repetition, relation in enumerate(bank.relations):
            local, boundary_batch, boundary_output, boundary_value = _verify_relation(
                challenge_digest, bank_index, repetition, relation, challenger
            )
            claims[bank_index].extend(local)
            if bank_index > 0:
                claims[bank_index - 1].append(
                    _last_activation_claim(
                        boundary_batch, boundary_output, boundary_value
                    )
                )
            relation_count += 1
        if bank_index > 0:
            completed = bank_index - 1
            _verify_opening(
                completed,
                fixed_commitments[completed],
                banks[completed].dynamic_commitment,
                claims[completed],
                banks[completed].opening,
                challenger,
            )
            opening_count += 1

    final_values = [
        value[0]
        for value in struct.iter_unpack(
            "<I", data[OUTER_HEADER_BYTES : OUTER_HEADER_BYTES + FINAL_ACTIVATION_BYTES]
        )
    ]
    for repetition in range(RELATION_REPETITIONS):
        final_point = _sample_point(
            challenger, FINAL_POINT_DOMAIN, BANKS - 1, repetition, 19
        )
        final_value = _multilinear_evaluate_base(final_values, final_point)
        claims[BANKS - 1].append(
            _last_activation_claim(final_point[:7], final_point[7:], final_value)
        )
    _verify_opening(
        BANKS - 1,
        fixed_commitments[BANKS - 1],
        banks[BANKS - 1].dynamic_commitment,
        claims[BANKS - 1],
        banks[BANKS - 1].opening,
        challenger,
    )
    opening_count += 1
    return {
        "relations_verified": relation_count,
        "opening_reductions_verified": opening_count,
        "basefold_transcripts_replayed": opening_count,
        "basefold_merkle_and_query_folds_verified": False,
        "initial_activation_boundaries_verified": False,
    }
