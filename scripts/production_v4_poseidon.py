"""Independent KoalaBear extension field and ProductionV4 Poseidon2 challenger.

Constants and round structure are pinned to SP1/slop revision
92b8eabaea9ab7306da5826caa700adabf7445ba. This module contains no Rust FFI
and imports no Common Foundry implementation code.
"""

from __future__ import annotations

from dataclasses import dataclass

MODULUS = 0x7F000001
WIDTH = 16
RATE = 8
MONTGOMERY_INVERSE = pow(1 << 32, -1, MODULUS)
INTERNAL_SHIFTS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15)

BEGIN_ROUND_CONSTANTS = (
    (
        0x7EE56A48,
        0x11367045,
        0x12E41941,
        0x7EBBC12B,
        0x1970B7D5,
        0x662B60E8,
        0x3E4990C6,
        0x679F91F5,
        0x350813BB,
        0x00874AD4,
        0x28A0081A,
        0x18FA5872,
        0x5F25B071,
        0x5E5D5998,
        0x5E6FD3E7,
        0x5B2E2660,
    ),
    (
        0x6F1837BF,
        0x3FE6182B,
        0x1EDD7AC5,
        0x57470D00,
        0x43D486D5,
        0x1982C70F,
        0x0EA53AF9,
        0x61D6165B,
        0x51639C00,
        0x2DEC352C,
        0x2950E531,
        0x2D2CB947,
        0x08256CEF,
        0x1A0109F6,
        0x1F51FAF3,
        0x5CEF1C62,
    ),
    (
        0x3D65E50E,
        0x33D91626,
        0x133D5A1E,
        0x0FF49B0D,
        0x38900CD1,
        0x2C22CC3F,
        0x28852BB2,
        0x06C65A02,
        0x7B2CF7BC,
        0x68016E1A,
        0x15E16BC0,
        0x5248149A,
        0x6DD212A0,
        0x18D6830A,
        0x5001BE82,
        0x64DAC34E,
    ),
    (
        0x5902B287,
        0x426583A0,
        0x0C921632,
        0x3FE028A5,
        0x245F8E49,
        0x43BB297E,
        0x7873DBD9,
        0x3CC987DF,
        0x286BB4CE,
        0x640A8DCD,
        0x512A8E36,
        0x03A4CF55,
        0x481837A2,
        0x03D6DA84,
        0x73726AC7,
        0x760E7FDF,
    ),
)
PARTIAL_ROUND_CONSTANTS = (
    0x54DFEB5D,
    0x7D40AFD6,
    0x722CB316,
    0x106A4573,
    0x45A7CCDB,
    0x44061375,
    0x154077A5,
    0x45744FAA,
    0x4EB5E5EE,
    0x3794E83F,
    0x47C7093C,
    0x5694903C,
    0x69CB6299,
    0x373DF84C,
    0x46A0DF58,
    0x46B8758A,
    0x3241EBCB,
    0x0B09D233,
    0x1AF42357,
    0x1E66CEC2,
)
END_ROUND_CONSTANTS = (
    (
        0x43E7DC24,
        0x259A5D61,
        0x27E85A3B,
        0x1B9133FA,
        0x343E5628,
        0x485CD4C2,
        0x16E269F5,
        0x165B60C6,
        0x25F683D9,
        0x124F81F9,
        0x174331F9,
        0x77344DC5,
        0x5A821DBA,
        0x5FC4177F,
        0x54153BF5,
        0x5E3F1194,
    ),
    (
        0x3BDBF191,
        0x088C84A3,
        0x68256C9B,
        0x3C90BBC6,
        0x6846166A,
        0x03F4238D,
        0x463335FB,
        0x5E3D3551,
        0x6E59AE6F,
        0x32D06CC0,
        0x596293F3,
        0x6C87EDB2,
        0x08FC60B5,
        0x34BCCA80,
        0x24F007F3,
        0x62731C6F,
    ),
    (
        0x1E1DB6C6,
        0x0CA409BB,
        0x585C1E78,
        0x56E94EDC,
        0x16D22734,
        0x18E11467,
        0x7B2C3730,
        0x770075E4,
        0x35D1B18C,
        0x22BE3DB5,
        0x4FB1FBB7,
        0x477CB3ED,
        0x7D5311C6,
        0x5B62AE7D,
        0x559C5FA8,
        0x77F15048,
    ),
    (
        0x3211570B,
        0x490FEF6A,
        0x77EC311F,
        0x2247171B,
        0x4E0AC711,
        0x2EDF69C9,
        0x3B5A8850,
        0x65809421,
        0x5619B4AA,
        0x362019A7,
        0x6BF9D4ED,
        0x5B413DFF,
        0x617E181E,
        0x5E7AB57B,
        0x33AD7833,
        0x3466C7CA,
    ),
)


@dataclass(frozen=True)
class Extension:
    """Element of KoalaBear[X]/(X^4 - 3), coefficient first."""

    coefficients: tuple[int, int, int, int]

    def __post_init__(self) -> None:
        if len(self.coefficients) != 4:
            raise ValueError("an extension element requires exactly four coefficients")
        object.__setattr__(
            self, "coefficients", tuple(value % MODULUS for value in self.coefficients)
        )

    @classmethod
    def zero(cls) -> Extension:
        return cls((0, 0, 0, 0))

    @classmethod
    def one(cls) -> Extension:
        return cls((1, 0, 0, 0))

    @classmethod
    def from_base(cls, value: int) -> Extension:
        return cls((value, 0, 0, 0))

    def __add__(self, other: Extension) -> Extension:
        return Extension(
            tuple(a + b for a, b in zip(self.coefficients, other.coefficients))
        )

    def __radd__(self, other: object) -> Extension:
        if other == 0:
            return self
        return NotImplemented

    def __sub__(self, other: Extension) -> Extension:
        return Extension(
            tuple(a - b for a, b in zip(self.coefficients, other.coefficients))
        )

    def __neg__(self) -> Extension:
        return Extension(tuple(-value for value in self.coefficients))

    def __mul__(self, other: Extension) -> Extension:
        product = [0] * 7
        for left_index, left in enumerate(self.coefficients):
            for right_index, right in enumerate(other.coefficients):
                product[left_index + right_index] += left * right
        for degree in range(6, 3, -1):
            product[degree - 4] += 3 * product[degree]
        return Extension(tuple(product[:4]))

    def __pow__(self, exponent: int) -> Extension:
        if exponent < 0:
            return self.inverse() ** -exponent
        result = Extension.one()
        base = self
        while exponent:
            if exponent & 1:
                result = result * base
            base = base * base
            exponent >>= 1
        return result

    def inverse(self) -> Extension:
        if self == Extension.zero():
            raise ZeroDivisionError("zero has no multiplicative inverse")
        return self ** (MODULUS**4 - 2)

    def __truediv__(self, other: Extension) -> Extension:
        return self * other.inverse()


def _external_linear_layer(state: list[int]) -> list[int]:
    output = list(state)
    for start in range(0, WIDTH, 4):
        x0, x1, x2, x3 = output[start : start + 4]
        t01 = x0 + x1
        t23 = x2 + x3
        t0123 = t01 + t23
        t01123 = t0123 + x1
        t01233 = t0123 + x3
        output[start : start + 4] = (
            t01123 + t01,
            t01123 + 2 * x2,
            t01233 + t23,
            t01233 + 2 * x0,
        )
    sums = [sum(output[index::4]) for index in range(4)]
    return [(value + sums[index % 4]) % MODULUS for index, value in enumerate(output)]


def _internal_linear_layer(state: list[int]) -> list[int]:
    full_sum = sum(state)
    output = [((full_sum - 2 * state[0]) * MONTGOMERY_INVERSE) % MODULUS]
    output.extend(
        ((full_sum + (1 << shift) * state[index]) * MONTGOMERY_INVERSE) % MODULUS
        for index, shift in enumerate(INTERNAL_SHIFTS, start=1)
    )
    return output


def poseidon2_permute(values: list[int] | tuple[int, ...]) -> list[int]:
    if len(values) != WIDTH:
        raise ValueError(f"Poseidon2 state requires {WIDTH} field elements")
    state = [value % MODULUS for value in values]
    state = _external_linear_layer(state)
    for constants in BEGIN_ROUND_CONSTANTS:
        state = [
            pow(value + constant, 3, MODULUS)
            for value, constant in zip(state, constants)
        ]
        state = _external_linear_layer(state)
    for constant in PARTIAL_ROUND_CONSTANTS:
        state[0] = pow(state[0] + constant, 3, MODULUS)
        state = _internal_linear_layer(state)
    for constants in END_ROUND_CONSTANTS:
        state = [
            pow(value + constant, 3, MODULUS)
            for value, constant in zip(state, constants)
        ]
        state = _external_linear_layer(state)
    return state


class DuplexChallenger:
    """Width-16, rate-8 challenger used by KoalaBearDegree4Duplex."""

    def __init__(self) -> None:
        self.state = [0] * WIDTH
        self.input_buffer: list[int] = []
        self.output_buffer: list[int] = []

    def _duplex(self) -> None:
        if len(self.input_buffer) > RATE:
            raise AssertionError("challenger input buffer exceeded its rate")
        self.state[: len(self.input_buffer)] = self.input_buffer
        self.input_buffer.clear()
        self.state = poseidon2_permute(self.state)
        self.output_buffer = list(self.state[:RATE])

    def observe(self, value: int) -> None:
        if value < 0 or value >= MODULUS:
            raise ValueError(
                "observed value is not a canonical KoalaBear field element"
            )
        self.output_buffer.clear()
        self.input_buffer.append(value)
        if len(self.input_buffer) == RATE:
            self._duplex()

    def observe_ext(self, value: Extension) -> None:
        for coefficient in value.coefficients:
            self.observe(coefficient)

    def observe_digest(self, value: tuple[int, ...] | list[int]) -> None:
        if len(value) != 8:
            raise ValueError(
                "a ProductionV4 digest contains exactly eight field elements"
            )
        for coefficient in value:
            self.observe(coefficient)

    def observe_bytes(self, value: bytes) -> None:
        self.observe(len(value))
        for byte in value:
            self.observe(byte)

    def sample(self) -> int:
        if self.input_buffer or not self.output_buffer:
            self._duplex()
        return self.output_buffer.pop()

    def sample_ext(self) -> Extension:
        return Extension(tuple(self.sample() for _ in range(4)))

    def sample_bits(self, bits: int) -> int:
        if bits < 0 or (1 << bits) >= MODULUS:
            raise ValueError("sample width is outside the KoalaBear field capacity")
        return self.sample() & ((1 << bits) - 1)
