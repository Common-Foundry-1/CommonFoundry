//! Executable checkpoint for moving the bounded ForgeMatrix relation to a
//! pairing-curve scalar field.
//!
//! This does not map arbitrary cubic Goldilocks elements into the Dory field.
//! Such a unital field map cannot exist because the characteristics differ.
//! Instead, it confirms that the canonical integer witness makes the same 121
//! local constraint polynomials vanish when those bounded integers are lifted
//! independently into either field.

use std::fmt::Debug;

use dory_pcs::backends::arkworks::ArkFr;
use dory_pcs::primitives::arithmetic::Field;

use crate::{
    STRUCTURED_TRANSITION_CONSTRAINTS, STRUCTURED_TRANSITION_RANGE_DIGITS,
    STRUCTURED_TRANSITION_RANGE_SPEC_COUNT, StructuredTransitionStatement, V2_TRANSITION_MODULUS,
    structured_sumcheck::{ExtensionField, GOLDILOCKS_MODULUS},
    structured_transition::structured_transition_range_specs,
};

const OUTPUT_MODULUS: u64 = 251;
const OUTPUT_CENTER: i64 = 125;

trait ConstraintField: Copy + Debug + Eq {
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u64(value: u64) -> Self;
    fn from_i64(value: i64) -> Self;
    fn add(self, rhs: Self) -> Self;
    fn sub(self, rhs: Self) -> Self;
    fn mul(self, rhs: Self) -> Self;
}

impl ConstraintField for ExtensionField {
    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
    }

    fn from_u64(value: u64) -> Self {
        Self::from_u64(value)
    }

    fn from_i64(value: i64) -> Self {
        Self::from_signed(value)
    }

    fn add(self, rhs: Self) -> Self {
        self.add(rhs)
    }

    fn sub(self, rhs: Self) -> Self {
        self.sub(rhs)
    }

    fn mul(self, rhs: Self) -> Self {
        self.mul(rhs)
    }
}

impl ConstraintField for ArkFr {
    fn zero() -> Self {
        <Self as Field>::zero()
    }

    fn one() -> Self {
        <Self as Field>::one()
    }

    fn from_u64(value: u64) -> Self {
        <Self as Field>::from_u64(value)
    }

    fn from_i64(value: i64) -> Self {
        <Self as Field>::from_i64(value)
    }

    fn add(self, rhs: Self) -> Self {
        self + rhs
    }

    fn sub(self, rhs: Self) -> Self {
        self - rhs
    }

    fn mul(self, rhs: Self) -> Self {
        self * rhs
    }
}

#[derive(Clone, Copy)]
struct IntegerTransitionFixture {
    accumulator: i64,
    mask: u64,
    encoded: u64,
    square_quotient: u64,
    square_remainder: u64,
    cube_quotient: u64,
    cube_remainder: u64,
    output_quotient: u64,
    output_remainder: u64,
    negative: u64,
    activation: i64,
    shifted_accumulator: u64,
}

impl IntegerTransitionFixture {
    fn canonical(accumulator: i64, mask: u64, maximum: u64) -> Self {
        let z = i128::from(accumulator) + i128::from(mask);
        let modulus = i128::from(V2_TRANSITION_MODULUS);
        assert!(z.unsigned_abs() < V2_TRANSITION_MODULUS.into());
        let negative = u64::from(z < 0);
        let encoded = u64::try_from(if z < 0 { modulus + z } else { z }).unwrap();
        let transition_modulus = u64::from(V2_TRANSITION_MODULUS);
        let square = encoded * encoded;
        let square_quotient = square / transition_modulus;
        let square_remainder = square % transition_modulus;
        let cube = square_remainder * encoded;
        let cube_quotient = cube / transition_modulus;
        let cube_remainder = cube % transition_modulus;
        let output_quotient = cube_remainder / OUTPUT_MODULUS;
        let output_remainder = cube_remainder % OUTPUT_MODULUS;
        let activation = i64::try_from(output_remainder).unwrap() - OUTPUT_CENTER;
        let shifted_accumulator = u64::try_from(i128::from(accumulator) + i128::from(maximum))
            .expect("fixture accumulator is inside the declared symmetric bound");
        Self {
            accumulator,
            mask,
            encoded,
            square_quotient,
            square_remainder,
            cube_quotient,
            cube_remainder,
            output_quotient,
            output_remainder,
            negative,
            activation,
            shifted_accumulator,
        }
    }

    fn range_sources(self) -> [u64; STRUCTURED_TRANSITION_RANGE_SPEC_COUNT] {
        [
            self.encoded,
            self.square_quotient,
            self.square_remainder,
            self.cube_quotient,
            self.cube_remainder,
            self.output_quotient,
            self.output_remainder,
            self.shifted_accumulator,
        ]
    }
}

#[derive(Clone, Copy)]
struct DigitMutation {
    spec: usize,
    digit: usize,
    slack: bool,
    replacement: u64,
}

fn evaluate_constraints<F: ConstraintField>(
    statement: StructuredTransitionStatement,
    fixture: IntegerTransitionFixture,
    digit_mutation: Option<DigitMutation>,
) -> Vec<F> {
    let modulus = F::from_u64(u64::from(V2_TRANSITION_MODULUS));
    let encoded = F::from_u64(fixture.encoded);
    let square_remainder = F::from_u64(fixture.square_remainder);
    let cube_remainder = F::from_u64(fixture.cube_remainder);
    let mut constraints = vec![
        encoded
            .sub(F::from_i64(fixture.accumulator))
            .sub(F::from_u64(fixture.mask))
            .sub(F::from_u64(fixture.negative).mul(modulus)),
        encoded
            .mul(encoded)
            .sub(F::from_u64(fixture.square_quotient).mul(modulus))
            .sub(square_remainder),
        square_remainder
            .mul(encoded)
            .sub(F::from_u64(fixture.cube_quotient).mul(modulus))
            .sub(cube_remainder),
        cube_remainder
            .sub(F::from_u64(fixture.output_quotient).mul(F::from_u64(OUTPUT_MODULUS)))
            .sub(F::from_u64(fixture.output_remainder)),
        F::from_i64(fixture.activation)
            .sub(F::from_u64(fixture.output_remainder))
            .add(F::from_u64(OUTPUT_CENTER as u64)),
        F::from_u64(fixture.negative).mul(F::from_u64(fixture.negative).sub(F::one())),
        F::from_u64(fixture.shifted_accumulator)
            .sub(F::from_i64(fixture.accumulator))
            .sub(F::from_u64(statement.max_abs_accumulator)),
    ];

    let specs = structured_transition_range_specs(statement).unwrap();
    let sources = fixture.range_sources();
    let mut all_digits =
        Vec::with_capacity(STRUCTURED_TRANSITION_RANGE_DIGITS.iter().sum::<usize>() * 2);
    for (spec_index, (spec, source)) in specs.iter().zip(sources).enumerate() {
        let slack = spec.maximum - source;
        let mut reconstructed = F::zero();
        let mut reconstructed_slack = F::zero();
        let mut radix = 1u64;
        for digit_index in 0..spec.digits {
            let mut digit = (source >> (digit_index * 4)) & 0xf;
            let mut slack_digit = (slack >> (digit_index * 4)) & 0xf;
            if let Some(mutation) = digit_mutation
                && mutation.spec == spec_index
                && mutation.digit == digit_index
            {
                if mutation.slack {
                    slack_digit = mutation.replacement;
                } else {
                    digit = mutation.replacement;
                }
            }
            reconstructed = reconstructed.add(F::from_u64(digit).mul(F::from_u64(radix)));
            reconstructed_slack =
                reconstructed_slack.add(F::from_u64(slack_digit).mul(F::from_u64(radix)));
            all_digits.push(digit);
            all_digits.push(slack_digit);
            radix *= 16;
        }
        constraints.push(reconstructed.sub(F::from_u64(source)));
        constraints.push(
            reconstructed_slack
                .add(F::from_u64(source))
                .sub(F::from_u64(spec.maximum)),
        );
    }

    for digit in all_digits {
        let membership = (0..16).fold(F::one(), |product, allowed| {
            product.mul(F::from_u64(digit).sub(F::from_u64(allowed)))
        });
        constraints.push(membership);
    }
    assert_eq!(constraints.len(), STRUCTURED_TRANSITION_CONSTRAINTS);
    constraints
}

fn zero_pattern<F: ConstraintField>(values: &[F]) -> Vec<bool> {
    values.iter().map(|value| *value == F::zero()).collect()
}

#[test]
fn arbitrary_goldilocks_elements_cannot_be_naively_embedded() {
    assert_eq!(
        ExtensionField::from_u64(GOLDILOCKS_MODULUS),
        ExtensionField::ZERO
    );
    assert_ne!(
        <ArkFr as Field>::from_u64(GOLDILOCKS_MODULUS),
        <ArkFr as Field>::zero()
    );
}

#[test]
fn all_121_bounded_transition_constraints_are_scalar_field_portable() {
    let statement = StructuredTransitionStatement {
        layers: 1,
        rows: 1,
        cols: 1,
        max_abs_accumulator: 65_536,
        max_mask: 4_096,
    };
    let fixtures = [
        IntegerTransitionFixture::canonical(-65_535, 0, 65_536),
        IntegerTransitionFixture::canonical(-1_000, 123, 65_536),
        IntegerTransitionFixture::canonical(0, 4_095, 65_536),
        IntegerTransitionFixture::canonical(65_535, 0, 65_536),
    ];

    let largest_product = u128::from(V2_TRANSITION_MODULUS - 1).pow(2);
    assert!(largest_product < u128::from(GOLDILOCKS_MODULUS));

    for fixture in fixtures {
        let goldilocks = evaluate_constraints::<ExtensionField>(statement, fixture, None);
        let dory_scalar = evaluate_constraints::<ArkFr>(statement, fixture, None);
        assert!(
            goldilocks
                .iter()
                .all(|value| *value == ExtensionField::ZERO)
        );
        assert!(
            dory_scalar
                .iter()
                .all(|value| *value == <ArkFr as Field>::zero())
        );
    }

    let mut bad_core = fixtures[1];
    bad_core.square_remainder += 1;
    let goldilocks_bad = evaluate_constraints::<ExtensionField>(statement, bad_core, None);
    let scalar_bad = evaluate_constraints::<ArkFr>(statement, bad_core, None);
    assert_eq!(zero_pattern(&goldilocks_bad), zero_pattern(&scalar_bad));
    assert!(zero_pattern(&goldilocks_bad).contains(&false));

    let bad_digit = Some(DigitMutation {
        spec: 0,
        digit: 0,
        slack: false,
        replacement: 16,
    });
    let goldilocks_bad = evaluate_constraints::<ExtensionField>(statement, fixtures[1], bad_digit);
    let scalar_bad = evaluate_constraints::<ArkFr>(statement, fixtures[1], bad_digit);
    assert_eq!(zero_pattern(&goldilocks_bad), zero_pattern(&scalar_bad));
    assert!(zero_pattern(&goldilocks_bad).contains(&false));
}
