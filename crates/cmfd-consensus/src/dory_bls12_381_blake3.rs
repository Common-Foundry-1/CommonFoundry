//! Fail-closed production projection for proving BLAKE3 inside the BLS/Dory aggregate.
//!
//! This module does not implement or activate a proof. It pins the conservative
//! wire and opening-claim budget for replacing the separate Goldilocks FRI
//! bridge with two BLS12-381 scalar-field arguments:
//!
//! 1. an execution sumcheck over the complete narrow BLAKE3 trace; and
//! 2. a row-indexed LogUp permutation that binds every committed `next` row to
//!    the following committed `local` row.
//!
//! The adjacency argument is required. Merely placing local and next values in
//! one prover-supplied table would not prove that adjacent rows are related.

#[cfg(all(test, feature = "whir-prototype"))]
use dory_pcs::primitives::arithmetic::Field as DoryField;
#[cfg(all(test, feature = "whir-prototype"))]
use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression, get_symbolic_constraints,
};
#[cfg(all(test, feature = "whir-prototype"))]
use p3_field::PrimeField64;

#[cfg(all(test, feature = "whir-prototype"))]
use crate::dory_bls12_381_prototype::BlsDoryFr;
#[cfg(all(test, feature = "whir-prototype"))]
use crate::{
    ExtensionElement, GOLDILOCKS_MODULUS, StructuredBlake3Statement,
    structured_blake3_narrow::{F as Goldilocks, NarrowBlake3Air, NarrowBlake3Error},
};
use crate::{
    dory_bls12_381_layout::BLS_DORY_SHARED_PRODUCTION_CLAIMS,
    wire::MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
};

/// Version of this projection only; no wire proof uses it.
pub const BLS_DORY_BLAKE3_PROJECTION_VERSION: u16 = 1;
/// The production final activation contains 128 * 4096 bytes.
pub const BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES: usize = 1 << 19;
/// The narrow tree schedule pads the production computation to 2^20 rows.
pub const BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS: usize = 1 << 20;
/// Twenty Boolean variables address the production trace rows.
pub const BLS_DORY_BLAKE3_TRACE_VARIABLES: usize = 20;
/// BLS-native evaluation uses one accumulator instead of three Goldilocks limbs.
pub const BLS_DORY_BLAKE3_MAIN_WIDTH: usize = 289;
/// The deterministic BLAKE3 schedule retains the existing fixed preprocessing width.
pub const BLS_DORY_BLAKE3_PREPROCESSED_WIDTH: usize = 84;
/// The translated execution constraints have degree at most sixteen.
pub const BLS_DORY_BLAKE3_EXECUTION_CONSTRAINT_DEGREE: usize = 16;
/// Multiplying by the row-equality polynomial raises sumcheck degree by one.
pub const BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE: usize =
    BLS_DORY_BLAKE3_EXECUTION_CONSTRAINT_DEGREE + 1;
/// The row-indexed LogUp adjacency relation has degree at most three after equality weighting.
pub const BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE: usize = 3;
/// Execution opens every local/next main column and every fixed preprocessing column.
pub const BLS_DORY_BLAKE3_EXECUTION_CLAIMS: usize =
    2 * BLS_DORY_BLAKE3_MAIN_WIDTH + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
/// Adjacency reopens local/next columns and the two LogUp inverse columns.
pub const BLS_DORY_BLAKE3_ADJACENCY_CLAIMS: usize = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH + 2;
/// Complete claim count after composing with the existing production shared proof.
pub const BLS_DORY_BLAKE3_COMPOSED_CLAIMS: usize = BLS_DORY_SHARED_PRODUCTION_CLAIMS
    + BLS_DORY_BLAKE3_EXECUTION_CLAIMS
    + BLS_DORY_BLAKE3_ADJACENCY_CLAIMS;
/// Proposed future parser bound. The active aggregate parser remains at 128 claims.
pub const BLS_DORY_BLAKE3_PROPOSED_MAX_CLAIMS: usize = 2_048;

const SCALAR_BYTES: usize = 32;
const GT_BYTES: usize = 576;
const COMPONENT_HEADER_BYTES: usize = 20;
const TRANSCRIPT_DIGEST_BYTES: usize = 32;
const FRAME_LENGTH_BYTES: usize = 4;
const CURRENT_SHARED_PRODUCTION_BYTES: usize = 133_409;

/// Conservative execution-component wire projection.
pub const BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES: usize = COMPONENT_HEADER_BYTES
    + GT_BYTES
    + BLS_DORY_BLAKE3_TRACE_VARIABLES
        * (BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE + 1)
        * SCALAR_BYTES
    + BLS_DORY_BLAKE3_EXECUTION_CLAIMS * SCALAR_BYTES
    + TRANSCRIPT_DIGEST_BYTES;
/// Conservative adjacency-component wire projection.
pub const BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES: usize = COMPONENT_HEADER_BYTES
    + GT_BYTES
    + BLS_DORY_BLAKE3_TRACE_VARIABLES
        * (BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1)
        * SCALAR_BYTES
    + BLS_DORY_BLAKE3_ADJACENCY_CLAIMS * SCALAR_BYTES
    + TRANSCRIPT_DIGEST_BYTES;
/// Projected V3 payload after replacing, rather than composing with, the FRI bridge.
pub const BLS_DORY_BLAKE3_PROJECTED_V3_BYTES: usize = CURRENT_SHARED_PRODUCTION_BYTES
    + 2 * FRAME_LENGTH_BYTES
    + BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES
    + BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES;
/// Remaining room under the existing V3 structured-proof allowance.
pub const BLS_DORY_BLAKE3_PROJECTED_HEADROOM_BYTES: usize =
    MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES - BLS_DORY_BLAKE3_PROJECTED_V3_BYTES;

const _: () = {
    assert!(BLS_DORY_BLAKE3_PROJECTED_V3_BYTES < MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES);
    assert!(BLS_DORY_BLAKE3_COMPOSED_CLAIMS <= BLS_DORY_BLAKE3_PROPOSED_MAX_CLAIMS);
    assert!(!BLS_DORY_BLAKE3_PRODUCTION_READY);
};

/// This is a bounded design projection, not an implemented production proof.
pub const BLS_DORY_BLAKE3_PRODUCTION_READY: bool = false;
/// Gates that must remain closed before this design can replace the FRI bridge.
pub const BLS_DORY_BLAKE3_PRODUCTION_BLOCKERS: [&str; 4] = [
    "the translated 1,305 narrow BLAKE3 constraints have not been wired into a Dory execution sumcheck",
    "the row-indexed LogUp adjacency argument and its complete Fiat-Shamir soundness bound have not been implemented or independently reviewed",
    "the shared aggregate parser still intentionally caps claim count at 128 and must not be widened before the new components verify end to end",
    "the complete n=33 proof size, proving time, verification time, peak memory, and peak scratch have not been measured or audited",
];

/// Field-independent variable reference emitted by the existing BLAKE3 AIR.
#[cfg(all(test, feature = "whir-prototype"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlsDoryBlake3Variable {
    Main { offset: u8, index: u16 },
    Preprocessed { offset: u8, index: u16 },
    Public { index: u16 },
    Periodic { index: u16 },
}

/// Canonical integer expression translated from one Goldilocks AIR constraint.
#[cfg(all(test, feature = "whir-prototype"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BlsDoryBlake3ConstraintExpr {
    Variable(BlsDoryBlake3Variable),
    FirstRow,
    LastRow,
    Transition,
    Constant(i64),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Neg(Box<Self>),
    Mul(Box<Self>, Box<Self>),
}

#[cfg(all(test, feature = "whir-prototype"))]
pub(crate) struct BlsDoryBlake3Evaluation<'a> {
    pub main_local: &'a [BlsDoryFr],
    pub main_next: &'a [BlsDoryFr],
    pub preprocessed_local: &'a [BlsDoryFr],
    pub preprocessed_next: &'a [BlsDoryFr],
    pub public: &'a [BlsDoryFr],
    pub periodic: &'a [BlsDoryFr],
    pub first_row: BlsDoryFr,
    pub last_row: BlsDoryFr,
    pub transition: BlsDoryFr,
}

#[cfg(all(test, feature = "whir-prototype"))]
impl BlsDoryBlake3ConstraintExpr {
    pub(crate) fn evaluate(&self, values: &BlsDoryBlake3Evaluation<'_>) -> BlsDoryFr {
        match self {
            Self::Variable(variable) => match *variable {
                BlsDoryBlake3Variable::Main { offset: 0, index } => {
                    values.main_local[usize::from(index)]
                }
                BlsDoryBlake3Variable::Main { offset: 1, index } => {
                    values.main_next[usize::from(index)]
                }
                BlsDoryBlake3Variable::Preprocessed { offset: 0, index } => {
                    values.preprocessed_local[usize::from(index)]
                }
                BlsDoryBlake3Variable::Preprocessed { offset: 1, index } => {
                    values.preprocessed_next[usize::from(index)]
                }
                BlsDoryBlake3Variable::Public { index } => values.public[usize::from(index)],
                BlsDoryBlake3Variable::Periodic { index } => values.periodic[usize::from(index)],
                BlsDoryBlake3Variable::Main { offset, .. }
                | BlsDoryBlake3Variable::Preprocessed { offset, .. } => {
                    panic!("BLAKE3 constraint IR contains unsupported row offset {offset}")
                }
            },
            Self::FirstRow => values.first_row,
            Self::LastRow => values.last_row,
            Self::Transition => values.transition,
            Self::Constant(value) => BlsDoryFr::from_i64(*value),
            Self::Add(left, right) => left.evaluate(values) + right.evaluate(values),
            Self::Sub(left, right) => left.evaluate(values) - right.evaluate(values),
            Self::Neg(value) => -value.evaluate(values),
            Self::Mul(left, right) => left.evaluate(values) * right.evaluate(values),
        }
    }
}

/// Generate the exact existing narrow-BLAKE3 equations as a field-independent IR.
#[cfg(all(test, feature = "whir-prototype"))]
pub(crate) fn bls_dory_blake3_constraint_ir(
    activation_len: usize,
) -> Result<Vec<BlsDoryBlake3ConstraintExpr>, NarrowBlake3Error> {
    if activation_len < 32 || !activation_len.is_power_of_two() {
        return Err(NarrowBlake3Error::UnsupportedShape);
    }
    let point_variables = activation_len.ilog2() as usize;
    let statement = StructuredBlake3Statement {
        challenge_digest: [0; 32],
        final_activation_len: activation_len,
        final_activation_digest: [0; 32],
        final_activation_point: vec![ExtensionElement { limbs: [0; 3] }; point_variables],
        final_activation_evaluation: ExtensionElement { limbs: [0; 3] },
    };
    let air = NarrowBlake3Air::new(&statement)?;
    let layout = AirLayout::from_air(&air);
    get_symbolic_constraints::<Goldilocks, _>(&air, layout)
        .iter()
        .map(translate_constraint)
        .collect()
}

#[cfg(all(test, feature = "whir-prototype"))]
fn translate_constraint(
    expression: &SymbolicExpression<Goldilocks>,
) -> Result<BlsDoryBlake3ConstraintExpr, NarrowBlake3Error> {
    Ok(match expression {
        SymbolicExpr::Leaf(BaseLeaf::Variable(variable)) => {
            BlsDoryBlake3ConstraintExpr::Variable(match variable.entry {
                BaseEntry::Main { offset } => BlsDoryBlake3Variable::Main {
                    offset: u8::try_from(offset).map_err(|_| NarrowBlake3Error::Encoding)?,
                    index: u16::try_from(variable.index)
                        .map_err(|_| NarrowBlake3Error::Encoding)?,
                },
                BaseEntry::Preprocessed { offset } => BlsDoryBlake3Variable::Preprocessed {
                    offset: u8::try_from(offset).map_err(|_| NarrowBlake3Error::Encoding)?,
                    index: u16::try_from(variable.index)
                        .map_err(|_| NarrowBlake3Error::Encoding)?,
                },
                BaseEntry::Public => BlsDoryBlake3Variable::Public {
                    index: u16::try_from(variable.index)
                        .map_err(|_| NarrowBlake3Error::Encoding)?,
                },
                BaseEntry::Periodic => BlsDoryBlake3Variable::Periodic {
                    index: u16::try_from(variable.index)
                        .map_err(|_| NarrowBlake3Error::Encoding)?,
                },
            })
        }
        SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => BlsDoryBlake3ConstraintExpr::FirstRow,
        SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => BlsDoryBlake3ConstraintExpr::LastRow,
        SymbolicExpr::Leaf(BaseLeaf::IsTransition) => BlsDoryBlake3ConstraintExpr::Transition,
        SymbolicExpr::Leaf(BaseLeaf::Constant(value)) => {
            BlsDoryBlake3ConstraintExpr::Constant(centered_goldilocks(*value))
        }
        SymbolicExpr::Add { x, y, .. } => BlsDoryBlake3ConstraintExpr::Add(
            Box::new(translate_constraint(x)?),
            Box::new(translate_constraint(y)?),
        ),
        SymbolicExpr::Sub { x, y, .. } => BlsDoryBlake3ConstraintExpr::Sub(
            Box::new(translate_constraint(x)?),
            Box::new(translate_constraint(y)?),
        ),
        SymbolicExpr::Neg { x, .. } => {
            BlsDoryBlake3ConstraintExpr::Neg(Box::new(translate_constraint(x)?))
        }
        SymbolicExpr::Mul { x, y, .. } => BlsDoryBlake3ConstraintExpr::Mul(
            Box::new(translate_constraint(x)?),
            Box::new(translate_constraint(y)?),
        ),
    })
}

#[cfg(all(test, feature = "whir-prototype"))]
fn centered_goldilocks(value: Goldilocks) -> i64 {
    let canonical = value.as_canonical_u64();
    if canonical <= GOLDILOCKS_MODULUS / 2 {
        canonical as i64
    } else {
        -i64::try_from(GOLDILOCKS_MODULUS - canonical)
            .expect("centered Goldilocks constant fits i64")
    }
}

/// Exact projection values exposed to tests and activation tooling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryBlake3Projection {
    pub execution_claims: usize,
    pub adjacency_claims: usize,
    pub composed_claims: usize,
    pub execution_proof_bytes: usize,
    pub adjacency_proof_bytes: usize,
    pub projected_v3_bytes: usize,
    pub projected_headroom_bytes: usize,
}

pub const fn projected_bls_dory_blake3_v3() -> BlsDoryBlake3Projection {
    BlsDoryBlake3Projection {
        execution_claims: BLS_DORY_BLAKE3_EXECUTION_CLAIMS,
        adjacency_claims: BLS_DORY_BLAKE3_ADJACENCY_CLAIMS,
        composed_claims: BLS_DORY_BLAKE3_COMPOSED_CLAIMS,
        execution_proof_bytes: BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES,
        adjacency_proof_bytes: BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES,
        projected_v3_bytes: BLS_DORY_BLAKE3_PROJECTED_V3_BYTES,
        projected_headroom_bytes: BLS_DORY_BLAKE3_PROJECTED_HEADROOM_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dory_bls12_381_aggregate::MAX_BLS_DORY_AGGREGATE_CLAIMS;
    #[cfg(feature = "whir-prototype")]
    use crate::structured_blake3_narrow::{generate_main_trace, public_values};
    #[cfg(feature = "whir-prototype")]
    use crate::structured_blake3_tree::build_tree_witness;
    #[cfg(feature = "whir-prototype")]
    use p3_air::BaseAir;
    #[cfg(feature = "whir-prototype")]
    use p3_matrix::Matrix;

    #[cfg(feature = "whir-prototype")]
    const OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";

    #[cfg(feature = "whir-prototype")]
    fn bls_values(values: impl IntoIterator<Item = Goldilocks>) -> Vec<BlsDoryFr> {
        values
            .into_iter()
            .map(|value| BlsDoryFr::from_i64(centered_goldilocks(value)))
            .collect()
    }

    #[cfg(feature = "whir-prototype")]
    fn maximum_abs_constant(expression: &BlsDoryBlake3ConstraintExpr) -> u64 {
        match expression {
            BlsDoryBlake3ConstraintExpr::Constant(value) => value.unsigned_abs(),
            BlsDoryBlake3ConstraintExpr::Add(left, right)
            | BlsDoryBlake3ConstraintExpr::Sub(left, right)
            | BlsDoryBlake3ConstraintExpr::Mul(left, right) => {
                maximum_abs_constant(left).max(maximum_abs_constant(right))
            }
            BlsDoryBlake3ConstraintExpr::Neg(value) => maximum_abs_constant(value),
            BlsDoryBlake3ConstraintExpr::Variable(_)
            | BlsDoryBlake3ConstraintExpr::FirstRow
            | BlsDoryBlake3ConstraintExpr::LastRow
            | BlsDoryBlake3ConstraintExpr::Transition => 0,
        }
    }

    #[test]
    fn native_blake3_projection_is_bounded_but_fail_closed() {
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES, 524_288);
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS, 1_048_576);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_CLAIMS, 662);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_CLAIMS, 580);
        assert_eq!(BLS_DORY_BLAKE3_COMPOSED_CLAIMS, 1_370);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES, 33_332);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES, 21_748);
        assert_eq!(
            crate::dory_bls12_381_layout::projected_shared_production_proof_bytes().unwrap(),
            133_409
        );
        assert_eq!(BLS_DORY_BLAKE3_PROJECTED_V3_BYTES, 188_497);
        assert_eq!(MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES, 261_947);
        assert_eq!(BLS_DORY_BLAKE3_PROJECTED_HEADROOM_BYTES, 73_450);
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_BLOCKERS.len(), 4);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn production_air_translates_to_bounded_integer_constraints() {
        let constraints =
            bls_dory_blake3_constraint_ir(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES).unwrap();
        assert_eq!(constraints.len(), 1_305);
        let maximum = constraints.iter().map(maximum_abs_constant).max().unwrap();
        assert_eq!(maximum, 1_u64 << 33);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn honest_narrow_blake3_trace_satisfies_translated_bls_constraints() {
        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let challenge_digest = [0x42; 32];
        let witness = build_tree_witness(OUTPUT_CONTEXT, challenge_digest, &activation).unwrap();
        let point = (0..activation.len().ilog2())
            .map(|index| ExtensionElement {
                limbs: [
                    u64::from(index) + 2,
                    u64::from(index) + 3,
                    u64::from(index) + 4,
                ],
            })
            .collect::<Vec<_>>();
        let native_point = point
            .iter()
            .copied()
            .map(ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let table = activation
            .iter()
            .map(|value| {
                crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
            })
            .collect::<Vec<_>>();
        let statement = StructuredBlake3Statement {
            challenge_digest,
            final_activation_len: activation.len(),
            final_activation_digest: witness.digest,
            final_activation_point: point,
            final_activation_evaluation: ExtensionElement::from_field(
                crate::structured_sumcheck::evaluate_mle(&table, &native_point),
            ),
        };
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let main = generate_main_trace(&air, &statement, &witness);
        let preprocessed = air.preprocessed_trace().unwrap();
        let public = bls_values(public_values(&statement).unwrap());
        let constraints = bls_dory_blake3_constraint_ir(activation.len()).unwrap();
        assert_eq!(constraints.len(), 1_305);

        for row in 0..air.trace_rows() {
            let next_row = (row + 1) % air.trace_rows();
            let main_local = bls_values(unsafe { main.row_unchecked(row) });
            let main_next = bls_values(unsafe { main.row_unchecked(next_row) });
            let preprocessed_local = bls_values(unsafe { preprocessed.row_unchecked(row) });
            let preprocessed_next = bls_values(unsafe { preprocessed.row_unchecked(next_row) });
            let periodic = bls_values(air.periodic_values(row));
            let values = BlsDoryBlake3Evaluation {
                main_local: &main_local,
                main_next: &main_next,
                preprocessed_local: &preprocessed_local,
                preprocessed_next: &preprocessed_next,
                public: &public,
                periodic: &periodic,
                first_row: BlsDoryFr::from_u64(u64::from(row == 0)),
                last_row: BlsDoryFr::from_u64(u64::from(row + 1 == air.trace_rows())),
                transition: BlsDoryFr::from_u64(u64::from(row + 1 != air.trace_rows())),
            };
            for (constraint_index, constraint) in constraints.iter().enumerate() {
                assert_eq!(
                    constraint.evaluate(&values),
                    BlsDoryFr::zero(),
                    "translated constraint {constraint_index} failed at row {row}"
                );
            }
        }

        let main_next = bls_values(unsafe { main.row_unchecked(1) });
        let mut changed_main = bls_values(unsafe { main.row_unchecked(0) });
        changed_main[0] = changed_main[0] + BlsDoryFr::from_u64(1);
        let preprocessed_local = bls_values(unsafe { preprocessed.row_unchecked(0) });
        let preprocessed_next = bls_values(unsafe { preprocessed.row_unchecked(1) });
        let periodic = bls_values(air.periodic_values(0));
        let changed = BlsDoryBlake3Evaluation {
            main_local: &changed_main,
            main_next: &main_next,
            preprocessed_local: &preprocessed_local,
            preprocessed_next: &preprocessed_next,
            public: &public,
            periodic: &periodic,
            first_row: BlsDoryFr::from_u64(1),
            last_row: BlsDoryFr::zero(),
            transition: BlsDoryFr::from_u64(1),
        };
        assert!(
            constraints
                .iter()
                .any(|constraint| constraint.evaluate(&changed) != BlsDoryFr::zero())
        );

        let mut changed_public = public.clone();
        changed_public[72] = changed_public[72] + BlsDoryFr::from_u64(1);
        let point_mutation_rejected = (0..air.trace_rows()).any(|row| {
            let next_row = (row + 1) % air.trace_rows();
            let main_local = bls_values(unsafe { main.row_unchecked(row) });
            let main_next = bls_values(unsafe { main.row_unchecked(next_row) });
            let preprocessed_local = bls_values(unsafe { preprocessed.row_unchecked(row) });
            let preprocessed_next = bls_values(unsafe { preprocessed.row_unchecked(next_row) });
            let periodic = bls_values(air.periodic_values(row));
            let changed = BlsDoryBlake3Evaluation {
                main_local: &main_local,
                main_next: &main_next,
                preprocessed_local: &preprocessed_local,
                preprocessed_next: &preprocessed_next,
                public: &changed_public,
                periodic: &periodic,
                first_row: BlsDoryFr::from_u64(u64::from(row == 0)),
                last_row: BlsDoryFr::from_u64(u64::from(row + 1 == air.trace_rows())),
                transition: BlsDoryFr::from_u64(u64::from(row + 1 != air.trace_rows())),
            };
            constraints
                .iter()
                .any(|constraint| constraint.evaluate(&changed) != BlsDoryFr::zero())
        });
        assert!(point_mutation_rejected);
    }
}
