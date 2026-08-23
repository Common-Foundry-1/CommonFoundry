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
use dory_pcs::primitives::{arithmetic::Field as DoryField, transcript::Transcript};
#[cfg(all(test, feature = "whir-prototype"))]
use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression, get_symbolic_constraints,
};
#[cfg(all(test, feature = "whir-prototype"))]
use p3_field::PrimeField64;

#[cfg(all(test, feature = "whir-prototype"))]
use crate::dory_bls12_381_prototype::{BlsDoryFr, BlsDoryTranscript};
#[cfg(all(test, feature = "whir-prototype"))]
use crate::{
    ExtensionElement, GOLDILOCKS_MODULUS, StructuredBlake3Statement,
    dory_bls12_381_output_bridge::BlsDoryOutputBridgeStatement,
    structured_blake3_narrow::{
        F as Goldilocks, NarrowBlake3Air, NarrowBlake3Error, TEST_EVALUATION_ACCUMULATOR_START,
        TEST_MAIN_WIDTH, TEST_ORIGINAL_NIBBLES_START, TEST_STACK_START,
    },
};
use crate::{
    dory_bls12_381_layout::BLS_DORY_SHARED_PRODUCTION_CLAIMS,
    dory_bls12_381_soundness::{
        BlsDorySoundnessError, BlsDorySoundnessTerm, production_bls_dory_soundness_report,
    },
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
/// Eleven selector variables separate main and preprocessing tables into 1,024-slot halves.
pub const BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES: usize = 11;
/// Adjacency fixes the source half selector and randomizes the remaining ten variables.
pub const BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES: usize = 10;
/// Twenty trace variables plus eleven source selectors define the shared commitment.
pub const BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES: usize = 31;
/// Dory rows address the eleven high-order selector variables.
pub const BLS_DORY_BLAKE3_SOURCE_DORY_NU: usize = BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES;
/// Dory columns address the twenty low-order trace-row variables.
pub const BLS_DORY_BLAKE3_SOURCE_DORY_SIGMA: usize = BLS_DORY_BLAKE3_TRACE_VARIABLES;
/// The translated execution constraints have degree at most sixteen.
pub const BLS_DORY_BLAKE3_EXECUTION_CONSTRAINT_DEGREE: usize = 16;
/// The native relation keeps 1,296 BLAKE3 constraints and replaces nine
/// three-limb evaluation constraints with three scalar constraints.
pub const BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS: usize = 1_299;
/// Multiplying by the row-equality polynomial raises sumcheck degree by one.
pub const BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE: usize =
    BLS_DORY_BLAKE3_EXECUTION_CONSTRAINT_DEGREE + 1;
/// The row-indexed LogUp adjacency relation has degree at most three after equality weighting.
pub const BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE: usize = 3;
/// Local and next terminal evaluations exposed by the execution sumcheck.
pub const BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS: usize =
    2 * (BLS_DORY_BLAKE3_MAIN_WIDTH + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH);
/// One transcript-random selector batches every execution terminal evaluation.
pub const BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS: usize = 1;
/// Local/next and inverse terminal evaluations exposed by the adjacency sumcheck.
pub const BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS: usize =
    2 * BLS_DORY_BLAKE3_MAIN_WIDTH + 2;
/// Separate source and post-challenge inverse commitments require two openings.
pub const BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS: usize = 2;
/// Complete Dory opening-claim count after composition with the shared proof.
pub const BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS: usize = BLS_DORY_SHARED_PRODUCTION_CLAIMS
    + BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS
    + BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS;
/// Proposed future parser bound. The active aggregate parser remains at 128 claims.
pub const BLS_DORY_BLAKE3_PROPOSED_MAX_OPENING_CLAIMS: usize = 256;

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
    + BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS * SCALAR_BYTES
    + TRANSCRIPT_DIGEST_BYTES;
/// Conservative adjacency-component wire projection.
pub const BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES: usize = COMPONENT_HEADER_BYTES
    + GT_BYTES
    + BLS_DORY_BLAKE3_TRACE_VARIABLES
        * (BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE + 1)
        * SCALAR_BYTES
    + BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS * SCALAR_BYTES
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
    assert!(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS <= BLS_DORY_BLAKE3_PROPOSED_MAX_OPENING_CLAIMS);
    assert!(
        BLS_DORY_BLAKE3_SOURCE_DORY_NU + BLS_DORY_BLAKE3_SOURCE_DORY_SIGMA
            == BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES
    );
    assert!(!BLS_DORY_BLAKE3_PRODUCTION_READY);
};

/// This is a bounded design projection, not an implemented production proof.
pub const BLS_DORY_BLAKE3_PRODUCTION_READY: bool = false;
/// Gates that must remain closed before this design can replace the FRI bridge.
pub const BLS_DORY_BLAKE3_PRODUCTION_BLOCKERS: [&str; 4] = [
    "the bounded composed fixture makes execution and adjacency reuse the exact same Dory-authenticated main commitments, and a bounded row source preserves exact commitment and opening bytes with fail-closed scratch authentication; the unified 31-variable production source/inverse commitment and out-of-core opening path are not implemented or measured",
    "the executable union bound covers execution, row compression, lookup, sumchecks, and selector batching at a 219-bit algebraic floor, but it is not independently reviewed and does not replace Dory knowledge-soundness or Fiat-Shamir analysis",
    "the shared aggregate parser still intentionally caps claim count at 128 and must not be widened before the new components verify end to end",
    "the complete n=33 proof size, proving time, verification time, peak memory, and peak scratch have not been measured or audited",
];

/// Executable algebraic union bound for the shared proof plus BLAKE3 replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryBlake3SoundnessReport {
    pub shared_algebraic_numerator_upper_bound: u64,
    pub blake3_terms: Vec<BlsDorySoundnessTerm>,
    pub blake3_algebraic_numerator_upper_bound: u64,
    pub composed_algebraic_numerator_upper_bound: u64,
    pub nonzero_challenge_space_lower_bound_bits: u32,
    pub algebraic_soundness_bits: u32,
    pub required_algebraic_soundness_bits: u32,
    pub grinding_headroom_bits: u32,
    pub composed_opening_claims: usize,
    pub proposed_maximum_opening_claims: usize,
    pub independently_reviewed: bool,
}

/// Conservative algebraic terms for the exact projected BLAKE3 topology.
pub fn projected_bls_dory_blake3_soundness_report()
-> Result<BlsDoryBlake3SoundnessReport, BlsDorySoundnessError> {
    const NONZERO_CHALLENGE_BITS: u32 = 254;
    const REQUIRED_BITS: u32 = 128;
    let rows = u64::try_from(BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS)
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    let trace_variables = u64::try_from(BLS_DORY_BLAKE3_TRACE_VARIABLES)
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    let terms = vec![
        blake3_soundness_term(
            "BLAKE3 execution constraint mixing",
            u64::try_from(BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS - 1)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term("BLAKE3 execution local equality point", trace_variables),
        blake3_soundness_term(
            "BLAKE3 execution sumcheck",
            u64::try_from(BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?
                .checked_mul(trace_variables)
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 execution source selector batching",
            u64::try_from(BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 adjacency row compression",
            rows.checked_mul(
                u64::try_from(BLS_DORY_BLAKE3_MAIN_WIDTH)
                    .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
            )
            .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 adjacency lookup-alpha rational identity",
            rows.checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term("BLAKE3 adjacency local relation mixing", 1),
        blake3_soundness_term("BLAKE3 adjacency global relation mixing", 1),
        blake3_soundness_term("BLAKE3 adjacency local equality point", trace_variables),
        blake3_soundness_term(
            "BLAKE3 adjacency sumcheck",
            u64::try_from(BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?
                .checked_mul(trace_variables)
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 adjacency source selector batching",
            u64::try_from(BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
        blake3_soundness_term(
            "BLAKE3 adjacency inverse selector batching",
            u64::try_from(BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES)
                .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?,
        ),
    ];
    let blake3_algebraic_numerator_upper_bound = terms.iter().try_fold(0_u64, |total, term| {
        total
            .checked_add(term.total_numerator_upper_bound()?)
            .ok_or(BlsDorySoundnessError::ArithmeticOverflow)
    })?;
    let shared = production_bls_dory_soundness_report()?;
    let composed_algebraic_numerator_upper_bound = shared
        .total_algebraic_numerator_upper_bound
        .checked_add(blake3_algebraic_numerator_upper_bound)
        .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?;
    let algebraic_soundness_bits = NONZERO_CHALLENGE_BITS
        .checked_sub(blake3_ceil_log2(composed_algebraic_numerator_upper_bound))
        .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?;
    let grinding_headroom_bits = algebraic_soundness_bits
        .checked_sub(REQUIRED_BITS)
        .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?;
    Ok(BlsDoryBlake3SoundnessReport {
        shared_algebraic_numerator_upper_bound: shared.total_algebraic_numerator_upper_bound,
        blake3_terms: terms,
        blake3_algebraic_numerator_upper_bound,
        composed_algebraic_numerator_upper_bound,
        nonzero_challenge_space_lower_bound_bits: NONZERO_CHALLENGE_BITS,
        algebraic_soundness_bits,
        required_algebraic_soundness_bits: REQUIRED_BITS,
        grinding_headroom_bits,
        composed_opening_claims: BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS,
        proposed_maximum_opening_claims: BLS_DORY_BLAKE3_PROPOSED_MAX_OPENING_CLAIMS,
        independently_reviewed: false,
    })
}

fn blake3_soundness_term(label: &'static str, numerator: u64) -> BlsDorySoundnessTerm {
    BlsDorySoundnessTerm {
        label,
        instances: 1,
        numerator_upper_bound_per_instance: numerator,
    }
}

const fn blake3_ceil_log2(value: u64) -> u32 {
    if value <= 1 {
        0
    } else {
        u64::BITS - (value - 1).leading_zeros()
    }
}

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

#[cfg(all(test, feature = "whir-prototype"))]
fn uses_old_evaluation_constraint(expression: &BlsDoryBlake3ConstraintExpr) -> bool {
    match expression {
        BlsDoryBlake3ConstraintExpr::Variable(BlsDoryBlake3Variable::Main { index, .. }) => {
            (TEST_EVALUATION_ACCUMULATOR_START..TEST_STACK_START).contains(&usize::from(*index))
        }
        BlsDoryBlake3ConstraintExpr::Add(left, right)
        | BlsDoryBlake3ConstraintExpr::Sub(left, right)
        | BlsDoryBlake3ConstraintExpr::Mul(left, right) => {
            uses_old_evaluation_constraint(left) || uses_old_evaluation_constraint(right)
        }
        BlsDoryBlake3ConstraintExpr::Neg(value) => uses_old_evaluation_constraint(value),
        BlsDoryBlake3ConstraintExpr::Variable(_)
        | BlsDoryBlake3ConstraintExpr::FirstRow
        | BlsDoryBlake3ConstraintExpr::LastRow
        | BlsDoryBlake3ConstraintExpr::Transition
        | BlsDoryBlake3ConstraintExpr::Constant(_) => false,
    }
}

#[cfg(all(test, feature = "whir-prototype"))]
fn remap_native_main_constraint(
    expression: &BlsDoryBlake3ConstraintExpr,
) -> Result<BlsDoryBlake3ConstraintExpr, NarrowBlake3Error> {
    Ok(match expression {
        BlsDoryBlake3ConstraintExpr::Variable(variable) => {
            let variable = match *variable {
                BlsDoryBlake3Variable::Main { offset, index } => {
                    let index = usize::from(index);
                    if (TEST_EVALUATION_ACCUMULATOR_START..TEST_STACK_START).contains(&index) {
                        return Err(NarrowBlake3Error::Encoding);
                    }
                    let native_index = if index >= TEST_STACK_START {
                        index - (TEST_STACK_START - TEST_EVALUATION_ACCUMULATOR_START - 1)
                    } else {
                        index
                    };
                    BlsDoryBlake3Variable::Main {
                        offset,
                        index: u16::try_from(native_index)
                            .map_err(|_| NarrowBlake3Error::Encoding)?,
                    }
                }
                other => other,
            };
            BlsDoryBlake3ConstraintExpr::Variable(variable)
        }
        BlsDoryBlake3ConstraintExpr::FirstRow => BlsDoryBlake3ConstraintExpr::FirstRow,
        BlsDoryBlake3ConstraintExpr::LastRow => BlsDoryBlake3ConstraintExpr::LastRow,
        BlsDoryBlake3ConstraintExpr::Transition => BlsDoryBlake3ConstraintExpr::Transition,
        BlsDoryBlake3ConstraintExpr::Constant(value) => {
            BlsDoryBlake3ConstraintExpr::Constant(*value)
        }
        BlsDoryBlake3ConstraintExpr::Add(left, right) => BlsDoryBlake3ConstraintExpr::Add(
            Box::new(remap_native_main_constraint(left)?),
            Box::new(remap_native_main_constraint(right)?),
        ),
        BlsDoryBlake3ConstraintExpr::Sub(left, right) => BlsDoryBlake3ConstraintExpr::Sub(
            Box::new(remap_native_main_constraint(left)?),
            Box::new(remap_native_main_constraint(right)?),
        ),
        BlsDoryBlake3ConstraintExpr::Neg(value) => {
            BlsDoryBlake3ConstraintExpr::Neg(Box::new(remap_native_main_constraint(value)?))
        }
        BlsDoryBlake3ConstraintExpr::Mul(left, right) => BlsDoryBlake3ConstraintExpr::Mul(
            Box::new(remap_native_main_constraint(left)?),
            Box::new(remap_native_main_constraint(right)?),
        ),
    })
}

#[cfg(all(test, feature = "whir-prototype"))]
fn uses_removed_native_input(expression: &BlsDoryBlake3ConstraintExpr) -> bool {
    match expression {
        BlsDoryBlake3ConstraintExpr::Variable(BlsDoryBlake3Variable::Public { index }) => {
            usize::from(*index) >= 72
        }
        BlsDoryBlake3ConstraintExpr::Variable(BlsDoryBlake3Variable::Periodic { .. }) => true,
        BlsDoryBlake3ConstraintExpr::Add(left, right)
        | BlsDoryBlake3ConstraintExpr::Sub(left, right)
        | BlsDoryBlake3ConstraintExpr::Mul(left, right) => {
            uses_removed_native_input(left) || uses_removed_native_input(right)
        }
        BlsDoryBlake3ConstraintExpr::Neg(value) => uses_removed_native_input(value),
        BlsDoryBlake3ConstraintExpr::Variable(_)
        | BlsDoryBlake3ConstraintExpr::FirstRow
        | BlsDoryBlake3ConstraintExpr::LastRow
        | BlsDoryBlake3ConstraintExpr::Transition
        | BlsDoryBlake3ConstraintExpr::Constant(_) => false,
    }
}

#[cfg(all(test, feature = "whir-prototype"))]
fn bls_dory_native_blake3_constraint_ir(
    activation_len: usize,
) -> Result<Vec<BlsDoryBlake3ConstraintExpr>, NarrowBlake3Error> {
    bls_dory_blake3_constraint_ir(activation_len)?
        .iter()
        .filter(|constraint| !uses_old_evaluation_constraint(constraint))
        .map(remap_native_main_constraint)
        .collect()
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_main_row(old_row: &[BlsDoryFr], accumulator: BlsDoryFr) -> Vec<BlsDoryFr> {
    assert_eq!(old_row.len(), TEST_MAIN_WIDTH);
    let mut row = Vec::with_capacity(BLS_DORY_BLAKE3_MAIN_WIDTH);
    row.extend_from_slice(&old_row[..TEST_EVALUATION_ACCUMULATOR_START]);
    row.push(accumulator);
    row.extend_from_slice(&old_row[TEST_STACK_START..]);
    assert_eq!(row.len(), BLS_DORY_BLAKE3_MAIN_WIDTH);
    row
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_activation_contribution(
    main_local: &[BlsDoryFr],
    activation_group: Option<usize>,
    point: &[BlsDoryFr],
) -> BlsDoryFr {
    let coefficients = native_byte_coefficients(activation_group, point);
    native_activation_contribution_from_coefficients(main_local, &coefficients)
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_byte_coefficients(
    activation_group: Option<usize>,
    point: &[BlsDoryFr],
) -> [BlsDoryFr; 8] {
    let Some(group) = activation_group else {
        return [BlsDoryFr::zero(); 8];
    };
    std::array::from_fn(|byte| {
        let index = group + byte;
        point
            .iter()
            .enumerate()
            .fold(BlsDoryFr::from_u64(1), |weight, (variable, coordinate)| {
                if (index >> variable) & 1 == 1 {
                    weight * *coordinate
                } else {
                    weight * (BlsDoryFr::from_u64(1) - *coordinate)
                }
            })
    })
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_activation_contribution_from_coefficients(
    main_local: &[BlsDoryFr],
    coefficients: &[BlsDoryFr; 8],
) -> BlsDoryFr {
    (0..8).fold(BlsDoryFr::zero(), |sum, byte| {
        let low = main_local[TEST_ORIGINAL_NIBBLES_START + 2 * byte];
        let high = main_local[TEST_ORIGINAL_NIBBLES_START + 2 * byte + 1];
        let value = low + BlsDoryFr::from_u64(16) * high;
        sum + value * coefficients[byte]
    })
}

#[cfg(all(test, feature = "whir-prototype"))]
struct BlsDoryNativeEvaluationRow<'a> {
    main_local: &'a [BlsDoryFr],
    main_next: &'a [BlsDoryFr],
    first_row: BlsDoryFr,
    last_row: BlsDoryFr,
    transition: BlsDoryFr,
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_evaluation_residuals(
    row: &BlsDoryNativeEvaluationRow<'_>,
    activation_group: Option<usize>,
    point: &[BlsDoryFr],
    raw_evaluation: BlsDoryFr,
) -> [BlsDoryFr; 3] {
    let coefficients = native_byte_coefficients(activation_group, point);
    native_evaluation_residuals_from_coefficients(row, &coefficients, raw_evaluation)
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_evaluation_residuals_from_coefficients(
    row: &BlsDoryNativeEvaluationRow<'_>,
    coefficients: &[BlsDoryFr; 8],
    raw_evaluation: BlsDoryFr,
) -> [BlsDoryFr; 3] {
    let current = row.main_local[TEST_EVALUATION_ACCUMULATOR_START];
    let next = row.main_next[TEST_EVALUATION_ACCUMULATOR_START];
    let contribution =
        native_activation_contribution_from_coefficients(row.main_local, coefficients);
    [
        row.first_row * current,
        row.transition * (next - current - contribution),
        row.last_row * (current - raw_evaluation),
    ]
}

#[cfg(all(test, feature = "whir-prototype"))]
fn native_accumulator_trace(
    air: &NarrowBlake3Air,
    old_main_rows: &[Vec<BlsDoryFr>],
    statement: &BlsDoryOutputBridgeStatement,
) -> Vec<BlsDoryFr> {
    let mut accumulator = BlsDoryFr::zero();
    old_main_rows
        .iter()
        .enumerate()
        .map(|(row, main_local)| {
            let current = accumulator;
            accumulator = accumulator
                + native_activation_contribution(
                    main_local,
                    air.activation_group_index_at_row(row),
                    statement.cell_point(),
                );
            current
        })
        .collect()
}

/// Exact projection values exposed to tests and activation tooling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryBlake3Projection {
    pub execution_terminal_evaluations: usize,
    pub adjacency_terminal_evaluations: usize,
    pub composed_opening_claims: usize,
    pub execution_proof_bytes: usize,
    pub adjacency_proof_bytes: usize,
    pub projected_v3_bytes: usize,
    pub projected_headroom_bytes: usize,
}

pub const fn projected_bls_dory_blake3_v3() -> BlsDoryBlake3Projection {
    BlsDoryBlake3Projection {
        execution_terminal_evaluations: BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS,
        adjacency_terminal_evaluations: BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS,
        composed_opening_claims: BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS,
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
    use crate::dory_bls12_381_aggregate::{
        BlsDoryAggregateError, BlsDoryCommittedPolynomial, BlsDoryCompactRowSource,
        BlsDoryDeferredOpeningSet, BlsDoryOpeningClaim,
        commit_bls_dory_compact_row_source_with_scratch, commit_bls_dory_polynomial,
        commit_bls_dory_row_source_with_scratch, prove_bls_dory_deferred_opening_sets,
        prove_bls_dory_same_commitment_openings, verify_bls_dory_openings,
    };
    #[cfg(feature = "whir-prototype")]
    use crate::dory_bls12_381_prototype::{BlsDoryGt, DeterministicBlsDorySetup};
    #[cfg(feature = "whir-prototype")]
    use crate::dory_bls12_381_streaming::BlsDoryRowSource;
    #[cfg(feature = "whir-prototype")]
    use crate::structured_blake3_narrow::{generate_main_trace, public_values};
    #[cfg(feature = "whir-prototype")]
    use crate::structured_blake3_tree::build_tree_witness;
    #[cfg(feature = "whir-prototype")]
    use p3_air::BaseAir;
    #[cfg(feature = "whir-prototype")]
    use p3_matrix::Matrix;
    #[cfg(feature = "whir-prototype")]
    use std::{
        io::{Seek, SeekFrom, Write},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(feature = "whir-prototype")]
    const OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";

    #[cfg(feature = "whir-prototype")]
    static BLAKE3_SCRATCH_NONCE: AtomicU64 = AtomicU64::new(1);

    #[cfg(feature = "whir-prototype")]
    struct Blake3ScratchDirectory(std::path::PathBuf);

    #[cfg(feature = "whir-prototype")]
    impl Blake3ScratchDirectory {
        fn create() -> Self {
            let nonce = BLAKE3_SCRATCH_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-blake3-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    #[cfg(feature = "whir-prototype")]
    impl Drop for Blake3ScratchDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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

    #[cfg(feature = "whir-prototype")]
    const DENSE_EXECUTION_SUMCHECK_DEGREE: usize = BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE;
    #[cfg(feature = "whir-prototype")]
    const DENSE_ADJACENCY_SUMCHECK_DEGREE: usize = BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE;

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseExecutionSumcheckProof {
        rounds: Vec<Vec<BlsDoryFr>>,
        terminal_evaluations: Vec<BlsDoryFr>,
        transcript_digest: [u8; 32],
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAdjacencySumcheckProof {
        rounds: Vec<Vec<BlsDoryFr>>,
        terminal_evaluations: Vec<BlsDoryFr>,
        transcript_digest: [u8; 32],
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseExecutionOpeningBatch {
        commitment: BlsDoryGt,
        terminal_count: usize,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAuthenticatedExecutionProof {
        sumcheck: DenseExecutionSumcheckProof,
        opening_batches: Vec<DenseExecutionOpeningBatch>,
        opening_proof: Vec<u8>,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAdjacencyOpeningBatch {
        commitment: BlsDoryGt,
        terminal_start: usize,
        terminal_count: usize,
        selector_variables: usize,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAuthenticatedAdjacencyProof {
        sumcheck: DenseAdjacencySumcheckProof,
        opening_batches: Vec<DenseAdjacencyOpeningBatch>,
        opening_proof: Vec<u8>,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone)]
    struct DenseAuthenticatedBlake3Proof {
        execution_sumcheck: DenseExecutionSumcheckProof,
        adjacency_sumcheck: DenseAdjacencySumcheckProof,
        execution_batches: Vec<DenseExecutionOpeningBatch>,
        inverse_commitment: BlsDoryGt,
        opening_proof: Vec<u8>,
    }

    #[cfg(feature = "whir-prototype")]
    struct DenseBlake3Fixture {
        air: NarrowBlake3Air,
        tables: Vec<Vec<BlsDoryFr>>,
        public: Vec<BlsDoryFr>,
        constraints: Vec<BlsDoryBlake3ConstraintExpr>,
        bridge: BlsDoryOutputBridgeStatement,
    }

    #[cfg(feature = "whir-prototype")]
    struct DenseExecutionRelation<'a> {
        public: &'a [BlsDoryFr],
        constraints: &'a [BlsDoryBlake3ConstraintExpr],
        mixing_powers: &'a [BlsDoryFr],
        raw_evaluation: BlsDoryFr,
    }

    #[cfg(feature = "whir-prototype")]
    #[derive(Clone, Copy)]
    struct DenseAdjacencyRelation {
        trace_rows: BlsDoryFr,
        compression: BlsDoryFr,
        alpha: BlsDoryFr,
        local_mixing: [BlsDoryFr; 2],
        rational_mixing: BlsDoryFr,
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_execution_tables(
        main_rows: &[Vec<BlsDoryFr>],
        preprocessed_rows: &[Vec<BlsDoryFr>],
    ) -> Vec<Vec<BlsDoryFr>> {
        assert_eq!(main_rows.len(), preprocessed_rows.len());
        assert!(main_rows.len().is_power_of_two());
        assert!(
            main_rows
                .iter()
                .all(|row| row.len() == BLS_DORY_BLAKE3_MAIN_WIDTH)
        );
        assert!(
            preprocessed_rows
                .iter()
                .all(|row| row.len() == BLS_DORY_BLAKE3_PREPROCESSED_WIDTH)
        );
        let mut tables = Vec::with_capacity(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS);
        for column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH {
            tables.push(main_rows.iter().map(|row| row[column]).collect());
        }
        for column in 0..BLS_DORY_BLAKE3_MAIN_WIDTH {
            tables.push(
                main_rows[1..]
                    .iter()
                    .chain(&main_rows[..1])
                    .map(|row| row[column])
                    .collect(),
            );
        }
        for column in 0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
            tables.push(preprocessed_rows.iter().map(|row| row[column]).collect());
        }
        for column in 0..BLS_DORY_BLAKE3_PREPROCESSED_WIDTH {
            tables.push(
                preprocessed_rows[1..]
                    .iter()
                    .chain(&preprocessed_rows[..1])
                    .map(|row| row[column])
                    .collect(),
            );
        }
        assert_eq!(tables.len(), BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS);
        tables
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_relation_value(
        terminal: &[BlsDoryFr],
        selectors: [BlsDoryFr; 3],
        coefficients: &[BlsDoryFr; 8],
        relation: &DenseExecutionRelation<'_>,
    ) -> BlsDoryFr {
        let main_next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
        let preprocessed_local_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        let preprocessed_next_start = preprocessed_local_start + BLS_DORY_BLAKE3_PREPROCESSED_WIDTH;
        let values = BlsDoryBlake3Evaluation {
            main_local: &terminal[..main_next_start],
            main_next: &terminal[main_next_start..preprocessed_local_start],
            preprocessed_local: &terminal[preprocessed_local_start..preprocessed_next_start],
            preprocessed_next: &terminal[preprocessed_next_start..],
            public: relation.public,
            periodic: &[],
            first_row: selectors[0],
            last_row: selectors[1],
            transition: selectors[2],
        };
        let mut mixed = relation
            .constraints
            .iter()
            .zip(relation.mixing_powers)
            .fold(BlsDoryFr::zero(), |sum, (constraint, coefficient)| {
                sum + constraint.evaluate(&values) * *coefficient
            });
        let native = native_evaluation_residuals_from_coefficients(
            &BlsDoryNativeEvaluationRow {
                main_local: values.main_local,
                main_next: values.main_next,
                first_row: values.first_row,
                last_row: values.last_row,
                transition: values.transition,
            },
            coefficients,
            relation.raw_evaluation,
        );
        for (residual, coefficient) in native
            .into_iter()
            .zip(&relation.mixing_powers[relation.constraints.len()..])
        {
            mixed = mixed + residual * *coefficient;
        }
        mixed
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_execution_transcript(
        bridge: &BlsDoryOutputBridgeStatement,
        commitments: &[BlsDoryGt],
    ) -> BlsDoryTranscript {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-execution-sumcheck");
        transcript.append_bytes(b"protocol-version", &1_u16.to_le_bytes());
        transcript.append_bytes(b"challenge-digest", &bridge.challenge_digest());
        transcript.append_bytes(
            b"activation-length",
            &(bridge.final_activation_len() as u64).to_le_bytes(),
        );
        transcript.append_bytes(b"activation-digest", &bridge.final_activation_digest());
        transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
        transcript.append_bytes(
            b"point-count",
            &(bridge.cell_point().len() as u64).to_le_bytes(),
        );
        for coordinate in bridge.cell_point() {
            transcript.append_field(b"dory-point", coordinate);
        }
        transcript.append_field(b"raw-evaluation", &bridge.raw_byte_evaluation());
        transcript.append_bytes(
            b"commitment-count",
            &(commitments.len() as u64).to_le_bytes(),
        );
        for commitment in commitments {
            transcript.append_group(b"packed-execution-commitment", commitment);
        }
        transcript
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_constraint_powers(transcript: &mut BlsDoryTranscript) -> Vec<BlsDoryFr> {
        let mixing = transcript.challenge_scalar(b"constraint-mixing");
        let mut powers = Vec::with_capacity(BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS);
        let mut power = BlsDoryFr::from_u64(1);
        for _ in 0..BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS {
            powers.push(power);
            power = power * mixing;
        }
        powers
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_cell_point(transcript: &mut BlsDoryTranscript, variables: usize) -> Vec<BlsDoryFr> {
        (0..variables)
            .map(|index| {
                transcript.append_bytes(b"cell-index", &(index as u64).to_le_bytes());
                transcript.challenge_scalar(b"cell-point")
            })
            .collect()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_absorb_round(
        transcript: &mut BlsDoryTranscript,
        round_index: usize,
        evaluations: &[BlsDoryFr],
    ) {
        transcript.append_bytes(b"round-index", &(round_index as u64).to_le_bytes());
        transcript.append_bytes(b"round-count", &(evaluations.len() as u64).to_le_bytes());
        for evaluation in evaluations {
            transcript.append_field(b"round-evaluation", evaluation);
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_absorb_terminal(transcript: &mut BlsDoryTranscript, terminal: &[BlsDoryFr]) {
        transcript.append_bytes(b"terminal-count", &(terminal.len() as u64).to_le_bytes());
        for evaluation in terminal {
            transcript.append_field(b"terminal-evaluation", evaluation);
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_interpolate(pair: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
        pair[0] + point * (pair[1] - pair[0])
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_fold(table: &[BlsDoryFr], point: BlsDoryFr) -> Vec<BlsDoryFr> {
        table
            .chunks_exact(2)
            .map(|pair| dense_interpolate(pair, point))
            .collect()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_equality_table(point: &[BlsDoryFr]) -> Vec<BlsDoryFr> {
        let mut table = vec![BlsDoryFr::from_u64(1); 1usize << point.len()];
        let mut active = 1usize;
        for coordinate in point {
            for index in (0..active).rev() {
                let value = table[index];
                table[index] = value * (BlsDoryFr::from_u64(1) - *coordinate);
                table[index + active] = value * *coordinate;
            }
            active *= 2;
        }
        table
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_equality_evaluation(left: &[BlsDoryFr], right: &[BlsDoryFr]) -> BlsDoryFr {
        left.iter()
            .zip(right)
            .fold(BlsDoryFr::from_u64(1), |product, (left, right)| {
                product
                    * ((BlsDoryFr::from_u64(1) - *left) * (BlsDoryFr::from_u64(1) - *right)
                        + *left * *right)
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_evaluate_samples(values: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
        assert_eq!(values.len(), DENSE_EXECUTION_SUMCHECK_DEGREE + 1);
        values
            .iter()
            .copied()
            .enumerate()
            .fold(BlsDoryFr::zero(), |result, (index, value)| {
                let mut numerator = BlsDoryFr::from_u64(1);
                let mut denominator = BlsDoryFr::from_u64(1);
                for other in 0..values.len() {
                    if other != index {
                        numerator = numerator * (point - BlsDoryFr::from_u64(other as u64));
                        denominator =
                            denominator * BlsDoryFr::from_i64(index as i64 - other as i64);
                    }
                }
                result + value * numerator * denominator.inv().unwrap()
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_boolean_equality(index: usize, point: &[BlsDoryFr]) -> BlsDoryFr {
        point
            .iter()
            .enumerate()
            .fold(BlsDoryFr::from_u64(1), |weight, (variable, coordinate)| {
                if (index >> variable) & 1 == 1 {
                    weight * *coordinate
                } else {
                    weight * (BlsDoryFr::from_u64(1) - *coordinate)
                }
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_coefficient_terminal(
        air: &NarrowBlake3Air,
        dory_point: &[BlsDoryFr],
        sumcheck_point: &[BlsDoryFr],
    ) -> [BlsDoryFr; 8] {
        let mut terminal = [BlsDoryFr::zero(); 8];
        for row in 0..air.trace_rows() {
            let equality = dense_boolean_equality(row, sumcheck_point);
            let coefficients =
                native_byte_coefficients(air.activation_group_index_at_row(row), dory_point);
            for byte in 0..8 {
                terminal[byte] = terminal[byte] + equality * coefficients[byte];
            }
        }
        terminal
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_execution_sumcheck(
        mut tables: Vec<Vec<BlsDoryFr>>,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        commitments: &[BlsDoryGt],
    ) -> DenseExecutionSumcheckProof {
        assert_eq!(tables.len(), BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS);
        let rows = tables[0].len();
        assert!(rows.is_power_of_two());
        assert!(tables.iter().all(|table| table.len() == rows));
        assert_eq!(constraints.len() + 3, BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS);
        let variables = rows.ilog2() as usize;
        let mut transcript = dense_execution_transcript(bridge, commitments);
        let mixing_powers = dense_constraint_powers(&mut transcript);
        let cell_point = dense_cell_point(&mut transcript, variables);
        let relation = DenseExecutionRelation {
            public,
            constraints,
            mixing_powers: &mixing_powers,
            raw_evaluation: bridge.raw_byte_evaluation(),
        };
        let mut equality = dense_equality_table(&cell_point);
        let mut first = vec![BlsDoryFr::zero(); rows];
        first[0] = BlsDoryFr::from_u64(1);
        let mut last = vec![BlsDoryFr::zero(); rows];
        last[rows - 1] = BlsDoryFr::from_u64(1);
        let mut transition = vec![BlsDoryFr::from_u64(1); rows];
        transition[rows - 1] = BlsDoryFr::zero();
        let mut byte_coefficients: [Vec<BlsDoryFr>; 8] = std::array::from_fn(|byte| {
            (0..rows)
                .map(|row| {
                    native_byte_coefficients(
                        air.activation_group_index_at_row(row),
                        bridge.cell_point(),
                    )[byte]
                })
                .collect()
        });
        let mut claim = BlsDoryFr::zero();
        let mut rounds = Vec::with_capacity(variables);
        for round_index in 0..variables {
            let pair_count = equality.len() / 2;
            let evaluations = (0..=DENSE_EXECUTION_SUMCHECK_DEGREE)
                .map(|sample| {
                    let sample = BlsDoryFr::from_u64(sample as u64);
                    (0..pair_count).fold(BlsDoryFr::zero(), |sum, pair| {
                        let offset = 2 * pair;
                        let terminal = tables
                            .iter()
                            .map(|table| dense_interpolate(&table[offset..offset + 2], sample))
                            .collect::<Vec<_>>();
                        let selectors = [
                            dense_interpolate(&first[offset..offset + 2], sample),
                            dense_interpolate(&last[offset..offset + 2], sample),
                            dense_interpolate(&transition[offset..offset + 2], sample),
                        ];
                        let coefficients = std::array::from_fn(|byte| {
                            dense_interpolate(&byte_coefficients[byte][offset..offset + 2], sample)
                        });
                        sum + dense_interpolate(&equality[offset..offset + 2], sample)
                            * dense_relation_value(&terminal, selectors, &coefficients, &relation)
                    })
                })
                .collect::<Vec<_>>();
            assert_eq!(evaluations[0] + evaluations[1], claim);
            dense_absorb_round(&mut transcript, round_index, &evaluations);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_samples(&evaluations, challenge);
            for table in &mut tables {
                *table = dense_fold(table, challenge);
            }
            equality = dense_fold(&equality, challenge);
            first = dense_fold(&first, challenge);
            last = dense_fold(&last, challenge);
            transition = dense_fold(&transition, challenge);
            for coefficients in &mut byte_coefficients {
                *coefficients = dense_fold(coefficients, challenge);
            }
            rounds.push(evaluations);
        }
        let terminal_evaluations = tables.iter().map(|table| table[0]).collect::<Vec<_>>();
        let selectors = [first[0], last[0], transition[0]];
        let coefficients = std::array::from_fn(|byte| byte_coefficients[byte][0]);
        assert_eq!(
            claim,
            equality[0]
                * dense_relation_value(&terminal_evaluations, selectors, &coefficients, &relation,)
        );
        dense_absorb_terminal(&mut transcript, &terminal_evaluations);
        DenseExecutionSumcheckProof {
            rounds,
            terminal_evaluations,
            transcript_digest: transcript.digest(),
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_execution_sumcheck(
        proof: &DenseExecutionSumcheckProof,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        commitments: &[BlsDoryGt],
    ) -> bool {
        let variables = air.trace_rows().ilog2() as usize;
        if proof.rounds.len() != variables
            || proof.terminal_evaluations.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
            || proof
                .rounds
                .iter()
                .any(|round| round.len() != DENSE_EXECUTION_SUMCHECK_DEGREE + 1)
        {
            return false;
        }
        let mut transcript = dense_execution_transcript(bridge, commitments);
        let mixing_powers = dense_constraint_powers(&mut transcript);
        let cell_point = dense_cell_point(&mut transcript, variables);
        let relation = DenseExecutionRelation {
            public,
            constraints,
            mixing_powers: &mixing_powers,
            raw_evaluation: bridge.raw_byte_evaluation(),
        };
        let mut claim = BlsDoryFr::zero();
        let mut sumcheck_point = Vec::with_capacity(variables);
        for (round_index, round) in proof.rounds.iter().enumerate() {
            if round[0] + round[1] != claim {
                return false;
            }
            dense_absorb_round(&mut transcript, round_index, round);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_samples(round, challenge);
            sumcheck_point.push(challenge);
        }
        let first = sumcheck_point
            .iter()
            .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
                value * (BlsDoryFr::from_u64(1) - *coordinate)
            });
        let last = sumcheck_point
            .iter()
            .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
                value * *coordinate
            });
        let selectors = [first, last, BlsDoryFr::from_u64(1) - last];
        let coefficients = dense_coefficient_terminal(air, bridge.cell_point(), &sumcheck_point);
        if claim
            != dense_equality_evaluation(&cell_point, &sumcheck_point)
                * dense_relation_value(
                    &proof.terminal_evaluations,
                    selectors,
                    &coefficients,
                    &relation,
                )
        {
            return false;
        }
        dense_absorb_terminal(&mut transcript, &proof.terminal_evaluations);
        transcript.digest() == proof.transcript_digest
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_source_tables(execution_tables: &[Vec<BlsDoryFr>]) -> Vec<Vec<BlsDoryFr>> {
        assert_eq!(
            execution_tables.len(),
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        );
        execution_tables[..2 * BLS_DORY_BLAKE3_MAIN_WIDTH].to_vec()
    }

    #[cfg(feature = "whir-prototype")]
    fn synthetic_dense_adjacency_tables(rows: usize) -> Vec<Vec<BlsDoryFr>> {
        assert!(rows.is_power_of_two());
        let local = (0..BLS_DORY_BLAKE3_MAIN_WIDTH)
            .map(|column| {
                (0..rows)
                    .map(|row| {
                        BlsDoryFr::from_u64(
                            1 + row as u64 * BLS_DORY_BLAKE3_MAIN_WIDTH as u64 + column as u64,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut tables = Vec::with_capacity(2 * BLS_DORY_BLAKE3_MAIN_WIDTH);
        tables.extend(local.iter().cloned());
        tables.extend(
            local
                .iter()
                .map(|table| table[1..].iter().chain(&table[..1]).copied().collect()),
        );
        tables
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_transcript(
        bridge: &BlsDoryOutputBridgeStatement,
        trace_rows: usize,
        source_commitments: &[BlsDoryGt],
    ) -> BlsDoryTranscript {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-row-adjacency-sumcheck");
        transcript.append_bytes(b"protocol-version", &1_u16.to_le_bytes());
        transcript.append_bytes(b"challenge-digest", &bridge.challenge_digest());
        transcript.append_bytes(
            b"activation-length",
            &(bridge.final_activation_len() as u64).to_le_bytes(),
        );
        transcript.append_bytes(b"activation-digest", &bridge.final_activation_digest());
        transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
        transcript.append_bytes(b"trace-rows", &(trace_rows as u64).to_le_bytes());
        transcript.append_bytes(
            b"main-width",
            &(BLS_DORY_BLAKE3_MAIN_WIDTH as u64).to_le_bytes(),
        );
        transcript.append_bytes(
            b"source-commitment-count",
            &(source_commitments.len() as u64).to_le_bytes(),
        );
        for commitment in source_commitments {
            transcript.append_group(b"packed-adjacency-source-commitment", commitment);
        }
        transcript
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_key(
        values: impl IntoIterator<Item = BlsDoryFr>,
        row_label: BlsDoryFr,
        compression: BlsDoryFr,
    ) -> BlsDoryFr {
        values
            .into_iter()
            .fold(row_label, |key, value| key * compression + value)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_relation(
        terminal: &[BlsDoryFr],
        row_index: BlsDoryFr,
        first_row: BlsDoryFr,
        equality: BlsDoryFr,
        relation: DenseAdjacencyRelation,
    ) -> BlsDoryFr {
        let next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
        let inverse_start = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        assert_eq!(terminal.len(), inverse_start + 2);
        let local_key = dense_adjacency_key(
            terminal[..next_start].iter().copied(),
            row_index - BlsDoryFr::from_u64(1) + relation.trace_rows * first_row,
            relation.compression,
        );
        let next_key = dense_adjacency_key(
            terminal[next_start..inverse_start].iter().copied(),
            row_index,
            relation.compression,
        );
        let local_inverse = terminal[inverse_start];
        let next_inverse = terminal[inverse_start + 1];
        let local_constraint =
            local_inverse * (relation.alpha - local_key) - BlsDoryFr::from_u64(1);
        let next_constraint = next_inverse * (relation.alpha - next_key) - BlsDoryFr::from_u64(1);
        equality
            * (relation.local_mixing[0] * local_constraint
                + relation.local_mixing[1] * next_constraint)
            + relation.rational_mixing * (next_inverse - local_inverse)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_inverse_tables(
        source_tables: &[Vec<BlsDoryFr>],
        compression: BlsDoryFr,
        alpha: BlsDoryFr,
    ) -> Option<[Vec<BlsDoryFr>; 2]> {
        if source_tables.len() != 2 * BLS_DORY_BLAKE3_MAIN_WIDTH || source_tables.is_empty() {
            return None;
        }
        let rows = source_tables[0].len();
        if !rows.is_power_of_two() || source_tables.iter().any(|table| table.len() != rows) {
            return None;
        }
        let mut local_inverse = Vec::with_capacity(rows);
        let mut next_inverse = Vec::with_capacity(rows);
        for row in 0..rows {
            let first = u64::from(row == 0);
            let local_label = row as u64 - u64::from(row != 0) + (rows as u64 - 1) * first;
            let local_key = dense_adjacency_key(
                source_tables[..BLS_DORY_BLAKE3_MAIN_WIDTH]
                    .iter()
                    .map(|table| table[row]),
                BlsDoryFr::from_u64(local_label),
                compression,
            );
            let next_key = dense_adjacency_key(
                source_tables[BLS_DORY_BLAKE3_MAIN_WIDTH..]
                    .iter()
                    .map(|table| table[row]),
                BlsDoryFr::from_u64(row as u64),
                compression,
            );
            local_inverse.push((alpha - local_key).inv()?);
            next_inverse.push((alpha - next_key).inv()?);
        }
        Some([local_inverse, next_inverse])
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_evaluate_adjacency_samples(values: &[BlsDoryFr], point: BlsDoryFr) -> BlsDoryFr {
        assert_eq!(values.len(), DENSE_ADJACENCY_SUMCHECK_DEGREE + 1);
        values
            .iter()
            .copied()
            .enumerate()
            .fold(BlsDoryFr::zero(), |result, (index, value)| {
                let mut numerator = BlsDoryFr::from_u64(1);
                let mut denominator = BlsDoryFr::from_u64(1);
                for other in 0..values.len() {
                    if other != index {
                        numerator = numerator * (point - BlsDoryFr::from_u64(other as u64));
                        denominator =
                            denominator * BlsDoryFr::from_i64(index as i64 - other as i64);
                    }
                }
                result + value * numerator * denominator.inv().unwrap()
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_row_index_evaluation(point: &[BlsDoryFr]) -> BlsDoryFr {
        point
            .iter()
            .enumerate()
            .fold(BlsDoryFr::zero(), |value, (variable, coordinate)| {
                value + BlsDoryFr::from_u64(1_u64 << variable) * *coordinate
            })
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_adjacency_sumcheck(
        mut source_tables: Vec<Vec<BlsDoryFr>>,
        bridge: &BlsDoryOutputBridgeStatement,
        source_commitments: &[BlsDoryGt],
        inverse_commitments: &[BlsDoryGt],
    ) -> Option<DenseAdjacencySumcheckProof> {
        let rows = source_tables.first()?.len();
        if source_tables.len() != 2 * BLS_DORY_BLAKE3_MAIN_WIDTH
            || !rows.is_power_of_two()
            || source_tables.iter().any(|table| table.len() != rows)
        {
            return None;
        }
        let variables = rows.ilog2() as usize;
        let mut transcript = dense_adjacency_transcript(bridge, rows, source_commitments);
        let compression = transcript.challenge_scalar(b"row-compression");
        let alpha = transcript.challenge_scalar(b"lookup-alpha");
        let inverses = dense_adjacency_inverse_tables(&source_tables, compression, alpha)?;
        source_tables.extend(inverses);
        transcript.append_bytes(
            b"inverse-commitment-count",
            &(inverse_commitments.len() as u64).to_le_bytes(),
        );
        for commitment in inverse_commitments {
            transcript.append_group(b"packed-adjacency-inverse-commitment", commitment);
        }
        let local_mixing = [
            transcript.challenge_scalar(b"local-mixing"),
            transcript.challenge_scalar(b"local-mixing"),
        ];
        let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
        let equality_point = dense_cell_point(&mut transcript, variables);
        let relation = DenseAdjacencyRelation {
            trace_rows: BlsDoryFr::from_u64(rows as u64),
            compression,
            alpha,
            local_mixing,
            rational_mixing,
        };
        let mut equality = dense_equality_table(&equality_point);
        let mut row_index = (0..rows)
            .map(|row| BlsDoryFr::from_u64(row as u64))
            .collect::<Vec<_>>();
        let mut first = vec![BlsDoryFr::zero(); rows];
        first[0] = BlsDoryFr::from_u64(1);
        let mut claim = BlsDoryFr::zero();
        let mut rounds = Vec::with_capacity(variables);
        for round_index in 0..variables {
            let pair_count = equality.len() / 2;
            let evaluations = (0..=DENSE_ADJACENCY_SUMCHECK_DEGREE)
                .map(|sample| {
                    let sample = BlsDoryFr::from_u64(sample as u64);
                    (0..pair_count).fold(BlsDoryFr::zero(), |sum, pair| {
                        let offset = 2 * pair;
                        let terminal = source_tables
                            .iter()
                            .map(|table| dense_interpolate(&table[offset..offset + 2], sample))
                            .collect::<Vec<_>>();
                        sum + dense_adjacency_relation(
                            &terminal,
                            dense_interpolate(&row_index[offset..offset + 2], sample),
                            dense_interpolate(&first[offset..offset + 2], sample),
                            dense_interpolate(&equality[offset..offset + 2], sample),
                            relation,
                        )
                    })
                })
                .collect::<Vec<_>>();
            if evaluations[0] + evaluations[1] != claim {
                return None;
            }
            dense_absorb_round(&mut transcript, round_index, &evaluations);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_adjacency_samples(&evaluations, challenge);
            for table in &mut source_tables {
                *table = dense_fold(table, challenge);
            }
            equality = dense_fold(&equality, challenge);
            row_index = dense_fold(&row_index, challenge);
            first = dense_fold(&first, challenge);
            rounds.push(evaluations);
        }
        let terminal_evaluations = source_tables
            .iter()
            .map(|table| table[0])
            .collect::<Vec<_>>();
        if claim
            != dense_adjacency_relation(
                &terminal_evaluations,
                row_index[0],
                first[0],
                equality[0],
                relation,
            )
        {
            return None;
        }
        dense_absorb_terminal(&mut transcript, &terminal_evaluations);
        Some(DenseAdjacencySumcheckProof {
            rounds,
            terminal_evaluations,
            transcript_digest: transcript.digest(),
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_adjacency_sumcheck(
        proof: &DenseAdjacencySumcheckProof,
        trace_rows: usize,
        bridge: &BlsDoryOutputBridgeStatement,
        source_commitments: &[BlsDoryGt],
        inverse_commitments: &[BlsDoryGt],
    ) -> bool {
        if !trace_rows.is_power_of_two()
            || proof.rounds.len() != trace_rows.ilog2() as usize
            || proof.terminal_evaluations.len() != BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
            || proof
                .rounds
                .iter()
                .any(|round| round.len() != DENSE_ADJACENCY_SUMCHECK_DEGREE + 1)
        {
            return false;
        }
        let variables = trace_rows.ilog2() as usize;
        let mut transcript = dense_adjacency_transcript(bridge, trace_rows, source_commitments);
        let compression = transcript.challenge_scalar(b"row-compression");
        let alpha = transcript.challenge_scalar(b"lookup-alpha");
        transcript.append_bytes(
            b"inverse-commitment-count",
            &(inverse_commitments.len() as u64).to_le_bytes(),
        );
        for commitment in inverse_commitments {
            transcript.append_group(b"packed-adjacency-inverse-commitment", commitment);
        }
        let local_mixing = [
            transcript.challenge_scalar(b"local-mixing"),
            transcript.challenge_scalar(b"local-mixing"),
        ];
        let rational_mixing = transcript.challenge_scalar(b"rational-mixing");
        let equality_point = dense_cell_point(&mut transcript, variables);
        let relation = DenseAdjacencyRelation {
            trace_rows: BlsDoryFr::from_u64(trace_rows as u64),
            compression,
            alpha,
            local_mixing,
            rational_mixing,
        };
        let mut claim = BlsDoryFr::zero();
        let mut sumcheck_point = Vec::with_capacity(variables);
        for (round_index, evaluations) in proof.rounds.iter().enumerate() {
            if evaluations[0] + evaluations[1] != claim {
                return false;
            }
            dense_absorb_round(&mut transcript, round_index, evaluations);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_adjacency_samples(evaluations, challenge);
            sumcheck_point.push(challenge);
        }
        let first = sumcheck_point
            .iter()
            .fold(BlsDoryFr::from_u64(1), |value, coordinate| {
                value * (BlsDoryFr::from_u64(1) - *coordinate)
            });
        let expected = dense_adjacency_relation(
            &proof.terminal_evaluations,
            dense_adjacency_row_index_evaluation(&sumcheck_point),
            first,
            dense_equality_evaluation(&equality_point, &sumcheck_point),
            relation,
        );
        if claim != expected {
            return false;
        }
        dense_absorb_terminal(&mut transcript, &proof.terminal_evaluations);
        transcript.digest() == proof.transcript_digest
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_replay_adjacency_point(
        proof: &DenseAdjacencySumcheckProof,
        trace_rows: usize,
        bridge: &BlsDoryOutputBridgeStatement,
        source_commitments: &[BlsDoryGt],
        inverse_commitments: &[BlsDoryGt],
    ) -> Option<Vec<BlsDoryFr>> {
        if !trace_rows.is_power_of_two()
            || proof.rounds.len() != trace_rows.ilog2() as usize
            || proof
                .rounds
                .iter()
                .any(|round| round.len() != DENSE_ADJACENCY_SUMCHECK_DEGREE + 1)
        {
            return None;
        }
        let mut transcript = dense_adjacency_transcript(bridge, trace_rows, source_commitments);
        transcript.challenge_scalar(b"row-compression");
        transcript.challenge_scalar(b"lookup-alpha");
        transcript.append_bytes(
            b"inverse-commitment-count",
            &(inverse_commitments.len() as u64).to_le_bytes(),
        );
        for commitment in inverse_commitments {
            transcript.append_group(b"packed-adjacency-inverse-commitment", commitment);
        }
        transcript.challenge_scalar(b"local-mixing");
        transcript.challenge_scalar(b"local-mixing");
        transcript.challenge_scalar(b"rational-mixing");
        dense_cell_point(&mut transcript, proof.rounds.len());
        let mut claim = BlsDoryFr::zero();
        let mut point = Vec::with_capacity(proof.rounds.len());
        for (round_index, round) in proof.rounds.iter().enumerate() {
            if round[0] + round[1] != claim {
                return None;
            }
            dense_absorb_round(&mut transcript, round_index, round);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_adjacency_samples(round, challenge);
            point.push(challenge);
        }
        Some(point)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_pack_adjacency_tables(
        tables: &[Vec<BlsDoryFr>],
        rows: usize,
        slots: usize,
    ) -> Option<Vec<BlsDoryFr>> {
        if tables.is_empty()
            || tables.len() > slots
            || tables.iter().any(|table| table.len() != rows)
        {
            return None;
        }
        let mut packed = Vec::with_capacity(rows.checked_mul(slots)?);
        for slot in 0..slots {
            if let Some(table) = tables.get(slot) {
                packed.extend_from_slice(table);
            } else {
                packed.resize(packed.len().checked_add(rows)?, BlsDoryFr::zero());
            }
        }
        Some(packed)
    }

    #[cfg(feature = "whir-prototype")]
    struct DensePackedTableRowSource<'a> {
        tables: &'a [Vec<BlsDoryFr>],
        trace_rows: usize,
        selector_slots: usize,
        reads: usize,
        fail_at: Option<usize>,
        short_at: Option<usize>,
    }

    #[cfg(feature = "whir-prototype")]
    impl<'a> DensePackedTableRowSource<'a> {
        fn new(tables: &'a [Vec<BlsDoryFr>], trace_rows: usize, selector_slots: usize) -> Self {
            Self {
                tables,
                trace_rows,
                selector_slots,
                reads: 0,
                fail_at: None,
                short_at: None,
            }
        }
    }

    #[cfg(feature = "whir-prototype")]
    impl BlsDoryRowSource for DensePackedTableRowSource<'_> {
        type Error = ();

        fn rows(&self) -> usize {
            self.selector_slots
        }

        fn columns(&self) -> usize {
            self.trace_rows
        }

        fn explicit_scalar_count(&self) -> usize {
            self.tables.len().saturating_mul(self.trace_rows)
        }

        fn read_row(
            &mut self,
            row_index: usize,
            output: &mut [BlsDoryFr],
        ) -> Result<usize, Self::Error> {
            if self.fail_at == Some(row_index) {
                return Err(());
            }
            let table = self.tables.get(row_index).ok_or(())?;
            if output.len() != self.trace_rows || table.len() != self.trace_rows {
                return Err(());
            }
            output.copy_from_slice(table);
            self.reads += 1;
            Ok(if self.short_at == Some(row_index) {
                output.len() - 1
            } else {
                output.len()
            })
        }
    }

    #[cfg(feature = "whir-prototype")]
    struct DensePackedSignedWordRowSource<'a> {
        tables: &'a [Vec<i64>],
        trace_rows: usize,
        selector_slots: usize,
        dictionary: [BlsDoryFr; 1],
    }

    #[cfg(feature = "whir-prototype")]
    impl<'a> DensePackedSignedWordRowSource<'a> {
        fn new(tables: &'a [Vec<i64>], trace_rows: usize, selector_slots: usize) -> Self {
            Self {
                tables,
                trace_rows,
                selector_slots,
                dictionary: [BlsDoryFr::zero()],
            }
        }
    }

    #[cfg(feature = "whir-prototype")]
    impl BlsDoryCompactRowSource for DensePackedSignedWordRowSource<'_> {
        type Error = ();

        fn rows(&self) -> usize {
            self.selector_slots
        }

        fn columns(&self) -> usize {
            self.trace_rows
        }

        fn explicit_scalar_count(&self) -> usize {
            self.tables.len().saturating_mul(self.trace_rows)
        }

        fn word_scalar_count(&self) -> usize {
            self.tables.len().saturating_mul(self.trace_rows)
        }

        fn word_group_len(&self) -> usize {
            self.trace_rows
        }

        fn signed_word_selectors(&self) -> u64 {
            u64::MAX
        }

        fn dictionary(&self) -> &[BlsDoryFr] {
            &self.dictionary
        }

        fn read_word_row(
            &mut self,
            row_index: usize,
            output: &mut [u64],
        ) -> Result<usize, Self::Error> {
            let table = self.tables.get(row_index).ok_or(())?;
            if output.len() != self.trace_rows || table.len() != self.trace_rows {
                return Err(());
            }
            for (word, value) in output.iter_mut().zip(table) {
                *word = u64::from_le_bytes(value.to_le_bytes());
            }
            Ok(output.len())
        }

        fn read_code_row(
            &mut self,
            _row_index: usize,
            _output: &mut [u8],
        ) -> Result<usize, Self::Error> {
            Err(())
        }
    }

    #[cfg(feature = "whir-prototype")]
    struct DensePackedCodeRowSource<'a> {
        tables: &'a [Vec<u8>],
        trace_rows: usize,
        selector_slots: usize,
        dictionary: Vec<BlsDoryFr>,
    }

    #[cfg(feature = "whir-prototype")]
    impl BlsDoryCompactRowSource for DensePackedCodeRowSource<'_> {
        type Error = ();

        fn rows(&self) -> usize {
            self.selector_slots
        }

        fn columns(&self) -> usize {
            self.trace_rows
        }

        fn explicit_scalar_count(&self) -> usize {
            self.tables.len().saturating_mul(self.trace_rows)
        }

        fn word_scalar_count(&self) -> usize {
            0
        }

        fn code_bits(&self) -> u8 {
            4
        }

        fn word_group_len(&self) -> usize {
            self.trace_rows
        }

        fn signed_word_selectors(&self) -> u64 {
            0
        }

        fn dictionary(&self) -> &[BlsDoryFr] {
            &self.dictionary
        }

        fn read_word_row(
            &mut self,
            _row_index: usize,
            _output: &mut [u64],
        ) -> Result<usize, Self::Error> {
            Err(())
        }

        fn read_code_row(
            &mut self,
            row_index: usize,
            output: &mut [u8],
        ) -> Result<usize, Self::Error> {
            let table = self.tables.get(row_index).ok_or(())?;
            if output.len() != self.trace_rows || table.len() != self.trace_rows {
                return Err(());
            }
            output.copy_from_slice(table);
            Ok(output.len())
        }
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_adjacency_opening_selector_points(
        sumcheck_digest: [u8; 32],
        batches: &[DenseAdjacencyOpeningBatch],
    ) -> (Vec<Vec<BlsDoryFr>>, [u8; 32]) {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-adjacency-opening-selectors");
        transcript.append_bytes(b"sumcheck-digest", &sumcheck_digest);
        transcript.append_bytes(b"batch-count", &(batches.len() as u64).to_le_bytes());
        let points = batches
            .iter()
            .enumerate()
            .map(|(batch_index, batch)| {
                transcript.append_bytes(b"batch-index", &(batch_index as u64).to_le_bytes());
                transcript.append_bytes(
                    b"terminal-start",
                    &(batch.terminal_start as u64).to_le_bytes(),
                );
                transcript.append_bytes(
                    b"terminal-count",
                    &(batch.terminal_count as u64).to_le_bytes(),
                );
                transcript.append_bytes(
                    b"selector-variables",
                    &(batch.selector_variables as u64).to_le_bytes(),
                );
                transcript.append_group(b"packed-adjacency-commitment", &batch.commitment);
                (0..batch.selector_variables)
                    .map(|selector| {
                        transcript
                            .append_bytes(b"selector-index", &(selector as u64).to_le_bytes());
                        transcript.challenge_scalar(b"opening-selector")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        (points, transcript.digest())
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_authenticated_adjacency(
        source_tables: Vec<Vec<BlsDoryFr>>,
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<DenseAuthenticatedAdjacencyProof, BlsDoryAggregateError> {
        const ROWS: usize = 1 << 4;
        const SELECTOR_VARIABLES: usize = 12;
        const SLOTS: usize = 1 << SELECTOR_VARIABLES;
        if source_tables.len() != 2 * BLS_DORY_BLAKE3_MAIN_WIDTH
            || source_tables.iter().any(|table| table.len() != ROWS)
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let source = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&source_tables, ROWS, SLOTS)
                .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?,
            8,
            8,
            setup,
        )?;
        let source_commitments = [source.commitment()];
        let mut challenge_transcript =
            dense_adjacency_transcript(bridge, ROWS, &source_commitments);
        let compression = challenge_transcript.challenge_scalar(b"row-compression");
        let alpha = challenge_transcript.challenge_scalar(b"lookup-alpha");
        let inverse_tables = dense_adjacency_inverse_tables(&source_tables, compression, alpha)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let inverse = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&inverse_tables, ROWS, SLOTS)
                .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?,
            8,
            8,
            setup,
        )?;
        let inverse_commitments = [inverse.commitment()];
        let sumcheck = prove_dense_adjacency_sumcheck(
            source_tables,
            bridge,
            &source_commitments,
            &inverse_commitments,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let sumcheck_point = dense_replay_adjacency_point(
            &sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let opening_batches = vec![
            DenseAdjacencyOpeningBatch {
                commitment: source_commitments[0],
                terminal_start: 0,
                terminal_count: 2 * BLS_DORY_BLAKE3_MAIN_WIDTH,
                selector_variables: SELECTOR_VARIABLES,
            },
            DenseAdjacencyOpeningBatch {
                commitment: inverse_commitments[0],
                terminal_start: 2 * BLS_DORY_BLAKE3_MAIN_WIDTH,
                terminal_count: 2,
                selector_variables: SELECTOR_VARIABLES,
            },
        ];
        let (selector_points, opening_binding) =
            dense_adjacency_opening_selector_points(sumcheck.transcript_digest, &opening_batches);
        let points = selector_points
            .iter()
            .map(|selector| dense_opening_point(&sumcheck_point, selector))
            .collect::<Vec<_>>();
        let openings = BlsDoryDeferredOpeningSet::new(vec![source, inverse], vec![0, 1], points)?;
        for ((claim, selector), batch) in openings
            .claims()
            .iter()
            .zip(&selector_points)
            .zip(&opening_batches)
        {
            let terminal_end = batch.terminal_start + batch.terminal_count;
            let expected = dense_terminal_selector_evaluation(
                &sumcheck.terminal_evaluations[batch.terminal_start..terminal_end],
                selector,
            );
            if claim.evaluation != expected {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
        }
        let (_, opening_proof) =
            prove_bls_dory_deferred_opening_sets(&opening_binding, &[&openings], setup)?;
        Ok(DenseAuthenticatedAdjacencyProof {
            sumcheck,
            opening_batches,
            opening_proof,
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_authenticated_adjacency(
        proof: &DenseAuthenticatedAdjacencyProof,
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> bool {
        const ROWS: usize = 1 << 4;
        const SELECTOR_VARIABLES: usize = 12;
        let expected = [
            (0, 2 * BLS_DORY_BLAKE3_MAIN_WIDTH),
            (2 * BLS_DORY_BLAKE3_MAIN_WIDTH, 2),
        ];
        if proof.opening_batches.len() != expected.len()
            || proof.opening_proof.is_empty()
            || proof
                .opening_batches
                .iter()
                .zip(expected)
                .any(|(batch, (start, count))| {
                    batch.terminal_start != start
                        || batch.terminal_count != count
                        || batch.selector_variables != SELECTOR_VARIABLES
                })
        {
            return false;
        }
        let source_commitments = [proof.opening_batches[0].commitment];
        let inverse_commitments = [proof.opening_batches[1].commitment];
        if !verify_dense_adjacency_sumcheck(
            &proof.sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        ) {
            return false;
        }
        let Some(sumcheck_point) = dense_replay_adjacency_point(
            &proof.sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        ) else {
            return false;
        };
        let (selector_points, opening_binding) = dense_adjacency_opening_selector_points(
            proof.sumcheck.transcript_digest,
            &proof.opening_batches,
        );
        let claims = proof
            .opening_batches
            .iter()
            .zip(&selector_points)
            .map(|(batch, selector)| {
                let terminal_end = batch.terminal_start + batch.terminal_count;
                BlsDoryOpeningClaim {
                    commitment: batch.commitment,
                    point: dense_opening_point(&sumcheck_point, selector),
                    evaluation: dense_terminal_selector_evaluation(
                        &proof.sumcheck.terminal_evaluations[batch.terminal_start..terminal_end],
                        selector,
                    ),
                }
            })
            .collect::<Vec<_>>();
        verify_bls_dory_openings(&opening_binding, &claims, &proof.opening_proof, setup).is_ok()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_replay_sumcheck_point(
        proof: &DenseExecutionSumcheckProof,
        bridge: &BlsDoryOutputBridgeStatement,
        commitments: &[BlsDoryGt],
    ) -> Option<Vec<BlsDoryFr>> {
        let variables = proof.rounds.len();
        if variables == 0
            || proof
                .rounds
                .iter()
                .any(|round| round.len() != DENSE_EXECUTION_SUMCHECK_DEGREE + 1)
        {
            return None;
        }
        let mut transcript = dense_execution_transcript(bridge, commitments);
        dense_constraint_powers(&mut transcript);
        dense_cell_point(&mut transcript, variables);
        let mut claim = BlsDoryFr::zero();
        let mut point = Vec::with_capacity(variables);
        for (round_index, round) in proof.rounds.iter().enumerate() {
            if round[0] + round[1] != claim {
                return None;
            }
            dense_absorb_round(&mut transcript, round_index, round);
            let challenge = transcript.challenge_scalar(b"sumcheck-challenge");
            claim = dense_evaluate_samples(round, challenge);
            point.push(challenge);
        }
        Some(point)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_opening_point(
        sumcheck_point: &[BlsDoryFr],
        selector_point: &[BlsDoryFr],
    ) -> Vec<BlsDoryFr> {
        let mut point = Vec::with_capacity(16);
        point.extend_from_slice(sumcheck_point);
        point.extend_from_slice(selector_point);
        assert_eq!(point.len(), 16);
        point
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_terminal_selector_evaluation(
        terminal: &[BlsDoryFr],
        selector_point: &[BlsDoryFr],
    ) -> BlsDoryFr {
        assert!(terminal.len() <= 1usize << selector_point.len());
        let mut table = terminal.to_vec();
        table.resize(1usize << selector_point.len(), BlsDoryFr::zero());
        for coordinate in selector_point {
            table = dense_fold(&table, *coordinate);
        }
        assert_eq!(table.len(), 1);
        table[0]
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_opening_selector_points(
        sumcheck_digest: [u8; 32],
        batches: &[DenseExecutionOpeningBatch],
    ) -> (Vec<Vec<BlsDoryFr>>, [u8; 32]) {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-execution-opening-selectors");
        transcript.append_bytes(b"sumcheck-digest", &sumcheck_digest);
        transcript.append_bytes(b"batch-count", &(batches.len() as u64).to_le_bytes());
        let points = batches
            .iter()
            .enumerate()
            .map(|(batch_index, batch)| {
                transcript.append_bytes(b"batch-index", &(batch_index as u64).to_le_bytes());
                transcript.append_bytes(
                    b"terminal-count",
                    &(batch.terminal_count as u64).to_le_bytes(),
                );
                transcript.append_group(b"packed-execution-commitment", &batch.commitment);
                (0..8)
                    .map(|selector| {
                        transcript
                            .append_bytes(b"selector-index", &(selector as u64).to_le_bytes());
                        transcript.challenge_scalar(b"opening-selector")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        (points, transcript.digest())
    }

    #[cfg(feature = "whir-prototype")]
    fn commit_dense_execution_batches(
        tables: &[Vec<BlsDoryFr>],
        setup: &DeterministicBlsDorySetup,
    ) -> Result<
        (
            Vec<BlsDoryCommittedPolynomial>,
            Vec<DenseExecutionOpeningBatch>,
        ),
        BlsDoryAggregateError,
    > {
        const ROWS: usize = 1 << 8;
        const PACKED_SLOTS: usize = 1 << 8;
        if tables.len() != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
            || tables.iter().any(|table| table.len() != ROWS)
        {
            return Err(BlsDoryAggregateError::InvalidCoefficientCount);
        }
        let mut committed_batches = Vec::new();
        let mut opening_batches = Vec::new();
        let main_terminals = 2 * BLS_DORY_BLAKE3_MAIN_WIDTH;
        for group in [&tables[..main_terminals], &tables[main_terminals..]] {
            for batch in group.chunks(PACKED_SLOTS) {
                let packed = dense_pack_adjacency_tables(batch, ROWS, PACKED_SLOTS)
                    .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?;
                let committed = commit_bls_dory_polynomial(packed, 8, 8, setup)?;
                opening_batches.push(DenseExecutionOpeningBatch {
                    commitment: committed.commitment(),
                    terminal_count: batch.len(),
                });
                committed_batches.push(committed);
            }
        }
        Ok((committed_batches, opening_batches))
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_authenticated_execution(
        tables: Vec<Vec<BlsDoryFr>>,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<DenseAuthenticatedExecutionProof, BlsDoryAggregateError> {
        let (committed_batches, opening_batches) = commit_dense_execution_batches(&tables, setup)?;
        let commitments = opening_batches
            .iter()
            .map(|batch| batch.commitment)
            .collect::<Vec<_>>();
        let sumcheck =
            prove_dense_execution_sumcheck(tables, air, public, constraints, bridge, &commitments);
        let sumcheck_point = dense_replay_sumcheck_point(&sumcheck, bridge, &commitments)
            .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let (selector_points, opening_binding) =
            dense_opening_selector_points(sumcheck.transcript_digest, &opening_batches);
        let points = selector_points
            .iter()
            .map(|selector| dense_opening_point(&sumcheck_point, selector))
            .collect::<Vec<_>>();
        let openings = BlsDoryDeferredOpeningSet::new(
            committed_batches,
            (0..opening_batches.len()).collect(),
            points,
        )?;
        let mut terminal_start = 0usize;
        for ((claim, selector), batch) in openings
            .claims()
            .iter()
            .zip(&selector_points)
            .zip(&opening_batches)
        {
            let terminal_end = terminal_start + batch.terminal_count;
            let expected = dense_terminal_selector_evaluation(
                &sumcheck.terminal_evaluations[terminal_start..terminal_end],
                selector,
            );
            if claim.evaluation != expected {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
            terminal_start = terminal_end;
        }
        let (_, opening_proof) =
            prove_bls_dory_deferred_opening_sets(&opening_binding, &[&openings], setup)?;
        Ok(DenseAuthenticatedExecutionProof {
            sumcheck,
            opening_batches,
            opening_proof,
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_authenticated_execution(
        proof: &DenseAuthenticatedExecutionProof,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> bool {
        let expected_counts = [256, 256, 66, 168];
        if proof.opening_batches.len() != expected_counts.len() || proof.opening_proof.is_empty() {
            return false;
        }
        let commitments = proof
            .opening_batches
            .iter()
            .map(|batch| batch.commitment)
            .collect::<Vec<_>>();
        if !verify_dense_execution_sumcheck(
            &proof.sumcheck,
            air,
            public,
            constraints,
            bridge,
            &commitments,
        ) {
            return false;
        }
        let Some(sumcheck_point) =
            dense_replay_sumcheck_point(&proof.sumcheck, bridge, &commitments)
        else {
            return false;
        };
        let (selector_points, opening_binding) =
            dense_opening_selector_points(proof.sumcheck.transcript_digest, &proof.opening_batches);
        let mut terminal_start = 0usize;
        let mut claims = Vec::with_capacity(expected_counts.len());
        for (((batch, selector), expected_count), batch_index) in proof
            .opening_batches
            .iter()
            .zip(&selector_points)
            .zip(expected_counts)
            .zip(0..)
        {
            if batch.terminal_count != expected_count {
                return false;
            }
            let terminal_end = terminal_start + expected_count;
            claims.push(BlsDoryOpeningClaim {
                commitment: batch.commitment,
                point: dense_opening_point(&sumcheck_point, selector),
                evaluation: dense_terminal_selector_evaluation(
                    &proof.sumcheck.terminal_evaluations[terminal_start..terminal_end],
                    selector,
                ),
            });
            terminal_start = terminal_end;
            if batch_index + 1 == expected_counts.len()
                && terminal_start != BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
            {
                return false;
            }
        }
        verify_bls_dory_openings(&opening_binding, &claims, &proof.opening_proof, setup).is_ok()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_composed_adjacency_batches(
        execution_batches: &[DenseExecutionOpeningBatch],
        inverse_commitment: BlsDoryGt,
    ) -> Option<Vec<DenseAdjacencyOpeningBatch>> {
        let source_counts = [256, 256, 66];
        if execution_batches.len() != 4
            || execution_batches
                .iter()
                .zip([256, 256, 66, 168])
                .any(|(batch, count)| batch.terminal_count != count)
        {
            return None;
        }
        let mut terminal_start = 0usize;
        let mut batches = execution_batches[..3]
            .iter()
            .zip(source_counts)
            .map(|(batch, count)| {
                let opening = DenseAdjacencyOpeningBatch {
                    commitment: batch.commitment,
                    terminal_start,
                    terminal_count: count,
                    selector_variables: 8,
                };
                terminal_start += count;
                opening
            })
            .collect::<Vec<_>>();
        batches.push(DenseAdjacencyOpeningBatch {
            commitment: inverse_commitment,
            terminal_start,
            terminal_count: 2,
            selector_variables: 8,
        });
        Some(batches)
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_composed_opening_binding(
        bridge: &BlsDoryOutputBridgeStatement,
        execution_digest: [u8; 32],
        adjacency_digest: [u8; 32],
        execution_selector_binding: [u8; 32],
        adjacency_selector_binding: [u8; 32],
        execution_batches: &[DenseExecutionOpeningBatch],
        inverse_commitment: BlsDoryGt,
    ) -> [u8; 32] {
        let mut transcript = BlsDoryTranscript::new(b"blake3-native-composed-dory-opening");
        transcript.append_bytes(b"dory-binding", &bridge.transcript_binding());
        transcript.append_bytes(b"execution-sumcheck", &execution_digest);
        transcript.append_bytes(b"adjacency-sumcheck", &adjacency_digest);
        transcript.append_bytes(b"execution-selectors", &execution_selector_binding);
        transcript.append_bytes(b"adjacency-selectors", &adjacency_selector_binding);
        transcript.append_bytes(
            b"execution-batch-count",
            &(execution_batches.len() as u64).to_le_bytes(),
        );
        for batch in execution_batches {
            transcript.append_bytes(
                b"execution-terminal-count",
                &(batch.terminal_count as u64).to_le_bytes(),
            );
            transcript.append_group(b"execution-commitment", &batch.commitment);
        }
        transcript.append_group(b"adjacency-inverse-commitment", &inverse_commitment);
        transcript.digest()
    }

    #[cfg(feature = "whir-prototype")]
    fn prove_dense_authenticated_blake3(
        tables: Vec<Vec<BlsDoryFr>>,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> Result<DenseAuthenticatedBlake3Proof, BlsDoryAggregateError> {
        const ROWS: usize = 1 << 8;
        const SLOTS: usize = 1 << 8;
        let adjacency_tables = dense_adjacency_source_tables(&tables);
        let (mut committed_batches, execution_batches) =
            commit_dense_execution_batches(&tables, setup)?;
        let execution_commitments = execution_batches
            .iter()
            .map(|batch| batch.commitment)
            .collect::<Vec<_>>();
        let execution_sumcheck = prove_dense_execution_sumcheck(
            tables,
            air,
            public,
            constraints,
            bridge,
            &execution_commitments,
        );

        let source_commitments = execution_commitments[..3].to_vec();
        let mut challenge_transcript =
            dense_adjacency_transcript(bridge, ROWS, &source_commitments);
        let compression = challenge_transcript.challenge_scalar(b"row-compression");
        let alpha = challenge_transcript.challenge_scalar(b"lookup-alpha");
        let inverse_tables = dense_adjacency_inverse_tables(&adjacency_tables, compression, alpha)
            .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let inverse = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&inverse_tables, ROWS, SLOTS)
                .ok_or(BlsDoryAggregateError::InvalidCoefficientCount)?,
            8,
            8,
            setup,
        )?;
        let inverse_commitment = inverse.commitment();
        let inverse_commitments = [inverse_commitment];
        let adjacency_sumcheck = prove_dense_adjacency_sumcheck(
            adjacency_tables,
            bridge,
            &source_commitments,
            &inverse_commitments,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;

        let execution_point =
            dense_replay_sumcheck_point(&execution_sumcheck, bridge, &execution_commitments)
                .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let adjacency_point = dense_replay_adjacency_point(
            &adjacency_sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        )
        .ok_or(BlsDoryAggregateError::SumcheckFailed)?;
        let adjacency_batches =
            dense_composed_adjacency_batches(&execution_batches, inverse_commitment)
                .ok_or(BlsDoryAggregateError::InvalidProofShape)?;
        let (execution_selectors, execution_selector_binding) =
            dense_opening_selector_points(execution_sumcheck.transcript_digest, &execution_batches);
        let (adjacency_selectors, adjacency_selector_binding) =
            dense_adjacency_opening_selector_points(
                adjacency_sumcheck.transcript_digest,
                &adjacency_batches,
            );
        let mut points = execution_selectors
            .iter()
            .map(|selector| dense_opening_point(&execution_point, selector))
            .collect::<Vec<_>>();
        points.extend(
            adjacency_selectors
                .iter()
                .map(|selector| dense_opening_point(&adjacency_point, selector)),
        );
        committed_batches.push(inverse);
        let mut polynomial_indices = (0..execution_batches.len()).collect::<Vec<_>>();
        polynomial_indices.extend([0, 1, 2, 4]);
        let openings =
            BlsDoryDeferredOpeningSet::new(committed_batches, polynomial_indices, points)?;
        let mut opening_index = 0usize;
        let mut terminal_start = 0usize;
        for (batch, selector) in execution_batches.iter().zip(&execution_selectors) {
            let terminal_end = terminal_start + batch.terminal_count;
            let expected = dense_terminal_selector_evaluation(
                &execution_sumcheck.terminal_evaluations[terminal_start..terminal_end],
                selector,
            );
            if openings.claims()[opening_index].evaluation != expected {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
            terminal_start = terminal_end;
            opening_index += 1;
        }
        for (batch, selector) in adjacency_batches.iter().zip(&adjacency_selectors) {
            let terminal_end = batch.terminal_start + batch.terminal_count;
            let expected = dense_terminal_selector_evaluation(
                &adjacency_sumcheck.terminal_evaluations[batch.terminal_start..terminal_end],
                selector,
            );
            if openings.claims()[opening_index].evaluation != expected {
                return Err(BlsDoryAggregateError::InvalidProofShape);
            }
            opening_index += 1;
        }
        let opening_binding = dense_composed_opening_binding(
            bridge,
            execution_sumcheck.transcript_digest,
            adjacency_sumcheck.transcript_digest,
            execution_selector_binding,
            adjacency_selector_binding,
            &execution_batches,
            inverse_commitment,
        );
        let (_, opening_proof) =
            prove_bls_dory_deferred_opening_sets(&opening_binding, &[&openings], setup)?;
        Ok(DenseAuthenticatedBlake3Proof {
            execution_sumcheck,
            adjacency_sumcheck,
            execution_batches,
            inverse_commitment,
            opening_proof,
        })
    }

    #[cfg(feature = "whir-prototype")]
    fn verify_dense_authenticated_blake3(
        proof: &DenseAuthenticatedBlake3Proof,
        air: &NarrowBlake3Air,
        public: &[BlsDoryFr],
        constraints: &[BlsDoryBlake3ConstraintExpr],
        bridge: &BlsDoryOutputBridgeStatement,
        setup: &DeterministicBlsDorySetup,
    ) -> bool {
        const ROWS: usize = 1 << 8;
        if proof.opening_proof.is_empty()
            || proof.execution_batches.len() != 4
            || proof
                .execution_batches
                .iter()
                .zip([256, 256, 66, 168])
                .any(|(batch, count)| batch.terminal_count != count)
        {
            return false;
        }
        let execution_commitments = proof
            .execution_batches
            .iter()
            .map(|batch| batch.commitment)
            .collect::<Vec<_>>();
        let source_commitments = execution_commitments[..3].to_vec();
        let inverse_commitments = [proof.inverse_commitment];
        if !verify_dense_execution_sumcheck(
            &proof.execution_sumcheck,
            air,
            public,
            constraints,
            bridge,
            &execution_commitments,
        ) || !verify_dense_adjacency_sumcheck(
            &proof.adjacency_sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        ) {
            return false;
        }
        let Some(execution_point) =
            dense_replay_sumcheck_point(&proof.execution_sumcheck, bridge, &execution_commitments)
        else {
            return false;
        };
        let Some(adjacency_point) = dense_replay_adjacency_point(
            &proof.adjacency_sumcheck,
            ROWS,
            bridge,
            &source_commitments,
            &inverse_commitments,
        ) else {
            return false;
        };
        let Some(adjacency_batches) =
            dense_composed_adjacency_batches(&proof.execution_batches, proof.inverse_commitment)
        else {
            return false;
        };
        let (execution_selectors, execution_selector_binding) = dense_opening_selector_points(
            proof.execution_sumcheck.transcript_digest,
            &proof.execution_batches,
        );
        let (adjacency_selectors, adjacency_selector_binding) =
            dense_adjacency_opening_selector_points(
                proof.adjacency_sumcheck.transcript_digest,
                &adjacency_batches,
            );
        let mut claims = Vec::with_capacity(8);
        let mut terminal_start = 0usize;
        for (batch, selector) in proof.execution_batches.iter().zip(&execution_selectors) {
            let terminal_end = terminal_start + batch.terminal_count;
            claims.push(BlsDoryOpeningClaim {
                commitment: batch.commitment,
                point: dense_opening_point(&execution_point, selector),
                evaluation: dense_terminal_selector_evaluation(
                    &proof.execution_sumcheck.terminal_evaluations[terminal_start..terminal_end],
                    selector,
                ),
            });
            terminal_start = terminal_end;
        }
        for (batch, selector) in adjacency_batches.iter().zip(&adjacency_selectors) {
            let terminal_end = batch.terminal_start + batch.terminal_count;
            claims.push(BlsDoryOpeningClaim {
                commitment: batch.commitment,
                point: dense_opening_point(&adjacency_point, selector),
                evaluation: dense_terminal_selector_evaluation(
                    &proof.adjacency_sumcheck.terminal_evaluations
                        [batch.terminal_start..terminal_end],
                    selector,
                ),
            });
        }
        let opening_binding = dense_composed_opening_binding(
            bridge,
            proof.execution_sumcheck.transcript_digest,
            proof.adjacency_sumcheck.transcript_digest,
            execution_selector_binding,
            adjacency_selector_binding,
            &proof.execution_batches,
            proof.inverse_commitment,
        );
        verify_bls_dory_openings(&opening_binding, &claims, &proof.opening_proof, setup).is_ok()
    }

    #[cfg(feature = "whir-prototype")]
    fn dense_blake3_fixture() -> DenseBlake3Fixture {
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
        let signed_activation = activation
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
                crate::structured_sumcheck::evaluate_mle(&signed_activation, &native_point),
            ),
        };
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            challenge_digest,
            witness.digest,
            &activation,
            [0x51; 32],
            [2_u64, 3, 5, 7, 11]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let main = generate_main_trace(&air, &statement, &witness);
        let old_main_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { main.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let accumulators = native_accumulator_trace(&air, &old_main_rows, &bridge);
        let native_rows = old_main_rows
            .iter()
            .zip(&accumulators)
            .map(|(row, accumulator)| native_main_row(row, *accumulator))
            .collect::<Vec<_>>();
        let preprocessed = air.preprocessed_trace().unwrap();
        let preprocessed_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { preprocessed.row_unchecked(row) }))
            .collect::<Vec<_>>();
        DenseBlake3Fixture {
            tables: dense_execution_tables(&native_rows, &preprocessed_rows),
            public: bls_values(public_values(&statement).unwrap()),
            constraints: bls_dory_native_blake3_constraint_ir(activation.len()).unwrap(),
            bridge,
            air,
        }
    }

    #[test]
    fn native_blake3_projection_is_bounded_but_fail_closed() {
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES, 524_288);
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS, 1_048_576);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS, 746);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS, 1);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS, 1_299);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES, 11);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES, 10);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES, 31);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_DORY_NU, 11);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_DORY_SIGMA, 20);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS, 580);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS, 2);
        assert_eq!(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS, 131);
        assert_eq!(BLS_DORY_BLAKE3_EXECUTION_PROOF_BYTES, 36_020);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_PROOF_BYTES, 21_748);
        assert_eq!(
            crate::dory_bls12_381_layout::projected_shared_production_proof_bytes().unwrap(),
            133_409
        );
        assert_eq!(BLS_DORY_BLAKE3_PROJECTED_V3_BYTES, 191_185);
        assert_eq!(MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES, 261_947);
        assert_eq!(BLS_DORY_BLAKE3_PROJECTED_HEADROOM_BYTES, 70_762);
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_BLOCKERS.len(), 4);
    }

    #[test]
    fn composed_blake3_soundness_report_pins_every_algebraic_term() {
        let report = projected_bls_dory_blake3_soundness_report().unwrap();
        let expected = [
            ("BLAKE3 execution constraint mixing", 1_298),
            ("BLAKE3 execution local equality point", 20),
            ("BLAKE3 execution sumcheck", 340),
            ("BLAKE3 execution source selector batching", 11),
            ("BLAKE3 adjacency row compression", 303_038_464),
            ("BLAKE3 adjacency lookup-alpha rational identity", 2_097_151),
            ("BLAKE3 adjacency local relation mixing", 1),
            ("BLAKE3 adjacency global relation mixing", 1),
            ("BLAKE3 adjacency local equality point", 20),
            ("BLAKE3 adjacency sumcheck", 60),
            ("BLAKE3 adjacency source selector batching", 10),
            ("BLAKE3 adjacency inverse selector batching", 10),
        ];
        assert_eq!(report.blake3_terms.len(), expected.len());
        for (term, (label, numerator)) in report.blake3_terms.iter().zip(expected) {
            assert_eq!(term.label, label);
            assert_eq!(term.instances, 1);
            assert_eq!(term.numerator_upper_bound_per_instance, numerator);
        }
        assert_eq!(
            report.shared_algebraic_numerator_upper_bound,
            19_781_388_263
        );
        assert_eq!(report.blake3_algebraic_numerator_upper_bound, 305_137_386);
        assert_eq!(
            report.composed_algebraic_numerator_upper_bound,
            20_086_525_649
        );
        assert_eq!(report.nonzero_challenge_space_lower_bound_bits, 254);
        assert_eq!(
            blake3_ceil_log2(report.composed_algebraic_numerator_upper_bound),
            35
        );
        assert_eq!(report.algebraic_soundness_bits, 219);
        assert_eq!(report.required_algebraic_soundness_bits, 128);
        assert_eq!(report.grinding_headroom_bits, 91);
        assert_eq!(report.composed_opening_claims, 131);
        assert_eq!(report.proposed_maximum_opening_claims, 256);
        assert!(!report.independently_reviewed);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn production_air_translates_to_bounded_integer_constraints() {
        let constraints =
            bls_dory_blake3_constraint_ir(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES).unwrap();
        assert_eq!(constraints.len(), 1_305);
        let maximum = constraints.iter().map(maximum_abs_constant).max().unwrap();
        assert_eq!(maximum, 1_u64 << 33);
        let native =
            bls_dory_native_blake3_constraint_ir(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES)
                .unwrap();
        assert_eq!(native.len() + 3, BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS);
        assert!(
            native
                .iter()
                .all(|constraint| !uses_removed_native_input(constraint))
        );
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

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn native_bls_accumulator_replaces_three_goldilocks_limbs() {
        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let challenge_digest = [0x42; 32];
        let witness = build_tree_witness(OUTPUT_CONTEXT, challenge_digest, &activation).unwrap();
        let goldilocks_point = (0..activation.len().ilog2())
            .map(|index| ExtensionElement {
                limbs: [
                    u64::from(index) + 2,
                    u64::from(index) + 3,
                    u64::from(index) + 4,
                ],
            })
            .collect::<Vec<_>>();
        let native_point = goldilocks_point
            .iter()
            .copied()
            .map(ExtensionElement::to_field)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let signed_activation = activation
            .iter()
            .map(|value| {
                crate::structured_sumcheck::ExtensionField::from_signed(i64::from(*value) - 125)
            })
            .collect::<Vec<_>>();
        let statement = StructuredBlake3Statement {
            challenge_digest,
            final_activation_len: activation.len(),
            final_activation_digest: witness.digest,
            final_activation_point: goldilocks_point,
            final_activation_evaluation: ExtensionElement::from_field(
                crate::structured_sumcheck::evaluate_mle(&signed_activation, &native_point),
            ),
        };
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            challenge_digest,
            witness.digest,
            &activation,
            [0x51; 32],
            [2_u64, 3, 5, 7, 11]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        bridge.validate_activation(&activation).unwrap();

        let air = NarrowBlake3Air::new(&statement).unwrap();
        let main = generate_main_trace(&air, &statement, &witness);
        let preprocessed = air.preprocessed_trace().unwrap();
        let public = bls_values(public_values(&statement).unwrap());
        let old_main_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { main.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let accumulators = native_accumulator_trace(&air, &old_main_rows, &bridge);
        assert_eq!(TEST_MAIN_WIDTH, 291);
        assert_eq!(BLS_DORY_BLAKE3_MAIN_WIDTH, 289);
        assert_eq!(accumulators.last(), Some(&bridge.raw_byte_evaluation()));

        let original_constraints = bls_dory_blake3_constraint_ir(activation.len()).unwrap();
        assert_eq!(
            original_constraints
                .iter()
                .filter(|constraint| uses_old_evaluation_constraint(constraint))
                .count(),
            9
        );
        let constraints = bls_dory_native_blake3_constraint_ir(activation.len()).unwrap();
        assert_eq!(constraints.len(), 1_296);
        assert!(
            constraints
                .iter()
                .all(|constraint| !uses_removed_native_input(constraint))
        );

        let native_rows = old_main_rows
            .iter()
            .zip(&accumulators)
            .map(|(row, accumulator)| native_main_row(row, *accumulator))
            .collect::<Vec<_>>();
        for row in 0..air.trace_rows() {
            let next_row = (row + 1) % air.trace_rows();
            let preprocessed_local = bls_values(unsafe { preprocessed.row_unchecked(row) });
            let preprocessed_next = bls_values(unsafe { preprocessed.row_unchecked(next_row) });
            let first_row = BlsDoryFr::from_u64(u64::from(row == 0));
            let last_row = BlsDoryFr::from_u64(u64::from(row + 1 == air.trace_rows()));
            let transition = BlsDoryFr::from_u64(u64::from(row + 1 != air.trace_rows()));
            let values = BlsDoryBlake3Evaluation {
                main_local: &native_rows[row],
                main_next: &native_rows[next_row],
                preprocessed_local: &preprocessed_local,
                preprocessed_next: &preprocessed_next,
                public: &public,
                periodic: &[],
                first_row,
                last_row,
                transition,
            };
            for (constraint_index, constraint) in constraints.iter().enumerate() {
                assert_eq!(
                    constraint.evaluate(&values),
                    BlsDoryFr::zero(),
                    "native constraint {constraint_index} failed at row {row}"
                );
            }
            assert_eq!(
                native_evaluation_residuals(
                    &BlsDoryNativeEvaluationRow {
                        main_local: &native_rows[row],
                        main_next: &native_rows[next_row],
                        first_row,
                        last_row,
                        transition,
                    },
                    air.activation_group_index_at_row(row),
                    bridge.cell_point(),
                    bridge.raw_byte_evaluation(),
                ),
                [BlsDoryFr::zero(); 3],
                "native evaluation relation failed at row {row}"
            );
        }

        let mut changed_first = native_rows[0].clone();
        changed_first[TEST_EVALUATION_ACCUMULATOR_START] = BlsDoryFr::from_u64(1);
        assert_ne!(
            native_evaluation_residuals(
                &BlsDoryNativeEvaluationRow {
                    main_local: &changed_first,
                    main_next: &native_rows[1],
                    first_row: BlsDoryFr::from_u64(1),
                    last_row: BlsDoryFr::zero(),
                    transition: BlsDoryFr::from_u64(1),
                },
                air.activation_group_index_at_row(0),
                bridge.cell_point(),
                bridge.raw_byte_evaluation(),
            ),
            [BlsDoryFr::zero(); 3]
        );

        let activation_row = (0..air.trace_rows())
            .find(|row| air.activation_group_index_at_row(*row).is_some())
            .unwrap();
        let mut changed_byte = native_rows[activation_row].clone();
        changed_byte[TEST_ORIGINAL_NIBBLES_START] =
            changed_byte[TEST_ORIGINAL_NIBBLES_START] + BlsDoryFr::from_u64(1);
        assert_ne!(
            native_evaluation_residuals(
                &BlsDoryNativeEvaluationRow {
                    main_local: &changed_byte,
                    main_next: &native_rows[activation_row + 1],
                    first_row: BlsDoryFr::zero(),
                    last_row: BlsDoryFr::zero(),
                    transition: BlsDoryFr::from_u64(1),
                },
                air.activation_group_index_at_row(activation_row),
                bridge.cell_point(),
                bridge.raw_byte_evaluation(),
            ),
            [BlsDoryFr::zero(); 3]
        );

        let mut changed_point = bridge.cell_point().to_vec();
        changed_point[0] = changed_point[0] + BlsDoryFr::from_u64(1);
        let point_mutation_rejected = (0..air.trace_rows()).any(|row| {
            let next_row = (row + 1) % air.trace_rows();
            native_evaluation_residuals(
                &BlsDoryNativeEvaluationRow {
                    main_local: &native_rows[row],
                    main_next: &native_rows[next_row],
                    first_row: BlsDoryFr::from_u64(u64::from(row == 0)),
                    last_row: BlsDoryFr::from_u64(u64::from(row + 1 == air.trace_rows())),
                    transition: BlsDoryFr::from_u64(u64::from(row + 1 != air.trace_rows())),
                },
                air.activation_group_index_at_row(row),
                &changed_point,
                bridge.raw_byte_evaluation(),
            ) != [BlsDoryFr::zero(); 3]
        });
        assert!(point_mutation_rejected);

        let last_row = air.trace_rows() - 1;
        assert_ne!(
            native_evaluation_residuals(
                &BlsDoryNativeEvaluationRow {
                    main_local: &native_rows[last_row],
                    main_next: &native_rows[0],
                    first_row: BlsDoryFr::zero(),
                    last_row: BlsDoryFr::from_u64(1),
                    transition: BlsDoryFr::zero(),
                },
                air.activation_group_index_at_row(last_row),
                bridge.cell_point(),
                bridge.raw_byte_evaluation() + BlsDoryFr::from_u64(1),
            ),
            [BlsDoryFr::zero(); 3]
        );

        let preprocessed_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { preprocessed.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let tables = dense_execution_tables(&native_rows, &preprocessed_rows);
        let proof = prove_dense_execution_sumcheck(
            tables.clone(),
            &air,
            &public,
            &constraints,
            &bridge,
            &[],
        );
        assert_eq!(proof.rounds.len(), 8);
        assert!(
            proof
                .rounds
                .iter()
                .all(|round| round.len() == DENSE_EXECUTION_SUMCHECK_DEGREE + 1)
        );
        assert_eq!(
            proof.terminal_evaluations.len(),
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        );
        assert!(verify_dense_execution_sumcheck(
            &proof,
            &air,
            &public,
            &constraints,
            &bridge,
            &[],
        ));

        let mut changed_round = proof.clone();
        changed_round.rounds[0][0] = changed_round.rounds[0][0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_execution_sumcheck(
            &changed_round,
            &air,
            &public,
            &constraints,
            &bridge,
            &[],
        ));

        let mut changed_terminal = proof.clone();
        changed_terminal.terminal_evaluations[0] =
            changed_terminal.terminal_evaluations[0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_execution_sumcheck(
            &changed_terminal,
            &air,
            &public,
            &constraints,
            &bridge,
            &[],
        ));

        let adjacency_tables = dense_adjacency_source_tables(&tables);
        let adjacency =
            prove_dense_adjacency_sumcheck(adjacency_tables.clone(), &bridge, &[], &[]).unwrap();
        assert_eq!(adjacency.rounds.len(), 8);
        assert!(
            adjacency
                .rounds
                .iter()
                .all(|round| round.len() == DENSE_ADJACENCY_SUMCHECK_DEGREE + 1)
        );
        assert_eq!(
            adjacency.terminal_evaluations.len(),
            BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
        );
        assert!(verify_dense_adjacency_sumcheck(
            &adjacency,
            air.trace_rows(),
            &bridge,
            &[],
            &[],
        ));

        let mut changed_adjacency_round = adjacency.clone();
        changed_adjacency_round.rounds[0][0] =
            changed_adjacency_round.rounds[0][0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_adjacency_sumcheck(
            &changed_adjacency_round,
            air.trace_rows(),
            &bridge,
            &[],
            &[],
        ));

        let mut changed_adjacency_terminal = adjacency.clone();
        changed_adjacency_terminal.terminal_evaluations[0] =
            changed_adjacency_terminal.terminal_evaluations[0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_adjacency_sumcheck(
            &changed_adjacency_terminal,
            air.trace_rows(),
            &bridge,
            &[],
            &[],
        ));

        let next_start = BLS_DORY_BLAKE3_MAIN_WIDTH;
        let mut substituted_next = adjacency_tables.clone();
        substituted_next[next_start][7] = substituted_next[next_start][7] + BlsDoryFr::from_u64(1);
        assert!(prove_dense_adjacency_sumcheck(substituted_next, &bridge, &[], &[]).is_none());

        let mut reordered_next = adjacency_tables.clone();
        for table in &mut reordered_next[next_start..] {
            table.swap(4, 5);
        }
        assert!(prove_dense_adjacency_sumcheck(reordered_next, &bridge, &[], &[]).is_none());

        let mut duplicated_next = adjacency_tables.clone();
        for table in &mut duplicated_next[next_start..] {
            table[9] = table[8];
        }
        assert!(prove_dense_adjacency_sumcheck(duplicated_next, &bridge, &[], &[]).is_none());

        let mut changed_boundary = adjacency_tables;
        let final_row = air.trace_rows() - 1;
        changed_boundary[next_start][final_row] =
            changed_boundary[next_start][final_row] + BlsDoryFr::from_u64(1);
        assert!(prove_dense_adjacency_sumcheck(changed_boundary, &bridge, &[], &[]).is_none());
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    fn blake3_streamed_source_rejects_failed_short_and_malformed_rows() {
        const TRACE_ROWS: usize = 1 << 3;
        const SELECTOR_SLOTS: usize = 1 << 3;
        let tables = (0..5)
            .map(|selector| {
                (0..TRACE_ROWS)
                    .map(|row| BlsDoryFr::from_u64((selector * TRACE_ROWS + row + 1) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(6).unwrap();
        let scratch = Blake3ScratchDirectory::create();

        let mut failed = DensePackedTableRowSource::new(&tables, TRACE_ROWS, SELECTOR_SLOTS);
        failed.fail_at = Some(1);
        assert!(matches!(
            commit_bls_dory_row_source_with_scratch(&mut failed, 3, 3, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::CoefficientSource)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut short = DensePackedTableRowSource::new(&tables, TRACE_ROWS, SELECTOR_SLOTS);
        short.short_at = Some(0);
        assert!(matches!(
            commit_bls_dory_row_source_with_scratch(&mut short, 3, 3, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::InvalidCoefficientCount)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

        let mut malformed_tables = tables;
        malformed_tables[0].pop();
        let mut malformed =
            DensePackedTableRowSource::new(&malformed_tables, TRACE_ROWS, SELECTOR_SLOTS);
        assert!(matches!(
            commit_bls_dory_row_source_with_scratch(&mut malformed, 3, 3, &setup, &scratch.0,),
            Err(BlsDoryAggregateError::CoefficientSource)
        ));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "the exact 16-variable Dory commitment and opening comparison is intentionally expensive"]
    fn blake3_streamed_source_preserves_commitment_and_exact_opening_bytes() {
        const TRACE_VARIABLES: usize = 8;
        const SELECTOR_VARIABLES: usize = 8;
        const TRACE_ROWS: usize = 1 << TRACE_VARIABLES;
        const SELECTOR_SLOTS: usize = 1 << SELECTOR_VARIABLES;
        let tables = (0..137)
            .map(|selector| {
                (0..TRACE_ROWS)
                    .map(|row| {
                        BlsDoryFr::from_u64(
                            ((selector as u64 + 3) * 65_537 + (row as u64 + 5) * 257) % 65_521,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let materialized = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&tables, TRACE_ROWS, SELECTOR_SLOTS).unwrap(),
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
        )
        .unwrap();
        let mut source = DensePackedTableRowSource::new(&tables, TRACE_ROWS, SELECTOR_SLOTS);
        let streamed = commit_bls_dory_row_source_with_scratch(
            &mut source,
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(source.reads, tables.len());
        assert_eq!(streamed.commitment(), materialized.commitment());

        let points = vec![
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 2) * 7))
                .collect::<Vec<_>>(),
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 3) * 11))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"blake3-row-source-equivalence",
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_same_commitment_openings(
            b"blake3-row-source-equivalence",
            &streamed,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"blake3-row-source-equivalence",
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();

        let artifact_path = std::fs::read_dir(&scratch.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut artifact = std::fs::OpenOptions::new()
            .write(true)
            .open(artifact_path)
            .unwrap();
        artifact.seek(SeekFrom::Start(100)).unwrap();
        artifact.write_all(&[0xff]).unwrap();
        artifact.flush().unwrap();
        drop(artifact);
        assert_eq!(
            prove_bls_dory_same_commitment_openings(
                b"blake3-row-source-corruption",
                &streamed,
                &points,
                &setup,
            ),
            Err(BlsDoryAggregateError::ProverStorage)
        );
        drop(streamed);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "the exact 16-variable compact Dory comparison is intentionally expensive"]
    fn blake3_signed_word_source_preserves_commitment_and_opening_bytes() {
        const TRACE_VARIABLES: usize = 8;
        const SELECTOR_VARIABLES: usize = 8;
        const TRACE_ROWS: usize = 1 << TRACE_VARIABLES;
        const SELECTOR_SLOTS: usize = 1 << SELECTOR_VARIABLES;
        let signed_tables = (0..137)
            .map(|selector| {
                (0..TRACE_ROWS)
                    .map(|row| {
                        let magnitude = ((selector * TRACE_ROWS + row + 1) % 1_000_003) as i64;
                        if (selector + row).is_multiple_of(3) {
                            -magnitude
                        } else {
                            magnitude
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let field_tables = signed_tables
            .iter()
            .map(|table| {
                table
                    .iter()
                    .copied()
                    .map(BlsDoryFr::from_i64)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let materialized = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&field_tables, TRACE_ROWS, SELECTOR_SLOTS).unwrap(),
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
        )
        .unwrap();
        let mut source =
            DensePackedSignedWordRowSource::new(&signed_tables, TRACE_ROWS, SELECTOR_SLOTS);
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(compact.commitment(), materialized.commitment());
        let artifact_path = std::fs::read_dir(&scratch.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let compact_bytes = std::fs::metadata(artifact_path).unwrap().len();
        let literal_bytes = (signed_tables.len() * TRACE_ROWS * 32) as u64;
        assert!(compact_bytes * 3 < literal_bytes);

        let points = vec![
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 5) * 13))
                .collect::<Vec<_>>(),
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 7) * 17))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"blake3-compact-source-equivalence",
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_same_commitment_openings(
            b"blake3-compact-source-equivalence",
            &compact,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"blake3-compact-source-equivalence",
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "the exact 16-variable code-only Dory comparison is intentionally expensive"]
    fn blake3_code_only_source_preserves_commitment_and_opening_bytes() {
        const TRACE_VARIABLES: usize = 8;
        const SELECTOR_VARIABLES: usize = 8;
        const TRACE_ROWS: usize = 1 << TRACE_VARIABLES;
        const SELECTOR_SLOTS: usize = 1 << SELECTOR_VARIABLES;
        let dictionary = std::iter::once(BlsDoryFr::zero())
            .chain((-7..=-1).chain(1..=8).map(BlsDoryFr::from_i64))
            .collect::<Vec<_>>();
        let code_tables = (0..137)
            .map(|selector| {
                (0..TRACE_ROWS)
                    .map(|row| ((selector * 7 + row * 11) % dictionary.len()) as u8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let field_tables = code_tables
            .iter()
            .map(|table| {
                table
                    .iter()
                    .map(|code| dictionary[usize::from(*code)])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let scratch = Blake3ScratchDirectory::create();
        let materialized = commit_bls_dory_polynomial(
            dense_pack_adjacency_tables(&field_tables, TRACE_ROWS, SELECTOR_SLOTS).unwrap(),
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
        )
        .unwrap();
        let mut source = DensePackedCodeRowSource {
            tables: &code_tables,
            trace_rows: TRACE_ROWS,
            selector_slots: SELECTOR_SLOTS,
            dictionary,
        };
        let compact = commit_bls_dory_compact_row_source_with_scratch(
            &mut source,
            SELECTOR_VARIABLES,
            TRACE_VARIABLES,
            &setup,
            &scratch.0,
        )
        .unwrap();
        assert_eq!(compact.commitment(), materialized.commitment());
        let artifact_path = std::fs::read_dir(&scratch.0)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let compact_bytes = std::fs::metadata(artifact_path).unwrap().len();
        let literal_bytes = (code_tables.len() * TRACE_ROWS * 32) as u64;
        assert!(compact_bytes * 32 < literal_bytes);

        let points = vec![
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 11) * 19))
                .collect::<Vec<_>>(),
            (0..16)
                .map(|coordinate| BlsDoryFr::from_u64((coordinate as u64 + 13) * 23))
                .collect::<Vec<_>>(),
        ];
        let ordinary = prove_bls_dory_same_commitment_openings(
            b"blake3-code-source-equivalence",
            &materialized,
            &points,
            &setup,
        )
        .unwrap();
        let artifact_backed = prove_bls_dory_same_commitment_openings(
            b"blake3-code-source-equivalence",
            &compact,
            &points,
            &setup,
        )
        .unwrap();
        assert_eq!(artifact_backed, ordinary);
        verify_bls_dory_openings(
            b"blake3-code-source-equivalence",
            &artifact_backed.0,
            &artifact_backed.1,
            &setup,
        )
        .unwrap();
        drop(compact);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "three packed Dory commitments are intentionally expensive in debug builds"]
    fn native_execution_sumcheck_terminal_values_are_dory_authenticated() {
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
        let signed_activation = activation
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
                crate::structured_sumcheck::evaluate_mle(&signed_activation, &native_point),
            ),
        };
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            challenge_digest,
            witness.digest,
            &activation,
            [0x51; 32],
            [2_u64, 3, 5, 7, 11]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        let air = NarrowBlake3Air::new(&statement).unwrap();
        let main = generate_main_trace(&air, &statement, &witness);
        let old_main_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { main.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let accumulators = native_accumulator_trace(&air, &old_main_rows, &bridge);
        let native_rows = old_main_rows
            .iter()
            .zip(&accumulators)
            .map(|(row, accumulator)| native_main_row(row, *accumulator))
            .collect::<Vec<_>>();
        let preprocessed = air.preprocessed_trace().unwrap();
        let preprocessed_rows = (0..air.trace_rows())
            .map(|row| bls_values(unsafe { preprocessed.row_unchecked(row) }))
            .collect::<Vec<_>>();
        let tables = dense_execution_tables(&native_rows, &preprocessed_rows);
        let public = bls_values(public_values(&statement).unwrap());
        let constraints = bls_dory_native_blake3_constraint_ir(activation.len()).unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let authenticated = prove_dense_authenticated_execution(
            tables,
            &air,
            &public,
            &constraints,
            &bridge,
            &setup,
        )
        .unwrap();
        assert_eq!(authenticated.opening_batches.len(), 4);
        assert_eq!(
            authenticated
                .opening_batches
                .iter()
                .map(|batch| batch.terminal_count)
                .sum::<usize>(),
            BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS
        );
        assert!(verify_dense_authenticated_execution(
            &authenticated,
            &air,
            &public,
            &constraints,
            &bridge,
            &setup,
        ));

        let mut changed_opening = authenticated.clone();
        changed_opening.opening_proof[0] ^= 1;
        assert!(!verify_dense_authenticated_execution(
            &changed_opening,
            &air,
            &public,
            &constraints,
            &bridge,
            &setup,
        ));
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "five shared Dory commitments are intentionally expensive in debug builds"]
    fn native_execution_and_adjacency_share_authenticated_source_commitments() {
        let fixture = dense_blake3_fixture();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let proving_started = std::time::Instant::now();
        let authenticated = prove_dense_authenticated_blake3(
            fixture.tables,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            &setup,
        )
        .unwrap();
        let proving_elapsed = proving_started.elapsed();
        assert_eq!(authenticated.execution_batches.len(), 4);
        assert_eq!(authenticated.execution_sumcheck.rounds.len(), 8);
        assert_eq!(authenticated.adjacency_sumcheck.rounds.len(), 8);
        let verification_started = std::time::Instant::now();
        let verified = verify_dense_authenticated_blake3(
            &authenticated,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            &setup,
        );
        let verification_elapsed = verification_started.elapsed();
        eprintln!(
            "composed BLAKE3 fixture: prove_ms={} verify_ms={} opening_bytes={}",
            proving_elapsed.as_millis(),
            verification_elapsed.as_millis(),
            authenticated.opening_proof.len(),
        );
        assert!(verified);

        let mut changed_shared_source = authenticated.clone();
        changed_shared_source.execution_batches[0].commitment =
            changed_shared_source.execution_batches[1].commitment;
        assert!(!verify_dense_authenticated_blake3(
            &changed_shared_source,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            &setup,
        ));

        let mut changed_adjacency_terminal = authenticated.clone();
        changed_adjacency_terminal
            .adjacency_sumcheck
            .terminal_evaluations[0] = changed_adjacency_terminal
            .adjacency_sumcheck
            .terminal_evaluations[0]
            + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_authenticated_blake3(
            &changed_adjacency_terminal,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            &setup,
        ));

        let mut changed_inverse = authenticated.clone();
        changed_inverse.inverse_commitment = changed_inverse.execution_batches[0].commitment;
        assert!(!verify_dense_authenticated_blake3(
            &changed_inverse,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            &setup,
        ));

        let mut changed_opening = authenticated;
        changed_opening.opening_proof[0] ^= 1;
        assert!(!verify_dense_authenticated_blake3(
            &changed_opening,
            &fixture.air,
            &fixture.public,
            &fixture.constraints,
            &fixture.bridge,
            &setup,
        ));
    }

    #[test]
    #[cfg(feature = "whir-prototype")]
    #[ignore = "two packed Dory commitments are intentionally expensive in debug builds"]
    fn native_adjacency_sumcheck_sources_and_terminals_are_dory_authenticated() {
        let activation = (0_u8..32).map(|index| 100 + index).collect::<Vec<_>>();
        let bridge = BlsDoryOutputBridgeStatement::from_test_parts(
            [0x42; 32],
            [0x43; 32],
            &activation,
            [0x51; 32],
            [2_u64, 3, 5, 7, 11]
                .into_iter()
                .map(BlsDoryFr::from_u64)
                .collect(),
        )
        .unwrap();
        let setup = crate::dory_bls12_381_prototype::deterministic_bls_dory_setup(16).unwrap();
        let authenticated = prove_dense_authenticated_adjacency(
            synthetic_dense_adjacency_tables(16),
            &bridge,
            &setup,
        )
        .unwrap();
        assert_eq!(authenticated.sumcheck.rounds.len(), 4);
        assert_eq!(
            authenticated.sumcheck.terminal_evaluations.len(),
            BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS
        );
        assert_eq!(authenticated.opening_batches.len(), 2);
        assert!(verify_dense_authenticated_adjacency(
            &authenticated,
            &bridge,
            &setup,
        ));

        let mut changed_source_commitment = authenticated.clone();
        changed_source_commitment.opening_batches[0].commitment =
            changed_source_commitment.opening_batches[1].commitment;
        assert!(!verify_dense_authenticated_adjacency(
            &changed_source_commitment,
            &bridge,
            &setup,
        ));

        let mut changed_terminal = authenticated.clone();
        changed_terminal.sumcheck.terminal_evaluations[0] =
            changed_terminal.sumcheck.terminal_evaluations[0] + BlsDoryFr::from_u64(1);
        assert!(!verify_dense_authenticated_adjacency(
            &changed_terminal,
            &bridge,
            &setup,
        ));

        let mut changed_opening = authenticated;
        changed_opening.opening_proof[0] ^= 1;
        assert!(!verify_dense_authenticated_adjacency(
            &changed_opening,
            &bridge,
            &setup,
        ));
    }
}
