//! Executable algebraic soundness accounting for the production BLS/Dory layout.
//!
//! This report deliberately separates information-theoretic algebraic error
//! from the computational assumptions of Dory, BLS12-381, BLAKE3, and the
//! Fiat-Shamir transform. It is an activation input, not an audit certificate.

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use thiserror::Error;

use crate::{
    PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    PRODUCTION_V2_LAYERS_PER_BANK, STRUCTURED_TRANSITION_ORACLES,
    STRUCTURED_TRANSITION_RANGE_SPEC_COUNT, STRUCTURED_TRANSITION_REGULAR_ORACLES,
    StructuredMatrixStatement, StructuredSumcheckError, StructuredTransitionError,
    StructuredTransitionStatement, StructuredWiringError, StructuredWiringStatement,
    dory_bls12_381_aggregate::{BLS_DORY_AGGREGATE_SUMCHECK_DEGREE, MAX_BLS_DORY_AGGREGATE_CLAIMS},
    dory_bls12_381_layout::{
        BLS_DORY_SHARED_LINKS_PER_BANK, BLS_DORY_SHARED_PRODUCTION_CLAIMS,
        BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS, BLS_DORY_SHARED_PRODUCTION_VARIABLES,
        MAX_BLS_DORY_SHARED_MATRIX_PROOFS, MAX_BLS_DORY_SHARED_TRANSITION_PROOFS,
    },
    dory_bls12_381_logup::{
        BLS_DORY_RANGE_LOGUP_SELECTOR_SUMCHECK_DEGREE, BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES,
        BLS_DORY_RANGE_LOGUP_SUMCHECK_DEGREE, BLS_DORY_RANGE_LOGUP_TABLE_VALUES,
    },
    dory_bls12_381_output_bridge::BLS_DORY_OUTPUT_BRIDGE_PRODUCTION_VARIABLES,
    dory_bls12_381_prototype::{
        BLS_DORY_EXACT_NONZERO_CHALLENGE_SAMPLING, BLS_DORY_TRANSCRIPT_VERSION,
    },
    dory_bls12_381_transition::{
        BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS, BLS_DORY_TRANSITION_SUMCHECK_DEGREE,
    },
};

/// Minimum algebraic soundness required before this backend can activate.
pub const REQUIRED_BLS_DORY_ALGEBRAIC_SOUNDNESS_BITS: u32 = 128;
/// Conventional computational-security target for the selected primitives.
pub const BLS_DORY_COMPUTATIONAL_SECURITY_TARGET_BITS: u32 = 128;
/// Independent review status is deliberately fail-closed.
pub const BLS_DORY_KNOWLEDGE_SOUNDNESS_REVIEWED: bool = false;
/// Independent Fiat-Shamir review status is deliberately fail-closed.
pub const BLS_DORY_FIAT_SHAMIR_REVIEWED: bool = false;
/// External implementation and cryptographic audit status is fail-closed.
pub const BLS_DORY_EXTERNAL_AUDIT_COMPLETE: bool = false;

const PRODUCTION_MAX_ABS_ACTIVATION: u64 = 125;
const PRODUCTION_MAX_ABS_WEIGHT: u64 = 125;
const PRODUCTION_MAX_ABS_ACCUMULATOR: u64 = 64_000_000;
const PRODUCTION_MAX_MASK: u64 = 5_000;
/// One line item in the conservative union bound over uniform nonzero Fr challenges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDorySoundnessTerm {
    pub label: &'static str,
    pub instances: u64,
    pub numerator_upper_bound_per_instance: u64,
}

impl BlsDorySoundnessTerm {
    pub fn total_numerator_upper_bound(&self) -> Result<u64, BlsDorySoundnessError> {
        self.instances
            .checked_mul(self.numerator_upper_bound_per_instance)
            .ok_or(BlsDorySoundnessError::ArithmeticOverflow)
    }
}

/// Machine-derived production report for the algebraic part of the proof system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryProductionSoundnessReport {
    pub transcript_version: u16,
    pub scalar_modulus_bits: u32,
    pub nonzero_challenge_space_lower_bound_bits: u32,
    pub aggregate_claims: usize,
    pub maximum_aggregate_claims: usize,
    pub terms: Vec<BlsDorySoundnessTerm>,
    pub total_algebraic_numerator_upper_bound: u64,
    pub algebraic_soundness_bits: u32,
    pub required_algebraic_soundness_bits: u32,
    pub grinding_headroom_bits: u32,
    pub computational_security_target_bits: u32,
    pub exact_nonzero_challenge_sampling: bool,
    pub dory_knowledge_soundness_reviewed: bool,
    pub fiat_shamir_reviewed: bool,
    pub external_audit_complete: bool,
}

impl BlsDoryProductionSoundnessReport {
    /// This covers only the soundness-review gate, not streaming or benchmark gates.
    #[must_use]
    pub fn soundness_review_gate_ready(&self) -> bool {
        self.aggregate_claims <= self.maximum_aggregate_claims
            && self.algebraic_soundness_bits >= self.required_algebraic_soundness_bits
            && self.computational_security_target_bits >= self.required_algebraic_soundness_bits
            && self.exact_nonzero_challenge_sampling
            && self.dory_knowledge_soundness_reviewed
            && self.fiat_shamir_reviewed
            && self.external_audit_complete
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlsDorySoundnessError {
    #[error("production soundness geometry is inconsistent")]
    InvalidProductionGeometry,
    #[error("production soundness arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("production matrix geometry is invalid: {0}")]
    Matrix(#[from] StructuredSumcheckError),
    #[error("production transition geometry is invalid: {0}")]
    Transition(#[from] StructuredTransitionError),
    #[error("production wiring geometry is invalid: {0}")]
    Wiring(#[from] StructuredWiringError),
}

/// Build the conservative algebraic union bound for the exact production topology.
pub fn production_bls_dory_soundness_report()
-> Result<BlsDoryProductionSoundnessReport, BlsDorySoundnessError> {
    let matrix = production_matrix_statement()?;
    let initialization = production_initialization_statement()?;
    let transition = production_transition_statement()?;
    let wiring = production_wiring_statement()?;

    let matrix_instances = u64::from(PRODUCTION_V2_BANKS);
    let transition_instances = u64::try_from(MAX_BLS_DORY_SHARED_TRANSITION_PROOFS)
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    let bank_transition_instances = matrix_instances;
    let matrix_point_variables = matrix.layers.ilog2() + matrix.rows.ilog2() + matrix.cols.ilog2();
    let initialization_cell_variables = initialization.elements()?.ilog2();
    let bank_cell_variables = transition.elements()?.ilog2();
    let shared_variables = u64::try_from(BLS_DORY_SHARED_PRODUCTION_VARIABLES)
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    let selector_variables = u64::try_from(BLS_DORY_RANGE_LOGUP_SELECTOR_VARIABLES)
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    if !STRUCTURED_TRANSITION_RANGE_SPEC_COUNT.is_power_of_two() {
        return Err(BlsDorySoundnessError::InvalidProductionGeometry);
    }
    let range_spec_variables = STRUCTURED_TRANSITION_RANGE_SPEC_COUNT.ilog2();
    let active_range_oracles = STRUCTURED_TRANSITION_ORACLES
        .checked_sub(STRUCTURED_TRANSITION_REGULAR_ORACLES)
        .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?;
    // A false LogUp multiset identity is a nonzero rational function of alpha.
    // Clearing denominators gives at most one root per active query value plus
    // one per fixed table value. Duplicates only reduce this conservative bound.
    let initialization_range_values = u64::try_from(initialization.elements()?)?
        .checked_mul(u64::try_from(active_range_oracles)?)
        .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?;
    let bank_range_values = u64::try_from(transition.elements()?)?
        .checked_mul(u64::try_from(active_range_oracles)?)
        .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?;
    let lookup_table_values = u64::try_from(BLS_DORY_RANGE_LOGUP_TABLE_VALUES)?;
    let constraint_mixing_degree = u64::try_from(
        BLS_DORY_TRANSITION_ARITHMETIC_CONSTRAINTS
            .checked_sub(1)
            .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?,
    )?;
    let transition_sumcheck_degree = u64::try_from(BLS_DORY_TRANSITION_SUMCHECK_DEGREE)?;
    let logup_sumcheck_degree = u64::try_from(BLS_DORY_RANGE_LOGUP_SUMCHECK_DEGREE)?;
    let selector_sumcheck_degree = u64::try_from(BLS_DORY_RANGE_LOGUP_SELECTOR_SUMCHECK_DEGREE)?;
    let aggregate_sumcheck_degree = u64::try_from(BLS_DORY_AGGREGATE_SUMCHECK_DEGREE)?;
    let bank_equality_links = MAX_BLS_DORY_SHARED_MATRIX_PROOFS
        .checked_mul(BLS_DORY_SHARED_LINKS_PER_BANK)
        .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?;

    let terms = vec![
        term(
            "matrix relation random-point reduction",
            matrix_instances,
            matrix_point_variables,
        )?,
        term(
            "matrix sumchecks",
            matrix_instances,
            matrix.sumcheck_error_numerator()?,
        )?,
        term(
            "initialization transition relation point",
            1,
            initialization_cell_variables,
        )?,
        term(
            "bank transition relation points",
            bank_transition_instances,
            bank_cell_variables,
        )?,
        term(
            "transition constraint mixing",
            transition_instances,
            constraint_mixing_degree,
        )?,
        term(
            "initialization transition sumcheck",
            1,
            transition_sumcheck_degree * u64::from(initialization_cell_variables),
        )?,
        term(
            "bank transition sumchecks",
            bank_transition_instances,
            transition_sumcheck_degree * u64::from(bank_cell_variables),
        )?,
        term(
            "initialization LogUp lookup-alpha rational identity",
            1,
            initialization_range_values
                .checked_add(lookup_table_values)
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        )?,
        term(
            "bank LogUp lookup-alpha rational identities",
            bank_transition_instances,
            bank_range_values
                .checked_add(lookup_table_values)
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?,
        )?,
        term("LogUp local relation mixing", transition_instances, 1)?,
        term("LogUp global relation mixing", transition_instances, 1)?,
        term(
            "LogUp local equality points",
            transition_instances,
            shared_variables,
        )?,
        term(
            "LogUp sumchecks",
            transition_instances,
            logup_sumcheck_degree * shared_variables,
        )?,
        term(
            "initialization reconstruction cell point",
            1,
            initialization_cell_variables,
        )?,
        term(
            "bank reconstruction cell points",
            bank_transition_instances,
            bank_cell_variables,
        )?,
        term(
            "reconstruction range-spec points",
            transition_instances,
            range_spec_variables,
        )?,
        term("reconstruction slack mixing", transition_instances, 1)?,
        term(
            "source/digit reconstruction mixing",
            transition_instances,
            1,
        )?,
        term(
            "reconstruction selector sumchecks",
            transition_instances,
            selector_sumcheck_degree * selector_variables,
        )?,
        term(
            "successor wiring identities",
            1,
            wiring.soundness_error_numerator()?,
        )?,
        term(
            "fixed base-input equality link",
            1,
            initialization_cell_variables,
        )?,
        term(
            "initialization-output equality link",
            1,
            initialization_cell_variables,
        )?,
        term(
            "bank equality links",
            bank_equality_links,
            bank_cell_variables,
        )?,
        term(
            "final-output BLAKE3/Dory equality point",
            1,
            u64::try_from(BLS_DORY_OUTPUT_BRIDGE_PRODUCTION_VARIABLES)?,
        )?,
        term("distinct-point claim batching", 1, 1)?,
        term(
            "distinct-point aggregate sumcheck",
            1,
            aggregate_sumcheck_degree * shared_variables,
        )?,
    ];

    let total_algebraic_numerator_upper_bound = terms.iter().try_fold(0_u64, |total, term| {
        total
            .checked_add(term.total_numerator_upper_bound()?)
            .ok_or(BlsDorySoundnessError::ArithmeticOverflow)
    })?;
    let scalar_modulus_bits = Fr::MODULUS_BIT_SIZE;
    let nonzero_challenge_space_lower_bound_bits = scalar_modulus_bits
        .checked_sub(1)
        .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?;
    let algebraic_soundness_bits = nonzero_challenge_space_lower_bound_bits
        .checked_sub(ceil_log2(total_algebraic_numerator_upper_bound))
        .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?;
    let grinding_headroom_bits = algebraic_soundness_bits
        .checked_sub(REQUIRED_BLS_DORY_ALGEBRAIC_SOUNDNESS_BITS)
        .ok_or(BlsDorySoundnessError::InvalidProductionGeometry)?;

    if PRODUCTION_V2_BANKS
        .checked_mul(PRODUCTION_V2_LAYERS_PER_BANK)
        .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?
        != PRODUCTION_V2_LAYERS
        || matrix_instances != u64::try_from(MAX_BLS_DORY_SHARED_MATRIX_PROOFS)?
        || transition_instances != matrix_instances + 1
        || BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS
            != 2usize
                .checked_add(bank_equality_links)
                .ok_or(BlsDorySoundnessError::ArithmeticOverflow)?
        || BLS_DORY_SHARED_PRODUCTION_CLAIMS > MAX_BLS_DORY_AGGREGATE_CLAIMS
    {
        return Err(BlsDorySoundnessError::InvalidProductionGeometry);
    }

    Ok(BlsDoryProductionSoundnessReport {
        transcript_version: BLS_DORY_TRANSCRIPT_VERSION,
        scalar_modulus_bits,
        nonzero_challenge_space_lower_bound_bits,
        aggregate_claims: BLS_DORY_SHARED_PRODUCTION_CLAIMS,
        maximum_aggregate_claims: MAX_BLS_DORY_AGGREGATE_CLAIMS,
        terms,
        total_algebraic_numerator_upper_bound,
        algebraic_soundness_bits,
        required_algebraic_soundness_bits: REQUIRED_BLS_DORY_ALGEBRAIC_SOUNDNESS_BITS,
        grinding_headroom_bits,
        computational_security_target_bits: BLS_DORY_COMPUTATIONAL_SECURITY_TARGET_BITS,
        exact_nonzero_challenge_sampling: BLS_DORY_EXACT_NONZERO_CHALLENGE_SAMPLING,
        dory_knowledge_soundness_reviewed: BLS_DORY_KNOWLEDGE_SOUNDNESS_REVIEWED,
        fiat_shamir_reviewed: BLS_DORY_FIAT_SHAMIR_REVIEWED,
        external_audit_complete: BLS_DORY_EXTERNAL_AUDIT_COMPLETE,
    })
}

fn production_matrix_statement() -> Result<StructuredMatrixStatement, BlsDorySoundnessError> {
    let statement = StructuredMatrixStatement {
        layers: usize::try_from(PRODUCTION_V2_LAYERS_PER_BANK)?,
        rows: usize::try_from(PRODUCTION_V2_BATCH)?,
        inner: usize::try_from(PRODUCTION_V2_DIMENSION)?,
        cols: usize::try_from(PRODUCTION_V2_DIMENSION)?,
        max_abs_activation: PRODUCTION_MAX_ABS_ACTIVATION,
        max_abs_weight: PRODUCTION_MAX_ABS_WEIGHT,
        max_abs_accumulator: PRODUCTION_MAX_ABS_ACCUMULATOR,
    };
    statement.sumcheck_error_numerator()?;
    Ok(statement)
}

fn production_initialization_statement()
-> Result<StructuredTransitionStatement, BlsDorySoundnessError> {
    let statement = StructuredTransitionStatement {
        layers: 1,
        rows: usize::try_from(PRODUCTION_V2_BATCH)?,
        cols: usize::try_from(PRODUCTION_V2_DIMENSION)?,
        max_abs_accumulator: PRODUCTION_MAX_ABS_ACCUMULATOR,
        max_mask: PRODUCTION_MAX_MASK,
    };
    statement.sumcheck_error_numerator()?;
    Ok(statement)
}

fn production_transition_statement() -> Result<StructuredTransitionStatement, BlsDorySoundnessError>
{
    let statement = StructuredTransitionStatement {
        layers: usize::try_from(PRODUCTION_V2_LAYERS_PER_BANK)?,
        rows: usize::try_from(PRODUCTION_V2_BATCH)?,
        cols: usize::try_from(PRODUCTION_V2_DIMENSION)?,
        max_abs_accumulator: PRODUCTION_MAX_ABS_ACCUMULATOR,
        max_mask: PRODUCTION_MAX_MASK,
    };
    statement.sumcheck_error_numerator()?;
    Ok(statement)
}

fn production_wiring_statement() -> Result<StructuredWiringStatement, BlsDorySoundnessError> {
    let statement = StructuredWiringStatement {
        banks: usize::try_from(PRODUCTION_V2_BANKS)?,
        layers_per_bank: usize::try_from(PRODUCTION_V2_LAYERS_PER_BANK)?,
        rows: usize::try_from(PRODUCTION_V2_BATCH)?,
        cols: usize::try_from(PRODUCTION_V2_DIMENSION)?,
        max_abs_activation: PRODUCTION_MAX_ABS_ACTIVATION,
    };
    statement.soundness_error_numerator()?;
    Ok(statement)
}

fn term(
    label: &'static str,
    instances: impl TryInto<u64>,
    numerator: impl TryInto<u64>,
) -> Result<BlsDorySoundnessTerm, BlsDorySoundnessError> {
    let instances = instances
        .try_into()
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    let numerator_upper_bound_per_instance = numerator
        .try_into()
        .map_err(|_| BlsDorySoundnessError::ArithmeticOverflow)?;
    if instances == 0 || numerator_upper_bound_per_instance == 0 {
        return Err(BlsDorySoundnessError::InvalidProductionGeometry);
    }
    Ok(BlsDorySoundnessTerm {
        label,
        instances,
        numerator_upper_bound_per_instance,
    })
}

fn ceil_log2(value: u64) -> u32 {
    if value <= 1 {
        0
    } else {
        u64::BITS - (value - 1).leading_zeros()
    }
}

impl From<std::num::TryFromIntError> for BlsDorySoundnessError {
    fn from(_: std::num::TryFromIntError) -> Self {
        Self::ArithmeticOverflow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_report_pins_every_algebraic_line_item() {
        let report = production_bls_dory_soundness_report().unwrap();
        let expected = [
            ("matrix relation random-point reduction", 3, 26),
            ("matrix sumchecks", 3, 45),
            ("initialization transition relation point", 1, 19),
            ("bank transition relation points", 3, 26),
            ("transition constraint mixing", 4, 6),
            ("initialization transition sumcheck", 1, 57),
            ("bank transition sumchecks", 3, 78),
            (
                "initialization LogUp lookup-alpha rational identity",
                1,
                51_380_240,
            ),
            (
                "bank LogUp lookup-alpha rational identities",
                3,
                6_576_668_688,
            ),
            ("LogUp local relation mixing", 4, 1),
            ("LogUp global relation mixing", 4, 1),
            ("LogUp local equality points", 4, 33),
            ("LogUp sumchecks", 4, 132),
            ("initialization reconstruction cell point", 1, 19),
            ("bank reconstruction cell points", 3, 26),
            ("reconstruction range-spec points", 4, 3),
            ("reconstruction slack mixing", 4, 1),
            ("source/digit reconstruction mixing", 4, 1),
            ("reconstruction selector sumchecks", 4, 14),
            ("successor wiring identities", 1, 135),
            ("fixed base-input equality link", 1, 19),
            ("initialization-output equality link", 1, 19),
            ("bank equality links", 9, 26),
            ("final-output BLAKE3/Dory equality point", 1, 19),
            ("distinct-point claim batching", 1, 1),
            ("distinct-point aggregate sumcheck", 1, 66),
        ];
        assert_eq!(report.terms.len(), expected.len());
        for (term, (label, instances, numerator)) in report.terms.iter().zip(expected) {
            assert_eq!(term.label, label);
            assert_eq!(term.instances, instances);
            assert_eq!(term.numerator_upper_bound_per_instance, numerator);
        }
    }

    #[test]
    fn production_report_clears_algebraic_gate_but_not_review_gate() {
        let report = production_bls_dory_soundness_report().unwrap();
        assert_eq!(report.transcript_version, 2);
        assert_eq!(report.scalar_modulus_bits, 255);
        assert_eq!(report.nonzero_challenge_space_lower_bound_bits, 254);
        assert_eq!(report.aggregate_claims, 128);
        assert_eq!(report.maximum_aggregate_claims, 128);
        assert_eq!(report.total_algebraic_numerator_upper_bound, 19_781_388_263);
        assert_eq!(ceil_log2(report.total_algebraic_numerator_upper_bound), 35);
        assert_eq!(report.algebraic_soundness_bits, 219);
        assert_eq!(report.required_algebraic_soundness_bits, 128);
        assert_eq!(report.grinding_headroom_bits, 91);
        assert_eq!(report.computational_security_target_bits, 128);
        assert!(report.exact_nonzero_challenge_sampling);
        assert!(!report.dory_knowledge_soundness_reviewed);
        assert!(!report.fiat_shamir_reviewed);
        assert!(!report.external_audit_complete);
        assert!(!report.soundness_review_gate_ready());
    }
}
