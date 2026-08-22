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
    "the 1,305 narrow BLAKE3 constraints have not been translated to and differentially tested over the BLS12-381 scalar field",
    "the row-indexed LogUp adjacency argument and its complete Fiat-Shamir soundness bound have not been implemented or independently reviewed",
    "the shared aggregate parser still intentionally caps claim count at 128 and must not be widened before the new components verify end to end",
    "the complete n=33 proof size, proving time, verification time, peak memory, and peak scratch have not been measured or audited",
];

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
}
