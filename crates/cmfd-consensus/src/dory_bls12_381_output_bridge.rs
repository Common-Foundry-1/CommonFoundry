//! Cross-field statement shared by the BLS/Dory execution proof and the
//! final-output BLAKE3 argument.
//!
//! Dory authenticates the signed final activation over BLS12-381 `Fr`. The
//! BLAKE3 argument sees the canonical bytes `signed + 125`. Both sides must
//! evaluate their table at the same challenge-derived `Fr` point. The byte-side
//! evaluation is therefore exactly the Dory evaluation plus the MLE of the
//! constant table 125, which is 125.

use ark_ff::{BigInteger, PrimeField};
use dory_pcs::primitives::arithmetic::Field;
use thiserror::Error;

use crate::dory_bls12_381_layout::VerifiedBlsDoryFinalOutputOpening;
use crate::dory_bls12_381_prototype::BlsDoryFr;

pub const BLS_DORY_OUTPUT_BRIDGE_VERSION: u16 = 1;
pub const BLS_DORY_OUTPUT_BRIDGE_PRODUCTION_VARIABLES: usize = 19;
pub const BLS_DORY_OUTPUT_BRIDGE_SCALAR_LIMBS: usize = 8;
pub const BLS_DORY_OUTPUT_BRIDGE_SINGLE_ATTEMPT_SOUNDNESS_BITS: u32 = 249;
pub const BLS_DORY_OUTPUT_BRIDGE_GRINDING_HEADROOM_BITS: u32 = 121;
const ACTIVATION_BYTE_OFFSET: u64 = 125;

/// Public statement consumed by the eventual BLAKE3/BLS cross-field AIR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsDoryOutputBridgeStatement {
    challenge_digest: [u8; 32],
    final_activation_digest: [u8; 32],
    final_activation_len: usize,
    transcript_binding: [u8; 32],
    cell_point: Vec<BlsDoryFr>,
    raw_byte_evaluation: BlsDoryFr,
}

impl BlsDoryOutputBridgeStatement {
    /// Construct only from a final-output opening returned by the complete Dory
    /// verifier. This does not verify the BLAKE3 side of the bridge.
    pub fn from_verified_dory(
        challenge_digest: [u8; 32],
        final_activation_digest: [u8; 32],
        final_activation_len: usize,
        opening: &VerifiedBlsDoryFinalOutputOpening,
    ) -> Result<Self, BlsDoryOutputBridgeError> {
        Self::new(
            challenge_digest,
            final_activation_digest,
            final_activation_len,
            opening.transcript_binding(),
            opening.cell_point().to_vec(),
            opening.signed_evaluation(),
        )
    }

    #[cfg(all(test, feature = "whir-prototype"))]
    pub(crate) fn from_test_parts(
        challenge_digest: [u8; 32],
        final_activation_digest: [u8; 32],
        activation: &[u8],
        transcript_binding: [u8; 32],
        cell_point: Vec<BlsDoryFr>,
    ) -> Result<Self, BlsDoryOutputBridgeError> {
        let raw_byte_evaluation = evaluate_raw_activation_mle(activation, &cell_point)?;
        Self::new(
            challenge_digest,
            final_activation_digest,
            activation.len(),
            transcript_binding,
            cell_point,
            raw_byte_evaluation - BlsDoryFr::from_u64(ACTIVATION_BYTE_OFFSET),
        )
    }

    fn new(
        challenge_digest: [u8; 32],
        final_activation_digest: [u8; 32],
        final_activation_len: usize,
        transcript_binding: [u8; 32],
        cell_point: Vec<BlsDoryFr>,
        signed_evaluation: BlsDoryFr,
    ) -> Result<Self, BlsDoryOutputBridgeError> {
        if final_activation_len == 0
            || !final_activation_len.is_power_of_two()
            || final_activation_len.ilog2() as usize != cell_point.len()
            || cell_point.len() > BLS_DORY_OUTPUT_BRIDGE_PRODUCTION_VARIABLES
            || transcript_binding == [0; 32]
        {
            return Err(BlsDoryOutputBridgeError::Shape);
        }
        Ok(Self {
            challenge_digest,
            final_activation_digest,
            final_activation_len,
            transcript_binding,
            cell_point,
            raw_byte_evaluation: signed_evaluation + BlsDoryFr::from_u64(ACTIVATION_BYTE_OFFSET),
        })
    }

    pub const fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    pub const fn final_activation_digest(&self) -> [u8; 32] {
        self.final_activation_digest
    }

    pub const fn final_activation_len(&self) -> usize {
        self.final_activation_len
    }

    pub const fn transcript_binding(&self) -> [u8; 32] {
        self.transcript_binding
    }

    pub fn cell_point(&self) -> &[BlsDoryFr] {
        &self.cell_point
    }

    pub const fn raw_byte_evaluation(&self) -> BlsDoryFr {
        self.raw_byte_evaluation
    }

    pub fn point_limbs(&self) -> Vec<[u32; BLS_DORY_OUTPUT_BRIDGE_SCALAR_LIMBS]> {
        self.cell_point
            .iter()
            .copied()
            .map(bls_dory_scalar_limbs)
            .collect()
    }

    pub fn raw_byte_evaluation_limbs(&self) -> [u32; BLS_DORY_OUTPUT_BRIDGE_SCALAR_LIMBS] {
        bls_dory_scalar_limbs(self.raw_byte_evaluation)
    }

    /// Prover-side consistency check before constructing the hash argument.
    pub fn validate_activation(&self, activation: &[u8]) -> Result<(), BlsDoryOutputBridgeError> {
        let got = evaluate_raw_activation_mle(activation, &self.cell_point)?;
        if got == self.raw_byte_evaluation {
            Ok(())
        } else {
            Err(BlsDoryOutputBridgeError::Evaluation)
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BlsDoryOutputBridgeError {
    #[error("the final-output bridge has an invalid table or point shape")]
    Shape,
    #[error("the final activation contains a noncanonical byte")]
    ActivationByte,
    #[error("the final activation does not match the Dory-authenticated evaluation")]
    Evaluation,
}

/// Evaluate canonical activation bytes as a multilinear polynomial over
/// BLS12-381 `Fr`. The low-index table coordinate is folded first, matching the
/// Dory evaluation-form polynomial convention.
pub fn evaluate_raw_activation_mle(
    activation: &[u8],
    point: &[BlsDoryFr],
) -> Result<BlsDoryFr, BlsDoryOutputBridgeError> {
    if activation.is_empty()
        || !activation.len().is_power_of_two()
        || activation.len().ilog2() as usize != point.len()
        || point.len() > BLS_DORY_OUTPUT_BRIDGE_PRODUCTION_VARIABLES
    {
        return Err(BlsDoryOutputBridgeError::Shape);
    }
    if activation.iter().any(|value| *value > 250) {
        return Err(BlsDoryOutputBridgeError::ActivationByte);
    }
    let mut layer = activation
        .iter()
        .map(|value| BlsDoryFr::from_u64(u64::from(*value)))
        .collect::<Vec<_>>();
    for coordinate in point {
        for index in 0..layer.len() / 2 {
            let low = layer[2 * index];
            let high = layer[2 * index + 1];
            layer[index] = low + (high - low) * coordinate;
        }
        layer.truncate(layer.len() / 2);
    }
    layer
        .first()
        .copied()
        .ok_or(BlsDoryOutputBridgeError::Shape)
}

pub fn bls_dory_scalar_limbs(scalar: BlsDoryFr) -> [u32; BLS_DORY_OUTPUT_BRIDGE_SCALAR_LIMBS] {
    let mut bytes = scalar.0.into_bigint().to_bytes_le();
    bytes.resize(32, 0);
    std::array::from_fn(|limb| {
        let offset = limb * 4;
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("a resized scalar has eight complete limbs"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point() -> Vec<BlsDoryFr> {
        vec![
            BlsDoryFr::from_u64(3),
            BlsDoryFr::from_u64(5),
            BlsDoryFr::from_u64(7),
        ]
    }

    #[test]
    fn raw_and_signed_tables_differ_by_exact_constant_offset() {
        let raw = [0_u8, 1, 2, 3, 247, 248, 249, 250];
        let point = point();
        let raw_evaluation = evaluate_raw_activation_mle(&raw, &point).unwrap();
        let signed = raw
            .iter()
            .map(|value| BlsDoryFr::from_i64(i64::from(*value) - 125))
            .collect::<Vec<_>>();
        let mut layer = signed;
        for coordinate in &point {
            for index in 0..layer.len() / 2 {
                let low = layer[2 * index];
                let high = layer[2 * index + 1];
                layer[index] = low + (high - low) * coordinate;
            }
            layer.truncate(layer.len() / 2);
        }
        assert_eq!(
            raw_evaluation,
            layer[0] + BlsDoryFr::from_u64(ACTIVATION_BYTE_OFFSET)
        );
    }

    #[test]
    fn activation_shape_range_and_substitution_fail_closed() {
        let point = point();
        assert_eq!(
            evaluate_raw_activation_mle(&[0; 4], &point),
            Err(BlsDoryOutputBridgeError::Shape)
        );
        let mut invalid = [0_u8; 8];
        invalid[3] = 251;
        assert_eq!(
            evaluate_raw_activation_mle(&invalid, &point),
            Err(BlsDoryOutputBridgeError::ActivationByte)
        );

        let raw = [0_u8, 1, 2, 3, 4, 5, 6, 7];
        let evaluation = evaluate_raw_activation_mle(&raw, &point).unwrap();
        let statement = BlsDoryOutputBridgeStatement::new(
            [1; 32],
            [2; 32],
            raw.len(),
            [3; 32],
            point,
            evaluation - BlsDoryFr::from_u64(ACTIVATION_BYTE_OFFSET),
        )
        .unwrap();
        statement.validate_activation(&raw).unwrap();
        let mut changed = raw;
        changed[6] ^= 1;
        assert_eq!(
            statement.validate_activation(&changed),
            Err(BlsDoryOutputBridgeError::Evaluation)
        );
    }

    #[test]
    fn scalar_limbs_are_canonical_little_endian() {
        let limbs = bls_dory_scalar_limbs(BlsDoryFr::from_u64(0x1122_3344_5566_7788));
        assert_eq!(limbs[0], 0x5566_7788);
        assert_eq!(limbs[1], 0x1122_3344);
        assert!(limbs[2..].iter().all(|limb| *limb == 0));
    }
}
