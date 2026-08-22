use std::sync::Arc;

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BlockChallenge, ForgeMatrixError, ForgeMatrixProfile, ForgeMatrixProof,
    ForgeMatrixV2AcceleratorBatch, ForgeMatrixV2AcceleratorModel, ForgeMatrixV2CompactProof,
    ForgeMatrixV2Descriptor, ForgeMatrixV2Error, ForgeMatrixV2Reference, ForgeMatrixVerifier,
};

pub const POW_TYPE_V1_LEGACY: u16 = 1;
pub const POW_TYPE_V2_REFERENCE: u16 = 2;
/// Reserved wire identity for the fail-closed structured production candidate.
pub const POW_TYPE_V3_CANDIDATE: u16 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowParameters {
    V1Legacy(ForgeMatrixProfile),
    V2Reference(ForgeMatrixV2Descriptor),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockProof {
    V1Legacy(ForgeMatrixProof),
    V2Reference(ForgeMatrixV2CompactProof),
    /// Length-bounded production candidate. No consensus verifier can select
    /// this variant until the final model and proof parameters are pinned.
    V3Candidate(Box<ForgeMatrixV3CandidateProof>),
}

/// Existing V2 public fields plus one canonical structured aggregate encoding.
///
/// The aggregate stays opaque at the block framing layer so expensive parsing
/// and cryptographic verification can run in a separately bounded verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeMatrixV3CandidateProof {
    pub algorithm_version: u32,
    pub proof_version: u32,
    pub nonce: u64,
    pub model_manifest_digest: [u8; 32],
    pub challenge_digest: [u8; 32],
    pub final_activation_digest: [u8; 32],
    pub work_digest: [u8; 32],
    pub structured_proof: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PowError {
    #[error("legacy ForgeMatrix v1 failed: {0}")]
    V1(#[from] ForgeMatrixError),
    #[error("ForgeMatrix v2 reference verification failed: {0}")]
    V2(#[from] ForgeMatrixV2Error),
    #[error("block proof type does not match the network proof parameters")]
    WrongProofType,
    #[error("proof verifier identity does not match the network parameters")]
    ParameterMismatch,
    #[error("ForgeMatrix v2 descriptor belongs to another network")]
    WrongNetwork,
}

#[derive(Debug, Clone)]
pub enum ConsensusPowVerifier {
    V1Legacy(Arc<ForgeMatrixVerifier>),
    V2Reference(Arc<ForgeMatrixV2Reference>),
}

impl PowParameters {
    pub fn validate(self, network_id: [u8; 32]) -> Result<(), PowError> {
        match self {
            Self::V1Legacy(profile) => {
                ForgeMatrixVerifier::new(profile)?;
            }
            Self::V2Reference(descriptor) => {
                if descriptor.network_id != network_id {
                    return Err(PowError::WrongNetwork);
                }
                descriptor.validate_research()?;
            }
        }
        Ok(())
    }

    pub(crate) fn absorb(self, network_id: [u8; 32], hasher: &mut Hasher) -> Result<(), PowError> {
        match self {
            Self::V1Legacy(profile) => {
                hasher.update(&POW_TYPE_V1_LEGACY.to_le_bytes());
                hasher.update(&profile.algorithm_version.to_le_bytes());
                hasher.update(&profile.model_version.to_le_bytes());
                hasher.update(&profile.dimension.to_le_bytes());
                hasher.update(&profile.batch.to_le_bytes());
                hasher.update(&profile.layers.to_le_bytes());
                hasher.update(&profile.model_seed);
                let verifier = ForgeMatrixVerifier::new(profile)?;
                hasher.update(&verifier.model_root());
            }
            Self::V2Reference(descriptor) => {
                if descriptor.network_id != network_id {
                    return Err(PowError::WrongNetwork);
                }
                descriptor.validate_research()?;
                hasher.update(&POW_TYPE_V2_REFERENCE.to_le_bytes());
                hasher.update(&descriptor.network_id);
                hasher.update(&descriptor.algorithm_version.to_le_bytes());
                hasher.update(&descriptor.proof_version.to_le_bytes());
                hasher.update(&descriptor.banks.to_le_bytes());
                hasher.update(&descriptor.layers_per_bank.to_le_bytes());
                let manifest_digest = descriptor
                    .model
                    .digest()
                    .map_err(ForgeMatrixV2Error::from)?;
                hasher.update(&manifest_digest);
            }
        }
        Ok(())
    }
}

impl BlockProof {
    pub fn proof_type(&self) -> u16 {
        match self {
            Self::V1Legacy(_) => POW_TYPE_V1_LEGACY,
            Self::V2Reference(_) => POW_TYPE_V2_REFERENCE,
            Self::V3Candidate(_) => POW_TYPE_V3_CANDIDATE,
        }
    }

    /// Returns the committed work digest by value so callers cannot mutate a
    /// proof through the accessor.
    pub fn work_digest(&self) -> [u8; 32] {
        match self {
            Self::V1Legacy(proof) => proof.work_digest,
            Self::V2Reference(proof) => proof.work_digest,
            Self::V3Candidate(proof) => proof.work_digest,
        }
    }

    pub(crate) fn absorb(&self, hasher: &mut Hasher) {
        hasher.update(&self.proof_type().to_le_bytes());
        match self {
            Self::V1Legacy(proof) => {
                hasher.update(&proof.algorithm_version.to_le_bytes());
                hasher.update(&proof.model_version.to_le_bytes());
                hasher.update(&proof.nonce.to_le_bytes());
                hasher.update(&proof.model_root);
                hasher.update(&proof.output_digest);
                hasher.update(&proof.work_digest);
            }
            Self::V2Reference(proof) => {
                hasher.update(&proof.algorithm_version.to_le_bytes());
                hasher.update(&proof.proof_version.to_le_bytes());
                hasher.update(&proof.nonce.to_le_bytes());
                hasher.update(&proof.model_manifest_digest);
                hasher.update(&proof.challenge_digest);
                hasher.update(&proof.final_activation_digest);
                hasher.update(&proof.work_digest);
            }
            Self::V3Candidate(proof) => {
                hasher.update(&proof.algorithm_version.to_le_bytes());
                hasher.update(&proof.proof_version.to_le_bytes());
                hasher.update(&proof.nonce.to_le_bytes());
                hasher.update(&proof.model_manifest_digest);
                hasher.update(&proof.challenge_digest);
                hasher.update(&proof.final_activation_digest);
                hasher.update(&proof.work_digest);
                hasher.update(&(proof.structured_proof.len() as u64).to_le_bytes());
                hasher.update(&proof.structured_proof);
            }
        }
    }
}

impl ConsensusPowVerifier {
    pub fn v1_legacy(profile: ForgeMatrixProfile) -> Result<Self, PowError> {
        Ok(Self::V1Legacy(Arc::new(ForgeMatrixVerifier::new(profile)?)))
    }

    pub fn v2_reference(reference: ForgeMatrixV2Reference) -> Self {
        Self::V2Reference(Arc::new(reference))
    }

    pub fn parameters(&self) -> PowParameters {
        match self {
            Self::V1Legacy(verifier) => PowParameters::V1Legacy(verifier.profile()),
            Self::V2Reference(reference) => PowParameters::V2Reference(reference.descriptor()),
        }
    }

    pub fn verify(&self, block: &BlockChallenge, proof: &BlockProof) -> Result<(), PowError> {
        match (self, proof) {
            (Self::V1Legacy(verifier), BlockProof::V1Legacy(proof)) => {
                verifier.verify(block, proof)?;
                Ok(())
            }
            (Self::V2Reference(reference), BlockProof::V2Reference(proof)) => {
                reference.verify_compact(block, proof)?;
                Ok(())
            }
            _ => Err(PowError::WrongProofType),
        }
    }

    /// Deterministically evaluates the configured proof relation for one
    /// nonce. This deliberately does not apply `block.target`; it is suitable
    /// for recomputing pool shares, not for accepting blocks.
    pub fn evaluate(&self, block: &BlockChallenge, nonce: u64) -> Result<BlockProof, PowError> {
        match self {
            Self::V1Legacy(verifier) => Ok(BlockProof::V1Legacy(verifier.prove(block, nonce))),
            Self::V2Reference(reference) => Ok(BlockProof::V2Reference(
                reference.prove_compact(block, nonce)?,
            )),
        }
    }

    /// Returns the explicit tiny v2 model for an optional untrusted mining
    /// accelerator. Legacy v1 has no accelerator contract.
    pub fn v2_accelerator_model(&self) -> Result<ForgeMatrixV2AcceleratorModel, PowError> {
        match self {
            Self::V2Reference(reference) => Ok(reference.accelerator_model()),
            Self::V1Legacy(_) => Err(PowError::WrongProofType),
        }
    }

    pub fn prepare_v2_accelerator_batch(
        &self,
        block: &BlockChallenge,
        start_nonce: u64,
        count: u32,
    ) -> Result<ForgeMatrixV2AcceleratorBatch, PowError> {
        match self {
            Self::V2Reference(reference) => {
                Ok(reference.prepare_accelerator_batch(block, start_nonce, count)?)
            }
            Self::V1Legacy(_) => Err(PowError::WrongProofType),
        }
    }

    pub fn verify_v2_accelerator_candidate(
        &self,
        block: &BlockChallenge,
        batch: &ForgeMatrixV2AcceleratorBatch,
        index: usize,
        claimed_work_digest: [u8; 32],
    ) -> Result<BlockProof, PowError> {
        match self {
            Self::V2Reference(reference) => Ok(BlockProof::V2Reference(
                reference.verify_accelerator_candidate(block, batch, index, claimed_work_digest)?,
            )),
            Self::V1Legacy(_) => Err(PowError::WrongProofType),
        }
    }

    pub fn validate_v2_accelerator_batch(
        &self,
        block: &BlockChallenge,
        batch: &ForgeMatrixV2AcceleratorBatch,
    ) -> Result<(), PowError> {
        match self {
            Self::V2Reference(reference)
                if batch.matches_statement(reference.descriptor(), block) =>
            {
                Ok(())
            }
            Self::V2Reference(_) => Err(PowError::ParameterMismatch),
            Self::V1Legacy(_) => Err(PowError::WrongProofType),
        }
    }

    /// Recomputes and verifies the configured committed proof relation while
    /// intentionally leaving target enforcement to the caller. Consensus
    /// block validation must continue to call [`Self::verify`].
    pub fn verify_evaluation(
        &self,
        block: &BlockChallenge,
        proof: &BlockProof,
    ) -> Result<(), PowError> {
        match (self, proof) {
            (Self::V1Legacy(verifier), BlockProof::V1Legacy(proof)) => {
                verifier.verify_relation(block, proof)?;
                Ok(())
            }
            (Self::V2Reference(reference), BlockProof::V2Reference(proof)) => {
                reference.verify_compact_relation(block, proof)?;
                Ok(())
            }
            _ => Err(PowError::WrongProofType),
        }
    }

    pub fn mine(
        &self,
        block: &BlockChallenge,
        start_nonce: u64,
        attempts: u64,
    ) -> Result<BlockProof, PowError> {
        match self {
            Self::V1Legacy(verifier) => Ok(BlockProof::V1Legacy(verifier.mine(
                block,
                start_nonce,
                attempts,
            )?)),
            Self::V2Reference(reference) => Ok(BlockProof::V2Reference(reference.mine_compact(
                block,
                start_nonce,
                attempts,
            )?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TEST_PROFILE, v2_test_reference};

    fn block(network_id: [u8; 32]) -> BlockChallenge {
        BlockChallenge {
            network_id,
            previous_block: [1; 32],
            transaction_root: [2; 32],
            height: 1,
            timestamp: 60,
            target: [0xff; 32],
        }
    }

    #[test]
    fn configured_verifier_rejects_the_other_proof_type() {
        let v1 = ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap();
        let v2_reference = v2_test_reference().unwrap();
        let v2_network = v2_reference.descriptor().network_id;
        let v2_proof =
            BlockProof::V2Reference(v2_reference.prove_compact(&block(v2_network), 0).unwrap());
        assert!(matches!(
            v1.verify(&block(v2_network), &v2_proof),
            Err(PowError::WrongProofType)
        ));
    }

    #[test]
    fn compact_v2_mines_and_verifies_through_the_common_interface() {
        let reference = v2_test_reference().unwrap();
        let network_id = reference.descriptor().network_id;
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let proof = verifier.mine(&block(network_id), 7, 1).unwrap();
        verifier.verify(&block(network_id), &proof).unwrap();
        assert_eq!(proof.proof_type(), POW_TYPE_V2_REFERENCE);
    }
}
