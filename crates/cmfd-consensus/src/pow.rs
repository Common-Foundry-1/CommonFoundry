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
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const FORGEMATRIX_V3_BLOCK_ID_PROOF_FIELDS: &str = "pow_type_u16le,algorithm_version_u32le,proof_version_u32le,nonce_u64le,model_manifest_digest[32],challenge_digest[32],final_activation_digest[32],work_digest[32],structured_length_u64le,structured_bytes";
const PREVERIFIED_VERIFIER_DOMAIN: &str = "CMFD/POW/PREVERIFIED-VERIFIER/V1";
const PREVERIFIED_STATEMENT_DOMAIN: &str = "CMFD/POW/PREVERIFIED-STATEMENT/V1";

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

/// Process-local evidence that the configured verifier accepted one exact
/// challenge and proof.
///
/// The fields are deliberately private and this type implements neither
/// serialization nor a public constructor. Network bytes can therefore never
/// manufacture the capability used by the chain's preverified path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreverifiedBlockProof {
    verifier_identity: [u8; 32],
    statement_identity: [u8; 32],
}

/// Exact verifier and statement identities transported across a trusted
/// external-verifier boundary.
///
/// This is not proof of verification by itself. It exists so a process runner
/// can bind a worker response to the exact consensus verifier, challenge, and
/// proof bytes requested by the parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalPreverificationBinding {
    verifier_identity: [u8; 32],
    statement_identity: [u8; 32],
}

impl ExternalPreverificationBinding {
    pub fn verifier_identity(self) -> [u8; 32] {
        self.verifier_identity
    }

    pub fn statement_identity(self) -> [u8; 32] {
        self.statement_identity
    }
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
    #[error("preverified proof does not match the verifier, challenge, or proof bytes")]
    PreverificationMismatch,
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

    /// Performs the expensive proof verification and returns a process-local
    /// capability bound to this verifier and the exact statement bytes.
    pub fn preverify(
        &self,
        block: &BlockChallenge,
        proof: &BlockProof,
    ) -> Result<PreverifiedBlockProof, PowError> {
        self.verify(block, proof)?;
        Ok(PreverifiedBlockProof {
            verifier_identity: self.preverification_identity(block.network_id)?,
            statement_identity: preverified_statement_identity(block, proof),
        })
    }

    /// Returns the exact identities an external verifier must echo after
    /// validating this statement with this configured verifier.
    pub fn external_preverification_binding(
        &self,
        block: &BlockChallenge,
        proof: &BlockProof,
    ) -> Result<ExternalPreverificationBinding, PowError> {
        self.require_matching_proof_type(proof)?;
        Ok(ExternalPreverificationBinding {
            verifier_identity: self.preverification_identity(block.network_id)?,
            statement_identity: preverified_statement_identity(block, proof),
        })
    }

    /// Issues the process-local capability after a trusted external verifier
    /// has accepted the exact bound statement.
    ///
    /// # Safety
    ///
    /// The caller must have obtained `binding` from a fail-closed verifier
    /// process whose executable identity, canonical request/response, exit
    /// status, execution time, memory, and output were independently bounded.
    /// Calling this based only on untrusted bytes bypasses proof verification.
    pub unsafe fn issue_external_preverification(
        &self,
        block: &BlockChallenge,
        proof: &BlockProof,
        binding: ExternalPreverificationBinding,
    ) -> Result<PreverifiedBlockProof, PowError> {
        let expected = self.external_preverification_binding(block, proof)?;
        if binding != expected {
            return Err(PowError::PreverificationMismatch);
        }
        Ok(PreverifiedBlockProof {
            verifier_identity: binding.verifier_identity,
            statement_identity: binding.statement_identity,
        })
    }

    pub(crate) fn verify_preverified(
        &self,
        block: &BlockChallenge,
        proof: &BlockProof,
        preverified: &PreverifiedBlockProof,
    ) -> Result<(), PowError> {
        self.require_matching_proof_type(proof)?;
        if preverified.verifier_identity != self.preverification_identity(block.network_id)?
            || preverified.statement_identity != preverified_statement_identity(block, proof)
        {
            return Err(PowError::PreverificationMismatch);
        }
        Ok(())
    }

    fn require_matching_proof_type(&self, proof: &BlockProof) -> Result<(), PowError> {
        if matches!(
            (self, proof),
            (Self::V1Legacy(_), BlockProof::V1Legacy(_))
                | (Self::V2Reference(_), BlockProof::V2Reference(_))
        ) {
            Ok(())
        } else {
            Err(PowError::WrongProofType)
        }
    }

    fn preverification_identity(&self, network_id: [u8; 32]) -> Result<[u8; 32], PowError> {
        let mut hasher = Hasher::new_derive_key(PREVERIFIED_VERIFIER_DOMAIN);
        self.parameters().absorb(network_id, &mut hasher)?;
        Ok(*hasher.finalize().as_bytes())
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

    /// Returns the committed identity of the model bytes expected by the v2
    /// accelerator contract.
    pub fn v2_accelerator_model_identity(&self) -> Result<[u8; 32], PowError> {
        match self {
            Self::V2Reference(reference) => Ok(reference.accelerator_model_identity()?),
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

fn preverified_statement_identity(block: &BlockChallenge, proof: &BlockProof) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(PREVERIFIED_STATEMENT_DOMAIN);
    hasher.update(&block.network_id);
    hasher.update(&block.previous_block);
    hasher.update(&block.transaction_root);
    hasher.update(&block.height.to_le_bytes());
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(&block.target);
    proof.absorb(&mut hasher);
    *hasher.finalize().as_bytes()
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

    #[test]
    fn preverification_capability_is_bound_to_verifier_challenge_and_proof() {
        let reference = v2_test_reference().unwrap();
        let network_id = reference.descriptor().network_id;
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let challenge = block(network_id);
        let proof = verifier.mine(&challenge, 7, 1).unwrap();
        let preverified = verifier.preverify(&challenge, &proof).unwrap();
        verifier
            .verify_preverified(&challenge, &proof, &preverified)
            .unwrap();

        let mut changed_challenge = challenge;
        changed_challenge.timestamp += 1;
        assert!(matches!(
            verifier.verify_preverified(&changed_challenge, &proof, &preverified),
            Err(PowError::PreverificationMismatch)
        ));

        let mut changed_proof = proof;
        let BlockProof::V2Reference(proof) = &mut changed_proof else {
            unreachable!();
        };
        proof.work_digest[0] ^= 1;
        assert!(matches!(
            verifier.verify_preverified(&challenge, &changed_proof, &preverified),
            Err(PowError::PreverificationMismatch)
        ));

        let legacy = ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap();
        assert!(matches!(
            legacy.verify_preverified(&challenge, &changed_proof, &preverified),
            Err(PowError::WrongProofType)
        ));
    }

    #[test]
    fn external_preverification_issuance_rechecks_the_exact_binding() {
        let reference = v2_test_reference().unwrap();
        let network_id = reference.descriptor().network_id;
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let challenge = block(network_id);
        let proof = verifier.mine(&challenge, 7, 1).unwrap();
        let binding = verifier
            .external_preverification_binding(&challenge, &proof)
            .unwrap();

        // SAFETY: this unit test models a successful external verifier and
        // immediately checks the resulting capability through consensus.
        let preverified = unsafe {
            verifier
                .issue_external_preverification(&challenge, &proof, binding)
                .unwrap()
        };
        verifier
            .verify_preverified(&challenge, &proof, &preverified)
            .unwrap();

        let mut substituted = binding;
        substituted.statement_identity[0] ^= 1;
        // SAFETY: the deliberately substituted binding must be rejected before
        // any capability is issued.
        assert!(matches!(
            unsafe { verifier.issue_external_preverification(&challenge, &proof, substituted) },
            Err(PowError::PreverificationMismatch)
        ));
    }

    #[test]
    fn external_preverification_rejects_v3_before_binding_or_capability_use() {
        let reference = v2_test_reference().unwrap();
        let network_id = reference.descriptor().network_id;
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let challenge = block(network_id);
        let v2_proof = verifier.mine(&challenge, 7, 1).unwrap();
        let preverified = verifier.preverify(&challenge, &v2_proof).unwrap();
        let v3_proof = BlockProof::V3Candidate(Box::new(ForgeMatrixV3CandidateProof {
            algorithm_version: 2,
            proof_version: 1,
            nonce: 7,
            model_manifest_digest: [1; 32],
            challenge_digest: [2; 32],
            final_activation_digest: [3; 32],
            work_digest: [4; 32],
            structured_proof: vec![5],
        }));

        assert!(matches!(
            verifier.external_preverification_binding(&challenge, &v3_proof),
            Err(PowError::WrongProofType)
        ));
        assert!(matches!(
            verifier.verify_preverified(&challenge, &v3_proof, &preverified),
            Err(PowError::WrongProofType)
        ));

        let forged_binding = ExternalPreverificationBinding {
            verifier_identity: [6; 32],
            statement_identity: [7; 32],
        };
        // SAFETY: the deliberately incompatible proof type must be rejected
        // before the untrusted binding is compared or any capability exists.
        assert!(matches!(
            unsafe {
                verifier.issue_external_preverification(&challenge, &v3_proof, forged_binding)
            },
            Err(PowError::WrongProofType)
        ));
    }
}
