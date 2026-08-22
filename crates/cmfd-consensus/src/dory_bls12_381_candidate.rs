//! Non-consensus verifier boundary for the production-shaped BLS/Dory algebraic proof.
//!
//! This module intentionally cannot produce [`crate::PreverifiedBlockProof`].
//! The shared Dory layout proves the ForgeMatrix arithmetic and wiring, but it
//! does not yet prove that the final activation hashed by the BLAKE3 argument
//! is the same table authenticated by Dory. Returning success here therefore
//! means "algebraic candidate verified", not "block proof verified".

use std::sync::Arc;

use thiserror::Error;

use crate::{
    BlockChallenge, ForgeMatrixV2Descriptor, ForgeMatrixV3CandidateProof, ModelBankError,
    ModelBankManifest, ModelPcsIdentity, POW_TYPE_V3_CANDIDATE, PRODUCTION_V2_BANKS,
    PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    PRODUCTION_V2_LAYERS_PER_BANK, StructuredMaskPolynomial, StructuredMatrixStatement,
    StructuredTransitionError, StructuredTransitionStatement, StructuredWiringStatement,
    dory_bls12_381_layout::{
        BLS_DORY_SHARED_PRODUCTION_VARIABLES, BlsDoryFixedModelIdentity, BlsDorySharedLayoutError,
        BlsDorySharedLayoutProof, verify_bls_dory_shared_layout_at_variables,
    },
    dory_bls12_381_model_commitment::{
        BlsDoryModelCommitmentRecord, BlsDoryModelCommitmentRecordError,
    },
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    forgematrix_v2::{
        FORGEMATRIX_V2_ALGORITHM_VERSION, FORGEMATRIX_V2_PROOF_VERSION, challenge_digest,
        work_digest_from_roots,
    },
    structured_proof::StructuredForgeMatrixResearchShape,
    wire::MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
};

const ALGEBRAIC_BINDING_VERSION: u16 = 1;
const ALGEBRAIC_BINDING_DOMAIN: &str = "CommonFoundry/ForgeMatrix/V3/BlsDoryAlgebraicBinding/v1";

/// Production-shaped verifier for only the algebraic portion of a V3 candidate.
///
/// Construction requires an authenticated fixed-model commitment record and
/// exact n=33 setup. The final hash/table link remains deliberately outside
/// this type so it cannot be mistaken for a consensus verifier.
pub struct BlsDoryV3AlgebraicVerifier {
    network_id: [u8; 32],
    manifest: ModelBankManifest,
    trusted_model: ModelPcsIdentity,
    fixed_model: BlsDoryFixedModelIdentity,
    record_digest: [u8; 32],
    setup: Arc<DeterministicBlsDorySetup>,
}

/// Opaque evidence that one exact candidate passed only the Dory algebraic checks.
///
/// This value is intentionally unrelated to the chain-admission capability.
/// Its binding is exposed only for diagnostics and later hash-bridge composition.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBlsDoryV3AlgebraicCandidate {
    binding: [u8; 32],
    proof_digest: [u8; 32],
}

impl VerifiedBlsDoryV3AlgebraicCandidate {
    /// Exact public binding accepted by the algebraic verifier.
    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    /// Digest of the exact structured Dory bytes that were verified.
    pub const fn proof_digest(&self) -> [u8; 32] {
        self.proof_digest
    }
}

#[derive(Debug, Error)]
pub enum BlsDoryV3CandidateError {
    #[error("the V3 algebraic verifier requires a nonzero network identity")]
    NetworkIdentity,
    #[error("the block belongs to a different network")]
    WrongNetwork,
    #[error("the commitment record does not describe the exact production geometry")]
    ProductionGeometry,
    #[error("the fixed-model commitment record is invalid: {0}")]
    ModelRecord(#[from] BlsDoryModelCommitmentRecordError),
    #[error("the model manifest or PCS identity is invalid: {0}")]
    Model(#[from] ModelBankError),
    #[error("candidate algorithm version mismatch")]
    AlgorithmVersion,
    #[error("candidate proof version mismatch")]
    ProofVersion,
    #[error("candidate model-manifest digest mismatch")]
    ModelManifestDigest,
    #[error("candidate challenge digest mismatch")]
    ChallengeDigest,
    #[error("candidate work digest mismatch")]
    WorkDigest,
    #[error("candidate work digest does not meet the block target")]
    HighHash,
    #[error("candidate structured proof is empty or exceeds its wire allowance")]
    ProofSize,
    #[error("candidate mask derivation failed: {0}")]
    Mask(#[from] StructuredTransitionError),
    #[error("candidate Dory proof failed: {0}")]
    Dory(#[from] BlsDorySharedLayoutError),
}

impl BlsDoryV3AlgebraicVerifier {
    /// Pin one authenticated production model and its exact deterministic setup.
    pub fn new(
        network_id: [u8; 32],
        record: &BlsDoryModelCommitmentRecord,
        setup: Arc<DeterministicBlsDorySetup>,
    ) -> Result<Self, BlsDoryV3CandidateError> {
        if network_id == [0; 32] {
            return Err(BlsDoryV3CandidateError::NetworkIdentity);
        }
        record.validate(&setup)?;
        validate_production_record(record, &setup)?;
        Ok(Self {
            network_id,
            manifest: record.manifest,
            trusted_model: record.model_pcs_identity.clone(),
            fixed_model: record.fixed_identity()?,
            record_digest: record.canonical_digest()?,
            setup,
        })
    }

    /// Verify the exact block/public fields and the real shared Dory payload.
    ///
    /// Success deliberately does not establish the final-activation BLAKE3
    /// relation and is therefore insufficient for chain admission.
    pub fn verify_algebraic_candidate(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixV3CandidateProof,
    ) -> Result<VerifiedBlsDoryV3AlgebraicCandidate, BlsDoryV3CandidateError> {
        if block.network_id != self.network_id {
            return Err(BlsDoryV3CandidateError::WrongNetwork);
        }
        if proof.algorithm_version != FORGEMATRIX_V2_ALGORITHM_VERSION {
            return Err(BlsDoryV3CandidateError::AlgorithmVersion);
        }
        if proof.proof_version != FORGEMATRIX_V2_PROOF_VERSION {
            return Err(BlsDoryV3CandidateError::ProofVersion);
        }
        if proof.structured_proof.is_empty()
            || proof.structured_proof.len() > MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
        {
            return Err(BlsDoryV3CandidateError::ProofSize);
        }
        let manifest_digest = self.manifest.digest()?;
        if proof.model_manifest_digest != manifest_digest {
            return Err(BlsDoryV3CandidateError::ModelManifestDigest);
        }
        let descriptor = ForgeMatrixV2Descriptor {
            network_id: self.network_id,
            algorithm_version: FORGEMATRIX_V2_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V2_PROOF_VERSION,
            banks: PRODUCTION_V2_BANKS,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model: self.manifest,
        };
        let expected_challenge = challenge_digest(&descriptor, block, proof.nonce)
            .map_err(|_| BlsDoryV3CandidateError::ChallengeDigest)?;
        if proof.challenge_digest != expected_challenge {
            return Err(BlsDoryV3CandidateError::ChallengeDigest);
        }
        let expected_work = work_digest_from_roots(
            expected_challenge,
            self.manifest.raw_blake3_root,
            self.manifest.pcs_commitment_root,
            proof.final_activation_digest,
        );
        if proof.work_digest != expected_work {
            return Err(BlsDoryV3CandidateError::WorkDigest);
        }
        if proof.work_digest > block.target {
            return Err(BlsDoryV3CandidateError::HighHash);
        }

        let binding = algebraic_binding(
            self.network_id,
            self.record_digest,
            manifest_digest,
            block,
            proof,
        );
        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        shape
            .validate_verifier_shape()
            .map_err(|_| BlsDoryV3CandidateError::ProductionGeometry)?;
        let matrix_statements = shape.matrix_statements;
        let mut transition_statements = Vec::with_capacity(PRODUCTION_V2_BANKS as usize + 1);
        transition_statements.push(shape.initialization_statement);
        transition_statements.extend_from_slice(&shape.transition_statements);
        let masks = production_masks(expected_challenge, &shape)?;
        let mask_refs = masks.iter().collect::<Vec<_>>();
        verify_algebraic_payload(
            &binding,
            &self.trusted_model,
            &self.fixed_model,
            &matrix_statements,
            &transition_statements,
            &mask_refs,
            shape.wiring_statement,
            &proof.structured_proof,
            BLS_DORY_SHARED_PRODUCTION_VARIABLES,
            &self.setup,
        )?;
        let mut proof_hasher =
            blake3::Hasher::new_derive_key("CommonFoundry/ForgeMatrix/V3/BlsDoryAlgebraicProof/v1");
        proof_hasher.update(&binding);
        proof_hasher.update(&(proof.structured_proof.len() as u64).to_le_bytes());
        proof_hasher.update(&proof.structured_proof);
        Ok(VerifiedBlsDoryV3AlgebraicCandidate {
            binding,
            proof_digest: *proof_hasher.finalize().as_bytes(),
        })
    }
}

fn validate_production_record(
    record: &BlsDoryModelCommitmentRecord,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDoryV3CandidateError> {
    let manifest = record.manifest;
    let model = &record.model_pcs_identity;
    manifest.verify_pcs_identity(model)?;
    if setup.max_log_n() != BLS_DORY_SHARED_PRODUCTION_VARIABLES
        || usize::try_from(record.padded_variables).ok()
            != Some(BLS_DORY_SHARED_PRODUCTION_VARIABLES)
        || manifest.model_version != 2
        || manifest.batch != PRODUCTION_V2_BATCH
        || manifest.dimension != PRODUCTION_V2_DIMENSION
        || manifest.layers != PRODUCTION_V2_LAYERS
        || model.model_version != manifest.model_version
        || model.batch != PRODUCTION_V2_BATCH
        || model.dimension != PRODUCTION_V2_DIMENSION
        || model.layers_per_bank != PRODUCTION_V2_LAYERS_PER_BANK
        || model.weight_bank_commitments.len() != PRODUCTION_V2_BANKS as usize
    {
        return Err(BlsDoryV3CandidateError::ProductionGeometry);
    }
    Ok(())
}

fn production_masks(
    challenge: [u8; 32],
    shape: &StructuredForgeMatrixResearchShape,
) -> Result<Vec<StructuredMaskPolynomial>, StructuredTransitionError> {
    let mut masks = Vec::with_capacity(PRODUCTION_V2_BANKS as usize + 1);
    masks.push(StructuredMaskPolynomial::from_virtual_challenge(
        &challenge,
        shape.initialization_statement.rows,
        shape.initialization_statement.cols,
    )?);
    for (bank, statement) in shape.transition_statements.iter().enumerate() {
        let first_layer = u32::try_from(bank)
            .ok()
            .and_then(|bank| bank.checked_mul(PRODUCTION_V2_LAYERS_PER_BANK))
            .ok_or(StructuredTransitionError::ArithmeticOverflow)?;
        masks.push(StructuredMaskPolynomial::from_challenge_at_layer_offset(
            &challenge,
            first_layer,
            statement.layers,
            statement.rows,
            statement.cols,
        )?);
    }
    Ok(masks)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_algebraic_payload(
    binding: &[u8],
    trusted_model: &ModelPcsIdentity,
    fixed_model: &BlsDoryFixedModelIdentity,
    matrix_statements: &[StructuredMatrixStatement],
    transition_statements: &[StructuredTransitionStatement],
    masks: &[&StructuredMaskPolynomial],
    wiring_statement: StructuredWiringStatement,
    encoded: &[u8],
    padded_variables: usize,
    setup: &DeterministicBlsDorySetup,
) -> Result<(), BlsDorySharedLayoutError> {
    let proof = BlsDorySharedLayoutProof::decode_with_variables(
        encoded,
        matrix_statements,
        transition_statements,
        wiring_statement,
        padded_variables,
    )?;
    verify_bls_dory_shared_layout_at_variables(
        binding,
        trusted_model,
        fixed_model,
        matrix_statements,
        transition_statements,
        masks,
        wiring_statement,
        &proof,
        padded_variables,
        setup,
    )
}

fn algebraic_binding(
    network_id: [u8; 32],
    record_digest: [u8; 32],
    manifest_digest: [u8; 32],
    block: &BlockChallenge,
    proof: &ForgeMatrixV3CandidateProof,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ALGEBRAIC_BINDING_DOMAIN);
    hasher.update(&ALGEBRAIC_BINDING_VERSION.to_le_bytes());
    hasher.update(&POW_TYPE_V3_CANDIDATE.to_le_bytes());
    hasher.update(&network_id);
    hasher.update(&proof.algorithm_version.to_le_bytes());
    hasher.update(&proof.proof_version.to_le_bytes());
    hasher.update(&record_digest);
    hasher.update(&manifest_digest);
    hasher.update(&block.previous_block);
    hasher.update(&block.transaction_root);
    hasher.update(&block.height.to_le_bytes());
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(&block.target);
    hasher.update(&proof.nonce.to_le_bytes());
    hasher.update(&proof.challenge_digest);
    hasher.update(&proof.final_activation_digest);
    hasher.update(&proof.work_digest);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> BlockChallenge {
        BlockChallenge {
            network_id: [0x31; 32],
            previous_block: [0x42; 32],
            transaction_root: [0x53; 32],
            height: 17,
            timestamp: 23,
            target: [0xff; 32],
        }
    }

    fn proof() -> ForgeMatrixV3CandidateProof {
        ForgeMatrixV3CandidateProof {
            algorithm_version: FORGEMATRIX_V2_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V2_PROOF_VERSION,
            nonce: 29,
            model_manifest_digest: [0x64; 32],
            challenge_digest: [0x75; 32],
            final_activation_digest: [0x86; 32],
            work_digest: [0x97; 32],
            structured_proof: vec![1],
        }
    }

    #[test]
    fn algebraic_binding_commits_every_block_and_public_proof_field() {
        let network = [0x31; 32];
        let record = [0xa8; 32];
        let manifest = [0xb9; 32];
        let base_block = block();
        let base_proof = proof();
        let expected = algebraic_binding(network, record, manifest, &base_block, &base_proof);

        type Mutation = fn(&mut BlockChallenge, &mut ForgeMatrixV3CandidateProof);
        let mutations: [Mutation; 11] = [
            |block, _| block.previous_block[0] ^= 1,
            |block, _| block.transaction_root[0] ^= 1,
            |block, _| block.height ^= 1,
            |block, _| block.timestamp ^= 1,
            |block, _| block.target[0] ^= 1,
            |_, proof| proof.algorithm_version ^= 1,
            |_, proof| proof.proof_version ^= 1,
            |_, proof| proof.nonce ^= 1,
            |_, proof| proof.challenge_digest[0] ^= 1,
            |_, proof| proof.final_activation_digest[0] ^= 1,
            |_, proof| proof.work_digest[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed_block = base_block;
            let mut changed_proof = base_proof.clone();
            mutate(&mut changed_block, &mut changed_proof);
            assert_ne!(
                algebraic_binding(network, record, manifest, &changed_block, &changed_proof),
                expected
            );
        }
        assert_ne!(
            algebraic_binding([0x30; 32], record, manifest, &base_block, &base_proof),
            expected
        );
        assert_ne!(
            algebraic_binding(network, [0xa9; 32], manifest, &base_block, &base_proof),
            expected
        );
        assert_ne!(
            algebraic_binding(network, record, [0xb8; 32], &base_block, &base_proof),
            expected
        );
    }

    #[test]
    fn pow_parameters_still_have_no_v3_selector() {
        let parameters =
            crate::PowParameters::V2Reference(crate::v2_test_reference().unwrap().descriptor());
        assert!(matches!(parameters, crate::PowParameters::V2Reference(_)));
    }
}
