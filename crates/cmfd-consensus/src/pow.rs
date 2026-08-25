use std::sync::Arc;

#[cfg(feature = "dory-v3-consensus-adapter")]
use std::fmt;

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BlockChallenge, ForgeMatrixError, ForgeMatrixProfile, ForgeMatrixProof,
    ForgeMatrixV2AcceleratorBatch, ForgeMatrixV2AcceleratorModel, ForgeMatrixV2CompactProof,
    ForgeMatrixV2Descriptor, ForgeMatrixV2Error, ForgeMatrixV2Reference, ForgeMatrixVerifier,
};

#[cfg(feature = "dory-v3-consensus-adapter")]
use crate::{
    dory_bls12_381_candidate::{
        BlsDoryV3CandidateError, verify_bls_dory_v3_layout_v5_candidate,
        verify_bls_dory_v3_layout_v5_candidate_relation,
    },
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    dory_v3_model_record::BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    dory_v3_suite::{
        DORY_V3_ALGORITHM_VERSION, DORY_V3_PROOF_VERSION, DORY_V3_SETUP_IDENTITY,
        production_dory_v3_suite_digest,
    },
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
    #[cfg(feature = "dory-v3-consensus-adapter")]
    V3Candidate(ForgeMatrixV3CandidateParameters),
}

/// Immutable identities committed by the dormant Dory V3 consensus adapter.
///
/// This value contains no paths, JSON, model bytes, or mutable configuration.
/// Its fields can only be derived by this module from a bank-authenticated
/// Record V2 and the exact deterministic setup accepted by the full verifier.
#[cfg(feature = "dory-v3-consensus-adapter")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForgeMatrixV3CandidateParameters {
    network_id: [u8; 32],
    algorithm_version: u32,
    proof_version: u32,
    suite_digest: [u8; 32],
    model_record_digest: [u8; 32],
    model_manifest_digest: [u8; 32],
    model_identity_digest: [u8; 32],
    setup_identity: [u8; 32],
}

#[cfg(feature = "dory-v3-consensus-adapter")]
impl ForgeMatrixV3CandidateParameters {
    pub const fn network_id(self) -> [u8; 32] {
        self.network_id
    }

    pub const fn algorithm_version(self) -> u32 {
        self.algorithm_version
    }

    pub const fn proof_version(self) -> u32 {
        self.proof_version
    }

    pub const fn suite_digest(self) -> [u8; 32] {
        self.suite_digest
    }

    pub const fn model_record_digest(self) -> [u8; 32] {
        self.model_record_digest
    }

    pub const fn model_manifest_digest(self) -> [u8; 32] {
        self.model_manifest_digest
    }

    pub const fn model_identity_digest(self) -> [u8; 32] {
        self.model_identity_digest
    }

    pub const fn setup_identity(self) -> [u8; 32] {
        self.setup_identity
    }

    fn from_authenticated(
        network_id: [u8; 32],
        authenticated: &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    ) -> Self {
        let record = authenticated.record();
        Self {
            network_id,
            algorithm_version: DORY_V3_ALGORITHM_VERSION,
            proof_version: DORY_V3_PROOF_VERSION,
            suite_digest: record.suite_digest().into_bytes(),
            model_record_digest: record.record_digest().into_bytes(),
            model_manifest_digest: record.manifest_digest().into_bytes(),
            model_identity_digest: record.model_identity_digest().into_bytes(),
            setup_identity: record.setup_identity().into_bytes(),
        }
    }

    fn validate_for_network(self, network_id: [u8; 32]) -> Result<(), PowError> {
        if self.network_id != network_id {
            return Err(PowError::WrongNetwork);
        }
        if network_id == [0; 32]
            || self.algorithm_version != DORY_V3_ALGORITHM_VERSION
            || self.proof_version != DORY_V3_PROOF_VERSION
            || self.suite_digest != production_dory_v3_suite_digest().into_bytes()
            || self.setup_identity != DORY_V3_SETUP_IDENTITY.into_bytes()
            || self.model_record_digest == [0; 32]
            || self.model_manifest_digest == [0; 32]
            || self.model_identity_digest == [0; 32]
        {
            return Err(PowError::ParameterMismatch);
        }
        Ok(())
    }

    fn absorb(self, hasher: &mut Hasher) {
        hasher.update(&POW_TYPE_V3_CANDIDATE.to_le_bytes());
        hasher.update(&self.network_id);
        hasher.update(&self.algorithm_version.to_le_bytes());
        hasher.update(&self.proof_version.to_le_bytes());
        hasher.update(&self.suite_digest);
        hasher.update(&self.model_record_digest);
        hasher.update(&self.model_manifest_digest);
        hasher.update(&self.model_identity_digest);
        hasher.update(&self.setup_identity);
    }
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
    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[error("ForgeMatrix Dory v3 candidate verification failed: {0}")]
    V3(#[from] BlsDoryV3CandidateError),
    #[error("block proof type does not match the network proof parameters")]
    WrongProofType,
    #[error("proof verifier identity does not match the network parameters")]
    ParameterMismatch,
    #[error("preverified proof does not match the verifier, challenge, or proof bytes")]
    PreverificationMismatch,
    #[error("proof-of-work parameters belong to another network")]
    WrongNetwork,
}

#[derive(Debug, Clone)]
pub enum ConsensusPowVerifier {
    V1Legacy(Arc<ForgeMatrixVerifier>),
    V2Reference(Arc<ForgeMatrixV2Reference>),
    #[cfg(feature = "dory-v3-consensus-adapter")]
    V3Candidate(Arc<ForgeMatrixV3ConsensusVerifier>),
}

#[cfg(feature = "dory-v3-consensus-adapter")]
enum ForgeMatrixV3VerifierAuthority {
    Production {
        authenticated: Box<BankAuthenticatedDoryV3ModelCommitmentRecordV2>,
        setup: Box<DeterministicBlsDorySetup>,
    },
    #[cfg(test)]
    BoundTestStatement { statement_identity: [u8; 32] },
}

/// Dormant verifier authority for the complete Record-V2/Layout-V5 candidate.
///
/// The production authority has no public constructor. It can only be reached
/// through [`ConsensusPowVerifier::v3_candidate`] by consuming authenticated,
/// pinned artifacts. Debug output deliberately exposes identities only.
#[cfg(feature = "dory-v3-consensus-adapter")]
pub struct ForgeMatrixV3ConsensusVerifier {
    parameters: ForgeMatrixV3CandidateParameters,
    authority: ForgeMatrixV3VerifierAuthority,
}

#[cfg(feature = "dory-v3-consensus-adapter")]
impl fmt::Debug for ForgeMatrixV3ConsensusVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForgeMatrixV3ConsensusVerifier")
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(parameters) => {
                parameters.validate_for_network(network_id)?;
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(parameters) => {
                parameters.validate_for_network(network_id)?;
                parameters.absorb(hasher);
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

    /// Construct the dormant V3 verifier from one authenticated model bank,
    /// its immutable Record V2, and the exact compiled deterministic setup.
    ///
    /// No path, JSON document, or caller-supplied identity can enter the
    /// consensus verifier through this boundary.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    pub fn v3_candidate(
        network_id: [u8; 32],
        authenticated: BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: DeterministicBlsDorySetup,
    ) -> Result<Self, PowError> {
        if network_id == [0; 32] {
            return Err(BlsDoryV3CandidateError::NetworkIdentity.into());
        }
        authenticated
            .record()
            .validate_production(&setup)
            .map_err(BlsDoryV3CandidateError::from)?;
        let parameters =
            ForgeMatrixV3CandidateParameters::from_authenticated(network_id, &authenticated);
        parameters.validate_for_network(network_id)?;
        Ok(Self::V3Candidate(Arc::new(
            ForgeMatrixV3ConsensusVerifier {
                parameters,
                authority: ForgeMatrixV3VerifierAuthority::Production {
                    authenticated: Box::new(authenticated),
                    setup: Box::new(setup),
                },
            },
        )))
    }

    pub fn parameters(&self) -> PowParameters {
        match self {
            Self::V1Legacy(verifier) => PowParameters::V1Legacy(verifier.profile()),
            Self::V2Reference(reference) => PowParameters::V2Reference(reference.descriptor()),
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(verifier) => PowParameters::V3Candidate(verifier.parameters),
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            (Self::V3Candidate(verifier), BlockProof::V3Candidate(proof)) => {
                verifier.verify(block, proof, true)
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
        let matches = match (self, proof) {
            (Self::V1Legacy(_), BlockProof::V1Legacy(_))
            | (Self::V2Reference(_), BlockProof::V2Reference(_)) => true,
            #[cfg(feature = "dory-v3-consensus-adapter")]
            (Self::V3Candidate(_), BlockProof::V3Candidate(_)) => true,
            _ => false,
        };
        if matches {
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(_) => Err(PowError::WrongProofType),
        }
    }

    /// Returns the explicit tiny v2 model for an optional untrusted mining
    /// accelerator. Legacy v1 has no accelerator contract.
    pub fn v2_accelerator_model(&self) -> Result<ForgeMatrixV2AcceleratorModel, PowError> {
        match self {
            Self::V2Reference(reference) => Ok(reference.accelerator_model()),
            Self::V1Legacy(_) => Err(PowError::WrongProofType),
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(_) => Err(PowError::WrongProofType),
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(_) => Err(PowError::WrongProofType),
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(_) => Err(PowError::WrongProofType),
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(_) => Err(PowError::WrongProofType),
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            (Self::V3Candidate(verifier), BlockProof::V3Candidate(proof)) => {
                verifier.verify(block, proof, false)
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
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(_) => Err(PowError::WrongProofType),
        }
    }
}

#[cfg(feature = "dory-v3-consensus-adapter")]
impl ForgeMatrixV3ConsensusVerifier {
    fn verify(
        &self,
        block: &BlockChallenge,
        proof: &ForgeMatrixV3CandidateProof,
        enforce_target: bool,
    ) -> Result<(), PowError> {
        match &self.authority {
            ForgeMatrixV3VerifierAuthority::Production {
                authenticated,
                setup,
            } => {
                if enforce_target {
                    let _verified = verify_bls_dory_v3_layout_v5_candidate(
                        self.parameters.network_id,
                        authenticated,
                        block,
                        proof,
                        setup,
                    )?;
                } else {
                    let _verified = verify_bls_dory_v3_layout_v5_candidate_relation(
                        self.parameters.network_id,
                        authenticated,
                        block,
                        proof,
                        setup,
                    )?;
                }
                Ok(())
            }
            #[cfg(test)]
            ForgeMatrixV3VerifierAuthority::BoundTestStatement { statement_identity } => {
                let candidate = BlockProof::V3Candidate(Box::new(proof.clone()));
                if preverified_statement_identity(block, &candidate) != *statement_identity {
                    return Err(BlsDoryV3CandidateError::ChallengeDigest.into());
                }
                Ok(())
            }
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

    #[cfg(feature = "dory-v3-consensus-adapter")]
    use crate::{
        BLOCK_VERSION, Block, BlockValidationContext, ChainError, ChainState, Coinbase,
        DEFAULT_MONETARY_POLICY, FixedRewardDestinations, NETWORK_PROTOCOL_VERSION, NetworkParams,
        dory_v3_model_record::BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        dory_v3_suite::{DORY_V3_SETUP_IDENTITY, DORY_V3_SUITE_ACTIVATION_READY},
        merkle_root,
    };
    #[cfg(feature = "dory-v3-consensus-adapter")]
    use k256::schnorr::SigningKey;

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
            verifier.verify(&challenge, &v3_proof),
            Err(PowError::WrongProofType)
        ));
        assert!(matches!(
            verifier.verify_evaluation(&challenge, &v3_proof),
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

    #[cfg(feature = "dory-v3-consensus-adapter")]
    fn v3_parameters() -> ForgeMatrixV3CandidateParameters {
        ForgeMatrixV3CandidateParameters {
            network_id: [0x31; 32],
            algorithm_version: DORY_V3_ALGORITHM_VERSION,
            proof_version: DORY_V3_PROOF_VERSION,
            suite_digest: production_dory_v3_suite_digest().into_bytes(),
            model_record_digest: [0x42; 32],
            model_manifest_digest: [0x53; 32],
            model_identity_digest: [0x64; 32],
            setup_identity: DORY_V3_SETUP_IDENTITY.into_bytes(),
        }
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    fn v3_proof() -> ForgeMatrixV3CandidateProof {
        ForgeMatrixV3CandidateProof {
            algorithm_version: DORY_V3_ALGORITHM_VERSION,
            proof_version: DORY_V3_PROOF_VERSION,
            nonce: 7,
            model_manifest_digest: v3_parameters().model_manifest_digest,
            challenge_digest: [0x75; 32],
            final_activation_digest: [0x86; 32],
            work_digest: [0x97; 32],
            structured_proof: vec![0xa8, 0xb9, 0xca],
        }
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    fn bound_v3_test_verifier(
        parameters: ForgeMatrixV3CandidateParameters,
        challenge: &BlockChallenge,
        proof: &ForgeMatrixV3CandidateProof,
    ) -> ConsensusPowVerifier {
        let proof = BlockProof::V3Candidate(Box::new(proof.clone()));
        ConsensusPowVerifier::V3Candidate(Arc::new(ForgeMatrixV3ConsensusVerifier {
            parameters,
            authority: ForgeMatrixV3VerifierAuthority::BoundTestStatement {
                statement_identity: preverified_statement_identity(challenge, &proof),
            },
        }))
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    type V3StatementMutation = fn(&mut BlockChallenge, &mut ForgeMatrixV3CandidateProof);

    #[cfg(feature = "dory-v3-consensus-adapter")]
    fn v3_statement_mutations() -> [(&'static str, V3StatementMutation); 15] {
        [
            ("network_id", |challenge, _| challenge.network_id[0] ^= 1),
            ("previous_block", |challenge, _| {
                challenge.previous_block[0] ^= 1
            }),
            ("transaction_root", |challenge, _| {
                challenge.transaction_root[0] ^= 1
            }),
            ("height", |challenge, _| challenge.height ^= 1),
            ("timestamp", |challenge, _| challenge.timestamp ^= 1),
            ("target", |challenge, _| challenge.target[0] ^= 1),
            ("algorithm_version", |_, proof| proof.algorithm_version ^= 1),
            ("proof_version", |_, proof| proof.proof_version ^= 1),
            ("nonce", |_, proof| proof.nonce ^= 1),
            ("model_manifest_digest", |_, proof| {
                proof.model_manifest_digest[0] ^= 1
            }),
            ("challenge_digest", |_, proof| {
                proof.challenge_digest[0] ^= 1
            }),
            ("final_activation_digest", |_, proof| {
                proof.final_activation_digest[0] ^= 1
            }),
            ("work_digest", |_, proof| proof.work_digest[0] ^= 1),
            ("structured_proof_byte", |_, proof| {
                proof.structured_proof[0] ^= 1
            }),
            ("structured_proof_length", |_, proof| {
                proof.structured_proof.push(0xdb)
            }),
        ]
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[test]
    fn v3_parameters_absorb_every_immutable_identity_and_reject_compiled_identity_changes() {
        let baseline = v3_parameters();
        baseline.validate_for_network(baseline.network_id).unwrap();
        let baseline_challenge = block(baseline.network_id);
        let baseline_candidate = v3_proof();
        let baseline_verifier =
            bound_v3_test_verifier(baseline, &baseline_challenge, &baseline_candidate);
        let baseline_proof = BlockProof::V3Candidate(Box::new(baseline_candidate.clone()));
        let baseline_binding = baseline_verifier
            .external_preverification_binding(&baseline_challenge, &baseline_proof)
            .unwrap();
        let digest = |parameters: ForgeMatrixV3CandidateParameters| {
            let mut hasher = Hasher::new();
            parameters.absorb(&mut hasher);
            *hasher.finalize().as_bytes()
        };
        let expected = digest(baseline);

        type Mutation = fn(&mut ForgeMatrixV3CandidateParameters);
        let mutations: [(&str, Mutation, bool); 8] = [
            ("network_id", |value| value.network_id[0] ^= 1, true),
            (
                "algorithm_version",
                |value| value.algorithm_version ^= 1,
                true,
            ),
            ("proof_version", |value| value.proof_version ^= 1, true),
            ("suite_digest", |value| value.suite_digest[0] ^= 1, true),
            (
                "model_record_digest",
                |value| value.model_record_digest[0] ^= 1,
                false,
            ),
            (
                "model_manifest_digest",
                |value| value.model_manifest_digest[0] ^= 1,
                false,
            ),
            (
                "model_identity_digest",
                |value| value.model_identity_digest[0] ^= 1,
                false,
            ),
            ("setup_identity", |value| value.setup_identity[0] ^= 1, true),
        ];
        for (name, mutate, must_reject) in mutations {
            let mut changed = baseline;
            mutate(&mut changed);
            assert_ne!(digest(changed), expected, "identity not absorbed: {name}");
            if must_reject {
                assert!(
                    changed.validate_for_network(baseline.network_id).is_err(),
                    "compiled identity mutation accepted: {name}"
                );
            }
            let mut changed_challenge = baseline_challenge;
            if name == "network_id" {
                changed_challenge.network_id = changed.network_id;
            }
            let changed_verifier =
                bound_v3_test_verifier(changed, &changed_challenge, &baseline_candidate);
            match changed_verifier
                .external_preverification_binding(&changed_challenge, &baseline_proof)
            {
                Ok(binding) => assert_ne!(
                    binding.verifier_identity(),
                    baseline_binding.verifier_identity(),
                    "verifier identity not changed: {name}"
                ),
                Err(error) => assert!(
                    matches!(error, PowError::ParameterMismatch),
                    "unexpected fail-closed result for {name}: {error}"
                ),
            }
        }

        let _constructor: fn(
            [u8; 32],
            BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            DeterministicBlsDorySetup,
        ) -> Result<ConsensusPowVerifier, PowError> = ConsensusPowVerifier::v3_candidate;
        const {
            assert!(!DORY_V3_SUITE_ACTIVATION_READY);
        }
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[test]
    fn v3_direct_and_preverified_paths_bind_every_statement_byte() {
        let parameters = v3_parameters();
        let challenge = block(parameters.network_id);
        let candidate = v3_proof();
        let proof = BlockProof::V3Candidate(Box::new(candidate.clone()));
        let verifier = bound_v3_test_verifier(parameters, &challenge, &candidate);

        verifier.verify(&challenge, &proof).unwrap();
        verifier.verify_evaluation(&challenge, &proof).unwrap();
        assert!(matches!(
            verifier.evaluate(&challenge, candidate.nonce),
            Err(PowError::WrongProofType)
        ));
        assert!(matches!(
            verifier.mine(&challenge, candidate.nonce, 1),
            Err(PowError::WrongProofType)
        ));
        assert!(matches!(
            verifier.v2_accelerator_model(),
            Err(PowError::WrongProofType)
        ));
        let preverified = verifier.preverify(&challenge, &proof).unwrap();
        verifier
            .verify_preverified(&challenge, &proof, &preverified)
            .unwrap();
        let external = verifier
            .external_preverification_binding(&challenge, &proof)
            .unwrap();
        // SAFETY: the bound test verifier accepted this exact statement above.
        let external_preverified = unsafe {
            verifier
                .issue_external_preverification(&challenge, &proof, external)
                .unwrap()
        };
        verifier
            .verify_preverified(&challenge, &proof, &external_preverified)
            .unwrap();

        for mutate in [
            |binding: &mut ExternalPreverificationBinding| binding.verifier_identity[0] ^= 1,
            |binding: &mut ExternalPreverificationBinding| binding.statement_identity[0] ^= 1,
        ] {
            let mut substituted = external;
            mutate(&mut substituted);
            // SAFETY: each substituted worker response must be rejected before
            // the process-local capability can be issued.
            assert!(matches!(
                unsafe { verifier.issue_external_preverification(&challenge, &proof, substituted) },
                Err(PowError::PreverificationMismatch)
            ));
        }

        let expected_statement = preverified_statement_identity(&challenge, &proof);
        for (name, mutate) in v3_statement_mutations() {
            let mut changed_challenge = challenge;
            let mut changed_candidate = candidate.clone();
            mutate(&mut changed_challenge, &mut changed_candidate);
            let changed_proof = BlockProof::V3Candidate(Box::new(changed_candidate));
            assert_ne!(
                preverified_statement_identity(&changed_challenge, &changed_proof),
                expected_statement,
                "statement mutation not absorbed: {name}"
            );
            assert!(
                matches!(
                    verifier.verify(&changed_challenge, &changed_proof),
                    Err(PowError::V3(_))
                ),
                "safe direct verification accepted mutation: {name}"
            );
            assert!(
                matches!(
                    verifier.verify_evaluation(&changed_challenge, &changed_proof),
                    Err(PowError::V3(_))
                ),
                "relation verification accepted mutation: {name}"
            );
            assert!(
                matches!(
                    verifier.preverify(&changed_challenge, &changed_proof),
                    Err(PowError::V3(_))
                ),
                "safe preverification accepted mutation: {name}"
            );
            if name == "network_id" {
                assert!(matches!(
                    verifier.verify_preverified(&changed_challenge, &changed_proof, &preverified),
                    Err(PowError::WrongNetwork)
                ));
                assert!(matches!(
                    verifier.external_preverification_binding(&changed_challenge, &changed_proof),
                    Err(PowError::WrongNetwork)
                ));
                // SAFETY: the changed network must fail before the old worker
                // response can be compared or a capability can be issued.
                assert!(matches!(
                    unsafe {
                        verifier.issue_external_preverification(
                            &changed_challenge,
                            &changed_proof,
                            external,
                        )
                    },
                    Err(PowError::WrongNetwork)
                ));
            } else {
                assert!(
                    matches!(
                        verifier.verify_preverified(
                            &changed_challenge,
                            &changed_proof,
                            &preverified
                        ),
                        Err(PowError::PreverificationMismatch)
                    ),
                    "capability replay accepted mutation: {name}"
                );
                let changed_binding = verifier
                    .external_preverification_binding(&changed_challenge, &changed_proof)
                    .unwrap();
                assert_ne!(
                    changed_binding.statement_identity(),
                    external.statement_identity(),
                    "external statement identity not changed: {name}"
                );
                // SAFETY: an old worker response is deliberately replayed
                // against a changed request and must be rejected before
                // capability issuance.
                assert!(
                    matches!(
                        unsafe {
                            verifier.issue_external_preverification(
                                &changed_challenge,
                                &changed_proof,
                                external,
                            )
                        },
                        Err(PowError::PreverificationMismatch)
                    ),
                    "unsafe external issuance accepted mutation: {name}"
                );
            }
        }
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    fn destination(byte: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[byte; 32])
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into()
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    fn v3_chain_fixture() -> (NetworkParams, ConsensusPowVerifier, Block) {
        let parameters = v3_parameters();
        let rewards = FixedRewardDestinations {
            steward: destination(3),
            community: destination(4),
        };
        let allocation = DEFAULT_MONETARY_POLICY.allocation(1, 0).unwrap();
        let coinbase = Coinbase::new(1, allocation, destination(2), rewards);
        let challenge = BlockChallenge {
            network_id: parameters.network_id,
            previous_block: [0x22; 32],
            transaction_root: merkle_root(&[coinbase.commitment(parameters.network_id)]),
            height: 1,
            timestamp: 60,
            target: [0xff; 32],
        };
        let candidate = v3_proof();
        let verifier = bound_v3_test_verifier(parameters, &challenge, &candidate);
        let params = NetworkParams {
            network_id: parameters.network_id,
            protocol_version: NETWORK_PROTOCOL_VERSION,
            genesis_hash: challenge.previous_block,
            genesis_timestamp: 0,
            pow_limit: challenge.target,
            pow: verifier.parameters(),
            monetary_policy: DEFAULT_MONETARY_POLICY,
            rewards,
            max_future_offset_secs: 7_200,
        };
        let block = Block {
            version: BLOCK_VERSION,
            challenge,
            proof: BlockProof::V3Candidate(Box::new(candidate)),
            coinbase,
            transactions: Vec::new(),
        };
        (params, verifier, block)
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[test]
    fn v3_chain_direct_and_preverified_admission_reject_every_statement_mutation() {
        let (params, verifier, candidate_block) = v3_chain_fixture();
        let state = ChainState::new(params, verifier.clone()).unwrap();
        let context = BlockValidationContext {
            now_unix_seconds: 60,
        };
        state.validate_block(&candidate_block, context).unwrap();
        let preverified = verifier
            .preverify(&candidate_block.challenge, &candidate_block.proof)
            .unwrap();
        state
            .validate_block_preverified(&candidate_block, context, &preverified)
            .unwrap();

        for (name, mutate) in v3_statement_mutations() {
            let mut changed = candidate_block.clone();
            let BlockProof::V3Candidate(candidate) = &mut changed.proof else {
                unreachable!();
            };
            mutate(&mut changed.challenge, candidate);
            let direct = state.validate_block(&changed, context);
            let with_preverification =
                state.validate_block_preverified(&changed, context, &preverified);
            let proof_mutation = !matches!(
                name,
                "network_id"
                    | "previous_block"
                    | "transaction_root"
                    | "height"
                    | "timestamp"
                    | "target"
            );
            if proof_mutation {
                assert!(
                    matches!(direct, Err(ChainError::InvalidV3Proof)),
                    "direct chain admission did not reject V3 proof mutation: {name}"
                );
                assert!(
                    matches!(
                        with_preverification,
                        Err(ChainError::PreverifiedProofMismatch)
                    ),
                    "preverified chain admission did not reject V3 proof mutation: {name}"
                );
            } else {
                assert!(direct.is_err(), "direct chain accepted mutation: {name}");
                assert!(
                    with_preverification.is_err(),
                    "preverified chain accepted mutation: {name}"
                );
            }
        }

        let legacy = BlockProof::V1Legacy(
            ForgeMatrixVerifier::new(TEST_PROFILE)
                .unwrap()
                .prove(&candidate_block.challenge, 7),
        );
        assert!(matches!(
            verifier.verify(&candidate_block.challenge, &legacy),
            Err(PowError::WrongProofType)
        ));
        let v2_reference = v2_test_reference().unwrap();
        let v2_challenge = block(v2_reference.descriptor().network_id);
        let v2 = BlockProof::V2Reference(v2_reference.prove_compact(&v2_challenge, 7).unwrap());
        assert!(matches!(
            verifier.verify(&candidate_block.challenge, &v2),
            Err(PowError::WrongProofType)
        ));

        let mut wrong_params = params;
        let PowParameters::V3Candidate(parameters) = &mut wrong_params.pow else {
            unreachable!();
        };
        parameters.model_record_digest[0] ^= 1;
        assert!(matches!(
            ChainState::new(wrong_params, verifier),
            Err(ChainError::PowParameterMismatch)
        ));
    }
}
