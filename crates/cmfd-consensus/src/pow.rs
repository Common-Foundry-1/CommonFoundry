use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

#[cfg(feature = "dory-v3-consensus-adapter")]
use std::{io::Read, path::Path, sync::atomic::AtomicBool};

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
        BlsDoryV3CandidateError, preflight_bls_dory_v3_layout_v5_candidate,
        verify_bls_dory_v3_layout_v5_candidate, verify_bls_dory_v3_layout_v5_candidate_relation,
    },
    dory_bls12_381_execution_provider::{
        BlsDoryV3AcceleratedReplayAccumulators, BlsDoryV3WinningNonceClaim,
        prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model,
        prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model_with_accelerated_replay,
        prove_bls_dory_v3_layout_v5_candidate_from_winning_nonce_claim,
        validate_dory_v3_replay_claim,
    },
    dory_bls12_381_layout::{
        BlsDoryPreparedFixedModelV5,
        prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch_and_cancel,
    },
    dory_bls12_381_prototype::DeterministicBlsDorySetup,
    dory_v3_model_record::BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    dory_v3_suite::{
        DORY_V3_ALGORITHM_VERSION, DORY_V3_PROOF_VERSION, DORY_V3_SETUP_IDENTITY,
        production_dory_v3_suite_digest,
    },
    dory_v3_transcript::{DoryV3TranscriptContext, dory_v3_mask_coefficients},
};

pub const POW_TYPE_V1_LEGACY: u16 = 1;
pub const POW_TYPE_V2_REFERENCE: u16 = 2;
/// Reserved wire identity for the fail-closed structured production candidate.
pub const POW_TYPE_V3_CANDIDATE: u16 = 3;
/// Reserved wire identity for the isolated ProductionV4 latency testnet.
pub const POW_TYPE_V4_CANDIDATE: u16 = 4;
/// Largest native BLAKE3 block-row batch accepted by the runtime V3 prover.
///
/// This is an operational memory bound, not a consensus parameter. Callers
/// must still select and report an explicit nonzero value for every run.
#[cfg(feature = "dory-v3-consensus-adapter")]
pub const MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS: usize = 131_072;
#[cfg(feature = "dory-v3-consensus-adapter")]
pub const MAX_PRODUCTION_V3_ACCELERATOR_BATCH: u32 = 64;
#[cfg(feature = "dory-bls12-381-prototype")]
pub(crate) const FORGEMATRIX_V3_BLOCK_ID_PROOF_FIELDS: &str = "pow_type_u16le,algorithm_version_u32le,proof_version_u32le,nonce_u64le,model_manifest_digest[32],challenge_digest[32],final_activation_digest[32],work_digest[32],structured_length_u64le,structured_bytes";
const PREVERIFIED_VERIFIER_DOMAIN: &str = "CMFD/POW/PREVERIFIED-VERIFIER/V1";
const PREVERIFIED_CAPABILITY_DOMAIN: &str = "CMFD/POW/PREVERIFIED-CAPABILITY/V1";
static PREVERIFICATION_PROCESS_KEY: OnceLock<[u8; 32]> = OnceLock::new();
static NEXT_VERIFIER_CAPABILITY_NONCE: AtomicU64 = AtomicU64::new(1);
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

/// Untrusted accelerator claim for one possible Production V3 winning nonce.
///
/// The model identities make accidental cross-bank submission cheap to reject.
/// They do not authorize the claim: the runtime prover replays the nonce from
/// the authenticated bank and recomputes both digests before proving.
#[cfg(feature = "dory-v3-consensus-adapter")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForgeMatrixV3WinningNonceClaim {
    network_id: [u8; 32],
    model_record_digest: [u8; 32],
    model_identity_digest: [u8; 32],
    nonce: u64,
    final_activation_digest: [u8; 32],
    work_digest: [u8; 32],
}

/// Exact transcript coefficients for a bounded batch of Production V3 nonces.
///
/// Fields are private so an accelerator cannot detach outputs from the block,
/// network, and authenticated model identities used to derive its masks.
#[cfg(feature = "dory-v3-consensus-adapter")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeMatrixV3AcceleratorBatch {
    block: BlockChallenge,
    model_record_digest: [u8; 32],
    model_identity_digest: [u8; 32],
    start_nonce: u64,
    count: u32,
    activation_len: usize,
    coefficients: Vec<u8>,
}

#[cfg(feature = "dory-v3-consensus-adapter")]
impl ForgeMatrixV3AcceleratorBatch {
    pub const fn start_nonce(&self) -> u64 {
        self.start_nonce
    }

    pub const fn count(&self) -> u32 {
        self.count
    }

    pub const fn activation_len(&self) -> usize {
        self.activation_len
    }

    pub fn coefficients(&self) -> &[u8] {
        &self.coefficients
    }

    pub fn nonce_at(&self, index: usize) -> Option<u64> {
        (index < self.count as usize).then(|| self.start_nonce.wrapping_add(index as u64))
    }
}

/// Reusable fixed-model prover state prepared once from the authenticated
/// production bank and shared by every immutable mining job in the process.
#[cfg(feature = "dory-v3-consensus-adapter")]
#[derive(Clone)]
pub struct PreparedForgeMatrixV3Model {
    parameters: ForgeMatrixV3CandidateParameters,
    prepared: Arc<BlsDoryPreparedFixedModelV5>,
}

#[cfg(feature = "dory-v3-consensus-adapter")]
impl fmt::Debug for PreparedForgeMatrixV3Model {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedForgeMatrixV3Model")
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "dory-v3-consensus-adapter")]
impl ForgeMatrixV3WinningNonceClaim {
    const fn new(
        network_id: [u8; 32],
        model_record_digest: [u8; 32],
        model_identity_digest: [u8; 32],
        nonce: u64,
        final_activation_digest: [u8; 32],
        work_digest: [u8; 32],
    ) -> Self {
        Self {
            network_id,
            model_record_digest,
            model_identity_digest,
            nonce,
            final_activation_digest,
            work_digest,
        }
    }

    pub const fn network_id(self) -> [u8; 32] {
        self.network_id
    }

    pub const fn model_record_digest(self) -> [u8; 32] {
        self.model_record_digest
    }

    pub const fn model_identity_digest(self) -> [u8; 32] {
        self.model_identity_digest
    }

    pub const fn nonce(self) -> u64 {
        self.nonce
    }

    pub const fn final_activation_digest(self) -> [u8; 32] {
        self.final_activation_digest
    }

    pub const fn work_digest(self) -> [u8; 32] {
        self.work_digest
    }
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
    /// Length-bounded transparent-proof candidate for the isolated V4 testnet.
    /// Existing verifiers deliberately reject this variant until the complete
    /// V4 relation and verifier parameters are pinned.
    V4Candidate(Box<ForgeMatrixV4CandidateProof>),
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

/// Public V4 statement fields plus one canonical transparent proof encoding.
///
/// The proof-system digest binds the exact field, PCS, transcript, query, and
/// soundness parameters. The proof bytes remain opaque to block framing so the
/// future verifier can parse them behind its own strict resource bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeMatrixV4CandidateProof {
    pub algorithm_version: u32,
    pub proof_version: u32,
    pub nonce: u64,
    pub proof_system_digest: [u8; 32],
    pub model_manifest_digest: [u8; 32],
    pub challenge_digest: [u8; 32],
    pub final_activation_digest: [u8; 32],
    pub work_digest: [u8; 32],
    pub transparent_proof: Vec<u8>,
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
    capability_mac: [u8; 32],
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
    #[error("operating-system entropy is unavailable for process-local proof capabilities")]
    PreverificationEntropy,
    #[error("proof-of-work parameters belong to another network")]
    WrongNetwork,
}

#[derive(Debug, Clone)]
pub enum ConsensusPowVerifier {
    V1Legacy(Arc<VerifierInstance<ForgeMatrixVerifier>>),
    V2Reference(Arc<VerifierInstance<ForgeMatrixV2Reference>>),
    #[cfg(feature = "dory-v3-consensus-adapter")]
    V3Candidate(Arc<VerifierInstance<ForgeMatrixV3ConsensusVerifier>>),
}

#[doc(hidden)]
pub struct VerifierInstance<T> {
    verifier: T,
    capability_nonce: u64,
    #[cfg(test)]
    relation_dispatches: AtomicU64,
}

impl<T> VerifierInstance<T> {
    fn new(verifier: T) -> Self {
        Self {
            verifier,
            capability_nonce: NEXT_VERIFIER_CAPABILITY_NONCE.fetch_add(1, Ordering::Relaxed),
            #[cfg(test)]
            relation_dispatches: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn record_relation_dispatch(&self) {
        self.relation_dispatches.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn relation_dispatches(&self) -> u64 {
        self.relation_dispatches.load(Ordering::Relaxed)
    }
}

impl<T> Deref for VerifierInstance<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.verifier
    }
}

impl<T: fmt::Debug> fmt::Debug for VerifierInstance<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.verifier.fmt(formatter)
    }
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
            Self::V4Candidate(_) => POW_TYPE_V4_CANDIDATE,
        }
    }

    /// Returns the committed work digest by value so callers cannot mutate a
    /// proof through the accessor.
    pub fn work_digest(&self) -> [u8; 32] {
        match self {
            Self::V1Legacy(proof) => proof.work_digest,
            Self::V2Reference(proof) => proof.work_digest,
            Self::V3Candidate(proof) => proof.work_digest,
            Self::V4Candidate(proof) => proof.work_digest,
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
            Self::V4Candidate(proof) => {
                hasher.update(&proof.algorithm_version.to_le_bytes());
                hasher.update(&proof.proof_version.to_le_bytes());
                hasher.update(&proof.nonce.to_le_bytes());
                hasher.update(&proof.proof_system_digest);
                hasher.update(&proof.model_manifest_digest);
                hasher.update(&proof.challenge_digest);
                hasher.update(&proof.final_activation_digest);
                hasher.update(&proof.work_digest);
                hasher.update(&(proof.transparent_proof.len() as u64).to_le_bytes());
                hasher.update(&proof.transparent_proof);
            }
        }
    }
}

impl ConsensusPowVerifier {
    pub fn v1_legacy(profile: ForgeMatrixProfile) -> Result<Self, PowError> {
        Ok(Self::V1Legacy(Arc::new(VerifierInstance::new(
            ForgeMatrixVerifier::new(profile)?,
        ))))
    }

    pub fn v2_reference(reference: ForgeMatrixV2Reference) -> Self {
        Self::V2Reference(Arc::new(VerifierInstance::new(reference)))
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
        Ok(Self::V3Candidate(Arc::new(VerifierInstance::new(
            ForgeMatrixV3ConsensusVerifier {
                parameters,
                authority: ForgeMatrixV3VerifierAuthority::Production {
                    authenticated: Box::new(authenticated),
                    setup: Box::new(setup),
                },
            },
        ))))
    }

    /// Test-only constructor for exercising the bank-read authority boundary
    /// independently of the production geometry validator.
    #[cfg(all(test, feature = "dory-v3-consensus-adapter"))]
    pub(crate) fn v3_unchecked_for_bank_authority_test(
        network_id: [u8; 32],
        authenticated: BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        setup: DeterministicBlsDorySetup,
    ) -> Self {
        let parameters =
            ForgeMatrixV3CandidateParameters::from_authenticated(network_id, &authenticated);
        Self::V3Candidate(Arc::new(VerifierInstance::new(
            ForgeMatrixV3ConsensusVerifier {
                parameters,
                authority: ForgeMatrixV3VerifierAuthority::Production {
                    authenticated: Box::new(authenticated),
                    setup: Box::new(setup),
                },
            },
        )))
    }

    /// Reject a Production V3 accelerator claim unless its immutable network
    /// and model identities match this exact verifier.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    pub fn validate_v3_winning_nonce_claim(
        &self,
        block: &BlockChallenge,
        claim: ForgeMatrixV3WinningNonceClaim,
    ) -> Result<(), PowError> {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        let cancel = AtomicBool::new(false);
        verifier.validate_winning_nonce_claim(block, claim, &cancel)?;
        Ok(())
    }

    /// Derive the exact virtual-input and 384 transition masks consumed by the
    /// authenticated production CUDA evaluator for a bounded nonce batch.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    pub fn prepare_v3_accelerator_batch(
        &self,
        block: &BlockChallenge,
        start_nonce: u64,
        count: u32,
    ) -> Result<ForgeMatrixV3AcceleratorBatch, PowError> {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        verifier.prepare_accelerator_batch(block, start_nonce, count)
    }

    /// Authenticate one accelerator output against the exact batch statement.
    /// High work is a normal non-winning result; malformed or mismatched
    /// batches fail closed.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    pub fn v3_winning_nonce_claim_from_accelerator_batch_output(
        &self,
        block: &BlockChallenge,
        batch: &ForgeMatrixV3AcceleratorBatch,
        index: usize,
        final_activation: &[u8],
    ) -> Result<Option<ForgeMatrixV3WinningNonceClaim>, PowError> {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        verifier.winning_nonce_claim_from_accelerator_batch_output(
            block,
            batch,
            index,
            final_activation,
        )
    }

    /// Authenticate and prepare the fixed production model once. The returned
    /// capability can be cheaply cloned across immutable mining work.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    pub fn prepare_v3_fixed_model<FixedModelBank: Read>(
        &self,
        fixed_model_bank: FixedModelBank,
        scratch_directory: &Path,
        cancel: &AtomicBool,
    ) -> Result<PreparedForgeMatrixV3Model, PowError> {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
            return Err(BlsDoryV3CandidateError::ProverConfiguration.into());
        }
        let (authenticated, setup) = verifier.production_authority()?;
        let prepared =
            prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch_and_cancel(
                fixed_model_bank,
                authenticated,
                setup,
                scratch_directory,
                cancel,
            )
            .map_err(BlsDoryV3CandidateError::from)?;
        if !prepared.is_bound_to_bank_authenticated_record(authenticated) {
            return Err(BlsDoryV3CandidateError::ProverConfiguration.into());
        }
        Ok(PreparedForgeMatrixV3Model {
            parameters: verifier.parameters,
            prepared: Arc::new(prepared),
        })
    }

    /// Borrow the exact non-serializable authority that authenticated this
    /// production verifier. Accelerator initialization may use this capability
    /// to authenticate a resident model once; loose records cannot construct
    /// it or bypass the pinned artifact gate.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    pub fn v3_production_authority(
        &self,
    ) -> Result<
        (
            &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            &DeterministicBlsDorySetup,
        ),
        PowError,
    > {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        verifier.production_authority()
    }

    /// Convert one accelerator-produced final activation into a typed winning
    /// claim under this verifier's authenticated transcript. The accelerator's
    /// retained model identities must match before its large output is hashed.
    /// The activation remains untrusted; [`Self::prove_v3_winning_nonce_claim`]
    /// replays the nonce from the bank and refuses any mismatch before proof
    /// construction.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    pub fn v3_winning_nonce_claim_from_accelerator_output(
        &self,
        block: &BlockChallenge,
        accelerator_model_record_digest: [u8; 32],
        accelerator_model_identity_digest: [u8; 32],
        nonce: u64,
        final_activation: &[u8],
    ) -> Result<ForgeMatrixV3WinningNonceClaim, PowError> {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        verifier.winning_nonce_claim_from_accelerator_output(
            block,
            accelerator_model_record_digest,
            accelerator_model_identity_digest,
            nonce,
            final_activation,
        )
    }

    /// Reauthenticate and replay an exact accelerator winning-nonce claim,
    /// build the complete Layout V5/Dory proof, and self-verify it.
    ///
    /// This operation is intentionally independent of node state. Callers
    /// should obtain an immutable mining job under their node lock, release
    /// that lock, run this method, and reacquire the lock only to submit the
    /// returned block. Both readers must start at byte zero of the pinned bank.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[allow(clippy::too_many_arguments)]
    pub fn prove_v3_winning_nonce_claim<FixedModelBank: Read, ReplayBank: Read>(
        &self,
        block: &BlockChallenge,
        claim: ForgeMatrixV3WinningNonceClaim,
        fixed_model_bank: FixedModelBank,
        replay_bank: ReplayBank,
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
        cancel: &AtomicBool,
    ) -> Result<BlockProof, PowError> {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        verifier.validate_winning_nonce_claim(block, claim, cancel)?;
        if maximum_native_block_rows == 0
            || maximum_native_block_rows > MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS
        {
            return Err(BlsDoryV3CandidateError::ProverConfiguration.into());
        }
        let (authenticated, setup) = verifier.production_authority()?;
        let proof = prove_bls_dory_v3_layout_v5_candidate_from_winning_nonce_claim(
            authenticated,
            block,
            BlsDoryV3WinningNonceClaim {
                nonce: claim.nonce,
                final_activation_digest: claim.final_activation_digest,
                work_digest: claim.work_digest,
            },
            setup,
            fixed_model_bank,
            replay_bank,
            scratch_directory,
            maximum_native_block_rows,
            cancel,
        )?;
        Ok(BlockProof::V3Candidate(Box::new(proof)))
    }

    /// Prove one winning claim with process-reusable fixed-model state. Claim
    /// and target validation happens before the replay reader is touched.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[allow(clippy::too_many_arguments)]
    pub fn prove_v3_winning_nonce_claim_with_prepared_model<ReplayBank: Read>(
        &self,
        block: &BlockChallenge,
        claim: ForgeMatrixV3WinningNonceClaim,
        prepared_model: &PreparedForgeMatrixV3Model,
        replay_bank: ReplayBank,
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
        cancel: &AtomicBool,
    ) -> Result<BlockProof, PowError> {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        verifier.validate_winning_nonce_claim(block, claim, cancel)?;
        if prepared_model.parameters != verifier.parameters
            || maximum_native_block_rows == 0
            || maximum_native_block_rows > MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS
        {
            return Err(BlsDoryV3CandidateError::ProverConfiguration.into());
        }
        let (authenticated, setup) = verifier.production_authority()?;
        let proof = prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model(
            authenticated,
            block,
            BlsDoryV3WinningNonceClaim {
                nonce: claim.nonce,
                final_activation_digest: claim.final_activation_digest,
                work_digest: claim.work_digest,
            },
            setup,
            prepared_model.prepared.as_ref(),
            replay_bank,
            scratch_directory,
            maximum_native_block_rows,
            cancel,
        )?;
        Ok(BlockProof::V3Candidate(Box::new(proof)))
    }

    /// Prove one winning claim with process-reusable fixed-model state and an
    /// optional accelerator-proposed replay accumulator bundle. `None` is the
    /// unchanged CPU replay. `Some` never extends trust to the accelerator:
    /// the complete bank still authenticates on this call's replay reader,
    /// every accumulator is bound-checked, the published digests are
    /// re-derived on the CPU, the matrix sumcheck proves the accumulators
    /// against the CPU-committed weights, and the candidate self-verifies.
    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[allow(clippy::too_many_arguments)]
    pub fn prove_v3_winning_nonce_claim_with_prepared_model_and_accelerated_replay<
        ReplayBank: Read,
    >(
        &self,
        block: &BlockChallenge,
        claim: ForgeMatrixV3WinningNonceClaim,
        prepared_model: &PreparedForgeMatrixV3Model,
        replay_bank: ReplayBank,
        scratch_directory: &Path,
        maximum_native_block_rows: usize,
        accelerated_replay: Option<BlsDoryV3AcceleratedReplayAccumulators>,
        cancel: &AtomicBool,
    ) -> Result<BlockProof, PowError> {
        let Self::V3Candidate(verifier) = self else {
            return Err(PowError::WrongProofType);
        };
        verifier.validate_winning_nonce_claim(block, claim, cancel)?;
        if prepared_model.parameters != verifier.parameters
            || maximum_native_block_rows == 0
            || maximum_native_block_rows > MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS
        {
            return Err(BlsDoryV3CandidateError::ProverConfiguration.into());
        }
        let (authenticated, setup) = verifier.production_authority()?;
        let proof = prove_bls_dory_v3_layout_v5_candidate_from_prepared_fixed_model_with_accelerated_replay(
            authenticated,
            block,
            BlsDoryV3WinningNonceClaim {
                nonce: claim.nonce,
                final_activation_digest: claim.final_activation_digest,
                work_digest: claim.work_digest,
            },
            setup,
            prepared_model.prepared.as_ref(),
            replay_bank,
            scratch_directory,
            maximum_native_block_rows,
            accelerated_replay,
            cancel,
        )?;
        Ok(BlockProof::V3Candidate(Box::new(proof)))
    }

    pub fn parameters(&self) -> PowParameters {
        match self {
            Self::V1Legacy(verifier) => PowParameters::V1Legacy(verifier.profile()),
            Self::V2Reference(reference) => PowParameters::V2Reference(reference.descriptor()),
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(verifier) => PowParameters::V3Candidate(verifier.parameters),
        }
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    pub fn v3_candidate_parameters(&self) -> Result<ForgeMatrixV3CandidateParameters, PowError> {
        match self {
            Self::V3Candidate(verifier) => Ok(verifier.parameters),
            _ => Err(PowError::WrongProofType),
        }
    }

    pub fn verify(&self, block: &BlockChallenge, proof: &BlockProof) -> Result<(), PowError> {
        self.preflight(block, proof)?;
        match (self, proof) {
            (Self::V1Legacy(verifier), BlockProof::V1Legacy(proof)) => {
                #[cfg(test)]
                verifier.record_relation_dispatch();
                verifier.verify(block, proof)?;
                Ok(())
            }
            (Self::V2Reference(reference), BlockProof::V2Reference(proof)) => {
                #[cfg(test)]
                reference.record_relation_dispatch();
                reference.verify_compact(block, proof)?;
                Ok(())
            }
            #[cfg(feature = "dory-v3-consensus-adapter")]
            (Self::V3Candidate(verifier), BlockProof::V3Candidate(proof)) => {
                #[cfg(test)]
                verifier.record_relation_dispatch();
                verifier.verify(block, proof, true)
            }
            _ => Err(PowError::WrongProofType),
        }
    }

    /// Reject every verifier-owned, cheaply decidable proof-envelope and
    /// target failure without parsing or verifying an expensive proof.
    ///
    /// `verify` invokes this same method before its authoritative relation
    /// check. Nodes may therefore use it as an admission optimization without
    /// creating a consensus rule that the full verifier does not enforce.
    pub fn preflight(&self, block: &BlockChallenge, proof: &BlockProof) -> Result<(), PowError> {
        match (self, proof) {
            (Self::V1Legacy(verifier), BlockProof::V1Legacy(proof)) => {
                verifier.preflight(block, proof).map_err(PowError::from)
            }
            (Self::V2Reference(reference), BlockProof::V2Reference(proof)) => reference
                .preflight_compact(block, proof)
                .map_err(PowError::from),
            #[cfg(feature = "dory-v3-consensus-adapter")]
            (Self::V3Candidate(verifier), BlockProof::V3Candidate(proof)) => {
                // These public-envelope checks are common to the production
                // authority and the bounded relation test authority below.
                // The production helper repeats them before deriving its
                // transcript statement, so this early target gate can change
                // only rejection order, never proof validity.
                if block.network_id != verifier.parameters.network_id {
                    return Err(BlsDoryV3CandidateError::WrongNetwork.into());
                }
                if proof.algorithm_version != DORY_V3_ALGORITHM_VERSION {
                    return Err(BlsDoryV3CandidateError::AlgorithmVersion.into());
                }
                if proof.proof_version != DORY_V3_PROOF_VERSION {
                    return Err(BlsDoryV3CandidateError::ProofVersion.into());
                }
                if proof.model_manifest_digest != verifier.parameters.model_manifest_digest {
                    return Err(BlsDoryV3CandidateError::ModelManifestDigest.into());
                }
                if proof.structured_proof.is_empty()
                    || proof.structured_proof.len()
                        > crate::MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
                {
                    return Err(BlsDoryV3CandidateError::ProofSize.into());
                }
                if proof.work_digest > block.target {
                    return Err(BlsDoryV3CandidateError::HighHash.into());
                }
                match &verifier.authority {
                    ForgeMatrixV3VerifierAuthority::Production {
                        authenticated,
                        setup,
                    } => preflight_bls_dory_v3_layout_v5_candidate(
                        verifier.parameters.network_id,
                        authenticated,
                        block,
                        proof,
                        setup,
                    )
                    .map_err(PowError::from),
                    #[cfg(test)]
                    ForgeMatrixV3VerifierAuthority::BoundTestStatement { .. } => Ok(()),
                }
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
        self.issue_preverification_capability(block, proof)
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

    /// Returns the verifier identity used by the external-preverification
    /// capability protocol for this exact network. A persistent verifier uses
    /// this during its startup handshake so a wrong-profile or wrong-model
    /// worker is rejected before the node starts accepting peers.
    pub fn external_preverification_identity(
        &self,
        network_id: [u8; 32],
    ) -> Result<[u8; 32], PowError> {
        self.preverification_identity(network_id)
    }

    /// Issues the process-local capability after a trusted external verifier
    /// has accepted the exact bound statement.
    ///
    /// # Safety
    ///
    /// The caller must have obtained `binding` from a fail-closed verifier
    /// process whose executable identity, verifier profile, canonical
    /// request/response, execution time, memory, and output were independently
    /// bounded. A one-shot process must have exited successfully; a persistent
    /// process must have completed its authenticated startup handshake and
    /// remained live through the exact successful response. Calling this based
    /// only on untrusted bytes bypasses proof verification.
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
        self.issue_preverification_capability(block, proof)
    }

    pub(crate) fn verify_preverified(
        &self,
        block: &BlockChallenge,
        proof: &BlockProof,
        preverified: &PreverifiedBlockProof,
    ) -> Result<(), PowError> {
        self.require_matching_proof_type(proof)?;
        let verifier_identity = self.preverification_identity(block.network_id)?;
        let statement_identity = preverified_statement_identity(block, proof);
        if preverified.verifier_identity != verifier_identity
            || preverified.statement_identity != statement_identity
            || preverified.capability_mac
                != self.preverification_capability_mac(verifier_identity, statement_identity)?
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

    fn issue_preverification_capability(
        &self,
        block: &BlockChallenge,
        proof: &BlockProof,
    ) -> Result<PreverifiedBlockProof, PowError> {
        let verifier_identity = self.preverification_identity(block.network_id)?;
        let statement_identity = preverified_statement_identity(block, proof);
        Ok(PreverifiedBlockProof {
            verifier_identity,
            statement_identity,
            capability_mac: self
                .preverification_capability_mac(verifier_identity, statement_identity)?,
        })
    }

    fn capability_nonce(&self) -> u64 {
        match self {
            Self::V1Legacy(instance) => instance.capability_nonce,
            Self::V2Reference(instance) => instance.capability_nonce,
            #[cfg(feature = "dory-v3-consensus-adapter")]
            Self::V3Candidate(instance) => instance.capability_nonce,
        }
    }

    fn preverification_capability_mac(
        &self,
        verifier_identity: [u8; 32],
        statement_identity: [u8; 32],
    ) -> Result<[u8; 32], PowError> {
        let mut hasher = Hasher::new_keyed(preverification_process_key()?);
        hasher.update(PREVERIFIED_CAPABILITY_DOMAIN.as_bytes());
        hasher.update(&self.capability_nonce().to_le_bytes());
        hasher.update(&verifier_identity);
        hasher.update(&statement_identity);
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

    /// Returns the committed identity of the model bytes expected by the v2
    /// accelerator contract.
    pub fn v2_accelerator_model_identity(&self) -> Result<[u8; 32], PowError> {
        match self {
            Self::V2Reference(reference) => Ok(reference.accelerator_model_identity()?),
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
    fn production_authority(
        &self,
    ) -> Result<
        (
            &BankAuthenticatedDoryV3ModelCommitmentRecordV2,
            &DeterministicBlsDorySetup,
        ),
        PowError,
    > {
        match &self.authority {
            ForgeMatrixV3VerifierAuthority::Production {
                authenticated,
                setup,
            } if authenticated.authorizes_bank_reads() => Ok((authenticated, setup)),
            ForgeMatrixV3VerifierAuthority::Production { .. } => {
                Err(BlsDoryV3CandidateError::ProverConfiguration.into())
            }
            #[cfg(test)]
            ForgeMatrixV3VerifierAuthority::BoundTestStatement { .. } => {
                Err(BlsDoryV3CandidateError::ProverConfiguration.into())
            }
        }
    }

    fn prepare_accelerator_batch(
        &self,
        block: &BlockChallenge,
        start_nonce: u64,
        count: u32,
    ) -> Result<ForgeMatrixV3AcceleratorBatch, PowError> {
        if count == 0 || count > MAX_PRODUCTION_V3_ACCELERATOR_BATCH {
            return Err(BlsDoryV3CandidateError::ProverConfiguration.into());
        }
        let (authenticated, _) = self.production_authority()?;
        let transcript = DoryV3TranscriptContext::from_bank_authenticated_record(
            block.network_id,
            authenticated,
        )
        .map_err(BlsDoryV3CandidateError::from)?;
        let identity = authenticated.record().model_identity();
        let rows = usize::try_from(identity.batch())
            .map_err(|_| BlsDoryV3CandidateError::ProductionGeometry)?;
        let columns = usize::try_from(identity.dimension())
            .map_err(|_| BlsDoryV3CandidateError::ProductionGeometry)?;
        let layers = identity
            .weight_bank_count()
            .ok()
            .and_then(|banks| banks.checked_mul(identity.layers_per_bank()))
            .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?;
        let activation_len = rows
            .checked_mul(columns)
            .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?;
        let coefficient_count = 1usize
            .checked_add(rows.ilog2() as usize)
            .and_then(|value| value.checked_add(columns.ilog2() as usize))
            .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?;
        let coefficients_per_nonce = usize::try_from(layers)
            .ok()
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_mul(coefficient_count))
            .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?;
        let mut coefficients = Vec::with_capacity(
            (count as usize)
                .checked_mul(coefficients_per_nonce)
                .ok_or(BlsDoryV3CandidateError::ProductionGeometry)?,
        );
        for offset in 0..count {
            let nonce = start_nonce.wrapping_add(u64::from(offset));
            let challenge_digest = transcript
                .challenge_digest(block, nonce)
                .map_err(BlsDoryV3CandidateError::from)?;
            coefficients.extend(
                dory_v3_mask_coefficients(&challenge_digest, u32::MAX, rows, columns)
                    .map_err(BlsDoryV3CandidateError::from)?,
            );
            for layer in 0..layers {
                coefficients.extend(
                    dory_v3_mask_coefficients(&challenge_digest, layer, rows, columns)
                        .map_err(BlsDoryV3CandidateError::from)?,
                );
            }
        }
        if coefficients.len() != (count as usize) * coefficients_per_nonce {
            return Err(BlsDoryV3CandidateError::ProductionGeometry.into());
        }
        Ok(ForgeMatrixV3AcceleratorBatch {
            block: *block,
            model_record_digest: self.parameters.model_record_digest,
            model_identity_digest: self.parameters.model_identity_digest,
            start_nonce,
            count,
            activation_len,
            coefficients,
        })
    }

    fn winning_nonce_claim_from_accelerator_batch_output(
        &self,
        block: &BlockChallenge,
        batch: &ForgeMatrixV3AcceleratorBatch,
        index: usize,
        final_activation: &[u8],
    ) -> Result<Option<ForgeMatrixV3WinningNonceClaim>, PowError> {
        let nonce = batch
            .nonce_at(index)
            .ok_or(BlsDoryV3CandidateError::ProverConfiguration)?;
        if batch.block != *block
            || batch.model_record_digest != self.parameters.model_record_digest
            || batch.model_identity_digest != self.parameters.model_identity_digest
            || final_activation.len() != batch.activation_len
        {
            return Err(BlsDoryV3CandidateError::ChallengeDigest.into());
        }
        match self.winning_nonce_claim_from_accelerator_output(
            block,
            batch.model_record_digest,
            batch.model_identity_digest,
            nonce,
            final_activation,
        ) {
            Ok(claim) => Ok(Some(claim)),
            Err(PowError::V3(BlsDoryV3CandidateError::HighHash)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn winning_nonce_claim_from_accelerator_output(
        &self,
        block: &BlockChallenge,
        accelerator_model_record_digest: [u8; 32],
        accelerator_model_identity_digest: [u8; 32],
        nonce: u64,
        final_activation: &[u8],
    ) -> Result<ForgeMatrixV3WinningNonceClaim, PowError> {
        if block.network_id != self.parameters.network_id {
            return Err(BlsDoryV3CandidateError::WrongNetwork.into());
        }
        if accelerator_model_record_digest != self.parameters.model_record_digest {
            return Err(BlsDoryV3CandidateError::ModelRecordDigest.into());
        }
        if accelerator_model_identity_digest != self.parameters.model_identity_digest {
            return Err(BlsDoryV3CandidateError::ModelIdentityDigest.into());
        }
        let (authenticated, _) = self.production_authority()?;
        let transcript =
            crate::dory_v3_transcript::DoryV3TranscriptContext::from_bank_authenticated_record(
                block.network_id,
                authenticated,
            )
            .map_err(BlsDoryV3CandidateError::from)?;
        let challenge = transcript
            .challenge_context(block, nonce)
            .map_err(BlsDoryV3CandidateError::from)?;
        let final_activation_digest = challenge
            .output_digest(final_activation)
            .map_err(BlsDoryV3CandidateError::from)?;
        let work_digest = challenge.work_digest(final_activation_digest);
        if work_digest > block.target {
            return Err(BlsDoryV3CandidateError::HighHash.into());
        }
        Ok(ForgeMatrixV3WinningNonceClaim::new(
            self.parameters.network_id,
            self.parameters.model_record_digest,
            self.parameters.model_identity_digest,
            nonce,
            final_activation_digest,
            work_digest,
        ))
    }

    fn validate_winning_nonce_claim(
        &self,
        block: &BlockChallenge,
        claim: ForgeMatrixV3WinningNonceClaim,
        cancel: &AtomicBool,
    ) -> Result<(), PowError> {
        if block.network_id != self.parameters.network_id
            || claim.network_id != self.parameters.network_id
        {
            return Err(BlsDoryV3CandidateError::WrongNetwork.into());
        }
        if claim.model_record_digest != self.parameters.model_record_digest {
            return Err(BlsDoryV3CandidateError::ModelRecordDigest.into());
        }
        if claim.model_identity_digest != self.parameters.model_identity_digest {
            return Err(BlsDoryV3CandidateError::ModelIdentityDigest.into());
        }
        #[cfg(test)]
        if matches!(
            self.authority,
            ForgeMatrixV3VerifierAuthority::BoundTestStatement { .. }
        ) {
            return Ok(());
        }
        let (authenticated, _) = self.production_authority()?;
        let transcript = DoryV3TranscriptContext::from_bank_authenticated_record(
            block.network_id,
            authenticated,
        )
        .map_err(BlsDoryV3CandidateError::from)?;
        let _ = validate_dory_v3_replay_claim(
            authenticated,
            transcript,
            block,
            BlsDoryV3WinningNonceClaim {
                nonce: claim.nonce,
                final_activation_digest: claim.final_activation_digest,
                work_digest: claim.work_digest,
            },
            cancel,
        )
        .map_err(BlsDoryV3CandidateError::from)?;
        Ok(())
    }

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

fn preverification_process_key() -> Result<&'static [u8; 32], PowError> {
    if let Some(key) = PREVERIFICATION_PROCESS_KEY.get() {
        return Ok(key);
    }
    let mut candidate = [0_u8; 32];
    getrandom::fill(&mut candidate).map_err(|_| PowError::PreverificationEntropy)?;
    let _ = PREVERIFICATION_PROCESS_KEY.set(candidate);
    PREVERIFICATION_PROCESS_KEY
        .get()
        .ok_or(PowError::PreverificationEntropy)
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

        let v4_proof = BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
            algorithm_version: 4,
            proof_version: 1,
            nonce: 0,
            proof_system_digest: [1; 32],
            model_manifest_digest: [2; 32],
            challenge_digest: [3; 32],
            final_activation_digest: [4; 32],
            work_digest: [5; 32],
            transparent_proof: vec![6],
        }));
        assert_eq!(v4_proof.proof_type(), POW_TYPE_V4_CANDIDATE);
        assert_eq!(v4_proof.work_digest(), [5; 32]);
        assert!(matches!(
            v1.verify(&block(crate::PRODUCTION_V4_TESTNET_NETWORK_ID), &v4_proof),
            Err(PowError::WrongProofType)
        ));
    }

    #[test]
    fn v4_statement_identity_binds_every_challenge_and_proof_byte() {
        let challenge = block(crate::PRODUCTION_V4_TESTNET_NETWORK_ID);
        let candidate = ForgeMatrixV4CandidateProof {
            algorithm_version: 4,
            proof_version: 1,
            nonce: 7,
            proof_system_digest: [1; 32],
            model_manifest_digest: [2; 32],
            challenge_digest: [3; 32],
            final_activation_digest: [4; 32],
            work_digest: [5; 32],
            transparent_proof: vec![6, 7],
        };
        let proof = BlockProof::V4Candidate(Box::new(candidate.clone()));
        let expected = preverified_statement_identity(&challenge, &proof);

        type Mutation = fn(&mut BlockChallenge, &mut ForgeMatrixV4CandidateProof);
        let mutations: [(&str, Mutation); 16] = [
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
            ("proof_system_digest", |_, proof| {
                proof.proof_system_digest[0] ^= 1
            }),
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
            ("transparent_proof_byte", |_, proof| {
                proof.transparent_proof[0] ^= 1
            }),
            ("transparent_proof_length", |_, proof| {
                proof.transparent_proof.push(8)
            }),
        ];

        for (name, mutate) in mutations {
            let mut changed_challenge = challenge;
            let mut changed_candidate = candidate.clone();
            mutate(&mut changed_challenge, &mut changed_candidate);
            let changed_proof = BlockProof::V4Candidate(Box::new(changed_candidate));
            assert_ne!(
                preverified_statement_identity(&changed_challenge, &changed_proof),
                expected,
                "statement mutation not absorbed: {name}"
            );
        }
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
    fn v1_cheap_preflight_rejects_every_bound_mutation_before_relation_dispatch() {
        let verifier = ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap();
        let challenge = block([0x63; 32]);
        let proof = verifier.mine(&challenge, 0, 1).unwrap();
        type Mutation = fn(&mut BlockChallenge, &mut ForgeMatrixProof);
        let mutations: [(&str, Mutation); 11] = [
            ("network", |block, _| block.network_id[0] ^= 1),
            ("parent", |block, _| block.previous_block[0] ^= 1),
            ("transaction_root", |block, _| {
                block.transaction_root[0] ^= 1
            }),
            ("height", |block, _| block.height ^= 1),
            ("timestamp", |block, _| block.timestamp ^= 1),
            ("target", |block, _| block.target[0] ^= 1),
            ("algorithm_version", |_, proof| proof.algorithm_version ^= 1),
            ("model_version", |_, proof| proof.model_version ^= 1),
            ("nonce", |_, proof| proof.nonce ^= 1),
            ("model_root", |_, proof| proof.model_root[0] ^= 1),
            ("output_digest", |_, proof| proof.output_digest[0] ^= 1),
        ];
        for (name, mutate) in mutations {
            let mut changed_block = challenge;
            let BlockProof::V1Legacy(mut changed_proof) = proof.clone() else {
                unreachable!();
            };
            mutate(&mut changed_block, &mut changed_proof);
            assert!(
                verifier
                    .verify(&changed_block, &BlockProof::V1Legacy(changed_proof))
                    .is_err(),
                "cheap mutation accepted: {name}"
            );
            assert_eq!(relation_dispatches(&verifier), 0, "dispatched: {name}");
        }

        let mut high_block = challenge;
        high_block.target = [0; 32];
        let BlockProof::V1Legacy(mut high_proof) = proof.clone() else {
            unreachable!();
        };
        let ConsensusPowVerifier::V1Legacy(inner) = &verifier else {
            unreachable!();
        };
        high_proof.work_digest =
            inner.claimed_work_digest(&high_block, high_proof.nonce, high_proof.output_digest);
        assert_ne!(high_proof.work_digest, [0; 32]);
        assert!(matches!(
            verifier.verify(&high_block, &BlockProof::V1Legacy(high_proof)),
            Err(PowError::V1(ForgeMatrixError::HighHash))
        ));
        assert_eq!(relation_dispatches(&verifier), 0);

        verifier.verify(&challenge, &proof).unwrap();
        assert_eq!(relation_dispatches(&verifier), 1);
    }

    #[test]
    fn v2_cheap_preflight_rejects_every_bound_mutation_before_relation_dispatch() {
        let reference = v2_test_reference().unwrap();
        let challenge = block(reference.descriptor().network_id);
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let proof = verifier.mine(&challenge, 0, 1).unwrap();
        type Mutation = fn(&mut BlockChallenge, &mut ForgeMatrixV2CompactProof);
        let mutations: [(&str, Mutation); 13] = [
            ("network", |block, _| block.network_id[0] ^= 1),
            ("parent", |block, _| block.previous_block[0] ^= 1),
            ("transaction_root", |block, _| {
                block.transaction_root[0] ^= 1
            }),
            ("height", |block, _| block.height ^= 1),
            ("timestamp", |block, _| block.timestamp ^= 1),
            ("target", |block, _| block.target[0] ^= 1),
            ("algorithm_version", |_, proof| proof.algorithm_version ^= 1),
            ("proof_version", |_, proof| proof.proof_version ^= 1),
            ("nonce", |_, proof| proof.nonce ^= 1),
            ("manifest", |_, proof| proof.model_manifest_digest[0] ^= 1),
            ("challenge", |_, proof| proof.challenge_digest[0] ^= 1),
            ("activation", |_, proof| {
                proof.final_activation_digest[0] ^= 1
            }),
            ("work", |_, proof| proof.work_digest[0] ^= 1),
        ];
        for (name, mutate) in mutations {
            let mut changed_block = challenge;
            let BlockProof::V2Reference(mut changed_proof) = proof.clone() else {
                unreachable!();
            };
            mutate(&mut changed_block, &mut changed_proof);
            assert!(
                verifier
                    .verify(&changed_block, &BlockProof::V2Reference(changed_proof),)
                    .is_err(),
                "cheap mutation accepted: {name}"
            );
            assert_eq!(relation_dispatches(&verifier), 0, "dispatched: {name}");
        }

        let mut high_block = challenge;
        high_block.target = [0; 32];
        let BlockProof::V2Reference(mut high_proof) = proof.clone() else {
            unreachable!();
        };
        let ConsensusPowVerifier::V2Reference(inner) = &verifier else {
            unreachable!();
        };
        (high_proof.challenge_digest, high_proof.work_digest) = inner
            .claimed_compact_digests(
                &high_block,
                high_proof.nonce,
                high_proof.final_activation_digest,
            )
            .unwrap();
        assert_ne!(high_proof.work_digest, [0; 32]);
        assert!(matches!(
            verifier.verify(&high_block, &BlockProof::V2Reference(high_proof)),
            Err(PowError::V2(ForgeMatrixV2Error::HighHash))
        ));
        assert_eq!(relation_dispatches(&verifier), 0);

        verifier.verify(&challenge, &proof).unwrap();
        assert_eq!(relation_dispatches(&verifier), 1);
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
    fn independent_same_parameter_verifier_cannot_mint_a_live_capability() {
        let reference = v2_test_reference().unwrap();
        let network_id = reference.descriptor().network_id;
        let live = ConsensusPowVerifier::v2_reference(reference.clone());
        let attacker = ConsensusPowVerifier::v2_reference(reference);
        let challenge = block(network_id);
        let proof = live.mine(&challenge, 7, 1).unwrap();
        let binding = attacker
            .external_preverification_binding(&challenge, &proof)
            .unwrap();
        let forged_for_own_instance = unsafe {
            attacker
                .issue_external_preverification(&challenge, &proof, binding)
                .unwrap()
        };

        assert!(matches!(
            live.verify_preverified(&challenge, &proof, &forged_for_own_instance),
            Err(PowError::PreverificationMismatch)
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
        ConsensusPowVerifier::V3Candidate(Arc::new(VerifierInstance::new(
            ForgeMatrixV3ConsensusVerifier {
                parameters,
                authority: ForgeMatrixV3VerifierAuthority::BoundTestStatement {
                    statement_identity: preverified_statement_identity(challenge, &proof),
                },
            },
        )))
    }

    fn relation_dispatches(verifier: &ConsensusPowVerifier) -> u64 {
        match verifier {
            ConsensusPowVerifier::V1Legacy(verifier) => verifier.relation_dispatches(),
            ConsensusPowVerifier::V2Reference(verifier) => verifier.relation_dispatches(),
            #[cfg(feature = "dory-v3-consensus-adapter")]
            ConsensusPowVerifier::V3Candidate(verifier) => verifier.relation_dispatches(),
        }
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    fn v3_winning_claim(
        parameters: ForgeMatrixV3CandidateParameters,
    ) -> ForgeMatrixV3WinningNonceClaim {
        ForgeMatrixV3WinningNonceClaim::new(
            parameters.network_id(),
            parameters.model_record_digest(),
            parameters.model_identity_digest(),
            9,
            [0x81; 32],
            [0x92; 32],
        )
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[test]
    fn v3_winning_claim_is_bound_to_the_exact_network_and_model() {
        let parameters = v3_parameters();
        let challenge = block(parameters.network_id());
        let proof = v3_proof();
        let verifier = bound_v3_test_verifier(parameters, &challenge, &proof);
        let claim = v3_winning_claim(parameters);
        verifier
            .validate_v3_winning_nonce_claim(&challenge, claim)
            .unwrap();

        let wrong_network = ForgeMatrixV3WinningNonceClaim::new(
            [0x11; 32],
            claim.model_record_digest(),
            claim.model_identity_digest(),
            claim.nonce(),
            claim.final_activation_digest(),
            claim.work_digest(),
        );
        assert!(matches!(
            verifier.validate_v3_winning_nonce_claim(&challenge, wrong_network),
            Err(PowError::V3(BlsDoryV3CandidateError::WrongNetwork))
        ));

        let wrong_record = ForgeMatrixV3WinningNonceClaim::new(
            claim.network_id(),
            [0x22; 32],
            claim.model_identity_digest(),
            claim.nonce(),
            claim.final_activation_digest(),
            claim.work_digest(),
        );
        assert!(matches!(
            verifier.validate_v3_winning_nonce_claim(&challenge, wrong_record),
            Err(PowError::V3(BlsDoryV3CandidateError::ModelRecordDigest))
        ));

        let wrong_model = ForgeMatrixV3WinningNonceClaim::new(
            claim.network_id(),
            claim.model_record_digest(),
            [0x33; 32],
            claim.nonce(),
            claim.final_activation_digest(),
            claim.work_digest(),
        );
        assert!(matches!(
            verifier.validate_v3_winning_nonce_claim(&challenge, wrong_model),
            Err(PowError::V3(BlsDoryV3CandidateError::ModelIdentityDigest))
        ));

        let mut wrong_challenge = challenge;
        wrong_challenge.network_id[0] ^= 1;
        assert!(matches!(
            verifier.validate_v3_winning_nonce_claim(&wrong_challenge, claim),
            Err(PowError::V3(BlsDoryV3CandidateError::WrongNetwork))
        ));
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[test]
    fn v3_accelerator_output_rejects_wrong_model_identity_before_replay() {
        let parameters = v3_parameters();
        let challenge = block(parameters.network_id());
        let proof = v3_proof();
        let verifier = bound_v3_test_verifier(parameters, &challenge, &proof);

        assert!(matches!(
            verifier.v3_winning_nonce_claim_from_accelerator_output(
                &challenge,
                [0x22; 32],
                parameters.model_identity_digest(),
                9,
                &[],
            ),
            Err(PowError::V3(BlsDoryV3CandidateError::ModelRecordDigest))
        ));
        assert!(matches!(
            verifier.v3_winning_nonce_claim_from_accelerator_output(
                &challenge,
                parameters.model_record_digest(),
                [0x33; 32],
                9,
                &[],
            ),
            Err(PowError::V3(BlsDoryV3CandidateError::ModelIdentityDigest))
        ));
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[test]
    fn v2_verifier_never_accepts_or_falls_back_for_a_v3_winning_claim() {
        let reference = v2_test_reference().unwrap();
        let challenge = block(reference.descriptor().network_id);
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let parameters = v3_parameters();
        let claim = v3_winning_claim(parameters);
        assert!(matches!(
            verifier.validate_v3_winning_nonce_claim(&challenge, claim),
            Err(PowError::WrongProofType)
        ));
        assert!(matches!(
            verifier.prove_v3_winning_nonce_claim(
                &challenge,
                claim,
                std::io::empty(),
                std::io::empty(),
                &std::env::current_dir().unwrap(),
                MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS,
                &AtomicBool::new(false),
            ),
            Err(PowError::WrongProofType)
        ));
    }

    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[test]
    fn runtime_v3_prover_rejects_unbounded_native_row_limits_before_bank_reads() {
        let parameters = v3_parameters();
        let challenge = block(parameters.network_id());
        let proof = v3_proof();
        let verifier = bound_v3_test_verifier(parameters, &challenge, &proof);
        let claim = v3_winning_claim(parameters);
        for rows in [0, MAX_PRODUCTION_V3_NATIVE_BLOCK_ROWS + 1] {
            assert!(matches!(
                verifier.prove_v3_winning_nonce_claim(
                    &challenge,
                    claim,
                    std::io::empty(),
                    std::io::empty(),
                    &std::env::current_dir().unwrap(),
                    rows,
                    &AtomicBool::new(false),
                ),
                Err(PowError::V3(BlsDoryV3CandidateError::ProverConfiguration))
            ));
        }
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
        assert!(matches!(
            verifier.v2_accelerator_model_identity(),
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
