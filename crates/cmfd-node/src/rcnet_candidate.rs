//! Canonical, create-new ProductionV4 launch-candidate derivation for RCNet-1.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use cmfd_consensus::forgematrix_v4_proof_codec::FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES;
use cmfd_consensus::{
    BLOCK_VERSION, COIN, COINBASE_MATURITY, CONSENSUS_SIGNATURE_BYTES, DEFAULT_MONETARY_POLICY,
    DGW_WINDOW, FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_FIXED_ARTIFACT_RECORD_VERSION,
    FORGEMATRIX_V4_PROOF_VERSION, FixedRewardDestinations, ForgeMatrixV4FixedArtifactRecordV1,
    MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS, MAX_BLOCK_SIGNATURE_CHECKS,
    MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS, MAX_FUTURE_OFFSET_SECS, MAX_TRANSACTION_BYTES,
    MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS, MEDIAN_TIME_WINDOW, NETWORK_PROTOCOL_VERSION,
    POW_TYPE_V4_CANDIDATE, PRODUCTION_V2_BANKS, PRODUCTION_V2_LAYERS_PER_BANK,
    PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST, PRODUCTION_V4_MAX_BLOCK_BYTES,
    PRODUCTION_V4_MAX_PROOF_BYTES, PRODUCTION_V4_MODEL_MANIFEST_DIGEST, TARGET_SPACING_SECONDS,
    TRANSACTION_VERSION, WIRE_HEADER_BYTES, WIRE_VERSION,
    canonical_forgematrix_v4_fixed_artifact_record_json,
    forgematrix_v4_fixed_artifact_format_digest, forgematrix_v4_proof_system_digest,
    verify_model_bank,
};
use k256::schnorr::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const CANDIDATE_SCHEMA: &str = "CMFD_RCNET_LAUNCH_CANDIDATE_V2";
const PROFILE_NAME: &str = "CommonFoundry RCNet-1";
const PROOF_SELECTION: &str = "ProductionV4";
const LAUNCH_ROOT_DOMAIN: &str = "CMFD/RCNET/LAUNCH-ROOT/V2";
const NETWORK_ID_DOMAIN: &str = "CMFD/RCNET/NETWORK-ID/V2";
const VIRTUAL_GENESIS_DOMAIN: &str = "CMFD/RCNET/VIRTUAL-GENESIS/V2";
const MAX_FIXED_RECORD_BYTES: u64 = 1024 * 1024;

const INSECURE_DEV_DESTINATIONS: [[u8; 32]; 2] = [
    [
        0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61, 0x5d,
        0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07, 0x58,
        0x71, 0xaa,
    ],
    [
        0x63, 0x60, 0xe8, 0x56, 0x31, 0x0c, 0xe5, 0xd2, 0x94, 0xe8, 0xbe, 0x33, 0xfc, 0x80, 0x70,
        0x77, 0xdc, 0x56, 0xac, 0x80, 0xd9, 0x5d, 0x9c, 0xd4, 0xdd, 0xbd, 0x21, 0x32, 0x5e, 0xff,
        0x73, 0xf7,
    ],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RcnetLaunchConfiguration {
    pub virtual_genesis_timestamp: u64,
    pub pow_limit: [u8; 32],
    pub rewards: FixedRewardDestinations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RcnetLaunchCandidate {
    schema: String,
    payload: RcnetLaunchPayload,
    launch_root: String,
    network_id: String,
    virtual_genesis_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RcnetLaunchPayload {
    profile: String,
    artifacts: ProductionV4ArtifactIdentity,
    virtual_genesis_timestamp_unix_seconds: u64,
    consensus: ConsensusParameters,
    proof_of_work: ProofOfWorkParameters,
    monetary_policy: MonetaryPolicyParameters,
    reward_destinations: RewardDestinations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionV4ArtifactIdentity {
    bank: ArtifactFileIdentity,
    fixed_record: ArtifactFileIdentity,
    fixed_record_version: u16,
    proof_system_digest: String,
    model_manifest_digest: String,
    fixed_artifact_format_digest: String,
    fixed_artifact_record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFileIdentity {
    bytes: u64,
    blake3: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsensusParameters {
    network_protocol_version: u32,
    block_version: u32,
    transaction_version: u32,
    wire_version: u16,
    maximum_future_offset_seconds: u64,
    target_spacing_seconds: u64,
    coinbase_maturity_blocks: u64,
    median_time_window: u64,
    max_block_transactions: u64,
    max_transaction_inputs: u64,
    max_transaction_outputs: u64,
    max_block_aggregate_inputs: u64,
    max_block_aggregate_outputs: u64,
    max_block_signature_checks: u64,
    max_coinbase_outputs: u64,
    consensus_signature_bytes: u64,
    dgw_window: u64,
    wire_header_bytes: u64,
    max_transaction_bytes: u64,
    max_proof_bytes: u64,
    max_block_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofOfWorkParameters {
    selection: String,
    wire_type: u16,
    algorithm_version: u32,
    proof_version: u32,
    banks: u32,
    layers_per_bank: u32,
    exact_transparent_proof_bytes: u64,
    pow_limit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MonetaryPolicyParameters {
    atoms_per_coin: u64,
    initial_subsidy_atoms: u64,
    tail_height: u64,
    tail_subsidy_atoms: u64,
    steward_percent: u8,
    community_percent: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RewardDestinations {
    steward_xonly_public_key: String,
    community_xonly_public_key: String,
}

#[derive(Debug, Error)]
pub enum RcnetCandidateError {
    #[error("ProductionV4 fixed artifact record is invalid: {0}")]
    InvalidFixedRecord(#[from] cmfd_consensus::ForgeMatrixV4FixedArtifactRecordError),
    #[error("ProductionV4 model bank is invalid: {0}")]
    InvalidModelBank(#[from] cmfd_consensus::ModelBankError),
    #[error("launch candidate JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("launch candidate artifact could not be read or written: {0}")]
    Io(#[from] std::io::Error),
    #[error("ProductionV4 fixed artifact record is not canonically encoded")]
    NonCanonicalFixedRecord,
    #[error("RCNet-1 launch candidate is not canonically encoded")]
    NonCanonicalCandidate,
    #[error("launch candidate is not the exact compiled RCNet-1 Candidate V2")]
    UnexpectedCompiledCandidate,
    #[error("launch candidate field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("launch candidate derived identity does not match its payload")]
    DerivedIdentityMismatch,
}

impl ConsensusParameters {
    fn compiled() -> Self {
        Self {
            network_protocol_version: NETWORK_PROTOCOL_VERSION,
            block_version: BLOCK_VERSION,
            transaction_version: TRANSACTION_VERSION,
            wire_version: WIRE_VERSION,
            maximum_future_offset_seconds: MAX_FUTURE_OFFSET_SECS,
            target_spacing_seconds: TARGET_SPACING_SECONDS,
            coinbase_maturity_blocks: COINBASE_MATURITY,
            median_time_window: MEDIAN_TIME_WINDOW as u64,
            max_block_transactions: MAX_BLOCK_TRANSACTIONS as u64,
            max_transaction_inputs: MAX_TRANSACTION_INPUTS as u64,
            max_transaction_outputs: MAX_TRANSACTION_OUTPUTS as u64,
            max_block_aggregate_inputs: MAX_BLOCK_AGGREGATE_INPUTS as u64,
            max_block_aggregate_outputs: MAX_BLOCK_AGGREGATE_OUTPUTS as u64,
            max_block_signature_checks: MAX_BLOCK_SIGNATURE_CHECKS as u64,
            max_coinbase_outputs: MAX_COINBASE_OUTPUTS as u64,
            consensus_signature_bytes: CONSENSUS_SIGNATURE_BYTES as u64,
            dgw_window: DGW_WINDOW as u64,
            wire_header_bytes: WIRE_HEADER_BYTES as u64,
            max_transaction_bytes: MAX_TRANSACTION_BYTES as u64,
            max_proof_bytes: PRODUCTION_V4_MAX_PROOF_BYTES as u64,
            max_block_bytes: PRODUCTION_V4_MAX_BLOCK_BYTES as u64,
        }
    }
}

impl ProofOfWorkParameters {
    fn compiled(pow_limit: [u8; 32]) -> Self {
        Self {
            selection: PROOF_SELECTION.to_owned(),
            wire_type: POW_TYPE_V4_CANDIDATE,
            algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V4_PROOF_VERSION,
            banks: PRODUCTION_V2_BANKS,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            exact_transparent_proof_bytes: FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES as u64,
            pow_limit: hex::encode(pow_limit),
        }
    }
}

impl MonetaryPolicyParameters {
    fn compiled() -> Self {
        Self {
            atoms_per_coin: COIN,
            initial_subsidy_atoms: DEFAULT_MONETARY_POLICY.initial_subsidy,
            tail_height: DEFAULT_MONETARY_POLICY.tail_height,
            tail_subsidy_atoms: DEFAULT_MONETARY_POLICY.tail_subsidy,
            steward_percent: DEFAULT_MONETARY_POLICY.steward_percent,
            community_percent: DEFAULT_MONETARY_POLICY.community_percent,
        }
    }
}

impl ProductionV4ArtifactIdentity {
    fn from_files(bank: ArtifactFileIdentity, fixed_record: ArtifactFileIdentity) -> Self {
        Self {
            bank,
            fixed_record,
            fixed_record_version: FORGEMATRIX_V4_FIXED_ARTIFACT_RECORD_VERSION,
            proof_system_digest: hex::encode(forgematrix_v4_proof_system_digest()),
            model_manifest_digest: hex::encode(PRODUCTION_V4_MODEL_MANIFEST_DIGEST),
            fixed_artifact_format_digest: hex::encode(forgematrix_v4_fixed_artifact_format_digest()),
            fixed_artifact_record_digest: hex::encode(PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST),
        }
    }
}

impl RcnetLaunchCandidate {
    /// Reconstructs the one RCNet-1 launch candidate selected by the
    /// ProductionV4 qualification build. This uses compiled file identities;
    /// callers must still authenticate the supplied artifact files before
    /// producing qualification work.
    #[cfg(feature = "production-v4-testnet")]
    pub fn compiled_rcnet1() -> Result<Self, RcnetCandidateError> {
        let pins = crate::release_gate::PRODUCTION_V4_ARTIFACT_PINS;
        let artifacts = ProductionV4ArtifactIdentity::from_files(
            ArtifactFileIdentity {
                bytes: pins.bank.bytes,
                blake3: hex::encode(pins.bank.blake3),
                sha256: hex::encode(pins.bank.sha256),
            },
            ArtifactFileIdentity {
                bytes: pins.fixed_record.bytes,
                blake3: hex::encode(pins.fixed_record.blake3),
                sha256: hex::encode(pins.fixed_record.sha256),
            },
        );
        let profile = crate::RCNET1_PROFILE;
        let candidate = Self::from_artifact_identities(
            artifacts,
            RcnetLaunchConfiguration {
                virtual_genesis_timestamp: profile.virtual_genesis_timestamp,
                pow_limit: profile.pow_limit,
                rewards: FixedRewardDestinations {
                    steward: profile.rewards.steward,
                    community: profile.rewards.community,
                },
            },
        )?;
        if decode_hex32(&candidate.network_id)? != profile.network_id
            || decode_hex32(&candidate.virtual_genesis_hash)? != profile.virtual_genesis_hash
        {
            return Err(RcnetCandidateError::UnexpectedCompiledCandidate);
        }
        Ok(candidate)
    }

    /// Parses only byte-exact canonical Candidate V2 JSON for the compiled
    /// RCNet-1 identity. A self-consistent alternative candidate is rejected.
    #[cfg(feature = "production-v4-testnet")]
    pub fn parse_exact_compiled_rcnet1(bytes: &[u8]) -> Result<Self, RcnetCandidateError> {
        let candidate: Self = serde_json::from_slice(bytes)?;
        if candidate.canonical_json()? != bytes {
            return Err(RcnetCandidateError::NonCanonicalCandidate);
        }
        if candidate != Self::compiled_rcnet1()? {
            return Err(RcnetCandidateError::UnexpectedCompiledCandidate);
        }
        Ok(candidate)
    }

    /// Authenticates the exact canonical fixed record and the complete model bank
    /// before deriving an immutable RCNet identity from their file identities.
    pub fn from_artifact_paths(
        model_bank_path: &Path,
        fixed_record_path: &Path,
        config: RcnetLaunchConfiguration,
    ) -> Result<Self, RcnetCandidateError> {
        let (fixed_record, fixed_record_file) = load_fixed_record(fixed_record_path)?;
        validate_compiled_fixed_record(&fixed_record)?;
        let bank_file = authenticate_and_hash_model_bank(model_bank_path, &fixed_record)?;
        Self::from_artifact_identities(
            ProductionV4ArtifactIdentity::from_files(bank_file, fixed_record_file),
            config,
        )
    }

    fn from_artifact_identities(
        artifacts: ProductionV4ArtifactIdentity,
        config: RcnetLaunchConfiguration,
    ) -> Result<Self, RcnetCandidateError> {
        let payload = RcnetLaunchPayload {
            profile: PROFILE_NAME.to_owned(),
            artifacts,
            virtual_genesis_timestamp_unix_seconds: config.virtual_genesis_timestamp,
            consensus: ConsensusParameters::compiled(),
            proof_of_work: ProofOfWorkParameters::compiled(config.pow_limit),
            monetary_policy: MonetaryPolicyParameters::compiled(),
            reward_destinations: RewardDestinations {
                steward_xonly_public_key: hex::encode(config.rewards.steward),
                community_xonly_public_key: hex::encode(config.rewards.community),
            },
        };
        Self::from_payload(payload)
    }

    fn from_payload(payload: RcnetLaunchPayload) -> Result<Self, RcnetCandidateError> {
        validate_payload(&payload)?;
        let launch_root = derive(LAUNCH_ROOT_DOMAIN, &serde_json::to_vec(&payload)?);
        let network_id = derive(NETWORK_ID_DOMAIN, &launch_root);
        let virtual_genesis_hash = derive(VIRTUAL_GENESIS_DOMAIN, &launch_root);
        Ok(Self {
            schema: CANDIDATE_SCHEMA.to_owned(),
            payload,
            launch_root: hex::encode(launch_root),
            network_id: hex::encode(network_id),
            virtual_genesis_hash: hex::encode(virtual_genesis_hash),
        })
    }

    pub fn validate(&self) -> Result<(), RcnetCandidateError> {
        if self.schema != CANDIDATE_SCHEMA {
            return Err(RcnetCandidateError::InvalidField("schema"));
        }
        validate_payload(&self.payload)?;
        let launch_root = derive(LAUNCH_ROOT_DOMAIN, &serde_json::to_vec(&self.payload)?);
        let network_id = derive(NETWORK_ID_DOMAIN, &launch_root);
        let virtual_genesis_hash = derive(VIRTUAL_GENESIS_DOMAIN, &launch_root);
        if decode_hex32(&self.launch_root)? != launch_root
            || decode_hex32(&self.network_id)? != network_id
            || decode_hex32(&self.virtual_genesis_hash)? != virtual_genesis_hash
            || network_id == virtual_genesis_hash
        {
            return Err(RcnetCandidateError::DerivedIdentityMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, RcnetCandidateError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

pub fn write_candidate_create_new(
    path: &Path,
    candidate: &RcnetLaunchCandidate,
) -> Result<(), RcnetCandidateError> {
    let bytes = candidate.canonical_json()?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}

fn load_fixed_record(
    path: &Path,
) -> Result<(ForgeMatrixV4FixedArtifactRecordV1, ArtifactFileIdentity), RcnetCandidateError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_FIXED_RECORD_BYTES {
        return Err(RcnetCandidateError::InvalidField(
            "fixed artifact record file length",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(RcnetCandidateError::InvalidField(
            "fixed artifact record changed while being read",
        ));
    }
    let record: ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_slice(&bytes)?;
    record.validate()?;
    if bytes != canonical_forgematrix_v4_fixed_artifact_record_json(&record)? {
        return Err(RcnetCandidateError::NonCanonicalFixedRecord);
    }
    let identity = file_identity_from_bytes(&bytes);
    validate_file_identity(&identity, "fixed artifact record file identity")?;
    Ok((record, identity))
}

fn validate_compiled_fixed_record(
    record: &ForgeMatrixV4FixedArtifactRecordV1,
) -> Result<(), RcnetCandidateError> {
    if record.manifest_digest() != PRODUCTION_V4_MODEL_MANIFEST_DIGEST {
        return Err(RcnetCandidateError::InvalidField(
            "fixed artifact record model-manifest digest",
        ));
    }
    if record.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        return Err(RcnetCandidateError::InvalidField(
            "fixed artifact record digest",
        ));
    }
    Ok(())
}

fn authenticate_and_hash_model_bank(
    path: &Path,
    record: &ForgeMatrixV4FixedArtifactRecordV1,
) -> Result<ArtifactFileIdentity, RcnetCandidateError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(RcnetCandidateError::InvalidField("model bank file length"));
    }
    let expected_bytes = metadata.len();
    let mut reader = IdentityReader::new(file);
    verify_model_bank(&mut reader, record.manifest())?;
    let identity = reader.finish(expected_bytes)?;
    validate_file_identity(&identity, "model bank file identity")?;
    Ok(identity)
}

struct IdentityReader<R> {
    inner: R,
    bytes: u64,
    blake3: blake3::Hasher,
    sha256: Sha256,
}

impl<R> IdentityReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes: 0,
            blake3: blake3::Hasher::new(),
            sha256: Sha256::new(),
        }
    }

    fn finish(self, expected_bytes: u64) -> Result<ArtifactFileIdentity, RcnetCandidateError> {
        if self.bytes != expected_bytes {
            return Err(RcnetCandidateError::InvalidField(
                "model bank changed while being authenticated",
            ));
        }
        Ok(ArtifactFileIdentity {
            bytes: self.bytes,
            blake3: hex::encode(self.blake3.finalize().as_bytes()),
            sha256: hex::encode(self.sha256.finalize()),
        })
    }
}

impl<R: Read> Read for IdentityReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        let read_u64 = u64::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact read length exceeds u64",
            )
        })?;
        self.bytes = self.bytes.checked_add(read_u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact read length overflowed",
            )
        })?;
        self.blake3.update(&buffer[..read]);
        self.sha256.update(&buffer[..read]);
        Ok(read)
    }
}

fn file_identity_from_bytes(bytes: &[u8]) -> ArtifactFileIdentity {
    ArtifactFileIdentity {
        bytes: bytes.len() as u64,
        blake3: blake3::hash(bytes).to_hex().to_string(),
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

fn validate_file_identity(
    identity: &ArtifactFileIdentity,
    field: &'static str,
) -> Result<(), RcnetCandidateError> {
    if identity.bytes == 0
        || decode_hex32(&identity.blake3)? == [0; 32]
        || decode_hex32(&identity.sha256)? == [0; 32]
    {
        return Err(RcnetCandidateError::InvalidField(field));
    }
    Ok(())
}

fn validate_payload(payload: &RcnetLaunchPayload) -> Result<(), RcnetCandidateError> {
    if payload.profile != PROFILE_NAME {
        return Err(RcnetCandidateError::InvalidField("profile"));
    }
    validate_file_identity(&payload.artifacts.bank, "model bank file identity")?;
    validate_file_identity(
        &payload.artifacts.fixed_record,
        "fixed artifact record file identity",
    )?;
    if payload.artifacts.fixed_record_version != FORGEMATRIX_V4_FIXED_ARTIFACT_RECORD_VERSION
        || payload.artifacts.proof_system_digest
            != hex::encode(forgematrix_v4_proof_system_digest())
        || payload.artifacts.model_manifest_digest
            != hex::encode(PRODUCTION_V4_MODEL_MANIFEST_DIGEST)
        || payload.artifacts.fixed_artifact_format_digest
            != hex::encode(forgematrix_v4_fixed_artifact_format_digest())
        || payload.artifacts.fixed_artifact_record_digest
            != hex::encode(PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST)
    {
        return Err(RcnetCandidateError::InvalidField(
            "ProductionV4 artifact identity",
        ));
    }
    if payload.virtual_genesis_timestamp_unix_seconds == 0
        || payload
            .virtual_genesis_timestamp_unix_seconds
            .checked_add(MAX_FUTURE_OFFSET_SECS)
            .is_none()
    {
        return Err(RcnetCandidateError::InvalidField(
            "virtual genesis timestamp",
        ));
    }
    if payload.consensus != ConsensusParameters::compiled() {
        return Err(RcnetCandidateError::InvalidField("consensus parameters"));
    }
    let pow_limit = decode_hex32(&payload.proof_of_work.pow_limit)?;
    if pow_limit == [0; 32] || payload.proof_of_work != ProofOfWorkParameters::compiled(pow_limit) {
        return Err(RcnetCandidateError::InvalidField(
            "proof-of-work parameters",
        ));
    }
    if payload.monetary_policy != MonetaryPolicyParameters::compiled() {
        return Err(RcnetCandidateError::InvalidField("monetary policy"));
    }
    for (name, encoded) in [
        (
            "steward reward destination",
            &payload.reward_destinations.steward_xonly_public_key,
        ),
        (
            "community reward destination",
            &payload.reward_destinations.community_xonly_public_key,
        ),
    ] {
        let destination = decode_hex32(encoded)?;
        VerifyingKey::from_bytes(&destination)
            .map_err(|_| RcnetCandidateError::InvalidField(name))?;
        if INSECURE_DEV_DESTINATIONS.contains(&destination) {
            return Err(RcnetCandidateError::InvalidField(
                "known insecure development reward destination",
            ));
        }
    }
    Ok(())
}

fn derive(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn decode_hex32(value: &str) -> Result<[u8; 32], RcnetCandidateError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RcnetCandidateError::InvalidField(
            "32-byte lowercase hexadecimal value",
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| RcnetCandidateError::InvalidField("32-byte hexadecimal value"))?;
    bytes
        .try_into()
        .map_err(|_| RcnetCandidateError::InvalidField("32-byte hexadecimal value"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmfd_consensus::{
        ForgeMatrixV4FixedBankArtifactV1, ModelBankManifest, PRODUCTION_V2_BATCH,
        PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    };
    use k256::schnorr::SigningKey;

    fn destination(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into()
    }

    fn config() -> RcnetLaunchConfiguration {
        RcnetLaunchConfiguration {
            virtual_genesis_timestamp: 1_800_000_000,
            pow_limit: [0xff; 32],
            rewards: FixedRewardDestinations {
                steward: destination(0x21),
                community: destination(0x22),
            },
        }
    }

    fn file_identity(seed: u8) -> ArtifactFileIdentity {
        ArtifactFileIdentity {
            bytes: 1_000 + u64::from(seed),
            blake3: hex::encode([seed; 32]),
            sha256: hex::encode([seed.wrapping_add(64); 32]),
        }
    }

    fn artifacts() -> ProductionV4ArtifactIdentity {
        ProductionV4ArtifactIdentity::from_files(file_identity(1), file_identity(2))
    }

    fn payload() -> RcnetLaunchPayload {
        RcnetLaunchPayload {
            profile: PROFILE_NAME.to_owned(),
            artifacts: artifacts(),
            virtual_genesis_timestamp_unix_seconds: config().virtual_genesis_timestamp,
            consensus: ConsensusParameters::compiled(),
            proof_of_work: ProofOfWorkParameters::compiled(config().pow_limit),
            monetary_policy: MonetaryPolicyParameters::compiled(),
            reward_destinations: RewardDestinations {
                steward_xonly_public_key: hex::encode(config().rewards.steward),
                community_xonly_public_key: hex::encode(config().rewards.community),
            },
        }
    }

    fn fixed_record_fixture() -> ForgeMatrixV4FixedArtifactRecordV1 {
        let dimension = u64::from(PRODUCTION_V2_DIMENSION);
        let manifest = ModelBankManifest {
            model_version: 2,
            dimension: PRODUCTION_V2_DIMENSION,
            batch: PRODUCTION_V2_BATCH,
            layers: PRODUCTION_V2_LAYERS,
            base_input_bytes: u64::from(PRODUCTION_V2_BATCH) * dimension,
            bytes_per_layer: dimension * dimension,
            payload_bytes: u64::from(PRODUCTION_V2_BATCH) * dimension
                + u64::from(PRODUCTION_V2_LAYERS) * dimension * dimension,
            raw_blake3_root: [1; 32],
            layer_roots_aggregate: [2; 32],
            pcs_parameter_digest: [3; 32],
            pcs_commitment_root: [4; 32],
        };
        let banks = std::array::from_fn(|bank| {
            ForgeMatrixV4FixedBankArtifactV1::new(
                bank as u32,
                [bank as u32 + 1; 8],
                [bank as u32 + 11; 8],
                [bank as u8 + 21; 32],
                [bank as u8 + 31; 32],
            )
            .unwrap()
        });
        ForgeMatrixV4FixedArtifactRecordV1::new(manifest, banks).unwrap()
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-rcnet-candidate-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn derivation_is_deterministic_non_circular_and_domain_separated() {
        let first = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        let second = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        assert_eq!(first, second);
        first.validate().unwrap();
        assert_ne!(first.launch_root, first.network_id);
        assert_ne!(first.launch_root, first.virtual_genesis_hash);
        assert_ne!(first.network_id, first.virtual_genesis_hash);
        let root = decode_hex32(&first.launch_root).unwrap();
        assert_eq!(
            decode_hex32(&first.network_id).unwrap(),
            derive(NETWORK_ID_DOMAIN, &root)
        );
        assert_ne!(
            decode_hex32(&first.network_id).unwrap(),
            derive(VIRTUAL_GENESIS_DOMAIN, &root)
        );
    }

    #[cfg(feature = "production-v4-testnet")]
    #[test]
    fn compiled_rcnet1_candidate_parser_is_byte_exact_and_rejects_alternatives() {
        let expected = RcnetLaunchCandidate::compiled_rcnet1().unwrap();
        assert_eq!(
            decode_hex32(&expected.network_id).unwrap(),
            crate::RCNET1_PROFILE.network_id
        );
        assert_eq!(
            decode_hex32(&expected.virtual_genesis_hash).unwrap(),
            crate::RCNET1_PROFILE.virtual_genesis_hash
        );
        let canonical = expected.canonical_json().unwrap();
        assert_eq!(
            RcnetLaunchCandidate::parse_exact_compiled_rcnet1(&canonical).unwrap(),
            expected
        );

        let mut noncanonical = canonical.clone();
        noncanonical.insert(0, b' ');
        assert!(matches!(
            RcnetLaunchCandidate::parse_exact_compiled_rcnet1(&noncanonical),
            Err(RcnetCandidateError::NonCanonicalCandidate)
        ));

        let mut alternate_payload = expected.payload.clone();
        alternate_payload.artifacts.bank.sha256 = hex::encode([0x51; 32]);
        let alternate = RcnetLaunchCandidate::from_payload(alternate_payload).unwrap();
        assert!(matches!(
            RcnetLaunchCandidate::parse_exact_compiled_rcnet1(&alternate.canonical_json().unwrap()),
            Err(RcnetCandidateError::UnexpectedCompiledCandidate)
        ));

        let mut wrong_network = expected;
        wrong_network.network_id = hex::encode([0x52; 32]);
        assert!(
            RcnetLaunchCandidate::parse_exact_compiled_rcnet1(
                &serde_json::to_vec_pretty(&wrong_network).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_payload_contains_no_operational_services_or_seed_material() {
        let candidate = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        let value = serde_json::to_value(&candidate).unwrap();
        let payload = value["payload"].as_object().unwrap();
        assert_eq!(
            payload
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "artifacts",
                "consensus",
                "monetary_policy",
                "profile",
                "proof_of_work",
                "reward_destinations",
                "virtual_genesis_timestamp_unix_seconds",
            ]
            .into_iter()
            .collect()
        );
        let encoded = serde_json::to_string(&candidate)
            .unwrap()
            .to_ascii_lowercase();
        for forbidden in [
            "services",
            "bootstrap",
            "seed",
            "ipv4",
            "rpc_port",
            "p2p_port",
            "pool_port",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "found forbidden field {forbidden}"
            );
        }
    }

    #[test]
    fn immutable_mutations_change_the_launch_root_or_fail_validation() {
        let baseline = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        let mut variants = Vec::new();
        let mut value = payload();
        value.artifacts.bank.sha256 = hex::encode([7; 32]);
        variants.push(value);
        let mut value = payload();
        value.artifacts.fixed_record.blake3 = hex::encode([8; 32]);
        variants.push(value);
        let mut value = payload();
        value.virtual_genesis_timestamp_unix_seconds += 1;
        variants.push(value);
        let mut value = payload();
        value.proof_of_work.pow_limit = hex::encode([0xfe; 32]);
        variants.push(value);
        let mut value = payload();
        value.reward_destinations.steward_xonly_public_key = hex::encode(destination(0x23));
        variants.push(value);
        for variant in variants {
            assert_ne!(
                RcnetLaunchCandidate::from_payload(variant)
                    .unwrap()
                    .launch_root,
                baseline.launch_root
            );
        }

        let mut invalid = payload();
        invalid.consensus.target_spacing_seconds += 1;
        assert!(RcnetLaunchCandidate::from_payload(invalid).is_err());
    }

    #[test]
    fn artifact_placeholders_and_internal_digest_mutations_are_rejected() {
        let mut zero_file_digest = payload();
        zero_file_digest.artifacts.bank.blake3 = hex::encode([0; 32]);
        assert!(RcnetLaunchCandidate::from_payload(zero_file_digest).is_err());

        let mut wrong_record_digest = payload();
        wrong_record_digest.artifacts.fixed_artifact_record_digest = hex::encode([9; 32]);
        assert!(RcnetLaunchCandidate::from_payload(wrong_record_digest).is_err());
    }

    #[test]
    fn identity_reader_hashes_the_complete_stream_once() {
        let bytes = b"authenticated ProductionV4 model-bank fixture";
        let mut reader = IdentityReader::new(std::io::Cursor::new(bytes));
        let mut consumed = Vec::new();
        reader.read_to_end(&mut consumed).unwrap();
        assert_eq!(consumed, bytes);
        assert_eq!(
            reader.finish(bytes.len() as u64).unwrap(),
            file_identity_from_bytes(bytes)
        );
    }

    #[test]
    fn canonical_fixed_record_is_loaded_with_its_exact_file_identity() {
        let record = fixed_record_fixture();
        let encoded = canonical_forgematrix_v4_fixed_artifact_record_json(&record).unwrap();
        let path = temp_path("canonical-record");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, &encoded).unwrap();
        let (loaded, identity) = load_fixed_record(&path).unwrap();
        assert_eq!(loaded, record);
        assert_eq!(identity, file_identity_from_bytes(&encoded));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn noncanonical_fixed_record_is_rejected_before_the_bank_is_opened() {
        let record = fixed_record_fixture();
        let path = temp_path("noncanonical-record");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        let missing_bank = path.with_extension("missing-bank");
        assert!(matches!(
            RcnetLaunchCandidate::from_artifact_paths(&missing_bank, &path, config()),
            Err(RcnetCandidateError::NonCanonicalFixedRecord)
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unknown_fields_and_derived_mutations_are_rejected() {
        let candidate = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        let mut value = serde_json::to_value(&candidate).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::json!(1));
        assert!(serde_json::from_value::<RcnetLaunchCandidate>(value).is_err());

        let mut altered = candidate;
        altered.network_id = hex::encode([9; 32]);
        assert!(matches!(
            altered.validate(),
            Err(RcnetCandidateError::DerivedIdentityMismatch)
        ));
    }

    #[test]
    fn unsafe_rewards_are_rejected_and_output_is_create_new() {
        let mut dev_reward = payload();
        dev_reward.reward_destinations.steward_xonly_public_key =
            hex::encode(INSECURE_DEV_DESTINATIONS[0]);
        assert!(RcnetLaunchCandidate::from_payload(dev_reward).is_err());

        let candidate = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        let path = temp_path("create-new");
        let _ = std::fs::remove_file(&path);
        write_candidate_create_new(&path, &candidate).unwrap();
        let encoded = std::fs::read(&path).unwrap();
        assert_eq!(encoded.last(), Some(&b'\n'));
        serde_json::from_slice::<RcnetLaunchCandidate>(&encoded)
            .unwrap()
            .validate()
            .unwrap();
        assert!(write_candidate_create_new(&path, &candidate).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
