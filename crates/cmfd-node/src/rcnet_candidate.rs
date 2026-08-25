//! Canonical, create-new launch candidate derivation for RCNet-1.

use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

use cmfd_consensus::dory_bls12_381_prototype::deterministic_bls_dory_setup;
use cmfd_consensus::dory_v3_model_record::DoryV3ModelCommitmentRecordV2;
use cmfd_consensus::dory_v3_suite::{
    DORY_V3_ALGORITHM_VERSION, DORY_V3_BANKS, DORY_V3_LAYERS_PER_BANK,
    DORY_V3_MAX_STRUCTURED_PROOF_BYTES, DORY_V3_MODEL_RECORD_VERSION, DORY_V3_PADDED_VARIABLES,
    DORY_V3_PROOF_VERSION,
};
use cmfd_consensus::{
    BLOCK_VERSION, COIN, COINBASE_MATURITY, CONSENSUS_SIGNATURE_BYTES, DEFAULT_MONETARY_POLICY,
    DGW_WINDOW, FixedRewardDestinations, MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS,
    MAX_BLOCK_BYTES, MAX_BLOCK_SIGNATURE_CHECKS, MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS,
    MAX_FUTURE_OFFSET_SECS, MAX_PROOF_BYTES, MAX_TRANSACTION_BYTES, MAX_TRANSACTION_INPUTS,
    MAX_TRANSACTION_OUTPUTS, MEDIAN_TIME_WINDOW, NETWORK_PROTOCOL_VERSION, TARGET_SPACING_SECONDS,
    TRANSACTION_VERSION, WIRE_HEADER_BYTES, WIRE_VERSION,
};
use k256::schnorr::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CANDIDATE_SCHEMA: &str = "CMFD_RCNET_LAUNCH_CANDIDATE_V1";
const PROFILE_NAME: &str = "CommonFoundry RCNet-1";
const LAUNCH_ROOT_DOMAIN: &str = "CMFD/RCNET/LAUNCH-ROOT/V1";
const NETWORK_ID_DOMAIN: &str = "CMFD/RCNET/NETWORK-ID/V1";
const VIRTUAL_GENESIS_DOMAIN: &str = "CMFD/RCNET/VIRTUAL-GENESIS/V1";

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
    pub bootstrap_ipv4: Ipv4Addr,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub pool_port: u16,
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
    record_v2: RecordV2Identity,
    virtual_genesis_timestamp_unix_seconds: u64,
    services: ServiceParameters,
    consensus: ConsensusParameters,
    proof_of_work: ProofOfWorkParameters,
    monetary_policy: MonetaryPolicyParameters,
    reward_destinations: RewardDestinations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordV2Identity {
    record_version: u16,
    record_digest: String,
    manifest_digest: String,
    model_identity_digest: String,
    suite_digest: String,
    setup_identity: String,
    padded_variables: u32,
    commitment_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceParameters {
    bootstrap_ipv4: String,
    rpc_port: u16,
    p2p_port: u16,
    pool_port: u16,
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
    algorithm_version: u32,
    proof_version: u32,
    banks: u32,
    layers_per_bank: u32,
    maximum_structured_proof_bytes: u64,
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
    #[error("Record V2 is invalid: {0}")]
    InvalidRecord(#[from] cmfd_consensus::dory_v3_model_record::DoryV3ModelCommitmentRecordError),
    #[error("production Dory setup derivation failed: {0}")]
    InvalidSetup(#[from] cmfd_consensus::dory_bls12_381_prototype::BlsDoryPrototypeError),
    #[error("launch candidate JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("launch candidate output could not be written: {0}")]
    Io(#[from] std::io::Error),
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
            max_proof_bytes: MAX_PROOF_BYTES as u64,
            max_block_bytes: MAX_BLOCK_BYTES as u64,
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

impl RcnetLaunchCandidate {
    pub fn from_record(
        record: &DoryV3ModelCommitmentRecordV2,
        config: RcnetLaunchConfiguration,
    ) -> Result<Self, RcnetCandidateError> {
        let setup = deterministic_bls_dory_setup(DORY_V3_PADDED_VARIABLES as usize)?;
        record.validate_production(&setup)?;
        let payload = RcnetLaunchPayload {
            profile: PROFILE_NAME.to_owned(),
            record_v2: RecordV2Identity {
                record_version: record.record_version(),
                record_digest: hex::encode(record.record_digest().into_bytes()),
                manifest_digest: hex::encode(record.manifest_digest().into_bytes()),
                model_identity_digest: hex::encode(record.model_identity_digest().into_bytes()),
                suite_digest: hex::encode(record.suite_digest().into_bytes()),
                setup_identity: hex::encode(record.setup_identity().into_bytes()),
                padded_variables: record.padded_variables(),
                commitment_root: hex::encode(record.commitment_root().into_bytes()),
            },
            virtual_genesis_timestamp_unix_seconds: config.virtual_genesis_timestamp,
            services: ServiceParameters {
                bootstrap_ipv4: config.bootstrap_ipv4.to_string(),
                rpc_port: config.rpc_port,
                p2p_port: config.p2p_port,
                pool_port: config.pool_port,
            },
            consensus: ConsensusParameters::compiled(),
            proof_of_work: ProofOfWorkParameters {
                algorithm_version: DORY_V3_ALGORITHM_VERSION,
                proof_version: DORY_V3_PROOF_VERSION,
                banks: DORY_V3_BANKS,
                layers_per_bank: DORY_V3_LAYERS_PER_BANK,
                maximum_structured_proof_bytes: u64::from(DORY_V3_MAX_STRUCTURED_PROOF_BYTES),
                pow_limit: hex::encode(config.pow_limit),
            },
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

fn validate_payload(payload: &RcnetLaunchPayload) -> Result<(), RcnetCandidateError> {
    if payload.profile != PROFILE_NAME {
        return Err(RcnetCandidateError::InvalidField("profile"));
    }
    if payload.record_v2.record_version != DORY_V3_MODEL_RECORD_VERSION
        || payload.record_v2.padded_variables != DORY_V3_PADDED_VARIABLES
    {
        return Err(RcnetCandidateError::InvalidField("Record V2 geometry"));
    }
    for digest in [
        &payload.record_v2.record_digest,
        &payload.record_v2.manifest_digest,
        &payload.record_v2.model_identity_digest,
        &payload.record_v2.suite_digest,
        &payload.record_v2.setup_identity,
        &payload.record_v2.commitment_root,
    ] {
        if decode_hex32(digest)? == [0; 32] {
            return Err(RcnetCandidateError::InvalidField("Record V2 identity"));
        }
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
    let bootstrap: Ipv4Addr = payload
        .services
        .bootstrap_ipv4
        .parse()
        .map_err(|_| RcnetCandidateError::InvalidField("bootstrap IPv4 address"))?;
    let octets = bootstrap.octets();
    if matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    ) {
        return Err(RcnetCandidateError::InvalidField(
            "RFC 5737 bootstrap IPv4 address",
        ));
    }
    let ports = [
        payload.services.rpc_port,
        payload.services.p2p_port,
        payload.services.pool_port,
    ];
    if ports.contains(&0) || ports[0] == ports[1] || ports[0] == ports[2] || ports[1] == ports[2] {
        return Err(RcnetCandidateError::InvalidField("service ports"));
    }
    if payload.consensus != ConsensusParameters::compiled() {
        return Err(RcnetCandidateError::InvalidField("consensus parameters"));
    }
    let pow_limit = decode_hex32(&payload.proof_of_work.pow_limit)?;
    let expected_pow = ProofOfWorkParameters {
        pow_limit: payload.proof_of_work.pow_limit.clone(),
        algorithm_version: DORY_V3_ALGORITHM_VERSION,
        proof_version: DORY_V3_PROOF_VERSION,
        banks: DORY_V3_BANKS,
        layers_per_bank: DORY_V3_LAYERS_PER_BANK,
        maximum_structured_proof_bytes: u64::from(DORY_V3_MAX_STRUCTURED_PROOF_BYTES),
    };
    if pow_limit == [0; 32] || payload.proof_of_work != expected_pow {
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
    use k256::schnorr::SigningKey;

    fn destination(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into()
    }

    fn payload() -> RcnetLaunchPayload {
        RcnetLaunchPayload {
            profile: PROFILE_NAME.to_owned(),
            record_v2: RecordV2Identity {
                record_version: DORY_V3_MODEL_RECORD_VERSION,
                record_digest: hex::encode([1; 32]),
                manifest_digest: hex::encode([2; 32]),
                model_identity_digest: hex::encode([3; 32]),
                suite_digest: hex::encode([4; 32]),
                setup_identity: hex::encode([5; 32]),
                padded_variables: DORY_V3_PADDED_VARIABLES,
                commitment_root: hex::encode([6; 32]),
            },
            virtual_genesis_timestamp_unix_seconds: 1_800_000_000,
            services: ServiceParameters {
                bootstrap_ipv4: "8.8.8.8".to_owned(),
                rpc_port: 19_443,
                p2p_port: 19_444,
                pool_port: 19_445,
            },
            consensus: ConsensusParameters::compiled(),
            proof_of_work: ProofOfWorkParameters {
                algorithm_version: DORY_V3_ALGORITHM_VERSION,
                proof_version: DORY_V3_PROOF_VERSION,
                banks: DORY_V3_BANKS,
                layers_per_bank: DORY_V3_LAYERS_PER_BANK,
                maximum_structured_proof_bytes: u64::from(DORY_V3_MAX_STRUCTURED_PROOF_BYTES),
                pow_limit: hex::encode([0xff; 32]),
            },
            monetary_policy: MonetaryPolicyParameters::compiled(),
            reward_destinations: RewardDestinations {
                steward_xonly_public_key: hex::encode(destination(0x21)),
                community_xonly_public_key: hex::encode(destination(0x22)),
            },
        }
    }

    #[test]
    fn derivation_is_non_circular_and_domain_separated() {
        let candidate = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        candidate.validate().unwrap();
        assert_ne!(candidate.launch_root, candidate.network_id);
        assert_ne!(candidate.launch_root, candidate.virtual_genesis_hash);
        assert_ne!(candidate.network_id, candidate.virtual_genesis_hash);
        let root = decode_hex32(&candidate.launch_root).unwrap();
        assert_eq!(
            decode_hex32(&candidate.network_id).unwrap(),
            derive(NETWORK_ID_DOMAIN, &root)
        );
        assert_ne!(
            decode_hex32(&candidate.network_id).unwrap(),
            derive(VIRTUAL_GENESIS_DOMAIN, &root)
        );
    }

    #[test]
    fn mutations_change_the_launch_root_or_fail_validation() {
        let baseline = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        let mut variants = Vec::new();
        let mut value = payload();
        value.record_v2.record_digest = hex::encode([7; 32]);
        variants.push(value);
        let mut value = payload();
        value.virtual_genesis_timestamp_unix_seconds += 1;
        variants.push(value);
        let mut value = payload();
        value.services.p2p_port += 10;
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
    fn unsafe_placeholders_are_rejected_and_output_is_create_new() {
        let mut rfc = payload();
        rfc.services.bootstrap_ipv4 = "192.0.2.1".to_owned();
        assert!(RcnetLaunchCandidate::from_payload(rfc).is_err());
        let mut dev_reward = payload();
        dev_reward.reward_destinations.steward_xonly_public_key =
            hex::encode(INSECURE_DEV_DESTINATIONS[0]);
        assert!(RcnetLaunchCandidate::from_payload(dev_reward).is_err());

        let candidate = RcnetLaunchCandidate::from_payload(payload()).unwrap();
        let path = std::env::temp_dir().join(format!(
            "cmfd-rcnet-candidate-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
