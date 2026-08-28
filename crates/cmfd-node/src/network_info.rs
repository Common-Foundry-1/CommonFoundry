#[cfg(feature = "production-v3")]
use crate::NetworkProfileKind;
#[cfg(feature = "production-v3")]
use cmfd_consensus::POW_TYPE_V3_CANDIDATE;
#[cfg(feature = "production-v3")]
use cmfd_consensus::dory_v3_suite::{
    DORY_V3_BANKS, DORY_V3_BATCH, DORY_V3_DIMENSION, DORY_V3_LAYERS, DORY_V3_LAYERS_PER_BANK,
    DORY_V3_MAX_STRUCTURED_PROOF_BYTES, DORY_V3_MODEL_BANK_FORMAT_VERSION,
    DORY_V3_MODEL_RECORD_VERSION, DORY_V3_MODEL_VERSION, DORY_V3_PADDED_VARIABLES,
};
use cmfd_consensus::{
    BLOCK_VERSION, COIN, COINBASE_MATURITY, CONSENSUS_SIGNATURE_BYTES, DGW_WINDOW,
    ForgeMatrixV2Error, MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS,
    MAX_BLOCK_SIGNATURE_CHECKS, MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS,
    MAX_TRANSACTION_BYTES, MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS, MEDIAN_TIME_WINDOW,
    POW_TYPE_V2_REFERENCE, PowError, PowParameters, TARGET_SPACING_SECONDS, TRANSACTION_VERSION,
    WIRE_HEADER_BYTES, WIRE_VERSION, max_block_bytes_for_network, max_proof_bytes_for_network,
};
#[cfg(feature = "production-v4-testnet")]
use cmfd_consensus::{
    POW_TYPE_V4_CANDIDATE, forgematrix_v4_proof_codec::FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
};
use cmfd_proof_worker::{ProductionV3VerifierArtifacts, ProductionV3VerifierRecord};
use serde::Serialize;
#[cfg(feature = "production-v3")]
use sha2::{Digest as _, Sha256};

use crate::{
    COMPILED_NETWORK_PROFILE, NetworkProfile, NodeError, ProductionV4VerifierArtifacts,
    network_params_and_verifier_for_profile,
};

const NETWORK_INFO_FORMAT: &str = "commonfoundry-network-info";
const NETWORK_INFO_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Serialize, PartialEq, Eq)]
struct NetworkInfo {
    format: &'static str,
    format_version: u32,
    network: NetworkIdentity,
    consensus: ConsensusIdentity,
    proof_of_work: ProofOfWorkIdentity,
    services: ServiceIdentity,
    data_directories: DataDirectoryIdentity,
    monetary_policy: MonetaryPolicyIdentity,
    reward_destinations: RewardDestinationIdentity,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct NetworkIdentity {
    name: &'static str,
    network_id: String,
    virtual_genesis_hash: String,
    virtual_genesis_timestamp_unix_seconds: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ConsensusIdentity {
    consensus_fingerprint: String,
    versions: ConsensusVersions,
    limits: ConsensusLimits,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ConsensusVersions {
    network_protocol_version: u32,
    block_version: u32,
    transaction_version: u32,
    wire_version: u16,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ConsensusLimits {
    maximum_future_offset_seconds: String,
    target_spacing_seconds: String,
    coinbase_maturity_blocks: String,
    median_time_window: String,
    max_block_transactions: String,
    max_transaction_inputs: String,
    max_transaction_outputs: String,
    max_block_aggregate_inputs: String,
    max_block_aggregate_outputs: String,
    max_block_signature_checks: String,
    max_coinbase_outputs: String,
    consensus_signature_bytes: String,
    dgw_window: String,
    wire_header_bytes: String,
    max_transaction_bytes: String,
    max_proof_bytes: String,
    max_block_bytes: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // Serialized once for NETWORK-INFO; boxing adds needless heap indirection.
enum ProofOfWorkIdentity {
    V2Reference(V2ProofOfWorkIdentity),
    #[cfg(feature = "production-v3")]
    ProductionV3(ProductionV3ProofOfWorkIdentity),
    #[cfg(feature = "production-v4-testnet")]
    ProductionV4(ProductionV4ProofOfWorkIdentity),
}

#[cfg(feature = "production-v4-testnet")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProductionV4ProofOfWorkIdentity {
    selection: &'static str,
    profile: &'static str,
    wire_type: u16,
    pow_limit: String,
    algorithm_version: u32,
    proof_version: u32,
    proof_system_digest: String,
    model_manifest_digest: String,
    fixed_artifact_record_digest: String,
    exact_transparent_proof_bytes: String,
    artifacts: ProductionV4ArtifactIdentities,
}

#[cfg(feature = "production-v4-testnet")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProductionV4ArtifactIdentities {
    bank: ProductionV4FileIdentity,
    fixed_record: ProductionV4FileIdentity,
}

#[cfg(feature = "production-v4-testnet")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProductionV4FileIdentity {
    bytes: String,
    blake3: String,
    sha256: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct V2ProofOfWorkIdentity {
    profile: &'static str,
    wire_type: u16,
    pow_limit: String,
    algorithm_version: u32,
    proof_version: u32,
    banks: u32,
    layers_per_bank: u32,
    model: ModelIdentity,
}

#[cfg(feature = "production-v3")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProductionV3ProofOfWorkIdentity {
    selection: &'static str,
    profile: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_source_commit: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation_evidence_sha256: Option<String>,
    runtime_verifier_worker_sha256: String,
    runtime_verifier_workers: ProductionV3VerifierWorkerIdentities,
    wire_type: u16,
    pow_limit: String,
    algorithm_version: u32,
    proof_version: u32,
    banks: u32,
    layers_per_bank: u32,
    maximum_structured_proof_bytes: String,
    artifacts: ProductionV3ArtifactIdentities,
    model: ProductionV3ModelIdentity,
}

#[cfg(feature = "production-v3")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProductionV3VerifierWorkerIdentities {
    windows_x86_64_sha256: String,
    linux_x86_64_sha256: String,
}

#[cfg(feature = "production-v3")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProductionV3ArtifactIdentities {
    bank: ProductionV3FileIdentity,
    manifest: ProductionV3FileIdentity,
    record_v2: ProductionV3FileIdentity,
}

#[cfg(feature = "production-v3")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProductionV3FileIdentity {
    bytes: String,
    blake3: String,
    sha256: String,
}

#[cfg(feature = "production-v3")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProductionV3ModelIdentity {
    bank_format_version: u32,
    record_version: u16,
    record_digest: String,
    manifest_digest: String,
    model_identity_digest: String,
    suite_digest: String,
    setup_identity: String,
    model_version: u32,
    dimension: u32,
    batch: u32,
    layers: u32,
    padded_variables: u32,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ModelIdentity {
    manifest_digest: String,
    model_version: u32,
    dimension: u32,
    batch: u32,
    layers: u32,
    base_input_bytes: String,
    bytes_per_layer: String,
    payload_bytes: String,
    raw_blake3_root: String,
    layer_roots_aggregate: String,
    pcs_parameter_digest: String,
    pcs_commitment_root: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ServiceIdentity {
    rpc_port: u16,
    p2p_port: u16,
    pool_port: u16,
    bootstrap_peer: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct DataDirectoryIdentity {
    node: &'static str,
    wallet: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct MonetaryPolicyIdentity {
    atoms_per_coin: String,
    initial_subsidy_atoms: String,
    tail_height: String,
    tail_subsidy_atoms: String,
    steward_percent: u8,
    community_percent: u8,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct RewardDestinationIdentity {
    steward_xonly_public_key: String,
    community_xonly_public_key: String,
}

/// Returns the canonical, compile-time network manifest without opening node storage.
///
/// All 32-byte identities are lowercase hexadecimal without a prefix. Values that
/// may cross JSON implementations as consensus-sized integers use base-10 strings.
/// Struct field order and the single trailing LF are part of the version-1 encoding.
pub fn canonical_network_info_json() -> Result<Vec<u8>, NodeError> {
    canonical_network_info_json_with_artifacts(None)
}

/// Returns the canonical manifest for the compiled network, authenticating
/// the production model artifacts first when the profile selects V3.
pub fn canonical_network_info_json_with_artifacts(
    production_v3_artifacts: Option<&ProductionV3VerifierArtifacts>,
) -> Result<Vec<u8>, NodeError> {
    let production_v3_record =
        crate::production_v3_record_for_profile(COMPILED_NETWORK_PROFILE, production_v3_artifacts)?;
    canonical_network_info_json_with_record(production_v3_record.as_ref())
}

/// Returns the canonical manifest while authenticating only the exact
/// release-pinned Record V2 needed by a verifier-only node.
pub fn canonical_network_info_json_with_record(
    production_v3_record: Option<&ProductionV3VerifierRecord>,
) -> Result<Vec<u8>, NodeError> {
    canonical_network_info_json_for_profile(COMPILED_NETWORK_PROFILE, production_v3_record, None)
}

/// Returns the canonical V4 network manifest after authenticating the pinned
/// fixed record and complete model bank used to construct verifier authority.
pub fn canonical_network_info_json_with_v4_artifacts(
    production_v4_artifacts: &ProductionV4VerifierArtifacts,
) -> Result<Vec<u8>, NodeError> {
    canonical_network_info_json_for_profile(
        COMPILED_NETWORK_PROFILE,
        None,
        Some(production_v4_artifacts),
    )
}

fn canonical_network_info_json_for_profile(
    profile: NetworkProfile,
    production_v3_record: Option<&ProductionV3VerifierRecord>,
    production_v4_artifacts: Option<&ProductionV4VerifierArtifacts>,
) -> Result<Vec<u8>, NodeError> {
    let (params, verifier) = network_params_and_verifier_for_profile(
        profile,
        production_v3_record,
        production_v4_artifacts,
    )?;
    let proof_of_work = match verifier.parameters() {
        PowParameters::V2Reference(descriptor) => {
            let model_manifest_digest = descriptor
                .model
                .digest()
                .map_err(ForgeMatrixV2Error::from)
                .map_err(PowError::from)?;
            ProofOfWorkIdentity::V2Reference(V2ProofOfWorkIdentity {
                profile: profile.proof_name(),
                wire_type: POW_TYPE_V2_REFERENCE,
                pow_limit: hex::encode(params.pow_limit),
                algorithm_version: descriptor.algorithm_version,
                proof_version: descriptor.proof_version,
                banks: descriptor.banks,
                layers_per_bank: descriptor.layers_per_bank,
                model: ModelIdentity {
                    manifest_digest: hex::encode(model_manifest_digest),
                    model_version: descriptor.model.model_version,
                    dimension: descriptor.model.dimension,
                    batch: descriptor.model.batch,
                    layers: descriptor.model.layers,
                    base_input_bytes: descriptor.model.base_input_bytes.to_string(),
                    bytes_per_layer: descriptor.model.bytes_per_layer.to_string(),
                    payload_bytes: descriptor.model.payload_bytes.to_string(),
                    raw_blake3_root: hex::encode(descriptor.model.raw_blake3_root),
                    layer_roots_aggregate: hex::encode(descriptor.model.layer_roots_aggregate),
                    pcs_parameter_digest: hex::encode(descriptor.model.pcs_parameter_digest),
                    pcs_commitment_root: hex::encode(descriptor.model.pcs_commitment_root),
                },
            })
        }
        #[cfg(feature = "production-v3")]
        PowParameters::V3Candidate(parameters) => {
            let release_profile = crate::release_gate::COMPILED_RELEASE_PROFILE;
            let artifacts = release_profile
                .production_v3_artifacts
                .ok_or(NodeError::ProductionV3ArtifactPinsMissing)?;
            let workers = release_profile.production_v3_verifier_workers.ok_or(
                NodeError::ProductionV3ActivationEvidence(
                    "compiled runtime verifier-worker pins are absent",
                ),
            )?;
            let (build_source_commit, activation_evidence_sha256) = match profile.kind {
                NetworkProfileKind::Rcnet => {
                    let build_source_commit = option_env!("CMFD_BUILD_SOURCE_COMMIT").ok_or(
                        NodeError::ProductionV3ActivationEvidence(
                            "trusted build source commit is absent",
                        ),
                    )?;
                    let activation_evidence =
                        crate::release_gate::canonical_production_v3_activation_evidence_json(
                            crate::release_gate::COMPILED_RELEASE_PROFILE,
                            build_source_commit,
                        )
                        .map_err(NodeError::ProductionV3ActivationEvidence)?;
                    (
                        Some(build_source_commit),
                        Some(hex::encode(Sha256::digest(&activation_evidence))),
                    )
                }
                NetworkProfileKind::ProductionV3Testnet => (None, None),
                NetworkProfileKind::Devnet => {
                    unreachable!("the Devnet network profile cannot select ProductionV3 parameters")
                }
            };
            ProofOfWorkIdentity::ProductionV3(ProductionV3ProofOfWorkIdentity {
                selection: "ProductionV3",
                profile: profile.proof_name(),
                build_source_commit,
                activation_evidence_sha256,
                runtime_verifier_worker_sha256: hex::encode(
                    crate::compiled_production_v3_worker_sha256()?,
                ),
                runtime_verifier_workers: ProductionV3VerifierWorkerIdentities {
                    windows_x86_64_sha256: hex::encode(workers.windows_x86_64_sha256),
                    linux_x86_64_sha256: hex::encode(workers.linux_x86_64_sha256),
                },
                wire_type: POW_TYPE_V3_CANDIDATE,
                pow_limit: hex::encode(params.pow_limit),
                algorithm_version: parameters.algorithm_version(),
                proof_version: parameters.proof_version(),
                banks: DORY_V3_BANKS,
                layers_per_bank: DORY_V3_LAYERS_PER_BANK,
                maximum_structured_proof_bytes: DORY_V3_MAX_STRUCTURED_PROOF_BYTES.to_string(),
                artifacts: ProductionV3ArtifactIdentities {
                    bank: production_v3_file_identity(artifacts.bank),
                    manifest: production_v3_file_identity(artifacts.manifest),
                    record_v2: production_v3_file_identity(artifacts.record_v2),
                },
                model: ProductionV3ModelIdentity {
                    bank_format_version: DORY_V3_MODEL_BANK_FORMAT_VERSION,
                    record_version: DORY_V3_MODEL_RECORD_VERSION,
                    record_digest: hex::encode(parameters.model_record_digest()),
                    manifest_digest: hex::encode(parameters.model_manifest_digest()),
                    model_identity_digest: hex::encode(parameters.model_identity_digest()),
                    suite_digest: hex::encode(parameters.suite_digest()),
                    setup_identity: hex::encode(parameters.setup_identity()),
                    model_version: DORY_V3_MODEL_VERSION,
                    dimension: DORY_V3_DIMENSION,
                    batch: DORY_V3_BATCH,
                    layers: DORY_V3_LAYERS,
                    padded_variables: DORY_V3_PADDED_VARIABLES,
                },
            })
        }
        #[cfg(feature = "production-v4-testnet")]
        PowParameters::V4Candidate(parameters) => {
            let pins = crate::release_gate::PRODUCTION_V4_TESTNET_ARTIFACT_PINS;
            ProofOfWorkIdentity::ProductionV4(ProductionV4ProofOfWorkIdentity {
                selection: "ProductionV4",
                profile: profile.proof_name(),
                wire_type: POW_TYPE_V4_CANDIDATE,
                pow_limit: hex::encode(params.pow_limit),
                algorithm_version: parameters.algorithm_version(),
                proof_version: parameters.proof_version(),
                proof_system_digest: hex::encode(parameters.proof_system_digest()),
                model_manifest_digest: hex::encode(parameters.model_manifest_digest()),
                fixed_artifact_record_digest: hex::encode(
                    parameters.fixed_artifact_record_digest(),
                ),
                exact_transparent_proof_bytes: FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES.to_string(),
                artifacts: ProductionV4ArtifactIdentities {
                    bank: production_v4_file_identity(pins.bank),
                    fixed_record: production_v4_file_identity(pins.fixed_record),
                },
            })
        }
        _ => {
            unreachable!("the compiled network profile passed proof selection validation")
        }
    };

    let info = NetworkInfo {
        format: NETWORK_INFO_FORMAT,
        format_version: NETWORK_INFO_FORMAT_VERSION,
        network: NetworkIdentity {
            name: profile.name,
            network_id: hex::encode(params.network_id),
            virtual_genesis_hash: hex::encode(params.genesis_hash),
            virtual_genesis_timestamp_unix_seconds: params.genesis_timestamp.to_string(),
        },
        consensus: ConsensusIdentity {
            consensus_fingerprint: hex::encode(params.fingerprint()?),
            versions: ConsensusVersions {
                network_protocol_version: params.protocol_version,
                block_version: BLOCK_VERSION,
                transaction_version: TRANSACTION_VERSION,
                wire_version: WIRE_VERSION,
            },
            limits: ConsensusLimits {
                maximum_future_offset_seconds: params.max_future_offset_secs.to_string(),
                target_spacing_seconds: TARGET_SPACING_SECONDS.to_string(),
                coinbase_maturity_blocks: COINBASE_MATURITY.to_string(),
                median_time_window: MEDIAN_TIME_WINDOW.to_string(),
                max_block_transactions: MAX_BLOCK_TRANSACTIONS.to_string(),
                max_transaction_inputs: MAX_TRANSACTION_INPUTS.to_string(),
                max_transaction_outputs: MAX_TRANSACTION_OUTPUTS.to_string(),
                max_block_aggregate_inputs: MAX_BLOCK_AGGREGATE_INPUTS.to_string(),
                max_block_aggregate_outputs: MAX_BLOCK_AGGREGATE_OUTPUTS.to_string(),
                max_block_signature_checks: MAX_BLOCK_SIGNATURE_CHECKS.to_string(),
                max_coinbase_outputs: MAX_COINBASE_OUTPUTS.to_string(),
                consensus_signature_bytes: CONSENSUS_SIGNATURE_BYTES.to_string(),
                dgw_window: DGW_WINDOW.to_string(),
                wire_header_bytes: WIRE_HEADER_BYTES.to_string(),
                max_transaction_bytes: MAX_TRANSACTION_BYTES.to_string(),
                max_proof_bytes: max_proof_bytes_for_network(profile.network_id).to_string(),
                max_block_bytes: max_block_bytes_for_network(profile.network_id).to_string(),
            },
        },
        proof_of_work,
        services: ServiceIdentity {
            rpc_port: profile.rpc_port,
            p2p_port: profile.p2p_port,
            pool_port: profile.pool_port,
            bootstrap_peer: profile.bootstrap_peer().to_string(),
        },
        data_directories: DataDirectoryIdentity {
            node: profile.default_data_dir_identity,
            wallet: profile.wallet_data_dir_identity,
        },
        monetary_policy: MonetaryPolicyIdentity {
            atoms_per_coin: COIN.to_string(),
            initial_subsidy_atoms: params.monetary_policy.initial_subsidy.to_string(),
            tail_height: params.monetary_policy.tail_height.to_string(),
            tail_subsidy_atoms: params.monetary_policy.tail_subsidy.to_string(),
            steward_percent: params.monetary_policy.steward_percent,
            community_percent: params.monetary_policy.community_percent,
        },
        reward_destinations: RewardDestinationIdentity {
            steward_xonly_public_key: hex::encode(params.rewards.steward),
            community_xonly_public_key: hex::encode(params.rewards.community),
        },
    };

    let mut encoded = serde_json::to_vec_pretty(&info)?;
    encoded.push(b'\n');
    Ok(encoded)
}

#[cfg(feature = "production-v3")]
fn production_v3_file_identity(
    pin: crate::release_gate::ProductionV3FileIdentityPin,
) -> ProductionV3FileIdentity {
    ProductionV3FileIdentity {
        bytes: pin.bytes.to_string(),
        blake3: hex::encode(pin.blake3),
        sha256: hex::encode(pin.sha256),
    }
}

#[cfg(feature = "production-v4-testnet")]
fn production_v4_file_identity(
    pin: crate::release_gate::ProductionV3FileIdentityPin,
) -> ProductionV4FileIdentity {
    ProductionV4FileIdentity {
        bytes: pin.bytes.to_string(),
        blake3: hex::encode(pin.blake3),
        sha256: hex::encode(pin.sha256),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(any(feature = "production-v3-testnet", feature = "production-v4-testnet")))]
    const EXPECTED_DEVNET_NETWORK_INFO: &str = r#"{
  "format": "commonfoundry-network-info",
  "format_version": 1,
  "network": {
    "name": "CommonFoundry Devnet-0",
    "network_id": "6363636363636363636363636363636363636363636363636363636363636363",
    "virtual_genesis_hash": "4747474747474747474747474747474747474747474747474747474747474747",
    "virtual_genesis_timestamp_unix_seconds": "1700000000"
  },
  "consensus": {
    "consensus_fingerprint": "bbbadca69495910a1e6b73fe95db17d5b8b9b056361ce1c9dca9dc183114eddf",
    "versions": {
      "network_protocol_version": 2,
      "block_version": 1,
      "transaction_version": 1,
      "wire_version": 1
    },
    "limits": {
      "maximum_future_offset_seconds": "86400",
      "target_spacing_seconds": "60",
      "coinbase_maturity_blocks": "100",
      "median_time_window": "11",
      "max_block_transactions": "1024",
      "max_transaction_inputs": "128",
      "max_transaction_outputs": "128",
      "max_block_aggregate_inputs": "4096",
      "max_block_aggregate_outputs": "4096",
      "max_block_signature_checks": "2048",
      "max_coinbase_outputs": "3",
      "consensus_signature_bytes": "64",
      "dgw_window": "180",
      "wire_header_bytes": "16",
      "max_transaction_bytes": "65536",
      "max_proof_bytes": "262144",
      "max_block_bytes": "1048576"
    }
  },
  "proof_of_work": {
    "profile": "ForgeMatrix-v2 tiny full-recompute reference",
    "wire_type": 2,
    "pow_limit": "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "algorithm_version": 2,
    "proof_version": 1,
    "banks": 1,
    "layers_per_bank": 4,
    "model": {
      "manifest_digest": "bbb45823caef6fb0770a4da7ea59c8ed24f053de4e3430c365a165675a43012d",
      "model_version": 2,
      "dimension": 4,
      "batch": 2,
      "layers": 4,
      "base_input_bytes": "8",
      "bytes_per_layer": "16",
      "payload_bytes": "72",
      "raw_blake3_root": "82851bc14d7103775fdbec54165e03608d7e2575b57d1e222fd762aa4441864b",
      "layer_roots_aggregate": "3e04a95c74983968c8a14bdda6b6f5f00f4cb1f028760d6125c409392ea91b52",
      "pcs_parameter_digest": "9191919191919191919191919191919191919191919191919191919191919191",
      "pcs_commitment_root": "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
    }
  },
  "services": {
    "rpc_port": 18443,
    "p2p_port": 18444,
    "pool_port": 18445,
    "bootstrap_peer": "107.214.187.2:18444"
  },
  "data_directories": {
    "node": "commonfoundry-devnet0",
    "wallet": "devnet-0"
  },
  "monetary_policy": {
    "atoms_per_coin": "100000000",
    "initial_subsidy_atoms": "50000000000",
    "tail_height": "2628001",
    "tail_subsidy_atoms": "500000000",
    "steward_percent": 25,
    "community_percent": 5
  },
  "reward_destinations": {
    "steward_xonly_public_key": "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    "community_xonly_public_key": "6360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7"
  }
}
"#;

    #[cfg(not(any(feature = "production-v3-testnet", feature = "production-v4-testnet")))]
    #[test]
    fn current_network_info_bytes_are_exact() {
        assert_eq!(
            canonical_network_info_json().unwrap(),
            EXPECTED_DEVNET_NETWORK_INFO.as_bytes()
        );
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn production_v3_testnet_network_info_requires_v3_artifacts_without_v2_fallback() {
        assert_eq!(
            COMPILED_NETWORK_PROFILE,
            crate::PRODUCTION_V3_TESTNET_PROFILE
        );
        assert!(matches!(
            canonical_network_info_json(),
            Err(NodeError::ProductionV3ArtifactsMissing)
        ));
    }

    #[test]
    fn rcnet_network_info_never_falls_back_to_the_devnet_manifest() {
        let result = canonical_network_info_json_for_profile(crate::RCNET1_PROFILE, None, None);
        #[cfg(feature = "production-v3")]
        assert!(matches!(
            result,
            Err(NodeError::ProductionV3ArtifactsMissing)
        ));
        #[cfg(not(feature = "production-v3"))]
        assert!(matches!(result, Err(NodeError::ProductionV3Unavailable)));
    }
}
