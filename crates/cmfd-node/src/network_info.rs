use cmfd_consensus::{
    BLOCK_VERSION, COIN, COINBASE_MATURITY, CONSENSUS_SIGNATURE_BYTES, DGW_WINDOW,
    ForgeMatrixV2Error, MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS, MAX_BLOCK_BYTES,
    MAX_BLOCK_SIGNATURE_CHECKS, MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS, MAX_PROOF_BYTES,
    MAX_TRANSACTION_BYTES, MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS, MEDIAN_TIME_WINDOW,
    POW_TYPE_V2_REFERENCE, PowError, PowParameters, TARGET_SPACING_SECONDS, TRANSACTION_VERSION,
    WIRE_HEADER_BYTES, WIRE_VERSION,
};
use serde::Serialize;

use crate::{COMPILED_NETWORK_PROFILE, NodeError, devnet_params};

const NETWORK_INFO_FORMAT: &str = "commonfoundry-network-info";
const NETWORK_INFO_FORMAT_VERSION: u32 = 1;
const DEVNET_POW_PROFILE: &str = "ForgeMatrix-v2 tiny full-recompute reference";

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
struct ProofOfWorkIdentity {
    profile: &'static str,
    wire_type: u16,
    pow_limit: String,
    algorithm_version: u32,
    proof_version: u32,
    banks: u32,
    layers_per_bank: u32,
    model: ModelIdentity,
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
    let params = devnet_params()?;
    let descriptor = match params.pow {
        PowParameters::V2Reference(descriptor) => descriptor,
        _ => unreachable!("the compiled Devnet manifest passed validation as v2"),
    };
    let model_manifest_digest = descriptor
        .model
        .digest()
        .map_err(ForgeMatrixV2Error::from)
        .map_err(PowError::from)?;

    let info = NetworkInfo {
        format: NETWORK_INFO_FORMAT,
        format_version: NETWORK_INFO_FORMAT_VERSION,
        network: NetworkIdentity {
            name: COMPILED_NETWORK_PROFILE.name,
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
                max_proof_bytes: MAX_PROOF_BYTES.to_string(),
                max_block_bytes: MAX_BLOCK_BYTES.to_string(),
            },
        },
        proof_of_work: ProofOfWorkIdentity {
            profile: DEVNET_POW_PROFILE,
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
        },
        services: ServiceIdentity {
            rpc_port: COMPILED_NETWORK_PROFILE.rpc_port,
            p2p_port: COMPILED_NETWORK_PROFILE.p2p_port,
            pool_port: COMPILED_NETWORK_PROFILE.pool_port,
            bootstrap_peer: COMPILED_NETWORK_PROFILE.bootstrap_peer().to_string(),
        },
        data_directories: DataDirectoryIdentity {
            node: COMPILED_NETWORK_PROFILE.default_data_dir_identity,
            wallet: COMPILED_NETWORK_PROFILE.wallet_data_dir_identity,
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

#[cfg(test)]
mod tests {
    use super::*;

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
    "consensus_fingerprint": "7ae1b8fadadc6e9316e480968fe2647b3a627df33a1a1c7f7c6c53433a4ff778",
    "versions": {
      "network_protocol_version": 1,
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

    #[test]
    fn current_network_info_bytes_are_exact() {
        assert_eq!(
            canonical_network_info_json().unwrap(),
            EXPECTED_DEVNET_NETWORK_INFO.as_bytes()
        );
    }
}
