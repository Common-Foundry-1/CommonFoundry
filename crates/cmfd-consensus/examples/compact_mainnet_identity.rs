//! Print the reproducible, pinned compact-proof mainnet fork identity.
use cmfd_consensus::compact_mainnet_fork::{
    COMPACT_MAINNET_FINGERPRINT_DOMAIN, CompactMainnetForkIdentity, CompactMainnetProofRule,
};
use serde_json::json;

fn rule_json(rule: CompactMainnetProofRule) -> serde_json::Value {
    json!({
        "proof_version": rule.proof_version,
        "proof_system_digest": hex::encode(rule.proof_system_digest),
        "maximum_proof_frame_bytes": rule.maximum_proof_frame_bytes,
        "direct_packet_exclusive_limit_bytes": rule.direct_packet_exclusive_limit_bytes,
        "required_work_replay": rule.required_work_replay,
        "complete_proof_verification": rule.complete_proof_verification,
    })
}

fn main() {
    let identity = CompactMainnetForkIdentity::pinned();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "CMFD_COMPACT_MAINNET_FORK_IDENTITY_V1",
            "activation_height": identity.activation_height,
            "network_id": hex::encode(identity.network_id),
            "predecessor_fingerprint": hex::encode(identity.predecessor_fingerprint),
            "consensus_fingerprint": hex::encode(identity.fingerprint()),
            "fingerprint_hash": "BLAKE3 derive_key",
            "fingerprint_domain": COMPACT_MAINNET_FINGERPRINT_DOMAIN,
            "fingerprint_preimage_hex": hex::encode(identity.canonical_bytes()),
            "algorithm_version": identity.algorithm_version,
            "model_manifest_digest": hex::encode(identity.model_manifest_digest),
            "fixed_artifact_record_digest": hex::encode(identity.fixed_artifact_record_digest),
            "maximum_block_bytes": identity.maximum_block_bytes,
            "before_activation": rule_json(identity.before),
            "at_and_after_activation": rule_json(identity.after),
        }))
        .expect("fork identity serializes")
    );
}
