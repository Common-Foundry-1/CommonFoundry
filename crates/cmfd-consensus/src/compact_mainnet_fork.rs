//! Pinned consensus identity for the compact-proof mainnet upgrade.
//!
//! This defines the scheduled rules and their reproducible commitment. Node
//! activation, historical-storage migration and peer transition must consume
//! this identity when the mainnet fork implementation is assembled.

use crate::forgematrix_v4::{
    FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP,
    FORGEMATRIX_V4_BASEFOLD_POW_BITS, FORGEMATRIX_V4_BASEFOLD_QUERIES,
    PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST, PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
    forgematrix_v4_proof_system_digest,
};

pub const COMPACT_MAINNET_ACTIVATION_HEIGHT: u64 = 65_535;
pub const COMPACT_MAINNET_FINGERPRINT_DOMAIN: &str = "CMFD/MAINNET/COMPACT-FORK/FINGERPRINT/V1";
pub const COMPACT_MAINNET_PROOF_SYSTEM_DOMAIN: &str =
    "CMFD/ForgeMatrix/V4/DirectProofSystem/Mainnet/V1";
pub const COMPACT_MAINNET_FINGERPRINT_HEX: &str =
    "5b9626178bb3777230ceda1cfc0fee5a8872ad0bb0ac1c5d0c7457cf67f083a5";
pub const COMPACT_MAINNET_PROOF_SYSTEM_DIGEST_HEX: &str =
    "d1671fc4760134bf86f0b37d8694f4827037e5cea2642e312cb2eb705f3aef0d";
pub const COMPACT_MAINNET_NETWORK_ID: [u8; 32] = [
    0x88, 0x29, 0x6b, 0xc3, 0x9c, 0x10, 0xe8, 0xbc, 0x1d, 0xd4, 0x81, 0x8d, 0x4d, 0x42, 0x41, 0x2f,
    0xe5, 0xf0, 0x82, 0x10, 0x65, 0x11, 0x10, 0x37, 0x7f, 0x49, 0x5d, 0xa2, 0x99, 0x81, 0x2f, 0x62,
];
/// Existing mainnet identity, including its genesis, monetary policy, workload,
/// model and fixed commitments, transaction rules and block limits.
pub const COMPACT_MAINNET_PREDECESSOR_FINGERPRINT: [u8; 32] = [
    0xe9, 0xd8, 0x1f, 0x15, 0xc5, 0x80, 0x03, 0x13, 0x02, 0x65, 0x66, 0x09, 0xeb, 0x24, 0xfa, 0x83,
    0x51, 0xef, 0xe0, 0xa3, 0x41, 0x35, 0xad, 0x89, 0x4c, 0x79, 0x3f, 0x3d, 0xd9, 0x04, 0x40, 0x79,
];

/// The compact mainnet transcript binds every untrusted evaluation before
/// sampling the batching challenge. Its domain is separate from the testnet.
pub fn compact_mainnet_proof_system_digest() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(COMPACT_MAINNET_PROOF_SYSTEM_DOMAIN);
    hasher.update(&1_u32.to_le_bytes());
    hasher.update(&forgematrix_v4_proof_system_digest());
    hasher.update(&2_u32.to_le_bytes());
    hasher.update(b"CMFDDR02");
    hasher.update(&[1, 6]); // canonical zlib level and commitment count
    hasher.update(&FORGEMATRIX_V4_BASEFOLD_LOG_BLOWUP.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_BASEFOLD_QUERIES.to_le_bytes());
    hasher.update(&FORGEMATRIX_V4_BASEFOLD_POW_BITS.to_le_bytes());
    let binding = b"all-relations-first;verify-untrusted-evaluations;all-evaluation-limbs-before-batch-challenge/v1";
    hasher.update(&(binding.len() as u64).to_le_bytes());
    hasher.update(binding);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactMainnetProofRule {
    pub proof_version: u32,
    pub proof_system_digest: [u8; 32],
    pub maximum_proof_frame_bytes: u64,
    /// Zero for the legacy fixed-layout proof. The compact packet must be
    /// strictly smaller than this limit, matching the complete CPU verifier.
    pub direct_packet_exclusive_limit_bytes: u64,
    pub required_work_replay: bool,
    pub complete_proof_verification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactMainnetForkIdentity {
    pub network_id: [u8; 32],
    pub predecessor_fingerprint: [u8; 32],
    pub activation_height: u64,
    pub algorithm_version: u32,
    pub model_manifest_digest: [u8; 32],
    pub fixed_artifact_record_digest: [u8; 32],
    pub maximum_block_bytes: u64,
    pub before: CompactMainnetProofRule,
    pub after: CompactMainnetProofRule,
}

#[derive(Debug, thiserror::Error)]
pub enum CompactMainnetIdentityError {
    #[error("compact mainnet fork requires the existing mainnet network ID")]
    WrongNetwork,
    #[error("mainnet parameters differ from the pinned predecessor fingerprint")]
    PredecessorMismatch,
    #[error(transparent)]
    Parameters(#[from] crate::network::NetworkError),
}

impl CompactMainnetForkIdentity {
    /// Bind this fork to the actual resolved launch parameters. A build with
    /// different genesis, rewards, workload or limits cannot reuse the pin.
    pub fn from_mainnet_params(
        params: &crate::network::NetworkParams,
    ) -> Result<Self, CompactMainnetIdentityError> {
        if params.network_id != COMPACT_MAINNET_NETWORK_ID {
            return Err(CompactMainnetIdentityError::WrongNetwork);
        }
        if params.fingerprint()? != COMPACT_MAINNET_PREDECESSOR_FINGERPRINT {
            return Err(CompactMainnetIdentityError::PredecessorMismatch);
        }
        Ok(Self::pinned())
    }

    pub fn pinned() -> Self {
        Self {
            network_id: COMPACT_MAINNET_NETWORK_ID,
            predecessor_fingerprint: COMPACT_MAINNET_PREDECESSOR_FINGERPRINT,
            activation_height: COMPACT_MAINNET_ACTIVATION_HEIGHT,
            algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
            model_manifest_digest: PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
            fixed_artifact_record_digest: PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
            maximum_block_bytes: crate::PRODUCTION_V4_MAX_BLOCK_BYTES as u64,
            before: CompactMainnetProofRule {
                proof_version: 1,
                proof_system_digest: forgematrix_v4_proof_system_digest(),
                maximum_proof_frame_bytes: crate::PRODUCTION_V4_MAX_PROOF_BYTES as u64,
                direct_packet_exclusive_limit_bytes: 0,
                required_work_replay: true,
                complete_proof_verification: true,
            },
            after: CompactMainnetProofRule {
                proof_version: 2,
                proof_system_digest: compact_mainnet_proof_system_digest(),
                maximum_proof_frame_bytes: 6_100_000,
                direct_packet_exclusive_limit_bytes: 6_000_000,
                required_work_replay: false,
                complete_proof_verification: true,
            },
        }
    }

    pub fn rule_at_height(&self, height: u64) -> CompactMainnetProofRule {
        if height < self.activation_height {
            self.before
        } else {
            self.after
        }
    }

    /// Canonical preimage: integers are fixed-width little endian; hashes are
    /// raw 32-byte arrays; booleans are single bytes (0 or 1). Order is pinned.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.predecessor_fingerprint);
        bytes.extend_from_slice(&self.activation_height.to_le_bytes());
        bytes.extend_from_slice(&self.algorithm_version.to_le_bytes());
        bytes.extend_from_slice(&self.model_manifest_digest);
        bytes.extend_from_slice(&self.fixed_artifact_record_digest);
        bytes.extend_from_slice(&self.maximum_block_bytes.to_le_bytes());
        for rule in [self.before, self.after] {
            bytes.extend_from_slice(&rule.proof_version.to_le_bytes());
            bytes.extend_from_slice(&rule.proof_system_digest);
            bytes.extend_from_slice(&rule.maximum_proof_frame_bytes.to_le_bytes());
            bytes.extend_from_slice(&rule.direct_packet_exclusive_limit_bytes.to_le_bytes());
            bytes.push(u8::from(rule.required_work_replay));
            bytes.push(u8::from(rule.complete_proof_verification));
        }
        bytes
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(COMPACT_MAINNET_FINGERPRINT_DOMAIN);
        hasher.update(&self.canonical_bytes());
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_mainnet_identity_has_pinned_known_answers() {
        let identity = CompactMainnetForkIdentity::pinned();
        assert_eq!(
            hex::encode(identity.fingerprint()),
            COMPACT_MAINNET_FINGERPRINT_HEX
        );
        assert_eq!(
            hex::encode(compact_mainnet_proof_system_digest()),
            COMPACT_MAINNET_PROOF_SYSTEM_DIGEST_HEX
        );
        assert_eq!(identity.canonical_bytes().len(), 260);
    }

    #[test]
    fn compact_mainnet_published_manifest_matches_the_pinned_rules() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/compact-proof-testnet/MAINNET-FORK-IDENTITY-65535.json"
        ))
        .unwrap();
        let identity = CompactMainnetForkIdentity::pinned();
        assert_eq!(
            manifest["consensus_fingerprint"],
            hex::encode(identity.fingerprint())
        );
        assert_eq!(
            manifest["fingerprint_preimage_hex"],
            hex::encode(identity.canonical_bytes())
        );
        assert_eq!(
            manifest["activation_height"],
            COMPACT_MAINNET_ACTIVATION_HEIGHT
        );
        assert_eq!(
            manifest["at_and_after_activation"]["required_work_replay"],
            false
        );
        assert_eq!(
            manifest["at_and_after_activation"]["complete_proof_verification"],
            true
        );
    }

    #[test]
    #[cfg(feature = "direct-proof-testnet")]
    fn compact_mainnet_identity_is_distinct_from_testnet() {
        assert_ne!(
            COMPACT_MAINNET_NETWORK_ID,
            crate::FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID
        );
        assert_ne!(
            compact_mainnet_proof_system_digest(),
            crate::forgematrix_v4_direct_proof_system_digest()
        );
        assert_eq!(
            CompactMainnetForkIdentity::pinned().fingerprint(),
            hex::decode(COMPACT_MAINNET_FINGERPRINT_HEX)
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            CompactMainnetForkIdentity::pinned()
                .after
                .direct_packet_exclusive_limit_bytes,
            crate::forgematrix_v4_direct::MAX_WIRE_BYTES as u64
        );
        assert_eq!(
            CompactMainnetForkIdentity::pinned()
                .after
                .maximum_proof_frame_bytes,
            crate::wire::DIRECT_PROOF_TESTNET_MAX_PROOF_BYTES as u64
        );
    }

    #[test]
    fn compact_mainnet_boundary_requires_the_complete_proof_without_work_replay() {
        let identity = CompactMainnetForkIdentity::pinned();
        assert_eq!(identity.rule_at_height(65_534).proof_version, 1);
        assert!(identity.rule_at_height(65_534).required_work_replay);
        for height in [65_535, 65_536] {
            let rule = identity.rule_at_height(height);
            assert_eq!(rule.proof_version, 2);
            assert!(!rule.required_work_replay);
            assert!(rule.complete_proof_verification);
            assert_eq!(rule.direct_packet_exclusive_limit_bytes, 6_000_000);
        }
    }

    #[test]
    fn compact_mainnet_fingerprint_binds_height_proof_and_admission() {
        let original = CompactMainnetForkIdentity::pinned();
        let mut alternatives = Vec::new();
        let mut changed = original.clone();
        changed.activation_height += 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.network_id[0] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.predecessor_fingerprint[0] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.model_manifest_digest[0] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.fixed_artifact_record_digest[0] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.before.proof_system_digest[0] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.after.proof_system_digest[0] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.after.maximum_proof_frame_bytes += 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.after.direct_packet_exclusive_limit_bytes += 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.after.required_work_replay = true;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.after.complete_proof_verification = false;
        alternatives.push(changed);
        for changed in alternatives {
            assert_ne!(changed.fingerprint(), original.fingerprint());
        }
        assert_ne!(original.fingerprint(), original.predecessor_fingerprint);
        assert_eq!(
            crate::mainnet_network::MAINNET_NETWORK_ID,
            Some(original.network_id)
        );
    }
}
