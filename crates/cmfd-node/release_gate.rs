//! Build-time identity gate for artifacts presented as production release candidates.

#[path = "../cmfd-launch/src/schedule.rs"]
#[allow(dead_code)]
pub(crate) mod mainnet_schedule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledNetworkProfile {
    #[cfg_attr(
        any(
            feature = "production-v3-testnet",
            feature = "production-v4-testnet",
            feature = "production-rc"
        ),
        allow(dead_code)
    )]
    Devnet,
    #[cfg_attr(not(feature = "production-v3-testnet"), allow(dead_code))]
    ProductionV3Testnet,
    #[cfg_attr(not(feature = "production-v4-testnet"), allow(dead_code))]
    ProductionV4Testnet,
    Rcnet,
    #[allow(dead_code)]
    Mainnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusProofSelection {
    #[cfg_attr(
        any(
            feature = "production-v3-testnet",
            feature = "production-v4-testnet",
            feature = "production-rc"
        ),
        allow(dead_code)
    )]
    DevnetV2Reference,
    ProductionV3,
    ProductionV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV3ActivationEvidence {
    pub schema: &'static str,
    pub qualification_source_commit: &'static str,
    pub qualification_manifest_sha256: &'static str,
    pub fresh_process_verifier_binary_sha256: &'static str,
    pub fresh_process_verifier_report_sha256: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV3FileIdentityPin {
    pub bytes: u64,
    pub blake3: [u8; 32],
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV3ArtifactIdentityPins {
    pub bank: ProductionV3FileIdentityPin,
    pub manifest: ProductionV3FileIdentityPin,
    pub record_v2: ProductionV3FileIdentityPin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV4ActivationEvidence {
    pub schema: &'static str,
    pub qualification_source_commit: &'static str,
    pub qualification_manifest_sha256: &'static str,
    pub fresh_process_verifier_binary_sha256: &'static str,
    pub fresh_process_verifier_report_sha256: &'static str,
    pub core_spec_sha256: &'static str,
    pub core_vector_sha256: &'static str,
    pub proof_algebra_sha256: &'static str,
    pub approval_trust: ProductionV4ActivationApprovalTrust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV4ActivationSignerTrust {
    pub signer_identity: &'static str,
    pub allowed_signers_sha256: &'static str,
    pub key_blob_sha256: &'static str,
    pub key_fingerprint: &'static str,
    pub key_type: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV4ActivationApprovalTrust {
    pub contract_schema: &'static str,
    pub qualification_binding_sha256: &'static str,
    pub ssh_keygen_sha256: &'static str,
    pub producer: ProductionV4ActivationSignerTrust,
    pub independent_reproducer: Option<ProductionV4ActivationSignerTrust>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // build.rs includes this module without using runtime artifact pins.
pub struct ProductionV4ArtifactIdentityPins {
    pub bank: ProductionV3FileIdentityPin,
    pub fixed_record: ProductionV3FileIdentityPin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionV3VerifierWorkerIdentityPins {
    pub windows_x86_64_sha256: [u8; 32],
    pub linux_x86_64_sha256: [u8; 32],
}

impl ProductionV3VerifierWorkerIdentityPins {
    #[allow(dead_code)] // build.rs includes this module but does not select a runtime target.
    pub(crate) fn for_target(self, os: &str, arch: &str) -> Option<[u8; 32]> {
        match (os, arch) {
            ("windows", "x86_64") => Some(self.windows_x86_64_sha256),
            ("linux", "x86_64") => Some(self.linux_x86_64_sha256),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionRcNetworkIdentityPin {
    pub network_id: [u8; 32],
    pub virtual_genesis_hash: [u8; 32],
    pub virtual_genesis_timestamp: u64,
    pub pow_limit: [u8; 32],
    pub steward_reward_destination: [u8; 32],
    pub community_reward_destination: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledReleaseProfile {
    pub network: CompiledNetworkProfile,
    pub proof: ConsensusProofSelection,
    pub activation: Option<ProductionV3ActivationEvidence>,
    pub production_v3_artifacts: Option<ProductionV3ArtifactIdentityPins>,
    /// Platform SHA-256 pins for the packaged persistent `cmfd-proof-worker`.
    /// This is separate from `fresh_process_verifier_binary_sha256`, which
    /// identifies the qualification harness executable rather than the runtime
    /// sidecar shipped to nodes and wallets.
    pub production_v3_verifier_workers: Option<ProductionV3VerifierWorkerIdentityPins>,
    pub production_v4_activation: Option<ProductionV4ActivationEvidence>,
    pub production_v4_artifacts: Option<ProductionV4ArtifactIdentityPins>,
    pub production_network_identity: Option<ProductionRcNetworkIdentityPin>,
}

/// Mainnet cannot inherit the RC single-producer approval or fixed RC genesis.
/// The launch-time genesis is authenticated separately at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MainnetReleaseConfiguration {
    pub launch_plan_digest: [u8; 32],
    pub network_id: [u8; 32],
    pub pow_limit: [u8; 32],
    pub initial_target: [u8; 32],
    pub steward_reward_destination: [u8; 32],
    pub community_reward_destination: [u8; 32],
    pub approval_manifest_sha256: &'static str,
    pub activation: ProductionV4ActivationEvidence,
}

#[allow(dead_code)]
pub const MAINNET_NETWORK_ID: Option<[u8; 32]> =
    include!("../cmfd-consensus/mainnet_network_id.inc.rs");
#[allow(dead_code)]
pub const MAINNET_RELEASE_CONFIGURATION: Option<MainnetReleaseConfiguration> =
    include!("mainnet_release_pin.inc.rs");

/// The exact ceremony artifacts accepted by the private ProductionV3 test
/// network. `RCNET1-MODEL-V2.bank` and its manifest are the miner-side inputs;
/// `RCNET1-MODEL-RECORD-V2.json` is the small verifier record carried by nodes
/// and wallets. Anything else fails closed at load time, so these must never be
/// replaced with placeholders or with hashes from an RCNet/mainnet package.
#[cfg(feature = "production-v3-testnet")]
const PRODUCTION_V3_TESTNET_ARTIFACT_PINS: Option<ProductionV3ArtifactIdentityPins> =
    Some(ProductionV3ArtifactIdentityPins {
        bank: ProductionV3FileIdentityPin {
            bytes: 6_442_975_416,
            blake3: [
                0xb8, 0xbe, 0x84, 0x50, 0xb9, 0x33, 0xdc, 0x75, 0x9a, 0xa3, 0x4f, 0x2d, 0x60, 0xe7,
                0x3c, 0xf4, 0xea, 0xc3, 0x06, 0x44, 0x07, 0xc6, 0xa9, 0xf4, 0x83, 0x72, 0x17, 0x5a,
                0xbe, 0x87, 0xb6, 0xac,
            ],
            sha256: [
                0x5f, 0x9b, 0x21, 0x3c, 0x3b, 0xda, 0x51, 0xb7, 0x4e, 0x4e, 0xba, 0xbb, 0x26, 0x60,
                0x7b, 0x67, 0x38, 0x5d, 0x61, 0x3a, 0xa8, 0xd9, 0x9a, 0xf9, 0x15, 0xa4, 0x8a, 0xb0,
                0x63, 0xe1, 0x7d, 0x4e,
            ],
        },
        manifest: ProductionV3FileIdentityPin {
            bytes: 1_398,
            blake3: [
                0xe3, 0x1e, 0xdc, 0xf4, 0xba, 0x47, 0x2e, 0xac, 0xb6, 0x8c, 0x11, 0x9f, 0xd0, 0x74,
                0x48, 0xdb, 0x82, 0x13, 0x2f, 0x79, 0xfa, 0x4d, 0x05, 0x74, 0xfd, 0x73, 0x1c, 0x9d,
                0xc6, 0x1c, 0x42, 0x64,
            ],
            sha256: [
                0x03, 0x65, 0xb8, 0x18, 0x08, 0x0d, 0xcd, 0x48, 0xf3, 0x7a, 0x9a, 0x8b, 0x8d, 0x1e,
                0xf4, 0xce, 0x40, 0x0f, 0xa3, 0x91, 0xb5, 0x4a, 0xcf, 0xbd, 0x0c, 0x15, 0x84, 0x1b,
                0x47, 0xcc, 0xc1, 0x9e,
            ],
        },
        record_v2: ProductionV3FileIdentityPin {
            bytes: 8_667,
            blake3: [
                0xd0, 0x3b, 0x00, 0x02, 0x9f, 0x26, 0x52, 0x38, 0xcb, 0x0f, 0xe3, 0x66, 0x8b, 0x33,
                0x3e, 0x6e, 0xac, 0x5a, 0x5e, 0x49, 0x88, 0xe0, 0xed, 0xc6, 0xf1, 0xa2, 0x36, 0x09,
                0xc8, 0x81, 0x63, 0xf7,
            ],
            sha256: [
                0xac, 0x00, 0xf4, 0xdf, 0x8e, 0xcb, 0x07, 0x02, 0x62, 0x81, 0x97, 0xfc, 0x71, 0xfb,
                0x16, 0x1a, 0x46, 0xfd, 0x73, 0x4c, 0xce, 0x7a, 0x89, 0xf7, 0x48, 0xd0, 0x9d, 0x69,
                0x20, 0x89, 0xb3, 0xc8,
            ],
        },
    });
/// SHA-256 of the packaged persistent `cmfd-proof-worker` for each supported
/// platform. A node or wallet runs no other verifier binary.
#[cfg(feature = "production-v3-testnet")]
const PRODUCTION_V3_TESTNET_WORKER_PINS: Option<ProductionV3VerifierWorkerIdentityPins> =
    Some(ProductionV3VerifierWorkerIdentityPins {
        windows_x86_64_sha256: [
            0xb6, 0x74, 0x07, 0x4f, 0x21, 0x34, 0xcb, 0x04, 0xbb, 0x27, 0x43, 0x1f, 0x55, 0x02,
            0x9f, 0x05, 0x18, 0x1e, 0xdd, 0xb9, 0x99, 0x75, 0x93, 0xef, 0x52, 0x88, 0xf7, 0xfa,
            0xff, 0xa9, 0x39, 0xdf,
        ],
        linux_x86_64_sha256: [
            0xa0, 0x2d, 0x34, 0x02, 0xbe, 0xe7, 0x5c, 0x87, 0x14, 0xf2, 0x5b, 0x82, 0x08, 0x8a,
            0xc6, 0xd0, 0x16, 0x9f, 0x6a, 0xa2, 0xe9, 0xe7, 0xf2, 0xe3, 0x6f, 0xcb, 0x86, 0x63,
            0xa9, 0x04, 0xb0, 0x6f,
        ],
    });

/// The identity actually selected by a private ProductionV3 test build.
///
/// Testnet deliberately does not carry production activation evidence or a
/// production network-identity pin. Its real artifact and worker identities
/// are still mandatory at runtime through the fail-closed pin insertion points
/// above.
#[cfg(feature = "production-v3-testnet")]
pub const COMPILED_RELEASE_PROFILE: CompiledReleaseProfile = CompiledReleaseProfile {
    network: CompiledNetworkProfile::ProductionV3Testnet,
    proof: ConsensusProofSelection::ProductionV3,
    activation: None,
    production_v3_artifacts: PRODUCTION_V3_TESTNET_ARTIFACT_PINS,
    production_v3_verifier_workers: PRODUCTION_V3_TESTNET_WORKER_PINS,
    production_v4_activation: None,
    production_v4_artifacts: None,
    production_network_identity: None,
};

/// Exact verifier inputs accepted by the isolated ProductionV4 latency
/// testnet. The fixed record binds all three fixed commitments; the complete
/// model bank is authenticated before its base-input prefix is retained.
#[cfg(feature = "production-v4")]
#[allow(dead_code)] // build.rs includes this module without loading verifier artifacts.
pub const PRODUCTION_V4_ARTIFACT_PINS: ProductionV4ArtifactIdentityPins =
    ProductionV4ArtifactIdentityPins {
        bank: ProductionV3FileIdentityPin {
            bytes: 6_442_975_416,
            blake3: [
                0xb8, 0xbe, 0x84, 0x50, 0xb9, 0x33, 0xdc, 0x75, 0x9a, 0xa3, 0x4f, 0x2d, 0x60, 0xe7,
                0x3c, 0xf4, 0xea, 0xc3, 0x06, 0x44, 0x07, 0xc6, 0xa9, 0xf4, 0x83, 0x72, 0x17, 0x5a,
                0xbe, 0x87, 0xb6, 0xac,
            ],
            sha256: [
                0x5f, 0x9b, 0x21, 0x3c, 0x3b, 0xda, 0x51, 0xb7, 0x4e, 0x4e, 0xba, 0xbb, 0x26, 0x60,
                0x7b, 0x67, 0x38, 0x5d, 0x61, 0x3a, 0xa8, 0xd9, 0x9a, 0xf9, 0x15, 0xa4, 0x8a, 0xb0,
                0x63, 0xe1, 0x7d, 0x4e,
            ],
        },
        fixed_record: ProductionV3FileIdentityPin {
            bytes: 6_973,
            blake3: [
                0x3c, 0x95, 0x87, 0xfb, 0x83, 0x32, 0x34, 0xcd, 0xfa, 0x88, 0xb9, 0x75, 0x02, 0xa8,
                0x9a, 0xbb, 0xa6, 0x13, 0xb9, 0x00, 0x2c, 0x16, 0xbb, 0x64, 0x83, 0xb3, 0x4d, 0x53,
                0x99, 0xde, 0xeb, 0xd0,
            ],
            sha256: [
                0xea, 0x21, 0x88, 0x31, 0xaa, 0x56, 0x7e, 0x48, 0x64, 0x26, 0xde, 0xd7, 0x7c, 0x84,
                0xa5, 0x75, 0x2a, 0x81, 0x73, 0x29, 0xc4, 0x96, 0xe3, 0x55, 0x7c, 0x6d, 0x43, 0x57,
                0x7f, 0x0a, 0xfe, 0x79,
            ],
        },
    };

#[cfg(feature = "production-v4-testnet")]
pub const COMPILED_RELEASE_PROFILE: CompiledReleaseProfile = CompiledReleaseProfile {
    network: CompiledNetworkProfile::ProductionV4Testnet,
    proof: ConsensusProofSelection::ProductionV4,
    activation: None,
    production_v3_artifacts: None,
    production_v3_verifier_workers: None,
    production_v4_activation: None,
    production_v4_artifacts: Some(PRODUCTION_V4_ARTIFACT_PINS),
    production_network_identity: None,
};

#[cfg(feature = "production-rc")]
pub const PRODUCTION_RC_NETWORK_IDENTITY: ProductionRcNetworkIdentityPin =
    ProductionRcNetworkIdentityPin {
        network_id: [
            0x3e, 0x99, 0xd4, 0x59, 0x59, 0xc1, 0x9c, 0x00, 0x53, 0xd8, 0xe9, 0xfe, 0xf3, 0x48,
            0x75, 0xb5, 0x7b, 0x46, 0xa8, 0xa1, 0xce, 0x33, 0x06, 0x37, 0xda, 0xdd, 0xab, 0x51,
            0x5b, 0xc7, 0xb9, 0x2d,
        ],
        virtual_genesis_hash: [
            0xa5, 0x72, 0xb6, 0xce, 0x50, 0x97, 0x85, 0x11, 0xce, 0x87, 0x71, 0xdb, 0x66, 0x03,
            0xa6, 0x02, 0xfa, 0xcc, 0xf3, 0x80, 0x2c, 0xf0, 0xd4, 0x79, 0x1c, 0x1c, 0xe4, 0xe4,
            0x67, 0xba, 0x6b, 0x71,
        ],
        virtual_genesis_timestamp: 1_788_800_400,
        pow_limit: [
            0x00, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ],
        steward_reward_destination: [
            0x69, 0x89, 0xa6, 0x15, 0x23, 0x1a, 0x86, 0x55, 0x8b, 0x8e, 0xbf, 0x1f, 0x0b, 0x00,
            0x11, 0xcf, 0x4f, 0xb1, 0xe0, 0x20, 0x9f, 0x68, 0xa7, 0xb1, 0x27, 0x4f, 0x38, 0x77,
            0xe3, 0xb1, 0x6a, 0x6b,
        ],
        community_reward_destination: [
            0x2d, 0x70, 0x66, 0xdf, 0x96, 0x29, 0x7c, 0x41, 0xf8, 0xe4, 0xbb, 0x3b, 0xe2, 0x18,
            0xce, 0xfb, 0x82, 0x2f, 0xf1, 0xe7, 0xdc, 0x6c, 0xc6, 0x48, 0xf4, 0x7f, 0x92, 0xa9,
            0xc0, 0xc8, 0x8e, 0xf8,
        ],
    };

/// Fail-closed insertion point for authenticated ProductionV4 activation
/// evidence. RCNet may use the explicit single-producer RC policy; mainnet
/// uses a distinct owner-signed policy and exact launch-plan approval.
#[cfg(feature = "production-rc")]
pub const PRODUCTION_V4_ACTIVATION: Option<ProductionV4ActivationEvidence> =
    include!("production_v4_activation_pin.inc.rs");

/// ProductionV4 release-candidate shape. The V2 launch candidate pins the
/// immutable RCNet identity and exact proof artifacts. Activation evidence
/// remains absent, so `production-rc` continues to fail closed until a
/// supported approval policy and fresh-process verifier report are pinned.
#[cfg(feature = "production-rc")]
pub const COMPILED_RELEASE_PROFILE: CompiledReleaseProfile = CompiledReleaseProfile {
    network: CompiledNetworkProfile::Rcnet,
    proof: ConsensusProofSelection::ProductionV4,
    activation: None,
    production_v3_artifacts: None,
    production_v3_verifier_workers: None,
    production_v4_activation: PRODUCTION_V4_ACTIVATION,
    production_v4_artifacts: Some(PRODUCTION_V4_ARTIFACT_PINS),
    production_network_identity: Some(PRODUCTION_RC_NETWORK_IDENTITY),
};

#[cfg(feature = "production-mainnet")]
pub const COMPILED_RELEASE_PROFILE: CompiledReleaseProfile = CompiledReleaseProfile {
    network: CompiledNetworkProfile::Mainnet,
    proof: ConsensusProofSelection::ProductionV4,
    activation: None,
    production_v3_artifacts: None,
    production_v3_verifier_workers: None,
    production_v4_activation: match MAINNET_RELEASE_CONFIGURATION {
        Some(pin) => Some(pin.activation),
        None => None,
    },
    production_v4_artifacts: Some(PRODUCTION_V4_ARTIFACT_PINS),
    production_network_identity: None,
};

/// The identity selected by an ordinary source-tree build.
///
/// A production RC build may change these values only together with the real
/// RCNet/V3 integration and committed qualification evidence. The release
/// checkout commit is deliberately not a source constant: trusted CI supplies
/// it to the build gate so the finalizer can compare it with the exact checkout
/// without a self-reference.
#[cfg(not(any(
    feature = "production-v3-testnet",
    feature = "production-v4-testnet",
    feature = "production-rc",
    feature = "production-mainnet"
)))]
pub const COMPILED_RELEASE_PROFILE: CompiledReleaseProfile = CompiledReleaseProfile {
    network: CompiledNetworkProfile::Devnet,
    proof: ConsensusProofSelection::DevnetV2Reference,
    activation: None,
    production_v3_artifacts: None,
    production_v3_verifier_workers: None,
    production_v4_activation: None,
    production_v4_artifacts: None,
    production_network_identity: None,
};

const INSECURE_DEV_STEWARD_DESTINATION: [u8; 32] = [
    0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61, 0x5d, 0x90,
    0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07, 0x58, 0x71, 0xaa,
];
const INSECURE_DEV_COMMUNITY_DESTINATION: [u8; 32] = [
    0x63, 0x60, 0xe8, 0x56, 0x31, 0x0c, 0xe5, 0xd2, 0x94, 0xe8, 0xbe, 0x33, 0xfc, 0x80, 0x70, 0x77,
    0xdc, 0x56, 0xac, 0x80, 0xd9, 0x5d, 0x9c, 0xd4, 0xdd, 0xbd, 0x21, 0x32, 0x5e, 0xff, 0x73, 0xf7,
];

pub fn is_production_rc_label(label: &str) -> bool {
    let normalized = label.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.contains("devnet") || normalized.contains("testnet") {
        return false;
    }
    let tokens = normalized
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty());
    normalized.contains("production-rc")
        || normalized.contains("production_rc")
        || normalized.contains("mainnet-rc")
        || tokens.into_iter().any(|token| {
            token == "rc"
                || token.strip_prefix("rc").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                })
        })
}

pub fn is_mainnet_label(label: &str) -> bool {
    let label = label.trim().to_ascii_lowercase();
    !label.contains("devnet")
        && !label.contains("testnet")
        && !is_production_rc_label(&label)
        && label
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|token| token == "mainnet")
}

fn is_nonzero_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_file_identity_pin(pin: ProductionV3FileIdentityPin) -> bool {
    pin.bytes != 0 && pin.blake3 != [0; 32] && pin.sha256 != [0; 32]
}

fn valid_signer_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(*byte, b'@' | b'.' | b'_' | b'+' | b'-')
        })
}

fn valid_key_fingerprint(value: &str) -> bool {
    value.strip_prefix("SHA256:").is_some_and(|digest| {
        digest.len() == 43
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    })
}

fn decode_lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn key_fingerprint_matches(key_blob_sha256: &str, fingerprint: &str) -> bool {
    if !is_nonzero_lower_hex(key_blob_sha256, 32) || !valid_key_fingerprint(fingerprint) {
        return false;
    }
    let encoded = key_blob_sha256.as_bytes();
    let mut digest = [0_u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        let Some(high) = decode_lower_hex_nibble(encoded[index * 2]) else {
            return false;
        };
        let Some(low) = decode_lower_hex_nibble(encoded[index * 2 + 1]) else {
            return false;
        };
        *output = (high << 4) | low;
    }

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut expected = String::with_capacity(50);
    expected.push_str("SHA256:");
    for chunk in digest.chunks_exact(3) {
        expected.push(ALPHABET[(chunk[0] >> 2) as usize] as char);
        expected.push(ALPHABET[(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)) as usize] as char);
        expected.push(ALPHABET[(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6)) as usize] as char);
        expected.push(ALPHABET[(chunk[2] & 0x3f) as usize] as char);
    }
    let remainder = digest.chunks_exact(3).remainder();
    expected.push(ALPHABET[(remainder[0] >> 2) as usize] as char);
    expected.push(ALPHABET[(((remainder[0] & 0x03) << 4) | (remainder[1] >> 4)) as usize] as char);
    expected.push(ALPHABET[((remainder[1] & 0x0f) << 2) as usize] as char);
    expected == fingerprint
}

fn validate_production_v4_approval_trust(
    trust: ProductionV4ActivationApprovalTrust,
) -> Result<(), &'static str> {
    const DUAL_APPROVAL_SCHEMA: &str = "CMFD_PRODUCTION_V4_ACTIVATION_APPROVAL_SUBJECT_V1";
    const SINGLE_PRODUCER_RC_SCHEMA: &str =
        "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_APPROVAL_SUBJECT_V1";
    const MAINNET_OWNER_SCHEMA: &str = "CMFD_MAINNET_SINGLE_SIGNER_APPROVAL_SUBJECT_V1";
    let independent_reproducer = match trust.contract_schema {
        DUAL_APPROVAL_SCHEMA => Some(
            trust
                .independent_reproducer
                .ok_or("ProductionV4 independent reproducer approval trust is absent")?,
        ),
        SINGLE_PRODUCER_RC_SCHEMA | MAINNET_OWNER_SCHEMA => {
            if trust.independent_reproducer.is_some() {
                return Err(
                    "ProductionV4 single-signer trust must not claim an independent reproducer",
                );
            }
            None
        }
        _ => return Err("ProductionV4 activation approval contract schema is unsupported"),
    };
    if !is_nonzero_lower_hex(trust.qualification_binding_sha256, 32) {
        return Err("ProductionV4 qualification binding digest is invalid");
    }
    if !is_nonzero_lower_hex(trust.ssh_keygen_sha256, 32) {
        return Err("ProductionV4 OpenSSH verifier trust digest is invalid");
    }
    for signer in [Some(trust.producer), independent_reproducer]
        .into_iter()
        .flatten()
    {
        if !valid_signer_token(signer.signer_identity) {
            return Err("ProductionV4 activation approval signer identity is invalid");
        }
        if !is_nonzero_lower_hex(signer.allowed_signers_sha256, 32)
            || !is_nonzero_lower_hex(signer.key_blob_sha256, 32)
        {
            return Err("ProductionV4 activation approval trust digest is invalid");
        }
        if !key_fingerprint_matches(signer.key_blob_sha256, signer.key_fingerprint) {
            return Err("ProductionV4 activation approval key fingerprint is invalid");
        }
        if !valid_signer_token(signer.key_type)
            || signer.key_type.contains("-cert-v01@openssh.com")
            || signer.key_type.starts_with("ssh-dss")
        {
            return Err("ProductionV4 activation approval key type is invalid");
        }
    }
    if let Some(reproducer) = independent_reproducer
        && (trust.producer.signer_identity == reproducer.signer_identity
            || trust.producer.allowed_signers_sha256 == reproducer.allowed_signers_sha256
            || trust.producer.key_blob_sha256 == reproducer.key_blob_sha256
            || trust.producer.key_fingerprint == reproducer.key_fingerprint)
    {
        return Err("ProductionV4 producer and reproducer approval authorities are not distinct");
    }
    Ok(())
}

fn is_repeated_byte(value: [u8; 32]) -> bool {
    value.iter().all(|byte| *byte == value[0])
}

fn valid_binary_identity_pin(value: [u8; 32]) -> bool {
    value != [0; 32] && !is_repeated_byte(value)
}

fn lower_hex(value: [u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in value {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn validate_production_network_identity(
    identity: ProductionRcNetworkIdentityPin,
) -> Result<(), &'static str> {
    if identity.network_id == [0; 32] || is_repeated_byte(identity.network_id) {
        return Err("production RC network identifier is zero or a known placeholder");
    }
    if identity.virtual_genesis_hash == [0; 32] || is_repeated_byte(identity.virtual_genesis_hash) {
        return Err("production RC virtual genesis is zero or a known placeholder");
    }
    if identity.network_id == identity.virtual_genesis_hash {
        return Err("production RC network identifier and virtual genesis are not distinct");
    }
    if identity.virtual_genesis_timestamp == 0 {
        return Err("production RC virtual genesis timestamp is invalid");
    }
    if identity.pow_limit == [0; 32] {
        return Err("production RC proof-of-work limit is zero");
    }
    for destination in [
        identity.steward_reward_destination,
        identity.community_reward_destination,
    ] {
        if destination == INSECURE_DEV_STEWARD_DESTINATION
            || destination == INSECURE_DEV_COMMUNITY_DESTINATION
        {
            return Err("production RC reward destination uses a known insecure development key");
        }
    }
    Ok(())
}

fn validate_legacy_production_v3_rc(
    profile: CompiledReleaseProfile,
    build_source_commit: &str,
) -> Result<(), &'static str> {
    if profile.network != CompiledNetworkProfile::Rcnet {
        return Err("compiled network profile is not RCNet");
    }
    if profile.proof != ConsensusProofSelection::ProductionV3 {
        return Err("compiled consensus proof selection is not ProductionV3");
    }
    validate_production_network_identity(
        profile
            .production_network_identity
            .ok_or("production RC network identity pin is absent")?,
    )?;
    let evidence = profile
        .activation
        .ok_or("ProductionV3 activation evidence is absent")?;
    if evidence.schema != "CMFD_PRODUCTION_V3_ACTIVATION_V1" {
        return Err("ProductionV3 activation evidence schema is unsupported");
    }
    if !is_nonzero_lower_hex(build_source_commit, 20)
        && !is_nonzero_lower_hex(build_source_commit, 32)
    {
        return Err("trusted production RC build source commit is invalid");
    }
    if !is_nonzero_lower_hex(evidence.qualification_source_commit, 20)
        && !is_nonzero_lower_hex(evidence.qualification_source_commit, 32)
    {
        return Err("ProductionV3 qualification source commit is invalid");
    }
    if !is_nonzero_lower_hex(evidence.qualification_manifest_sha256, 32) {
        return Err("ProductionV3 qualification manifest digest is invalid");
    }
    if !is_nonzero_lower_hex(evidence.fresh_process_verifier_binary_sha256, 32) {
        return Err("ProductionV3 fresh-process verifier binary digest is invalid");
    }
    if !is_nonzero_lower_hex(evidence.fresh_process_verifier_report_sha256, 32) {
        return Err("ProductionV3 fresh-process verifier report digest is invalid");
    }
    let artifacts = profile
        .production_v3_artifacts
        .ok_or("ProductionV3 artifact identity pins are absent")?;
    if !valid_file_identity_pin(artifacts.bank)
        || !valid_file_identity_pin(artifacts.manifest)
        || !valid_file_identity_pin(artifacts.record_v2)
    {
        return Err("ProductionV3 artifact identity pins are invalid");
    }
    let verifier_workers = profile
        .production_v3_verifier_workers
        .ok_or("ProductionV3 runtime verifier-worker pin is absent")?;
    if !valid_binary_identity_pin(verifier_workers.windows_x86_64_sha256)
        || !valid_binary_identity_pin(verifier_workers.linux_x86_64_sha256)
        || verifier_workers.windows_x86_64_sha256 == verifier_workers.linux_x86_64_sha256
    {
        return Err("ProductionV3 runtime verifier-worker pin is invalid");
    }
    Ok(())
}

pub fn validate_production_rc(
    profile: CompiledReleaseProfile,
    build_source_commit: &str,
) -> Result<(), &'static str> {
    if profile.network != CompiledNetworkProfile::Rcnet {
        return Err("compiled network profile is not RCNet");
    }
    if profile.proof != ConsensusProofSelection::ProductionV4 {
        return Err("compiled consensus proof selection is not ProductionV4");
    }
    if profile
        .production_v4_activation
        .is_some_and(|evidence| evidence.schema == "CMFD_MAINNET_SINGLE_SIGNER_PROOF_ACTIVATION_V1")
    {
        return Err("mainnet approval cannot authorize an RC release");
    }
    validate_production_network_identity(
        profile
            .production_network_identity
            .ok_or("production RC network identity pin is absent")?,
    )?;
    validate_v4_evidence_and_artifacts(profile, build_source_commit)
}

fn validate_v4_evidence_and_artifacts(
    profile: CompiledReleaseProfile,
    build_source_commit: &str,
) -> Result<(), &'static str> {
    let evidence = profile
        .production_v4_activation
        .ok_or("ProductionV4 activation evidence is absent")?;
    if !matches!(
        evidence.schema,
        "CMFD_PRODUCTION_V4_ACTIVATION_V1"
            | "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_ACTIVATION_V1"
            | "CMFD_MAINNET_SINGLE_SIGNER_PROOF_ACTIVATION_V1"
    ) {
        return Err("ProductionV4 activation evidence schema is unsupported");
    }
    if !is_nonzero_lower_hex(build_source_commit, 20)
        && !is_nonzero_lower_hex(build_source_commit, 32)
    {
        return Err("trusted production RC build source commit is invalid");
    }
    if !is_nonzero_lower_hex(evidence.qualification_source_commit, 20)
        && !is_nonzero_lower_hex(evidence.qualification_source_commit, 32)
    {
        return Err("ProductionV4 qualification source commit is invalid");
    }
    for (digest, error) in [
        (
            evidence.qualification_manifest_sha256,
            "ProductionV4 qualification manifest digest is invalid",
        ),
        (
            evidence.fresh_process_verifier_binary_sha256,
            "ProductionV4 fresh-process verifier binary digest is invalid",
        ),
        (
            evidence.fresh_process_verifier_report_sha256,
            "ProductionV4 fresh-process verifier report digest is invalid",
        ),
        (
            evidence.core_spec_sha256,
            "ProductionV4 core specification digest is invalid",
        ),
        (
            evidence.core_vector_sha256,
            "ProductionV4 core vector digest is invalid",
        ),
        (
            evidence.proof_algebra_sha256,
            "ProductionV4 proof algebra digest is invalid",
        ),
    ] {
        if !is_nonzero_lower_hex(digest, 32) {
            return Err(error);
        }
    }
    validate_production_v4_approval_trust(evidence.approval_trust)?;
    let schema_matches_trust = matches!(
        (
            evidence.schema,
            evidence.approval_trust.contract_schema,
            evidence.approval_trust.independent_reproducer,
        ),
        (
            "CMFD_PRODUCTION_V4_ACTIVATION_V1",
            "CMFD_PRODUCTION_V4_ACTIVATION_APPROVAL_SUBJECT_V1",
            Some(_),
        ) | (
            "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_ACTIVATION_V1",
            "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_APPROVAL_SUBJECT_V1",
            None,
        ) | (
            "CMFD_MAINNET_SINGLE_SIGNER_PROOF_ACTIVATION_V1",
            "CMFD_MAINNET_SINGLE_SIGNER_APPROVAL_SUBJECT_V1",
            None,
        )
    );
    if !schema_matches_trust {
        return Err("ProductionV4 activation evidence and approval policy do not match");
    }
    let artifacts = profile
        .production_v4_artifacts
        .ok_or("ProductionV4 artifact identity pins are absent")?;
    if !valid_file_identity_pin(artifacts.bank) || !valid_file_identity_pin(artifacts.fixed_record)
    {
        return Err("ProductionV4 artifact identity pins are invalid");
    }
    Ok(())
}

pub fn validate_mainnet_release(
    profile: CompiledReleaseProfile,
    configuration: Option<MainnetReleaseConfiguration>,
    consensus_network_id: Option<[u8; 32]>,
    build_source_commit: &str,
) -> Result<(), &'static str> {
    if profile.network != CompiledNetworkProfile::Mainnet
        || profile.proof != ConsensusProofSelection::ProductionV4
    {
        return Err("compiled network/proof profile is not mainnet ProductionV4");
    }
    let pin = configuration.ok_or("final mainnet launch plan and approval pins are absent")?;
    if [
        crate::network_profile::DEVNET_PROFILE.network_id,
        crate::network_profile::PRODUCTION_V3_TESTNET_PROFILE.network_id,
        crate::network_profile::PRODUCTION_V4_TESTNET_PROFILE.network_id,
        crate::network_profile::RCNET1_PROFILE.network_id,
    ]
    .contains(&pin.network_id)
    {
        return Err("mainnet cannot reuse a development or RC network identity");
    }
    if !valid_binary_identity_pin(pin.launch_plan_digest)
        || !valid_binary_identity_pin(pin.network_id)
        || consensus_network_id != Some(pin.network_id)
        || pin.launch_plan_digest == pin.network_id
    {
        return Err("mainnet plan/network pins are invalid or disagree with consensus");
    }
    if pin.pow_limit == [0; 32] {
        return Err("mainnet proof-of-work limit is zero");
    }
    if pin.initial_target == [0; 32] || pin.initial_target > pin.pow_limit {
        return Err("mainnet initial proof-of-work target is zero or exceeds the limit");
    }
    for destination in [
        pin.steward_reward_destination,
        pin.community_reward_destination,
    ] {
        if !valid_binary_identity_pin(destination)
            || [
                INSECURE_DEV_STEWARD_DESTINATION,
                INSECURE_DEV_COMMUNITY_DESTINATION,
            ]
            .contains(&destination)
        {
            return Err("mainnet reward destination is invalid or a development key");
        }
    }
    if !is_nonzero_lower_hex(pin.approval_manifest_sha256, 32) {
        return Err("mainnet approval manifest pin is absent or invalid");
    }
    if pin.activation.schema != "CMFD_MAINNET_SINGLE_SIGNER_PROOF_ACTIVATION_V1"
        || pin.activation.approval_trust.contract_schema
            != "CMFD_MAINNET_SINGLE_SIGNER_APPROVAL_SUBJECT_V1"
        || pin
            .activation
            .approval_trust
            .independent_reproducer
            .is_some()
    {
        return Err("mainnet requires its explicit single-owner release approval");
    }
    if profile.production_v4_activation != Some(pin.activation) {
        return Err("mainnet activation profile does not match its release pin");
    }
    validate_v4_evidence_and_artifacts(profile, build_source_commit)
}

/// Exact activation-evidence bytes hashed into the compiled ProductionV3
/// network manifest and staged by the release finalizer.
///
/// The dynamic release checkout commit is supplied by the trusted build job;
/// it is deliberately absent from source constants to avoid self-reference.
#[allow(dead_code)] // build.rs includes this shared module but does not serialize evidence.
pub fn canonical_production_v3_activation_evidence_json(
    profile: CompiledReleaseProfile,
    build_source_commit: &str,
) -> Result<Vec<u8>, &'static str> {
    validate_legacy_production_v3_rc(profile, build_source_commit)?;
    let evidence = profile
        .activation
        .ok_or("ProductionV3 activation evidence is absent")?;
    let artifacts = profile
        .production_v3_artifacts
        .ok_or("ProductionV3 artifact identity pins are absent")?;
    let workers = profile
        .production_v3_verifier_workers
        .ok_or("ProductionV3 runtime verifier-worker pin is absent")?;
    Ok(format!(
        concat!(
            "{{\"artifacts\":{{",
            "\"bank\":{{\"blake3\":\"{}\",\"bytes\":\"{}\",\"sha256\":\"{}\"}},",
            "\"manifest\":{{\"blake3\":\"{}\",\"bytes\":\"{}\",\"sha256\":\"{}\"}},",
            "\"record_v2\":{{\"blake3\":\"{}\",\"bytes\":\"{}\",\"sha256\":\"{}\"}}}},",
            "\"fresh_process_verifier_binary_sha256\":\"{}\",",
            "\"fresh_process_verifier_report_sha256\":\"{}\",",
            "\"network_profile\":\"RCNet-1\",",
            "\"proof_selection\":\"ProductionV3\",",
            "\"qualification_manifest_sha256\":\"{}\",",
            "\"qualification_source_commit\":\"{}\",",
            "\"runtime_verifier_workers\":{{",
            "\"linux_x86_64_sha256\":\"{}\",",
            "\"windows_x86_64_sha256\":\"{}\"}},",
            "\"schema\":\"{}\",",
            "\"source_commit\":\"{}\"}}\n"
        ),
        lower_hex(artifacts.bank.blake3),
        artifacts.bank.bytes,
        lower_hex(artifacts.bank.sha256),
        lower_hex(artifacts.manifest.blake3),
        artifacts.manifest.bytes,
        lower_hex(artifacts.manifest.sha256),
        lower_hex(artifacts.record_v2.blake3),
        artifacts.record_v2.bytes,
        lower_hex(artifacts.record_v2.sha256),
        evidence.fresh_process_verifier_binary_sha256,
        evidence.fresh_process_verifier_report_sha256,
        evidence.qualification_manifest_sha256,
        evidence.qualification_source_commit,
        lower_hex(workers.linux_x86_64_sha256),
        lower_hex(workers.windows_x86_64_sha256),
        evidence.schema,
        build_source_commit,
    )
    .into_bytes())
}

/// Exact activation-evidence bytes hashed into a ProductionV4 RC network
/// manifest. The source commit remains a trusted build input so the source
/// tree never attempts to hash a value that contains itself.
#[allow(dead_code)] // build.rs validates evidence but does not serialize it.
pub fn canonical_production_v4_activation_evidence_json(
    profile: CompiledReleaseProfile,
    build_source_commit: &str,
) -> Result<Vec<u8>, &'static str> {
    validate_production_rc(profile, build_source_commit)?;
    canonical_v4_evidence_json(profile, build_source_commit, "RCNet-1")
}

#[allow(dead_code)]
pub fn canonical_mainnet_activation_evidence_json(
    profile: CompiledReleaseProfile,
    configuration: MainnetReleaseConfiguration,
    consensus_network_id: Option<[u8; 32]>,
    build_source_commit: &str,
) -> Result<Vec<u8>, &'static str> {
    validate_mainnet_release(
        profile,
        Some(configuration),
        consensus_network_id,
        build_source_commit,
    )?;
    let proof = canonical_v4_evidence_json(profile, build_source_commit, "Mainnet")?;
    let proof = std::str::from_utf8(&proof)
        .map_err(|_| "invalid mainnet evidence encoding")?
        .trim_end_matches('\n');
    Ok(format!(
        concat!(
            "{{\"schema\":\"CMFD_MAINNET_ACTIVATION_V1\",",
            "\"launch_plan_digest\":\"{}\",\"network_id\":\"{}\",",
            "\"approval_manifest_sha256\":\"{}\",",
            "\"proof_activation\":{}}}\n"
        ),
        lower_hex(configuration.launch_plan_digest),
        lower_hex(configuration.network_id),
        configuration.approval_manifest_sha256,
        proof
    )
    .into_bytes())
}

fn canonical_v4_evidence_json(
    profile: CompiledReleaseProfile,
    build_source_commit: &str,
    network_profile: &str,
) -> Result<Vec<u8>, &'static str> {
    let evidence = profile
        .production_v4_activation
        .ok_or("ProductionV4 activation evidence is absent")?;
    let artifacts = profile
        .production_v4_artifacts
        .ok_or("ProductionV4 artifact identity pins are absent")?;
    let trust = evidence.approval_trust;
    let independent_reproducer = match trust.independent_reproducer {
        Some(signer) => format!(
            concat!(
                "{{\"allowed_signers_sha256\":\"{}\",",
                "\"key_blob_sha256\":\"{}\",",
                "\"key_fingerprint\":\"{}\",",
                "\"key_type\":\"{}\",",
                "\"signer_identity\":\"{}\"}}"
            ),
            signer.allowed_signers_sha256,
            signer.key_blob_sha256,
            signer.key_fingerprint,
            signer.key_type,
            signer.signer_identity,
        ),
        None => "null".to_owned(),
    };
    Ok(format!(
        concat!(
            "{{\"activation_approval_trust\":{{",
            "\"contract_schema\":\"{}\",",
            "\"independent_reproducer\":{},",
            "\"producer\":{{",
            "\"allowed_signers_sha256\":\"{}\",",
            "\"key_blob_sha256\":\"{}\",",
            "\"key_fingerprint\":\"{}\",",
            "\"key_type\":\"{}\",",
            "\"signer_identity\":\"{}\"}},",
            "\"qualification_binding_sha256\":\"{}\",",
            "\"ssh_keygen_sha256\":\"{}\"}},",
            "\"artifacts\":{{",
            "\"bank\":{{\"blake3\":\"{}\",\"bytes\":\"{}\",\"sha256\":\"{}\"}},",
            "\"fixed_record\":{{\"blake3\":\"{}\",\"bytes\":\"{}\",\"sha256\":\"{}\"}}}},",
            "\"core_spec_sha256\":\"{}\",",
            "\"core_vector_sha256\":\"{}\",",
            "\"fresh_process_verifier_binary_sha256\":\"{}\",",
            "\"fresh_process_verifier_report_sha256\":\"{}\",",
            "\"network_profile\":\"{}\",",
            "\"proof_algebra_sha256\":\"{}\",",
            "\"proof_selection\":\"ProductionV4\",",
            "\"qualification_manifest_sha256\":\"{}\",",
            "\"qualification_source_commit\":\"{}\",",
            "\"schema\":\"{}\",",
            "\"source_commit\":\"{}\"}}\n"
        ),
        trust.contract_schema,
        independent_reproducer,
        trust.producer.allowed_signers_sha256,
        trust.producer.key_blob_sha256,
        trust.producer.key_fingerprint,
        trust.producer.key_type,
        trust.producer.signer_identity,
        trust.qualification_binding_sha256,
        trust.ssh_keygen_sha256,
        lower_hex(artifacts.bank.blake3),
        artifacts.bank.bytes,
        lower_hex(artifacts.bank.sha256),
        lower_hex(artifacts.fixed_record.blake3),
        artifacts.fixed_record.bytes,
        lower_hex(artifacts.fixed_record.sha256),
        evidence.core_spec_sha256,
        evidence.core_vector_sha256,
        evidence.fresh_process_verifier_binary_sha256,
        evidence.fresh_process_verifier_report_sha256,
        network_profile,
        evidence.proof_algebra_sha256,
        evidence.qualification_manifest_sha256,
        evidence.qualification_source_commit,
        evidence.schema,
        build_source_commit,
    )
    .into_bytes())
}

pub fn validate_production_rc_for_network(
    profile: CompiledReleaseProfile,
    build_source_commit: &str,
    compiled_network_identity: ProductionRcNetworkIdentityPin,
) -> Result<(), &'static str> {
    validate_production_rc(profile, build_source_commit)?;
    if profile.production_network_identity != Some(compiled_network_identity) {
        return Err(
            "production RC network identity pin does not match the compiled network profile",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVIDENCE: ProductionV3ActivationEvidence = ProductionV3ActivationEvidence {
        schema: "CMFD_PRODUCTION_V3_ACTIVATION_V1",
        qualification_source_commit: "1111111111111111111111111111111111111111",
        qualification_manifest_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
        fresh_process_verifier_binary_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
        fresh_process_verifier_report_sha256: "4444444444444444444444444444444444444444444444444444444444444444",
    };
    const ARTIFACTS: ProductionV3ArtifactIdentityPins = ProductionV3ArtifactIdentityPins {
        bank: ProductionV3FileIdentityPin {
            bytes: 1,
            blake3: [0x44; 32],
            sha256: [0x45; 32],
        },
        manifest: ProductionV3FileIdentityPin {
            bytes: 2,
            blake3: [0x46; 32],
            sha256: [0x47; 32],
        },
        record_v2: ProductionV3FileIdentityPin {
            bytes: 3,
            blake3: [0x48; 32],
            sha256: [0x49; 32],
        },
    };
    const V4_APPROVAL_TRUST: ProductionV4ActivationApprovalTrust =
        ProductionV4ActivationApprovalTrust {
            contract_schema: "CMFD_PRODUCTION_V4_ACTIVATION_APPROVAL_SUBJECT_V1",
            qualification_binding_sha256: "9999999999999999999999999999999999999999999999999999999999999999",
            ssh_keygen_sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            producer: ProductionV4ActivationSignerTrust {
                signer_identity: "producer@example.invalid",
                allowed_signers_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                key_blob_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                key_fingerprint: "SHA256:u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s",
                key_type: "ssh-ed25519",
            },
            independent_reproducer: Some(ProductionV4ActivationSignerTrust {
                signer_identity: "reproducer@example.invalid",
                allowed_signers_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                key_blob_sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                key_fingerprint: "SHA256:3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0",
                key_type: "ssh-ed25519",
            }),
        };
    const V4_EVIDENCE: ProductionV4ActivationEvidence = ProductionV4ActivationEvidence {
        schema: "CMFD_PRODUCTION_V4_ACTIVATION_V1",
        qualification_source_commit: "1111111111111111111111111111111111111111",
        qualification_manifest_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
        fresh_process_verifier_binary_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
        fresh_process_verifier_report_sha256: "4444444444444444444444444444444444444444444444444444444444444444",
        core_spec_sha256: "6666666666666666666666666666666666666666666666666666666666666666",
        core_vector_sha256: "7777777777777777777777777777777777777777777777777777777777777777",
        proof_algebra_sha256: "8888888888888888888888888888888888888888888888888888888888888888",
        approval_trust: V4_APPROVAL_TRUST,
    };
    const SINGLE_PRODUCER_V4_APPROVAL_TRUST: ProductionV4ActivationApprovalTrust =
        ProductionV4ActivationApprovalTrust {
            contract_schema: "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_APPROVAL_SUBJECT_V1",
            independent_reproducer: None,
            ..V4_APPROVAL_TRUST
        };
    const SINGLE_PRODUCER_V4_EVIDENCE: ProductionV4ActivationEvidence =
        ProductionV4ActivationEvidence {
            schema: "CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_ACTIVATION_V1",
            approval_trust: SINGLE_PRODUCER_V4_APPROVAL_TRUST,
            ..V4_EVIDENCE
        };
    const MAINNET_OWNER_EVIDENCE: ProductionV4ActivationEvidence = ProductionV4ActivationEvidence {
        schema: "CMFD_MAINNET_SINGLE_SIGNER_PROOF_ACTIVATION_V1",
        approval_trust: ProductionV4ActivationApprovalTrust {
            contract_schema: "CMFD_MAINNET_SINGLE_SIGNER_APPROVAL_SUBJECT_V1",
            independent_reproducer: None,
            ..V4_APPROVAL_TRUST
        },
        ..V4_EVIDENCE
    };
    const V4_ARTIFACTS: ProductionV4ArtifactIdentityPins = ProductionV4ArtifactIdentityPins {
        bank: ProductionV3FileIdentityPin {
            bytes: 1,
            blake3: [0x44; 32],
            sha256: [0x45; 32],
        },
        fixed_record: ProductionV3FileIdentityPin {
            bytes: 2,
            blake3: [0x46; 32],
            sha256: [0x47; 32],
        },
    };
    const BUILD_SOURCE_COMMIT: &str = "5555555555555555555555555555555555555555";
    const fn varied(seed: u8) -> [u8; 32] {
        let mut value = [0_u8; 32];
        let mut index = 0;
        while index < value.len() {
            value[index] = seed.wrapping_add(index as u8);
            index += 1;
        }
        value
    }

    const VERIFIER_WORKERS: ProductionV3VerifierWorkerIdentityPins =
        ProductionV3VerifierWorkerIdentityPins {
            windows_x86_64_sha256: varied(0x5a),
            linux_x86_64_sha256: varied(0x9a),
        };

    const NETWORK_IDENTITY: ProductionRcNetworkIdentityPin = ProductionRcNetworkIdentityPin {
        network_id: varied(1),
        virtual_genesis_hash: varied(65),
        virtual_genesis_timestamp: 1_800_000_000,
        pow_limit: [0xff; 32],
        steward_reward_destination: varied(129),
        community_reward_destination: varied(193),
    };

    fn v4_profile() -> CompiledReleaseProfile {
        CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV4,
            activation: None,
            production_v3_artifacts: None,
            production_v3_verifier_workers: None,
            production_v4_activation: Some(V4_EVIDENCE),
            production_v4_artifacts: Some(V4_ARTIFACTS),
            production_network_identity: Some(NETWORK_IDENTITY),
        }
    }

    fn single_producer_v4_profile() -> CompiledReleaseProfile {
        CompiledReleaseProfile {
            production_v4_activation: Some(SINGLE_PRODUCER_V4_EVIDENCE),
            ..v4_profile()
        }
    }

    fn mainnet_fixture() -> (CompiledReleaseProfile, MainnetReleaseConfiguration) {
        let configuration = MainnetReleaseConfiguration {
            launch_plan_digest: varied(33),
            network_id: varied(2),
            pow_limit: NETWORK_IDENTITY.pow_limit,
            initial_target: NETWORK_IDENTITY.pow_limit,
            steward_reward_destination: NETWORK_IDENTITY.steward_reward_destination,
            community_reward_destination: NETWORK_IDENTITY.community_reward_destination,
            approval_manifest_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            activation: MAINNET_OWNER_EVIDENCE,
        };
        (
            CompiledReleaseProfile {
                network: CompiledNetworkProfile::Mainnet,
                production_network_identity: None,
                production_v4_activation: Some(MAINNET_OWNER_EVIDENCE),
                ..v4_profile()
            },
            configuration,
        )
    }

    #[test]
    fn mainnet_labels_require_the_mainnet_gate_without_reclassifying_rcnet() {
        assert!(is_mainnet_label("v1.0.0-mainnet"));
        assert!(is_mainnet_label("Mainnet"));
        for label in [
            "v0.1.0-rc.5",
            "mainnet-rc1",
            "devnet-mainnet-test",
            "testnet-mainnet",
            "v1.0.0",
        ] {
            assert!(!is_mainnet_label(label));
        }
    }

    #[test]
    fn mainnet_requires_distinct_release_and_consensus_pins() {
        let (profile, configuration) = mainnet_fixture();
        assert!(
            validate_mainnet_release(
                profile,
                Some(configuration),
                Some(configuration.network_id),
                BUILD_SOURCE_COMMIT
            )
            .is_ok()
        );
        assert!(
            validate_mainnet_release(
                profile,
                None,
                Some(configuration.network_id),
                BUILD_SOURCE_COMMIT
            )
            .is_err()
        );
        assert!(
            validate_mainnet_release(profile, Some(configuration), None, BUILD_SOURCE_COMMIT)
                .is_err()
        );
        assert!(
            validate_mainnet_release(
                profile,
                Some(configuration),
                Some(varied(3)),
                BUILD_SOURCE_COMMIT
            )
            .is_err()
        );
        for network in [
            crate::network_profile::RCNET1_PROFILE.network_id,
            crate::network_profile::PRODUCTION_V4_TESTNET_PROFILE.network_id,
        ] {
            let changed = MainnetReleaseConfiguration {
                network_id: network,
                ..configuration
            };
            assert!(
                validate_mainnet_release(
                    profile,
                    Some(changed),
                    Some(network),
                    BUILD_SOURCE_COMMIT
                )
                .is_err()
            );
        }
    }

    #[test]
    fn mainnet_release_checks_initial_target_bounds() {
        let (profile, configuration) = mainnet_fixture();
        for (initial_target, pow_limit) in [([0; 32], [0xff; 32]), ([0x30; 32], [0x20; 32])] {
            let invalid = MainnetReleaseConfiguration {
                initial_target,
                pow_limit,
                ..configuration
            };
            assert!(
                validate_mainnet_release(
                    profile,
                    Some(invalid),
                    Some(invalid.network_id),
                    BUILD_SOURCE_COMMIT
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rc_approval_cannot_authorize_mainnet_by_relabelling() {
        let (mut profile, mut configuration) = mainnet_fixture();
        configuration.activation = SINGLE_PRODUCER_V4_EVIDENCE;
        profile.production_v4_activation = Some(configuration.activation);
        assert_eq!(
            validate_mainnet_release(
                profile,
                Some(configuration),
                Some(configuration.network_id),
                BUILD_SOURCE_COMMIT
            ),
            Err("mainnet requires its explicit single-owner release approval")
        );
        configuration.activation = MAINNET_OWNER_EVIDENCE;
        configuration
            .activation
            .approval_trust
            .independent_reproducer = Some(V4_APPROVAL_TRUST.producer);
        profile.production_v4_activation = Some(configuration.activation);
        assert!(
            validate_mainnet_release(
                profile,
                Some(configuration),
                Some(configuration.network_id),
                BUILD_SOURCE_COMMIT
            )
            .is_err()
        );
    }

    #[test]
    fn mainnet_template_never_invents_a_genesis_or_configured_release() {
        let (_, configuration) = mainnet_fixture();
        assert!(crate::network_profile::mainnet_profile_template(None).is_none());
        let profile =
            crate::network_profile::mainnet_profile_template(Some(configuration)).unwrap();
        assert_eq!(
            profile.kind,
            crate::network_profile::NetworkProfileKind::Mainnet
        );
        assert_eq!(profile.virtual_genesis_hash, [0; 32]);
        assert_eq!(
            profile.virtual_genesis_timestamp,
            mainnet_schedule::MAINNET_LAUNCH_UNIX_SECONDS
        );
        assert_eq!(profile.network_id, configuration.network_id);
        assert_ne!(
            profile.default_data_dir_identity,
            crate::network_profile::RCNET1_PROFILE.default_data_dir_identity
        );
    }

    #[test]
    fn owner_mainnet_approval_cannot_authorize_rc() {
        let profile = CompiledReleaseProfile {
            production_v4_activation: Some(MAINNET_OWNER_EVIDENCE),
            ..v4_profile()
        };
        assert_eq!(
            validate_production_rc(profile, BUILD_SOURCE_COMMIT),
            Err("mainnet approval cannot authorize an RC release")
        );
    }

    #[test]
    fn mainnet_evidence_binds_the_new_plan_and_cannot_be_an_rc_record() {
        let (profile, configuration) = mainnet_fixture();
        let bytes = canonical_mainnet_activation_evidence_json(
            profile,
            configuration,
            Some(configuration.network_id),
            BUILD_SOURCE_COMMIT,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema"], "CMFD_MAINNET_ACTIVATION_V1");
        assert_eq!(
            value["launch_plan_digest"],
            lower_hex(configuration.launch_plan_digest)
        );
        assert_eq!(value["network_id"], lower_hex(configuration.network_id));
        assert_eq!(value["proof_activation"]["network_profile"], "Mainnet");
        assert!(
            value["proof_activation"]["activation_approval_trust"]["independent_reproducer"]
                .is_null()
        );
        assert!(
            canonical_production_v4_activation_evidence_json(profile, BUILD_SOURCE_COMMIT).is_err()
        );
    }

    #[test]
    fn production_rc_labels_are_distinct_from_devnet_rc_labels() {
        for label in ["production-rc1", "mainnet-rc.2", "v1.0.0-rc1"] {
            assert!(is_production_rc_label(label), "{label}");
        }
        for label in ["0.1.0-devnet.14", "v0.1.0-devnet.14-rc1", "debug"] {
            assert!(!is_production_rc_label(label), "{label}");
        }
    }

    #[test]
    #[cfg(not(feature = "production-rc"))]
    fn current_source_tree_fails_the_production_rc_gate() {
        assert_eq!(
            validate_production_rc(COMPILED_RELEASE_PROFILE, BUILD_SOURCE_COMMIT),
            Err("compiled network profile is not RCNet")
        );
    }

    #[test]
    fn legacy_v3_gate_requires_activation_artifacts_and_workers() {
        let no_v3 = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::DevnetV2Reference,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_v4_activation: None,
            production_v4_artifacts: None,
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_legacy_production_v3_rc(no_v3, BUILD_SOURCE_COMMIT),
            Err("compiled consensus proof selection is not ProductionV3")
        );

        let no_evidence = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: None,
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_v4_activation: None,
            production_v4_artifacts: None,
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_legacy_production_v3_rc(no_evidence, BUILD_SOURCE_COMMIT),
            Err("ProductionV3 activation evidence is absent")
        );

        let no_artifacts = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: None,
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_v4_activation: None,
            production_v4_artifacts: None,
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_legacy_production_v3_rc(no_artifacts, BUILD_SOURCE_COMMIT),
            Err("ProductionV3 artifact identity pins are absent")
        );

        let no_runtime_worker = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: None,
            production_v4_activation: None,
            production_v4_artifacts: None,
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_legacy_production_v3_rc(no_runtime_worker, BUILD_SOURCE_COMMIT),
            Err("ProductionV3 runtime verifier-worker pin is absent")
        );

        let zero_runtime_worker = CompiledReleaseProfile {
            production_v3_verifier_workers: Some(ProductionV3VerifierWorkerIdentityPins {
                windows_x86_64_sha256: [0; 32],
                linux_x86_64_sha256: [0x5b; 32],
            }),
            ..no_runtime_worker
        };
        assert_eq!(
            validate_legacy_production_v3_rc(zero_runtime_worker, BUILD_SOURCE_COMMIT),
            Err("ProductionV3 runtime verifier-worker pin is invalid")
        );

        let placeholder_runtime_worker = CompiledReleaseProfile {
            production_v3_verifier_workers: Some(ProductionV3VerifierWorkerIdentityPins {
                windows_x86_64_sha256: [0x5a; 32],
                linux_x86_64_sha256: varied(0x9a),
            }),
            ..no_runtime_worker
        };
        assert_eq!(
            validate_legacy_production_v3_rc(placeholder_runtime_worker, BUILD_SOURCE_COMMIT),
            Err("ProductionV3 runtime verifier-worker pin is invalid")
        );

        let identical_runtime_workers = CompiledReleaseProfile {
            production_v3_verifier_workers: Some(ProductionV3VerifierWorkerIdentityPins {
                windows_x86_64_sha256: varied(0x5a),
                linux_x86_64_sha256: varied(0x5a),
            }),
            ..no_runtime_worker
        };
        assert_eq!(
            validate_legacy_production_v3_rc(identical_runtime_workers, BUILD_SOURCE_COMMIT),
            Err("ProductionV3 runtime verifier-worker pin is invalid")
        );
    }

    #[test]
    fn runtime_verifier_worker_pin_is_platform_specific_and_fail_closed() {
        assert_eq!(
            VERIFIER_WORKERS.for_target("windows", "x86_64"),
            Some(varied(0x5a))
        );
        assert_eq!(
            VERIFIER_WORKERS.for_target("linux", "x86_64"),
            Some(varied(0x9a))
        );
        assert_eq!(VERIFIER_WORKERS.for_target("macos", "aarch64"), None);
    }

    #[test]
    fn production_rc_gate_requires_v4_evidence_and_artifact_pins() {
        let wrong_proof = CompiledReleaseProfile {
            proof: ConsensusProofSelection::ProductionV3,
            ..v4_profile()
        };
        assert_eq!(
            validate_production_rc(wrong_proof, BUILD_SOURCE_COMMIT),
            Err("compiled consensus proof selection is not ProductionV4")
        );

        let no_evidence = CompiledReleaseProfile {
            production_v4_activation: None,
            ..v4_profile()
        };
        assert_eq!(
            validate_production_rc(no_evidence, BUILD_SOURCE_COMMIT),
            Err("ProductionV4 activation evidence is absent")
        );

        let no_artifacts = CompiledReleaseProfile {
            production_v4_artifacts: None,
            ..v4_profile()
        };
        assert_eq!(
            validate_production_rc(no_artifacts, BUILD_SOURCE_COMMIT),
            Err("ProductionV4 artifact identity pins are absent")
        );

        let invalid_artifacts = CompiledReleaseProfile {
            production_v4_artifacts: Some(ProductionV4ArtifactIdentityPins {
                fixed_record: ProductionV3FileIdentityPin {
                    bytes: 0,
                    ..V4_ARTIFACTS.fixed_record
                },
                ..V4_ARTIFACTS
            }),
            ..v4_profile()
        };
        assert_eq!(
            validate_production_rc(invalid_artifacts, BUILD_SOURCE_COMMIT),
            Err("ProductionV4 artifact identity pins are invalid")
        );

        let self_approved = CompiledReleaseProfile {
            production_v4_activation: Some(ProductionV4ActivationEvidence {
                approval_trust: ProductionV4ActivationApprovalTrust {
                    independent_reproducer: Some(V4_APPROVAL_TRUST.producer),
                    ..V4_APPROVAL_TRUST
                },
                ..V4_EVIDENCE
            }),
            ..v4_profile()
        };
        assert_eq!(
            validate_production_rc(self_approved, BUILD_SOURCE_COMMIT),
            Err("ProductionV4 producer and reproducer approval authorities are not distinct")
        );
    }

    #[test]
    fn production_rc_gate_rejects_malformed_approval_trust() {
        let profile_with_trust = |approval_trust| CompiledReleaseProfile {
            production_v4_activation: Some(ProductionV4ActivationEvidence {
                approval_trust,
                ..V4_EVIDENCE
            }),
            ..v4_profile()
        };

        let zero_verifier = ProductionV4ActivationApprovalTrust {
            ssh_keygen_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            ..V4_APPROVAL_TRUST
        };
        assert_eq!(
            validate_production_rc(profile_with_trust(zero_verifier), BUILD_SOURCE_COMMIT),
            Err("ProductionV4 OpenSSH verifier trust digest is invalid")
        );

        let zero_policy = ProductionV4ActivationApprovalTrust {
            producer: ProductionV4ActivationSignerTrust {
                allowed_signers_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
                ..V4_APPROVAL_TRUST.producer
            },
            ..V4_APPROVAL_TRUST
        };
        assert_eq!(
            validate_production_rc(profile_with_trust(zero_policy), BUILD_SOURCE_COMMIT),
            Err("ProductionV4 activation approval trust digest is invalid")
        );

        let bad_fingerprint = ProductionV4ActivationApprovalTrust {
            producer: ProductionV4ActivationSignerTrust {
                key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ..V4_APPROVAL_TRUST.producer
            },
            ..V4_APPROVAL_TRUST
        };
        assert_eq!(
            validate_production_rc(profile_with_trust(bad_fingerprint), BUILD_SOURCE_COMMIT),
            Err("ProductionV4 activation approval key fingerprint is invalid")
        );

        for key_type in ["ssh-dss", "ssh-ed25519-cert-v01@openssh.com"] {
            let invalid_key_type = ProductionV4ActivationApprovalTrust {
                producer: ProductionV4ActivationSignerTrust {
                    key_type,
                    ..V4_APPROVAL_TRUST.producer
                },
                ..V4_APPROVAL_TRUST
            };
            assert_eq!(
                validate_production_rc(profile_with_trust(invalid_key_type), BUILD_SOURCE_COMMIT),
                Err("ProductionV4 activation approval key type is invalid")
            );
        }

        for duplicate in ["identity", "policy", "key"] {
            let reproducer = V4_APPROVAL_TRUST
                .independent_reproducer
                .expect("dual approval test trust has a reproducer");
            let independent_reproducer = Some(match duplicate {
                "identity" => ProductionV4ActivationSignerTrust {
                    signer_identity: V4_APPROVAL_TRUST.producer.signer_identity,
                    ..reproducer
                },
                "policy" => ProductionV4ActivationSignerTrust {
                    allowed_signers_sha256: V4_APPROVAL_TRUST.producer.allowed_signers_sha256,
                    ..reproducer
                },
                "key" => ProductionV4ActivationSignerTrust {
                    key_blob_sha256: V4_APPROVAL_TRUST.producer.key_blob_sha256,
                    key_fingerprint: V4_APPROVAL_TRUST.producer.key_fingerprint,
                    ..reproducer
                },
                _ => unreachable!(),
            });
            let not_distinct = ProductionV4ActivationApprovalTrust {
                independent_reproducer,
                ..V4_APPROVAL_TRUST
            };
            assert_eq!(
                validate_production_rc(profile_with_trust(not_distinct), BUILD_SOURCE_COMMIT),
                Err("ProductionV4 producer and reproducer approval authorities are not distinct"),
                "{duplicate}"
            );
        }
    }

    #[test]
    fn production_rc_gate_accepts_only_a_complete_rcnet_v4_profile() {
        let profile = v4_profile();
        assert_eq!(validate_production_rc(profile, BUILD_SOURCE_COMMIT), Ok(()));
        assert_eq!(
            validate_production_rc_for_network(profile, BUILD_SOURCE_COMMIT, NETWORK_IDENTITY),
            Ok(())
        );
        let mut mismatched = NETWORK_IDENTITY;
        mismatched.pow_limit[0] ^= 1;
        assert_eq!(
            validate_production_rc_for_network(profile, BUILD_SOURCE_COMMIT, mismatched),
            Err("production RC network identity pin does not match the compiled network profile")
        );
        assert_eq!(
            validate_production_rc(profile, ""),
            Err("trusted production RC build source commit is invalid")
        );
    }

    #[test]
    fn production_rc_gate_accepts_explicit_single_producer_rc_policy() {
        assert_eq!(
            validate_production_rc(single_producer_v4_profile(), BUILD_SOURCE_COMMIT),
            Ok(())
        );
    }

    #[test]
    fn production_rc_gate_keeps_dual_and_single_producer_policies_distinct() {
        let single_with_reproducer = CompiledReleaseProfile {
            production_v4_activation: Some(ProductionV4ActivationEvidence {
                approval_trust: ProductionV4ActivationApprovalTrust {
                    independent_reproducer: V4_APPROVAL_TRUST.independent_reproducer,
                    ..SINGLE_PRODUCER_V4_APPROVAL_TRUST
                },
                ..SINGLE_PRODUCER_V4_EVIDENCE
            }),
            ..single_producer_v4_profile()
        };
        assert_eq!(
            validate_production_rc(single_with_reproducer, BUILD_SOURCE_COMMIT),
            Err("ProductionV4 single-signer trust must not claim an independent reproducer")
        );

        let dual_without_reproducer = CompiledReleaseProfile {
            production_v4_activation: Some(ProductionV4ActivationEvidence {
                approval_trust: ProductionV4ActivationApprovalTrust {
                    independent_reproducer: None,
                    ..V4_APPROVAL_TRUST
                },
                ..V4_EVIDENCE
            }),
            ..v4_profile()
        };
        assert_eq!(
            validate_production_rc(dual_without_reproducer, BUILD_SOURCE_COMMIT),
            Err("ProductionV4 independent reproducer approval trust is absent")
        );

        let mismatched_schema = CompiledReleaseProfile {
            production_v4_activation: Some(ProductionV4ActivationEvidence {
                schema: SINGLE_PRODUCER_V4_EVIDENCE.schema,
                ..V4_EVIDENCE
            }),
            ..v4_profile()
        };
        assert_eq!(
            validate_production_rc(mismatched_schema, BUILD_SOURCE_COMMIT),
            Err("ProductionV4 activation evidence and approval policy do not match")
        );
    }

    #[test]
    fn v4_activation_evidence_encoding_is_canonical() {
        let encoded =
            canonical_production_v4_activation_evidence_json(v4_profile(), BUILD_SOURCE_COMMIT)
                .unwrap();
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            concat!(
                "{\"activation_approval_trust\":{\"contract_schema\":\"CMFD_PRODUCTION_V4_ACTIVATION_APPROVAL_SUBJECT_V1\",",
                "\"independent_reproducer\":{\"allowed_signers_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",",
                "\"key_blob_sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",",
                "\"key_fingerprint\":\"SHA256:3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0\",",
                "\"key_type\":\"ssh-ed25519\",\"signer_identity\":\"reproducer@example.invalid\"},",
                "\"producer\":{\"allowed_signers_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                "\"key_blob_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
                "\"key_fingerprint\":\"SHA256:u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s\",",
                "\"key_type\":\"ssh-ed25519\",\"signer_identity\":\"producer@example.invalid\"},",
                "\"qualification_binding_sha256\":\"9999999999999999999999999999999999999999999999999999999999999999\",",
                "\"ssh_keygen_sha256\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"},",
                "\"artifacts\":{\"bank\":{\"blake3\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
                "\"bytes\":\"1\",\"sha256\":\"4545454545454545454545454545454545454545454545454545454545454545\"},",
                "\"fixed_record\":{\"blake3\":\"4646464646464646464646464646464646464646464646464646464646464646\",",
                "\"bytes\":\"2\",\"sha256\":\"4747474747474747474747474747474747474747474747474747474747474747\"}},",
                "\"core_spec_sha256\":\"6666666666666666666666666666666666666666666666666666666666666666\",",
                "\"core_vector_sha256\":\"7777777777777777777777777777777777777777777777777777777777777777\",",
                "\"fresh_process_verifier_binary_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
                "\"fresh_process_verifier_report_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
                "\"network_profile\":\"RCNet-1\",",
                "\"proof_algebra_sha256\":\"8888888888888888888888888888888888888888888888888888888888888888\",",
                "\"proof_selection\":\"ProductionV4\",",
                "\"qualification_manifest_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
                "\"qualification_source_commit\":\"1111111111111111111111111111111111111111\",",
                "\"schema\":\"CMFD_PRODUCTION_V4_ACTIVATION_V1\",",
                "\"source_commit\":\"5555555555555555555555555555555555555555\"}\n"
            )
        );
    }

    #[test]
    fn single_producer_v4_activation_evidence_encoding_is_canonical() {
        let encoded = canonical_production_v4_activation_evidence_json(
            single_producer_v4_profile(),
            BUILD_SOURCE_COMMIT,
        )
        .unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(encoded.contains(
            "\"contract_schema\":\"CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_APPROVAL_SUBJECT_V1\""
        ));
        assert!(encoded.contains("\"independent_reproducer\":null"));
        assert!(
            encoded.contains("\"schema\":\"CMFD_PRODUCTION_V4_RC_SINGLE_PRODUCER_ACTIVATION_V1\"")
        );
    }

    #[test]
    fn legacy_v3_gate_accepts_a_complete_v3_profile() {
        let profile = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_v4_activation: None,
            production_v4_artifacts: None,
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_legacy_production_v3_rc(profile, BUILD_SOURCE_COMMIT),
            Ok(())
        );
        assert_eq!(
            validate_legacy_production_v3_rc(profile, ""),
            Err("trusted production RC build source commit is invalid")
        );
    }

    #[test]
    fn activation_evidence_encoding_is_canonical_and_uses_dynamic_build_commit() {
        let profile = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_v4_activation: None,
            production_v4_artifacts: None,
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        let encoded =
            canonical_production_v3_activation_evidence_json(profile, BUILD_SOURCE_COMMIT).unwrap();
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            concat!(
                "{\"artifacts\":{\"bank\":{\"blake3\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
                "\"bytes\":\"1\",\"sha256\":\"4545454545454545454545454545454545454545454545454545454545454545\"},",
                "\"manifest\":{\"blake3\":\"4646464646464646464646464646464646464646464646464646464646464646\",",
                "\"bytes\":\"2\",\"sha256\":\"4747474747474747474747474747474747474747474747474747474747474747\"},",
                "\"record_v2\":{\"blake3\":\"4848484848484848484848484848484848484848484848484848484848484848\",",
                "\"bytes\":\"3\",\"sha256\":\"4949494949494949494949494949494949494949494949494949494949494949\"}},",
                "\"fresh_process_verifier_binary_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
                "\"fresh_process_verifier_report_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
                "\"network_profile\":\"RCNet-1\",\"proof_selection\":\"ProductionV3\",",
                "\"qualification_manifest_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
                "\"qualification_source_commit\":\"1111111111111111111111111111111111111111\",",
                "\"runtime_verifier_workers\":{\"linux_x86_64_sha256\":\"9a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9\",",
                "\"windows_x86_64_sha256\":\"5a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70717273747576777879\"},",
                "\"schema\":\"CMFD_PRODUCTION_V3_ACTIVATION_V1\",",
                "\"source_commit\":\"5555555555555555555555555555555555555555\"}\n"
            )
        );
    }

    #[test]
    fn gate_rejects_placeholder_and_unsafe_network_identity_values() {
        let profile = |identity| CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV4,
            activation: None,
            production_v3_artifacts: None,
            production_v3_verifier_workers: None,
            production_v4_activation: Some(V4_EVIDENCE),
            production_v4_artifacts: Some(V4_ARTIFACTS),
            production_network_identity: identity,
        };
        assert_eq!(
            validate_production_rc(profile(None), BUILD_SOURCE_COMMIT),
            Err("production RC network identity pin is absent")
        );

        let mut identity = NETWORK_IDENTITY;
        identity.network_id = [0x72; 32];
        assert!(
            validate_production_rc(profile(Some(identity)), BUILD_SOURCE_COMMIT)
                .unwrap_err()
                .contains("placeholder")
        );

        let mut identity = NETWORK_IDENTITY;
        identity.virtual_genesis_hash = [0x52; 32];
        assert!(
            validate_production_rc(profile(Some(identity)), BUILD_SOURCE_COMMIT)
                .unwrap_err()
                .contains("placeholder")
        );

        let mut identity = NETWORK_IDENTITY;
        identity.steward_reward_destination = INSECURE_DEV_STEWARD_DESTINATION;
        assert!(
            validate_production_rc(profile(Some(identity)), BUILD_SOURCE_COMMIT)
                .unwrap_err()
                .contains("insecure development key")
        );
    }
}
