//! Build-time identity gate for artifacts presented as production release candidates.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledNetworkProfile {
    #[cfg_attr(feature = "production-v3-testnet", allow(dead_code))]
    Devnet,
    #[cfg_attr(not(feature = "production-v3-testnet"), allow(dead_code))]
    ProductionV3Testnet,
    Rcnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusProofSelection {
    #[cfg_attr(feature = "production-v3-testnet", allow(dead_code))]
    DevnetV2Reference,
    ProductionV3,
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
    pub bootstrap_ipv4: [u8; 4],
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
    pub production_network_identity: Option<ProductionRcNetworkIdentityPin>,
}

/// The private ProductionV3 test network remains fail-closed until the exact
/// ceremony artifacts and platform workers have been built and inserted here.
/// `None` is intentional: do not replace these with placeholders or with
/// hashes from an RCNet/mainnet package.
#[cfg(feature = "production-v3-testnet")]
const PRODUCTION_V3_TESTNET_ARTIFACT_PINS: Option<ProductionV3ArtifactIdentityPins> = None;
#[cfg(feature = "production-v3-testnet")]
const PRODUCTION_V3_TESTNET_WORKER_PINS: Option<ProductionV3VerifierWorkerIdentityPins> = None;

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
    production_network_identity: None,
};

/// The identity selected by an ordinary source-tree build.
///
/// A production RC build may change these values only together with the real
/// RCNet/V3 integration and committed qualification evidence. The release
/// checkout commit is deliberately not a source constant: trusted CI supplies
/// it to the build gate so the finalizer can compare it with the exact checkout
/// without a self-reference.
#[cfg(not(feature = "production-v3-testnet"))]
pub const COMPILED_RELEASE_PROFILE: CompiledReleaseProfile = CompiledReleaseProfile {
    network: CompiledNetworkProfile::Devnet,
    proof: ConsensusProofSelection::DevnetV2Reference,
    activation: None,
    production_v3_artifacts: None,
    production_v3_verifier_workers: None,
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

fn is_repeated_byte(value: [u8; 32]) -> bool {
    value.iter().all(|byte| *byte == value[0])
}

fn valid_binary_identity_pin(value: [u8; 32]) -> bool {
    value != [0; 32] && !is_repeated_byte(value)
}

fn is_rfc5737(address: [u8; 4]) -> bool {
    matches!(
        address,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
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
    if is_rfc5737(identity.bootstrap_ipv4) {
        return Err("production RC bootstrap address is an RFC 5737 documentation address");
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

pub fn validate_production_rc(
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
    validate_production_rc(profile, build_source_commit)?;
    let evidence = profile
        .activation
        .ok_or("ProductionV3 activation evidence is absent")?;
    Ok(format!(
        concat!(
            "{{\"fresh_process_verifier_binary_sha256\":\"{}\",",
            "\"fresh_process_verifier_report_sha256\":\"{}\",",
            "\"network_profile\":\"RCNet-1\",",
            "\"proof_selection\":\"ProductionV3\",",
            "\"qualification_manifest_sha256\":\"{}\",",
            "\"qualification_source_commit\":\"{}\",",
            "\"schema\":\"{}\",",
            "\"source_commit\":\"{}\"}}\n"
        ),
        evidence.fresh_process_verifier_binary_sha256,
        evidence.fresh_process_verifier_report_sha256,
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
        bootstrap_ipv4: [1, 1, 1, 1],
        pow_limit: [0xff; 32],
        steward_reward_destination: varied(129),
        community_reward_destination: varied(193),
    };

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
    fn current_source_tree_fails_the_production_rc_gate() {
        assert_eq!(
            validate_production_rc(COMPILED_RELEASE_PROFILE, BUILD_SOURCE_COMMIT),
            Err("compiled network profile is not RCNet")
        );
    }

    #[test]
    fn gate_requires_production_v3_activation_and_artifact_pins() {
        let no_v3 = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::DevnetV2Reference,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_production_rc(no_v3, BUILD_SOURCE_COMMIT),
            Err("compiled consensus proof selection is not ProductionV3")
        );

        let no_evidence = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: None,
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_production_rc(no_evidence, BUILD_SOURCE_COMMIT),
            Err("ProductionV3 activation evidence is absent")
        );

        let no_artifacts = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: None,
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_production_rc(no_artifacts, BUILD_SOURCE_COMMIT),
            Err("ProductionV3 artifact identity pins are absent")
        );

        let no_runtime_worker = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: None,
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        assert_eq!(
            validate_production_rc(no_runtime_worker, BUILD_SOURCE_COMMIT),
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
            validate_production_rc(zero_runtime_worker, BUILD_SOURCE_COMMIT),
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
            validate_production_rc(placeholder_runtime_worker, BUILD_SOURCE_COMMIT),
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
            validate_production_rc(identical_runtime_workers, BUILD_SOURCE_COMMIT),
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
    fn gate_accepts_only_a_complete_rcnet_v3_profile() {
        let profile = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_network_identity: Some(NETWORK_IDENTITY),
        };
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
    fn activation_evidence_encoding_is_canonical_and_uses_dynamic_build_commit() {
        let profile = CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
            production_network_identity: Some(NETWORK_IDENTITY),
        };
        let encoded =
            canonical_production_v3_activation_evidence_json(profile, BUILD_SOURCE_COMMIT).unwrap();
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            concat!(
                "{\"fresh_process_verifier_binary_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
                "\"fresh_process_verifier_report_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
                "\"network_profile\":\"RCNet-1\",\"proof_selection\":\"ProductionV3\",",
                "\"qualification_manifest_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
                "\"qualification_source_commit\":\"1111111111111111111111111111111111111111\",",
                "\"schema\":\"CMFD_PRODUCTION_V3_ACTIVATION_V1\",",
                "\"source_commit\":\"5555555555555555555555555555555555555555\"}\n"
            )
        );
    }

    #[test]
    fn gate_rejects_placeholder_and_unsafe_network_identity_values() {
        let profile = |identity| CompiledReleaseProfile {
            network: CompiledNetworkProfile::Rcnet,
            proof: ConsensusProofSelection::ProductionV3,
            activation: Some(EVIDENCE),
            production_v3_artifacts: Some(ARTIFACTS),
            production_v3_verifier_workers: Some(VERIFIER_WORKERS),
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
        identity.bootstrap_ipv4 = [203, 0, 113, 10];
        assert!(
            validate_production_rc(profile(Some(identity)), BUILD_SOURCE_COMMIT)
                .unwrap_err()
                .contains("RFC 5737")
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
