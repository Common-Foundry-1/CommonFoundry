//! Opaque mainnet startup authority, shared by node and thin-miner parameters.
//! A public NetworkProfile alone never grants mainnet startup authority.

use crate::{NetworkProfile, NetworkProfileKind, NodeError, ProofProfile};
#[cfg(feature = "production-v4")]
use cmfd_consensus::{NetworkParams, PowParameters};
#[cfg(feature = "production-v4")]
use std::{fs::File, io::Read, path::Path, sync::OnceLock};

#[cfg(feature = "production-v4")]
static COMPILED_MAINNET_RUNTIME: OnceLock<AuthenticatedMainnetRuntime> = OnceLock::new();

/// Created only after checking the pinned plan and the exact launch signature.
/// Private fields and the absence of Deserialize prevent a transport response
/// from masquerading as local verification.
#[derive(Debug, Clone)]
pub struct AuthenticatedMainnetRuntime {
    profile: NetworkProfile,
    launch_plan_digest: [u8; 32],
}

impl AuthenticatedMainnetRuntime {
    #[cfg(feature = "production-v4")]
    pub fn authenticate(
        plan_bytes: &[u8],
        beacon_bytes: &[u8],
        compiled_plan_digest: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<Self, NodeError> {
        let plan = crate::rcnet_candidate::MainnetLaunchPlan::parse_pinned(
            plan_bytes,
            compiled_plan_digest,
        )
        .map_err(|_| NodeError::MainnetLaunchEvidence("plan does not match the release pin"))?;
        let beacon = cmfd_launch::parse_certificate(beacon_bytes)
            .map_err(|_| NodeError::MainnetLaunchEvidence("invalid beacon encoding"))?;
        if now_unix_seconds < cmfd_launch::MAINNET_LAUNCH_UNIX_SECONDS {
            return Err(NodeError::MainnetLaunchRequired);
        }
        let verified = plan
            .authenticate_genesis(&beacon, now_unix_seconds)
            .map_err(|_| NodeError::MainnetLaunchEvidence("signature or round does not match"))?;
        let profile = plan.profile_after_launch(&verified).map_err(|_| {
            NodeError::MainnetLaunchEvidence("genesis does not belong to this plan")
        })?;
        Ok(Self {
            profile,
            launch_plan_digest: compiled_plan_digest,
        })
    }

    pub fn profile(&self) -> NetworkProfile {
        self.profile
    }

    pub fn launch_plan_digest(&self) -> [u8; 32] {
        self.launch_plan_digest
    }

    /// Thin miners and full nodes derive the same fingerprint, first parent,
    /// and expected initial target from this authenticated object.
    #[cfg(feature = "production-v4")]
    pub fn network_parameters(&self) -> Result<NetworkParams, NodeError> {
        crate::network_params_from_pow_with_launch(
            self.profile,
            PowParameters::V4Candidate(
                cmfd_consensus::ForgeMatrixV4CandidateParameters::for_network(
                    self.profile.network_id,
                )?,
            ),
            Some(self),
        )
    }
}

/// Load the release-pinned plan and exact launch beacon beside the executable.
/// No command-line hash, network, key, round, or clock override is accepted.
#[cfg(feature = "production-v4")]
pub fn compiled_mainnet_runtime() -> Result<&'static AuthenticatedMainnetRuntime, NodeError> {
    if crate::COMPILED_NETWORK_PROFILE.kind != NetworkProfileKind::Mainnet {
        return Err(NodeError::MainnetLaunchEvidence(
            "compiled profile is not mainnet",
        ));
    }
    if let Some(runtime) = COMPILED_MAINNET_RUNTIME.get() {
        return Ok(runtime);
    }
    let pin = compiled_release_pin()?;
    let now = crate::unix_time_seconds()?;
    if now < cmfd_launch::MAINNET_LAUNCH_UNIX_SECONDS {
        return Err(NodeError::MainnetLaunchRequired);
    }
    let executable = std::env::current_exe()
        .map_err(|_| NodeError::MainnetLaunchEvidence("cannot resolve package directory"))?;
    let directory = executable
        .parent()
        .ok_or(NodeError::MainnetLaunchEvidence(
            "package directory is absent",
        ))?
        .join("production-mainnet");
    let plan = read_bounded_file(&directory.join("MAINNET-PLAN.json"), 32 * 1024)?;
    let beacon = read_bounded_file(
        &directory.join("LAUNCH-BEACON.json"),
        cmfd_launch::MAX_BEACON_DOCUMENT_BYTES,
    )?;
    let runtime =
        AuthenticatedMainnetRuntime::authenticate(&plan, &beacon, pin.launch_plan_digest, now)?;
    let mut expected_profile = crate::COMPILED_NETWORK_PROFILE;
    expected_profile.virtual_genesis_hash = runtime.profile.virtual_genesis_hash;
    if runtime.profile != expected_profile {
        return Err(NodeError::MainnetLaunchEvidence(
            "launch plan disagrees with compiled runtime parameters",
        ));
    }
    require_authenticated_profile(runtime.profile, Some(&runtime))?;
    // Concurrent starts authenticate the same immutable release and unique BLS
    // signature. An error is never cached, so a missing beacon can be retried.
    let _ = COMPILED_MAINNET_RUNTIME.set(runtime);
    COMPILED_MAINNET_RUNTIME
        .get()
        .ok_or(NodeError::MainnetLaunchRequired)
}

#[cfg(feature = "production-v4")]
fn compiled_release_pin() -> Result<crate::release_gate::MainnetReleaseConfiguration, NodeError> {
    let pin = crate::release_gate::MAINNET_RELEASE_CONFIGURATION.ok_or(
        NodeError::MainnetLaunchEvidence("compiled mainnet release pin is absent"),
    )?;
    crate::release_gate::validate_mainnet_release(
        crate::release_gate::COMPILED_RELEASE_PROFILE,
        Some(pin),
        cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID,
        option_env!("CMFD_BUILD_SOURCE_COMMIT").unwrap_or_default(),
    )
    .map_err(NodeError::MainnetLaunchEvidence)?;
    Ok(pin)
}

/// Static package identity for the October 2 publication window. It never
/// requires the future beacon and never opens node storage or a wallet.
#[cfg(feature = "production-v4")]
pub fn canonical_mainnet_launch_info_json() -> Result<Vec<u8>, NodeError> {
    use sha2::{Digest, Sha256};
    let pin = compiled_release_pin()?;
    let executable = std::env::current_exe()
        .map_err(|_| NodeError::MainnetLaunchEvidence("cannot resolve package directory"))?;
    let directory = executable
        .parent()
        .ok_or(NodeError::MainnetLaunchEvidence(
            "package directory is absent",
        ))?
        .join("production-mainnet");
    let bytes = read_bounded_file(&directory.join("MAINNET-PLAN.json"), 32 * 1024)?;
    let plan =
        crate::rcnet_candidate::MainnetLaunchPlan::parse_pinned(&bytes, pin.launch_plan_digest)
            .map_err(|_| NodeError::MainnetLaunchEvidence("plan does not match the release pin"))?;
    plan.validate_profile_template(crate::COMPILED_NETWORK_PROFILE)
        .map_err(|_| {
            NodeError::MainnetLaunchEvidence(
                "launch plan disagrees with compiled runtime parameters",
            )
        })?;
    let commit = option_env!("CMFD_BUILD_SOURCE_COMMIT").unwrap_or_default();
    let approval = crate::release_gate::canonical_mainnet_activation_evidence_json(
        crate::release_gate::COMPILED_RELEASE_PROFILE,
        pin,
        cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID,
        commit,
    )
    .map_err(NodeError::MainnetLaunchEvidence)?;
    let approval_document: serde_json::Value = serde_json::from_slice(&approval)?;
    let document = serde_json::json!({
        "format": "commonfoundry-mainnet-launch-info", "format_version": 1,
        "source_commit": commit,
        "source_release_utc": cmfd_launch::SOURCE_RELEASE_UTC,
        "mining_start_utc": cmfd_launch::MAINNET_LAUNCH_UTC,
        "launch_plan": plan,
        "activation_evidence_sha256": hex::encode(Sha256::digest(approval)),
        "mainnet_approval_manifest_sha256": pin.approval_manifest_sha256,
        "proof_approval_trust": approval_document["proof_activation"]["activation_approval_trust"],
        "genesis_policy": "requires_verified_launch_beacon",
        "beacon_round": cmfd_launch::MAINNET_BEACON_ROUND,
    });
    let mut encoded = serde_json::to_vec(&document)?;
    encoded.push(b'\n');
    Ok(encoded)
}

#[cfg(feature = "production-v4")]
fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, NodeError> {
    let file = File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            NodeError::MainnetLaunchRequired
        } else {
            NodeError::MainnetLaunchEvidence("cannot read launch sidecar")
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|_| NodeError::MainnetLaunchEvidence("cannot inspect launch sidecar"))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(NodeError::MainnetLaunchEvidence(
            "launch sidecar is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| NodeError::MainnetLaunchEvidence("cannot read launch sidecar"))?;
    if bytes.len() > limit {
        return Err(NodeError::MainnetLaunchEvidence(
            "launch sidecar exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

/// Resolve only the compiled template. An arbitrary Mainnet struct still has
/// no authority and is rejected by the shared parameter constructor.
pub(crate) fn resolve_compiled_profile(
    profile: NetworkProfile,
) -> Result<(NetworkProfile, Option<&'static AuthenticatedMainnetRuntime>), NodeError> {
    if profile.kind != NetworkProfileKind::Mainnet || profile != crate::COMPILED_NETWORK_PROFILE {
        return Ok((profile, None));
    }
    #[cfg(feature = "production-v4")]
    {
        let runtime = compiled_mainnet_runtime()?;
        Ok((runtime.profile, Some(runtime)))
    }
    #[cfg(not(feature = "production-v4"))]
    Err(NodeError::MainnetLaunchRequired)
}

pub fn ensure_compiled_launch_ready() -> Result<(), NodeError> {
    resolve_compiled_profile(crate::COMPILED_NETWORK_PROFILE).map(|_| ())
}

pub(crate) fn require_authenticated_profile(
    profile: NetworkProfile,
    launch: Option<&AuthenticatedMainnetRuntime>,
) -> Result<(), NodeError> {
    if profile.kind != NetworkProfileKind::Mainnet {
        return if launch.is_none() {
            Ok(())
        } else {
            Err(NodeError::MainnetLaunchEvidence(
                "mainnet authority cannot be used for another network",
            ))
        };
    }
    let launch = launch.ok_or(NodeError::MainnetLaunchRequired)?;
    if profile != launch.profile
        || profile.proof != ProofProfile::ProductionV4
        || launch.launch_plan_digest == [0; 32]
    {
        return Err(NodeError::MainnetLaunchEvidence(
            "network profile was changed after authentication",
        ));
    }
    // The final mainnet network ID must be explicitly enrolled in consensus
    // wire/fee policy. Do not accidentally run with legacy 1 MiB / zero-fee rules.
    if cmfd_consensus::max_block_bytes_for_network(profile.network_id)
        != cmfd_consensus::PRODUCTION_V4_MAX_BLOCK_BYTES
        || cmfd_consensus::max_proof_bytes_for_network(profile.network_id)
            != cmfd_consensus::PRODUCTION_V4_MAX_PROOF_BYTES
        || cmfd_consensus::economics::minimum_transaction_fee(profile.network_id)
            != cmfd_consensus::economics::MIN_TRANSACTION_FEE_ATOMS
    {
        return Err(NodeError::MainnetLaunchEvidence(
            "mainnet wire and fee policy is not pinned",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEVNET_PROFILE, Node, RCNET1_PROFILE};

    fn untrusted_profile() -> NetworkProfile {
        NetworkProfile {
            kind: NetworkProfileKind::Mainnet,
            name: "CommonFoundry Mainnet",
            ..RCNET1_PROFILE
        }
    }

    #[test]
    fn development_startup_does_not_require_launch_sidecars() {
        if crate::COMPILED_NETWORK_PROFILE.kind != NetworkProfileKind::Mainnet {
            assert!(ensure_compiled_launch_ready().is_ok());
            let (profile, launch) =
                resolve_compiled_profile(crate::COMPILED_NETWORK_PROFILE).unwrap();
            assert_eq!(profile, crate::COMPILED_NETWORK_PROFILE);
            assert!(launch.is_none());
        }
    }

    #[test]
    #[cfg(feature = "production-v4")]
    fn package_reader_is_bounded_and_missing_files_are_retryable() {
        use std::fs;
        let path = std::env::temp_dir().join(format!(
            "cmfd-launch-bounded-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(matches!(
            read_bounded_file(&path, 32),
            Err(NodeError::MainnetLaunchRequired)
        ));
        fs::write(&path, [0_u8; 33]).unwrap();
        assert!(read_bounded_file(&path, 32).is_err());
        fs::write(&path, b"exact").unwrap();
        assert_eq!(read_bounded_file(&path, 5).unwrap(), b"exact");
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[cfg(feature = "production-v4")]
    fn public_authentication_requires_exact_plan_and_future_round() {
        let plan = crate::rcnet_candidate::MainnetLaunchPlan::from_release_artifacts(
            RCNET1_PROFILE.pow_limit,
            cmfd_consensus::FixedRewardDestinations {
                steward: RCNET1_PROFILE.rewards.steward,
                community: RCNET1_PROFILE.rewards.community,
            },
        )
        .unwrap();
        let bytes = plan.canonical_json().unwrap();
        let beacon = br#"{"round":123,"signature":"b75c69d0b72a5d906e854e808ba7e2accb1542ac355ae486d591aa9d43765482e26cd02df835d3546d23c4b13e0dfc92"}"#;
        assert!(matches!(
            AuthenticatedMainnetRuntime::authenticate(
                &bytes,
                beacon,
                plan.digest().unwrap(),
                cmfd_launch::MAINNET_LAUNCH_UNIX_SECONDS - 1
            ),
            Err(NodeError::MainnetLaunchRequired)
        ));
        assert!(matches!(
            AuthenticatedMainnetRuntime::authenticate(
                &bytes,
                beacon,
                plan.digest().unwrap(),
                u64::MAX
            ),
            Err(NodeError::MainnetLaunchEvidence(
                "signature or round does not match"
            ))
        ));
        assert!(matches!(
            AuthenticatedMainnetRuntime::authenticate(&bytes, beacon, [0; 32], u64::MAX),
            Err(NodeError::MainnetLaunchEvidence(
                "plan does not match the release pin"
            ))
        ));
        assert!(matches!(
            AuthenticatedMainnetRuntime::authenticate(
                &bytes,
                &vec![b' '; 4097],
                plan.digest().unwrap(),
                u64::MAX
            ),
            Err(NodeError::MainnetLaunchEvidence("invalid beacon encoding"))
        ));
    }

    #[test]
    fn bare_mainnet_profile_fails_before_artifact_reads_and_storage() {
        let root =
            std::env::temp_dir().join(format!("cmfd-no-mainnet-authority-{}", std::process::id()));
        assert!(!root.exists());
        assert!(matches!(
            Node::open_with_profile(&root, untrusted_profile()),
            Err(NodeError::MainnetLaunchRequired)
        ));
        assert!(!root.exists());
        assert!(matches!(
            crate::network_params_for_profile(untrusted_profile()),
            Err(NodeError::MainnetLaunchRequired)
        ));
    }

    #[test]
    fn authentication_cannot_be_downgraded_or_rebound() {
        // Test-only constructor exercises boundary checks, not a valid beacon.
        let launch = AuthenticatedMainnetRuntime {
            profile: untrusted_profile(),
            launch_plan_digest: [1; 32],
        };
        assert!(require_authenticated_profile(DEVNET_PROFILE, Some(&launch)).is_err());
        for field in 0..5 {
            let mut profile = launch.profile;
            match field {
                0 => profile.virtual_genesis_hash[0] ^= 1,
                1 => profile.network_id[0] ^= 1,
                2 => profile.pow_limit[0] ^= 1,
                3 => profile.rewards.steward[0] ^= 1,
                4 => profile.virtual_genesis_timestamp += 1,
                _ => unreachable!(),
            }
            assert!(require_authenticated_profile(profile, Some(&launch)).is_err());
        }
    }

    #[test]
    #[cfg(feature = "production-v4")]
    fn mainnet_id_must_have_explicit_consensus_frame_and_fee_rules() {
        let launch = AuthenticatedMainnetRuntime {
            profile: NetworkProfile {
                network_id: [0x42; 32],
                ..untrusted_profile()
            },
            launch_plan_digest: [1; 32],
        };
        assert!(matches!(
            launch.network_parameters(),
            Err(NodeError::MainnetLaunchEvidence(
                "mainnet wire and fee policy is not pinned"
            ))
        ));
    }

    #[test]
    #[cfg(feature = "production-v4")]
    fn authenticated_genesis_is_used_by_node_and_thin_miner_parameter_path() {
        // RC's enrolled wire/fee identity is a bounded fixture. It is not a
        // mainnet plan and cannot be produced by the public authenticate API.
        let profile = NetworkProfile {
            virtual_genesis_hash: [0xa7; 32],
            ..untrusted_profile()
        };
        let launch = AuthenticatedMainnetRuntime {
            profile,
            launch_plan_digest: [1; 32],
        };
        let parameters = launch.network_parameters().unwrap();
        assert_eq!(parameters.genesis_hash, [0xa7; 32]);
        assert_eq!(parameters.network_id, profile.network_id);
        assert_eq!(
            parameters.genesis_timestamp,
            profile.virtual_genesis_timestamp
        );
        assert!(crate::network_params_from_pow(profile, parameters.pow).is_err());
        assert_ne!(
            parameters.fingerprint().unwrap(),
            crate::network_params_from_pow(RCNET1_PROFILE, parameters.pow)
                .unwrap()
                .fingerprint()
                .unwrap()
        );
    }
}
