//! Opaque mainnet startup authority, shared by node and thin-miner parameters.
//! A public NetworkProfile alone never grants mainnet startup authority.

use crate::{NetworkProfile, NetworkProfileKind, NodeError, ProofProfile};
#[cfg(feature = "production-v4")]
use cmfd_consensus::{NetworkParams, PowParameters};

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
