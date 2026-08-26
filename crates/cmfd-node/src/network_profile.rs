use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::release_gate::{
    COMPILED_RELEASE_PROFILE, CompiledNetworkProfile, ConsensusProofSelection,
};

/// Compile-time identity and default endpoints for one Common Foundry network.
///
/// Consensus identity fields are bound through [`crate::devnet_params`]. The
/// remaining fields keep operators and packaged applications on the matching
/// ports and data directories without implying that endpoint changes alter
/// consensus identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkProfile {
    pub kind: NetworkProfileKind,
    pub proof: ProofProfile,
    pub name: &'static str,
    pub network_id: [u8; 32],
    pub virtual_genesis_hash: [u8; 32],
    pub virtual_genesis_timestamp: u64,
    pub pow_limit: [u8; 32],
    pub rewards: RewardDestinations,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub pool_port: u16,
    pub bootstrap_ipv4: Ipv4Addr,
    pub default_data_dir_identity: &'static str,
    pub wallet_data_dir_identity: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProfileKind {
    Devnet,
    ProductionV3Testnet,
    Rcnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardDestinations {
    pub steward: [u8; 32],
    pub community: [u8; 32],
}

/// Consensus proof relation selected by a network profile.
///
/// The launch-candidate value deliberately has no fallback to the tiny Devnet
/// relation. Until a production V3 verifier is wired into `PowParameters` and
/// `ConsensusPowVerifier`, selecting that profile must fail before node storage
/// is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofProfile {
    DevnetV2Reference,
    ProductionV3,
}

impl NetworkProfile {
    pub const fn short_name(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "Devnet-0",
            NetworkProfileKind::ProductionV3Testnet => "ProductionV3 Testnet-1",
            NetworkProfileKind::Rcnet => "RCNet-1",
        }
    }

    pub const fn network_notice(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "Testing network · No monetary value",
            NetworkProfileKind::ProductionV3Testnet => {
                "Private ProductionV3 test network · Not RCNet or mainnet"
            }
            NetworkProfileKind::Rcnet => "Release-candidate rehearsal network · Not mainnet",
        }
    }

    pub const fn network_purpose(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "Community testing",
            NetworkProfileKind::ProductionV3Testnet => "ProductionV3 end-to-end testing",
            NetworkProfileKind::Rcnet => "Launch rehearsal",
        }
    }

    pub const fn is_devnet(self) -> bool {
        matches!(self.kind, NetworkProfileKind::Devnet)
    }

    pub const fn wallet_window_title(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "Common Foundry Wallet — Devnet-0",
            NetworkProfileKind::ProductionV3Testnet => {
                "Common Foundry Wallet — ProductionV3 Testnet-1"
            }
            NetworkProfileKind::Rcnet => "Common Foundry Wallet — RCNet-1",
        }
    }

    pub const fn wallet_warning(self, legacy_shared_wallet: bool) -> &'static str {
        match (self.kind, legacy_shared_wallet) {
            (NetworkProfileKind::Devnet, true) => {
                "Devnet-0 legacy wallet: this upgraded data directory retains its original demonstration key so existing test coins remain available."
            }
            (NetworkProfileKind::Devnet, false) => {
                "Devnet-0 test wallet: back up wallet.key if you want to test wallet recovery."
            }
            (NetworkProfileKind::ProductionV3Testnet, true) => {
                "ProductionV3 Testnet-1 wallet uses a known development key. Create a fresh testnet wallet before testing."
            }
            (NetworkProfileKind::ProductionV3Testnet, false) => {
                "ProductionV3 Testnet-1 wallet: back up wallet.key before testing recovery. This is not RCNet or mainnet."
            }
            (NetworkProfileKind::Rcnet, true) => {
                "RCNet-1 wallet uses a known development key. Create a fresh RCNet wallet before testing."
            }
            (NetworkProfileKind::Rcnet, false) => {
                "RCNet-1 release-candidate wallet: back up wallet.key before testing recovery. This is not mainnet."
            }
        }
    }

    pub const fn miner_data_dir_identity(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "commonfoundry-miner-devnet0",
            NetworkProfileKind::ProductionV3Testnet => "commonfoundry-miner-production-v3-testnet1",
            NetworkProfileKind::Rcnet => "commonfoundry-miner-rcnet1",
        }
    }

    /// The embedded full-node miner listens one thousand ports above the
    /// network P2P service so it can run beside a regular node. This preserves
    /// the existing Devnet `19444` default while keeping RCNet isolated.
    pub const fn miner_p2p_address(self) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            self.p2p_port.saturating_add(1_000),
        )
    }

    pub const fn proof_name(self) -> &'static str {
        match self.proof {
            ProofProfile::DevnetV2Reference => "ForgeMatrix-v2 tiny full-recompute reference",
            ProofProfile::ProductionV3 => "ForgeMatrix-v3 production Dory",
        }
    }

    pub const fn rpc_address(self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.rpc_port)
    }

    pub const fn p2p_address(self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.p2p_port)
    }

    pub const fn pool_address(self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.pool_port)
    }

    pub const fn bootstrap_peer(self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.bootstrap_ipv4), self.p2p_port)
    }
}

impl ProofProfile {
    pub const fn profile_name(self) -> &'static str {
        match self {
            Self::DevnetV2Reference => "DevnetV2",
            Self::ProductionV3 => "ProductionV3",
        }
    }

    pub const fn supports_bounded_reference_mining(self) -> bool {
        matches!(self, Self::DevnetV2Reference)
    }
}

pub const DEVNET_PROFILE: NetworkProfile = NetworkProfile {
    kind: NetworkProfileKind::Devnet,
    proof: ProofProfile::DevnetV2Reference,
    name: "CommonFoundry Devnet-0",
    network_id: [0x63; 32],
    virtual_genesis_hash: [0x47; 32],
    virtual_genesis_timestamp: 1_700_000_000,
    pow_limit: [
        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    rewards: RewardDestinations {
        steward: [
            0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61,
            0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04,
            0x07, 0x58, 0x71, 0xaa,
        ],
        community: [
            0x63, 0x60, 0xe8, 0x56, 0x31, 0x0c, 0xe5, 0xd2, 0x94, 0xe8, 0xbe, 0x33, 0xfc, 0x80,
            0x70, 0x77, 0xdc, 0x56, 0xac, 0x80, 0xd9, 0x5d, 0x9c, 0xd4, 0xdd, 0xbd, 0x21, 0x32,
            0x5e, 0xff, 0x73, 0xf7,
        ],
    },
    rpc_port: 18_443,
    p2p_port: 18_444,
    pool_port: 18_445,
    bootstrap_ipv4: Ipv4Addr::new(107, 214, 187, 2),
    default_data_dir_identity: "commonfoundry-devnet0",
    wallet_data_dir_identity: "devnet-0",
};

/// Private, low-difficulty network for end-to-end ProductionV3 testing.
///
/// This identity is intentionally unrelated to both Devnet-0 and the RCNet
/// launch candidate. Test work cannot be replayed onto either network. The
/// bootstrap host is shared operational infrastructure, but it listens on the
/// isolated testnet P2P port.
pub const PRODUCTION_V3_TESTNET_PROFILE: NetworkProfile = NetworkProfile {
    kind: NetworkProfileKind::ProductionV3Testnet,
    proof: ProofProfile::ProductionV3,
    name: "CommonFoundry ProductionV3 Testnet-1",
    // SHA-256("CMFD/PRODUCTION-V3-TESTNET/V1/NETWORK-ID").
    network_id: [
        0xb6, 0x59, 0x4e, 0xa7, 0x2b, 0xbd, 0x86, 0x06, 0x83, 0x07, 0xba, 0xc8, 0x78, 0xb0, 0x51,
        0x64, 0x1d, 0x6d, 0xbf, 0x9c, 0xfe, 0xd3, 0x49, 0x9a, 0xf2, 0xe2, 0xbc, 0x5e, 0xb0, 0x6c,
        0x9d, 0xf5,
    ],
    // SHA-256("CMFD/PRODUCTION-V3-TESTNET/V1/VIRTUAL-GENESIS/2026-08-26").
    virtual_genesis_hash: [
        0xf6, 0xdb, 0xfd, 0xd9, 0x35, 0x21, 0x81, 0x9d, 0xb8, 0xed, 0xdc, 0x7b, 0x5b, 0x74, 0x48,
        0xb9, 0x5a, 0x4e, 0x82, 0x2f, 0x05, 0xb3, 0xad, 0x1a, 0x7f, 0xb6, 0x74, 0xbc, 0x3a, 0xc9,
        0x19, 0x59,
    ],
    virtual_genesis_timestamp: 1_787_702_400, // 2026-08-26T00:00:00Z
    // Deliberately easy so a small private tester group can exercise complete
    // proof generation, external verification, and block admission quickly.
    pow_limit: [0xff; 32],
    rewards: RewardDestinations {
        // Deterministic test-only x-only public keys derived from the
        // CMFD/PRODUCTION-V3-TESTNET/V1/{STEWARD,COMMUNITY} labels. They are
        // distinct from every planned RCNet/launch reward destination.
        steward: [
            0xbd, 0x54, 0x0c, 0x63, 0x80, 0x0e, 0xab, 0x70, 0x62, 0x3d, 0x3b, 0x5f, 0x91, 0x4f,
            0x6b, 0x9d, 0x65, 0x03, 0xf0, 0xf7, 0x5c, 0x8a, 0x00, 0xe9, 0x4b, 0x7e, 0x54, 0x4d,
            0x79, 0x21, 0x46, 0x79,
        ],
        community: [
            0x0a, 0x70, 0x53, 0x05, 0x01, 0xf1, 0x10, 0x58, 0x4d, 0x96, 0x85, 0xdd, 0x6c, 0x56,
            0x99, 0x05, 0x28, 0xca, 0xeb, 0x95, 0xf7, 0x23, 0xc9, 0x65, 0xb4, 0xe6, 0xa8, 0x8a,
            0xd6, 0xa4, 0xc7, 0xc0,
        ],
    },
    rpc_port: 21_443,
    p2p_port: 21_444,
    pool_port: 21_445,
    bootstrap_ipv4: Ipv4Addr::new(107, 214, 187, 2),
    default_data_dir_identity: "commonfoundry-production-v3-testnet1",
    wallet_data_dir_identity: "production-v3-testnet-1",
};

/// Isolated rehearsal identity for the first launch-candidate network.
///
/// RCNet-1 is not mainnet and cannot currently start. Its identity, service
/// ports, and storage paths are intentionally disjoint from Devnet-0 so a
/// future production-V3 integration cannot accidentally reuse Devnet state.
/// The production proof selector is the hard gate: code must never substitute
/// the tiny V2 reference relation for this profile.
pub const RCNET1_PROFILE: NetworkProfile = NetworkProfile {
    kind: NetworkProfileKind::Rcnet,
    proof: ProofProfile::ProductionV3,
    name: "CommonFoundry RCNet-1",
    network_id: [0x72; 32],
    virtual_genesis_hash: [0x52; 32],
    virtual_genesis_timestamp: 1_787_616_000,
    // These remain explicit blockers, not proposed launch values. The final
    // candidate must pin a reviewed limit and non-development destinations.
    pow_limit: DEVNET_PROFILE.pow_limit,
    rewards: DEVNET_PROFILE.rewards,
    rpc_port: 19_443,
    p2p_port: 19_444,
    pool_port: 19_445,
    // RFC 5737 TEST-NET-1. A real bootstrap must be selected and published as
    // part of the launch-candidate manifest before RCNet-1 is enabled.
    bootstrap_ipv4: Ipv4Addr::new(192, 0, 2, 1),
    default_data_dir_identity: "commonfoundry-rcnet1",
    wallet_data_dir_identity: "rcnet-1",
};

/// Network identity selected into every node-dependent artifact.
pub const COMPILED_NETWORK_PROFILE: NetworkProfile = match (
    COMPILED_RELEASE_PROFILE.network,
    COMPILED_RELEASE_PROFILE.proof,
) {
    (CompiledNetworkProfile::Devnet, ConsensusProofSelection::DevnetV2Reference) => DEVNET_PROFILE,
    (CompiledNetworkProfile::ProductionV3Testnet, ConsensusProofSelection::ProductionV3) => {
        PRODUCTION_V3_TESTNET_PROFILE
    }
    (CompiledNetworkProfile::Rcnet, ConsensusProofSelection::ProductionV3) => RCNET1_PROFILE,
    _ => panic!("compiled network and consensus proof selections are inconsistent"),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rcnet_is_identity_and_storage_isolated_from_devnet() {
        assert_ne!(RCNET1_PROFILE.network_id, DEVNET_PROFILE.network_id);
        assert_ne!(
            RCNET1_PROFILE.virtual_genesis_hash,
            DEVNET_PROFILE.virtual_genesis_hash
        );
        assert_ne!(RCNET1_PROFILE.rpc_port, DEVNET_PROFILE.rpc_port);
        assert_ne!(RCNET1_PROFILE.p2p_port, DEVNET_PROFILE.p2p_port);
        assert_ne!(RCNET1_PROFILE.pool_port, DEVNET_PROFILE.pool_port);
        assert_ne!(
            RCNET1_PROFILE.default_data_dir_identity,
            DEVNET_PROFILE.default_data_dir_identity
        );
        assert_ne!(
            RCNET1_PROFILE.wallet_data_dir_identity,
            DEVNET_PROFILE.wallet_data_dir_identity
        );
        assert_eq!(RCNET1_PROFILE.proof, ProofProfile::ProductionV3);
        assert_eq!(DEVNET_PROFILE.proof, ProofProfile::DevnetV2Reference);
        assert_eq!(DEVNET_PROFILE.short_name(), "Devnet-0");
        assert_eq!(DEVNET_PROFILE.proof.profile_name(), "DevnetV2");
        assert_eq!(RCNET1_PROFILE.short_name(), "RCNet-1");
        assert_eq!(RCNET1_PROFILE.proof.profile_name(), "ProductionV3");
        assert_eq!(RCNET1_PROFILE.rpc_address().to_string(), "127.0.0.1:19443");
        assert_eq!(RCNET1_PROFILE.p2p_address().to_string(), "127.0.0.1:19444");
        assert_eq!(RCNET1_PROFILE.pool_address().to_string(), "127.0.0.1:19445");
        assert_eq!(
            DEVNET_PROFILE.miner_p2p_address().to_string(),
            "127.0.0.1:19444"
        );
        assert_eq!(
            RCNET1_PROFILE.miner_p2p_address().to_string(),
            "127.0.0.1:20444"
        );
        assert_ne!(
            RCNET1_PROFILE.wallet_data_dir_identity,
            DEVNET_PROFILE.wallet_data_dir_identity
        );
        assert_ne!(
            RCNET1_PROFILE.wallet_window_title(),
            DEVNET_PROFILE.wallet_window_title()
        );
        assert!(!RCNET1_PROFILE.proof.supports_bounded_reference_mining());
        assert!(DEVNET_PROFILE.proof.supports_bounded_reference_mining());
    }

    #[test]
    fn production_v3_testnet_is_isolated_and_uses_v3() {
        let testnet = PRODUCTION_V3_TESTNET_PROFILE;
        for other in [DEVNET_PROFILE, RCNET1_PROFILE] {
            assert_ne!(testnet.network_id, other.network_id);
            assert_ne!(testnet.virtual_genesis_hash, other.virtual_genesis_hash);
            assert_ne!(
                testnet.virtual_genesis_timestamp,
                other.virtual_genesis_timestamp
            );
            assert_ne!(testnet.rpc_port, other.rpc_port);
            assert_ne!(testnet.p2p_port, other.p2p_port);
            assert_ne!(testnet.pool_port, other.pool_port);
            assert_ne!(
                testnet.default_data_dir_identity,
                other.default_data_dir_identity
            );
            assert_ne!(
                testnet.wallet_data_dir_identity,
                other.wallet_data_dir_identity
            );
            assert_ne!(testnet.rewards, other.rewards);
        }
        assert_eq!(testnet.proof, ProofProfile::ProductionV3);
        assert_eq!(testnet.short_name(), "ProductionV3 Testnet-1");
        assert!(testnet.network_notice().contains("Not RCNet or mainnet"));
        assert_eq!(testnet.rpc_port, 21_443);
        assert_eq!(testnet.p2p_port, 21_444);
        assert_eq!(testnet.pool_port, 21_445);
        assert_eq!(testnet.bootstrap_peer().to_string(), "107.214.187.2:21444");
        assert_eq!(testnet.miner_p2p_address().to_string(), "127.0.0.1:22444");
        assert_ne!(
            testnet.miner_p2p_address(),
            DEVNET_PROFILE.miner_p2p_address()
        );
        assert_ne!(
            testnet.miner_p2p_address(),
            RCNET1_PROFILE.miner_p2p_address()
        );
        assert_eq!(testnet.pow_limit, [0xff; 32]);
        assert!(k256::schnorr::VerifyingKey::from_bytes(&testnet.rewards.steward).is_ok());
        assert!(k256::schnorr::VerifyingKey::from_bytes(&testnet.rewards.community).is_ok());
    }

    #[test]
    fn compiled_profile_matches_the_release_gate_selection() {
        #[cfg(not(feature = "production-v3-testnet"))]
        {
            assert_eq!(COMPILED_NETWORK_PROFILE, DEVNET_PROFILE);
            assert_eq!(
                COMPILED_NETWORK_PROFILE.proof,
                ProofProfile::DevnetV2Reference
            );
        }
        #[cfg(feature = "production-v3-testnet")]
        {
            assert_eq!(COMPILED_NETWORK_PROFILE, PRODUCTION_V3_TESTNET_PROFILE);
            assert_eq!(COMPILED_NETWORK_PROFILE.proof, ProofProfile::ProductionV3);
        }
    }
}
