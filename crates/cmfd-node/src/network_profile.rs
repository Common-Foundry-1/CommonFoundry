use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::release_gate::{
    COMPILED_RELEASE_PROFILE, CompiledNetworkProfile, ConsensusProofSelection,
};

/// Mutable RCNet-1 cold-start infrastructure. These values are deliberately
/// excluded from the immutable network identity and may be rotated without a
/// consensus reset.
pub const PRODUCTION_RC_SEED_IPV4: Ipv4Addr = Ipv4Addr::new(173, 249, 35, 251);
pub const PRODUCTION_RC_SEED_PORT: u16 = 19_444;
/// Additional mainnet cold-start relays, dialled alongside the bootstrap seed
/// so a fresh node spreads its initial sync instead of loading the seed alone.
/// Operational infrastructure like the seed above: not part of any identity.
pub const MAINNET_BOOTSTRAP_RELAYS_IPV4: [Ipv4Addr; 1] = [Ipv4Addr::new(209, 145, 48, 36)];

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
    pub initial_target: Option<[u8; 32]>,
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
    ProductionV4Testnet,
    Rcnet,
    Mainnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardDestinations {
    pub steward: [u8; 32],
    pub community: [u8; 32],
}

/// Consensus proof relation selected by a network profile.
///
/// Production selections deliberately have no fallback to the tiny Devnet
/// relation. A profile without its matching verifier authority must fail
/// before node storage is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofProfile {
    DevnetV2Reference,
    ProductionV3,
    ProductionV4,
}

impl NetworkProfile {
    pub const fn short_name(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "Devnet-0",
            NetworkProfileKind::ProductionV3Testnet => "ProductionV3 Testnet-1",
            NetworkProfileKind::ProductionV4Testnet => "ProductionV4 Testnet-1",
            NetworkProfileKind::Rcnet => "RCNet-1",
            NetworkProfileKind::Mainnet => "Mainnet",
        }
    }

    pub const fn network_notice(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "Testing network · No monetary value",
            NetworkProfileKind::ProductionV3Testnet => {
                "Private ProductionV3 test network · Not RCNet or mainnet"
            }
            NetworkProfileKind::ProductionV4Testnet => {
                "Private ProductionV4 latency test network · Not RCNet or mainnet"
            }
            NetworkProfileKind::Rcnet => "Release-candidate rehearsal network · Not mainnet",
            NetworkProfileKind::Mainnet => "Common Foundry mainnet",
        }
    }

    pub const fn network_purpose(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "Community testing",
            NetworkProfileKind::ProductionV3Testnet => "ProductionV3 end-to-end testing",
            NetworkProfileKind::ProductionV4Testnet => "ProductionV4 latency and admission testing",
            NetworkProfileKind::Rcnet => "Launch rehearsal",
            NetworkProfileKind::Mainnet => "Mainnet",
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
            NetworkProfileKind::ProductionV4Testnet => {
                "Common Foundry Wallet — ProductionV4 Testnet-1"
            }
            NetworkProfileKind::Rcnet => "Common Foundry Wallet — RCNet-1",
            NetworkProfileKind::Mainnet => "Common Foundry Wallet — Mainnet",
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
            (NetworkProfileKind::ProductionV4Testnet, true) => {
                "ProductionV4 Testnet-1 wallet uses a known development key. Create a fresh testnet wallet before testing."
            }
            (NetworkProfileKind::ProductionV4Testnet, false) => {
                "ProductionV4 Testnet-1 wallet: back up wallet.key before testing recovery. This is not RCNet or mainnet."
            }
            (NetworkProfileKind::Rcnet, true) => {
                "RCNet-1 wallet uses a known development key. Create a fresh RCNet wallet before testing."
            }
            (NetworkProfileKind::Rcnet, false) => {
                "RCNet-1 release-candidate wallet: back up wallet.key before testing recovery. This is not mainnet."
            }
            (NetworkProfileKind::Mainnet, true) => {
                "Mainnet cannot use a legacy shared development wallet key."
            }
            (NetworkProfileKind::Mainnet, false) => {
                "Common Foundry mainnet wallet. Keep an encrypted backup in a separate location."
            }
        }
    }

    pub const fn miner_data_dir_identity(self) -> &'static str {
        match self.kind {
            NetworkProfileKind::Devnet => "commonfoundry-miner-devnet0",
            NetworkProfileKind::ProductionV3Testnet => "commonfoundry-miner-production-v3-testnet1",
            NetworkProfileKind::ProductionV4Testnet => "commonfoundry-miner-production-v4-testnet1",
            NetworkProfileKind::Rcnet => "commonfoundry-miner-rcnet1",
            NetworkProfileKind::Mainnet => "commonfoundry-miner-mainnet",
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
            ProofProfile::ProductionV4 => "ForgeMatrix-v4 transparent BaseFold",
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

    /// Every compiled cold-start endpoint: the bootstrap seed first, then the
    /// mainnet relays on the same P2P port. Other networks have only the seed.
    pub fn bootstrap_peers(self) -> Vec<SocketAddr> {
        let mut peers = vec![self.bootstrap_peer()];
        if matches!(self.kind, NetworkProfileKind::Mainnet) {
            peers.extend(
                MAINNET_BOOTSTRAP_RELAYS_IPV4
                    .iter()
                    .map(|relay| SocketAddr::new(IpAddr::V4(*relay), self.p2p_port)),
            );
        }
        peers
    }
}

impl ProofProfile {
    pub const fn profile_name(self) -> &'static str {
        match self {
            Self::DevnetV2Reference => "DevnetV2",
            Self::ProductionV3 => "ProductionV3",
            Self::ProductionV4 => "ProductionV4",
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
    initial_target: None,
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
    initial_target: None,
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

/// Isolated, low-difficulty network for the ProductionV4 latency proof.
///
/// The network id exactly matches the V4-only wire allowance in consensus.
/// Its ports and storage are disjoint from Devnet-0, ProductionV3 Testnet-1,
/// and RCNet-1, so its larger proof and block bounds cannot leak elsewhere.
pub const PRODUCTION_V4_TESTNET_PROFILE: NetworkProfile = NetworkProfile {
    kind: NetworkProfileKind::ProductionV4Testnet,
    proof: ProofProfile::ProductionV4,
    name: "CommonFoundry ProductionV4 Testnet-1",
    // SHA-256("CMFD/PRODUCTION-V4-TESTNET/V1/NETWORK-ID").
    network_id: [
        0xb9, 0xe5, 0x5d, 0x5a, 0x5e, 0x80, 0xc8, 0xe3, 0xd7, 0x3b, 0xf8, 0x1b, 0x19, 0x9b, 0xc6,
        0x43, 0xac, 0x93, 0x67, 0x43, 0x69, 0x62, 0xc2, 0x8b, 0x6a, 0xac, 0xdc, 0x37, 0xf3, 0x80,
        0x99, 0x62,
    ],
    // SHA-256("CMFD/PRODUCTION-V4-TESTNET/V1/VIRTUAL-GENESIS/2026-08-27").
    virtual_genesis_hash: [
        0x2b, 0xda, 0x6e, 0x00, 0xa7, 0xd1, 0x86, 0xe5, 0x8b, 0x39, 0x20, 0xa1, 0x2d, 0x55, 0x21,
        0xd9, 0x78, 0xe6, 0x37, 0x64, 0x1f, 0xff, 0x97, 0xc8, 0xef, 0x0e, 0x10, 0xf9, 0x45, 0x00,
        0xbb, 0xa6,
    ],
    virtual_genesis_timestamp: 1_787_788_800, // 2026-08-27T00:00:00Z
    initial_target: None,
    pow_limit: [0xff; 32],
    rewards: RewardDestinations {
        // Deterministic test-only x-only public keys derived from the V4
        // testnet STEWARD and COMMUNITY labels.
        steward: [
            0xb3, 0x62, 0xd0, 0x9f, 0xd1, 0x1d, 0x50, 0x15, 0x8c, 0x4c, 0xe1, 0xed, 0xad, 0x99,
            0xbd, 0xe8, 0x55, 0x14, 0xd2, 0x51, 0xc5, 0x45, 0xe0, 0x7a, 0xc1, 0x37, 0x02, 0xaa,
            0x4d, 0x5f, 0x2d, 0xde,
        ],
        community: [
            0x9a, 0xf8, 0x35, 0x9c, 0x02, 0x4c, 0xd0, 0xaf, 0xb4, 0xf3, 0x54, 0xe4, 0x49, 0x31,
            0x77, 0x3b, 0x8a, 0xfa, 0xc2, 0xe6, 0xaf, 0x3d, 0xfe, 0xc8, 0x0a, 0xff, 0xcc, 0x80,
            0xb0, 0x85, 0x7c, 0x52,
        ],
    },
    rpc_port: 22_443,
    p2p_port: 22_444,
    pool_port: 22_445,
    bootstrap_ipv4: Ipv4Addr::new(107, 214, 187, 2),
    default_data_dir_identity: "commonfoundry-production-v4-testnet1",
    wallet_data_dir_identity: "production-v4-testnet-1",
};

/// Isolated rehearsal identity for the first launch-candidate network.
///
/// RCNet-1 is not mainnet. Its immutable identity was derived from the
/// canonical `CMFD_RCNET_LAUNCH_CANDIDATE_V2`; service endpoints remain
/// replaceable operational configuration. Ports and storage paths are
/// intentionally disjoint from Devnet-0, and the ProductionV4 selector must
/// never fall back to the tiny V2 reference relation.
pub const RCNET1_PROFILE: NetworkProfile = NetworkProfile {
    kind: NetworkProfileKind::Rcnet,
    proof: ProofProfile::ProductionV4,
    name: "CommonFoundry RCNet-1",
    network_id: [
        0x3e, 0x99, 0xd4, 0x59, 0x59, 0xc1, 0x9c, 0x00, 0x53, 0xd8, 0xe9, 0xfe, 0xf3, 0x48, 0x75,
        0xb5, 0x7b, 0x46, 0xa8, 0xa1, 0xce, 0x33, 0x06, 0x37, 0xda, 0xdd, 0xab, 0x51, 0x5b, 0xc7,
        0xb9, 0x2d,
    ],
    virtual_genesis_hash: [
        0xa5, 0x72, 0xb6, 0xce, 0x50, 0x97, 0x85, 0x11, 0xce, 0x87, 0x71, 0xdb, 0x66, 0x03, 0xa6,
        0x02, 0xfa, 0xcc, 0xf3, 0x80, 0x2c, 0xf0, 0xd4, 0x79, 0x1c, 0x1c, 0xe4, 0xe4, 0x67, 0xba,
        0x6b, 0x71,
    ],
    virtual_genesis_timestamp: 1_788_800_400, // 2026-09-07T17:00:00Z
    initial_target: None,
    pow_limit: [
        0x00, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    rewards: RewardDestinations {
        steward: [
            0x69, 0x89, 0xa6, 0x15, 0x23, 0x1a, 0x86, 0x55, 0x8b, 0x8e, 0xbf, 0x1f, 0x0b, 0x00,
            0x11, 0xcf, 0x4f, 0xb1, 0xe0, 0x20, 0x9f, 0x68, 0xa7, 0xb1, 0x27, 0x4f, 0x38, 0x77,
            0xe3, 0xb1, 0x6a, 0x6b,
        ],
        community: [
            0x2d, 0x70, 0x66, 0xdf, 0x96, 0x29, 0x7c, 0x41, 0xf8, 0xe4, 0xbb, 0x3b, 0xe2, 0x18,
            0xce, 0xfb, 0x82, 0x2f, 0xf1, 0xe7, 0xdc, 0x6c, 0xc6, 0x48, 0xf4, 0x7f, 0x92, 0xa9,
            0xc0, 0xc8, 0x8e, 0xf8,
        ],
    },
    rpc_port: 19_443,
    p2p_port: PRODUCTION_RC_SEED_PORT,
    pool_port: 19_445,
    // Operational seed only; it is excluded from the immutable identity and
    // can be rotated without resetting RCNet-1 consensus.
    bootstrap_ipv4: PRODUCTION_RC_SEED_IPV4,
    default_data_dir_identity: "commonfoundry-rcnet1",
    wallet_data_dir_identity: "rcnet-1",
};

/// Network identity selected into every node-dependent artifact.
/// Mainnet's zero genesis is an unactivated marker, never a valid chain parent.
/// It is replaced only through AuthenticatedMainnetRuntime after beacon verification.
pub(crate) const fn mainnet_profile_template(
    configuration: Option<crate::release_gate::MainnetReleaseConfiguration>,
) -> Option<NetworkProfile> {
    match configuration {
        Some(pin) => Some(NetworkProfile {
            kind: NetworkProfileKind::Mainnet,
            proof: ProofProfile::ProductionV4,
            name: "CommonFoundry Mainnet",
            network_id: pin.network_id,
            virtual_genesis_hash: [0; 32],
            virtual_genesis_timestamp:
                crate::release_gate::mainnet_schedule::MAINNET_LAUNCH_UNIX_SECONDS,
            pow_limit: pin.pow_limit,
            initial_target: Some(pin.initial_target),
            rewards: RewardDestinations {
                steward: pin.steward_reward_destination,
                community: pin.community_reward_destination,
            },
            rpc_port: 29_443,
            p2p_port: 29_444,
            pool_port: 29_445,
            bootstrap_ipv4: PRODUCTION_RC_SEED_IPV4,
            default_data_dir_identity: "commonfoundry-mainnet",
            wallet_data_dir_identity: "mainnet",
        }),
        None => None,
    }
}

pub const COMPILED_NETWORK_PROFILE: NetworkProfile = match (
    COMPILED_RELEASE_PROFILE.network,
    COMPILED_RELEASE_PROFILE.proof,
) {
    (CompiledNetworkProfile::Devnet, ConsensusProofSelection::DevnetV2Reference) => DEVNET_PROFILE,
    (CompiledNetworkProfile::ProductionV3Testnet, ConsensusProofSelection::ProductionV3) => {
        PRODUCTION_V3_TESTNET_PROFILE
    }
    (CompiledNetworkProfile::ProductionV4Testnet, ConsensusProofSelection::ProductionV4) => {
        PRODUCTION_V4_TESTNET_PROFILE
    }
    (CompiledNetworkProfile::Rcnet, ConsensusProofSelection::ProductionV4) => RCNET1_PROFILE,
    (CompiledNetworkProfile::Mainnet, ConsensusProofSelection::ProductionV4) => {
        match mainnet_profile_template(crate::release_gate::MAINNET_RELEASE_CONFIGURATION) {
            Some(profile) => profile,
            None => panic!("final mainnet launch plan and approval pins are absent"),
        }
    }
    _ => panic!("compiled network and consensus proof selections are inconsistent"),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_dials_the_seed_and_the_relays_other_networks_only_the_seed() {
        assert_eq!(
            RCNET1_PROFILE.bootstrap_peers(),
            vec![crate::seed_peers::PRODUCTION_RC_SEED]
        );
        assert_eq!(
            DEVNET_PROFILE.bootstrap_peers(),
            vec![DEVNET_PROFILE.bootstrap_peer()]
        );
        let mainnet = NetworkProfile {
            kind: NetworkProfileKind::Mainnet,
            p2p_port: 29_444,
            ..RCNET1_PROFILE
        };
        assert_eq!(
            mainnet
                .bootstrap_peers()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["173.249.35.251:29444", "209.145.48.36:29444"]
        );
        assert_eq!(mainnet.bootstrap_peers()[0], mainnet.bootstrap_peer());
        // Relay endpoints are operational only; the identity fields are untouched.
        assert_eq!(mainnet.network_id, RCNET1_PROFILE.network_id);
    }

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
        assert_eq!(RCNET1_PROFILE.proof, ProofProfile::ProductionV4);
        assert_eq!(
            RCNET1_PROFILE.network_id,
            cmfd_consensus::PRODUCTION_V4_RCNET1_NETWORK_ID
        );
        assert_ne!(RCNET1_PROFILE.pow_limit, DEVNET_PROFILE.pow_limit);
        assert_ne!(RCNET1_PROFILE.rewards, DEVNET_PROFILE.rewards);
        assert!(k256::schnorr::VerifyingKey::from_bytes(&RCNET1_PROFILE.rewards.steward).is_ok());
        assert!(k256::schnorr::VerifyingKey::from_bytes(&RCNET1_PROFILE.rewards.community).is_ok());
        assert_eq!(DEVNET_PROFILE.proof, ProofProfile::DevnetV2Reference);
        assert_eq!(DEVNET_PROFILE.short_name(), "Devnet-0");
        assert_eq!(DEVNET_PROFILE.proof.profile_name(), "DevnetV2");
        assert_eq!(RCNET1_PROFILE.short_name(), "RCNet-1");
        assert_eq!(RCNET1_PROFILE.proof.profile_name(), "ProductionV4");
        assert_eq!(RCNET1_PROFILE.rpc_address().to_string(), "127.0.0.1:19443");
        assert_eq!(RCNET1_PROFILE.p2p_address().to_string(), "127.0.0.1:19444");
        assert_eq!(RCNET1_PROFILE.pool_address().to_string(), "127.0.0.1:19445");
        assert_eq!(
            RCNET1_PROFILE.bootstrap_peer(),
            crate::seed_peers::PRODUCTION_RC_SEED
        );
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
        #[cfg(not(any(
            feature = "production-v3-testnet",
            feature = "production-v4-testnet",
            feature = "production-rc",
            feature = "production-mainnet"
        )))]
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
        #[cfg(feature = "production-v4-testnet")]
        {
            assert_eq!(COMPILED_NETWORK_PROFILE, PRODUCTION_V4_TESTNET_PROFILE);
            assert_eq!(COMPILED_NETWORK_PROFILE.proof, ProofProfile::ProductionV4);
            assert_eq!(
                COMPILED_NETWORK_PROFILE.network_id,
                cmfd_consensus::PRODUCTION_V4_TESTNET_NETWORK_ID
            );
        }
        #[cfg(feature = "production-rc")]
        {
            assert_eq!(COMPILED_NETWORK_PROFILE, RCNET1_PROFILE);
            assert_eq!(COMPILED_NETWORK_PROFILE.proof, ProofProfile::ProductionV4);
        }
    }

    #[test]
    fn production_v4_testnet_is_fully_isolated() {
        let testnet = PRODUCTION_V4_TESTNET_PROFILE;
        for other in [
            DEVNET_PROFILE,
            PRODUCTION_V3_TESTNET_PROFILE,
            RCNET1_PROFILE,
        ] {
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
        }
        assert_eq!(testnet.proof, ProofProfile::ProductionV4);
        assert_eq!(
            testnet.network_id,
            cmfd_consensus::PRODUCTION_V4_TESTNET_NETWORK_ID
        );
        assert_eq!(testnet.bootstrap_peer().to_string(), "107.214.187.2:22444");
        assert_eq!(testnet.miner_p2p_address().to_string(), "127.0.0.1:23444");
        assert!(k256::schnorr::VerifyingKey::from_bytes(&testnet.rewards.steward).is_ok());
        assert!(k256::schnorr::VerifyingKey::from_bytes(&testnet.rewards.community).is_ok());
    }
}
