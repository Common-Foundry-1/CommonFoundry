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

pub const DEVNET_PROFILE: NetworkProfile = NetworkProfile {
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

/// Isolated rehearsal identity for the first launch-candidate network.
///
/// RCNet-1 is not mainnet and cannot currently start. Its identity, service
/// ports, and storage paths are intentionally disjoint from Devnet-0 so a
/// future production-V3 integration cannot accidentally reuse Devnet state.
/// The production proof selector is the hard gate: code must never substitute
/// the tiny V2 reference relation for this profile.
pub const RCNET1_PROFILE: NetworkProfile = NetworkProfile {
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
    }

    #[test]
    fn compiled_profile_matches_the_release_gate_selection() {
        assert_eq!(COMPILED_NETWORK_PROFILE, DEVNET_PROFILE);
        assert_eq!(
            COMPILED_NETWORK_PROFILE.proof,
            ProofProfile::DevnetV2Reference
        );
    }
}
