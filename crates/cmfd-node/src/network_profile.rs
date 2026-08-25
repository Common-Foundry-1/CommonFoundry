use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Compile-time identity and default endpoints for one Common Foundry network.
///
/// Consensus identity fields are bound through [`crate::devnet_params`]. The
/// remaining fields keep operators and packaged applications on the matching
/// ports and data directories without implying that endpoint changes alter
/// consensus identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkProfile {
    pub name: &'static str,
    pub network_id: [u8; 32],
    pub virtual_genesis_hash: [u8; 32],
    pub virtual_genesis_timestamp: u64,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub pool_port: u16,
    pub bootstrap_ipv4: Ipv4Addr,
    pub default_data_dir_identity: &'static str,
    pub wallet_data_dir_identity: &'static str,
}

impl NetworkProfile {
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
    name: "CommonFoundry Devnet-0",
    network_id: [0x63; 32],
    virtual_genesis_hash: [0x47; 32],
    virtual_genesis_timestamp: 1_700_000_000,
    rpc_port: 18_443,
    p2p_port: 18_444,
    pool_port: 18_445,
    bootstrap_ipv4: Ipv4Addr::new(107, 214, 187, 2),
    default_data_dir_identity: "commonfoundry-devnet0",
    wallet_data_dir_identity: "devnet-0",
};
