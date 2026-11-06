//! Pinned public mainnet identity from Common Foundry v1.0.16.

use serde::{Deserialize, Serialize};

/// Exact mainnet network id from `cmfd-consensus/mainnet_network_id.inc.rs`.
pub const MAINNET_NETWORK_ID: [u8; 32] = [
    0x88, 0x29, 0x6b, 0xc3, 0x9c, 0x10, 0xe8, 0xbc, 0x1d, 0xd4, 0x81, 0x8d, 0x4d, 0x42, 0x41, 0x2f,
    0xe5, 0xf0, 0x82, 0x10, 0x65, 0x11, 0x10, 0x37, 0x7f, 0x49, 0x5d, 0xa2, 0x99, 0x81, 0x2f, 0x62,
];

pub const ATOMS_PER_CMFD: u64 = 100_000_000;
pub const MIN_TRANSACTION_FEE_ATOMS: u64 = ATOMS_PER_CMFD / 10;
pub const TRANSACTION_VERSION: u32 = 1;
pub const MAX_TRANSACTION_INPUTS: usize = 128;
pub const MAX_TRANSACTION_OUTPUTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub name: &'static str,
    pub id: [u8; 32],
    pub address_hrp: &'static str,
    pub minimum_fee_atoms: u64,
}

pub const MAINNET: Network = Network {
    name: "CommonFoundry Mainnet",
    id: MAINNET_NETWORK_ID,
    address_hrp: "cmfd",
    minimum_fee_atoms: MIN_TRANSACTION_FEE_ATOMS,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_pin_matches_v1_0_16() {
        assert_eq!(
            hex::encode(MAINNET.id),
            "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62"
        );
        assert_eq!(MAINNET.minimum_fee_atoms, 10_000_000);
    }
}
