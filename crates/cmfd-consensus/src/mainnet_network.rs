//! One compile-time mainnet identity shared by wire and monetary policy.

pub const MAINNET_NETWORK_ID: Option<[u8; 32]> = include!("../mainnet_network_id.inc.rs");

pub fn is_mainnet_network(network_id: [u8; 32]) -> bool {
    matches_pin(network_id, MAINNET_NETWORK_ID)
}

fn matches_pin(network_id: [u8; 32], pin: Option<[u8; 32]>) -> bool {
    match pin {
        Some(expected) => {
            expected != [0; 32]
                && expected.iter().any(|byte| *byte != expected[0])
                && expected != crate::PRODUCTION_V4_RCNET1_NETWORK_ID
                && expected != crate::PRODUCTION_V4_TESTNET_NETWORK_ID
                && expected == network_id
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_nonzero_non_rc_network_can_match() {
        let mut mainnet = [0x42; 32];
        mainnet[1] = 0x19;
        assert!(matches_pin(mainnet, Some(mainnet)));
        assert!(!matches_pin(mainnet, None));
        assert!(!matches_pin([0; 32], Some([0; 32])));
        assert!(!matches_pin([0x43; 32], Some(mainnet)));
        assert!(!matches_pin(
            crate::PRODUCTION_V4_RCNET1_NETWORK_ID,
            Some(crate::PRODUCTION_V4_RCNET1_NETWORK_ID)
        ));
        assert!(!matches_pin(
            crate::PRODUCTION_V4_TESTNET_NETWORK_ID,
            Some(crate::PRODUCTION_V4_TESTNET_NETWORK_ID)
        ));
    }

    #[test]
    fn an_unconfigured_mainnet_never_changes_legacy_limits_or_fees() {
        if MAINNET_NETWORK_ID.is_none() {
            for id in [[0; 32], [0x42; 32], [0x63; 32]] {
                assert!(!is_mainnet_network(id));
                assert_eq!(
                    crate::max_proof_bytes_for_network(id),
                    crate::MAX_PROOF_BYTES
                );
                assert_eq!(crate::economics::minimum_transaction_fee(id), 0);
            }
        }
    }

    #[test]
    fn a_finalized_mainnet_pin_selects_the_production_wire_and_fee_rules() {
        if let Some(id) = MAINNET_NETWORK_ID {
            assert!(is_mainnet_network(id));
            assert_eq!(
                crate::max_proof_bytes_for_network(id),
                crate::PRODUCTION_V4_MAX_PROOF_BYTES
            );
            assert_eq!(
                crate::max_block_bytes_for_network(id),
                crate::PRODUCTION_V4_MAX_BLOCK_BYTES
            );
            assert_eq!(
                crate::economics::minimum_transaction_fee(id),
                crate::economics::MIN_TRANSACTION_FEE_ATOMS
            );
        }
    }
}
