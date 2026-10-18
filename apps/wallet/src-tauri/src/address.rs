//! Addresses the wallet window sends to the backend. Both forms are read
//! (hex, and bech32m with this build's network prefix); the node's own
//! request parsers take hex, so callers re-encode the key as hex.

use cmfd_node::COMPILED_NETWORK_PROFILE;
use cmfd_node::address::{AddressCodec, AddressError, AddressFormat, hrp_for_network};

fn codec() -> AddressCodec {
    AddressCodec {
        hrp: hrp_for_network(COMPILED_NETWORK_PROFILE.short_name()),
        output: AddressFormat::Hex,
    }
}

/// Reads an address in either form and checks that it is an x-only key.
/// Hex is read in either case, as the wallet always did.
pub(crate) fn read_address(text: &str) -> Result<[u8; 32], AddressError> {
    if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return codec()
            .decode(&text.to_ascii_lowercase())
            .map(|(key, _)| key);
    }
    codec().decode(text).map(|(key, _)| key)
}

#[cfg(test)]
mod tests {
    use cmfd_node::address::{MAINNET_HRP, TEST_NETWORK_HRP, encode};
    use cmfd_node::{NetworkProfileKind, default_miner_destination};

    use super::*;

    #[test]
    fn reads_both_forms_for_this_network_only() {
        let key = default_miner_destination();
        let (own, other) = if COMPILED_NETWORK_PROFILE.kind == NetworkProfileKind::Mainnet {
            (MAINNET_HRP, TEST_NETWORK_HRP)
        } else {
            (TEST_NETWORK_HRP, MAINNET_HRP)
        };
        assert_eq!(read_address(&hex::encode(key)), Ok(key));
        assert_eq!(read_address(&encode(own, &key)), Ok(key));
        assert_eq!(
            read_address(&encode(own, &key).to_ascii_uppercase()),
            Ok(key)
        );
        assert!(matches!(
            read_address(&encode(other, &key)),
            Err(AddressError::WrongNetwork { .. })
        ));
        assert_eq!(read_address(&hex::encode_upper(key)), Ok(key));
        let mut typo = encode(own, &key);
        let last = if typo.ends_with('q') { "p" } else { "q" };
        typo.replace_range(typo.len() - 1.., last);
        assert_eq!(read_address(&typo), Err(AddressError::Checksum));
        assert_eq!(read_address(&"ff".repeat(32)), Err(AddressError::NotAKey));
    }
}
