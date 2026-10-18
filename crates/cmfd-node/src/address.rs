//! Text forms of a Common Foundry address.
//!
//! An address is the 32-byte x-only secp256k1 public key that an output pays
//! (`OutputLock::Key`). It can be written two ways, and both decode to the
//! same bytes, so consensus and stored wallet data never see either form:
//!
//! * **hex**: 64 lowercase hexadecimal characters with no checksum. This was
//!   the only form before 1.0.16 and is still accepted everywhere.
//! * **bech32m** ([BIP-350]): the network prefix (`cmfd` on mainnet), the
//!   separator `1`, the key as 52 five-bit symbols (4 zero padding bits), and
//!   a 6-symbol checksum, 63 characters in all on mainnet. The checksum
//!   detects every error that changes up to 4 characters and lets any other
//!   error through with odds of about one in a billion. There is no
//!   witness-version symbol: CMFD has one address type.
//!
//! [BIP-350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

use k256::schnorr::VerifyingKey;
use thiserror::Error;

/// Prefix of mainnet addresses.
pub const MAINNET_HRP: &str = "cmfd";
/// Prefix of addresses on every test network (Devnet, Testnets, RCNet), so a
/// test-network address is refused on mainnet and the other way round.
pub const TEST_NETWORK_HRP: &str = "tcmfd";

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const CHECKSUM_SYMBOLS: usize = 6;
/// 256 key bits in 5-bit symbols, the last one carrying 4 zero padding bits.
const KEY_SYMBOLS: usize = 52;
/// BIP-173's limit on the whole string.
const MAX_LENGTH: usize = 90;

/// The address prefix of the network a binary was built for.
pub fn hrp_for_network(network_name: &str) -> &'static str {
    if network_name.eq_ignore_ascii_case("mainnet") {
        MAINNET_HRP
    } else {
        TEST_NETWORK_HRP
    }
}

/// A text form of an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFormat {
    Hex,
    Bech32m,
}

impl AddressFormat {
    pub fn name(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Bech32m => "bech32m",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "hex" => Some(Self::Hex),
            "bech32m" => Some(Self::Bech32m),
            _ => None,
        }
    }
}

/// How a program reads and writes addresses: its network's prefix and the
/// one form it prints. It reads both forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressCodec {
    pub hrp: &'static str,
    pub output: AddressFormat,
}

impl AddressCodec {
    /// Writes `key` in the output form; bech32m is always lowercase.
    pub fn render(self, key: &[u8; 32]) -> String {
        match self.output {
            AddressFormat::Hex => hex::encode(key),
            AddressFormat::Bech32m => encode(self.hrp, key),
        }
    }

    /// Reads either form; see [`decode`].
    pub fn decode(self, text: &str) -> Result<([u8; 32], AddressFormat), AddressError> {
        decode(self.hrp, text)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AddressError {
    #[error(
        "expected a {hrp}1... address or 64 lowercase hexadecimal characters encoding an x-only public key"
    )]
    Unrecognized { hrp: String },
    #[error("hex addresses must be lowercase")]
    UppercaseHex,
    #[error("address mixes upper and lower case")]
    MixedCase,
    #[error("address contains a character that is not used in addresses")]
    InvalidCharacter,
    #[error("address checksum does not match: the address is mistyped or incomplete")]
    Checksum,
    #[error("address is for another network: expected {expected}1..., found {found}1...")]
    WrongNetwork { expected: String, found: String },
    #[error("address has the wrong length")]
    WrongLength,
    #[error("address does not hold a 32-byte key")]
    BadPayload,
    #[error("address does not encode an x-only public key")]
    NotAKey,
}

/// Encodes `key` as a lowercase bech32m address. It does not check that the
/// key is on the curve; [`decode`] does.
pub fn encode(hrp: &str, key: &[u8; 32]) -> String {
    let mut symbols = Vec::with_capacity(KEY_SYMBOLS + CHECKSUM_SYMBOLS);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for &byte in key {
        buffer = ((buffer << 8) | u32::from(byte)) & 0xfff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            symbols.push(((buffer >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        symbols.push(((buffer << (5 - bits)) & 31) as u8);
    }
    let checksum = checksum(hrp, &symbols);
    symbols.extend(checksum);
    to_text(hrp, &symbols)
}

/// The checksum symbols BIP-350 appends to `symbols`.
fn checksum(hrp: &str, symbols: &[u8]) -> [u8; CHECKSUM_SYMBOLS] {
    let value = polymod(
        hrp_expand(hrp)
            .chain(symbols.iter().copied())
            .chain([0; CHECKSUM_SYMBOLS]),
    ) ^ BECH32M_CONST;
    std::array::from_fn(|index| ((value >> (5 * (CHECKSUM_SYMBOLS - 1 - index))) & 31) as u8)
}

fn to_text(hrp: &str, symbols: &[u8]) -> String {
    let mut text = String::with_capacity(hrp.len() + 1 + symbols.len());
    text.push_str(hrp);
    text.push('1');
    text.extend(
        symbols
            .iter()
            .map(|&symbol| char::from(CHARSET[usize::from(symbol)])),
    );
    text
}

/// Decodes either form of an address for the network whose prefix is `hrp`,
/// and checks that it is a valid x-only public key. Returns the key and the
/// form it was written in.
pub fn decode(hrp: &str, text: &str) -> Result<([u8; 32], AddressFormat), AddressError> {
    let (key, format) = decode_payload(hrp, text)?;
    VerifyingKey::from_bytes(&key).map_err(|_| AddressError::NotAKey)?;
    Ok((key, format))
}

/// Like [`decode`], but 64 hex digits may be in either case, as the node's
/// miner, payout and wallet-recipient inputs have always accepted.
pub fn decode_any_case_hex(
    hrp: &str,
    text: &str,
) -> Result<([u8; 32], AddressFormat), AddressError> {
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return decode(hrp, &text.to_ascii_lowercase());
    }
    decode(hrp, text)
}

/// Like [`decode`] without the curve check, for callers that check the key
/// later and report an invalid key with their own error.
pub fn decode_payload(hrp: &str, text: &str) -> Result<([u8; 32], AddressFormat), AddressError> {
    Ok(
        if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            // Every network prefix has a letter that is not a hex digit, so this
            // is a hex address or a damaged one, never bech32m.
            if text.len() != 64 {
                return Err(AddressError::Unrecognized {
                    hrp: hrp.to_owned(),
                });
            }
            if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
                return Err(AddressError::UppercaseHex);
            }
            let mut key = [0_u8; 32];
            hex::decode_to_slice(text, &mut key).map_err(|_| AddressError::InvalidCharacter)?;
            (key, AddressFormat::Hex)
        } else if text.contains('1') {
            (decode_bech32m(hrp, text)?, AddressFormat::Bech32m)
        } else {
            return Err(AddressError::Unrecognized {
                hrp: hrp.to_owned(),
            });
        },
    )
}

fn decode_bech32m(expected_hrp: &str, text: &str) -> Result<[u8; 32], AddressError> {
    // The checksum is checked before the prefix, so a typo in the prefix is
    // reported as a typo rather than as another network.
    let (hrp, symbols) = split_checked(text)?;
    if hrp != expected_hrp {
        return Err(AddressError::WrongNetwork {
            expected: expected_hrp.to_owned(),
            found: hrp,
        });
    }
    key_from_symbols(&symbols).ok_or(AddressError::BadPayload)
}

/// Validates a bech32m string (BIP-350) and returns its lowercase prefix and
/// its data symbols without the checksum.
fn split_checked(text: &str) -> Result<(String, Vec<u8>), AddressError> {
    if text.len() > MAX_LENGTH {
        return Err(AddressError::WrongLength);
    }
    if text.bytes().any(|byte| !(33..=126).contains(&byte)) {
        return Err(AddressError::InvalidCharacter);
    }
    if text.bytes().any(|byte| byte.is_ascii_lowercase())
        && text.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(AddressError::MixedCase);
    }
    let text = text.to_ascii_lowercase();
    let separator = text.rfind('1').ok_or(AddressError::InvalidCharacter)?;
    let (hrp, data) = (&text[..separator], &text[separator + 1..]);
    if hrp.is_empty() || data.len() < CHECKSUM_SYMBOLS {
        return Err(AddressError::WrongLength);
    }
    let mut symbols = data
        .bytes()
        .map(|byte| {
            CHARSET
                .iter()
                .position(|&symbol| symbol == byte)
                .map(|position| position as u8)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(AddressError::InvalidCharacter)?;
    if polymod(hrp_expand(hrp).chain(symbols.iter().copied())) != BECH32M_CONST {
        return Err(AddressError::Checksum);
    }
    symbols.truncate(symbols.len() - CHECKSUM_SYMBOLS);
    Ok((hrp.to_owned(), symbols))
}

/// Regroups 52 five-bit symbols into 32 bytes; the 4 leftover bits must be 0.
fn key_from_symbols(symbols: &[u8]) -> Option<[u8; 32]> {
    if symbols.len() != KEY_SYMBOLS {
        return None;
    }
    let mut key = [0_u8; 32];
    let (mut buffer, mut bits, mut filled) = (0_u32, 0_u32, 0);
    for &symbol in symbols {
        buffer = ((buffer << 5) | u32::from(symbol)) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            key[filled] = (buffer >> bits) as u8;
            filled += 1;
        }
    }
    (bits == 4 && buffer & 0xf == 0).then_some(key)
}

fn hrp_expand(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes()
        .map(|byte| byte >> 5)
        .chain([0])
        .chain(hrp.bytes().map(|byte| byte & 31))
}

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (index, generator) in GENERATOR.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;

    fn key(seed: u8) -> [u8; 32] {
        let secret = [seed.max(1); 32];
        SigningKey::from_bytes(&secret)
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into()
    }

    /// The first 32-byte value (counting up from all zeros) that is not the
    /// x coordinate of a curve point.
    fn off_curve() -> [u8; 32] {
        (0_u8..=255)
            .map(|last| {
                let mut bytes = [0_u8; 32];
                bytes[31] = last;
                bytes
            })
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .unwrap()
    }

    #[test]
    fn bip350_valid_vectors_verify() {
        for text in [
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ] {
            assert!(split_checked(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn bip350_invalid_vectors_fail() {
        for text in [
            "\u{20}1xj0phk",
            "\u{7f}1g6xzxy",
            "\u{80}1vctc34",
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "qyrz8wqd2c9m",
            "1qyrz8wqd2c9m",
            "y1b0jsk6g",
            "lt1igcx5c0",
            "in1muywd",
            "mm1crxm3i",
            "au1s5cgom",
            "M1VUXWEZ",
            "16plkw9",
            "1p2gdwpf",
        ] {
            assert!(split_checked(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn keys_round_trip_through_both_forms() {
        for seed in 1..=64 {
            let key = key(seed);
            let text = encode(MAINNET_HRP, &key);
            assert_eq!(text.len(), 63);
            assert!(text.starts_with("cmfd1"));
            assert_eq!(
                decode(MAINNET_HRP, &text),
                Ok((key, AddressFormat::Bech32m))
            );
            assert_eq!(
                decode(MAINNET_HRP, &hex::encode(key)),
                Ok((key, AddressFormat::Hex))
            );
            let test = encode(TEST_NETWORK_HRP, &key);
            assert_eq!(test.len(), 64);
            assert_eq!(
                decode(TEST_NETWORK_HRP, &test),
                Ok((key, AddressFormat::Bech32m))
            );
        }
    }

    #[test]
    fn known_key_encodes_to_a_fixed_address() {
        // Generator point G: secret key 1. Cross-checked against the
        // `bech32` npm package (bech32m.encode with toWords).
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let key = SigningKey::from_bytes(&secret)
            .unwrap()
            .verifying_key()
            .to_bytes();
        assert_eq!(
            hex::encode(key),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        let key: [u8; 32] = key.into();
        assert_eq!(
            encode(MAINNET_HRP, &key),
            "cmfd10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq4yhywr"
        );
        assert_eq!(
            encode(TEST_NETWORK_HRP, &key),
            "tcmfd10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq236tfw"
        );
    }

    #[test]
    fn every_single_character_substitution_is_detected() {
        let text = encode(MAINNET_HRP, &key(7));
        for position in 0..text.len() {
            for replacement in CHARSET.iter().chain(b"cmfdbio") {
                if text.as_bytes()[position] == *replacement {
                    continue;
                }
                let mut typo = text.clone().into_bytes();
                typo[position] = *replacement;
                let typo = String::from_utf8(typo).unwrap();
                assert!(decode(MAINNET_HRP, &typo).is_err(), "{typo}");
            }
        }
    }

    #[test]
    fn every_adjacent_transposition_is_detected() {
        for seed in 1..=8 {
            let text = encode(MAINNET_HRP, &key(seed));
            let bytes = text.as_bytes();
            for position in 0..text.len() - 1 {
                if bytes[position] == bytes[position + 1] {
                    continue;
                }
                let mut swapped = bytes.to_vec();
                swapped.swap(position, position + 1);
                let swapped = String::from_utf8(swapped).unwrap();
                assert!(decode(MAINNET_HRP, &swapped).is_err(), "{swapped}");
            }
        }
    }

    #[test]
    fn dropped_or_added_characters_are_detected() {
        let text = encode(MAINNET_HRP, &key(9));
        for position in 0..text.len() {
            let mut shorter = text.clone();
            shorter.remove(position);
            assert!(decode(MAINNET_HRP, &shorter).is_err(), "{shorter}");
            for &extra in CHARSET {
                let mut longer = text.clone();
                longer.insert(position, char::from(extra));
                assert!(decode(MAINNET_HRP, &longer).is_err(), "{longer}");
            }
        }
    }

    #[test]
    fn another_networks_address_is_refused() {
        let key = key(3);
        assert_eq!(
            decode(MAINNET_HRP, &encode(TEST_NETWORK_HRP, &key)),
            Err(AddressError::WrongNetwork {
                expected: "cmfd".to_owned(),
                found: "tcmfd".to_owned(),
            })
        );
        assert!(matches!(
            decode(TEST_NETWORK_HRP, &encode(MAINNET_HRP, &key)),
            Err(AddressError::WrongNetwork { .. })
        ));
        assert!(matches!(
            decode(MAINNET_HRP, &encode("bc", &key)),
            Err(AddressError::WrongNetwork { .. })
        ));
        // A typo in the prefix is a checksum failure, not another network.
        let typo = encode(MAINNET_HRP, &key).replacen("cmfd", "cmfe", 1);
        assert_eq!(decode(MAINNET_HRP, &typo), Err(AddressError::Checksum));
        assert_eq!(hrp_for_network("Mainnet"), MAINNET_HRP);
        assert_eq!(hrp_for_network("RCNet-1"), TEST_NETWORK_HRP);
    }

    #[test]
    fn case_rules_follow_bip173() {
        let key = key(5);
        let lower = encode(MAINNET_HRP, &key);
        assert_eq!(
            decode(MAINNET_HRP, &lower.to_ascii_uppercase()),
            Ok((key, AddressFormat::Bech32m))
        );
        let mut mixed = lower.clone().into_bytes();
        let letter = mixed
            .iter()
            .rposition(u8::is_ascii_lowercase)
            .expect("an address has letters");
        mixed[letter] = mixed[letter].to_ascii_uppercase();
        assert_eq!(
            decode(MAINNET_HRP, &String::from_utf8(mixed).unwrap()),
            Err(AddressError::MixedCase)
        );
        // Hex keeps its pre-1.0.16 rule: lowercase only.
        assert_eq!(
            decode(MAINNET_HRP, &hex::encode_upper(key)),
            Err(AddressError::UppercaseHex)
        );
    }

    #[test]
    fn malformed_payloads_are_refused() {
        let key = key(11);
        // A valid checksum over a payload with nonzero padding bits.
        let text = encode(MAINNET_HRP, &key);
        let (hrp, mut symbols) = split_checked(&text).unwrap();
        *symbols.last_mut().unwrap() |= 1;
        assert_eq!(
            decode(MAINNET_HRP, &with_checksum(&hrp, &symbols)),
            Err(AddressError::BadPayload)
        );
        // Valid checksums over payloads one or two symbols short or long.
        for length in [50, 51, 53, 54] {
            let symbols = vec![0_u8; length];
            assert_eq!(
                decode(MAINNET_HRP, &with_checksum(&hrp, &symbols)),
                Err(AddressError::BadPayload)
            );
        }
        // A well-formed address whose bytes are not an x-only key.
        let off = off_curve();
        assert_eq!(
            decode(MAINNET_HRP, &encode(MAINNET_HRP, &off)),
            Err(AddressError::NotAKey)
        );
        assert_eq!(
            decode(MAINNET_HRP, &hex::encode(off)),
            Err(AddressError::NotAKey)
        );
        for junk in [
            "",
            "cmfd",
            "cmfd1",
            &hex::encode(key)[..63],
            "not an address",
        ] {
            assert!(decode(MAINNET_HRP, junk).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn relaxed_decoders_differ_from_decode_only_where_documented() {
        let key = key(13);
        let upper = hex::encode_upper(key);
        assert_eq!(
            decode_any_case_hex(MAINNET_HRP, &upper),
            Ok((key, AddressFormat::Hex))
        );
        assert_eq!(
            decode_any_case_hex(MAINNET_HRP, &encode(MAINNET_HRP, &key).to_ascii_uppercase()),
            Ok((key, AddressFormat::Bech32m))
        );
        assert!(decode_any_case_hex(MAINNET_HRP, &upper[..63]).is_err());
        let off = off_curve();
        assert_eq!(
            decode_any_case_hex(MAINNET_HRP, &hex::encode_upper(off)),
            Err(AddressError::NotAKey)
        );
        // decode_payload returns off-curve bytes for the caller to judge, and
        // otherwise applies decode's rules.
        assert_eq!(
            decode_payload(MAINNET_HRP, &encode(MAINNET_HRP, &off)),
            Ok((off, AddressFormat::Bech32m))
        );
        assert_eq!(
            decode_payload(MAINNET_HRP, &hex::encode(off)),
            Ok((off, AddressFormat::Hex))
        );
        assert_eq!(
            decode_payload(MAINNET_HRP, &upper),
            Err(AddressError::UppercaseHex)
        );
        assert!(matches!(
            decode_payload(MAINNET_HRP, &encode(TEST_NETWORK_HRP, &key)),
            Err(AddressError::WrongNetwork { .. })
        ));
    }

    /// A string with a valid checksum over arbitrary symbols.
    fn with_checksum(hrp: &str, symbols: &[u8]) -> String {
        let mut all = symbols.to_vec();
        all.extend(checksum(hrp, symbols));
        to_text(hrp, &all)
    }
}
