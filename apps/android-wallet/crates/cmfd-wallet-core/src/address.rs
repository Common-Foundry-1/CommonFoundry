//! Common Foundry address codec, ported from v1.0.16 `cmfd-node/address.rs`.
//!
//! Consensus stores the 32-byte x-only secp256k1 public key. Mainnet displays
//! it either as 64 lowercase hexadecimal characters or a checksummed Bech32m
//! `cmfd1...` address. The checksum is BIP-350 with no witness-version symbol.

use k256::schnorr::VerifyingKey;
use thiserror::Error;

pub const MAINNET_HRP: &str = "cmfd";
pub const TEST_NETWORK_HRP: &str = "tcmfd";

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const CHECKSUM_SYMBOLS: usize = 6;
const KEY_SYMBOLS: usize = 52;
const MAX_LENGTH: usize = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFormat {
    Hex,
    Bech32m,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressCodec {
    pub hrp: &'static str,
    pub output: AddressFormat,
}

impl AddressCodec {
    pub const fn mainnet() -> Self {
        Self {
            hrp: MAINNET_HRP,
            output: AddressFormat::Bech32m,
        }
    }

    pub fn render(self, key: &[u8; 32]) -> String {
        match self.output {
            AddressFormat::Hex => hex::encode(key),
            AddressFormat::Bech32m => encode(self.hrp, key),
        }
    }

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
    symbols.extend(checksum(hrp, &symbols));
    to_text(hrp, &symbols)
}

pub fn decode(hrp: &str, text: &str) -> Result<([u8; 32], AddressFormat), AddressError> {
    let (key, format) = decode_payload(hrp, text)?;
    VerifyingKey::from_bytes((&key).into()).map_err(|_| AddressError::NotAKey)?;
    Ok((key, format))
}

fn decode_payload(hrp: &str, text: &str) -> Result<([u8; 32], AddressFormat), AddressError> {
    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
        return Ok((key, AddressFormat::Hex));
    }
    if !text.contains('1') {
        return Err(AddressError::Unrecognized {
            hrp: hrp.to_owned(),
        });
    }
    Ok((decode_bech32m(hrp, text)?, AddressFormat::Bech32m))
}

fn decode_bech32m(expected_hrp: &str, text: &str) -> Result<[u8; 32], AddressError> {
    let (hrp, symbols) = split_checked(text)?;
    if hrp != expected_hrp {
        return Err(AddressError::WrongNetwork {
            expected: expected_hrp.to_owned(),
            found: hrp,
        });
    }
    key_from_symbols(&symbols).ok_or(AddressError::BadPayload)
}

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

fn key_from_symbols(symbols: &[u8]) -> Option<[u8; 32]> {
    if symbols.len() != KEY_SYMBOLS {
        return None;
    }
    let mut key = [0_u8; 32];
    let (mut buffer, mut bits, mut written) = (0_u32, 0_u32, 0_usize);
    for &symbol in symbols {
        if symbol >= 32 {
            return None;
        }
        buffer = (buffer << 5) | u32::from(symbol);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if written >= key.len() {
                return None;
            }
            key[written] = ((buffer >> bits) & 0xff) as u8;
            written += 1;
        }
    }
    if written != key.len() || (bits > 0 && (buffer & ((1 << bits) - 1)) != 0) {
        return None;
    }
    Some(key)
}

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

fn hrp_expand(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes()
        .map(|byte| byte >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|byte| byte & 31))
}

fn polymod(symbols: impl IntoIterator<Item = u8>) -> u32 {
    let mut checksum = 1_u32;
    for symbol in symbols {
        let top = checksum >> 25;
        checksum = ((checksum & 0x1ff_ffff) << 5) ^ u32::from(symbol);
        for (bit, generator) in [
            0x3b6a_57b2,
            0x2650_8e6d,
            0x1ea1_19fa,
            0x3d42_33dd,
            0x2a14_62b3,
        ]
        .into_iter()
        .enumerate()
        {
            if (top >> bit) & 1 != 0 {
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

    fn public_key(secret: [u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes((&secret).into())
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into()
    }

    #[test]
    fn official_generator_vector_matches_v1_0_16() {
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let key = public_key(secret);
        assert_eq!(
            hex::encode(key),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
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
    fn both_mainnet_forms_round_trip_and_wrong_network_fails() {
        let key = public_key([7; 32]);
        let codec = AddressCodec::mainnet();
        let bech32m = codec.render(&key);
        assert_eq!(codec.decode(&bech32m), Ok((key, AddressFormat::Bech32m)));
        assert_eq!(
            codec.decode(&hex::encode(key)),
            Ok((key, AddressFormat::Hex))
        );
        assert!(matches!(
            codec.decode(&encode(TEST_NETWORK_HRP, &key)),
            Err(AddressError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn independent_synthetic_keys_accept_bech32m_and_lowercase_hex_equally() {
        let codec = AddressCodec::mainnet();
        for secret in [[7_u8; 32], [9_u8; 32]] {
            let expected = public_key(secret);
            let bech32m = codec.render(&expected);
            let hexadecimal = hex::encode(expected);
            assert_eq!(
                codec.decode(&bech32m),
                Ok((expected, AddressFormat::Bech32m))
            );
            assert_eq!(
                codec.decode(&hexadecimal),
                Ok((expected, AddressFormat::Hex))
            );
        }
    }

    #[test]
    fn checksum_and_case_errors_fail_closed() {
        let key = public_key([9; 32]);
        let valid = encode(MAINNET_HRP, &key);
        let mut damaged = valid.clone().into_bytes();
        let last = damaged.len() - 1;
        damaged[last] = if damaged[last] == b'q' { b'p' } else { b'q' };
        assert_eq!(
            decode(MAINNET_HRP, &String::from_utf8(damaged).unwrap()),
            Err(AddressError::Checksum)
        );
        assert_eq!(
            decode(MAINNET_HRP, &hex::encode_upper(key)),
            Err(AddressError::UppercaseHex)
        );
    }
}
