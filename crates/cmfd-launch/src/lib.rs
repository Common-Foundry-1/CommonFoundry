//! Mainnet launch-time beacon verification, independent of HTTP transports.
//!
//! The public key, scheme, and one exact round are release-pinned. A relay is
//! not a source of trust. The output genesis commits to the verified signature
//! and the immutable launch-plan digest. Node/miner integration must consume
//! this authenticated output, never a genesis value supplied by the relay.

use drand_verify::{G2PubkeyRfc, Pubkey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod acquire;

mod schedule;
pub use schedule::*;
pub const QUICKNET_GENESIS: u64 = 1_692_803_367;
pub const QUICKNET_PERIOD_SECONDS: u64 = 3;
pub const MAINNET_BEACON_ROUND: u64 = 32_747_812;
/// drand v2 routes by beacon ID; the pinned chain hash remains the verifier identity.
pub const QUICKNET_BEACON_ID: &str = "quicknet";
pub const QUICKNET_SCHEME: &str = "bls-unchained-g1-rfc9380";
pub const QUICKNET_CHAIN_HASH: &str =
    "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
pub const QUICKNET_PUBLIC_KEY: &str = concat!(
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1",
    "fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
);
pub const MAX_BEACON_DOCUMENT_BYTES: usize = 4_096;
const GENESIS_DOMAIN: &[u8] = b"CMFD/MAINNET/BEACON-GENESIS/V1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BeaconCertificate {
    pub round: u64,
    /// Canonical lowercase hexadecimal, 48 compressed G1 bytes.
    pub signature: String,
}

/// Only the verifier can construct this type. Deserialize is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedLaunch {
    launch_plan_digest: [u8; 32],
    genesis_hash: [u8; 32],
    randomness: [u8; 32],
    round: u64,
}

impl AuthenticatedLaunch {
    pub fn launch_plan_digest(&self) -> [u8; 32] {
        self.launch_plan_digest
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub fn randomness(&self) -> [u8; 32] {
        self.randomness
    }

    pub fn round(&self) -> u64 {
        self.round
    }
}

#[derive(Debug, Error)]
pub enum LaunchError {
    #[error("launch beacon document exceeds its 4096-byte bound")]
    DocumentTooLarge,
    #[error("launch beacon document is invalid")]
    InvalidDocument(#[source] serde_json::Error),
    #[error("mainnet launch plan digest cannot be zero")]
    MissingPlanDigest,
    #[error("mainnet mining opens at 2026-10-03T17:00:00Z (noon US Central)")]
    BeforeLaunch,
    #[error("launch beacon must use the single pinned round")]
    WrongRound,
    #[error("launch beacon signature must be 96 lowercase hexadecimal characters")]
    SignatureEncoding,
    #[error("compiled launch beacon identity is invalid")]
    InvalidBeaconIdentity,
    #[error("launch beacon signature does not verify under the pinned quicknet key")]
    InvalidSignature,
    #[error("launch time must match an exact quicknet round")]
    InvalidRoundTime,
}

pub fn parse_certificate(bytes: &[u8]) -> Result<BeaconCertificate, LaunchError> {
    if bytes.len() > MAX_BEACON_DOCUMENT_BYTES {
        return Err(LaunchError::DocumentTooLarge);
    }
    serde_json::from_slice(bytes).map_err(LaunchError::InvalidDocument)
}

pub fn round_at_exact_time(timestamp: u64) -> Result<u64, LaunchError> {
    let elapsed = timestamp
        .checked_sub(QUICKNET_GENESIS)
        .ok_or(LaunchError::InvalidRoundTime)?;
    if !elapsed.is_multiple_of(QUICKNET_PERIOD_SECONDS) {
        return Err(LaunchError::InvalidRoundTime);
    }
    (elapsed / QUICKNET_PERIOD_SECONDS)
        .checked_add(1)
        .ok_or(LaunchError::InvalidRoundTime)
}

/// Authenticate launch entropy using only the frozen October 3 policy.
///
/// `launch_plan_digest` must come from the final compiled mainnet release plan,
/// not a downloaded beacon or a command-line replacement network identity.
/// The wall clock is an additional operational guard. Prevention of advance
/// work relies on threshold-beacon unpredictability and on binding this genesis
/// to every consensus/mining entry point, not on an honest local clock alone.
pub fn verify_mainnet_launch(
    launch_plan_digest: [u8; 32],
    certificate: &BeaconCertificate,
    now_unix_seconds: u64,
) -> Result<AuthenticatedLaunch, LaunchError> {
    if round_at_exact_time(MAINNET_LAUNCH_UNIX_SECONDS)? != MAINNET_BEACON_ROUND {
        return Err(LaunchError::InvalidRoundTime);
    }
    verify_at_time(
        launch_plan_digest,
        certificate,
        MAINNET_LAUNCH_UNIX_SECONDS,
        now_unix_seconds,
    )
}

fn verify_at_time(
    launch_plan_digest: [u8; 32],
    certificate: &BeaconCertificate,
    launch_time: u64,
    now_unix_seconds: u64,
) -> Result<AuthenticatedLaunch, LaunchError> {
    if launch_plan_digest == [0; 32] {
        return Err(LaunchError::MissingPlanDigest);
    }
    if now_unix_seconds < launch_time {
        return Err(LaunchError::BeforeLaunch);
    }
    let expected_round = round_at_exact_time(launch_time)?;
    if certificate.round != expected_round {
        return Err(LaunchError::WrongRound);
    }
    if certificate.signature.len() != 96
        || !certificate
            .signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LaunchError::SignatureEncoding);
    }
    let signature =
        hex::decode(&certificate.signature).map_err(|_| LaunchError::SignatureEncoding)?;
    let public_key =
        hex::decode(QUICKNET_PUBLIC_KEY).map_err(|_| LaunchError::InvalidBeaconIdentity)?;
    let public_key =
        G2PubkeyRfc::from_variable(&public_key).map_err(|_| LaunchError::InvalidBeaconIdentity)?;
    if !public_key
        .verify(certificate.round, &[], &signature)
        .map_err(|_| LaunchError::InvalidSignature)?
    {
        return Err(LaunchError::InvalidSignature);
    }
    let randomness: [u8; 32] = Sha256::digest(&signature).into();
    let mut hash = Sha256::new();
    hash.update(GENESIS_DOMAIN);
    hash.update(launch_plan_digest);
    hash.update(hex::decode(QUICKNET_CHAIN_HASH).map_err(|_| LaunchError::InvalidBeaconIdentity)?);
    hash.update(certificate.round.to_be_bytes());
    hash.update(&signature);
    Ok(AuthenticatedLaunch {
        launch_plan_digest,
        genesis_hash: hash.finalize().into(),
        randomness,
        round: certificate.round,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Published quicknet round 123, retrieved independently from the drand relay
    // and cross-checked with the drand-verify upstream example on 2026-09-19.
    fn historical_certificate() -> BeaconCertificate {
        BeaconCertificate {
            round: 123,
            signature: "b75c69d0b72a5d906e854e808ba7e2accb1542ac355ae486d591aa9d43765482e26cd02df835d3546d23c4b13e0dfc92".into(),
        }
    }

    fn historical_time() -> u64 {
        QUICKNET_GENESIS + 122 * QUICKNET_PERIOD_SECONDS
    }

    #[test]
    fn schedule_is_exactly_noon_cdt_and_twenty_four_hours_apart() {
        assert_eq!(
            MAINNET_LAUNCH_UNIX_SECONDS - SOURCE_RELEASE_UNIX_SECONDS,
            86_400
        );
        assert_eq!(
            round_at_exact_time(MAINNET_LAUNCH_UNIX_SECONDS).unwrap(),
            32_747_812
        );
        assert_eq!(round_at_exact_time(historical_time()).unwrap(), 123);
        assert_eq!(round_at_exact_time(QUICKNET_GENESIS).unwrap(), 1);
        assert!(round_at_exact_time(QUICKNET_GENESIS - 1).is_err());
        assert!(round_at_exact_time(MAINNET_LAUNCH_UNIX_SECONDS + 1).is_err());
    }

    #[test]
    fn real_signature_verifies_and_genesis_commits_to_launch_plan() {
        let beacon = historical_certificate();
        let first = verify_at_time([1; 32], &beacon, historical_time(), historical_time()).unwrap();
        let second =
            verify_at_time([2; 32], &beacon, historical_time(), historical_time()).unwrap();
        assert_ne!(first.genesis_hash(), second.genesis_hash());
        assert_eq!(first.randomness(), second.randomness());
        assert_eq!(first.round(), 123);
        assert_eq!(first.launch_plan_digest(), [1; 32]);
        // Independently calculated using Node.js crypto SHA-256, not this code.
        assert_eq!(
            hex::encode(first.randomness()),
            "fb8f7bc29bf24db51871ec8c79f3a1e4bd0557bc0dfcee9ed1d924e69d1c60dc"
        );
        assert_eq!(
            hex::encode(first.genesis_hash()),
            "b0c6c6ad74b4fd08bc0812e058c47b753ee3c68b8b2ab264ae13aa2d5f591552"
        );
        assert_eq!(
            first,
            verify_at_time([1; 32], &beacon, historical_time(), u64::MAX).unwrap()
        );
    }

    #[test]
    fn relay_chain_hash_commits_to_the_pinned_quicknet_configuration() {
        // drand chain Info.Hash: period BE u32, genesis BE u64, compressed key,
        // raw genesis seed, and non-default beacon ID (without a length prefix).
        let mut hash = Sha256::new();
        hash.update((QUICKNET_PERIOD_SECONDS as u32).to_be_bytes());
        hash.update(QUICKNET_GENESIS.to_be_bytes());
        hash.update(hex::decode(QUICKNET_PUBLIC_KEY).unwrap());
        hash.update(
            hex::decode("f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e")
                .unwrap(),
        );
        hash.update(b"quicknet");
        assert_eq!(hex::encode(hash.finalize()), QUICKNET_CHAIN_HASH);
    }

    #[test]
    fn old_round_cannot_unlock_mainnet_even_with_a_future_local_clock() {
        assert!(matches!(
            verify_mainnet_launch([1; 32], &historical_certificate(), u64::MAX),
            Err(LaunchError::WrongRound)
        ));
        assert!(matches!(
            verify_mainnet_launch(
                [1; 32],
                &historical_certificate(),
                MAINNET_LAUNCH_UNIX_SECONDS - 1
            ),
            Err(LaunchError::BeforeLaunch)
        ));
        let mut forged = historical_certificate();
        forged.round = MAINNET_BEACON_ROUND;
        assert!(matches!(
            verify_mainnet_launch([1; 32], &forged, u64::MAX),
            Err(LaunchError::InvalidSignature)
        ));
    }

    #[test]
    fn signature_mutations_and_noncanonical_encodings_fail() {
        let original = historical_certificate();
        for offset in 0..48 {
            let mut bytes = hex::decode(&original.signature).unwrap();
            bytes[offset] ^= 1;
            let altered = BeaconCertificate {
                signature: hex::encode(bytes),
                ..original.clone()
            };
            assert!(
                verify_at_time([1; 32], &altered, historical_time(), historical_time()).is_err()
            );
        }
        for signature in [
            "00".repeat(48),
            "c0".to_owned() + &"00".repeat(47),
            "00".repeat(47),
            original.signature.to_uppercase(),
            "gg".repeat(48),
        ] {
            let altered = BeaconCertificate {
                signature,
                ..original.clone()
            };
            assert!(
                verify_at_time([1; 32], &altered, historical_time(), historical_time()).is_err()
            );
        }
        assert!(matches!(
            verify_at_time([0; 32], &original, historical_time(), historical_time()),
            Err(LaunchError::MissingPlanDigest)
        ));
    }

    #[test]
    fn strict_bounded_certificate_parser_rejects_substitution_fields() {
        let encoded = serde_json::to_vec(&historical_certificate()).unwrap();
        assert_eq!(
            parse_certificate(&encoded).unwrap(),
            historical_certificate()
        );
        assert!(parse_certificate(&vec![b' '; MAX_BEACON_DOCUMENT_BYTES + 1]).is_err());
        for value in [
            r#"{"round":123,"signature":"00","public_key":"replacement"}"#,
            r#"{"round":123,"round":123,"signature":"00"}"#,
            r#"{"round":-1,"signature":"00"}"#,
            r#"{"round":123,"signature":"00"}{}"#,
        ] {
            assert!(parse_certificate(value.as_bytes()).is_err());
        }
    }
}
