use blake3::Hasher;
use k256::schnorr::VerifyingKey;
use thiserror::Error;

use crate::chain::{BLOCK_VERSION, COINBASE_MATURITY, TRANSACTION_VERSION};
use crate::difficulty::{DGW_WINDOW, TARGET_SPACING_SECONDS};
use crate::economics::{EconomicsError, MonetaryPolicy};
use crate::forgematrix::ForgeMatrixError;
use crate::pow::{PowError, PowParameters};
use crate::structured_blake3_identity::{
    NARROW_BLAKE3_PROOF_VERSION, PINNED_PREPROCESSED_REGISTRY_VERSION, STRUCTURED_BLAKE3_VERSION,
    pinned_preprocessed_registry_digest,
};
use crate::wire::{
    MAX_BLOCK_BYTES, MAX_PROOF_BYTES, MAX_TRANSACTION_BYTES, WIRE_HEADER_BYTES, WIRE_VERSION,
};

const NETWORK_PARAMS_DOMAIN: &str = "CMFD/NETWORK/PARAMS/V2";

pub const NETWORK_PROTOCOL_VERSION: u32 = 1;
pub const MAX_FUTURE_OFFSET_SECS: u64 = 24 * 60 * 60;
pub const MEDIAN_TIME_WINDOW: usize = 11;
pub const MAX_BLOCK_TRANSACTIONS: usize = 1_024;
pub const MAX_TRANSACTION_INPUTS: usize = 128;
pub const MAX_TRANSACTION_OUTPUTS: usize = 128;
pub const MAX_BLOCK_AGGREGATE_INPUTS: usize = 4_096;
pub const MAX_BLOCK_AGGREGATE_OUTPUTS: usize = 4_096;
pub const MAX_BLOCK_SIGNATURE_CHECKS: usize = 2_048;
pub const MAX_COINBASE_OUTPUTS: usize = 3;
pub const CONSENSUS_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedRewardDestinations {
    pub steward: [u8; 32],
    pub community: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkParams {
    pub network_id: [u8; 32],
    pub protocol_version: u32,
    pub genesis_hash: [u8; 32],
    pub genesis_timestamp: u64,
    pub pow_limit: [u8; 32],
    pub pow: PowParameters,
    pub monetary_policy: MonetaryPolicy,
    pub rewards: FixedRewardDestinations,
    pub max_future_offset_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockValidationContext {
    pub now_unix_seconds: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkError {
    #[error("network identifier must be nonzero")]
    ZeroNetworkId,
    #[error("unsupported network protocol version")]
    UnsupportedProtocolVersion,
    #[error("genesis hash must be nonzero")]
    ZeroGenesisHash,
    #[error("proof-of-work limit must be nonzero")]
    ZeroPowLimit,
    #[error("maximum future timestamp offset must be nonzero")]
    ZeroFutureOffset,
    #[error("maximum future timestamp offset exceeds the 24-hour implementation limit")]
    FutureOffsetTooLarge,
    #[error("genesis timestamp leaves no representable future timestamp range")]
    UnusableGenesisTimestamp,
    #[error("monetary policy is invalid: {0}")]
    MonetaryPolicy(#[from] EconomicsError),
    #[error("steward destination is not a valid Schnorr public key")]
    InvalidStewardDestination,
    #[error("community destination is not a valid Schnorr public key")]
    InvalidCommunityDestination,
    #[error("ForgeMatrix profile is invalid: {0}")]
    ForgeMatrix(#[from] ForgeMatrixError),
    #[error("proof-of-work parameters are invalid")]
    InvalidPowParameters,
    #[error("proof-of-work parameters belong to another network")]
    WrongPowNetwork,
}

impl NetworkParams {
    pub fn validate(&self) -> Result<(), NetworkError> {
        self.validate_without_pow()?;
        self.pow
            .validate(self.network_id)
            .map_err(map_pow_parameter_error)
    }

    pub fn fingerprint(&self) -> Result<[u8; 32], NetworkError> {
        self.fingerprint_with_structured_blake3_identity(
            STRUCTURED_BLAKE3_VERSION,
            NARROW_BLAKE3_PROOF_VERSION,
            PINNED_PREPROCESSED_REGISTRY_VERSION,
            pinned_preprocessed_registry_digest(),
        )
    }

    fn fingerprint_with_structured_blake3_identity(
        &self,
        structured_blake3_version: u32,
        narrow_blake3_version: u32,
        pinned_keys_version: u32,
        pinned_keys_digest: [u8; 32],
    ) -> Result<[u8; 32], NetworkError> {
        self.validate_without_pow()?;
        let mut hasher = Hasher::new_derive_key(NETWORK_PARAMS_DOMAIN);
        hasher.update(&self.network_id);
        hasher.update(&self.protocol_version.to_le_bytes());
        hasher.update(&self.genesis_hash);
        hasher.update(&self.genesis_timestamp.to_le_bytes());
        hasher.update(&self.pow_limit);

        self.pow
            .absorb(self.network_id, &mut hasher)
            .map_err(map_pow_parameter_error)?;

        hasher.update(&structured_blake3_version.to_le_bytes());
        hasher.update(&narrow_blake3_version.to_le_bytes());
        hasher.update(&pinned_keys_version.to_le_bytes());
        hasher.update(&pinned_keys_digest);

        hasher.update(&self.monetary_policy.initial_subsidy.to_le_bytes());
        hasher.update(&self.monetary_policy.tail_height.to_le_bytes());
        hasher.update(&self.monetary_policy.tail_subsidy.to_le_bytes());
        hasher.update(&[self.monetary_policy.steward_percent]);
        hasher.update(&[self.monetary_policy.community_percent]);

        hasher.update(&self.rewards.steward);
        hasher.update(&self.rewards.community);
        hasher.update(&self.max_future_offset_secs.to_le_bytes());

        for cap in [
            MEDIAN_TIME_WINDOW,
            MAX_BLOCK_TRANSACTIONS,
            MAX_TRANSACTION_INPUTS,
            MAX_TRANSACTION_OUTPUTS,
            MAX_BLOCK_AGGREGATE_INPUTS,
            MAX_BLOCK_AGGREGATE_OUTPUTS,
            MAX_BLOCK_SIGNATURE_CHECKS,
            MAX_COINBASE_OUTPUTS,
            CONSENSUS_SIGNATURE_BYTES,
            DGW_WINDOW,
            WIRE_HEADER_BYTES,
            MAX_TRANSACTION_BYTES,
            MAX_PROOF_BYTES,
            MAX_BLOCK_BYTES,
        ] {
            hasher.update(&(cap as u64).to_le_bytes());
        }
        hasher.update(&BLOCK_VERSION.to_le_bytes());
        hasher.update(&TRANSACTION_VERSION.to_le_bytes());
        hasher.update(&COINBASE_MATURITY.to_le_bytes());
        hasher.update(&TARGET_SPACING_SECONDS.to_le_bytes());
        hasher.update(&WIRE_VERSION.to_le_bytes());

        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn validate_for_bound_verifier(&self) -> Result<(), NetworkError> {
        self.validate_without_pow()?;
        if let PowParameters::V2Reference(descriptor) = self.pow
            && descriptor.network_id != self.network_id
        {
            return Err(NetworkError::WrongPowNetwork);
        }
        Ok(())
    }

    pub(crate) fn validate_without_pow(&self) -> Result<(), NetworkError> {
        if self.network_id == [0; 32] {
            return Err(NetworkError::ZeroNetworkId);
        }
        if self.protocol_version != NETWORK_PROTOCOL_VERSION {
            return Err(NetworkError::UnsupportedProtocolVersion);
        }
        if self.genesis_hash == [0; 32] {
            return Err(NetworkError::ZeroGenesisHash);
        }
        if self.pow_limit == [0; 32] {
            return Err(NetworkError::ZeroPowLimit);
        }
        if self.max_future_offset_secs == 0 {
            return Err(NetworkError::ZeroFutureOffset);
        }
        if self.max_future_offset_secs > MAX_FUTURE_OFFSET_SECS {
            return Err(NetworkError::FutureOffsetTooLarge);
        }
        if self
            .genesis_timestamp
            .checked_add(self.max_future_offset_secs)
            .is_none()
        {
            return Err(NetworkError::UnusableGenesisTimestamp);
        }
        self.monetary_policy.validate()?;

        VerifyingKey::from_bytes(&self.rewards.steward)
            .map_err(|_| NetworkError::InvalidStewardDestination)?;
        VerifyingKey::from_bytes(&self.rewards.community)
            .map_err(|_| NetworkError::InvalidCommunityDestination)?;
        Ok(())
    }
}

fn map_pow_parameter_error(error: PowError) -> NetworkError {
    match error {
        PowError::V1(error) => NetworkError::ForgeMatrix(error),
        PowError::WrongNetwork => NetworkError::WrongPowNetwork,
        PowError::V2(_) | PowError::WrongProofType | PowError::ParameterMismatch => {
            NetworkError::InvalidPowParameters
        }
    }
}

#[cfg(test)]
mod tests {
    use k256::schnorr::SigningKey;

    use super::*;
    use crate::economics::DEFAULT_MONETARY_POLICY;
    use crate::forgematrix::{ForgeMatrixError, TEST_PROFILE};
    use crate::pow::PowParameters;
    use crate::v2_test_reference;

    fn destination(byte: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[byte; 32])
            .unwrap()
            .verifying_key()
            .to_bytes()
            .into()
    }

    fn params() -> NetworkParams {
        NetworkParams {
            network_id: [0x11; 32],
            protocol_version: 1,
            genesis_hash: [0x22; 32],
            genesis_timestamp: 1_777_777_777,
            pow_limit: [0xff; 32],
            pow: PowParameters::V1Legacy(TEST_PROFILE),
            monetary_policy: DEFAULT_MONETARY_POLICY,
            rewards: FixedRewardDestinations {
                steward: destination(3),
                community: destination(4),
            },
            max_future_offset_secs: 2 * 60 * 60,
        }
    }

    #[test]
    fn valid_parameters_accept_the_committed_pow_identity() {
        let params = params();
        params.validate().unwrap();
        assert_eq!(params.pow, PowParameters::V1Legacy(TEST_PROFILE));
    }

    #[test]
    fn zero_identifiers_and_future_offset_are_rejected() {
        let mut candidate = params();
        candidate.network_id = [0; 32];
        assert_eq!(candidate.validate(), Err(NetworkError::ZeroNetworkId));

        let mut candidate = params();
        candidate.protocol_version = 0;
        assert_eq!(
            candidate.validate(),
            Err(NetworkError::UnsupportedProtocolVersion)
        );

        let mut candidate = params();
        candidate.genesis_hash = [0; 32];
        assert_eq!(candidate.validate(), Err(NetworkError::ZeroGenesisHash));

        let mut candidate = params();
        candidate.max_future_offset_secs = 0;
        assert_eq!(candidate.validate(), Err(NetworkError::ZeroFutureOffset));

        let mut candidate = params();
        candidate.max_future_offset_secs = MAX_FUTURE_OFFSET_SECS + 1;
        assert_eq!(
            candidate.validate(),
            Err(NetworkError::FutureOffsetTooLarge)
        );

        let mut candidate = params();
        candidate.genesis_timestamp = u64::MAX;
        assert_eq!(
            candidate.validate(),
            Err(NetworkError::UnusableGenesisTimestamp)
        );
    }

    #[test]
    fn zero_pow_limit_is_rejected() {
        let mut candidate = params();
        candidate.pow_limit = [0; 32];
        assert_eq!(candidate.validate(), Err(NetworkError::ZeroPowLimit));
    }

    #[test]
    fn unsafe_monetary_policies_are_rejected() {
        let mut candidate = params();
        candidate.monetary_policy.tail_height = 1;
        assert_eq!(
            candidate.validate(),
            Err(NetworkError::MonetaryPolicy(
                EconomicsError::InvalidEmissionWindow
            ))
        );

        let mut candidate = params();
        candidate.monetary_policy.steward_percent = 96;
        assert_eq!(
            candidate.validate(),
            Err(NetworkError::MonetaryPolicy(
                EconomicsError::InvalidPercentages
            ))
        );

        let mut candidate = params();
        candidate.monetary_policy.initial_subsidy = u64::MAX;
        candidate.validate().unwrap();
    }

    #[test]
    fn malformed_fixed_destinations_are_rejected() {
        let mut candidate = params();
        candidate.rewards.steward = [0; 32];
        assert_eq!(
            candidate.validate(),
            Err(NetworkError::InvalidStewardDestination)
        );

        let mut candidate = params();
        candidate.rewards.community = [0; 32];
        assert_eq!(
            candidate.validate(),
            Err(NetworkError::InvalidCommunityDestination)
        );
    }

    #[test]
    fn invalid_forgematrix_profile_is_rejected() {
        let mut candidate = params();
        let PowParameters::V1Legacy(profile) = &mut candidate.pow else {
            unreachable!()
        };
        profile.dimension = 0;
        assert_eq!(
            candidate.validate(),
            Err(NetworkError::ForgeMatrix(ForgeMatrixError::EmptyProfile))
        );
    }

    #[test]
    fn v2_pow_identity_is_network_bound() {
        let descriptor = v2_test_reference().unwrap().descriptor();
        let mut candidate = params();
        candidate.pow = PowParameters::V2Reference(descriptor);
        assert_eq!(candidate.validate(), Err(NetworkError::WrongPowNetwork));

        candidate.network_id = descriptor.network_id;
        candidate.validate().unwrap();
    }

    #[test]
    fn fingerprint_is_deterministic_and_commits_consensus_fields() {
        let baseline = params();
        let fingerprint = baseline.fingerprint().unwrap();
        assert_eq!(fingerprint, baseline.fingerprint().unwrap());

        let registry_digest = pinned_preprocessed_registry_digest();
        assert_ne!(
            baseline
                .fingerprint_with_structured_blake3_identity(
                    STRUCTURED_BLAKE3_VERSION + 1,
                    NARROW_BLAKE3_PROOF_VERSION,
                    PINNED_PREPROCESSED_REGISTRY_VERSION,
                    registry_digest,
                )
                .unwrap(),
            fingerprint
        );
        assert_ne!(
            baseline
                .fingerprint_with_structured_blake3_identity(
                    STRUCTURED_BLAKE3_VERSION,
                    NARROW_BLAKE3_PROOF_VERSION + 1,
                    PINNED_PREPROCESSED_REGISTRY_VERSION,
                    registry_digest,
                )
                .unwrap(),
            fingerprint
        );
        assert_ne!(
            baseline
                .fingerprint_with_structured_blake3_identity(
                    STRUCTURED_BLAKE3_VERSION,
                    NARROW_BLAKE3_PROOF_VERSION,
                    PINNED_PREPROCESSED_REGISTRY_VERSION + 1,
                    registry_digest,
                )
                .unwrap(),
            fingerprint
        );
        let mut wrong_registry_digest = registry_digest;
        wrong_registry_digest[0] ^= 1;
        assert_ne!(
            baseline
                .fingerprint_with_structured_blake3_identity(
                    STRUCTURED_BLAKE3_VERSION,
                    NARROW_BLAKE3_PROOF_VERSION,
                    PINNED_PREPROCESSED_REGISTRY_VERSION,
                    wrong_registry_digest,
                )
                .unwrap(),
            fingerprint
        );

        let mut variants = Vec::new();

        let mut candidate = baseline;
        candidate.network_id[0] ^= 1;
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.genesis_hash[0] ^= 1;
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.genesis_timestamp += 1;
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.pow_limit[0] ^= 1;
        variants.push(candidate);

        let mut candidate = baseline;
        let PowParameters::V1Legacy(profile) = &mut candidate.pow else {
            unreachable!()
        };
        profile.model_seed[0] ^= 1;
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.monetary_policy.initial_subsidy += 1;
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.monetary_policy.tail_height -= 1;
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.monetary_policy.tail_subsidy += 1;
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.rewards.steward = destination(5);
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.rewards.community = destination(6);
        variants.push(candidate);

        let mut candidate = baseline;
        candidate.max_future_offset_secs += 1;
        variants.push(candidate);

        for candidate in variants {
            assert_ne!(candidate.fingerprint().unwrap(), fingerprint);
        }
    }
}
