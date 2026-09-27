//! Canonical mainnet rules and authenticated launch-entropy binding.
//!
//! Reuses the exact RC rule/artifact inventory while giving mainnet its own
//! domains and pinning the operator's October schedule. This is a plan builder,
//! not a replacement for release approval or the runtime mainnet profile.

use cmfd_launch::{
    AuthenticatedLaunch, BeaconCertificate, MAINNET_BEACON_ROUND, MAINNET_LAUNCH_UNIX_SECONDS,
    QUICKNET_CHAIN_HASH, QUICKNET_GENESIS, QUICKNET_PERIOD_SECONDS, QUICKNET_PUBLIC_KEY,
    QUICKNET_SCHEME, SOURCE_RELEASE_UNIX_SECONDS, verify_mainnet_launch,
};

use super::*;

const MAINNET_SCHEMA: &str = "CMFD_MAINNET_LAUNCH_PLAN_V2";
const MAINNET_PROFILE: &str = "CommonFoundry Mainnet";
const PLAN_DOMAIN: &[u8] = b"CMFD/MAINNET/LAUNCH-PLAN/V2\0";
const MAINNET_NETWORK_DOMAIN: &str = "CMFD/MAINNET/NETWORK-ID/V2";
const MAX_MAINNET_PLAN_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MainnetLaunchPlan {
    schema: String,
    payload: MainnetLaunchPayload,
    launch_plan_digest: String,
    network_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetLaunchPayload {
    rules: RcnetLaunchPayload,
    initial_target: String,
    minimum_transaction_fee_atoms: u64,
    source_release_unix_seconds: u64,
    beacon: MainnetBeaconPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MainnetBeaconPolicy {
    chain_hash: String,
    public_key: String,
    scheme: String,
    genesis_time: u64,
    period_seconds: u64,
    round: u64,
}

impl MainnetBeaconPolicy {
    fn compiled() -> Self {
        Self {
            chain_hash: QUICKNET_CHAIN_HASH.into(),
            public_key: QUICKNET_PUBLIC_KEY.into(),
            scheme: QUICKNET_SCHEME.into(),
            genesis_time: QUICKNET_GENESIS,
            period_seconds: QUICKNET_PERIOD_SECONDS,
            round: MAINNET_BEACON_ROUND,
        }
    }
}

impl MainnetLaunchPlan {
    /// Uses release-pinned model artifacts. Reward destinations, the starting
    /// target and the easiest target are required explicitly; no RC custody keys
    /// or implicit difficulty defaults are selected.
    pub fn from_release_artifacts(
        pow_limit: [u8; 32],
        initial_target: [u8; 32],
        rewards: FixedRewardDestinations,
    ) -> Result<Self, RcnetCandidateError> {
        let pins = crate::release_gate::PRODUCTION_V4_ARTIFACT_PINS;
        let file_identity =
            |pin: crate::release_gate::ProductionV3FileIdentityPin| ArtifactFileIdentity {
                bytes: pin.bytes,
                blake3: hex::encode(pin.blake3),
                sha256: hex::encode(pin.sha256),
            };
        let rules = RcnetLaunchPayload {
            profile: MAINNET_PROFILE.into(),
            artifacts: ProductionV4ArtifactIdentity::from_files(
                file_identity(pins.bank),
                file_identity(pins.fixed_record),
            ),
            virtual_genesis_timestamp_unix_seconds: MAINNET_LAUNCH_UNIX_SECONDS,
            consensus: ConsensusParameters::compiled(),
            proof_of_work: ProofOfWorkParameters::compiled(pow_limit),
            monetary_policy: MonetaryPolicyParameters::compiled(),
            reward_destinations: RewardDestinations {
                steward_xonly_public_key: hex::encode(rewards.steward),
                community_xonly_public_key: hex::encode(rewards.community),
            },
        };
        let payload = MainnetLaunchPayload {
            rules,
            initial_target: hex::encode(initial_target),
            minimum_transaction_fee_atoms: cmfd_consensus::economics::MIN_TRANSACTION_FEE_ATOMS,
            source_release_unix_seconds: SOURCE_RELEASE_UNIX_SECONDS,
            beacon: MainnetBeaconPolicy::compiled(),
        };
        let launch_plan_digest = payload_digest(&payload)?;
        let plan = Self {
            schema: MAINNET_SCHEMA.into(),
            network_id: hex::encode(derive(MAINNET_NETWORK_DOMAIN, &launch_plan_digest)),
            launch_plan_digest: hex::encode(launch_plan_digest),
            payload,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), RcnetCandidateError> {
        if self.schema != MAINNET_SCHEMA {
            return Err(RcnetCandidateError::InvalidField("mainnet plan schema"));
        }
        validate_payload_for_profile(&self.payload.rules, MAINNET_PROFILE)?;
        let initial_target = decode_hex32(&self.payload.initial_target)?;
        let pow_limit = decode_hex32(&self.payload.rules.proof_of_work.pow_limit)?;
        if initial_target == [0; 32] || initial_target > pow_limit {
            return Err(RcnetCandidateError::InvalidField(
                "mainnet initial target bounds",
            ));
        }
        if self.payload.source_release_unix_seconds != SOURCE_RELEASE_UNIX_SECONDS
            || self.payload.rules.virtual_genesis_timestamp_unix_seconds
                != MAINNET_LAUNCH_UNIX_SECONDS
            || self.payload.beacon != MainnetBeaconPolicy::compiled()
            || self.payload.minimum_transaction_fee_atoms
                != cmfd_consensus::economics::MIN_TRANSACTION_FEE_ATOMS
        {
            return Err(RcnetCandidateError::InvalidField("mainnet launch policy"));
        }
        // Rebuilding from the release pins rejects a self-consistent alternate
        // model bank, fixed record, timestamp, or economic policy.
        let pins = crate::release_gate::PRODUCTION_V4_ARTIFACT_PINS;
        for (actual, expected) in [
            (&self.payload.rules.artifacts.bank, pins.bank),
            (
                &self.payload.rules.artifacts.fixed_record,
                pins.fixed_record,
            ),
        ] {
            if actual.bytes != expected.bytes
                || decode_hex32(&actual.blake3)? != expected.blake3
                || decode_hex32(&actual.sha256)? != expected.sha256
            {
                return Err(RcnetCandidateError::InvalidField("mainnet artifact pin"));
            }
        }
        let digest = payload_digest(&self.payload)?;
        if decode_hex32(&self.launch_plan_digest)? != digest
            || decode_hex32(&self.network_id)? != derive(MAINNET_NETWORK_DOMAIN, &digest)
        {
            return Err(RcnetCandidateError::DerivedIdentityMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, RcnetCandidateError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Runtime callers additionally supply the digest pinned by the final
    /// mainnet release. A valid but different plan is not an accepted network.
    pub fn parse_pinned(
        bytes: &[u8],
        expected_digest: [u8; 32],
    ) -> Result<Self, RcnetCandidateError> {
        if bytes.len() > MAX_MAINNET_PLAN_BYTES || expected_digest == [0; 32] {
            return Err(RcnetCandidateError::InvalidField(
                "mainnet plan bounds or pin",
            ));
        }
        let plan: Self = serde_json::from_slice(bytes)?;
        if plan.canonical_json()? != bytes {
            return Err(RcnetCandidateError::NonCanonicalCandidate);
        }
        if plan.digest()? != expected_digest {
            return Err(RcnetCandidateError::DerivedIdentityMismatch);
        }
        Ok(plan)
    }

    pub fn digest(&self) -> Result<[u8; 32], RcnetCandidateError> {
        self.validate()?;
        decode_hex32(&self.launch_plan_digest)
    }

    pub fn network_id(&self) -> Result<[u8; 32], RcnetCandidateError> {
        self.validate()?;
        decode_hex32(&self.network_id)
    }

    pub fn reward_destinations(&self) -> Result<FixedRewardDestinations, RcnetCandidateError> {
        self.validate()?;
        Ok(FixedRewardDestinations {
            steward: decode_hex32(
                &self
                    .payload
                    .rules
                    .reward_destinations
                    .steward_xonly_public_key,
            )?,
            community: decode_hex32(
                &self
                    .payload
                    .rules
                    .reward_destinations
                    .community_xonly_public_key,
            )?,
        })
    }

    /// Derive a new candidate identity while preserving all approved rules,
    /// dates, targets, artifact pins and the existing Steward destination.
    pub fn with_replacement_community(
        &self,
        community: [u8; 32],
    ) -> Result<Self, RcnetCandidateError> {
        let previous = self.reward_destinations()?;
        if community == previous.community || community == previous.steward {
            return Err(RcnetCandidateError::InvalidField(
                "replacement community destination",
            ));
        }
        let mut payload = self.payload.clone();
        payload.rules.reward_destinations.community_xonly_public_key = hex::encode(community);
        let digest = payload_digest(&payload)?;
        let candidate = Self {
            schema: self.schema.clone(),
            network_id: hex::encode(derive(MAINNET_NETWORK_DOMAIN, &digest)),
            launch_plan_digest: hex::encode(digest),
            payload,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn authenticate_genesis(
        &self,
        certificate: &BeaconCertificate,
        now_unix_seconds: u64,
    ) -> Result<AuthenticatedLaunch, Box<dyn std::error::Error>> {
        Ok(verify_mainnet_launch(
            self.digest()?,
            certificate,
            now_unix_seconds,
        )?)
    }

    pub(crate) fn profile_after_launch(
        &self,
        launch: &AuthenticatedLaunch,
    ) -> Result<crate::NetworkProfile, RcnetCandidateError> {
        if launch.launch_plan_digest() != self.digest()? || launch.round() != MAINNET_BEACON_ROUND {
            return Err(RcnetCandidateError::DerivedIdentityMismatch);
        }
        Ok(crate::NetworkProfile {
            kind: crate::NetworkProfileKind::Mainnet,
            proof: crate::ProofProfile::ProductionV4,
            name: MAINNET_PROFILE,
            network_id: self.network_id()?,
            virtual_genesis_hash: launch.genesis_hash(),
            virtual_genesis_timestamp: MAINNET_LAUNCH_UNIX_SECONDS,
            pow_limit: decode_hex32(&self.payload.rules.proof_of_work.pow_limit)?,
            initial_target: Some(decode_hex32(&self.payload.initial_target)?),
            rewards: crate::network_profile::RewardDestinations {
                steward: decode_hex32(
                    &self
                        .payload
                        .rules
                        .reward_destinations
                        .steward_xonly_public_key,
                )?,
                community: decode_hex32(
                    &self
                        .payload
                        .rules
                        .reward_destinations
                        .community_xonly_public_key,
                )?,
            },
            rpc_port: 29_443,
            p2p_port: 29_444,
            pool_port: 29_445,
            bootstrap_ipv4: crate::network_profile::PRODUCTION_RC_SEED_IPV4,
            default_data_dir_identity: "commonfoundry-mainnet",
            wallet_data_dir_identity: "mainnet",
        })
    }

    /// Pre-launch packaging can check every fixed identity without inventing
    /// the future beacon-derived genesis hash or starting a chain database.
    pub(crate) fn validate_profile_template(
        &self,
        profile: crate::NetworkProfile,
    ) -> Result<(), RcnetCandidateError> {
        self.validate()?;
        if profile.kind != crate::NetworkProfileKind::Mainnet
            || profile.proof != crate::ProofProfile::ProductionV4
            || profile.network_id != self.network_id()?
            || profile.virtual_genesis_hash != [0; 32]
            || profile.virtual_genesis_timestamp != MAINNET_LAUNCH_UNIX_SECONDS
            || profile.pow_limit != decode_hex32(&self.payload.rules.proof_of_work.pow_limit)?
            || profile.initial_target != Some(decode_hex32(&self.payload.initial_target)?)
            || profile.rewards.steward
                != decode_hex32(
                    &self
                        .payload
                        .rules
                        .reward_destinations
                        .steward_xonly_public_key,
                )?
            || profile.rewards.community
                != decode_hex32(
                    &self
                        .payload
                        .rules
                        .reward_destinations
                        .community_xonly_public_key,
                )?
        {
            return Err(RcnetCandidateError::InvalidField(
                "compiled mainnet profile disagrees with launch plan",
            ));
        }
        Ok(())
    }
}

fn payload_digest(payload: &MainnetLaunchPayload) -> Result<[u8; 32], RcnetCandidateError> {
    let mut hash = Sha256::new();
    hash.update(PLAN_DOMAIN);
    hash.update(serde_json::to_vec(payload)?);
    Ok(hash.finalize().into())
}

pub fn write_mainnet_plan_create_new(
    path: &Path,
    plan: &MainnetLaunchPlan,
) -> Result<(), RcnetCandidateError> {
    let bytes = plan.canonical_json()?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> MainnetLaunchPlan {
        let rc = crate::RCNET1_PROFILE;
        MainnetLaunchPlan::from_release_artifacts(
            rc.pow_limit,
            rc.pow_limit,
            FixedRewardDestinations {
                steward: rc.rewards.steward,
                community: rc.rewards.community,
            },
        )
        .unwrap()
    }

    #[test]
    fn mainnet_plan_round_trips_and_cannot_be_confused_with_rcnet() {
        let plan = plan();
        let bytes = plan.canonical_json().unwrap();
        assert_eq!(
            MainnetLaunchPlan::parse_pinned(&bytes, plan.digest().unwrap()).unwrap(),
            plan
        );
        assert_ne!(plan.network_id().unwrap(), crate::RCNET1_PROFILE.network_id);
        assert!(serde_json::from_slice::<RcnetLaunchCandidate>(&bytes).is_err());
        assert_eq!(plan.payload.minimum_transaction_fee_atoms, 10_000_000);
        assert_eq!(
            plan.payload.rules.virtual_genesis_timestamp_unix_seconds,
            1_791_046_800
        );
    }

    #[test]
    fn alternative_rewards_and_target_require_a_new_release_pin() {
        let original = plan();
        let mut target = crate::RCNET1_PROFILE.pow_limit;
        target[1] ^= 1;
        let changed = MainnetLaunchPlan::from_release_artifacts(
            target,
            target,
            FixedRewardDestinations {
                steward: crate::RCNET1_PROFILE.rewards.community,
                community: crate::RCNET1_PROFILE.rewards.steward,
            },
        )
        .unwrap();
        assert_ne!(
            changed.network_id().unwrap(),
            original.network_id().unwrap()
        );
        assert!(
            MainnetLaunchPlan::parse_pinned(
                &changed.canonical_json().unwrap(),
                original.digest().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn policy_mutations_fail_even_with_recomputed_digests() {
        for field in 0..6 {
            let mut changed = plan();
            match field {
                0 => changed.payload.beacon.round -= 1,
                1 => changed.payload.source_release_unix_seconds += 1,
                2 => changed.payload.rules.virtual_genesis_timestamp_unix_seconds += 1,
                3 => changed.payload.minimum_transaction_fee_atoms = 0,
                4 => changed.payload.rules.artifacts.bank.sha256 = "01".repeat(32),
                5 => changed.payload.rules.profile = PROFILE_NAME.into(),
                _ => unreachable!(),
            }
            let digest = payload_digest(&changed.payload).unwrap();
            changed.launch_plan_digest = hex::encode(digest);
            changed.network_id = hex::encode(derive(MAINNET_NETWORK_DOMAIN, &digest));
            assert!(changed.validate().is_err());
        }
    }

    #[test]
    fn noncanonical_or_unpinned_plan_is_rejected() {
        let plan = plan();
        let bytes = plan.canonical_json().unwrap();
        let mut changed = bytes.clone();
        changed.push(b' ');
        assert!(MainnetLaunchPlan::parse_pinned(&changed, plan.digest().unwrap()).is_err());
        assert!(MainnetLaunchPlan::parse_pinned(&bytes, [0; 32]).is_err());
        assert!(
            MainnetLaunchPlan::parse_pinned(
                &vec![b' '; MAX_MAINNET_PLAN_BYTES + 1],
                plan.digest().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn initial_target_is_required_bounded_and_part_of_the_plan_identity() {
        let original = plan();
        let mut changed = original.clone();
        let initial = (((primitive_types::U256::one() << 246) / primitive_types::U256::from(5u8))
            - primitive_types::U256::one())
        .to_big_endian();
        changed.payload.initial_target = hex::encode(initial);
        let digest = payload_digest(&changed.payload).unwrap();
        changed.launch_plan_digest = hex::encode(digest);
        changed.network_id = hex::encode(derive(MAINNET_NETWORK_DOMAIN, &digest));
        changed.validate().unwrap();
        assert_ne!(changed.digest().unwrap(), original.digest().unwrap());
        assert_ne!(
            changed.network_id().unwrap(),
            original.network_id().unwrap()
        );
        assert!(
            MainnetLaunchPlan::parse_pinned(
                &changed.canonical_json().unwrap(),
                original.digest().unwrap()
            )
            .is_err()
        );
        for invalid in [[0; 32], [0xff; 32]] {
            let mut invalid_plan = changed.clone();
            invalid_plan.payload.initial_target = hex::encode(invalid);
            assert!(invalid_plan.validate().is_err());
        }
        let mut missing: serde_json::Value =
            serde_json::from_slice(&original.canonical_json().unwrap()).unwrap();
        missing["payload"]
            .as_object_mut()
            .unwrap()
            .remove("initial_target");
        assert!(serde_json::from_value::<MainnetLaunchPlan>(missing).is_err());
        let mut old_schema = original;
        old_schema.schema = "CMFD_MAINNET_LAUNCH_PLAN_V1".into();
        assert!(old_schema.validate().is_err());
    }

    #[test]
    fn compiled_template_must_match_both_difficulty_targets() {
        let rc = crate::RCNET1_PROFILE;
        let initial = (((primitive_types::U256::one() << 246) / primitive_types::U256::from(5u8))
            - primitive_types::U256::one())
        .to_big_endian();
        let candidate = MainnetLaunchPlan::from_release_artifacts(
            rc.pow_limit,
            initial,
            FixedRewardDestinations {
                steward: rc.rewards.steward,
                community: rc.rewards.community,
            },
        )
        .unwrap();
        let profile = crate::NetworkProfile {
            kind: crate::NetworkProfileKind::Mainnet,
            name: MAINNET_PROFILE,
            network_id: candidate.network_id().unwrap(),
            virtual_genesis_hash: [0; 32],
            virtual_genesis_timestamp: MAINNET_LAUNCH_UNIX_SECONDS,
            initial_target: Some(initial),
            ..rc
        };
        candidate.validate_profile_template(profile).unwrap();
        for changed in [
            crate::NetworkProfile {
                initial_target: None,
                ..profile
            },
            crate::NetworkProfile {
                initial_target: Some(rc.pow_limit),
                ..profile
            },
            crate::NetworkProfile {
                pow_limit: initial,
                ..profile
            },
        ] {
            assert!(candidate.validate_profile_template(changed).is_err());
        }
    }
}
