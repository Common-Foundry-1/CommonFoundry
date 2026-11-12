use super::*;
use crate::compact_mainnet_fork::*;
use crate::{ChainState, DEFAULT_MONETARY_POLICY, FixedRewardDestinations, NetworkParams};

pub(crate) fn params() -> NetworkParams {
    let plan: serde_json::Value =
        serde_json::from_str(include_str!("../../../packaging/mainnet/MAINNET-PLAN.json")).unwrap();
    let p = &plan["payload"];
    let hash = |value: &serde_json::Value| -> [u8; 32] {
        hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    NetworkParams {
        network_id: COMPACT_MAINNET_NETWORK_ID,
        protocol_version: 2,
        genesis_hash: hex::decode(
            "d8c9baa3b5a93f9ed0cbaa6a62e536b6df3f319dfeb2c72f49f88d684a6fdfe4",
        )
        .unwrap()
        .try_into()
        .unwrap(),
        genesis_timestamp: p["rules"]["virtual_genesis_timestamp_unix_seconds"]
            .as_u64()
            .unwrap(),
        pow_limit: hash(&p["rules"]["proof_of_work"]["pow_limit"]),
        initial_target: Some(hash(&p["initial_target"])),
        pow: PowParameters::V4Candidate(
            ForgeMatrixV4CandidateParameters::for_network(COMPACT_MAINNET_NETWORK_ID).unwrap(),
        ),
        monetary_policy: DEFAULT_MONETARY_POLICY,
        rewards: FixedRewardDestinations {
            steward: hash(&p["rules"]["reward_destinations"]["steward_xonly_public_key"]),
            community: hash(&p["rules"]["reward_destinations"]["community_xonly_public_key"]),
        },
        max_future_offset_secs: crate::MAX_FUTURE_OFFSET_SECS,
    }
}

#[test]
fn compact_mainnet_runtime_identity_is_exact_and_rejects_parameter_drift() {
    let p = params();
    assert_eq!(
        hex::encode(p.fingerprint().unwrap()),
        COMPACT_MAINNET_FINGERPRINT_HEX
    );
    let mut old = p;
    let PowParameters::V4Candidate(v4) = p.pow else {
        unreachable!()
    };
    old.pow = PowParameters::V4Candidate(v4.legacy_parameters());
    assert_eq!(
        old.fingerprint().unwrap(),
        COMPACT_MAINNET_PREDECESSOR_FINGERPRINT
    );
    let mut changed = p;
    changed.genesis_hash[0] ^= 1;
    assert!(changed.fingerprint().is_err());
    changed = p;
    changed.rewards.steward[0] ^= 1;
    assert!(changed.fingerprint().is_err());
}

#[test]
fn compact_mainnet_proof_version_boundary_is_checked_before_relation_dispatch() {
    let p = params();
    let PowParameters::V4Candidate(v4) = p.pow else {
        unreachable!()
    };
    let verifier = ConsensusPowVerifier::v4_local_state_fixture(v4);
    for (height, version, accepted) in [
        (65535, 1, true),
        (65535, 2, false),
        (67534, 1, true),
        (67534, 2, false),
        (67535, 1, false),
        (67535, 2, true),
        (67536, 1, false),
        (67536, 2, true),
    ] {
        let block = BlockChallenge {
            network_id: p.network_id,
            previous_block: [2; 32],
            transaction_root: [3; 32],
            height,
            timestamp: p.genesis_timestamp + height * 60,
            target: [0xff; 32],
        };
        let challenge = forgematrix_v4_challenge_digest(&block, 7, v4.model_manifest_digest());
        let final_activation_digest = [9; 32];
        let proof = BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
            algorithm_version: 4,
            proof_version: version,
            nonce: 7,
            proof_system_digest: if version == 2 {
                compact_mainnet_proof_system_digest()
            } else {
                forgematrix_v4_proof_system_digest()
            },
            model_manifest_digest: v4.model_manifest_digest(),
            challenge_digest: challenge,
            final_activation_digest,
            work_digest: forgematrix_v4_work_digest(
                v4.model_manifest_digest(),
                challenge,
                final_activation_digest,
            ),
            transparent_proof: vec![
                0;
                if version == 1 {
                    FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES
                } else {
                    2_200_000
                }
            ],
        }));
        assert_eq!(
            verifier.preflight(&block, &proof).is_ok(),
            accepted,
            "height {height}, version {version}"
        );
        if !accepted {
            assert!(verifier.verify(&block, &proof).is_err());
        }
    }
    if let ConsensusPowVerifier::V4Candidate(instance) = &verifier {
        assert_eq!(instance.relation_dispatches(), 0);
    }
}

#[test]
fn compact_mainnet_preserves_history_and_caps_future_frames() {
    let p = params();
    assert!(
        p.accepts_history_fingerprint(COMPACT_MAINNET_PREDECESSOR_FINGERPRINT, 67534)
            .unwrap()
    );
    assert!(
        !p.accepts_history_fingerprint(COMPACT_MAINNET_PREDECESSOR_FINGERPRINT, 67535)
            .unwrap()
    );
    assert!(!p.accepts_history_fingerprint([0x77; 32], 0).unwrap());
    assert_eq!(
        crate::wire::max_proof_bytes_at_height(p.network_id, 67534),
        13 * 1024 * 1024
    );
    assert_eq!(
        crate::wire::max_proof_bytes_at_height(p.network_id, 67535),
        6_100_000
    );
    let rule = crate::forgematrix_v4_work_rule(p.network_id).unwrap();
    assert!(rule.requires_recomputation(67534));
    assert!(!rule.requires_recomputation(67535));
    assert!(!rule.requires_recomputation(67536));
}

#[test]
fn compact_mainnet_imports_exact_legacy_local_state_and_writes_new_identity() {
    let p = params();
    let PowParameters::V4Candidate(v4) = p.pow else {
        unreachable!()
    };
    let mut old = p;
    old.pow = PowParameters::V4Candidate(v4.legacy_parameters());
    let old_verifier = ConsensusPowVerifier::v4_local_state_fixture(v4.legacy_parameters());
    let new_verifier = ConsensusPowVerifier::v4_local_state_fixture(v4);
    let state = ChainState::new(old, old_verifier.clone()).unwrap();
    let bytes = state.encode_local_snapshot().unwrap();
    let imported = ChainState::decode_local_snapshot(&bytes, p, new_verifier).unwrap();
    assert_eq!(imported.tip(), state.tip());
    assert_eq!(imported.next_height(), 1);
    assert_eq!(
        imported.params().fingerprint().unwrap(),
        p.fingerprint().unwrap()
    );
    let new_bytes = imported.encode_local_snapshot().unwrap();
    assert_ne!(new_bytes, bytes);
    assert!(ChainState::decode_local_snapshot(&new_bytes, old, old_verifier).is_err());
    let successor = crate::SuccessorHeaderPreflight::decode_local_snapshot(
        &state
            .successor_header_preflight()
            .unwrap()
            .encode_local_snapshot()
            .unwrap(),
        p,
    )
    .unwrap();
    assert_eq!(successor, imported.successor_header_preflight().unwrap());
}

#[test]
fn compact_mainnet_and_testnet_use_distinct_compact_statement_domains() {
    assert_eq!(
        crate::forgematrix_v4::forgematrix_v4_direct_proof_system_digest_for_network(
            COMPACT_MAINNET_NETWORK_ID
        ),
        Some(compact_mainnet_proof_system_digest())
    );
    assert_ne!(
        Some(compact_mainnet_proof_system_digest()),
        crate::forgematrix_v4::forgematrix_v4_direct_proof_system_digest_for_network(
            crate::FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID
        )
    );
    assert_eq!(
        crate::forgematrix_v4::forgematrix_v4_direct_proof_system_digest_for_network([0x77; 32]),
        None
    );
}
