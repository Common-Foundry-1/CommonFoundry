//! Offline complete proof checking and opt-in work auditing. No node data,
//! wallet, peer, pool ledger or admission decision is mutated by this command.
use super::*;
use cmfd_consensus::forgematrix_v4_proof::forgematrix_v4_final_activation_digest;
use cmfd_consensus::forgematrix_v4_proof_codec::decode_forgematrix_v4_transparent_proof;
use cmfd_consensus::{
    ForgeMatrixV4CandidateProof, forgematrix_v4_challenge_digest, forgematrix_v4_work_digest,
};

pub fn check(
    artifacts: &ProductionV4VerifierArtifacts,
    template: &[u8],
    packet: &[u8],
    audit_threads: Option<usize>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct Header {
        format_version: u16,
        challenge: BlockChallenge,
        nonce: u64,
    }
    let header: Header = serde_json::from_slice(template)?;
    if header.format_version != 1
        || header.challenge.network_id
            != cmfd_consensus::compact_mainnet_fork::COMPACT_MAINNET_NETWORK_ID
    {
        return Err("template does not identify the pinned mainnet".into());
    }
    let runtime = mainnet_runtime::compiled_mainnet_runtime()?;
    let (params, verifier, bank) = network_params_verifier_and_work_bank_with_launch(
        runtime.profile(),
        None,
        Some(artifacts),
        Some(runtime),
    )?;
    if header.challenge.target == [0; 32] || header.challenge.target > params.pow_limit {
        return Err("template target violates the mainnet proof-of-work limit".into());
    }
    let PowParameters::V4Candidate(v4) = params.pow else {
        return Err("a V4 verifier is required".into());
    };
    let challenge = forgematrix_v4_challenge_digest(
        &header.challenge,
        header.nonce,
        v4.model_manifest_digest(),
    );
    let final_activation_digest = if v4.uses_direct_proof_at_height(header.challenge.height) {
        cmfd_consensus::forgematrix_v4_direct::final_activation_digest_from_packet(
            challenge, packet,
        )?
    } else {
        forgematrix_v4_final_activation_digest(
            challenge,
            &decode_forgematrix_v4_transparent_proof(packet)?.final_activation,
        )
    };
    let work = forgematrix_v4_work_digest(
        v4.model_manifest_digest(),
        challenge,
        final_activation_digest,
    );
    let proof = BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
        algorithm_version: v4.algorithm_version(),
        proof_version: v4.proof_version_at_height(header.challenge.height),
        nonce: header.nonce,
        proof_system_digest: v4.proof_system_digest_at_height(header.challenge.height),
        model_manifest_digest: v4.model_manifest_digest(),
        challenge_digest: challenge,
        final_activation_digest,
        work_digest: work,
        transparent_proof: packet.to_vec(),
    }));
    verifier.verify(&header.challenge, &proof)?;
    let mut report = json!({"scope":"complete proof only; parent, transactions and chain admission are separate",
        "proof_valid":true,"height":header.challenge.height,"proof_version":v4.proof_version_at_height(header.challenge.height),
        "proof_system_digest":hex::encode(v4.proof_system_digest_at_height(header.challenge.height)),
        "consensus_fingerprint":hex::encode(params.fingerprint()?),"packet_bytes":packet.len(),
        "work_digest":hex::encode(work),"work_replay_performed":false,
        "additional_legacy_work_replay_required_for_admission":header.challenge.height<cmfd_consensus::compact_mainnet_fork::COMPACT_MAINNET_ACTIVATION_HEIGHT,
        "node_data_modified":false});
    if let Some(threads) = audit_threads {
        use cmfd_consensus::forgematrix_v4_execution::{
            ForgeMatrixV4FileLayerSource, forgematrix_v4_execute_challenge,
        };
        let bank = bank.ok_or("authenticated work bank unavailable")?;
        let source = ForgeMatrixV4FileLayerSource::new(
            bank.file,
            &bank.identity.manifest,
            bank.identity.base_input,
            bank.identity.layer_roots,
        )?;
        let replay = forgematrix_v4_execute_challenge(challenge, &source, threads, true)?;
        report["work_replay_performed"] = json!(true);
        report["audit_matches"] = json!(
            replay.work_digest == work && replay.final_activation_digest == final_activation_digest
        );
        if replay.work_digest != work || replay.final_activation_digest != final_activation_digest {
            return Err("independent work audit differs from the proof".into());
        }
    }
    Ok(report)
}
