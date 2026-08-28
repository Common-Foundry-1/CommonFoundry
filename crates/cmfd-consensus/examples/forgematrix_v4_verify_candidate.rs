use std::{fs::File, io::BufReader, path::PathBuf};

use anyhow::{Context, Result, ensure};
use cmfd_consensus::{
    BlockChallenge, BlockProof, ConsensusPowVerifier, FORGEMATRIX_V4_ALGORITHM_VERSION,
    FORGEMATRIX_V4_PROOF_VERSION, ForgeMatrixV4CandidateProof, ForgeMatrixV4FixedArtifactRecordV1,
    PRODUCTION_V4_TESTNET_NETWORK_ID, forgematrix_v4_challenge_digest,
    forgematrix_v4_proof::forgematrix_v4_final_activation_digest,
    forgematrix_v4_proof_codec::{
        FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES, decode_forgematrix_v4_transparent_proof,
    },
    forgematrix_v4_proof_system_digest, forgematrix_v4_work_digest,
};

const BANK_READER_BYTES: usize = 64 * 1024 * 1024;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let record_path = PathBuf::from(args.next().context("missing fixed-record path")?);
    let model_path = PathBuf::from(args.next().context("missing model-bank path")?);
    let proof_path = PathBuf::from(args.next().context("missing transparent-proof path")?);
    ensure!(args.next().is_none(), "unexpected extra arguments");

    let record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_reader(BufReader::new(File::open(record_path)?))?;
    let manifest_digest = record.manifest_digest();
    let verifier = ConsensusPowVerifier::v4_candidate(
        record,
        BufReader::with_capacity(BANK_READER_BYTES, File::open(model_path)?),
    )?;

    let transparent_proof = std::fs::read(proof_path)?;
    ensure!(
        transparent_proof.len() == FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
        "wrong complete-proof byte length"
    );
    let decoded = decode_forgematrix_v4_transparent_proof(&transparent_proof)?;
    let block = BlockChallenge {
        network_id: PRODUCTION_V4_TESTNET_NETWORK_ID,
        previous_block: [1; 32],
        transaction_root: [2; 32],
        height: 3,
        timestamp: 4,
        target: [0xff; 32],
    };
    let nonce = 6;
    let challenge_digest = forgematrix_v4_challenge_digest(&block, nonce, manifest_digest);
    let final_activation_digest =
        forgematrix_v4_final_activation_digest(challenge_digest, &decoded.final_activation);
    let work_digest =
        forgematrix_v4_work_digest(manifest_digest, challenge_digest, final_activation_digest);
    let proof = BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
        algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
        proof_version: FORGEMATRIX_V4_PROOF_VERSION,
        nonce,
        proof_system_digest: forgematrix_v4_proof_system_digest(),
        model_manifest_digest: manifest_digest,
        challenge_digest,
        final_activation_digest,
        work_digest,
        transparent_proof,
    }));

    verifier.verify(&block, &proof)?;
    println!(
        "common_v4_candidate_verifier=VERIFIED proof_bytes={} work_digest={}",
        FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
        hex::encode(proof.work_digest())
    );
    Ok(())
}
