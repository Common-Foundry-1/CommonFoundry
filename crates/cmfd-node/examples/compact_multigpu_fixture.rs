//! Export a public compact-testnet winner as deterministic GPU qualification inputs.
use cmfd_consensus::{
    BlockProof, FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID, ForgeMatrixV4FixedArtifactRecordV1,
    PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST, decode_block, encode_block,
    forgematrix_v4_challenge_digest, forgematrix_v4_final_activation_digest_from_le_bytes,
    forgematrix_v4_proof::forgematrix_v4_mask_coefficients, forgematrix_v4_work_digest,
};
use std::{fs, path::PathBuf};

#[derive(serde::Deserialize)]
struct Frozen {
    challenge: cmfd_consensus::BlockChallenge,
    nonce: u64,
}

fn fixed(path: &str) -> Result<ForgeMatrixV4FixedArtifactRecordV1, Box<dyn std::error::Error>> {
    let record: ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_slice(&fs::read(path)?)?;
    record.validate()?;
    if record.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        return Err("wrong fixed record".into());
    }
    Ok(record)
}
fn coefficients(
    block: &cmfd_consensus::BlockChallenge,
    nonce: u64,
    record: &ForgeMatrixV4FixedArtifactRecordV1,
) -> Vec<u8> {
    let challenge = forgematrix_v4_challenge_digest(block, nonce, record.manifest_digest());
    let mut output = Vec::new();
    output.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, u32::MAX));
    for layer in 0..384 {
        output.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, layer));
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 6 && args[0] == "--nonce-input" {
        let block = decode_block(
            &fs::read(&args[1])?,
            FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID,
        )?;
        let record = fixed(&args[2])?;
        let nonce = args[3].parse::<u64>()?;
        fs::write(
            &args[4],
            serde_json::to_vec(&serde_json::json!({"challenge":block.challenge,"nonce":nonce}))?,
        )?;
        fs::write(&args[5], coefficients(&block.challenge, nonce, &record))?;
        return Ok(());
    }
    if args.len() == 4 && args[0] == "--check-replay" {
        let frozen: Frozen = serde_json::from_slice(&fs::read(&args[1])?)?;
        let record = fixed(&args[2])?;
        if frozen.challenge.network_id != FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID {
            return Err("wrong network".into());
        }
        let challenge = forgematrix_v4_challenge_digest(
            &frozen.challenge,
            frozen.nonce,
            record.manifest_digest(),
        );
        let final_digest =
            forgematrix_v4_final_activation_digest_from_le_bytes(challenge, &fs::read(&args[3])?)?;
        let work = forgematrix_v4_work_digest(record.manifest_digest(), challenge, final_digest);
        println!(
            "{}",
            serde_json::json!({"meets_target":work<=frozen.challenge.target,"nonce":frozen.nonce,"work_digest":hex::encode(work),"challenge_digest":hex::encode(challenge),"final_activation_digest":hex::encode(final_digest)})
        );
        return Ok(());
    }
    if args.len() == 7 && args[0] == "--replace-proof-with-replay" {
        let mut block = decode_block(
            &fs::read(&args[1])?,
            FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID,
        )?;
        let frozen: Frozen = serde_json::from_slice(&fs::read(&args[2])?)?;
        let record = fixed(&args[3])?;
        block.challenge = frozen.challenge;
        let BlockProof::V4Candidate(candidate) = &mut block.proof else {
            return Err("not V4".into());
        };
        candidate.nonce = frozen.nonce;
        candidate.model_manifest_digest = record.manifest_digest();
        candidate.challenge_digest = forgematrix_v4_challenge_digest(
            &frozen.challenge,
            frozen.nonce,
            record.manifest_digest(),
        );
        candidate.final_activation_digest = forgematrix_v4_final_activation_digest_from_le_bytes(
            candidate.challenge_digest,
            &fs::read(&args[4])?,
        )?;
        candidate.work_digest = forgematrix_v4_work_digest(
            record.manifest_digest(),
            candidate.challenge_digest,
            candidate.final_activation_digest,
        );
        candidate.transparent_proof = fs::read(&args[5])?;
        let mut out = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&args[6])?;
        std::io::Write::write_all(&mut out, &encode_block(&block)?)?;
        return Ok(());
    }
    if args.len() == 4 && args[0] == "--replace-proof" {
        let mut block = decode_block(
            &fs::read(&args[1])?,
            FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID,
        )?;
        let BlockProof::V4Candidate(candidate) = &mut block.proof else {
            return Err("not a V4 block".into());
        };
        candidate.transparent_proof = fs::read(&args[2])?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&args[3])?;
        std::io::Write::write_all(&mut file, &encode_block(&block)?)?;
        return Ok(());
    }
    if args.len() != 3 {
        return Err(
            "usage: compact_multigpu_fixture PUBLIC_BLOCK FIXED_RECORD NEW_OUTPUT_DIR".into(),
        );
    }
    let block = decode_block(
        &fs::read(&args[0])?,
        FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID,
    )?;
    let BlockProof::V4Candidate(candidate) = &block.proof else {
        return Err("not a V4 block".into());
    };
    let fixed: ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_slice(&fs::read(&args[1])?)?;
    fixed.validate()?;
    if fixed.record_digest() != PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST {
        return Err("wrong fixed record".into());
    }
    let challenge =
        forgematrix_v4_challenge_digest(&block.challenge, candidate.nonce, fixed.manifest_digest());
    let out = PathBuf::from(&args[2]);
    fs::create_dir(&out)?;
    fs::write(
        out.join("template.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"challenge":block.challenge,"nonce":candidate.nonce}),
        )?,
    )?;
    let mut coefficients = Vec::new();
    coefficients.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, u32::MAX));
    for layer in 0..384 {
        coefficients.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, layer));
    }
    fs::write(out.join("coefficients.bin"), coefficients)?;
    // The expected full packet is independently verified by the CPU receiver.
    println!(
        "public fixture exported height={} nonce={}",
        block.challenge.height, candidate.nonce
    );
    Ok(())
}
