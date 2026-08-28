use std::{fs::File, path::PathBuf};

use anyhow::{Context, Result, ensure};
use cmfd_consensus::{
    BlockChallenge, ForgeMatrixV4FixedArtifactRecordV1, PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
    forgematrix_v4_challenge_digest, forgematrix_v4_proof::forgematrix_v4_mask_coefficients,
};
use serde::Deserialize;

const PRODUCTION_LAYERS: u32 = 384;

#[derive(Deserialize)]
struct FrozenProductionV4Template {
    challenge: BlockChallenge,
    nonce: u64,
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let template_path = PathBuf::from(args.next().context("missing frozen V4 template")?);
    let fixed_record_path = PathBuf::from(args.next().context("missing fixed artifact record")?);
    let output = PathBuf::from(args.next().context("missing coefficient output")?);
    ensure!(args.next().is_none(), "unexpected extra arguments");

    let template: FrozenProductionV4Template = serde_json::from_reader(File::open(template_path)?)?;
    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 =
        serde_json::from_reader(File::open(fixed_record_path)?)?;
    ensure!(
        fixed_record.record_digest() == PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
        "fixed artifact record is not the compiled V4 testnet record"
    );
    let challenge = forgematrix_v4_challenge_digest(
        &template.challenge,
        template.nonce,
        fixed_record.manifest_digest(),
    );
    let mut coefficients = Vec::with_capacity((PRODUCTION_LAYERS as usize + 1) * 20);
    coefficients.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, u32::MAX));
    for layer in 0..PRODUCTION_LAYERS {
        coefficients.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge, layer));
    }
    std::fs::write(&output, &coefficients).context("write replay coefficients")?;
    println!(
        "challenge_digest={} coefficient_bytes={} blake3={}",
        hex::encode(challenge),
        coefficients.len(),
        blake3::hash(&coefficients).to_hex()
    );
    Ok(())
}
