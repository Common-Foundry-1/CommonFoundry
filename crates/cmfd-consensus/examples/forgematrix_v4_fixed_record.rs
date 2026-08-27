use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use cmfd_consensus::{
    ForgeMatrixV4FixedArtifactRecordV1, ForgeMatrixV4FixedBankArtifactV1, ModelBankManifest,
    PRODUCTION_V2_BANKS, canonical_forgematrix_v4_fixed_artifact_record_json, verify_model_bank,
};

const HASH_CHUNK_BYTES: usize = 64 * 1024 * 1024;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let bank_path = PathBuf::from(args.next().context("missing model-bank path")?);
    let manifest_path = PathBuf::from(args.next().context("missing manifest path")?);
    let artifact_dir = PathBuf::from(args.next().context("missing artifact directory")?);
    ensure!(args.next().is_none(), "unexpected extra arguments");

    let manifest: ModelBankManifest = serde_json::from_reader(BufReader::new(
        File::open(&manifest_path)
            .with_context(|| format!("open manifest {}", manifest_path.display()))?,
    ))
    .context("decode trusted model-bank manifest")?;
    verify_model_bank(
        BufReader::with_capacity(
            HASH_CHUNK_BYTES,
            File::open(&bank_path)
                .with_context(|| format!("open model bank {}", bank_path.display()))?,
        ),
        &manifest,
    )
    .context("authenticate complete model bank with the consensus reader")?;

    let mut artifacts = Vec::with_capacity(PRODUCTION_V2_BANKS as usize);
    for bank in 0..PRODUCTION_V2_BANKS {
        let metadata_path = artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.json"));
        let artifact: ForgeMatrixV4FixedBankArtifactV1 = serde_json::from_reader(BufReader::new(
            File::open(&metadata_path)
                .with_context(|| format!("open bank metadata {}", metadata_path.display()))?,
        ))
        .context("decode fixed-bank metadata")?;
        ensure!(
            artifact.bank() == bank,
            "fixed-bank metadata is out of order"
        );

        verify_artifact(
            &artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.codeword")),
            artifact.codeword_bytes(),
            artifact.codeword_blake3(),
        )?;
        verify_artifact(
            &artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.tree")),
            artifact.tree_bytes(),
            artifact.tree_blake3(),
        )?;
        artifacts.push(artifact);
    }

    let artifacts: [ForgeMatrixV4FixedBankArtifactV1; PRODUCTION_V2_BANKS as usize] = artifacts
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong fixed-bank artifact count"))?;
    let record = ForgeMatrixV4FixedArtifactRecordV1::new(manifest, artifacts)?;
    let record_bytes = canonical_forgematrix_v4_fixed_artifact_record_json(&record)?;
    let record_path = artifact_dir.join("FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&record_path)
        .with_context(|| format!("create record {}", record_path.display()))?;
    let mut writer = BufWriter::new(file);
    writer.write_all(&record_bytes)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    println!(
        "fixed_artifact_record=VERIFIED path={} digest={}",
        record_path.display(),
        hex::encode(record.record_digest()),
    );
    Ok(())
}

fn verify_artifact(path: &Path, expected_bytes: u64, expected_digest: [u8; 32]) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open artifact {}", path.display()))?;
    ensure!(
        file.metadata()?.len() == expected_bytes,
        "artifact length mismatch for {}",
        path.display()
    );
    let mut reader = BufReader::with_capacity(HASH_CHUNK_BYTES, file);
    let mut buffer = vec![0_u8; HASH_CHUNK_BYTES];
    let mut hasher = blake3::Hasher::new();
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update_rayon(&buffer[..count]);
    }
    ensure!(
        hasher.finalize().as_bytes() == &expected_digest,
        "artifact digest mismatch for {}",
        path.display()
    );
    Ok(())
}
