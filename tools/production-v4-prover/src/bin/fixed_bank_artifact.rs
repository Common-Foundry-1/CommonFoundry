use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{bail, ensure, Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use slop_algebra::{AbstractField, PrimeField32};
use slop_alloc::Buffer;
use slop_basefold::FriConfig;
use slop_challenger::IopCtx;
use slop_tensor::Tensor;
use sp1_gpu_basefold::FriCudaProver;
use sp1_gpu_commit::commit_multilinears;
use sp1_gpu_cudart::{run_sync_in_place, DeviceBuffer, DeviceTensor};
use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
use sp1_gpu_utils::{AbstractChipLayoutWithHeights, Felt, JaggedTraceMle, TestGC};

const LOG_ROWS: u32 = 23;
const ROWS: usize = 1 << LOG_ROWS;
const FIXED_COLUMNS: usize = 256;
const LOG_BLOWUP: usize = 1;
const QUERIES: usize = 270;
const POW_BITS: usize = 16;
const READ_CHUNK_BYTES: usize = 64 * 1024 * 1024;
const MODEL_BANK_HEADER_BYTES: usize = 184;
const PRODUCTION_BANKS: u32 = 3;
const PRODUCTION_LAYERS_PER_BANK: u32 = 128;
const PRODUCTION_DIMENSION: u32 = 4096;
const PRODUCTION_BATCH: u32 = 128;
const PRODUCTION_LAYERS: u32 = 384;
const FIXED_CODEWORD_BYTES: u64 = 17_179_869_184;
const FIXED_TREE_BYTES: u64 = 1_073_741_792;
const RELEASED_BANK_SHA256: [u8; 32] = [
    0x5f, 0x9b, 0x21, 0x3c, 0x3b, 0xda, 0x51, 0xb7, 0x4e, 0x4e, 0xba, 0xbb, 0x26, 0x60, 0x7b, 0x67,
    0x38, 0x5d, 0x61, 0x3a, 0xa8, 0xd9, 0x9a, 0xf9, 0x15, 0xa4, 0x8a, 0xb0, 0x63, 0xe1, 0x7d, 0x4e,
];

type Digest = <TestGC as IopCtx>::Digest;

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelBankManifest {
    model_version: u32,
    dimension: u32,
    batch: u32,
    layers: u32,
    base_input_bytes: u64,
    bytes_per_layer: u64,
    payload_bytes: u64,
    raw_blake3_root: [u8; 32],
    layer_roots_aggregate: [u8; 32],
    pcs_parameter_digest: [u8; 32],
    pcs_commitment_root: [u8; 32],
}

#[derive(Serialize)]
struct FixedBankRecord {
    bank: u32,
    commitment: [u32; 8],
    merkle_root: [u32; 8],
    codeword_bytes: u64,
    tree_bytes: u64,
    codeword_blake3: [u8; 32],
    tree_blake3: [u8; 32],
}

struct HostArtifact {
    commitment: Digest,
    merkle_root: Digest,
    codeword: Tensor<Felt>,
    tree: Vec<Digest>,
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let bank_path = PathBuf::from(args.next().context("missing model-bank path")?);
    let manifest_path = PathBuf::from(args.next().context("missing manifest path")?);
    let output_dir = PathBuf::from(args.next().context("missing output directory")?);
    ensure!(args.next().is_none(), "unexpected extra arguments");
    ensure!(
        std::env::var_os("CMFD_BASEFOLD_FULL_TREE").is_some(),
        "CMFD_BASEFOLD_FULL_TREE must be set"
    );
    fs::create_dir(&output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;

    let manifest: ModelBankManifest = serde_json::from_reader(BufReader::new(
        File::open(&manifest_path)
            .with_context(|| format!("open manifest {}", manifest_path.display()))?,
    ))
    .context("decode trusted model-bank manifest")?;

    validate_manifest(manifest)?;
    let verify_started = Instant::now();
    let bank_sha256 = sha256_file(&bank_path)?;
    ensure!(
        bank_sha256 == RELEASED_BANK_SHA256,
        "model bank is not the released Devnet-15 bank"
    );
    eprintln!(
        "model_bank_verified_seconds={:.6} sha256={}",
        verify_started.elapsed().as_secs_f64(),
        hex::encode(bank_sha256),
    );

    for bank in 0..PRODUCTION_BANKS {
        let fields_started = Instant::now();
        let fields = read_bank_fields(&bank_path, &manifest, bank)?;
        eprintln!(
            "bank={bank} field_load_seconds={:.6} fields={}",
            fields_started.elapsed().as_secs_f64(),
            fields.len(),
        );

        let gpu_started = Instant::now();
        let artifact = build_host_artifact(bank, fields)?;
        eprintln!(
            "bank={bank} gpu_commit_and_copy_seconds={:.6}",
            gpu_started.elapsed().as_secs_f64(),
        );

        let codeword_path = output_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.codeword"));
        let tree_path = output_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.tree"));
        let codeword_bytes = raw_bytes(artifact.codeword.as_slice());
        let tree_bytes = raw_bytes(&artifact.tree);
        ensure!(
            codeword_bytes.len() as u64 == FIXED_CODEWORD_BYTES,
            "unexpected codeword length"
        );
        ensure!(
            tree_bytes.len() as u64 == FIXED_TREE_BYTES,
            "unexpected tree length"
        );

        let write_started = Instant::now();
        let codeword_blake3 = write_hashed_file(&codeword_path, codeword_bytes)?;
        let tree_blake3 = write_hashed_file(&tree_path, tree_bytes)?;
        eprintln!(
            "bank={bank} artifact_write_seconds={:.6} codeword_blake3={} tree_blake3={}",
            write_started.elapsed().as_secs_f64(),
            hex::encode(codeword_blake3),
            hex::encode(tree_blake3),
        );

        let bank_record = FixedBankRecord {
            bank,
            commitment: digest_words(artifact.commitment),
            merkle_root: digest_words(artifact.merkle_root),
            codeword_bytes: FIXED_CODEWORD_BYTES,
            tree_bytes: FIXED_TREE_BYTES,
            codeword_blake3,
            tree_blake3,
        };
        let bank_record_path = output_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.json"));
        let mut bank_json = serde_json::to_vec_pretty(&bank_record)?;
        bank_json.push(b'\n');
        write_new_file(&bank_record_path, &bank_json)?;
    }
    eprintln!("fixed_artifacts=GENERATED output={}", output_dir.display());
    Ok(())
}

fn read_bank_fields(path: &Path, manifest: &ModelBankManifest, bank: u32) -> Result<Vec<Felt>> {
    ensure!(bank < PRODUCTION_BANKS, "bank index out of range");
    let bank_bytes = u64::from(PRODUCTION_LAYERS_PER_BANK)
        .checked_mul(manifest.bytes_per_layer)
        .context("bank byte length overflow")?;
    ensure!(
        bank_bytes as usize == FIXED_COLUMNS * ROWS,
        "fixed trace shape does not match model bank"
    );
    let offset = (MODEL_BANK_HEADER_BYTES as u64)
        .checked_add(manifest.base_input_bytes)
        .and_then(|value| value.checked_add(u64::from(bank) * bank_bytes))
        .context("bank offset overflow")?;
    let mut reader = BufReader::with_capacity(
        READ_CHUNK_BYTES,
        File::open(path).with_context(|| format!("open model bank {}", path.display()))?,
    );
    reader.seek(SeekFrom::Start(offset))?;

    let field_count = usize::try_from(bank_bytes).context("bank field count does not fit usize")?;
    let mut fields = vec![Felt::zero(); field_count];
    let mut encoded = vec![0_u8; READ_CHUNK_BYTES];
    let mut completed = 0;
    while completed < field_count {
        let take = (field_count - completed).min(encoded.len());
        reader.read_exact(&mut encoded[..take])?;
        let output = &mut fields[completed..completed + take];
        output
            .par_iter_mut()
            .zip(encoded[..take].par_iter())
            .try_for_each(|(field, &value)| -> Result<(), u8> {
                if value > 250 {
                    return Err(value);
                }
                *field = if value >= 125 {
                    Felt::from_canonical_u32(u32::from(value - 125))
                } else {
                    -Felt::from_canonical_u32(u32::from(125 - value))
                };
                Ok(())
            })
            .map_err(|value| anyhow::anyhow!("out-of-range model byte {value}"))?;
        completed += take;
    }
    fields.resize(field_count + ROWS, Felt::zero());
    Ok(fields)
}

fn validate_manifest(manifest: ModelBankManifest) -> Result<()> {
    let dimension = u64::from(PRODUCTION_DIMENSION);
    let expected_base = u64::from(PRODUCTION_BATCH) * dimension;
    let expected_layer = dimension * dimension;
    let expected_payload = expected_base + u64::from(PRODUCTION_LAYERS) * expected_layer;
    ensure!(manifest.model_version == 2, "unexpected model version");
    ensure!(
        manifest.dimension == PRODUCTION_DIMENSION,
        "unexpected model dimension"
    );
    ensure!(manifest.batch == PRODUCTION_BATCH, "unexpected model batch");
    ensure!(
        manifest.layers == PRODUCTION_LAYERS,
        "unexpected model layer count"
    );
    ensure!(
        manifest.base_input_bytes == expected_base,
        "unexpected base-input length"
    );
    ensure!(
        manifest.bytes_per_layer == expected_layer,
        "unexpected layer length"
    );
    ensure!(
        manifest.payload_bytes == expected_payload,
        "unexpected payload length"
    );
    ensure!(manifest.raw_blake3_root != [0; 32], "zero raw model root");
    ensure!(
        manifest.layer_roots_aggregate != [0; 32],
        "zero layer aggregate"
    );
    ensure!(
        manifest.pcs_parameter_digest != [0; 32],
        "zero PCS parameter digest"
    );
    ensure!(
        manifest.pcs_commitment_root != [0; 32],
        "zero PCS commitment root"
    );
    Ok(())
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.len() == MODEL_BANK_HEADER_BYTES as u64 + 6_442_975_232,
        "unexpected model-bank file length"
    );
    let mut reader = BufReader::with_capacity(READ_CHUNK_BYTES, File::open(path)?);
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut hasher = Sha256::new();
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn build_host_artifact(bank: u32, fields: Vec<Felt>) -> Result<HostArtifact> {
    let layout = AbstractChipLayoutWithHeights::new(vec![(
        format!("fixed-bank-{bank}"),
        FIXED_COLUMNS,
        0,
        ROWS,
    )]);
    let host_trace = JaggedTraceMle::from_chip_layout(Buffer::from(fields), &layout, LOG_ROWS);
    Ok(run_sync_in_place(move |scope| {
        let device_trace = host_trace.into_device(&scope);
        let prover = FriCudaProver::<TestGC, _, Felt>::new(
            Poseidon2SP1Field16CudaProver::new(&scope),
            FriConfig::new(LOG_BLOWUP, QUERIES, POW_BITS),
            LOG_ROWS,
        );
        let (_, mut fixed_data) =
            commit_multilinears::<TestGC, _>(&device_trace, LOG_ROWS, true, false, &prover)
                .unwrap();
        scope.synchronize_blocking().unwrap();
        drop(device_trace);

        let commitment = fixed_data.original_commitment;
        let merkle_root = fixed_data.pcs_prover_data.merkle_tree_tcs_data.1;
        let codeword = fixed_data
            .pcs_prover_data
            .codeword_mle
            .take()
            .and_then(|codeword| Arc::try_unwrap(codeword).ok())
            .unwrap();
        let codeword = DeviceTensor::from_raw(codeword).to_host().unwrap();
        let tree = fixed_data.pcs_prover_data.merkle_tree_tcs_data.0;
        assert_eq!(tree.height, 24);
        assert_eq!(tree.stored_height, tree.height);
        let tree = DeviceBuffer::from_raw(tree.digests).to_host().unwrap();
        scope.synchronize_blocking().unwrap();
        HostArtifact {
            commitment,
            merkle_root,
            codeword,
            tree,
        }
    })?)
}

fn digest_words(digest: Digest) -> [u32; 8] {
    digest.map(|value| value.as_canonical_u32())
}

fn raw_bytes<T>(values: &[T]) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), std::mem::size_of_val(values))
    }
}

fn write_hashed_file(path: &Path, bytes: &[u8]) -> Result<[u8; 32]> {
    let digest = blake3::Hasher::new().update_rayon(bytes).finalize();
    write_new_file(path, bytes)?;
    Ok(*digest.as_bytes())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::with_capacity(16 * 1024 * 1024, file);
    writer.write_all(bytes)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    if writer.get_ref().metadata()?.len() != bytes.len() as u64 {
        bail!("short artifact write for {}", path.display());
    }
    Ok(())
}
