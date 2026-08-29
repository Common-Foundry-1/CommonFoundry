use std::{fs::File, path::PathBuf, time::Instant};

use anyhow::{ensure, Context, Result};
use memmap2::MmapOptions;
use rayon::prelude::*;
use serde::Serialize;
use slop_algebra::{AbstractField, PrimeField32};
use slop_alloc::Buffer;
use slop_basefold::FriConfig;
use sp1_core_machine::utils::setup_logger;
use sp1_gpu_basefold::FriCudaProver;
use sp1_gpu_commit::commit_multilinears;
use sp1_gpu_cudart::{cuda_memory_info, run_sync_in_place, TaskScope};
use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
use sp1_gpu_utils::{AbstractChipLayoutWithHeights, Felt, JaggedTraceMle, TestGC};

const BANKS: usize = 3;
const LOG_ROWS: u32 = 23;
const ROWS: usize = 1 << LOG_ROWS;
const DYNAMIC_COLUMNS: usize = 16;
const TRACE_BYTES: usize = DYNAMIC_COLUMNS * ROWS * size_of::<u32>();
const LOG_BLOWUP: usize = 1;
const QUERIES: usize = 270;
const POW_BITS: usize = 16;
const MODULUS: u32 = 0x7f00_0001;

#[derive(Serialize)]
struct DynamicCommitmentRecord {
    version: u32,
    encoding: &'static str,
    banks: Vec<DynamicBankRecord>,
}

#[derive(Serialize)]
struct DynamicBankRecord {
    bank: usize,
    trace_path: String,
    trace_bytes: usize,
    trace_blake3: String,
    commitment_words: [u32; 8],
    commit_seconds: f64,
    peak_allocated_gib: f64,
}

fn main() -> Result<()> {
    setup_logger();
    let mut args = std::env::args_os().skip(1);
    let prefix = PathBuf::from(args.next().context("missing replay trace prefix")?);
    let output = PathBuf::from(args.next().context("missing output record path")?);
    ensure!(args.next().is_none(), "unexpected extra arguments");

    let mut banks = Vec::with_capacity(BANKS);
    for bank in 0..BANKS {
        let path = PathBuf::from(format!("{}-bank{bank}-dynamic.bin", prefix.display()));
        let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        ensure!(
            file.metadata()?.len() == TRACE_BYTES as u64,
            "wrong dynamic trace length"
        );
        let map = unsafe { MmapOptions::new().map(&file)? };
        let mut trace_hasher = blake3::Hasher::new();
        trace_hasher.update_rayon(&map);
        let trace_blake3 = trace_hasher.finalize().to_hex().to_string();
        let values = montgomery_values(&map)?;
        let (commitment_words, commit_seconds, peak_allocated_gib) =
            run_sync_in_place(move |scope| commit_bank(bank, values, scope))??;
        eprintln!(
            "bank={bank} commitment={commitment_words:?} commit_seconds={commit_seconds:.6} peak_allocated_gib={peak_allocated_gib:.3}"
        );
        banks.push(DynamicBankRecord {
            bank,
            trace_path: path.display().to_string(),
            trace_bytes: TRACE_BYTES,
            trace_blake3,
            commitment_words,
            commit_seconds,
            peak_allocated_gib,
        });
    }
    let record = DynamicCommitmentRecord {
        version: 1,
        encoding: "koala-bear-montgomery-u32-le",
        banks,
    };
    std::fs::write(&output, serde_json::to_vec_pretty(&record)?)?;
    eprintln!("record_path={}", output.display());
    Ok(())
}

fn montgomery_values(map: &[u8]) -> Result<&[Felt]> {
    ensure!(map.len() == TRACE_BYTES, "wrong dynamic trace byte length");
    ensure!(
        map.as_ptr().align_offset(align_of::<Felt>()) == 0,
        "unaligned trace map"
    );
    let words = unsafe { std::slice::from_raw_parts(map.as_ptr().cast::<u32>(), map.len() / 4) };
    ensure!(
        words.par_iter().all(|value| *value < MODULUS),
        "dynamic trace contains a noncanonical Montgomery limb"
    );
    Ok(unsafe { std::slice::from_raw_parts(map.as_ptr().cast::<Felt>(), map.len() / 4) })
}

fn commit_bank(bank: usize, values: &[Felt], scope: TaskScope) -> Result<([u32; 8], f64, f64)> {
    let (baseline_free, total) = cuda_memory_info()?;
    let mut dense = Vec::with_capacity((DYNAMIC_COLUMNS + 1) * ROWS);
    dense.resize(ROWS, Felt::zero());
    dense.extend_from_slice(values);
    let layout = AbstractChipLayoutWithHeights::new(vec![(
        format!("v4-bank-{bank}-dynamic"),
        1,
        DYNAMIC_COLUMNS,
        ROWS,
    )]);
    let host = JaggedTraceMle::from_chip_layout(Buffer::from(dense), &layout, LOG_ROWS);
    let trace = host.into_device(&scope);
    let (free_after_upload, _) = cuda_memory_info()?;
    let prover = FriCudaProver::<TestGC, _, Felt>::new(
        Poseidon2SP1Field16CudaProver::new(&scope),
        FriConfig::new(LOG_BLOWUP, QUERIES, POW_BITS),
        LOG_ROWS,
    );
    let started = Instant::now();
    let (_, data) = commit_multilinears::<TestGC, _>(&trace, LOG_ROWS, false, false, &prover)?;
    scope.synchronize_blocking()?;
    let elapsed = started.elapsed().as_secs_f64();
    let (free_after_commit, _) = cuda_memory_info()?;
    let minimum_free = free_after_upload.min(free_after_commit);
    let peak = (baseline_free - minimum_free) as f64 / (1_u64 << 30) as f64;
    let words = data
        .original_commitment
        .map(|value| value.as_canonical_u32());
    ensure!(total > 0, "CUDA reported zero device memory");
    Ok((words, elapsed, peak))
}
