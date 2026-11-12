#[path="../device_relations.rs"]
mod device_relations;
#[cfg(feature="shared-resident-replay")]
#[path="../shared_replay.rs"]
mod shared_replay;
#[path="../gpu_witness.rs"]
mod gpu_witness;
#[path="../resident.rs"]
mod resident;
#[path="../multi_gpu.rs"]
mod multi_gpu;
#[path="../low_memory_sumcheck.rs"]
mod low_memory_sumcheck;
#[path="../pcs_hints.rs"]
mod pcs_hints;
#[path="../all_relations_verifier.rs"]
mod all_relations_verifier;
#[path="../direct_opening.rs"]
mod direct_opening;
#[cfg(test)]
extern crate cpu_slop_algebra as slop_algebra_legacy;
#[path="../gpu_reductions.rs"]
mod gpu_reductions;
#[path="../sealed_words.rs"]
mod sealed_words;
use sealed_words::SealedWords;
use std::mem::MaybeUninit;
use std::{
    ffi::OsString,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{ensure, Result};
use cmfd_consensus::forgematrix_v4_basefold::{
    forgematrix_v4_transcript, ForgeMatrixV4Digest as CpuDigest, ForgeMatrixV4Extension as CpuExt,
    ForgeMatrixV4Field as CpuFelt, ForgeMatrixV4OpeningClaim as CpuOpeningClaim,
    ForgeMatrixV4TranscriptStatement,
};
use cmfd_consensus::forgematrix_v4_proof::{
    forgematrix_v4_activation_evaluation, forgematrix_v4_final_activation_digest,
    forgematrix_v4_initial_activation_evaluation, forgematrix_v4_mask_coefficients,
    forgematrix_v4_mask_evaluation, verify_forgematrix_v4_transparent_proof,
    ForgeMatrixV4BankProof, ForgeMatrixV4RelationRepetitionProof, ForgeMatrixV4TransparentProof,
};
use cmfd_consensus::forgematrix_v4_proof_codec::{
    decode_forgematrix_v4_transparent_proof, encode_forgematrix_v4_transparent_proof,
    FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
};
use cmfd_consensus::forgematrix_v4_relations::{
    bind_forgematrix_v4_commitments, finalize_forgematrix_v4_bank_opening_claims,
    forgematrix_v4_cubic_opening_claims, forgematrix_v4_final_opening_claim,
    forgematrix_v4_matrix_opening_claims, forgematrix_v4_matrix_terminal_layer,
    forgematrix_v4_shift_boundary_opening_claim, forgematrix_v4_shift_boundary_point,
    forgematrix_v4_shift_opening_claim, sample_forgematrix_v4_cubic_point,
    sample_forgematrix_v4_final_point, sample_forgematrix_v4_matrix_point,
    verify_forgematrix_v4_cubic_relation, verify_forgematrix_v4_matrix_relation,
    verify_forgematrix_v4_shift_relation, ForgeMatrixV4CubicRelationProof as CpuCubicProof,
    ForgeMatrixV4MatrixRelationProof as CpuMatrixProof,
    ForgeMatrixV4ShiftRelationProof as CpuShiftProof,
};
use cmfd_consensus::{
    forgematrix_v4_challenge_digest, forgematrix_v4_direct_proof_system_digest,
    forgematrix_v4_work_digest, BlockChallenge, ForgeMatrixV4FixedArtifactRecordV1,
    FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_DIRECT_PROOF_VERSION,
    FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID,
    PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST, PRODUCTION_V4_RCNET1_NETWORK_ID,
    PRODUCTION_V4_TESTNET_NETWORK_ID,
};
use cpu_slop_algebra::AbstractField as CpuAbstractField;
use memmap2::{Mmap, MmapOptions};
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slop_algebra::{AbstractField, PrimeField32};
use slop_alloc::{Buffer, CpuBackend, RawBuffer};
use slop_basefold::FriConfig;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_multilinear::{Mle, Point};
use slop_tensor::{Dimensions, Tensor, TensorView};
use sp1_gpu_basefold::FriCudaProver;
use sp1_gpu_commit::commit_multilinears;
use sp1_gpu_cudart::{
    args, cuda_memory_info, dot_along_dim_view, run_sync_in_place, DeviceBuffer, DevicePoint,
    DeviceTensor, PinnedAllocator, TaskScope, PINNED_ALLOCATOR,
};
use low_memory_sumcheck::{
    cubic_transition_sumcheck, simple_hadamard_sumcheck, triple_hadamard_sumcheck,
};
use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
use sp1_gpu_sys::kernels::cmfd_weight_output_reduction_kernel;
use sp1_gpu_utils::{
    AbstractChipLayoutWithHeights, Ext, Felt, JaggedTraceMle, TestGC, TraceDenseData,
};

#[path = "../real_v4_opening.rs"]
mod real_v4_opening;

const LAYERS: usize = 128;
const BATCH: usize = 128;
const WIDTH: usize = 4096;
const LOG_ROWS: u32 = 23;
const ROWS: usize = 1 << LOG_ROWS;
const DYNAMIC_COLUMNS: usize = 16;
const CELLS: usize = BATCH * WIDTH;
const BANK_VALUES: usize = LAYERS * CELLS;
const BANK_BYTES: usize = LAYERS * WIDTH * WIDTH;
const DYNAMIC_BYTES: usize = 2 * BANK_VALUES * size_of::<u32>();
const MODEL_HEADER_BYTES: u64 = 184;
const MODULUS: u32 = 0x7f00_0001;
const LOG_BLOWUP: usize = 1;
const QUERIES: usize = 270;
const POW_BITS: usize = 16;
const COMMITMENTS_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/Commitments/v1";
const MATRIX_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/MatrixPoint/v1";
const MATRIX_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/MatrixProof/v1";
const SHIFT_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/ShiftProof/v1";
const CUBIC_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/CubicPoint/v1";
const CUBIC_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/CubicProof/v1";
const FINAL_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/FinalPoint/v1";
/// Memory the host must still have available after the server preloads its
/// fixed data. Smaller hosts (for example WSL solo miners) keep file mappings.
// The 32 GB research host keeps an independent 4 GiB runtime reserve guard.
// Twelve GiB here allows pinned fixed banks/trees and trace DMA staging while
// leaving room for the pinned model cache and active proof buffers.
const PRELOAD_RESERVE_BYTES: u64 = 12 << 30;
const PIN_COPY_CHUNK_BYTES: usize = 1 << 24;

type GpuChallenger = <TestGC as IopCtx>::Challenger;
type GpuDigest = <TestGC as IopCtx>::Digest;
type PreparedDynamicTraces = [JaggedTraceMle<Felt, TaskScope>; 3];
type DynamicCommitmentWords = [[u32; 8]; 3];

#[derive(Deserialize)]
struct DynamicCommitmentRecord {
    banks: Vec<DynamicBankRecord>,
}

#[derive(Deserialize)]
struct DynamicBankRecord {
    bank: usize,
    commitment_words: [u32; 8],
}

#[derive(Deserialize)]
struct FrozenProductionV4Template {
    challenge: BlockChallenge,
    nonce: u64,
}

struct PreparedProver {
    source_model: PathBuf,
    fixed_record: ForgeMatrixV4FixedArtifactRecordV1,
    cpu_fixed: [CpuDigest; 3],
    gpu_fixed: [GpuDigest; 3],
    base_input: Vec<u8>,
    encoded_banks: [EncodedBank; 3],
    fixed_maps: [real_v4_opening::FixedArtifactMaps; 3],
}

/// One encoded model bank on the GPU: uploaded for this proof, or kept resident
/// by the persistent server (`CMFD_V4_PROOF_RESIDENT_BANKS=1`). Read-only either way.
enum DeviceBank<'a> {
    Owned(DeviceBuffer<u8>),
    Resident(&'a DeviceBuffer<u8>),
    Spilled,
}

impl DeviceBank<'_> {
    fn get(&self) -> &DeviceBuffer<u8> {
        match self {
            Self::Owned(buffer) => buffer,
            Self::Resident(buffer) => buffer,
            Self::Spilled => panic!("fixed bank must be reloaded before use"),
        }
    }
}

/// Page-locked host staging for the three dynamic traces, kept for the life of the
/// persistent server (about 1.6 GiB of locked RAM). On by default whenever the
/// encoded banks were pinned at start-up; `CMFD_V4_PROOF_PINNED_TRACES=0` turns it
/// off and `=1` turns it on without preloaded banks.
/// Each proof copies a trace into it in parallel and uploads it by DMA, instead of
/// building a fresh pageable buffer and uploading through the driver's bounce copy.
struct TraceStaging {
    buffers: [RawBuffer<u8, PinnedAllocator>; 3],
    layout: [TraceLayout; 3],
}

/// The jagged metadata of one bank's dynamic trace; identical for every proof.
struct TraceLayout {
    dense: TraceDenseData<Felt, CpuBackend>,
    col_index: Buffer<u32, CpuBackend>,
    start_indices: Buffer<u32, CpuBackend>,
    column_heights: Buffer<u32, CpuBackend>,
}

const TRACE_DENSE_VALUES: usize = (DYNAMIC_COLUMNS + 1) * ROWS;

fn pinned_traces_enabled(prepared: &PreparedProver) -> bool {
    match std::env::var("CMFD_V4_PROOF_PINNED_TRACES").as_deref() {
        Ok("0") => false,
        Ok("1") => true,
        _ => prepared
            .encoded_banks
            .iter()
            .all(|bank| matches!(bank, EncodedBank::Pinned(_))),
    }
}

fn dynamic_trace_layout(bank: usize) -> AbstractChipLayoutWithHeights {
    AbstractChipLayoutWithHeights::new(vec![(
        format!("v4-bank-{bank}-dynamic"),
        1,
        DYNAMIC_COLUMNS,
        ROWS,
    )])
}

impl TraceStaging {
    fn new() -> Result<Self> {
        let bytes = TRACE_DENSE_VALUES * size_of::<Felt>();
        let mut zeros = Some(Buffer::from(vec![Felt::zero(); TRACE_DENSE_VALUES]));
        let mut layouts = Vec::with_capacity(3);
        for bank in 0..3 {
            let trace = JaggedTraceMle::from_chip_layout(
                zeros.take().expect("dense buffer is returned after each bank"),
                &dynamic_trace_layout(bank),
                LOG_ROWS,
            );
            let JaggedTraceMle(inner) = trace;
            let mut dense = inner.dense_data;
            zeros = Some(std::mem::replace(&mut dense.dense, Buffer::from(Vec::new())));
            layouts.push(TraceLayout {
                dense,
                col_index: inner.col_index,
                start_indices: inner.start_indices,
                column_heights: inner.column_heights,
            });
        }
        let mut buffers = Vec::with_capacity(3);
        for _ in 0..3 {
            let buffer = RawBuffer::<u8, PinnedAllocator>::try_with_capacity_in(bytes, PINNED_ALLOCATOR)
                .map_err(|_| anyhow::anyhow!("cannot pin dynamic trace staging"))?;
            // SAFETY: the allocation holds `bytes` bytes; the zero row prefix is written
            // once here and never changed, the values are rewritten by every proof.
            unsafe { std::ptr::write_bytes(buffer.ptr() as *mut u8, 0, ROWS * size_of::<Felt>()) };
            buffers.push(buffer);
        }
        Ok(Self {
            buffers: buffers.try_into().map_err(|_| anyhow::anyhow!("staging count"))?,
            layout: layouts.try_into().map_err(|_| anyhow::anyhow!("layout count"))?,
        })
    }

    /// Copies one bank's values behind the zero rows and uploads the dense trace.
    fn upload(
        &mut self,
        bank: usize,
        values: &[Felt],
        scope: &TaskScope,
    ) -> Result<(JaggedTraceMle<Felt, TaskScope>, f64)> {
        ensure!(
            values.len() == TRACE_DENSE_VALUES - ROWS,
            "wrong dynamic trace value count"
        );
        let started = Instant::now();
        // The destination is uninitialized field storage. Do not form an &mut
        // [Felt] until every slot has been written from validated source words.
        let destination=unsafe{std::slice::from_raw_parts_mut((self.buffers[bank].ptr() as *mut MaybeUninit<Felt>).add(ROWS),values.len())};
        let chunk=PIN_COPY_CHUNK_BYTES/size_of::<Felt>();
        destination.par_chunks_mut(chunk).zip(values.par_chunks(chunk)).for_each(|(dst,src)|unsafe{std::ptr::copy_nonoverlapping(src.as_ptr(),dst.as_mut_ptr().cast::<Felt>(),src.len());});
        // Prefix was initialized to zero at startup; copied values are canonical.
        let dense=unsafe{std::slice::from_raw_parts(self.buffers[bank].ptr() as *const Felt,TRACE_DENSE_VALUES)};
        let copy_seconds = started.elapsed().as_secs_f64();
        let layout = &self.layout[bank];
        let device = DeviceBuffer::from_host_slice(dense, scope)?;
        let dense_data = TraceDenseData {
            dense: device.into_inner(),
            preprocessed_offset: layout.dense.preprocessed_offset,
            preprocessed_cols: layout.dense.preprocessed_cols,
            preprocessed_padding: layout.dense.preprocessed_padding,
            main_padding: layout.dense.main_padding,
            prep_padding_col_count: layout.dense.prep_padding_col_count,
            main_padding_col_count: layout.dense.main_padding_col_count,
            preprocessed_table_index: layout.dense.preprocessed_table_index.clone(),
            main_table_index: layout.dense.main_table_index.clone(),
        };
        let trace = JaggedTraceMle::new(
            dense_data,
            DeviceBuffer::from_host(&layout.col_index, scope)?.into_inner(),
            DeviceBuffer::from_host(&layout.start_indices, scope)?.into_inner(),
            DeviceBuffer::from_host(&layout.column_heights, scope)?.into_inner(),
        );
        Ok((trace, copy_seconds))
    }
}

/// `CMFD_V4_PROOF_RESIDENT_BANKS=1` uploads the three encoded banks once when the
/// server starts and reuses them for every proof (about 6.4 GiB of extra VRAM).
fn resident_banks_enabled() -> bool {
    std::env::var("CMFD_V4_PROOF_RESIDENT_BANKS").as_deref() == Ok("1")
}

/// Host bytes of one encoded model bank: the file mapping, or a page-locked
/// copy so each proof's relation upload is a direct DMA that never waits on
/// the page cache.
enum EncodedBank {
    Mapped(Mmap),
    Pinned(PinnedBank),
    Remote,
}

struct PinnedBank {
    buffer: RawBuffer<u8, PinnedAllocator>,
    len: usize,
}

impl EncodedBank {
    /// Keeps the mapping when the driver cannot pin that much memory.
    fn pin(map: Mmap) -> Self {
        let Ok(buffer) =
            RawBuffer::<u8, PinnedAllocator>::try_with_capacity_in(map.len(), PINNED_ALLOCATOR)
        else {
            return Self::Mapped(map);
        };
        let destination = buffer.ptr() as usize;
        map.par_chunks(PIN_COPY_CHUNK_BYTES)
            .enumerate()
            .for_each(|(index, chunk)| unsafe {
                // SAFETY: the chunks are disjoint ranges of the map.len()-byte allocation.
                std::ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    (destination as *mut u8).add(index * PIN_COPY_CHUNK_BYTES),
                    chunk.len(),
                );
            });
        Self::Pinned(PinnedBank {
            buffer,
            len: map.len(),
        })
    }
}

impl std::ops::Deref for EncodedBank {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Mapped(map) => &map[..],
            Self::Remote => panic!("fixed model is resident on the other GPU"),
            // SAFETY: `pin` initialized all `len` bytes, which are never written again.
            Self::Pinned(bank) => unsafe {
                std::slice::from_raw_parts(bank.buffer.ptr(), bank.len)
            },
        }
    }
}

fn main() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "network-info" {
        // No model files, CUDA context, or proving work are opened by this query.
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "schema": "CMFD_DIRECT_PROOF_TESTNET_WORKER_NETWORK_V1",
                "role": "direct_six_commitment_prover",
                "network_id": hex::encode(FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID),
                "proof_version": FORGEMATRIX_V4_DIRECT_PROOF_VERSION,
                "proof_system_digest": hex::encode(forgematrix_v4_direct_proof_system_digest()),
                "mainnet_supported": true,
                "mainnet_network_id": "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62",
                "mainnet_proof_system_digest": hex::encode(cmfd_consensus::compact_mainnet_fork::compact_mainnet_proof_system_digest()),
                "mainnet_activation_height": cmfd_consensus::compact_mainnet_fork::COMPACT_MAINNET_ACTIVATION_HEIGHT,
                "source_commit": option_env!("CMFD_BUILD_SOURCE_COMMIT"),
            }))?
        );
        return Ok(());
    }
    // Bounded-memory research policy: return unused async-pool reservations at
    // synchronization points instead of retaining an unbounded high-water mark.
    // This configures this prover's CUDA pool, not proof/security parameters.
    if args.first().is_some_and(|value| value=="--multi-worker") {
        let parent=unsafe{libc::getppid()};
        ensure!(parent>1,"multi-GPU coordinator is no longer running");
        ensure!(unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0,"install worker parent-death guard");
        ensure!(unsafe{libc::getppid()}==parent,"coordinator exited during worker initialization");
    }
    sp1_gpu_cudart::TaskPoolBuilder::new()
        .mem_release_threshold(0)
        .build_global()?;

    if args.first().is_some_and(|value| value == "--multi-worker") {
        ensure!(args.len()==5,"usage: --multi-worker ROLE NETWORK MODEL ARTIFACTS");
        let role=args[1].to_str().ok_or_else(||anyhow::anyhow!("invalid role"))?.to_owned();
        let network=parse_expected_network_id(&args[2])?;
        let prepared=prepare_prover(Path::new(&args[3]),Path::new(&args[4]),false)?;
        run_sync_in_place(move |scope|match role.as_str(){
            "fixed"=>resident::run_fixed(&prepared,network,&scope),
            "dynamic"=>resident::run_dynamic(&prepared,network,&scope),
            _=>multi_gpu::run_worker(&role,&prepared,network,&scope),
        })??;
        return Ok(());
    }
    if args.first().is_some_and(|value| value == "--server") {
        ensure!(
            args.len() == 4,
            "usage: --server EXPECTED_NETWORK_ID MODEL ARTIFACT_DIRECTORY"
        );
        let expected_network_id = parse_expected_network_id(&args[1])?;
        let preload = !preload_disabled(std::env::var("CMFD_V4_PROOF_PRELOAD").ok().as_deref());
        let prepared = prepare_prover(Path::new(&args[2]), Path::new(&args[3]), preload)?;
        run_sync_in_place(move |scope| {
            run_persistent_server(&prepared, expected_network_id, &scope)
        })??;
        return Ok(());
    }
    ensure!(
        args.len() == 9 && args.first().is_some_and(|value| value == "--network-id"),
        "usage: --network-id EXPECTED_NETWORK_ID MODEL ARTIFACT_DIRECTORY TEMPLATE TRACE_PREFIX DYNAMIC_RECORD FINAL OUTPUT"
    );
    run_one_shot(args)
}

fn run_one_shot(args: Vec<OsString>) -> Result<()> {
    let expected_network_id = parse_expected_network_id(&args[1])?;
    let model_path = PathBuf::from(&args[2]);
    let artifact_dir = PathBuf::from(&args[3]);
    let template_path = PathBuf::from(&args[4]);
    let dynamic_prefix = PathBuf::from(&args[5]);
    let dynamic_record_path = PathBuf::from(&args[6]);
    let final_path = PathBuf::from(&args[7]);
    let output_path = PathBuf::from(&args[8]);
    let prepared = prepare_prover(&model_path, &artifact_dir, false)?;
    let expected = read_dynamic_commitment_record(&dynamic_record_path)?;
    run_sync_in_place(move |scope| {
        prove_job(
            &prepared,
            expected_network_id,
            &template_path,
            &dynamic_prefix,
            &final_path,
            &output_path,
            Some(expected),
            true,
            None,
            None,
            &scope,
        )
    })??;
    Ok(())
}

fn parse_expected_network_id(value: &OsString) -> Result<[u8; 32]> {
    let value = value
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("expected network ID is not valid UTF-8"))?;
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "expected network ID must contain exactly 64 lowercase hexadecimal characters"
    );
    let mut network_id = [0_u8; 32];
    hex::decode_to_slice(value, &mut network_id)
        .map_err(|_| anyhow::anyhow!("expected network ID is not a 32-byte hexadecimal value"))?;
    ensure!(
        cmfd_consensus::forgematrix_v4::forgematrix_v4_direct_proof_system_digest_for_network(network_id).is_some(),
        "expected network ID is not the dedicated direct-proof testnet"
    );
    Ok(network_id)
}

#[cfg(test)]
mod network_tests {
    use super::*;

    #[test]
    fn accepts_only_pinned_compact_networks() {
        assert_eq!(
            parse_expected_network_id(&OsString::from(hex::encode(FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID))).unwrap(),
            FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID
        );
        for id in [[0; 32], [0xff; 32], [0x63; 32],
            PRODUCTION_V4_TESTNET_NETWORK_ID, PRODUCTION_V4_RCNET1_NETWORK_ID] {
            assert!(parse_expected_network_id(&OsString::from(hex::encode(id))).is_err());
        }
        if let Some(id) = cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID {
            assert!(parse_expected_network_id(&OsString::from(hex::encode(id))).is_ok());
        }
    }

    #[test]
    fn rejects_noncanonical_network_encodings() {
        for value in [
            "",
            "00",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64),
            &format!(" {}", hex::encode(PRODUCTION_V4_RCNET1_NETWORK_ID)),
            &format!("{}\n", hex::encode(PRODUCTION_V4_RCNET1_NETWORK_ID)),
        ] {
            assert!(parse_expected_network_id(&OsString::from(value)).is_err());
        }
    }
}

/// `preload` (server mode) keeps the fixed data read by every proof in memory:
/// the encoded banks in pinned host memory and the fixed Merkle trees on the
/// heap, when the host has room. Proof bytes do not depend on where they live.
fn prepare_prover(model_path: &Path, artifact_dir: &Path, preload: bool) -> Result<PreparedProver> {
    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_reader(File::open(
        artifact_dir.join("FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"),
    )?)?;
    fixed_record.validate()?;
    ensure!(
        fixed_record.record_digest() == PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
        "fixed artifact record is not the compiled ProductionV4 record"
    );
    let fixed_words: [[u32; 8]; 3] =
        std::array::from_fn(|bank| fixed_record.banks()[bank].commitment_words());
    let preload = preload
        && host_can_preload(
            3 * BANK_BYTES as u64
                + fixed_record
                    .banks()
                    .iter()
                    .map(|bank| bank.tree_bytes())
                    .sum::<u64>(),
        );
    let model_bank_prep_started = Instant::now();
    let base_input = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {
        resident::shared_base_input()?
    } else {read_base_input(model_path)?};
    let encoded_banks: [EncodedBank;3] = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {
        std::array::from_fn(|_|EncodedBank::Remote)
    } else {(0..3)
        .into_par_iter()
        .map(|bank| map_encoded_bank(model_path, bank))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|map| {
            if preload {
                EncodedBank::pin(map)
            } else {
                EncodedBank::Mapped(map)
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong model-bank count"))?};
    eprintln!(
        "fixed_data_preload={preload} pinned_banks={}",
        encoded_banks
            .iter()
            .filter(|bank| matches!(bank, EncodedBank::Pinned(_)))
            .count()
    );
    eprintln!(
        "model_bank_prep_total_seconds={:.6}",
        model_bank_prep_started.elapsed().as_secs_f64()
    );
    let artifact_prep_started = Instant::now();
    let fixed_maps: [real_v4_opening::FixedArtifactMaps; 3] = (0..3)
        .map(|bank| {
            let started = Instant::now();
            let maps = real_v4_opening::FixedArtifactMaps::open(
                artifact_dir,
                fixed_record.banks()[bank],
                preload,
            )?;
            eprintln!(
                "fixed_artifact_prep bank={bank} seconds={:.6}",
                started.elapsed().as_secs_f64()
            );
            Ok(maps)
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong fixed-artifact count"))?;
    eprintln!(
        "fixed_artifact_prep_total_seconds={:.6}",
        artifact_prep_started.elapsed().as_secs_f64()
    );
    Ok(PreparedProver {
        source_model: model_path.to_owned(),
        fixed_record,
        cpu_fixed: digest_words::<CpuFelt>(fixed_words),
        gpu_fixed: digest_words::<Felt>(fixed_words),
        base_input,
        encoded_banks,
        fixed_maps,
    })
}

/// `CMFD_V4_PROOF_PRELOAD=0` in the worker's environment keeps the server on
/// file mappings, for hosts that cannot spare the pinned banks and trees even
/// though `host_can_preload` would allow them. The node passes its own
/// environment through to the worker.
fn preload_disabled(value: Option<&str>) -> bool {
    matches!(
        value.map(|value| value.trim().to_ascii_lowercase()).as_deref(),
        Some("0" | "false" | "off" | "no")
    )
}

fn host_can_preload(bytes: u64) -> bool {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| mem_available_bytes(&meminfo))
        .is_some_and(|available| available >= bytes.saturating_add(PRELOAD_RESERVE_BYTES))
}

fn mem_available_bytes(meminfo: &str) -> Option<u64> {
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    kib.checked_mul(1024)
}

#[cfg(test)]
mod preload_tests {
    use super::*;

    #[test]
    fn reads_mem_available_only() {
        let meminfo = "MemTotal:       65000000 kB\nMemFree:          100000 kB\nMemAvailable:   58000000 kB\n";
        assert_eq!(mem_available_bytes(meminfo), Some(58_000_000 * 1024));
        assert_eq!(mem_available_bytes("MemTotal:       65000000 kB\n"), None);
        assert_eq!(mem_available_bytes("MemAvailable:   lots kB\n"), None);
    }

    #[test]
    fn preload_is_disabled_only_by_an_explicit_setting() {
        assert!(!preload_disabled(None));
        assert!(!preload_disabled(Some("")));
        assert!(!preload_disabled(Some("1")));
        assert!(!preload_disabled(Some("maybe")));
        assert!(preload_disabled(Some("0")));
        assert!(preload_disabled(Some(" OFF ")));
        assert!(preload_disabled(Some("false")));
        assert!(preload_disabled(Some("no")));
    }
}

fn run_persistent_server(
    prepared: &PreparedProver,
    expected_network_id: [u8; 32],
    scope: &TaskScope,
) -> Result<()> {
    let resident = if resident_banks_enabled() {
        // Opt-in: about 6.4 GiB of VRAM for the life of the server.
        let started = Instant::now();
        let banks = [
            DeviceBuffer::from_host_slice(&prepared.encoded_banks[0], scope)?,
            DeviceBuffer::from_host_slice(&prepared.encoded_banks[1], scope)?,
            DeviceBuffer::from_host_slice(&prepared.encoded_banks[2], scope)?,
        ];
        scope.synchronize_blocking()?;
        eprintln!(
            "resident_banks=3 upload_seconds={:.6}",
            started.elapsed().as_secs_f64()
        );
        Some(banks)
    } else {
        None
    };
    let mut staging = if pinned_traces_enabled(prepared) {
        let started = Instant::now();
        match TraceStaging::new() {
            Ok(staging) => {
                eprintln!(
                    "pinned_traces=3 setup_seconds={:.6}",
                    started.elapsed().as_secs_f64()
                );
                Some(staging)
            }
            // Proving still works without staging, only slower.
            Err(error) => {
                eprintln!("pinned_traces=0 reason={error}");
                None
            }
        }
    } else {
        eprintln!("pinned_traces=0");
        None
    };
    // Pinned proof inputs may displace the replay worker's file-cache pages
    // during startup. Fault the shared source back in before accepting shares;
    // this uses reclaimable mappings and allocates no second model copy.
    let warmup_started=Instant::now();
    let source=unsafe{MmapOptions::new().map(&File::open(&prepared.source_model)?)?};
    let touched=source.par_chunks(4096).map(|page|page[0] as u64).sum::<u64>();
    std::hint::black_box(touched);
    drop(source);
    eprintln!("shared_model_cache_warmup_seconds={:.6}",warmup_started.elapsed().as_secs_f64());
    println!("CMFD_V4_PROOF_READY");
    std::io::stdout().flush()?;
    for line in BufReader::new(std::io::stdin().lock()).lines() {
        let line = line?;
        let line = line.strip_suffix('\r').unwrap_or(&line);
        if line == "QUIT" {
            break;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        ensure!(
            fields.len() == 5 && fields[0] == "RUN" && fields[1..].iter().all(|v| !v.is_empty()),
            "invalid persistent proof command"
        );
        // No worker self-check here: the node decodes the written proof and runs
        // the consensus verifier on it before it builds and submits a block.
        prove_job(
            prepared,
            expected_network_id,
            Path::new(fields[1]),
            Path::new(fields[2]),
            Path::new(fields[3]),
            Path::new(fields[4]),
            None,
            false,
            resident.as_ref(),
            staging.as_mut(),
            scope,
        )?;
        // The pool may hand this same GPU back to mining immediately after
        // DONE. Complete stream-ordered frees first; the zero release threshold
        // then returns unused pool allocations instead of overlapping a reload.
        let release_started = Instant::now();
        scope.synchronize_blocking()?;
        let (free, total) = cuda_memory_info()?;
        eprintln!("proof_job_release seconds={:.6} used_bytes={}",
            release_started.elapsed().as_secs_f64(), total-free);
        println!("CMFD_V4_PROOF_DONE");
        std::io::stdout().flush()?;
    }
    Ok(())
}

fn read_dynamic_commitment_record(path: &Path) -> Result<[[u32; 8]; 3]> {
    let dynamic_record: DynamicCommitmentRecord = serde_json::from_reader(File::open(path)?)?;
    ensure!(
        dynamic_record.banks.len() == 3,
        "wrong dynamic commitment count"
    );
    for (expected, bank) in dynamic_record.banks.iter().enumerate() {
        ensure!(
            bank.bank == expected,
            "dynamic commitment bank order mismatch"
        );
    }
    Ok(std::array::from_fn(|bank| {
        dynamic_record.banks[bank].commitment_words
    }))
}

#[allow(clippy::too_many_arguments)]
fn prove_job(
    prepared: &PreparedProver,
    expected_network_id: [u8; 32],
    template_path: &Path,
    dynamic_prefix: &Path,
    final_path: &Path,
    output_path: &Path,
    expected_dynamic_words: Option<[[u32; 8]; 3]>,
    self_check: bool,
    resident: Option<&[DeviceBuffer<u8>; 3]>,
    staging: Option<&mut TraceStaging>,
    scope: &TaskScope,
) -> Result<()> {
    let frozen: FrozenProductionV4Template = serde_json::from_reader(File::open(template_path)?)?;
    ensure!(
        frozen.challenge.network_id == expected_network_id,
        "frozen template belongs to another network"
    );
    ensure!(!cmfd_consensus::mainnet_network::is_mainnet_network(expected_network_id) || frozen.challenge.height >= cmfd_consensus::compact_mainnet_fork::COMPACT_MAINNET_ACTIVATION_HEIGHT, "compact mainnet proof below activation");
    let final_activation = read_final_activation(final_path)?;
    let block = frozen.challenge;
    let nonce = frozen.nonce;
    let challenge_digest =
        forgematrix_v4_challenge_digest(&block, nonce, prepared.fixed_record.manifest_digest());
    let final_activation_digest =
        forgematrix_v4_final_activation_digest(challenge_digest, &final_activation);
    let statement = ForgeMatrixV4TranscriptStatement {
        block,
        algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
        proof_version: FORGEMATRIX_V4_DIRECT_PROOF_VERSION,
        nonce,
        proof_system_digest: cmfd_consensus::forgematrix_v4::forgematrix_v4_direct_proof_system_digest_for_network(expected_network_id).ok_or_else(|| anyhow::anyhow!("unsupported compact network"))?,
        model_manifest_digest: prepared.fixed_record.manifest_digest(),
        challenge_digest,
        final_activation_digest,
        work_digest: forgematrix_v4_work_digest(
            prepared.fixed_record.manifest_digest(),
            challenge_digest,
            final_activation_digest,
        ),
    };

    let load_started = Instant::now();
    // The initial vector is immutable and independent of trace commitment.
    // Compute the same vector while the main thread validates/uploads traces.
    let base_input = prepared.base_input.as_slice();
    let (dynamic_maps, dynamic_traces, dynamic_words, initial_activation) = thread::scope(|jobs| -> Result<_> {
        let initial_job = jobs.spawn(move || {
            let started = Instant::now();
            let values = build_initial_activation(challenge_digest, base_input);
            eprintln!("initial_activation_seconds={:.6}", started.elapsed().as_secs_f64());
            values
        });
        let map_started = Instant::now();
        let dynamic_maps = (0..3).into_par_iter().map(|bank| -> Result<SealedWords> {
            let path = PathBuf::from(format!("{}-bank{bank}-dynamic.bin", dynamic_prefix.display()));
            let map=SealedWords::open(&path,DYNAMIC_BYTES,MODULUS).map_err(|e|anyhow::anyhow!("sealed trace rejected: {e}"))?;
            Ok(map)
        }).collect::<Result<Vec<_>>>()?;
        eprintln!("trace_sealed_map_and_validation_seconds={:.6}", map_started.elapsed().as_secs_f64());
        let validate_started = Instant::now();
        let dynamic_values = dynamic_maps.par_iter().map(montgomery_values).collect::<Result<Vec<_>>>()?;
        eprintln!("trace_cached_view_seconds={:.6}", validate_started.elapsed().as_secs_f64());
        let commit_started = Instant::now();
        let (dynamic_traces, dynamic_words) = prepare_dynamic_traces(&dynamic_values, staging, scope)?;
        eprintln!("trace_commit_phase_seconds={:.6}", commit_started.elapsed().as_secs_f64());
        drop(dynamic_values);
        let initial_activation = initial_job.join().map_err(|_| anyhow::anyhow!("initial activation worker panicked"))?;
        Ok((dynamic_maps, dynamic_traces, dynamic_words, initial_activation))
    })?;
    // Not part of online_seconds: the time from the RUN command to a written proof
    // is this plus online_seconds.
    eprintln!(
        "trace_load_and_commit_seconds={:.6}",
        load_started.elapsed().as_secs_f64()
    );
    if let Some(expected) = expected_dynamic_words {
        ensure!(
            expected == dynamic_words,
            "fused dynamic commitments differ from the supplied record"
        );
    }
    let cpu_dynamic = digest_words::<CpuFelt>(dynamic_words);
    let gpu_dynamic = digest_words::<Felt>(dynamic_words);
    prove_complete_proof(
        prepared,
        statement,
        prepared.cpu_fixed,
        cpu_dynamic,
        prepared.gpu_fixed,
        gpu_dynamic,
        &prepared.base_input,
        final_activation,
        &prepared.encoded_banks,
        dynamic_maps,
        dynamic_traces,
        &prepared.fixed_maps,
        initial_activation,
        output_path,
        self_check,
        resident,
        scope,
    )
}

fn prepare_dynamic_traces(
    values: &[&[Felt]],
    mut staging: Option<&mut TraceStaging>,
    scope: &TaskScope,
) -> Result<(PreparedDynamicTraces, DynamicCommitmentWords)> {
    ensure!(values.len() == 3, "wrong dynamic trace count");
    let mut traces = Vec::with_capacity(3);
    let mut words = Vec::with_capacity(3);
    for (bank, values) in values.iter().enumerate() {
        let started = Instant::now();
        let (trace, dense_seconds) = match staging.as_deref_mut() {
            Some(staging) => staging.upload(bank, values, scope)?,
            None => {
                let mut dense = Vec::with_capacity(TRACE_DENSE_VALUES);
                dense.resize(ROWS, Felt::zero());
                dense.extend_from_slice(values);
                let dense_seconds = started.elapsed().as_secs_f64();
                let trace = JaggedTraceMle::from_chip_layout(
                    Buffer::from(dense),
                    &dynamic_trace_layout(bank),
                    LOG_ROWS,
                )
                .into_device(scope);
                (trace, dense_seconds)
            }
        };
        scope.synchronize_blocking()?;
        let upload_seconds = started.elapsed().as_secs_f64() - dense_seconds;
        let prover = FriCudaProver::<TestGC, _, Felt>::new(
            Poseidon2SP1Field16CudaProver::new(scope),
            FriConfig::new(LOG_BLOWUP, QUERIES, POW_BITS),
            LOG_ROWS,
        );
        let (_, data) = commit_multilinears::<TestGC, _>(&trace, LOG_ROWS, false, false, &prover)?;
        scope.synchronize_blocking()?;
        words.push(
            data.original_commitment
                .map(|value| value.as_canonical_u32()),
        );
        traces.push(trace);
        eprintln!(
            "bank={bank} fused_commit_seconds={:.6} dense_build_seconds={dense_seconds:.6} trace_upload_seconds={upload_seconds:.6}",
            started.elapsed().as_secs_f64()
        );
    }
    Ok((
        traces
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong prepared dynamic trace count"))?,
        words
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong dynamic commitment count"))?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn prove_complete_proof(
    prepared: &PreparedProver,
    statement: ForgeMatrixV4TranscriptStatement,
    cpu_fixed: [CpuDigest; 3],
    cpu_dynamic: [CpuDigest; 3],
    gpu_fixed: [GpuDigest; 3],
    gpu_dynamic: [GpuDigest; 3],
    base_input: &[u8],
    final_activation: Vec<CpuFelt>,
    encoded_banks: &[EncodedBank; 3],
    dynamic_maps: Vec<SealedWords>,
    dynamic_traces: [JaggedTraceMle<Felt, TaskScope>; 3],
    fixed_maps: &[real_v4_opening::FixedArtifactMaps; 3],
    initial_activation: Vec<Felt>,
    output_path: &Path,
    self_check: bool,
    resident: Option<&[DeviceBuffer<u8>; 3]>,
    scope: &TaskScope,
) -> Result<()> {
    let (baseline_free, total_device_bytes) = cuda_memory_info()?;
    let minimum_free = Arc::new(AtomicUsize::new(baseline_free));
    let sampling = Arc::new(AtomicBool::new(true));
    let sampler_minimum = Arc::clone(&minimum_free);
    let sampler_running = Arc::clone(&sampling);
    let sampling_thread = thread::spawn(move || {
        while sampler_running.load(Ordering::Relaxed) {
            if let Ok((free, _)) = cuda_memory_info() {
                sampler_minimum.fetch_min(free, Ordering::Relaxed);
            }
            // Parked rather than slept so stopping it does not wait out the interval.
            thread::park_timeout(Duration::from_millis(50));
        }
    });
    let online_started = Instant::now();
    let third_validation_started = Instant::now();
    let _dynamic_values = dynamic_maps.par_iter().map(montgomery_values).collect::<Result<Vec<_>>>()?;
    eprintln!("trace_cached_boundary_view_seconds={:.6}", third_validation_started.elapsed().as_secs_f64());
    let mut cpu_challenger = forgematrix_v4_transcript(statement);
    bind_forgematrix_v4_commitments(&mut cpu_challenger, &cpu_fixed, &cpu_dynamic);
    let mut gpu_challenger = gpu_transcript(&statement.digest());
    bind_gpu_commitments(&mut gpu_challenger, &gpu_fixed, &gpu_dynamic);

    let initial_gpu=DeviceTensor::from_host(&Tensor::from(initial_activation).reshape([BATCH,WIDTH]),scope)?;
    let mut relations = Vec::with_capacity(3);
    let mut claims = Vec::with_capacity(3);
    let mut openings = Vec::with_capacity(3);

    // New proof-version order: bind all relation messages before any opening
    // proof. Version 1 cannot be reused because bank 2 previously depended on
    // the bank 0 BaseFold transcript.
    ensure!(resident.is_none(),"all-relations-first foundation requires streamed fixed banks");
    let [dynamic_device, next_dynamic_device, final_dynamic_device] = dynamic_traces;
    let (bank_relations, bank_claims, boundary_claims, encoded_device, dynamic_device) = prove_bank_relations(
        0,statement,base_input,&encoded_banks[0],None,dynamic_device,&initial_gpu.as_view(),
        &mut cpu_challenger,&mut gpu_challenger,scope)?;
    ensure!(boundary_claims.is_empty(),"bank 0 produced a previous-bank boundary claim");relations.push(bank_relations);claims.push(bank_claims);
    let boundary=gpu_last_activation_layer(&dynamic_device)?;
    let (bank_relations,bank_claims,boundary_claims,next_encoded_device,next_dynamic_device)=prove_bank_relations(
        1,statement,base_input,&encoded_banks[1],None,next_dynamic_device,&boundary,
        &mut cpu_challenger,&mut gpu_challenger,scope)?;
    relations.push(bank_relations);claims.push(bank_claims);claims[0].extend(boundary_claims);drop(encoded_device);drop(next_encoded_device);scope.synchronize_blocking()?;
    let boundary=gpu_last_activation_layer(&next_dynamic_device)?;
    let (bank_relations,bank_claims,boundary_claims,final_encoded_device,final_dynamic_device)=prove_bank_relations(
        2,statement,base_input,&encoded_banks[2],None,final_dynamic_device,&boundary,
        &mut cpu_challenger,&mut gpu_challenger,scope)?;
    relations.push(bank_relations);claims.push(bank_claims);claims[1].extend(boundary_claims);scope.synchronize_blocking()?;
    for repetition in 0..2 {
        let cpu_point = sample_forgematrix_v4_final_point(&mut cpu_challenger, repetition)?;
        let gpu_point = sample_final_point(&mut gpu_challenger, repetition);
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_point.iter().copied().collect::<Vec<_>>())?
                == cpu_point
                    .batch
                    .iter()
                    .chain(cpu_point.output.iter())
                    .copied()
                    .collect::<Vec<_>>(),
            "final activation point diverged"
        );
        let value = forgematrix_v4_activation_evaluation(
            &final_activation,
            &cpu_point.batch,
            &cpu_point.output,
        )?;
        claims[2].push(forgematrix_v4_final_opening_claim(&cpu_point, value)?);
    }
    for bank in 0..3{finalize_forgematrix_v4_bank_opening_claims(&mut claims[bank])?;}
    // Generate only the three original reductions. No legacy BaseFold enters
    // the transcript; the final six-commitment proof authenticates all claims.
    let dynamic_traces=[dynamic_device,next_dynamic_device,final_dynamic_device];
    let retain_fixed = std::env::var("CMFD_DIRECT_RETAIN_FIXED_BANKS").as_deref() == Ok("1");
    let mut fixed_devices:[Option<DeviceBuffer<u8>>;3]=std::array::from_fn(|_|None);
    fixed_devices[2]=Some(match final_encoded_device {
        DeviceBank::Owned(buffer)=>buffer,
        DeviceBank::Spilled=>anyhow::bail!("unexpected spilled bank in single-device path"),
        DeviceBank::Resident(_)=>anyhow::bail!("unexpected resident relation bank"),
    });
    for (bank,dynamic) in dynamic_traces.iter().enumerate(){
        if fixed_devices[bank].is_none(){fixed_devices[bank]=Some(DeviceBuffer::from_host_slice(&encoded_banks[bank],scope)?);}
        let encoded=fixed_devices[bank].as_ref().expect("current fixed bank");scope.synchronize_blocking()?;
        openings.push(real_v4_opening::prove_public_bank_opening(
            bank,&fixed_maps[bank],encoded,dynamic,gpu_fixed[bank],gpu_dynamic[bank],&claims[bank],
            &mut gpu_challenger,&mut cpu_challenger,scope)?);
        if !retain_fixed && bank!=2 {drop(fixed_devices[bank].take());scope.synchronize_blocking()?;}
        let(free,total)=cuda_memory_info()?;
        ensure!(total-free<=(13usize<<30),"fixed-bank opening exceeded 13 GiB GPU guard");
        eprintln!("direct_fixed_bank={bank} retained={} used_bytes={}",retain_fixed,total-free);
    }

    let banks = (0..3)
        .map(|bank| ForgeMatrixV4BankProof {
            dynamic_commitment: cpu_dynamic[bank],
            relations: relations[bank].clone(),
            opening: openings[bank].clone(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong complete-proof bank count"))?;
    let proof = ForgeMatrixV4TransparentProof {
        final_activation,
        banks,
    };
    // The carrier has zero-filled legacy BaseFold fields solely for the
    // existing exact public codec. Only the direct packet is written.
    let result=direct_opening::prove_integrated(prepared,statement,&proof,dynamic_traces,fixed_devices,output_path,scope,self_check)?;
    ensure!(!self_check || result["selfcontained_verified"]==true,"standalone direct receiver did not verify");
    let online_seconds=online_started.elapsed().as_secs_f64();
    sampling.store(false, Ordering::Relaxed);
    sampling_thread.thread().unpark();
    sampling_thread
        .join()
        .map_err(|_| anyhow::anyhow!("GPU memory sampler panicked"))?;
    let peak_process_bytes = baseline_free.saturating_sub(minimum_free.load(Ordering::Relaxed));
    eprintln!(
        "gpu_memory total_bytes={} baseline_free_bytes={} peak_process_bytes={} peak_process_gib={:.3}",
        total_device_bytes,
        baseline_free,
        peak_process_bytes,
        peak_process_bytes as f64 / (1_u64 << 30) as f64,
    );
    eprintln!(
        "real_direct_proof={} bytes={} online_seconds={:.6} self_check={} output={}",
        if self_check {"VERIFIED"} else {"GENERATED_FOR_NODE_VERIFICATION"},
        result["wire_bytes"],
        online_seconds,
        self_check,
        output_path.display()
    );
    Ok(())
}

/// Standalone qualification checks on the finished proof: canonical codec,
/// CPU verification and mutation rejection. Returns the online seconds measured
/// right after verification. Server mode skips this; its node verifies the proof.
fn self_check_complete_proof(
    statement: ForgeMatrixV4TranscriptStatement,
    cpu_fixed: [CpuDigest; 3],
    base_input: &[u8],
    canonical: &[u8],
    online_started: Instant,
) -> Result<f64> {
    let decoded = decode_forgematrix_v4_transparent_proof(canonical)?;
    ensure!(
        encode_forgematrix_v4_transparent_proof(&decoded)? == canonical,
        "complete proof codec is not canonical"
    );
    let verify_started = Instant::now();
    verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, base_input, &decoded)?;
    eprintln!(
        "complete_cpu_verify_seconds={:.6}",
        verify_started.elapsed().as_secs_f64()
    );
    let online_seconds = online_started.elapsed().as_secs_f64();
    let mut changed = decoded.clone();
    changed.final_activation[0] += CpuFelt::one();
    ensure!(
        verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, base_input, &changed)
            .is_err(),
        "mutated final activation was accepted"
    );
    let mut changed = decoded.clone();
    changed.banks[0].relations[0]
        .matrix
        .preactivation_evaluation += CpuExt::one();
    ensure!(
        verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, base_input, &changed)
            .is_err(),
        "mutated matrix relation was accepted"
    );
    let mut changed = decoded.clone();
    changed.banks[1].opening.fixed_column_evaluations[0] += CpuExt::one();
    ensure!(
        verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, base_input, &changed)
            .is_err(),
        "mutated fixed opening was accepted"
    );
    ensure!(
        decode_forgematrix_v4_transparent_proof(&canonical[..canonical.len() - 1]).is_err(),
        "truncated complete proof was accepted"
    );
    let mut changed_bytes = canonical.to_vec();
    let last = changed_bytes.len() - 1;
    changed_bytes[last] ^= 1;
    ensure!(
        decode_forgematrix_v4_transparent_proof(&changed_bytes)
            .and_then(|changed| encode_forgematrix_v4_transparent_proof(&changed).map(|_| changed))
            .map_or(true, |changed| {
                verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, base_input, &changed)
                    .is_err()
            }),
        "mutated complete-proof byte was accepted"
    );
    eprintln!("complete_mutations=REJECTED final,matrix,opening,truncation,byte");
    Ok(online_seconds)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn prove_bank_relations<'a>(
    bank: usize,
    statement: ForgeMatrixV4TranscriptStatement,
    base_input: &[u8],
    encoded_bank: &[u8],
    resident: Option<&'a DeviceBuffer<u8>>,
    dynamic: JaggedTraceMle<Felt, TaskScope>,
    boundary_activation: &TensorView<'_,Felt,TaskScope>,
    cpu_challenger: &mut cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4Challenger,
    gpu_challenger: &mut GpuChallenger,
    scope: &TaskScope,
) -> Result<(
    [ForgeMatrixV4RelationRepetitionProof; 2],
    Vec<CpuOpeningClaim>,
    Vec<CpuOpeningClaim>,
    DeviceBank<'a>,
    JaggedTraceMle<Felt, TaskScope>,
)> {
    if device_relations::enabled() {
        return prove_bank_relations_device(bank,statement,base_input,encoded_bank,resident,dynamic,boundary_activation,cpu_challenger,gpu_challenger,scope);
    }
    let upload_started = Instant::now();
    let mut encoded_device = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {DeviceBank::Spilled} else {match resident {
        Some(buffer) => DeviceBank::Resident(buffer),
        None => {
            let uploaded = DeviceBuffer::from_host_slice(encoded_bank, scope)?;
            scope.synchronize_blocking()?;
            DeviceBank::Owned(uploaded)
        }
    }};
    eprintln!(
        "bank={bank} relation_upload_seconds={:.6}",
        upload_started.elapsed().as_secs_f64()
    );

    let mut opening_claims = Vec::<CpuOpeningClaim>::with_capacity(16);
    let mut boundary_claims = Vec::<CpuOpeningClaim>::with_capacity(2);
    let mut relations = Vec::with_capacity(2);

    for repetition in 0..2 {
        if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()!=Ok("dynamic") && matches!(encoded_device,DeviceBank::Spilled){
            encoded_device=DeviceBank::Owned(DeviceBuffer::from_host_slice(encoded_bank,scope)?);
            scope.synchronize_blocking()?;
        }
        let repetition_started = Instant::now();
        let cpu_matrix_point =
            sample_forgematrix_v4_matrix_point(cpu_challenger, bank, repetition)?;
        let gpu_matrix_point = sample_matrix_point(gpu_challenger, bank, repetition);
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_matrix_point.0.iter().copied().collect::<Vec<_>>())?
                == cpu_matrix_point.layer.iter().copied().collect::<Vec<_>>(),
            "matrix layer point diverged"
        );
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_matrix_point.1.iter().copied().collect::<Vec<_>>())?
                == cpu_matrix_point.batch.iter().copied().collect::<Vec<_>>(),
            "matrix batch point diverged"
        );
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_matrix_point.2.iter().copied().collect::<Vec<_>>())?
                == cpu_matrix_point.output.iter().copied().collect::<Vec<_>>(),
            "matrix output point diverged"
        );

        let dynamic_tensor = dynamic.main_virtual_tensor(LOG_ROWS);
        let preactivation_reduced = reduce_batches(&dynamic_tensor, 0, &gpu_matrix_point.1, scope)?;
        let next_reduced =
            reduce_batches(&dynamic_tensor, BANK_VALUES, &gpu_matrix_point.1, scope)?;
        let matrix_eval_started=Instant::now();
        let preactivation_evaluation = evaluate_matrix(
            &preactivation_reduced,
            &gpu_matrix_point.0,
            &gpu_matrix_point.2,
        );
        eprintln!("bank={bank} repetition={repetition} cpu_matrix_claim_evaluation_seconds={:.6}",matrix_eval_started.elapsed().as_secs_f64());
        let cpu_mask = forgematrix_v4_mask_evaluation(
            statement.challenge_digest,
            bank,
            &cpu_matrix_point.layer,
            &cpu_matrix_point.batch,
            &cpu_matrix_point.output,
        )?;
        let mask_evaluation: Ext = bridge(cpu_mask)?;
        observe_bytes(gpu_challenger, MATRIX_PROOF_DOMAIN);
        gpu_challenger.observe_ext_element(preactivation_evaluation);
        gpu_challenger.observe_ext_element(mask_evaluation);
        let matrix_claim = preactivation_evaluation - mask_evaluation;

        let weights = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {
            resident::weights(bank,&gpu_matrix_point.2,scope)?
        } else {reduce_weights(encoded_device.get(), &gpu_matrix_point.2, scope)?};
        let boundary_started=Instant::now();
        let boundary_coefficients=Mle::<Ext>::partial_lagrange(&gpu_matrix_point.1);
        let boundary=gpu_reductions::reduce(boundary_activation.clone(),boundary_coefficients.guts().as_slice(),1,BATCH,WIDTH,scope)?;
        eprintln!("bank={bank} repetition={repetition} gpu_boundary_reduce_seconds={:.6}",boundary_started.elapsed().as_secs_f64());
        let input_build_started=Instant::now();
        let mut input_values = Vec::with_capacity(LAYERS * WIDTH);
        input_values.extend_from_slice(&boundary);
        input_values.extend_from_slice(&next_reduced[..(LAYERS - 1) * WIDTH]);
        let layer_weights = Mle::<Ext>::partial_lagrange(&gpu_matrix_point.0);
        let equality_values = layer_weights
            .guts()
            .as_slice()
            .iter()
            .flat_map(|value| std::iter::repeat_n(*value, WIDTH))
            .collect::<Vec<_>>();
        eprintln!("bank={bank} repetition={repetition} cpu_matrix_input_build_seconds={:.6}",input_build_started.elapsed().as_secs_f64());
        let matrix_started = Instant::now();
        let (matrix_sumcheck, matrix_endpoints) = triple_hadamard_sumcheck(
            weights,
            upload_ext(input_values, scope),
            upload_ext(equality_values, scope),
            &mut *gpu_challenger,
            matrix_claim,
        );
        scope.synchronize_blocking()?;
        gpu_challenger.observe_ext_element(matrix_endpoints[0]);
        gpu_challenger.observe_ext_element(matrix_endpoints[1]);
        let cpu_matrix = CpuMatrixProof {
            sumcheck: bridge(matrix_sumcheck.clone())?,
            preactivation_evaluation: bridge(preactivation_evaluation)?,
            weight_evaluation: bridge(matrix_endpoints[0])?,
            input_evaluation: bridge(matrix_endpoints[1])?,
        };
        verify_forgematrix_v4_matrix_relation(
            &cpu_matrix_point,
            cpu_mask,
            &cpu_matrix,
            cpu_challenger,
        )?;
        opening_claims.extend(forgematrix_v4_matrix_opening_claims(
            &cpu_matrix_point,
            &cpu_matrix,
        )?);
        eprintln!(
            "bank={bank} repetition={repetition} matrix_seconds={:.6}",
            matrix_started.elapsed().as_secs_f64()
        );

        let terminal_layer = Point::from(
            matrix_sumcheck
                .point_and_eval
                .0
                .iter()
                .take(7)
                .copied()
                .collect::<Vec<_>>(),
        );
        let terminal_common = Point::from(
            matrix_sumcheck
                .point_and_eval
                .0
                .iter()
                .skip(7)
                .copied()
                .collect::<Vec<_>>(),
        );
        let next_eval_started=Instant::now();
        let next_values = evaluate_rows(&next_reduced, &terminal_common);
        let boundary_evaluation = evaluate_row(&boundary, &terminal_common);
        eprintln!("bank={bank} repetition={repetition} cpu_next_and_boundary_evaluation_seconds={:.6}",next_eval_started.elapsed().as_secs_f64());
        observe_bytes(gpu_challenger, SHIFT_PROOF_DOMAIN);
        gpu_challenger.observe_ext_element(matrix_endpoints[1]);
        gpu_challenger.observe_ext_element(boundary_evaluation);
        let shift_coefficients = shifted_coefficients(&terminal_layer);
        let shift_claim =
            matrix_endpoints[1] - equality_at_boolean(&terminal_layer, 0) * boundary_evaluation;
        let shift_started = Instant::now();
        let (shift_sumcheck, shift_endpoints) = simple_hadamard_sumcheck(
            upload_ext(next_values, scope),
            upload_ext(shift_coefficients, scope),
            &mut *gpu_challenger,
            shift_claim,
        );
        scope.synchronize_blocking()?;
        gpu_challenger.observe_ext_element(shift_endpoints[0]);
        let cpu_shift = CpuShiftProof {
            sumcheck: bridge(shift_sumcheck)?,
            boundary_evaluation: bridge(boundary_evaluation)?,
            next_activation_evaluation: bridge(shift_endpoints[0])?,
        };
        let cpu_terminal_layer = forgematrix_v4_matrix_terminal_layer(&cpu_matrix)?;
        verify_forgematrix_v4_shift_relation(
            &cpu_terminal_layer,
            cpu_matrix.input_evaluation,
            &cpu_shift,
            cpu_challenger,
        )?;
        opening_claims.push(forgematrix_v4_shift_opening_claim(
            &cpu_matrix_point,
            &cpu_matrix,
            &cpu_shift,
        )?);
        let initial_check = if bank == 0 {
            let cpu_boundary_point =
                forgematrix_v4_shift_boundary_point(&cpu_matrix_point, &cpu_matrix)?;
            let base_input=base_input.to_vec();
            let expected_boundary=cpu_shift.boundary_evaluation;
            Some(thread::spawn(move || -> Result<()> {
            let initial_check_started=Instant::now();
            let expected = forgematrix_v4_initial_activation_evaluation(
                statement.challenge_digest,
                &base_input,
                &cpu_boundary_point.batch,
                &cpu_boundary_point.output,
            )?;
            eprintln!("bank={bank} repetition={repetition} cpu_initial_boundary_check_seconds={:.6}",initial_check_started.elapsed().as_secs_f64());
            ensure!(
                expected == expected_boundary,
                "public initial activation boundary diverged"
            );
            Ok(())
            }))
        } else {
            boundary_claims.push(forgematrix_v4_shift_boundary_opening_claim(
                &cpu_matrix_point,
                &cpu_matrix,
                &cpu_shift,
            )?);
            None
        };
        eprintln!(
            "bank={bank} repetition={repetition} shift_seconds={:.6}",
            shift_started.elapsed().as_secs_f64()
        );

        let cpu_cubic_point = sample_forgematrix_v4_cubic_point(cpu_challenger, bank, repetition)?;
        let gpu_cubic_point = sample_cubic_point(gpu_challenger, bank, repetition);
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_cubic_point.iter().copied().collect::<Vec<_>>())?
                == cpu_cubic_point
                    .layer
                    .iter()
                    .chain(cpu_cubic_point.batch.iter())
                    .chain(cpu_cubic_point.output.iter())
                    .copied()
                    .collect::<Vec<_>>(),
            "cubic point diverged"
        );
        if std::env::var_os("CMFD_MULTI_GPU_STAGE").is_some(){
            scope.synchronize_blocking()?;
            encoded_device=DeviceBank::Spilled;
            scope.synchronize_blocking()?;
        }
        observe_bytes(gpu_challenger, CUBIC_PROOF_DOMAIN);
        let cubic_started = Instant::now();
        let preactivation = lift_dynamic_half(&dynamic_tensor, 0, scope)?;
        let next_activation = lift_dynamic_half(&dynamic_tensor, BANK_VALUES, scope)?;
        if std::env::var("CMFD_SHARED_MODEL").as_deref()==Ok("1") {gpu_witness::validate_lifts(&dynamic_tensor,&preactivation,&next_activation,scope)?;}

        let equality=low_memory_sumcheck::bounded_equality(&gpu_cubic_point,scope);
        let (cubic_sumcheck, cubic_endpoints) = cubic_transition_sumcheck(
            preactivation,
            next_activation,
            equality,
            &mut *gpu_challenger,
            Ext::zero(),
        );
        scope.synchronize_blocking()?;
        gpu_challenger.observe_ext_element(cubic_endpoints[0]);
        gpu_challenger.observe_ext_element(cubic_endpoints[1]);
        let cpu_cubic = CpuCubicProof {
            sumcheck: bridge(cubic_sumcheck)?,
            preactivation_evaluation: bridge(cubic_endpoints[0])?,
            next_activation_evaluation: bridge(cubic_endpoints[1])?,
        };
        verify_forgematrix_v4_cubic_relation(&cpu_cubic_point, &cpu_cubic, cpu_challenger)?;
        if let Some(check)=initial_check {
            check.join().map_err(|_|anyhow::anyhow!("initial boundary check panicked"))??;
        }
        opening_claims.extend(forgematrix_v4_cubic_opening_claims(&cpu_cubic)?);
        relations.push(ForgeMatrixV4RelationRepetitionProof {
            matrix: cpu_matrix,
            shift: cpu_shift,
            cubic: cpu_cubic,
        });
        eprintln!(
            "bank={bank} repetition={repetition} cubic_seconds={:.6}",
            cubic_started.elapsed().as_secs_f64()
        );
        eprintln!(
            "bank={bank} repetition={repetition} total_seconds={:.6}",
            repetition_started.elapsed().as_secs_f64()
        );
    }
    eprintln!("real_bank_relations=VERIFIED bank={bank} repetitions=2");
    Ok((
        relations
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong relation repetition count"))?,
        opening_claims,
        boundary_claims,
        encoded_device,
        dynamic,
    ))
}

fn prove_bank_relations_device<'a>(
    bank: usize,
    statement: ForgeMatrixV4TranscriptStatement,
    base_input: &[u8],
    encoded_bank: &[u8],
    resident: Option<&'a DeviceBuffer<u8>>,
    dynamic: JaggedTraceMle<Felt, TaskScope>,
    boundary_activation: &TensorView<'_,Felt,TaskScope>,
    cpu_challenger: &mut cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4Challenger,
    gpu_challenger: &mut GpuChallenger,
    scope: &TaskScope,
) -> Result<(
    [ForgeMatrixV4RelationRepetitionProof; 2],
    Vec<CpuOpeningClaim>,
    Vec<CpuOpeningClaim>,
    DeviceBank<'a>,
    JaggedTraceMle<Felt, TaskScope>,
)> {
    let upload_started = Instant::now();
    let mut encoded_device = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {DeviceBank::Spilled} else {match resident {
        Some(buffer) => DeviceBank::Resident(buffer),
        None => {
            let uploaded = DeviceBuffer::from_host_slice(encoded_bank, scope)?;
            scope.synchronize_blocking()?;
            DeviceBank::Owned(uploaded)
        }
    }};
    eprintln!(
        "bank={bank} relation_upload_seconds={:.6}",
        upload_started.elapsed().as_secs_f64()
    );

    let mut opening_claims = Vec::<CpuOpeningClaim>::with_capacity(16);
    let mut boundary_claims = Vec::<CpuOpeningClaim>::with_capacity(2);
    let mut relations = Vec::with_capacity(2);

    for repetition in 0..2 {
        if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()!=Ok("dynamic") && matches!(encoded_device,DeviceBank::Spilled){
            encoded_device=DeviceBank::Owned(DeviceBuffer::from_host_slice(encoded_bank,scope)?);
            scope.synchronize_blocking()?;
        }
        let repetition_started = Instant::now();
        let cpu_matrix_point =
            sample_forgematrix_v4_matrix_point(cpu_challenger, bank, repetition)?;
        let gpu_matrix_point = sample_matrix_point(gpu_challenger, bank, repetition);
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_matrix_point.0.iter().copied().collect::<Vec<_>>())?
                == cpu_matrix_point.layer.iter().copied().collect::<Vec<_>>(),
            "matrix layer point diverged"
        );
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_matrix_point.1.iter().copied().collect::<Vec<_>>())?
                == cpu_matrix_point.batch.iter().copied().collect::<Vec<_>>(),
            "matrix batch point diverged"
        );
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_matrix_point.2.iter().copied().collect::<Vec<_>>())?
                == cpu_matrix_point.output.iter().copied().collect::<Vec<_>>(),
            "matrix output point diverged"
        );

        let dynamic_tensor = dynamic.main_virtual_tensor(LOG_ROWS);
        let preactivation_reduced = device_relations::reduce_batches(&dynamic_tensor, 0, &gpu_matrix_point.1, scope)?;
        let next_reduced =
            device_relations::reduce_batches(&dynamic_tensor, BANK_VALUES, &gpu_matrix_point.1, scope)?;
        let matrix_eval_started=Instant::now();
        let preactivation_evaluation = device_relations::evaluate_matrix(
            &preactivation_reduced,
            &gpu_matrix_point.0,
            &gpu_matrix_point.2,
            scope,
        )?;
        eprintln!("bank={bank} repetition={repetition} device_matrix_claim_evaluation_seconds={:.6}",matrix_eval_started.elapsed().as_secs_f64());
        let cpu_mask = forgematrix_v4_mask_evaluation(
            statement.challenge_digest,
            bank,
            &cpu_matrix_point.layer,
            &cpu_matrix_point.batch,
            &cpu_matrix_point.output,
        )?;
        let mask_evaluation: Ext = bridge(cpu_mask)?;
        observe_bytes(gpu_challenger, MATRIX_PROOF_DOMAIN);
        gpu_challenger.observe_ext_element(preactivation_evaluation);
        gpu_challenger.observe_ext_element(mask_evaluation);
        let matrix_claim = preactivation_evaluation - mask_evaluation;

        drop(preactivation_reduced);
        let weights = if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref()==Ok("dynamic") {
            resident::weights(bank,&gpu_matrix_point.2,scope)?
        } else {reduce_weights(encoded_device.get(), &gpu_matrix_point.2, scope)?};
        let boundary_started=Instant::now();
        let boundary_coefficients=Mle::<Ext>::partial_lagrange(&gpu_matrix_point.1);
        let boundary=device_relations::reduce(boundary_activation.clone(),boundary_coefficients.guts().as_slice(),1,BATCH,WIDTH,scope)?;
        eprintln!("bank={bank} repetition={repetition} gpu_boundary_reduce_seconds={:.6}",boundary_started.elapsed().as_secs_f64());
        let input_build_started=Instant::now();
        let (input_values,equality_values)=device_relations::matrix_inputs(&next_reduced,&boundary,&gpu_matrix_point.0,WIDTH,scope)?;
        eprintln!("bank={bank} repetition={repetition} device_matrix_input_build_seconds={:.6}",input_build_started.elapsed().as_secs_f64());
        let matrix_started = Instant::now();
        let (matrix_sumcheck, matrix_endpoints) = triple_hadamard_sumcheck(
            weights,
            input_values,
            equality_values,
            &mut *gpu_challenger,
            matrix_claim,
        );
        scope.synchronize_blocking()?;
        gpu_challenger.observe_ext_element(matrix_endpoints[0]);
        gpu_challenger.observe_ext_element(matrix_endpoints[1]);
        let cpu_matrix = CpuMatrixProof {
            sumcheck: bridge(matrix_sumcheck.clone())?,
            preactivation_evaluation: bridge(preactivation_evaluation)?,
            weight_evaluation: bridge(matrix_endpoints[0])?,
            input_evaluation: bridge(matrix_endpoints[1])?,
        };
        verify_forgematrix_v4_matrix_relation(
            &cpu_matrix_point,
            cpu_mask,
            &cpu_matrix,
            cpu_challenger,
        )?;
        opening_claims.extend(forgematrix_v4_matrix_opening_claims(
            &cpu_matrix_point,
            &cpu_matrix,
        )?);
        eprintln!(
            "bank={bank} repetition={repetition} matrix_seconds={:.6}",
            matrix_started.elapsed().as_secs_f64()
        );

        let terminal_layer = Point::from(
            matrix_sumcheck
                .point_and_eval
                .0
                .iter()
                .take(7)
                .copied()
                .collect::<Vec<_>>(),
        );
        let terminal_common = Point::from(
            matrix_sumcheck
                .point_and_eval
                .0
                .iter()
                .skip(7)
                .copied()
                .collect::<Vec<_>>(),
        );
        let next_eval_started=Instant::now();
        let next_values = device_relations::evaluate_rows(&next_reduced, &terminal_common, scope)?;
        drop(next_reduced);
        let boundary_evaluation = device_relations::evaluate_scalar(&boundary, &terminal_common, scope)?;
        drop(boundary);
        eprintln!("bank={bank} repetition={repetition} device_next_and_boundary_evaluation_seconds={:.6}",next_eval_started.elapsed().as_secs_f64());
        observe_bytes(gpu_challenger, SHIFT_PROOF_DOMAIN);
        gpu_challenger.observe_ext_element(matrix_endpoints[1]);
        gpu_challenger.observe_ext_element(boundary_evaluation);
        let shift_coefficients = shifted_coefficients(&terminal_layer);
        let shift_claim =
            matrix_endpoints[1] - equality_at_boolean(&terminal_layer, 0) * boundary_evaluation;
        let shift_started = Instant::now();
        let (shift_sumcheck, shift_endpoints) = simple_hadamard_sumcheck(
            Mle::new(next_values.into_inner().reshape([1,LAYERS])),
            upload_ext(shift_coefficients, scope),
            &mut *gpu_challenger,
            shift_claim,
        );
        scope.synchronize_blocking()?;
        gpu_challenger.observe_ext_element(shift_endpoints[0]);
        let cpu_shift = CpuShiftProof {
            sumcheck: bridge(shift_sumcheck)?,
            boundary_evaluation: bridge(boundary_evaluation)?,
            next_activation_evaluation: bridge(shift_endpoints[0])?,
        };
        let cpu_terminal_layer = forgematrix_v4_matrix_terminal_layer(&cpu_matrix)?;
        verify_forgematrix_v4_shift_relation(
            &cpu_terminal_layer,
            cpu_matrix.input_evaluation,
            &cpu_shift,
            cpu_challenger,
        )?;
        opening_claims.push(forgematrix_v4_shift_opening_claim(
            &cpu_matrix_point,
            &cpu_matrix,
            &cpu_shift,
        )?);
        let initial_check = if bank == 0 {
            let cpu_boundary_point =
                forgematrix_v4_shift_boundary_point(&cpu_matrix_point, &cpu_matrix)?;
            let base_input=base_input.to_vec();
            let expected_boundary=cpu_shift.boundary_evaluation;
            Some(thread::spawn(move || -> Result<()> {
            let initial_check_started=Instant::now();
            let expected = forgematrix_v4_initial_activation_evaluation(
                statement.challenge_digest,
                &base_input,
                &cpu_boundary_point.batch,
                &cpu_boundary_point.output,
            )?;
            eprintln!("bank={bank} repetition={repetition} cpu_initial_boundary_check_seconds={:.6}",initial_check_started.elapsed().as_secs_f64());
            ensure!(
                expected == expected_boundary,
                "public initial activation boundary diverged"
            );
            Ok(())
            }))
        } else {
            boundary_claims.push(forgematrix_v4_shift_boundary_opening_claim(
                &cpu_matrix_point,
                &cpu_matrix,
                &cpu_shift,
            )?);
            None
        };
        eprintln!(
            "bank={bank} repetition={repetition} shift_seconds={:.6}",
            shift_started.elapsed().as_secs_f64()
        );

        let cpu_cubic_point = sample_forgematrix_v4_cubic_point(cpu_challenger, bank, repetition)?;
        let gpu_cubic_point = sample_cubic_point(gpu_challenger, bank, repetition);
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_cubic_point.iter().copied().collect::<Vec<_>>())?
                == cpu_cubic_point
                    .layer
                    .iter()
                    .chain(cpu_cubic_point.batch.iter())
                    .chain(cpu_cubic_point.output.iter())
                    .copied()
                    .collect::<Vec<_>>(),
            "cubic point diverged"
        );
        if std::env::var_os("CMFD_MULTI_GPU_STAGE").is_some(){
            scope.synchronize_blocking()?;
            encoded_device=DeviceBank::Spilled;
            scope.synchronize_blocking()?;
        }
        observe_bytes(gpu_challenger, CUBIC_PROOF_DOMAIN);
        let cubic_started = Instant::now();
        let preactivation = lift_dynamic_half(&dynamic_tensor, 0, scope)?;
        let next_activation = lift_dynamic_half(&dynamic_tensor, BANK_VALUES, scope)?;
        if std::env::var("CMFD_SHARED_MODEL").as_deref()==Ok("1") {gpu_witness::validate_lifts(&dynamic_tensor,&preactivation,&next_activation,scope)?;}

        let equality=low_memory_sumcheck::bounded_equality(&gpu_cubic_point,scope);
        let (cubic_sumcheck, cubic_endpoints) = cubic_transition_sumcheck(
            preactivation,
            next_activation,
            equality,
            &mut *gpu_challenger,
            Ext::zero(),
        );
        scope.synchronize_blocking()?;
        gpu_challenger.observe_ext_element(cubic_endpoints[0]);
        gpu_challenger.observe_ext_element(cubic_endpoints[1]);
        let cpu_cubic = CpuCubicProof {
            sumcheck: bridge(cubic_sumcheck)?,
            preactivation_evaluation: bridge(cubic_endpoints[0])?,
            next_activation_evaluation: bridge(cubic_endpoints[1])?,
        };
        verify_forgematrix_v4_cubic_relation(&cpu_cubic_point, &cpu_cubic, cpu_challenger)?;
        if let Some(check)=initial_check {
            check.join().map_err(|_|anyhow::anyhow!("initial boundary check panicked"))??;
        }
        opening_claims.extend(forgematrix_v4_cubic_opening_claims(&cpu_cubic)?);
        relations.push(ForgeMatrixV4RelationRepetitionProof {
            matrix: cpu_matrix,
            shift: cpu_shift,
            cubic: cpu_cubic,
        });
        eprintln!(
            "bank={bank} repetition={repetition} cubic_seconds={:.6}",
            cubic_started.elapsed().as_secs_f64()
        );
        eprintln!(
            "bank={bank} repetition={repetition} total_seconds={:.6}",
            repetition_started.elapsed().as_secs_f64()
        );
    }
    eprintln!("real_bank_relations=VERIFIED bank={bank} repetitions=2");
    Ok((
        relations
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong relation repetition count"))?,
        opening_claims,
        boundary_claims,
        encoded_device,
        dynamic,
    ))
}

fn read_base_input(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(MODEL_HEADER_BYTES))?;
    let mut base = vec![0_u8; CELLS];
    file.read_exact(&mut base)?;
    ensure!(
        base.iter().all(|value| *value <= 250),
        "invalid base input byte"
    );
    Ok(base)
}

fn map_encoded_bank(path: &Path, bank: usize) -> Result<Mmap> {
    ensure!(bank < 3, "bank index is out of range");
    let file = File::open(path)?;
    let offset = MODEL_HEADER_BYTES + CELLS as u64 + bank as u64 * BANK_BYTES as u64;
    ensure!(
        file.metadata()?.len() >= offset + BANK_BYTES as u64,
        "model bank is truncated"
    );
    let bank = unsafe {
        MmapOptions::new()
            .offset(offset)
            .len(BANK_BYTES)
            .map(&file)?
    };
    ensure!(
        bank.par_iter().all(|value| *value <= 250),
        "invalid weight byte"
    );
    Ok(bank)
}

fn read_final_activation(path: &Path) -> Result<Vec<CpuFelt>> {
    let bytes = std::fs::read(path)?;
    ensure!(bytes.len() == CELLS * 4, "wrong final activation length");
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|bytes| {
            let value = u32::from_le_bytes(*bytes);
            ensure!(value < MODULUS, "noncanonical final activation");
            Ok(CpuFelt::from_canonical_u32(value))
        })
        .collect()
}

fn montgomery_values(map:&SealedWords)->Result<&[Felt]>{
    ensure!(map.modulus()==MODULUS&&map.words().len()*4==DYNAMIC_BYTES,"wrong trusted sealed trace shape/field");
    ensure!(size_of::<Felt>()==4&&map.words().as_ptr().align_offset(align_of::<Felt>())==0,"sealed field representation mismatch");
    // SealedWords validated every word once. Kernel WRITE/GROW/SHRINK seals keep
    // those bytes immutable; its private mapping cannot be exposed mutably.
    Ok(unsafe{std::slice::from_raw_parts(map.words().as_ptr().cast::<Felt>(),map.words().len())})
}

fn last_activation_layer(dynamic: &[Felt]) -> &[Felt] {
    let start = BANK_VALUES + (LAYERS - 1) * CELLS;
    &dynamic[start..start + CELLS]
}

fn build_initial_activation(challenge: [u8; 32], base: &[u8]) -> Vec<Felt> {
    let coefficients = forgematrix_v4_mask_coefficients(challenge, u32::MAX);
    base.par_iter()
        .enumerate()
        .map(|(index, encoded)| {
            let row = index / WIDTH;
            let column = index % WIDTH;
            let mut mask = u32::from(coefficients[0]);
            for bit in 0..7 {
                if ((row >> bit) & 1) != 0 {
                    mask += u32::from(coefficients[1 + bit]);
                }
            }
            for bit in 0..12 {
                if ((column >> bit) & 1) != 0 {
                    mask += u32::from(coefficients[8 + bit]);
                }
            }
            let signed = i64::from(*encoded) - 125 + i64::from(mask);
            let canonical = signed.rem_euclid(i64::from(MODULUS)) as u32;
            let value = Felt::from_canonical_u32(canonical);
            value * value * value
        })
        .collect()
}

fn reduce_batches(
    dynamic: &TensorView<'_, Felt, TaskScope>,
    offset: usize,
    batch_point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Vec<Ext>> {
    ensure!(offset.checked_add(BANK_VALUES).is_some_and(|end|end<=dynamic.total_len()),"batch reduction range");
    let coefficients=Mle::<Ext>::partial_lagrange(batch_point);
    let view=unsafe{TensorView::from_raw_parts(dynamic.as_ptr().add(offset),Dimensions::try_from([BANK_VALUES])?,scope.clone())};
    let started=Instant::now();
    let result=gpu_reductions::reduce(view,coefficients.guts().as_slice(),LAYERS,BATCH,WIDTH,scope)?;
    eprintln!("fused_dynamic_batch_reduce_seconds={:.6}",started.elapsed().as_secs_f64());
    Ok(result)
}

/// Lifts half of the device-resident base-field dynamic trace (pre-activations at offset 0,
/// next activations at `BANK_VALUES`) into an extension-field MLE on the GPU.
///
/// A width-one dot with `Ext::one()` writes `[x, 0, 0, 0]` for each canonical Montgomery word
/// `x`, which are the same words the host `Ext::from_base` lift used to upload. The cubic
/// sumcheck inputs, and therefore the transcript and proof, are unchanged; this only removes
/// a 2 GiB host conversion and pageable upload per repetition.
fn lift_dynamic_half(
    dynamic: &TensorView<'_, Felt, TaskScope>,
    offset: usize,
    scope: &TaskScope,
) -> Result<Mle<Ext, TaskScope>> {
    ensure!(
        offset + BANK_VALUES <= dynamic.total_len(),
        "dynamic trace lift is out of range"
    );
    let one = DeviceTensor::from_host(&Tensor::from(vec![Ext::one()]), scope)?;
    let view = unsafe {
        TensorView::from_raw_parts(
            dynamic.as_ptr().add(offset),
            Dimensions::try_from([1, BANK_VALUES])?,
            scope.clone(),
        )
    };
    let lifted = dot_along_dim_view(view, one.as_view(), 0);
    scope.synchronize_blocking()?;
    Ok(Mle::new(lifted.reshape([1, BANK_VALUES])))
}

fn reduce_weights(
    encoded: &DeviceBuffer<u8>,
    output_point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Mle<Ext, TaskScope>> {
    let coefficients = Mle::<Ext>::partial_lagrange(output_point)
        .guts()
        .as_slice()
        .to_vec();
    let coefficients = DeviceBuffer::from_host(&Buffer::from(coefficients), scope)?;
    let mut output = DeviceTensor::<Ext>::with_sizes_in([1, LAYERS * WIDTH], scope.clone());
    unsafe {
        output.assume_init();
        let kernel_args = args!(
            encoded.as_ptr(),
            coefficients.as_ptr(),
            output.as_mut_ptr(),
            LAYERS * WIDTH,
            WIDTH
        );
        scope.launch_kernel(
            cmfd_weight_output_reduction_kernel(),
            u32::try_from(LAYERS * WIDTH)?,
            256_u32,
            &kernel_args,
            0,
        )?;
    }
    scope.synchronize_blocking()?;
    Ok(Mle::new(output.into_inner()))
}

fn gpu_last_activation_layer(dynamic:&JaggedTraceMle<Felt,TaskScope>)->Result<TensorView<'_,Felt,TaskScope>>{
    let tensor=dynamic.main_virtual_tensor(LOG_ROWS);let offset=BANK_VALUES+(LAYERS-1)*CELLS;
    ensure!(offset+CELLS<=tensor.total_len(),"GPU boundary trace range");
    Ok(unsafe{TensorView::from_raw_parts(tensor.as_ptr().add(offset),Dimensions::try_from([BATCH,WIDTH])?,tensor.backend().clone())})
}

fn evaluate_matrix(values: &[Ext], layer: &Point<Ext>, output: &Point<Ext>) -> Ext {
    evaluate_row(&evaluate_rows(values,output),layer)
}

fn evaluate_rows(values:&[Ext],point:&Point<Ext>)->Vec<Ext>{
    let equality=Mle::<Ext>::partial_lagrange(point);
    let weights=equality.guts().as_slice();
    assert!(!weights.is_empty() && values.len()%weights.len()==0);
    values.par_chunks_exact(weights.len())
        .map(|row|row.iter().zip(weights).map(|(a,b)|*a**b).sum())
        .collect()
}

fn evaluate_row(values: &[Ext], point: &Point<Ext>) -> Ext {
    let equality = Mle::<Ext>::partial_lagrange(point);
    values
        .iter()
        .zip(equality.guts().as_slice())
        .map(|(a, b)| *a * *b)
        .sum()
}

fn upload_ext(values: Vec<Ext>, scope: &TaskScope) -> Mle<Ext, TaskScope> {
    let storage = DeviceBuffer::from_host(&Buffer::<Ext, CpuBackend>::from(values), scope)
        .unwrap()
        .into_inner();
    let len = storage.len();
    Mle::new(Tensor {
        storage,
        dimensions: Dimensions::try_from([1, len]).unwrap(),
    })
}

fn equality_at_boolean(point: &Point<Ext>, index: usize) -> Ext {
    point
        .iter()
        .enumerate()
        .fold(Ext::one(), |accumulator, (coordinate, value)| {
            let shift = point.dimension() - coordinate - 1;
            accumulator
                * if ((index >> shift) & 1) == 1 {
                    *value
                } else {
                    Ext::one() - *value
                }
        })
}

fn shifted_coefficients(source: &Point<Ext>) -> Vec<Ext> {
    (0..LAYERS)
        .map(|layer| {
            if layer + 1 < LAYERS {
                equality_at_boolean(source, layer + 1)
            } else {
                Ext::zero()
            }
        })
        .collect()
}

fn gpu_transcript(statement_digest: &[u8; 32]) -> GpuChallenger {
    let mut challenger = TestGC::default_challenger();
    observe_bytes(&mut challenger, statement_digest);
    challenger
}

fn bind_gpu_commitments(
    challenger: &mut GpuChallenger,
    fixed: &[GpuDigest; 3],
    dynamic: &[GpuDigest; 3],
) {
    observe_bytes(challenger, COMMITMENTS_DOMAIN);
    for bank in 0..3 {
        challenger.observe(fixed[bank]);
        challenger.observe(dynamic[bank]);
    }
}

fn sample_matrix_point(
    challenger: &mut GpuChallenger,
    bank: usize,
    repetition: usize,
) -> (Point<Ext>, Point<Ext>, Point<Ext>) {
    observe_relation_index(challenger, MATRIX_POINT_DOMAIN, bank, repetition);
    (
        sample_point(challenger, 7),
        sample_point(challenger, 7),
        sample_point(challenger, 12),
    )
}

fn sample_cubic_point(
    challenger: &mut GpuChallenger,
    bank: usize,
    repetition: usize,
) -> Point<Ext> {
    observe_relation_index(challenger, CUBIC_POINT_DOMAIN, bank, repetition);
    Point::from(
        sample_point(challenger, 7)
            .iter()
            .chain(sample_point(challenger, 7).iter())
            .chain(sample_point(challenger, 12).iter())
            .copied()
            .collect::<Vec<_>>(),
    )
}

fn sample_final_point(challenger: &mut GpuChallenger, repetition: usize) -> Point<Ext> {
    observe_relation_index(challenger, FINAL_POINT_DOMAIN, 2, repetition);
    Point::from(
        sample_point(challenger, 7)
            .iter()
            .chain(sample_point(challenger, 12).iter())
            .copied()
            .collect::<Vec<_>>(),
    )
}

fn observe_relation_index(
    challenger: &mut GpuChallenger,
    domain: &[u8],
    bank: usize,
    repetition: usize,
) {
    observe_bytes(challenger, domain);
    challenger.observe(Felt::from_canonical_usize(bank));
    challenger.observe(Felt::from_canonical_usize(repetition));
}

fn sample_point(challenger: &mut GpuChallenger, variables: usize) -> Point<Ext> {
    Point::from(
        (0..variables)
            .map(|_| challenger.sample_ext_element())
            .collect::<Vec<_>>(),
    )
}

fn observe_bytes(challenger: &mut GpuChallenger, bytes: &[u8]) {
    challenger.observe(Felt::from_canonical_usize(bytes.len()));
    for byte in bytes {
        challenger.observe(Felt::from_canonical_u8(*byte));
    }
}

fn digest_words<F: AbstractField<F = F> + Copy>(words: [[u32; 8]; 3]) -> [[F; 8]; 3] {
    words.map(|digest| digest.map(F::from_canonical_u32))
}

fn bridge<T: Serialize, U: DeserializeOwned>(value: T) -> Result<U> {
    Ok(bincode::deserialize(&bincode::serialize(&value)?)?)
}

#[cfg(test)]
mod all_relations_transcript_tests {
    use super::*;
    #[test]
    fn factored_parallel_evaluations_match_the_original_flat_mle() {
        for seed in 1..5 {
            let mut challenger=TestGC::default_challenger();
            challenger.observe(Felt::from_canonical_usize(seed));
            let layer=sample_point(&mut challenger,3);
            let output=sample_point(&mut challenger,5);
            let values=(0..256).map(|_|challenger.sample_ext_element()).collect::<Vec<_>>();
            let flat=Point::from(layer.iter().chain(output.iter()).copied().collect::<Vec<_>>());
            assert_eq!(evaluate_matrix(&values,&layer,&output),evaluate_row(&values,&flat));
            let rows=evaluate_rows(&values,&output);
            assert_eq!(rows.len(),8);
            for (row,expected) in values.chunks_exact(32).zip(rows) {
                assert_eq!(expected,evaluate_row(row,&output));
            }
        }
    }

}
