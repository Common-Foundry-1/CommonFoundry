use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
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
    forgematrix_v4_challenge_digest, forgematrix_v4_proof_system_digest,
    forgematrix_v4_work_digest, BlockChallenge, ForgeMatrixV4FixedArtifactRecordV1,
    FORGEMATRIX_V4_ALGORITHM_VERSION, FORGEMATRIX_V4_PROOF_VERSION,
    PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST, PRODUCTION_V4_TESTNET_NETWORK_ID,
};
use cpu_slop_algebra::AbstractField as CpuAbstractField;
use memmap2::{Mmap, MmapOptions};
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_alloc::{Buffer, CpuBackend};
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_multilinear::{Mle, Point};
use slop_tensor::{Dimensions, Tensor, TensorView};
use sp1_gpu_cudart::{
    args, cuda_memory_info, dot_along_dim_view, run_sync_in_place, DeviceBuffer, DevicePoint,
    DeviceTensor, TaskScope,
};
use sp1_gpu_jagged_sumcheck::{
    cubic_transition_sumcheck, simple_hadamard_sumcheck, triple_hadamard_sumcheck,
};
use sp1_gpu_sys::kernels::cmfd_weight_output_reduction_kernel;
use sp1_gpu_utils::{Ext, Felt, TestGC};

#[path = "../real_v4_opening.rs"]
mod real_v4_opening;

const LAYERS: usize = 128;
const BATCH: usize = 128;
const WIDTH: usize = 4096;
const CELLS: usize = BATCH * WIDTH;
const BANK_VALUES: usize = LAYERS * CELLS;
const BANK_BYTES: usize = LAYERS * WIDTH * WIDTH;
const DYNAMIC_BYTES: usize = 2 * BANK_VALUES * size_of::<u32>();
const MODEL_HEADER_BYTES: u64 = 184;
const MODULUS: u32 = 0x7f00_0001;
const COMMITMENTS_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/Commitments/v1";
const MATRIX_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/MatrixPoint/v1";
const MATRIX_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/MatrixProof/v1";
const SHIFT_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/ShiftProof/v1";
const CUBIC_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/CubicPoint/v1";
const CUBIC_PROOF_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/CubicProof/v1";
const FINAL_POINT_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/FinalPoint/v1";

type GpuChallenger = <TestGC as IopCtx>::Challenger;
type GpuDigest = <TestGC as IopCtx>::Digest;

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

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let model_path = PathBuf::from(args.next().context("missing model-bank path")?);
    let artifact_dir = PathBuf::from(args.next().context("missing fixed-artifact directory")?);
    let template_path = PathBuf::from(args.next().context("missing frozen V4 template")?);
    let dynamic_prefix = PathBuf::from(args.next().context("missing dynamic trace prefix")?);
    let dynamic_record_path =
        PathBuf::from(args.next().context("missing dynamic commitment record")?);
    let final_path = PathBuf::from(args.next().context("missing final activation")?);
    let output_path = PathBuf::from(args.next().context("missing complete proof output")?);
    ensure!(args.next().is_none(), "unexpected extra arguments");

    let fixed_record: ForgeMatrixV4FixedArtifactRecordV1 = serde_json::from_reader(File::open(
        artifact_dir.join("FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"),
    )?)?;
    fixed_record.validate()?;
    ensure!(
        fixed_record.record_digest() == PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST,
        "fixed artifact record is not the compiled V4 testnet record"
    );
    let frozen: FrozenProductionV4Template = serde_json::from_reader(File::open(template_path)?)?;
    ensure!(
        frozen.challenge.network_id == PRODUCTION_V4_TESTNET_NETWORK_ID,
        "frozen template belongs to another network"
    );
    let dynamic_record: DynamicCommitmentRecord =
        serde_json::from_reader(File::open(dynamic_record_path)?)?;
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

    let fixed_words: [[u32; 8]; 3] =
        std::array::from_fn(|bank| fixed_record.banks()[bank].commitment_words());
    let dynamic_words: [[u32; 8]; 3] =
        std::array::from_fn(|bank| dynamic_record.banks[bank].commitment_words);
    let cpu_fixed = digest_words::<CpuFelt>(fixed_words);
    let cpu_dynamic = digest_words::<CpuFelt>(dynamic_words);
    let gpu_fixed = digest_words::<Felt>(fixed_words);
    let gpu_dynamic = digest_words::<Felt>(dynamic_words);

    let base_input = read_base_input(&model_path)?;
    let final_activation = read_final_activation(&final_path)?;
    let block = frozen.challenge;
    let nonce = frozen.nonce;
    let challenge_digest =
        forgematrix_v4_challenge_digest(&block, nonce, fixed_record.manifest_digest());
    let final_activation_digest =
        forgematrix_v4_final_activation_digest(challenge_digest, &final_activation);
    let statement = ForgeMatrixV4TranscriptStatement {
        block,
        algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
        proof_version: FORGEMATRIX_V4_PROOF_VERSION,
        nonce,
        proof_system_digest: forgematrix_v4_proof_system_digest(),
        model_manifest_digest: fixed_record.manifest_digest(),
        challenge_digest,
        final_activation_digest,
        work_digest: forgematrix_v4_work_digest(
            fixed_record.manifest_digest(),
            challenge_digest,
            final_activation_digest,
        ),
    };

    let mut dynamic_maps = Vec::with_capacity(3);
    for bank in 0..3 {
        let path = PathBuf::from(format!(
            "{}-bank{bank}-dynamic.bin",
            dynamic_prefix.display()
        ));
        let file = File::open(&path)?;
        ensure!(
            file.metadata()?.len() == DYNAMIC_BYTES as u64,
            "wrong dynamic trace length"
        );
        let map = unsafe { MmapOptions::new().map(&file)? };
        montgomery_values(&map)?;
        dynamic_maps.push(map);
    }
    let initial_activation = build_initial_activation(challenge_digest, &base_input);
    let model_bank_prep_started = Instant::now();
    let encoded_banks: [Vec<u8>; 3] = (0..3)
        .map(|bank| read_encoded_bank(&model_path, bank))
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong model-bank count"))?;
    eprintln!(
        "model_bank_prep_total_seconds={:.6}",
        model_bank_prep_started.elapsed().as_secs_f64()
    );
    let artifact_prep_started = Instant::now();
    let mut fixed_maps = Vec::with_capacity(3);
    for bank in 0..3 {
        let started = Instant::now();
        fixed_maps.push(real_v4_opening::FixedArtifactMaps::open(
            &artifact_dir,
            fixed_record.banks()[bank],
        )?);
        eprintln!(
            "fixed_artifact_prep bank={bank} seconds={:.6}",
            started.elapsed().as_secs_f64()
        );
    }
    eprintln!(
        "fixed_artifact_prep_total_seconds={:.6}",
        artifact_prep_started.elapsed().as_secs_f64()
    );

    run_sync_in_place(move |scope| {
        prove_complete_proof(
            statement,
            cpu_fixed,
            cpu_dynamic,
            gpu_fixed,
            gpu_dynamic,
            base_input,
            final_activation,
            encoded_banks,
            dynamic_maps,
            fixed_maps,
            initial_activation,
            output_path,
            scope,
        )
    })??;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove_complete_proof(
    statement: ForgeMatrixV4TranscriptStatement,
    cpu_fixed: [CpuDigest; 3],
    cpu_dynamic: [CpuDigest; 3],
    gpu_fixed: [GpuDigest; 3],
    gpu_dynamic: [GpuDigest; 3],
    base_input: Vec<u8>,
    final_activation: Vec<CpuFelt>,
    encoded_banks: [Vec<u8>; 3],
    dynamic_maps: Vec<Mmap>,
    mut fixed_maps: Vec<real_v4_opening::FixedArtifactMaps>,
    initial_activation: Vec<Felt>,
    output_path: PathBuf,
    scope: TaskScope,
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
            thread::sleep(Duration::from_millis(1));
        }
    });
    let online_started = Instant::now();
    let dynamic_values = dynamic_maps
        .iter()
        .map(montgomery_values)
        .collect::<Result<Vec<_>>>()?;
    let mut cpu_challenger = forgematrix_v4_transcript(statement);
    bind_forgematrix_v4_commitments(&mut cpu_challenger, &cpu_fixed, &cpu_dynamic);
    let mut gpu_challenger = gpu_transcript(&statement.digest());
    bind_gpu_commitments(&mut gpu_challenger, &gpu_fixed, &gpu_dynamic);

    let mut relations = Vec::with_capacity(3);
    let mut claims = Vec::with_capacity(3);
    let mut openings = Vec::with_capacity(3);

    let [mut encoded, next_encoded, final_encoded] = encoded_banks;
    let (bank_relations, bank_claims, boundary_claims) = prove_bank_relations(
        0,
        statement,
        &base_input,
        &encoded,
        dynamic_values[0],
        &initial_activation,
        &mut cpu_challenger,
        &mut gpu_challenger,
        &scope,
    )?;
    ensure!(
        boundary_claims.is_empty(),
        "bank 0 produced a previous-bank boundary claim"
    );
    relations.push(bank_relations);
    claims.push(bank_claims);

    let boundary = last_activation_layer(dynamic_values[0]);
    let (bank_relations, bank_claims, boundary_claims) = prove_bank_relations(
        1,
        statement,
        &base_input,
        &next_encoded,
        dynamic_values[1],
        boundary,
        &mut cpu_challenger,
        &mut gpu_challenger,
        &scope,
    )?;
    relations.push(bank_relations);
    claims.push(bank_claims);
    claims[0].extend(boundary_claims);
    finalize_forgematrix_v4_bank_opening_claims(&mut claims[0])?;
    openings.push(real_v4_opening::prove_real_bank_opening(
        0,
        fixed_maps.remove(0),
        encoded,
        dynamic_values[0],
        gpu_fixed[0],
        gpu_dynamic[0],
        &claims[0],
        &mut gpu_challenger,
        &mut cpu_challenger,
        &scope,
    )?);
    encoded = next_encoded;

    let boundary = last_activation_layer(dynamic_values[1]);
    let next_encoded = final_encoded;
    let (bank_relations, bank_claims, boundary_claims) = prove_bank_relations(
        2,
        statement,
        &base_input,
        &next_encoded,
        dynamic_values[2],
        boundary,
        &mut cpu_challenger,
        &mut gpu_challenger,
        &scope,
    )?;
    relations.push(bank_relations);
    claims.push(bank_claims);
    claims[1].extend(boundary_claims);
    finalize_forgematrix_v4_bank_opening_claims(&mut claims[1])?;
    openings.push(real_v4_opening::prove_real_bank_opening(
        1,
        fixed_maps.remove(0),
        encoded,
        dynamic_values[1],
        gpu_fixed[1],
        gpu_dynamic[1],
        &claims[1],
        &mut gpu_challenger,
        &mut cpu_challenger,
        &scope,
    )?);
    encoded = next_encoded;

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
    finalize_forgematrix_v4_bank_opening_claims(&mut claims[2])?;
    openings.push(real_v4_opening::prove_real_bank_opening(
        2,
        fixed_maps.remove(0),
        encoded,
        dynamic_values[2],
        gpu_fixed[2],
        gpu_dynamic[2],
        &claims[2],
        &mut gpu_challenger,
        &mut cpu_challenger,
        &scope,
    )?);

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
    let canonical = encode_forgematrix_v4_transparent_proof(&proof)?;
    ensure!(
        canonical.len() == FORGEMATRIX_V4_TRANSPARENT_PROOF_BYTES,
        "complete proof has the wrong byte length"
    );
    let decoded = decode_forgematrix_v4_transparent_proof(&canonical)?;
    ensure!(
        encode_forgematrix_v4_transparent_proof(&decoded)? == canonical,
        "complete proof codec is not canonical"
    );
    let verify_started = Instant::now();
    verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, &base_input, &decoded)?;
    eprintln!(
        "complete_cpu_verify_seconds={:.6}",
        verify_started.elapsed().as_secs_f64()
    );
    let online_seconds = online_started.elapsed().as_secs_f64();
    let mut changed = decoded.clone();
    changed.final_activation[0] += CpuFelt::one();
    ensure!(
        verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, &base_input, &changed)
            .is_err(),
        "mutated final activation was accepted"
    );
    let mut changed = decoded.clone();
    changed.banks[0].relations[0]
        .matrix
        .preactivation_evaluation += CpuExt::one();
    ensure!(
        verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, &base_input, &changed)
            .is_err(),
        "mutated matrix relation was accepted"
    );
    let mut changed = decoded.clone();
    changed.banks[1].opening.fixed_column_evaluations[0] += CpuExt::one();
    ensure!(
        verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, &base_input, &changed)
            .is_err(),
        "mutated fixed opening was accepted"
    );
    ensure!(
        decode_forgematrix_v4_transparent_proof(&canonical[..canonical.len() - 1]).is_err(),
        "truncated complete proof was accepted"
    );
    let mut changed_bytes = canonical.clone();
    let last = changed_bytes.len() - 1;
    changed_bytes[last] ^= 1;
    ensure!(
        decode_forgematrix_v4_transparent_proof(&changed_bytes)
            .and_then(|changed| encode_forgematrix_v4_transparent_proof(&changed).map(|_| changed))
            .map_or(true, |changed| {
                verify_forgematrix_v4_transparent_proof(statement, cpu_fixed, &base_input, &changed)
                    .is_err()
            }),
        "mutated complete-proof byte was accepted"
    );
    eprintln!("complete_mutations=REJECTED final,matrix,opening,truncation,byte");
    std::fs::write(&output_path, &canonical)?;
    sampling.store(false, Ordering::Relaxed);
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
        "real_complete_proof=VERIFIED bytes={} online_seconds={:.6} output={}",
        canonical.len(),
        online_seconds,
        output_path.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove_bank_relations(
    bank: usize,
    statement: ForgeMatrixV4TranscriptStatement,
    base_input: &[u8],
    encoded_bank: &[u8],
    dynamic_values: &[Felt],
    boundary_activation: &[Felt],
    cpu_challenger: &mut cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4Challenger,
    gpu_challenger: &mut GpuChallenger,
    scope: &TaskScope,
) -> Result<(
    [ForgeMatrixV4RelationRepetitionProof; 2],
    Vec<CpuOpeningClaim>,
    Vec<CpuOpeningClaim>,
)> {
    let upload_started = Instant::now();
    let encoded_device = DeviceBuffer::from_host_slice(&encoded_bank, scope)?;
    let dynamic =
        DeviceTensor::from_raw(
            Tensor::from(DeviceBuffer::from_host_slice(dynamic_values, scope)?.into_inner())
                .reshape([2 * LAYERS, BATCH, WIDTH]),
        );
    scope.synchronize_blocking()?;
    eprintln!(
        "bank={bank} relation_upload_seconds={:.6}",
        upload_started.elapsed().as_secs_f64()
    );

    let mut opening_claims = Vec::<CpuOpeningClaim>::with_capacity(16);
    let mut boundary_claims = Vec::<CpuOpeningClaim>::with_capacity(2);
    let mut relations = Vec::with_capacity(2);

    for repetition in 0..2 {
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

        let preactivation_reduced = reduce_batches(&dynamic, 0, &gpu_matrix_point.1, scope)?;
        let next_reduced = reduce_batches(&dynamic, BANK_VALUES, &gpu_matrix_point.1, scope)?;
        let preactivation_evaluation = evaluate_matrix(
            &preactivation_reduced,
            &gpu_matrix_point.0,
            &gpu_matrix_point.2,
        );
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

        let weights = reduce_weights(&encoded_device, &gpu_matrix_point.2, scope)?;
        let boundary = reduce_initial_activation(boundary_activation, &gpu_matrix_point.1);
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
        let next_values = (0..LAYERS)
            .map(|layer| {
                evaluate_row(
                    &next_reduced[layer * WIDTH..(layer + 1) * WIDTH],
                    &terminal_common,
                )
            })
            .collect::<Vec<_>>();
        let boundary_evaluation = evaluate_row(&boundary, &terminal_common);
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
        if bank == 0 {
            let cpu_boundary_point =
                forgematrix_v4_shift_boundary_point(&cpu_matrix_point, &cpu_matrix)?;
            let expected = forgematrix_v4_initial_activation_evaluation(
                statement.challenge_digest,
                base_input,
                &cpu_boundary_point.batch,
                &cpu_boundary_point.output,
            )?;
            ensure!(
                expected == cpu_shift.boundary_evaluation,
                "public initial activation boundary diverged"
            );
        } else {
            boundary_claims.push(forgematrix_v4_shift_boundary_opening_claim(
                &cpu_matrix_point,
                &cpu_matrix,
                &cpu_shift,
            )?);
        }
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
        observe_bytes(gpu_challenger, CUBIC_PROOF_DOMAIN);
        let cubic_started = Instant::now();
        let preactivation = dynamic_values[..BANK_VALUES]
            .par_iter()
            .map(|value| Ext::from_base(*value))
            .collect::<Vec<_>>();
        let next_activation = dynamic_values[BANK_VALUES..]
            .par_iter()
            .map(|value| Ext::from_base(*value))
            .collect::<Vec<_>>();
        let equality: Mle<Ext, TaskScope> = DevicePoint::from_host(&gpu_cubic_point, scope)?
            .partial_lagrange()
            .into();
        let (cubic_sumcheck, cubic_endpoints) = cubic_transition_sumcheck(
            upload_ext(preactivation, scope),
            upload_ext(next_activation, scope),
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

fn read_encoded_bank(path: &Path, bank: usize) -> Result<Vec<u8>> {
    ensure!(bank < 3, "bank index is out of range");
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(
        MODEL_HEADER_BYTES + CELLS as u64 + bank as u64 * BANK_BYTES as u64,
    ))?;
    let mut bank = vec![0_u8; BANK_BYTES];
    file.read_exact(&mut bank)?;
    ensure!(
        bank.iter().all(|value| *value <= 250),
        "invalid weight byte"
    );
    Ok(bank)
}

fn read_final_activation(path: &Path) -> Result<Vec<CpuFelt>> {
    let bytes = std::fs::read(path)?;
    ensure!(bytes.len() == CELLS * 4, "wrong final activation length");
    bytes
        .chunks_exact(4)
        .map(|bytes| {
            let value = u32::from_le_bytes(bytes.try_into().unwrap());
            ensure!(value < MODULUS, "noncanonical final activation");
            Ok(CpuFelt::from_canonical_u32(value))
        })
        .collect()
}

fn montgomery_values(map: &Mmap) -> Result<&[Felt]> {
    ensure!(
        map.len() == DYNAMIC_BYTES,
        "wrong dynamic trace byte length"
    );
    ensure!(
        map.as_ptr().align_offset(align_of::<Felt>()) == 0,
        "unaligned dynamic trace"
    );
    let words = unsafe { std::slice::from_raw_parts(map.as_ptr().cast::<u32>(), map.len() / 4) };
    ensure!(
        words.par_iter().all(|value| *value < MODULUS),
        "invalid Montgomery field limb"
    );
    Ok(unsafe { std::slice::from_raw_parts(map.as_ptr().cast::<Felt>(), map.len() / 4) })
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
    dynamic: &DeviceTensor<Felt>,
    offset: usize,
    batch_point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Vec<Ext>> {
    let coefficients = Mle::<Ext>::partial_lagrange(batch_point)
        .guts()
        .as_slice()
        .to_vec();
    let coefficients = DeviceTensor::from_host(&Tensor::from(coefficients), scope)?;
    let mut result = DeviceBuffer::with_capacity_in(LAYERS * WIDTH, scope.clone());
    for layer in 0..LAYERS {
        let view = unsafe {
            TensorView::from_raw_parts(
                dynamic.as_ptr().add(offset + layer * CELLS),
                Dimensions::try_from([BATCH, WIDTH])?,
                scope.clone(),
            )
        };
        let reduced = dot_along_dim_view(view, coefficients.as_view(), 0);
        result.extend_from_device_slice(reduced.as_buffer())?;
    }
    scope.synchronize_blocking()?;
    Ok(result.to_host()?)
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
    Ok(Mle::new(output.into_inner()))
}

fn reduce_initial_activation(values: &[Felt], batch_point: &Point<Ext>) -> Vec<Ext> {
    let coefficients = Mle::<Ext>::partial_lagrange(batch_point);
    (0..WIDTH)
        .into_par_iter()
        .map(|column| {
            (0..BATCH)
                .map(|row| coefficients.guts().as_slice()[row] * values[row * WIDTH + column])
                .sum()
        })
        .collect()
}

fn evaluate_matrix(values: &[Ext], layer: &Point<Ext>, output: &Point<Ext>) -> Ext {
    let point = Point::from(
        layer
            .iter()
            .chain(output.iter())
            .copied()
            .collect::<Vec<_>>(),
    );
    evaluate_row(values, &point)
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
