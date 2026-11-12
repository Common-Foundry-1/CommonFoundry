use std::{fs::File, io::Read, path::Path, sync::Arc, time::Instant};

use anyhow::{ensure, Context, Result};
use cmfd_consensus::{
    forgematrix_v4_basefold::{
        verify_forgematrix_v4_opening_reduction, ForgeMatrixV4Challenger as CpuChallenger,
        ForgeMatrixV4OpeningClaim as CpuClaim, ForgeMatrixV4OpeningCommitment as CpuCommitment,
        ForgeMatrixV4OpeningReductionProof as CpuProof,
    },
    ForgeMatrixV4FixedBankArtifactV1,
};
use memmap2::{Mmap, MmapOptions};
#[path = "row_reads.rs"]
mod row_reads;
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, PrimeField32};
use slop_alloc::Buffer;
use slop_basefold::{BasefoldProof, FriConfig};
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_commit::Rounds;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;
use sp1_gpu_basefold::{CudaStackedPcsProverData, FriCudaProver, TrustedComponentOpeningBuilder};
use sp1_gpu_commit::commit_multilinears;
use sp1_gpu_cudart::{
    args, dot_along_dim_view, DeviceBuffer, DevicePoint, DeviceTensor, TaskScope,
};
use crate::low_memory_sumcheck::multi_hadamard_sumcheck_at_points;
use sp1_gpu_merkle_tree::{CudaTcsProver, MerkleTree, Poseidon2SP1Field16CudaProver};
use sp1_gpu_sys::kernels::{
    cmfd_ext_add_in_place_kernel, cmfd_fixed_bank_evaluate_columns_kernel,
    cmfd_fixed_bank_rlc_kernel,
};
use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle, TestGC};

const LOG_ROWS: u32 = 23;
const ROWS: usize = 1 << LOG_ROWS;
const FIXED_COLUMNS: usize = 256;
const DYNAMIC_COLUMNS: usize = 16;
const LOG_BLOWUP: usize = 1;
const QUERIES: usize = 270;
const POW_BITS: usize = 16;
const TREE_HEIGHT: usize = 24;
const CODEWORD_ROWS: usize = 1 << TREE_HEIGHT;
const OPENING_DOMAIN: &[u8] = b"CommonFoundry/ForgeMatrix/V4/OpeningReduction/v2";

type GpuChallenger = <TestGC as IopCtx>::Challenger;
type GpuDigest = <TestGC as IopCtx>::Digest;

#[derive(Clone)]
struct GpuClaim {
    commitment: CpuCommitment,
    column_point: Point<Ext>,
    row_point: Point<Ext>,
    value: Ext,
}

pub struct FixedArtifactMaps {
    bank: usize,
    commitment: GpuDigest,
    codeword: Arc<Mmap>,
    row_major: bool,
    row_file: Option<Arc<File>>,
    row_io_workers: usize,
    tree: Arc<FixedBytes>,
    pub(crate) root: GpuDigest,
}

/// A fixed artifact's bytes: a file mapping, or a heap copy whose reads never
/// wait on the page cache.
enum FixedBytes {
    Mapped(Mmap),
    Resident(Vec<u8>),
}

impl std::ops::Deref for FixedBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Mapped(map) => &map[..],
            Self::Resident(bytes) => &bytes[..],
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prove_real_bank_opening(
    bank: usize,
    maps: &FixedArtifactMaps,
    encoded_bank: &DeviceBuffer<u8>,
    dynamic_trace: JaggedTraceMle<Felt, TaskScope>,
    fixed_commitment: GpuDigest,
    dynamic_commitment: GpuDigest,
    claims: &[CpuClaim],
    gpu_challenger: &mut GpuChallenger,
    cpu_challenger: &mut CpuChallenger,
    captured: &mut Vec<crate::pcs_hints::PcsStates>,
    scope: &TaskScope,
) -> Result<CpuProof> {
    ensure!(
        claims.len() == 16,
        "a V4 bank opening requires exactly 16 claims"
    );
    ensure!(maps.bank == bank, "fixed artifact bank mismatch");
    ensure!(
        encoded_bank.len() == FIXED_COLUMNS * ROWS,
        "wrong encoded bank length"
    );
    ensure!(
        dynamic_trace.main_size() == DYNAMIC_COLUMNS * ROWS,
        "wrong dynamic trace length"
    );
    eprintln!("bank={bank} opening_upload_seconds=0.000000");

    let prover = FriCudaProver::<TestGC, _, Felt>::new(
        Poseidon2SP1Field16CudaProver::new(scope),
        FriConfig::new(LOG_BLOWUP, QUERIES, POW_BITS),
        LOG_ROWS,
    );
    let commit_started = Instant::now();
    let (_, dynamic_data) =
        commit_multilinears::<TestGC, _>(&dynamic_trace, LOG_ROWS, false, false, &prover)?;
    scope.synchronize_blocking()?;
    ensure!(
        dynamic_data.original_commitment == dynamic_commitment,
        "reconstructed dynamic commitment differs from the transcript root"
    );
    eprintln!(
        "bank={bank} opening_recommit_seconds={:.6}",
        commit_started.elapsed().as_secs_f64()
    );

    let fixed_data = CudaStackedPcsProverData {
        merkle_tree_tcs_data: (
            MerkleTree {
                digests: Buffer::with_capacity_in(0, scope.clone()),
                height: TREE_HEIGHT,
                stored_height: 0,
            },
            maps.root,
            TREE_HEIGHT,
            FIXED_COLUMNS,
        ),
        codeword_mle: None,
    };
    ensure!(
        maps.commitment == fixed_commitment,
        "fixed artifact commitment mismatch"
    );
    let gpu_claims = claims.iter().map(gpu_claim).collect::<Result<Vec<_>>>()?;
    observe_opening(
        gpu_challenger,
        &[fixed_commitment, dynamic_commitment],
        &gpu_claims,
    );
    let powers = rlc_powers(gpu_challenger.sample_ext_element(), gpu_claims.len());
    let claimed_sum = gpu_claims
        .iter()
        .zip(&powers)
        .map(|(claim, power)| claim.value * *power)
        .sum::<Ext>();

    let reduction_started = Instant::now();
    let dynamic_tensor = dynamic_trace.main_virtual_tensor(LOG_ROWS);
    let mut trace_mles = Vec::with_capacity(gpu_claims.len());
    for (claim, power) in gpu_claims.iter().zip(&powers) {
        let coefficients = Mle::<Ext>::partial_lagrange(&claim.column_point)
            .guts()
            .as_slice()
            .iter()
            .map(|value| *value * *power)
            .collect::<Vec<_>>();
        let row = match claim.commitment {
            CpuCommitment::Fixed => fixed_bank_rlc(&encoded_bank, &coefficients, scope)?,
            CpuCommitment::Dynamic => {
                let coefficients = DeviceTensor::from_host(&Tensor::from(coefficients), scope)?;
                let row = dot_along_dim_view(dynamic_tensor.clone(), coefficients.as_view(), 0);
                Mle::new(row.reshape([1, ROWS]))
            }
        };
        trace_mles.push(row);
    }
    let equality_points = gpu_claims
        .iter()
        .map(|claim| claim.row_point.clone())
        .collect::<Vec<_>>();
    let component_claims = gpu_claims
        .iter()
        .zip(&powers)
        .map(|(claim, power)| claim.value * *power)
        .collect::<Vec<_>>();
    let (sumcheck, _) = multi_hadamard_sumcheck_at_points(
        trace_mles,
        &equality_points,
        component_claims,
        &mut *gpu_challenger,
        claimed_sum,
    );
    scope.synchronize_blocking()?;
    eprintln!(
        "bank={bank} opening_reduction_seconds={:.6}",
        reduction_started.elapsed().as_secs_f64()
    );

    let opening_point = sumcheck.point_and_eval.0.clone();
    let fixed_evaluations = evaluate_fixed_columns(&encoded_bank, &opening_point, scope)?;
    let dynamic_evaluations =
        evaluate_dynamic_columns(dynamic_tensor.clone(), &opening_point, scope)?;
    let mut flat_evaluations = fixed_evaluations.clone();
    flat_evaluations.extend_from_slice(&dynamic_evaluations);

    let batch_builder = Box::new(
        move |batching_coefficients: &Tensor<Ext>, builder_scope: &TaskScope| {
            let mut fixed = fixed_bank_rlc(
                &encoded_bank,
                &batching_coefficients.as_slice()[..FIXED_COLUMNS],
                builder_scope,
            )
            .expect("fixed-bank RLC kernel");
            let dynamic_coefficients = DeviceTensor::from_host(
                &Tensor::from(
                    batching_coefficients.as_slice()
                        [FIXED_COLUMNS..FIXED_COLUMNS + DYNAMIC_COLUMNS]
                        .to_vec(),
                ),
                builder_scope,
            )
            .expect("upload dynamic batching coefficients");
            let dynamic =
                dot_along_dim_view(dynamic_tensor.clone(), dynamic_coefficients.as_view(), 0);
            add_ext_in_place(&mut fixed, &dynamic, builder_scope)
                .expect("combine fixed and dynamic batching rows");
            fixed
        },
    );
    let fixed_opening_builder = maps.opening_builder();
    let stacked_data: Rounds<_> = [&fixed_data, &dynamic_data.pcs_prover_data]
        .into_iter()
        .collect();
    let hint_before=crate::pcs_hints::State::gpu(gpu_challenger);
    let opening_started = Instant::now();
    let basefold = prover.prove_trusted_evaluations_basefold_with_component_openings(
        opening_point,
        flat_evaluations,
        None,
        Some(batch_builder),
        stacked_data,
        Some(vec![Some(fixed_opening_builder), None]),
        gpu_challenger,
    )?;
    scope.synchronize_blocking()?;
    eprintln!(
        "bank={bank} basefold_opening_seconds={:.6}",
        opening_started.elapsed().as_secs_f64()
    );

    let hint_after=crate::pcs_hints::State::gpu(gpu_challenger);
    let proof = CpuProof {
        sumcheck: bridge::<PartialSumcheckProof<Ext>, _>(&sumcheck)?,
        fixed_column_evaluations: bridge(&fixed_evaluations)?,
        dynamic_column_evaluations: bridge(&dynamic_evaluations)?,
        basefold: bridge::<BasefoldProof<TestGC>, _>(&basefold)?,
    };
    let cpu_commitments = [
        fixed_commitment.map(|value| CpuFelt::from_canonical_u32(value.as_canonical_u32())),
        dynamic_commitment.map(|value| CpuFelt::from_canonical_u32(value.as_canonical_u32())),
    ];
    let cpu_verify_started = Instant::now();
    verify_forgematrix_v4_opening_reduction(cpu_commitments, claims, &proof, cpu_challenger)?;
    ensure!(hint_after==crate::pcs_hints::State::cpu(cpu_challenger),"GPU/CPU complete PCS after-state mismatch");
    captured.push(crate::pcs_hints::PcsStates{bank,before:hint_before,after:hint_after});
    eprintln!("bank={bank} opening_cpu_verify_seconds={:.6}", cpu_verify_started.elapsed().as_secs_f64());
    eprintln!("bank={bank} real_opening=VERIFIED claims={}", claims.len());
    Ok(proof)
}

/// The direct format retains this unchanged reduction but defers all PCS
/// authentication to one six-commitment BaseFold proof. The zero BaseFold
/// decoded below is only a private carrier for the pinned public codec; it is
/// never serialized into the direct packet or accepted by a verifier.
#[allow(clippy::too_many_arguments)]
pub fn prove_public_bank_opening(
    bank: usize,
    maps: &FixedArtifactMaps,
    encoded_bank: &DeviceBuffer<u8>,
    dynamic_trace: &JaggedTraceMle<Felt, TaskScope>,
    fixed_commitment: GpuDigest,
    dynamic_commitment: GpuDigest,
    claims: &[CpuClaim],
    gpu_challenger: &mut GpuChallenger,
    cpu_challenger: &mut CpuChallenger,
    scope: &TaskScope,
) -> Result<CpuProof> {
    ensure!(claims.len() == 16 && maps.bank == bank
        && maps.commitment == fixed_commitment, "direct bank shape or fixed commitment");
    ensure!(encoded_bank.len() == FIXED_COLUMNS * ROWS
        && dynamic_trace.main_size() == DYNAMIC_COLUMNS * ROWS,
        "direct bank trace geometry");
    let gpu_claims = claims.iter().map(gpu_claim).collect::<Result<Vec<_>>>()?;
    observe_opening(gpu_challenger, &[fixed_commitment, dynamic_commitment], &gpu_claims);
    let powers = rlc_powers(gpu_challenger.sample_ext_element(), gpu_claims.len());
    let claimed_sum = gpu_claims.iter().zip(&powers)
        .map(|(claim, power)| claim.value * *power).sum::<Ext>();
    let started = Instant::now();
    let dynamic_tensor = dynamic_trace.main_virtual_tensor(LOG_ROWS);
    let mut traces = Vec::with_capacity(gpu_claims.len());
    for (claim, power) in gpu_claims.iter().zip(&powers) {
        let coefficients = Mle::<Ext>::partial_lagrange(&claim.column_point)
            .guts().as_slice().iter().map(|value| *value * *power).collect::<Vec<_>>();
        let row = match claim.commitment {
            CpuCommitment::Fixed => fixed_bank_rlc(encoded_bank, &coefficients, scope)?,
            CpuCommitment::Dynamic => {
                let coefficients = DeviceTensor::from_host(&Tensor::from(coefficients), scope)?;
                let row = dot_along_dim_view(dynamic_tensor.clone(), coefficients.as_view(), 0);
                Mle::new(row.reshape([1, ROWS]))
            }
        };
        traces.push(row);
    }
    let equality_points = gpu_claims.iter().map(|claim| claim.row_point.clone()).collect::<Vec<_>>();
    let component_claims = gpu_claims.iter().zip(&powers)
        .map(|(claim, power)| claim.value * *power).collect::<Vec<_>>();
    let (sumcheck, _) = multi_hadamard_sumcheck_at_points(
        traces, &equality_points, component_claims, &mut *gpu_challenger, claimed_sum);
    scope.synchronize_blocking()?;
    let opening_point = sumcheck.point_and_eval.0.clone();
    let fixed_evaluations = evaluate_fixed_columns(encoded_bank, &opening_point, scope)?;
    let dynamic_evaluations = evaluate_dynamic_columns(dynamic_tensor, &opening_point, scope)?;
    eprintln!("direct_bank={bank} public_opening_seconds={:.6}", started.elapsed().as_secs_f64());

    fn write_ext(bytes: &mut Vec<u8>, value: &Ext) {
        let fields: &[Felt] = value.as_base_slice();
        for field in fields {
            bytes.extend_from_slice(&field.as_canonical_u32().to_le_bytes());
        }
    }
    let mut bytes = Vec::with_capacity(3_300_008);
    bytes.extend_from_slice(b"CMV4BF01");
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    ensure!(sumcheck.univariate_polys.len() == 23
        && sumcheck.point_and_eval.0.len() == 23, "direct sumcheck round shape");
    for polynomial in &sumcheck.univariate_polys {
        ensure!(polynomial.coefficients.len() == 3, "direct sumcheck degree");
        for value in &polynomial.coefficients { write_ext(&mut bytes, value); }
    }
    write_ext(&mut bytes, &sumcheck.claimed_sum);
    for value in sumcheck.point_and_eval.0.iter() { write_ext(&mut bytes, value); }
    write_ext(&mut bytes, &sumcheck.point_and_eval.1);
    ensure!(fixed_evaluations.len() == 256 && dynamic_evaluations.len() == 16,
        "direct column evaluation shape");
    for value in fixed_evaluations.iter().chain(dynamic_evaluations.iter()) {
        write_ext(&mut bytes, value);
    }
    ensure!(bytes.len() == 5_872, "direct public opening bytes");
    bytes.resize(3_300_008, 0);
    let placeholder = cmfd_consensus::forgematrix_v4_basefold_codec::
        decode_forgematrix_v4_opening_reduction(&bytes, 16)?;
    let cpu_commitments = [fixed_commitment.map(|field|
        CpuFelt::from_canonical_u32(field.as_canonical_u32())),
        dynamic_commitment.map(|field|
        CpuFelt::from_canonical_u32(field.as_canonical_u32()))];
    cmfd_consensus::forgematrix_v4_direct::verify_public_opening(
        cpu_commitments, claims, &placeholder, cpu_challenger)?;
    ensure!(crate::pcs_hints::State::gpu(gpu_challenger)
        == crate::pcs_hints::State::cpu(cpu_challenger),
        "direct public opening CPU/GPU transcript mismatch");
    Ok(placeholder)
}

pub fn prove_public_bank_opening_remote(
    bank: usize,
    maps: &FixedArtifactMaps,
    dynamic_trace: &JaggedTraceMle<Felt, TaskScope>,
    fixed_commitment: GpuDigest,
    dynamic_commitment: GpuDigest,
    claims: &[CpuClaim],
    gpu_challenger: &mut GpuChallenger,
    cpu_challenger: &mut CpuChallenger,
    scope: &TaskScope,
) -> Result<CpuProof> {
    ensure!(claims.len() == 16 && maps.bank == bank
        && maps.commitment == fixed_commitment, "direct bank shape or fixed commitment");
    ensure!(dynamic_trace.main_size() == DYNAMIC_COLUMNS * ROWS,
        "direct bank trace geometry");
    let gpu_claims = claims.iter().map(gpu_claim).collect::<Result<Vec<_>>>()?;
    observe_opening(gpu_challenger, &[fixed_commitment, dynamic_commitment], &gpu_claims);
    let powers = rlc_powers(gpu_challenger.sample_ext_element(), gpu_claims.len());
    let claimed_sum = gpu_claims.iter().zip(&powers)
        .map(|(claim, power)| claim.value * *power).sum::<Ext>();
    let started = Instant::now();
    let dynamic_tensor = dynamic_trace.main_virtual_tensor(LOG_ROWS);
    let mut traces=Vec::new();let mut equality_points=Vec::new();let mut component_claims=Vec::new();let mut fixed=Vec::new();
    let mut device_coefficients=Vec::new();
    for (claim,power) in gpu_claims.iter().zip(&powers) {
        let coefficients=Mle::<Ext>::partial_lagrange(&claim.column_point).guts().as_slice().iter().map(|value|*value**power).collect::<Vec<_>>();
        if claim.commitment==CpuCommitment::Fixed {
            fixed.push(crate::resident::opening_fixed_component(bank,coefficients,&claim.row_point,claim.value**power));
        } else {
            let coefficients=DeviceTensor::from_host(&Tensor::from(coefficients),scope)?;
            let row=dot_along_dim_view(dynamic_tensor.clone(),coefficients.as_view(),0);
            device_coefficients.push(coefficients);
            traces.push(Mle::new(row.reshape([1,ROWS])));if !crate::device_relations::enabled(){scope.synchronize_blocking()?;}equality_points.push(claim.row_point.clone());component_claims.push(claim.value**power);
        }
    }
    scope.synchronize_blocking()?;
    drop(device_coefficients);
    let sumcheck=crate::resident::distributed_sumcheck(traces,equality_points,component_claims,fixed,gpu_challenger,claimed_sum)?;
    scope.synchronize_blocking()?;
    let opening_point = sumcheck.point_and_eval.0.clone();
    let (fixed_evaluations,dynamic_evaluations)=crate::resident::opening_evaluations(bank,&opening_point,dynamic_tensor,scope)?;
    eprintln!("direct_bank={bank} public_opening_seconds={:.6}", started.elapsed().as_secs_f64());

    fn write_ext(bytes: &mut Vec<u8>, value: &Ext) {
        let fields: &[Felt] = value.as_base_slice();
        for field in fields {
            bytes.extend_from_slice(&field.as_canonical_u32().to_le_bytes());
        }
    }
    let mut bytes = Vec::with_capacity(3_300_008);
    bytes.extend_from_slice(b"CMV4BF01");
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    ensure!(sumcheck.univariate_polys.len() == 23
        && sumcheck.point_and_eval.0.len() == 23, "direct sumcheck round shape");
    for polynomial in &sumcheck.univariate_polys {
        ensure!(polynomial.coefficients.len() == 3, "direct sumcheck degree");
        for value in &polynomial.coefficients { write_ext(&mut bytes, value); }
    }
    write_ext(&mut bytes, &sumcheck.claimed_sum);
    for value in sumcheck.point_and_eval.0.iter() { write_ext(&mut bytes, value); }
    write_ext(&mut bytes, &sumcheck.point_and_eval.1);
    ensure!(fixed_evaluations.len() == 256 && dynamic_evaluations.len() == 16,
        "direct column evaluation shape");
    for value in fixed_evaluations.iter().chain(dynamic_evaluations.iter()) {
        write_ext(&mut bytes, value);
    }
    ensure!(bytes.len() == 5_872, "direct public opening bytes");
    bytes.resize(3_300_008, 0);
    let placeholder = cmfd_consensus::forgematrix_v4_basefold_codec::
        decode_forgematrix_v4_opening_reduction(&bytes, 16)?;
    let cpu_commitments = [fixed_commitment.map(|field|
        CpuFelt::from_canonical_u32(field.as_canonical_u32())),
        dynamic_commitment.map(|field|
        CpuFelt::from_canonical_u32(field.as_canonical_u32()))];
    cmfd_consensus::forgematrix_v4_direct::verify_public_opening(
        cpu_commitments, claims, &placeholder, cpu_challenger)?;
    ensure!(crate::pcs_hints::State::gpu(gpu_challenger)
        == crate::pcs_hints::State::cpu(cpu_challenger),
        "direct public opening CPU/GPU transcript mismatch");
    Ok(placeholder)
}

use cmfd_consensus::forgematrix_v4_basefold::ForgeMatrixV4Field as CpuFelt;

fn gpu_claim(claim: &CpuClaim) -> Result<GpuClaim> {
    Ok(GpuClaim {
        commitment: claim.commitment,
        column_point: Point::from(bridge::<_, Vec<Ext>>(
            &claim.column_point.iter().copied().collect::<Vec<_>>(),
        )?),
        row_point: Point::from(bridge::<_, Vec<Ext>>(
            &claim.row_point.iter().copied().collect::<Vec<_>>(),
        )?),
        value: bridge(&claim.value)?,
    })
}

fn observe_opening(
    challenger: &mut GpuChallenger,
    commitments: &[GpuDigest; 2],
    claims: &[GpuClaim],
) {
    observe_bytes(challenger, OPENING_DOMAIN);
    challenger.observe(commitments[0]);
    challenger.observe(commitments[1]);
    challenger.observe(Felt::from_canonical_usize(claims.len()));
    for claim in claims {
        challenger.observe(Felt::from_canonical_u8(claim.commitment as u8));
        for coordinate in claim.column_point.iter() {
            challenger.observe_ext_element(*coordinate);
        }
        for coordinate in claim.row_point.iter() {
            challenger.observe_ext_element(*coordinate);
        }
        challenger.observe_ext_element(claim.value);
    }
}

fn observe_bytes(challenger: &mut GpuChallenger, bytes: &[u8]) {
    challenger.observe(Felt::from_canonical_usize(bytes.len()));
    for byte in bytes {
        challenger.observe(Felt::from_canonical_u8(*byte));
    }
}

fn rlc_powers(lambda: Ext, count: usize) -> Vec<Ext> {
    let mut powers = vec![Ext::one(); count];
    for index in (0..count - 1).rev() {
        powers[index] = powers[index + 1] * lambda;
    }
    powers
}

pub(crate) fn fixed_bank_rlc(
    encoded: &DeviceBuffer<u8>,
    coefficients: &[Ext],
    scope: &TaskScope,
) -> Result<Mle<Ext, TaskScope>> {
    ensure!(coefficients.len() == FIXED_COLUMNS, "wrong fixed RLC width");
    let coefficients = DeviceBuffer::from_host(&Buffer::from(coefficients.to_vec()), scope)?;
    let mut output = DeviceTensor::<Ext>::with_sizes_in([1, ROWS], scope.clone());
    unsafe {
        output.assume_init();
        let block = 256_u32;
        let kernel_args = args!(
            encoded.as_ptr(),
            coefficients.as_ptr(),
            output.as_mut_ptr(),
            ROWS,
            FIXED_COLUMNS
        );
        scope.launch_kernel(
            cmfd_fixed_bank_rlc_kernel(),
            u32::try_from(ROWS.div_ceil(block as usize))?,
            block,
            &kernel_args,
            0,
        )?;
    }
    scope.synchronize_blocking()?;
    Ok(Mle::new(output.into_inner()))
}

pub(crate) fn evaluate_fixed_columns(
    encoded: &DeviceBuffer<u8>,
    point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Vec<Ext>> {
    let equality=crate::low_memory_sumcheck::bounded_equality(point,scope);
    let mut output = DeviceTensor::<Ext>::with_sizes_in([FIXED_COLUMNS], scope.clone());
    unsafe {
        output.assume_init();
        let kernel_args = args!(
            encoded.as_ptr(),
            equality.guts().as_ptr(),
            output.as_mut_ptr(),
            ROWS
        );
        scope.launch_kernel(
            cmfd_fixed_bank_evaluate_columns_kernel(),
            FIXED_COLUMNS as u32,
            256_u32,
            &kernel_args,
            0,
        )?;
    }
    scope.synchronize_blocking()?;
    Ok(output.to_host()?.into_buffer().into_vec())
}

pub(crate) fn evaluate_dynamic_columns(
    dynamic: slop_tensor::TensorView<'_, Felt, TaskScope>,
    point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Vec<Ext>> {
    let equality=crate::low_memory_sumcheck::bounded_equality(point,scope);
    let output = dot_along_dim_view(dynamic, equality.guts().as_view(), 1);
    scope.synchronize_blocking()?;
    Ok(DeviceTensor::from_raw(output)
        .to_host()?
        .into_buffer()
        .into_vec())
}

pub(crate) fn add_ext_in_place(
    destination: &mut Mle<Ext, TaskScope>,
    source: &Tensor<Ext, TaskScope>,
    scope: &TaskScope,
) -> Result<()> {
    ensure!(
        destination.guts().total_len() == source.total_len(),
        "row length mismatch"
    );
    let block = 256_u32;
    let count = source.total_len();
    let kernel_args = args!(destination.guts_mut().as_mut_ptr(), source.as_ptr(), count);
    unsafe {
        scope.launch_kernel(
            cmfd_ext_add_in_place_kernel(),
            u32::try_from(count.div_ceil(block as usize))?,
            block,
            &kernel_args,
            0,
        )?;
    }
    Ok(())
}

impl FixedArtifactMaps {
    pub(crate) fn tree_bytes(&self)->&[u8]{&self.tree}

    /// `resident_tree` reads the Merkle tree onto the heap instead of mapping it.
    pub fn open(
        artifact_dir: &Path,
        artifact: ForgeMatrixV4FixedBankArtifactV1,
        resident_tree: bool,
    ) -> Result<Self> {
        let bank = artifact.bank();
        let canonical_path =
            artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.codeword"));
        let row_major_path = artifact_dir.join(format!(
            "FORGEMATRIX-V4-FIXED-BANK-{bank}.row-major.codeword"
        ));
        let shared_tree=crate::resident::shared_tree_path(bank as usize)?;
        let mut tree_file=File::open(shared_tree.as_deref().map(Path::to_path_buf).unwrap_or_else(||artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.tree"))))?;
        ensure!(
            tree_file.metadata()?.len() == artifact.tree_bytes(),
            "fixed tree length mismatch"
        );
        let canonical_codeword = if canonical_path.is_file() {
            let codeword_file = File::open(&canonical_path)?;
            ensure!(
                codeword_file.metadata()?.len() == artifact.codeword_bytes(),
                "fixed codeword length mismatch"
            );
            let codeword = unsafe { MmapOptions::new().map(&codeword_file)? };
            ensure!(
                blake3::Hasher::new()
                    .update_rayon(&codeword)
                    .finalize()
                    .as_bytes()
                    == &artifact.codeword_blake3(),
                "fixed codeword digest mismatch"
            );
            Some(Arc::new(codeword))
        } else {
            None
        };
        let tree = Arc::new(if resident_tree {
            let mut bytes = Vec::with_capacity(usize::try_from(artifact.tree_bytes())?);
            tree_file.read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == artifact.tree_bytes(),
                "fixed tree length mismatch"
            );
            FixedBytes::Resident(bytes)
        } else {
            FixedBytes::Mapped(unsafe { MmapOptions::new().map(&tree_file)? })
        });
        // The fixed service hashes its owned kernel-sealed snapshot before
        // publication. This is the same immutable inode, not a mutable cache.
        if shared_tree.is_none() {
        ensure!(
            blake3::Hasher::new()
                .update_rayon(&tree)
                .finalize()
                .as_bytes()
                == &artifact.tree_blake3(),
            "fixed tree digest mismatch"
        );
        }
        let root = raw_digest(&tree, 0)?;
        ensure!(
            root.map(|value| value.as_canonical_u32()) == artifact.merkle_root_words(),
            "fixed tree root mismatch"
        );
        // The row-major file is an untrusted read cache. Every value used from it is opened
        // against the digest-pinned Merkle tree, and the finished proof is CPU-verified (by
        // this worker in standalone mode, by the node's consensus verifier in server mode).
        let (codeword, row_major, row_file) = if row_major_path.is_file() {
            let row_major_file = File::open(&row_major_path)?;
            ensure!(
                row_major_file.metadata()?.len() == artifact.codeword_bytes(),
                "row-major fixed codeword length mismatch"
            );
            (
                Arc::new(unsafe { MmapOptions::new().map(&row_major_file)? }),
                true,
                Some(Arc::new(row_major_file)),
            )
        } else {
            (
                canonical_codeword
                    .context("missing both canonical and row-major fixed codeword artifacts")?,
                false,
                None,
            )
        };
        let mode = std::env::var("CMFD_FIXED_ROW_IO").unwrap_or_else(|_|"mmap".into());
        ensure!(mode=="mmap" || mode=="pread", "unsupported fixed-row reader");
        let workers = std::env::var("CMFD_FIXED_IO_WORKERS").unwrap_or_else(|_|"16".into()).parse::<usize>()?;
        ensure!((1..=32).contains(&workers), "fixed-row I/O concurrency out of bounds");
        ensure!(mode!="pread" || row_major, "positional reader requires the authenticated row-major cache");
        let row_io_workers=if mode=="pread" {workers} else {0};
        eprintln!("bank={bank} fixed_row_reader={mode} io_workers={row_io_workers}");
        let commitment = artifact.commitment_words().map(Felt::from_canonical_u32);
        Ok(Self {
            bank: bank as usize,
            commitment,
            codeword,
            row_major,
            row_file,
            row_io_workers,
            tree,
            root,
        })
    }

    pub(crate) fn opening_builder(&self) -> TrustedComponentOpeningBuilder<'static, TestGC> {
        let codeword = Arc::clone(&self.codeword);
        let tree = Arc::clone(&self.tree);
        let row_major = self.row_major;
        let row_file = if self.row_io_workers>0 {self.row_file.clone()} else {None};
        let workers=self.row_io_workers;
        let bank=self.bank;
        let root = self.root;
        Box::new(move |query_indices| {
            let rows_started=Instant::now();
            let prefetched = if let Some(file)=row_file.as_ref() {
                Some(row_reads::read_rows(file,&query_indices[..],CODEWORD_ROWS,FIXED_COLUMNS*4,workers)?)
            } else {None};
            let read_seconds=rows_started.elapsed().as_secs_f64();
            // Each query reads a random codeword row that is usually not in the
            // page cache. Fault the rows in concurrently; collect keeps query order.
            let openings = query_indices
                .par_iter()
                .enumerate()
                .map(|(slot,query_index)| {
                    if *query_index >= CODEWORD_ROWS {
                        return None;
                    }
                    let row = (0..FIXED_COLUMNS)
                        .map(|column| {
                            let word_index = if row_major {
                                query_index * FIXED_COLUMNS + column
                            } else {
                                column * CODEWORD_ROWS + query_index
                            };
                            if let Some(rows)=prefetched.as_ref() {raw_felt(&rows[slot],column)}
                            else {raw_felt(&codeword, word_index)}
                        })
                        .collect::<Option<Vec<_>>>()?;
                    let mut path = Vec::with_capacity(TREE_HEIGHT);
                    let mut node = CODEWORD_ROWS - 1 + query_index;
                    for _ in 0..TREE_HEIGHT {
                        let sibling = if node & 1 == 0 { node - 1 } else { node + 1 };
                        path.push(raw_digest(&tree, sibling).ok()?);
                        node = (node - 1) >> 1;
                    }
                    Some((row, path))
                })
                .collect::<Option<Vec<_>>>()?;
            eprintln!("bank={bank} fixed_row_gather_seconds={:.6} positional_read_seconds={read_seconds:.6} rows={}",rows_started.elapsed().as_secs_f64(),query_indices.len());
            let mut values = Vec::with_capacity(query_indices.len() * FIXED_COLUMNS);
            let mut paths = Vec::with_capacity(query_indices.len() * TREE_HEIGHT);
            for (row, path) in openings {
                values.extend(row);
                paths.extend(path);
            }
            Some(slop_merkle_tree::MerkleTreeOpeningAndProof {
                values: Tensor::from(values).reshape([query_indices.len(), FIXED_COLUMNS]),
                proof: slop_merkle_tree::MerkleTreeTcsProof {
                    merkle_root: root,
                    log_tensor_height: TREE_HEIGHT,
                    width: FIXED_COLUMNS,
                    paths: Tensor::from(paths).reshape([query_indices.len(), TREE_HEIGHT]),
                },
            })
        })
    }
}

fn raw_felt(bytes: &[u8], word_index: usize) -> Option<Felt> {
    let start = word_index.checked_mul(4)?;
    let raw = u32::from_le_bytes(bytes.get(start..start + 4)?.try_into().ok()?);
    if raw >= 0x7f00_0001 {
        return None;
    }
    Some(unsafe { std::mem::transmute::<u32, Felt>(raw) })
}

fn raw_digest(bytes: &[u8], digest_index: usize) -> Result<GpuDigest> {
    let first_word = digest_index
        .checked_mul(8)
        .context("digest index overflow")?;
    let mut digest = [Felt::zero(); 8];
    for (index, value) in digest.iter_mut().enumerate() {
        *value = raw_felt(bytes, first_word + index).context("invalid raw digest")?;
    }
    Ok(digest)
}

fn bridge<T: Serialize, U: DeserializeOwned>(value: &T) -> Result<U> {
    Ok(bincode::deserialize(&bincode::serialize(value)?)?)
}
