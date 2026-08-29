use std::{fs::File, path::Path, sync::Arc, time::Instant};

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
use serde::{de::DeserializeOwned, Serialize};
use slop_algebra::{AbstractField, PrimeField32};
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
use sp1_gpu_jagged_sumcheck::multi_hadamard_sumcheck_at_points;
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
    tree: Arc<Mmap>,
    root: GpuDigest,
}

#[allow(clippy::too_many_arguments)]
pub fn prove_real_bank_opening(
    bank: usize,
    maps: &FixedArtifactMaps,
    encoded_bank: DeviceBuffer<u8>,
    dynamic_trace: JaggedTraceMle<Felt, TaskScope>,
    fixed_commitment: GpuDigest,
    dynamic_commitment: GpuDigest,
    claims: &[CpuClaim],
    gpu_challenger: &mut GpuChallenger,
    cpu_challenger: &mut CpuChallenger,
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
    verify_forgematrix_v4_opening_reduction(cpu_commitments, claims, &proof, cpu_challenger)?;
    eprintln!("bank={bank} real_opening=VERIFIED claims={}", claims.len());
    Ok(proof)
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

fn fixed_bank_rlc(
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
    Ok(Mle::new(output.into_inner()))
}

fn evaluate_fixed_columns(
    encoded: &DeviceBuffer<u8>,
    point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Vec<Ext>> {
    let equality: Mle<Ext, TaskScope> = DevicePoint::from_host(point, scope)?
        .partial_lagrange()
        .into();
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

fn evaluate_dynamic_columns(
    dynamic: slop_tensor::TensorView<'_, Felt, TaskScope>,
    point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Vec<Ext>> {
    let equality: Mle<Ext, TaskScope> = DevicePoint::from_host(point, scope)?
        .partial_lagrange()
        .into();
    let output = dot_along_dim_view(dynamic, equality.guts().as_view(), 1);
    scope.synchronize_blocking()?;
    Ok(DeviceTensor::from_raw(output)
        .to_host()?
        .into_buffer()
        .into_vec())
}

fn add_ext_in_place(
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
    pub fn open(artifact_dir: &Path, artifact: ForgeMatrixV4FixedBankArtifactV1) -> Result<Self> {
        let bank = artifact.bank();
        let canonical_path =
            artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.codeword"));
        let row_major_path = artifact_dir.join(format!(
            "FORGEMATRIX-V4-FIXED-BANK-{bank}.row-major.codeword"
        ));
        let tree_file =
            File::open(artifact_dir.join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.tree")))?;
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
        let tree = Arc::new(unsafe { MmapOptions::new().map(&tree_file)? });
        ensure!(
            blake3::Hasher::new()
                .update_rayon(&tree)
                .finalize()
                .as_bytes()
                == &artifact.tree_blake3(),
            "fixed tree digest mismatch"
        );
        let root = raw_digest(&tree, 0)?;
        ensure!(
            root.map(|value| value.as_canonical_u32()) == artifact.merkle_root_words(),
            "fixed tree root mismatch"
        );
        // The row-major file is an untrusted read cache. Every value used from it is opened
        // against the digest-pinned Merkle tree, and the finished proof is CPU-self-verified.
        let (codeword, row_major) = if row_major_path.is_file() {
            let row_major_file = File::open(row_major_path)?;
            ensure!(
                row_major_file.metadata()?.len() == artifact.codeword_bytes(),
                "row-major fixed codeword length mismatch"
            );
            (
                Arc::new(unsafe { MmapOptions::new().map(&row_major_file)? }),
                true,
            )
        } else {
            (
                canonical_codeword
                    .context("missing both canonical and row-major fixed codeword artifacts")?,
                false,
            )
        };
        let commitment = artifact.commitment_words().map(Felt::from_canonical_u32);
        Ok(Self {
            bank: bank as usize,
            commitment,
            codeword,
            row_major,
            tree,
            root,
        })
    }

    fn opening_builder(&self) -> TrustedComponentOpeningBuilder<'static, TestGC> {
        let codeword = Arc::clone(&self.codeword);
        let tree = Arc::clone(&self.tree);
        let row_major = self.row_major;
        let root = self.root;
        Box::new(move |query_indices| {
            let mut values = Vec::with_capacity(query_indices.len() * FIXED_COLUMNS);
            let mut paths = Vec::with_capacity(query_indices.len() * TREE_HEIGHT);
            for query_index in query_indices {
                if *query_index >= CODEWORD_ROWS {
                    return None;
                }
                for column in 0..FIXED_COLUMNS {
                    let word_index = if row_major {
                        query_index * FIXED_COLUMNS + column
                    } else {
                        column * CODEWORD_ROWS + query_index
                    };
                    values.push(raw_felt(&codeword, word_index)?);
                }
                let mut node = CODEWORD_ROWS - 1 + query_index;
                for _ in 0..TREE_HEIGHT {
                    let sibling = if node & 1 == 0 { node - 1 } else { node + 1 };
                    paths.push(raw_digest(&tree, sibling).ok()?);
                    node = (node - 1) >> 1;
                }
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
