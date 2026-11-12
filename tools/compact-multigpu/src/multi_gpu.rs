//! Process-isolated GPU stages for one unchanged compact proof.
//!
//! CUDA pointers never cross processes. The coordinator freezes the witness
//! once; commitments, public relations and the final verifier bind every stage.
use super::*;
use slop_algebra::AbstractExtensionField;
use slop_commit::Rounds;
use sp1_gpu_basefold::CudaStackedPcsProverData;
use sp1_gpu_merkle_tree::MerkleTree;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};

const CAP: usize = 7 << 30;
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
type Words = [u32; 4];

#[derive(Deserialize)]
struct Command {
    op: String,
    #[serde(default)]
    template: PathBuf,
    #[serde(default)]
    prefix: PathBuf,
    #[serde(default)]
    final_path: PathBuf,
    #[serde(default)]
    bundle: PathBuf,
    #[serde(default)]
    output: PathBuf,
    #[serde(default)]
    roots: [[u32; 8]; 3],
    #[serde(default)]
    coefficients: Vec<Words>,
    #[serde(default)]
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct State {
    sponge: [u32; 16],
    input: Vec<u32>,
    output: Vec<u32>,
}
impl State {
    fn capture(c: &GpuChallenger) -> Self {
        Self {
            sponge: c.sponge_state.map(|x| x.as_canonical_u32()),
            input: c
                .input_buffer
                .iter()
                .map(|x| x.as_canonical_u32())
                .collect(),
            output: c
                .output_buffer
                .iter()
                .map(|x| x.as_canonical_u32())
                .collect(),
        }
    }
    fn restore(&self) -> Result<GpuChallenger> {
        ensure!(
            self.input.len() < 8 && self.output.len() <= 16,
            "invalid challenger buffers"
        );
        ensure!(
            self.sponge
                .iter()
                .chain(&self.input)
                .chain(&self.output)
                .all(|x| *x < MODULUS),
            "noncanonical challenger"
        );
        let mut c = TestGC::default_challenger();
        c.sponge_state = self.sponge.map(Felt::from_canonical_u32);
        c.input_buffer = self
            .input
            .iter()
            .map(|x| Felt::from_canonical_u32(*x))
            .collect();
        c.output_buffer = self
            .output
            .iter()
            .map(|x| Felt::from_canonical_u32(*x))
            .collect();
        Ok(c)
    }
}

#[derive(Serialize, Deserialize)]
struct Bundle {
    statement_digest: [u8; 32],
    carrier: Vec<u8>,
    reduction: cmfd_consensus::forgematrix_v4_direct::ReductionProof,
    shared_point: Vec<Ext>,
    shared_values: [Vec<Ext>; 6],
    state: State,
}

pub(crate) fn send(value: serde_json::Value) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer(&mut out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
fn receive(input: &mut impl BufRead) -> Result<Command> {
    let mut line = String::new();
    ensure!(
        input.take(1 << 20).read_line(&mut line)? > 0,
        "coordinator closed the stage pipe"
    );
    ensure!(
        line.ends_with('\n'),
        "oversized or unterminated stage command"
    );
    Ok(serde_json::from_str(&line)?)
}
pub(crate) fn budget(scope: &TaskScope, phase: &str) -> Result<()> {
    scope.synchronize_blocking()?;
    let (free, total) = cuda_memory_info()?;
    let used = total - free;
    eprintln!("CMFD_MULTI_GPU_MEMORY phase={phase} used_bytes={used} cap_bytes={CAP}");
    ensure!(used <= CAP, "{phase} exceeded the 7 GiB device budget");
    Ok(())
}
pub(crate) fn trace(
    prefix: &Path,
    bank: usize,
    scope: &TaskScope,
) -> Result<JaggedTraceMle<Felt, TaskScope>> {
    let words = SealedWords::open(
        &PathBuf::from(format!("{}-bank{bank}-dynamic.bin", prefix.display())),
        DYNAMIC_BYTES,
        MODULUS,
    )
    .map_err(anyhow::Error::msg)?;
    let values = montgomery_values(&words)?;
    let mut dense = Vec::with_capacity(TRACE_DENSE_VALUES);
    dense.resize(ROWS, Felt::zero());
    dense.extend_from_slice(values);
    let result = JaggedTraceMle::from_chip_layout(
        Buffer::from(dense),
        &dynamic_trace_layout(bank),
        LOG_ROWS,
    )
    .into_device(scope);
    budget(scope, "trace-upload")?;
    Ok(result)
}
fn statement(
    prepared: &PreparedProver,
    command: &Command,
    network: [u8; 32],
) -> Result<(ForgeMatrixV4TranscriptStatement, Vec<CpuFelt>)> {
    let frozen: FrozenProductionV4Template =
        serde_json::from_reader(File::open(&command.template)?)?;
    ensure!(
        frozen.challenge.network_id == network,
        "template network mismatch"
    );
    ensure!(!cmfd_consensus::mainnet_network::is_mainnet_network(network) || frozen.challenge.height >= cmfd_consensus::compact_mainnet_fork::COMPACT_MAINNET_ACTIVATION_HEIGHT, "compact mainnet proof below activation");
    let final_activation = read_final_activation(&command.final_path)?;
    let manifest = prepared.fixed_record.manifest_digest();
    let challenge_digest =
        forgematrix_v4_challenge_digest(&frozen.challenge, frozen.nonce, manifest);
    let final_activation_digest =
        forgematrix_v4_final_activation_digest(challenge_digest, &final_activation);
    Ok((
        ForgeMatrixV4TranscriptStatement {
            block: frozen.challenge,
            algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
            proof_version: FORGEMATRIX_V4_DIRECT_PROOF_VERSION,
            nonce: frozen.nonce,
            proof_system_digest: cmfd_consensus::forgematrix_v4::forgematrix_v4_direct_proof_system_digest_for_network(network).ok_or_else(|| anyhow::anyhow!("unsupported compact network"))?,
            model_manifest_digest: manifest,
            challenge_digest,
            final_activation_digest,
            work_digest: forgematrix_v4_work_digest(
                manifest,
                challenge_digest,
                final_activation_digest,
            ),
        },
        final_activation,
    ))
}

/// Owned immutable staging. Opening through /proc sees the same sealed inode.
pub(crate) struct Snapshot(File);
impl Snapshot {
    pub(crate) fn bytes(bytes: &[u8]) -> Result<Self> {
        let name = CString::new("cmfd-multi-gpu-stage")?;
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        ensure!(
            fd >= 0,
            "create staging memfd: {}",
            std::io::Error::last_os_error()
        );
        let mut f = unsafe { File::from_raw_fd(fd) };
        f.write_all(bytes)?;
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } == 0,
            "seal staging memfd"
        );
        Ok(Self(f))
    }
    pub(crate) fn slice<T>(values: &[T]) -> Result<Self> {
        Self::bytes(unsafe {
            std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), std::mem::size_of_val(values))
        })
    }
    pub(crate) fn path(&self) -> PathBuf {
        format!("/proc/{}/fd/{}", std::process::id(), self.0.as_raw_fd()).into()
    }
    pub(crate) fn map(&self) -> Result<Mmap> {
        Ok(unsafe { MmapOptions::new().map(&self.0)? })
    }
}

struct DynamicData {
    codeword: Snapshot,
    tree: Snapshot,
    root: GpuDigest,
    commitment: GpuDigest,
    height: usize,
    stored_height: usize,
    width: usize,
}
impl DynamicData {
    fn commit(dynamic: &JaggedTraceMle<Felt, TaskScope>, scope: &TaskScope) -> Result<Self> {
        let prover = prover(scope);
        let (_, data) = commit_multilinears::<TestGC, _>(dynamic, LOG_ROWS, false, false, &prover)?;
        budget(scope, "dynamic-commit")?;
        let pcs = &data.pcs_prover_data;
        let codeword = DeviceTensor::copy_to_host(
            pcs.codeword_mle
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing codeword"))?,
        )?;
        let codeword = Snapshot::slice(codeword.as_slice())?;
        let (tree, root, height, width) = &pcs.merkle_tree_tcs_data;
        let digests = DeviceBuffer::from_raw(tree.digests.clone()).to_host()?;
        let tree_snapshot = Snapshot::slice(&digests)?;
        // `root` is the raw Merkle root. The public commitment additionally
        // binds height and width; relation transcripts must observe that bound
        // commitment, while opening proofs retain the raw root.
        let result = Self {
            codeword,
            tree: tree_snapshot,
            root: *root,
            commitment: data.original_commitment,
            height: *height,
            stored_height: tree.stored_height,
            width: *width,
        };
        drop(data);
        budget(scope, "dynamic-offloaded")?;
        Ok(result)
    }
    fn metadata(&self, scope: &TaskScope) -> CudaStackedPcsProverData<TestGC> {
        CudaStackedPcsProverData {
            merkle_tree_tcs_data: (
                MerkleTree {
                    digests: Buffer::with_capacity_in(0, scope.clone()),
                    height: self.height,
                    stored_height: self.stored_height,
                },
                self.root,
                self.height,
                self.width,
            ),
            codeword_mle: None,
        }
    }
    fn resident(&self, scope: &TaskScope) -> Result<CudaStackedPcsProverData<TestGC>> {
        let codeword = self.codeword.map()?;
        let tree = self.tree.map()?;
        ensure!(
            codeword.len() == 16 * (1usize << 24) * 4,
            "resident codeword shape"
        );
        ensure!(
            tree.len() % std::mem::size_of::<GpuDigest>() == 0,
            "resident tree shape"
        );
        let values = unsafe {
            std::slice::from_raw_parts(codeword.as_ptr().cast::<Felt>(), codeword.len() / 4)
        };
        let digests = unsafe {
            std::slice::from_raw_parts(
                tree.as_ptr().cast::<GpuDigest>(),
                tree.len() / std::mem::size_of::<GpuDigest>(),
            )
        };
        let tensor = Tensor {
            storage: DeviceBuffer::from_host_slice(values, scope)?.into_inner(),
            dimensions: Dimensions::try_from([16, 1usize << 24])?,
        };
        let merkle = MerkleTree {
            digests: DeviceBuffer::from_host_slice(digests, scope)?.into_inner(),
            height: self.height,
            stored_height: self.stored_height,
        };
        Ok(CudaStackedPcsProverData {
            merkle_tree_tcs_data: (merkle, self.root, self.height, self.width),
            codeword_mle: Some(Arc::new(tensor)),
        })
    }
    fn opening<'a>(
        &'a self,
        scope: &'a TaskScope,
    ) -> sp1_gpu_basefold::TrustedComponentOpeningBuilder<'a, TestGC> {
        Box::new(move |indices| {
            let operation = || -> Result<_> {
                let started = Instant::now();
                let codeword = self.codeword.map()?;
                let tree = self.tree.map()?;
                ensure!(
                    codeword.len() == 16 * (1usize << 24) * 4,
                    "staged codeword shape"
                );
                ensure!(
                    tree.len() % std::mem::size_of::<GpuDigest>() == 0,
                    "staged tree shape"
                );
                let values = unsafe {
                    std::slice::from_raw_parts(codeword.as_ptr().cast::<Felt>(), codeword.len() / 4)
                };
                let digests = unsafe {
                    std::slice::from_raw_parts(
                        tree.as_ptr().cast::<GpuDigest>(),
                        tree.len() / std::mem::size_of::<GpuDigest>(),
                    )
                };
                let device = DeviceBuffer::from_host_slice(values, scope)?;
                let tensor = Tensor {
                    storage: device.into_inner(),
                    dimensions: Dimensions::try_from([16, 1usize << 24])?,
                };
                let merkle = MerkleTree {
                    digests: DeviceBuffer::from_host_slice(digests, scope)?.into_inner(),
                    height: self.height,
                    stored_height: self.stored_height,
                };
                let data = (merkle, self.root, self.height, self.width);
                budget(scope, "dynamic-query-upload")?;
                let tcs = Poseidon2SP1Field16CudaProver::new(scope);
                let values = tcs.compute_openings_at_indices(&tensor, indices);
                let proof = tcs.prove_openings_at_indices(&data, &tensor, indices)?;
                scope.synchronize_blocking()?;
                eprintln!(
                    "CMFD_MULTI_GPU_TRANSFER dynamic_query_seconds={:.6} bytes={}",
                    started.elapsed().as_secs_f64(),
                    codeword.len() + tree.len()
                );
                Ok(slop_merkle_tree::MerkleTreeOpeningAndProof { values, proof })
            };
            match operation() {
                Ok(value) => Some(value),
                Err(e) => {
                    eprintln!("dynamic opening failed: {e:#}");
                    None
                }
            }
        })
    }
}
pub(crate) fn prover(
    scope: &TaskScope,
) -> FriCudaProver<TestGC, Poseidon2SP1Field16CudaProver, Felt> {
    FriCudaProver::new(
        Poseidon2SP1Field16CudaProver::new(scope),
        FriConfig::new(LOG_BLOWUP, QUERIES, POW_BITS),
        LOG_ROWS,
    )
}

fn relations(
    prepared: &PreparedProver,
    command: &Command,
    network: [u8; 32],
    scope: &TaskScope,
) -> Result<Bundle> {
    let (statement, final_activation) = statement(prepared, command, network)?;
    ensure!(
        command.roots.iter().flatten().all(|x| *x < MODULUS),
        "noncanonical commitment"
    );
    let cpu_dynamic = digest_words::<CpuFelt>(command.roots);
    let gpu_dynamic = digest_words::<Felt>(command.roots);
    let mut cpu = forgematrix_v4_transcript(statement);
    bind_forgematrix_v4_commitments(&mut cpu, &prepared.cpu_fixed, &cpu_dynamic);
    let mut gpu = gpu_transcript(&statement.digest());
    bind_gpu_commitments(&mut gpu, &prepared.gpu_fixed, &gpu_dynamic);
    let mut boundary = build_initial_activation(statement.challenge_digest, &prepared.base_input);
    let mut relations = Vec::new();
    let mut claims: Vec<Vec<CpuOpeningClaim>> = Vec::new();
    for bank in 0..3 {
        let dynamic = trace(&command.prefix, bank, scope)?;
        let boundary_gpu =
            DeviceTensor::from_host(&Tensor::from(boundary).reshape([BATCH, WIDTH]), scope)?;
        let (relation, bank_claims, previous, encoded, dynamic) = prove_bank_relations(
            bank,
            statement,
            &prepared.base_input,
            &prepared.encoded_banks[bank],
            None,
            dynamic,
            &boundary_gpu.as_view(),
            &mut cpu,
            &mut gpu,
            scope,
        )?;
        ensure!(
            bank > 0 || previous.is_empty(),
            "unexpected initial boundary claim"
        );
        if bank > 0 {
            claims[bank - 1].extend(previous);
        }
        relations.push(relation);
        claims.push(bank_claims);
        let host = SealedWords::open(
            &PathBuf::from(format!(
                "{}-bank{bank}-dynamic.bin",
                command.prefix.display()
            )),
            DYNAMIC_BYTES,
            MODULUS,
        )
        .map_err(anyhow::Error::msg)?;
        let values = montgomery_values(&host)?;
        boundary =
            values[BANK_VALUES + (LAYERS - 1) * CELLS..BANK_VALUES + LAYERS * CELLS].to_vec();
        drop(dynamic);
        drop(encoded);
        drop(boundary_gpu);
        budget(scope, "bank-relations-freed")?;
    }
    for repetition in 0..2 {
        let cpu_point = sample_forgematrix_v4_final_point(&mut cpu, repetition)?;
        let gpu_point = sample_final_point(&mut gpu, repetition);
        ensure!(
            bridge::<_, Vec<CpuExt>>(gpu_point.iter().copied().collect::<Vec<_>>())?
                == cpu_point
                    .batch
                    .iter()
                    .chain(cpu_point.output.iter())
                    .copied()
                    .collect::<Vec<_>>(),
            "final point diverged"
        );
        let value = forgematrix_v4_activation_evaluation(
            &final_activation,
            &cpu_point.batch,
            &cpu_point.output,
        )?;
        claims[2].push(forgematrix_v4_final_opening_claim(&cpu_point, value)?);
    }
    for bank_claims in &mut claims {
        finalize_forgematrix_v4_bank_opening_claims(bank_claims)?;
    }
    let mut openings = Vec::new();
    for bank in 0..3 {
        let dynamic = trace(&command.prefix, bank, scope)?;
        let fixed = DeviceBuffer::from_host_slice(&prepared.encoded_banks[bank], scope)?;
        openings.push(real_v4_opening::prove_public_bank_opening(
            bank,
            &prepared.fixed_maps[bank],
            &fixed,
            &dynamic,
            prepared.gpu_fixed[bank],
            gpu_dynamic[bank],
            &claims[bank],
            &mut gpu,
            &mut cpu,
            scope,
        )?);
        drop(fixed);
        drop(dynamic);
        budget(scope, "public-opening-freed")?;
    }
    let banks = (0..3)
        .map(|bank| ForgeMatrixV4BankProof {
            dynamic_commitment: cpu_dynamic[bank],
            relations: relations[bank].clone(),
            opening: openings[bank].clone(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("bank count"))?;
    let carrier = ForgeMatrixV4TransparentProof {
        final_activation,
        banks,
    };
    let (lab, roots, points, evaluations) =
        direct_opening::direct_statement(prepared, statement, &carrier)?;
    let (mut challenger, witness, weights, total) =
        direct_opening::direct_start(lab.job, &roots, &points, &evaluations);
    let mut traces = Vec::new();
    let mut component_claims = Vec::new();
    let mut offset = 0;
    for bank in 0..3 {
        let fixed = DeviceBuffer::from_host_slice(&prepared.encoded_banks[bank], scope)?;
        traces.push(real_v4_opening::fixed_bank_rlc(
            &fixed,
            &weights[offset..offset + 256],
            scope,
        )?);
        component_claims.push(
            evaluations[bank * 2]
                .iter()
                .zip(&weights[offset..offset + 256])
                .map(|(v, w)| *v * *w)
                .sum(),
        );
        offset += 256;
        scope.synchronize_blocking()?;
        drop(fixed);
        let dynamic = trace(&command.prefix, bank, scope)?;
        let coefficients =
            DeviceTensor::from_host(&Tensor::from(weights[offset..offset + 16].to_vec()), scope)?;
        let row = dot_along_dim_view(
            dynamic.main_virtual_tensor(LOG_ROWS),
            coefficients.as_view(),
            0,
        );
        traces.push(Mle::new(row.reshape([1, ROWS])));
        component_claims.push(
            evaluations[bank * 2 + 1]
                .iter()
                .zip(&weights[offset..offset + 16])
                .map(|(v, w)| *v * *w)
                .sum(),
        );
        offset += 16;
        scope.synchronize_blocking()?;
        drop(dynamic);
        budget(scope, "secondary-input")?;
    }
    let eq_points = (0..6)
        .map(|i| Point::from(points[i / 2].clone()))
        .collect::<Vec<_>>();
    let (sumcheck, _) = low_memory_sumcheck::multi_hadamard_sumcheck_at_points(
        traces,
        &eq_points,
        component_claims,
        &mut challenger,
        total,
    );
    budget(scope, "secondary-reduction")?;
    let shared_point = sumcheck.point_and_eval.0.clone();
    let mut shared: [Vec<Ext>; 6] = std::array::from_fn(|_| Vec::new());
    for bank in 0..3 {
        let fixed = DeviceBuffer::from_host_slice(&prepared.encoded_banks[bank], scope)?;
        shared[bank * 2] = real_v4_opening::evaluate_fixed_columns(&fixed, &shared_point, scope)?;
        scope.synchronize_blocking()?;
        drop(fixed);
        let dynamic = trace(&command.prefix, bank, scope)?;
        shared[bank * 2 + 1] = real_v4_opening::evaluate_dynamic_columns(
            dynamic.main_virtual_tensor(LOG_ROWS),
            &shared_point,
            scope,
        )?;
        scope.synchronize_blocking()?;
        drop(dynamic);
        budget(scope, "shared-evaluations")?;
    }
    let rounds = sumcheck
        .univariate_polys
        .iter()
        .map(|poly| {
            ensure!(poly.coefficients.len() == 3, "secondary degree");
            bridge([
                poly.coefficients[0],
                poly.coefficients[1],
                poly.coefficients[2],
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    let lab_reduction = cmfd_consensus::forgematrix_v4_direct::reduction::ReductionProof {
        batch_witness: bridge(witness)?,
        rounds,
        evaluations_at_shared_point: bridge(shared.clone())?,
    };
    let obligation = cmfd_consensus::forgematrix_v4_direct::reduction::verify_reduction(&lab, &lab_reduction)?;
    ensure!(
        obligation.point()
            == bridge::<_, Vec<_>>(shared_point.iter().copied().collect::<Vec<_>>())?.as_slice(),
        "shared point diverged"
    );
    ensure!(
        obligation.values() == &bridge::<_, [Vec<_>; 6]>(shared.clone())?,
        "shared evaluations diverged"
    );
    Ok(Bundle {
        statement_digest: statement.digest(),
        carrier: encode_forgematrix_v4_transparent_proof(&carrier)?,
        reduction: bridge(lab_reduction)?,
        shared_point: shared_point.iter().copied().collect(),
        shared_values: shared,
        state: State::capture(&challenger),
    })
}

fn rlc(prepared: &PreparedProver, command: &Command, scope: &TaskScope) -> Result<Snapshot> {
    ensure!(command.coefficients.len() == 816, "RLC coefficient count");
    ensure!(
        command.coefficients.iter().flatten().all(|x| *x < MODULUS),
        "noncanonical RLC coefficient"
    );
    let coefficients = command
        .coefficients
        .iter()
        .map(|w| Ext::from_base_slice(&w.map(Felt::from_canonical_u32)))
        .collect::<Vec<_>>();
    let mut combined: Option<Mle<Ext, TaskScope>> = None;
    let mut at = 0;
    for bank in 0..3 {
        let fixed = DeviceBuffer::from_host_slice(&prepared.encoded_banks[bank], scope)?;
        let part = real_v4_opening::fixed_bank_rlc(&fixed, &coefficients[at..at + 256], scope)?;
        at += 256;
        if let Some(current) = combined.as_mut() {
            real_v4_opening::add_ext_in_place(current, part.guts(), scope)?;
        } else {
            combined = Some(part);
        }
        scope.synchronize_blocking()?;
        drop(fixed);
        let dynamic = trace(&command.prefix, bank, scope)?;
        let c = DeviceTensor::from_host(&Tensor::from(coefficients[at..at + 16].to_vec()), scope)?;
        at += 16;
        let part = dot_along_dim_view(dynamic.main_virtual_tensor(LOG_ROWS), c.as_view(), 0);
        real_v4_opening::add_ext_in_place(combined.as_mut().unwrap(), &part, scope)?;
        scope.synchronize_blocking()?;
        drop(dynamic);
        budget(scope, "joint-rlc-bank")?;
    }
    let host = DeviceTensor::copy_to_host(combined.as_ref().unwrap().guts())?;
    Snapshot::slice(host.as_slice())
}

fn finish(
    network: [u8; 32],
    prepared: &PreparedProver,
    command: &Command,
    data: &[DynamicData],
    input: &mut impl BufRead,
    scope: &TaskScope,
) -> Result<serde_json::Value> {
    ensure!(data.len() == 3, "dynamic stages not prepared");
    let mut bundle_bytes = Vec::new();
    File::open(&command.bundle)?
        .take((24 << 20) + 1)
        .read_to_end(&mut bundle_bytes)?;
    ensure!(bundle_bytes.len() <= 24 << 20, "oversized stage bundle");
    let bundle: Bundle = bincode::deserialize(&bundle_bytes)?;
    let (expected, final_activation) =
        statement(prepared, command, network)?;
    let carrier = decode_forgematrix_v4_transparent_proof(&bundle.carrier)?;
    ensure!(
        expected.digest() == bundle.statement_digest
            && final_activation == carrier.final_activation,
        "bundle statement mismatch"
    );
    for bank in 0..3 {
        ensure!(
            data[bank].commitment
                == bridge::<_, GpuDigest>(carrier.banks[bank].dynamic_commitment)?,
            "offloaded commitment mismatch"
        );
    }
    let mut challenger = bundle.state.restore()?;
    let shared_point = Point::from(bundle.shared_point.clone());
    direct_opening::tag(&mut challenger, direct_opening::PCS_DOMAIN);
    for x in shared_point.iter() {
        direct_opening::observe_ext(&mut challenger, *x);
    }
    for values in &bundle.shared_values {
        for x in values {
            direct_opening::observe_ext(&mut challenger, *x);
        }
    }
    let fixed = (0..3)
        .map(|b| direct_opening::fixed_data(&prepared.fixed_maps[b], scope))
        .collect::<Vec<_>>();
    let mut dynamic = data.iter().map(|d| d.metadata(scope)).collect::<Vec<_>>();
    // The unchanged SDK obtains its CUDA scope from a resident component.
    // Keep one authenticated 1 GiB codeword/tree on this card; stage the other
    // two only for query openings. This uses the stock six-component PCS path.
    dynamic[2] = data[2].resident(scope)?;
    budget(scope, "joint-resident-component")?;
    let mut refs = Vec::new();
    for bank in 0..3 {
        refs.push(&fixed[bank]);
        refs.push(&dynamic[bank]);
    }
    let stacked: Rounds<_> = refs.into_iter().collect();
    let builder = Box::new(
        move |coefficients: &Tensor<Ext>, builder_scope: &TaskScope| {
            assert_eq!(
                coefficients.as_slice().len(),
                1024,
                "padded six-component batching width"
            );
            let words = coefficients.as_slice()[..816]
                .iter()
                .map(|x| {
                    let base: &[Felt] = x.as_base_slice();
                    base.iter()
                        .map(|x| x.as_canonical_u32())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            send(serde_json::json!({"event":"rlc_request","coefficients":words}))
                .expect("RLC request");
            let answer = receive(input).expect("RLC response");
            assert_eq!(answer.op, "rlc_result");
            let words = SealedWords::open(&answer.path, ROWS * std::mem::size_of::<Ext>(), MODULUS)
                .expect("sealed RLC vector");
            let values =
                unsafe { std::slice::from_raw_parts(words.words().as_ptr().cast::<Ext>(), ROWS) };
            let storage = DeviceBuffer::from_host_slice(values, builder_scope)
                .expect("RLC vector upload")
                .into_inner();
            Mle::new(Tensor {
                storage,
                dimensions: Dimensions::try_from([1, ROWS]).unwrap(),
            })
        },
    );
    let builders = vec![
        Some(prepared.fixed_maps[0].opening_builder()),
        Some(data[0].opening(scope)),
        Some(prepared.fixed_maps[1].opening_builder()),
        Some(data[1].opening(scope)),
        Some(prepared.fixed_maps[2].opening_builder()),
        None,
    ];
    let flat = bundle
        .shared_values
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let began = Instant::now();
    let basefold = prover(scope).prove_trusted_evaluations_basefold_with_component_openings(
        shared_point,
        flat,
        None,
        Some(builder),
        stacked,
        Some(builders),
        &mut challenger,
    )?;
    budget(scope, "joint-basefold")?;
    let basefold = bincode::deserialize(&bincode::serialize(&basefold)?)?;
    let wire = cmfd_consensus::forgematrix_v4_direct::encode(
        &carrier,
        expected,
        &bundle.reduction,
        &basefold,
    )?;
    let verify_started = Instant::now();
    cmfd_consensus::forgematrix_v4_direct::verify_wire(
        expected,
        prepared.cpu_fixed,
        &prepared.base_input,
        &wire,
    )?;
    let verify_seconds = verify_started.elapsed().as_secs_f64();
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&command.output)?
        .write_all(&wire)?;
    Ok(
        serde_json::json!({"verified":true,"wire_bytes":wire.len(),"joint_basefold_including_rlc_seconds":began.elapsed().as_secs_f64(),"full_cpu_verification_seconds":verify_seconds,"gpu_cap_bytes":CAP,"proof_version":2,"parameters":{"log_blowup":1,"queries":270,"grinding_bits":16,"commitments":6}}),
    )
}

pub fn run_worker(
    role: &str,
    prepared: &PreparedProver,
    network: [u8; 32],
    scope: &TaskScope,
) -> Result<()> {
    ensure!(
        role == "relations" || role == "pcs",
        "unknown multi-GPU role"
    );
    ensure!(
        cmfd_consensus::forgematrix_v4::forgematrix_v4_direct_proof_system_digest_for_network(network).is_some(),
        "multi-GPU qualification requires compact testnet"
    );
    ensure!(
        std::env::var("CMFD_MULTI_GPU_STAGE").as_deref() == Ok(role),
        "missing stage isolation"
    );
    let mask = std::env::var("CUDA_VISIBLE_DEVICES")?;
    ensure!(
        mask.starts_with("GPU-") && !mask.contains(','),
        "worker must see exactly one physical GPU UUID"
    );
    budget(scope, "worker-start")?;
    send(serde_json::json!({"event":"ready","role":role,"pid":std::process::id()}))?;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut data = Vec::new();
    let mut rlc_snapshot = None;
    loop {
        let command = receive(&mut input)?;
        let began = Instant::now();
        match (role, command.op.as_str()) {
            (_, "quit") => break,
            ("pcs", "prepare") => {
                ensure!(data.is_empty(), "worker already has a proof job");
                statement(prepared, &command, network)?;
                for bank in 0..3 {
                    let dynamic = trace(&command.prefix, bank, scope)?;
                    data.push(DynamicData::commit(&dynamic, scope)?);
                    drop(dynamic);
                    budget(scope, "commit-bank-freed")?;
                }
                let roots = data
                    .iter()
                    .map(|d| d.commitment.map(|x| x.as_canonical_u32()))
                    .collect::<Vec<_>>();
                send(
                    serde_json::json!({"event":"prepared","roots":roots,"seconds":began.elapsed().as_secs_f64()}),
                )?;
            }
            ("relations", "relations") => {
                let bundle = relations(prepared, &command, network, scope)?;
                let mut out = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&command.bundle)?;
                // Serialize once in memory rather than making millions of
                // one-byte file syscalls for the carrier's codec bytes.
                out.write_all(&bincode::serialize(&bundle)?)?;
                out.flush()?;
                send(
                    serde_json::json!({"event":"relations_done","seconds":began.elapsed().as_secs_f64()}),
                )?;
            }
            ("relations", "rlc") => {
                ensure!(
                    rlc_snapshot.is_none(),
                    "only one joint RLC is allowed per proof"
                );
                rlc_snapshot = Some(rlc(prepared, &command, scope)?);
                send(
                    serde_json::json!({"event":"rlc_done","path":rlc_snapshot.as_ref().unwrap().path(),"bytes":ROWS*16,"seconds":began.elapsed().as_secs_f64()}),
                )?;
            }
            ("pcs", "finish") => {
                let report = finish(network, prepared, &command, &data, &mut input, scope)?;
                send(
                    serde_json::json!({"event":"done","report":report,"seconds":began.elapsed().as_secs_f64()}),
                )?;
            }
            _ => anyhow::bail!("command is not permitted for this stage"),
        }
    }
    drop(data);
    drop(rlc_snapshot);
    scope.synchronize_blocking()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenger_snapshot_roundtrip() {
        let mut c = TestGC::default_challenger();
        for i in 0..35 {
            c.observe(Felt::from_canonical_u32(i));
        }
        let _ = c.sample_ext_element::<Ext>();
        let mut d = State::capture(&c).restore().unwrap();
        for _ in 0..12 {
            assert_eq!(c.sample_ext_element::<Ext>(), d.sample_ext_element::<Ext>());
        }
    }
    #[test]
    fn challenger_rejects_noncanonical_state() {
        let mut s = State::capture(&TestGC::default_challenger());
        s.sponge[0] = MODULUS;
        assert!(s.restore().is_err());
    }
    #[test]
    fn staging_snapshot_is_immutable() {
        let snapshot = Snapshot::slice(&[1u32, 2, 3, 4]).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(snapshot.0.as_raw_fd(), libc::F_GET_SEALS) } & SEALS,
            SEALS
        );
        assert_eq!(unsafe { libc::ftruncate(snapshot.0.as_raw_fd(), 0) }, -1);
        assert_eq!(
            SealedWords::open(&snapshot.path(), 16, MODULUS)
                .unwrap()
                .words(),
            &[1, 2, 3, 4]
        );
    }
    #[test]
    #[ignore = "requires an explicitly reserved GPU"]
    fn streamed_equalities_match_stock_gpu_transcript() {
        run_sync_in_place(|scope| {
            for count in [6usize, 16] {
                let points = (0..count)
                    .map(|i| {
                        Point::from(
                            (0..8)
                                .map(|j| Ext::from_canonical_usize(i * 8 + j + 1))
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>();
                let values = (0..count)
                    .map(|i| {
                        (0..256)
                            .map(|j| Ext::from_canonical_usize((i + 1) * j + 7))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let claims = values
                    .iter()
                    .zip(&points)
                    .map(|(v, p)| {
                        let eq = Mle::<Ext>::partial_lagrange(p);
                        v.iter()
                            .zip(eq.guts().as_slice())
                            .map(|(a, b)| *a * *b)
                            .sum::<Ext>()
                    })
                    .collect::<Vec<_>>();
                let total = claims.iter().copied().sum();
                let mut a = TestGC::default_challenger();
                let mut b = a.clone();
                let traces = values
                    .iter()
                    .map(|v| upload_ext(v.clone(), &scope))
                    .collect();
                let (stock, stock_ends) =
                    sp1_gpu_jagged_sumcheck::multi_hadamard_sumcheck_at_points(
                        traces,
                        &points,
                        claims.clone(),
                        &mut a,
                        total,
                    );
                let traces = values
                    .iter()
                    .map(|v| upload_ext(v.clone(), &scope))
                    .collect();
                let (streamed, ends) = low_memory_sumcheck::multi_hadamard_sumcheck_at_points(
                    traces, &points, claims, &mut b, total,
                );
                scope.synchronize_blocking().unwrap();
                assert_eq!(
                    bincode::serialize(&stock).unwrap(),
                    bincode::serialize(&streamed).unwrap()
                );
                assert_eq!(stock_ends, ends);
                assert_eq!(State::capture(&a).sponge, State::capture(&b).sponge);
                assert_eq!(State::capture(&a).input, State::capture(&b).input);
                assert_eq!(State::capture(&a).output, State::capture(&b).output);
            }
        })
        .unwrap();
    }
}
