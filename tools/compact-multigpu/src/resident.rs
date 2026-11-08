//! Resident fixed-bank service and distributed reductions for one v2 proof.
//! Public transcript order, commitment binding and receiver verification are
//! unchanged. Large model banks never move to the dynamic proving GPU.
use super::*;
use anyhow::Context as _;
use gpu_witness::trace;
use multi_gpu::{prover, send, Snapshot};
use slop_algebra::{AbstractExtensionField, UnivariatePolynomial};
use slop_commit::Rounds;
use slop_sumcheck::PartialSumcheckProof;
use sp1_gpu_basefold::{CudaStackedPcsProverData, TrustedComponentOpeningBuilder};
use std::{cell::Cell, os::fd::AsRawFd};

type Words = [u32; 4];
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const DEVICE_CAP: usize = 29 << 28;
unsafe extern "C" {
    fn cudaDeviceGetDefaultMemPool(pool: *mut *mut std::ffi::c_void, device: i32) -> i32;
    fn cudaMemPoolSetAttribute(
        pool: *mut std::ffi::c_void,
        attribute: i32,
        value: *const std::ffi::c_void,
    ) -> i32;
    fn cudaMemPoolTrimTo(pool: *mut std::ffi::c_void, minimum: usize) -> i32;
}
fn dynamic_workspace_cache(scope: &TaskScope, initialize: bool) -> Result<()> {
    scope.synchronize_blocking()?;
    let mut pool = std::ptr::null_mut();
    unsafe {
        ensure!(
            cudaDeviceGetDefaultMemPool(&mut pool, 0) == 0,
            "dynamic memory pool"
        );
        if initialize {
            // Retain a bounded workspace only within a proof; job completion
            // explicitly trims it. Captured uploads synchronize separately.
            let threshold = 4u64 << 30;
            ensure!(
                cudaMemPoolSetAttribute(pool, 4, (&threshold as *const u64).cast()) == 0,
                "bounded dynamic workspace cache"
            );
        } else {
            ensure!(
                cudaMemPoolTrimTo(pool, 0) == 0,
                "release dynamic workspace after proof"
            );
        }
    }
    Ok(())
}
fn budget(scope: &TaskScope, phase: &str) -> Result<()> {
    scope.synchronize_blocking()?;
    let (free, total) = cuda_memory_info()?;
    let cap = if std::env::var("CMFD_SHARED_MODEL").as_deref() == Ok("1") {
        15 << 29
    } else {
        DEVICE_CAP
    };
    eprintln!(
        "CMFD_RESIDENT_MEMORY phase={phase} used_bytes={} cap_bytes={cap}",
        total - free
    );
    ensure!(
        total - free <= cap,
        "{phase} exceeded the configured total-device ceiling"
    );
    Ok(())
}
#[derive(Serialize, Deserialize)]
struct Cache {
    pid: u32,
    record_digest: String,
    base: PathBuf,
    trees: [PathBuf; 3],
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Component {
    pub coefficients: Vec<Words>,
    pub point: Vec<Words>,
    pub claim: Words,
}
#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    id: u64,
    #[serde(default)]
    bank: usize,
    #[serde(default)]
    point: Vec<Words>,
    #[serde(default)]
    coefficients: Vec<Words>,
    #[serde(default)]
    components: Vec<Component>,
    #[serde(default)]
    alpha: Option<Words>,
    #[serde(default)]
    round: usize,
    #[serde(default)]
    template: PathBuf,
    #[serde(default)]
    prefix: PathBuf,
    #[serde(default)]
    final_path: PathBuf,
    #[serde(default)]
    output: PathBuf,
    #[serde(default)]
    replay_mode: String,
    #[serde(default)]
    replay_coefficients: PathBuf,
    #[serde(default)]
    replay_batch_size: u32,
    #[serde(default)]
    replay_challenges: PathBuf,
    #[serde(default)]
    capture_id: String,
    #[serde(default)]
    provider_pid: u32,
}
#[derive(Deserialize)]
struct Response {
    op: String,
    #[serde(default)]
    id: u64,
    #[serde(default)]
    path: PathBuf,
    #[serde(default)]
    elements: usize,
    #[serde(default)]
    values: Vec<Words>,
    #[serde(default)]
    polynomial: Vec<Words>,
    #[serde(default)]
    finished: bool,
}
fn read<T: DeserializeOwned>() -> Result<T> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    ensure!(
        input.by_ref().take(1 << 20).read_line(&mut line)? > 0 && line.ends_with('\n'),
        "bounded resident command missing"
    );
    Ok(serde_json::from_str(&line)?)
}
fn word(value: Ext) -> Words {
    let fields: &[Felt] = value.as_base_slice();
    std::array::from_fn(|i| fields[i].as_canonical_u32())
}
fn ext(value: Words) -> Result<Ext> {
    ensure!(
        value.iter().all(|x| *x < MODULUS),
        "noncanonical extension word"
    );
    Ok(Ext::from_base_slice(&value.map(Felt::from_canonical_u32)))
}
fn values(words: &[Words]) -> Result<Vec<Ext>> {
    words.iter().copied().map(ext).collect()
}
fn validate_worker(role: &str) -> Result<()> {
    ensure!(
        std::env::var("CMFD_MULTI_GPU_STAGE").as_deref() == Ok(role),
        "resident worker role isolation"
    );
    let mask = std::env::var("CUDA_VISIBLE_DEVICES")?;
    ensure!(
        mask.starts_with("GPU-") && !mask.contains(','),
        "resident worker requires one physical GPU UUID"
    );
    Ok(())
}
fn point(words: &[Words], dimension: usize) -> Result<Point<Ext>> {
    ensure!(words.len() == dimension, "remote point dimension");
    Ok(Point::from(values(words)?))
}
fn cache() -> Result<Cache> {
    let value: Cache = serde_json::from_str(&std::env::var("CMFD_MULTI_SHARED_FIXED")?)?;
    ensure!(
        value.pid > 1
            && value.record_digest == hex::encode(PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST),
        "shared fixed record identity"
    );
    Ok(value)
}
fn sealed_path(path: &Path, pid: u32, bytes: Option<usize>) -> Result<File> {
    let prefix = format!("/proc/{pid}/fd/");
    let path_string = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid shared path"))?;
    let suffix = path_string
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("shared cache belongs to another process"))?;
    ensure!(
        !suffix.is_empty() && suffix.bytes().all(|x| x.is_ascii_digit()),
        "invalid shared descriptor"
    );
    let file = File::open(path)?;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    ensure!(
        seals >= 0 && seals & SEALS == SEALS,
        "shared cache lacks immutable kernel seals"
    );
    if let Some(bytes) = bytes {
        ensure!(
            file.metadata()?.len() == bytes as u64,
            "shared cache length"
        );
    }
    Ok(file)
}
pub(crate) fn shared_tree_path(bank: usize) -> Result<Option<PathBuf>> {
    if std::env::var("CMFD_MULTI_GPU_STAGE").as_deref() != Ok("dynamic") {
        return Ok(None);
    }
    ensure!(bank < 3, "shared tree bank");
    let cache = cache()?;
    sealed_path(&cache.trees[bank], cache.pid, None)?;
    Ok(Some(cache.trees[bank].clone()))
}
pub(crate) fn shared_base_input() -> Result<Vec<u8>> {
    let cache = cache()?;
    let mut file = sealed_path(&cache.base, cache.pid, Some(CELLS))?;
    let mut bytes = Vec::with_capacity(CELLS);
    file.read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() == CELLS && bytes.iter().all(|x| *x <= 250),
        "shared base encoding"
    );
    Ok(bytes)
}
thread_local! {static NEXT_ID:Cell<u64>=const{Cell::new(0)};}
fn begin_exchange(mut request: serde_json::Value) -> Result<u64> {
    let id = NEXT_ID.with(|id| {
        let next = id.get() + 1;
        id.set(next);
        next
    });
    request["id"] = id.into();
    request["event"] = "fixed_request".into();
    send(request)?;
    Ok(id)
}
fn finish_exchange(id: u64) -> Result<Response> {
    let response: Response = read()?;
    ensure!(
        response.op == "fixed_response" && response.id == id,
        "out-of-order fixed response"
    );
    Ok(response)
}
fn exchange(request: serde_json::Value) -> Result<Response> {
    finish_exchange(begin_exchange(request)?)
}
fn vector(response: Response, elements: usize, scope: &TaskScope) -> Result<Mle<Ext, TaskScope>> {
    ensure!(response.elements == elements, "remote vector shape");
    let cache = cache()?;
    sealed_path(&response.path, cache.pid, Some(elements * size_of::<Ext>()))?;
    let words = SealedWords::open(&response.path, elements * size_of::<Ext>(), MODULUS)
        .map_err(anyhow::Error::msg)?;
    let values =
        unsafe { std::slice::from_raw_parts(words.words().as_ptr().cast::<Ext>(), elements) };
    let storage = DeviceBuffer::from_host_slice(values, scope)?.into_inner();
    scope.synchronize_blocking()?;
    Ok(Mle::new(Tensor {
        storage,
        dimensions: Dimensions::try_from([1, elements])?,
    }))
}
pub(crate) fn weights(
    bank: usize,
    output: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Mle<Ext, TaskScope>> {
    vector(
        exchange(
            serde_json::json!({"op":"weights","bank":bank,"point":output.iter().copied().map(word).collect::<Vec<_>>()}),
        )?,
        LAYERS * WIDTH,
        scope,
    )
}
pub(crate) fn fixed_evaluations(bank: usize, evaluation_point: &Point<Ext>) -> Result<Vec<Ext>> {
    let response = exchange(
        serde_json::json!({"op":"evaluate","bank":bank,"point":evaluation_point.iter().copied().map(word).collect::<Vec<_>>()}),
    )?;
    ensure!(response.values.len() == 256, "fixed evaluation count");
    values(&response.values)
}
pub(crate) fn opening_evaluations(
    bank: usize,
    point: &Point<Ext>,
    dynamic: TensorView<'_, Felt, TaskScope>,
    scope: &TaskScope,
) -> Result<(Vec<Ext>, Vec<Ext>)> {
    if std::env::var("CMFD_DEVICE_RELATIONS").as_deref() != Ok("1") {
        return Ok((
            fixed_evaluations(bank, point)?,
            real_v4_opening::evaluate_dynamic_columns(dynamic, point, scope)?,
        ));
    }
    // The point is already fixed by the transcript. These two evaluations are
    // independent and can run on B and A at the same time. Only one RPC is in flight.
    let id = begin_exchange(
        serde_json::json!({"op":"evaluate","bank":bank,"point":point.iter().copied().map(word).collect::<Vec<_>>()}),
    )?;
    let local = real_v4_opening::evaluate_dynamic_columns(dynamic, point, scope)?;
    let remote = finish_exchange(id)?;
    ensure!(remote.values.len() == 256, "fixed evaluation count");
    Ok((values(&remote.values)?, local))
}
pub(crate) fn component(
    coefficients: Vec<Ext>,
    evaluation_point: &Point<Ext>,
    claim: Ext,
) -> Component {
    Component {
        coefficients: coefficients.into_iter().map(word).collect(),
        point: evaluation_point.iter().copied().map(word).collect(),
        claim: word(claim),
    }
}
pub(crate) fn distributed_sumcheck(
    traces: Vec<Mle<Ext, TaskScope>>,
    points: Vec<Point<Ext>>,
    claims: Vec<Ext>,
    fixed: Vec<Component>,
    challenger: &mut GpuChallenger,
    total: Ext,
) -> Result<PartialSumcheckProof<Ext>> {
    ensure!(
        !traces.is_empty() && !fixed.is_empty(),
        "distributed component partition"
    );
    let variables = traces[0].num_variables() as usize;
    ensure!(variables == 23, "distributed production row geometry");
    let fixed_total = fixed
        .iter()
        .map(|c| ext(c.claim))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<Ext>();
    ensure!(
        claims.iter().copied().sum::<Ext>() + fixed_total == total,
        "distributed claimed sum"
    );
    let pipelined = std::env::var("CMFD_DEVICE_RELATIONS").as_deref() == Ok("1");
    let initial = begin_exchange(serde_json::json!({"op":"begin","components":fixed}))?;
    let mut remote = if pipelined {
        None
    } else {
        Some(finish_exchange(initial)?)
    };
    let mut local = low_memory_sumcheck::ComponentSumcheck::new(traces, points, claims);
    if pipelined {
        remote = Some(finish_exchange(initial)?);
    }
    let mut remote = remote.unwrap();
    let mut polynomials = Vec::new();
    let mut evaluation_point = Vec::new();
    let mut terminal = total;
    for round in 0..variables {
        ensure!(
            remote.polynomial.len() == 3 && !remote.finished,
            "remote polynomial degree"
        );
        let remote_poly = UnivariatePolynomial::new(values(&remote.polynomial)?);
        let polynomial =
            low_memory_sumcheck::add_round_polynomials(&local.polynomial(), &remote_poly);
        low_memory_sumcheck::observe_sumcheck_round(challenger, &polynomial);
        let alpha = challenger.sample_ext_element();
        evaluation_point.insert(0, alpha);
        terminal = polynomial.eval_at_point(alpha);
        polynomials.push(polynomial);
        let request = serde_json::json!({"op":"step","round":round,"alpha":word(alpha)});
        if pipelined {
            let id = begin_exchange(request)?;
            local.fold(alpha);
            remote = finish_exchange(id)?;
        } else {
            local.fold(alpha);
            remote = exchange(request)?;
        }
    }
    ensure!(
        remote.finished && remote.polynomial.is_empty(),
        "remote sumcheck did not finish"
    );
    Ok(PartialSumcheckProof {
        univariate_polys: polynomials,
        claimed_sum: total,
        point_and_eval: (Point::from(evaluation_point), terminal),
    })
}

pub(crate) fn run_fixed(
    prepared: &PreparedProver,
    network: [u8; 32],
    scope: &TaskScope,
) -> Result<()> {
    validate_worker("fixed")?;
    let started = Instant::now();
    ensure!(
        network == FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID,
        "fixed worker network"
    );
    // Warm the reduction kernels before the large model occupies VRAM.
    {
        let count = 1usize << 20;
        let mut state = low_memory_sumcheck::ComponentSumcheck::new(
            (0..3)
                .map(|_| upload_ext(vec![Ext::zero(); count], scope))
                .collect(),
            (0..3)
                .map(|_| Point::from(vec![Ext::from_canonical_usize(3); 20]))
                .collect(),
            vec![Ext::zero(); 3],
        );
        let _ = state.polynomial();
        state.fold(Ext::from_canonical_usize(7));
        drop(state);
        scope.synchronize_blocking()?;
    }
    budget(scope, "resident-kernels-warmed")?;
    let mut banks = Vec::new();
    for bank in 0..3 {
        banks.push(DeviceBuffer::from_host_slice(
            &prepared.encoded_banks[bank],
            scope,
        )?);
        budget(scope, "resident-fixed-bank")?;
    }
    scope.synchronize_blocking()?;
    budget(scope, "resident-fixed-ready")?;
    let shared_model_mode = std::env::var("CMFD_SHARED_MODEL").as_deref() == Ok("1");
    #[cfg(not(feature = "shared-resident-replay"))]
    ensure!(
        !shared_model_mode,
        "shared model replay is not compiled into this worker"
    );
    #[cfg(feature = "shared-resident-replay")]
    let mut shared_model = if shared_model_mode {
        Some(shared_replay::Model::open(prepared, &banks, scope)?)
    } else {
        None
    };
    // Authenticate each owned snapshot after sealing. The dynamic process can
    // safely reuse these same immutable inodes without re-reading SSD files.
    let mut trees = Vec::new();
    for bank in 0..3 {
        let tree = Snapshot::bytes(prepared.fixed_maps[bank].tree_bytes())?;
        ensure!(
            blake3::Hasher::new()
                .update_rayon(&tree.map()?)
                .finalize()
                .as_bytes()
                == &prepared.fixed_record.banks()[bank].tree_blake3(),
            "sealed fixed tree digest"
        );
        trees.push(tree);
    }
    let base = Snapshot::bytes(&prepared.base_input)?;
    let cache = Cache {
        pid: std::process::id(),
        record_digest: hex::encode(PRODUCTION_V4_FIXED_ARTIFACT_RECORD_DIGEST),
        base: base.path(),
        trees: std::array::from_fn(|i| trees[i].path()),
    };
    send(
        serde_json::json!({"event":"ready","role":"fixed","cache":cache,"shared_model":shared_model_mode,"network_id":hex::encode(network),"proof_version":FORGEMATRIX_V4_DIRECT_PROOF_VERSION,"proof_system_digest":hex::encode(forgematrix_v4_direct_proof_system_digest()),"seconds":started.elapsed().as_secs_f64()}),
    )?;
    let mut snapshot: Option<Snapshot> = None;
    let mut reduction: Option<low_memory_sumcheck::ComponentSumcheck> = None;
    let mut current_round = 0;
    loop {
        let request: Request = read()?;
        let began = Instant::now();
        // Return unused allocation pages before another fixed-bank reduction.
        // Live model and sumcheck buffers remain owned throughout the request.
        if matches!(
            request.op.as_str(),
            "begin" | "weights" | "combined" | "evaluate"
        ) {
            low_memory_sumcheck::release_component_reservations(scope, "before-fixed-operation");
        }
        let mut reply = serde_json::json!({"event":"fixed_done","id":request.id});
        match request.op.as_str() {
            "quit" => break,
            #[cfg(feature = "shared-resident-replay")]
            "replay" => {
                ensure!(
                    reduction.is_none(),
                    "replay cannot interrupt an active fixed sumcheck"
                );
                snapshot = None;
                shared_model
                    .as_mut()
                    .context("resident replay was not enabled")?
                    .run(
                        &request.replay_mode,
                        &request.replay_coefficients,
                        &request.prefix,
                        request.replay_batch_size,
                        &request.replay_challenges,
                    )?;
            }
            #[cfg(feature = "shared-resident-replay")]
            "replay_trim" => {
                ensure!(
                    reduction.is_none(),
                    "replay trim cannot interrupt an active fixed sumcheck"
                );
                shared_model
                    .as_mut()
                    .context("resident replay was not enabled")?
                    .trim()?;
            }
            "reset" => {
                snapshot = None;
                reduction = None;
                budget(scope, "resident-reset")?;
                send(serde_json::json!({"event":"reset"}))?;
                continue;
            }
            "weights" => {
                ensure!(
                    request.bank < 3 && reduction.is_none(),
                    "matrix request phase"
                );
                let result =
                    reduce_weights(&banks[request.bank], &point(&request.point, 12)?, scope)?;
                snapshot = Some(Snapshot::slice(
                    DeviceTensor::copy_to_host(result.guts())?.as_slice(),
                )?);
                reply["path"] = serde_json::to_value(snapshot.as_ref().unwrap().path())?;
                reply["elements"] = (LAYERS * WIDTH).into();
            }
            "evaluate" => {
                ensure!(
                    request.bank < 3 && reduction.is_none(),
                    "evaluation request phase"
                );
                let result = real_v4_opening::evaluate_fixed_columns(
                    &banks[request.bank],
                    &point(&request.point, 23)?,
                    scope,
                )?;
                reply["values"] =
                    serde_json::to_value(result.into_iter().map(word).collect::<Vec<_>>())?;
            }
            "begin" => {
                ensure!(
                    reduction.is_none() && (1..=3).contains(&request.components.len()),
                    "fixed sumcheck phase or width"
                );
                snapshot = None;
                let mut traces = Vec::new();
                let mut points = Vec::new();
                let mut claims = Vec::new();
                for component in request.components {
                    ensure!(
                        component.coefficients.len() == 257,
                        "fixed component bank and column geometry"
                    );
                    let bank = component.coefficients[0][0] as usize;
                    ensure!(
                        bank < 3 && component.coefficients[0][1..] == [0, 0, 0],
                        "fixed component bank encoding"
                    );
                    traces.push(real_v4_opening::fixed_bank_rlc(
                        &banks[bank],
                        &values(&component.coefficients[1..])?,
                        scope,
                    )?);
                    points.push(point(&component.point, 23)?);
                    claims.push(ext(component.claim)?);
                }
                let mut state = low_memory_sumcheck::ComponentSumcheck::new(traces, points, claims);
                reply["polynomial"] = serde_json::to_value(
                    state
                        .polynomial()
                        .coefficients
                        .into_iter()
                        .map(word)
                        .collect::<Vec<_>>(),
                )?;
                reduction = Some(state);
                current_round = 0;
            }
            "step" => {
                ensure!(
                    request.round == current_round && current_round < 23,
                    "fixed sumcheck round order"
                );
                let state = reduction
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("fixed sumcheck not started"))?;
                state.fold(ext(request
                    .alpha
                    .ok_or_else(|| anyhow::anyhow!("missing round challenge"))?)?);
                current_round += 1;
                if current_round == 23 {
                    reply["finished"] = true.into();
                    reduction = None;
                } else {
                    reply["polynomial"] = serde_json::to_value(
                        state
                            .polynomial()
                            .coefficients
                            .into_iter()
                            .map(word)
                            .collect::<Vec<_>>(),
                    )?;
                }
            }
            "combined" => {
                ensure!(
                    request.coefficients.len() == 816 && reduction.is_none(),
                    "joint RLC geometry or phase"
                );
                let coefficients = values(&request.coefficients)?;
                let mut combined: Option<Mle<Ext, TaskScope>> = None;
                for bank in 0..3 {
                    let part = real_v4_opening::fixed_bank_rlc(
                        &banks[bank],
                        &coefficients[bank * 272..bank * 272 + 256],
                        scope,
                    )?;
                    if let Some(current) = combined.as_mut() {
                        real_v4_opening::add_ext_in_place(current, part.guts(), scope)?;
                    } else {
                        combined = Some(part)
                    }
                    scope.synchronize_blocking()?;
                }
                snapshot = Some(Snapshot::slice(
                    DeviceTensor::copy_to_host(combined.as_ref().unwrap().guts())?.as_slice(),
                )?);
                reply["path"] = serde_json::to_value(snapshot.as_ref().unwrap().path())?;
                reply["elements"] = ROWS.into();
            }
            _ => anyhow::bail!("unsupported fixed service operation"),
        }
        budget(scope, "resident-fixed-operation")?;
        reply["seconds"] = began.elapsed().as_secs_f64().into();
        send(reply)?;
    }
    drop(snapshot);
    drop(reduction);
    drop(banks);
    drop(trees);
    drop(base);
    scope.synchronize_blocking()?;
    Ok(())
}

fn fixed_component(
    bank: usize,
    coefficients: Vec<Ext>,
    point: &Point<Ext>,
    claim: Ext,
) -> Component {
    let mut component = component(coefficients, point, claim);
    component.coefficients.insert(0, [bank as u32, 0, 0, 0]);
    component
}
pub(crate) fn opening_fixed_component(
    bank: usize,
    coefficients: Vec<Ext>,
    point: &Point<Ext>,
    claim: Ext,
) -> Component {
    fixed_component(bank, coefficients, point, claim)
}
fn dynamic_opening<'a>(
    dynamic: &'a JaggedTraceMle<Felt, TaskScope>,
    expected: GpuDigest,
    scope: &'a TaskScope,
) -> TrustedComponentOpeningBuilder<'a, TestGC> {
    Box::new(move |indices| {
        let operation = || -> Result<_> {
            let (_, data) =
                commit_multilinears::<TestGC, _>(dynamic, LOG_ROWS, false, false, &prover(scope))?;
            ensure!(
                data.original_commitment == expected,
                "recomputed dynamic commitment"
            );
            let pcs = &data.pcs_prover_data;
            let codeword = pcs
                .codeword_mle
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("dynamic codeword missing"))?;
            let tcs = Poseidon2SP1Field16CudaProver::new(scope);
            let values = tcs.compute_openings_at_indices(codeword, indices);
            let proof =
                tcs.prove_openings_at_indices(&pcs.merkle_tree_tcs_data, codeword, indices)?;
            budget(scope, "resident-dynamic-opening")?;
            Ok(slop_merkle_tree::MerkleTreeOpeningAndProof { values, proof })
        };
        match operation() {
            Ok(opening) => Some(opening),
            Err(error) => {
                eprintln!("dynamic opening: {error:#}");
                None
            }
        }
    })
}

fn prove(
    prepared: &PreparedProver,
    request: &Request,
    network: [u8; 32],
    scope: &TaskScope,
    captured: Option<gpu_witness::StreamCapture>,
) -> Result<serde_json::Value> {
    NEXT_ID.with(|id| id.set(0));
    let began = Instant::now();
    let frozen: FrozenProductionV4Template =
        serde_json::from_reader(File::open(&request.template)?)?;
    ensure!(
        frozen.challenge.network_id == network,
        "resident proof network"
    );
    let final_activation = read_final_activation(&request.final_path)?;
    let manifest = prepared.fixed_record.manifest_digest();
    let challenge_digest =
        forgematrix_v4_challenge_digest(&frozen.challenge, frozen.nonce, manifest);
    let final_activation_digest =
        forgematrix_v4_final_activation_digest(challenge_digest, &final_activation);
    let statement = ForgeMatrixV4TranscriptStatement {
        block: frozen.challenge,
        nonce: frozen.nonce,
        algorithm_version: FORGEMATRIX_V4_ALGORITHM_VERSION,
        proof_version: FORGEMATRIX_V4_DIRECT_PROOF_VERSION,
        proof_system_digest: forgematrix_v4_direct_proof_system_digest(),
        model_manifest_digest: manifest,
        challenge_digest,
        final_activation_digest,
        work_digest: forgematrix_v4_work_digest(
            manifest,
            challenge_digest,
            final_activation_digest,
        ),
    };
    let upload_started = Instant::now();
    let capture_stats = captured.as_ref().map(|c| c.stats.clone());
    let mut traces = if let Some(captured) = captured {
        ensure!(
            captured.capture_id == request.capture_id,
            "captured stream identity differs"
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(&forgematrix_v4_mask_coefficients(
            challenge_digest,
            u32::MAX,
        ));
        for layer in 0..384 {
            expected.extend_from_slice(&forgematrix_v4_mask_coefficients(challenge_digest, layer));
        }
        ensure!(
            hex::decode(captured.coefficients_hex)? == expected,
            "captured stream belongs to another nonce/template"
        );
        captured.traces.into_iter().map(Some).collect::<Vec<_>>()
    } else if let Some(captured) = gpu_witness::from_gpu(&request.prefix, challenge_digest, scope)?
    {
        captured.into_iter().map(Some).collect::<Vec<_>>()
    } else {
        (0..3)
            .map(|bank| trace(&request.prefix, bank, scope).map(Some))
            .collect::<Result<Vec<_>>>()?
    };
    let upload_seconds = upload_started.elapsed().as_secs_f64();
    let commit_started = Instant::now();
    let mut gpu_dynamic = Vec::new();
    let mut raw_dynamic_roots = Vec::new();
    for bank in 0..3 {
        let (_, data) = commit_multilinears::<TestGC, _>(
            traces[bank].as_ref().unwrap(),
            LOG_ROWS,
            false,
            false,
            &prover(scope),
        )?;
        gpu_dynamic.push(data.original_commitment);
        raw_dynamic_roots.push(data.pcs_prover_data.merkle_tree_tcs_data.1);
        drop(data);
        if std::env::var("CMFD_SHARED_MODEL").as_deref() == Ok("1") {
            for (index, trace) in traces.iter().enumerate() {
                gpu_witness::validate_capture(
                    trace.as_ref().unwrap(),
                    &format!("commit-{bank}-bank-{index}"),
                    scope,
                )?;
            }
        }
        budget(scope, "resident-initial-commit")?;
    }
    let gpu_dynamic: [GpuDigest; 3] = gpu_dynamic
        .try_into()
        .map_err(|_| anyhow::anyhow!("commitment count"))?;
    let cpu_dynamic: [CpuDigest; 3] = bridge(gpu_dynamic)?;
    let commit_seconds = commit_started.elapsed().as_secs_f64();
    let mut cpu = forgematrix_v4_transcript(statement);
    bind_forgematrix_v4_commitments(&mut cpu, &prepared.cpu_fixed, &cpu_dynamic);
    let mut gpu = gpu_transcript(&statement.digest());
    bind_gpu_commitments(&mut gpu, &prepared.gpu_fixed, &gpu_dynamic);
    let initial = DeviceTensor::from_host(
        &Tensor::from(build_initial_activation(
            challenge_digest,
            &prepared.base_input,
        ))
        .reshape([BATCH, WIDTH]),
        scope,
    )?;
    let mut relations = Vec::new();
    let mut claims: Vec<Vec<CpuOpeningClaim>> = Vec::new();
    let relations_started = Instant::now();
    for bank in 0..3 {
        let dynamic = traces[bank].take().unwrap();
        let boundary = if bank == 0 {
            initial.as_view()
        } else {
            gpu_last_activation_layer(traces[bank - 1].as_ref().unwrap())?
        };
        let (relation, bank_claims, previous, encoded, dynamic) = prove_bank_relations(
            bank,
            statement,
            &prepared.base_input,
            &[],
            None,
            dynamic,
            &boundary,
            &mut cpu,
            &mut gpu,
            scope,
        )?;
        ensure!(
            bank > 0 || previous.is_empty(),
            "unexpected initial boundary"
        );
        if bank > 0 {
            claims[bank - 1].extend(previous)
        }
        relations.push(relation);
        claims.push(bank_claims);
        traces[bank] = Some(dynamic);
        if std::env::var("CMFD_SHARED_MODEL").as_deref() == Ok("1") {
            for (index, trace) in traces.iter().enumerate() {
                gpu_witness::validate_capture(
                    trace.as_ref().unwrap(),
                    &format!("relations-{bank}-bank-{index}"),
                    scope,
                )?;
            }
        }
        drop(encoded);
        budget(scope, "resident-bank-relations")?;
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
            "resident final point"
        );
        claims[2].push(forgematrix_v4_final_opening_claim(
            &cpu_point,
            forgematrix_v4_activation_evaluation(
                &final_activation,
                &cpu_point.batch,
                &cpu_point.output,
            )?,
        )?);
    }
    for bank in 0..3 {
        finalize_forgematrix_v4_bank_opening_claims(&mut claims[bank])?;
    }
    let mut openings = Vec::new();
    for bank in 0..3 {
        openings.push(real_v4_opening::prove_public_bank_opening_remote(
            bank,
            &prepared.fixed_maps[bank],
            traces[bank].as_ref().unwrap(),
            prepared.gpu_fixed[bank],
            gpu_dynamic[bank],
            &claims[bank],
            &mut gpu,
            &mut cpu,
            scope,
        )?);
    }
    let relations_seconds = relations_started.elapsed().as_secs_f64();
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
    let secondary_started = Instant::now();
    let mut local_traces = Vec::new();
    let mut local_points = Vec::new();
    let mut local_claims = Vec::new();
    let mut fixed = Vec::new();
    for bank in 0..3 {
        let at = bank * 272;
        let fixed_claim = evaluations[bank * 2]
            .iter()
            .zip(&weights[at..at + 256])
            .map(|(v, w)| *v * *w)
            .sum();
        fixed.push(fixed_component(
            bank,
            weights[at..at + 256].to_vec(),
            &Point::from(points[bank].clone()),
            fixed_claim,
        ));
        let coefficients =
            DeviceTensor::from_host(&Tensor::from(weights[at + 256..at + 272].to_vec()), scope)?;
        let row = dot_along_dim_view(
            traces[bank].as_ref().unwrap().main_virtual_tensor(LOG_ROWS),
            coefficients.as_view(),
            0,
        );
        local_traces.push(Mle::new(row.reshape([1, ROWS])));
        scope.synchronize_blocking()?;
        local_points.push(Point::from(points[bank].clone()));
        local_claims.push(
            evaluations[bank * 2 + 1]
                .iter()
                .zip(&weights[at + 256..at + 272])
                .map(|(v, w)| *v * *w)
                .sum(),
        );
    }
    let sumcheck = distributed_sumcheck(
        local_traces,
        local_points,
        local_claims,
        fixed,
        &mut challenger,
        total,
    )?;
    let shared_point = sumcheck.point_and_eval.0.clone();
    let mut shared: [Vec<Ext>; 6] = std::array::from_fn(|_| Vec::new());
    for bank in 0..3 {
        shared[bank * 2] = fixed_evaluations(bank, &shared_point)?;
        shared[bank * 2 + 1] = real_v4_opening::evaluate_dynamic_columns(
            traces[bank].as_ref().unwrap().main_virtual_tensor(LOG_ROWS),
            &shared_point,
            scope,
        )?;
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
    let reduction = cmfd_direct_batched_opening_lab::ReductionProof {
        batch_witness: bridge(witness)?,
        rounds,
        evaluations_at_shared_point: bridge(shared.clone())?,
    };
    let obligation = cmfd_direct_batched_opening_lab::verify_reduction(&lab, &reduction)?;
    ensure!(
        obligation.point()
            == bridge::<_, Vec<_>>(shared_point.iter().copied().collect::<Vec<_>>())?.as_slice(),
        "secondary shared point"
    );
    ensure!(
        obligation.values() == &bridge::<_, [Vec<_>; 6]>(shared.clone())?,
        "secondary shared values"
    );
    let secondary_seconds = secondary_started.elapsed().as_secs_f64();
    let (_, last) = commit_multilinears::<TestGC, _>(
        traces[2].as_ref().unwrap(),
        LOG_ROWS,
        false,
        false,
        &prover(scope),
    )?;
    ensure!(
        last.original_commitment == gpu_dynamic[2],
        "resident final commitment"
    );
    let metadata = (0..3)
        .map(|bank| direct_opening::fixed_data(&prepared.fixed_maps[bank], scope))
        .collect::<Vec<_>>();
    let empty_dynamic = (0..2)
        .map(|bank| CudaStackedPcsProverData::<TestGC> {
            merkle_tree_tcs_data: (
                sp1_gpu_merkle_tree::MerkleTree {
                    digests: Buffer::with_capacity_in(0, scope.clone()),
                    height: 24,
                    stored_height: 0,
                },
                raw_dynamic_roots[bank],
                24,
                16,
            ),
            codeword_mle: None,
        })
        .collect::<Vec<_>>();
    let stacked: Rounds<_> = vec![
        &metadata[0],
        &empty_dynamic[0],
        &metadata[1],
        &empty_dynamic[1],
        &metadata[2],
        &last.pcs_prover_data,
    ]
    .into_iter()
    .collect();
    let traces_ref = &traces;
    let builder = Box::new(
        move |coefficients: &Tensor<Ext>, builder_scope: &TaskScope| {
            assert_eq!(coefficients.as_slice().len(), 1024);
            let reply=exchange(serde_json::json!({"op":"combined","coefficients":coefficients.as_slice()[..816].iter().copied().map(word).collect::<Vec<_>>()})).expect("fixed joint RLC");
            let mut combined = vector(reply, ROWS, builder_scope).expect("joint fixed vector");
            for bank in 0..3 {
                let at = bank * 272 + 256;
                let weights = DeviceTensor::from_host(
                    &Tensor::from(coefficients.as_slice()[at..at + 16].to_vec()),
                    builder_scope,
                )
                .unwrap();
                let part = dot_along_dim_view(
                    traces_ref[bank]
                        .as_ref()
                        .unwrap()
                        .main_virtual_tensor(LOG_ROWS),
                    weights.as_view(),
                    0,
                );
                real_v4_opening::add_ext_in_place(&mut combined, &part, builder_scope).unwrap();
                builder_scope.synchronize_blocking().unwrap();
            }
            combined
        },
    );
    let builders = vec![
        Some(prepared.fixed_maps[0].opening_builder()),
        Some(dynamic_opening(
            traces[0].as_ref().unwrap(),
            gpu_dynamic[0],
            scope,
        )),
        Some(prepared.fixed_maps[1].opening_builder()),
        Some(dynamic_opening(
            traces[1].as_ref().unwrap(),
            gpu_dynamic[1],
            scope,
        )),
        Some(prepared.fixed_maps[2].opening_builder()),
        None,
    ];
    direct_opening::tag(&mut challenger, direct_opening::PCS_DOMAIN);
    for value in shared_point.iter() {
        direct_opening::observe_ext(&mut challenger, *value)
    }
    for values in &shared {
        for value in values {
            direct_opening::observe_ext(&mut challenger, *value)
        }
    }
    let pcs_started = Instant::now();
    let basefold = prover(scope).prove_trusted_evaluations_basefold_with_component_openings(
        shared_point,
        shared.iter().flatten().copied().collect(),
        None,
        Some(builder),
        stacked,
        Some(builders),
        &mut challenger,
    )?;
    budget(scope, "resident-joint-proof")?;
    let pcs_seconds = pcs_started.elapsed().as_secs_f64();
    let reduction = bridge(reduction)?;
    let basefold = bincode::deserialize(&bincode::serialize(&basefold)?)?;
    let wire =
        cmfd_consensus::forgematrix_v4_direct::encode(&carrier, statement, &reduction, &basefold)?;
    let verify_started = Instant::now();
    cmfd_consensus::forgematrix_v4_direct::verify_wire(
        statement,
        prepared.cpu_fixed,
        &prepared.base_input,
        &wire,
    )?;
    let verify_seconds = verify_started.elapsed().as_secs_f64();
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&request.output)?
        .write_all(&wire)?;
    Ok(
        serde_json::json!({"verified":true,"wire_bytes":wire.len(),"proof_version":2,"stream_capture":capture_stats,"device_relations":std::env::var("CMFD_DEVICE_RELATIONS").as_deref()==Ok("1"),"workspace_cache_limit_bytes":if std::env::var("CMFD_SHARED_MODEL").as_deref()==Ok("1"){4u64<<30}else{0},"trace_upload_seconds":upload_seconds,"initial_commit_seconds":commit_seconds,"relations_and_openings_seconds":relations_seconds,"secondary_seconds":secondary_seconds,"joint_basefold_seconds":pcs_seconds,"full_cpu_verification_seconds":verify_seconds,"proof_seconds":began.elapsed().as_secs_f64(),"parameters":{"log_blowup":1,"queries":270,"grinding_bits":16,"commitments":6}}),
    )
}

pub(crate) fn run_dynamic(
    prepared: &PreparedProver,
    network: [u8; 32],
    scope: &TaskScope,
) -> Result<()> {
    validate_worker("dynamic")?;
    ensure!(
        network == FORGEMATRIX_V4_DIRECT_TESTNET_NETWORK_ID,
        "dynamic network"
    );
    budget(scope, "resident-dynamic-ready")?;
    let persistent = std::env::var("CMFD_SHARED_MODEL").as_deref() == Ok("1");
    if persistent {
        dynamic_workspace_cache(scope, true)?;
    }
    send(serde_json::json!({"event":"ready","role":"dynamic"}))?;
    let mut captured = None;
    loop {
        let request: Request = read()?;
        if request.op == "quit" {
            break;
        }
        if request.op == "prefetch" {
            ensure!(
                persistent
                    && std::env::var("CMFD_WITNESS_PIPELINE").as_deref() == Ok("1")
                    && captured.is_none(),
                "stream capture phase"
            );
            let result = gpu_witness::capture_stream(
                &request.prefix,
                request.provider_pid,
                &request.capture_id,
                &request.replay_coefficients,
                scope,
            )?;
            let stats = result.stats.clone();
            captured = Some(result);
            send(
                serde_json::json!({"event":"captured","capture_id":request.capture_id,"stats":stats}),
            )?;
            continue;
        }
        if request.op == "discard_capture" {
            captured = None;
            scope.synchronize_blocking()?;
            dynamic_workspace_cache(scope, false)?;
            send(serde_json::json!({"event":"discarded"}))?;
            continue;
        }
        ensure!(request.op == "prove", "dynamic proof request");
        let report = prove(prepared, &request, network, scope, captured.take())?;
        scope.synchronize_blocking()?;
        if persistent {
            dynamic_workspace_cache(scope, false)?;
        }
        send(serde_json::json!({"event":"done","report":report}))?;
        if !persistent {
            let request: Request = read()?;
            ensure!(
                request.op == "quit",
                "dynamic worker must exit before replay reload"
            );
            break;
        }
    }
    scope.synchronize_blocking()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_cache_rejects_mutable_files_wrong_provider_and_wrong_lengths() {
        let pid = std::process::id();
        let snapshot = Snapshot::bytes(b"immutable").unwrap();
        assert!(sealed_path(&snapshot.path(), pid, Some(9)).is_ok());
        assert!(sealed_path(&snapshot.path(), pid + 1, Some(9)).is_err());
        assert!(sealed_path(&snapshot.path(), pid, Some(8)).is_err());
        let path = std::env::temp_dir().join(format!("cmfd-resident-seal-test-{pid}"));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(9).unwrap();
        let descriptor = PathBuf::from(format!("/proc/{pid}/fd/{}", file.as_raw_fd()));
        assert!(sealed_path(&descriptor, pid, Some(9)).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    #[ignore = "requires a reserved GPU"]
    fn bounded_grid_differential() {
        run_sync_in_place(|scope| {
            let point = Point::from(
                (0..20)
                    .map(|i| {
                        Ext::from_base_slice(&[
                            Felt::from_canonical_usize(i + 2),
                            Felt::one(),
                            Felt::from_canonical_usize(i + 5),
                            Felt::zero(),
                        ])
                    })
                    .collect::<Vec<_>>(),
            );
            let stock: Mle<Ext, TaskScope> = DevicePoint::from_host(&point, &scope)
                .unwrap()
                .partial_lagrange()
                .into();
            let bounded = low_memory_sumcheck::bounded_equality(&point, &scope);
            assert_eq!(
                DeviceTensor::copy_to_host(stock.guts()).unwrap().as_slice(),
                DeviceTensor::copy_to_host(bounded.guts())
                    .unwrap()
                    .as_slice()
            );
            drop(stock);
            drop(bounded);
            scope.synchronize_blocking().unwrap();
            let n = (1usize << 20) + 1;
            let a = (0..n)
                .map(|i| Ext::from_canonical_usize(i % 2039 + 1))
                .collect::<Vec<_>>();
            let b = (0..n)
                .map(|i| Ext::from_canonical_usize(i % 109 + 7))
                .collect::<Vec<_>>();
            let alpha = Ext::from_base_slice(&[
                Felt::from_canonical_usize(3),
                Felt::from_canonical_usize(2),
                Felt::from_canonical_usize(5),
                Felt::from_canonical_usize(7),
            ]);
            let (stock_a, stock_b) = sp1_gpu_jagged_sumcheck::fix_last_variable(
                upload_ext(a.clone(), &scope),
                upload_ext(b.clone(), &scope),
                alpha,
                sp1_gpu_sys::kernels::mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            let (bounded_a, bounded_b) = low_memory_sumcheck::fix_last_variable(
                upload_ext(a, &scope),
                upload_ext(b, &scope),
                alpha,
                sp1_gpu_sys::kernels::mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            );
            assert_eq!(
                DeviceTensor::copy_to_host(stock_a.guts())
                    .unwrap()
                    .as_slice(),
                DeviceTensor::copy_to_host(bounded_a.guts())
                    .unwrap()
                    .as_slice()
            );
            assert_eq!(
                DeviceTensor::copy_to_host(stock_b.guts())
                    .unwrap()
                    .as_slice(),
                DeviceTensor::copy_to_host(bounded_b.guts())
                    .unwrap()
                    .as_slice()
            );
        })
        .unwrap();
    }
    #[test]
    #[ignore = "requires a reserved GPU"]
    fn resident_gpu_differentials() {
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
                let data = (0..count)
                    .map(|i| {
                        (0..256)
                            .map(|j| Ext::from_canonical_usize((i + 1) * j + 7))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let claims = data
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
                let mut stock_challenger = TestGC::default_challenger();
                let mut grouped_challenger = stock_challenger.clone();
                let (stock, _) = sp1_gpu_jagged_sumcheck::multi_hadamard_sumcheck_at_points(
                    data.iter().map(|v| upload_ext(v.clone(), &scope)).collect(),
                    &points,
                    claims.clone(),
                    &mut stock_challenger,
                    total,
                );
                let indices = (0..count).partition::<Vec<_>, _>(|index| {
                    if count == 6 {
                        index % 2 == 0
                    } else {
                        *index == 0 || *index == 8
                    }
                });
                let make = |indices: &Vec<usize>| {
                    low_memory_sumcheck::ComponentSumcheck::new(
                        indices
                            .iter()
                            .map(|i| upload_ext(data[*i].clone(), &scope))
                            .collect(),
                        indices.iter().map(|i| points[*i].clone()).collect(),
                        indices.iter().map(|i| claims[*i]).collect(),
                    )
                };
                let mut a = make(&indices.0);
                let mut b = make(&indices.1);
                let mut rounds = Vec::new();
                let mut point = Vec::new();
                let mut terminal = total;
                for _ in 0..8 {
                    let poly = low_memory_sumcheck::add_round_polynomials(
                        &a.polynomial(),
                        &b.polynomial(),
                    );
                    low_memory_sumcheck::observe_sumcheck_round(&mut grouped_challenger, &poly);
                    let alpha = grouped_challenger.sample_ext_element();
                    terminal = poly.eval_at_point(alpha);
                    point.insert(0, alpha);
                    rounds.push(poly);
                    a.fold(alpha);
                    b.fold(alpha);
                }
                let grouped = PartialSumcheckProof {
                    univariate_polys: rounds,
                    claimed_sum: total,
                    point_and_eval: (Point::from(point), terminal),
                };
                assert_eq!(
                    bincode::serialize(&stock).unwrap(),
                    bincode::serialize(&grouped).unwrap()
                );
                assert_eq!(
                    pcs_hints::State::gpu(&stock_challenger),
                    pcs_hints::State::gpu(&grouped_challenger)
                );
            }
            let pre = (0..256)
                .map(|i| {
                    Ext::from_base_slice(&[
                        Felt::from_canonical_usize(i + 3),
                        Felt::one(),
                        Felt::from_canonical_usize(i + 7),
                        Felt::zero(),
                    ])
                })
                .collect::<Vec<_>>();
            let next = pre.iter().map(|x| *x * *x * *x).collect::<Vec<_>>();
            let point = Point::from(
                (0..8)
                    .map(|i| Ext::from_canonical_usize(i + 9))
                    .collect::<Vec<_>>(),
            );
            let equality = Mle::<Ext>::partial_lagrange(&point)
                .guts()
                .as_slice()
                .to_vec();
            let mut a = TestGC::default_challenger();
            let mut b = a.clone();
            let (stock, stock_ends) = sp1_gpu_jagged_sumcheck::cubic_transition_sumcheck(
                upload_ext(pre.clone(), &scope),
                upload_ext(next.clone(), &scope),
                upload_ext(equality.clone(), &scope),
                &mut a,
                Ext::zero(),
            );
            let (streamed, ends) = low_memory_sumcheck::cubic_transition_sumcheck(
                upload_ext(pre, &scope),
                upload_ext(next, &scope),
                upload_ext(equality, &scope),
                &mut b,
                Ext::zero(),
            );
            assert_eq!(
                bincode::serialize(&stock).unwrap(),
                bincode::serialize(&streamed).unwrap()
            );
            assert_eq!(stock_ends, ends);
            assert_eq!(pcs_hints::State::gpu(&a), pcs_hints::State::gpu(&b));
        })
        .unwrap();
    }
}
