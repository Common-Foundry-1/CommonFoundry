//! Opt-in rehearsal rooted in a synthetic TRUSTED LOCAL pruned checkpoint.
//! The checkpoint is not authenticated mainnet history. Blocks above it use
//! the actual H=67535 mainnet rules and complete GPU proofs. No height override
//! or bootstrap command is compiled into a distributed node/wallet binary.
use super::{PoolJob, PoolWorkSearchResult, ProductionV4PoolShareVerifier};
use crate::production_v4_pool::{
    ProductionV4PersistentPoolVerifier, ProductionV4PoolVerifierConfig,
    ProductionV4PoolWorkerCommand,
};
use crate::{Node, ProductionV4VerifierArtifacts, mainnet_runtime, pruning, work_gate};
use cmfd_consensus::compact_mainnet_fork::*;
use cmfd_consensus::{
    BLOCK_VERSION, Block, BlockChallenge, BlockProof, COIN, ChainState, Coinbase,
    ForgeMatrixV4CandidateProof, ForgeMatrixV4WorkRule, HeaderWork, MEDIAN_TIME_WINDOW, OutputLock,
    PowParameters, SuccessorHeaderPreflight, TxOutput, next_work_target,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use std::{
    process::{Child, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const SEED_HEIGHT: u64 = COMPACT_MAINNET_ACTIVATION_HEIGHT - 2;
const PASSWORD: &[u8] = b"disposable-isolated-fork-rehearsal-password";
const SEED_VALUE: u64 = 1000 * COIN;

#[derive(Clone, Serialize, Deserialize)]
struct Config {
    root: PathBuf,
    bank: PathBuf,
    fixed: PathBuf,
    plan: PathBuf,
    beacon: PathBuf,
    replay_worker: PathBuf,
    proof_router: PathBuf,
    gpu: String,
    #[serde(default)]
    miner: PathBuf,
}

fn config() -> Config {
    assert_eq!(
        std::env::var("CMFD_RUN_COMPACT_FORK_REHEARSAL").as_deref(),
        Ok("1")
    );
    // A separate network namespace is mandatory even for bootstrap. The test
    // cannot announce its synthetic mainnet-looking history outside loopback.
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap(),
        fs::read_link("/proc/1/ns/net").unwrap()
    );
    let links = Command::new("ip")
        .args(["-j", "link", "show"])
        .output()
        .unwrap();
    assert!(links.status.success());
    let links: serde_json::Value = serde_json::from_slice(&links.stdout).unwrap();
    assert_eq!(links.as_array().unwrap().len(), 1);
    assert_eq!(links[0]["ifname"], "lo");
    let path = PathBuf::from(
        std::env::var_os("CMFD_COMPACT_FORK_REHEARSAL_CONFIG").expect("explicit config"),
    );
    let c: Config = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert!(c.root.is_absolute());
    assert!(
        c.root
            .to_string_lossy()
            .starts_with("/mnt/c/Source/_ops/cmfd-fork-rehearsal-wallet-20261112/run-")
    );
    c
}

fn launch(c: &Config) -> mainnet_runtime::AuthenticatedMainnetRuntime {
    let p: serde_json::Value = serde_json::from_slice(&fs::read(&c.plan).unwrap()).unwrap();
    let digest: [u8; 32] = hex::decode(p["launch_plan_digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    mainnet_runtime::AuthenticatedMainnetRuntime::authenticate(
        &fs::read(&c.plan).unwrap(),
        &fs::read(&c.beacon).unwrap(),
        digest,
        crate::unix_time_seconds().unwrap(),
    )
    .unwrap()
}

fn hash(domain: &str, bytes: &[u8]) -> [u8; 32] {
    blake3::derive_key(domain, bytes)
}
fn median(raw: &[u64]) -> u64 {
    let mut v = raw[raw.len().saturating_sub(MEDIAN_TIME_WINDOW)..].to_vec();
    v.sort_unstable();
    v[v.len() / 2]
}
fn checkpoint_id(height: u64) -> [u8; 32] {
    hash(
        "CMFD/ISOLATED/FORK-REHEARSAL/TRUSTED-HEADER/V1",
        &height.to_le_bytes(),
    )
}
fn work_rule() -> ForgeMatrixV4WorkRule {
    ForgeMatrixV4WorkRule::with_pinned_heights(SEED_HEIGHT, checkpoint_id(SEED_HEIGHT), [])
        .unwrap()
        .with_recomputation_end_for_test(COMPACT_MAINNET_ACTIVATION_HEIGHT)
}
fn open(c: &Config, data: &Path) -> Node {
    work_gate::OPEN_WITH_WORK_RULE.with(|v| *v.borrow_mut() = Some(work_rule()));
    let n = Node::open_with_authenticated_mainnet(
        data,
        &launch(c),
        &ProductionV4VerifierArtifacts {
            bank: c.bank.clone(),
            fixed_record: c.fixed.clone(),
        },
        Some(PASSWORD),
    );
    work_gate::OPEN_WITH_WORK_RULE.with(|v| *v.borrow_mut() = None);
    n.unwrap()
}

fn seed(c: &Config) -> serde_json::Value {
    assert!(!c.root.exists(), "refusing existing rehearsal root");
    fs::create_dir(&c.root).unwrap();
    fs::write(c.root.join("SYNTHETIC-TRUSTED-CHECKPOINT-NOT-MAINNET.txt"),b"Disposable synthetic trusted checkpoint. No authentic historical PoW is claimed. Never copy this data into an operator node.\n").unwrap();
    let data = c.root.join("seed");
    let n = open(c, &data);
    let params = n.params;
    let verifier = n.verifier.clone();
    let owner = n.wallet_destination();
    drop(n);
    let key_before = hex::encode(Sha256::digest(fs::read(data.join("wallet.key")).unwrap()));
    let PowParameters::V4Candidate(v4) = params.pow else {
        panic!("mainnet V4 required")
    };
    let now = crate::unix_time_seconds().unwrap();
    let mut history = vec![HeaderWork {
        timestamp: params.genesis_timestamp,
        target: params.initial_work_target(),
    }];
    let mut raw = vec![params.genesis_timestamp];
    let mut parent = params.genesis_hash;
    let mut previous_digest = [0; 32];
    let mut log = File::create(data.join("blocks.log")).unwrap();
    let mut last_successor = None;
    for height in 1..=SEED_HEIGHT {
        let timestamp = if height < SEED_HEIGHT - 12_360 {
            raw.last().unwrap() + 1
        } else if height < SEED_HEIGHT - 360 {
            raw.last().unwrap() + 180
        } else {
            now - (SEED_HEIGHT - height + 1) * 60
        };
        assert!(timestamp > *raw.last().unwrap());
        let target = next_work_target(&history, params.pow_limit).unwrap();
        raw.push(timestamp);
        let effective = median(&raw);
        history.push(HeaderWork {
            timestamp: effective,
            target,
        });
        let id = checkpoint_id(height);
        let coinbase = Coinbase {
            height,
            // The trusted checkpoint's synthetic funding must also exist in
            // retained history, so wallet attribution can trace its spends.
            outputs: if height == 1 {
                vec![TxOutput {
                    value: SEED_VALUE,
                    lock: OutputLock::Key(owner),
                    spendable_height: 0,
                }]
            } else {
                vec![]
            },
        };
        let transaction_root =
            cmfd_consensus::merkle_root(&[coinbase.commitment(params.network_id)]);
        let block = Block {
            version: BLOCK_VERSION,
            challenge: BlockChallenge {
                network_id: params.network_id,
                previous_block: parent,
                transaction_root,
                height,
                timestamp,
                target,
            },
            coinbase,
            transactions: vec![],
            proof: BlockProof::V4Candidate(Box::new(ForgeMatrixV4CandidateProof {
                algorithm_version: 4,
                proof_version: 1,
                nonce: 0,
                proof_system_digest: v4.proof_system_digest_at_height(height),
                model_manifest_digest: v4.model_manifest_digest(),
                challenge_digest: [0; 32],
                final_activation_digest: [0; 32],
                work_digest: [0; 32],
                transparent_proof: vec![],
            })),
        };
        let mut bytes = [0; SuccessorHeaderPreflight::LOCAL_SNAPSHOT_BYTES];
        bytes[..32].copy_from_slice(&COMPACT_MAINNET_PREDECESSOR_FINGERPRINT);
        bytes[32..64].copy_from_slice(&id);
        bytes[64..72].copy_from_slice(&(height + 1).to_le_bytes());
        bytes[72..80].copy_from_slice(&effective.to_le_bytes());
        bytes[80..].copy_from_slice(&next_work_target(&history, params.pow_limit).unwrap());
        let successor = SuccessorHeaderPreflight::decode_local_snapshot(&bytes, params).unwrap();
        let mut body = pruning::encode_pruned_body(&block, id, successor, 12_025_864).unwrap();
        body[42..74].copy_from_slice(&COMPACT_MAINNET_PREDECESSOR_FINGERPRINT);
        let record = crate::encode_record_pruned(now, &body, previous_digest).unwrap();
        previous_digest = crate::complete_record_digest(&record);
        log.write_all(&record).unwrap();
        parent = id;
        last_successor = Some(successor);
    }
    log.sync_all().unwrap();
    drop(log);
    assert_eq!(
        next_work_target(&history, params.pow_limit).unwrap(),
        params.pow_limit,
        "rehearsal target must recover to the real mainnet limit"
    );
    let count = SEED_HEIGHT + 1;
    let mut state = Vec::new();
    state.extend_from_slice(b"CMFDCSN\0");
    state.extend_from_slice(&1u32.to_le_bytes());
    state.extend_from_slice(&COMPACT_MAINNET_PREDECESSOR_FINGERPRINT);
    state.extend_from_slice(&parent);
    state.extend_from_slice(&count.to_le_bytes());
    for n in [count, count, 1, 0, 0] {
        state.extend_from_slice(&n.to_le_bytes());
    }
    for h in &history {
        state.extend_from_slice(&h.timestamp.to_le_bytes());
        state.extend_from_slice(&h.target);
    }
    for ts in &raw {
        state.extend_from_slice(&ts.to_le_bytes());
    }
    let funding = cmfd_consensus::coinbase_outpoint_id(params.network_id, checkpoint_id(1));
    state.extend_from_slice(&funding);
    state.extend_from_slice(&0u32.to_le_bytes());
    state.extend_from_slice(&SEED_VALUE.to_le_bytes());
    state.push(0);
    state.extend_from_slice(&owner);
    state.extend_from_slice(&0u64.to_le_bytes());
    state.extend_from_slice(&hash(
        "CMFD/CHAIN-STATE-SNAPSHOT/LOCAL-INTEGRITY/V1",
        &state,
    ));
    let state = ChainState::decode_local_snapshot(&state, params, verifier).unwrap();
    let path = pruning::anchor_path(&data, SEED_HEIGHT);
    pruning::write_state_file(
        &path,
        COMPACT_MAINNET_PREDECESSOR_FINGERPRINT,
        parent,
        SEED_HEIGHT,
        last_successor.unwrap(),
        &state,
    )
    .unwrap();
    // Preserve the complete predecessor encoding in both nested snapshots.
    let mut bytes = fs::read(&path).unwrap();
    bytes[84..116].copy_from_slice(&COMPACT_MAINNET_PREDECESSOR_FINGERPRINT);
    let at = 204;
    bytes[at + 12..at + 44].copy_from_slice(&COMPACT_MAINNET_PREDECESSOR_FINGERPRINT);
    let end = bytes.len() - 32;
    let inner_end = end - 32;
    let d = hash(
        "CMFD/CHAIN-STATE-SNAPSHOT/LOCAL-INTEGRITY/V1",
        &bytes[at..inner_end],
    );
    bytes[inner_end..end].copy_from_slice(&d);
    let d = hash("CMFD/NODE/PRUNE-STATE/LOCAL-INTEGRITY/V1", &bytes[..end]);
    bytes[end..].copy_from_slice(&d);
    fs::write(path, bytes).unwrap();
    let metadata = data.join("network.meta");
    let mut bytes = fs::read(&metadata).unwrap();
    bytes[8..40].copy_from_slice(&COMPACT_MAINNET_PREDECESSOR_FINGERPRINT);
    fs::write(metadata, bytes).unwrap();
    copy_tree(&data, &c.root.join("pre-upgrade-backup"));
    let mut n = open(c, &data);
    assert_eq!(n.state.next_height(), COMPACT_MAINNET_ACTIVATION_HEIGHT - 1);
    assert_eq!(n.state.tip(), parent);
    assert_eq!(n.prune_height(), Some(SEED_HEIGHT));
    let key_after = hex::encode(Sha256::digest(fs::read(data.join("wallet.key")).unwrap()));
    assert_eq!(key_before, key_after);
    assert!(data.join("network.meta.pre-compact-67535").is_file());
    assert_eq!(
        n.wallet_snapshot().unwrap().balances.spendable_atoms,
        SEED_VALUE.to_string()
    );
    let out = serde_json::json!({"scope":"synthetic trusted local checkpoint; historical PoW not claimed","activation_height":COMPACT_MAINNET_ACTIVATION_HEIGHT,"seed_height":SEED_HEIGHT,"seed_tip":hex::encode(parent),"wallet_key_preserved":true,"predecessor_metadata_and_prune_anchor_upgraded":true,"consensus_fingerprint":hex::encode(n.params.fingerprint().unwrap()),"network_namespace_isolated":true});
    fs::write(
        c.root.join("BOOTSTRAP-RESULT.json"),
        serde_json::to_vec_pretty(&out).unwrap(),
    )
    .unwrap();
    out
}

#[test]
#[ignore = "requires explicit isolated network namespace, authenticated inputs and create-new rehearsal root"]
fn isolated_checkpoint_bootstrap() {
    let c = config();
    println!("{}", seed(&c));
}

fn copy_tree(from: &Path, to: &Path) {
    assert!(!to.exists());
    fs::create_dir(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        assert!(!ty.is_symlink());
        let dest = to.join(entry.file_name());
        if ty.is_dir() {
            copy_tree(&entry.path(), &dest)
        } else {
            assert!(ty.is_file());
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}
fn atomic_json(path: &Path, value: &serde_json::Value) {
    let temp = path.with_extension("tmp");
    fs::write(&temp, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    fs::rename(temp, path).unwrap();
}
fn status(shared: &Arc<Mutex<Node>>, data: &Path) -> serde_json::Value {
    let n = shared.lock().unwrap();
    serde_json::json!({"height":n.state.next_height()-1,"tip":hex::encode(n.state.tip()),"fingerprint":hex::encode(n.params.fingerprint().unwrap()),"wire_fingerprint":hex::encode(n.peer_hello().consensus_fingerprint),"validated_height":n.work_validated_height(),"prune_height":n.prune_height(),"wallet_key_sha256":hex::encode(Sha256::digest(fs::read(data.join("wallet.key")).unwrap()))})
}
fn worker(c: &Config, role: &str) -> ProductionV4PersistentPoolVerifier {
    let env = vec![
        ("CUDA_VISIBLE_DEVICES".into(), c.gpu.clone().into()),
        ("HOME".into(), "/root".into()),
        (
            "LD_LIBRARY_PATH".into(),
            c.proof_router
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("lib")
                .into_os_string(),
        ),
        ("RAYON_NUM_THREADS".into(), "2".into()),
    ];
    let scratch = c.root.join(format!("worker-{role}"));
    let mut w = ProductionV4PersistentPoolVerifier::start_for_network(
        COMPACT_MAINNET_NETWORK_ID,
        ProductionV4PoolVerifierConfig {
            replay: ProductionV4PoolWorkerCommand {
                program: c.replay_worker.clone(),
                arguments: vec!["--server".into(), c.bank.clone().into_os_string()],
                environment: env.clone(),
            },
            extra_replays: vec![],
            proof: ProductionV4PoolWorkerCommand {
                program: c.proof_router.clone(),
                arguments: vec![
                    "--server".into(),
                    hex::encode(COMPACT_MAINNET_NETWORK_ID).into(),
                    c.bank.clone().into_os_string(),
                    c.fixed.parent().unwrap().as_os_str().to_owned(),
                ],
                environment: env,
            },
            scratch_directory: scratch.clone(),
            worker_scratch_directory: scratch.to_string_lossy().into_owned(),
            work_check_pin: None,
        },
    )
    .unwrap();
    w.enable_serial_gpu().unwrap();
    w
}

#[test]
#[ignore = "child process of isolated full-size fork rehearsal only"]
fn isolated_node_process() {
    let c = config();
    let role = std::env::var("CMFD_REHEARSAL_ROLE").unwrap();
    assert!(["a", "b", "c", "reference", "rollback"].contains(&role.as_str()));
    let data = c.root.join(format!("node-{role}"));
    let control = c.root.join(format!("control-{role}"));
    assert!(data.is_dir());
    fs::create_dir_all(&control).unwrap();
    let mut n = open(&c, &data);
    let (checker, _) = n
        .install_work_engines(
            2,
            crate::honest_work::WorkThreadPriority::BelowNormal,
            crate::work_gate::WorkBankMode::Streamed,
            None,
        )
        .unwrap()
        .unwrap();
    let kat = checker.run_known_answer_tests();
    assert_eq!(kat.cpu, Some(crate::honest_work::WorkEngineHealth::Ready));
    let shared = Arc::new(Mutex::new(n));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p2p_address = listener.local_addr().unwrap();
    let p2p = crate::p2p::spawn_inbound_listener_with_policy(
        Arc::clone(&shared),
        listener,
        crate::peer::PeerLimits::default(),
        crate::peer::PeerAddressPolicy::PrivateOnly,
    )
    .unwrap();
    let rpc = crate::spawn_rpc_server(Arc::clone(&shared), "127.0.0.1:0".parse().unwrap()).unwrap();
    atomic_json(
        &control.join("ready.json"),
        &serde_json::json!({"p2p":p2p_address.to_string(),"rpc":rpc.local_addr().to_string(),"status":status(&shared,&data)}),
    );
    let mut last = 0u64;
    let mut gpu_worker = None;
    let mut pool: Option<super::PoolServerHandle> = None;
    let mut follow: Option<(Arc<AtomicBool>, thread::JoinHandle<()>)> = None;
    let began = Instant::now();
    loop {
        assert!(began.elapsed() < Duration::from_secs(3300));
        let request = control.join("request.json");
        if !request.exists() {
            thread::sleep(Duration::from_millis(25));
            continue;
        }
        // drvfs replacement can transiently report ENOENT between the
        // controller's rename and this open. This is control-channel I/O,
        // never a reason to terminate a node that is processing a block.
        let bytes = match fs::read(&request) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => panic!("read isolated command: {e}"),
        };
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let id = value["id"].as_u64().unwrap();
        if id <= last {
            thread::sleep(Duration::from_millis(25));
            continue;
        }
        last = id;
        let op = value["op"].as_str().unwrap();
        let reply = match op {
            "status" => status(&shared, &data),
            "mine" => {
                if gpu_worker.is_none() {
                    gpu_worker = Some(worker(&c, &role))
                }
                let job = {
                    let n = shared.lock().unwrap();
                    n.build_mining_job(n.wallet_destination(), crate::unix_time_seconds().unwrap())
                        .unwrap()
                };
                let pool_job = PoolJob {
                    job_id: hash(
                        "CMFD/ISOLATED/REHEARSAL/JOB/V1",
                        &job.challenge().height.to_le_bytes(),
                    ),
                    challenge: *job.challenge(),
                    share_target: job.challenge().target,
                };
                let stop = AtomicBool::new(false);
                let mut nonce = 0;
                let mut attempts = 0;
                let started = Instant::now();
                let winning = loop {
                    assert!(started.elapsed() < Duration::from_secs(600));
                    match gpu_worker
                        .as_ref()
                        .unwrap()
                        .search(&pool_job, nonce, &stop)
                        .unwrap()
                    {
                        PoolWorkSearchResult::Found { nonce, .. } => break nonce,
                        PoolWorkSearchResult::Exhausted {
                            next_nonce,
                            attempts_completed,
                        } => {
                            nonce = next_nonce;
                            attempts += attempts_completed
                        }
                        _ => panic!("cancelled"),
                    }
                };
                let evaluation = gpu_worker
                    .as_ref()
                    .unwrap()
                    .evaluate(&job.template, winning, job.challenge().target)
                    .unwrap();
                let proof = evaluation.chain_proof.unwrap();
                let block = *job.build_block_if_chain_valid(&proof).unwrap().unwrap();
                let height = block.challenge.height;
                let block_id = block.block_id();
                let BlockProof::V4Candidate(p) = &block.proof else {
                    unreachable!()
                };
                let proof_version = p.proof_version;
                let proof_bytes = p.transparent_proof.len();
                let blocks = c.root.join("blocks");
                fs::create_dir_all(&blocks).unwrap();
                let file = blocks.join(format!("{role}-{height}-{}.bin", hex::encode(block_id)));
                fs::write(&file, cmfd_consensus::encode_block(&block).unwrap()).unwrap();
                crate::submit_shared_block(&shared, block, crate::unix_time_seconds().unwrap())
                    .unwrap();
                serde_json::json!({"height":height,"tip":hex::encode(block_id),"proof_version":proof_version,"proof_bytes":proof_bytes,"file":file,"search_attempts_before_winner_batch":attempts,"seconds":started.elapsed().as_secs_f64(),"status":status(&shared,&data)})
            }
            "release_gpu" => {
                gpu_worker = None;
                serde_json::json!({"released":true})
            }
            "sync" => {
                let addr: std::net::SocketAddr = value["peer"].as_str().unwrap().parse().unwrap();
                assert!(addr.ip().is_loopback());
                let r = crate::p2p::sync_from_peer_once_with_policy(
                    Arc::clone(&shared),
                    addr,
                    crate::peer::PeerLimits::default(),
                    crate::peer::PeerAddressPolicy::PrivateOnly,
                );
                serde_json::json!({"result":format!("{r:?}"),"status":status(&shared,&data)})
            }
            "follow" => {
                assert!(follow.is_none());
                let addr: std::net::SocketAddr = value["peer"].as_str().unwrap().parse().unwrap();
                assert!(addr.ip().is_loopback());
                let flag = Arc::new(AtomicBool::new(false));
                let done = Arc::clone(&flag);
                let n = Arc::clone(&shared);
                let log = control.join("follow.jsonl");
                let handle = thread::spawn(move || {
                    let mut out = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(log)
                        .unwrap();
                    while !done.load(Ordering::Acquire) {
                        let r = crate::p2p::sync_from_peer_once_with_policy(
                            Arc::clone(&n),
                            addr,
                            crate::peer::PeerLimits::default(),
                            crate::peer::PeerAddressPolicy::PrivateOnly,
                        );
                        writeln!(out, "{}", serde_json::json!({"result":format!("{r:?}")}))
                            .unwrap();
                        thread::sleep(Duration::from_millis(250));
                    }
                });
                follow = Some((flag, handle));
                serde_json::json!({"following":addr.to_string()})
            }
            "state_hash" => {
                let mut n = shared.lock().unwrap();
                serde_json::json!({"state_sha256":hex::encode(Sha256::digest(n.state.encode_local_snapshot().unwrap())),"wallet":n.wallet_snapshot().unwrap(),"status":status_unlocked(&n)})
            }
            "save_candidate" => {
                let n = shared.lock().unwrap();
                let h = n.state.next_height() - 1;
                pruning::write_state_file(
                    &pruning::candidate_path(&data, h),
                    n.params.fingerprint().unwrap(),
                    n.state.tip(),
                    h,
                    n.state.successor_header_preflight().unwrap(),
                    &n.state,
                )
                .unwrap();
                serde_json::json!({"height":h,"saved":true})
            }
            "start_pool" => {
                assert!(pool.is_none());
                gpu_worker = None;
                let payee: k256::schnorr::SigningKey =
                    k256::schnorr::SigningKey::from_slice(&[0x31; 32]).unwrap();
                let payee: [u8; 32] = payee.verifying_key().to_bytes().into();
                let old = c.root.join("legacy-pool-ledger");
                let current = c.root.join("pool-ledger");
                let mut rebind = serde_json::Value::Null;
                if !current.exists() {
                    let generation = {
                        let ledger = super::DurableLedger::open(
                            Some(old.clone()),
                            COMPACT_MAINNET_NETWORK_ID,
                            COMPACT_MAINNET_PREDECESSOR_FINGERPRINT,
                        )
                        .unwrap();
                        super::register_session(
                            &ledger,
                            1,
                            "synthetic-pre-fork-credit".to_owned(),
                            payee,
                        )
                        .unwrap();
                        super::credit_accepted_share(&ledger, 1, 2 * COIN).unwrap();
                        let guard = ledger.state.lock().unwrap();
                        guard.generation
                    };
                    rebind = serde_json::to_value(
                        super::rebind_pool_ledger_fingerprint(
                            &old,
                            &current,
                            COMPACT_MAINNET_NETWORK_ID,
                            COMPACT_MAINNET_PREDECESSOR_FINGERPRINT,
                            shared.lock().unwrap().params.fingerprint().unwrap(),
                            generation,
                            super::DEFAULT_POOL_LEDGER_MAX_BYTES,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                }
                let cert_dir = c.root.join("pool-tls");
                fs::create_dir_all(&cert_dir).unwrap();
                let cert = cert_dir.join("certificate.der");
                let key = cert_dir.join("key.der");
                if !cert.exists() {
                    super::generate_pool_certificate(&cert, &key).unwrap();
                }
                let pin = hex::encode(Sha256::digest(fs::read(&cert).unwrap()));
                let mut cfg = super::PoolServerConfig::devnet(
                    "127.0.0.1:0".parse().unwrap(),
                    fs::read(&cert).unwrap(),
                    fs::read(&key).unwrap(),
                    shared.lock().unwrap().wallet_destination(),
                );
                cfg.share_target = shared.lock().unwrap().params.pow_limit;
                cfg.test_credit_atoms_per_share = 0;
                cfg.allow_address_only_payouts = true;
                cfg.ledger_directory = Some(current);
                cfg.payout_policy = Some(super::PoolPayoutPolicy {
                    minimum_payout_atoms: COIN,
                    fee_atoms: COIN / 10,
                });
                cfg.production_v4_share_verifier = Some(Arc::new(worker(&c, "pool")));
                let handle = super::spawn_pool_server(Arc::clone(&shared), cfg).unwrap();
                let url = format!("cmfd+tls://{}?pin={pin}", handle.local_addr());
                pool = Some(handle);
                serde_json::json!({"url":url,"payee":hex::encode(payee),"ledger_rebind":rebind,"synthetic_initial_credit_atoms":2*COIN})
            }
            "pool_snapshot" => {
                serde_json::to_value(pool.as_ref().unwrap().ledger_snapshot().unwrap()).unwrap()
            }
            "stop_pool" => {
                if let Some(p) = pool.take() {
                    p.stop().unwrap();
                }
                serde_json::json!({"stopped":true})
            }
            "prune" => {
                assert!(pool.is_none());
                pruning::REHEARSAL_INTERVAL.with(|v| v.set(Some(1)));
                shared.lock().unwrap().prune_keep_blocks = Some(2);
                let report = pruning::prune_shared_node(&shared).unwrap();
                pruning::REHEARSAL_INTERVAL.with(|v| v.set(None));
                serde_json::json!({"report":format!("{report:?}"),"rehearsal_keep_blocks":2,"production_minimum_keep_blocks":288,"status":status(&shared,&data)})
            }
            "quit" => {
                atomic_json(
                    &control.join(format!("reply-{id}.json")),
                    &serde_json::json!({"stopping":true}),
                );
                break;
            }
            _ => panic!("unknown isolated command"),
        };
        atomic_json(&control.join(format!("reply-{id}.json")), &reply);
    }
    if let Some((stop, handle)) = follow {
        stop.store(true, Ordering::Release);
        handle.join().unwrap();
    }
    drop(gpu_worker);
    if let Some(p) = pool {
        p.stop().unwrap();
    }
    p2p.stop().unwrap();
    rpc.stop().unwrap();
    drop(shared);
}
fn status_unlocked(n: &Node) -> serde_json::Value {
    serde_json::json!({"height":n.state.next_height()-1,"tip":hex::encode(n.state.tip()),"wire_fingerprint":hex::encode(n.peer_hello().consensus_fingerprint),"validated_height":n.work_validated_height()})
}

struct Driver {
    c: Config,
    children: std::collections::HashMap<String, Child>,
    sequence: u64,
    ready: std::collections::HashMap<String, serde_json::Value>,
}
impl Driver {
    fn start(&mut self, role: &str) {
        let data = self.c.root.join(format!("node-{role}"));
        if !data.exists() {
            copy_tree(&self.c.root.join("pre-upgrade-backup"), &data)
        }
        let control = self.c.root.join(format!("control-{role}"));
        fs::create_dir_all(&control).unwrap();
        for n in ["request.json", "ready.json"] {
            let p = control.join(n);
            if p.exists() {
                fs::remove_file(p).unwrap();
            }
        }
        let log = File::create(control.join("process.log")).unwrap();
        let p = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pool::compact_fork_rehearsal::isolated_node_process",
                "--ignored",
                "--nocapture",
            ])
            .env("CMFD_REHEARSAL_ROLE", role)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.children.insert(role.to_owned(), p);
        let start = Instant::now();
        while !control.join("ready.json").exists() {
            self.live(role);
            assert!(start.elapsed() < Duration::from_secs(240));
            thread::sleep(Duration::from_millis(100));
        }
        self.ready.insert(
            role.to_owned(),
            serde_json::from_slice(&fs::read(control.join("ready.json")).unwrap()).unwrap(),
        );
    }
    fn live(&mut self, role: &str) {
        assert!(
            self.children
                .get_mut(role)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none(),
            "child {role} exited; inspect its process.log"
        );
    }
    fn command(&mut self, role: &str, mut value: serde_json::Value) -> serde_json::Value {
        self.sequence += 1;
        let id = self.sequence;
        value["id"] = serde_json::json!(id);
        let control = self.c.root.join(format!("control-{role}"));
        atomic_json(&control.join("request.json"), &value);
        let reply = control.join(format!("reply-{id}.json"));
        let start = Instant::now();
        while !reply.exists() {
            self.live(role);
            assert!(
                start.elapsed() < Duration::from_secs(720),
                "command deadline"
            );
            thread::sleep(Duration::from_millis(100));
        }
        serde_json::from_slice(&fs::read(reply).unwrap()).unwrap()
    }
    fn stop(&mut self, role: &str) {
        self.command(role, serde_json::json!({"op":"quit"}));
        let mut child = self.children.remove(role).unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(start.elapsed() < Duration::from_secs(150));
            thread::sleep(Duration::from_millis(100));
        }
    }
    fn wait_tip(&mut self, role: &str, tip: &serde_json::Value) {
        let start = Instant::now();
        loop {
            let s = self.command(role, serde_json::json!({"op":"status"}));
            if s["tip"] == *tip {
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(240));
            thread::sleep(Duration::from_millis(250));
        }
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        for p in self.children.values_mut() {
            let _ = p.kill();
            let _ = p.wait();
        }
    }
}

#[test]
#[ignore = "requires loopback-only network namespace, exclusive GPU and create-new output"]
fn isolated_full_size_multi_node_fork() {
    let c = config();
    let bootstrap = seed(&c);
    let mut d = Driver {
        c: c.clone(),
        children: Default::default(),
        sequence: 0,
        ready: Default::default(),
    };
    d.start("a");
    d.start("b");
    d.start("c");
    let a_peer = d.ready["a"]["p2p"].clone();
    d.command("c", serde_json::json!({"op":"follow","peer":a_peer}));
    let mut a = Vec::new();
    for expected in [67534, 67535, 67536] {
        let b = d.command("a", serde_json::json!({"op":"mine"}));
        assert_eq!(b["height"], expected);
        assert_eq!(b["proof_version"], if expected < 67535 { 1 } else { 2 });
        d.wait_tip("c", &b["tip"]);
        a.push(b);
    }
    d.command("a", serde_json::json!({"op":"release_gpu"}));
    d.stop("a");
    d.start("a");
    assert_eq!(d.ready["a"]["status"]["tip"], a[2]["tip"]);
    let mut b = Vec::new();
    for _ in 0..4 {
        b.push(d.command("b", serde_json::json!({"op":"mine"})));
    }
    d.command("b", serde_json::json!({"op":"release_gpu"}));
    let b_peer = d.ready["b"]["p2p"].clone();
    d.command("a", serde_json::json!({"op":"sync","peer":b_peer}));
    d.wait_tip("a", &b[3]["tip"]);
    // C's old A listener was intentionally restarted: explicitly reconnect.
    d.command(
        "c",
        serde_json::json!({"op":"sync","peer":d.ready["a"]["p2p"]}),
    );
    d.wait_tip("c", &b[3]["tip"]);
    let sa = d.command("a", serde_json::json!({"op":"state_hash"}));
    let sb = d.command("b", serde_json::json!({"op":"state_hash"}));
    let sc = d.command("c", serde_json::json!({"op":"state_hash"}));
    assert_eq!(sa["state_sha256"], sb["state_sha256"]);
    assert_eq!(sa["state_sha256"], sc["state_sha256"]);
    for role in ["a", "b", "c"] {
        d.stop(role)
    }
    let report = serde_json::json!({"scope":"real mainnet-height full proof/block admission above a synthetic trusted local checkpoint","bootstrap":bootstrap,"branch_a":a,"branch_b":b,"three_node_state_hash":sa["state_sha256"],"multi_process_p2p_sync":true,"cold_restart_preserved_tip":true,"reorganization_crosses_activation":true,"activation_height":67535,"public_network_contact":false});
    fs::write(
        c.root.join("REHEARSAL-RESULT.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{report}");
}
