use super::*;
use cmfd_node::pool::{PoolJob, ProductionV4PoolShareVerifier};
use cmfd_node::production_v4_pool::{
    ProductionV4PersistentPoolVerifier, production_v4_solo_config,
};

const SETUP: &str = "Prepare mining first: close the wallet and run PREPARE-MINING.bat (Windows) or prepare-mining.sh (Linux) from the complete runtime package. Solo mining needs NVIDIA CUDA and about 61 GB of model/proof inputs plus scratch space. Windows requires WSL2 Ubuntu-22.04. Opening this tab does not download files or start mining.";

pub(super) fn check_assets(assets: &ProductionV4PoolSearchAssets) -> Result<(), String> {
    let directory = assets.model_bank.parent().ok_or(SETUP)?;
    for name in [
        "cmfd-v4-replay",
        "real_bank0_relations",
        "MODEL-V2.bank",
        "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json",
    ] {
        if !directory.join(name).is_file() {
            return Err(SETUP.to_owned());
        }
    }
    for bank in 0..3 {
        for suffix in ["row-major.codeword", "tree"] {
            if !directory
                .join("fixed")
                .join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"))
                .is_file()
            {
                return Err(SETUP.to_owned());
            }
        }
    }
    Ok(())
}

fn stage(status: &Mutex<MiningStatus>, message: &str) {
    if let Ok(mut current) = status.lock() {
        current.stage = Some(message.to_owned());
        current.engine = MiningEngine::Cuda;
    }
}

pub(super) fn run(
    node: Arc<Mutex<Node>>,
    status: Arc<Mutex<MiningStatus>>,
    stop: Arc<AtomicBool>,
    payout: [u8; 32],
    assets: ProductionV4PoolSearchAssets,
) {
    let result = run_inner(&node, &status, &stop, payout, &assets);
    if let Err(error) = result {
        fail_worker(&status, error);
    }
    if let Ok(mut current) = status.lock() {
        current.matrix_attempts_per_second = 0.0;
        current.stage = None;
        if stop.load(Ordering::Acquire) {
            current.lifecycle = MiningLifecycle::Stopped;
        }
    }
}

fn run_inner(
    node: &Arc<Mutex<Node>>,
    status: &Arc<Mutex<MiningStatus>>,
    stop: &Arc<AtomicBool>,
    payout: [u8; 32],
    assets: &ProductionV4PoolSearchAssets,
) -> Result<(), String> {
    check_assets(assets)?;
    // Validate node readiness before allocating GPU memory or authenticating large inputs.
    let mut template = node
        .lock()
        .map_err(|_| "Node unavailable")?
        .build_template(payout, unix_time_seconds())
        .map_err(|error| error.to_string())?;
    let directory = assets.model_bank.parent().ok_or(SETUP)?;
    stage(
        status,
        "Authenticating model and starting production GPU workers",
    );
    let config = production_v4_solo_config(
        &assets.replay_worker,
        &directory.join("real_bank0_relations"),
        &assets.model_bank,
        &directory.join("fixed"),
        &assets.scratch_directory.join("solo"),
        assets.wsl_distribution.as_deref(),
    )
    .map_err(|error| error.to_string())?;
    let worker =
        ProductionV4PersistentPoolVerifier::start(config).map_err(|error| error.to_string())?;
    let mut nonce = 0;
    let mut refreshed = Instant::now();
    while !stop.load(Ordering::Acquire) {
        if refreshed.elapsed() >= Duration::from_secs(15) || !current_parent(node, &template) {
            template = node
                .lock()
                .map_err(|_| "Node unavailable")?
                .build_template(payout, unix_time_seconds())
                .map_err(|error| error.to_string())?;
            nonce = 0;
            refreshed = Instant::now();
        }
        stage(status, "Searching ProductionV4 nonces on GPU");
        if let Ok(mut current) = status.lock() {
            current.lifecycle = MiningLifecycle::Running;
            current.current_height = template.challenge.height.saturating_sub(1);
        }
        let started = Instant::now();
        let result = worker
            .search(
                &PoolJob {
                    job_id: template.challenge.previous_block,
                    challenge: template.challenge,
                    share_target: template.challenge.target,
                },
                nonce,
                stop,
            )
            .map_err(|error| error.to_string())?;
        let (attempts, next) = match &result {
            PoolWorkSearchResult::Found {
                attempts_completed,
                next_nonce,
                ..
            }
            | PoolWorkSearchResult::Exhausted {
                attempts_completed,
                next_nonce,
            }
            | PoolWorkSearchResult::Cancelled {
                attempts_completed,
                next_nonce,
            } => (*attempts_completed, *next_nonce),
        };
        nonce = next;
        if let Ok(mut current) = status.lock() {
            current.session_attempts = current.session_attempts.saturating_add(attempts);
            current.matrix_attempts_per_second =
                attempts as f64 / started.elapsed().as_secs_f64().max(f64::EPSILON);
        }
        if stop.load(Ordering::Acquire) {
            break;
        }
        let PoolWorkSearchResult::Found { nonce: winner, .. } = result else {
            continue;
        };
        if !current_parent(node, &template) {
            continue;
        }
        stage(status, "Building and CPU-verifying the winning block proof");
        let evaluation = worker
            .evaluate(&template, winner, template.challenge.target)
            .map_err(|error| error.to_string())?;
        if stop.load(Ordering::Acquire) {
            break;
        }
        if !current_parent(node, &template) {
            continue;
        }
        let proof = evaluation
            .chain_proof
            .ok_or("Winning nonce did not produce a chain proof")?;
        let block = cmfd_consensus::Block {
            version: cmfd_consensus::BLOCK_VERSION,
            challenge: template.challenge,
            coinbase: template.coinbase.clone(),
            transactions: template.transactions.clone(),
            proof,
        };
        stage(status, "Submitting block to the embedded node");
        if let Some(accepted) =
            submit_solo_candidate(node, &block, stop).map_err(|error| error.to_string())?
            && let Ok(mut current) = status.lock()
        {
            current.blocks_found = current.blocks_found.saturating_add(1);
            current.current_height = accepted.accepted_height;
            current.last_block = Some(MinedBlockSummary {
                height: block.challenge.height,
                block_id: hex::encode(block.block_id()),
            });
        }
    }
    Ok(())
}

fn current_parent(node: &Mutex<Node>, template: &cmfd_node::BlockTemplate) -> bool {
    node.lock()
        .ok()
        .and_then(|node| node.status().ok())
        .is_some_and(|current| current.tip == hex::encode(template.challenge.previous_block))
}

#[cfg(all(test, feature = "production-v4-testnet"))]
mod hardware_tests {
    use super::*;

    #[test]
    #[ignore = "Requires explicit operator approval, the full mining runtime, and an idle NVIDIA GPU"]
    fn production_solo_gpu_round_trip() {
        let runtime = PathBuf::from(
            std::env::var_os("CMFD_RC5_GPU_RUNTIME").expect("CMFD_RC5_GPU_RUNTIME is required"),
        );
        assert!(runtime.is_absolute());
        let data = runtime.join(format!("qualification-node-{}", std::process::id()));
        assert!(
            !data.exists(),
            "qualification must use a fresh, isolated directory"
        );
        let artifacts = cmfd_node::ProductionV4VerifierArtifacts {
            bank: runtime.join("MODEL-V2.bank"),
            fixed_record: runtime.join("FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json"),
        };
        let node = Node::open_with_v4_artifacts(&data, &artifacts).unwrap();
        let payout = hex::encode(node.wallet_destination());
        let node = Arc::new(Mutex::new(node));
        let manager = MiningManager::new_with_production_v4_pool_search(
            node.clone(),
            ProductionV4PoolSearchAssets {
                replay_worker: runtime.join("cmfd-v4-replay"),
                model_bank: artifacts.bank,
                scratch_directory: data.join("mining-scratch"),
                wsl_distribution: cfg!(windows).then(|| "Ubuntu-22.04".to_owned()),
            },
        );
        assert!(manager.status().unwrap().production_solo_available);
        manager
            .start(MiningStartRequest {
                mode: MiningMode::Solo,
                payout,
                pool_url: None,
                worker_name: None,
            })
            .unwrap();
        let started = Instant::now();
        let mut last_stage = None;
        loop {
            let current = manager.status().unwrap();
            if current.stage != last_stage {
                eprintln!(
                    "GPU qualification {:.1}s: {:?}",
                    started.elapsed().as_secs_f64(),
                    current
                );
                last_stage = current.stage.clone();
            }
            if current.blocks_found > 0 {
                break;
            }
            if current.last_error.is_some() || started.elapsed() > Duration::from_secs(600) {
                manager.stop().unwrap();
                panic!("GPU qualification failed: {current:?}");
            }
            thread::sleep(Duration::from_millis(250));
        }
        let stopped = manager.stop().unwrap();
        assert_eq!(stopped.lifecycle, MiningLifecycle::Stopped);
        assert!(stopped.blocks_found >= 1);
        assert!(node.lock().unwrap().status().unwrap().accepted_height >= 1);
        eprintln!(
            "GPU qualification passed in {:.1}s; blocks={}, attempts={}; isolated evidence retained at {}",
            started.elapsed().as_secs_f64(),
            stopped.blocks_found,
            stopped.session_attempts,
            data.display()
        );
    }
}
