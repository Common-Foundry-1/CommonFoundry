//! Offline hardware qualification only: synthetic templates, no node, sockets,
//! wallet, chain acceptance, or public mining. The real prover CPU-checks every
//! full proof. Run only with an exclusive GPU and authenticated input files.
#[cfg(not(feature = "production-v4"))]
fn main() {
    panic!("requires production-v4");
}

#[cfg(feature = "production-v4")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cmfd_node::pool::{PoolJob, ProductionV4PoolShareVerifier};
    use cmfd_node::production_v4_pool::{
        ProductionV4PersistentPoolVerifier, ProductionV4PoolVerifierConfig,
        ProductionV4PoolWorkerCommand,
    };
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 {
        return Err("usage: qualify_pool_idle_gpu INPUTS REPLAY PROOF NEW_OUTPUT".into());
    }
    let inputs = PathBuf::from(&args[1]);
    let scratch = PathBuf::from(&args[4]);
    if scratch.exists() || !scratch.is_absolute() {
        return Err("output must be a new absolute path".into());
    }
    let model = inputs.join("MODEL-V2.bank");
    let fixed = inputs.join("fixed");
    let network = cmfd_node::network_profile::PRODUCTION_V4_TESTNET_PROFILE.network_id;
    let verifier = Arc::new(ProductionV4PersistentPoolVerifier::start_for_network(
        network,
        ProductionV4PoolVerifierConfig {
            replay: ProductionV4PoolWorkerCommand {
                program: PathBuf::from(&args[2]),
                arguments: vec!["--server".into(), model.clone().into_os_string()],
                environment: vec![],
            },
            proof: ProductionV4PoolWorkerCommand {
                program: PathBuf::from(&args[3]),
                arguments: vec![
                    "--server".into(),
                    hex::encode(network).into(),
                    model.into_os_string(),
                    fixed.into_os_string(),
                ],
                environment: vec![],
            },
            scratch_directory: scratch.clone(),
            worker_scratch_directory: scratch.to_str().ok_or("invalid output path")?.into(),
        },
    )?);
    let template = cmfd_node::BlockTemplate {
        challenge: cmfd_consensus::BlockChallenge {
            network_id: network,
            previous_block: [7; 32],
            transaction_root: [8; 32],
            height: 1,
            timestamp: 1,
            target: [255; 32],
        },
        coinbase: cmfd_consensus::Coinbase {
            height: 1,
            outputs: vec![],
        },
        transactions: vec![],
        total_fees_burned: 0,
    };
    let job = PoolJob {
        job_id: [1; 32],
        challenge: template.challenge,
        share_target: [255; 32],
    };
    let stop = Arc::new(AtomicBool::new(false));
    let searched = Arc::new(AtomicUsize::new(0));
    let yielded = Arc::new(AtomicUsize::new(0));
    let worker = Arc::clone(&verifier);
    let cancel = Arc::clone(&stop);
    let progress = Arc::clone(&searched);
    let pauses = Arc::clone(&yielded);
    let task = std::thread::spawn(move || -> Result<(), String> {
        let mut nonce = 1000;
        while !cancel.load(Ordering::Acquire) {
            let result = match worker.idle_search(&job, nonce, &cancel) {
                Ok(result) => result,
                Err(_) if cancel.load(Ordering::Acquire) => return Ok(()),
                Err(error) => return Err(error.to_string()),
            };
            match result {
                Some(result) => {
                    nonce = match result {
                        cmfd_node::pool::PoolWorkSearchResult::Found { next_nonce, .. }
                        | cmfd_node::pool::PoolWorkSearchResult::Exhausted { next_nonce, .. }
                        | cmfd_node::pool::PoolWorkSearchResult::Cancelled { next_nonce, .. } => {
                            next_nonce
                        }
                    };
                    progress.fetch_add(1, Ordering::SeqCst);
                }
                None => {
                    pauses.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        Ok(())
    });
    let test = (|| -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while searched.load(Ordering::SeqCst) == 0 {
            if Instant::now() >= deadline || task.is_finished() {
                return Err("idle GPU search did not start".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for cycle in 0..3 {
            let before_pause = yielded.load(Ordering::SeqCst);
            let started = Instant::now();
            let proof = verifier
                .evaluate(&template, cycle, [255; 32])?
                .chain_proof
                .ok_or("missing full proof")?;
            let cmfd_consensus::BlockProof::V4Candidate(proof) = proof else {
                return Err("wrong proof profile".into());
            };
            if yielded.load(Ordering::SeqCst) <= before_pause {
                return Err("search did not yield for proof".into());
            }
            let before_resume = searched.load(Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(60);
            while searched.load(Ordering::SeqCst) <= before_resume {
                if Instant::now() >= deadline || task.is_finished() {
                    return Err("search did not resume after proof".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            println!(
                "GPU_HANDOFF_CYCLE {}",
                serde_json::json!({"cycle":cycle,"proof_bytes":proof.transparent_proof.len(),
                "seconds":started.elapsed().as_secs_f64(),"paused":true,"resumed":true,"chain_admission_tested":false})
            );
        }
        Ok(())
    })();
    stop.store(true, Ordering::Release);
    let worker_result = task.join().map_err(|_| "search thread panicked")?;
    test?;
    worker_result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    println!("GPU_HANDOFF_COMPLETE");
    Ok(())
}
