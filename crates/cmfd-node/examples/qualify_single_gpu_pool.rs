//! Opt-in RC pool qualification when the test miner shares the pool's GPU.
//! Drop the test search worker before submitting a chain-winning nonce so its
//! model allocation does not distort the pool's standalone memory requirement.
//! The pool still replays the nonce, builds the full proof and validates it.

#[cfg(not(feature = "production-rc"))]
fn main() {
    eprintln!("Build this qualification example with --features production-rc");
    std::process::exit(2);
}

#[cfg(feature = "production-rc")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    use cmfd_node::pool::{PoolClient, PoolClientConfig, PoolWorkSearchResult};
    use cmfd_node::production_v4_pool::{
        ProductionV4PersistentPoolSearcher, production_v4_pool_searcher_config,
    };

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        return Err(
            "usage: qualify_single_gpu_pool ADDRESS PIN PAYOUT MODEL WORKER SCRATCH".into(),
        );
    }
    let pin: [u8; 32] = hex::decode(&args[2])?
        .try_into()
        .map_err(|_| "pin must contain 32 bytes")?;
    let payout: [u8; 32] = hex::decode(&args[3])?
        .try_into()
        .map_err(|_| "payout must contain 32 bytes")?;
    let config = PoolClientConfig::compiled_network_address_only(
        args[1].parse()?,
        pin,
        "single-gpu-qualification",
        payout,
    )?;
    let mut client = PoolClient::connect(config)?;
    let mut searcher = Some(ProductionV4PersistentPoolSearcher::start(
        production_v4_pool_searcher_config(
            Path::new(&args[5]),
            Path::new(&args[4]),
            Path::new(&args[6]),
            32,
            None,
            None,
        )?,
    )?);
    let stop = AtomicBool::new(false);
    let started = Instant::now();
    let mut job_id = client.current_job().job_id;
    let mut next_nonce = client.initial_nonce_for_job(client.current_job());
    let mut attempts = 0_u64;
    while started.elapsed() < Duration::from_secs(900) {
        let job = client.current_job().clone();
        if job.job_id != job_id {
            job_id = job.job_id;
            next_nonce = client.initial_nonce_for_job(&job);
        }
        let result = searcher
            .as_ref()
            .ok_or("search worker already released")?
            .search(&job, next_nonce, &stop)?;
        let (completed, following) = match result {
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
            } => (attempts_completed, next_nonce),
        };
        attempts = attempts.saturating_add(completed);
        next_nonce = following;
        client.report_work_progress(attempts, started.elapsed().as_micros().try_into()?)?;
        if let PoolWorkSearchResult::Found {
            nonce,
            meets_chain_target,
            ..
        } = result
        {
            if meets_chain_target {
                drop(searcher.take());
                println!("TEST_SEARCH_WORKER_RELEASED nonce={nonce}");
            }
            let accepted = client.submit_share(job.job_id, nonce)?;
            println!("{}", serde_json::to_string(&accepted)?);
            if meets_chain_target {
                if accepted.accepted && accepted.block_accepted {
                    println!("RC_POOL_FULL_BLOCK_ACCEPTED");
                    return Ok(());
                }
                return Err(format!("winning submission not accepted: {}", accepted.code).into());
            }
        }
    }
    Err("no winning nonce within 900 seconds".into())
}
