//! Produce an offline proof through the real pool replay/proof pipeline.
//! The synthetic header has no chain parent and must never be relayed.
use clap::Parser;
use cmfd_consensus::compact_mainnet_fork::{
    COMPACT_MAINNET_ACTIVATION_HEIGHT, COMPACT_MAINNET_NETWORK_ID,
};
use cmfd_consensus::{BlockChallenge, BlockProof, Coinbase};
use cmfd_node::pool::{PoolJob, PoolWorkSearchResult, ProductionV4PoolShareVerifier};
use cmfd_node::production_v4_pool::{
    ProductionV4PersistentPoolVerifier, ProductionV4PoolVerifierConfig,
    ProductionV4PoolWorkerCommand,
};
use cmfd_node::{BlockTemplate, unix_time_seconds};
use std::{ffi::OsString, path::PathBuf, sync::atomic::AtomicBool};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    bank: PathBuf,
    #[arg(long)]
    fixed_directory: PathBuf,
    #[arg(long)]
    replay_worker: PathBuf,
    #[arg(long)]
    proof_router: PathBuf,
    #[arg(long)]
    scratch: PathBuf,
    #[arg(long)]
    gpu: String,
    #[arg(long)]
    proof_gpus: Option<String>,
    /// Frozen header height, not an activation override. No node or network is opened.
    #[arg(long,default_value_t=COMPACT_MAINNET_ACTIVATION_HEIGHT)]
    height: u64,
    #[arg(long, default_value_t = 50_000)]
    max_attempts: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if !args.scratch.is_absolute() || args.scratch.exists() {
        return Err("use a new absolute fixture scratch directory".into());
    }
    std::fs::create_dir(&args.scratch)?;
    let replay_env = vec![(
        OsString::from("CUDA_VISIBLE_DEVICES"),
        OsString::from(&args.gpu),
    )];
    let mut proof_env = replay_env.clone();
    if let Some(devices) = args.proof_gpus {
        proof_env.push(("CMFD_DIRECT_MULTI_GPU_DEVICES".into(), devices.into()));
    }
    let mut verifier = ProductionV4PersistentPoolVerifier::start_for_network(
        COMPACT_MAINNET_NETWORK_ID,
        ProductionV4PoolVerifierConfig {
            replay: ProductionV4PoolWorkerCommand {
                program: args.replay_worker,
                arguments: vec!["--server".into(), args.bank.clone().into_os_string()],
                environment: replay_env,
            },
            extra_replays: Vec::new(),
            proof: ProductionV4PoolWorkerCommand {
                program: args.proof_router,
                arguments: vec![
                    "--server".into(),
                    hex::encode(COMPACT_MAINNET_NETWORK_ID).into(),
                    args.bank.into_os_string(),
                    args.fixed_directory.into_os_string(),
                ],
                environment: proof_env,
            },
            scratch_directory: args.scratch.clone(),
            worker_scratch_directory: args.scratch.to_string_lossy().into_owned(),
            work_check_pin: None,
        },
    )?;
    verifier.enable_serial_gpu()?;
    let plan: serde_json::Value =
        serde_json::from_str(include_str!("../../../packaging/mainnet/MAINNET-PLAN.json"))?;
    let target: [u8; 32] = hex::decode(
        plan["payload"]["rules"]["proof_of_work"]["pow_limit"]
            .as_str()
            .ok_or("missing pinned target")?,
    )?
    .try_into()
    .map_err(|_| "invalid pinned target")?;
    let template = BlockTemplate {
        challenge: BlockChallenge {
            network_id: COMPACT_MAINNET_NETWORK_ID,
            previous_block: [0x42; 32],
            transaction_root: [0x43; 32],
            height: args.height,
            timestamp: unix_time_seconds()?,
            target,
        },
        coinbase: Coinbase {
            height: args.height,
            outputs: Vec::new(),
        },
        transactions: Vec::new(),
        total_fees_burned: 0,
    };
    let job = PoolJob {
        job_id: [0x44; 32],
        challenge: template.challenge,
        share_target: target,
    };
    let stop = AtomicBool::new(false);
    let mut next = 0;
    let mut attempts = 0;
    while attempts < args.max_attempts {
        match verifier.search(&job, next, &stop)? {
            PoolWorkSearchResult::Found {
                nonce,
                attempts_completed,
                ..
            } => {
                attempts += attempts_completed;
                let evaluated = verifier.evaluate(&template, nonce, target)?;
                let Some(BlockProof::V4Candidate(proof)) = evaluated.chain_proof else {
                    return Err("winning replay did not produce its proof".into());
                };
                let frozen = serde_json::json!({"format_version":1,"challenge":template.challenge,"coinbase":template.coinbase,"transactions":template.transactions,"nonce":nonce});
                let template_path = args.scratch.join("template.json");
                let proof_path = args.scratch.join("proof.bin");
                std::fs::write(&template_path, serde_json::to_vec_pretty(&frozen)?)?;
                std::fs::write(&proof_path, &proof.transparent_proof)?;
                println!(
                    "{}",
                    serde_json::json!({"scope":"offline pool-proof fixture, not a chain-admitted block","height":args.height,"nonce":nonce,"attempts":attempts,"proof_version":proof.proof_version,"proof_system_digest":hex::encode(proof.proof_system_digest),"work_digest":hex::encode(proof.work_digest),"packet_bytes":proof.transparent_proof.len(),"template":template_path,"proof":proof_path})
                );
                return Ok(());
            }
            PoolWorkSearchResult::Exhausted {
                next_nonce,
                attempts_completed,
            } => {
                next = next_nonce;
                attempts += attempts_completed;
            }
            PoolWorkSearchResult::Cancelled { .. } => return Err("fixture search cancelled".into()),
        }
    }
    Err("no winning nonce within the bounded fixture search".into())
}
