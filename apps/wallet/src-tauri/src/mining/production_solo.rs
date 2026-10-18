use super::*;
use cmfd_node::pool::{PoolJob, ProductionV4PoolShareVerifier};
use cmfd_node::production_v4_pool::{
    ProductionV4PersistentPoolVerifier, production_v4_solo_config,
};
use std::path::{Path, PathBuf};

const FIXED_RECORD: &str = "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json";
/// The `production-v4` files besides the prepared `fixed/` folder.
const PACKAGED: [&str; 4] = [
    "cmfd-v4-replay",
    "real_bank0_relations",
    "MODEL-V2.bank",
    FIXED_RECORD,
];
/// A failed adoption is tried again at most this often: the mining tab asks
/// for the status every second.
const ADOPTION_RETRY: Duration = Duration::from_secs(15);

/// What to tell the user, naming the package folder PREPARE-MINING runs
/// from (the parent of `directory`, the `production-v4` folder). A mainnet
/// wallet also links the files in from the folder the user knows, when
/// hard links work between the two; `unlinkable` is a folder whose
/// prepared files could not be linked in.
fn setup(directory: &Path, unlinkable: Option<&Path>) -> String {
    let plain = |path: &Path| cmfd_node::plain_package_path(path.to_path_buf());
    let package = directory.parent().map(plain);
    let place = match (&package, unlinkable) {
        (Some(package), Some(source)) => format!(
            "from {} (the files prepared in {} cannot be linked in: OneDrive, another drive and exFAT or FAT32 drives do not allow it)",
            package.display(),
            plain(source).display()
        ),
        (Some(package), None) if cfg!(feature = "production-mainnet") => format!(
            "from {} (or from your usual package folder if it is on the same drive and outside OneDrive; the wallet links the prepared files in)",
            package.display()
        ),
        (Some(package), None) => format!("from {}", package.display()),
        (None, _) => "from the complete runtime package".to_owned(),
    };
    format!(
        "Prepare mining first: close the wallet and run PREPARE-MINING.bat (Windows) or prepare-mining.sh (Linux) {place}. Solo mining needs NVIDIA CUDA and about 61 GB of model/proof inputs plus scratch space. Windows requires WSL2 Ubuntu-22.04. Opening this tab does not download files or start mining."
    )
}

#[derive(Debug, PartialEq, Eq)]
enum Missing {
    /// A packaged file: only a complete package or PREPARE-MINING helps.
    Packaged,
    /// Only prepared `fixed/` files, which may be linked in from elsewhere.
    Fixed,
}

fn missing(directory: &Path) -> Option<Missing> {
    if PACKAGED.iter().any(|name| !directory.join(name).is_file()) {
        return Some(Missing::Packaged);
    }
    let fixed = directory.join("fixed");
    let caches_present = (0..3).all(|bank| {
        ["row-major.codeword", "tree"].iter().all(|suffix| {
            fixed
                .join(format!("FORGEMATRIX-V4-FIXED-BANK-{bank}.{suffix}"))
                .is_file()
        })
    });
    (!caches_present || !fixed.join(FIXED_RECORD).is_file()).then_some(Missing::Fixed)
}

pub(super) fn check_assets(assets: &ProductionV4PoolSearchAssets) -> Result<(), String> {
    static NEXT_ADOPTION: Mutex<Option<Instant>> = Mutex::new(None);
    /// From the last adoption, for the checks until the next one.
    static UNLINKABLE: Mutex<Option<PathBuf>> = Mutex::new(None);
    check_assets_adopting(assets, |directory| {
        let Ok(mut unlinkable) = UNLINKABLE.lock() else {
            return None;
        };
        if adoption_due(&NEXT_ADOPTION, Instant::now()) {
            *unlinkable = crate::updater::adopt_mining_inputs(directory).unlinkable;
        }
        unlinkable.clone()
    })
}

/// [`check_assets`] with the adoption step given: when only prepared
/// `fixed/` files are missing, `adopt` runs once for the `production-v4`
/// folder and the files are checked again. `adopt` returns a folder whose
/// prepared files could not be linked in, for the setup text.
fn check_assets_adopting(
    assets: &ProductionV4PoolSearchAssets,
    adopt: impl FnOnce(&Path) -> Option<PathBuf>,
) -> Result<(), String> {
    let Some(directory) = assets.model_bank.parent() else {
        return Err(setup(Path::new(""), None));
    };
    match missing(directory) {
        None => Ok(()),
        Some(Missing::Packaged) => Err(setup(directory, None)),
        Some(Missing::Fixed) => {
            let unlinkable = adopt(directory);
            match missing(directory) {
                None => Ok(()),
                Some(_) => Err(setup(directory, unlinkable.as_deref())),
            }
        }
    }
}

/// True at most once per [`ADOPTION_RETRY`]; the first call is due.
fn adoption_due(next: &Mutex<Option<Instant>>, now: Instant) -> bool {
    let Ok(mut next) = next.lock() else {
        return false;
    };
    if next.is_some_and(|next| now < next) {
        return false;
    }
    *next = Some(now + ADOPTION_RETRY);
    true
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
    solo_hold: SoloHold,
) {
    let result = run_inner(&node, &status, &stop, payout, &assets, &solo_hold);
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
    solo_hold: &SoloHold,
) -> Result<(), String> {
    check_assets(assets)?;
    if solo_hold
        .wait(node, status, stop)
        .map_err(|error| error.to_string())?
        .is_none()
    {
        return Ok(());
    }
    // Validate node readiness before allocating GPU memory or authenticating large inputs.
    let mut template = node
        .lock()
        .map_err(|_| "Node unavailable")?
        .build_template(payout, unix_time_seconds())
        .map_err(|error| error.to_string())?;
    let directory = assets
        .model_bank
        .parent()
        .ok_or_else(|| setup(Path::new(""), None))?;
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
        let Some(node_status) = solo_hold
            .wait(node, status, stop)
            .map_err(|error| error.to_string())?
        else {
            break;
        };
        if refreshed.elapsed() >= Duration::from_secs(15)
            || node_status.tip != hex::encode(template.challenge.previous_block)
        {
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
        if !still_current(node, &template, solo_hold)? {
            continue;
        }
        stage(status, "Building and CPU-verifying the winning block proof");
        let evaluation = worker
            .evaluate(&template, winner, template.challenge.target)
            .map_err(|error| error.to_string())?;
        if stop.load(Ordering::Acquire) {
            break;
        }
        if !still_current(node, &template, solo_hold)? {
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
        if let Some(accepted) = submit_solo_candidate(node, &block, stop, solo_hold)
            .map_err(|error| error.to_string())?
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

/// One status read: the template's parent is still the tip and Solo is not
/// waiting for the newest blocks to be checked.
fn still_current(
    node: &Mutex<Node>,
    template: &cmfd_node::BlockTemplate,
    solo_hold: &SoloHold,
) -> Result<bool, String> {
    let node_status = node
        .lock()
        .map_err(|_| "Node unavailable")?
        .status()
        .map_err(|error| error.to_string())?;
    Ok(
        node_status.tip == hex::encode(template.challenge.previous_block)
            && !solo_hold.waits_in(&node_status),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::sync::atomic::AtomicU32;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "cmfd-solo-assets-{}-{}-{}",
                std::process::id(),
                unix_time_seconds(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const CACHES: [&str; 6] = [
        "FORGEMATRIX-V4-FIXED-BANK-0.row-major.codeword",
        "FORGEMATRIX-V4-FIXED-BANK-0.tree",
        "FORGEMATRIX-V4-FIXED-BANK-1.row-major.codeword",
        "FORGEMATRIX-V4-FIXED-BANK-1.tree",
        "FORGEMATRIX-V4-FIXED-BANK-2.row-major.codeword",
        "FORGEMATRIX-V4-FIXED-BANK-2.tree",
    ];

    /// A package folder whose `production-v4` holds the packaged files and,
    /// with `prepared`, everything PREPARE-MINING writes into `fixed/`.
    fn package(root: &Path, prepared: bool) -> (PathBuf, ProductionV4PoolSearchAssets) {
        let package = root.join("commonfoundry-mainnet-runtime-v1.0.17");
        let inputs = package.join("production-v4");
        fs::create_dir_all(inputs.join("fixed")).unwrap();
        for name in PACKAGED {
            fs::write(inputs.join(name), name).unwrap();
        }
        if prepared {
            prepare(&inputs);
        }
        let assets = ProductionV4PoolSearchAssets {
            replay_worker: inputs.join("cmfd-v4-replay"),
            model_bank: inputs.join("MODEL-V2.bank"),
            scratch_directory: root.join("scratch"),
            wsl_distribution: None,
        };
        (package, assets)
    }

    fn prepare(inputs: &Path) {
        for name in CACHES.iter().chain([&FIXED_RECORD]) {
            fs::write(inputs.join("fixed").join(name), name).unwrap();
        }
    }

    #[test]
    fn prepared_inputs_pass_without_adopting() {
        let temp = TempDir::new();
        let (_, assets) = package(&temp.0, true);
        let calls = Cell::new(0);
        assert_eq!(
            check_assets_adopting(&assets, |_| {
                calls.set(calls.get() + 1);
                None
            }),
            Ok(())
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn missing_caches_are_adopted_once_then_checked_again() {
        let temp = TempDir::new();
        let (package, assets) = package(&temp.0, false);
        let inputs = package.join("production-v4");
        let adopted = Cell::new(0);
        assert_eq!(
            check_assets_adopting(&assets, |directory| {
                assert_eq!(directory, inputs);
                adopted.set(adopted.get() + 1);
                prepare(directory);
                None
            }),
            Ok(())
        );
        assert_eq!(adopted.get(), 1);
    }

    #[test]
    fn a_missing_fixed_record_alone_also_asks_for_adoption() {
        let temp = TempDir::new();
        let (package, assets) = package(&temp.0, true);
        let record = package.join("production-v4/fixed").join(FIXED_RECORD);
        fs::remove_file(&record).unwrap();
        let adopted = Cell::new(false);
        let result = check_assets_adopting(&assets, |_| {
            adopted.set(true);
            None
        });
        assert!(adopted.get());
        assert_eq!(result, Err(setup(&package.join("production-v4"), None)));
    }

    #[test]
    fn the_setup_text_names_the_running_folder_when_nothing_was_adopted() {
        let temp = TempDir::new();
        let (package, assets) = package(&temp.0, false);
        let message = check_assets_adopting(&assets, |_| None).unwrap_err();
        let folder = cmfd_node::plain_package_path(package).display().to_string();
        assert!(message.contains(&format!("prepare-mining.sh (Linux) from {folder}")));
        assert!(message.starts_with("Prepare mining first: close the wallet"));
        if cfg!(feature = "production-mainnet") {
            assert!(message.contains(
                "(or from your usual package folder if it is on the same drive and outside OneDrive; the wallet links the prepared files in)"
            ));
        }
    }

    #[test]
    fn the_setup_text_names_a_folder_whose_prepared_files_cannot_be_linked() {
        let temp = TempDir::new();
        let (package, assets) = package(&temp.0, false);
        let anchor = temp.0.join("OneDrive").join("CommonFoundry");
        let message = check_assets_adopting(&assets, |_| Some(anchor.clone())).unwrap_err();
        let folder = cmfd_node::plain_package_path(package).display().to_string();
        let anchor = cmfd_node::plain_package_path(anchor).display().to_string();
        assert!(message.contains(&format!(
            "prepare-mining.sh (Linux) from {folder} (the files prepared in {anchor} cannot be linked in: OneDrive, another drive and exFAT or FAT32 drives do not allow it). Solo mining needs"
        )));
        assert!(!message.contains("your usual package folder"));
    }

    #[test]
    fn a_missing_packaged_file_is_not_adopted() {
        let temp = TempDir::new();
        let (package, assets) = package(&temp.0, true);
        fs::remove_file(package.join("production-v4/real_bank0_relations")).unwrap();
        let adopted = Cell::new(false);
        assert!(
            check_assets_adopting(&assets, |_| {
                adopted.set(true);
                None
            })
            .is_err()
        );
        assert!(!adopted.get());
    }

    #[test]
    fn without_a_package_folder_the_setup_text_stays_generic() {
        let assets = ProductionV4PoolSearchAssets {
            replay_worker: PathBuf::from("cmfd-v4-replay"),
            model_bank: PathBuf::new(),
            scratch_directory: PathBuf::new(),
            wsl_distribution: None,
        };
        let message =
            check_assets_adopting(&assets, |_| panic!("nothing to adopt into")).unwrap_err();
        assert!(message.contains("from the complete runtime package."));
    }

    #[test]
    fn adoption_is_retried_at_most_every_fifteen_seconds() {
        let next = Mutex::new(None);
        let start = Instant::now();
        assert!(adoption_due(&next, start));
        assert!(!adoption_due(&next, start + Duration::from_secs(1)));
        assert!(!adoption_due(
            &next,
            start + ADOPTION_RETRY - Duration::from_millis(1)
        ));
        assert!(adoption_due(&next, start + ADOPTION_RETRY));
        assert!(!adoption_due(&next, start + ADOPTION_RETRY));
    }
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
