use std::fs;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
#[cfg(all(feature = "production-rc", target_os = "windows"))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(all(feature = "production-rc", target_os = "windows"))]
use std::{io, os::windows::process::CommandExt};

use cmfd_node::p2p::{InboundPeerHandle, PeerDiscovery, spawn_inbound_listener_with_discovery};
use cmfd_node::peer::{PeerAddressPolicy, PeerLimits};
use cmfd_node::wallet_backup::{
    WalletBackupError, WalletKeyStorage, authenticate_encrypted_wallet, create_encrypted_wallet,
    create_encrypted_wallet_backup, inspect_wallet_key_storage, migrate_plaintext_wallet_key,
    read_wallet_passphrase_file, restore_encrypted_wallet_backup,
};
use cmfd_node::work_gate::CatchUpSource;
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, NetworkProfile, Node, NodeClientError, NodeError,
    ProductionV3VerifierRecord, ProductionV4VerifierArtifacts, ProofProfile, PrunerHandle,
    compiled_production_v3_record_identity, compiled_production_v3_worker_sha256,
    production_v3_package_layout, production_v4_package_artifacts,
};
use cmfd_proof_worker::{ProofWorkerError, VerifierWorkerConfig, VerifierWorkerError};
use tauri::{App, Manager, Runtime};

#[cfg(feature = "production-v4")]
use crate::mining::ProductionV4PoolSearchAssets;
use crate::mining::{MiningLifecycle, MiningManager};
use crate::updater::lifecycle::{self, ExitStarted, NodeOperation, NodePhase, RestartGuard};

mod config;
mod launch;
mod peers;
mod power;

pub(crate) use config::{ConfigError, NodeRuntimeConfig, ProcessCommand};
use config::{
    DEFAULT_PROOF_VERIFIER_MEMORY_BYTES, DEFAULT_PROOF_VERIFIER_STARTUP_TIMEOUT_MS,
    DEFAULT_PROOF_VERIFIER_TIMEOUT_MS, WorkCheck,
};
pub(crate) use peers::{PeerManager, PeerSettings, UpdatePeerSettingsRequest};

const STATIC_PEER_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Lets startup and the first sync settle before the first proof-pruning
/// check; later checks follow `cmfd_node::PRUNE_CHECK_INTERVAL`.
const FIRST_PRUNE_CHECK_DELAY: Duration = Duration::from_secs(120);
/// The startup error code for a stored chain that cannot be kept and must be
/// synced again; the wallet offers [`RuntimeHandle::resync_chain`] for it.
pub(crate) const CHAIN_RESYNC_REQUIRED: &str = "chain_resync_required";

#[derive(Clone)]
enum NodeAvailability {
    Starting,
    Ready(Arc<Mutex<Node>>),
    Failed(NodeClientError),
}

struct ServiceHandles {
    inbound: InboundPeerHandle,
    pruner: Option<PrunerHandle>,
    /// Background check of the block history a fast start did not re-read.
    history_scrub: Option<cmfd_node::HistoryScrub>,
    /// Background work check of stored blocks, for a network with the
    /// release work rule.
    work_backlog: Option<cmfd_node::work_gate::WorkBacklogHandle>,
}

struct EmbeddedNode {
    node: Arc<Mutex<Node>>,
    peers: Arc<PeerManager>,
    services: ServiceHandles,
    #[cfg(feature = "production-v4")]
    production_v4_pool_search: Option<ProductionV4PoolSearchAssets>,
}

struct PreparedNodeSecurity {
    production_v3_record: Option<ProductionV3VerifierRecord>,
    production_v4_artifacts: Option<ProductionV4VerifierArtifacts>,
    verifier_worker: Option<VerifierWorkerConfig>,
}

struct RuntimeParts {
    node: NodeAvailability,
    mining: Option<Arc<MiningManager>>,
    peers: Option<Arc<PeerManager>>,
    services: Option<ServiceHandles>,
    // Public data only; offline preparation never keeps an unlocked signing key.
    prepared_destination: Option<[u8; 32]>,
}

#[derive(Clone)]
pub(crate) struct RuntimeHandle {
    inner: Arc<Mutex<RuntimeParts>>,
    operation: Arc<Mutex<()>>,
    stopping: Arc<AtomicBool>,
    /// "Restart to update" waits for sends and custody operations.
    update: Arc<RestartGuard>,
    config: NodeRuntimeConfig,
    data_dir: Result<PathBuf, NodeClientError>,
    launch: Arc<launch::LaunchPreparation>,
}

pub struct RuntimeState {
    handle: RuntimeHandle,
    // Held for the life of the process: dropping it stops the non-blocking
    // file writer from flushing buffered log lines.
    _log_guard: Option<cmfd_node::logging::WorkerGuard>,
}

/// What a resync did: the stored chain was moved to `moved_to`, a folder
/// inside the data directory that can be deleted once the wallet has synced
/// again.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ChainResyncReport {
    pub custody: WalletCustodyStatus,
    pub moved_to: String,
    pub moved_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WalletCustodyStatus {
    pub network: String,
    pub storage: &'static str,
    pub unlocked: bool,
    pub requires_migration: bool,
    pub can_restore: bool,
    pub data_directory: String,
    pub destination: Option<String>,
    pub launch: Option<launch::WalletLaunchStatus>,
}

impl RuntimeParts {
    fn starting() -> Self {
        Self {
            node: NodeAvailability::Starting,
            mining: None,
            peers: None,
            services: None,
            prepared_destination: None,
        }
    }

    fn ready(started: EmbeddedNode) -> Self {
        #[cfg(feature = "production-v4")]
        let mining = match started.production_v4_pool_search.clone() {
            Some(assets) => {
                MiningManager::new_with_production_v4_pool_search(Arc::clone(&started.node), assets)
            }
            None => MiningManager::new(Arc::clone(&started.node)),
        };
        #[cfg(not(feature = "production-v4"))]
        let mining = MiningManager::new(Arc::clone(&started.node));
        Self {
            mining: Some(Arc::new(mining)),
            node: NodeAvailability::Ready(started.node),
            peers: Some(started.peers),
            services: Some(started.services),
            prepared_destination: None,
        }
    }

    fn failed(error: NodeClientError) -> Self {
        Self {
            node: NodeAvailability::Failed(error),
            mining: None,
            peers: None,
            services: None,
            prepared_destination: None,
        }
    }
}

impl RuntimeState {
    /// `held`: a newer version failed after it had opened this wallet's
    /// data, so the node does not open them until the user chooses "Run
    /// anyway" ([`RuntimeHandle::run_held_start`]); the node shows `held`
    /// meanwhile.
    pub fn start<R: Runtime>(
        app: &App<R>,
        config: NodeRuntimeConfig,
        held: Option<NodeClientError>,
    ) -> Self {
        let allow = config.allow_public_peers;
        let peers = config.peers.len();
        eprintln!(
            "Common Foundry Wallet ({}, {}) node starting on {} with {} configured peer(s), allow_public_peers={allow}",
            COMPILED_NETWORK_PROFILE.short_name(),
            COMPILED_NETWORK_PROFILE.proof.profile_name(),
            config.p2p_bind,
            peers
        );
        let data_dir = match &config.data_dir {
            Some(directory) => Ok(directory.clone()),
            None => app
                .path()
                .app_local_data_dir()
                .map(|root| wallet_data_dir(&root, COMPILED_NETWORK_PROFILE))
                .map_err(|_| {
                    startup_error(
                        "data_directory_unavailable",
                        "The desktop wallet could not resolve its local data directory.",
                        false,
                    )
                }),
        };
        let log_guard = data_dir
            .as_ref()
            .ok()
            .map(|path| cmfd_node::logging::init_tracing(path, config.verbose));
        let stopping = Arc::new(AtomicBool::new(false));
        let launch = Arc::new(launch::LaunchPreparation::start(Arc::clone(&stopping)));
        let handle = RuntimeHandle {
            inner: Arc::new(Mutex::new(match &data_dir {
                Ok(_) => RuntimeParts::starting(),
                Err(error) => RuntimeParts::failed(error.clone()),
            })),
            operation: Arc::new(Mutex::new(())),
            stopping,
            update: Arc::default(),
            launch,
            config: config.clone(),
            data_dir: data_dir.clone(),
        };
        match (&data_dir, held) {
            (Ok(_), Some(held)) => {
                handle.update.hold(held.clone());
                if let Ok(mut runtime) = handle.inner.lock() {
                    *runtime = RuntimeParts::failed(held);
                }
            }
            (Ok(startup_data_dir), None) => handle.spawn_startup(startup_data_dir.clone()),
            (Err(_), _) => {}
        }
        Self {
            handle,
            _log_guard: log_guard,
        }
    }

    pub fn node(&self) -> Result<Arc<Mutex<Node>>, NodeClientError> {
        let runtime = self
            .handle
            .inner
            .lock()
            .map_err(|_| runtime_state_error())?;
        match &runtime.node {
            NodeAvailability::Starting => Err(node_starting_error()),
            NodeAvailability::Ready(node) => Ok(Arc::clone(node)),
            NodeAvailability::Failed(error) => Err(error.clone()),
        }
    }

    pub fn mining(&self) -> Result<Arc<MiningManager>, NodeClientError> {
        let runtime = self
            .handle
            .inner
            .lock()
            .map_err(|_| runtime_state_error())?;
        runtime.mining.clone().ok_or_else(|| match &runtime.node {
            NodeAvailability::Starting => node_starting_error(),
            NodeAvailability::Failed(error) => error.clone(),
            NodeAvailability::Ready(_) => startup_error(
                "mining_manager_unavailable",
                "The desktop mining service is unavailable. Reopen the wallet.",
                true,
            ),
        })
    }

    pub fn peers(&self) -> Result<Arc<PeerManager>, NodeClientError> {
        let runtime = self
            .handle
            .inner
            .lock()
            .map_err(|_| runtime_state_error())?;
        runtime.peers.clone().ok_or_else(|| match &runtime.node {
            NodeAvailability::Starting => node_starting_error(),
            NodeAvailability::Failed(error) => error.clone(),
            NodeAvailability::Ready(_) => startup_error(
                "peer_manager_unavailable",
                "The desktop peer service is unavailable. Reopen the wallet.",
                true,
            ),
        })
    }

    pub fn stop_services(&self) {
        self.handle.stopping.store(true, Ordering::Release);
        self.handle.launch.stop();
        if let Ok(mut runtime) = self.handle.inner.lock() {
            stop_runtime_parts(&mut runtime);
        }
    }

    pub(crate) fn handle(&self) -> RuntimeHandle {
        self.handle.clone()
    }

    #[cfg(test)]
    pub(crate) fn locked_for_test() -> Self {
        Self::failed_for_test(wallet_locked_error())
    }

    #[cfg(test)]
    fn failed_for_test(error: NodeClientError) -> Self {
        Self {
            handle: RuntimeHandle {
                inner: Arc::new(Mutex::new(RuntimeParts::failed(error))),
                operation: Arc::new(Mutex::new(())),
                stopping: Arc::new(AtomicBool::new(false)),
                update: Arc::default(),
                config: NodeRuntimeConfig::default_for_test(),
                launch: Arc::default(),
                data_dir: Err(startup_error(
                    "data_directory_unavailable",
                    "test data directory unavailable",
                    false,
                )),
            },
            _log_guard: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn starting_for_test() -> Self {
        Self {
            handle: RuntimeHandle {
                inner: Arc::new(Mutex::new(RuntimeParts::starting())),
                operation: Arc::new(Mutex::new(())),
                stopping: Arc::new(AtomicBool::new(false)),
                update: Arc::default(),
                config: NodeRuntimeConfig::default_for_test(),
                launch: Arc::default(),
                data_dir: Ok(PathBuf::from("test-wallet-data")),
            },
            _log_guard: None,
        }
    }
}

impl RuntimeHandle {
    /// Starts the node in the background, as at launch.
    fn spawn_startup(&self, startup_data_dir: PathBuf) {
        let config = self.config.clone();
        let startup_inner = Arc::clone(&self.inner);
        let startup_stopping = Arc::clone(&self.stopping);
        let startup_update = Arc::clone(&self.update);
        let spawn = thread::Builder::new()
            .name("cmfd-wallet-startup".to_owned())
            .spawn(move || {
                let started = catch_unwind(AssertUnwindSafe(|| {
                    let wallet_passphrase = config
                        .wallet_passphrase_file
                        .as_deref()
                        .map(read_wallet_passphrase_file)
                        .transpose()
                        .map_err(|error| {
                            startup_error(
                                "wallet_passphrase_file",
                                format!(
                                    "The wallet passphrase file could not be used: {error}"
                                ),
                                false,
                            )
                        })?;
                    start_embedded_node(
                        &startup_data_dir,
                        &config,
                        wallet_passphrase.as_ref().map(|value| value.as_slice()),
                        lifecycle::startup_data_dir_wait(),
                        &startup_stopping,
                        &startup_update,
                    )
                }))
                .unwrap_or_else(|_| {
                    Err(startup_error(
                        "node_startup_panicked",
                        "The embedded node stopped unexpectedly during startup. Reopen the wallet and inspect its log if this repeats.",
                        true,
                    ))
                });

                if let Ok(mut runtime) = startup_inner.lock() {
                    if startup_stopping.load(Ordering::Acquire) {
                        if let Ok(started) = started {
                            let mut stopped = RuntimeParts::ready(started);
                            stop_runtime_parts(&mut stopped);
                        }
                    } else {
                        *runtime = match started {
                            Ok(started) => RuntimeParts::ready(started),
                            Err(error) => RuntimeParts::failed(error),
                        };
                    }
                }
            });
        if spawn.is_err()
            && let Ok(mut runtime) = self.inner.lock()
        {
            *runtime = RuntimeParts::failed(startup_error(
                "node_startup_unavailable",
                "The embedded node startup worker could not be created. Reopen the wallet and try again.",
                true,
            ));
        }
    }

    /// "Run anyway" after a newer version failed once it had opened the
    /// wallet data: ends the hold and starts the node. Refused when there
    /// is no hold.
    pub(crate) fn run_held_start(&self) -> Result<(), NodeClientError> {
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.update.refuse_if_exiting()?;
        if !self.update.release_hold() {
            return Err(startup_error(
                "update_not_held",
                "This wallet is not waiting for a choice about a failed update.",
                false,
            ));
        }
        let data_dir = self.data_dir.clone()?;
        *self.inner.lock().map_err(|_| runtime_state_error())? = RuntimeParts::starting();
        self.spawn_startup(data_dir);
        Ok(())
    }
}

impl RuntimeHandle {
    pub(crate) fn custody_status(&self) -> Result<WalletCustodyStatus, NodeClientError> {
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.custody_status_inner()
    }

    fn custody_status_inner(&self) -> Result<WalletCustodyStatus, NodeClientError> {
        let launch = self.launch.status()?;
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        let storage = inspect_wallet_key_storage(data_dir).map_err(custody_error)?;
        let runtime = self.inner.lock().map_err(|_| runtime_state_error())?;
        let destination = match &runtime.node {
            NodeAvailability::Starting => return Err(node_starting_error()),
            NodeAvailability::Ready(node) => Some(hex::encode(
                node.lock()
                    .map_err(|_| runtime_state_error())?
                    .wallet_destination(),
            )),
            NodeAvailability::Failed(_) => runtime.prepared_destination.map(hex::encode),
        };
        Ok(WalletCustodyStatus {
            network: COMPILED_NETWORK_PROFILE.name.to_owned(),
            storage: match storage {
                WalletKeyStorage::Missing => "missing",
                WalletKeyStorage::Plaintext => "plaintext",
                WalletKeyStorage::Encrypted => "encrypted",
            },
            unlocked: matches!(runtime.node, NodeAvailability::Ready(_)),
            requires_migration: storage == WalletKeyStorage::Plaintext,
            can_restore: storage == WalletKeyStorage::Missing,
            data_directory: data_dir.display().to_string(),
            destination,
            launch,
        })
    }

    pub(crate) fn unlock(&self, passphrase: &[u8]) -> Result<WalletCustodyStatus, NodeClientError> {
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        let started_at = Instant::now();
        tracing::info!("unlock received");
        self.update.refuse_if_exiting()?;
        // Before the node open refuses it, which would be kept as an unlock
        // failure and show the hold again after "Run anyway".
        self.update.refuse_if_held()?;
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        let already_unlocked = matches!(
            &self.inner.lock().map_err(|_| runtime_state_error())?.node,
            NodeAvailability::Ready(_)
        );
        if matches!(
            &self.inner.lock().map_err(|_| runtime_state_error())?.node,
            NodeAvailability::Starting
        ) {
            return Err(node_starting_error());
        }
        if already_unlocked {
            return Err(startup_error(
                "wallet_already_unlocked",
                "The wallet is already unlocked.",
                false,
            ));
        }
        if inspect_wallet_key_storage(data_dir).map_err(custody_error)?
            == WalletKeyStorage::Plaintext
        {
            return Err(startup_error(
                "wallet_migration_required",
                "Encrypt and back up this wallet before using lock controls.",
                false,
            ));
        }
        if self.launch.status()?.is_some_and(|launch| !launch.ready) {
            let destination = authenticate_encrypted_wallet(
                data_dir,
                COMPILED_NETWORK_PROFILE.network_id,
                passphrase,
            )
            .map_err(unlock_error)?;
            self.inner
                .lock()
                .map_err(|_| runtime_state_error())?
                .prepared_destination = Some(destination);
            return self.custody_status_inner();
        }
        // A wrong passphrase is refused here, in the time the key derivation
        // takes, not after the node open authenticated the whole model bank.
        // It is no unlock failure for the start check. Anything else (the
        // data dir still held during a restart to update, an unreadable key)
        // is left to the open, which reports it as before.
        match authenticate_encrypted_wallet(
            data_dir,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase,
        ) {
            Ok(_) => tracing::info!(
                elapsed_ms = elapsed_ms(started_at),
                "unlock: passphrase accepted"
            ),
            Err(
                error @ (WalletBackupError::AuthenticationFailed
                | WalletBackupError::InvalidPassphrase),
            ) => {
                tracing::info!(
                    elapsed_ms = elapsed_ms(started_at),
                    "unlock: passphrase refused"
                );
                return Err(unlock_error(error));
            }
            Err(_) => {}
        }
        let started = match start_embedded_node(
            data_dir,
            &self.config,
            Some(passphrase),
            Duration::ZERO,
            &self.stopping,
            &self.update,
        ) {
            Ok(started) => started,
            // An encrypted wallet's node first opens its stored chain here:
            // keep the refusal, so the wallet offers the resync.
            Err(error) if error.code == CHAIN_RESYNC_REQUIRED => {
                *self.inner.lock().map_err(|_| runtime_state_error())? =
                    RuntimeParts::failed(error.clone());
                return Err(error);
            }
            // The wallet stays locked, but the start check of an updated
            // version sees why the node could not open.
            Err(error) => {
                self.update.record_unlock_failure(&error);
                return Err(error);
            }
        };
        let mut runtime = self.inner.lock().map_err(|_| runtime_state_error())?;
        *runtime = RuntimeParts::ready(started);
        drop(runtime);
        tracing::info!(
            elapsed_ms = elapsed_ms(started_at),
            "unlock: wallet unlocked and node ready"
        );
        self.custody_status_inner()
    }

    pub(crate) fn lock(&self) -> Result<WalletCustodyStatus, NodeClientError> {
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.update.refuse_if_exiting()?;
        // A held wallet has no node to lock; locking would hide the hold.
        self.update.refuse_if_held()?;
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        if inspect_wallet_key_storage(data_dir).map_err(custody_error)?
            != WalletKeyStorage::Encrypted
        {
            return Err(startup_error(
                "wallet_migration_required",
                "Create an encrypted backup and migrate this wallet before locking it.",
                false,
            ));
        }
        self.stop_and_mark_locked()?;
        self.custody_status_inner()
    }

    pub(crate) fn backup(
        &self,
        output: &Path,
        passphrase: &[u8],
    ) -> Result<WalletCustodyStatus, NodeClientError> {
        require_absolute_custody_path(output)?;
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.update.refuse_if_exiting()?;
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        // A backup only reads the wallet data. A held wallet runs no node
        // and keeps showing the hold, so it may still be backed up before
        // "Run anyway".
        if !self.update.is_held() {
            self.stop_and_mark_locked()?;
        }
        create_encrypted_wallet_backup(
            data_dir,
            output,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase,
        )
        .map_err(custody_error)?;
        self.custody_status_inner()
    }

    pub(crate) fn create(
        &self,
        backup_output: &Path,
        passphrase: &[u8],
    ) -> Result<WalletCustodyStatus, NodeClientError> {
        require_absolute_custody_path(backup_output)?;
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.update.refuse_if_exiting()?;
        self.update.refuse_if_held()?;
        self.launch.status()?;
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        self.stop_and_mark_locked()?;
        let info = create_encrypted_wallet(
            data_dir,
            backup_output,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase,
        )
        .map_err(custody_error)?;
        self.inner
            .lock()
            .map_err(|_| runtime_state_error())?
            .prepared_destination = Some(info.destination);
        self.custody_status_inner()
    }

    pub(crate) fn migrate(
        &self,
        backup_output: &Path,
        passphrase: &[u8],
    ) -> Result<WalletCustodyStatus, NodeClientError> {
        require_absolute_custody_path(backup_output)?;
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.update.refuse_if_exiting()?;
        self.update.refuse_if_held()?;
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        self.stop_and_mark_locked()?;
        migrate_plaintext_wallet_key(
            data_dir,
            backup_output,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase,
        )
        .map_err(custody_error)?;
        self.custody_status_inner()
    }

    pub(crate) fn restore(
        &self,
        input: &Path,
        passphrase: &[u8],
    ) -> Result<WalletCustodyStatus, NodeClientError> {
        require_absolute_custody_path(input)?;
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.update.refuse_if_exiting()?;
        self.update.refuse_if_held()?;
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        self.stop_and_mark_locked()?;
        self.launch.status()?;
        let info = restore_encrypted_wallet_backup(
            input,
            data_dir,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase,
        )
        .map_err(custody_error)?;
        self.inner
            .lock()
            .map_err(|_| runtime_state_error())?
            .prepared_destination = Some(info.destination);
        self.custody_status_inner()
    }

    fn stop_and_mark_locked(&self) -> Result<(), NodeClientError> {
        let mut runtime = self.inner.lock().map_err(|_| runtime_state_error())?;
        if matches!(runtime.node, NodeAvailability::Starting) {
            return Err(node_starting_error());
        }
        stop_runtime_parts(&mut runtime);
        *runtime = RuntimeParts::failed(wallet_locked_error());
        Ok(())
    }

    /// Moves the stored chain aside and starts the node again, which then
    /// syncs the chain from its peers. Only when the stored chain cannot be
    /// kept: startup refused it, block admission is halted, or the validated
    /// height is held below the tip by a stored block this computer's check
    /// found not to match (with one kind of engine nothing else settles it).
    /// The wallet key stays, and nothing is deleted
    /// ([`cmfd_node::storage::set_chain_data_aside`]). An encrypted wallet is
    /// locked afterwards unless a passphrase file is configured.
    pub(crate) fn resync_chain(&self) -> Result<ChainResyncReport, NodeClientError> {
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.update.refuse_if_exiting()?;
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        if self.stopping.load(Ordering::Acquire) {
            return Err(runtime_state_error());
        }
        {
            let mut runtime = self.inner.lock().map_err(|_| runtime_state_error())?;
            let needed = match &runtime.node {
                NodeAvailability::Starting => return Err(node_starting_error()),
                NodeAvailability::Failed(error) => error.code == CHAIN_RESYNC_REQUIRED,
                NodeAvailability::Ready(node) => {
                    let node = node.lock().map_err(|_| runtime_state_error())?;
                    node.work_rule_halted() || node.work_validated_height_held_by_unsettled_block()
                }
            };
            if !needed {
                return Err(startup_error(
                    "chain_resync_not_needed",
                    "This wallet's stored chain does not need a resync.",
                    false,
                ));
            }
            // Releases the node, and with it the data directory.
            stop_runtime_parts(&mut runtime);
            *runtime = RuntimeParts::failed(chain_resync_required_error());
        }
        let report = set_chain_data_aside_when_released(data_dir).map_err(|error| {
            eprintln!("Common Foundry Wallet could not set the stored chain aside: {error}");
            startup_error(
                "chain_resync_failed",
                "The stored chain could not be moved aside. Close and reopen the wallet, then try again.",
                true,
            )
        })?;
        eprintln!(
            "Common Foundry Wallet moved its stored chain ({}) to {}; the node syncs it again",
            report.moved.join(", "),
            report.folder.display()
        );
        // Without the configured passphrase file the wallet stays locked,
        // and unlocking starts the node.
        let passphrase = match self
            .config
            .wallet_passphrase_file
            .as_deref()
            .map(read_wallet_passphrase_file)
            .transpose()
        {
            Ok(passphrase) => passphrase,
            Err(error) => {
                eprintln!(
                    "Common Foundry Wallet could not read its passphrase file after the resync; unlock the wallet to continue: {error}"
                );
                None
            }
        };
        let started = start_embedded_node(
            data_dir,
            &self.config,
            passphrase.as_ref().map(|value| value.as_slice()),
            Duration::ZERO,
            &self.stopping,
            &self.update,
        );
        *self.inner.lock().map_err(|_| runtime_state_error())? = match started {
            Ok(started) => RuntimeParts::ready(started),
            Err(error) => RuntimeParts::failed(error),
        };
        Ok(ChainResyncReport {
            custody: self.custody_status_inner()?,
            moved_to: report.folder.display().to_string(),
            moved_bytes: report.moved_bytes,
        })
    }
}

/// The hooks of "Restart to update" and of the start check
/// (UPDATER-DESIGN.md sections 2.7 and 2.9).
impl RuntimeHandle {
    /// The wallet data dir, if it could be resolved.
    pub(crate) fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref().ok()
    }

    /// `--no-auto-update` was given.
    pub(crate) fn no_auto_update(&self) -> bool {
        self.config.no_auto_update()
    }

    /// The node waits for "Run anyway" or "Retry" after a newer version
    /// failed once it had opened the wallet data.
    pub(crate) fn is_held(&self) -> bool {
        self.update.is_held()
    }

    #[cfg(test)]
    pub(crate) fn hold_for_test(&self, error: NodeClientError) {
        self.update.hold(error);
    }

    /// Whether mining is starting, running or stopping. Without a mining
    /// service nothing mines.
    pub(crate) fn mining_active(&self) -> Result<bool, NodeClientError> {
        let mining = self
            .inner
            .lock()
            .map_err(|_| runtime_state_error())?
            .mining
            .clone();
        let Some(mining) = mining else {
            return Ok(false);
        };
        Ok(matches!(
            mining.status()?.lifecycle,
            MiningLifecycle::Starting | MiningLifecycle::Running | MiningLifecycle::Stopping
        ))
    }

    /// For a send, a consolidation, a peer-settings change or a mining
    /// start: refused once a restart to update began, and counted until the
    /// returned guard drops.
    pub(crate) fn begin_node_operation(&self) -> Result<NodeOperation, NodeClientError> {
        self.update.begin_node_operation()
    }

    /// Begins closing the wallet for a restart to update; refused during a
    /// send, a consolidation or a custody operation.
    pub(crate) fn try_begin_exit(&self) -> Result<ExitStarted, NodeClientError> {
        self.update.try_begin_exit(&self.operation)
    }

    /// Remembers a send the node accepted just now.
    pub(crate) fn record_send(&self, txid: &str) {
        self.update.record_send(txid, lifecycle::unix_now());
    }

    /// This session's sends that are still in the mempool. Without a running
    /// node the mempool is gone, so there are none.
    pub(crate) fn unrelayed_sends(&self) -> Result<lifecycle::UnrelayedSends, NodeClientError> {
        let node = match &self.inner.lock().map_err(|_| runtime_state_error())?.node {
            NodeAvailability::Ready(node) => Arc::clone(node),
            _ => return Ok(lifecycle::UnrelayedSends::default()),
        };
        let node = node.lock().map_err(|_| runtime_state_error())?;
        let mempool = node.mempool_snapshot();
        // Peers that cannot be listed count as none.
        let connected = node
            .status()
            .map(|status| {
                status
                    .peers
                    .iter()
                    .filter(|peer| peer.active_connections > 0)
                    .count()
            })
            .unwrap_or(0);
        Ok(lifecycle::unrelayed_sends(
            &self.update.recent_sends(),
            mempool.entries.iter().map(|entry| entry.txid.as_str()),
            connected,
            lifecycle::unix_now(),
        ))
    }

    pub(crate) fn node_phase(&self) -> NodePhase {
        self.node_phase_at(lifecycle::unix_now())
    }

    fn node_phase_at(&self, now: u64) -> NodePhase {
        lifecycle::with_launch_passed(
            lifecycle::with_unlock_failure(self.stored_node_phase(), self.update.unlock_failure()),
            self.launch.failure(),
            now,
        )
    }

    fn stored_node_phase(&self) -> NodePhase {
        match self.inner.lock() {
            Ok(runtime) => match &runtime.node {
                NodeAvailability::Starting => NodePhase::Starting,
                NodeAvailability::Ready(_) => NodePhase::Ready,
                NodeAvailability::Failed(error) => NodePhase::Failed {
                    code: error.code,
                    retryable: error.retryable,
                    message: error.message.clone(),
                },
            },
            Err(_) => {
                let error = runtime_state_error();
                NodePhase::Failed {
                    code: error.code,
                    retryable: error.retryable,
                    message: error.message,
                }
            }
        }
    }

    /// For a version the updater installed: records `started_ok` once its
    /// start is known to work, and hands `on_failed` the reason of a start
    /// that failed. Call once setup completed and the main window was built.
    pub(crate) fn spawn_start_watch(&self, on_failed: impl FnOnce(String) + Send + 'static) {
        let handle = self.clone();
        let stopping = Arc::clone(&self.stopping);
        let update = Arc::clone(&self.update);
        lifecycle::spawn_start_watch(
            move || handle.node_phase(),
            move || stopping.load(Ordering::Acquire),
            move || update.data_opened_for(),
            on_failed,
        );
    }
}

/// How long a resync waits for the stopped node's last holders (a command
/// still running, a peer thread finishing its exchange) to release the data
/// directory.
const DATA_DIR_RELEASE_WAIT: Duration = Duration::from_secs(10);

/// Sets the stored chain aside once the data directory is released.
fn set_chain_data_aside_when_released(
    data_dir: &Path,
) -> Result<cmfd_node::storage::ChainSetAsideReport, NodeError> {
    let deadline = std::time::Instant::now() + DATA_DIR_RELEASE_WAIT;
    loop {
        match cmfd_node::storage::set_chain_data_aside(data_dir) {
            Err(NodeError::DataDirLocked(_)) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(200));
            }
            result => return result,
        }
    }
}

/// `data_dir_wait` is how long opening the node waits for a data dir that
/// another process still holds (a wallet closing for a restart to update);
/// only the open itself is tried again, and not while the lock is seen
/// held. `stopping` (the wallet is closing) ends that wait. `update` learns
/// when the open returned, for the start check.
fn start_embedded_node(
    data_dir: &Path,
    config: &NodeRuntimeConfig,
    wallet_passphrase: Option<&[u8]>,
    data_dir_wait: Duration,
    stopping: &AtomicBool,
    update: &RestartGuard,
) -> Result<EmbeddedNode, NodeClientError> {
    let started_at = Instant::now();
    // Not while a newer version that failed after opening the wallet data
    // waits for the user's choice.
    update.refuse_if_held()?;
    // Resolve launch authority before expensive artifact loading or any node I/O.
    cmfd_node::mainnet_runtime::ensure_compiled_launch_ready()
        .map_err(|error| error.client_error())?;
    let security = prepare_node_security(COMPILED_NETWORK_PROFILE, config)?;
    let PreparedNodeSecurity {
        production_v3_record,
        production_v4_artifacts,
        verifier_worker,
    } = security;
    // From here on a failed start of an updated version is one after
    // opening the wallet data.
    lifecycle::before_node_open().map_err(|error| {
        // Not eprintln!, which panics when stderr is a closed pipe; inside
        // the startup's catch_unwind that would count as a failed start.
        let _ = writeln!(
            std::io::stderr(),
            "Common Foundry Wallet could not record its start before opening its data: {error}"
        );
        startup_error(
            "update_state_unwritable",
            "This updated wallet could not read or write its update state in its own folder, so it did not open the wallet data. Check that the folder is writable and has free space, then reopen the wallet.",
            // A file held for a moment, not a fault of this version.
            true,
        )
    })?;
    let mut node = lifecycle::open_retrying_while_locked(
        data_dir_wait,
        || lifecycle::data_dir_lock_held(data_dir),
        || {
            if opens_as_locked(data_dir, wallet_passphrase) {
                tracing::info!(
                    "wallet.key is encrypted and no passphrase file is set; the node opens once the wallet is unlocked"
                );
                return Err(NodeError::WalletLocked);
            }
            Node::open_with_runtime_security_and_wallet_passphrase(
                data_dir,
                production_v3_record.as_ref(),
                production_v4_artifacts.as_ref(),
                verifier_worker.as_ref(),
                wallet_passphrase,
            )
        },
        || stopping.load(Ordering::Acquire),
        std::time::Instant::now,
        thread::sleep,
    )
    .map_err(|error| sanitize_node_startup_error(COMPILED_NETWORK_PROFILE, error))?;
    // The stored blocks were replayed inside the open.
    update.mark_data_opened();
    node.configure_pruning(config.prune_keep_blocks)
        .map_err(|error| startup_error("prune_setting_invalid", error.to_string(), false))?;
    install_work_engine(&mut node, config.work_threads)?;
    apply_work_check(config.work_check, catch_up_sources, |sources| {
        node.enable_wallet_catch_up(sources)
    });
    #[cfg(feature = "production-v4")]
    let production_v4_pool_search =
        production_v4_artifacts
            .as_ref()
            .map(|artifacts| ProductionV4PoolSearchAssets {
                replay_worker: artifacts
                    .bank
                    .parent()
                    .expect("packaged ProductionV4 bank has a parent directory")
                    .join("cmfd-v4-replay"),
                model_bank: artifacts.bank.clone(),
                scratch_directory: data_dir.join("production-v4-pool-search"),
                wsl_distribution: if cfg!(windows) {
                    Some("Ubuntu-22.04".to_owned())
                } else {
                    None
                },
            });
    let discovery_hello = node.peer_hello();
    let enforces_work_rule = node.work_validated_height().is_some();
    let shared = Arc::new(Mutex::new(node));
    // Dropping the handle on any later startup error stops the thread. It
    // runs the engine's known answers first, then checks stored blocks.
    let work_backlog = enforces_work_rule
        .then(|| {
            cmfd_node::work_gate::spawn_work_backlog_with_pause(
                Arc::clone(&shared),
                power::on_battery,
            )
        })
        .transpose()
        .map_err(|_| {
            startup_error(
                "work_check_start_failed",
                "The embedded node could not start checking blocks. Reopen the wallet and try again.",
                true,
            )
        })?;
    // Dropping the handle on any later startup error stops the thread.
    let pruner = config
        .prune_keep_blocks
        .map(|_| cmfd_node::spawn_pruner(Arc::clone(&shared), FIRST_PRUNE_CHECK_DELAY))
        .transpose()
        .map_err(|_| {
            startup_error(
                "prune_start_failed",
                "The embedded node could not start proof pruning. Reopen the wallet and try again.",
                true,
            )
        })?;
    let listener = TcpListener::bind(config.p2p_bind).map_err(|_| {
        startup_error(
            "p2p_bind_failed",
            format!(
                "The embedded node could not bind {} P2P on {}. Stop the process using that address, then reopen Common Foundry Wallet.",
                COMPILED_NETWORK_PROFILE.short_name(), config.p2p_bind
            ),
            true,
        )
    })?;
    let p2p_address = listener.local_addr().map_err(|_| {
        startup_error(
            "p2p_address_unavailable",
            format!(
                "The embedded node could not inspect its {} P2P listener address.",
                COMPILED_NETWORK_PROFILE.short_name()
            ),
            true,
        )
    })?;
    let limits = PeerLimits::default();
    let discovery = Arc::new(PeerDiscovery::open(
        data_dir,
        discovery_hello,
        p2p_address,
        PeerAddressPolicy::AllowPublic,
    ));
    let inbound = spawn_inbound_listener_with_discovery(
        Arc::clone(&shared),
        listener,
        limits,
        config.address_policy(),
        Arc::clone(&discovery),
    )
    .map_err(|_| {
        startup_error(
            "p2p_start_failed",
            format!(
                "The embedded {} peer service could not start. Reopen the wallet and try again.",
                COMPILED_NETWORK_PROFILE.short_name()
            ),
            true,
        )
    })?;
    let peers = match PeerManager::start(
        Arc::clone(&shared),
        config,
        data_dir,
        p2p_address,
        limits,
        STATIC_PEER_POLL_INTERVAL,
        discovery,
    ) {
        Ok(peers) => Arc::new(peers),
        Err(error) => {
            let _ = inbound.stop();
            return Err(error);
        }
    };
    let history_scrub = cmfd_node::spawn_history_scrub(Arc::clone(&shared)).ok();
    tracing::info!(elapsed_ms = elapsed_ms(started_at), "embedded node ready");
    Ok(EmbeddedNode {
        node: shared,
        peers,
        services: ServiceHandles {
            inbound,
            pruner,
            history_scrub,
            work_backlog,
        },
        #[cfg(feature = "production-v4")]
        production_v4_pool_search,
    })
}

/// Installs the CPU work engine on a network with the release work rule.
///
/// The embedded node listens on a local address only, so other nodes do not
/// connect to it: it reaches the chain by syncing from the peers it connects
/// to. It still re-executes the work of every block above the release
/// checkpoint before it accepts it, because it follows the heaviest branch
/// those peers serve. Unlike a server node it does not check its stored
/// blocks before it starts its services: the engine's known answers run in
/// the background (blocks wait meanwhile and are fetched again), and so does
/// the check of stored blocks, which pauses on battery. The engine uses half
/// the logical processors, at most eight, below normal priority, unless
/// `--work-threads` sets the count (a wallet that runs all day beside a miner
/// can use fewer). It streams the model bank from disk rather than holding it
/// in memory.
fn install_work_engine(node: &mut Node, work_threads: Option<u64>) -> Result<(), NodeClientError> {
    #[cfg(feature = "production-v4")]
    {
        // Never more threads than logical processors, or than the default's
        // eight when their count is unknown.
        let threads = work_threads
            .and_then(|threads| usize::try_from(threads).ok())
            .map(|threads| {
                threads.min(std::thread::available_parallelism().map_or(8, |logical| logical.get()))
            })
            .unwrap_or_else(cmfd_node::work_gate::default_work_threads);
        node.install_work_engines(
            threads,
            cmfd_node::honest_work::WorkThreadPriority::BelowNormal,
            cmfd_node::work_gate::WorkBankMode::Streamed,
            None,
        )
        .map_err(work_engine_error)?;
    }
    #[cfg(not(feature = "production-v4"))]
    let _ = work_threads;
    if node.work_checker_missing() {
        return Err(startup_error(
            "work_engine_unavailable",
            "This wallet build cannot check the blocks of this network. Install the matching wallet package.",
            false,
        ));
    }
    Ok(())
}

/// The hosting provider of each compiled relay, by IP. Sources in one group
/// count as one: a block is taken without a check here only if sources in two
/// groups list it. Any other IP is a group of its own.
const CATCH_UP_PROVIDER_GROUPS: [(Ipv4Addr, u8); 4] = [
    // The seed and St. Louis: Contabo.
    (Ipv4Addr::new(173, 249, 35, 251), 0),
    (Ipv4Addr::new(209, 145, 48, 36), 0),
    // Singapore: AWS, enforcing the block work rule since 1.0.16.
    (Ipv4Addr::new(13, 140, 66, 6), 1),
    // Independently hosted Proxmox relay.
    (Ipv4Addr::new(107, 214, 187, 2), 2),
];

/// The compiled relays the wallet catches up from: the release's bootstrap
/// peers, never the peers the user configured.
fn catch_up_sources() -> Vec<CatchUpSource> {
    catch_up_sources_from(&COMPILED_NETWORK_PROFILE.bootstrap_peers())
}

/// Every compiled peer, each with its provider group.
fn catch_up_sources_from(peers: &[SocketAddr]) -> Vec<CatchUpSource> {
    let mut own_groups: Vec<IpAddr> = Vec::new();
    let first_own_group = CATCH_UP_PROVIDER_GROUPS
        .iter()
        .map(|(_, group)| group + 1)
        .max()
        .unwrap_or(0);
    peers
        .iter()
        .map(|&addr| {
            let group = CATCH_UP_PROVIDER_GROUPS
                .iter()
                .find(|(ip, _)| IpAddr::V4(*ip) == addr.ip())
                .map(|(_, group)| *group)
                .unwrap_or_else(|| {
                    let position = own_groups
                        .iter()
                        .position(|ip| *ip == addr.ip())
                        .unwrap_or_else(|| {
                            own_groups.push(addr.ip());
                            own_groups.len() - 1
                        });
                    first_own_group.saturating_add(u8::try_from(position).unwrap_or(u8::MAX))
                });
            CatchUpSource { addr, group }
        })
        .collect()
}

/// Turns the wallet catch-up on with `--work-check standard`, through
/// `enable`, and reports whether it is on. With `full`, or when it cannot be
/// turned on (fewer than two sources in different groups, as on every network
/// but mainnet), every block is checked before it is accepted. Startup never
/// fails because of it.
fn apply_work_check(
    work_check: WorkCheck,
    sources: impl FnOnce() -> Vec<CatchUpSource>,
    enable: impl FnOnce(Vec<CatchUpSource>) -> Result<bool, NodeError>,
) -> bool {
    if work_check == WorkCheck::Full {
        tracing::info!(
            target: "work_rule::catch_up",
            "--work-check full: every block is checked before it is accepted"
        );
        return false;
    }
    let sources = sources();
    let count = sources.len();
    match enable(sources) {
        Ok(true) => {
            tracing::info!(
                target: "work_rule::catch_up",
                sources = count,
                "catch-up is on: recent blocks two relays list are checked in the background"
            );
            true
        }
        Ok(false) => {
            tracing::info!(
                target: "work_rule::catch_up",
                sources = count,
                "catch-up is off on this network or data directory; every block is checked before it is accepted"
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                target: "work_rule::catch_up",
                %error,
                "catch-up could not be turned on; every block is checked before it is accepted"
            );
            false
        }
    }
}

/// Whether opening the node could only refuse a locked wallet: `wallet.key`
/// is encrypted and no passphrase was given. The open authenticates the
/// whole model bank before it reads the key, so it is not tried then. A data
/// dir another process holds still goes to the open, which reports that.
fn opens_as_locked(data_dir: &Path, wallet_passphrase: Option<&[u8]>) -> bool {
    wallet_passphrase.is_none()
        && matches!(
            inspect_wallet_key_storage(data_dir),
            Ok(WalletKeyStorage::Encrypted)
        )
        && !lifecycle::data_dir_lock_held(data_dir)
}

/// The startup error for a failed work-engine installation. A stored chain
/// that differs from the one the release pins is set aside and synced again
/// ([`RuntimeHandle::resync_chain`]).
#[cfg(feature = "production-v4")]
fn work_engine_error(error: NodeError) -> NodeClientError {
    match error {
        NodeError::WorkCheckpointConflict { .. } | NodeError::WorkRuleResyncRequired(_) => {
            chain_resync_required_error()
        }
        error => sanitize_node_startup_error(COMPILED_NETWORK_PROFILE, error),
    }
}

fn chain_resync_required_error() -> NodeClientError {
    startup_error(
        CHAIN_RESYNC_REQUIRED,
        "The blocks this wallet stored differ from the chain this release pins. Resync the chain: the stored blocks are moved aside and downloaded again, and the wallet key stays.",
        false,
    )
}

fn stop_runtime_parts(runtime: &mut RuntimeParts) {
    if let Some(mining) = runtime.mining.take() {
        mining.stop_for_shutdown();
    }
    if let Some(peers) = runtime.peers.take() {
        peers.stop();
    }
    if let Some(services) = runtime.services.take() {
        let _ = services.inbound.stop();
        if let Some(pruner) = services.pruner {
            pruner.stop();
        }
        if let Some(history_scrub) = services.history_scrub {
            history_scrub.stop();
        }
        if let Some(work_backlog) = services.work_backlog {
            work_backlog.stop();
        }
    }
    if let NodeAvailability::Ready(node) = &runtime.node
        && let Ok(node) = node.lock()
    {
        // The pruner and the scrub are joined above, so no prune swap is
        // under way. The cache refuses to write for a faulted node or one
        // whose log and index disagree, which leaves the last one in place.
        // Saving it here spares the next start reading the records appended
        // since the last refresh.
        let _ = node.persist_index_cache();
        node.shutdown_proof_verifier();
    }
}

/// An unlock's passphrase check failed. A passphrase that does not decrypt
/// `wallet.key` gets its own code and words, not the lock screen's.
fn unlock_error(error: WalletBackupError) -> NodeClientError {
    match error {
        WalletBackupError::AuthenticationFailed => NodeClientError {
            code: "wallet_authentication_failed",
            status: 401,
            retryable: false,
            message: "That passphrase does not unlock this wallet. Check it and try again."
                .to_owned(),
        },
        error => custody_error(error),
    }
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn wallet_locked_error() -> NodeClientError {
    NodeClientError {
        code: "wallet_locked",
        status: 423,
        retryable: false,
        message: "Wallet locked. Unlock it from Wallet security to start the node.".to_owned(),
    }
}

fn node_starting_error() -> NodeClientError {
    startup_error(
        "node_starting",
        "Opening wallet: preparing and authenticating proof inputs, then replaying local chain history. The first RCNet run may download about 6.4 GB.",
        true,
    )
}

fn runtime_state_error() -> NodeClientError {
    startup_error(
        "runtime_state_unavailable",
        "The wallet runtime state is unavailable. Reopen the wallet.",
        true,
    )
}

fn require_absolute_custody_path(path: &Path) -> Result<(), NodeClientError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(NodeClientError {
            code: "wallet_path_invalid",
            status: 400,
            retryable: false,
            message: "Wallet backup and restore paths must be absolute.".to_owned(),
        })
    }
}

fn custody_error(error: WalletBackupError) -> NodeClientError {
    let (code, status) = match error {
        WalletBackupError::InvalidPassphrase => ("wallet_passphrase_invalid", 400),
        WalletBackupError::AuthenticationFailed => ("wallet_authentication_failed", 401),
        WalletBackupError::WrongNetwork => ("wallet_backup_wrong_network", 409),
        WalletBackupError::AlreadyEncrypted => ("wallet_already_encrypted", 409),
        WalletBackupError::WalletKeyAlreadyExists => ("wallet_key_already_exists", 409),
        WalletBackupError::OverlappingPaths => ("wallet_paths_overlap", 400),
        WalletBackupError::InvalidBackup | WalletBackupError::DestinationMismatch => {
            ("wallet_backup_invalid", 400)
        }
        WalletBackupError::InvalidWalletKey => ("invalid_wallet_key", 500),
        WalletBackupError::InsecurePassphraseFilePermissions => {
            ("wallet_passphrase_file_insecure", 400)
        }
        WalletBackupError::Node(_) | WalletBackupError::Io { .. } => ("wallet_storage_io", 500),
    };
    NodeClientError {
        code,
        status,
        retryable: false,
        message: error.to_string(),
    }
}

fn prepare_node_security(
    profile: NetworkProfile,
    config: &NodeRuntimeConfig,
) -> Result<PreparedNodeSecurity, NodeClientError> {
    if profile.proof == ProofProfile::DevnetV2Reference {
        return prepare_node_security_with_package(profile, config, Path::new("."), None);
    }
    let package_executable = std::env::current_exe().map_err(|_| {
        startup_error(
            "production_package_unavailable",
            "The wallet could not resolve its signed package directory.",
            false,
        )
    })?;
    prepare_packaged_rcnet_runtime(profile, &package_executable)?;
    let expected_worker_sha256 = if profile.proof == ProofProfile::ProductionV3 {
        Some(
            compiled_production_v3_worker_sha256()
                .map_err(|error| sanitize_node_startup_error(profile, error))?,
        )
    } else {
        None
    };
    prepare_node_security_with_package(profile, config, &package_executable, expected_worker_sha256)
}

#[cfg(all(feature = "production-rc", target_os = "windows"))]
fn prepare_packaged_rcnet_runtime(
    profile: NetworkProfile,
    package_executable: &Path,
) -> Result<(), NodeClientError> {
    if profile.proof != ProofProfile::ProductionV4 {
        return Ok(());
    }
    let artifacts = production_v4_package_artifacts(package_executable)
        .map_err(|error| sanitize_node_startup_error(profile, error))?;
    if artifacts.bank.is_file() && artifacts.fixed_record.is_file() {
        return Ok(());
    }
    let package_directory = package_executable.parent().ok_or_else(|| {
        sanitize_node_startup_error(profile, NodeError::ProductionV4ArtifactsMissing)
    })?;
    let preparation = package_directory.join("PREPARE-RCNET-RUNTIME.ps1");
    if !preparation.is_file() {
        return Ok(());
    }
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&preparation)
        .arg("-Destination")
        .arg(
            artifacts
                .bank
                .parent()
                .expect("packaged ProductionV4 bank has a parent directory"),
        )
        .creation_flags(CREATE_NEW_CONSOLE)
        .status()
        .map_err(rcnet_runtime_preparation_error)?;
    if !status.success() {
        return Err(startup_error(
            "rcnet_runtime_preparation_failed",
            format!(
                "RCNet-1 runtime preparation stopped with exit code {}. Reopen the wallet to resume the authenticated download.",
                status
                    .code()
                    .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
            ),
            true,
        ));
    }
    Ok(())
}

#[cfg(all(feature = "production-rc", target_os = "windows"))]
fn rcnet_runtime_preparation_error(error: io::Error) -> NodeClientError {
    startup_error(
        "rcnet_runtime_preparation_failed",
        format!(
            "RCNet-1 runtime preparation could not start ({error}). Reopen the wallet to retry, or run PREPARE-RCNET-RUNTIME.ps1 from the installation directory."
        ),
        true,
    )
}

#[cfg(not(all(feature = "production-rc", target_os = "windows")))]
fn prepare_packaged_rcnet_runtime(
    _profile: NetworkProfile,
    _package_executable: &Path,
) -> Result<(), NodeClientError> {
    Ok(())
}

fn prepare_node_security_with_package(
    profile: NetworkProfile,
    config: &NodeRuntimeConfig,
    package_executable: &Path,
    expected_worker_sha256: Option<[u8; 32]>,
) -> Result<PreparedNodeSecurity, NodeClientError> {
    let options = &config.production_v3;
    match profile.proof {
        ProofProfile::DevnetV2Reference => {
            if options.is_configured() {
                return Err(startup_error(
                    "production_v3_configuration_unexpected",
                    format!(
                        "{} ({}) does not accept ProductionV3 artifacts or proof-verifier settings.",
                        profile.short_name(),
                        profile.proof.profile_name()
                    ),
                    false,
                ));
            }
            Ok(PreparedNodeSecurity {
                production_v3_record: None,
                production_v4_artifacts: None,
                verifier_worker: None,
            })
        }
        ProofProfile::ProductionV3 => {
            let expected_worker_sha256 = expected_worker_sha256.ok_or_else(|| {
                startup_error(
                    "proof_verifier_configuration",
                    format!(
                        "{} ({}) has no compiled proof-verifier worker identity.",
                        profile.short_name(),
                        profile.proof.profile_name()
                    ),
                    false,
                )
            })?;
            if options
                .verifier_worker_sha256
                .is_some_and(|configured| configured != expected_worker_sha256)
            {
                return Err(startup_error(
                    "proof_verifier_identity_mismatch",
                    format!(
                        "{} ({}) rejected a proof-verifier SHA-256 that does not match the compiled package pin.",
                        profile.short_name(),
                        profile.proof.profile_name()
                    ),
                    false,
                ));
            }
            if options.bank.is_some() || options.manifest.is_some() {
                return Err(startup_error(
                    "production_v3_configuration_missing",
                    format!(
                        "{} ({}) uses the model bank and manifest only in the standalone miner; wallet verification accepts Record V2 and the proof worker.",
                        profile.short_name(),
                        profile.proof.profile_name()
                    ),
                    false,
                ));
            }
            let path_override_count =
                [options.record_v2.as_ref(), options.verifier_worker.as_ref()]
                    .into_iter()
                    .filter(|value| value.is_some())
                    .count();
            let (mut record, verifier_worker) = if path_override_count == 0 {
                let layout = production_v3_package_layout(package_executable)
                    .map_err(|error| sanitize_node_startup_error(profile, error))?;
                (layout.record, layout.worker)
            } else if path_override_count == 2 {
                (
                    ProductionV3VerifierRecord {
                        record_v2: options
                            .record_v2
                            .clone()
                            .expect("both verifier paths were counted"),
                        expected_file: compiled_production_v3_record_identity()
                            .map_err(|error| sanitize_node_startup_error(profile, error))?,
                    },
                    options
                        .verifier_worker
                        .clone()
                        .expect("both verifier paths were counted"),
                )
            } else {
                return Err(startup_error(
                    "production_v3_configuration_missing",
                    format!(
                        "{} ({}) requires either the packaged Record V2 and proof worker or both explicit verifier paths.",
                        profile.short_name(),
                        profile.proof.profile_name()
                    ),
                    false,
                ));
            };

            record.record_v2 = canonical_runtime_file(profile, "Record V2", &record.record_v2)?;
            let worker = VerifierWorkerConfig {
                worker_executable: canonical_runtime_file(
                    profile,
                    "proof-verifier worker",
                    &verifier_worker,
                )?,
                worker_sha256: expected_worker_sha256,
                startup_timeout: Duration::from_millis(
                    options
                        .verifier_startup_timeout_ms
                        .unwrap_or(DEFAULT_PROOF_VERIFIER_STARTUP_TIMEOUT_MS),
                ),
                timeout: Duration::from_millis(
                    options
                        .verifier_timeout_ms
                        .unwrap_or(DEFAULT_PROOF_VERIFIER_TIMEOUT_MS),
                ),
                memory_limit_bytes: options
                    .verifier_memory_bytes
                    .unwrap_or(DEFAULT_PROOF_VERIFIER_MEMORY_BYTES),
                cpu_quota_micros: options.verifier_cpu_quota_us,
                cpu_period_micros: options.verifier_cpu_period_us,
                pids_limit: options.verifier_pids_limit,
                production_v3_record: Some(record.clone()),
            };
            worker
                .validate_executable()
                .map_err(|error| sanitize_worker_configuration_error(profile, error))?;

            Ok(PreparedNodeSecurity {
                production_v3_record: Some(record),
                production_v4_artifacts: None,
                verifier_worker: Some(worker),
            })
        }
        ProofProfile::ProductionV4 => {
            if options.is_configured() {
                return Err(startup_error(
                    "production_v4_configuration_unexpected",
                    format!(
                        "{} ({}) does not accept ProductionV3 artifacts or proof-verifier settings.",
                        profile.short_name(),
                        profile.proof.profile_name()
                    ),
                    false,
                ));
            }
            let artifacts = production_v4_package_artifacts(package_executable)
                .map_err(|error| sanitize_node_startup_error(profile, error))?;
            Ok(PreparedNodeSecurity {
                production_v3_record: None,
                production_v4_artifacts: Some(artifacts),
                verifier_worker: None,
            })
        }
    }
}

fn canonical_runtime_file(
    profile: NetworkProfile,
    component: &'static str,
    configured: &Path,
) -> Result<PathBuf, NodeClientError> {
    if !configured.is_absolute() {
        return Err(startup_error(
            "production_v3_path_invalid",
            format!(
                "{} ({}) requires an absolute path to the configured {component} file.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        ));
    }
    let canonical = cmfd_node::plain_package_path(fs::canonicalize(configured).map_err(|_| {
        startup_error(
            "production_v3_file_unavailable",
            format!(
                "{} ({}) could not open the configured {component} file.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        )
    })?);
    let metadata = fs::metadata(&canonical).map_err(|_| {
        startup_error(
            "production_v3_file_unavailable",
            format!(
                "{} ({}) could not inspect the configured {component} file.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        )
    })?;
    if !metadata.is_file() {
        return Err(startup_error(
            "production_v3_path_invalid",
            format!(
                "{} ({}) requires the configured {component} path to name a regular file.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        ));
    }
    Ok(canonical)
}

fn sanitize_worker_configuration_error(
    profile: NetworkProfile,
    error: VerifierWorkerError,
) -> NodeClientError {
    let (code, message) = match error {
        VerifierWorkerError::Process(ProofWorkerError::HashMismatch { .. }) => (
            "proof_verifier_identity_mismatch",
            "the proof-verifier worker does not match its configured SHA-256 pin",
        ),
        VerifierWorkerError::Process(ProofWorkerError::FileRead { .. }) => (
            "proof_verifier_unavailable",
            "the proof-verifier worker could not be read",
        ),
        VerifierWorkerError::InvalidConfig(_) => (
            "proof_verifier_configuration",
            "the ProductionV3 artifact or proof-verifier configuration is invalid",
        ),
        _ => (
            "proof_verifier_configuration",
            "the proof-verifier worker could not be validated",
        ),
    };
    startup_error(
        code,
        format!(
            "{} ({}) cannot start because {message}.",
            profile.short_name(),
            profile.proof.profile_name()
        ),
        false,
    )
}

#[cfg(test)]
fn open_with_record_gate<T>(
    data_dir: &Path,
    profile: NetworkProfile,
    security: &PreparedNodeSecurity,
    open: impl FnOnce(&Path, Option<&ProductionV3VerifierRecord>) -> Result<T, NodeError>,
) -> Result<T, NodeClientError> {
    open(data_dir, security.production_v3_record.as_ref())
        .map_err(|error| sanitize_node_startup_error(profile, error))
}

fn sanitize_node_startup_error(profile: NetworkProfile, error: NodeError) -> NodeClientError {
    let client = error.client_error();
    match (profile.proof, client.code) {
        (ProofProfile::ProductionV3, "production_v3_unavailable") => startup_error(
            client.code,
            format!(
                "{} ({}) cannot start because this wallet build does not include the ProductionV3 verifier.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        ),
        (ProofProfile::ProductionV3, "proof_verifier_configuration") => startup_error(
            client.code,
            format!(
                "{} ({}) rejected the configured Record V2 or proof-verifier identity. Re-download the package if any file changed, keep the production-v3 folder beside the wallet private to your account, and retry.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        ),
        (ProofProfile::ProductionV4, "production_v4_unavailable") => startup_error(
            client.code,
            format!(
                "{} ({}) cannot start because this wallet build does not include the ProductionV4 verifier.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        ),
        (ProofProfile::ProductionV4, "production_v4_artifacts_missing") => startup_error(
            client.code,
            format!(
                "{} ({}) cannot start because its authenticated runtime files are missing. Place production-v4/MODEL-V2.bank and production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json beside the wallet executable, or complete the RCNet runtime preparation first, then reopen the wallet.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        ),
        (ProofProfile::ProductionV4, "proof_verifier_configuration") => startup_error(
            client.code,
            format!(
                "{} ({}) rejected the packaged model bank or fixed artifact record. Re-download the package and retry.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        ),
        _ => client,
    }
}

fn wallet_data_dir(root: &Path, profile: cmfd_node::NetworkProfile) -> PathBuf {
    root.join(profile.wallet_data_dir_identity)
}

pub(crate) fn parse_command() -> Result<ProcessCommand, ConfigError> {
    NodeRuntimeConfig::from_process_args()
}

pub(crate) fn command_help_text() -> String {
    command_help_text_for_profile(COMPILED_NETWORK_PROFILE)
}

fn command_help_text_for_profile(profile: NetworkProfile) -> String {
    let mut help = format!(
        concat!(
            "Common Foundry Wallet\n",
            "Compiled network: {} ({})\n",
            "Usage: common-foundry-wallet [runtime-identity|--help|--version] [--data-dir <absolute-path>] [--p2p-bind <addr>] [--peer <addr> ...] [--allow-public-peers] [--wallet-passphrase-file <path>] [--prune-keep-blocks <n>|--no-prune] [--work-threads <n>] [--work-check standard|full] [--no-auto-update] [-v...]\n",
            "Arguments:\n",
            "  --help (-h)             Show this help\n",
            "  --version (-V)          Print version\n",
            "  runtime-identity        Authenticate packaged V4 artifacts and print compiled wallet identity\n",
            "  -v, --verbose           Increase console verbosity (repeatable)\n",
            "  --data-dir <path>       Explicit absolute local network data directory\n",
            "  --p2p-bind <addr>       Local P2P bind address (default {})\n",
            "  --peer <addr>           Public or private outbound peer (repeatable)\n",
            "  --allow-public-peers     Allow public peers for explicit --peer entries\n",
            "                          (the default bootstrap peer is always added if no --peer is configured)\n",
            "  --wallet-passphrase-file <path> Unlock or create encrypted wallet.key\n",
            "  --prune-keep-blocks <n>  Keep proofs for the newest n blocks (default {}, minimum {});\n",
            "                          older blocks keep their header and transactions\n",
            "  --no-prune              Keep every block proof\n",
            "  --work-threads <n>      Threads for the block check (default: half the logical\n",
            "                          processors, at most 8; fewer keep the computer cooler)\n",
            "  --work-check <mode>     standard (default): after time offline, take recent blocks that two\n",
            "                          Common Foundry relays list, then check the newest here and the rest\n",
            "                          in the background; full: check every block before it is accepted\n",
            "  --no-auto-update        Do not check for, download or switch to wallet updates this run (mainnet only)\n",
        ),
        profile.name,
        profile.proof.profile_name(),
        profile.p2p_address(),
        config::DEFAULT_PRUNE_KEEP_BLOCKS,
        cmfd_node::MIN_PRUNE_KEEP_BLOCKS,
    );
    if profile.proof == ProofProfile::ProductionV3 {
        help.push_str(&format!(
            concat!(
                "ProductionV3 startup uses the fixed packaged sidecars beside the wallet when no paths are supplied.\n",
                "Explicit overrides must be complete, absolute, and match the compiled pins:\n",
                "  --production-v3-record-v2 <path>            Canonical Dory Record V2\n",
                "  --proof-verifier-worker <path>               Hash-pinned verifier worker\n",
                "  --proof-verifier-worker-sha256 <hex>         Exact worker SHA-256\n",
                "  --proof-verifier-startup-timeout-ms <integer> Model authentication timeout (default {})\n",
                "  --proof-verifier-timeout-ms <integer>        Worker timeout (default {})\n",
                "  --proof-verifier-memory-bytes <integer>      Worker memory cap (default {})\n",
                "  --proof-verifier-cpu-quota-us <integer>      Measured Linux cgroup CPU quota\n",
                "  --proof-verifier-cpu-period-us <integer>     Measured Linux cgroup CPU period\n",
                "  --proof-verifier-pids-limit <integer>        Measured Linux cgroup task limit\n",
            ),
            DEFAULT_PROOF_VERIFIER_STARTUP_TIMEOUT_MS,
            DEFAULT_PROOF_VERIFIER_TIMEOUT_MS,
            DEFAULT_PROOF_VERIFIER_MEMORY_BYTES
        ));
    } else if profile.proof == ProofProfile::ProductionV4 {
        help.push_str(
            "ProductionV4 startup authenticates the packaged model bank and fixed artifact record before opening node storage.\n",
        );
    }
    help
}

pub fn startup_error(
    code: &'static str,
    message: impl Into<String>,
    retryable: bool,
) -> NodeClientError {
    NodeClientError {
        code,
        status: 503,
        retryable,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmfd_node::{DEVNET_PROFILE, PRODUCTION_V3_TESTNET_PROFILE, RCNET1_PROFILE};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestFiles {
        root: PathBuf,
    }

    impl TestFiles {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "cmfd-wallet-v3-runtime-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self { root }
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn base_config(profile: NetworkProfile) -> NodeRuntimeConfig {
        NodeRuntimeConfig {
            p2p_bind: profile.p2p_address(),
            peers: vec![profile.bootstrap_peer()],
            allow_public_peers: true,
            peers_explicit: false,
            verbose: 0,
            data_dir: None,
            wallet_passphrase_file: None,
            prune_keep_blocks: Some(config::DEFAULT_PRUNE_KEEP_BLOCKS),
            work_threads: None,
            work_check: WorkCheck::Standard,
            production_v3: config::ProductionV3RuntimeOptions::default(),
            no_auto_update: false,
        }
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn security_error(result: Result<PreparedNodeSecurity, NodeClientError>) -> NodeClientError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("expected ProductionV3 startup configuration to fail"),
        }
    }

    fn configured_rc(files: &TestFiles, worker_sha256: [u8; 32]) -> NodeRuntimeConfig {
        let mut config = base_config(PRODUCTION_V3_TESTNET_PROFILE);
        config.production_v3 = config::ProductionV3RuntimeOptions {
            bank: None,
            manifest: None,
            record_v2: Some(files.write("record-v2.json", b"bounded Record V2 fixture")),
            verifier_worker: Some(files.write("cmfd-proof-worker.bin", b"bounded worker fixture")),
            verifier_worker_sha256: Some(worker_sha256),
            verifier_startup_timeout_ms: Some(1_234),
            verifier_timeout_ms: Some(1_234),
            verifier_memory_bytes: Some(4_096),
            verifier_cpu_quota_us: Some(100_000),
            verifier_cpu_period_us: Some(100_000),
            verifier_pids_limit: Some(16),
        };
        config
    }

    fn prepare_for_test(
        profile: NetworkProfile,
        config: &NodeRuntimeConfig,
        package_root: &Path,
    ) -> Result<PreparedNodeSecurity, NodeClientError> {
        let package_executable = package_root.join(format!(
            "common-foundry-wallet{}",
            std::env::consts::EXE_SUFFIX
        ));
        let expected = (profile.proof == ProofProfile::ProductionV3)
            .then(|| sha256(b"bounded worker fixture"));
        prepare_node_security_with_package(profile, config, &package_executable, expected)
    }

    #[test]
    fn offline_create_and_restore_expose_only_public_destination() {
        // Mainnet's real status path authenticates the plan beside the current
        // executable. Test a genuine isolated package, never skip that gate or
        // write sidecars into the shared Cargo target directory.
        #[cfg(feature = "production-mainnet")]
        let package_case = match std::env::var("CMFD_WALLET_PACKAGE_TEST_CASE") {
            Err(std::env::VarError::NotPresent) => {
                run_offline_mainnet_package_cases();
                return;
            }
            Ok(value) if matches!(value.as_str(), "missing-plan" | "prepared") => value,
            _ => panic!("unexpected wallet package fixture mode"),
        };
        let files = TestFiles::new();
        let state = RuntimeState::failed_for_test(wallet_locked_error());
        let mut handle = state.handle();
        handle.data_dir = Ok(files.root.join("wallet"));
        let passphrase = b"correct horse battery staple";
        let backup = files.root.join("wallet.cmfd-backup");
        #[cfg(feature = "production-mainnet")]
        if package_case == "missing-plan" {
            assert_eq!(
                handle.create(&backup, passphrase).unwrap_err().code,
                "mainnet_launch_required"
            );
            assert!(!backup.exists());
            assert!(!files.root.join("wallet").exists());
            return;
        }
        let created = handle.create(&backup, passphrase).unwrap();
        assert_eq!(created.storage, "encrypted");
        assert!(!created.unlocked);
        assert!(created.destination.is_some());
        #[cfg(feature = "production-mainnet")]
        assert!(
            !created
                .launch
                .as_ref()
                .expect("packaged mainnet launch state")
                .ready
        );
        assert!(state.node().is_err());
        assert!(state.mining().is_err());
        assert!(state.peers().is_err());
        let original = fs::read(files.root.join("wallet/wallet.key")).unwrap();
        assert!(handle.create(&backup, passphrase).is_err());
        assert_eq!(
            fs::read(files.root.join("wallet/wallet.key")).unwrap(),
            original
        );
        let locked = handle.lock().unwrap();
        assert!(locked.destination.is_none());
        handle.data_dir = Ok(files.root.join("restored"));
        let restored = handle.restore(&backup, passphrase).unwrap();
        assert_eq!(restored.destination, created.destination);
        assert!(!restored.unlocked);
        assert!(state.node().is_err());
        assert!(!files.root.join("restored/blocks.log").exists());
    }

    #[cfg(feature = "production-mainnet")]
    fn run_offline_mainnet_package_cases() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let files = TestFiles::new();
        let executable = files.root.join(format!(
            "wallet-package-test{}",
            std::env::consts::EXE_SUFFIX
        ));
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        for case in ["missing-plan", "prepared"] {
            if case == "prepared" {
                let sidecar = files.root.join("production-mainnet");
                fs::create_dir(&sidecar).unwrap();
                fs::write(
                    sidecar.join("MAINNET-PLAN.json"),
                    include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../../packaging/mainnet/MAINNET-PLAN.json"
                    )),
                )
                .unwrap();
            }
            let mut command = Command::new(&executable);
            command
                .current_dir(&files.root)
                .args([
                    "--exact",
                    "runtime::tests::offline_create_and_restore_expose_only_public_destination",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("CMFD_WALLET_PACKAGE_TEST_CASE", case)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x0800_0000);
            }
            let mut child = command.spawn().unwrap();
            let started = Instant::now();
            while child.try_wait().unwrap().is_none() {
                if started.elapsed() > Duration::from_secs(60) {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("offline mainnet package fixture timed out: {case}");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{case}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn startup_failure_is_stable_and_shutdown_is_idempotent() {
        let expected = startup_error("startup_failed", "embedded node unavailable", true);
        let state = RuntimeState::failed_for_test(expected.clone());

        match state.node() {
            Ok(_) => panic!("failed startup unexpectedly exposed a node"),
            Err(error) => assert_eq!(error, expected),
        }
        state.stop_services();
        state.stop_services();
    }

    #[test]
    fn custody_operations_are_refused_once_a_restart_to_update_began() {
        let files = TestFiles::new();
        let path = files.root.join("wallet.backup");
        let handle = RuntimeState::starting_for_test().handle();
        handle.try_begin_exit().unwrap().commit();
        type Operation<'a> = Box<dyn Fn(&RuntimeHandle) -> Option<NodeClientError> + 'a>;
        let operations: [(&str, Operation); 7] = [
            ("unlock", Box::new(|h| h.unlock(b"passphrase").err())),
            ("lock", Box::new(|h| h.lock().err())),
            ("backup", Box::new(|h| h.backup(&path, b"passphrase").err())),
            ("create", Box::new(|h| h.create(&path, b"passphrase").err())),
            (
                "migrate",
                Box::new(|h| h.migrate(&path, b"passphrase").err()),
            ),
            (
                "restore",
                Box::new(|h| h.restore(&path, b"passphrase").err()),
            ),
            ("resync", Box::new(|h| h.resync_chain().err())),
        ];
        for (name, operation) in operations {
            let error = operation(&handle).unwrap_or_else(|| panic!("{name} ran"));
            assert_eq!(error.code, "update_restarting", "{name}");
        }
        assert_eq!(
            handle.begin_node_operation().unwrap_err().code,
            "update_restarting"
        );
        // Status polling is not refused.
        assert_ne!(
            handle.custody_status().err().map(|error| error.code),
            Some("update_restarting")
        );
        assert_eq!(fs::read_dir(&files.root).unwrap().count(), 0);
    }

    #[test]
    fn a_restart_to_update_waits_for_sends_and_custody_operations() {
        let handle = RuntimeState::starting_for_test().handle();
        let send = handle.begin_node_operation().unwrap();
        assert_eq!(handle.try_begin_exit().unwrap_err().code, "update_busy");
        drop(send);
        let backup = handle.operation.lock().unwrap();
        assert_eq!(handle.try_begin_exit().unwrap_err().code, "update_busy");
        drop(backup);
        // A refused restart leaves the wallet usable.
        drop(handle.begin_node_operation().unwrap());
        // Clones share the guard.
        let exit = handle.clone().try_begin_exit().unwrap();
        assert!(handle.begin_node_operation().is_err());
        drop(exit);
        assert!(handle.begin_node_operation().is_ok());
    }

    #[test]
    fn without_a_running_node_no_send_waits_for_relay() {
        let handle = RuntimeState::starting_for_test().handle();
        handle.record_send(&"ab".repeat(32));
        assert_eq!(
            handle.unrelayed_sends().unwrap(),
            lifecycle::UnrelayedSends::default()
        );
    }

    #[test]
    fn a_held_wallet_refuses_every_write_to_its_data_until_run_anyway() {
        let files = TestFiles::new();
        let path = files.root.join("wallet.backup");
        let held = startup_error(lifecycle::FALLBACK_HELD_CODE, "held", false);
        let handle = RuntimeState::failed_for_test(held.clone()).handle();
        handle.update.hold(held.clone());
        type Operation<'a> = Box<dyn Fn(&RuntimeHandle) -> Option<NodeClientError> + 'a>;
        let operations: [(&str, Operation); 5] = [
            ("unlock", Box::new(|h| h.unlock(b"passphrase").err())),
            ("lock", Box::new(|h| h.lock().err())),
            ("create", Box::new(|h| h.create(&path, b"passphrase").err())),
            (
                "migrate",
                Box::new(|h| h.migrate(&path, b"passphrase").err()),
            ),
            (
                "restore",
                Box::new(|h| h.restore(&path, b"passphrase").err()),
            ),
        ];
        for (name, operation) in &operations {
            assert_eq!(operation(&handle), Some(held.clone()), "{name}");
        }
        assert_eq!(fs::read_dir(&files.root).unwrap().count(), 0);
        // A refused unlock is no unlock failure, which would show as the
        // node's phase once the hold ended.
        assert_eq!(handle.update.unlock_failure(), None);

        // After "Run anyway" they are no longer refused for the hold (here
        // the test state's missing data dir stops them).
        assert_eq!(
            handle.run_held_start().unwrap_err().code,
            "data_directory_unavailable"
        );
        for (name, operation) in &operations {
            assert_ne!(
                operation(&handle).map(|error| error.code),
                Some(lifecycle::FALLBACK_HELD_CODE),
                "{name}"
            );
        }
    }

    #[test]
    fn a_held_wallet_may_be_backed_up_and_keeps_its_hold() {
        let files = TestFiles::new();
        let output = files.root.join("wallet.backup");
        let held = startup_error(lifecycle::FALLBACK_HELD_CODE, "held", false);
        let mut state = RuntimeState::failed_for_test(held.clone());
        state.handle.data_dir = Ok(files.root.join("no-wallet-here"));
        let handle = state.handle();
        handle.update.hold(held.clone());
        // No wallet key to read here, so the backup itself fails.
        assert!(handle.backup(&output, b"passphrase").is_err());
        assert!(!output.exists());
        assert!(handle.is_held());
        assert_eq!(
            handle.stored_node_phase(),
            NodePhase::Failed {
                code: held.code,
                retryable: held.retryable,
                message: held.message,
            }
        );
    }

    #[test]
    fn a_held_wallet_opens_no_node_until_run_anyway() {
        let held = startup_error(lifecycle::FALLBACK_HELD_CODE, "held", false);
        let guard = RestartGuard::default();
        guard.hold(held.clone());
        let data_dir = Path::new("held-wallet-data-never-created");
        let refused = start_embedded_node(
            data_dir,
            &NodeRuntimeConfig::default_for_test(),
            None,
            Duration::ZERO,
            &AtomicBool::new(false),
            &guard,
        )
        .err();
        assert_eq!(refused, Some(held.clone()));
        assert!(!data_dir.exists());

        let handle = RuntimeState::failed_for_test(held.clone()).handle();
        assert_eq!(handle.run_held_start().unwrap_err().code, "update_not_held");
        handle.update.hold(held);
        assert!(handle.is_held());
        // Released, then the missing data dir of this test state stops it.
        assert_eq!(
            handle.run_held_start().unwrap_err().code,
            "data_directory_unavailable"
        );
        assert!(!handle.is_held());
    }

    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    fn encrypted_wallet(files: &TestFiles) -> PathBuf {
        let data_dir = files.root.join("wallet");
        cmfd_node::wallet_backup::create_encrypted_wallet(
            &data_dir,
            &files.root.join("wallet.cmfd-backup"),
            COMPILED_NETWORK_PROFILE.network_id,
            PASSPHRASE,
        )
        .unwrap();
        data_dir
    }

    #[test]
    fn only_an_encrypted_key_without_a_passphrase_skips_the_node_open() {
        let files = TestFiles::new();
        let data_dir = files.root.join("plain");
        fs::create_dir(&data_dir).unwrap();
        assert!(!opens_as_locked(&data_dir, None), "missing key");
        fs::write(data_dir.join("wallet.key"), [7; 32]).unwrap();
        assert!(!opens_as_locked(&data_dir, None), "plaintext key");

        let data_dir = encrypted_wallet(&files);
        assert!(opens_as_locked(&data_dir, None));
        assert!(
            !opens_as_locked(&data_dir, Some(PASSPHRASE)),
            "passphrase file"
        );
        // Another process holds the data dir: the open reports that.
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data_dir.join("node.lock"))
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        assert!(!opens_as_locked(&data_dir, None), "data dir held");
        fs2::FileExt::unlock(&lock).unwrap();
        assert!(opens_as_locked(&data_dir, None));
    }

    #[cfg(not(feature = "production-mainnet"))]
    #[test]
    fn an_encrypted_wallet_without_a_passphrase_file_waits_for_unlock_without_opening_the_node() {
        let files = TestFiles::new();
        let data_dir = encrypted_wallet(&files);
        let refused = start_embedded_node(
            &data_dir,
            &NodeRuntimeConfig::default_for_test(),
            None,
            Duration::ZERO,
            &AtomicBool::new(false),
            &RestartGuard::default(),
        )
        .err()
        .expect("a locked wallet does not start its node");
        assert_eq!(refused, NodeError::WalletLocked.client_error());
        // The node open, and with it the model bank pass, never ran.
        assert!(!data_dir.join("blocks.log").exists());
    }

    #[cfg(not(feature = "production-mainnet"))]
    #[test]
    fn a_wrong_passphrase_is_refused_before_the_node_opens() {
        let files = TestFiles::new();
        let mut state = RuntimeState::failed_for_test(wallet_locked_error());
        state.handle.data_dir = Ok(encrypted_wallet(&files));
        let handle = state.handle();
        let refused = handle.unlock(b"wrong horse battery staple").unwrap_err();
        assert_eq!(refused.code, "wallet_authentication_failed");
        assert_eq!(refused.status, 401);
        // Not the node's failure: the start check still sees a locked wallet.
        assert_eq!(handle.update.unlock_failure(), None);
        assert_eq!(handle.node_phase(), handle.stored_node_phase());
        assert!(matches!(
            handle.stored_node_phase(),
            NodePhase::Failed {
                code: "wallet_locked",
                ..
            }
        ));
        assert!(!files.root.join("wallet/blocks.log").exists());
        // Too short a passphrase is refused the same way, as invalid.
        assert_eq!(
            handle.unlock(b"short").unwrap_err().code,
            "wallet_passphrase_invalid"
        );
    }

    #[cfg(not(any(feature = "production-v3-testnet", feature = "production-v4")))]
    #[test]
    fn stopping_the_node_saves_its_index_cache() {
        let files = TestFiles::new();
        let data_dir = files.root.join("node");
        let mut node = Node::open(&data_dir).unwrap();
        let cache = data_dir.join("startup-index.bin");
        let opened = fs::read(&cache).unwrap();
        node.mine_once(
            node.wallet_destination(),
            cmfd_node::unix_time_seconds().unwrap(),
            cmfd_node::DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        // One new record does not refresh the cache yet.
        assert_eq!(fs::read(&cache).unwrap(), opened);
        let mut runtime = RuntimeParts {
            node: NodeAvailability::Ready(Arc::new(Mutex::new(node))),
            ..RuntimeParts::starting()
        };
        stop_runtime_parts(&mut runtime);
        assert_ne!(fs::read(&cache).unwrap(), opened);
        drop(runtime);
        let reopened = Node::open(&data_dir).unwrap();
        let status = reopened.status().unwrap();
        assert!(status.startup_snapshot_used);
        assert!(status.storage_healthy);
        assert_eq!(status.accepted_height, 1);
    }

    #[test]
    fn the_start_check_sees_the_node_phase() {
        assert_eq!(
            RuntimeState::starting_for_test().handle().node_phase(),
            NodePhase::Starting
        );
        let failed = RuntimeState::failed_for_test(wallet_locked_error());
        assert_eq!(
            failed.handle().node_phase(),
            NodePhase::Failed {
                code: "wallet_locked",
                retryable: false,
                message: wallet_locked_error().message,
            }
        );
        // A missing launch file counts after the launch time only once the
        // launch preparation gave up on it.
        let after_launch = cmfd_launch::MAINNET_LAUNCH_UNIX_SECONDS;
        let mut missing =
            RuntimeState::failed_for_test(NodeError::MainnetLaunchRequired.client_error());
        assert!(matches!(
            missing.handle().node_phase_at(after_launch),
            NodePhase::Failed {
                code: "mainnet_launch_required",
                retryable: true,
                ..
            }
        ));
        missing.handle.launch =
            Arc::new(launch::LaunchPreparation::failed_for_test("plan is absent"));
        assert!(matches!(
            missing.handle().node_phase_at(after_launch),
            NodePhase::Failed {
                code: "mainnet_launch_required",
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn the_start_check_sees_why_an_unlock_could_not_open_the_node() {
        let locked = RuntimeState::failed_for_test(wallet_locked_error()).handle();
        let error = startup_error("corrupt_block_log", "The block log is damaged.", false);
        locked.update.record_unlock_failure(&error);
        assert_eq!(
            locked.node_phase(),
            NodePhase::Failed {
                code: "corrupt_block_log",
                retryable: false,
                message: error.message.clone(),
            }
        );
        // The wallet itself still shows the lock screen.
        assert_eq!(
            locked.stored_node_phase(),
            NodePhase::Failed {
                code: "wallet_locked",
                retryable: false,
                message: wallet_locked_error().message,
            }
        );
    }

    #[test]
    fn a_resync_is_refused_unless_the_stored_chain_cannot_be_kept() {
        let files = TestFiles::new();
        let log = files.write("blocks.log", b"stored chain");
        let handle = |node| RuntimeHandle {
            inner: Arc::new(Mutex::new(RuntimeParts {
                node,
                ..RuntimeParts::starting()
            })),
            operation: Arc::new(Mutex::new(())),
            stopping: Arc::new(AtomicBool::new(false)),
            update: Arc::default(),
            config: NodeRuntimeConfig::default_for_test(),
            launch: Arc::default(),
            data_dir: Ok(files.root.clone()),
        };
        let other = startup_error("startup_failed", "embedded node unavailable", true);
        let refused = handle(NodeAvailability::Failed(other))
            .resync_chain()
            .unwrap_err();
        assert_eq!(refused.code, "chain_resync_not_needed");
        let starting = handle(NodeAvailability::Starting)
            .resync_chain()
            .unwrap_err();
        assert_eq!(starting.code, "node_starting");
        let stopping = handle(NodeAvailability::Failed(chain_resync_required_error()));
        stopping.stopping.store(true, Ordering::Release);
        assert!(stopping.resync_chain().is_err());
        // Nothing was moved.
        assert_eq!(fs::read(&log).unwrap(), b"stored chain");
        assert_eq!(fs::read_dir(&files.root).unwrap().count(), 1);
    }

    #[test]
    fn the_resync_error_is_stable_and_not_retryable() {
        let error = chain_resync_required_error();
        assert_eq!(error.code, CHAIN_RESYNC_REQUIRED);
        assert!(!error.retryable);
        assert!(error.message.contains("wallet key stays"));
    }

    #[test]
    fn startup_in_progress_is_retryable_and_shutdown_is_idempotent() {
        let state = RuntimeState::starting_for_test();

        let error = match state.node() {
            Ok(_) => panic!("starting runtime unexpectedly exposed a node"),
            Err(error) => error,
        };
        assert_eq!(error.code, "node_starting");
        assert!(error.retryable);
        state.stop_services();
        state.stop_services();
    }

    #[test]
    fn invalid_operator_configuration_is_a_stable_client_error() {
        let error = NodeClientError {
            code: "invalid_p2p_configuration",
            status: 400,
            retryable: false,
            message: "Invalid desktop P2P configuration: unknown wallet argument: --public-peer"
                .to_string(),
        };

        assert_eq!(error.code, "invalid_p2p_configuration");
        assert_eq!(error.status, 400);
        assert!(!error.retryable);
        assert!(error.message.contains("--public-peer"));
    }

    #[test]
    fn catch_up_sources_are_the_current_compiled_relays_each_with_its_provider() {
        use cmfd_node::NetworkProfileKind;
        use cmfd_node::network_profile::{MAINNET_BOOTSTRAP_RELAYS_IPV4, PRODUCTION_RC_SEED_IPV4};

        let source = |addr: &str, group| CatchUpSource {
            addr: addr.parse().unwrap(),
            group,
        };
        let expected = vec![
            source("173.249.35.251:29444", 0),
            source("209.145.48.36:29444", 0),
            source("13.140.66.6:29444", 1),
            source("107.214.187.2:29444", 2),
        ];
        let mainnet = NetworkProfile {
            kind: NetworkProfileKind::Mainnet,
            p2p_port: 29_444,
            ..RCNET1_PROFILE
        };
        assert_eq!(catch_up_sources_from(&mainnet.bootstrap_peers()), expected);
        let mut compiled = vec![SocketAddr::new(IpAddr::V4(PRODUCTION_RC_SEED_IPV4), 29_444)];
        compiled.extend(
            MAINNET_BOOTSTRAP_RELAYS_IPV4
                .iter()
                .map(|relay| SocketAddr::new(IpAddr::V4(*relay), 29_444)),
        );
        assert_eq!(catch_up_sources_from(&compiled), expected);
        // Any other IP is a group of its own, one group per IP.
        let groups = catch_up_sources_from(&[
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:1".parse().unwrap(),
            "10.0.0.1:2".parse().unwrap(),
            "13.140.66.6:1".parse().unwrap(),
            "107.214.187.2:1".parse().unwrap(),
        ])
        .iter()
        .map(|source| source.group)
        .collect::<Vec<_>>();
        assert_eq!(groups, [3, 4, 3, 1, 2]);

        // Other networks dial the seed alone, which cannot turn the catch-up
        // on. The wallet reads the compiled peers, never the configured ones.
        assert_eq!(
            catch_up_sources_from(&RCNET1_PROFILE.bootstrap_peers()).len(),
            1
        );
        assert_eq!(
            catch_up_sources_from(&DEVNET_PROFILE.bootstrap_peers()).len(),
            1
        );
        assert_eq!(
            catch_up_sources(),
            catch_up_sources_from(&COMPILED_NETWORK_PROFILE.bootstrap_peers())
        );
    }

    #[test]
    fn mainnet_catch_up_keeps_independent_providers_after_a_relay_outage() {
        use cmfd_node::NetworkProfileKind;

        let mainnet = NetworkProfile {
            kind: NetworkProfileKind::Mainnet,
            p2p_port: 29_444,
            ..RCNET1_PROFILE
        };
        let sources = catch_up_sources_from(&mainnet.bootstrap_peers());
        let retired: SocketAddr = "88.198.110.195:29444".parse().unwrap();
        assert!(sources.iter().all(|source| source.addr != retired));

        // Removing any one endpoint must leave agreement available from
        // different providers, rather than require the retired relay.
        for unavailable in &sources {
            let groups = sources
                .iter()
                .filter(|source| source.addr != unavailable.addr)
                .map(|source| source.group)
                .collect::<std::collections::BTreeSet<_>>();
            assert!(groups.len() >= 2, "unavailable: {}", unavailable.addr);
        }
        // Both Contabo locations are one provider; either surviving
        // independent relay supplies the second provider.
        let contabo = "173.249.35.251:29444".parse().unwrap();
        let st_louis = "209.145.48.36:29444".parse().unwrap();
        let group = |addr| {
            sources
                .iter()
                .find(|source| source.addr == addr)
                .unwrap()
                .group
        };
        assert_eq!(group(contabo), group(st_louis));
        for independent in ["13.140.66.6:29444", "107.214.187.2:29444"] {
            assert_ne!(group(contabo), group(independent.parse().unwrap()));
        }
    }

    #[test]
    fn full_never_turns_the_catch_up_on_and_standard_never_fails_startup() {
        assert!(!apply_work_check(
            WorkCheck::Full,
            || panic!("full reads no sources"),
            |_| panic!("full never calls the setter"),
        ));
        let mut given = None;
        assert!(apply_work_check(
            WorkCheck::Standard,
            catch_up_sources,
            |sources| {
                given = Some(sources);
                Ok(true)
            },
        ));
        assert_eq!(given, Some(catch_up_sources()));
        assert!(!apply_work_check(
            WorkCheck::Standard,
            catch_up_sources,
            |_| Ok(false)
        ));
        assert!(!apply_work_check(
            WorkCheck::Standard,
            catch_up_sources,
            |_| Err(NodeError::SharedNodePoisoned)
        ));
    }

    #[cfg(not(any(feature = "production-v3-testnet", feature = "production-v4")))]
    #[test]
    fn a_one_peer_build_runs_strict() {
        let files = TestFiles::new();
        let mut node = Node::open(files.root.join("node")).unwrap();
        assert_eq!(catch_up_sources().len(), 1);
        assert!(!node.enable_wallet_catch_up(catch_up_sources()).unwrap());
        assert!(!apply_work_check(
            WorkCheck::Standard,
            catch_up_sources,
            |sources| { node.enable_wallet_catch_up(sources) }
        ));
        let status = serde_json::to_value(node.status().unwrap()).unwrap();
        assert!(
            status["work_rule"].is_null() || status["work_rule"].get("wallet_catch_up").is_none(),
            "{status}"
        );
    }

    #[test]
    fn wallet_storage_identity_is_network_specific() {
        let root = Path::new("wallet-data-root");
        assert_eq!(wallet_data_dir(root, DEVNET_PROFILE), root.join("devnet-0"));
        assert_eq!(wallet_data_dir(root, RCNET1_PROFILE), root.join("rcnet-1"));
        assert_ne!(
            wallet_data_dir(root, DEVNET_PROFILE),
            wallet_data_dir(root, RCNET1_PROFILE)
        );
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn production_v3_no_argument_package_missing_and_partial_overrides_fail_closed() {
        let files = TestFiles::new();
        let empty = base_config(PRODUCTION_V3_TESTNET_PROFILE);
        let error = security_error(prepare_for_test(
            PRODUCTION_V3_TESTNET_PROFILE,
            &empty,
            &files.root,
        ));
        assert_eq!(error.code, "production_v3_file_unavailable");
        assert!(
            error
                .message
                .contains("ProductionV3 Testnet-1 (ProductionV3)")
        );

        let mut partial = base_config(PRODUCTION_V3_TESTNET_PROFILE);
        partial.production_v3.record_v2 = Some(files.write("only-record.json", b"record"));
        let error = security_error(prepare_for_test(
            PRODUCTION_V3_TESTNET_PROFILE,
            &partial,
            &files.root,
        ));
        assert_eq!(error.code, "production_v3_configuration_missing");
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn production_v3_no_argument_package_layout_resolves_fixed_sidecars() {
        let files = TestFiles::new();
        let artifact_root = files
            .root
            .join(cmfd_node::PRODUCTION_V3_PACKAGE_ARTIFACT_DIRECTORY);
        fs::create_dir(&artifact_root).unwrap();
        files.write(
            &format!("cmfd-proof-worker{}", std::env::consts::EXE_SUFFIX),
            b"bounded worker fixture",
        );
        fs::write(
            artifact_root.join(cmfd_node::PRODUCTION_V3_PACKAGE_RECORD_V2),
            b"bounded Record V2 fixture",
        )
        .unwrap();

        let config = base_config(PRODUCTION_V3_TESTNET_PROFILE);
        #[cfg(target_os = "linux")]
        let config = {
            // Linux ProductionV3 deliberately has no packaged cgroup defaults;
            // the operator-supplied measured limits remain explicit even when
            // artifact sidecar paths are resolved from the package layout.
            let mut config = config;
            config.production_v3.verifier_cpu_quota_us = Some(100_000);
            config.production_v3.verifier_cpu_period_us = Some(100_000);
            config.production_v3.verifier_pids_limit = Some(16);
            config
        };
        let security =
            prepare_for_test(PRODUCTION_V3_TESTNET_PROFILE, &config, &files.root).unwrap();
        let record = security.production_v3_record.unwrap();
        // The resolved path must be the plain form: the trusted ceremony
        // filesystem rejects the `\\?\` verbatim syntax `fs::canonicalize`
        // produces on Windows.
        assert_eq!(
            record.record_v2,
            cmfd_node::plain_package_path(
                fs::canonicalize(artifact_root.join(cmfd_node::PRODUCTION_V3_PACKAGE_RECORD_V2))
                    .unwrap()
            )
        );
        assert_eq!(
            security.verifier_worker.unwrap().worker_sha256,
            sha256(b"bounded worker fixture")
        );
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn production_v3_rejects_relative_paths_without_echoing_them() {
        let files = TestFiles::new();
        let mut config = base_config(PRODUCTION_V3_TESTNET_PROFILE);
        config.production_v3 = config::ProductionV3RuntimeOptions {
            bank: None,
            manifest: None,
            record_v2: Some(PathBuf::from("private/record-v2.json")),
            verifier_worker: Some(PathBuf::from("private/worker.exe")),
            verifier_worker_sha256: Some(sha256(b"bounded worker fixture")),
            verifier_startup_timeout_ms: None,
            verifier_timeout_ms: None,
            verifier_memory_bytes: None,
            verifier_cpu_quota_us: None,
            verifier_cpu_period_us: None,
            verifier_pids_limit: None,
        };

        let error = security_error(prepare_for_test(
            PRODUCTION_V3_TESTNET_PROFILE,
            &config,
            &files.root,
        ));
        assert_eq!(error.code, "production_v3_path_invalid");
        assert!(!error.message.contains("private"));
        assert!(!error.message.contains("record-v2.json"));
    }

    #[cfg(not(feature = "production-v4"))]
    #[test]
    fn production_v3_rejects_a_worker_hash_mismatch_without_leaking_its_path() {
        let files = TestFiles::new();
        let config = configured_rc(&files, [0; 32]);

        let error = security_error(prepare_for_test(
            PRODUCTION_V3_TESTNET_PROFILE,
            &config,
            &files.root,
        ));
        assert_eq!(error.code, "proof_verifier_identity_mismatch");
        assert!(
            !error
                .message
                .contains(files.root.to_string_lossy().as_ref())
        );
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn production_v3_happy_path_is_canonical_and_passed_to_the_node_gate() {
        let files = TestFiles::new();
        let worker_bytes = b"bounded worker fixture";
        let config = configured_rc(&files, sha256(worker_bytes));
        let security =
            prepare_for_test(PRODUCTION_V3_TESTNET_PROFILE, &config, &files.root).unwrap();
        let record = security.production_v3_record.as_ref().unwrap();
        assert!(record.record_v2.is_absolute());
        let worker = security.verifier_worker.as_ref().unwrap();
        assert!(worker.worker_executable.is_absolute());
        assert_eq!(worker.production_v3_record.as_ref(), Some(record));
        assert_eq!(worker.startup_timeout, Duration::from_millis(1_234));
        assert_eq!(worker.timeout, Duration::from_millis(1_234));
        assert_eq!(worker.memory_limit_bytes, 4_096);

        let data_dir = files.root.join("rcnet-data");
        open_with_record_gate(
            &data_dir,
            PRODUCTION_V3_TESTNET_PROFILE,
            &security,
            |received_dir, received| {
                assert_eq!(received_dir, data_dir);
                assert_eq!(received, Some(record));
                Ok(())
            },
        )
        .unwrap();
    }

    #[cfg(not(feature = "production-v4"))]
    #[test]
    fn production_record_gate_failures_are_sanitized_and_fail_closed() {
        let security = PreparedNodeSecurity {
            production_v3_record: Some(ProductionV3VerifierRecord {
                record_v2: PathBuf::from("C:\\private\\record-v2.json"),
                expected_file: cmfd_consensus::FileIdentity {
                    bytes: 1,
                    blake3: [1; 32],
                    sha256: [2; 32],
                },
            }),
            production_v4_artifacts: None,
            verifier_worker: None,
        };
        for node_error in [
            NodeError::ProductionV3ArtifactPinsMissing,
            NodeError::ProductionV3ArtifactIdentityMismatch("Record V2"),
        ] {
            let error = open_with_record_gate(
                Path::new("unused"),
                PRODUCTION_V3_TESTNET_PROFILE,
                &security,
                |_, record| {
                    assert!(record.is_some());
                    Err::<(), _>(node_error)
                },
            )
            .unwrap_err();
            assert_eq!(error.code, "proof_verifier_configuration");
            assert!(
                error
                    .message
                    .contains("ProductionV3 Testnet-1 (ProductionV3)")
            );
            assert!(!error.message.contains("C:\\private"));
        }
    }

    #[test]
    fn devnet_runtime_keeps_the_original_no_artifact_startup_path() {
        let config = base_config(DEVNET_PROFILE);
        let security = prepare_for_test(DEVNET_PROFILE, &config, Path::new("unused")).unwrap();
        assert!(security.production_v3_record.is_none());
        assert!(security.production_v4_artifacts.is_none());
        assert!(security.verifier_worker.is_none());
        assert!(!command_help_text_for_profile(DEVNET_PROFILE).contains("ProductionV3 startup"));
        assert!(command_help_text_for_profile(DEVNET_PROFILE).contains("[--no-auto-update]"));
        assert!(command_help_text_for_profile(DEVNET_PROFILE).contains("  --no-auto-update  "));
        assert!(command_help_text_for_profile(RCNET1_PROFILE).contains("ProductionV4 startup"));

        let result = open_with_record_gate(
            Path::new("devnet-data"),
            DEVNET_PROFILE,
            &security,
            |_, artifacts| {
                assert!(artifacts.is_none());
                Ok("devnet")
            },
        )
        .unwrap();
        assert_eq!(result, "devnet");
    }

    #[test]
    fn devnet_rejects_production_inputs_instead_of_silently_ignoring_them() {
        let files = TestFiles::new();
        let config = configured_rc(&files, sha256(b"bounded worker fixture"));
        let error = security_error(prepare_for_test(DEVNET_PROFILE, &config, &files.root));
        assert_eq!(error.code, "production_v3_configuration_unexpected");
    }

    #[test]
    fn production_v4_package_layout_is_distinct_and_rejects_v3_options() {
        let files = TestFiles::new();
        let profile = cmfd_node::PRODUCTION_V4_TESTNET_PROFILE;
        let config = base_config(profile);
        let security = prepare_for_test(profile, &config, &files.root).unwrap();
        let artifacts = security.production_v4_artifacts.unwrap();
        let expected_root = files
            .root
            .join(cmfd_node::PRODUCTION_V4_PACKAGE_ARTIFACT_DIRECTORY);
        assert_eq!(
            artifacts.bank,
            expected_root.join(cmfd_node::PRODUCTION_V4_PACKAGE_BANK)
        );
        assert_eq!(
            artifacts.fixed_record,
            expected_root.join(cmfd_node::PRODUCTION_V4_PACKAGE_FIXED_RECORD)
        );

        let configured = configured_rc(&files, sha256(b"bounded worker fixture"));
        let error = security_error(prepare_for_test(profile, &configured, &files.root));
        assert_eq!(error.code, "production_v4_configuration_unexpected");
    }

    #[cfg(feature = "production-v4")]
    #[test]
    fn production_v4_missing_artifacts_explain_runtime_setup() {
        let error =
            sanitize_node_startup_error(RCNET1_PROFILE, NodeError::ProductionV4ArtifactsMissing);
        assert_eq!(error.code, "production_v4_artifacts_missing");
        assert!(error.message.contains("production-v4/MODEL-V2.bank"));
        assert!(
            error
                .message
                .contains("FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json")
        );
        assert!(error.message.contains("RCNet runtime preparation"));
    }
}
