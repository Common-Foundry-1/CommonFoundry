use std::fs;
use std::net::TcpListener;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use cmfd_node::p2p::{InboundPeerHandle, spawn_inbound_listener_with_policy};
use cmfd_node::peer::PeerLimits;
use cmfd_node::wallet_backup::{
    WalletBackupError, WalletKeyStorage, create_encrypted_wallet_backup,
    inspect_wallet_key_storage, migrate_plaintext_wallet_key, read_wallet_passphrase_file,
    restore_encrypted_wallet_backup,
};
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, NetworkProfile, Node, NodeClientError, NodeError,
    ProductionV3VerifierRecord, ProductionV4VerifierArtifacts, ProofProfile,
    compiled_production_v3_record_identity, compiled_production_v3_worker_sha256,
    production_v3_package_layout, production_v4_package_artifacts,
};
use cmfd_proof_worker::{ProofWorkerError, VerifierWorkerConfig, VerifierWorkerError};
use tauri::{App, Manager, Runtime};

use crate::mining::MiningManager;
#[cfg(feature = "production-v4")]
use crate::mining::ProductionV4PoolSearchAssets;

mod config;
mod peers;

pub(crate) use config::{ConfigError, NodeRuntimeConfig, ProcessCommand};
use config::{
    DEFAULT_PROOF_VERIFIER_MEMORY_BYTES, DEFAULT_PROOF_VERIFIER_STARTUP_TIMEOUT_MS,
    DEFAULT_PROOF_VERIFIER_TIMEOUT_MS,
};
pub(crate) use peers::{PeerManager, PeerSettings, UpdatePeerSettingsRequest};

const STATIC_PEER_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
enum NodeAvailability {
    Starting,
    Ready(Arc<Mutex<Node>>),
    Failed(NodeClientError),
}

struct ServiceHandles {
    inbound: InboundPeerHandle,
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
}

#[derive(Clone)]
pub(crate) struct RuntimeHandle {
    inner: Arc<Mutex<RuntimeParts>>,
    operation: Arc<Mutex<()>>,
    stopping: Arc<AtomicBool>,
    config: NodeRuntimeConfig,
    data_dir: Result<PathBuf, NodeClientError>,
}

pub struct RuntimeState {
    handle: RuntimeHandle,
    // Held for the life of the process: dropping it stops the non-blocking
    // file writer from flushing buffered log lines.
    _log_guard: Option<cmfd_node::logging::WorkerGuard>,
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
}

impl RuntimeParts {
    fn starting() -> Self {
        Self {
            node: NodeAvailability::Starting,
            mining: None,
            peers: None,
            services: None,
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
        }
    }

    fn failed(error: NodeClientError) -> Self {
        Self {
            node: NodeAvailability::Failed(error),
            mining: None,
            peers: None,
            services: None,
        }
    }
}

impl RuntimeState {
    pub fn start<R: Runtime>(app: &App<R>, config: NodeRuntimeConfig) -> Self {
        let allow = config.allow_public_peers;
        let peers = config.peers.len();
        eprintln!(
            "Common Foundry Wallet ({}, {}) node starting on {} with {} configured peer(s), allow_public_peers={allow}",
            COMPILED_NETWORK_PROFILE.short_name(),
            COMPILED_NETWORK_PROFILE.proof.profile_name(),
            config.p2p_bind,
            peers
        );
        let data_dir = app
            .path()
            .app_local_data_dir()
            .map(|root| wallet_data_dir(&root, COMPILED_NETWORK_PROFILE))
            .map_err(|_| {
                startup_error(
                    "data_directory_unavailable",
                    "The desktop wallet could not resolve its local data directory.",
                    false,
                )
            });
        let log_guard = data_dir
            .as_ref()
            .ok()
            .map(|path| cmfd_node::logging::init_tracing(path, config.verbose));
        let handle = RuntimeHandle {
            inner: Arc::new(Mutex::new(match &data_dir {
                Ok(_) => RuntimeParts::starting(),
                Err(error) => RuntimeParts::failed(error.clone()),
            })),
            operation: Arc::new(Mutex::new(())),
            stopping: Arc::new(AtomicBool::new(false)),
            config: config.clone(),
            data_dir: data_dir.clone(),
        };
        if let Ok(startup_data_dir) = data_dir {
            let startup_inner = Arc::clone(&handle.inner);
            let startup_stopping = Arc::clone(&handle.stopping);
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
                && let Ok(mut runtime) = handle.inner.lock()
            {
                *runtime = RuntimeParts::failed(startup_error(
                    "node_startup_unavailable",
                    "The embedded node startup worker could not be created. Reopen the wallet and try again.",
                    true,
                ));
            }
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
        if let Ok(mut runtime) = self.handle.inner.lock() {
            stop_runtime_parts(&mut runtime);
        }
    }

    pub(crate) fn handle(&self) -> RuntimeHandle {
        self.handle.clone()
    }

    #[cfg(test)]
    fn failed_for_test(error: NodeClientError) -> Self {
        Self {
            handle: RuntimeHandle {
                inner: Arc::new(Mutex::new(RuntimeParts::failed(error))),
                operation: Arc::new(Mutex::new(())),
                stopping: Arc::new(AtomicBool::new(false)),
                config: NodeRuntimeConfig::default_for_test(),
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
    fn starting_for_test() -> Self {
        Self {
            handle: RuntimeHandle {
                inner: Arc::new(Mutex::new(RuntimeParts::starting())),
                operation: Arc::new(Mutex::new(())),
                stopping: Arc::new(AtomicBool::new(false)),
                config: NodeRuntimeConfig::default_for_test(),
                data_dir: Ok(PathBuf::from("test-wallet-data")),
            },
            _log_guard: None,
        }
    }
}

impl RuntimeHandle {
    pub(crate) fn custody_status(&self) -> Result<WalletCustodyStatus, NodeClientError> {
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
        self.custody_status_inner()
    }

    fn custody_status_inner(&self) -> Result<WalletCustodyStatus, NodeClientError> {
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
            NodeAvailability::Failed(_) => None,
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
        })
    }

    pub(crate) fn unlock(&self, passphrase: &[u8]) -> Result<WalletCustodyStatus, NodeClientError> {
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
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
        let started = start_embedded_node(data_dir, &self.config, Some(passphrase))?;
        let mut runtime = self.inner.lock().map_err(|_| runtime_state_error())?;
        *runtime = RuntimeParts::ready(started);
        drop(runtime);
        self.custody_status_inner()
    }

    pub(crate) fn lock(&self) -> Result<WalletCustodyStatus, NodeClientError> {
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
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
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        self.stop_and_mark_locked()?;
        create_encrypted_wallet_backup(
            data_dir,
            output,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase,
        )
        .map_err(custody_error)?;
        self.custody_status_inner()
    }

    pub(crate) fn migrate(
        &self,
        backup_output: &Path,
        passphrase: &[u8],
    ) -> Result<WalletCustodyStatus, NodeClientError> {
        require_absolute_custody_path(backup_output)?;
        let _operation = self.operation.lock().map_err(|_| runtime_state_error())?;
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
        let data_dir = self.data_dir.as_ref().map_err(Clone::clone)?;
        self.stop_and_mark_locked()?;
        restore_encrypted_wallet_backup(
            input,
            data_dir,
            COMPILED_NETWORK_PROFILE.network_id,
            passphrase,
        )
        .map_err(custody_error)?;
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
}

fn start_embedded_node(
    data_dir: &Path,
    config: &NodeRuntimeConfig,
    wallet_passphrase: Option<&[u8]>,
) -> Result<EmbeddedNode, NodeClientError> {
    let security = prepare_node_security(COMPILED_NETWORK_PROFILE, config)?;
    let PreparedNodeSecurity {
        production_v3_record,
        production_v4_artifacts,
        verifier_worker,
    } = security;
    let node = Node::open_with_runtime_security_and_wallet_passphrase(
        data_dir,
        production_v3_record.as_ref(),
        production_v4_artifacts.as_ref(),
        verifier_worker.as_ref(),
        wallet_passphrase,
    )
    .map_err(|error| sanitize_node_startup_error(COMPILED_NETWORK_PROFILE, error))?;
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
    let shared = Arc::new(Mutex::new(node));
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
    let inbound = spawn_inbound_listener_with_policy(
        Arc::clone(&shared),
        listener,
        limits,
        config.address_policy(),
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
    ) {
        Ok(peers) => Arc::new(peers),
        Err(error) => {
            let _ = inbound.stop();
            return Err(error);
        }
    };
    Ok(EmbeddedNode {
        node: shared,
        peers,
        services: ServiceHandles { inbound },
        #[cfg(feature = "production-v4")]
        production_v4_pool_search,
    })
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
    }
    if let NodeAvailability::Ready(node) = &runtime.node
        && let Ok(node) = node.lock()
    {
        node.shutdown_proof_verifier();
    }
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
        "Opening wallet: authenticating proof inputs and replaying local chain history.",
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
            "Usage: common-foundry-wallet [--help|--version] [--p2p-bind <addr>] [--peer <addr> ...] [--allow-public-peers] [--wallet-passphrase-file <path>] [-v...]\n",
            "Arguments:\n",
            "  --help (-h)             Show this help\n",
            "  --version (-V)          Print version\n",
            "  -v, --verbose           Increase console verbosity (repeatable)\n",
            "  --p2p-bind <addr>       Local P2P bind address (default {})\n",
            "  --peer <addr>           Public or private outbound peer (repeatable)\n",
            "  --allow-public-peers     Allow public peers for explicit --peer entries\n",
            "                          (the default bootstrap peer is always added if no --peer is configured)\n",
            "  --wallet-passphrase-file <path> Unlock or create encrypted wallet.key\n",
        ),
        profile.name,
        profile.proof.profile_name(),
        profile.p2p_address(),
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
            wallet_passphrase_file: None,
            production_v3: config::ProductionV3RuntimeOptions::default(),
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
    fn wallet_storage_identity_is_network_specific() {
        let root = Path::new("wallet-data-root");
        assert_eq!(wallet_data_dir(root, DEVNET_PROFILE), root.join("devnet-0"));
        assert_eq!(wallet_data_dir(root, RCNET1_PROFILE), root.join("rcnet-1"));
        assert_ne!(
            wallet_data_dir(root, DEVNET_PROFILE),
            wallet_data_dir(root, RCNET1_PROFILE)
        );
    }

    #[cfg(not(feature = "production-v4"))]
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

    #[cfg(not(feature = "production-v4"))]
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

    #[cfg(not(feature = "production-v4"))]
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

    #[cfg(not(feature = "production-v4"))]
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
                expected_file: cmfd_consensus::dory_v3_model_ceremony_transcript::FileIdentity {
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
}
