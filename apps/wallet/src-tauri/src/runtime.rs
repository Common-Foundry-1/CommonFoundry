use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cmfd_node::p2p::{InboundPeerHandle, spawn_inbound_listener_with_policy};
use cmfd_node::peer::PeerLimits;
use cmfd_node::{
    COMPILED_NETWORK_PROFILE, NetworkProfile, Node, NodeClientError, NodeError, ProofProfile,
    compiled_production_v3_worker_sha256, production_v3_package_layout,
};
use cmfd_proof_worker::{
    ProductionV3VerifierArtifacts, ProofWorkerError, VerifierWorkerConfig, VerifierWorkerError,
};
use tauri::{App, Manager, Runtime};

use crate::mining::MiningManager;

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
    log_guard: cmfd_node::logging::WorkerGuard,
}

struct PreparedNodeSecurity {
    production_v3_artifacts: Option<ProductionV3VerifierArtifacts>,
    verifier_worker: Option<VerifierWorkerConfig>,
}

pub struct RuntimeState {
    node: NodeAvailability,
    mining: Option<Arc<MiningManager>>,
    peers: Option<Arc<PeerManager>>,
    services: Mutex<Option<ServiceHandles>>,
    // Held for the life of the process: dropping it stops the non-blocking
    // file writer from flushing buffered log lines.
    _log_guard: Option<cmfd_node::logging::WorkerGuard>,
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
        match start_embedded_node(app, config) {
            Ok(started) => Self {
                mining: Some(Arc::new(MiningManager::new(Arc::clone(&started.node)))),
                node: NodeAvailability::Ready(started.node),
                peers: Some(started.peers),
                services: Mutex::new(Some(started.services)),
                _log_guard: Some(started.log_guard),
            },
            Err(error) => Self {
                node: NodeAvailability::Failed(error),
                mining: None,
                peers: None,
                services: Mutex::new(None),
                _log_guard: None,
            },
        }
    }

    pub fn node(&self) -> Result<Arc<Mutex<Node>>, NodeClientError> {
        match &self.node {
            NodeAvailability::Ready(node) => Ok(Arc::clone(node)),
            NodeAvailability::Failed(error) => Err(error.clone()),
        }
    }

    pub fn mining(&self) -> Result<Arc<MiningManager>, NodeClientError> {
        self.mining.clone().ok_or_else(|| match &self.node {
            NodeAvailability::Failed(error) => error.clone(),
            NodeAvailability::Ready(_) => startup_error(
                "mining_manager_unavailable",
                "The desktop mining service is unavailable. Reopen the wallet.",
                true,
            ),
        })
    }

    pub fn peers(&self) -> Result<Arc<PeerManager>, NodeClientError> {
        self.peers.clone().ok_or_else(|| match &self.node {
            NodeAvailability::Failed(error) => error.clone(),
            NodeAvailability::Ready(_) => startup_error(
                "peer_manager_unavailable",
                "The desktop peer service is unavailable. Reopen the wallet.",
                true,
            ),
        })
    }

    pub fn stop_services(&self) {
        if let NodeAvailability::Ready(node) = &self.node
            && let Ok(node) = node.lock()
        {
            node.shutdown_proof_verifier();
        }
        if let Some(mining) = &self.mining {
            mining.stop_for_shutdown();
        }
        if let Some(peers) = &self.peers {
            peers.stop();
        }
        let services = self
            .services
            .lock()
            .ok()
            .and_then(|mut services| services.take());
        if let Some(services) = services {
            let _ = services.inbound.stop();
        }
    }

    #[cfg(test)]
    fn failed_for_test(error: NodeClientError) -> Self {
        Self {
            node: NodeAvailability::Failed(error),
            mining: None,
            peers: None,
            services: Mutex::new(None),
            _log_guard: None,
        }
    }
}

fn start_embedded_node<R: Runtime>(
    app: &App<R>,
    config: NodeRuntimeConfig,
) -> Result<EmbeddedNode, NodeClientError> {
    let security = prepare_node_security(COMPILED_NETWORK_PROFILE, &config)?;
    let app_data_root = app.path().app_local_data_dir().map_err(|_| {
        startup_error(
            "data_directory_unavailable",
            "The desktop wallet could not resolve its local data directory.",
            false,
        )
    })?;
    let data_dir = wallet_data_dir(&app_data_root, COMPILED_NETWORK_PROFILE);
    let log_guard = cmfd_node::logging::init_tracing(&data_dir, config.verbose);
    let PreparedNodeSecurity {
        production_v3_artifacts,
        verifier_worker,
    } = security;
    let node = match (production_v3_artifacts.as_ref(), verifier_worker) {
        (Some(artifacts), Some(worker)) => {
            Node::open_with_artifacts_and_verifier_worker(&data_dir, Some(artifacts), worker)
        }
        (None, None) => Node::open_with_artifacts(&data_dir, None),
        _ => Err(NodeError::ProofVerifierProfileMismatch),
    }
    .map_err(|error| sanitize_node_startup_error(COMPILED_NETWORK_PROFILE, error))?;
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
        &config,
        &data_dir,
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
        log_guard,
    })
}

fn prepare_node_security(
    profile: NetworkProfile,
    config: &NodeRuntimeConfig,
) -> Result<PreparedNodeSecurity, NodeClientError> {
    if profile.proof != ProofProfile::ProductionV3 {
        return prepare_node_security_with_package(profile, config, Path::new("."), None);
    }
    let package_executable = std::env::current_exe().map_err(|_| {
        startup_error(
            "production_v3_package_unavailable",
            "The wallet could not resolve its signed package directory.",
            false,
        )
    })?;
    let expected_worker_sha256 = Some(
        compiled_production_v3_worker_sha256()
            .map_err(|error| sanitize_node_startup_error(profile, error))?,
    );
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
                production_v3_artifacts: None,
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
            let path_override_count = [
                options.bank.as_ref(),
                options.manifest.as_ref(),
                options.record_v2.as_ref(),
                options.verifier_worker.as_ref(),
            ]
            .into_iter()
            .filter(|value| value.is_some())
            .count();
            let (bank, manifest, record_v2, verifier_worker) = if path_override_count == 0 {
                let layout = production_v3_package_layout(package_executable)
                    .map_err(|error| sanitize_node_startup_error(profile, error))?;
                (
                    layout.artifacts.bank,
                    layout.artifacts.manifest,
                    layout.artifacts.record_v2,
                    layout.worker,
                )
            } else if path_override_count == 4 {
                (
                    options.bank.clone().expect("all four paths were counted"),
                    options
                        .manifest
                        .clone()
                        .expect("all four paths were counted"),
                    options
                        .record_v2
                        .clone()
                        .expect("all four paths were counted"),
                    options
                        .verifier_worker
                        .clone()
                        .expect("all four paths were counted"),
                )
            } else {
                return Err(startup_error(
                    "production_v3_configuration_missing",
                    format!(
                        "{} ({}) requires either the complete packaged sidecar layout or all four explicit artifact and worker paths.",
                        profile.short_name(),
                        profile.proof.profile_name()
                    ),
                    false,
                ));
            };

            let artifacts = ProductionV3VerifierArtifacts {
                bank: canonical_runtime_file(profile, "model bank", &bank)?,
                manifest: canonical_runtime_file(profile, "model-bank manifest", &manifest)?,
                record_v2: canonical_runtime_file(profile, "Record V2", &record_v2)?,
            };
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
                production_v3_artifacts: Some(artifacts.clone()),
            };
            worker
                .validate_executable()
                .map_err(|error| sanitize_worker_configuration_error(profile, error))?;

            Ok(PreparedNodeSecurity {
                production_v3_artifacts: Some(artifacts),
                verifier_worker: Some(worker),
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
    let canonical = fs::canonicalize(configured).map_err(|_| {
        startup_error(
            "production_v3_file_unavailable",
            format!(
                "{} ({}) could not open the configured {component} file.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        )
    })?;
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
fn open_with_artifact_gate<T>(
    data_dir: &Path,
    profile: NetworkProfile,
    security: &PreparedNodeSecurity,
    open: impl FnOnce(&Path, Option<&ProductionV3VerifierArtifacts>) -> Result<T, NodeError>,
) -> Result<T, NodeClientError> {
    open(data_dir, security.production_v3_artifacts.as_ref())
        .map_err(|error| sanitize_node_startup_error(profile, error))
}

fn sanitize_node_startup_error(profile: NetworkProfile, error: NodeError) -> NodeClientError {
    let client = error.client_error();
    if profile.proof != ProofProfile::ProductionV3 {
        return client;
    }
    match client.code {
        "production_v3_unavailable" => startup_error(
            client.code,
            format!(
                "{} ({}) cannot start because this wallet build does not include the ProductionV3 verifier.",
                profile.short_name(),
                profile.proof.profile_name()
            ),
            false,
        ),
        "proof_verifier_configuration" => startup_error(
            client.code,
            format!(
                "{} ({}) rejected the configured model bank, manifest, Record V2, or proof-verifier identity. Verify the RC package and launch settings.",
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
            "Usage: common-foundry-wallet [--help|--version] [--p2p-bind <addr>] [--peer <addr> ...] [--allow-public-peers] [-v...]\n",
            "Arguments:\n",
            "  --help (-h)             Show this help\n",
            "  --version (-V)          Print version\n",
            "  -v, --verbose           Increase console verbosity (repeatable)\n",
            "  --p2p-bind <addr>       Local P2P bind address (default {})\n",
            "  --peer <addr>           Public or private outbound peer (repeatable)\n",
            "  --allow-public-peers     Allow public peers for explicit --peer entries\n",
            "                          (the default bootstrap peer is always added if no --peer is configured)\n",
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
                "  --production-v3-bank <path>                 Authenticated production model bank\n",
                "  --production-v3-manifest <path>             Canonical model-bank manifest\n",
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
    use cmfd_node::{DEVNET_PROFILE, RCNET1_PROFILE};
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
        let mut config = base_config(RCNET1_PROFILE);
        config.production_v3 = config::ProductionV3RuntimeOptions {
            bank: Some(files.write("model.bank", b"bounded model bank fixture")),
            manifest: Some(files.write("model.manifest.json", b"bounded manifest fixture")),
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

    #[test]
    fn production_v3_no_argument_package_missing_and_partial_overrides_fail_closed() {
        let files = TestFiles::new();
        let empty = base_config(RCNET1_PROFILE);
        let error = security_error(prepare_for_test(RCNET1_PROFILE, &empty, &files.root));
        assert_eq!(error.code, "production_v3_file_unavailable");
        assert!(error.message.contains("RCNet-1 (ProductionV3)"));

        let mut partial = base_config(RCNET1_PROFILE);
        partial.production_v3.bank = Some(files.write("only.bank", b"bank"));
        let error = security_error(prepare_for_test(RCNET1_PROFILE, &partial, &files.root));
        assert_eq!(error.code, "production_v3_configuration_missing");
    }

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
            artifact_root.join(cmfd_node::PRODUCTION_V3_PACKAGE_BANK),
            b"bounded model bank fixture",
        )
        .unwrap();
        fs::write(
            artifact_root.join(cmfd_node::PRODUCTION_V3_PACKAGE_MANIFEST),
            b"bounded manifest fixture",
        )
        .unwrap();
        fs::write(
            artifact_root.join(cmfd_node::PRODUCTION_V3_PACKAGE_RECORD_V2),
            b"bounded Record V2 fixture",
        )
        .unwrap();

        let security =
            prepare_for_test(RCNET1_PROFILE, &base_config(RCNET1_PROFILE), &files.root).unwrap();
        let artifacts = security.production_v3_artifacts.unwrap();
        assert_eq!(
            artifacts.bank,
            fs::canonicalize(artifact_root.join(cmfd_node::PRODUCTION_V3_PACKAGE_BANK)).unwrap()
        );
        assert_eq!(
            security.verifier_worker.unwrap().worker_sha256,
            sha256(b"bounded worker fixture")
        );
    }

    #[test]
    fn production_v3_rejects_relative_paths_without_echoing_them() {
        let files = TestFiles::new();
        let mut config = base_config(RCNET1_PROFILE);
        config.production_v3 = config::ProductionV3RuntimeOptions {
            bank: Some(PathBuf::from("private/model.bank")),
            manifest: Some(PathBuf::from("private/manifest.json")),
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

        let error = security_error(prepare_for_test(RCNET1_PROFILE, &config, &files.root));
        assert_eq!(error.code, "production_v3_path_invalid");
        assert!(!error.message.contains("private"));
        assert!(!error.message.contains("model.bank"));
    }

    #[test]
    fn production_v3_rejects_a_worker_hash_mismatch_without_leaking_its_path() {
        let files = TestFiles::new();
        let config = configured_rc(&files, [0; 32]);

        let error = security_error(prepare_for_test(RCNET1_PROFILE, &config, &files.root));
        assert_eq!(error.code, "proof_verifier_identity_mismatch");
        assert!(
            !error
                .message
                .contains(files.root.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn production_v3_happy_path_is_canonical_and_passed_to_the_node_gate() {
        let files = TestFiles::new();
        let worker_bytes = b"bounded worker fixture";
        let config = configured_rc(&files, sha256(worker_bytes));
        let security = prepare_for_test(RCNET1_PROFILE, &config, &files.root).unwrap();
        let artifacts = security.production_v3_artifacts.as_ref().unwrap();
        assert!(artifacts.bank.is_absolute());
        assert!(artifacts.manifest.is_absolute());
        assert!(artifacts.record_v2.is_absolute());
        let worker = security.verifier_worker.as_ref().unwrap();
        assert!(worker.worker_executable.is_absolute());
        assert_eq!(worker.production_v3_artifacts.as_ref(), Some(artifacts));
        assert_eq!(worker.startup_timeout, Duration::from_millis(1_234));
        assert_eq!(worker.timeout, Duration::from_millis(1_234));
        assert_eq!(worker.memory_limit_bytes, 4_096);

        let data_dir = files.root.join("rcnet-data");
        open_with_artifact_gate(
            &data_dir,
            RCNET1_PROFILE,
            &security,
            |received_dir, received| {
                assert_eq!(received_dir, data_dir);
                assert_eq!(received, Some(artifacts));
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn production_artifact_gate_failures_are_sanitized_and_fail_closed() {
        let security = PreparedNodeSecurity {
            production_v3_artifacts: Some(ProductionV3VerifierArtifacts {
                bank: PathBuf::from("C:\\private\\model.bank"),
                manifest: PathBuf::from("C:\\private\\manifest.json"),
                record_v2: PathBuf::from("C:\\private\\record-v2.json"),
            }),
            verifier_worker: None,
        };
        for node_error in [
            NodeError::ProductionV3ArtifactPinsMissing,
            NodeError::ProductionV3ArtifactIdentityMismatch("bank"),
        ] {
            let error = open_with_artifact_gate(
                Path::new("unused"),
                RCNET1_PROFILE,
                &security,
                |_, artifacts| {
                    assert!(artifacts.is_some());
                    Err::<(), _>(node_error)
                },
            )
            .unwrap_err();
            assert_eq!(error.code, "proof_verifier_configuration");
            assert!(error.message.contains("RCNet-1 (ProductionV3)"));
            assert!(!error.message.contains("C:\\private"));
        }
    }

    #[test]
    fn devnet_runtime_keeps_the_original_no_artifact_startup_path() {
        let config = base_config(DEVNET_PROFILE);
        let security = prepare_for_test(DEVNET_PROFILE, &config, Path::new("unused")).unwrap();
        assert!(security.production_v3_artifacts.is_none());
        assert!(security.verifier_worker.is_none());
        assert!(!command_help_text_for_profile(DEVNET_PROFILE).contains("ProductionV3 startup"));
        assert!(command_help_text_for_profile(RCNET1_PROFILE).contains("ProductionV3 startup"));

        let result = open_with_artifact_gate(
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
}
