use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cmfd_node::p2p::{InboundPeerHandle, spawn_inbound_listener_with_policy};
use cmfd_node::peer::PeerLimits;
use cmfd_node::{DEVNET_PROFILE, Node, NodeClientError};
use tauri::{App, Manager, Runtime};

use crate::mining::MiningManager;

mod config;
mod peers;

pub(crate) use config::{ConfigError, NodeRuntimeConfig, ProcessCommand};
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
            "Common Foundry Wallet node starting on {} with {} configured peer(s), allow_public_peers={allow}",
            config.p2p_bind, peers
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
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|_| {
            startup_error(
                "data_directory_unavailable",
                "The desktop wallet could not resolve its local data directory.",
                false,
            )
        })?
        .join(DEVNET_PROFILE.wallet_data_dir_identity);
    let log_guard = cmfd_node::logging::init_tracing(&data_dir, config.verbose);
    let node = Node::open(&data_dir).map_err(|error| error.client_error())?;
    let shared = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind(config.p2p_bind).map_err(|_| {
        startup_error(
            "p2p_bind_failed",
            format!(
                "The embedded node could not bind Devnet P2P on {}. Stop the process using that address, then reopen Common Foundry Wallet.",
                config.p2p_bind
            ),
            true,
        )
    })?;
    let p2p_address = listener.local_addr().map_err(|_| {
        startup_error(
            "p2p_address_unavailable",
            "The embedded node could not inspect its Devnet P2P listener address.",
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
            "The embedded Devnet peer service could not start. Reopen the wallet and try again.",
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

pub(crate) fn parse_command() -> Result<ProcessCommand, ConfigError> {
    NodeRuntimeConfig::from_process_args()
}

pub(crate) fn command_help_text() -> String {
    format!(
        concat!(
            "Common Foundry Wallet\n",
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
        DEVNET_PROFILE.p2p_address(),
    )
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
}
