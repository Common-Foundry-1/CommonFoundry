use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cmfd_node::p2p::{
    InboundPeerHandle, StaticPeerPollHandle, spawn_inbound_listener_with_policy,
    spawn_static_peer_polling,
};
use cmfd_node::peer::PeerLimits;
use cmfd_node::{Node, NodeClientError};
use tauri::{App, Manager, Runtime};

use crate::mining::MiningManager;

mod config;

use config::{ConfigError, NodeRuntimeConfig};

const STATIC_PEER_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
enum NodeAvailability {
    Ready(Arc<Mutex<Node>>),
    Failed(NodeClientError),
}

struct ServiceHandles {
    static_peer_poller: Option<StaticPeerPollHandle>,
    inbound: InboundPeerHandle,
}

pub struct RuntimeState {
    node: NodeAvailability,
    mining: Option<Arc<MiningManager>>,
    services: Mutex<Option<ServiceHandles>>,
    // Held for the life of the process: dropping it stops the non-blocking
    // file writer from flushing buffered log lines.
    _log_guard: Option<cmfd_node::logging::WorkerGuard>,
}

impl RuntimeState {
    pub fn start<R: Runtime>(app: &App<R>) -> Self {
        let config = match NodeRuntimeConfig::from_process_args() {
            Ok(config) => config,
            Err(error) => {
                return Self {
                    node: NodeAvailability::Failed(configuration_error(error)),
                    mining: None,
                    services: Mutex::new(None),
                    _log_guard: None,
                };
            }
        };
        match start_embedded_node(app, config) {
            Ok((node, services, log_guard)) => Self {
                mining: Some(Arc::new(MiningManager::new(Arc::clone(&node)))),
                node: NodeAvailability::Ready(node),
                services: Mutex::new(Some(services)),
                _log_guard: Some(log_guard),
            },
            Err(error) => Self {
                node: NodeAvailability::Failed(error),
                mining: None,
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

    pub fn stop_services(&self) {
        if let Some(mining) = &self.mining {
            mining.stop_for_shutdown();
        }
        let services = self
            .services
            .lock()
            .ok()
            .and_then(|mut services| services.take());
        if let Some(services) = services {
            let ServiceHandles {
                static_peer_poller,
                inbound,
            } = services;
            if let Some(poller) = static_peer_poller {
                let _ = poller.stop();
            }
            let _ = inbound.stop();
        }
    }

    #[cfg(test)]
    fn failed_for_test(error: NodeClientError) -> Self {
        Self {
            node: NodeAvailability::Failed(error),
            mining: None,
            services: Mutex::new(None),
            _log_guard: None,
        }
    }
}

fn start_embedded_node<R: Runtime>(
    app: &App<R>,
    config: NodeRuntimeConfig,
) -> Result<
    (
        Arc<Mutex<Node>>,
        ServiceHandles,
        cmfd_node::logging::WorkerGuard,
    ),
    NodeClientError,
> {
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
        .join("devnet-0");
    let log_guard = cmfd_node::logging::init_tracing(&data_dir, config.verbose);
    let mut node = Node::open(&data_dir).map_err(|error| error.client_error())?;
    node.set_public_peer_mode(config.allow_public_peers);
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
    let static_peer_poller = if config.peers.is_empty() {
        None
    } else {
        let mut static_peers = config.static_peers(limits);
        static_peers.listen_address = p2p_address;
        match spawn_static_peer_polling(
            Arc::clone(&shared),
            static_peers,
            STATIC_PEER_POLL_INTERVAL,
        ) {
            Ok(poller) => Some(poller),
            Err(_) => {
                let _ = inbound.stop();
                return Err(startup_error(
                    "static_peer_poller_start_failed",
                    "The embedded node could not start outbound Devnet peer polling. Check the peer configuration, then reopen the wallet.",
                    true,
                ));
            }
        }
    };
    Ok((
        shared,
        ServiceHandles {
            static_peer_poller,
            inbound,
        },
        log_guard,
    ))
}

fn configuration_error(error: ConfigError) -> NodeClientError {
    NodeClientError {
        code: "invalid_p2p_configuration",
        status: 400,
        retryable: false,
        message: format!("Invalid desktop P2P configuration: {error}"),
    }
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
        let error = configuration_error(ConfigError::UnknownArgument("--public-peer".to_owned()));

        assert_eq!(error.code, "invalid_p2p_configuration");
        assert_eq!(error.status, 400);
        assert!(!error.retryable);
        assert!(error.message.contains("--public-peer"));
    }
}
