use std::fs::{self, OpenOptions};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cmfd_node::p2p::{StaticPeerPollHandle, spawn_static_peer_polling};
use cmfd_node::peer::{PeerAddressPolicy, PeerLimits, StaticPeerConfig};
use cmfd_node::{Node, NodeClientError};
use serde::{Deserialize, Serialize};

use super::config::{DEFAULT_BOOTSTRAP_PEER, NodeRuntimeConfig};

const PEER_SETTINGS_VERSION: u8 = 1;
const DEFAULT_PEER_PORT: u16 = cmfd_node::DEVNET_PROFILE.p2p_port;
const MAX_PEER_INPUT_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerSettings {
    pub peers: Vec<String>,
    pub bootstrap_peer: String,
    pub default_peer_port: u16,
    pub max_peers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UpdatePeerSettingsRequest {
    pub peers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerSettingsFile {
    version: u8,
    peers: Vec<String>,
}

struct PeerControl {
    peers: Vec<SocketAddr>,
    poller: Option<StaticPeerPollHandle>,
    stopped: bool,
}

pub struct PeerManager {
    node: Arc<Mutex<Node>>,
    p2p_address: SocketAddr,
    settings_path: PathBuf,
    limits: PeerLimits,
    poll_interval: Duration,
    control: Mutex<PeerControl>,
}

impl PeerManager {
    pub(super) fn start(
        node: Arc<Mutex<Node>>,
        config: &NodeRuntimeConfig,
        data_dir: &Path,
        p2p_address: SocketAddr,
        limits: PeerLimits,
        poll_interval: Duration,
    ) -> Result<Self, NodeClientError> {
        let settings_path = data_dir.join("peers.json");
        let (peers, allow_public_peers) = if config.peers_explicit {
            (config.peers.clone(), config.allow_public_peers)
        } else {
            load_saved_peers(&settings_path, p2p_address, limits).unwrap_or_else(|error| {
                if error.code != "peer_settings_missing" {
                    eprintln!(
                        "Common Foundry Wallet ignored saved peer settings: {}",
                        error.message
                    );
                }
                (config.peers.clone(), config.allow_public_peers)
            })
        };

        let poller = start_poller(
            Arc::clone(&node),
            p2p_address,
            peers.clone(),
            allow_public_peers,
            limits,
            poll_interval,
        )?;
        node.lock()
            .map_err(|_| {
                peer_runtime_error(
                    "peer_settings_unavailable",
                    "The node peer state is unavailable.",
                )
            })?
            .set_public_peer_mode(allow_public_peers);

        Ok(Self {
            node,
            p2p_address,
            settings_path,
            limits,
            poll_interval,
            control: Mutex::new(PeerControl {
                peers,
                poller,
                stopped: false,
            }),
        })
    }

    pub fn settings(&self) -> Result<PeerSettings, NodeClientError> {
        let control = self.control.lock().map_err(|_| {
            peer_runtime_error(
                "peer_settings_unavailable",
                "Peer settings are unavailable.",
            )
        })?;
        Ok(settings_snapshot(&control.peers, self.limits))
    }

    pub fn update(
        &self,
        request: UpdatePeerSettingsRequest,
    ) -> Result<PeerSettings, NodeClientError> {
        let peers = normalize_peer_inputs(&request.peers)?;
        let allow_public_peers = peers.iter().any(|peer| is_public(*peer));
        validate_peers(self.p2p_address, &peers, allow_public_peers, self.limits)?;

        let mut control = self.control.lock().map_err(|_| {
            peer_runtime_error(
                "peer_settings_unavailable",
                "Peer settings are unavailable.",
            )
        })?;
        if control.stopped {
            return Err(peer_runtime_error(
                "peer_service_stopped",
                "The peer service is stopping. Reopen the wallet and try again.",
            ));
        }

        let new_poller = start_poller(
            Arc::clone(&self.node),
            self.p2p_address,
            peers.clone(),
            allow_public_peers,
            self.limits,
            self.poll_interval,
        )?;
        if let Err(error) = persist_peers(&self.settings_path, &peers) {
            if let Some(poller) = new_poller {
                let _ = poller.stop();
            }
            return Err(error);
        }

        self.node
            .lock()
            .map_err(|_| {
                peer_runtime_error(
                    "peer_settings_unavailable",
                    "The node peer state is unavailable.",
                )
            })?
            .set_public_peer_mode(allow_public_peers);
        let old_poller = std::mem::replace(&mut control.poller, new_poller);
        control.peers = peers;
        let snapshot = settings_snapshot(&control.peers, self.limits);
        drop(control);
        if let Some(poller) = old_poller {
            let _ = poller.stop();
        }
        Ok(snapshot)
    }

    pub fn stop(&self) {
        let poller = self.control.lock().ok().and_then(|mut control| {
            control.stopped = true;
            control.poller.take()
        });
        if let Some(poller) = poller {
            let _ = poller.stop();
        }
    }
}

fn load_saved_peers(
    path: &Path,
    p2p_address: SocketAddr,
    limits: PeerLimits,
) -> Result<(Vec<SocketAddr>, bool), NodeClientError> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            peer_error("peer_settings_missing", "No saved peer settings exist yet.")
        } else {
            peer_storage_error(
                "peer_settings_read_failed",
                "Saved peer settings could not be read.",
            )
        }
    })?;
    let saved: PeerSettingsFile = serde_json::from_slice(&bytes).map_err(|_| {
        peer_error(
            "peer_settings_invalid",
            "Saved peer settings are malformed.",
        )
    })?;
    if saved.version != PEER_SETTINGS_VERSION {
        return Err(peer_error(
            "peer_settings_invalid",
            "Saved peer settings use an unsupported version.",
        ));
    }
    let peers = normalize_peer_inputs(&saved.peers)?;
    let allow_public_peers = peers.iter().any(|peer| is_public(*peer));
    validate_peers(p2p_address, &peers, allow_public_peers, limits)?;
    Ok((peers, allow_public_peers))
}

fn persist_peers(path: &Path, peers: &[SocketAddr]) -> Result<(), NodeClientError> {
    let encoded = serde_json::to_vec_pretty(&PeerSettingsFile {
        version: PEER_SETTINGS_VERSION,
        peers: peers.iter().map(ToString::to_string).collect(),
    })
    .map_err(|_| {
        peer_storage_error(
            "peer_settings_write_failed",
            "Peer settings could not be encoded.",
        )
    })?;
    fs::write(path, encoded).map_err(|_| {
        peer_storage_error(
            "peer_settings_write_failed",
            "Peer settings could not be saved.",
        )
    })?;
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| {
            peer_storage_error(
                "peer_settings_write_failed",
                "Peer settings could not be saved.",
            )
        })
}

fn normalize_peer_inputs(values: &[String]) -> Result<Vec<SocketAddr>, NodeClientError> {
    if values.is_empty() {
        return Err(peer_error(
            "peer_list_empty",
            "Keep at least one peer configured. Use Reset to restore the community bootstrap peer.",
        ));
    }
    values.iter().map(|value| parse_peer_input(value)).collect()
}

fn parse_peer_input(value: &str) -> Result<SocketAddr, NodeClientError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_PEER_INPUT_BYTES {
        return Err(peer_error(
            "invalid_peer_address",
            "Enter a numeric IP address, optionally followed by :port.",
        ));
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    value
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, DEFAULT_PEER_PORT))
        .map_err(|_| {
            peer_error(
                "invalid_peer_address",
                "Enter a numeric IP address, optionally followed by :port.",
            )
        })
}

fn validate_peers(
    p2p_address: SocketAddr,
    peers: &[SocketAddr],
    allow_public_peers: bool,
    limits: PeerLimits,
) -> Result<(), NodeClientError> {
    StaticPeerConfig {
        listen_address: p2p_address,
        peers: peers.to_vec(),
        limits,
        address_policy: address_policy(allow_public_peers),
    }
    .validate()
    .map_err(|error| peer_error("invalid_peer_configuration", error.to_string()))
}

fn start_poller(
    node: Arc<Mutex<Node>>,
    p2p_address: SocketAddr,
    peers: Vec<SocketAddr>,
    allow_public_peers: bool,
    limits: PeerLimits,
    poll_interval: Duration,
) -> Result<Option<StaticPeerPollHandle>, NodeClientError> {
    if peers.is_empty() {
        return Ok(None);
    }
    spawn_static_peer_polling(
        node,
        StaticPeerConfig {
            listen_address: p2p_address,
            peers,
            limits,
            address_policy: address_policy(allow_public_peers),
        },
        poll_interval,
    )
    .map(Some)
    .map_err(|_| {
        peer_runtime_error(
            "peer_poller_start_failed",
            "Outbound peer polling could not start. Check the peer list and try again.",
        )
    })
}

fn settings_snapshot(peers: &[SocketAddr], limits: PeerLimits) -> PeerSettings {
    PeerSettings {
        peers: peers.iter().map(ToString::to_string).collect(),
        bootstrap_peer: DEFAULT_BOOTSTRAP_PEER.to_string(),
        default_peer_port: DEFAULT_PEER_PORT,
        max_peers: limits.max_peers,
    }
}

fn address_policy(allow_public_peers: bool) -> PeerAddressPolicy {
    if allow_public_peers {
        PeerAddressPolicy::AllowPublic
    } else {
        PeerAddressPolicy::PrivateOnly
    }
}

fn is_public(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => !(ip.is_loopback() || ip.is_private()),
        IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()),
    }
}

fn peer_error(code: &'static str, message: impl Into<String>) -> NodeClientError {
    NodeClientError {
        code,
        status: 400,
        retryable: false,
        message: message.into(),
    }
}

fn peer_runtime_error(code: &'static str, message: impl Into<String>) -> NodeClientError {
    NodeClientError {
        code,
        status: 503,
        retryable: true,
        message: message.into(),
    }
}

fn peer_storage_error(code: &'static str, message: impl Into<String>) -> NodeClientError {
    NodeClientError {
        code,
        status: 500,
        retryable: true,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn peer_inputs_accept_default_ports_and_reject_names() {
        assert_eq!(
            parse_peer_input("192.168.1.20").unwrap(),
            "192.168.1.20:18444".parse().unwrap()
        );
        assert_eq!(
            parse_peer_input("[fd12::20]:19000").unwrap(),
            "[fd12::20]:19000".parse().unwrap()
        );
        assert_eq!(
            parse_peer_input("fd12::20").unwrap(),
            "[fd12::20]:18444".parse().unwrap()
        );
        assert_eq!(
            parse_peer_input("peer.example.com").unwrap_err().code,
            "invalid_peer_address"
        );
    }

    #[test]
    fn peer_validation_rejects_empty_duplicate_and_self_lists() {
        let listen = "127.0.0.1:18444".parse().unwrap();
        let limits = PeerLimits::default();
        assert_eq!(
            normalize_peer_inputs(&[]).unwrap_err().code,
            "peer_list_empty"
        );
        for peers in [
            vec![
                "127.0.0.1:18455".parse().unwrap(),
                "127.0.0.1:18455".parse().unwrap(),
            ],
            vec![listen],
        ] {
            assert_eq!(
                validate_peers(listen, &peers, false, limits)
                    .unwrap_err()
                    .code,
                "invalid_peer_configuration"
            );
        }
    }

    #[test]
    fn public_mode_is_derived_from_the_saved_addresses() {
        assert!(!is_public("127.0.0.1:18444".parse().unwrap()));
        assert!(!is_public("192.168.1.10:18444".parse().unwrap()));
        assert!(is_public("107.214.187.2:18444".parse().unwrap()));
    }

    #[test]
    fn saved_peers_round_trip_with_canonical_addresses() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "cmfd-peer-settings-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("peers.json");
        let expected = vec![
            "192.168.1.20:18444".parse().unwrap(),
            "107.214.187.2:18444".parse().unwrap(),
        ];

        persist_peers(&path, &expected).unwrap();
        let (loaded, public) = load_saved_peers(
            &path,
            "127.0.0.1:18444".parse().unwrap(),
            PeerLimits::default(),
        )
        .unwrap();

        assert_eq!(loaded, expected);
        assert!(public);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
