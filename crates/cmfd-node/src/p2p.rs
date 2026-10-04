//! Minimal bounded peer runtime for Devnet-0.
//!
//! The transport handshake binds network and consensus parameters, but it does
//! not authenticate peer identity or encrypt traffic. This module therefore
//! defaults to loopback/private addresses; public peers require an explicit
//! unsafe Devnet opt-in enforced by `peer`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(all(test, feature = "production-v4", any(windows, target_os = "linux")))]
#[path = "real_peer_catchup_tests.rs"]
mod real_peer_catchup_tests;

use cmfd_consensus::{
    Block, ChainError, MAX_TRANSACTION_BYTES, Transaction, WireError, decode_block,
    max_block_bytes_for_network,
};
use thiserror::Error;

#[cfg(feature = "production-v3")]
use crate::ProductionV3MiningPeerIdentity;
use crate::peer::{
    BlockSubmissionResult, BlockSubmissionStatus, MAX_GOSSIP_PEERS, PeerAddressPolicy,
    PeerConnection, PeerError, PeerHello, PeerLimits, PeerMessage, PeerSession,
    SUBMIT_BLOCK_RESPONSE_BUDGET, StaticPeerConfig, validate_peer_address,
};
use crate::{
    Node, NodeError, PeerDirection, RemoteProofPeerId, RemoteProofRequest,
    submit_shared_peer_block_cancellable, unix_time_seconds,
};

/// Absolute item-count cap for one block synchronization request. The active
/// byte-size cap is derived from the network's maximum block frame below.
pub const MAX_BLOCKS_PER_SYNC: usize = 16;
/// A single poll downloads only a small prefix of an advertised mempool.
/// Accepted candidates become locally known, allowing later polls to proceed
/// farther through an honest peer's inventory.
pub const MAX_TRANSACTIONS_PER_SYNC: usize = 64;
// Leave room in the shared session budget for a full transaction batch plus
// peer frames, inventories, requests, and the handshake. This keeps the V4
// 16 MiB block frame inside the existing 32 MiB anti-abuse boundary without
// reducing the legacy network's 16-block batch.
const SYNC_CONTROL_RESERVE_BYTES: u64 = 1024 * 1024;
const LISTENER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const PEER_DISCONNECT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PEER_CACHE_FILE: &str = "peers-v1.txt";
const PEER_CACHE_MAGIC: &str = "CMFD_PEERS_V1";
const MAX_DISCOVERED_PEERS: usize = 64;
const MAX_PEER_CACHE_BYTES: u64 = 16 * 1024;
const MAX_DYNAMIC_TARGETS_PER_ROUND: usize = 2;
const MAX_CATCHUP_EXTRA_SESSIONS_PER_PEER: usize = 3;
const MAX_CATCHUP_EXTRA_SESSIONS_PER_ROUND: usize = 8;
// This limits starts after the normal fair peer pass, not an in-flight proof.
// Every started session retains its existing byte/message/deadline bounds.
const CATCHUP_EXTRA_SESSION_START_BUDGET: Duration = Duration::from_secs(30);
const MAX_UNVERIFIED_PEER_FAILURES: u8 = 3;
const MAX_DISCOVERED_PEERS_PER_IP: usize = 8;
// Keep source-tracking memory fixed, prevent one address from consuming the
// default 16-peer listener, and leave ample reconnect headroom for several
// honest nodes behind one NAT. Bans are deliberately temporary so operator
// mistakes and rolling-upgrade incompatibilities recover without intervention.
const MAX_PEER_REPUTATIONS: usize = 1_024;
const MAX_INBOUND_CONNECTIONS_PER_IP: usize = 4;
const MAX_INBOUND_ATTEMPTS_PER_WINDOW: u16 = 64;
const INBOUND_ATTEMPT_WINDOW: Duration = Duration::from_secs(10);
const PEER_BAN_DURATION: Duration = Duration::from_secs(5 * 60);
const PEER_BAN_SCORE: u16 = 100;
const COMPRESSED_PEER_STRIKES: u8 = 1;
const COMPRESSED_PEER_COOLDOWN: Duration = Duration::from_secs(60 * 60);
const CLEAN_SESSION_CREDIT: u16 = 10;
const TRANSIENT_FAILURE_PENALTY: u16 = 5;
const UNKNOWN_REQUEST_PENALTY: u16 = 10;
const INVALID_BLOCK_PENALTY: u16 = 25;
const INVALID_TRANSACTION_PENALTY: u16 = 25;
const PROTOCOL_VIOLATION_PENALTY: u16 = 50;
const RESOURCE_ABUSE_PENALTY: u16 = PEER_BAN_SCORE;
const DYNAMIC_PEER_RETRY_INTERVAL: Duration = Duration::from_secs(10);
// A newly active tip is pushed to peers immediately instead of waiting for the
// serial poll round to reach each of them. Bounded in targets and concurrency,
// and skipped while the chain is far behind (catch-up blocks are not news).
const TIP_ANNOUNCE_CHECK_INTERVAL: Duration = Duration::from_millis(200);
const MAX_TIP_ANNOUNCE_TARGETS: usize = 16;
// Bounded header re-requests per session while walking an already-stored prefix.
const MAX_KNOWN_PREFIX_HEADER_ROUNDS: usize = 64;
const MAX_TIP_ANNOUNCE_IN_FLIGHT: usize = 8;
const MAX_TIP_ANNOUNCE_REPEATS: usize = 3;

/// Configured static peers (relays, the seed, the pool node) are announced
/// first and never wait behind the in-flight cap, so a slow dynamic peer that
/// is still receiving the previous block cannot delay the relay fan-out.
/// Dynamic peers share the remaining bounded slots.
fn tip_announce_slot_available(static_peer: bool, in_flight: usize) -> bool {
    static_peer || in_flight < MAX_TIP_ANNOUNCE_IN_FLIGHT
}
// A peer that keeps answering Busy for the same offered block (for example a
// slow node stuck on another branch) is not re-offered that block every round:
// each re-offer occupies its single verifier and starves its own sync.
const RELAY_BUSY_REPEATS_BEFORE_BACKOFF: u32 = 3;
const RELAY_BUSY_BACKOFF_BASE: Duration = Duration::from_secs(30);
const RELAY_BUSY_BACKOFF_MAX: Duration = Duration::from_secs(10 * 60);
const TIP_ANNOUNCE_MAX_MEDIAN_AGE_SECONDS: u64 = 30 * 60;
const MAX_DYNAMIC_PEER_BACKOFF: Duration = Duration::from_secs(5 * 60);
const DISCOVERY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DISCOVERY_UNSUPPORTED_RETRY_INTERVAL: Duration = Duration::from_secs(5 * 60);
// The receiver owns a 120-second response budget. The server stops admission
// at 110 seconds and reserves five seconds for local response serialization,
// leaving a final five seconds for transport/scheduling at the client.
const SUBMIT_BLOCK_SERVER_RESPONSE_MARGIN: Duration = Duration::from_secs(5);
const SUBMIT_BLOCK_ACCEPTANCE_MARGIN: Duration = Duration::from_secs(5);
const SUBMIT_BLOCK_SERVER_RESPONSE_BUDGET: Duration = Duration::from_secs(
    SUBMIT_BLOCK_RESPONSE_BUDGET.as_secs() - SUBMIT_BLOCK_SERVER_RESPONSE_MARGIN.as_secs(),
);
const SUBMIT_BLOCK_ACCEPTANCE_BUDGET: Duration = Duration::from_secs(
    SUBMIT_BLOCK_SERVER_RESPONSE_BUDGET.as_secs() - SUBMIT_BLOCK_ACCEPTANCE_MARGIN.as_secs(),
);
static NEXT_REMOTE_PROOF_PEER_ID: AtomicU64 = AtomicU64::new(1);

fn block_sync_batch_limit(network_id: [u8; 32], limits: PeerLimits) -> usize {
    let transaction_reserve =
        (MAX_TRANSACTIONS_PER_SYNC as u64).saturating_mul(MAX_TRANSACTION_BYTES as u64);
    let block_budget = limits
        .max_bytes_per_peer
        .saturating_sub(transaction_reserve)
        .saturating_sub(SYNC_CONTROL_RESERVE_BYTES);
    let maximum_block_bytes = max_block_bytes_for_network(network_id) as u64;
    usize::try_from(block_budget / maximum_block_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_BLOCKS_PER_SYNC)
}

#[derive(Debug, Error)]
pub enum P2pError {
    #[error(transparent)]
    Peer(#[from] PeerError),
    #[error(transparent)]
    Node(#[from] NodeError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("peer runtime node mutex is poisoned")]
    PoisonedNode,
    #[error("SubmitBlock deadline overflowed the monotonic clock")]
    SubmitBlockDeadlineOverflow,
    #[error("peer runtime stop mutex is poisoned")]
    PoisonedStop,
    #[error("peer runtime active-socket registry is poisoned")]
    PoisonedActiveSockets,
    #[error("peer discovery registry is poisoned")]
    PoisonedPeerDiscovery,
    #[error("peer reputation registry is poisoned")]
    PoisonedPeerReputation,
    #[error("peer {0} is temporarily banned")]
    PeerTemporarilyBanned(IpAddr),
    #[error("peer service is stopping")]
    ServiceStopping,
    #[error("unexpected peer message: expected {expected}, received {actual}")]
    UnexpectedMessage {
        expected: &'static str,
        actual: &'static str,
    },
    #[error("peer returned block {actual:?} for requested identifier {requested:?}")]
    WrongBlock {
        requested: [u8; 32],
        actual: [u8; 32],
    },
    #[error("peer returned transaction {actual:?} for requested identifier {requested:?}")]
    WrongTransaction {
        requested: [u8; 32],
        actual: [u8; 32],
    },
    #[error("peer returned a block-submission result for {actual:?}, expected {submitted:?}")]
    WrongBlockSubmission {
        submitted: [u8; 32],
        actual: [u8; 32],
    },
    #[error("peer rejected submitted block {0:?}")]
    RejectedBlockSubmission([u8; 32]),
    #[error(
        "peer deferred submitted block {0:?} (retryable: verifier busy, stale tip, missing parent, or fork reconstruction)"
    )]
    BusyBlockSubmission([u8; 32]),
    #[error("peer inventory is not parent-ordered at block {block_id:?}")]
    NonContiguousInventory { block_id: [u8; 32] },
    #[error("peer requested an unknown or body-less block {0:?}")]
    UnknownRequestedBlock([u8; 32]),
    #[error("peer requested an unknown mempool transaction {0:?}")]
    UnknownRequestedTransaction([u8; 32]),
    #[error("peer returned a mining template that does not extend its advertised tip")]
    UnexpectedMiningTemplate,
    #[error("peer returned a mining template with the wrong miner payout destination")]
    UnexpectedMiningPayout,
    #[error("peer polling interval must be nonzero")]
    ZeroPollInterval,
    #[error("peer service thread panicked")]
    ThreadPanicked,
    #[error("process-local peer admission identity space is exhausted")]
    PeerAdmissionIdentityExhausted,
    #[error("peer listener I/O failed: {0}")]
    ListenerIo(#[source] io::Error),
}

impl P2pError {
    /// Returns true only for loss of transport or an exhausted transport
    /// deadline. Framing, handshake, message-shape, and identifier failures are
    /// protocol violations and deliberately remain distinguishable.
    pub fn is_transport_disconnect(&self) -> bool {
        matches!(
            self,
            Self::Peer(
                PeerError::ConnectionClosed
                    | PeerError::TotalTimeout
                    | PeerError::IdleTimeout
                    | PeerError::SubmitBlockResponseTimeout
                    | PeerError::BlockValidationWaitTimeout
                    | PeerError::Io(_)
            )
        )
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Peer(PeerError::Cancelled))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    pub remote_hello: PeerHello,
    pub inventory_items: usize,
    pub requested_blocks: usize,
    pub accepted_blocks: usize,
    pub already_known: usize,
    pub transaction_inventory_items: usize,
    pub requested_transactions: usize,
    pub accepted_transactions: usize,
    pub already_known_transactions: usize,
    pub rejected_transactions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayReport {
    pub remote_hello: PeerHello,
    pub offered_blocks: usize,
    pub accepted_blocks: usize,
    pub already_known: usize,
    pub offered_transactions: usize,
    pub peer_height: u64,
    pub peer_tip: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningTemplateResponse {
    pub remote_hello: PeerHello,
    pub template: crate::peer::MiningTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerDiscoveryReport {
    pub remote_hello: PeerHello,
    pub addresses: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Copy)]
struct DiscoveredPeer {
    verified: bool,
    failures: u8,
    next_sync: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PeerReputationKey {
    V4([u8; 4]),
    V6([u8; 8]),
}

impl PeerReputationKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip.octets()),
            IpAddr::V6(ip) => {
                if let Some(ip) = ip.to_ipv4_mapped() {
                    Self::V4(ip.octets())
                } else {
                    let octets = ip.octets();
                    Self::V6(octets[..8].try_into().expect("fixed IPv6 /64 prefix"))
                }
            }
        }
    }
}

#[derive(Debug)]
struct PeerReputationEntry {
    score: u16,
    banned_until: Option<Instant>,
    active_connections: usize,
    attempt_window_started: Instant,
    connection_attempts: u16,
    last_updated: Instant,
    /// The peer sent us a version-5 frame, so it accepts compressed blocks.
    /// Consecutive version-5 sessions that died in transport before any
    /// reply, the signature of a version-4 peer rejecting our hello.
    compressed_strikes: u8,
    compressed_cooldown_until: Option<Instant>,
}

impl PeerReputationEntry {
    fn new(now: Instant) -> Self {
        Self {
            score: 0,
            banned_until: None,
            active_connections: 0,
            attempt_window_started: now,
            connection_attempts: 0,
            last_updated: now,
            compressed_strikes: 0,
            compressed_cooldown_until: None,
        }
    }

    fn refresh(&mut self, now: Instant) {
        if self.banned_until.is_some_and(|until| until <= now) {
            self.score = 0;
            self.banned_until = None;
            self.attempt_window_started = now;
            self.connection_attempts = 0;
        }
        if now.saturating_duration_since(self.attempt_window_started) >= INBOUND_ATTEMPT_WINDOW {
            self.attempt_window_started = now;
            self.connection_attempts = 0;
        }
        self.last_updated = now;
    }
}

#[derive(Debug, Default)]
struct PeerSecurityState {
    reputations: BTreeMap<PeerReputationKey, PeerReputationEntry>,
    /// Operator-configured peers; assumed to accept compressed blocks until
    /// they prove otherwise.
    static_peers: BTreeSet<PeerReputationKey>,
}

#[derive(Debug, Default)]
struct PeerSecurity {
    state: Mutex<PeerSecurityState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerAdmissionRejection {
    Banned,
    PerIpLimit,
    RateLimit,
    Capacity,
}

enum PeerAdmission {
    Accepted(PeerAdmissionGuard),
    Rejected(PeerAdmissionRejection),
}

struct PeerAdmissionGuard {
    security: Arc<PeerSecurity>,
    key: PeerReputationKey,
}

impl Drop for PeerAdmissionGuard {
    fn drop(&mut self) {
        self.security.release(self.key);
    }
}

impl PeerSecurity {
    fn reserve_inbound(self: &Arc<Self>, ip: IpAddr) -> Result<PeerAdmission, P2pError> {
        self.reserve_inbound_at(ip, Instant::now())
    }

    fn reserve_inbound_at(
        self: &Arc<Self>,
        ip: IpAddr,
        now: Instant,
    ) -> Result<PeerAdmission, P2pError> {
        let key = PeerReputationKey::from_ip(ip);
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerReputation)?;
        let Some(entry) = peer_reputation_entry(&mut state, key, now) else {
            return Ok(PeerAdmission::Rejected(PeerAdmissionRejection::Capacity));
        };
        entry.refresh(now);
        if entry.banned_until.is_some_and(|until| until > now) {
            return Ok(PeerAdmission::Rejected(PeerAdmissionRejection::Banned));
        }
        if entry.connection_attempts >= MAX_INBOUND_ATTEMPTS_PER_WINDOW {
            entry.score = PEER_BAN_SCORE;
            entry.banned_until = Some(now + PEER_BAN_DURATION);
            tracing::warn!(peer = %ip, "temporarily banned peer after excessive connection churn");
            return Ok(PeerAdmission::Rejected(PeerAdmissionRejection::RateLimit));
        }
        entry.connection_attempts = entry.connection_attempts.saturating_add(1);
        if entry.active_connections >= MAX_INBOUND_CONNECTIONS_PER_IP {
            return Ok(PeerAdmission::Rejected(PeerAdmissionRejection::PerIpLimit));
        }
        entry.active_connections = entry.active_connections.saturating_add(1);
        Ok(PeerAdmission::Accepted(PeerAdmissionGuard {
            security: Arc::clone(self),
            key,
        }))
    }

    fn record_success(&self, ip: IpAddr) -> Result<(), P2pError> {
        let now = Instant::now();
        let key = PeerReputationKey::from_ip(ip);
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerReputation)?;
        let Some(entry) = state.reputations.get_mut(&key) else {
            return Ok(());
        };
        entry.refresh(now);
        if entry.banned_until.is_none() {
            entry.score = entry.score.saturating_sub(CLEAN_SESSION_CREDIT);
        }
        Ok(())
    }

    fn register_static_peers(&self, peers: &[SocketAddr]) -> Result<(), P2pError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerReputation)?;
        state.static_peers.extend(
            peers
                .iter()
                .map(|peer| PeerReputationKey::from_ip(peer.ip())),
        );
        Ok(())
    }

    /// Whether to open a session to this peer with version-5 (compressed block)
    /// frames: it is a configured static peer whose last version-5 session did
    /// not die in the handshake. Nothing is learned per address, because one
    /// address may front several nodes (NAT); a session that is greeted with
    /// version 5 answers in version 5 on its own (see `PeerSession`).
    fn compresses_blocks(&self, ip: IpAddr) -> Result<bool, P2pError> {
        let now = Instant::now();
        let key = PeerReputationKey::from_ip(ip);
        let state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerReputation)?;
        let entry = state.reputations.get(&key);
        if entry.is_some_and(|entry| {
            entry
                .compressed_cooldown_until
                .is_some_and(|until| until > now)
        }) {
            return Ok(false);
        }
        Ok(state.static_peers.contains(&key))
    }

    /// Outcome of a session we opened with version 5. A version-4 peer closes
    /// the connection on our hello and counts it as a protocol violation, so a
    /// single such closure pauses compression toward that peer for an hour,
    /// before a second violation would get us banned there; a completed
    /// session resets the count.
    fn record_compressed_session(
        &self,
        ip: IpAddr,
        result: Result<(), &P2pError>,
    ) -> Result<(), P2pError> {
        let now = Instant::now();
        let key = PeerReputationKey::from_ip(ip);
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerReputation)?;
        let Some(entry) = peer_reputation_entry(&mut state, key, now) else {
            return Ok(());
        };
        let rejected = match result {
            Ok(()) => {
                entry.compressed_strikes = 0;
                return Ok(());
            }
            Err(P2pError::Peer(PeerError::ConnectionClosed)) => true,
            // A reset or abort after our hello is the older peer closing on it. A
            // refused or unreachable connection says nothing about its version,
            // so an outage of a static peer does not cost an hour uncompressed.
            Err(P2pError::Peer(PeerError::Io(error))) => matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ),
            Err(_) => false,
        };
        if rejected {
            entry.compressed_strikes = entry.compressed_strikes.saturating_add(1);
            if entry.compressed_strikes >= COMPRESSED_PEER_STRIKES {
                entry.compressed_strikes = 0;
                entry.compressed_cooldown_until = Some(now + COMPRESSED_PEER_COOLDOWN);
                tracing::warn!(peer = %ip, "peer rejected compressed-block frames; falling back to version 4 for an hour");
            }
        }
        Ok(())
    }

    fn record_failure(
        &self,
        ip: IpAddr,
        penalty: u16,
        reason: &'static str,
    ) -> Result<bool, P2pError> {
        self.record_failure_at(ip, penalty, Instant::now(), reason)
    }

    fn record_failure_at(
        &self,
        ip: IpAddr,
        penalty: u16,
        now: Instant,
        reason: &'static str,
    ) -> Result<bool, P2pError> {
        if penalty == 0 {
            return Ok(false);
        }
        let key = PeerReputationKey::from_ip(ip);
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerReputation)?;
        let Some(entry) = peer_reputation_entry(&mut state, key, now) else {
            return Ok(false);
        };
        entry.refresh(now);
        if entry.banned_until.is_some_and(|until| until > now) {
            return Ok(true);
        }
        entry.score = entry.score.saturating_add(penalty).min(PEER_BAN_SCORE);
        let banned = entry.score >= PEER_BAN_SCORE;
        if banned {
            entry.banned_until = Some(now + PEER_BAN_DURATION);
            tracing::warn!(peer = %ip, score = entry.score, %reason, "temporarily banned misbehaving peer");
        } else {
            tracing::debug!(peer = %ip, score = entry.score, %reason, "recorded peer misbehavior");
        }
        Ok(banned)
    }

    fn is_banned(&self, ip: IpAddr) -> Result<bool, P2pError> {
        self.is_banned_at(ip, Instant::now())
    }

    fn is_banned_at(&self, ip: IpAddr, now: Instant) -> Result<bool, P2pError> {
        let key = PeerReputationKey::from_ip(ip);
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerReputation)?;
        let Some(entry) = state.reputations.get_mut(&key) else {
            return Ok(false);
        };
        entry.refresh(now);
        Ok(entry.banned_until.is_some_and(|until| until > now))
    }

    fn release(&self, key: PeerReputationKey) {
        if let Ok(mut state) = self.state.lock()
            && let Some(entry) = state.reputations.get_mut(&key)
        {
            entry.active_connections = entry.active_connections.saturating_sub(1);
            entry.last_updated = Instant::now();
        }
    }
}

fn peer_reputation_entry(
    state: &mut PeerSecurityState,
    key: PeerReputationKey,
    now: Instant,
) -> Option<&mut PeerReputationEntry> {
    if !state.reputations.contains_key(&key) && state.reputations.len() >= MAX_PEER_REPUTATIONS {
        let eviction = state
            .reputations
            .iter()
            .filter(|(_, entry)| {
                entry.active_connections == 0 && entry.banned_until.is_none_or(|until| until <= now)
            })
            .min_by_key(|(_, entry)| entry.last_updated)
            .map(|(key, _)| *key);
        if let Some(eviction) = eviction {
            state.reputations.remove(&eviction);
        }
    }
    if !state.reputations.contains_key(&key) && state.reputations.len() >= MAX_PEER_REPUTATIONS {
        return None;
    }
    Some(
        state
            .reputations
            .entry(key)
            .or_insert_with(|| PeerReputationEntry::new(now)),
    )
}

#[derive(Debug, Default)]
struct PeerDiscoveryState {
    peers: BTreeMap<SocketAddr, DiscoveredPeer>,
    next_discovery: HashMap<SocketAddr, Instant>,
}

/// Bounded process-local discovery state backed by a small cache of peers that
/// this node has successfully handshaken with. Advertised and gossiped
/// addresses remain unverified candidates until an outbound sync succeeds.
#[derive(Debug)]
pub struct PeerDiscovery {
    cache_path: PathBuf,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    listen_address: SocketAddr,
    address_policy: PeerAddressPolicy,
    security: Arc<PeerSecurity>,
    state: Mutex<PeerDiscoveryState>,
}

impl PeerDiscovery {
    pub fn open(
        data_dir: &Path,
        local_hello: PeerHello,
        listen_address: SocketAddr,
        address_policy: PeerAddressPolicy,
    ) -> Self {
        let cache_path = data_dir.join(PEER_CACHE_FILE);
        let mut state = PeerDiscoveryState::default();
        match load_peer_cache(
            &cache_path,
            local_hello.network_id,
            local_hello.consensus_fingerprint,
            listen_address,
            address_policy,
        ) {
            Ok(addresses) => {
                let now = Instant::now();
                for address in addresses {
                    state.peers.insert(
                        address,
                        DiscoveredPeer {
                            verified: true,
                            failures: 0,
                            next_sync: now,
                        },
                    );
                }
            }
            Err(error) => {
                tracing::warn!(path = %cache_path.display(), %error, "ignoring invalid peer cache");
            }
        }
        Self {
            cache_path,
            network_id: local_hello.network_id,
            consensus_fingerprint: local_hello.consensus_fingerprint,
            listen_address,
            address_policy,
            security: Arc::new(PeerSecurity::default()),
            state: Mutex::new(state),
        }
    }

    fn add_candidate(&self, address: SocketAddr) -> Result<(), P2pError> {
        validate_peer_address(address, self.address_policy)?;
        if address == self.listen_address {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerDiscovery)?;
        if state.peers.contains_key(&address)
            || state.peers.len() >= MAX_DISCOVERED_PEERS
            || state
                .peers
                .keys()
                .filter(|known| known.ip() == address.ip())
                .count()
                >= MAX_DISCOVERED_PEERS_PER_IP
        {
            return Ok(());
        }
        state.peers.insert(
            address,
            DiscoveredPeer {
                verified: false,
                failures: 0,
                next_sync: Instant::now(),
            },
        );
        Ok(())
    }

    fn add_candidates(&self, addresses: &[SocketAddr]) -> Result<(), P2pError> {
        for address in addresses {
            self.add_candidate(*address)?;
        }
        Ok(())
    }

    fn poll_targets(&self, limit: usize) -> Result<Vec<SocketAddr>, P2pError> {
        self.poll_targets_at(Instant::now(), limit)
    }

    /// Due dynamic peers, least recently scheduled first. Address order would
    /// hand every round to the same lowest addresses once a round outlasts
    /// `DYNAMIC_PEER_RETRY_INTERVAL`, so a relay with a high address would
    /// never be polled while lower ones keep answering.
    fn poll_targets_at(&self, now: Instant, limit: usize) -> Result<Vec<SocketAddr>, P2pError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerDiscovery)?;
        let mut due: Vec<_> = state
            .peers
            .iter()
            .filter_map(|(address, peer)| {
                (peer.next_sync <= now).then_some((peer.next_sync, *address))
            })
            .collect();
        due.sort();
        let targets: Vec<_> = due
            .into_iter()
            .take(limit)
            .map(|(_, address)| address)
            .collect();
        for address in &targets {
            if let Some(peer) = state.peers.get_mut(address) {
                peer.next_sync = now + DYNAMIC_PEER_RETRY_INTERVAL;
            }
        }
        Ok(targets)
    }

    fn mark_verified(&self, address: SocketAddr) -> Result<(), P2pError> {
        validate_peer_address(address, self.address_policy)?;
        if address == self.listen_address {
            return Ok(());
        }
        let verified_addresses = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| P2pError::PoisonedPeerDiscovery)?;
            let was_verified = state.peers.get(&address).is_some_and(|peer| peer.verified);
            if !state.peers.contains_key(&address) && state.peers.len() >= MAX_DISCOVERED_PEERS {
                let Some(unverified) = state
                    .peers
                    .iter()
                    .find_map(|(address, peer)| (!peer.verified).then_some(*address))
                else {
                    return Ok(());
                };
                state.peers.remove(&unverified);
                state.next_discovery.remove(&unverified);
            }
            state.peers.insert(
                address,
                DiscoveredPeer {
                    verified: true,
                    failures: 0,
                    next_sync: Instant::now() + DYNAMIC_PEER_RETRY_INTERVAL,
                },
            );
            if was_verified {
                return Ok(());
            }
            state
                .peers
                .iter()
                .filter_map(|(address, peer)| peer.verified.then_some(*address))
                .collect::<Vec<_>>()
        };
        if let Err(error) = write_peer_cache(
            &self.cache_path,
            self.network_id,
            self.consensus_fingerprint,
            &verified_addresses,
        ) {
            tracing::warn!(path = %self.cache_path.display(), %error, "failed to persist peer cache");
        }
        Ok(())
    }

    fn mark_failed(&self, address: SocketAddr) -> Result<(), P2pError> {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerDiscovery)?;
        let remove = match state.peers.get_mut(&address) {
            Some(peer) => {
                peer.failures = peer.failures.saturating_add(1);
                let remove = !peer.verified && peer.failures >= MAX_UNVERIFIED_PEER_FAILURES;
                if !remove {
                    let multiplier = 1_u32 << u32::from(peer.failures.min(5));
                    peer.next_sync = now
                        + DYNAMIC_PEER_RETRY_INTERVAL
                            .saturating_mul(multiplier)
                            .min(MAX_DYNAMIC_PEER_BACKOFF);
                }
                remove
            }
            None => return Ok(()),
        };
        if remove {
            state.peers.remove(&address);
            state.next_discovery.remove(&address);
        }
        Ok(())
    }

    /// Verified peers without a recent failure, for immediate new-tip relay.
    fn announce_targets(&self, limit: usize) -> Result<Vec<SocketAddr>, P2pError> {
        let state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerDiscovery)?;
        Ok(state
            .peers
            .iter()
            .filter_map(|(address, peer)| (peer.verified && peer.failures == 0).then_some(*address))
            .take(limit)
            .collect())
    }

    fn gossip_addresses(&self, exclude: SocketAddr) -> Result<Vec<SocketAddr>, P2pError> {
        let state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerDiscovery)?;
        Ok(state
            .peers
            .iter()
            .filter_map(|(address, peer)| {
                (peer.verified && *address != exclude).then_some(*address)
            })
            .take(MAX_GOSSIP_PEERS)
            .collect())
    }

    fn discovery_due(&self, address: SocketAddr) -> Result<bool, P2pError> {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerDiscovery)?;
        if state
            .next_discovery
            .get(&address)
            .is_some_and(|deadline| *deadline > now)
        {
            return Ok(false);
        }
        state
            .next_discovery
            .insert(address, now + DISCOVERY_REFRESH_INTERVAL);
        Ok(true)
    }

    fn defer_discovery(&self, address: SocketAddr) -> Result<(), P2pError> {
        self.state
            .lock()
            .map_err(|_| P2pError::PoisonedPeerDiscovery)?
            .next_discovery
            .insert(
                address,
                Instant::now() + DISCOVERY_UNSUPPORTED_RETRY_INTERVAL,
            );
        Ok(())
    }
}

fn load_peer_cache(
    path: &Path,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    listen_address: SocketAddr,
    address_policy: PeerAddressPolicy,
) -> Result<Vec<SocketAddr>, io::Error> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if metadata.len() > MAX_PEER_CACHE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer cache exceeds its byte limit",
        ));
    }
    let contents = fs::read_to_string(path)?;
    let mut lines = contents.lines();
    let expected_network_id = hex::encode(network_id);
    let expected_consensus_fingerprint = hex::encode(consensus_fingerprint);
    if lines.next() != Some(PEER_CACHE_MAGIC)
        || lines.next() != Some(expected_network_id.as_str())
        || lines.next() != Some(expected_consensus_fingerprint.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer cache identity does not match this network",
        ));
    }
    let mut addresses = Vec::new();
    for line in lines {
        let address: SocketAddr = line.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "peer cache address is invalid")
        })?;
        validate_peer_address(address, address_policy)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if address != listen_address && !addresses.contains(&address) {
            addresses.push(address);
        }
        if addresses.len() >= MAX_DISCOVERED_PEERS {
            break;
        }
    }
    Ok(addresses)
}

fn write_peer_cache(
    path: &Path,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    addresses: &[SocketAddr],
) -> Result<(), io::Error> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    writeln!(file, "{PEER_CACHE_MAGIC}")?;
    writeln!(file, "{}", hex::encode(network_id))?;
    writeln!(file, "{}", hex::encode(consensus_fingerprint))?;
    for address in addresses.iter().take(MAX_DISCOVERED_PEERS) {
        writeln!(file, "{address}")?;
    }
    file.sync_all()
}

impl SyncReport {
    pub fn up_to_date(&self) -> bool {
        self.inventory_items == 0
            && self
                .transaction_inventory_items
                .saturating_sub(self.already_known_transactions)
                <= self.requested_transactions
    }
}

fn discover_peers_from_peer_once_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    discovery: &Arc<PeerDiscovery>,
    nonce_override: Option<[u8; 32]>,
    active_sockets: Option<&Arc<ActiveSocketRegistry>>,
) -> Result<PeerDiscoveryReport, P2pError> {
    let hello = with_nonce(lock_node(&shared)?.peer_hello(), nonce_override);
    let session = PeerSession::new(hello, limits)?;
    let mut connection = PeerConnection::connect_with_policy(address, session, address_policy)?;
    if let Some(registry) = active_sockets {
        connection.set_cancellation(Arc::clone(&registry.stopping));
    }
    let _active_socket = match active_sockets {
        Some(registry) => Some(registry.register(connection.try_clone_stream()?)?),
        None => None,
    };
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;
    connection.send(PeerMessage::GetPeers {
        listen_port: discovery.listen_address.port(),
    })?;
    let addresses = expect_peers(connection.receive()?)?;
    discovery.add_candidates(&addresses)?;
    Ok(PeerDiscoveryReport {
        remote_hello,
        addresses,
    })
}

/// Fetches one complete immutable mining template without downloading or
/// maintaining the remote node's chain. The node chooses all block contents;
/// the caller only searches the returned challenge.
pub fn request_mining_template_once_with_policy(
    address: SocketAddr,
    payout: [u8; 32],
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<MiningTemplateResponse, P2pError> {
    request_mining_template_once_with_hello_and_policy(
        address,
        payout,
        thin_miner_hello()?,
        limits,
        address_policy,
    )
}

/// ProductionV3 template request whose handshake identity can only be issued
/// by an already authenticated mining-work factory.
#[cfg(feature = "production-v3")]
pub fn request_production_v3_mining_template_once_with_policy(
    address: SocketAddr,
    payout: [u8; 32],
    identity: ProductionV3MiningPeerIdentity,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<MiningTemplateResponse, P2pError> {
    request_mining_template_once_with_hello_and_policy(
        address,
        payout,
        identity.peer_hello(),
        limits,
        address_policy,
    )
}

fn request_mining_template_once_with_hello_and_policy(
    address: SocketAddr,
    payout: [u8; 32],
    hello: PeerHello,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<MiningTemplateResponse, P2pError> {
    let session = PeerSession::new(hello, limits)?;
    let mut connection = PeerConnection::connect_with_policy(address, session, address_policy)?;
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;
    connection.send(PeerMessage::GetMiningTemplate { payout })?;
    let template = expect_mining_template(connection.receive()?)?;
    if template.challenge.previous_block != remote_hello.tip
        || template.challenge.height != remote_hello.height.saturating_add(1)
    {
        return Err(P2pError::UnexpectedMiningTemplate);
    }
    if !matches!(
        template.coinbase.outputs.first(),
        Some(cmfd_consensus::TxOutput {
            lock: cmfd_consensus::OutputLock::Key(destination),
            ..
        }) if *destination == payout
    ) {
        return Err(P2pError::UnexpectedMiningPayout);
    }
    Ok(MiningTemplateResponse {
        remote_hello,
        template,
    })
}

/// Submits a complete node-selected template with its mined proof. Consensus
/// validation and durable acceptance remain exclusively on the receiving node.
pub fn submit_mined_block_once_with_policy(
    address: SocketAddr,
    block: Block,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<BlockSubmissionResult, P2pError> {
    submit_mined_block_once_with_policy_deadline(
        address,
        block,
        thin_miner_hello()?,
        limits,
        address_policy,
        None,
        None,
    )
}

/// ProductionV3 exact-block submission using the identity issued by the
/// authenticated mining-work factory.
#[cfg(feature = "production-v3")]
pub fn submit_production_v3_mined_block_once_with_policy(
    address: SocketAddr,
    block: Block,
    identity: ProductionV3MiningPeerIdentity,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<BlockSubmissionResult, P2pError> {
    submit_mined_block_once_with_policy_deadline(
        address,
        block,
        identity.peer_hello(),
        limits,
        address_policy,
        None,
        None,
    )
}

/// Same exact-block submission with an additional caller-owned absolute
/// deadline. This is used by bounded Busy/reconnect retry so connect,
/// handshake, request, and response cannot overrun the retained candidate's
/// total retry budget.
pub fn submit_mined_block_once_with_policy_before(
    address: SocketAddr,
    block: Block,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    deadline: Instant,
) -> Result<BlockSubmissionResult, P2pError> {
    submit_mined_block_once_with_policy_deadline(
        address,
        block,
        thin_miner_hello()?,
        limits,
        address_policy,
        Some(deadline),
        None,
    )
}

/// Same exact-block submission as [`submit_mined_block_once_with_policy_before`],
/// with cancellation threaded through connect, handshake, request write, and
/// response read. Each connect attempt and every established-socket I/O wait
/// polls cancellation at a short bounded interval.
pub fn submit_mined_block_once_with_policy_before_cancellable(
    address: SocketAddr,
    block: Block,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    deadline: Instant,
    cancellation: Arc<AtomicBool>,
) -> Result<BlockSubmissionResult, P2pError> {
    submit_mined_block_once_with_policy_deadline(
        address,
        block,
        thin_miner_hello()?,
        limits,
        address_policy,
        Some(deadline),
        Some(cancellation),
    )
}

/// ProductionV3 exact-block submission with a caller-owned deadline and
/// cancellation, retaining the factory-authenticated peer identity across
/// reconnect attempts.
#[cfg(feature = "production-v3")]
pub fn submit_production_v3_mined_block_once_with_policy_before_cancellable(
    address: SocketAddr,
    block: Block,
    identity: ProductionV3MiningPeerIdentity,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    deadline: Instant,
    cancellation: Arc<AtomicBool>,
) -> Result<BlockSubmissionResult, P2pError> {
    submit_mined_block_once_with_policy_deadline(
        address,
        block,
        identity.peer_hello(),
        limits,
        address_policy,
        Some(deadline),
        Some(cancellation),
    )
}

fn submit_mined_block_once_with_policy_deadline(
    address: SocketAddr,
    block: Block,
    local_hello: PeerHello,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    deadline: Option<Instant>,
    cancellation: Option<Arc<AtomicBool>>,
) -> Result<BlockSubmissionResult, P2pError> {
    let submitted = block.block_id();
    let session = PeerSession::new(local_hello, limits)?;
    let mut connection = match (deadline, cancellation) {
        (Some(deadline), Some(cancellation)) => {
            PeerConnection::connect_with_policy_before_cancellable(
                address,
                session,
                address_policy,
                deadline,
                cancellation,
            )?
        }
        (Some(deadline), None) => {
            PeerConnection::connect_with_policy_before(address, session, address_policy, deadline)?
        }
        (None, None) => PeerConnection::connect_with_policy(address, session, address_policy)?,
        (None, Some(_)) => unreachable!("cancellable submission always has a deadline"),
    };
    connection.send_hello()?;
    expect_hello(connection.receive()?)?;
    connection.send(PeerMessage::SubmitBlock(block))?;
    let result = expect_block_submission_result(connection.receive_submit_block_response()?)?;
    if result.block_id != submitted {
        return Err(P2pError::WrongBlockSubmission {
            submitted,
            actual: result.block_id,
        });
    }
    Ok(result)
}

fn thin_miner_hello() -> Result<PeerHello, P2pError> {
    let params = crate::thin_miner_network_params()?;
    Ok(PeerHello {
        network_id: params.network_id,
        consensus_fingerprint: params.fingerprint().map_err(NodeError::from)?,
        node_nonce: crate::peer::process_node_nonce(),
        tip: params.genesis_hash,
        height: 0,
        cumulative_work: crate::peer::ChainWork::ZERO,
    })
}

/// Performs one bounded pull from a configured peer.
///
/// The remote height and work are informational hints. Every returned block is
/// matched to the requested identifier, checked for parent order, and submitted
/// through the node's fork-aware consensus path. Acceptance time always comes
/// from this process immediately before submission. After block synchronization,
/// unknown advertised transactions are identifier-checked and submitted through
/// the node's normal mempool policy path.
pub fn sync_from_peer_once(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
) -> Result<SyncReport, P2pError> {
    sync_from_peer_once_inner(shared, address, limits, None)
}

/// Performs one bounded pull using the explicitly selected address policy.
///
/// Public Devnet peers remain rejected unless the caller has deliberately
/// selected [`PeerAddressPolicy::AllowPublic`].
pub fn sync_from_peer_once_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<SyncReport, P2pError> {
    sync_from_peer_once_inner_with_policy(shared, address, limits, address_policy, None, None)
}

fn sync_from_peer_once_inner(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    nonce_override: Option<[u8; 32]>,
) -> Result<SyncReport, P2pError> {
    sync_from_peer_once_inner_with_policy(
        shared,
        address,
        limits,
        PeerAddressPolicy::PrivateOnly,
        nonce_override,
        None,
    )
}

#[tracing::instrument(skip_all, fields(peer = %address, direction = "outbound"))]
fn sync_from_peer_once_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    active_sockets: Option<&Arc<ActiveSocketRegistry>>,
) -> Result<SyncReport, P2pError> {
    let observation_address = observed_address(PeerDirection::Outbound, address);
    record_peer_started(
        &shared,
        PeerDirection::Outbound,
        observation_address.clone(),
    );
    let result = perform_sync_from_peer_once_inner_with_policy(
        Arc::clone(&shared),
        address,
        limits,
        address_policy,
        nonce_override,
        active_sockets,
    );
    if let Ok(report) = &result {
        record_peer_succeeded(
            &shared,
            PeerDirection::Outbound,
            observation_address.clone(),
            report.remote_hello,
        );
    }
    if let Err(error) = &result {
        tracing::warn!(%error, "outbound sync from peer failed");
    }
    record_peer_ended(
        &shared,
        PeerDirection::Outbound,
        observation_address,
        result.is_err(),
    );
    result
}

/// Peers advertise using their own bounded session budget. A larger offer is
/// not resource abuse: accept the protocol-sized offer, but download only the
/// prefix that fits our unchanged local session budget.
fn expect_sync_inventory(message: PeerMessage) -> Result<Vec<[u8; 32]>, P2pError> {
    let inventory = expect_inventory(message)?;
    if inventory.len() > MAX_BLOCKS_PER_SYNC {
        return Err(PeerError::CountLimit {
            field: "sync inventory",
            actual: inventory.len(),
            max: MAX_BLOCKS_PER_SYNC,
        }
        .into());
    }
    Ok(inventory)
}

fn perform_sync_from_peer_once_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    active_sockets: Option<&Arc<ActiveSocketRegistry>>,
) -> Result<SyncReport, P2pError> {
    let observation_address = observed_address(PeerDirection::Outbound, address);
    let (hello, locator, mut sync_cursor) = {
        let node = lock_node(&shared)?;
        let hello = node.peer_hello();
        let (locator, cursor) = node.peer_sync_locator(&observation_address, MAX_BLOCKS_PER_SYNC);
        (hello, locator, cursor)
    };
    let block_batch_limit = block_sync_batch_limit(hello.network_id, limits);
    let hello = with_nonce(hello, nonce_override);

    let session = PeerSession::new(hello, limits)?;
    let mut connection = PeerConnection::connect_with_policy(address, session, address_policy)?;
    if let Some(registry) = active_sockets {
        connection.set_cancellation(Arc::clone(&registry.stopping));
    }
    let _active_socket = match active_sockets {
        Some(registry) => Some(registry.register(connection.try_clone_stream()?)?),
        None => None,
    };
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;
    let proof_peer = next_remote_proof_peer_id()?;

    connection.send(PeerMessage::GetHeaders {
        locator,
        stop: remote_hello.tip,
    })?;
    let mut inventory = expect_sync_inventory(connection.receive()?)?;
    let mut inventory_items = inventory.len();
    let mut header_rounds = 1;

    let mut requested_blocks = 0;
    let mut accepted_blocks = 0;
    let mut already_known = 0;
    let mut previous_inventory_id = None;

    loop {
        let mut reached_unknown = false;
        // Already-stored blocks cost no download budget: walking a known prefix
        // one id per session made a deep, already-partly-stored branch unreachable.
        for requested in inventory.iter() {
            let known = {
                let node = lock_node(&shared)?;
                node.contains_block(*requested)
            };
            if known {
                if lock_node(&shared)?.advance_peer_sync_cursor(
                    &observation_address,
                    sync_cursor,
                    *requested,
                ) {
                    sync_cursor = Some(*requested);
                }
                already_known += 1;
                previous_inventory_id = Some(*requested);
                continue;
            }
            reached_unknown = true;
            if requested_blocks >= block_batch_limit {
                break;
            }

            connection.send(PeerMessage::GetBlock {
                block_id: *requested,
            })?;
            let block = expect_block(connection.receive()?)?;
            requested_blocks += 1;

            let actual = block.block_id();
            if actual != *requested {
                return Err(P2pError::WrongBlock {
                    requested: *requested,
                    actual,
                });
            }

            let parent_is_ordered = if let Some(previous) = previous_inventory_id {
                block.challenge.previous_block == previous
            } else {
                let node = lock_node(&shared)?;
                node.contains_block(block.challenge.previous_block)
            };
            if !parent_is_ordered {
                return Err(P2pError::NonContiguousInventory {
                    block_id: *requested,
                });
            }

            let accepted_at = unix_time_seconds()?;
            let acceptance_deadline =
                checked_submit_deadline(Instant::now(), SUBMIT_BLOCK_ACCEPTANCE_BUDGET)?;
            let request = RemoteProofRequest::new(acceptance_deadline);
            // We requested and received this complete, bounded block. Its source
            // may close an idle connection while we verify it or reconstruct a
            // fork. That must not discard local progress and repeat the same work
            // forever. Local shutdown and the fixed admission deadline still win.
            let monitor = PeerSubmissionMonitor::local_validation(
                active_sockets.map(|registry| Arc::clone(&registry.stopping)),
                request.clone(),
            )?;
            let accepted = match submit_shared_peer_block_cancellable(
                &shared,
                block,
                accepted_at,
                proof_peer,
                request,
            ) {
                Ok(_) => true,
                Err(NodeError::DuplicateBlock(_)) => false,
                Err(error) => return Err(error.into()),
            };
            drop(monitor);
            if lock_node(&shared)?.advance_peer_sync_cursor(
                &observation_address,
                sync_cursor,
                *requested,
            ) {
                sync_cursor = Some(*requested);
            }
            if accepted {
                accepted_blocks += 1;
            } else {
                already_known += 1;
            }
            previous_inventory_id = Some(*requested);
        }
        // Peers offer only what fits their own budget (one id for stock mainnet
        // nodes). When the whole offer is already stored, ask again from the
        // advanced cursor in the same session instead of ending it.
        if reached_unknown
            || inventory.is_empty()
            || header_rounds >= MAX_KNOWN_PREFIX_HEADER_ROUNDS
        {
            break;
        }
        let locator = lock_node(&shared)?
            .peer_sync_locator(&observation_address, MAX_BLOCKS_PER_SYNC)
            .0;
        connection.send(PeerMessage::GetHeaders {
            locator,
            stop: remote_hello.tip,
        })?;
        inventory = expect_sync_inventory(connection.receive()?)?;
        inventory_items += inventory.len();
        header_rounds += 1;
    }

    connection.send(PeerMessage::GetMempool)?;
    let transaction_inventory = expect_transaction_inventory(connection.receive()?)?;
    let known_transactions: HashSet<_> = {
        let node = lock_node(&shared)?;
        node.mempool_entries().map(|entry| entry.txid).collect()
    };
    let already_known_transactions = transaction_inventory
        .iter()
        .filter(|txid| known_transactions.contains(*txid))
        .count();
    let mut requested_transactions = 0;
    let mut accepted_transactions = 0;
    let mut rejected_transactions = 0;

    for requested in transaction_inventory
        .iter()
        .filter(|txid| !known_transactions.contains(*txid))
        .take(MAX_TRANSACTIONS_PER_SYNC)
    {
        connection.send(PeerMessage::GetTransaction { txid: *requested })?;
        let transaction = expect_transaction(connection.receive()?)?;
        requested_transactions += 1;

        let actual = transaction.txid();
        if actual != *requested {
            return Err(P2pError::WrongTransaction {
                requested: *requested,
                actual,
            });
        }

        // Admission is the node's normal atomic policy/consensus path. An
        // invalid peer candidate is isolated to the mempool and must not stop
        // later static peers or mutate chain state.
        let admission = {
            let mut node = lock_node(&shared)?;
            node.submit_transaction(transaction)
        };
        if admission.is_ok() {
            accepted_transactions += 1;
        } else {
            rejected_transactions += 1;
        }
    }

    Ok(SyncReport {
        remote_hello,
        inventory_items,
        requested_blocks,
        accepted_blocks,
        already_known,
        transaction_inventory_items: transaction_inventory.len(),
        requested_transactions,
        accepted_transactions,
        already_known_transactions,
        rejected_transactions,
    })
}

/// Offers a byte-budgeted prefix of locally active blocks that follows the
/// peer's advertised tip. Each block is acknowledged only after the peer has
/// passed it through its normal durable consensus path. A later poll continues
/// from the peer's new tip, so temporary disconnects recover in bounded steps.
pub fn relay_blocks_to_peer_once_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<RelayReport, P2pError> {
    relay_blocks_to_peer_once_inner_with_policy(shared, address, limits, address_policy, None, None)
}

#[tracing::instrument(skip_all, fields(peer = %address, direction = "outbound"))]
fn relay_blocks_to_peer_once_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    active_sockets: Option<&Arc<ActiveSocketRegistry>>,
) -> Result<RelayReport, P2pError> {
    let observation_address = observed_address(PeerDirection::Outbound, address);
    record_peer_started(
        &shared,
        PeerDirection::Outbound,
        observation_address.clone(),
    );
    let result = perform_relay_blocks_to_peer_once_inner_with_policy(
        Arc::clone(&shared),
        address,
        limits,
        address_policy,
        nonce_override,
        active_sockets,
    );
    if let Ok(report) = &result {
        record_peer_succeeded(
            &shared,
            PeerDirection::Outbound,
            observation_address.clone(),
            report.remote_hello,
        );
    }
    if let Err(error) = &result {
        tracing::warn!(%error, "outbound relay to peer failed");
    }
    record_peer_ended(
        &shared,
        PeerDirection::Outbound,
        observation_address,
        result.is_err(),
    );
    result
}

fn perform_relay_blocks_to_peer_once_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    active_sockets: Option<&Arc<ActiveSocketRegistry>>,
) -> Result<RelayReport, P2pError> {
    let hello = with_nonce(
        {
            let node = lock_node(&shared)?;
            node.peer_hello()
        },
        nonce_override,
    );
    let network_id = hello.network_id;
    let block_batch_limit = block_sync_batch_limit(network_id, limits);
    let session = PeerSession::new(hello, limits)?;
    let mut connection = PeerConnection::connect_with_policy(address, session, address_policy)?;
    if let Some(registry) = active_sockets {
        connection.set_cancellation(Arc::clone(&registry.stopping));
    }
    let _active_socket = match active_sockets {
        Some(registry) => Some(registry.register(connection.try_clone_stream()?)?),
        None => None,
    };
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;

    let observation_address = observed_address(PeerDirection::Outbound, address);
    let (block_ids, mut relay_cursor) = {
        let node = lock_node(&shared)?;
        node.peer_relay_inventory(&observation_address, remote_hello.tip, block_batch_limit)
    };
    let mut accepted_blocks = 0;
    let mut already_known = 0;
    let mut peer_height = remote_hello.height;
    let mut peer_tip = remote_hello.tip;

    for block_id in &block_ids {
        let canonical = {
            let mut node = lock_node(&shared)?;
            node.canonical_block(*block_id)?
        }
        .ok_or(P2pError::UnknownRequestedBlock(*block_id))?;
        let block = decode_block(&canonical, network_id)?;
        let actual = block.block_id();
        if actual != *block_id {
            return Err(P2pError::WrongBlock {
                requested: *block_id,
                actual,
            });
        }

        connection.send(PeerMessage::SubmitBlock(block))?;
        let result = expect_block_submission_result(connection.receive_submit_block_response()?)?;
        if result.block_id != *block_id {
            return Err(P2pError::WrongBlockSubmission {
                submitted: *block_id,
                actual: result.block_id,
            });
        }
        peer_height = result.peer_height;
        peer_tip = result.peer_tip;
        match result.status {
            BlockSubmissionStatus::Accepted => accepted_blocks += 1,
            BlockSubmissionStatus::AlreadyKnown => already_known += 1,
            BlockSubmissionStatus::Rejected => {
                lock_node(&shared)?.set_peer_relay_cursor(&observation_address, relay_cursor, None);
                return Err(P2pError::RejectedBlockSubmission(*block_id));
            }
            BlockSubmissionStatus::Busy => {
                return Err(P2pError::BusyBlockSubmission(*block_id));
            }
        }
        if lock_node(&shared)?.set_peer_relay_cursor(
            &observation_address,
            relay_cursor,
            Some(*block_id),
        ) {
            relay_cursor = Some(*block_id);
        }
    }

    // Static peers are normally outbound-only from wallets behind NAT. Ask
    // what the peer already knows, then advertise a bounded prefix of our
    // remaining mempool through the same canonical transaction frame used by
    // pull synchronization. The receiver still applies its ordinary atomic
    // mempool policy; this path never bypasses validation.
    connection.send(PeerMessage::GetMempool)?;
    let remote_transactions: HashSet<_> = expect_transaction_inventory(connection.receive()?)?
        .into_iter()
        .collect();
    let transactions = {
        let node = lock_node(&shared)?;
        node.mempool_entries()
            .filter(|entry| !remote_transactions.contains(&entry.txid))
            .take(MAX_TRANSACTIONS_PER_SYNC)
            .map(|entry| (entry.txid, entry.transaction.clone()))
            .collect::<Vec<_>>()
    };
    for (txid, transaction) in &transactions {
        let actual = transaction.txid();
        if actual != *txid {
            return Err(P2pError::WrongTransaction {
                requested: *txid,
                actual,
            });
        }
        connection.send(PeerMessage::Transaction(transaction.clone()))?;
    }

    Ok(RelayReport {
        remote_hello,
        offered_blocks: block_ids.len(),
        accepted_blocks,
        already_known,
        offered_transactions: transactions.len(),
        peer_height,
        peer_tip,
    })
}

/// Serves one already-accepted inbound connection until the peer closes it or
/// violates the bounded protocol.
pub fn respond_to_peer(
    shared: Arc<Mutex<Node>>,
    stream: TcpStream,
    limits: PeerLimits,
) -> Result<(), P2pError> {
    respond_to_peer_inner(shared, stream, limits, None)
}

fn respond_to_peer_inner(
    shared: Arc<Mutex<Node>>,
    stream: TcpStream,
    limits: PeerLimits,
    nonce_override: Option<[u8; 32]>,
) -> Result<(), P2pError> {
    respond_to_peer_inner_with_policy(
        shared,
        stream,
        limits,
        PeerAddressPolicy::PrivateOnly,
        nonce_override,
        None,
        None,
    )
}

fn respond_to_peer_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    stream: TcpStream,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    cancellation: Option<Arc<AtomicBool>>,
    discovery: Option<Arc<PeerDiscovery>>,
) -> Result<(), P2pError> {
    let security = discovery.as_ref().map_or_else(
        || Arc::new(PeerSecurity::default()),
        |discovery| Arc::clone(&discovery.security),
    );
    respond_to_peer_inner_with_options(
        shared,
        stream,
        limits,
        InboundPeerOptions {
            address_policy,
            nonce_override,
            cancellation,
            discovery,
            security,
        },
    )
}

#[derive(Clone)]
struct InboundPeerOptions {
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    cancellation: Option<Arc<AtomicBool>>,
    discovery: Option<Arc<PeerDiscovery>>,
    security: Arc<PeerSecurity>,
}

fn respond_to_peer_inner_with_options(
    shared: Arc<Mutex<Node>>,
    stream: TcpStream,
    limits: PeerLimits,
    options: InboundPeerOptions,
) -> Result<(), P2pError> {
    let remote_address = stream.peer_addr().map_err(P2pError::ListenerIo)?;
    let span =
        tracing::info_span!("respond_to_peer", peer = %remote_address, direction = "inbound");
    let _entered = span.enter();
    let observation_address = observed_address(PeerDirection::Inbound, remote_address);
    record_peer_started(&shared, PeerDirection::Inbound, observation_address.clone());
    let security = Arc::clone(&options.security);
    let mut handshake_complete = false;
    let result = perform_respond_to_peer_inner_with_policy(
        Arc::clone(&shared),
        stream,
        limits,
        remote_address,
        observation_address.clone(),
        options,
        &mut handshake_complete,
    );
    match &result {
        Ok(()) => {
            if let Err(error) = security.record_success(remote_address.ip()) {
                tracing::warn!(%error, "failed to update peer reputation after successful session");
            }
        }
        Err(error) => {
            let (penalty, reason) = inbound_reputation_penalty(error, handshake_complete);
            if let Err(reputation_error) =
                security.record_failure(remote_address.ip(), penalty, reason)
            {
                tracing::warn!(%reputation_error, "failed to update peer reputation after failed session");
            }
        }
    }
    if let Err(error) = &result {
        tracing::warn!(%error, "inbound peer session ended with error");
    }
    record_peer_ended(
        &shared,
        PeerDirection::Inbound,
        observation_address,
        result.is_err(),
    );
    result
}

fn perform_respond_to_peer_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    stream: TcpStream,
    limits: PeerLimits,
    remote_address: SocketAddr,
    observation_address: String,
    options: InboundPeerOptions,
    handshake_complete: &mut bool,
) -> Result<(), P2pError> {
    let hello = {
        let node = lock_node(&shared)?;
        with_nonce(node.peer_hello(), options.nonce_override)
    };
    let network_id = hello.network_id;
    let block_batch_limit = block_sync_batch_limit(network_id, limits);
    let limits = compressed_limits(&options.security, remote_address, limits);
    let session = PeerSession::new(hello, limits)?;
    let mut connection =
        PeerConnection::from_stream_with_policy(stream, session, options.address_policy)?;
    if let Some(cancellation) = options.cancellation {
        connection.set_cancellation(cancellation);
    }
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;
    *handshake_complete = true;
    let proof_peer = next_remote_proof_peer_id()?;
    record_peer_succeeded(
        &shared,
        PeerDirection::Inbound,
        observation_address,
        remote_hello,
    );

    let mut block_was_served = false;
    loop {
        let received = if block_was_served {
            connection.receive_after_served_block()
        } else {
            connection.receive()
        };
        block_was_served = false;
        let message = match received {
            Ok(message) => message,
            Err(PeerError::ConnectionClosed) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        match message {
            PeerMessage::GetHeaders { locator, stop } => {
                let block_ids = {
                    let node = lock_node(&shared)?;
                    node.inventory_after(&locator, stop, block_batch_limit)
                };
                connection.send(PeerMessage::Inventory { block_ids })?;
            }
            PeerMessage::GetBlock { block_id } => {
                let canonical = {
                    let mut node = lock_node(&shared)?;
                    node.canonical_block(block_id)?
                }
                .ok_or(P2pError::UnknownRequestedBlock(block_id))?;
                let block = decode_block(&canonical, network_id)?;
                if block.block_id() != block_id {
                    return Err(P2pError::WrongBlock {
                        requested: block_id,
                        actual: block.block_id(),
                    });
                }
                connection.send(PeerMessage::Block(block))?;
                block_was_served = true;
            }
            PeerMessage::GetMempool => {
                let txids = {
                    let node = lock_node(&shared)?;
                    node.mempool_entries().map(|entry| entry.txid).collect()
                };
                connection.send(PeerMessage::TransactionInventory { txids })?;
            }
            PeerMessage::GetTransaction { txid } => {
                let transaction = {
                    let node = lock_node(&shared)?;
                    node.mempool_entries()
                        .find(|entry| entry.txid == txid)
                        .map(|entry| entry.transaction.clone())
                }
                .ok_or(P2pError::UnknownRequestedTransaction(txid))?;
                if transaction.txid() != txid {
                    return Err(P2pError::WrongTransaction {
                        requested: txid,
                        actual: transaction.txid(),
                    });
                }
                connection.send(PeerMessage::Transaction(transaction))?;
            }
            PeerMessage::Transaction(transaction) => {
                let txid = transaction.txid();
                let admission = {
                    let mut node = lock_node(&shared)?;
                    node.submit_transaction(transaction)
                };
                match admission {
                    Ok(_) | Err(NodeError::DuplicateMempoolTransaction(_)) => {}
                    Err(NodeError::MempoolTransactionLimit | NodeError::MempoolByteLimit) => {}
                    Err(error) if error.client_error().status < 500 => {
                        let peer_fault = transaction_rejection_is_peer_fault(&error);
                        tracing::debug!(
                            txid = %hex::encode(txid),
                            %error,
                            peer_fault,
                            "rejected relayed transaction"
                        );
                        if peer_fault
                            && options.security.record_failure(
                                remote_address.ip(),
                                INVALID_TRANSACTION_PENALTY,
                                "intrinsically invalid transaction",
                            )?
                        {
                            return Err(P2pError::PeerTemporarilyBanned(remote_address.ip()));
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            PeerMessage::GetMiningTemplate { payout } => {
                let template = {
                    let node = lock_node(&shared)?;
                    node.build_template(payout, unix_time_seconds()?)?
                };
                connection.send(PeerMessage::MiningTemplate(crate::peer::MiningTemplate {
                    challenge: template.challenge,
                    coinbase: template.coinbase,
                    transactions: template.transactions,
                }))?;
            }
            PeerMessage::SubmitBlock(block) => {
                let started = Instant::now();
                let block_id = block.block_id();
                let block_height = block.challenge.height;
                let accepted_at = unix_time_seconds()?;
                let acceptance_deadline =
                    checked_submit_deadline(started, SUBMIT_BLOCK_ACCEPTANCE_BUDGET)?;
                let response_deadline =
                    checked_submit_deadline(started, SUBMIT_BLOCK_SERVER_RESPONSE_BUDGET)?;
                let request = RemoteProofRequest::new(acceptance_deadline);
                let monitor = PeerSubmissionMonitor::start(&connection, request.clone())?;
                let status = match submit_shared_peer_block_cancellable(
                    &shared,
                    block,
                    accepted_at,
                    proof_peer,
                    request,
                ) {
                    Ok(_) => BlockSubmissionStatus::Accepted,
                    Err(NodeError::DuplicateBlock(_)) => BlockSubmissionStatus::AlreadyKnown,
                    Err(error) if is_retryable_block_admission(&error) => {
                        // The wire status cannot carry a reason, and peers
                        // report every retryable cause with the same deferred status.
                        tracing::warn!(
                            block_id = %hex::encode(block_id),
                            height = block_height,
                            reason = error.client_error().code,
                            %error,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "deferred submitted block"
                        );
                        BlockSubmissionStatus::Busy
                    }
                    Err(error) if error.client_error().status < 500 => {
                        tracing::warn!(
                            block_id = %hex::encode(block_id),
                            height = block_height,
                            reason = error.client_error().code,
                            %error,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "rejected submitted block"
                        );
                        BlockSubmissionStatus::Rejected
                    }
                    Err(error) => return Err(error.into()),
                };
                drop(monitor);
                send_block_submission_result_before(
                    &shared,
                    &mut connection,
                    block_id,
                    status,
                    response_deadline,
                )?;
                if status == BlockSubmissionStatus::Rejected
                    && options.security.record_failure(
                        remote_address.ip(),
                        INVALID_BLOCK_PENALTY,
                        "deterministically rejected block",
                    )?
                {
                    return Err(P2pError::PeerTemporarilyBanned(remote_address.ip()));
                }
            }
            PeerMessage::GetPeers { listen_port } => {
                let Some(discovery) = options.discovery.as_ref() else {
                    return Err(P2pError::UnexpectedMessage {
                        expected: "GetHeaders, GetBlock, GetMempool, GetTransaction, Transaction, GetMiningTemplate, or SubmitBlock",
                        actual: "GetPeers",
                    });
                };
                let advertised = SocketAddr::new(remote_address.ip(), listen_port);
                discovery.add_candidate(advertised)?;
                let addresses = discovery.gossip_addresses(advertised)?;
                connection.send(PeerMessage::Peers { addresses })?;
            }
            other => {
                return Err(P2pError::UnexpectedMessage {
                    expected: "GetHeaders, GetBlock, GetMempool, GetTransaction, Transaction, GetMiningTemplate, SubmitBlock, or GetPeers",
                    actual: message_name(&other),
                });
            }
        }
    }
}

fn is_retryable_block_admission(error: &NodeError) -> bool {
    error.client_error().retryable
}

/// Blame a relaying peer only for invalidity intrinsic to the transaction.
/// Missing/immature inputs, conflicts, fees, custody policy and aggregate
/// mempool limits can differ between honest nodes, especially during catch-up.
/// Unknown errors stay nonpunitive; malformed wire frames are handled separately.
fn transaction_rejection_is_peer_fault(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::Chain(
            ChainError::WrongNetwork
                | ChainError::UnsupportedTransactionVersion
                | ChainError::NoInputs
                | ChainError::NoOutputs
                | ChainError::ZeroValueOutput
                | ChainError::MalformedSignature
                | ChainError::InvalidSignature
                | ChainError::TransactionInputLimit
                | ChainError::TransactionOutputLimit
                | ChainError::SignatureLength
        ) | NodeError::Wire(
            WireError::WrongNetworkId { .. }
                | WireError::SizeLimit { .. }
                | WireError::CountLimit { .. }
                | WireError::SignatureLength { .. }
                | WireError::LengthOverflow
        )
    )
}

fn inbound_reputation_penalty(error: &P2pError, handshake_complete: bool) -> (u16, &'static str) {
    match error {
        P2pError::Peer(
            PeerError::PayloadTooLarge { .. }
            | PeerError::CountLimit { .. }
            | PeerError::PeerBudgetExceeded,
        ) => (RESOURCE_ABUSE_PENALTY, "peer resource limit violation"),
        // A peer with a larger valid session budget may relay more
        // protocol-sized blocks than ours accepts. Closing the session already
        // bounds the cost, and the next session resumes after the accepted
        // prefix. Oversized frames and message floods remain abuse above.
        P2pError::Peer(PeerError::Cancelled | PeerError::PeerByteBudgetReached)
        | P2pError::PeerTemporarilyBanned(_) => (0, "no peer fault"),
        P2pError::Peer(
            PeerError::ConnectionClosed
            | PeerError::TotalTimeout
            | PeerError::IdleTimeout
            | PeerError::SubmitBlockResponseTimeout
            | PeerError::BlockValidationWaitTimeout
            | PeerError::Io(_),
        ) => {
            // Stock clients send their hello immediately after connecting, but
            // may pause between later requests while their node validates a
            // block or waits for its node lock. Such slowness is bounded by
            // the session timeouts and per-IP limits, not evidence of abuse.
            if handshake_complete {
                (0, "no peer fault")
            } else {
                (TRANSIENT_FAILURE_PENALTY, "inbound transport churn")
            }
        }
        P2pError::Peer(_) | P2pError::UnexpectedMessage { .. } => {
            (PROTOCOL_VIOLATION_PENALTY, "peer protocol violation")
        }
        P2pError::UnknownRequestedBlock(_) | P2pError::UnknownRequestedTransaction(_) => {
            (UNKNOWN_REQUEST_PENALTY, "peer requested unknown data")
        }
        _ => (0, "no peer fault"),
    }
}

fn outbound_reputation_penalty(error: &P2pError) -> (u16, &'static str) {
    match error {
        P2pError::Peer(
            PeerError::PayloadTooLarge { .. }
            | PeerError::CountLimit { .. }
            | PeerError::PeerBudgetExceeded
            | PeerError::PeerByteBudgetReached,
        ) => (RESOURCE_ABUSE_PENALTY, "remote resource limit violation"),
        P2pError::Peer(
            PeerError::ConnectionClosed
            | PeerError::TotalTimeout
            | PeerError::IdleTimeout
            | PeerError::SubmitBlockResponseTimeout
            | PeerError::BlockValidationWaitTimeout
            | PeerError::Cancelled
            | PeerError::Io(_),
        )
        | P2pError::RejectedBlockSubmission(_)
        | P2pError::BusyBlockSubmission(_) => (0, "no remote peer fault"),
        P2pError::Peer(_)
        | P2pError::UnexpectedMessage { .. }
        | P2pError::WrongBlock { .. }
        | P2pError::WrongTransaction { .. }
        | P2pError::WrongBlockSubmission { .. }
        | P2pError::NonContiguousInventory { .. }
        | P2pError::UnexpectedMiningTemplate
        | P2pError::UnexpectedMiningPayout => {
            (PROTOCOL_VIOLATION_PENALTY, "remote peer protocol violation")
        }
        _ => (0, "no remote peer fault"),
    }
}

fn checked_submit_deadline(start: Instant, budget: Duration) -> Result<Instant, P2pError> {
    start
        .checked_add(budget)
        .ok_or(P2pError::SubmitBlockDeadlineOverflow)
}

fn send_block_submission_result_before(
    shared: &Arc<Mutex<Node>>,
    connection: &mut PeerConnection,
    block_id: [u8; 32],
    status: BlockSubmissionStatus,
    deadline: Instant,
) -> Result<(), P2pError> {
    let peer = lock_node_before(shared, deadline)?.peer_hello();
    connection.send_before(
        PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
            block_id,
            status,
            peer_height: peer.height,
            peer_tip: peer.tip,
        }),
        deadline,
    )?;
    Ok(())
}

/// Watches the otherwise idle inbound half of a request/response session while
/// block admission is waiting. Any EOF, socket error, or pipelined input ends
/// the current submission: honest peers wait for `BlockSubmissionResult`, and
/// treating unexpected input as cancellation prevents unread bytes from
/// masking a FIN behind them.
struct PeerSubmissionMonitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PeerSubmissionMonitor {
    fn local_validation(
        cancellation: Option<Arc<AtomicBool>>,
        request: RemoteProofRequest,
    ) -> Result<Self, P2pError> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = if let Some(cancellation) = cancellation {
            let watcher_stop = Arc::clone(&stop);
            Some(
                thread::Builder::new()
                    .name("cmfd-pull-validation-monitor".to_owned())
                    .spawn(move || {
                        while !watcher_stop.load(Ordering::Acquire) {
                            if cancellation.load(Ordering::Acquire)
                                || Instant::now() >= request.deadline()
                            {
                                request.cancel();
                                break;
                            }
                            thread::sleep(PEER_DISCONNECT_POLL_INTERVAL);
                        }
                    })
                    .map_err(P2pError::ListenerIo)?,
            )
        } else {
            None
        };
        Ok(Self { stop, thread })
    }

    fn start(connection: &PeerConnection, request: RemoteProofRequest) -> Result<Self, P2pError> {
        let stream = connection.try_clone_stream()?;
        stream
            .set_read_timeout(Some(PEER_DISCONNECT_POLL_INTERVAL))
            .map_err(P2pError::ListenerIo)?;
        let stop = Arc::new(AtomicBool::new(false));
        let watcher_request = request.clone();
        let watcher_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("cmfd-peer-submit-monitor".to_owned())
            .spawn(move || {
                let mut byte = [0_u8; 1];
                while !watcher_stop.load(Ordering::Acquire) {
                    if Instant::now() >= watcher_request.deadline() {
                        watcher_request.cancel();
                        break;
                    }
                    match stream.peek(&mut byte) {
                        Ok(_) => {
                            watcher_request.cancel();
                            break;
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                                    | io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => {
                            watcher_request.cancel();
                            break;
                        }
                    }
                }
            })
            .map_err(P2pError::ListenerIo)?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for PeerSubmissionMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn next_remote_proof_peer_id() -> Result<RemoteProofPeerId, P2pError> {
    let value = NEXT_REMOTE_PROOF_PEER_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| P2pError::PeerAdmissionIdentityExhausted)?;
    RemoteProofPeerId::new(value).ok_or(P2pError::PeerAdmissionIdentityExhausted)
}

fn observed_address(direction: PeerDirection, address: SocketAddr) -> String {
    match direction {
        PeerDirection::Inbound => address.ip().to_string(),
        PeerDirection::Outbound => address.to_string(),
    }
}

fn observation_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn record_peer_started(shared: &Arc<Mutex<Node>>, direction: PeerDirection, address: String) {
    if let Ok(mut node) = shared.lock() {
        node.record_peer_started(direction, address, observation_time());
    }
}

fn record_peer_succeeded(
    shared: &Arc<Mutex<Node>>,
    direction: PeerDirection,
    address: String,
    remote_hello: PeerHello,
) {
    if let Ok(mut node) = shared.lock() {
        node.record_peer_succeeded(
            direction,
            address,
            remote_hello.height,
            remote_hello.tip,
            observation_time(),
        );
    }
}

fn record_peer_ended(
    shared: &Arc<Mutex<Node>>,
    direction: PeerDirection,
    address: String,
    failed: bool,
) {
    if let Ok(mut node) = shared.lock() {
        node.record_peer_ended(direction, address, failed, observation_time());
    }
}

/// A stoppable inbound listener. Malformed peer sessions are isolated to their
/// connection; listener failures remain visible through `stop`.
pub struct InboundPeerHandle {
    stop: Arc<AtomicBool>,
    active_sockets: Arc<ActiveSocketRegistry>,
    security: Arc<PeerSecurity>,
    local_address: SocketAddr,
    thread: Option<JoinHandle<Result<(), P2pError>>>,
}

impl InboundPeerHandle {
    pub fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }

    pub fn peer_is_temporarily_banned(&self, ip: IpAddr) -> Result<bool, P2pError> {
        self.security.is_banned(ip)
    }

    pub fn stop(mut self) -> Result<(), P2pError> {
        self.stop.store(true, Ordering::Release);
        let socket_result = self.active_sockets.stop();
        let join_result = join_service_thread(self.thread.take());
        socket_result?;
        join_result
    }
}

impl Drop for InboundPeerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.active_sockets.stop();
    }
}

pub fn spawn_inbound_listener(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    limits: PeerLimits,
) -> Result<InboundPeerHandle, P2pError> {
    spawn_inbound_listener_inner(shared, listener, limits, None)
}

pub fn spawn_inbound_listener_with_policy(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<InboundPeerHandle, P2pError> {
    spawn_inbound_listener_inner_with_policy(shared, listener, limits, address_policy, None, None)
}

pub fn spawn_inbound_listener_with_discovery(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    discovery: Arc<PeerDiscovery>,
) -> Result<InboundPeerHandle, P2pError> {
    spawn_inbound_listener_inner_with_policy(
        shared,
        listener,
        limits,
        address_policy,
        None,
        Some(discovery),
    )
}

fn spawn_inbound_listener_inner(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    limits: PeerLimits,
    nonce_override: Option<[u8; 32]>,
) -> Result<InboundPeerHandle, P2pError> {
    spawn_inbound_listener_inner_with_policy(
        shared,
        listener,
        limits,
        PeerAddressPolicy::PrivateOnly,
        nonce_override,
        None,
    )
}

fn spawn_inbound_listener_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    discovery: Option<Arc<PeerDiscovery>>,
) -> Result<InboundPeerHandle, P2pError> {
    limits.validate()?;
    let local_address = listener.local_addr().map_err(P2pError::ListenerIo)?;
    StaticPeerConfig {
        listen_address: local_address,
        peers: Vec::new(),
        limits,
        address_policy,
    }
    .validate()?;
    listener
        .set_nonblocking(true)
        .map_err(P2pError::ListenerIo)?;

    let stop = Arc::new(AtomicBool::new(false));
    let active_sockets = Arc::new(ActiveSocketRegistry::default());
    let security = discovery.as_ref().map_or_else(
        || Arc::new(PeerSecurity::default()),
        |discovery| Arc::clone(&discovery.security),
    );
    let thread_stop = Arc::clone(&stop);
    let thread_active_sockets = Arc::clone(&active_sockets);
    let options = InboundPeerOptions {
        address_policy,
        nonce_override,
        cancellation: Some(Arc::clone(&thread_stop)),
        discovery,
        security: Arc::clone(&security),
    };
    let thread = thread::Builder::new()
        .name("cmfd-peer-listener".to_owned())
        .spawn(move || {
            listener_loop(
                shared,
                listener,
                limits,
                thread_stop,
                thread_active_sockets,
                options,
            )
        })
        .map_err(P2pError::ListenerIo)?;
    Ok(InboundPeerHandle {
        stop,
        active_sockets,
        security,
        local_address,
        thread: Some(thread),
    })
}

fn listener_loop(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    limits: PeerLimits,
    stop: Arc<AtomicBool>,
    active_sockets: Arc<ActiveSocketRegistry>,
    options: InboundPeerOptions,
) -> Result<(), P2pError> {
    let active = Arc::new(AtomicUsize::new(0));
    let mut workers: Vec<JoinHandle<()>> = Vec::new();

    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, remote_address)) => {
                // Accepted sockets can inherit the listener's nonblocking mode
                // on some platforms. PeerConnection supplies its own bounded
                // blocking read/write deadlines.
                if stream.set_nonblocking(false).is_err() {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                reap_workers(&mut workers);
                let admission = match options.security.reserve_inbound(remote_address.ip())? {
                    PeerAdmission::Accepted(guard) => guard,
                    PeerAdmission::Rejected(reason) => {
                        tracing::debug!(peer = %remote_address, ?reason, "rejected inbound peer admission");
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                };
                if !reserve_connection(&active, limits.max_peers) {
                    tracing::debug!(peer = %remote_address, "rejected inbound peer: connection capacity reached");
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let shutdown_stream = match stream.try_clone() {
                    Ok(stream) => stream,
                    Err(_) => {
                        active.fetch_sub(1, Ordering::AcqRel);
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                };
                let socket_guard = match active_sockets.register(shutdown_stream) {
                    Ok(guard) => guard,
                    Err(P2pError::ServiceStopping) => {
                        active.fetch_sub(1, Ordering::AcqRel);
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    Err(error) => {
                        active.fetch_sub(1, Ordering::AcqRel);
                        let _ = stream.shutdown(Shutdown::Both);
                        return Err(error);
                    }
                };
                let worker_node = Arc::clone(&shared);
                let worker_active = Arc::clone(&active);
                let worker_stop = Arc::clone(&stop);
                let worker_options = options.clone();
                workers.push(thread::spawn(move || {
                    let _admission = admission;
                    let _guard = ActiveConnectionGuard {
                        active: worker_active,
                        _socket: socket_guard,
                    };
                    if worker_stop.load(Ordering::Acquire) {
                        let _ = stream.shutdown(Shutdown::Both);
                        return;
                    }
                    // A malformed or incompatible peer closes only its own
                    // connection; it must not stop the listener. The error is
                    // already logged via tracing inside
                    // respond_to_peer_inner_with_policy.
                    let _ = respond_to_peer_inner_with_options(
                        worker_node,
                        stream,
                        limits,
                        worker_options,
                    );
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(LISTENER_POLL_INTERVAL);
            }
            Err(error) => return Err(P2pError::ListenerIo(error)),
        }
    }

    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn reserve_connection(active: &AtomicUsize, max: usize) -> bool {
    let mut current = active.load(Ordering::Acquire);
    loop {
        if current >= max {
            return false;
        }
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

struct ActiveConnectionGuard {
    active: Arc<AtomicUsize>,
    _socket: ActiveSocketGuard,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Default)]
struct ActiveSocketRegistry {
    stopping: Arc<AtomicBool>,
    next_id: AtomicU64,
    sockets: Mutex<HashMap<u64, TcpStream>>,
}

impl ActiveSocketRegistry {
    fn register(self: &Arc<Self>, stream: TcpStream) -> Result<ActiveSocketGuard, P2pError> {
        let mut sockets = self
            .sockets
            .lock()
            .map_err(|_| P2pError::PoisonedActiveSockets)?;
        if self.stopping.load(Ordering::Acquire) {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(P2pError::ServiceStopping);
        }
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        sockets.insert(id, stream);
        Ok(ActiveSocketGuard {
            registry: Arc::clone(self),
            id,
        })
    }

    fn stop(&self) -> Result<(), P2pError> {
        self.stopping.store(true, Ordering::Release);
        let sockets = self
            .sockets
            .lock()
            .map_err(|_| P2pError::PoisonedActiveSockets)?;
        for stream in sockets.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        Ok(())
    }
}

struct ActiveSocketGuard {
    registry: Arc<ActiveSocketRegistry>,
    id: u64,
}

impl Drop for ActiveSocketGuard {
    fn drop(&mut self) {
        if let Ok(mut sockets) = self.registry.sockets.lock() {
            sockets.remove(&self.id);
        }
    }
}

fn reap_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

/// Stoppable, bounded round-robin static-peer synchronization. Each interval
/// pulls from every configured peer and then offers locally active blocks that
/// follow that peer's tip. Failures never suppress later peers or later rounds.
pub struct StaticPeerPollHandle {
    stop: Arc<(Mutex<bool>, Condvar)>,
    active_sockets: Arc<ActiveSocketRegistry>,
    thread: Option<JoinHandle<()>>,
    announcer: Option<JoinHandle<()>>,
}

struct PeerPollOptions {
    nonce_override: Option<[u8; 32]>,
    discovery: Option<Arc<PeerDiscovery>>,
    security: Arc<PeerSecurity>,
    relay_backoff: Arc<RelayBackoff>,
}

#[derive(Debug, Clone, Copy)]
struct RelayBackoffEntry {
    block_id: [u8; 32],
    repeats: u32,
    until: Option<Instant>,
}

/// Outbound relay back-off for peers that repeatedly defer the same block.
/// Pulling from such a peer is unaffected; only re-offering is delayed.
#[derive(Debug, Default)]
struct RelayBackoff {
    entries: Mutex<HashMap<SocketAddr, RelayBackoffEntry>>,
}

impl RelayBackoff {
    fn allows(&self, peer: SocketAddr, now: Instant) -> bool {
        self.entries.lock().map_or(true, |entries| {
            entries
                .get(&peer)
                .and_then(|entry| entry.until)
                .is_none_or(|until| until <= now)
        })
    }

    fn record(&self, peer: SocketAddr, result: &Result<RelayReport, P2pError>, now: Instant) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        match result {
            Ok(_) => {
                entries.remove(&peer);
            }
            Err(P2pError::BusyBlockSubmission(block_id)) => {
                let entry = entries.entry(peer).or_insert(RelayBackoffEntry {
                    block_id: *block_id,
                    repeats: 0,
                    until: None,
                });
                if entry.block_id != *block_id {
                    *entry = RelayBackoffEntry {
                        block_id: *block_id,
                        repeats: 0,
                        until: None,
                    };
                }
                entry.repeats = entry.repeats.saturating_add(1);
                if entry.repeats >= RELAY_BUSY_REPEATS_BEFORE_BACKOFF {
                    let doublings = (entry.repeats - RELAY_BUSY_REPEATS_BEFORE_BACKOFF).min(5);
                    let backoff = RELAY_BUSY_BACKOFF_BASE
                        .saturating_mul(1 << doublings)
                        .min(RELAY_BUSY_BACKOFF_MAX);
                    entry.until = now.checked_add(backoff);
                }
            }
            Err(_) => {}
        }
        if entries.len() > MAX_DISCOVERED_PEERS * 4 {
            entries.retain(|_, entry| entry.until.is_some_and(|until| until > now));
        }
    }
}

impl StaticPeerPollHandle {
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }

    pub fn stop(mut self) -> Result<(), P2pError> {
        let signal_result = signal_poll_stop(&self.stop);
        let socket_result = self.active_sockets.stop();
        let join_result = self
            .thread
            .take()
            .ok_or(P2pError::ThreadPanicked)?
            .join()
            .map_err(|_| P2pError::ThreadPanicked);
        let announcer_result = match self.announcer.take() {
            Some(announcer) => announcer.join().map_err(|_| P2pError::ThreadPanicked),
            None => Ok(()),
        };
        signal_result?;
        socket_result?;
        join_result?;
        announcer_result
    }
}

impl Drop for StaticPeerPollHandle {
    fn drop(&mut self) {
        if let Ok(mut stopped) = self.stop.0.lock() {
            *stopped = true;
            self.stop.1.notify_all();
        }
        let _ = self.active_sockets.stop();
    }
}

pub fn spawn_static_peer_polling(
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    poll_interval: Duration,
) -> Result<StaticPeerPollHandle, P2pError> {
    spawn_static_peer_polling_inner(shared, config, poll_interval, None)
}

pub fn spawn_peer_polling_with_discovery(
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    poll_interval: Duration,
    discovery: Arc<PeerDiscovery>,
) -> Result<StaticPeerPollHandle, P2pError> {
    spawn_peer_polling_inner(shared, config, poll_interval, None, Some(discovery))
}

fn spawn_static_peer_polling_inner(
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    poll_interval: Duration,
    nonce_override: Option<[u8; 32]>,
) -> Result<StaticPeerPollHandle, P2pError> {
    spawn_peer_polling_inner(shared, config, poll_interval, nonce_override, None)
}

fn spawn_peer_polling_inner(
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    poll_interval: Duration,
    nonce_override: Option<[u8; 32]>,
    discovery: Option<Arc<PeerDiscovery>>,
) -> Result<StaticPeerPollHandle, P2pError> {
    config.validate()?;
    if poll_interval.is_zero() {
        return Err(P2pError::ZeroPollInterval);
    }
    let security = discovery.as_ref().map_or_else(
        || Arc::new(PeerSecurity::default()),
        |discovery| Arc::clone(&discovery.security),
    );
    security.register_static_peers(&config.peers)?;
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let active_sockets = Arc::new(ActiveSocketRegistry::default());
    let thread_stop = Arc::clone(&stop);
    let thread_active_sockets = Arc::clone(&active_sockets);
    let relay_backoff = Arc::new(RelayBackoff::default());
    let announcer = TipAnnouncer {
        shared: Arc::clone(&shared),
        config: config.clone(),
        stop: Arc::clone(&stop),
        active_sockets: Arc::clone(&active_sockets),
        nonce_override,
        discovery: discovery.clone(),
        security: Arc::clone(&security),
        relay_backoff: Arc::clone(&relay_backoff),
        in_flight: Arc::new(Mutex::new(HashSet::new())),
    };
    let announcer = thread::Builder::new()
        .name("cmfd-tip-announce".to_owned())
        .spawn(move || tip_announce_loop(announcer))
        .map_err(P2pError::ListenerIo)?;
    let options = PeerPollOptions {
        nonce_override,
        discovery,
        security,
        relay_backoff,
    };
    let thread = thread::Builder::new()
        .name("cmfd-static-peer-poll".to_owned())
        .spawn(move || {
            static_peer_poll_loop(
                shared,
                config,
                poll_interval,
                thread_stop,
                thread_active_sockets,
                options,
            )
        })
        .map_err(P2pError::ListenerIo);
    let thread = match thread {
        Ok(thread) => thread,
        Err(error) => {
            let _ = signal_poll_stop(&stop);
            let _ = announcer.join();
            return Err(error);
        }
    };
    Ok(StaticPeerPollHandle {
        stop,
        active_sockets,
        thread: Some(thread),
        announcer: Some(announcer),
    })
}

#[derive(Clone)]
struct TipAnnouncer {
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    stop: Arc<(Mutex<bool>, Condvar)>,
    active_sockets: Arc<ActiveSocketRegistry>,
    nonce_override: Option<[u8; 32]>,
    discovery: Option<Arc<PeerDiscovery>>,
    security: Arc<PeerSecurity>,
    relay_backoff: Arc<RelayBackoff>,
    in_flight: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl TipAnnouncer {
    /// The active tip and whether it is recent enough to be news worth
    /// pushing; `None` when the node lock is busy.
    fn observe_tip(&self) -> Option<([u8; 32], bool)> {
        let node = self.shared.try_lock().ok()?;
        let fresh = unix_time_seconds().is_ok_and(|now| {
            now.saturating_sub(node.state.median_time_past()) <= TIP_ANNOUNCE_MAX_MEDIAN_AGE_SECONDS
        });
        Some((node.state.tip(), fresh))
    }

    fn targets(&self) -> Vec<SocketAddr> {
        let mut targets = self.config.peers.clone();
        if let Some(discovery) = self.discovery.as_ref() {
            match discovery.announce_targets(MAX_TIP_ANNOUNCE_TARGETS) {
                Ok(dynamic) => {
                    for address in dynamic {
                        if !targets.contains(&address) {
                            targets.push(address);
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "tip announce target selection failed"),
            }
        }
        targets.retain(|peer| matches!(self.security.is_banned(peer.ip()), Ok(false)));
        targets
    }

    fn claim(&self, peer: SocketAddr) -> bool {
        self.in_flight
            .lock()
            .is_ok_and(|mut in_flight| in_flight.insert(peer))
    }

    fn release(&self, peer: SocketAddr) {
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.remove(&peer);
        }
    }

    /// Relays through the ordinary bounded relay path, so every limit, cursor
    /// and validation rule is unchanged. Repeats only if the tip moved while
    /// the previous relay was in flight.
    fn announce(&self, peer: SocketAddr) {
        for _ in 0..MAX_TIP_ANNOUNCE_REPEATS {
            if poll_stopped(&self.stop) || !matches!(self.security.is_banned(peer.ip()), Ok(false))
            {
                break;
            }
            if !self.relay_backoff.allows(peer, Instant::now()) {
                break;
            }
            let Ok(started_tip) = lock_node(&self.shared).map(|node| node.state.tip()) else {
                break;
            };
            let limits = compressed_limits(&self.security, peer, self.config.limits);
            let result = relay_blocks_to_peer_once_inner_with_policy(
                Arc::clone(&self.shared),
                peer,
                limits,
                self.config.address_policy,
                self.nonce_override,
                Some(&self.active_sockets),
            );
            record_compressed_outcome(&self.security, peer, limits, &result);
            self.relay_backoff.record(peer, &result, Instant::now());
            if let Err(error) = &result {
                let (penalty, reason) = outbound_reputation_penalty(error);
                if let Err(reputation_error) =
                    self.security.record_failure(peer.ip(), penalty, reason)
                {
                    tracing::warn!(%reputation_error, %peer, "failed to update outbound peer reputation");
                }
                break;
            }
            if lock_node(&self.shared).map_or(true, |node| node.state.tip() == started_tip) {
                break;
            }
        }
        self.release(peer);
    }
}

fn tip_announce_loop(announcer: TipAnnouncer) {
    let mut announced: Option<[u8; 32]> = None;
    let mut workers = Vec::new();
    loop {
        {
            let (mutex, wake) = &*announcer.stop;
            let Ok(stopped) = mutex.lock() else {
                break;
            };
            match wake.wait_timeout_while(stopped, TIP_ANNOUNCE_CHECK_INTERVAL, |value| !*value) {
                Ok((stopped, _)) if !*stopped => {}
                _ => break,
            }
        }
        reap_workers(&mut workers);
        let Some((tip, fresh)) = announcer.observe_tip() else {
            continue;
        };
        // The tip present at startup is not news; ordinary polling covers it.
        let previous = announced.replace(tip);
        if previous.is_none_or(|previous| previous == tip) || !fresh {
            continue;
        }
        for peer in announcer.targets() {
            let static_peer = announcer.config.peers.contains(&peer);
            if !tip_announce_slot_available(static_peer, workers.len()) {
                // Targets are ordered static peers first, so nothing behind
                // this dynamic peer is entitled to a slot either.
                break;
            }
            if !announcer.claim(peer) {
                continue;
            }
            let worker = announcer.clone();
            match thread::Builder::new()
                .name("cmfd-tip-announce-peer".to_owned())
                .spawn(move || worker.announce(peer))
            {
                Ok(handle) => workers.push(handle),
                Err(error) => {
                    announcer.release(peer);
                    tracing::warn!(%error, %peer, "failed to start tip announcement");
                }
            }
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

#[derive(Clone, Copy)]
struct CatchupCandidate {
    address: SocketAddr,
    remote_hello: PeerHello,
    remaining_sessions: usize,
}

struct CatchupRound {
    pending: VecDeque<CatchupCandidate>,
    started_at: Instant,
    reserved_sessions: usize,
}

impl CatchupRound {
    fn new(pending: VecDeque<CatchupCandidate>, started_at: Instant) -> Self {
        Self {
            pending,
            started_at,
            reserved_sessions: 0,
        }
    }

    fn next(&mut self, now: Instant, stopped: bool) -> Option<CatchupCandidate> {
        if stopped
            || self.reserved_sessions >= MAX_CATCHUP_EXTRA_SESSIONS_PER_ROUND
            || now.saturating_duration_since(self.started_at) >= CATCHUP_EXTRA_SESSION_START_BUDGET
        {
            return None;
        }
        let candidate = self.pending.pop_front()?;
        // A candidate that became banned or up to date may leave this slot
        // unused. It must never increase the round's total allowance.
        self.reserved_sessions += 1;
        Some(candidate)
    }

    fn complete(&mut self, mut candidate: CatchupCandidate, continuation: Option<PeerHello>) {
        candidate.remaining_sessions = candidate.remaining_sessions.saturating_sub(1);
        if let Some(remote_hello) = continuation
            && candidate.remaining_sessions > 0
        {
            candidate.remote_hello = remote_hello;
            self.pending.push_back(candidate);
        }
    }
}

fn peer_sync_progress_cursor(shared: &Arc<Mutex<Node>>, address: SocketAddr) -> Option<[u8; 32]> {
    let node = lock_node(shared).ok()?;
    node.peer_sync_locator(
        &observed_address(PeerDirection::Outbound, address),
        MAX_BLOCKS_PER_SYNC,
    )
    .1
}

fn validated_sync_cursor_advanced(
    node: &Node,
    before: Option<[u8; 32]>,
    after: Option<[u8; 32]>,
) -> bool {
    let Some(after) = after.filter(|id| *id != node.index.genesis) else {
        return false;
    };
    let Some(after_entry) = node.index.blocks.get(&after) else {
        return false;
    };
    let Some(before) = before else {
        return true;
    };
    let before_height = if before == node.index.genesis {
        0
    } else if let Some(entry) = node.index.blocks.get(&before) {
        entry.height()
    } else {
        return false;
    };
    after_entry.height() > before_height
        && node.index.ancestor_at_height(after, before_height).ok() == Some(before)
}

fn catchup_remote_after_result(
    result: &Result<SyncReport, P2pError>,
    cursor_advanced: bool,
    local: PeerHello,
) -> Option<PeerHello> {
    // An error after a durable block is still an error. It receives normal
    // accounting and waits for the next ordinary pass, never an extra retry.
    let report = result.as_ref().ok()?;
    let progressed = report.accepted_blocks > 0 || (report.already_known > 0 && cursor_advanced);
    (progressed
        && report.remote_hello.tip != local.tip
        && report.remote_hello.cumulative_work > local.cumulative_work)
        .then_some(report.remote_hello)
}

fn catchup_remote_after_sync(
    shared: &Arc<Mutex<Node>>,
    address: SocketAddr,
    cursor_before: Option<[u8; 32]>,
    result: &Result<SyncReport, P2pError>,
) -> Option<PeerHello> {
    result.as_ref().ok()?;
    let node = lock_node(shared).ok()?;
    let cursor_after = node
        .peer_sync_locator(
            &observed_address(PeerDirection::Outbound, address),
            MAX_BLOCKS_PER_SYNC,
        )
        .1;
    catchup_remote_after_result(
        result,
        validated_sync_cursor_advanced(&node, cursor_before, cursor_after),
        node.peer_hello(),
    )
}

/// Session limits for `peer`, sending compressed block frames only when the
/// peer is known to accept them.
fn compressed_limits(security: &PeerSecurity, peer: SocketAddr, limits: PeerLimits) -> PeerLimits {
    let mut limits = limits;
    limits.compress_blocks = security
        .compresses_blocks(peer.ip())
        .unwrap_or_else(|error| {
            tracing::warn!(%error, %peer, "failed to consult peer compression capability");
            false
        });
    limits
}

fn record_compressed_outcome<T>(
    security: &PeerSecurity,
    peer: SocketAddr,
    limits: PeerLimits,
    result: &Result<T, P2pError>,
) {
    if !limits.compress_blocks {
        return;
    }
    if let Err(error) = security.record_compressed_session(peer.ip(), result.as_ref().map(|_| ())) {
        tracing::warn!(%error, %peer, "failed to record compressed-session outcome");
    }
}

fn record_poll_sync_result(
    options: &PeerPollOptions,
    peer: SocketAddr,
    result: &Result<SyncReport, P2pError>,
) -> bool {
    let banned = result.as_ref().err().is_some_and(|error| {
        let (penalty, reason) = outbound_reputation_penalty(error);
        options
            .security
            .record_failure(peer.ip(), penalty, reason)
            .unwrap_or_else(|error| {
                tracing::warn!(%error, %peer, "failed to update outbound peer reputation");
                false
            })
    });
    if let Some(discovery) = options.discovery.as_ref() {
        let update = if result.is_ok() {
            discovery.mark_verified(peer)
        } else {
            discovery.mark_failed(peer)
        };
        if let Err(error) = update {
            tracing::warn!(%error, %peer, "failed to update peer discovery state");
        }
    }
    banned
}

fn static_peer_poll_loop(
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    poll_interval: Duration,
    stop: Arc<(Mutex<bool>, Condvar)>,
    active_sockets: Arc<ActiveSocketRegistry>,
    options: PeerPollOptions,
) {
    loop {
        if poll_stopped(&stop) {
            return;
        }
        let mut targets = config.peers.clone();
        if let Some(discovery) = options.discovery.as_ref() {
            match discovery.poll_targets(MAX_DYNAMIC_TARGETS_PER_ROUND) {
                Ok(dynamic) => {
                    for address in dynamic {
                        if !targets.contains(&address) {
                            targets.push(address);
                        }
                    }
                }
                Err(error) => tracing::warn!(%error, "peer discovery target selection failed"),
            }
        }
        let mut catchup_candidates = VecDeque::new();
        for peer in targets {
            if poll_stopped(&stop) {
                return;
            }
            match options.security.is_banned(peer.ip()) {
                Ok(true) => {
                    tracing::debug!(%peer, "skipping temporarily banned outbound peer");
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error, %peer, "failed to consult outbound peer reputation");
                    continue;
                }
            }
            // Errors are already logged via tracing inside these calls;
            // a failure with one peer must not stop later peers or rounds.
            let cursor_before = peer_sync_progress_cursor(&shared, peer);
            let limits = compressed_limits(&options.security, peer, config.limits);
            let sync_result = sync_from_peer_once_inner_with_policy(
                Arc::clone(&shared),
                peer,
                limits,
                config.address_policy,
                options.nonce_override,
                Some(&active_sockets),
            );
            record_compressed_outcome(&options.security, peer, limits, &sync_result);
            let mut round_succeeded = sync_result.is_ok();
            let sync_banned = record_poll_sync_result(&options, peer, &sync_result);
            if sync_banned {
                continue;
            }
            if poll_stopped(&stop) {
                return;
            }
            let relay_result = if options.relay_backoff.allows(peer, Instant::now()) {
                let limits = compressed_limits(&options.security, peer, config.limits);
                let result = relay_blocks_to_peer_once_inner_with_policy(
                    Arc::clone(&shared),
                    peer,
                    limits,
                    config.address_policy,
                    options.nonce_override,
                    Some(&active_sockets),
                );
                record_compressed_outcome(&options.security, peer, limits, &result);
                options.relay_backoff.record(peer, &result, Instant::now());
                Some(result)
            } else {
                None
            };
            round_succeeded &= relay_result.as_ref().is_none_or(Result::is_ok);
            let relay_banned = relay_result
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .is_some_and(|error| {
                let (penalty, reason) = outbound_reputation_penalty(error);
                options
                    .security
                    .record_failure(peer.ip(), penalty, reason)
                    .unwrap_or_else(|reputation_error| {
                        tracing::warn!(%reputation_error, %peer, "failed to update outbound peer reputation");
                        false
                    })
            });
            if relay_banned {
                continue;
            }
            if round_succeeded && let Err(error) = options.security.record_success(peer.ip()) {
                tracing::warn!(%error, %peer, "failed to update outbound peer reputation after successful round");
            }
            if let Some(discovery) = options.discovery.as_ref()
                && sync_result.is_ok()
            {
                match discovery.discovery_due(peer) {
                    Ok(true) => {
                        if let Err(error) = discover_peers_from_peer_once_with_policy(
                            Arc::clone(&shared),
                            peer,
                            config.limits,
                            config.address_policy,
                            discovery,
                            options.nonce_override,
                            Some(&active_sockets),
                        ) {
                            let _ = discovery.defer_discovery(peer);
                            tracing::debug!(%error, peer = %peer, "peer discovery extension unavailable");
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, peer = %peer, "failed to schedule peer discovery")
                    }
                }
            }
            // A non-banning reverse-relay failure must not suppress useful
            // downloads. Keep combined success only for reputation credit.
            if let Some(remote_hello) =
                catchup_remote_after_sync(&shared, peer, cursor_before, &sync_result)
            {
                catchup_candidates.push_back(CatchupCandidate {
                    address: peer,
                    remote_hello,
                    remaining_sessions: MAX_CATCHUP_EXTRA_SESSIONS_PER_PEER,
                });
            }
        }

        // Every selected peer has received its ordinary turn. Only useful,
        // successful pulls get bounded extra sessions, interleaved fairly.
        let mut catchup = CatchupRound::new(catchup_candidates, Instant::now());
        while let Some(candidate) = catchup.next(Instant::now(), poll_stopped(&stop)) {
            let peer = candidate.address;
            match options.security.is_banned(peer.ip()) {
                Ok(false) => {}
                Ok(true) => continue,
                Err(error) => {
                    tracing::warn!(%error, %peer, "failed to consult catch-up peer reputation");
                    continue;
                }
            }
            let still_ahead = lock_node(&shared).is_ok_and(|node| {
                candidate.remote_hello.tip != node.peer_hello().tip
                    && candidate.remote_hello.cumulative_work > node.cumulative_work()
            });
            if !still_ahead || poll_stopped(&stop) {
                continue;
            }
            let cursor_before = peer_sync_progress_cursor(&shared, peer);
            if poll_stopped(&stop)
                || Instant::now().saturating_duration_since(catchup.started_at)
                    >= CATCHUP_EXTRA_SESSION_START_BUDGET
            {
                break;
            }
            let limits = compressed_limits(&options.security, peer, config.limits);
            let result = sync_from_peer_once_inner_with_policy(
                Arc::clone(&shared),
                peer,
                limits,
                config.address_policy,
                options.nonce_override,
                Some(&active_sockets),
            );
            record_compressed_outcome(&options.security, peer, limits, &result);
            let banned = record_poll_sync_result(&options, peer, &result);
            let continuation = if banned {
                None
            } else {
                catchup_remote_after_sync(&shared, peer, cursor_before, &result)
            };
            catchup.complete(candidate, continuation);
        }

        let (mutex, wake) = &*stop;
        let stopped = match mutex.lock() {
            Ok(stopped) => stopped,
            Err(_) => return,
        };
        if *stopped {
            return;
        }
        match wake.wait_timeout_while(stopped, poll_interval, |value| !*value) {
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

fn poll_stopped(stop: &Arc<(Mutex<bool>, Condvar)>) -> bool {
    stop.0.lock().map_or(true, |stopped| *stopped)
}

fn signal_poll_stop(stop: &Arc<(Mutex<bool>, Condvar)>) -> Result<(), P2pError> {
    let mut stopped = stop.0.lock().map_err(|_| P2pError::PoisonedStop)?;
    *stopped = true;
    stop.1.notify_all();
    Ok(())
}

fn lock_node(shared: &Arc<Mutex<Node>>) -> Result<MutexGuard<'_, Node>, P2pError> {
    shared.lock().map_err(|_| P2pError::PoisonedNode)
}

fn lock_node_before<'a>(
    shared: &'a Arc<Mutex<Node>>,
    deadline: Instant,
) -> Result<MutexGuard<'a, Node>, P2pError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PeerError::SubmitBlockResponseTimeout)?;
        match shared.try_lock() {
            Ok(node) => {
                if Instant::now() >= deadline {
                    drop(node);
                    return Err(PeerError::SubmitBlockResponseTimeout.into());
                }
                return Ok(node);
            }
            Err(TryLockError::WouldBlock) => {
                thread::sleep(remaining.min(LISTENER_POLL_INTERVAL));
            }
            Err(TryLockError::Poisoned(_)) => return Err(P2pError::PoisonedNode),
        }
    }
}

fn with_nonce(mut hello: PeerHello, nonce_override: Option<[u8; 32]>) -> PeerHello {
    if let Some(nonce) = nonce_override {
        hello.node_nonce = nonce;
    }
    hello
}

fn expect_hello(message: PeerMessage) -> Result<PeerHello, P2pError> {
    match message {
        PeerMessage::Hello(hello) => Ok(hello),
        other => Err(P2pError::UnexpectedMessage {
            expected: "Hello",
            actual: message_name(&other),
        }),
    }
}

fn expect_inventory(message: PeerMessage) -> Result<Vec<[u8; 32]>, P2pError> {
    match message {
        PeerMessage::Inventory { block_ids } => Ok(block_ids),
        other => Err(P2pError::UnexpectedMessage {
            expected: "Inventory",
            actual: message_name(&other),
        }),
    }
}

fn expect_block(message: PeerMessage) -> Result<Block, P2pError> {
    match message {
        PeerMessage::Block(block) => Ok(block),
        other => Err(P2pError::UnexpectedMessage {
            expected: "Block",
            actual: message_name(&other),
        }),
    }
}

fn expect_transaction_inventory(message: PeerMessage) -> Result<Vec<[u8; 32]>, P2pError> {
    match message {
        PeerMessage::TransactionInventory { txids } => Ok(txids),
        other => Err(P2pError::UnexpectedMessage {
            expected: "TransactionInventory",
            actual: message_name(&other),
        }),
    }
}

fn expect_transaction(message: PeerMessage) -> Result<Transaction, P2pError> {
    match message {
        PeerMessage::Transaction(transaction) => Ok(transaction),
        other => Err(P2pError::UnexpectedMessage {
            expected: "Transaction",
            actual: message_name(&other),
        }),
    }
}

fn expect_block_submission_result(message: PeerMessage) -> Result<BlockSubmissionResult, P2pError> {
    match message {
        PeerMessage::BlockSubmissionResult(result) => Ok(result),
        other => Err(P2pError::UnexpectedMessage {
            expected: "BlockSubmissionResult",
            actual: message_name(&other),
        }),
    }
}

fn expect_mining_template(message: PeerMessage) -> Result<crate::peer::MiningTemplate, P2pError> {
    match message {
        PeerMessage::MiningTemplate(template) => Ok(template),
        other => Err(P2pError::UnexpectedMessage {
            expected: "MiningTemplate",
            actual: message_name(&other),
        }),
    }
}

fn expect_peers(message: PeerMessage) -> Result<Vec<SocketAddr>, P2pError> {
    match message {
        PeerMessage::Peers { addresses } => Ok(addresses),
        other => Err(P2pError::UnexpectedMessage {
            expected: "Peers",
            actual: message_name(&other),
        }),
    }
}

fn message_name(message: &PeerMessage) -> &'static str {
    match message {
        PeerMessage::Hello(_) => "Hello",
        PeerMessage::GetHeaders { .. } => "GetHeaders",
        PeerMessage::Inventory { .. } => "Inventory",
        PeerMessage::GetBlock { .. } => "GetBlock",
        PeerMessage::Block(_) => "Block",
        PeerMessage::SubmitBlock(_) => "SubmitBlock",
        PeerMessage::BlockSubmissionResult(_) => "BlockSubmissionResult",
        PeerMessage::GetMempool => "GetMempool",
        PeerMessage::TransactionInventory { .. } => "TransactionInventory",
        PeerMessage::GetTransaction { .. } => "GetTransaction",
        PeerMessage::Transaction(_) => "Transaction",
        PeerMessage::GetMiningTemplate { .. } => "GetMiningTemplate",
        PeerMessage::MiningTemplate(_) => "MiningTemplate",
        PeerMessage::GetPeers { .. } => "GetPeers",
        PeerMessage::Peers { .. } => "Peers",
    }
}

fn join_service_thread(thread: Option<JoinHandle<Result<(), P2pError>>>) -> Result<(), P2pError> {
    let thread = thread.ok_or(P2pError::ThreadPanicked)?;
    thread.join().map_err(|_| P2pError::ThreadPanicked)?
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[cfg(feature = "production-v3-testnet")]
    use cmfd_consensus::{BlockChallenge, Coinbase, merkle_root};
    use cmfd_consensus::{
        ConsensusPowVerifier, InputWitness, OutPoint, OutputLock, TRANSACTION_VERSION, TxInput,
        TxOutput, v2_test_reference,
    };
    use cmfd_proof_worker::VerifierWorkerError;
    use k256::schnorr::SigningKey;

    use crate::peer::{
        PEER_FRAME_HEADER_BYTES, PeerFrame, WriteDeadlineBarrier, encode_peer_frame,
        process_node_nonce,
    };
    use crate::{DEFAULT_MINING_ATTEMPTS, default_miner_destination, insecure_dev_destination};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);
    const SOURCE_NONCE: [u8; 32] = [0x51; 32];
    const TARGET_NONCE: [u8; 32] = [0x52; 32];

    fn test_dir(name: &str) -> PathBuf {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("cmfd-p2p-{name}-{}-{id}", std::process::id()))
    }

    fn clean_test_dir(path: &Path) {
        if path.exists() {
            fs::remove_dir_all(path).expect("remove isolated P2P test directory");
        }
    }

    #[test]
    fn static_peers_bypass_the_tip_announce_in_flight_cap() {
        assert!(tip_announce_slot_available(false, 0));
        assert!(tip_announce_slot_available(
            false,
            MAX_TIP_ANNOUNCE_IN_FLIGHT - 1
        ));
        assert!(!tip_announce_slot_available(
            false,
            MAX_TIP_ANNOUNCE_IN_FLIGHT
        ));
        assert!(tip_announce_slot_available(
            true,
            MAX_TIP_ANNOUNCE_IN_FLIGHT
        ));
        assert!(tip_announce_slot_available(
            true,
            MAX_TIP_ANNOUNCE_IN_FLIGHT * 4
        ));
    }

    fn open_shared(path: &Path) -> Arc<Mutex<Node>> {
        clean_test_dir(path);
        Arc::new(Mutex::new(
            Node::open_with_profile(path, crate::DEVNET_PROFILE).expect("open isolated node"),
        ))
    }

    fn test_thin_miner_hello() -> PeerHello {
        let (params, _) =
            crate::network_params_and_verifier_for_profile(crate::DEVNET_PROFILE, None, None)
                .unwrap();
        PeerHello {
            network_id: params.network_id,
            consensus_fingerprint: params.fingerprint().unwrap(),
            node_nonce: process_node_nonce(),
            tip: params.genesis_hash,
            height: 0,
            cumulative_work: crate::peer::ChainWork::ZERO,
        }
    }

    fn test_request_mining_template_once_with_policy(
        address: SocketAddr,
        payout: [u8; 32],
        limits: PeerLimits,
        address_policy: PeerAddressPolicy,
    ) -> Result<MiningTemplateResponse, P2pError> {
        request_mining_template_once_with_hello_and_policy(
            address,
            payout,
            test_thin_miner_hello(),
            limits,
            address_policy,
        )
    }

    fn test_submit_mined_block_once_with_policy(
        address: SocketAddr,
        block: Block,
        limits: PeerLimits,
        address_policy: PeerAddressPolicy,
    ) -> Result<BlockSubmissionResult, P2pError> {
        submit_mined_block_once_with_policy_deadline(
            address,
            block,
            test_thin_miner_hello(),
            limits,
            address_policy,
            None,
            None,
        )
    }

    fn test_submit_mined_block_once_with_policy_before_cancellable(
        address: SocketAddr,
        block: Block,
        limits: PeerLimits,
        address_policy: PeerAddressPolicy,
        deadline: Instant,
        cancellation: Arc<AtomicBool>,
    ) -> Result<BlockSubmissionResult, P2pError> {
        submit_mined_block_once_with_policy_deadline(
            address,
            block,
            test_thin_miner_hello(),
            limits,
            address_policy,
            Some(deadline),
            Some(cancellation),
        )
    }

    fn test_limits() -> PeerLimits {
        PeerLimits {
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(5),
            max_peers: 4,
            max_messages_per_peer: 256,
            max_bytes_per_peer: 32 * 1024 * 1024,
            compress_blocks: false,
        }
    }

    #[test]
    fn compressed_block_capability_is_static_only_and_backs_off_after_one_rejection() {
        let security = PeerSecurity::default();
        let stranger: IpAddr = "203.0.113.9".parse().unwrap();
        let static_peer: SocketAddr = "198.51.100.7:29444".parse().unwrap();
        assert!(!security.compresses_blocks(stranger).unwrap());
        security.register_static_peers(&[static_peer]).unwrap();
        assert!(security.compresses_blocks(static_peer.ip()).unwrap());
        // A completed session keeps compression on.
        security
            .record_compressed_session(static_peer.ip(), Ok(()))
            .unwrap();
        assert!(security.compresses_blocks(static_peer.ip()).unwrap());
        // One handshake death (an older peer closing on our version-5 hello)
        // pauses compression toward that peer before it can ban us.
        let closed = P2pError::Peer(PeerError::ConnectionClosed);
        security
            .record_compressed_session(static_peer.ip(), Err(&closed))
            .unwrap();
        assert!(!security.compresses_blocks(static_peer.ip()).unwrap());
        // Non-transport errors and an unreachable peer never count as a rejection;
        // a reset after the hello does.
        let other: SocketAddr = "203.0.113.10:29444".parse().unwrap();
        security.register_static_peers(&[other]).unwrap();
        let refused = P2pError::Peer(PeerError::Io(io::Error::from(
            io::ErrorKind::ConnectionRefused,
        )));
        for error in [
            &P2pError::UnknownRequestedBlock([1; 32]),
            &refused,
            &refused,
        ] {
            security
                .record_compressed_session(other.ip(), Err(error))
                .unwrap();
        }
        assert!(security.compresses_blocks(other.ip()).unwrap());
        let reset = P2pError::Peer(PeerError::Io(io::Error::from(
            io::ErrorKind::ConnectionReset,
        )));
        security
            .record_compressed_session(other.ip(), Err(&reset))
            .unwrap();
        assert!(!security.compresses_blocks(other.ip()).unwrap());
    }

    fn test_catchup_candidate(index: u8) -> CatchupCandidate {
        let mut remote_hello = test_thin_miner_hello();
        remote_hello.tip = [index; 32];
        remote_hello.cumulative_work.0[63] = 100;
        CatchupCandidate {
            address: SocketAddr::from(([127, 0, 0, 1], 29000 + u16::from(index))),
            remote_hello,
            remaining_sessions: MAX_CATCHUP_EXTRA_SESSIONS_PER_PEER,
        }
    }

    fn test_catchup_report(remote_hello: PeerHello) -> SyncReport {
        SyncReport {
            remote_hello,
            inventory_items: 0,
            requested_blocks: 0,
            accepted_blocks: 0,
            already_known: 0,
            transaction_inventory_items: 0,
            requested_transactions: 0,
            accepted_transactions: 0,
            already_known_transactions: 0,
            rejected_transactions: 0,
        }
    }

    #[test]
    fn catchup_round_is_round_robin_and_globally_bounded() {
        let now = Instant::now();
        let peers: Vec<_> = (1..=4).map(test_catchup_candidate).collect();
        let mut round = CatchupRound::new(peers.iter().copied().collect(), now);
        let mut order = Vec::new();
        for _ in 0..MAX_CATCHUP_EXTRA_SESSIONS_PER_ROUND {
            let peer = round.next(now, false).unwrap();
            order.push(peer.address);
            round.complete(peer, Some(peer.remote_hello));
        }
        assert_eq!(
            order,
            peers
                .iter()
                .cycle()
                .take(8)
                .map(|p| p.address)
                .collect::<Vec<_>>()
        );
        assert!(round.next(now, false).is_none());
        assert!(
            !round.pending.is_empty(),
            "global cap must stop otherwise eligible work"
        );
    }

    #[test]
    fn catchup_round_caps_each_peer_and_does_not_requeue_failed_progress() {
        let now = Instant::now();
        let candidate = test_catchup_candidate(1);
        let mut round = CatchupRound::new([candidate].into(), now);
        for _ in 0..MAX_CATCHUP_EXTRA_SESSIONS_PER_PEER {
            let peer = round.next(now, false).unwrap();
            round.complete(peer, Some(peer.remote_hello));
        }
        assert!(round.next(now, false).is_none());
        let mut round = CatchupRound::new([candidate, test_catchup_candidate(2)].into(), now);
        let failed = round.next(now, false).unwrap();
        round.complete(failed, None);
        let other = round.next(now, false).unwrap();
        assert_ne!(other.address, failed.address);
        round.complete(other, None);
        assert!(round.next(now, false).is_none());
    }

    #[test]
    fn catchup_round_stops_new_sessions_at_time_budget_or_shutdown() {
        let now = Instant::now();
        let mut expired = CatchupRound::new([test_catchup_candidate(1)].into(), now);
        assert!(
            expired
                .next(now + CATCHUP_EXTRA_SESSION_START_BUDGET, false)
                .is_none()
        );
        assert_eq!(expired.reserved_sessions, 0);
        let mut stopped = CatchupRound::new([test_catchup_candidate(1)].into(), now);
        assert!(stopped.next(now, true).is_none());
        assert_eq!(stopped.reserved_sessions, 0);
        let mut live = CatchupRound::new([test_catchup_candidate(1)].into(), now);
        assert!(
            live.next(
                now + CATCHUP_EXTRA_SESSION_START_BUDGET - Duration::from_millis(1),
                false
            )
            .is_some()
        );
    }

    #[test]
    fn catchup_requires_valid_progress_not_claimed_work_or_height() {
        let remote = test_catchup_candidate(1).remote_hello;
        let mut local = test_thin_miner_hello();
        local.cumulative_work.0[63] = 10;
        local.height = 775;
        let mut report = test_catchup_report(remote);
        report.remote_hello.height = 751;
        report.remote_hello.cumulative_work.0 = [0xff; 64];
        assert!(catchup_remote_after_result(&Ok(report), true, local).is_none());
        report.inventory_items = 1;
        report.already_known = 1;
        assert!(catchup_remote_after_result(&Ok(report), false, local).is_none());
        assert!(catchup_remote_after_result(&Ok(report), true, local).is_some());
        report.already_known = 0;
        report.requested_blocks = 1;
        report.accepted_blocks = 1;
        assert!(
            catchup_remote_after_result(&Ok(report), false, local).is_some(),
            "a shorter but higher-work branch must remain eligible"
        );
        report.remote_hello.cumulative_work = local.cumulative_work;
        assert!(catchup_remote_after_result(&Ok(report), true, local).is_none());
        report.remote_hello.cumulative_work.0 = [0xff; 64];
        report.remote_hello.tip = local.tip;
        assert!(catchup_remote_after_result(&Ok(report), true, local).is_none());
        for error in [
            P2pError::Peer(PeerError::CountLimit {
                field: "sync inventory",
                actual: 17,
                max: 16,
            }),
            P2pError::Peer(PeerError::ConnectionClosed),
            P2pError::Peer(PeerError::Cancelled),
        ] {
            assert!(
                catchup_remote_after_result(&Err(error), true, local).is_none(),
                "errors, including after durable progress, never authorize an extra retry"
            );
        }
    }

    #[test]
    fn catchup_known_cursor_must_advance_along_validated_ancestry() {
        let path = test_dir("catchup-cursor-ancestry");
        let node = open_shared(&path);
        let now = unix_time_seconds().unwrap();
        mine(&node, 3, now);
        {
            let mut node = node.lock().unwrap();
            let genesis = node.index.genesis;
            let first = node.active_block_id_at_height(1).unwrap();
            let second = node.active_block_id_at_height(2).unwrap();
            let side = crate::tests::mined_child(&node, genesis, now + 10, 0x71);
            let side_id = side.block_id();
            node.submit_block(side, now + 10).unwrap();
            let child = crate::tests::mined_child(&node, side_id, now + 11, 0x72);
            let child_id = child.block_id();
            node.submit_block(child, now + 11).unwrap();
            assert!(validated_sync_cursor_advanced(&node, None, Some(first)));
            assert!(validated_sync_cursor_advanced(
                &node,
                Some(first),
                Some(second)
            ));
            assert!(!validated_sync_cursor_advanced(
                &node,
                Some(second),
                Some(first)
            ));
            assert!(!validated_sync_cursor_advanced(
                &node,
                Some(first),
                Some(first)
            ));
            assert!(!validated_sync_cursor_advanced(
                &node,
                Some(first),
                Some(child_id)
            ));
            assert!(!validated_sync_cursor_advanced(
                &node,
                None,
                Some([0xab; 32])
            ));
            assert!(!validated_sync_cursor_advanced(&node, None, Some(genesis)));
        }
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn block_sync_batch_limit_tracks_the_network_frame_size() {
        let limits = test_limits();
        let legacy_network_id = crate::DEVNET_PROFILE.network_id;
        let v4_network_id = cmfd_consensus::PRODUCTION_V4_TESTNET_NETWORK_ID;

        assert_eq!(
            block_sync_batch_limit(legacy_network_id, limits),
            MAX_BLOCKS_PER_SYNC
        );
        assert_eq!(block_sync_batch_limit(v4_network_id, limits), 1);

        let v4_block_budget = limits
            .max_bytes_per_peer
            .saturating_sub((MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64)
            .saturating_sub(SYNC_CONTROL_RESERVE_BYTES);
        let v4_maximum_block_bytes = max_block_bytes_for_network(v4_network_id) as u64;
        assert!(v4_maximum_block_bytes <= v4_block_budget);
        assert!(v4_maximum_block_bytes.saturating_mul(2) > v4_block_budget);
    }

    #[test]
    fn peer_reputation_bans_protocol_violations_and_recovers() {
        let security = Arc::new(PeerSecurity::default());
        let ip = "127.0.0.1".parse().unwrap();
        let started = Instant::now();

        for offset in 0..2 {
            security
                .record_failure_at(
                    ip,
                    PROTOCOL_VIOLATION_PENALTY,
                    started + Duration::from_millis(offset),
                    "test protocol violation",
                )
                .unwrap();
        }
        assert!(security.is_banned_at(ip, started).unwrap());
        assert!(matches!(
            security.reserve_inbound_at(ip, started).unwrap(),
            PeerAdmission::Rejected(PeerAdmissionRejection::Banned)
        ));

        let recovered_at = started + PEER_BAN_DURATION + Duration::from_millis(1);
        let guard = match security.reserve_inbound_at(ip, recovered_at).unwrap() {
            PeerAdmission::Accepted(guard) => guard,
            PeerAdmission::Rejected(reason) => panic!("recovered peer was rejected: {reason:?}"),
        };
        assert!(!security.is_banned_at(ip, recovered_at).unwrap());
        drop(guard);
    }

    #[test]
    fn peer_reputation_reserves_only_a_fair_per_ip_share() {
        let security = Arc::new(PeerSecurity::default());
        let ip = "127.0.0.1".parse().unwrap();
        let now = Instant::now();
        let mut guards = Vec::new();

        for _ in 0..MAX_INBOUND_CONNECTIONS_PER_IP {
            match security.reserve_inbound_at(ip, now).unwrap() {
                PeerAdmission::Accepted(guard) => guards.push(guard),
                PeerAdmission::Rejected(reason) => {
                    panic!("connection inside per-IP allowance was rejected: {reason:?}")
                }
            }
        }
        assert!(matches!(
            security.reserve_inbound_at(ip, now).unwrap(),
            PeerAdmission::Rejected(PeerAdmissionRejection::PerIpLimit)
        ));

        drop(guards.pop());
        assert!(matches!(
            security.reserve_inbound_at(ip, now).unwrap(),
            PeerAdmission::Accepted(_)
        ));
    }

    #[test]
    fn peer_reputation_rate_limits_reconnect_churn() {
        let security = Arc::new(PeerSecurity::default());
        let ip = "127.0.0.1".parse().unwrap();
        let now = Instant::now();

        for _ in 0..MAX_INBOUND_ATTEMPTS_PER_WINDOW {
            let guard = match security.reserve_inbound_at(ip, now).unwrap() {
                PeerAdmission::Accepted(guard) => guard,
                PeerAdmission::Rejected(reason) => {
                    panic!("connection inside rate allowance was rejected: {reason:?}")
                }
            };
            drop(guard);
        }
        assert!(matches!(
            security.reserve_inbound_at(ip, now).unwrap(),
            PeerAdmission::Rejected(PeerAdmissionRejection::RateLimit)
        ));
        assert!(security.is_banned_at(ip, now).unwrap());
    }

    #[test]
    fn peer_reputation_groups_ipv6_addresses_by_prefix() {
        let first = PeerReputationKey::from_ip("2001:db8:1234:5678::1".parse().unwrap());
        let second = PeerReputationKey::from_ip("2001:db8:1234:5678::ffff".parse().unwrap());
        let other = PeerReputationKey::from_ip("2001:db8:1234:5679::1".parse().unwrap());
        let ipv4 = PeerReputationKey::from_ip("192.0.2.1".parse().unwrap());
        let ipv4_mapped = PeerReputationKey::from_ip("::ffff:192.0.2.1".parse().unwrap());

        assert_eq!(first, second);
        assert_ne!(first, other);
        assert_eq!(ipv4, ipv4_mapped);
    }

    #[test]
    fn peer_reputation_does_not_ban_outbound_transport_outages() {
        let transport = P2pError::Peer(PeerError::ConnectionClosed);
        let malformed = P2pError::Peer(PeerError::InvalidMagic);
        let oversized = P2pError::Peer(PeerError::PayloadTooLarge { actual: 2, max: 1 });

        assert_eq!(outbound_reputation_penalty(&transport).0, 0);
        assert_eq!(
            inbound_reputation_penalty(&transport, false).0,
            TRANSIENT_FAILURE_PENALTY
        );
        assert_eq!(inbound_reputation_penalty(&transport, true).0, 0);
        assert_eq!(
            outbound_reputation_penalty(&malformed).0,
            PROTOCOL_VIOLATION_PENALTY
        );
        assert_eq!(
            outbound_reputation_penalty(&oversized).0,
            RESOURCE_ABUSE_PENALTY
        );
    }

    #[test]
    fn peer_discovery_polls_due_peers_least_recently_scheduled_first() {
        let path = test_dir("discovery-rotation");
        let node = open_shared(&path);
        let hello = node.lock().unwrap().peer_hello();
        let listen_address: SocketAddr = "127.0.0.1:22444".parse().unwrap();
        let low: SocketAddr = "127.0.0.1:22445".parse().unwrap();
        let high: SocketAddr = "127.0.0.1:22446".parse().unwrap();
        let discovery =
            PeerDiscovery::open(&path, hello, listen_address, PeerAddressPolicy::PrivateOnly);
        discovery.add_candidate(low).unwrap();
        discovery.add_candidate(high).unwrap();

        // Both fresh candidates are due; polling reschedules both to the same
        // retry instant, so the next single pick falls back to address order.
        let start = Instant::now() + DYNAMIC_PEER_RETRY_INTERVAL;
        assert_eq!(
            discovery.poll_targets_at(start, 2).unwrap(),
            vec![low, high]
        );
        let first_round = start + DYNAMIC_PEER_RETRY_INTERVAL;
        assert_eq!(
            discovery.poll_targets_at(first_round, 1).unwrap(),
            vec![low]
        );
        // A round later both are due again. The peer polled longest ago goes
        // first even though its address sorts after the other, and the pair
        // keeps alternating instead of the low address winning every round.
        let second_round = first_round + DYNAMIC_PEER_RETRY_INTERVAL;
        assert_eq!(
            discovery.poll_targets_at(second_round, 1).unwrap(),
            vec![high]
        );
        assert_eq!(
            discovery.poll_targets_at(second_round, 1).unwrap(),
            vec![low]
        );
        assert!(
            discovery
                .poll_targets_at(second_round, 1)
                .unwrap()
                .is_empty()
        );
        drop(discovery);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn peer_discovery_persists_only_successfully_verified_addresses() {
        let path = test_dir("discovery-cache");
        let node = open_shared(&path);
        let hello = node.lock().unwrap().peer_hello();
        let listen_address: SocketAddr = "127.0.0.1:22444".parse().unwrap();
        let candidate: SocketAddr = "127.0.0.1:22445".parse().unwrap();

        let discovery =
            PeerDiscovery::open(&path, hello, listen_address, PeerAddressPolicy::PrivateOnly);
        discovery.add_candidate(candidate).unwrap();
        for port in 22500..22516 {
            discovery
                .add_candidate(SocketAddr::new(candidate.ip(), port))
                .unwrap();
        }
        assert_eq!(
            discovery.state.lock().unwrap().peers.len(),
            MAX_DISCOVERED_PEERS_PER_IP
        );
        let rejected_candidate = SocketAddr::new(candidate.ip(), 22500);
        for _ in 0..MAX_UNVERIFIED_PEER_FAILURES {
            discovery.mark_failed(rejected_candidate).unwrap();
        }
        assert!(
            !discovery
                .state
                .lock()
                .unwrap()
                .peers
                .contains_key(&rejected_candidate)
        );
        assert!(
            discovery
                .gossip_addresses(listen_address)
                .unwrap()
                .is_empty()
        );
        drop(discovery);

        let discovery =
            PeerDiscovery::open(&path, hello, listen_address, PeerAddressPolicy::PrivateOnly);
        assert!(
            discovery
                .gossip_addresses(listen_address)
                .unwrap()
                .is_empty()
        );
        discovery.mark_verified(candidate).unwrap();
        drop(discovery);

        let discovery =
            PeerDiscovery::open(&path, hello, listen_address, PeerAddressPolicy::PrivateOnly);
        assert_eq!(
            discovery.gossip_addresses(listen_address).unwrap(),
            vec![candidate]
        );

        drop(discovery);
        let mut wrong_network = hello;
        wrong_network.network_id[0] ^= 1;
        let discovery = PeerDiscovery::open(
            &path,
            wrong_network,
            listen_address,
            PeerAddressPolicy::PrivateOnly,
        );
        assert!(
            discovery
                .gossip_addresses(listen_address)
                .unwrap()
                .is_empty()
        );
        drop(discovery);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn peer_discovery_gossips_an_address_only_after_connect_back_verification() {
        const CLIENT_NONCE: [u8; 32] = [0x53; 32];
        let seed_path = test_dir("discovery-seed");
        let advertised_path = test_dir("discovery-advertised");
        let client_path = test_dir("discovery-client");
        let seed = open_shared(&seed_path);
        let advertised = open_shared(&advertised_path);
        let client = open_shared(&client_path);

        let seed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let seed_address = seed_listener.local_addr().unwrap();
        let seed_discovery = Arc::new(PeerDiscovery::open(
            &seed_path,
            seed.lock().unwrap().peer_hello(),
            seed_address,
            PeerAddressPolicy::PrivateOnly,
        ));
        let seed_handle = spawn_inbound_listener_inner_with_policy(
            Arc::clone(&seed),
            seed_listener,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            Some(SOURCE_NONCE),
            Some(Arc::clone(&seed_discovery)),
        )
        .unwrap();

        let (advertised_handle, advertised_address) =
            start_listener(Arc::clone(&advertised), TARGET_NONCE);
        let advertised_discovery = Arc::new(PeerDiscovery::open(
            &advertised_path,
            advertised.lock().unwrap().peer_hello(),
            advertised_address,
            PeerAddressPolicy::PrivateOnly,
        ));

        let first = discover_peers_from_peer_once_with_policy(
            Arc::clone(&advertised),
            seed_address,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            &advertised_discovery,
            Some(TARGET_NONCE),
            None,
        )
        .unwrap();
        assert!(first.addresses.is_empty());
        assert!(
            seed_discovery
                .gossip_addresses(seed_address)
                .unwrap()
                .is_empty()
        );

        let seed_poller = spawn_peer_polling_inner(
            Arc::clone(&seed),
            StaticPeerConfig {
                listen_address: seed_address,
                peers: Vec::new(),
                limits: test_limits(),
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_millis(10),
            Some(SOURCE_NONCE),
            Some(Arc::clone(&seed_discovery)),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline
            && seed_discovery
                .gossip_addresses(seed_address)
                .unwrap()
                .is_empty()
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            seed_discovery.gossip_addresses(seed_address).unwrap(),
            vec![advertised_address]
        );

        let client_discovery = Arc::new(PeerDiscovery::open(
            &client_path,
            client.lock().unwrap().peer_hello(),
            "127.0.0.1:22446".parse().unwrap(),
            PeerAddressPolicy::PrivateOnly,
        ));
        let second = discover_peers_from_peer_once_with_policy(
            Arc::clone(&client),
            seed_address,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            &client_discovery,
            Some(CLIENT_NONCE),
            None,
        )
        .unwrap();
        assert_eq!(second.addresses, vec![advertised_address]);
        assert_eq!(
            client_discovery
                .poll_targets(MAX_DYNAMIC_TARGETS_PER_ROUND)
                .unwrap(),
            vec![advertised_address]
        );

        seed_poller.stop().unwrap();
        seed_handle.stop().unwrap();
        advertised_handle.stop().unwrap();
        drop(client_discovery);
        drop(advertised_discovery);
        drop(seed_discovery);
        drop(client);
        drop(advertised);
        drop(seed);
        clean_test_dir(&client_path);
        clean_test_dir(&advertised_path);
        clean_test_dir(&seed_path);
    }

    fn submission_test_block(label: &str) -> Block {
        let path = test_dir(label);
        let node = open_shared(&path);
        let block = node
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        drop(node);
        clean_test_dir(&path);
        block
    }

    fn mine(node: &Arc<Mutex<Node>>, count: usize, start_time: u64) {
        let mut node = node.lock().unwrap();
        for offset in 0..count {
            node.mine_once(
                default_miner_destination(),
                start_time + offset as u64,
                DEFAULT_MINING_ATTEMPTS,
            )
            .expect("mine test block");
        }
    }

    fn start_listener(node: Arc<Mutex<Node>>, nonce: [u8; 32]) -> (InboundPeerHandle, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle =
            spawn_inbound_listener_inner(node, listener, test_limits(), Some(nonce)).unwrap();
        (handle, address)
    }

    fn tips_match(left: &Arc<Mutex<Node>>, right: &Arc<Mutex<Node>>) -> bool {
        left.lock().unwrap().peer_hello().tip == right.lock().unwrap().peer_hello().tip
    }

    fn spend_community_output(node: &Node, block: &Block, fee: u64) -> Transaction {
        let owner = SigningKey::from_bytes(&[0x12; 32]).unwrap();
        let previous_output = &block.coinbase.outputs[2];
        let mut transaction = Transaction {
            network_id: node.peer_hello().network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: OutPoint {
                    txid: block.coinbase_outpoint_id(),
                    index: 2,
                },
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: Vec::new(),
                },
            }],
            outputs: vec![TxOutput {
                value: previous_output.value.checked_sub(fee).unwrap(),
                lock: OutputLock::Key(insecure_dev_destination(0x71)),
                spendable_height: node.status().unwrap().next_height,
            }],
        };
        transaction.sign_all(&[&owner]).unwrap();
        transaction
    }

    fn invalid_transaction(network_id: [u8; 32], discriminator: u32) -> Transaction {
        Transaction {
            network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: OutPoint {
                    txid: [0xa5; 32],
                    index: discriminator,
                },
                witness: InputWitness::Key {
                    public_key: [0x23; 32],
                    signature: vec![0x34; 64],
                },
            }],
            outputs: vec![TxOutput {
                value: 1,
                lock: OutputLock::Key(insecure_dev_destination(0x72)),
                spendable_height: 1,
            }],
        }
    }

    fn accept_test_peer(listener: TcpListener, hello: PeerHello) -> PeerConnection {
        let (stream, _) = listener.accept().unwrap();
        let session = PeerSession::new(hello, test_limits()).unwrap();
        let mut connection = PeerConnection::from_stream(stream, session).unwrap();
        connection.send_hello().unwrap();
        assert!(matches!(
            connection.receive().unwrap(),
            PeerMessage::Hello(_)
        ));
        connection
    }

    fn connected_peer_pair() -> (PeerConnection, PeerConnection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let client_hello = with_nonce(test_thin_miner_hello(), Some([0x61; 32]));
        let server_hello = with_nonce(test_thin_miner_hello(), Some([0x62; 32]));
        let mut client = PeerConnection::from_stream(
            client_stream,
            PeerSession::new(client_hello, test_limits()).unwrap(),
        )
        .unwrap();
        let mut server = PeerConnection::from_stream(
            server_stream,
            PeerSession::new(server_hello, test_limits()).unwrap(),
        )
        .unwrap();
        client.send_hello().unwrap();
        server.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));
        assert!(matches!(server.receive().unwrap(), PeerMessage::Hello(_)));
        (client, server)
    }

    #[test]
    fn submit_response_deadline_bounds_peer_hello_lock_without_writing() {
        let path = test_dir("submit-response-lock-deadline");
        let shared = open_shared(&path);
        let (client, server) = connected_peer_pair();
        let mut raw_client = client.try_clone_stream().unwrap();
        raw_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let guard = shared.lock().unwrap();
        let deadline = checked_submit_deadline(Instant::now(), Duration::from_millis(50)).unwrap();
        let response_node = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            let mut server = server;
            send_block_submission_result_before(
                &response_node,
                &mut server,
                [0x71; 32],
                BlockSubmissionStatus::Busy,
                deadline,
            )
        });
        assert!(matches!(
            worker.join().unwrap(),
            Err(P2pError::Peer(PeerError::SubmitBlockResponseTimeout))
        ));
        drop(guard);
        let mut byte = [0_u8; 1];
        assert_eq!(raw_client.read(&mut byte).unwrap(), 0);
        drop(client);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn submit_response_deadline_rechecks_after_slow_writer_pause() {
        let (client, mut server) = connected_peer_pair();
        let mut raw_client = client.try_clone_stream().unwrap();
        raw_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let barrier = Arc::new(WriteDeadlineBarrier::new());
        server.set_write_deadline_barrier(Arc::clone(&barrier));
        let deadline = checked_submit_deadline(Instant::now(), Duration::from_millis(50)).unwrap();
        let worker = thread::spawn(move || {
            server.send_before(
                PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                    block_id: [0x72; 32],
                    status: BlockSubmissionStatus::Busy,
                    peer_height: 0,
                    peer_tip: [0x73; 32],
                }),
                deadline,
            )
        });
        barrier.entered.wait();
        while Instant::now() < deadline {
            thread::yield_now();
        }
        barrier.release.wait();
        assert!(matches!(
            worker.join().unwrap(),
            Err(PeerError::SubmitBlockResponseTimeout)
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(raw_client.read(&mut byte).unwrap(), 0);
        drop(client);
    }

    #[test]
    fn submit_deadline_overflow_is_a_controlled_error() {
        assert!(matches!(
            checked_submit_deadline(Instant::now(), Duration::MAX),
            Err(P2pError::SubmitBlockDeadlineOverflow)
        ));
    }

    #[test]
    fn restarted_source_serves_locator_backed_blocks_and_equal_tip_is_a_noop() {
        let source_path = test_dir("initial-source");
        let target_path = test_dir("initial-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let now = unix_time_seconds().unwrap();
        mine(&source, 3, now);
        drop(source);
        let source = Arc::new(Mutex::new(
            Node::open_with_profile(&source_path, crate::DEVNET_PROFILE)
                .expect("reopen locator-backed source node"),
        ));
        let (listener, address) = start_listener(Arc::clone(&source), SOURCE_NONCE);

        let first = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert_eq!(first.inventory_items, 3);
        assert_eq!(first.requested_blocks, 3);
        assert_eq!(first.accepted_blocks, 3);
        assert!(tips_match(&source, &target));

        let second = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert!(second.up_to_date());
        assert_eq!(second.requested_blocks, 0);
        assert_eq!(second.accepted_blocks, 0);

        let target_status = target.lock().unwrap().status().unwrap();
        assert_eq!(target_status.peers.len(), 1);
        let outbound = &target_status.peers[0];
        assert_eq!(outbound.address, address.to_string());
        assert_eq!(outbound.direction, PeerDirection::Outbound);
        assert_eq!(outbound.state, crate::PeerState::Reachable);
        assert_eq!(outbound.successful_sessions, 2);
        assert_eq!(outbound.failed_sessions, 0);
        assert_eq!(outbound.active_connections, 0);
        assert_eq!(outbound.remote_height, Some(3));
        assert_eq!(outbound.remote_tip, Some(target_status.tip.clone()));

        let inbound = (0..100).find_map(|_| {
            let peer = source
                .lock()
                .unwrap()
                .status()
                .unwrap()
                .peers
                .into_iter()
                .find(|peer| {
                    peer.direction == PeerDirection::Inbound
                        && peer.successful_sessions == 2
                        && peer.active_connections == 0
                });
            if peer.is_none() {
                thread::sleep(Duration::from_millis(10));
            }
            peer
        });
        let inbound = inbound.expect("inbound peer observation");
        assert_eq!(inbound.address, address.ip().to_string());
        assert_eq!(inbound.state, crate::PeerState::Reachable);
        assert_eq!(inbound.remote_height, Some(3));
        assert_eq!(inbound.remote_tip, Some(target_status.tip));

        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn one_sync_call_obeys_the_block_batch_bound() {
        let source_path = test_dir("batch-source");
        let target_path = test_dir("batch-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let now = unix_time_seconds().unwrap();
        mine(&source, MAX_BLOCKS_PER_SYNC + 1, now);
        let (listener, address) = start_listener(Arc::clone(&source), SOURCE_NONCE);

        let first = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert_eq!(first.inventory_items, MAX_BLOCKS_PER_SYNC);
        assert_eq!(first.accepted_blocks, MAX_BLOCKS_PER_SYNC);
        assert!(!tips_match(&source, &target));

        let second = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert_eq!(second.inventory_items, 1);
        assert_eq!(second.accepted_blocks, 1);
        assert!(tips_match(&source, &target));

        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn known_side_branch_prefix_does_not_consume_the_download_budget() {
        let source_path = test_dir("known-prefix-source");
        let target_path = test_dir("known-prefix-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let now = unix_time_seconds().unwrap();
        let source_blocks: Vec<Block> = (0..5)
            .map(|offset| {
                source
                    .lock()
                    .unwrap()
                    .mine_once(
                        default_miner_destination(),
                        now + offset,
                        DEFAULT_MINING_ATTEMPTS,
                    )
                    .unwrap()
            })
            .collect();
        {
            let mut node = target.lock().unwrap();
            for offset in 0..6 {
                node.mine_once(
                    insecure_dev_destination(0x75),
                    now + 1 + offset,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            }
        }
        // The target already stores the first three source blocks as a side
        // branch beneath its own longer chain.
        for block in &source_blocks[..3] {
            crate::submit_shared_block(&target, block.clone(), now + 10).unwrap();
        }
        let active_tip = target.lock().unwrap().peer_hello().tip;
        assert!(
            !target
                .lock()
                .unwrap()
                .contains_block(source_blocks[3].block_id())
        );

        let reserve =
            (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64 + SYNC_CONTROL_RESERVE_BYTES;
        let block_bytes = max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64;
        let receiver_limits = PeerLimits {
            max_bytes_per_peer: reserve + block_bytes,
            compress_blocks: false,
            ..test_limits()
        };
        assert_eq!(
            block_sync_batch_limit(crate::DEVNET_PROFILE.network_id, receiver_limits),
            1
        );
        // Like stock mainnet nodes, the source offers one id per request.
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let listener = spawn_inbound_listener_inner(
            Arc::clone(&source),
            socket,
            receiver_limits,
            Some(SOURCE_NONCE),
        )
        .unwrap();
        let report = sync_from_peer_once_inner_with_policy(
            Arc::clone(&target),
            address,
            receiver_limits,
            PeerAddressPolicy::PrivateOnly,
            Some(TARGET_NONCE),
            None,
        )
        .unwrap();

        // One session walks the whole known prefix and still downloads the
        // first unknown block of the branch.
        assert_eq!(report.already_known, 3);
        assert_eq!(report.accepted_blocks, 1);
        assert!(
            target
                .lock()
                .unwrap()
                .contains_block(source_blocks[3].block_id())
        );
        assert_eq!(target.lock().unwrap().peer_hello().tip, active_tip);

        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn larger_valid_inventory_respects_receiver_budget_without_banning_peer() {
        let source_path = test_dir("heterogeneous-budget-source");
        let target_path = test_dir("heterogeneous-budget-target");
        let limited_path = test_dir("heterogeneous-budget-direct");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let limited = open_shared(&limited_path);
        mine(&source, 3, unix_time_seconds().unwrap());
        let reserve =
            (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64 + SYNC_CONTROL_RESERVE_BYTES;
        let block_bytes = max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64;
        let receiver_limits = PeerLimits {
            max_bytes_per_peer: reserve + block_bytes,
            compress_blocks: false,
            ..test_limits()
        };
        let sender_limits = PeerLimits {
            max_bytes_per_peer: reserve + 2 * block_bytes,
            compress_blocks: false,
            ..test_limits()
        };
        assert_eq!(
            block_sync_batch_limit(crate::DEVNET_PROFILE.network_id, receiver_limits),
            1
        );
        assert_eq!(
            block_sync_batch_limit(crate::DEVNET_PROFILE.network_id, sender_limits),
            2
        );
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let source_discovery = Arc::new(PeerDiscovery::open(
            &source_path,
            source.lock().unwrap().peer_hello(),
            address,
            PeerAddressPolicy::PrivateOnly,
        ));
        let listener = spawn_inbound_listener_inner_with_policy(
            Arc::clone(&source),
            socket,
            sender_limits,
            PeerAddressPolicy::PrivateOnly,
            Some(SOURCE_NONCE),
            Some(source_discovery),
        )
        .unwrap();
        let target_address = "127.0.0.1:28447".parse().unwrap();
        let discovery = Arc::new(PeerDiscovery::open(
            &target_path,
            target.lock().unwrap().peer_hello(),
            target_address,
            PeerAddressPolicy::PrivateOnly,
        ));
        let poller = spawn_peer_polling_inner(
            Arc::clone(&target),
            StaticPeerConfig {
                listen_address: target_address,
                peers: vec![address],
                limits: receiver_limits,
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_secs(30),
            Some(TARGET_NONCE),
            Some(Arc::clone(&discovery)),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while target.lock().unwrap().peer_hello().height == 0
            && !discovery.security.is_banned(address.ip()).unwrap()
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(5));
        }
        let banned = discovery.security.is_banned(address.ip()).unwrap();
        let height = target.lock().unwrap().peer_hello().height;
        poller.stop().unwrap();
        assert!(
            !banned,
            "a valid two-block offer must not become a resource-abuse peer ban"
        );
        assert!(
            height > 0,
            "a receiver with a smaller local budget must still make progress"
        );

        // Exercise one direct session separately, so later catch-up scheduling
        // cannot hide an accidental increase in the per-session download cap.
        let report = sync_from_peer_once_inner(
            Arc::clone(&limited),
            address,
            receiver_limits,
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert_eq!(report.inventory_items, 2);
        assert_eq!(report.requested_blocks, 1);
        assert_eq!(report.accepted_blocks, 1);
        assert_eq!(limited.lock().unwrap().peer_hello().height, 1);
        listener.stop().unwrap();
        drop(source);
        drop(target);
        drop(limited);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
        clean_test_dir(&limited_path);
    }

    #[test]
    fn sync_inventory_above_protocol_offer_limit_remains_resource_abuse() {
        let path = test_dir("oversized-sync-offer");
        let target = open_shared(&path);
        let mut hello = target.lock().unwrap().peer_hello();
        hello.node_nonce = SOURCE_NONCE;
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut connection = accept_test_peer(socket, hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::GetHeaders { .. }
            ));
            let block_ids = (1..=MAX_BLOCKS_PER_SYNC + 1)
                .map(|value| [value as u8; 32])
                .collect();
            connection
                .send(PeerMessage::Inventory { block_ids })
                .unwrap();
            assert!(matches!(
                connection.receive(),
                Err(PeerError::ConnectionClosed)
            ));
        });
        let limits = PeerLimits {
            max_bytes_per_peer: (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64
                + SYNC_CONTROL_RESERVE_BYTES
                + max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64,
            ..test_limits()
        };
        let error =
            sync_from_peer_once_inner(Arc::clone(&target), address, limits, Some(TARGET_NONCE))
                .unwrap_err();
        assert!(matches!(
            error,
            P2pError::Peer(PeerError::CountLimit {
                field: "sync inventory",
                actual: 17,
                max: MAX_BLOCKS_PER_SYNC,
            })
        ));
        let (penalty, reason) = outbound_reputation_penalty(&error);
        assert_eq!(penalty, RESOURCE_ABUSE_PENALTY);
        let security = PeerSecurity::default();
        assert!(
            security
                .record_failure(address.ip(), penalty, reason)
                .unwrap()
        );
        assert!(security.is_banned(address.ip()).unwrap());
        assert_eq!(target.lock().unwrap().peer_hello().height, 0);
        server.join().unwrap();
        drop(target);
        clean_test_dir(&path);
    }

    fn wait_for_failed_inbound_sessions(node: &Arc<Mutex<Node>>, failed: u64) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let recorded = node
                .lock()
                .unwrap()
                .status()
                .unwrap()
                .peers
                .iter()
                .filter(|peer| peer.direction == PeerDirection::Inbound)
                .map(|peer| peer.failed_sessions)
                .sum::<u64>();
            if recorded >= failed || Instant::now() >= deadline {
                assert!(
                    recorded >= failed,
                    "inbound session outcome was not recorded"
                );
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn larger_valid_relay_respects_receiver_budget_without_banning_peer() {
        let source_path = test_dir("heterogeneous-relay-source");
        let target_path = test_dir("heterogeneous-relay-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let start_time = unix_time_seconds().unwrap();
        let blocks = (0..3)
            .map(|offset| {
                source
                    .lock()
                    .unwrap()
                    .mine_once(
                        default_miner_destination(),
                        start_time + offset,
                        DEFAULT_MINING_ATTEMPTS,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let frame_bytes = blocks
            .iter()
            .map(|block| {
                encode_peer_frame(&PeerFrame {
                    sequence: 1,
                    message: PeerMessage::SubmitBlock(block.clone()),
                })
                .unwrap()
                .len() as u64
            })
            .collect::<Vec<_>>();
        let largest = *frame_bytes.iter().max().unwrap();
        let smallest = *frame_bytes.iter().min().unwrap();
        let hello = source.lock().unwrap().peer_hello();
        let network_id = hello.network_id;
        let frame_len = |message: PeerMessage| {
            encode_peer_frame(&PeerFrame {
                sequence: 1,
                message,
            })
            .unwrap()
            .len() as u64
        };
        let handshake_bytes = 2 * frame_len(PeerMessage::Hello(hello));
        let result_bytes = frame_len(PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
            block_id: [0; 32],
            status: BlockSubmissionStatus::Accepted,
            peer_height: 0,
            peer_tip: [0; 32],
        }));
        let mempool_bytes = frame_len(PeerMessage::GetMempool)
            + frame_len(PeerMessage::TransactionInventory { txids: Vec::new() });
        // Room for the handshake, one valid block, its acknowledgement, and an
        // empty mempool exchange, but never for a second block in one session.
        let receiver_limits = PeerLimits {
            max_bytes_per_peer: handshake_bytes + largest + result_bytes + mempool_bytes,
            compress_blocks: false,
            ..test_limits()
        };
        assert!(largest + mempool_bytes < 2 * smallest);
        let sender_limits = test_limits();
        assert!(block_sync_batch_limit(network_id, sender_limits) >= blocks.len());

        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let listener = spawn_inbound_listener_inner(
            Arc::clone(&target),
            socket,
            receiver_limits,
            Some(TARGET_NONCE),
        )
        .unwrap();

        // The sender offers its whole valid, protocol-sized batch. The
        // receiver accepts what fits its own budget and closes the session at
        // the next block frame instead of treating the peer as an abuser.
        for (session, expected_height) in [1_u64, 2, 3].into_iter().enumerate() {
            let result = relay_blocks_to_peer_once_inner_with_policy(
                Arc::clone(&source),
                address,
                sender_limits,
                PeerAddressPolicy::PrivateOnly,
                Some(SOURCE_NONCE),
                None,
            );
            if expected_height < blocks.len() as u64 {
                assert!(
                    result.is_err(),
                    "the receiver must close the over-budget session"
                );
                wait_for_failed_inbound_sessions(&target, session as u64 + 1);
            } else {
                assert_eq!(result.unwrap().accepted_blocks, 1);
            }
            assert!(
                !listener.peer_is_temporarily_banned(address.ip()).unwrap(),
                "a valid block stream above the receiver budget must not ban the sender"
            );
            assert_eq!(
                target.lock().unwrap().peer_hello().height,
                expected_height,
                "each relay session must still deliver the block that fits"
            );
        }
        assert!(tips_match(&source, &target));

        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn inbound_message_floods_and_oversized_frames_remain_resource_abuse() {
        for error in [
            PeerError::PeerBudgetExceeded,
            PeerError::PayloadTooLarge { actual: 2, max: 1 },
            PeerError::CountLimit {
                field: "test",
                actual: 2,
                max: 1,
            },
        ] {
            assert_eq!(
                inbound_reputation_penalty(&P2pError::Peer(error), true).0,
                RESOURCE_ABUSE_PENALTY
            );
        }
    }

    #[test]
    fn slow_inbound_peer_after_handshake_is_not_banned_for_transport_churn() {
        let path = test_dir("slow-handshaken-peer");
        let shared = open_shared(&path);
        let security = Arc::new(PeerSecurity::default());
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        // Earlier transient failures leave the address one penalty short of a ban.
        assert!(
            !security
                .record_failure(
                    loopback,
                    PEER_BAN_SCORE - TRANSIENT_FAILURE_PENALTY,
                    "earlier transport churn",
                )
                .unwrap()
        );
        let client_hello = with_nonce(shared.lock().unwrap().peer_hello(), Some(SOURCE_NONCE));

        // A handshaken peer that pauses past the idle timeout, as a stock
        // client does while its node validates, ends the session unpenalized.
        // A connection that never sends its hello is still churn.
        for (sends_hello, banned_after) in [(true, false), (false, true)] {
            let socket = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = socket.local_addr().unwrap();
            let client = thread::spawn(move || {
                let mut stream = Some(TcpStream::connect(address).unwrap());
                let mut connection = None;
                if sends_hello {
                    let mut handshaken = PeerConnection::from_stream(
                        stream.take().unwrap(),
                        PeerSession::new(client_hello, test_limits()).unwrap(),
                    )
                    .unwrap();
                    handshaken.send_hello().unwrap();
                    assert!(matches!(
                        handshaken.receive().unwrap(),
                        PeerMessage::Hello(_)
                    ));
                    connection = Some(handshaken);
                }
                thread::sleep(test_limits().idle_timeout + Duration::from_millis(500));
                drop((stream, connection));
            });
            let (stream, _) = socket.accept().unwrap();
            let error = respond_to_peer_inner_with_options(
                Arc::clone(&shared),
                stream,
                test_limits(),
                InboundPeerOptions {
                    address_policy: PeerAddressPolicy::PrivateOnly,
                    nonce_override: Some(TARGET_NONCE),
                    cancellation: None,
                    discovery: None,
                    security: Arc::clone(&security),
                },
            )
            .unwrap_err();
            assert!(matches!(error, P2pError::Peer(PeerError::IdleTimeout)));
            assert_eq!(security.is_banned(loopback).unwrap(), banned_after);
            client.join().unwrap();
        }
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn single_block_batches_continue_a_competing_branch_across_sessions() {
        check_single_block_fork_continuation(false, false);
    }

    #[test]
    fn single_block_sync_crosses_a_known_active_prefix_after_sparse_locator() {
        let source_path = test_dir("sparse-active-prefix-source");
        let target_path = test_dir("sparse-active-prefix-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let now = unix_time_seconds().unwrap();
        for offset in 0..16 {
            let block = source
                .lock()
                .unwrap()
                .mine_once(
                    default_miner_destination(),
                    now + offset,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            target
                .lock()
                .unwrap()
                .submit_block(block, now + offset)
                .unwrap();
        }
        mine(&target, 13, now + 100);
        mine(&source, 14, now + 16);
        let (common_tip, first_known, expected_progress) = {
            let node = source.lock().unwrap();
            (
                node.active_block_id_at_height(16).unwrap(),
                node.active_block_id_at_height(14).unwrap(),
                (14..=30)
                    .map(|height| node.active_block_id_at_height(height).unwrap())
                    .collect::<Vec<_>>(),
            )
        };
        let locator = target.lock().unwrap().block_locator(MAX_BLOCKS_PER_SYNC);
        assert!(!locator.contains(&common_tip));
        assert_eq!(
            source.lock().unwrap().inventory_after(&locator, [0; 32], 1),
            vec![first_known],
            "the sparse locator must initially return a known active block before the fork"
        );
        let limits = PeerLimits {
            max_bytes_per_peer: (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64
                + SYNC_CONTROL_RESERVE_BYTES
                + max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64,
            ..test_limits()
        };
        assert_eq!(
            block_sync_batch_limit(crate::DEVNET_PROFILE.network_id, limits),
            1
        );
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let listener =
            spawn_inbound_listener_inner(Arc::clone(&source), socket, limits, Some(SOURCE_NONCE))
                .unwrap();
        let observation = observed_address(PeerDirection::Outbound, address);
        // The first session walks the three known active blocks and downloads
        // the first fork block; every later session downloads one block.
        for (session, expected_cursor) in expected_progress.into_iter().skip(3).enumerate() {
            let report =
                sync_from_peer_once_inner(Arc::clone(&target), address, limits, Some(TARGET_NONCE))
                    .unwrap();
            let cursor = target
                .lock()
                .unwrap()
                .peer_sync_locator(&observation, MAX_BLOCKS_PER_SYNC)
                .1;
            assert_eq!(report.inventory_items, if session == 0 { 4 } else { 1 });
            assert_eq!(
                cursor,
                Some(expected_cursor),
                "session {session} repeated a known active prefix: requested={}, accepted={}, already_known={}",
                report.requested_blocks,
                report.accepted_blocks,
                report.already_known
            );
            assert_eq!(report.already_known, if session == 0 { 3 } else { 0 });
            assert_eq!(report.accepted_blocks, 1);
        }
        assert!(tips_match(&source, &target));
        assert_eq!(target.lock().unwrap().peer_hello().height, 30);
        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn single_block_fork_continuation_recovers_after_receiver_restart() {
        check_single_block_fork_continuation(true, false);
    }

    #[test]
    fn single_block_fork_continuation_survives_a_changing_remote_tip() {
        check_single_block_fork_continuation(false, true);
    }

    #[test]
    fn repeated_competing_forks_reuse_state_while_both_tips_move() {
        fn mine_active(node: &Arc<Mutex<Node>>, timestamp: u64, payout: u8) -> Block {
            let block = {
                let node = node.lock().unwrap();
                let template = node
                    .build_template(insecure_dev_destination(payout), timestamp)
                    .unwrap();
                let proof = node
                    .verifier
                    .mine(&template.challenge, 0, DEFAULT_MINING_ATTEMPTS)
                    .unwrap();
                Block {
                    version: cmfd_consensus::BLOCK_VERSION,
                    challenge: template.challenge,
                    proof,
                    coinbase: template.coinbase,
                    transactions: template.transactions,
                }
            };
            crate::submit_shared_block(node, block.clone(), timestamp).unwrap();
            block
        }

        let source_path = test_dir("repeated-fork-state-source");
        let target_path = test_dir("repeated-fork-state-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let start = unix_time_seconds().unwrap().saturating_sub(600);
        for offset in 0..16 {
            let block = mine_active(&source, start + offset, 0x81);
            target
                .lock()
                .unwrap()
                .submit_block(block, start + offset)
                .unwrap();
        }
        // Exercise production branch admission with cheap deterministic V2
        // proofs; this is a state-reuse regression, not a V4 speed benchmark.
        target.lock().unwrap().profile.proof = crate::ProofProfile::ProductionV4;
        let replayed = Arc::clone(&target.lock().unwrap().block_preverifier.replay_state_blocks);
        let limits = PeerLimits {
            max_bytes_per_peer: (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64
                + SYNC_CONTROL_RESERVE_BYTES
                + max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64,
            ..test_limits()
        };
        assert_eq!(
            block_sync_batch_limit(crate::DEVNET_PROFILE.network_id, limits),
            1
        );
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let listener =
            spawn_inbound_listener_inner(Arc::clone(&source), socket, limits, Some(SOURCE_NONCE))
                .unwrap();

        for round in 0..3 {
            assert!(tips_match(&source, &target));
            let round_replays = replayed.load(Ordering::Relaxed);
            let timestamp = start + 100 + round * 100;
            let transaction = {
                let mut node = source.lock().unwrap();
                let tip = node.peer_hello().tip;
                let funding = decode_block(
                    &node.canonical_block(tip).unwrap().unwrap(),
                    node.peer_hello().network_id,
                )
                .unwrap();
                spend_community_output(&node, &funding, 10)
            };
            let source_output = OutPoint {
                txid: transaction.txid(),
                index: 0,
            };
            let mut competing_transaction = transaction.clone();
            competing_transaction.outputs[0].lock = OutputLock::Key(insecure_dev_destination(0x92));
            competing_transaction
                .sign_all(&[&SigningKey::from_bytes(&[0x12; 32]).unwrap()])
                .unwrap();
            let target_output = OutPoint {
                txid: competing_transaction.txid(),
                index: 0,
            };
            source
                .lock()
                .unwrap()
                .submit_transaction(transaction)
                .unwrap();
            target
                .lock()
                .unwrap()
                .submit_transaction(competing_transaction)
                .unwrap();
            for offset in 1..=3 {
                mine_active(&source, timestamp + offset, 0x81);
            }
            mine_active(&target, timestamp + 21, 0x91);
            let mut local_tip = mine_active(&target, timestamp + 22, 0x91).block_id();
            let mut warmed_replays = None;

            for session in 0..5 {
                let report = sync_from_peer_once_inner(
                    Arc::clone(&target),
                    address,
                    limits,
                    Some(TARGET_NONCE),
                )
                .unwrap();
                assert_eq!(report.inventory_items, 1);
                assert_eq!(report.requested_blocks, 1);
                assert_eq!(report.accepted_blocks, 1);
                assert_eq!(report.already_known, 0);
                let completed_replays = replayed.load(Ordering::Relaxed);
                if let Some(warmed) = warmed_replays {
                    assert_eq!(
                        completed_replays, warmed,
                        "round {round} session {session} replayed ancestors instead of reusing the validated side tip"
                    );
                } else {
                    assert!(
                        completed_replays - round_replays
                            <= crate::ACTIVE_BRANCH_CHECKPOINT_INTERVAL,
                        "round {round} lost its recent active anchor before the next fork"
                    );
                    warmed_replays = Some(completed_replays);
                }
                if session < 3 {
                    let node = target.lock().unwrap();
                    assert_eq!(
                        node.peer_hello().tip,
                        local_tip,
                        "equal or lower work must not switch branches"
                    );
                    assert!(node.state.utxos().get(&target_output).is_some());
                    assert!(node.state.utxos().get(&source_output).is_none());
                }
                if session == 0 {
                    // Change both tips while the target retains a validated
                    // side branch. A new local revision must not lose it.
                    local_tip = mine_active(&target, timestamp + 23, 0x91).block_id();
                    mine_active(&source, timestamp + 4, 0x81);
                } else if session == 1 {
                    mine_active(&source, timestamp + 5, 0x81);
                }
            }
            assert!(tips_match(&source, &target));
            let source_node = source.lock().unwrap();
            let target_node = target.lock().unwrap();
            assert_eq!(source_node.cumulative_work(), target_node.cumulative_work());
            assert_eq!(
                source_node.state.encode_local_snapshot().unwrap(),
                target_node.state.encode_local_snapshot().unwrap(),
                "round {round} must converge on the exact transaction and chain state"
            );
            assert!(target_node.state.utxos().get(&source_output).is_some());
            assert!(target_node.state.utxos().get(&target_output).is_none());
        }
        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    fn check_single_block_fork_continuation(restart: bool, grow: bool) {
        let source_path = test_dir("single-fork-source");
        let target_path = test_dir("single-fork-target");
        let source = open_shared(&source_path);
        let mut target = open_shared(&target_path);
        let now = unix_time_seconds().unwrap();
        mine(&source, 4, now);
        mine(&target, 2, now + 20);
        let limits = PeerLimits {
            max_bytes_per_peer: (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64
                + SYNC_CONTROL_RESERVE_BYTES
                + max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64,
            ..test_limits()
        };
        assert_eq!(
            block_sync_batch_limit(crate::DEVNET_PROFILE.network_id, limits),
            1
        );
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let listener =
            spawn_inbound_listener_inner(Arc::clone(&source), socket, limits, Some(SOURCE_NONCE))
                .unwrap();
        let total_blocks = 4 + usize::from(grow);
        let mut fetched = 0;
        let mut session = 0;
        while fetched < total_blocks {
            let report =
                sync_from_peer_once_inner(Arc::clone(&target), address, limits, Some(TARGET_NONCE))
                    .unwrap();
            assert_eq!(report.inventory_items, 1);
            assert_eq!(
                report.accepted_blocks, 1,
                "session {session} repeated a known side-chain prefix instead of continuing"
            );
            fetched += 1;
            if session == 0 {
                if grow {
                    mine(&source, 1, now + 4);
                }
                if restart {
                    drop(target);
                    target = Arc::new(Mutex::new(
                        Node::open_with_profile(&target_path, crate::DEVNET_PROFILE).unwrap(),
                    ));
                    let recovered = sync_from_peer_once_inner(
                        Arc::clone(&target),
                        address,
                        limits,
                        Some(TARGET_NONCE),
                    )
                    .unwrap();
                    // The restarted receiver walks the stored block and
                    // continues with the next one in the same session.
                    assert_eq!(recovered.already_known, 1);
                    assert_eq!(recovered.accepted_blocks, 1);
                    fetched += 1;
                }
            }
            session += 1;
        }
        assert!(tips_match(&source, &target));
        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn longer_fork_converges_without_trusting_advertised_work() {
        let source_path = test_dir("fork-source");
        let target_path = test_dir("fork-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let now = unix_time_seconds().unwrap();
        mine(&source, 2, now);
        mine(&target, 1, now + 20);
        assert!(!tips_match(&source, &target));
        let (listener, address) = start_listener(Arc::clone(&source), SOURCE_NONCE);

        let report = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert_eq!(report.accepted_blocks, 2);
        assert!(tips_match(&source, &target));
        assert_eq!(
            source.lock().unwrap().cumulative_work(),
            target.lock().unwrap().cumulative_work()
        );

        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn single_block_push_batches_continue_a_competing_branch() {
        let source_path = test_dir("single-push-source");
        let target_path = test_dir("single-push-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let now = unix_time_seconds().unwrap();
        mine(&source, 4, now);
        mine(&target, 2, now + 20);
        let target_branch = {
            let mut node = target.lock().unwrap();
            let genesis = node.block_locator(1);
            node.inventory_after(&genesis, [0; 32], 2)
                .into_iter()
                .map(|id| {
                    decode_block(
                        &node.canonical_block(id).unwrap().unwrap(),
                        crate::DEVNET_PROFILE.network_id,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        for block in target_branch {
            source
                .lock()
                .unwrap()
                .submit_block(block, now + 30)
                .unwrap();
        }
        let limits = PeerLimits {
            max_bytes_per_peer: (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64
                + SYNC_CONTROL_RESERVE_BYTES
                + max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64,
            ..test_limits()
        };
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let listener =
            spawn_inbound_listener_inner(Arc::clone(&target), socket, limits, Some(TARGET_NONCE))
                .unwrap();
        for session in 0..4 {
            let report = relay_blocks_to_peer_once_inner_with_policy(
                Arc::clone(&source),
                address,
                limits,
                PeerAddressPolicy::PrivateOnly,
                Some(SOURCE_NONCE),
                None,
            )
            .unwrap();
            assert_eq!(report.offered_blocks, 1);
            assert_eq!(
                report.accepted_blocks, 1,
                "push session {session} repeated an acknowledged prefix"
            );
        }
        assert!(tips_match(&source, &target));
        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn block_then_transaction_pull_propagates_between_two_nodes() {
        let source_path = test_dir("transaction-source");
        let target_path = test_dir("transaction-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let funding = source
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let transaction = {
            let node = source.lock().unwrap();
            spend_community_output(&node, &funding, 10)
        };
        let txid = transaction.txid();
        source
            .lock()
            .unwrap()
            .submit_transaction(transaction)
            .unwrap();
        let (listener, address) = start_listener(Arc::clone(&source), SOURCE_NONCE);

        let report = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert_eq!(report.accepted_blocks, 1);
        assert_eq!(report.transaction_inventory_items, 1);
        assert_eq!(report.requested_transactions, 1);
        assert_eq!(report.accepted_transactions, 1);
        assert_eq!(report.rejected_transactions, 0);
        assert!(tips_match(&source, &target));
        let target_txids: Vec<_> = target
            .lock()
            .unwrap()
            .mempool_entries()
            .map(|entry| entry.txid)
            .collect();
        assert_eq!(target_txids, vec![txid]);

        let second = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert!(second.up_to_date());
        assert_eq!(second.transaction_inventory_items, 1);
        assert_eq!(second.already_known_transactions, 1);
        assert_eq!(second.requested_transactions, 0);

        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn outbound_relay_propagates_wallet_transaction_to_static_peer() {
        let wallet_path = test_dir("transaction-relay-wallet");
        let seed_path = test_dir("transaction-relay-seed");
        let wallet = open_shared(&wallet_path);
        let seed = open_shared(&seed_path);
        let funding = wallet
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let transaction = {
            let node = wallet.lock().unwrap();
            spend_community_output(&node, &funding, 10)
        };
        let txid = transaction.txid();
        wallet
            .lock()
            .unwrap()
            .submit_transaction(transaction)
            .unwrap();
        let (listener, address) = start_listener(Arc::clone(&seed), TARGET_NONCE);

        let report = relay_blocks_to_peer_once_inner_with_policy(
            Arc::clone(&wallet),
            address,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            Some(SOURCE_NONCE),
            None,
        )
        .unwrap();
        assert_eq!(report.offered_blocks, 1);
        assert_eq!(report.offered_transactions, 1);

        let deadline = Instant::now() + Duration::from_secs(2);
        while seed.lock().unwrap().mempool_entries().len() != 1 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let seed_txids: Vec<_> = seed
            .lock()
            .unwrap()
            .mempool_entries()
            .map(|entry| entry.txid)
            .collect();
        assert_eq!(seed_txids, vec![txid]);

        let second = relay_blocks_to_peer_once_inner_with_policy(
            Arc::clone(&wallet),
            address,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            Some(SOURCE_NONCE),
            None,
        )
        .unwrap();
        assert_eq!(second.offered_blocks, 0);
        assert_eq!(second.offered_transactions, 0);

        listener.stop().unwrap();
        drop(wallet);
        drop(seed);
        clean_test_dir(&wallet_path);
        clean_test_dir(&seed_path);
    }

    #[test]
    fn transaction_peer_fault_classification_excludes_local_state_and_policy() {
        let outpoint = OutPoint {
            txid: [0x31; 32],
            index: 0,
        };
        let nonpunitive = [
            NodeError::DuplicateMempoolTransaction([0x32; 32]),
            NodeError::MempoolUnconfirmedInput(outpoint),
            NodeError::MempoolInputConflict(outpoint),
            NodeError::ExchangeWithdrawalInputReserved(outpoint),
            NodeError::ExchangeWithdrawalReservationMismatch(outpoint),
            NodeError::ExchangeCustodyV3WalletExclusive,
            NodeError::MempoolTransactionLimit,
            NodeError::MempoolByteLimit,
            NodeError::MempoolFeeTooLow {
                required: 2,
                actual: 1,
            },
            NodeError::Chain(ChainError::MissingInput),
            NodeError::Chain(ChainError::ImmatureInput(100)),
            NodeError::Chain(ChainError::DuplicateInput),
            NodeError::Chain(ChainError::WrongOwner),
            NodeError::Chain(ChainError::WrongWitness),
            NodeError::Chain(ChainError::CreatesValue),
            NodeError::Chain(ChainError::FeeTooLow {
                required: 2,
                actual: 1,
            }),
            NodeError::Chain(ChainError::AmountOverflow),
            NodeError::Chain(ChainError::ChannelCloseShape),
            NodeError::Chain(ChainError::BlockTransactionLimit),
            NodeError::Chain(ChainError::BlockAggregateLimit),
            NodeError::Chain(ChainError::BlockSignatureLimit),
        ];
        for error in nonpunitive {
            assert!(!transaction_rejection_is_peer_fault(&error), "{error}");
        }
        let intrinsic = [
            NodeError::Chain(ChainError::WrongNetwork),
            NodeError::Chain(ChainError::UnsupportedTransactionVersion),
            NodeError::Chain(ChainError::NoInputs),
            NodeError::Chain(ChainError::NoOutputs),
            NodeError::Chain(ChainError::ZeroValueOutput),
            NodeError::Chain(ChainError::MalformedSignature),
            NodeError::Chain(ChainError::InvalidSignature),
            NodeError::Chain(ChainError::TransactionInputLimit),
            NodeError::Chain(ChainError::TransactionOutputLimit),
            NodeError::Chain(ChainError::SignatureLength),
            NodeError::Wire(WireError::SignatureLength { actual: 63 }),
        ];
        for error in intrinsic {
            assert!(transaction_rejection_is_peer_fault(&error), "{error}");
        }
        let malformed_frame =
            P2pError::Peer(PeerError::ConsensusWire(WireError::SignatureLength {
                actual: 63,
            }));
        assert_eq!(
            inbound_reputation_penalty(&malformed_frame, true).0,
            PROTOCOL_VIOLATION_PENALTY
        );
    }

    #[test]
    fn relayed_invalid_signatures_still_ban_the_peer() {
        let path = test_dir("invalid-signature-relay");
        let target = open_shared(&path);
        let invalid = {
            let mut node = target.lock().unwrap();
            let funding = node
                .mine_once(
                    default_miner_destination(),
                    unix_time_seconds().unwrap(),
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            let mut transaction = spend_community_output(&node, &funding, 10);
            transaction.outputs[0].value -= 1;
            assert!(matches!(
                node.submit_transaction(transaction.clone()),
                Err(NodeError::Chain(ChainError::InvalidSignature))
            ));
            transaction
        };
        let initial_tip = target.lock().unwrap().peer_hello().tip;
        let (listener, address) = start_listener(Arc::clone(&target), TARGET_NONCE);
        let hello = with_nonce(target.lock().unwrap().peer_hello(), Some(SOURCE_NONCE));
        let session = PeerSession::new(hello, test_limits()).unwrap();
        let mut client = PeerConnection::connect(address, session).unwrap();
        client.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));
        for index in 0..4 {
            client
                .send(PeerMessage::Transaction(invalid.clone()))
                .unwrap();
            client.send(PeerMessage::GetMempool).unwrap();
            let response = client.receive();
            if index < 3 {
                assert_eq!(
                    response.unwrap(),
                    PeerMessage::TransactionInventory { txids: Vec::new() }
                );
            } else {
                assert!(response.is_err());
            }
        }
        assert!(listener.peer_is_temporarily_banned(address.ip()).unwrap());
        assert_eq!(target.lock().unwrap().mempool_entries().len(), 0);
        assert_eq!(target.lock().unwrap().peer_hello().tip, initial_tip);
        drop(client);
        listener.stop().unwrap();
        drop(target);
        clean_test_dir(&path);
    }

    #[test]
    fn ahead_peer_transactions_do_not_ban_a_catching_up_receiver() {
        let source_path = test_dir("ahead-transaction-source");
        let target_path = test_dir("ahead-transaction-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let transactions = {
            let mut node = source.lock().unwrap();
            let now = unix_time_seconds().unwrap();
            let funding: Vec<_> = (0..4)
                .map(|offset| {
                    node.mine_once(
                        default_miner_destination(),
                        now + offset,
                        DEFAULT_MINING_ATTEMPTS,
                    )
                    .unwrap()
                })
                .collect();
            funding
                .iter()
                .map(|block| {
                    let transaction = spend_community_output(&node, block, 10);
                    node.submit_transaction(transaction.clone()).unwrap();
                    transaction
                })
                .collect::<Vec<_>>()
        };
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let discovery = Arc::new(PeerDiscovery::open(
            &target_path,
            target.lock().unwrap().peer_hello(),
            address,
            PeerAddressPolicy::PrivateOnly,
        ));
        let listener = spawn_inbound_listener_inner_with_policy(
            Arc::clone(&target),
            socket,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            Some(TARGET_NONCE),
            Some(Arc::clone(&discovery)),
        )
        .unwrap();
        let hello = with_nonce(source.lock().unwrap().peer_hello(), Some(SOURCE_NONCE));
        let session = PeerSession::new(hello, test_limits()).unwrap();
        let mut client = PeerConnection::connect(address, session).unwrap();
        client.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));

        for transaction in transactions {
            client.send(PeerMessage::Transaction(transaction)).unwrap();
            client.send(PeerMessage::GetMempool).unwrap();
            let response = client.receive();
            assert!(
                !listener.peer_is_temporarily_banned(address.ip()).unwrap(),
                "an honest ahead peer must not be banned for inputs absent from the local chain"
            );
            assert_eq!(
                response.unwrap(),
                PeerMessage::TransactionInventory { txids: Vec::new() }
            );
        }
        assert_eq!(target.lock().unwrap().mempool_entries().len(), 0);
        assert_eq!(target.lock().unwrap().peer_hello().height, 0);
        drop(client);

        let (source_listener, source_address) = start_listener(Arc::clone(&source), SOURCE_NONCE);
        let poller = spawn_peer_polling_inner(
            Arc::clone(&target),
            StaticPeerConfig {
                listen_address: address,
                peers: vec![source_address],
                limits: test_limits(),
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_millis(10),
            Some(TARGET_NONCE),
            Some(discovery),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !tips_match(&source, &target) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            tips_match(&source, &target),
            "block synchronization must remain available"
        );
        assert!(!listener.peer_is_temporarily_banned(address.ip()).unwrap());
        poller.stop().unwrap();
        source_listener.stop().unwrap();
        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn invalid_relayed_transaction_is_not_admitted() {
        let target_path = test_dir("invalid-relayed-transaction");
        let target = open_shared(&target_path);
        let (listener, address) = start_listener(Arc::clone(&target), TARGET_NONCE);
        let mut hello = target.lock().unwrap().peer_hello();
        hello.node_nonce = SOURCE_NONCE;
        let invalid = invalid_transaction(hello.network_id, 0);
        let session = PeerSession::new(hello, test_limits()).unwrap();
        let mut client = PeerConnection::connect(address, session).unwrap();
        client.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));

        client.send(PeerMessage::Transaction(invalid)).unwrap();
        client.send(PeerMessage::GetMempool).unwrap();
        assert_eq!(
            client.receive().unwrap(),
            PeerMessage::TransactionInventory { txids: Vec::new() }
        );
        assert_eq!(target.lock().unwrap().mempool_entries().len(), 0);

        drop(client);
        listener.stop().unwrap();
        drop(target);
        clean_test_dir(&target_path);
    }

    #[test]
    fn invalid_transaction_is_rejected_without_changing_chain_or_stopping_sync() {
        let target_path = test_dir("invalid-transaction");
        let target = open_shared(&target_path);
        let (listener, address) = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            (listener, address)
        };
        let mut server_hello = target.lock().unwrap().peer_hello();
        server_hello.node_nonce = SOURCE_NONCE;
        let invalid = invalid_transaction(server_hello.network_id, 0);
        let txid = invalid.txid();
        let server = thread::spawn(move || {
            let mut connection = accept_test_peer(listener, server_hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::GetHeaders { .. }
            ));
            connection
                .send(PeerMessage::Inventory {
                    block_ids: Vec::new(),
                })
                .unwrap();
            assert_eq!(connection.receive().unwrap(), PeerMessage::GetMempool);
            connection
                .send(PeerMessage::TransactionInventory { txids: vec![txid] })
                .unwrap();
            assert_eq!(
                connection.receive().unwrap(),
                PeerMessage::GetTransaction { txid }
            );
            connection.send(PeerMessage::Transaction(invalid)).unwrap();
        });
        let before = target.lock().unwrap().peer_hello();

        let report = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert_eq!(report.requested_transactions, 1);
        assert_eq!(report.accepted_transactions, 0);
        assert_eq!(report.rejected_transactions, 1);
        let node = target.lock().unwrap();
        assert_eq!(node.peer_hello().tip, before.tip);
        assert_eq!(node.peer_hello().height, before.height);
        assert_eq!(node.mempool_entries().len(), 0);
        drop(node);

        server.join().unwrap();
        drop(target);
        clean_test_dir(&target_path);
    }

    #[test]
    fn mismatched_transaction_body_is_a_peer_error_and_is_not_admitted() {
        let target_path = test_dir("mismatched-transaction");
        let target = open_shared(&target_path);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut server_hello = target.lock().unwrap().peer_hello();
        server_hello.node_nonce = SOURCE_NONCE;
        let transaction = invalid_transaction(server_hello.network_id, 1);
        let actual = transaction.txid();
        let requested = [0x7c; 32];
        assert_ne!(requested, actual);
        let server = thread::spawn(move || {
            let mut connection = accept_test_peer(listener, server_hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::GetHeaders { .. }
            ));
            connection
                .send(PeerMessage::Inventory {
                    block_ids: Vec::new(),
                })
                .unwrap();
            assert_eq!(connection.receive().unwrap(), PeerMessage::GetMempool);
            connection
                .send(PeerMessage::TransactionInventory {
                    txids: vec![requested],
                })
                .unwrap();
            assert_eq!(
                connection.receive().unwrap(),
                PeerMessage::GetTransaction { txid: requested }
            );
            connection
                .send(PeerMessage::Transaction(transaction))
                .unwrap();
        });
        let before = target.lock().unwrap().peer_hello();

        let error = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            P2pError::WrongTransaction {
                requested: returned_requested,
                actual: returned_actual,
            } if returned_requested == requested && returned_actual == actual
        ));
        let node = target.lock().unwrap();
        assert_eq!(node.peer_hello().tip, before.tip);
        assert_eq!(node.peer_hello().height, before.height);
        assert_eq!(node.mempool_entries().len(), 0);
        drop(node);

        server.join().unwrap();
        drop(target);
        clean_test_dir(&target_path);
    }

    #[test]
    fn one_sync_call_requests_at_most_the_transaction_batch_bound() {
        let target_path = test_dir("transaction-bound");
        let target = open_shared(&target_path);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut server_hello = target.lock().unwrap().peer_hello();
        server_hello.node_nonce = SOURCE_NONCE;
        let transactions: Vec<_> = (0..=MAX_TRANSACTIONS_PER_SYNC as u32)
            .map(|index| invalid_transaction(server_hello.network_id, index))
            .collect();
        let txids: Vec<_> = transactions.iter().map(Transaction::txid).collect();
        let expected_requested = txids[..MAX_TRANSACTIONS_PER_SYNC].to_vec();
        let server = thread::spawn(move || {
            let mut connection = accept_test_peer(listener, server_hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::GetHeaders { .. }
            ));
            connection
                .send(PeerMessage::Inventory {
                    block_ids: Vec::new(),
                })
                .unwrap();
            assert_eq!(connection.receive().unwrap(), PeerMessage::GetMempool);
            connection
                .send(PeerMessage::TransactionInventory { txids })
                .unwrap();

            let mut requested = Vec::new();
            for transaction in transactions.into_iter().take(MAX_TRANSACTIONS_PER_SYNC) {
                let txid = transaction.txid();
                assert_eq!(
                    connection.receive().unwrap(),
                    PeerMessage::GetTransaction { txid }
                );
                requested.push(txid);
                connection
                    .send(PeerMessage::Transaction(transaction))
                    .unwrap();
            }
            requested
        });

        let report = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        assert_eq!(
            report.transaction_inventory_items,
            MAX_TRANSACTIONS_PER_SYNC + 1
        );
        assert_eq!(report.requested_transactions, MAX_TRANSACTIONS_PER_SYNC);
        assert_eq!(report.accepted_transactions, 0);
        assert_eq!(report.rejected_transactions, MAX_TRANSACTIONS_PER_SYNC);
        assert!(!report.up_to_date());
        assert_eq!(server.join().unwrap(), expected_requested);
        assert_eq!(target.lock().unwrap().mempool_entries().len(), 0);

        drop(target);
        clean_test_dir(&target_path);
    }

    #[test]
    fn wrong_fingerprint_hello_is_rejected() {
        let target_path = test_dir("wrong-fingerprint");
        let target = open_shared(&target_path);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let target_for_server = Arc::clone(&target);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut inbound_header = [0_u8; PEER_FRAME_HEADER_BYTES];
            stream.read_exact(&mut inbound_header).unwrap();
            let inbound_len =
                u32::from_le_bytes(inbound_header[16..20].try_into().unwrap()) as usize;
            let mut inbound_payload = vec![0_u8; inbound_len];
            stream.read_exact(&mut inbound_payload).unwrap();
            let mut hello = target_for_server.lock().unwrap().peer_hello();
            hello.consensus_fingerprint[0] ^= 1;
            hello.node_nonce = SOURCE_NONCE;
            let frame = encode_peer_frame(&PeerFrame {
                sequence: 0,
                message: PeerMessage::Hello(hello),
            })
            .unwrap();
            stream.write_all(&frame).unwrap();
        });

        let error = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        )
        .unwrap_err();
        assert!(
            matches!(&error, P2pError::Peer(PeerError::WrongConsensusFingerprint)),
            "{error:?}"
        );
        server.join().unwrap();
        drop(target);
        clean_test_dir(&target_path);
    }

    #[test]
    fn unknown_get_block_closes_the_connection() {
        let source_path = test_dir("unknown-block");
        let source = open_shared(&source_path);
        let (listener, address) = start_listener(Arc::clone(&source), SOURCE_NONCE);
        let mut hello = source.lock().unwrap().peer_hello();
        hello.node_nonce = TARGET_NONCE;
        let session = PeerSession::new(hello, test_limits()).unwrap();
        let mut client = PeerConnection::connect(address, session).unwrap();
        client.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));
        client
            .send(PeerMessage::GetBlock {
                block_id: [0xa5; 32],
            })
            .unwrap();
        assert!(client.receive().is_err());

        drop(client);
        listener.stop().unwrap();
        drop(source);
        clean_test_dir(&source_path);
    }

    #[test]
    fn unknown_get_transaction_closes_only_that_connection() {
        let source_path = test_dir("unknown-transaction");
        let source = open_shared(&source_path);
        let (listener, address) = start_listener(Arc::clone(&source), SOURCE_NONCE);
        let mut hello = source.lock().unwrap().peer_hello();
        hello.node_nonce = TARGET_NONCE;
        let session = PeerSession::new(hello, test_limits()).unwrap();
        let mut client = PeerConnection::connect(address, session).unwrap();
        client.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));
        client
            .send(PeerMessage::GetTransaction { txid: [0xa6; 32] })
            .unwrap();
        assert!(client.receive().is_err());

        drop(client);

        // The listener remains healthy after isolating the failed session.
        let mut retry_hello = source.lock().unwrap().peer_hello();
        retry_hello.node_nonce = [0x53; 32];
        let retry_session = PeerSession::new(retry_hello, test_limits()).unwrap();
        let mut retry = PeerConnection::connect(address, retry_session).unwrap();
        retry.send_hello().unwrap();
        assert!(matches!(retry.receive().unwrap(), PeerMessage::Hello(_)));
        retry.send(PeerMessage::GetMempool).unwrap();
        assert_eq!(
            retry.receive().unwrap(),
            PeerMessage::TransactionInventory { txids: Vec::new() }
        );

        drop(retry);
        listener.stop().unwrap();
        drop(source);
        clean_test_dir(&source_path);
    }

    #[test]
    fn submitted_blocks_are_acknowledged_rejected_and_deduplicated() {
        let source_path = test_dir("submit-source");
        let target_path = test_dir("submit-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let block = source
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let mut invalid = block.clone();
        invalid.challenge.timestamp = invalid.challenge.timestamp.saturating_add(1);
        let invalid_id = invalid.block_id();
        let block_id = block.block_id();
        let (listener, address) = start_listener(Arc::clone(&target), TARGET_NONCE);

        let mut hello = source.lock().unwrap().peer_hello();
        hello.node_nonce = SOURCE_NONCE;
        let session = PeerSession::new(hello, test_limits()).unwrap();
        let mut client = PeerConnection::connect(address, session).unwrap();
        client.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));

        client.send(PeerMessage::SubmitBlock(invalid)).unwrap();
        assert!(matches!(
            client.receive().unwrap(),
            PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                block_id: returned,
                status: BlockSubmissionStatus::Rejected,
                peer_height: 0,
                ..
            }) if returned == invalid_id
        ));
        assert_eq!(target.lock().unwrap().peer_hello().height, 0);

        client
            .send(PeerMessage::SubmitBlock(block.clone()))
            .unwrap();
        assert!(matches!(
            client.receive().unwrap(),
            PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                block_id: returned,
                status: BlockSubmissionStatus::Accepted,
                peer_height: 1,
                peer_tip,
            }) if returned == block_id && peer_tip == block_id
        ));
        client.send(PeerMessage::SubmitBlock(block)).unwrap();
        assert!(matches!(
            client.receive().unwrap(),
            PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                block_id: returned,
                status: BlockSubmissionStatus::AlreadyKnown,
                peer_height: 1,
                peer_tip,
            }) if returned == block_id && peer_tip == block_id
        ));

        drop(client);
        listener.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn submit_cancellation_interrupts_handshake_and_closes_the_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (handshake_waiting, waiting_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut header = [0_u8; PEER_FRAME_HEADER_BYTES];
            stream.read_exact(&mut header).unwrap();
            let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
            let mut payload = vec![0_u8; payload_len];
            stream.read_exact(&mut payload).unwrap();
            handshake_waiting.send(()).unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancellation);
        let block = submission_test_block("cancel-handshake-block");
        let worker = thread::spawn(move || {
            test_submit_mined_block_once_with_policy_before_cancellable(
                address,
                block,
                test_limits(),
                PeerAddressPolicy::PrivateOnly,
                Instant::now().checked_add(Duration::from_secs(5)).unwrap(),
                worker_cancel,
            )
        });

        waiting_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let stopped_at = Instant::now();
        cancellation.store(true, Ordering::Release);
        let error = worker.join().unwrap().unwrap_err();
        assert!(error.is_cancelled());
        assert!(stopped_at.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn submit_cancellation_interrupts_response_wait_and_closes_the_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (response_waiting, waiting_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let hello = with_nonce(test_thin_miner_hello(), Some(TARGET_NONCE));
            let mut connection = accept_test_peer(listener, hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::SubmitBlock(_)
            ));
            response_waiting.send(()).unwrap();
            assert!(matches!(
                connection.receive(),
                Err(PeerError::ConnectionClosed)
            ));
        });
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancellation);
        let block = submission_test_block("cancel-response-block");
        let worker = thread::spawn(move || {
            test_submit_mined_block_once_with_policy_before_cancellable(
                address,
                block,
                test_limits(),
                PeerAddressPolicy::PrivateOnly,
                Instant::now().checked_add(Duration::from_secs(5)).unwrap(),
                worker_cancel,
            )
        });

        waiting_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let stopped_at = Instant::now();
        cancellation.store(true, Ordering::Release);
        let error = worker.join().unwrap().unwrap_err();
        assert!(error.is_cancelled());
        assert!(stopped_at.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn submission_wrong_id_is_a_protocol_violation_not_a_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let hello = with_nonce(test_thin_miner_hello(), Some(TARGET_NONCE));
            let mut connection = accept_test_peer(listener, hello);
            let PeerMessage::SubmitBlock(block) = connection.receive().unwrap() else {
                panic!("expected submitted block")
            };
            let mut wrong_id = block.block_id();
            wrong_id[0] ^= 1;
            connection
                .send(PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                    block_id: wrong_id,
                    status: BlockSubmissionStatus::Accepted,
                    peer_height: block.challenge.height,
                    peer_tip: wrong_id,
                }))
                .unwrap();
        });
        let cancellation = Arc::new(AtomicBool::new(false));
        let error = test_submit_mined_block_once_with_policy_before_cancellable(
            address,
            submission_test_block("wrong-id-block"),
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            Instant::now().checked_add(Duration::from_secs(5)).unwrap(),
            cancellation,
        )
        .unwrap_err();
        assert!(matches!(error, P2pError::WrongBlockSubmission { .. }));
        assert!(!error.is_transport_disconnect());
        server.join().unwrap();
    }

    #[test]
    fn malformed_submission_response_is_not_reported_as_a_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let hello = with_nonce(test_thin_miner_hello(), Some(TARGET_NONCE));
            let mut connection = accept_test_peer(listener, hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::SubmitBlock(_)
            ));
            let mut raw = connection.try_clone_stream().unwrap();
            let mut header = [0_u8; PEER_FRAME_HEADER_BYTES];
            header[..4].copy_from_slice(b"BAD!");
            raw.write_all(&header).unwrap();
        });
        let error = test_submit_mined_block_once_with_policy_before_cancellable(
            address,
            submission_test_block("malformed-response-block"),
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            Instant::now().checked_add(Duration::from_secs(5)).unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap_err();
        assert!(matches!(error, P2pError::Peer(PeerError::InvalidMagic)));
        assert!(!error.is_transport_disconnect());
        server.join().unwrap();
    }

    #[test]
    fn closed_submission_response_is_reported_as_a_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let hello = with_nonce(test_thin_miner_hello(), Some(TARGET_NONCE));
            let mut connection = accept_test_peer(listener, hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::SubmitBlock(_)
            ));
        });
        let error = test_submit_mined_block_once_with_policy_before_cancellable(
            address,
            submission_test_block("closed-response-block"),
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            Instant::now().checked_add(Duration::from_secs(5)).unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap_err();
        assert!(matches!(error, P2pError::Peer(PeerError::ConnectionClosed)));
        assert!(error.is_transport_disconnect());
        server.join().unwrap();
    }

    #[test]
    fn downloaded_block_wait_keeps_the_total_session_deadline() {
        let source_path = test_dir("download-wait-bounded-source");
        let source = open_shared(&source_path);
        let block = source
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let mut limits = test_limits();
        limits.idle_timeout = Duration::from_millis(100);
        limits.total_timeout = Duration::from_millis(650);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle =
            spawn_inbound_listener_inner(Arc::clone(&source), listener, limits, Some(SOURCE_NONCE))
                .unwrap();
        let mut hello = source.lock().unwrap().peer_hello();
        hello.node_nonce = TARGET_NONCE;
        let session = PeerSession::new(hello, test_limits()).unwrap();
        let mut client = PeerConnection::connect(address, session).unwrap();
        client.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));
        client
            .send(PeerMessage::GetBlock {
                block_id: block.block_id(),
            })
            .unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Block(_)));
        let mut socket = client.try_clone_stream().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let started = Instant::now();
        assert_eq!(socket.read(&mut [0u8; 1]).unwrap(), 0);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(socket);
        drop(client);
        handle.stop().unwrap();
        drop(source);
        clean_test_dir(&source_path);
    }

    #[test]
    fn downloaded_block_validation_outlives_ordinary_peer_idle_timeout() {
        let source_path = test_dir("slow-download-source");
        let target_path = test_dir("slow-download-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        mine(&source, 1, unix_time_seconds().unwrap());
        target
            .lock()
            .unwrap()
            .block_preverifier
            .set_proof_dispatch_delay(Some(Duration::from_millis(400)));
        let mut limits = test_limits();
        limits.idle_timeout = Duration::from_millis(100);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle =
            spawn_inbound_listener_inner(Arc::clone(&source), listener, limits, Some(SOURCE_NONCE))
                .unwrap();
        let report =
            sync_from_peer_once_inner(Arc::clone(&target), address, limits, Some(TARGET_NONCE))
                .unwrap();
        assert_eq!(report.accepted_blocks, 1);
        assert!(tips_match(&source, &target));
        handle.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn downloaded_block_validation_stops_on_local_shutdown() {
        let source_path = test_dir("stop-download-source");
        let target_path = test_dir("stop-download-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let block = source
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let block_id = block.block_id();
        target
            .lock()
            .unwrap()
            .block_preverifier
            .set_proof_dispatch_delay(Some(Duration::from_millis(500)));
        let mut hello = source.lock().unwrap().peer_hello();
        hello.node_nonce = SOURCE_NONCE;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let observer = Arc::clone(&target);
        let registry = Arc::new(ActiveSocketRegistry::default());
        let stopper = Arc::clone(&registry);
        let server = thread::spawn(move || {
            let mut connection = accept_test_peer(listener, hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::GetHeaders { .. }
            ));
            connection
                .send(PeerMessage::Inventory {
                    block_ids: vec![block_id],
                })
                .unwrap();
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::GetBlock { .. }
            ));
            connection.send(PeerMessage::Block(block)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while observer
                .lock()
                .unwrap()
                .block_preverifier
                .worker_dispatches
                .load(Ordering::Acquire)
                == 0
            {
                assert!(Instant::now() < deadline);
                thread::yield_now();
            }
            stopper.stop().unwrap();
        });
        let result = sync_from_peer_once_inner_with_policy(
            Arc::clone(&target),
            address,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
            Some(TARGET_NONCE),
            Some(&registry),
        );
        server.join().unwrap();
        assert!(result.is_err());
        assert!(!target.lock().unwrap().contains_block(block_id));
        assert_eq!(target.lock().unwrap().peer_hello().height, 0);
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn downloaded_block_survives_source_disconnect_during_validation() {
        let source_path = test_dir("download-disconnect-source");
        let target_path = test_dir("download-disconnect-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let block = source
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let block_id = block.block_id();
        target
            .lock()
            .unwrap()
            .block_preverifier
            .set_proof_dispatch_delay(Some(Duration::from_millis(500)));
        let mut hello = source.lock().unwrap().peer_hello();
        hello.node_nonce = SOURCE_NONCE;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let observer = Arc::clone(&target);
        let server = thread::spawn(move || {
            let mut connection = accept_test_peer(listener, hello);
            assert!(matches!(
                connection.receive().unwrap(),
                PeerMessage::GetHeaders { .. }
            ));
            connection
                .send(PeerMessage::Inventory {
                    block_ids: vec![block_id],
                })
                .unwrap();
            assert!(
                matches!(connection.receive().unwrap(), PeerMessage::GetBlock { block_id: id } if id == block_id)
            );
            connection.send(PeerMessage::Block(block)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while observer
                .lock()
                .unwrap()
                .block_preverifier
                .worker_dispatches
                .load(Ordering::Acquire)
                == 0
            {
                assert!(
                    Instant::now() < deadline,
                    "download never reached proof validation"
                );
                thread::yield_now();
            }
            // Models the source's ordinary idle timeout after delivering the
            // complete requested block, while local validation is still busy.
            drop(connection);
        });
        let _transport_result = sync_from_peer_once_inner(
            Arc::clone(&target),
            address,
            test_limits(),
            Some(TARGET_NONCE),
        );
        server.join().unwrap();
        assert!(
            target.lock().unwrap().contains_block(block_id),
            "a complete solicited block was discarded when its source closed the connection"
        );
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn honest_submit_longer_than_idle_timeout_is_accepted_within_submit_budget() {
        let source_path = test_dir("delayed-submit-source");
        let target_path = test_dir("delayed-submit-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let block = source
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        target
            .lock()
            .unwrap()
            .block_preverifier
            .set_proof_dispatch_delay(Some(Duration::from_millis(10_250)));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = spawn_inbound_listener_inner(
            Arc::clone(&target),
            listener,
            PeerLimits::default(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        let started = Instant::now();
        let result = test_submit_mined_block_once_with_policy(
            address,
            block,
            PeerLimits::default(),
            PeerAddressPolicy::PrivateOnly,
        )
        .unwrap();

        assert_eq!(result.status, BlockSubmissionStatus::Accepted);
        assert!(
            started.elapsed() > PeerLimits::default().idle_timeout,
            "test did not cross the ordinary 10-second idle timeout"
        );
        assert!(started.elapsed() < SUBMIT_BLOCK_RESPONSE_BUDGET);
        assert_eq!(target.lock().unwrap().peer_hello().height, 1);

        handle.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn disconnect_during_proof_prevents_durable_acceptance() {
        let source_path = test_dir("disconnect-submit-source");
        let target_path = test_dir("disconnect-submit-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let block = source
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let block_id = block.block_id();
        target
            .lock()
            .unwrap()
            .block_preverifier
            .set_proof_dispatch_delay(Some(Duration::from_millis(500)));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = spawn_inbound_listener_inner(
            Arc::clone(&target),
            listener,
            PeerLimits::default(),
            Some(TARGET_NONCE),
        )
        .unwrap();
        let mut hello = source.lock().unwrap().peer_hello();
        hello.node_nonce = SOURCE_NONCE;
        let session = PeerSession::new(hello, PeerLimits::default()).unwrap();
        let mut client = PeerConnection::connect(address, session).unwrap();
        client.send_hello().unwrap();
        assert!(matches!(client.receive().unwrap(), PeerMessage::Hello(_)));
        client.send(PeerMessage::SubmitBlock(block)).unwrap();

        let dispatch_deadline = Instant::now() + Duration::from_secs(2);
        while target
            .lock()
            .unwrap()
            .block_preverifier
            .worker_dispatches
            .load(Ordering::Acquire)
            == 0
            && Instant::now() < dispatch_deadline
        {
            thread::yield_now();
        }
        assert_eq!(
            target
                .lock()
                .unwrap()
                .block_preverifier
                .worker_dispatches
                .load(Ordering::Acquire),
            1
        );
        drop(client);

        let cancellation_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (height, active) = {
                let node = target.lock().unwrap();
                (
                    node.peer_hello().height,
                    node.block_preverifier.queue.counts().unwrap().0,
                )
            };
            if active == 0 {
                assert_eq!(height, 0);
                break;
            }
            assert!(
                Instant::now() < cancellation_deadline,
                "disconnected submission did not leave proof admission"
            );
            thread::yield_now();
        }
        let node = target.lock().unwrap();
        assert_eq!(node.peer_hello().height, 0);
        assert!(!node.contains_block(block_id));
        drop(node);

        handle.stop().unwrap();
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn submit_block_maps_capacity_and_worker_recovery_to_busy_only() {
        for error in [
            NodeError::ProofVerificationQueueFull,
            NodeError::ProofVerificationQueueTimeout,
            NodeError::ProofVerifierWorker(VerifierWorkerError::Restarting),
            NodeError::ProofVerifierWorker(VerifierWorkerError::Unavailable),
            NodeError::ProofVerifierWorker(VerifierWorkerError::RequestDeadlineExpired),
        ] {
            assert!(is_retryable_block_admission(&error));
        }

        let invalid = NodeError::ProofVerifierWorker(VerifierWorkerError::ProofRejected(
            "invalid proof".to_owned(),
        ));
        assert!(!is_retryable_block_admission(&invalid));
        assert!(invalid.client_error().status < 500);
    }

    #[test]
    fn eight_submit_close_sessions_cannot_pin_remote_proof_admission() {
        let path = test_dir("submit-close-proof-admission");
        let node = open_shared(&path);
        let hello = node.lock().unwrap().peer_hello();
        let remote = Arc::new(crate::RemoteProofAdmissionQueue::new(
            crate::MAX_REMOTE_PROOF_ADMISSIONS,
            Duration::from_secs(2),
            Duration::from_secs(60),
        ));
        let mut clients = Vec::new();
        let mut connections = Vec::new();
        let mut monitors = Vec::new();
        let mut waiters = Vec::new();

        for value in 1..=crate::MAX_REMOTE_PROOF_ADMISSIONS as u64 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            let session = PeerSession::new(hello, test_limits()).unwrap();
            let connection = PeerConnection::from_stream(server, session).unwrap();
            let acceptance_deadline =
                checked_submit_deadline(Instant::now(), SUBMIT_BLOCK_ACCEPTANCE_BUDGET).unwrap();
            let request = crate::RemoteProofRequest::new(acceptance_deadline);
            let monitor = PeerSubmissionMonitor::start(&connection, request.clone()).unwrap();
            let waiter_remote = Arc::clone(&remote);
            waiters.push(thread::spawn(move || {
                let permit = waiter_remote
                    .acquire_cancellable(RemoteProofPeerId::new(value).unwrap(), request.clone())?;
                let deadline = Instant::now() + Duration::from_secs(2);
                while !request.is_cancelled() && Instant::now() < deadline {
                    thread::yield_now();
                }
                drop(permit);
                Err::<(), NodeError>(NodeError::ProofVerificationQueueTimeout)
            }));
            clients.push(client);
            connections.push(connection);
            monitors.push(monitor);

            let expected = value as usize;
            let deadline = Instant::now() + Duration::from_secs(2);
            while {
                let telemetry = remote.telemetry().unwrap();
                telemetry.active + telemetry.queued != expected && Instant::now() < deadline
            } {
                thread::yield_now();
            }
            let telemetry = remote.telemetry().unwrap();
            assert_eq!(telemetry.active + telemetry.queued, expected);
        }

        drop(clients);
        for waiter in waiters {
            assert!(matches!(
                waiter.join().unwrap(),
                Err(NodeError::ProofVerificationQueueTimeout)
            ));
        }
        let telemetry = remote.telemetry().unwrap();
        assert_eq!(telemetry.active, 0);
        assert_eq!(telemetry.queued, 0);
        assert_eq!(telemetry.proof_failures, 0);
        drop(
            remote
                .acquire(RemoteProofPeerId::new(100).unwrap())
                .unwrap(),
        );

        drop(monitors);
        drop(connections);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn thin_miner_fetches_a_template_and_submits_without_a_local_chain() {
        let node_path = test_dir("thin-mining-node");
        let node = open_shared(&node_path);
        let payout = insecure_dev_destination(0x7a);
        let (listener, address) = start_listener(Arc::clone(&node), TARGET_NONCE);

        let response = test_request_mining_template_once_with_policy(
            address,
            payout,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
        )
        .unwrap();
        assert_eq!(response.remote_hello.height, 0);
        assert_eq!(response.template.challenge.height, 1);
        assert_eq!(
            response.template.challenge.previous_block,
            response.remote_hello.tip
        );
        assert!(response.template.coinbase.outputs.iter().any(
            |output| matches!(output.lock, OutputLock::Key(destination) if destination == payout)
        ));

        let verifier = ConsensusPowVerifier::v2_reference(v2_test_reference().unwrap());
        let proof = verifier
            .mine(&response.template.challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let block = response.template.into_block(proof);
        let block_id = block.block_id();
        let result = test_submit_mined_block_once_with_policy(
            address,
            block,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
        )
        .unwrap();

        assert_eq!(result.status, BlockSubmissionStatus::Accepted);
        assert_eq!(result.block_id, block_id);
        assert_eq!(result.peer_height, 1);
        assert_eq!(node.lock().unwrap().peer_hello().tip, block_id);

        listener.stop().unwrap();
        drop(node);
        clean_test_dir(&node_path);
    }

    #[cfg(feature = "production-v3-testnet")]
    fn production_v3_test_peer_identity() -> ProductionV3MiningPeerIdentity {
        ProductionV3MiningPeerIdentity::for_test(
            crate::PRODUCTION_V3_TESTNET_PROFILE.network_id,
            [0x93; 32],
            crate::PRODUCTION_V3_TESTNET_PROFILE.virtual_genesis_hash,
        )
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn production_v3_template_request_sends_the_factory_issued_testnet_hello() {
        let identity = production_v3_test_peer_identity();
        let expected = identity.peer_hello();
        assert_eq!(
            expected.network_id,
            crate::PRODUCTION_V3_TESTNET_PROFILE.network_id
        );
        assert_eq!(
            expected.tip,
            crate::PRODUCTION_V3_TESTNET_PROFILE.virtual_genesis_hash
        );
        assert_eq!(expected.height, 0);
        assert_eq!(expected.cumulative_work, crate::peer::ChainWork::ZERO);

        let payout = insecure_dev_destination(0x79);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut server_hello = expected;
            server_hello.node_nonce = TARGET_NONCE;
            let session = PeerSession::new(server_hello, test_limits()).unwrap();
            let mut connection = PeerConnection::from_stream(stream, session).unwrap();
            connection.send_hello().unwrap();
            let PeerMessage::Hello(received) = connection.receive().unwrap() else {
                panic!("expected ProductionV3 thin-miner hello")
            };
            assert_eq!(
                connection.receive().unwrap(),
                PeerMessage::GetMiningTemplate { payout }
            );
            received
        });

        let error = request_production_v3_mining_template_once_with_policy(
            address,
            payout,
            identity,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
        )
        .unwrap_err();
        assert!(error.is_transport_disconnect());
        assert_eq!(server.join().unwrap(), expected);
    }

    #[cfg(feature = "production-v3-testnet")]
    #[test]
    fn production_v3_block_submission_sends_the_factory_issued_testnet_hello() {
        let identity = production_v3_test_peer_identity();
        let expected = identity.peer_hello();
        let payout = insecure_dev_destination(0x78);
        let coinbase = Coinbase {
            height: 1,
            outputs: vec![TxOutput {
                value: 1,
                lock: OutputLock::Key(payout),
                spendable_height: 1,
            }],
        };
        let block = Block {
            version: cmfd_consensus::BLOCK_VERSION,
            challenge: BlockChallenge {
                network_id: expected.network_id,
                previous_block: expected.tip,
                transaction_root: merkle_root(&[coinbase.commitment(expected.network_id)]),
                height: 1,
                timestamp: crate::PRODUCTION_V3_TESTNET_PROFILE
                    .virtual_genesis_timestamp
                    .saturating_add(1),
                target: crate::PRODUCTION_V3_TESTNET_PROFILE.pow_limit,
            },
            proof: submission_test_block("production-v3-hello-proof").proof,
            coinbase,
            transactions: Vec::new(),
        };
        let block_id = block.block_id();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut server_hello = expected;
            server_hello.node_nonce = TARGET_NONCE;
            let session = PeerSession::new(server_hello, test_limits()).unwrap();
            let mut connection = PeerConnection::from_stream(stream, session).unwrap();
            connection.send_hello().unwrap();
            let PeerMessage::Hello(received) = connection.receive().unwrap() else {
                panic!("expected ProductionV3 thin-miner hello")
            };
            let PeerMessage::SubmitBlock(submitted) = connection.receive().unwrap() else {
                panic!("expected ProductionV3 block submission")
            };
            assert_eq!(submitted.block_id(), block_id);
            connection
                .send(PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                    block_id,
                    status: BlockSubmissionStatus::Rejected,
                    peer_height: 0,
                    peer_tip: expected.tip,
                }))
                .unwrap();
            received
        });

        let result = submit_production_v3_mined_block_once_with_policy(
            address,
            block,
            identity,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
        )
        .unwrap();
        assert_eq!(result.status, BlockSubmissionStatus::Rejected);
        assert_eq!(server.join().unwrap(), expected);
    }

    #[test]
    fn thin_miner_stale_template_cannot_advance_the_active_tip() {
        let node_path = test_dir("thin-mining-stale-template");
        let node = open_shared(&node_path);
        let payout = insecure_dev_destination(0x7b);
        let (listener, address) = start_listener(Arc::clone(&node), TARGET_NONCE);

        let stale = test_request_mining_template_once_with_policy(
            address,
            payout,
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
        )
        .unwrap()
        .template;
        mine(&node, 1, unix_time_seconds().unwrap());
        let current = node.lock().unwrap().peer_hello();

        let verifier = ConsensusPowVerifier::v2_reference(v2_test_reference().unwrap());
        let proof = verifier
            .mine(&stale.challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let result = test_submit_mined_block_once_with_policy(
            address,
            stale.into_block(proof),
            test_limits(),
            PeerAddressPolicy::PrivateOnly,
        )
        .unwrap();

        assert_eq!(result.status, BlockSubmissionStatus::Accepted);
        assert_ne!(result.block_id, result.peer_tip);
        assert_eq!(result.peer_height, current.height);
        assert_eq!(result.peer_tip, current.tip);
        assert_eq!(node.lock().unwrap().peer_hello(), current);

        listener.stop().unwrap();
        drop(node);
        clean_test_dir(&node_path);
    }

    #[test]
    fn one_sided_static_peer_configuration_relays_mined_blocks_outbound() {
        let miner_path = test_dir("outbound-miner");
        let wallet_path = test_dir("outbound-wallet");
        let miner = open_shared(&miner_path);
        let wallet = open_shared(&wallet_path);
        mine(
            &miner,
            MAX_BLOCKS_PER_SYNC + 1,
            unix_time_seconds().unwrap(),
        );
        let (listener, address) = start_listener(Arc::clone(&wallet), TARGET_NONCE);
        let poller = spawn_static_peer_polling_inner(
            Arc::clone(&miner),
            StaticPeerConfig {
                listen_address: "127.0.0.1:28444".parse().unwrap(),
                peers: vec![address],
                limits: test_limits(),
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_millis(20),
            Some(SOURCE_NONCE),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !tips_match(&miner, &wallet) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(tips_match(&miner, &wallet));
        assert_eq!(
            wallet.lock().unwrap().peer_hello().height,
            (MAX_BLOCKS_PER_SYNC + 1) as u64
        );

        poller.stop().unwrap();
        listener.stop().unwrap();
        drop(miner);
        drop(wallet);
        clean_test_dir(&miner_path);
        clean_test_dir(&wallet_path);
    }

    #[test]
    fn relay_backs_off_only_after_repeated_busy_for_the_same_block() {
        let backoff = RelayBackoff::default();
        let peer: SocketAddr = "127.0.0.1:29444".parse().unwrap();
        let now = Instant::now();
        let busy = |id: u8| Err(P2pError::BusyBlockSubmission([id; 32]));
        backoff.record(peer, &busy(1), now);
        backoff.record(peer, &busy(1), now);
        assert!(
            backoff.allows(peer, now),
            "two deferrals are ordinary contention"
        );
        // A different block restarts the count.
        backoff.record(peer, &busy(2), now);
        backoff.record(peer, &busy(2), now);
        assert!(backoff.allows(peer, now));
        backoff.record(peer, &busy(2), now);
        assert!(!backoff.allows(peer, now));
        assert!(!backoff.allows(peer, now + Duration::from_secs(29)));
        assert!(backoff.allows(peer, now + RELAY_BUSY_BACKOFF_BASE));
        // Further deferrals double the wait, up to the cap.
        backoff.record(peer, &busy(2), now);
        assert!(!backoff.allows(peer, now + Duration::from_secs(59)));
        for _ in 0..20 {
            backoff.record(peer, &busy(2), now);
        }
        assert!(!backoff.allows(peer, now + Duration::from_secs(9 * 60)));
        assert!(backoff.allows(peer, now + RELAY_BUSY_BACKOFF_MAX));
        // Other failures do not change it; any successful relay clears it.
        backoff.record(peer, &Err(P2pError::ThreadPanicked), now);
        assert!(!backoff.allows(peer, now));
        let other: SocketAddr = "127.0.0.2:29444".parse().unwrap();
        assert!(backoff.allows(other, now));
        let hello = PeerHello {
            network_id: [0; 32],
            consensus_fingerprint: [0; 32],
            node_nonce: [1; 32],
            tip: [0; 32],
            height: 0,
            cumulative_work: crate::peer::ChainWork([0; 64]),
        };
        backoff.record(
            peer,
            &Ok(RelayReport {
                remote_hello: hello,
                offered_blocks: 0,
                accepted_blocks: 0,
                already_known: 0,
                offered_transactions: 0,
                peer_height: 0,
                peer_tip: [0; 32],
            }),
            now,
        );
        assert!(backoff.allows(peer, now));
    }

    #[test]
    fn new_local_tip_is_announced_without_waiting_for_the_next_poll() {
        let miner_path = test_dir("announce-miner");
        let wallet_path = test_dir("announce-wallet");
        let miner = open_shared(&miner_path);
        let wallet = open_shared(&wallet_path);
        mine(&miner, 1, unix_time_seconds().unwrap());
        let (listener, address) = start_listener(Arc::clone(&wallet), TARGET_NONCE);
        let poller = spawn_static_peer_polling_inner(
            Arc::clone(&miner),
            StaticPeerConfig {
                listen_address: "127.0.0.1:28444".parse().unwrap(),
                peers: vec![address],
                limits: test_limits(),
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_secs(60),
            Some(SOURCE_NONCE),
        )
        .unwrap();

        // The first ordinary round relays the initial block; the next ordinary
        // round is a full minute away.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !tips_match(&miner, &wallet) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(tips_match(&miner, &wallet));
        thread::sleep(Duration::from_millis(300));

        // A newly found block must reach the peer promptly, not after the poll.
        mine(&miner, 1, unix_time_seconds().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !tips_match(&miner, &wallet) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(tips_match(&miner, &wallet));
        assert_eq!(wallet.lock().unwrap().peer_hello().height, 2);

        poller.stop().unwrap();
        listener.stop().unwrap();
        drop(miner);
        drop(wallet);
        clean_test_dir(&miner_path);
        clean_test_dir(&wallet_path);
    }

    #[test]
    fn one_sided_relay_crosses_an_equal_work_fork_after_local_extension() {
        let miner_path = test_dir("fork-relay-miner");
        let wallet_path = test_dir("fork-relay-wallet");
        let miner = open_shared(&miner_path);
        let wallet = open_shared(&wallet_path);
        let now = unix_time_seconds().unwrap();
        let miner_first = miner
            .lock()
            .unwrap()
            .mine_once(default_miner_destination(), now, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let wallet_first = wallet
            .lock()
            .unwrap()
            .mine_once(
                insecure_dev_destination(0x75),
                now.saturating_add(1),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        assert_ne!(miner_first.block_id(), wallet_first.block_id());

        let (listener, address) = start_listener(Arc::clone(&wallet), TARGET_NONCE);
        let poller = spawn_static_peer_polling_inner(
            Arc::clone(&miner),
            StaticPeerConfig {
                listen_address: "127.0.0.1:28445".parse().unwrap(),
                peers: vec![address],
                limits: test_limits(),
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_millis(20),
            Some(SOURCE_NONCE),
        )
        .unwrap();

        let first_deadline = Instant::now() + Duration::from_secs(5);
        while !wallet
            .lock()
            .unwrap()
            .contains_block(miner_first.block_id())
            && Instant::now() < first_deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            wallet
                .lock()
                .unwrap()
                .contains_block(miner_first.block_id())
        );
        assert!(!tips_match(&miner, &wallet));

        miner
            .lock()
            .unwrap()
            .mine_once(
                default_miner_destination(),
                now.saturating_add(2),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !tips_match(&miner, &wallet) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(tips_match(&miner, &wallet));
        assert_eq!(wallet.lock().unwrap().peer_hello().height, 2);

        poller.stop().unwrap();
        listener.stop().unwrap();
        drop(miner);
        drop(wallet);
        clean_test_dir(&miner_path);
        clean_test_dir(&wallet_path);
    }

    #[test]
    fn successful_pull_continues_after_nonbanning_reverse_relay_failure() {
        fn serve(
            source: &Arc<Mutex<Node>>,
            stream: TcpStream,
            limits: PeerLimits,
            pulls: &AtomicUsize,
            relay_failures: &AtomicUsize,
        ) -> Result<(), PeerError> {
            stream.set_nonblocking(false).unwrap();
            let hello = with_nonce(source.lock().unwrap().peer_hello(), Some(SOURCE_NONCE));
            let mut connection =
                PeerConnection::from_stream(stream, PeerSession::new(hello, limits)?)?;
            connection.send_hello()?;
            assert!(matches!(connection.receive()?, PeerMessage::Hello(_)));
            match connection.receive()? {
                PeerMessage::GetMempool => {
                    // An outbound relay begins here when the source is ahead.
                    // Close without a reply; its pull service still works.
                    relay_failures.fetch_add(1, Ordering::Release);
                    Ok(())
                }
                PeerMessage::GetHeaders { locator, stop } => {
                    pulls.fetch_add(1, Ordering::Release);
                    let block_ids = source.lock().unwrap().inventory_after(&locator, stop, 1);
                    connection.send(PeerMessage::Inventory { block_ids })?;
                    loop {
                        match connection.receive()? {
                            PeerMessage::GetBlock { block_id } => {
                                let canonical = source
                                    .lock()
                                    .unwrap()
                                    .canonical_block(block_id)
                                    .unwrap()
                                    .unwrap();
                                let block = decode_block(&canonical, hello.network_id).unwrap();
                                connection.send(PeerMessage::Block(block))?;
                            }
                            PeerMessage::GetMempool => {
                                connection.send(PeerMessage::TransactionInventory {
                                    txids: Vec::new(),
                                })?;
                                return Ok(());
                            }
                            _ => panic!("unexpected pull request"),
                        }
                    }
                }
                _ => panic!("unexpected first request"),
            }
        }

        let source_path = test_dir("relay-failure-catchup-source");
        let target_path = test_dir("relay-failure-catchup-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        mine(&source, 6, unix_time_seconds().unwrap());
        let limits = PeerLimits {
            max_bytes_per_peer: (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64
                + SYNC_CONTROL_RESERVE_BYTES
                + max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64,
            ..test_limits()
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server_stop = Arc::new(AtomicBool::new(false));
        let pulls = Arc::new(AtomicUsize::new(0));
        let relay_failures = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&server_stop);
        let worker_pulls = Arc::clone(&pulls);
        let worker_failures = Arc::clone(&relay_failures);
        let worker_source = Arc::clone(&source);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let result = serve(
                            &worker_source,
                            stream,
                            limits,
                            &worker_pulls,
                            &worker_failures,
                        );
                        assert!(
                            result.is_ok() || matches!(result, Err(PeerError::ConnectionClosed))
                        );
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            }
        });
        let poller = spawn_static_peer_polling_inner(
            Arc::clone(&target),
            StaticPeerConfig {
                listen_address: "127.0.0.1:28448".parse().unwrap(),
                peers: vec![address],
                limits,
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_secs(30),
            Some(TARGET_NONCE),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let ready = target
                .lock()
                .unwrap()
                .peer_observations()
                .iter()
                .any(|peer| {
                    peer.direction == PeerDirection::Outbound
                        && peer.address == address.to_string()
                        && peer.successful_sessions == 4
                        && peer.active_connections == 0
                });
            if ready || Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        poller.stop().unwrap();
        server_stop.store(true, Ordering::Release);
        worker.join().unwrap();
        assert_eq!(
            pulls.load(Ordering::Acquire),
            4,
            "working downloads must continue despite the failed reverse relay"
        );
        assert_eq!(relay_failures.load(Ordering::Acquire), 1);
        let node = target.lock().unwrap();
        assert_eq!(node.peer_hello().height, 4);
        let peer = node
            .peer_observations()
            .into_iter()
            .find(|peer| {
                peer.direction == PeerDirection::Outbound && peer.address == address.to_string()
            })
            .unwrap();
        assert_eq!(
            peer.failed_sessions, 1,
            "the relay error must remain an error"
        );
        assert_eq!(peer.successful_sessions, 4);
        drop(node);
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn one_block_catchup_continues_before_revisiting_a_stalled_peer() {
        let source_path = test_dir("catchup-burst-source");
        let target_path = test_dir("catchup-burst-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        mine(&source, 6, unix_time_seconds().unwrap());
        let limits = PeerLimits {
            connect_timeout: Duration::from_millis(100),
            idle_timeout: Duration::from_millis(100),
            max_bytes_per_peer: (MAX_TRANSACTIONS_PER_SYNC * MAX_TRANSACTION_BYTES) as u64
                + SYNC_CONTROL_RESERVE_BYTES
                + max_block_bytes_for_network(crate::DEVNET_PROFILE.network_id) as u64,
            ..test_limits()
        };
        assert_eq!(
            block_sync_batch_limit(crate::DEVNET_PROFILE.network_id, limits),
            1
        );
        let source_socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let source_address = source_socket.local_addr().unwrap();
        let source_listener = spawn_inbound_listener_inner(
            Arc::clone(&source),
            source_socket,
            limits,
            Some(SOURCE_NONCE),
        )
        .unwrap();
        let stalled_socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let stalled_address = stalled_socket.local_addr().unwrap();
        stalled_socket.set_nonblocking(true).unwrap();
        let stalled_stop = Arc::new(AtomicBool::new(false));
        let stalled_connections = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&stalled_stop);
        let worker_connections = Arc::clone(&stalled_connections);
        let stalled_worker = thread::spawn(move || {
            let mut sockets = Vec::new();
            while !worker_stop.load(Ordering::Acquire) {
                match stalled_socket.accept() {
                    Ok((stream, _)) => {
                        sockets.push(stream);
                        worker_connections.fetch_add(1, Ordering::Release);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("stalled fixture accept failed: {error}"),
                }
            }
        });
        let poller = spawn_static_peer_polling_inner(
            Arc::clone(&target),
            StaticPeerConfig {
                listen_address: "127.0.0.1:28446".parse().unwrap(),
                peers: vec![stalled_address, source_address],
                limits,
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            // Make the round boundary explicit: only bounded continuations,
            // not another periodic pass, can deliver the remaining blocks.
            Duration::from_secs(30),
            Some(TARGET_NONCE),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while target.lock().unwrap().peer_hello().height < 4 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let height = target.lock().unwrap().peer_hello().height;
        let stalled_attempts = stalled_connections.load(Ordering::Acquire);
        poller.stop().unwrap();
        stalled_stop.store(true, Ordering::Release);
        stalled_worker.join().unwrap();
        source_listener.stop().unwrap();
        assert_eq!(
            height, 4,
            "one-block catch-up unnecessarily waited for another full polling round"
        );
        assert_eq!(
            stalled_attempts, 2,
            "failed pull and relay must not join the continuation queue"
        );
        assert_eq!(
            target.lock().unwrap().peer_hello().tip,
            source.lock().unwrap().active_block_id_at_height(4).unwrap()
        );
        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn static_polling_syncs_and_stops_cleanly() {
        let source_path = test_dir("poll-source");
        let target_path = test_dir("poll-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        mine(&source, 2, unix_time_seconds().unwrap());
        let (listener, address) = start_listener(Arc::clone(&source), SOURCE_NONCE);
        let poller = spawn_static_peer_polling_inner(
            Arc::clone(&target),
            StaticPeerConfig {
                listen_address: "127.0.0.1:28443".parse().unwrap(),
                peers: vec![address],
                limits: test_limits(),
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_millis(20),
            Some(TARGET_NONCE),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !tips_match(&source, &target) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(tips_match(&source, &target));
        poller.stop().unwrap();
        listener.stop().unwrap();

        drop(source);
        drop(target);
        clean_test_dir(&source_path);
        clean_test_dir(&target_path);
    }

    #[test]
    fn responder_does_not_accept_a_peer_timestamp_field() {
        // The protocol has no acceptance-time field. This locks the frame shape
        // to a local timestamp by proving a normal GetBlock frame contains only
        // its identifier and header.
        let encoded = encode_peer_frame(&PeerFrame {
            sequence: 1,
            message: PeerMessage::GetBlock { block_id: [9; 32] },
        })
        .unwrap();
        assert_eq!(encoded.len(), PEER_FRAME_HEADER_BYTES + 32);
        assert_ne!(process_node_nonce(), [0; 32]);
    }

    #[test]
    fn listener_rejects_more_than_the_configured_concurrency() {
        let node_path = test_dir("connection-bound");
        let node = open_shared(&node_path);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut limits = test_limits();
        limits.max_peers = 1;
        let service =
            spawn_inbound_listener_inner(Arc::clone(&node), listener, limits, Some(SOURCE_NONCE))
                .unwrap();

        let first = TcpStream::connect(address).unwrap();
        thread::sleep(Duration::from_millis(30));
        let mut second = TcpStream::connect(address).unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        assert!(matches!(second.read(&mut byte), Ok(0) | Err(_)));

        drop(first);
        drop(second);
        service.stop().unwrap();
        drop(node);
        clean_test_dir(&node_path);
    }

    #[test]
    fn listener_temporarily_bans_repeated_malformed_handshakes() {
        let node_path = test_dir("malformed-handshake-ban");
        let node = open_shared(&node_path);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let service = spawn_inbound_listener_inner(
            Arc::clone(&node),
            listener,
            test_limits(),
            Some(SOURCE_NONCE),
        )
        .unwrap();

        for _ in 0..2 {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut hello_header = [0_u8; PEER_FRAME_HEADER_BYTES];
            stream.read_exact(&mut hello_header).unwrap();
            let hello_bytes = u32::from_le_bytes(hello_header[16..20].try_into().unwrap()) as usize;
            let mut hello_payload = vec![0_u8; hello_bytes];
            stream.read_exact(&mut hello_payload).unwrap();

            let mut invalid_header = [0_u8; PEER_FRAME_HEADER_BYTES];
            invalid_header[..4].copy_from_slice(b"BAD!");
            stream.write_all(&invalid_header).unwrap();
            drop(stream);

            let deadline = Instant::now() + Duration::from_secs(2);
            while !service.active_sockets.sockets.lock().unwrap().is_empty()
                && Instant::now() < deadline
            {
                thread::sleep(Duration::from_millis(10));
            }
        }

        assert!(
            service
                .peer_is_temporarily_banned("127.0.0.1".parse().unwrap())
                .unwrap()
        );
        let mut rejected = TcpStream::connect(address).unwrap();
        rejected
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        assert!(matches!(rejected.read(&mut byte), Ok(0) | Err(_)));

        drop(rejected);
        service.stop().unwrap();
        drop(node);
        clean_test_dir(&node_path);
    }

    #[test]
    fn listener_stop_interrupts_a_stalled_peer_session() {
        let node_path = test_dir("stalled-inbound-stop");
        let node = open_shared(&node_path);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut limits = test_limits();
        limits.idle_timeout = Duration::from_secs(30);
        limits.total_timeout = Duration::from_secs(60);
        let service =
            spawn_inbound_listener_inner(Arc::clone(&node), listener, limits, Some(SOURCE_NONCE))
                .unwrap();

        let stream = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while service.active_sockets.sockets.lock().unwrap().is_empty() && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(service.active_sockets.sockets.lock().unwrap().len(), 1);

        let started = Instant::now();
        service.stop().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "listener stop waited for the normal peer idle deadline"
        );
        drop(stream);
        TcpListener::bind(address).unwrap();
        drop(node);
        clean_test_dir(&node_path);
    }

    #[test]
    fn static_poller_stop_interrupts_a_stalled_outbound_session() {
        let node_path = test_dir("stalled-outbound-stop");
        let node = open_shared(&node_path);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_sender, accepted_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let stalled_peer = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            accepted_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            drop(stream);
        });
        let mut limits = test_limits();
        limits.idle_timeout = Duration::from_secs(30);
        limits.total_timeout = Duration::from_secs(60);
        let poller = spawn_static_peer_polling_inner(
            Arc::clone(&node),
            StaticPeerConfig {
                listen_address: "127.0.0.1:28446".parse().unwrap(),
                peers: vec![address],
                limits,
                address_policy: PeerAddressPolicy::PrivateOnly,
            },
            Duration::from_secs(30),
            Some(TARGET_NONCE),
        )
        .unwrap();

        accepted_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while poller.active_sockets.sockets.lock().unwrap().is_empty() && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(poller.active_sockets.sockets.lock().unwrap().len(), 1);

        let started = Instant::now();
        poller.stop().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "static-poller stop waited for the normal peer idle deadline"
        );
        release_sender.send(()).unwrap();
        stalled_peer.join().unwrap();
        drop(node);
        clean_test_dir(&node_path);
    }
}
