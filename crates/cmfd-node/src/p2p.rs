//! Minimal bounded peer runtime for Devnet-0.
//!
//! The transport handshake binds network and consensus parameters, but it does
//! not authenticate peer identity or encrypt traffic. This module therefore
//! defaults to loopback/private addresses; public peers require an explicit
//! unsafe Devnet opt-in enforced by `peer`.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cmfd_consensus::{
    Block, MAX_TRANSACTION_BYTES, Transaction, WireError, decode_block, max_block_bytes_for_network,
};
use thiserror::Error;

#[cfg(feature = "production-v3")]
use crate::ProductionV3MiningPeerIdentity;
use crate::peer::{
    BlockSubmissionResult, BlockSubmissionStatus, PeerAddressPolicy, PeerConnection, PeerError,
    PeerHello, PeerLimits, PeerMessage, PeerSession, SUBMIT_BLOCK_RESPONSE_BUDGET,
    StaticPeerConfig,
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
    #[error("peer deferred submitted block {0:?} because admission is busy")]
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
    pub peer_height: u64,
    pub peer_tip: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningTemplateResponse {
    pub remote_hello: PeerHello,
    pub template: crate::peer::MiningTemplate,
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

fn perform_sync_from_peer_once_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    active_sockets: Option<&Arc<ActiveSocketRegistry>>,
) -> Result<SyncReport, P2pError> {
    let (hello, locator) = {
        let node = lock_node(&shared)?;
        let hello = node.peer_hello();
        (hello, node.block_locator(MAX_BLOCKS_PER_SYNC))
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
    let inventory = expect_inventory(connection.receive()?)?;
    if inventory.len() > block_batch_limit {
        return Err(PeerError::CountLimit {
            field: "sync inventory",
            actual: inventory.len(),
            max: block_batch_limit,
        }
        .into());
    }

    let mut requested_blocks = 0;
    let mut accepted_blocks = 0;
    let mut already_known = 0;
    let mut previous_inventory_id = None;

    for requested in &inventory {
        let known = {
            let node = lock_node(&shared)?;
            node.contains_block(*requested)
        };
        if known {
            already_known += 1;
            previous_inventory_id = Some(*requested);
            continue;
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
        let monitor = PeerSubmissionMonitor::start(&connection, request.clone())?;
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
        if accepted {
            accepted_blocks += 1;
        } else {
            already_known += 1;
        }
        previous_inventory_id = Some(*requested);
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
        inventory_items: inventory.len(),
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

    let block_ids = {
        let node = lock_node(&shared)?;
        node.relay_inventory_after(remote_hello.tip, block_batch_limit)
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
                return Err(P2pError::RejectedBlockSubmission(*block_id));
            }
            BlockSubmissionStatus::Busy => {
                return Err(P2pError::BusyBlockSubmission(*block_id));
            }
        }
    }

    Ok(RelayReport {
        remote_hello,
        offered_blocks: block_ids.len(),
        accepted_blocks,
        already_known,
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
    )
}

fn respond_to_peer_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    stream: TcpStream,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    cancellation: Option<Arc<AtomicBool>>,
) -> Result<(), P2pError> {
    let remote_address = stream.peer_addr().map_err(P2pError::ListenerIo)?;
    let span =
        tracing::info_span!("respond_to_peer", peer = %remote_address, direction = "inbound");
    let _entered = span.enter();
    let observation_address = observed_address(PeerDirection::Inbound, remote_address);
    record_peer_started(&shared, PeerDirection::Inbound, observation_address.clone());
    let result = perform_respond_to_peer_inner_with_policy(
        Arc::clone(&shared),
        stream,
        limits,
        address_policy,
        nonce_override,
        observation_address.clone(),
        cancellation,
    );
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
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
    observation_address: String,
    cancellation: Option<Arc<AtomicBool>>,
) -> Result<(), P2pError> {
    let hello = {
        let node = lock_node(&shared)?;
        with_nonce(node.peer_hello(), nonce_override)
    };
    let network_id = hello.network_id;
    let block_batch_limit = block_sync_batch_limit(network_id, limits);
    let session = PeerSession::new(hello, limits)?;
    let mut connection = PeerConnection::from_stream_with_policy(stream, session, address_policy)?;
    if let Some(cancellation) = cancellation {
        connection.set_cancellation(cancellation);
    }
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;
    let proof_peer = next_remote_proof_peer_id()?;
    record_peer_succeeded(
        &shared,
        PeerDirection::Inbound,
        observation_address,
        remote_hello,
    );

    loop {
        let message = match connection.receive() {
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
                        BlockSubmissionStatus::Busy
                    }
                    Err(error) if error.client_error().status < 500 => {
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
            }
            other => {
                return Err(P2pError::UnexpectedMessage {
                    expected: "GetHeaders, GetBlock, GetMempool, GetTransaction, GetMiningTemplate, or SubmitBlock",
                    actual: message_name(&other),
                });
            }
        }
    }
}

fn is_retryable_block_admission(error: &NodeError) -> bool {
    error.client_error().retryable
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
    spawn_inbound_listener_inner_with_policy(shared, listener, limits, address_policy, None)
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
    )
}

fn spawn_inbound_listener_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
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
    let thread_stop = Arc::clone(&stop);
    let thread_active_sockets = Arc::clone(&active_sockets);
    let thread = thread::Builder::new()
        .name("cmfd-peer-listener".to_owned())
        .spawn(move || {
            listener_loop(
                shared,
                listener,
                limits,
                address_policy,
                thread_stop,
                thread_active_sockets,
                nonce_override,
            )
        })
        .map_err(P2pError::ListenerIo)?;
    Ok(InboundPeerHandle {
        stop,
        active_sockets,
        local_address,
        thread: Some(thread),
    })
}

fn listener_loop(
    shared: Arc<Mutex<Node>>,
    listener: TcpListener,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    stop: Arc<AtomicBool>,
    active_sockets: Arc<ActiveSocketRegistry>,
    nonce_override: Option<[u8; 32]>,
) -> Result<(), P2pError> {
    let active = Arc::new(AtomicUsize::new(0));
    let mut workers: Vec<JoinHandle<()>> = Vec::new();

    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Accepted sockets can inherit the listener's nonblocking mode
                // on some platforms. PeerConnection supplies its own bounded
                // blocking read/write deadlines.
                if stream.set_nonblocking(false).is_err() {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                reap_workers(&mut workers);
                if !reserve_connection(&active, limits.max_peers) {
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
                workers.push(thread::spawn(move || {
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
                    let _ = respond_to_peer_inner_with_policy(
                        worker_node,
                        stream,
                        limits,
                        address_policy,
                        nonce_override,
                        Some(worker_stop),
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
        signal_result?;
        socket_result?;
        join_result
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

fn spawn_static_peer_polling_inner(
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    poll_interval: Duration,
    nonce_override: Option<[u8; 32]>,
) -> Result<StaticPeerPollHandle, P2pError> {
    config.validate()?;
    if poll_interval.is_zero() {
        return Err(P2pError::ZeroPollInterval);
    }
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let active_sockets = Arc::new(ActiveSocketRegistry::default());
    let thread_stop = Arc::clone(&stop);
    let thread_active_sockets = Arc::clone(&active_sockets);
    let thread = thread::Builder::new()
        .name("cmfd-static-peer-poll".to_owned())
        .spawn(move || {
            static_peer_poll_loop(
                shared,
                config,
                poll_interval,
                thread_stop,
                thread_active_sockets,
                nonce_override,
            )
        })
        .map_err(P2pError::ListenerIo)?;
    Ok(StaticPeerPollHandle {
        stop,
        active_sockets,
        thread: Some(thread),
    })
}

fn static_peer_poll_loop(
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    poll_interval: Duration,
    stop: Arc<(Mutex<bool>, Condvar)>,
    active_sockets: Arc<ActiveSocketRegistry>,
    nonce_override: Option<[u8; 32]>,
) {
    loop {
        if poll_stopped(&stop) {
            return;
        }
        for peer in &config.peers {
            if poll_stopped(&stop) {
                return;
            }
            // Errors are already logged via tracing inside these calls;
            // a failure with one peer must not stop later peers or rounds.
            let _ = sync_from_peer_once_inner_with_policy(
                Arc::clone(&shared),
                *peer,
                config.limits,
                config.address_policy,
                nonce_override,
                Some(&active_sockets),
            );
            if poll_stopped(&stop) {
                return;
            }
            let _ = relay_blocks_to_peer_once_inner_with_policy(
                Arc::clone(&shared),
                *peer,
                config.limits,
                config.address_policy,
                nonce_override,
                Some(&active_sockets),
            );
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
        }
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
