//! Minimal bounded peer runtime for Devnet-0.
//!
//! The transport handshake binds network and consensus parameters, but it does
//! not authenticate peer identity or encrypt traffic. This module therefore
//! defaults to loopback/private addresses; public peers require an explicit
//! unsafe Devnet opt-in enforced by `peer`.

use std::collections::HashSet;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cmfd_consensus::{Block, Transaction, WireError, decode_block};
use thiserror::Error;

use crate::peer::{
    BlockSubmissionResult, BlockSubmissionStatus, PeerAddressPolicy, PeerConnection, PeerError,
    PeerHello, PeerLimits, PeerMessage, PeerSession, StaticPeerConfig,
};
use crate::{Node, NodeError, PeerDirection, devnet_params, unix_time_seconds};

/// One request is deliberately small enough that sixteen maximum-size blocks,
/// sixty-four maximum-size transactions, their outer peer frames, and
/// request/handshake traffic remain below the default 32 MiB per-connection
/// budget. Static polling advances longer chains in multiple independently
/// bounded calls.
pub const MAX_BLOCKS_PER_SYNC: usize = 16;
/// A single poll downloads only a small prefix of an advertised mempool.
/// Accepted candidates become locally known, allowing later polls to proceed
/// farther through an honest peer's inventory.
pub const MAX_TRANSACTIONS_PER_SYNC: usize = 64;
const LISTENER_POLL_INTERVAL: Duration = Duration::from_millis(10);

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
    #[error("peer runtime stop mutex is poisoned")]
    PoisonedStop,
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
    #[error("peer listener I/O failed: {0}")]
    ListenerIo(#[source] io::Error),
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
    let hello = thin_miner_hello()?;
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
    let submitted = block.block_id();
    let session = PeerSession::new(thin_miner_hello()?, limits)?;
    let mut connection = PeerConnection::connect_with_policy(address, session, address_policy)?;
    connection.send_hello()?;
    expect_hello(connection.receive()?)?;
    connection.send(PeerMessage::SubmitBlock(block))?;
    let result = expect_block_submission_result(connection.receive()?)?;
    if result.block_id != submitted {
        return Err(P2pError::WrongBlockSubmission {
            submitted,
            actual: result.block_id,
        });
    }
    Ok(result)
}

fn thin_miner_hello() -> Result<PeerHello, P2pError> {
    let params = devnet_params()?;
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
    sync_from_peer_once_inner_with_policy(shared, address, limits, address_policy, None)
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
    )
}

#[tracing::instrument(skip_all, fields(peer = %address, direction = "outbound"))]
fn sync_from_peer_once_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
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
) -> Result<SyncReport, P2pError> {
    let (hello, locator) = {
        let node = lock_node(&shared)?;
        (node.peer_hello(), node.block_locator(MAX_BLOCKS_PER_SYNC))
    };
    let hello = with_nonce(hello, nonce_override);

    let session = PeerSession::new(hello, limits)?;
    let mut connection = PeerConnection::connect_with_policy(address, session, address_policy)?;
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;

    connection.send(PeerMessage::GetHeaders {
        locator,
        stop: remote_hello.tip,
    })?;
    let inventory = expect_inventory(connection.receive()?)?;
    if inventory.len() > MAX_BLOCKS_PER_SYNC {
        return Err(PeerError::CountLimit {
            field: "sync inventory",
            actual: inventory.len(),
            max: MAX_BLOCKS_PER_SYNC,
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

        // `Node::submit_block` currently performs proof verification and the
        // durable append under `&mut self`, so this is the one deliberately
        // unavoidable long node critical section. Socket I/O is never done
        // while holding the mutex.
        let accepted_at = unix_time_seconds()?;
        {
            let mut node = lock_node(&shared)?;
            node.submit_block(block, accepted_at)?;
        }
        accepted_blocks += 1;
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

/// Offers up to `MAX_BLOCKS_PER_SYNC` locally active blocks that follow the
/// peer's advertised tip. Each block is acknowledged only after the peer has
/// passed it through its normal durable consensus path. A later poll continues
/// from the peer's new tip, so temporary disconnects recover in bounded steps.
pub fn relay_blocks_to_peer_once_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
) -> Result<RelayReport, P2pError> {
    relay_blocks_to_peer_once_inner_with_policy(shared, address, limits, address_policy, None)
}

#[tracing::instrument(skip_all, fields(peer = %address, direction = "outbound"))]
fn relay_blocks_to_peer_once_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    address: SocketAddr,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
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
) -> Result<RelayReport, P2pError> {
    let hello = with_nonce(
        {
            let node = lock_node(&shared)?;
            node.peer_hello()
        },
        nonce_override,
    );
    let network_id = hello.network_id;
    let session = PeerSession::new(hello, limits)?;
    let mut connection = PeerConnection::connect_with_policy(address, session, address_policy)?;
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;

    let block_ids = {
        let node = lock_node(&shared)?;
        node.relay_inventory_after(remote_hello.tip, MAX_BLOCKS_PER_SYNC)
    };
    let mut accepted_blocks = 0;
    let mut already_known = 0;
    let mut peer_height = remote_hello.height;
    let mut peer_tip = remote_hello.tip;

    for block_id in &block_ids {
        let canonical = {
            let node = lock_node(&shared)?;
            node.canonical_block(*block_id).map(|bytes| bytes.to_vec())
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
        let result = expect_block_submission_result(connection.receive()?)?;
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
    )
}

fn respond_to_peer_inner_with_policy(
    shared: Arc<Mutex<Node>>,
    stream: TcpStream,
    limits: PeerLimits,
    address_policy: PeerAddressPolicy,
    nonce_override: Option<[u8; 32]>,
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
) -> Result<(), P2pError> {
    let hello = with_nonce(
        {
            let node = lock_node(&shared)?;
            node.peer_hello()
        },
        nonce_override,
    );
    let network_id = hello.network_id;
    let session = PeerSession::new(hello, limits)?;
    let mut connection = PeerConnection::from_stream_with_policy(stream, session, address_policy)?;
    connection.send_hello()?;
    let remote_hello = expect_hello(connection.receive()?)?;
    record_peer_succeeded(
        &shared,
        PeerDirection::Inbound,
        observation_address,
        remote_hello,
    );

    loop {
        let message = match connection.receive() {
            Ok(message) => message,
            Err(PeerError::Truncated {
                needed,
                remaining: 0,
            }) if needed == crate::peer::PEER_FRAME_HEADER_BYTES => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        match message {
            PeerMessage::GetHeaders { locator, stop } => {
                let block_ids = {
                    let node = lock_node(&shared)?;
                    node.inventory_after(&locator, stop, MAX_BLOCKS_PER_SYNC)
                };
                connection.send(PeerMessage::Inventory { block_ids })?;
            }
            PeerMessage::GetBlock { block_id } => {
                let canonical = {
                    let node = lock_node(&shared)?;
                    node.canonical_block(block_id).map(|bytes| bytes.to_vec())
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
                let block_id = block.block_id();
                let accepted_at = unix_time_seconds()?;
                let status = {
                    let mut node = lock_node(&shared)?;
                    if node.contains_block(block_id) {
                        BlockSubmissionStatus::AlreadyKnown
                    } else if node.submit_block(block, accepted_at).is_ok() {
                        BlockSubmissionStatus::Accepted
                    } else {
                        BlockSubmissionStatus::Rejected
                    }
                };
                let peer = {
                    let node = lock_node(&shared)?;
                    node.peer_hello()
                };
                connection.send(PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                    block_id,
                    status,
                    peer_height: peer.height,
                    peer_tip: peer.tip,
                }))?;
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
    local_address: SocketAddr,
    thread: Option<JoinHandle<Result<(), P2pError>>>,
}

impl InboundPeerHandle {
    pub fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    pub fn stop(mut self) -> Result<(), P2pError> {
        self.stop.store(true, Ordering::Release);
        join_service_thread(self.thread.take())
    }
}

impl Drop for InboundPeerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
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
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("cmfd-peer-listener".to_owned())
        .spawn(move || {
            listener_loop(
                shared,
                listener,
                limits,
                address_policy,
                thread_stop,
                nonce_override,
            )
        })
        .map_err(P2pError::ListenerIo)?;
    Ok(InboundPeerHandle {
        stop,
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
                let worker_node = Arc::clone(&shared);
                let worker_active = Arc::clone(&active);
                workers.push(thread::spawn(move || {
                    let _guard = ActiveConnectionGuard(worker_active);
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

struct ActiveConnectionGuard(Arc<AtomicUsize>);

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
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
    thread: Option<JoinHandle<()>>,
}

impl StaticPeerPollHandle {
    pub fn stop(mut self) -> Result<(), P2pError> {
        signal_poll_stop(&self.stop)?;
        let thread = self.thread.take().ok_or(P2pError::ThreadPanicked)?;
        thread.join().map_err(|_| P2pError::ThreadPanicked)
    }
}

impl Drop for StaticPeerPollHandle {
    fn drop(&mut self) {
        if let Ok(mut stopped) = self.stop.0.lock() {
            *stopped = true;
            self.stop.1.notify_all();
        }
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
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("cmfd-static-peer-poll".to_owned())
        .spawn(move || {
            static_peer_poll_loop(shared, config, poll_interval, thread_stop, nonce_override)
        })
        .map_err(P2pError::ListenerIo)?;
    Ok(StaticPeerPollHandle {
        stop,
        thread: Some(thread),
    })
}

fn static_peer_poll_loop(
    shared: Arc<Mutex<Node>>,
    config: StaticPeerConfig,
    poll_interval: Duration,
    stop: Arc<(Mutex<bool>, Condvar)>,
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
            );
            let _ = relay_blocks_to_peer_once_inner_with_policy(
                Arc::clone(&shared),
                *peer,
                config.limits,
                config.address_policy,
                nonce_override,
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
    use std::time::{Duration, Instant};

    use cmfd_consensus::{
        ConsensusPowVerifier, InputWitness, OutPoint, OutputLock, TRANSACTION_VERSION, TxInput,
        TxOutput, v2_test_reference,
    };
    use k256::schnorr::SigningKey;

    use crate::peer::{PEER_FRAME_HEADER_BYTES, PeerFrame, encode_peer_frame, process_node_nonce};
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
        Arc::new(Mutex::new(Node::open(path).expect("open isolated node")))
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

    #[test]
    fn initial_sync_and_equal_tip_noop() {
        let source_path = test_dir("initial-source");
        let target_path = test_dir("initial-target");
        let source = open_shared(&source_path);
        let target = open_shared(&target_path);
        let now = unix_time_seconds().unwrap();
        mine(&source, 3, now);
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
    fn thin_miner_fetches_a_template_and_submits_without_a_local_chain() {
        let node_path = test_dir("thin-mining-node");
        let node = open_shared(&node_path);
        let payout = insecure_dev_destination(0x7a);
        let (listener, address) = start_listener(Arc::clone(&node), TARGET_NONCE);

        let response = request_mining_template_once_with_policy(
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
        let result = submit_mined_block_once_with_policy(
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

    #[test]
    fn thin_miner_stale_template_cannot_advance_the_active_tip() {
        let node_path = test_dir("thin-mining-stale-template");
        let node = open_shared(&node_path);
        let payout = insecure_dev_destination(0x7b);
        let (listener, address) = start_listener(Arc::clone(&node), TARGET_NONCE);

        let stale = request_mining_template_once_with_policy(
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
        let result = submit_mined_block_once_with_policy(
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
}
