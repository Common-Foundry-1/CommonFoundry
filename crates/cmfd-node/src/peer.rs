//! Bounded peer wire protocol and deterministic linear-sync planning for Devnet-0.
//!
//! This module deliberately does not apply received blocks, admit transactions,
//! or choose forks. Callers must pass surfaced candidates through node policy and
//! consensus validation.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
#[cfg(test)]
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use cmfd_consensus::{
    Block, BlockChallenge, BlockProof, Coinbase, MAX_BLOCK_BYTES, MAX_BLOCK_TRANSACTIONS,
    MAX_COINBASE_OUTPUTS, MAX_TRANSACTION_BYTES, OutputLock, Transaction, TxOutput, WireError,
    decode_block, decode_transaction, encode_block, encode_transaction, merkle_root,
};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use thiserror::Error;

pub const PEER_MAGIC: [u8; 4] = *b"CMFP";
pub const PEER_PROTOCOL_VERSION: u16 = 4;
pub const PEER_FRAME_HEADER_BYTES: usize = 20;
pub const MAX_PEER_PAYLOAD_BYTES: usize = MAX_BLOCK_BYTES;
pub const MAX_HEADER_LOCATORS: usize = 32;
pub const MAX_INVENTORY_ITEMS: usize = 1_024;
pub const MAX_CONFIGURED_PEERS: usize = 64;
pub const MAX_MESSAGES_PER_PEER: u64 = 4_096;
pub const MAX_BYTES_PER_PEER: u64 = 64 * 1024 * 1024;
pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Authoritative client budget for one `SubmitBlock` response. Proof
/// admission and verification may legitimately remain silent for longer than
/// the ordinary peer idle timeout, so mining and relay clients use this
/// dedicated contract instead of `PeerLimits::idle_timeout`.
pub const SUBMIT_BLOCK_RESPONSE_BUDGET: Duration = Duration::from_secs(120);

const HELLO_PAYLOAD_BYTES: usize = 200;
const MIN_SESSION_HANDSHAKE_BYTES: u64 = 2 * (PEER_FRAME_HEADER_BYTES + HELLO_PAYLOAD_BYTES) as u64;
const PEER_CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct WriteDeadlineBarrier {
    pub(crate) entered: Barrier,
    pub(crate) release: Barrier,
}

#[cfg(test)]
impl WriteDeadlineBarrier {
    pub(crate) fn new() -> Self {
        Self {
            entered: Barrier::new(2),
            release: Barrier::new(2),
        }
    }
}

pub const HELLO_KIND: u8 = 1;
pub const GET_HEADERS_KIND: u8 = 2;
pub const INVENTORY_KIND: u8 = 3;
pub const GET_BLOCK_KIND: u8 = 4;
pub const BLOCK_KIND: u8 = 5;
pub const GET_MEMPOOL_KIND: u8 = 6;
pub const TRANSACTION_INVENTORY_KIND: u8 = 7;
pub const GET_TRANSACTION_KIND: u8 = 8;
pub const TRANSACTION_KIND: u8 = 9;
pub const SUBMIT_BLOCK_KIND: u8 = 10;
pub const BLOCK_SUBMISSION_RESULT_KIND: u8 = 11;
pub const GET_MINING_TEMPLATE_KIND: u8 = 12;
pub const MINING_TEMPLATE_KIND: u8 = 13;

const BLOCK_CHALLENGE_BYTES: usize = 32 + 32 + 32 + 8 + 8 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainWork(pub [u8; 64]);

impl ChainWork {
    pub const ZERO: Self = Self([0; 64]);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerHello {
    pub network_id: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
    pub node_nonce: [u8; 32],
    pub tip: [u8; 32],
    pub height: u64,
    /// Canonical unsigned U512 chain work, encoded most-significant byte first.
    pub cumulative_work: ChainWork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockSubmissionStatus {
    Accepted = 0,
    AlreadyKnown = 1,
    Rejected = 2,
    /// The exact candidate was not judged invalid. The sender may retry it
    /// while this peer still reports the candidate's parent as its active tip.
    Busy = 3,
}

impl BlockSubmissionStatus {
    fn from_byte(value: u8) -> Result<Self, PeerError> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::AlreadyKnown),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Busy),
            other => Err(PeerError::InvalidBlockSubmissionStatus(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSubmissionResult {
    pub block_id: [u8; 32],
    pub status: BlockSubmissionStatus,
    pub peer_height: u64,
    pub peer_tip: [u8; 32],
}

/// A complete node-selected block template without a proof. A thin miner only
/// evaluates the immutable challenge, inserts its proof, and returns the
/// resulting canonical block to the node for normal consensus validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningTemplate {
    pub challenge: BlockChallenge,
    pub coinbase: Coinbase,
    pub transactions: Vec<Transaction>,
}

impl MiningTemplate {
    pub fn into_block(self, proof: BlockProof) -> Block {
        Block {
            version: cmfd_consensus::BLOCK_VERSION,
            challenge: self.challenge,
            proof,
            coinbase: self.coinbase,
            transactions: self.transactions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMessage {
    Hello(PeerHello),
    GetHeaders {
        locator: Vec<[u8; 32]>,
        stop: [u8; 32],
    },
    Inventory {
        block_ids: Vec<[u8; 32]>,
    },
    GetBlock {
        block_id: [u8; 32],
    },
    /// A decoded canonical candidate. Receiving it never mutates chain state.
    Block(Block),
    /// A canonical block offered for validation through the receiving node's
    /// normal durable consensus path.
    SubmitBlock(Block),
    BlockSubmissionResult(BlockSubmissionResult),
    GetMempool,
    TransactionInventory {
        txids: Vec<[u8; 32]>,
    },
    GetTransaction {
        txid: [u8; 32],
    },
    /// A decoded canonical candidate. Receiving it never mutates the mempool.
    Transaction(Transaction),
    GetMiningTemplate {
        payout: [u8; 32],
    },
    MiningTemplate(MiningTemplate),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerFrame {
    pub sequence: u64,
    pub message: PeerMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLimits {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub max_peers: usize,
    pub max_messages_per_peer: u64,
    pub max_bytes_per_peer: u64,
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(5 * 60),
            max_peers: 16,
            max_messages_per_peer: 512,
            max_bytes_per_peer: 32 * 1024 * 1024,
        }
    }
}

impl PeerLimits {
    pub fn validate(self) -> Result<(), PeerError> {
        if self.connect_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.total_timeout.is_zero()
            || self.max_peers == 0
            || self.max_peers > MAX_CONFIGURED_PEERS
            || self.max_messages_per_peer < 2
            || self.max_messages_per_peer > MAX_MESSAGES_PER_PEER
            || self.max_bytes_per_peer < MIN_SESSION_HANDSHAKE_BYTES
            || self.max_bytes_per_peer > MAX_BYTES_PER_PEER
            || self.connect_timeout > MAX_CONNECT_TIMEOUT
            || self.idle_timeout > MAX_IDLE_TIMEOUT
            || self.total_timeout > MAX_TOTAL_TIMEOUT
        {
            return Err(PeerError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddressPolicy {
    PrivateOnly,
    AllowPublic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPeerConfig {
    pub listen_address: SocketAddr,
    pub peers: Vec<SocketAddr>,
    pub limits: PeerLimits,
    pub address_policy: PeerAddressPolicy,
}

impl StaticPeerConfig {
    pub fn validate(&self) -> Result<(), PeerError> {
        self.limits.validate()?;
        validate_peer_address(self.listen_address, self.address_policy)?;
        self.validate_peer_list(true)
    }

    pub fn validate_client_peers(&self) -> Result<(), PeerError> {
        self.limits.validate()?;
        self.validate_peer_list(false)
    }

    fn validate_peer_list(&self, reject_listener: bool) -> Result<(), PeerError> {
        if self.peers.len() > self.limits.max_peers {
            return Err(PeerError::TooManyPeers {
                actual: self.peers.len(),
                max: self.limits.max_peers,
            });
        }
        let mut unique = HashSet::with_capacity(self.peers.len());
        for peer in &self.peers {
            validate_peer_address(*peer, self.address_policy)?;
            if reject_listener && *peer == self.listen_address {
                return Err(PeerError::ConfiguredSelfAddress(*peer));
            }
            if !unique.insert(*peer) {
                return Err(PeerError::DuplicatePeer(*peer));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("peer frame is truncated: need {needed} bytes, have {remaining}")]
    Truncated { needed: usize, remaining: usize },
    #[error("peer frame magic is invalid")]
    InvalidMagic,
    #[error("unsupported peer protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("peer frame flags must be zero")]
    NonZeroFlags,
    #[error("unknown peer message kind {0}")]
    UnknownKind(u8),
    #[error("invalid block-submission status {0}")]
    InvalidBlockSubmissionStatus(u8),
    #[error("peer payload is {actual} bytes, exceeding the {max}-byte limit")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("peer frame contains {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("{field} count {actual} exceeds the limit of {max}")]
    CountLimit {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("header locator must not be empty")]
    EmptyLocator,
    #[error("{0} contains a duplicate identifier")]
    DuplicateIdentifier(&'static str),
    #[error("peer hello contains a zero node nonce")]
    ZeroNodeNonce,
    #[error("peer belongs to another network")]
    WrongNetwork,
    #[error("peer consensus fingerprint does not match")]
    WrongConsensusFingerprint,
    #[error("peer node nonce matches this process")]
    SelfConnect,
    #[error("local hello must be the first outbound message")]
    LocalHelloRequired,
    #[error("peer hello must be the first inbound message")]
    RemoteHelloRequired,
    #[error("peer hello was sent or received more than once")]
    DuplicateHello,
    #[error("mutual handshake is required before block protocol messages")]
    HandshakeRequired,
    #[error("peer sequence mismatch: expected {expected}, received {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
    #[error("peer sequence number exhausted")]
    SequenceExhausted,
    #[error("per-peer message or byte budget exhausted")]
    PeerBudgetExceeded,
    #[error("peer limits are zero, unusable for a mutual hello, or exceed hard protocol bounds")]
    InvalidLimits,
    #[error(
        "peer address must use a nonzero port on loopback or a private IP unless public peers were explicitly enabled: {0}"
    )]
    NonPrivateAddress(SocketAddr),
    #[error("peer address is unspecified, multicast, broadcast, or otherwise unsafe: {0}")]
    UnsafeAddress(SocketAddr),
    #[error("configured peer count {actual} exceeds limit {max}")]
    TooManyPeers { actual: usize, max: usize },
    #[error("configured peer duplicates the local listener: {0}")]
    ConfiguredSelfAddress(SocketAddr),
    #[error("configured peer appears more than once: {0}")]
    DuplicatePeer(SocketAddr),
    #[error("peer connection exceeded its total lifetime")]
    TotalTimeout,
    #[error("peer connection exceeded its idle timeout")]
    IdleTimeout,
    #[error("peer block-submission response exceeded its dedicated timeout")]
    SubmitBlockResponseTimeout,
    #[error("peer connection was cancelled")]
    Cancelled,
    #[error("peer closed the connection")]
    ConnectionClosed,
    #[error("peer I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("block frame is not canonical")]
    NonCanonicalBlock,
    #[error("transaction frame is not canonical")]
    NonCanonicalTransaction,
    #[error("mining template is invalid: {0}")]
    InvalidMiningTemplate(&'static str),
    #[error("unknown mining-template output-lock tag {0}")]
    InvalidMiningOutputLockTag(u8),
    #[error(transparent)]
    ConsensusWire(#[from] WireError),
}

pub fn process_node_nonce() -> [u8; 32] {
    static NONCE: OnceLock<[u8; 32]> = OnceLock::new();
    *NONCE.get_or_init(|| {
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        if nonce == [0; 32] {
            nonce[31] = 1;
        }
        nonce
    })
}

fn validate_peer_address(address: SocketAddr, policy: PeerAddressPolicy) -> Result<(), PeerError> {
    let private = match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    };
    let unsafe_address = address.port() == 0
        || match address.ip() {
            IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.octets() == [255; 4],
            IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
        };
    if unsafe_address {
        return Err(PeerError::UnsafeAddress(address));
    }
    if !private && policy == PeerAddressPolicy::PrivateOnly {
        return Err(PeerError::NonPrivateAddress(address));
    }
    Ok(())
}

pub fn encode_peer_frame(frame: &PeerFrame) -> Result<Vec<u8>, PeerError> {
    let (kind, payload) = encode_message(&frame.message)?;
    if payload.len() > MAX_PEER_PAYLOAD_BYTES {
        return Err(PeerError::PayloadTooLarge {
            actual: payload.len(),
            max: MAX_PEER_PAYLOAD_BYTES,
        });
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| PeerError::PayloadTooLarge {
        actual: payload.len(),
        max: MAX_PEER_PAYLOAD_BYTES,
    })?;
    let mut encoded = Vec::with_capacity(PEER_FRAME_HEADER_BYTES + payload.len());
    encoded.extend_from_slice(&PEER_MAGIC);
    encoded.extend_from_slice(&PEER_PROTOCOL_VERSION.to_le_bytes());
    encoded.push(kind);
    encoded.push(0);
    encoded.extend_from_slice(&frame.sequence.to_le_bytes());
    encoded.extend_from_slice(&payload_len.to_le_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub fn decode_peer_frame(
    bytes: &[u8],
    expected_network_id: [u8; 32],
) -> Result<PeerFrame, PeerError> {
    if bytes.len() < PEER_FRAME_HEADER_BYTES {
        return Err(PeerError::Truncated {
            needed: PEER_FRAME_HEADER_BYTES,
            remaining: bytes.len(),
        });
    }
    if bytes[..4] != PEER_MAGIC {
        return Err(PeerError::InvalidMagic);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != PEER_PROTOCOL_VERSION {
        return Err(PeerError::UnsupportedVersion(version));
    }
    let kind = bytes[6];
    if bytes[7] != 0 {
        return Err(PeerError::NonZeroFlags);
    }
    let sequence = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed frame header"));
    let payload_len =
        u32::from_le_bytes(bytes[16..20].try_into().expect("fixed frame header")) as usize;
    let payload_limit = if kind == TRANSACTION_KIND {
        MAX_TRANSACTION_BYTES
    } else {
        MAX_PEER_PAYLOAD_BYTES
    };
    if payload_len > payload_limit {
        return Err(PeerError::PayloadTooLarge {
            actual: payload_len,
            max: payload_limit,
        });
    }
    let expected_len =
        PEER_FRAME_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(PeerError::PayloadTooLarge {
                actual: payload_len,
                max: MAX_PEER_PAYLOAD_BYTES,
            })?;
    if bytes.len() < expected_len {
        return Err(PeerError::Truncated {
            needed: expected_len,
            remaining: bytes.len(),
        });
    }
    if bytes.len() > expected_len {
        return Err(PeerError::TrailingBytes(bytes.len() - expected_len));
    }
    let message = decode_message(kind, &bytes[PEER_FRAME_HEADER_BYTES..], expected_network_id)?;
    Ok(PeerFrame { sequence, message })
}

fn encode_message(message: &PeerMessage) -> Result<(u8, Vec<u8>), PeerError> {
    match message {
        PeerMessage::Hello(hello) => {
            validate_hello(hello)?;
            let mut payload = Vec::with_capacity(HELLO_PAYLOAD_BYTES);
            payload.extend_from_slice(&hello.network_id);
            payload.extend_from_slice(&hello.consensus_fingerprint);
            payload.extend_from_slice(&hello.node_nonce);
            payload.extend_from_slice(&hello.tip);
            payload.extend_from_slice(&hello.height.to_le_bytes());
            payload.extend_from_slice(&hello.cumulative_work.0);
            Ok((HELLO_KIND, payload))
        }
        PeerMessage::GetHeaders { locator, stop } => {
            validate_identifiers(locator, MAX_HEADER_LOCATORS, "header locator", true)?;
            let mut payload = Vec::with_capacity(2 + locator.len() * 32 + 32);
            payload.extend_from_slice(&(locator.len() as u16).to_le_bytes());
            for block_id in locator {
                payload.extend_from_slice(block_id);
            }
            payload.extend_from_slice(stop);
            Ok((GET_HEADERS_KIND, payload))
        }
        PeerMessage::Inventory { block_ids } => {
            validate_identifiers(block_ids, MAX_INVENTORY_ITEMS, "inventory", false)?;
            let mut payload = Vec::with_capacity(2 + block_ids.len() * 32);
            payload.extend_from_slice(&(block_ids.len() as u16).to_le_bytes());
            for block_id in block_ids {
                payload.extend_from_slice(block_id);
            }
            Ok((INVENTORY_KIND, payload))
        }
        PeerMessage::GetBlock { block_id } => Ok((GET_BLOCK_KIND, block_id.to_vec())),
        PeerMessage::Block(block) => Ok((BLOCK_KIND, encode_block(block)?)),
        PeerMessage::SubmitBlock(block) => Ok((SUBMIT_BLOCK_KIND, encode_block(block)?)),
        PeerMessage::BlockSubmissionResult(result) => {
            let mut payload = Vec::with_capacity(73);
            payload.extend_from_slice(&result.block_id);
            payload.push(result.status as u8);
            payload.extend_from_slice(&result.peer_height.to_le_bytes());
            payload.extend_from_slice(&result.peer_tip);
            Ok((BLOCK_SUBMISSION_RESULT_KIND, payload))
        }
        PeerMessage::GetMempool => Ok((GET_MEMPOOL_KIND, Vec::new())),
        PeerMessage::TransactionInventory { txids } => {
            validate_identifiers(txids, MAX_INVENTORY_ITEMS, "transaction inventory", false)?;
            let mut payload = Vec::with_capacity(2 + txids.len() * 32);
            payload.extend_from_slice(&(txids.len() as u16).to_le_bytes());
            for txid in txids {
                payload.extend_from_slice(txid);
            }
            Ok((TRANSACTION_INVENTORY_KIND, payload))
        }
        PeerMessage::GetTransaction { txid } => Ok((GET_TRANSACTION_KIND, txid.to_vec())),
        PeerMessage::Transaction(transaction) => {
            let payload = encode_transaction(transaction)?;
            if payload.len() > MAX_TRANSACTION_BYTES {
                return Err(PeerError::PayloadTooLarge {
                    actual: payload.len(),
                    max: MAX_TRANSACTION_BYTES,
                });
            }
            Ok((TRANSACTION_KIND, payload))
        }
        PeerMessage::GetMiningTemplate { payout } => {
            Ok((GET_MINING_TEMPLATE_KIND, payout.to_vec()))
        }
        PeerMessage::MiningTemplate(template) => {
            Ok((MINING_TEMPLATE_KIND, encode_mining_template(template)?))
        }
    }
}

fn decode_message(
    kind: u8,
    payload: &[u8],
    expected_network_id: [u8; 32],
) -> Result<PeerMessage, PeerError> {
    match kind {
        HELLO_KIND => {
            let mut reader = PayloadReader::new(payload);
            let hello = PeerHello {
                network_id: reader.array()?,
                consensus_fingerprint: reader.array()?,
                node_nonce: reader.array()?,
                tip: reader.array()?,
                height: reader.u64()?,
                cumulative_work: ChainWork(reader.array()?),
            };
            reader.finish()?;
            validate_hello(&hello)?;
            if hello.network_id != expected_network_id {
                return Err(PeerError::WrongNetwork);
            }
            Ok(PeerMessage::Hello(hello))
        }
        GET_HEADERS_KIND => {
            let mut reader = PayloadReader::new(payload);
            let count = reader.u16()? as usize;
            if count == 0 {
                return Err(PeerError::EmptyLocator);
            }
            if count > MAX_HEADER_LOCATORS {
                return Err(PeerError::CountLimit {
                    field: "header locator",
                    actual: count,
                    max: MAX_HEADER_LOCATORS,
                });
            }
            let mut locator = Vec::with_capacity(count);
            for _ in 0..count {
                locator.push(reader.array()?);
            }
            let stop = reader.array()?;
            reader.finish()?;
            validate_identifiers(&locator, MAX_HEADER_LOCATORS, "header locator", true)?;
            Ok(PeerMessage::GetHeaders { locator, stop })
        }
        INVENTORY_KIND => {
            let mut reader = PayloadReader::new(payload);
            let count = reader.u16()? as usize;
            if count > MAX_INVENTORY_ITEMS {
                return Err(PeerError::CountLimit {
                    field: "inventory",
                    actual: count,
                    max: MAX_INVENTORY_ITEMS,
                });
            }
            let mut block_ids = Vec::with_capacity(count);
            for _ in 0..count {
                block_ids.push(reader.array()?);
            }
            reader.finish()?;
            validate_identifiers(&block_ids, MAX_INVENTORY_ITEMS, "inventory", false)?;
            Ok(PeerMessage::Inventory { block_ids })
        }
        GET_BLOCK_KIND => {
            let mut reader = PayloadReader::new(payload);
            let block_id = reader.array()?;
            reader.finish()?;
            Ok(PeerMessage::GetBlock { block_id })
        }
        BLOCK_KIND => {
            let block = decode_block(payload, expected_network_id)?;
            if encode_block(&block)? != payload {
                return Err(PeerError::NonCanonicalBlock);
            }
            Ok(PeerMessage::Block(block))
        }
        SUBMIT_BLOCK_KIND => {
            let block = decode_block(payload, expected_network_id)?;
            if encode_block(&block)? != payload {
                return Err(PeerError::NonCanonicalBlock);
            }
            Ok(PeerMessage::SubmitBlock(block))
        }
        BLOCK_SUBMISSION_RESULT_KIND => {
            let mut reader = PayloadReader::new(payload);
            let result = BlockSubmissionResult {
                block_id: reader.array()?,
                status: BlockSubmissionStatus::from_byte(reader.u8()?)?,
                peer_height: reader.u64()?,
                peer_tip: reader.array()?,
            };
            reader.finish()?;
            Ok(PeerMessage::BlockSubmissionResult(result))
        }
        GET_MEMPOOL_KIND => {
            PayloadReader::new(payload).finish()?;
            Ok(PeerMessage::GetMempool)
        }
        TRANSACTION_INVENTORY_KIND => {
            let mut reader = PayloadReader::new(payload);
            let count = reader.u16()? as usize;
            if count > MAX_INVENTORY_ITEMS {
                return Err(PeerError::CountLimit {
                    field: "transaction inventory",
                    actual: count,
                    max: MAX_INVENTORY_ITEMS,
                });
            }
            let mut txids = Vec::with_capacity(count);
            for _ in 0..count {
                txids.push(reader.array()?);
            }
            reader.finish()?;
            validate_identifiers(&txids, MAX_INVENTORY_ITEMS, "transaction inventory", false)?;
            Ok(PeerMessage::TransactionInventory { txids })
        }
        GET_TRANSACTION_KIND => {
            let mut reader = PayloadReader::new(payload);
            let txid = reader.array()?;
            reader.finish()?;
            Ok(PeerMessage::GetTransaction { txid })
        }
        TRANSACTION_KIND => {
            if payload.len() > MAX_TRANSACTION_BYTES {
                return Err(PeerError::PayloadTooLarge {
                    actual: payload.len(),
                    max: MAX_TRANSACTION_BYTES,
                });
            }
            let transaction = decode_transaction(payload, expected_network_id)?;
            if encode_transaction(&transaction)? != payload {
                return Err(PeerError::NonCanonicalTransaction);
            }
            Ok(PeerMessage::Transaction(transaction))
        }
        GET_MINING_TEMPLATE_KIND => {
            let mut reader = PayloadReader::new(payload);
            let payout = reader.array()?;
            reader.finish()?;
            Ok(PeerMessage::GetMiningTemplate { payout })
        }
        MINING_TEMPLATE_KIND => Ok(PeerMessage::MiningTemplate(decode_mining_template(
            payload,
            expected_network_id,
        )?)),
        other => Err(PeerError::UnknownKind(other)),
    }
}

fn encode_mining_template(template: &MiningTemplate) -> Result<Vec<u8>, PeerError> {
    validate_mining_template(template, template.challenge.network_id)?;
    let mut payload = Vec::with_capacity(BLOCK_CHALLENGE_BYTES + 128);
    encode_block_challenge(&template.challenge, &mut payload);
    payload.extend_from_slice(&template.coinbase.height.to_le_bytes());
    payload.push(template.coinbase.outputs.len() as u8);
    for output in &template.coinbase.outputs {
        encode_template_output(output, &mut payload);
    }
    payload.extend_from_slice(&(template.transactions.len() as u16).to_le_bytes());
    for transaction in &template.transactions {
        let encoded = encode_transaction(transaction)?;
        let length = u32::try_from(encoded.len()).map_err(|_| PeerError::PayloadTooLarge {
            actual: encoded.len(),
            max: MAX_TRANSACTION_BYTES,
        })?;
        payload.extend_from_slice(&length.to_le_bytes());
        payload.extend_from_slice(&encoded);
    }
    Ok(payload)
}

fn decode_mining_template(
    payload: &[u8],
    expected_network_id: [u8; 32],
) -> Result<MiningTemplate, PeerError> {
    let mut reader = PayloadReader::new(payload);
    let challenge = decode_block_challenge(&mut reader, expected_network_id)?;
    let coinbase_height = reader.u64()?;
    let output_count = reader.u8()? as usize;
    if output_count > MAX_COINBASE_OUTPUTS {
        return Err(PeerError::CountLimit {
            field: "mining template coinbase outputs",
            actual: output_count,
            max: MAX_COINBASE_OUTPUTS,
        });
    }
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(decode_template_output(&mut reader)?);
    }
    let transaction_count = reader.u16()? as usize;
    if transaction_count > MAX_BLOCK_TRANSACTIONS {
        return Err(PeerError::CountLimit {
            field: "mining template transactions",
            actual: transaction_count,
            max: MAX_BLOCK_TRANSACTIONS,
        });
    }
    let mut transactions = Vec::with_capacity(transaction_count);
    for _ in 0..transaction_count {
        let length = reader.u32()? as usize;
        if length > MAX_TRANSACTION_BYTES {
            return Err(PeerError::PayloadTooLarge {
                actual: length,
                max: MAX_TRANSACTION_BYTES,
            });
        }
        let encoded = reader.take(length)?;
        let transaction = decode_transaction(encoded, expected_network_id)?;
        if encode_transaction(&transaction)? != encoded {
            return Err(PeerError::NonCanonicalTransaction);
        }
        transactions.push(transaction);
    }
    reader.finish()?;
    let template = MiningTemplate {
        challenge,
        coinbase: Coinbase {
            height: coinbase_height,
            outputs,
        },
        transactions,
    };
    validate_mining_template(&template, expected_network_id)?;
    Ok(template)
}

fn validate_mining_template(
    template: &MiningTemplate,
    expected_network_id: [u8; 32],
) -> Result<(), PeerError> {
    if template.challenge.network_id != expected_network_id {
        return Err(PeerError::WrongNetwork);
    }
    if template.coinbase.height != template.challenge.height {
        return Err(PeerError::InvalidMiningTemplate(
            "coinbase height does not match challenge height",
        ));
    }
    if template.coinbase.outputs.len() > MAX_COINBASE_OUTPUTS {
        return Err(PeerError::CountLimit {
            field: "mining template coinbase outputs",
            actual: template.coinbase.outputs.len(),
            max: MAX_COINBASE_OUTPUTS,
        });
    }
    if template.transactions.len() > MAX_BLOCK_TRANSACTIONS {
        return Err(PeerError::CountLimit {
            field: "mining template transactions",
            actual: template.transactions.len(),
            max: MAX_BLOCK_TRANSACTIONS,
        });
    }
    if template
        .transactions
        .iter()
        .any(|transaction| transaction.network_id != expected_network_id)
    {
        return Err(PeerError::WrongNetwork);
    }
    let mut commitments = Vec::with_capacity(template.transactions.len().saturating_add(1));
    commitments.push(template.coinbase.commitment(expected_network_id));
    commitments.extend(template.transactions.iter().map(Transaction::txid));
    if merkle_root(&commitments) != template.challenge.transaction_root {
        return Err(PeerError::InvalidMiningTemplate(
            "transaction root does not match template contents",
        ));
    }
    Ok(())
}

fn encode_block_challenge(challenge: &BlockChallenge, payload: &mut Vec<u8>) {
    payload.extend_from_slice(&challenge.network_id);
    payload.extend_from_slice(&challenge.previous_block);
    payload.extend_from_slice(&challenge.transaction_root);
    payload.extend_from_slice(&challenge.height.to_le_bytes());
    payload.extend_from_slice(&challenge.timestamp.to_le_bytes());
    payload.extend_from_slice(&challenge.target);
}

fn decode_block_challenge(
    reader: &mut PayloadReader<'_>,
    expected_network_id: [u8; 32],
) -> Result<BlockChallenge, PeerError> {
    let challenge = BlockChallenge {
        network_id: reader.array()?,
        previous_block: reader.array()?,
        transaction_root: reader.array()?,
        height: reader.u64()?,
        timestamp: reader.u64()?,
        target: reader.array()?,
    };
    if challenge.network_id != expected_network_id {
        return Err(PeerError::WrongNetwork);
    }
    Ok(challenge)
}

fn encode_template_output(output: &TxOutput, payload: &mut Vec<u8>) {
    payload.extend_from_slice(&output.value.to_le_bytes());
    match output.lock {
        OutputLock::Key(key) => {
            payload.push(0);
            payload.extend_from_slice(&key);
        }
        OutputLock::InferenceChannel { channel_id } => {
            payload.push(1);
            payload.extend_from_slice(&channel_id);
        }
    }
    payload.extend_from_slice(&output.spendable_height.to_le_bytes());
}

fn decode_template_output(reader: &mut PayloadReader<'_>) -> Result<TxOutput, PeerError> {
    let value = reader.u64()?;
    let lock = match reader.u8()? {
        0 => OutputLock::Key(reader.array()?),
        1 => OutputLock::InferenceChannel {
            channel_id: reader.array()?,
        },
        tag => return Err(PeerError::InvalidMiningOutputLockTag(tag)),
    };
    let spendable_height = reader.u64()?;
    Ok(TxOutput {
        value,
        lock,
        spendable_height,
    })
}

fn validate_hello(hello: &PeerHello) -> Result<(), PeerError> {
    if hello.node_nonce == [0; 32] {
        return Err(PeerError::ZeroNodeNonce);
    }
    Ok(())
}

fn validate_identifiers(
    identifiers: &[[u8; 32]],
    max: usize,
    field: &'static str,
    require_nonempty: bool,
) -> Result<(), PeerError> {
    if require_nonempty && identifiers.is_empty() {
        return Err(PeerError::EmptyLocator);
    }
    if identifiers.len() > max {
        return Err(PeerError::CountLimit {
            field,
            actual: identifiers.len(),
            max,
        });
    }
    let mut unique = HashSet::with_capacity(identifiers.len());
    if identifiers
        .iter()
        .any(|identifier| !unique.insert(*identifier))
    {
        return Err(PeerError::DuplicateIdentifier(field));
    }
    Ok(())
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PeerError> {
        let end = self.offset.checked_add(count).ok_or(PeerError::Truncated {
            needed: usize::MAX,
            remaining: self.bytes.len().saturating_sub(self.offset),
        })?;
        if end > self.bytes.len() {
            return Err(PeerError::Truncated {
                needed: count,
                remaining: self.bytes.len().saturating_sub(self.offset),
            });
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u16(&mut self) -> Result<u16, PeerError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("fixed payload field"),
        ))
    }

    fn u32(&mut self) -> Result<u32, PeerError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("fixed payload field"),
        ))
    }

    fn u8(&mut self) -> Result<u8, PeerError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, PeerError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed payload field"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PeerError> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("payload slice has requested fixed length"))
    }

    fn finish(self) -> Result<(), PeerError> {
        let remaining = self.bytes.len() - self.offset;
        if remaining != 0 {
            return Err(PeerError::TrailingBytes(remaining));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PeerSession {
    local_hello: PeerHello,
    remote_hello: Option<PeerHello>,
    hello_sent: bool,
    next_outbound_sequence: u64,
    next_inbound_sequence: u64,
    messages_used: u64,
    bytes_used: u64,
    limits: PeerLimits,
}

impl PeerSession {
    pub fn new(local_hello: PeerHello, limits: PeerLimits) -> Result<Self, PeerError> {
        limits.validate()?;
        validate_hello(&local_hello)?;
        Ok(Self {
            local_hello,
            remote_hello: None,
            hello_sent: false,
            next_outbound_sequence: 0,
            next_inbound_sequence: 0,
            messages_used: 0,
            bytes_used: 0,
            limits,
        })
    }

    pub fn limits(&self) -> PeerLimits {
        self.limits
    }

    pub fn local_hello(&self) -> PeerHello {
        self.local_hello
    }

    pub fn remote_hello(&self) -> Option<PeerHello> {
        self.remote_hello
    }

    pub fn handshake_complete(&self) -> bool {
        self.hello_sent && self.remote_hello.is_some()
    }

    pub fn encode_hello(&mut self) -> Result<Vec<u8>, PeerError> {
        self.encode_outbound(PeerMessage::Hello(self.local_hello))
    }

    pub fn encode_outbound(&mut self, message: PeerMessage) -> Result<Vec<u8>, PeerError> {
        match &message {
            PeerMessage::Hello(hello) => {
                if self.hello_sent {
                    return Err(PeerError::DuplicateHello);
                }
                if *hello != self.local_hello {
                    return Err(PeerError::WrongNetwork);
                }
            }
            _ if !self.hello_sent => return Err(PeerError::LocalHelloRequired),
            _ if self.remote_hello.is_none() => return Err(PeerError::HandshakeRequired),
            _ => {}
        }

        let sequence = self.next_outbound_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(PeerError::SequenceExhausted)?;
        let encoded = encode_peer_frame(&PeerFrame { sequence, message })?;
        self.ensure_budget(encoded.len())?;
        self.charge(encoded.len());
        self.next_outbound_sequence = next_sequence;
        if sequence == 0 {
            self.hello_sent = true;
        }
        Ok(encoded)
    }

    pub fn accept_inbound(&mut self, bytes: &[u8]) -> Result<PeerMessage, PeerError> {
        self.ensure_budget(bytes.len())?;
        let frame = decode_peer_frame(bytes, self.local_hello.network_id)?;
        if frame.sequence != self.next_inbound_sequence {
            return Err(PeerError::UnexpectedSequence {
                expected: self.next_inbound_sequence,
                actual: frame.sequence,
            });
        }
        let next_sequence = self
            .next_inbound_sequence
            .checked_add(1)
            .ok_or(PeerError::SequenceExhausted)?;

        match &frame.message {
            PeerMessage::Hello(hello) => {
                if self.remote_hello.is_some() {
                    return Err(PeerError::DuplicateHello);
                }
                if hello.consensus_fingerprint != self.local_hello.consensus_fingerprint {
                    return Err(PeerError::WrongConsensusFingerprint);
                }
                if hello.node_nonce == self.local_hello.node_nonce {
                    return Err(PeerError::SelfConnect);
                }
            }
            _ if self.remote_hello.is_none() => return Err(PeerError::RemoteHelloRequired),
            _ if !self.hello_sent => return Err(PeerError::HandshakeRequired),
            _ => {}
        }

        self.charge(bytes.len());
        self.next_inbound_sequence = next_sequence;
        if let PeerMessage::Hello(hello) = frame.message {
            self.remote_hello = Some(hello);
            Ok(PeerMessage::Hello(hello))
        } else {
            Ok(frame.message)
        }
    }

    fn ensure_budget(&self, frame_bytes: usize) -> Result<(), PeerError> {
        let next_messages = self
            .messages_used
            .checked_add(1)
            .ok_or(PeerError::PeerBudgetExceeded)?;
        let next_bytes = self
            .bytes_used
            .checked_add(frame_bytes as u64)
            .ok_or(PeerError::PeerBudgetExceeded)?;
        if next_messages > self.limits.max_messages_per_peer
            || next_bytes > self.limits.max_bytes_per_peer
        {
            return Err(PeerError::PeerBudgetExceeded);
        }
        Ok(())
    }

    fn charge(&mut self, frame_bytes: usize) {
        self.messages_used += 1;
        self.bytes_used += frame_bytes as u64;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSummary {
    pub tip: [u8; 32],
    pub height: u64,
    pub cumulative_work: ChainWork,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPlan {
    UpToDate,
    RequestInventory {
        locator: Vec<[u8; 32]>,
        stop: [u8; 32],
    },
    RequestBlock {
        block_id: [u8; 32],
    },
    AwaitInventory,
    /// The peer claims more work without being a simple higher chain.
    /// No fork is selected or applied by this layer.
    ForkChoiceRequired,
}

pub fn plan_initial_sync(
    local: ChainSummary,
    remote: PeerHello,
    locator: Vec<[u8; 32]>,
) -> Result<SyncPlan, PeerError> {
    if remote.cumulative_work <= local.cumulative_work {
        return Ok(SyncPlan::UpToDate);
    }
    if remote.height <= local.height {
        return Ok(SyncPlan::ForkChoiceRequired);
    }
    validate_identifiers(&locator, MAX_HEADER_LOCATORS, "header locator", true)?;
    Ok(SyncPlan::RequestInventory {
        locator,
        stop: remote.tip,
    })
}

pub fn plan_inventory_sync(
    local: ChainSummary,
    remote: PeerHello,
    block_ids: &[[u8; 32]],
) -> Result<SyncPlan, PeerError> {
    if remote.cumulative_work <= local.cumulative_work {
        return Ok(SyncPlan::UpToDate);
    }
    if remote.height <= local.height {
        return Ok(SyncPlan::ForkChoiceRequired);
    }
    validate_identifiers(block_ids, MAX_INVENTORY_ITEMS, "inventory", false)?;
    let Some(block_id) = block_ids.first() else {
        return Ok(SyncPlan::AwaitInventory);
    };
    if *block_id == local.tip {
        return Ok(SyncPlan::ForkChoiceRequired);
    }
    Ok(SyncPlan::RequestBlock {
        block_id: *block_id,
    })
}

pub struct PeerConnection {
    stream: TcpStream,
    session: PeerSession,
    deadline: Instant,
    cancellation: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    write_deadline_barrier: Option<Arc<WriteDeadlineBarrier>>,
}

fn connect_stream_cancellable_with<Connect>(
    address: SocketAddr,
    connect_timeout: Duration,
    operation_deadline: Option<Instant>,
    cancellation: &AtomicBool,
    mut connect: Connect,
) -> Result<TcpStream, PeerError>
where
    Connect: FnMut(&SocketAddr, Duration) -> io::Result<TcpStream>,
{
    let now = Instant::now();
    let connect_deadline = now
        .checked_add(connect_timeout)
        .ok_or(PeerError::InvalidLimits)?;
    let deadline =
        operation_deadline.map_or(connect_deadline, |deadline| deadline.min(connect_deadline));
    loop {
        if cancellation.load(Ordering::Acquire) {
            return Err(PeerError::Cancelled);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PeerError::TotalTimeout)?;
        let attempt_timeout = remaining.min(PEER_CANCEL_POLL_INTERVAL);
        match connect(&address, attempt_timeout) {
            Ok(stream) => {
                if cancellation.load(Ordering::Acquire) {
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(PeerError::Cancelled);
                }
                if Instant::now() >= deadline {
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(PeerError::TotalTimeout);
                }
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                if cancellation.load(Ordering::Acquire) {
                    return Err(PeerError::Cancelled);
                }
            }
            Err(error) => {
                if cancellation.load(Ordering::Acquire) {
                    return Err(PeerError::Cancelled);
                }
                return Err(PeerError::Io(error));
            }
        }
    }
}

impl PeerConnection {
    pub fn connect(address: SocketAddr, session: PeerSession) -> Result<Self, PeerError> {
        Self::connect_with_policy(address, session, PeerAddressPolicy::PrivateOnly)
    }

    pub fn connect_with_policy(
        address: SocketAddr,
        session: PeerSession,
        address_policy: PeerAddressPolicy,
    ) -> Result<Self, PeerError> {
        Self::connect_with_policy_deadline(address, session, address_policy, None, None)
    }

    pub(crate) fn connect_with_policy_before(
        address: SocketAddr,
        session: PeerSession,
        address_policy: PeerAddressPolicy,
        deadline: Instant,
    ) -> Result<Self, PeerError> {
        Self::connect_with_policy_deadline(address, session, address_policy, Some(deadline), None)
    }

    pub(crate) fn connect_with_policy_before_cancellable(
        address: SocketAddr,
        session: PeerSession,
        address_policy: PeerAddressPolicy,
        deadline: Instant,
        cancellation: Arc<AtomicBool>,
    ) -> Result<Self, PeerError> {
        Self::connect_with_policy_deadline(
            address,
            session,
            address_policy,
            Some(deadline),
            Some(cancellation),
        )
    }

    fn connect_with_policy_deadline(
        address: SocketAddr,
        session: PeerSession,
        address_policy: PeerAddressPolicy,
        deadline: Option<Instant>,
        cancellation: Option<Arc<AtomicBool>>,
    ) -> Result<Self, PeerError> {
        validate_peer_address(address, address_policy)?;
        let limits = session.limits();
        let stream = match cancellation.as_deref() {
            Some(cancellation) => connect_stream_cancellable_with(
                address,
                limits.connect_timeout,
                deadline,
                cancellation,
                TcpStream::connect_timeout,
            )?,
            None => {
                let connect_timeout = match deadline {
                    Some(deadline) => deadline
                        .checked_duration_since(Instant::now())
                        .filter(|remaining| !remaining.is_zero())
                        .map(|remaining| remaining.min(limits.connect_timeout))
                        .ok_or(PeerError::TotalTimeout)?,
                    None => limits.connect_timeout,
                };
                TcpStream::connect_timeout(&address, connect_timeout).map_err(PeerError::Io)?
            }
        };
        let mut connection =
            Self::from_stream_with_policy_deadline(stream, session, address_policy, deadline)?;
        if let Some(cancellation) = cancellation {
            connection.set_cancellation(cancellation);
            connection.ensure_not_cancelled()?;
        }
        Ok(connection)
    }

    pub fn from_stream(stream: TcpStream, session: PeerSession) -> Result<Self, PeerError> {
        Self::from_stream_with_policy(stream, session, PeerAddressPolicy::PrivateOnly)
    }

    pub fn from_stream_with_policy(
        stream: TcpStream,
        session: PeerSession,
        address_policy: PeerAddressPolicy,
    ) -> Result<Self, PeerError> {
        Self::from_stream_with_policy_deadline(stream, session, address_policy, None)
    }

    fn from_stream_with_policy_deadline(
        stream: TcpStream,
        session: PeerSession,
        address_policy: PeerAddressPolicy,
        operation_deadline: Option<Instant>,
    ) -> Result<Self, PeerError> {
        validate_peer_address(stream.peer_addr().map_err(PeerError::Io)?, address_policy)?;
        let limits = session.limits();
        limits.validate()?;
        stream.set_nodelay(true).map_err(PeerError::Io)?;
        let now = Instant::now();
        let total_deadline = now
            .checked_add(limits.total_timeout)
            .ok_or(PeerError::InvalidLimits)?;
        let deadline =
            operation_deadline.map_or(total_deadline, |deadline| deadline.min(total_deadline));
        if deadline <= now {
            return Err(PeerError::TotalTimeout);
        }
        Ok(Self {
            stream,
            session,
            deadline,
            cancellation: None,
            #[cfg(test)]
            write_deadline_barrier: None,
        })
    }

    pub fn session(&self) -> &PeerSession {
        &self.session
    }

    pub(crate) fn try_clone_stream(&self) -> Result<TcpStream, PeerError> {
        self.stream.try_clone().map_err(PeerError::Io)
    }

    pub(crate) fn set_cancellation(&mut self, cancellation: Arc<AtomicBool>) {
        self.cancellation = Some(cancellation);
    }

    #[cfg(test)]
    pub(crate) fn set_write_deadline_barrier(&mut self, barrier: Arc<WriteDeadlineBarrier>) {
        self.write_deadline_barrier = Some(barrier);
    }

    pub fn send_hello(&mut self) -> Result<(), PeerError> {
        let bytes = self.session.encode_hello()?;
        self.write_all_bounded(&bytes)
    }

    pub fn send(&mut self, message: PeerMessage) -> Result<(), PeerError> {
        let bytes = self.session.encode_outbound(message)?;
        self.write_all_bounded(&bytes)
    }

    pub(crate) fn send_before(
        &mut self,
        message: PeerMessage,
        deadline: Instant,
    ) -> Result<(), PeerError> {
        let bytes = self.session.encode_outbound(message)?;
        self.write_all_before(&bytes, Some(deadline))
    }

    pub fn receive(&mut self) -> Result<PeerMessage, PeerError> {
        self.receive_before(None)
    }

    pub(crate) fn receive_submit_block_response(&mut self) -> Result<PeerMessage, PeerError> {
        let deadline = Instant::now()
            .checked_add(SUBMIT_BLOCK_RESPONSE_BUDGET)
            .ok_or(PeerError::InvalidLimits)?;
        self.receive_before(Some(deadline))
    }

    fn receive_before(
        &mut self,
        submit_response_deadline: Option<Instant>,
    ) -> Result<PeerMessage, PeerError> {
        let header = self.read_exact_bounded(PEER_FRAME_HEADER_BYTES, submit_response_deadline)?;
        validate_frame_header(&header)?;
        let payload_len =
            u32::from_le_bytes(header[16..20].try_into().expect("fixed frame header")) as usize;
        let payload_limit = if header[6] == TRANSACTION_KIND {
            MAX_TRANSACTION_BYTES
        } else {
            MAX_PEER_PAYLOAD_BYTES
        };
        if payload_len > payload_limit {
            return Err(PeerError::PayloadTooLarge {
                actual: payload_len,
                max: payload_limit,
            });
        }
        let frame_len = PEER_FRAME_HEADER_BYTES + payload_len;
        self.session.ensure_budget(frame_len)?;
        let mut bytes = Vec::with_capacity(frame_len);
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&self.read_exact_bounded(payload_len, submit_response_deadline)?);
        self.session.accept_inbound(&bytes)
    }

    fn read_exact_bounded(
        &mut self,
        length: usize,
        submit_response_deadline: Option<Instant>,
    ) -> Result<Vec<u8>, PeerError> {
        let mut bytes = vec![0_u8; length];
        let mut offset = 0;
        let mut last_progress = Instant::now();
        while offset < length {
            self.ensure_not_cancelled()?;
            self.set_read_timeout(last_progress, submit_response_deadline)?;
            match self.stream.read(&mut bytes[offset..]) {
                Ok(0) => {
                    return if offset == 0 {
                        Err(PeerError::ConnectionClosed)
                    } else {
                        Err(PeerError::Truncated {
                            needed: length,
                            remaining: offset,
                        })
                    };
                }
                Ok(read) => {
                    offset += read;
                    last_progress = Instant::now();
                }
                Err(error)
                    if error.kind() == io::ErrorKind::TimedOut
                        || error.kind() == io::ErrorKind::WouldBlock =>
                {
                    if self.cancellation.is_none() {
                        return Err(self.timeout_error(submit_response_deadline));
                    }
                    self.ensure_not_cancelled()?;
                    self.ensure_io_deadlines(last_progress, submit_response_deadline)?;
                }
                Err(error)
                    if offset == 0
                        && matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                                | io::ErrorKind::NotConnected
                                | io::ErrorKind::UnexpectedEof
                        ) =>
                {
                    return Err(PeerError::ConnectionClosed);
                }
                Err(error) => return Err(PeerError::Io(error)),
            }
        }
        Ok(bytes)
    }

    fn write_all_bounded(&mut self, bytes: &[u8]) -> Result<(), PeerError> {
        self.write_all_before(bytes, None)
    }

    fn write_all_before(
        &mut self,
        bytes: &[u8],
        operation_deadline: Option<Instant>,
    ) -> Result<(), PeerError> {
        let mut offset = 0;
        let mut last_progress = Instant::now();
        while offset < bytes.len() {
            self.ensure_not_cancelled()?;
            self.set_write_timeout(last_progress, operation_deadline)?;
            #[cfg(test)]
            if let Some(barrier) = self.write_deadline_barrier.take() {
                barrier.entered.wait();
                barrier.release.wait();
            }
            // Recheck after any scheduling delay and immediately before each
            // write system call. No later chunk begins after the absolute
            // SubmitBlock response cutoff.
            self.ensure_io_deadlines(last_progress, operation_deadline)?;
            match self.stream.write(&bytes[offset..]) {
                Ok(0) => {
                    return Err(PeerError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "peer socket wrote zero bytes",
                    )));
                }
                Ok(written) => {
                    offset += written;
                    last_progress = Instant::now();
                }
                Err(error)
                    if error.kind() == io::ErrorKind::TimedOut
                        || error.kind() == io::ErrorKind::WouldBlock =>
                {
                    if self.cancellation.is_none() {
                        return Err(self.timeout_error(operation_deadline));
                    }
                    self.ensure_not_cancelled()?;
                    self.ensure_io_deadlines(last_progress, operation_deadline)?;
                }
                Err(error) => return Err(PeerError::Io(error)),
            }
        }
        Ok(())
    }

    fn set_read_timeout(
        &self,
        last_progress: Instant,
        submit_response_deadline: Option<Instant>,
    ) -> Result<(), PeerError> {
        let remaining = self.io_timeout(last_progress, submit_response_deadline)?;
        self.stream
            .set_read_timeout(Some(remaining))
            .map_err(PeerError::Io)
    }

    fn set_write_timeout(
        &self,
        last_progress: Instant,
        operation_deadline: Option<Instant>,
    ) -> Result<(), PeerError> {
        let remaining = self.io_timeout(last_progress, operation_deadline)?;
        self.stream
            .set_write_timeout(Some(remaining))
            .map_err(PeerError::Io)
    }

    fn io_timeout(
        &self,
        last_progress: Instant,
        submit_response_deadline: Option<Instant>,
    ) -> Result<Duration, PeerError> {
        let total = self.remaining_total()?;
        let operation = match submit_response_deadline {
            Some(deadline) => deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(PeerError::SubmitBlockResponseTimeout)?,
            None => self
                .session
                .limits
                .idle_timeout
                .checked_sub(last_progress.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(PeerError::IdleTimeout)?,
        };
        let bounded = total.min(operation);
        Ok(if self.cancellation.is_some() {
            bounded.min(PEER_CANCEL_POLL_INTERVAL)
        } else {
            bounded
        })
    }

    fn ensure_io_deadlines(
        &self,
        last_progress: Instant,
        submit_response_deadline: Option<Instant>,
    ) -> Result<(), PeerError> {
        self.remaining_total()?;
        if let Some(deadline) = submit_response_deadline {
            if Instant::now() >= deadline {
                return Err(PeerError::SubmitBlockResponseTimeout);
            }
        } else if last_progress.elapsed() >= self.session.limits.idle_timeout {
            return Err(PeerError::IdleTimeout);
        }
        Ok(())
    }

    fn ensure_not_cancelled(&self) -> Result<(), PeerError> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
        {
            return Err(PeerError::Cancelled);
        }
        Ok(())
    }

    fn remaining_total(&self) -> Result<Duration, PeerError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PeerError::TotalTimeout)
    }

    fn timeout_error(&self, operation_deadline: Option<Instant>) -> PeerError {
        if Instant::now() >= self.deadline {
            PeerError::TotalTimeout
        } else if operation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            PeerError::SubmitBlockResponseTimeout
        } else {
            PeerError::IdleTimeout
        }
    }
}

fn validate_frame_header(header: &[u8]) -> Result<(), PeerError> {
    if header.len() != PEER_FRAME_HEADER_BYTES {
        return Err(PeerError::Truncated {
            needed: PEER_FRAME_HEADER_BYTES,
            remaining: header.len(),
        });
    }
    if header[..4] != PEER_MAGIC {
        return Err(PeerError::InvalidMagic);
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != PEER_PROTOCOL_VERSION {
        return Err(PeerError::UnsupportedVersion(version));
    }
    if !matches!(
        header[6],
        HELLO_KIND
            | GET_HEADERS_KIND
            | INVENTORY_KIND
            | GET_BLOCK_KIND
            | BLOCK_KIND
            | GET_MEMPOOL_KIND
            | TRANSACTION_INVENTORY_KIND
            | GET_TRANSACTION_KIND
            | TRANSACTION_KIND
            | SUBMIT_BLOCK_KIND
            | BLOCK_SUBMISSION_RESULT_KIND
            | GET_MINING_TEMPLATE_KIND
            | MINING_TEMPLATE_KIND
    ) {
        return Err(PeerError::UnknownKind(header[6]));
    }
    if header[7] != 0 {
        return Err(PeerError::NonZeroFlags);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Barrier;
    use std::thread;

    use cmfd_consensus::{
        BLOCK_VERSION, BlockChallenge, BlockValidationContext, ChainState, Coinbase,
        ConsensusPowVerifier, merkle_root, v2_test_reference,
    };

    use super::*;

    const NETWORK_ID: [u8; 32] = [0x63; 32];
    const FINGERPRINT: [u8; 32] = [0x44; 32];

    fn work(value: u8) -> ChainWork {
        let mut bytes = [0_u8; 64];
        bytes[63] = value;
        ChainWork(bytes)
    }

    fn hello(nonce: u8, height: u64, cumulative_work: u8) -> PeerHello {
        PeerHello {
            network_id: NETWORK_ID,
            consensus_fingerprint: FINGERPRINT,
            node_nonce: [nonce; 32],
            tip: [height as u8; 32],
            height,
            cumulative_work: work(cumulative_work),
        }
    }

    fn sample_block() -> Block {
        let (params, _) =
            crate::network_params_and_verifier_for_profile(crate::DEVNET_PROFILE, None).unwrap();
        let reference = v2_test_reference().unwrap();
        let verifier = ConsensusPowVerifier::v2_reference(reference);
        let state = ChainState::new(params, verifier.clone()).unwrap();
        let height = state.next_height();
        let coinbase = Coinbase::new(
            height,
            params.monetary_policy.allocation(height, 0).unwrap(),
            crate::default_miner_destination(),
            params.rewards,
        );
        let challenge = BlockChallenge {
            network_id: params.network_id,
            previous_block: state.tip(),
            transaction_root: merkle_root(&[coinbase.commitment(params.network_id)]),
            height,
            timestamp: params.genesis_timestamp + 1,
            target: state.expected_target().unwrap(),
        };
        let proof = verifier
            .mine(&challenge, 0, crate::DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let block = Block {
            version: BLOCK_VERSION,
            challenge,
            proof,
            coinbase,
            transactions: Vec::new(),
        };
        let mut check = ChainState::new(params, verifier).unwrap();
        check
            .validate_and_apply(
                &block,
                BlockValidationContext {
                    now_unix_seconds: params.genesis_timestamp + 1,
                },
            )
            .unwrap();
        block
    }

    fn sample_transaction(network_id: [u8; 32]) -> Transaction {
        Transaction {
            network_id,
            version: cmfd_consensus::TRANSACTION_VERSION,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    fn raw_frame(kind: u8, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(PEER_FRAME_HEADER_BYTES + payload.len());
        encoded.extend_from_slice(&PEER_MAGIC);
        encoded.extend_from_slice(&PEER_PROTOCOL_VERSION.to_le_bytes());
        encoded.push(kind);
        encoded.push(0);
        encoded.extend_from_slice(&sequence.to_le_bytes());
        encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        encoded.extend_from_slice(payload);
        encoded
    }

    fn all_messages() -> Vec<PeerMessage> {
        let block = sample_block();
        let block_id = block.block_id();
        let template = MiningTemplate {
            challenge: block.challenge,
            coinbase: block.coinbase.clone(),
            transactions: block.transactions.clone(),
        };
        vec![
            PeerMessage::Hello(hello(1, 7, 9)),
            PeerMessage::GetHeaders {
                locator: vec![[1; 32], [2; 32]],
                stop: [3; 32],
            },
            PeerMessage::Inventory {
                block_ids: vec![[4; 32], [5; 32]],
            },
            PeerMessage::GetBlock { block_id: [6; 32] },
            PeerMessage::Block(block.clone()),
            PeerMessage::SubmitBlock(block),
            PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                block_id,
                status: BlockSubmissionStatus::Accepted,
                peer_height: 1,
                peer_tip: block_id,
            }),
            PeerMessage::BlockSubmissionResult(BlockSubmissionResult {
                block_id,
                status: BlockSubmissionStatus::Busy,
                peer_height: 0,
                peer_tip: [0; 32],
            }),
            PeerMessage::GetMempool,
            PeerMessage::TransactionInventory {
                txids: vec![[7; 32], [8; 32]],
            },
            PeerMessage::GetTransaction { txid: [9; 32] },
            PeerMessage::Transaction(sample_transaction(NETWORK_ID)),
            PeerMessage::GetMiningTemplate {
                payout: crate::default_miner_destination(),
            },
            PeerMessage::MiningTemplate(template),
        ]
    }

    #[test]
    fn every_message_round_trips_with_explicit_sequence() {
        for (sequence, message) in all_messages().into_iter().enumerate() {
            let frame = PeerFrame {
                sequence: sequence as u64,
                message,
            };
            let encoded = encode_peer_frame(&frame).unwrap();
            assert_eq!(decode_peer_frame(&encoded, NETWORK_ID).unwrap(), frame);
        }
    }

    #[test]
    fn hello_carries_the_full_big_endian_u512_work_value() {
        let mut work_bytes = [0_u8; 64];
        for (index, byte) in work_bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut value = hello(1, 7, 0);
        value.cumulative_work = ChainWork(work_bytes);
        let encoded = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::Hello(value),
        })
        .unwrap();
        assert_eq!(&encoded[encoded.len() - 64..], &work_bytes);
        assert_eq!(
            decode_peer_frame(&encoded, NETWORK_ID).unwrap().message,
            PeerMessage::Hello(value)
        );
    }

    #[test]
    fn every_truncation_is_rejected_without_panicking() {
        for (sequence, message) in all_messages().into_iter().enumerate() {
            let encoded = encode_peer_frame(&PeerFrame {
                sequence: sequence as u64,
                message,
            })
            .unwrap();
            for length in 0..encoded.len() {
                assert!(decode_peer_frame(&encoded[..length], NETWORK_ID).is_err());
            }
        }
    }

    #[test]
    fn framing_mutations_oversize_and_trailing_bytes_are_rejected() {
        let frame = PeerFrame {
            sequence: 0,
            message: PeerMessage::Hello(hello(1, 0, 1)),
        };
        let encoded = encode_peer_frame(&frame).unwrap();

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            decode_peer_frame(&bad_magic, NETWORK_ID),
            Err(PeerError::InvalidMagic)
        ));
        let mut bad_version = encoded.clone();
        bad_version[4..6].copy_from_slice(&(PEER_PROTOCOL_VERSION + 1).to_le_bytes());
        assert!(matches!(
            decode_peer_frame(&bad_version, NETWORK_ID),
            Err(PeerError::UnsupportedVersion(_))
        ));
        let mut bad_flags = encoded.clone();
        bad_flags[7] = 1;
        assert!(matches!(
            decode_peer_frame(&bad_flags, NETWORK_ID),
            Err(PeerError::NonZeroFlags)
        ));
        let mut bad_kind = encoded.clone();
        bad_kind[6] = 0xff;
        assert!(matches!(
            decode_peer_frame(&bad_kind, NETWORK_ID),
            Err(PeerError::UnknownKind(0xff))
        ));
        let mut oversized = encoded.clone();
        oversized[16..20].copy_from_slice(&((MAX_PEER_PAYLOAD_BYTES as u32) + 1).to_le_bytes());
        assert!(matches!(
            decode_peer_frame(&oversized, NETWORK_ID),
            Err(PeerError::PayloadTooLarge { .. })
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            decode_peer_frame(&trailing, NETWORK_ID),
            Err(PeerError::TrailingBytes(1))
        ));

        let mut invalid_submission = vec![0_u8; 73];
        invalid_submission[32] = 0xff;
        assert!(matches!(
            decode_peer_frame(
                &raw_frame(BLOCK_SUBMISSION_RESULT_KIND, 1, &invalid_submission),
                NETWORK_ID
            ),
            Err(PeerError::InvalidBlockSubmissionStatus(0xff))
        ));
    }

    #[test]
    fn mining_templates_reject_wrong_network_shape_and_lock_tags() {
        let block = sample_block();
        let template = MiningTemplate {
            challenge: block.challenge,
            coinbase: block.coinbase,
            transactions: block.transactions,
        };

        let mut wrong_network = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::MiningTemplate(template.clone()),
        })
        .unwrap();
        wrong_network[PEER_FRAME_HEADER_BYTES] ^= 1;
        assert!(matches!(
            decode_peer_frame(&wrong_network, NETWORK_ID),
            Err(PeerError::WrongNetwork)
        ));

        let mut wrong_height = template.clone();
        wrong_height.coinbase.height = wrong_height.coinbase.height.saturating_add(1);
        assert!(matches!(
            encode_peer_frame(&PeerFrame {
                sequence: 0,
                message: PeerMessage::MiningTemplate(wrong_height),
            }),
            Err(PeerError::InvalidMiningTemplate(
                "coinbase height does not match challenge height"
            ))
        ));

        let mut too_many_outputs = template.clone();
        too_many_outputs.coinbase.outputs =
            vec![template.coinbase.outputs[0].clone(); MAX_COINBASE_OUTPUTS + 1];
        assert!(matches!(
            encode_peer_frame(&PeerFrame {
                sequence: 0,
                message: PeerMessage::MiningTemplate(too_many_outputs),
            }),
            Err(PeerError::CountLimit {
                field: "mining template coinbase outputs",
                ..
            })
        ));

        let mut encoded = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::MiningTemplate(template),
        })
        .unwrap();
        let first_lock_tag = PEER_FRAME_HEADER_BYTES + BLOCK_CHALLENGE_BYTES + 8 + 1 + 8;
        encoded[first_lock_tag] = 0xff;
        assert!(matches!(
            decode_peer_frame(&encoded, NETWORK_ID),
            Err(PeerError::InvalidMiningOutputLockTag(0xff))
        ));
    }

    #[test]
    fn counts_and_duplicate_identifiers_are_rejected_before_allocation() {
        let duplicate = PeerFrame {
            sequence: 1,
            message: PeerMessage::Inventory {
                block_ids: vec![[7; 32], [7; 32]],
            },
        };
        assert!(matches!(
            encode_peer_frame(&duplicate),
            Err(PeerError::DuplicateIdentifier("inventory"))
        ));

        let mut payload = Vec::new();
        payload.extend_from_slice(&((MAX_INVENTORY_ITEMS as u16) + 1).to_le_bytes());
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&PEER_MAGIC);
        encoded.extend_from_slice(&PEER_PROTOCOL_VERSION.to_le_bytes());
        encoded.push(INVENTORY_KIND);
        encoded.push(0);
        encoded.extend_from_slice(&1_u64.to_le_bytes());
        encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        encoded.extend_from_slice(&payload);
        assert!(matches!(
            decode_peer_frame(&encoded, NETWORK_ID),
            Err(PeerError::CountLimit {
                field: "inventory",
                ..
            })
        ));

        let duplicate_transactions = PeerFrame {
            sequence: 1,
            message: PeerMessage::TransactionInventory {
                txids: vec![[8; 32], [8; 32]],
            },
        };
        assert!(matches!(
            encode_peer_frame(&duplicate_transactions),
            Err(PeerError::DuplicateIdentifier("transaction inventory"))
        ));

        let oversized_count = ((MAX_INVENTORY_ITEMS as u16) + 1).to_le_bytes();
        assert!(matches!(
            decode_peer_frame(
                &raw_frame(TRANSACTION_INVENTORY_KIND, 1, &oversized_count),
                NETWORK_ID
            ),
            Err(PeerError::CountLimit {
                field: "transaction inventory",
                ..
            })
        ));

        let mut duplicate_payload = Vec::with_capacity(2 + 64);
        duplicate_payload.extend_from_slice(&2_u16.to_le_bytes());
        duplicate_payload.extend_from_slice(&[9; 32]);
        duplicate_payload.extend_from_slice(&[9; 32]);
        assert!(matches!(
            decode_peer_frame(
                &raw_frame(TRANSACTION_INVENTORY_KIND, 1, &duplicate_payload),
                NETWORK_ID
            ),
            Err(PeerError::DuplicateIdentifier("transaction inventory"))
        ));
    }

    #[test]
    fn block_payload_is_canonical_and_network_bound() {
        let block = sample_block();
        let encoded = encode_peer_frame(&PeerFrame {
            sequence: 1,
            message: PeerMessage::Block(block),
        })
        .unwrap();
        assert!(matches!(
            decode_peer_frame(&encoded, [0x64; 32]),
            Err(PeerError::ConsensusWire(_))
        ));
    }

    #[test]
    fn transaction_payload_is_bounded_canonical_and_network_bound() {
        let wrong_network = encode_peer_frame(&PeerFrame {
            sequence: 1,
            message: PeerMessage::Transaction(sample_transaction([0x64; 32])),
        })
        .unwrap();
        assert!(matches!(
            decode_peer_frame(&wrong_network, NETWORK_ID),
            Err(PeerError::ConsensusWire(
                WireError::WrongNetworkMagic | WireError::WrongNetworkId { .. }
            ))
        ));

        let mut noncanonical = encode_transaction(&sample_transaction(NETWORK_ID)).unwrap();
        noncanonical.push(0);
        assert!(matches!(
            decode_peer_frame(&raw_frame(TRANSACTION_KIND, 1, &noncanonical), NETWORK_ID),
            Err(PeerError::ConsensusWire(WireError::TrailingBytes {
                remaining: 1
            }))
        ));

        let oversized_length = (MAX_TRANSACTION_BYTES as u32) + 1;
        let mut oversized = raw_frame(TRANSACTION_KIND, 1, &[]);
        oversized[16..20].copy_from_slice(&oversized_length.to_le_bytes());
        assert!(matches!(
            decode_peer_frame(&oversized, NETWORK_ID),
            Err(PeerError::PayloadTooLarge {
                max: MAX_TRANSACTION_BYTES,
                ..
            })
        ));

        assert!(matches!(
            decode_peer_frame(&raw_frame(GET_MEMPOOL_KIND, 1, &[0]), NETWORK_ID),
            Err(PeerError::TrailingBytes(1))
        ));
    }

    #[test]
    fn transaction_protocol_messages_require_the_mutual_handshake() {
        let limits = PeerLimits::default();
        let mut local = PeerSession::new(hello(1, 1, 1), limits).unwrap();
        assert!(matches!(
            local.encode_outbound(PeerMessage::GetMempool),
            Err(PeerError::LocalHelloRequired)
        ));

        let inventory = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::TransactionInventory {
                txids: vec![[3; 32]],
            },
        })
        .unwrap();
        assert!(matches!(
            local.accept_inbound(&inventory),
            Err(PeerError::RemoteHelloRequired)
        ));

        let remote_hello = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::Hello(hello(2, 2, 2)),
        })
        .unwrap();
        local.accept_inbound(&remote_hello).unwrap();
        let get_transaction = encode_peer_frame(&PeerFrame {
            sequence: 1,
            message: PeerMessage::GetTransaction { txid: [4; 32] },
        })
        .unwrap();
        assert!(matches!(
            local.accept_inbound(&get_transaction),
            Err(PeerError::HandshakeRequired)
        ));
    }

    #[test]
    fn mutual_handshake_is_required_and_identity_is_checked() {
        let limits = PeerLimits::default();
        let mut local = PeerSession::new(hello(1, 1, 1), limits).unwrap();
        let data = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::GetBlock { block_id: [9; 32] },
        })
        .unwrap();
        assert!(matches!(
            local.accept_inbound(&data),
            Err(PeerError::RemoteHelloRequired)
        ));
        assert!(matches!(
            local.encode_outbound(PeerMessage::GetBlock { block_id: [9; 32] }),
            Err(PeerError::LocalHelloRequired)
        ));

        let remote_hello = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::Hello(hello(2, 2, 2)),
        })
        .unwrap();
        local.accept_inbound(&remote_hello).unwrap();
        let remote_data = encode_peer_frame(&PeerFrame {
            sequence: 1,
            message: PeerMessage::Inventory {
                block_ids: Vec::new(),
            },
        })
        .unwrap();
        assert!(matches!(
            local.accept_inbound(&remote_data),
            Err(PeerError::HandshakeRequired)
        ));
        local.encode_hello().unwrap();
        assert!(local.handshake_complete());

        let mut wrong_fingerprint = PeerSession::new(hello(1, 1, 1), limits).unwrap();
        let mut wrong = hello(2, 2, 2);
        wrong.consensus_fingerprint = [0x45; 32];
        let wrong = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::Hello(wrong),
        })
        .unwrap();
        assert!(matches!(
            wrong_fingerprint.accept_inbound(&wrong),
            Err(PeerError::WrongConsensusFingerprint)
        ));

        let mut self_session = PeerSession::new(hello(1, 1, 1), limits).unwrap();
        let reflected = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::Hello(hello(1, 2, 2)),
        })
        .unwrap();
        assert!(matches!(
            self_session.accept_inbound(&reflected),
            Err(PeerError::SelfConnect)
        ));

        let mut wrong_network = hello(2, 2, 2);
        wrong_network.network_id = [0x64; 32];
        let wrong_network = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::Hello(wrong_network),
        })
        .unwrap();
        assert!(matches!(
            decode_peer_frame(&wrong_network, NETWORK_ID),
            Err(PeerError::WrongNetwork)
        ));

        let duplicate_hello = encode_peer_frame(&PeerFrame {
            sequence: 1,
            message: PeerMessage::Hello(hello(3, 3, 3)),
        })
        .unwrap();
        assert!(matches!(
            local.accept_inbound(&duplicate_hello),
            Err(PeerError::DuplicateHello)
        ));
    }

    #[test]
    fn duplicate_or_out_of_order_frames_and_budget_exhaustion_are_rejected() {
        let mut a = PeerSession::new(hello(1, 1, 1), PeerLimits::default()).unwrap();
        let mut b = PeerSession::new(hello(2, 2, 2), PeerLimits::default()).unwrap();
        let a_hello = a.encode_hello().unwrap();
        let b_hello = b.encode_hello().unwrap();
        a.accept_inbound(&b_hello).unwrap();
        b.accept_inbound(&a_hello).unwrap();
        let message = b
            .encode_outbound(PeerMessage::TransactionInventory {
                txids: vec![[8; 32]],
            })
            .unwrap();
        a.accept_inbound(&message).unwrap();
        assert!(matches!(
            a.accept_inbound(&message),
            Err(PeerError::UnexpectedSequence { .. })
        ));

        let limits = PeerLimits {
            max_messages_per_peer: 2,
            ..PeerLimits::default()
        };
        let mut bounded = PeerSession::new(hello(3, 1, 1), limits).unwrap();
        bounded.encode_hello().unwrap();
        let peer_hello = encode_peer_frame(&PeerFrame {
            sequence: 0,
            message: PeerMessage::Hello(hello(4, 2, 2)),
        })
        .unwrap();
        bounded.accept_inbound(&peer_hello).unwrap();
        assert!(matches!(
            bounded.encode_outbound(PeerMessage::GetMempool),
            Err(PeerError::PeerBudgetExceeded)
        ));
    }

    #[test]
    fn process_nonce_is_stable_nonzero_and_self_connections_are_detectable() {
        let first = process_node_nonce();
        let second = process_node_nonce();
        assert_ne!(first, [0; 32]);
        assert_eq!(first, second);
    }

    #[test]
    fn cancellation_wins_a_connect_attempt_and_closes_the_late_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker_cancel = Arc::clone(&cancellation);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let worker = thread::spawn(move || {
            connect_stream_cancellable_with(
                address,
                Duration::from_secs(5),
                Instant::now().checked_add(Duration::from_secs(5)),
                &worker_cancel,
                |address, timeout| {
                    worker_entered.wait();
                    worker_release.wait();
                    TcpStream::connect_timeout(address, timeout)
                },
            )
        });

        entered.wait();
        let stopped_at = Instant::now();
        cancellation.store(true, Ordering::Release);
        release.wait();
        let (mut late_socket, _) = listener.accept().unwrap();
        late_socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(matches!(worker.join().unwrap(), Err(PeerError::Cancelled)));
        assert!(stopped_at.elapsed() < Duration::from_millis(500));
        let mut byte = [0_u8; 1];
        assert_eq!(late_socket.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn static_peer_configuration_requires_explicit_public_opt_in() {
        let valid = StaticPeerConfig {
            listen_address: "127.0.0.1:19000".parse().unwrap(),
            peers: vec![
                "127.0.0.1:19001".parse().unwrap(),
                "192.168.1.20:19000".parse().unwrap(),
            ],
            limits: PeerLimits::default(),
            address_policy: PeerAddressPolicy::PrivateOnly,
        };
        valid.validate().unwrap();

        let mut public = valid.clone();
        public.peers = vec!["8.8.8.8:19000".parse().unwrap()];
        assert!(matches!(
            public.validate(),
            Err(PeerError::NonPrivateAddress(_))
        ));
        public.address_policy = PeerAddressPolicy::AllowPublic;
        public.validate().unwrap();
        public.listen_address = "0.0.0.0:19000".parse().unwrap();
        assert!(matches!(
            public.validate(),
            Err(PeerError::UnsafeAddress(_))
        ));
        let mut duplicate = valid.clone();
        duplicate.peers = vec![
            "127.0.0.1:19001".parse().unwrap(),
            "127.0.0.1:19001".parse().unwrap(),
        ];
        assert!(matches!(
            duplicate.validate(),
            Err(PeerError::DuplicatePeer(_))
        ));
        let mut self_address = valid.clone();
        self_address.peers = vec![self_address.listen_address];
        self_address.validate_client_peers().unwrap();
        assert!(matches!(
            self_address.validate(),
            Err(PeerError::ConfiguredSelfAddress(_))
        ));
        let mut too_many = valid;
        too_many.limits.max_peers = 1;
        assert!(matches!(
            too_many.validate(),
            Err(PeerError::TooManyPeers { .. })
        ));

        assert!(matches!(
            PeerLimits {
                total_timeout: MAX_TOTAL_TIMEOUT + Duration::from_secs(1),
                ..PeerLimits::default()
            }
            .validate(),
            Err(PeerError::InvalidLimits)
        ));
    }

    #[test]
    fn planner_requests_only_a_surfaced_linear_candidate() {
        let local = ChainSummary {
            tip: [1; 32],
            height: 5,
            cumulative_work: work(5),
        };
        let remote = hello(2, 8, 9);
        assert_eq!(
            plan_initial_sync(local, remote, vec![local.tip]).unwrap(),
            SyncPlan::RequestInventory {
                locator: vec![local.tip],
                stop: remote.tip,
            }
        );
        assert_eq!(
            plan_inventory_sync(local, remote, &[[6; 32], [7; 32]]).unwrap(),
            SyncPlan::RequestBlock { block_id: [6; 32] }
        );

        let no_more_work = PeerHello {
            cumulative_work: local.cumulative_work,
            ..remote
        };
        assert_eq!(
            plan_initial_sync(local, no_more_work, vec![local.tip]).unwrap(),
            SyncPlan::UpToDate
        );
        let ambiguous = PeerHello {
            height: local.height,
            cumulative_work: work(10),
            ..remote
        };
        assert_eq!(
            plan_initial_sync(local, ambiguous, vec![local.tip]).unwrap(),
            SyncPlan::ForkChoiceRequired
        );
    }

    #[test]
    fn transport_rejects_oversize_before_payload_allocation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            let mut header = Vec::new();
            header.extend_from_slice(&PEER_MAGIC);
            header.extend_from_slice(&PEER_PROTOCOL_VERSION.to_le_bytes());
            header.push(BLOCK_KIND);
            header.push(0);
            header.extend_from_slice(&0_u64.to_le_bytes());
            header.extend_from_slice(&((MAX_PEER_PAYLOAD_BYTES as u32) + 1).to_le_bytes());
            stream.write_all(&header).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let session = PeerSession::new(hello(1, 1, 1), PeerLimits::default()).unwrap();
        let mut connection = PeerConnection::from_stream(stream, session).unwrap();
        assert!(matches!(
            connection.receive(),
            Err(PeerError::PayloadTooLarge { .. })
        ));
        writer.join().unwrap();
    }

    #[test]
    fn transport_applies_the_smaller_transaction_limit_before_allocation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            let mut header = Vec::new();
            header.extend_from_slice(&PEER_MAGIC);
            header.extend_from_slice(&PEER_PROTOCOL_VERSION.to_le_bytes());
            header.push(TRANSACTION_KIND);
            header.push(0);
            header.extend_from_slice(&0_u64.to_le_bytes());
            header.extend_from_slice(&((MAX_TRANSACTION_BYTES as u32) + 1).to_le_bytes());
            stream.write_all(&header).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let session = PeerSession::new(hello(1, 1, 1), PeerLimits::default()).unwrap();
        let mut connection = PeerConnection::from_stream(stream, session).unwrap();
        assert!(matches!(
            connection.receive(),
            Err(PeerError::PayloadTooLarge {
                max: MAX_TRANSACTION_BYTES,
                ..
            })
        ));
        writer.join().unwrap();
    }

    #[test]
    fn slow_drip_cannot_extend_the_absolute_connection_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            for byte in PEER_MAGIC.into_iter().cycle().take(20) {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let (stream, _) = listener.accept().unwrap();
        let limits = PeerLimits {
            idle_timeout: Duration::from_millis(60),
            total_timeout: Duration::from_millis(150),
            ..PeerLimits::default()
        };
        let session = PeerSession::new(hello(1, 1, 1), limits).unwrap();
        let error = {
            let mut connection = PeerConnection::from_stream(stream, session).unwrap();
            connection.receive().unwrap_err()
        };
        assert!(matches!(error, PeerError::TotalTimeout));
        writer.join().unwrap();
    }
}
