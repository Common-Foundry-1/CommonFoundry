//! Bitcoin-style hot wallet for exchanges (`cmfd-node exchange-wallet`).
//!
//! Every key derives from one master secret and chain code, so a single copy
//! of `wallet.json` backs up every address the wallet will ever hand out, and
//! new addresses can be derived while the wallet is encrypted and locked.
//! Chain data comes from an exchange RPC endpoint (the hosted endpoint or the
//! exchange's own node) through [`ChainSource`]; the wallet keeps only its own
//! coins, transactions and the hashes of the blocks it has scanned.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use cmfd_consensus::wire::encode_transaction;
use cmfd_consensus::{
    InputWitness, MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS, OutPoint, OutputLock,
    TRANSACTION_VERSION, Transaction, TxInput, TxOutput,
};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::{SigningKey, VerifyingKey};
use k256::{FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const WALLET_FILE: &str = "wallet.json";
pub const STATE_FILE: &str = "wallet-state.json";
pub const BLOCK_HASHES_FILE: &str = "block-hashes.bin";
const WALLET_FORMAT: &str = "cmfd-exchange-wallet-v1";
const STATE_FORMAT: &str = "cmfd-exchange-wallet-state-v1";
const DERIVATION_TAG: &[u8] = b"CommonFoundry exchange wallet key v1";
/// Unused keys scanned past the highest handed-out index, so a wallet
/// restored from an older backup still finds later deposits.
pub const KEY_LOOKAHEAD: u32 = 1_000;
/// Most recently disconnected blocks remembered for `listsinceblock`.
const ORPHAN_LIMIT: usize = 1_000;
const HASH_RECORD_BYTES: usize = 40;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
/// `walletpassphrase` timeouts are capped like Bitcoin Core's (~3 years).
pub const MAX_UNLOCK_SECONDS: u64 = 100_000_000;
const SAVE_EVERY_BLOCKS: u64 = 100;
/// Change is split so that at least this many coins stay spendable.
const KEEP_SPENDABLE_COINS: usize = 25;
/// Smallest coin produced when splitting change (1 CMFD).
const MIN_SPLIT_CHANGE: u64 = 100_000_000;
const SAVE_EVERY: Duration = Duration::from_secs(600);

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("{0}")]
    Invalid(String),
    #[error("Invalid Common Foundry address")]
    InvalidAddress,
    #[error("{0}")]
    InsufficientFunds(String),
    #[error("Error: Please enter the wallet passphrase with walletpassphrase first.")]
    Locked,
    #[error("Error: The wallet passphrase entered was incorrect.")]
    WrongPassphrase,
    #[error("{0}")]
    WrongEncryptionState(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Wallet(String),
    #[error("{operation} `{path}` failed: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("wallet file `{path}` is invalid: {reason}")]
    Corrupt { path: PathBuf, reason: String },
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> WalletError {
    WalletError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn corrupt(path: &Path, reason: impl Into<String>) -> WalletError {
    WalletError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

/// A 32-byte hash or key serialized as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct H32(pub [u8; 32]);

impl std::fmt::Display for H32 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Serialize for H32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for H32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse_h32(&text)
            .ok_or_else(|| serde::de::Error::custom("expected 64 lowercase hex characters"))
    }
}

pub fn parse_h32(text: &str) -> Option<H32> {
    let mut bytes = [0_u8; 32];
    (text.len() == 64
        && !text.bytes().any(|byte| byte.is_ascii_uppercase())
        && hex::decode_to_slice(text, &mut bytes).is_ok())
    .then_some(H32(bytes))
}

/// A Common Foundry address: 64 lowercase hex characters encoding a valid
/// x-only secp256k1 public key.
pub fn parse_address(text: &str) -> Option<[u8; 32]> {
    let address = parse_h32(text)?.0;
    VerifyingKey::from_bytes(&address).ok()?;
    Some(address)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyChain {
    Receive,
    Change,
}

impl KeyChain {
    fn byte(self) -> u8 {
        match self {
            Self::Receive => 0,
            Self::Change => 1,
        }
    }

    fn slot(self) -> usize {
        usize::from(self.byte())
    }
}

// ---------------------------------------------------------------------------
// Chain data supplied by the upstream endpoint.

#[derive(Clone, Debug)]
pub struct ChainTip {
    pub height: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct SourceBlock {
    pub hash: [u8; 32],
    pub height: u64,
    pub previous: [u8; 32],
    pub next: Option<[u8; 32]>,
    pub time: u64,
    pub active: bool,
    /// The coinbase first, then the block's transactions in order.
    pub transactions: Vec<SourceTransaction>,
}

#[derive(Clone, Debug)]
pub struct SourceTransaction {
    pub txid: [u8; 32],
    pub coinbase: bool,
    pub inputs: Vec<([u8; 32], u32)>,
    pub outputs: Vec<SourceOutput>,
    pub hex: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SourceOutput {
    pub value: u64,
    /// `None` for outputs that are not locked to a key.
    pub destination: Option<[u8; 32]>,
    pub spendable_height: u64,
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Error)]
pub enum BroadcastError {
    /// The endpoint refused the transaction for good; nobody else has it.
    #[error("{0}")]
    Rejected(String),
    /// The outcome is unknown (timeout, busy endpoint, transport failure).
    #[error("{0}")]
    Unknown(String),
}

/// Read access to the active chain plus transaction relay.
pub trait ChainSource {
    fn tip(&mut self) -> Result<ChainTip, SourceError>;
    fn block_hash(&mut self, height: u64) -> Result<Option<[u8; 32]>, SourceError>;
    fn block(&mut self, hash: [u8; 32]) -> Result<Option<SourceBlock>, SourceError>;
    fn broadcast(&mut self, transaction: &[u8]) -> Result<(), BroadcastError>;
    fn mempool_contains(&mut self, txid: [u8; 32]) -> Result<bool, SourceError>;
}

// ---------------------------------------------------------------------------
// Persistent records.

#[derive(Serialize, Deserialize)]
struct WalletFile {
    format: String,
    network_id: H32,
    created_at: u64,
    birth_height: u64,
    birth_hash: H32,
    master_public_key: String,
    chain_code: H32,
    secret: SecretFile,
    next_receive: u32,
    next_change: u32,
    #[serde(default)]
    labels: BTreeMap<u32, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SecretFile {
    Plain {
        master_secret: String,
    },
    Encrypted {
        argon2id_memory_kib: u32,
        argon2id_iterations: u32,
        argon2id_parallelism: u32,
        salt: String,
        nonce: String,
        ciphertext: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Coin {
    pub txid: H32,
    pub vout: u32,
    pub value: u64,
    pub address: H32,
    pub chain: KeyChain,
    pub index: u32,
    pub height: u64,
    pub spendable_height: u64,
    pub coinbase: bool,
    pub spent_by: Option<H32>,
    pub spent_height: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credit {
    pub vout: u32,
    pub address: H32,
    pub value: u64,
    pub chain: KeyChain,
    pub index: u32,
    pub spendable_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
    pub vout: u32,
    pub address: Option<H32>,
    pub value: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxBlock {
    pub hash: H32,
    pub height: u64,
    pub time: u64,
    pub position: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletTx {
    pub txid: H32,
    pub sequence: u64,
    pub time_received: u64,
    pub block: Option<TxBlock>,
    pub coinbase: bool,
    /// Outputs paying this wallet's keys (receive and change).
    pub credits: Vec<Credit>,
    /// This wallet's coins spent by the transaction.
    pub spends: Vec<(H32, u32)>,
    pub debit: u64,
    pub output_total: u64,
    pub input_count: usize,
    /// Outputs to other wallets; recorded only when this wallet paid.
    pub payments: Vec<Payment>,
    pub hex: Option<String>,
    /// Created by this wallet (rebroadcast until mined).
    pub ours: bool,
    pub comment: Option<String>,
    pub comment_to: Option<String>,
    pub abandoned: bool,
    pub conflicted_by: Option<H32>,
    pub consolidation: bool,
}

impl WalletTx {
    pub fn from_me(&self) -> bool {
        self.debit > 0
    }

    /// The fee, when every input belongs to this wallet.
    pub fn fee(&self) -> Option<u64> {
        (self.from_me() && self.spends.len() == self.input_count)
            .then(|| self.debit.saturating_sub(self.output_total))
    }

    fn is_pending_send(&self) -> bool {
        self.ours && self.block.is_none() && !self.abandoned && self.conflicted_by.is_none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrphanBlock {
    pub hash: H32,
    pub height: u64,
    pub previous: H32,
    pub txids: Vec<H32>,
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    format: String,
    network_id: H32,
    birth_height: u64,
    tip_height: u64,
    tip_hash: H32,
    coins: Vec<Coin>,
    txs: Vec<WalletTx>,
    orphans: Vec<OrphanBlock>,
    next_sequence: u64,
}

// ---------------------------------------------------------------------------
// Keys.

struct Keys {
    master_public: ProjectivePoint,
    master_public_bytes: [u8; 33],
    chain_code: [u8; 32],
    secret: Option<Zeroizing<[u8; 32]>>,
}

impl Keys {
    fn tweak(&self, chain: KeyChain, index: u32) -> Scalar {
        let digest = Sha256::new()
            .chain_update(DERIVATION_TAG)
            .chain_update(self.master_public_bytes)
            .chain_update(self.chain_code)
            .chain_update([chain.byte()])
            .chain_update(index.to_be_bytes())
            .finalize();
        <Scalar as Reduce<U256>>::reduce_bytes(&digest)
    }

    /// Public derivation: works without the master secret.
    fn address(&self, chain: KeyChain, index: u32) -> [u8; 32] {
        let point = (self.master_public + ProjectivePoint::GENERATOR * self.tweak(chain, index))
            .to_affine()
            .to_encoded_point(true);
        let mut address = [0_u8; 32];
        address.copy_from_slice(point.x().expect("a derived key is never the identity"));
        address
    }

    fn signing_key(&self, chain: KeyChain, index: u32) -> Result<SigningKey, WalletError> {
        let secret = self.secret.as_ref().ok_or(WalletError::Locked)?;
        let master = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(**secret)))
            .ok_or_else(|| {
                WalletError::Wallet("the master secret is not a valid key".to_owned())
            })?;
        let child: Zeroizing<[u8; 32]> =
            Zeroizing::new((master + self.tweak(chain, index)).to_bytes().into());
        SigningKey::from_bytes(child.as_ref())
            .map_err(|_| WalletError::Wallet("a derived signing key is invalid".to_owned()))
    }
}

fn public_from_secret(secret: &[u8; 32]) -> Result<(ProjectivePoint, [u8; 33]), WalletError> {
    let scalar = Option::<NonZeroScalar>::from(NonZeroScalar::from_repr(FieldBytes::from(*secret)))
        .ok_or_else(|| WalletError::Wallet("the master secret is not a valid key".to_owned()))?;
    let point = ProjectivePoint::GENERATOR * *scalar;
    let mut bytes = [0_u8; 33];
    bytes.copy_from_slice(point.to_affine().to_encoded_point(true).as_bytes());
    Ok((point, bytes))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], WalletError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|error| {
        WalletError::Wallet(format!(
            "the operating system random source failed: {error}"
        ))
    })?;
    Ok(bytes)
}

fn passphrase_key(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32)).map_err(|error| {
        WalletError::Wallet(format!("invalid key-derivation settings: {error}"))
    })?;
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|error| {
            WalletError::Wallet(format!("passphrase key derivation failed: {error}"))
        })?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// The wallet.

pub struct Balances {
    /// Confirmed spendable coins plus change from this wallet's own pending sends.
    pub trusted: u64,
    pub untrusted_pending: u64,
    pub immature: u64,
}

pub struct PreparedSend {
    pub txid: [u8; 32],
    pub transaction: Vec<u8>,
    pub fee: u64,
}

pub struct Wallet {
    dir: PathBuf,
    network_id: [u8; 32],
    file: WalletFile,
    keys: Keys,
    unlocked_until: Option<Instant>,
    lookup: HashMap<[u8; 32], (KeyChain, u32)>,
    derived: [u32; 2],
    /// Active-chain blocks from the birth block to the tip: (hash, time).
    hashes: Vec<([u8; 32], u64)>,
    hashes_file: File,
    coins: BTreeMap<(H32, u32), Coin>,
    txs: HashMap<H32, WalletTx>,
    orphans: Vec<OrphanBlock>,
    next_sequence: u64,
    dirty: bool,
    unsaved_blocks: u64,
    last_save: Instant,
}

impl Wallet {
    pub fn exists(dir: &Path) -> bool {
        dir.join(WALLET_FILE).exists()
    }

    /// Creates a new wallet whose scanning starts after `birth`.
    pub fn create(dir: &Path, network_id: [u8; 32], birth: &ChainTip) -> Result<Self, WalletError> {
        fs::create_dir_all(dir)
            .map_err(|source| io_error("create wallet directory", dir, source))?;
        let mut secret = Zeroizing::new(random_bytes::<32>()?);
        while Option::<NonZeroScalar>::from(NonZeroScalar::from_repr(FieldBytes::from(*secret)))
            .is_none()
        {
            *secret = random_bytes::<32>()?;
        }
        let (_, public) = public_from_secret(&secret)?;
        let file = WalletFile {
            format: WALLET_FORMAT.to_owned(),
            network_id: H32(network_id),
            created_at: unix_now(),
            birth_height: birth.height,
            birth_hash: H32(birth.hash),
            master_public_key: hex::encode(public),
            chain_code: H32(random_bytes::<32>()?),
            secret: SecretFile::Plain {
                master_secret: hex::encode(*secret),
            },
            next_receive: 0,
            next_change: 0,
            labels: BTreeMap::new(),
        };
        let path = dir.join(WALLET_FILE);
        if path.exists() {
            return Err(WalletError::Wallet(format!(
                "`{}` already exists",
                path.display()
            )));
        }
        write_atomically(
            &path,
            &serde_json::to_vec_pretty(&file).expect("wallet file serializes"),
        )?;
        for stale in [STATE_FILE, BLOCK_HASHES_FILE] {
            let stale = dir.join(stale);
            if stale.exists() {
                fs::remove_file(&stale)
                    .map_err(|source| io_error("remove stale wallet state", &stale, source))?;
            }
        }
        Self::open(dir, network_id)
    }

    pub fn open(dir: &Path, network_id: [u8; 32]) -> Result<Self, WalletError> {
        let path = dir.join(WALLET_FILE);
        let bytes =
            fs::read(&path).map_err(|source| io_error("read wallet file", &path, source))?;
        let file: WalletFile =
            serde_json::from_slice(&bytes).map_err(|error| corrupt(&path, error.to_string()))?;
        if file.format != WALLET_FORMAT {
            return Err(corrupt(
                &path,
                format!("unsupported format `{}`", file.format),
            ));
        }
        if file.network_id.0 != network_id {
            return Err(corrupt(
                &path,
                "the wallet belongs to a different network than this binary",
            ));
        }
        let mut public_bytes = [0_u8; 33];
        hex::decode_to_slice(&file.master_public_key, &mut public_bytes)
            .map_err(|_| corrupt(&path, "master_public_key is not 33 bytes of hex"))?;
        let master_public = PublicKey::from_sec1_bytes(&public_bytes)
            .map_err(|_| corrupt(&path, "master_public_key is not a valid key"))?
            .to_projective();
        let secret = match &file.secret {
            SecretFile::Plain { master_secret } => {
                let mut secret = Zeroizing::new([0_u8; 32]);
                hex::decode_to_slice(master_secret, secret.as_mut())
                    .map_err(|_| corrupt(&path, "master_secret is not 32 bytes of hex"))?;
                if public_from_secret(&secret)?.1 != public_bytes {
                    return Err(corrupt(
                        &path,
                        "master_secret does not match master_public_key",
                    ));
                }
                Some(secret)
            }
            SecretFile::Encrypted { .. } => None,
        };
        let keys = Keys {
            master_public,
            master_public_bytes: public_bytes,
            chain_code: file.chain_code.0,
            secret,
        };

        let hashes_path = dir.join(BLOCK_HASHES_FILE);
        let mut hashes_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&hashes_path)
            .map_err(|source| io_error("open block hash file", &hashes_path, source))?;
        let mut raw = Vec::new();
        hashes_file
            .read_to_end(&mut raw)
            .map_err(|source| io_error("read block hash file", &hashes_path, source))?;
        let mut hashes = raw
            .chunks_exact(HASH_RECORD_BYTES)
            .map(|record| {
                let mut hash = [0_u8; 32];
                hash.copy_from_slice(&record[..32]);
                let time = u64::from_le_bytes(record[32..].try_into().expect("8-byte time"));
                (hash, time)
            })
            .collect::<Vec<_>>();

        let mut wallet = Self {
            dir: dir.to_path_buf(),
            network_id,
            file,
            keys,
            unlocked_until: None,
            lookup: HashMap::new(),
            derived: [0, 0],
            hashes: Vec::new(),
            hashes_file,
            coins: BTreeMap::new(),
            txs: HashMap::new(),
            orphans: Vec::new(),
            next_sequence: 1,
            dirty: false,
            unsaved_blocks: 0,
            last_save: Instant::now(),
        };
        wallet.extend_lookahead();

        let state_path = dir.join(STATE_FILE);
        let state = match fs::read(&state_path) {
            Ok(bytes) => Some(
                serde_json::from_slice::<StateFile>(&bytes)
                    .map_err(|error| corrupt(&state_path, error.to_string()))?,
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(source) => return Err(io_error("read wallet state", &state_path, source)),
        };
        let birth = (wallet.file.birth_hash.0, 0);
        let consistent = state.as_ref().is_some_and(|state| {
            let needed = state
                .tip_height
                .checked_sub(wallet.file.birth_height)
                .map(|n| n + 1);
            state.format == STATE_FORMAT
                && state.network_id.0 == network_id
                && state.birth_height == wallet.file.birth_height
                && needed.is_some_and(|needed| {
                    let needed = usize::try_from(needed).unwrap_or(usize::MAX);
                    hashes.len() >= needed
                        && hashes.first().map(|first| first.0) == Some(birth.0)
                        && hashes[needed - 1].0 == state.tip_hash.0
                })
        });
        match state {
            Some(state) if consistent => {
                let needed = usize::try_from(state.tip_height - wallet.file.birth_height + 1)
                    .expect("checked above");
                hashes.truncate(needed);
                wallet.hashes = hashes;
                wallet.coins = state
                    .coins
                    .into_iter()
                    .map(|coin| ((coin.txid, coin.vout), coin))
                    .collect();
                wallet.txs = state.txs.into_iter().map(|tx| (tx.txid, tx)).collect();
                wallet.orphans = state.orphans;
                wallet.next_sequence = state.next_sequence;
            }
            Some(state) => {
                // The hash file lags the state (crash between writes) or does
                // not match: keep the transaction records and rescan.
                tracing::warn!(
                    "wallet block hashes do not match the saved state; rescanning from the wallet's birth block"
                );
                wallet.txs = state.txs.into_iter().map(|tx| (tx.txid, tx)).collect();
                wallet.next_sequence = state.next_sequence;
                wallet.reset_to_birth();
            }
            None => wallet.reset_to_birth(),
        }
        wallet.rewrite_hashes_file()?;
        wallet.save(true)?;
        Ok(wallet)
    }

    /// Forgets the scanned chain; transaction records stay and are
    /// re-confirmed as the rescan reaches them.
    fn reset_to_birth(&mut self) {
        self.hashes = vec![(self.file.birth_hash.0, 0)];
        self.coins.clear();
        self.orphans.clear();
        for tx in self.txs.values_mut() {
            tx.block = None;
        }
        // Received-only records reappear during the rescan; own sends keep
        // their inputs reserved until the rescan confirms them.
        self.txs.retain(|_, tx| tx.ours);
        self.dirty = true;
    }

    fn rewrite_hashes_file(&mut self) -> Result<(), WalletError> {
        let path = self.dir.join(BLOCK_HASHES_FILE);
        let mut bytes = Vec::with_capacity(self.hashes.len() * HASH_RECORD_BYTES);
        for (hash, time) in &self.hashes {
            bytes.extend_from_slice(hash);
            bytes.extend_from_slice(&time.to_le_bytes());
        }
        self.hashes_file
            .set_len(0)
            .and_then(|()| self.hashes_file.seek(io::SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| self.hashes_file.write_all(&bytes))
            .and_then(|()| self.hashes_file.sync_data())
            .map_err(|source| io_error("write block hash file", &path, source))
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn birth_height(&self) -> u64 {
        self.file.birth_height
    }

    pub fn created_at(&self) -> u64 {
        self.file.created_at
    }

    pub fn tip(&self) -> (u64, [u8; 32]) {
        let height = self.file.birth_height + self.hashes.len() as u64 - 1;
        (
            height,
            self.hashes
                .last()
                .expect("the birth block is always present")
                .0,
        )
    }

    pub fn tip_time(&self) -> u64 {
        self.hashes.last().map_or(0, |entry| entry.1)
    }

    /// Main-chain hash at `height`, if the wallet has scanned it.
    pub fn hash_at(&self, height: u64) -> Option<[u8; 32]> {
        let offset = height.checked_sub(self.file.birth_height)?;
        self.hashes
            .get(usize::try_from(offset).ok()?)
            .map(|entry| entry.0)
    }

    /// Height of a scanned main-chain block.
    pub fn height_of(&self, hash: [u8; 32]) -> Option<u64> {
        self.hashes
            .iter()
            .rposition(|entry| entry.0 == hash)
            .map(|offset| self.file.birth_height + offset as u64)
    }

    pub fn orphan(&self, hash: [u8; 32]) -> Option<&OrphanBlock> {
        self.orphans
            .iter()
            .rev()
            .find(|orphan| orphan.hash.0 == hash)
    }

    pub fn confirmations_at(&self, height: u64) -> u64 {
        self.tip().0.saturating_add(1).saturating_sub(height)
    }

    /// Bitcoin-style depth: positive in the active chain, 0 when unconfirmed,
    /// -1 when another transaction spent the same coins.
    pub fn tx_confirmations(&self, tx: &WalletTx) -> i64 {
        match (&tx.block, tx.conflicted_by) {
            (Some(block), _) => {
                i64::try_from(self.confirmations_at(block.height)).unwrap_or(i64::MAX)
            }
            (None, Some(_)) => -1,
            (None, None) => 0,
        }
    }

    pub fn is_mature(&self, spendable_height: u64) -> bool {
        self.tip().0 + 1 >= spendable_height
    }

    // -- keys and labels ----------------------------------------------------

    fn extend_lookahead(&mut self) {
        for chain in [KeyChain::Receive, KeyChain::Change] {
            let used = match chain {
                KeyChain::Receive => self.file.next_receive,
                KeyChain::Change => self.file.next_change,
            };
            let target = used.saturating_add(KEY_LOOKAHEAD);
            while self.derived[chain.slot()] < target {
                let index = self.derived[chain.slot()];
                self.lookup
                    .insert(self.keys.address(chain, index), (chain, index));
                self.derived[chain.slot()] += 1;
            }
        }
    }

    pub fn owner(&self, address: [u8; 32]) -> Option<(KeyChain, u32)> {
        self.lookup.get(&address).copied().filter(|(chain, index)| {
            // Lookahead keys count only once handed out or seen on chain.
            *index
                < match chain {
                    KeyChain::Receive => self.file.next_receive,
                    KeyChain::Change => self.file.next_change,
                }
        })
    }

    fn note_used(&mut self, chain: KeyChain, index: u32) -> Result<(), WalletError> {
        let next = match chain {
            KeyChain::Receive => &mut self.file.next_receive,
            KeyChain::Change => &mut self.file.next_change,
        };
        if index >= *next {
            *next = index + 1;
            self.extend_lookahead();
            self.write_wallet_file()?;
        }
        Ok(())
    }

    pub fn new_address(&mut self, chain: KeyChain, label: &str) -> Result<[u8; 32], WalletError> {
        let index = match chain {
            KeyChain::Receive => self.file.next_receive,
            KeyChain::Change => self.file.next_change,
        };
        let address = self.keys.address(chain, index);
        match chain {
            KeyChain::Receive => {
                self.file.next_receive += 1;
                if !label.is_empty() {
                    self.file.labels.insert(index, label.to_owned());
                }
            }
            KeyChain::Change => self.file.next_change += 1,
        }
        self.extend_lookahead();
        self.write_wallet_file()?;
        Ok(address)
    }

    pub fn label(&self, address: [u8; 32]) -> Option<&str> {
        match self.owner(address)? {
            (KeyChain::Receive, index) => {
                Some(self.file.labels.get(&index).map_or("", String::as_str))
            }
            (KeyChain::Change, _) => None,
        }
    }

    pub fn set_label(&mut self, address: [u8; 32], label: &str) -> Result<(), WalletError> {
        match self.owner(address) {
            Some((KeyChain::Receive, index)) => {
                if label.is_empty() {
                    self.file.labels.remove(&index);
                } else {
                    self.file.labels.insert(index, label.to_owned());
                }
                self.write_wallet_file()
            }
            Some((KeyChain::Change, _)) => Err(WalletError::Invalid(
                "change addresses cannot be labeled".to_owned(),
            )),
            None => Err(WalletError::Invalid(
                "Address is not in this wallet".to_owned(),
            )),
        }
    }

    /// Handed-out receive addresses with their labels, oldest first.
    pub fn receive_addresses(&self) -> Vec<([u8; 32], &str)> {
        (0..self.file.next_receive)
            .map(|index| {
                (
                    self.keys.address(KeyChain::Receive, index),
                    self.file.labels.get(&index).map_or("", String::as_str),
                )
            })
            .collect()
    }

    pub fn keypool_size(&self) -> u32 {
        KEY_LOOKAHEAD
    }

    // -- encryption -----------------------------------------------------------

    pub fn is_encrypted(&self) -> bool {
        matches!(self.file.secret, SecretFile::Encrypted { .. })
    }

    /// Unlock expiry as Unix seconds (0 when locked), for `getwalletinfo`.
    pub fn unlocked_until_unix(&mut self) -> Option<u64> {
        if !self.is_encrypted() {
            return None;
        }
        self.expire_unlock();
        Some(self.unlocked_until.map_or(0, |until| {
            unix_now() + until.saturating_duration_since(Instant::now()).as_secs()
        }))
    }

    pub fn expire_unlock(&mut self) {
        if self
            .unlocked_until
            .is_some_and(|until| Instant::now() >= until)
        {
            self.lock();
        }
    }

    fn require_unlocked(&mut self) -> Result<(), WalletError> {
        self.expire_unlock();
        if self.keys.secret.is_some() {
            Ok(())
        } else {
            Err(WalletError::Locked)
        }
    }

    pub fn can_sign(&mut self) -> bool {
        self.require_unlocked().is_ok()
    }

    fn encryption_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(160);
        aad.extend_from_slice(WALLET_FORMAT.as_bytes());
        aad.extend_from_slice(&self.network_id);
        aad.extend_from_slice(&self.keys.master_public_bytes);
        aad.extend_from_slice(&self.keys.chain_code);
        aad
    }

    fn encrypted_secret(
        &self,
        secret: &[u8; 32],
        passphrase: &[u8],
    ) -> Result<SecretFile, WalletError> {
        let salt = random_bytes::<16>()?;
        let nonce = random_bytes::<24>()?;
        let key = passphrase_key(
            passphrase,
            &salt,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )?;
        let ciphertext = XChaCha20Poly1305::new((&*key).into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: secret,
                    aad: &self.encryption_aad(),
                },
            )
            .map_err(|_| WalletError::Wallet("wallet encryption failed".to_owned()))?;
        Ok(SecretFile::Encrypted {
            argon2id_memory_kib: ARGON2_MEMORY_KIB,
            argon2id_iterations: ARGON2_ITERATIONS,
            argon2id_parallelism: ARGON2_PARALLELISM,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        })
    }

    fn decrypt_secret(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>, WalletError> {
        let SecretFile::Encrypted {
            argon2id_memory_kib,
            argon2id_iterations,
            argon2id_parallelism,
            salt,
            nonce,
            ciphertext,
        } = &self.file.secret
        else {
            return Err(WalletError::WrongEncryptionState(
                "Error: running with an unencrypted wallet, but walletpassphrase was called."
                    .to_owned(),
            ));
        };
        let path = self.dir.join(WALLET_FILE);
        let salt = hex::decode(salt).map_err(|_| corrupt(&path, "salt is not hex"))?;
        let mut nonce_bytes = [0_u8; 24];
        hex::decode_to_slice(nonce, &mut nonce_bytes)
            .map_err(|_| corrupt(&path, "nonce is not 24 bytes of hex"))?;
        let ciphertext =
            hex::decode(ciphertext).map_err(|_| corrupt(&path, "ciphertext is not hex"))?;
        let key = passphrase_key(
            passphrase,
            &salt,
            *argon2id_memory_kib,
            *argon2id_iterations,
            *argon2id_parallelism,
        )?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new((&*key).into())
                .decrypt(
                    &XNonce::from(nonce_bytes),
                    Payload {
                        msg: &ciphertext,
                        aad: &self.encryption_aad(),
                    },
                )
                .map_err(|_| WalletError::WrongPassphrase)?,
        );
        let secret: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| corrupt(&path, "decrypted secret is not 32 bytes"))?;
        let secret = Zeroizing::new(secret);
        if public_from_secret(&secret)?.1 != self.keys.master_public_bytes {
            return Err(corrupt(
                &path,
                "decrypted secret does not match master_public_key",
            ));
        }
        Ok(secret)
    }

    pub fn encrypt(&mut self, passphrase: &[u8]) -> Result<(), WalletError> {
        if passphrase.is_empty() {
            return Err(WalletError::Invalid(
                "passphrase cannot be empty".to_owned(),
            ));
        }
        let SecretFile::Plain { .. } = &self.file.secret else {
            return Err(WalletError::WrongEncryptionState(
                "Error: running with an encrypted wallet, but encryptwallet was called.".to_owned(),
            ));
        };
        let secret = self.keys.secret.take().ok_or(WalletError::Locked)?;
        self.file.secret = self.encrypted_secret(&secret, passphrase)?;
        self.unlocked_until = None;
        self.write_wallet_file()
    }

    pub fn unlock(&mut self, passphrase: &[u8], seconds: u64) -> Result<(), WalletError> {
        let secret = self.decrypt_secret(passphrase)?;
        self.keys.secret = Some(secret);
        self.unlocked_until =
            Some(Instant::now() + Duration::from_secs(seconds.min(MAX_UNLOCK_SECONDS)));
        Ok(())
    }

    pub fn lock(&mut self) {
        if self.is_encrypted() {
            self.keys.secret = None;
            self.unlocked_until = None;
        }
    }

    pub fn change_passphrase(&mut self, old: &[u8], new: &[u8]) -> Result<(), WalletError> {
        if new.is_empty() {
            return Err(WalletError::Invalid(
                "passphrase cannot be empty".to_owned(),
            ));
        }
        let secret = self.decrypt_secret(old)?;
        self.file.secret = self.encrypted_secret(&secret, new)?;
        self.write_wallet_file()
    }

    // -- chain tracking -----------------------------------------------------

    pub fn connect_block(&mut self, block: &SourceBlock) -> Result<(), WalletError> {
        let (height, hash) = self.tip();
        if block.height != height + 1 || block.previous != hash {
            return Err(WalletError::Wallet(format!(
                "block {} at height {} does not extend the wallet tip {} at height {height}",
                hex::encode(block.hash),
                block.height,
                hex::encode(hash),
            )));
        }
        let mut relevant = false;
        for (position, transaction) in block.transactions.iter().enumerate() {
            let placed = TxBlock {
                hash: H32(block.hash),
                height: block.height,
                time: block.time,
                position: u32::try_from(position).unwrap_or(u32::MAX),
            };
            relevant |= self.apply_transaction(transaction, placed)?;
        }
        self.hashes.push((block.hash, block.time));
        let path = self.dir.join(BLOCK_HASHES_FILE);
        let mut record = [0_u8; HASH_RECORD_BYTES];
        record[..32].copy_from_slice(&block.hash);
        record[32..].copy_from_slice(&block.time.to_le_bytes());
        self.hashes_file
            .seek(io::SeekFrom::End(0))
            .and_then(|_| self.hashes_file.write_all(&record))
            .map_err(|source| io_error("append block hash", &path, source))?;
        self.unsaved_blocks += 1;
        self.dirty |= relevant;
        Ok(())
    }

    fn apply_transaction(
        &mut self,
        transaction: &SourceTransaction,
        placed: TxBlock,
    ) -> Result<bool, WalletError> {
        let txid = H32(transaction.txid);
        let mut spends = Vec::new();
        let mut debit = 0_u64;
        for &(previous, vout) in &transaction.inputs {
            let key = (H32(previous), vout);
            if let Some(coin) = self.coins.get_mut(&key) {
                coin.spent_by = Some(txid);
                coin.spent_height = Some(placed.height);
                debit = debit.saturating_add(coin.value);
                spends.push(key);
            }
        }
        if !spends.is_empty() {
            let spent = spends.iter().copied().collect::<HashSet<_>>();
            for other in self.txs.values_mut() {
                if other.txid != txid
                    && other.is_pending_send()
                    && other.spends.iter().any(|input| spent.contains(input))
                {
                    tracing::warn!(
                        txid = %other.txid,
                        conflicting = %txid,
                        "a wallet transaction was replaced by a conflicting confirmed transaction"
                    );
                    other.conflicted_by = Some(txid);
                }
            }
        }

        let mut credits = Vec::new();
        let mut payments = Vec::new();
        let mut output_total = 0_u64;
        for (vout, output) in transaction.outputs.iter().enumerate() {
            let vout = u32::try_from(vout).unwrap_or(u32::MAX);
            output_total = output_total.saturating_add(output.value);
            let owner = output.destination.and_then(|destination| {
                self.lookup
                    .get(&destination)
                    .copied()
                    .map(|owner| (destination, owner))
            });
            match owner {
                Some((destination, (chain, index))) => {
                    self.note_used(chain, index)?;
                    credits.push(Credit {
                        vout,
                        address: H32(destination),
                        value: output.value,
                        chain,
                        index,
                        spendable_height: output.spendable_height,
                    });
                    self.coins.insert(
                        (txid, vout),
                        Coin {
                            txid,
                            vout,
                            value: output.value,
                            address: H32(destination),
                            chain,
                            index,
                            height: placed.height,
                            spendable_height: output.spendable_height,
                            coinbase: transaction.coinbase,
                            spent_by: None,
                            spent_height: None,
                        },
                    );
                }
                None => payments.push(Payment {
                    vout,
                    address: output.destination.map(H32),
                    value: output.value,
                }),
            }
        }
        if debit == 0 && credits.is_empty() {
            return Ok(false);
        }
        if debit == 0 {
            payments.clear();
        }
        let sequence = self.next_sequence;
        let entry = self.txs.entry(txid).or_insert_with(|| WalletTx {
            txid,
            sequence,
            time_received: unix_now(),
            block: None,
            coinbase: transaction.coinbase,
            credits: Vec::new(),
            spends: Vec::new(),
            debit: 0,
            output_total: 0,
            input_count: 0,
            payments: Vec::new(),
            hex: None,
            ours: false,
            comment: None,
            comment_to: None,
            abandoned: false,
            conflicted_by: None,
            consolidation: false,
        });
        if entry.sequence == sequence {
            self.next_sequence += 1;
        }
        entry.block = Some(placed);
        entry.coinbase = transaction.coinbase;
        entry.credits = credits;
        entry.spends = spends;
        entry.debit = debit;
        entry.output_total = output_total;
        entry.input_count = transaction.inputs.len();
        entry.payments = payments;
        entry.abandoned = false;
        entry.conflicted_by = None;
        if entry.hex.is_none() {
            entry.hex = transaction.hex.clone();
        }
        Ok(true)
    }

    /// Undoes the tip block. Its transactions stay recorded as unconfirmed.
    pub fn disconnect_tip(&mut self) -> Result<(), WalletError> {
        if self.hashes.len() <= 1 {
            return Err(WalletError::Wallet(
                "the chain reorganized below the wallet's birth block; restore the wallet into a new directory to rescan".to_owned(),
            ));
        }
        let (height, hash) = self.tip();
        self.coins.retain(|_, coin| coin.height != height);
        for coin in self.coins.values_mut() {
            if coin.spent_height == Some(height) {
                coin.spent_by = None;
                coin.spent_height = None;
            }
        }
        let mut txids = Vec::new();
        for tx in self.txs.values_mut() {
            if tx.block.as_ref().is_some_and(|block| block.hash.0 == hash) {
                tx.block = None;
                txids.push(tx.txid);
            }
        }
        txids.sort_by_key(|txid| self.txs[txid].sequence);
        // Conflicts recorded by this block no longer hold.
        for tx in self.txs.values_mut() {
            if tx.conflicted_by.is_some_and(|by| txids.contains(&by)) {
                tx.conflicted_by = None;
            }
        }
        self.hashes.pop();
        let previous = self.tip().1;
        self.orphans.push(OrphanBlock {
            hash: H32(hash),
            height,
            previous: H32(previous),
            txids,
        });
        if self.orphans.len() > ORPHAN_LIMIT {
            self.orphans.remove(0);
        }
        let path = self.dir.join(BLOCK_HASHES_FILE);
        self.hashes_file
            .set_len((self.hashes.len() * HASH_RECORD_BYTES) as u64)
            .map_err(|source| io_error("truncate block hash file", &path, source))?;
        self.dirty = true;
        Ok(())
    }

    // -- coins and balances -------------------------------------------------

    fn locked_outpoints(&self) -> HashSet<(H32, u32)> {
        self.txs
            .values()
            .filter(|tx| tx.is_pending_send())
            .flat_map(|tx| tx.spends.iter().copied())
            .collect()
    }

    /// Unspent coins with their lock state, oldest first.
    pub fn unspent_coins(&self) -> Vec<(&Coin, bool)> {
        let locked = self.locked_outpoints();
        self.coins
            .values()
            .filter(|coin| coin.spent_by.is_none())
            .map(|coin| (coin, locked.contains(&(coin.txid, coin.vout))))
            .collect()
    }

    fn spendable(&self, minimum_confirmations: u64) -> Vec<Coin> {
        self.unspent_coins()
            .into_iter()
            .filter(|(coin, locked)| {
                !locked
                    && self.is_mature(coin.spendable_height)
                    && self.confirmations_at(coin.height) >= minimum_confirmations.max(1)
            })
            .map(|(coin, _)| coin.clone())
            .collect()
    }

    pub fn balance(&self, minimum_confirmations: u64) -> u64 {
        let confirmed = self
            .spendable(minimum_confirmations)
            .iter()
            .map(|coin| coin.value)
            .sum::<u64>();
        if minimum_confirmations == 0 {
            confirmed.saturating_add(self.pending_change())
        } else {
            confirmed
        }
    }

    fn pending_change(&self) -> u64 {
        self.txs
            .values()
            .filter(|tx| tx.is_pending_send())
            .flat_map(|tx| tx.credits.iter())
            .map(|credit| credit.value)
            .sum()
    }

    pub fn balances(&self) -> Balances {
        let immature = self
            .unspent_coins()
            .into_iter()
            .filter(|(coin, _)| !self.is_mature(coin.spendable_height))
            .map(|(coin, _)| coin.value)
            .sum();
        Balances {
            trusted: self.balance(0),
            untrusted_pending: 0,
            immature,
        }
    }

    // -- transactions ---------------------------------------------------------

    pub fn tx(&self, txid: [u8; 32]) -> Option<&WalletTx> {
        self.txs.get(&H32(txid))
    }

    /// All wallet transactions in the order the wallet first saw them.
    pub fn transactions(&self) -> Vec<&WalletTx> {
        let mut txs = self.txs.values().collect::<Vec<_>>();
        txs.sort_by_key(|tx| tx.sequence);
        txs
    }

    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    /// Builds, signs and records a payment. The caller broadcasts it; the
    /// inputs stay reserved until it is mined, conflicted or abandoned.
    pub fn prepare_send(
        &mut self,
        payments: &[([u8; 32], u64)],
        subtract_fee_from: &[usize],
        minimum_confirmations: u64,
        comment: Option<String>,
        comment_to: Option<String>,
    ) -> Result<PreparedSend, WalletError> {
        self.require_unlocked()?;
        if payments.is_empty() || payments.len() > MAX_TRANSACTION_OUTPUTS - 1 {
            return Err(WalletError::Invalid(format!(
                "a payment needs 1 to {} recipients",
                MAX_TRANSACTION_OUTPUTS - 1
            )));
        }
        if payments.iter().any(|(_, value)| *value == 0) {
            return Err(WalletError::Invalid("Invalid amount for send".to_owned()));
        }
        let total = payments
            .iter()
            .try_fold(0_u64, |sum, (_, value)| sum.checked_add(*value))
            .ok_or_else(|| WalletError::Invalid("Amount out of range".to_owned()))?;
        let mut coins = self.spendable(minimum_confirmations);
        coins.sort_by(|left, right| right.value.cmp(&left.value));
        let mut fee = cmfd_consensus::economics::minimum_transaction_fee(self.network_id).max(1);
        loop {
            let needed = if subtract_fee_from.is_empty() {
                total
                    .checked_add(fee)
                    .ok_or_else(|| WalletError::Invalid("Amount out of range".to_owned()))?
            } else {
                total
            };
            let mut selected = Vec::new();
            let mut gathered = 0_u64;
            for coin in &coins {
                if gathered >= needed {
                    break;
                }
                gathered += coin.value;
                selected.push(coin.clone());
            }
            if gathered < needed {
                return Err(WalletError::InsufficientFunds(
                    self.shortfall_message(needed, gathered),
                ));
            }
            if selected.len() > MAX_TRANSACTION_INPUTS {
                return Err(WalletError::InsufficientFunds(format!(
                    "Insufficient funds in one transaction: this payment needs more than {MAX_TRANSACTION_INPUTS} of the wallet's coins. The wallet merges small coins automatically; try again after the next block, or send a smaller amount."
                )));
            }
            let mut outputs = payments.to_vec();
            if !subtract_fee_from.is_empty() {
                let share = fee / subtract_fee_from.len() as u64;
                let remainder = fee % subtract_fee_from.len() as u64;
                for (position, &index) in subtract_fee_from.iter().enumerate() {
                    let cut = share + if position == 0 { remainder } else { 0 };
                    let output = outputs.get_mut(index).ok_or_else(|| {
                        WalletError::Invalid(
                            "subtractfeefrom names an unknown recipient".to_owned(),
                        )
                    })?;
                    output.1 = output
                        .1
                        .checked_sub(cut)
                        .filter(|value| *value > 0)
                        .ok_or_else(|| {
                            WalletError::Wallet(
                                "The transaction amount is too small to pay the fee".to_owned(),
                            )
                        })?;
                }
            }
            let paid = outputs.iter().map(|output| output.1).sum::<u64>();
            let change = gathered - paid - fee;
            // Outputs cannot be spent before they confirm, so keep enough
            // separate coins for the withdrawals of the next block or so.
            let parts = if change == 0 {
                0
            } else {
                let short = KEEP_SPENDABLE_COINS.saturating_sub(coins.len() - selected.len());
                let room = MAX_TRANSACTION_OUTPUTS - outputs.len();
                (short.min(room) as u64)
                    .min(change / MIN_SPLIT_CHANGE)
                    .max(1)
            };
            let first_change = self.file.next_change;
            let mut transaction = Transaction {
                network_id: self.network_id,
                version: TRANSACTION_VERSION,
                inputs: selected
                    .iter()
                    .map(|coin| TxInput {
                        previous: OutPoint {
                            txid: coin.txid.0,
                            index: coin.vout,
                        },
                        witness: InputWitness::Key {
                            public_key: coin.address.0,
                            signature: Vec::new(),
                        },
                    })
                    .collect(),
                outputs: outputs
                    .iter()
                    .map(|&(address, value)| key_output(address, value))
                    .collect(),
            };
            for part in 0..parts {
                let share = change / parts + if part == 0 { change % parts } else { 0 };
                let index = first_change + u32::try_from(part).expect("at most 128 parts");
                transaction.outputs.push(key_output(
                    self.keys.address(KeyChain::Change, index),
                    share,
                ));
            }
            let keys = selected
                .iter()
                .map(|coin| self.keys.signing_key(coin.chain, coin.index))
                .collect::<Result<Vec<_>, _>>()?;
            let key_refs = keys.iter().collect::<Vec<_>>();
            transaction
                .sign_all(&key_refs)
                .map_err(|error| WalletError::Wallet(format!("signing failed: {error}")))?;
            let encoded = encode_transaction(&transaction).map_err(|error| {
                WalletError::Wallet(format!("the transaction cannot be encoded: {error}"))
            })?;
            let required = crate::required_relay_fee(encoded.len(), self.network_id);
            if required > fee {
                fee = required;
                continue;
            }
            if parts > 0 {
                let last = first_change + u32::try_from(parts - 1).expect("at most 128 parts");
                self.note_used(KeyChain::Change, last)?;
            }
            let txid = transaction.txid();
            self.record_send(
                txid,
                &transaction,
                &encoded,
                &selected,
                comment,
                comment_to,
                false,
            )?;
            return Ok(PreparedSend {
                txid,
                transaction: encoded,
                fee,
            });
        }
    }

    fn shortfall_message(&self, needed: u64, available: u64) -> String {
        let waiting = self.pending_change();
        if available + waiting >= needed {
            format!(
                "Insufficient funds: {} CMFD returns as change when the previous withdrawal confirms (about one minute); try again then",
                format_amount(waiting)
            )
        } else {
            "Insufficient funds".to_owned()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_send(
        &mut self,
        txid: [u8; 32],
        transaction: &Transaction,
        encoded: &[u8],
        selected: &[Coin],
        comment: Option<String>,
        comment_to: Option<String>,
        consolidation: bool,
    ) -> Result<(), WalletError> {
        let mut credits = Vec::new();
        let mut payments = Vec::new();
        for (vout, output) in transaction.outputs.iter().enumerate() {
            let vout = u32::try_from(vout).unwrap_or(u32::MAX);
            let OutputLock::Key(address) = output.lock else {
                continue;
            };
            match self.owner(address) {
                Some((chain, index)) => credits.push(Credit {
                    vout,
                    address: H32(address),
                    value: output.value,
                    chain,
                    index,
                    spendable_height: output.spendable_height,
                }),
                None => payments.push(Payment {
                    vout,
                    address: Some(H32(address)),
                    value: output.value,
                }),
            }
        }
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.txs.insert(
            H32(txid),
            WalletTx {
                txid: H32(txid),
                sequence,
                time_received: unix_now(),
                block: None,
                coinbase: false,
                credits,
                spends: selected.iter().map(|coin| (coin.txid, coin.vout)).collect(),
                debit: selected.iter().map(|coin| coin.value).sum(),
                output_total: transaction.outputs.iter().map(|output| output.value).sum(),
                input_count: transaction.inputs.len(),
                payments,
                hex: Some(hex::encode(encoded)),
                ours: true,
                comment: comment.filter(|value| !value.is_empty()),
                comment_to: comment_to.filter(|value| !value.is_empty()),
                abandoned: false,
                conflicted_by: None,
                consolidation,
            },
        );
        self.dirty = true;
        self.save(true)
    }

    /// Merges the smallest coins into one when the wallet holds more than
    /// `threshold` spendable coins, so large withdrawals stay within the
    /// per-transaction input limit.
    pub fn prepare_consolidation(
        &mut self,
        threshold: usize,
    ) -> Result<Option<PreparedSend>, WalletError> {
        if threshold == 0 || !self.can_sign() {
            return Ok(None);
        }
        if self
            .txs
            .values()
            .any(|tx| tx.consolidation && tx.is_pending_send())
        {
            return Ok(None);
        }
        let mut coins = self.spendable(1);
        if coins.len() <= threshold {
            return Ok(None);
        }
        coins.sort_by_key(|coin| coin.value);
        coins.truncate(MAX_TRANSACTION_INPUTS);
        let total = coins.iter().map(|coin| coin.value).sum::<u64>();
        let mut fee = cmfd_consensus::economics::minimum_transaction_fee(self.network_id).max(1);
        loop {
            if total <= fee.saturating_mul(2) {
                return Ok(None);
            }
            let change_index = self.file.next_change;
            let mut transaction = Transaction {
                network_id: self.network_id,
                version: TRANSACTION_VERSION,
                inputs: coins
                    .iter()
                    .map(|coin| TxInput {
                        previous: OutPoint {
                            txid: coin.txid.0,
                            index: coin.vout,
                        },
                        witness: InputWitness::Key {
                            public_key: coin.address.0,
                            signature: Vec::new(),
                        },
                    })
                    .collect(),
                outputs: vec![key_output(
                    self.keys.address(KeyChain::Change, change_index),
                    total - fee,
                )],
            };
            let keys = coins
                .iter()
                .map(|coin| self.keys.signing_key(coin.chain, coin.index))
                .collect::<Result<Vec<_>, _>>()?;
            transaction
                .sign_all(&keys.iter().collect::<Vec<_>>())
                .map_err(|error| WalletError::Wallet(format!("signing failed: {error}")))?;
            let encoded = encode_transaction(&transaction).map_err(|error| {
                WalletError::Wallet(format!("the transaction cannot be encoded: {error}"))
            })?;
            let required = crate::required_relay_fee(encoded.len(), self.network_id);
            if required > fee {
                fee = required;
                continue;
            }
            self.note_used(KeyChain::Change, change_index)?;
            let txid = transaction.txid();
            self.record_send(txid, &transaction, &encoded, &coins, None, None, true)?;
            return Ok(Some(PreparedSend {
                txid,
                transaction: encoded,
                fee,
            }));
        }
    }

    /// Drops a just-prepared send that the endpoint refused outright.
    pub fn forget_rejected(&mut self, txid: [u8; 32]) -> Result<(), WalletError> {
        if self
            .txs
            .get(&H32(txid))
            .is_some_and(|tx| tx.ours && tx.block.is_none())
        {
            self.txs.remove(&H32(txid));
            self.dirty = true;
            self.save(true)?;
        }
        Ok(())
    }

    /// Own transactions that still need to reach the network.
    pub fn pending_sends(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.transactions()
            .into_iter()
            .filter(|tx| tx.is_pending_send())
            .filter_map(|tx| Some((tx.txid.0, hex::decode(tx.hex.as_ref()?).ok()?)))
            .collect()
    }

    pub fn abandon(&mut self, txid: [u8; 32]) -> Result<(), WalletError> {
        let tx = self.txs.get_mut(&H32(txid)).ok_or_else(|| {
            WalletError::NotFound("Invalid or non-wallet transaction id".to_owned())
        })?;
        if tx.block.is_some() || tx.abandoned {
            return Err(WalletError::NotFound(
                "Transaction not eligible for abandonment".to_owned(),
            ));
        }
        tx.abandoned = true;
        self.dirty = true;
        self.save(true)
    }

    // -- persistence ----------------------------------------------------------

    fn write_wallet_file(&self) -> Result<(), WalletError> {
        let bytes = serde_json::to_vec_pretty(&self.file).expect("wallet file serializes");
        write_atomically(&self.dir.join(WALLET_FILE), &bytes)
    }

    /// Saves when something relevant changed, or periodically for the tip.
    pub fn save(&mut self, force: bool) -> Result<(), WalletError> {
        let due = self.unsaved_blocks >= SAVE_EVERY_BLOCKS
            || (self.unsaved_blocks > 0 && self.last_save.elapsed() >= SAVE_EVERY);
        if !(force || self.dirty || due) {
            return Ok(());
        }
        let hashes_path = self.dir.join(BLOCK_HASHES_FILE);
        self.hashes_file
            .sync_data()
            .map_err(|source| io_error("sync block hash file", &hashes_path, source))?;
        let (tip_height, tip_hash) = self.tip();
        let mut txs = self.txs.values().cloned().collect::<Vec<_>>();
        txs.sort_by_key(|tx| tx.sequence);
        let state = StateFile {
            format: STATE_FORMAT.to_owned(),
            network_id: H32(self.network_id),
            birth_height: self.file.birth_height,
            tip_height,
            tip_hash: H32(tip_hash),
            coins: self.coins.values().cloned().collect(),
            txs,
            orphans: self.orphans.clone(),
            next_sequence: self.next_sequence,
        };
        write_atomically(
            &self.dir.join(STATE_FILE),
            &serde_json::to_vec(&state).expect("wallet state serializes"),
        )?;
        self.dirty = false;
        self.unsaved_blocks = 0;
        self.last_save = Instant::now();
        Ok(())
    }

    /// Copies `wallet.json` (keys, counters and labels) to `destination`.
    pub fn backup(&self, destination: &Path) -> Result<PathBuf, WalletError> {
        let target = if destination.is_dir() {
            destination.join(WALLET_FILE)
        } else {
            destination.to_path_buf()
        };
        if target == self.dir.join(WALLET_FILE) {
            return Err(WalletError::Wallet(
                "the backup destination is the wallet file itself".to_owned(),
            ));
        }
        let bytes = serde_json::to_vec_pretty(&self.file).expect("wallet file serializes");
        write_atomically(&target, &bytes)?;
        Ok(target)
    }
}

pub struct SyncProgress {
    pub caught_up: bool,
    pub height: u64,
    pub upstream_height: u64,
}

fn lock(wallet: &Mutex<Wallet>) -> std::sync::MutexGuard<'_, Wallet> {
    wallet
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Follows the source's active chain for at most `max_blocks` blocks,
/// disconnecting the wallet's tip whenever the source's chain no longer
/// contains it. The wallet lock is held only while applying a block.
pub fn sync_with(
    wallet: &Mutex<Wallet>,
    source: &mut impl ChainSource,
    expected_next: &mut Option<[u8; 32]>,
    max_blocks: usize,
    stop: &dyn Fn() -> bool,
) -> Result<SyncProgress, String> {
    let upstream = source.tip().map_err(|error| error.to_string())?;
    let progress = |caught_up: bool, height: u64| SyncProgress {
        caught_up,
        height,
        upstream_height: upstream.height,
    };
    let disconnect = || -> Result<(), String> {
        let mut wallet = lock(wallet);
        let (height, hash) = wallet.tip();
        wallet.disconnect_tip().map_err(|error| error.to_string())?;
        tracing::warn!(height, block = %hex::encode(hash), "chain reorganization: disconnected the wallet's tip block");
        Ok(())
    };
    for _ in 0..max_blocks {
        let (height, hash) = lock(wallet).tip();
        if stop() {
            return Ok(progress(false, height));
        }
        if hash == upstream.hash {
            return Ok(progress(true, height));
        }
        if height >= upstream.height {
            match source
                .block_hash(height)
                .map_err(|error| error.to_string())?
            {
                Some(active) if active != hash => {
                    disconnect()?;
                    *expected_next = None;
                    continue;
                }
                // The source is behind the wallet; wait for it.
                _ => return Ok(progress(true, height)),
            }
        }
        let next = match expected_next.take() {
            Some(next) => next,
            None => match source
                .block_hash(height + 1)
                .map_err(|error| error.to_string())?
            {
                Some(next) => next,
                None => return Ok(progress(false, height)),
            },
        };
        let Some(block) = source.block(next).map_err(|error| error.to_string())? else {
            return Ok(progress(false, height));
        };
        if !block.active || block.height != height + 1 {
            return Ok(progress(false, height));
        }
        if block.previous != hash {
            disconnect()?;
            continue;
        }
        lock(wallet)
            .connect_block(&block)
            .map_err(|error| error.to_string())?;
        *expected_next = block.next;
    }
    Ok(progress(false, lock(wallet).tip().0))
}

fn key_output(destination: [u8; 32], value: u64) -> TxOutput {
    TxOutput {
        value,
        lock: OutputLock::Key(destination),
        spendable_height: 0,
    }
}

/// Writes through a temporary file, then renames over the target, so a crash
/// leaves either the old or the new contents. Owner-only on Unix.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|source| io_error("create temporary wallet file", &temporary, source))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("write temporary wallet file", &temporary, source))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|source| io_error("replace wallet file", path, source))?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error("sync wallet directory", parent, source))?;
    }
    Ok(())
}

/// Formats atoms as a decimal CMFD amount with eight decimals.
pub fn format_amount(atoms: u64) -> String {
    format!("{}.{:08}", atoms / 100_000_000, atoms % 100_000_000)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use cmfd_consensus::wire::{decode_block, decode_transaction};
    use cmfd_consensus::{Block, COINBASE_MATURITY};

    use super::*;
    use crate::{
        BLOCK_LOG_FILE, DEFAULT_MINING_ATTEMPTS, DEVNET_GENESIS_TIMESTAMP, DEVNET_PROFILE, Node,
        NodeError,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-exchange-wallet-{label}-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Serves an in-process node the way the exchange RPC does.
    struct NodeSource<'a>(&'a mut Node);

    impl ChainSource for NodeSource<'_> {
        fn tip(&mut self) -> Result<ChainTip, SourceError> {
            Ok(ChainTip {
                height: self.0.state.next_height() - 1,
                hash: self.0.state.tip(),
            })
        }

        fn block_hash(&mut self, height: u64) -> Result<Option<[u8; 32]>, SourceError> {
            Ok(self.0.active_block_id_at_height(height))
        }

        fn block(&mut self, hash: [u8; 32]) -> Result<Option<SourceBlock>, SourceError> {
            let network = self.0.params.network_id;
            let Some(bytes) = self.0.canonical_block(hash).unwrap() else {
                return Ok(None);
            };
            let block = decode_block(&bytes, network).unwrap();
            let height = block.challenge.height;
            let active = self.0.active_block_id_at_height(height) == Some(hash);
            let outputs = |outputs: &[TxOutput]| {
                outputs
                    .iter()
                    .map(|output| SourceOutput {
                        value: output.value,
                        destination: match output.lock {
                            OutputLock::Key(destination) => Some(destination),
                            _ => None,
                        },
                        spendable_height: output.spendable_height,
                    })
                    .collect()
            };
            let mut transactions = vec![SourceTransaction {
                txid: block.coinbase_outpoint_id(),
                coinbase: true,
                inputs: Vec::new(),
                outputs: outputs(&block.coinbase.outputs),
                hex: None,
            }];
            for transaction in &block.transactions {
                transactions.push(SourceTransaction {
                    txid: transaction.txid(),
                    coinbase: false,
                    inputs: transaction
                        .inputs
                        .iter()
                        .map(|input| (input.previous.txid, input.previous.index))
                        .collect(),
                    outputs: outputs(&transaction.outputs),
                    hex: Some(hex::encode(encode_transaction(transaction).unwrap())),
                });
            }
            Ok(Some(SourceBlock {
                hash,
                height,
                previous: block.challenge.previous_block,
                next: active
                    .then(|| self.0.active_block_id_at_height(height + 1))
                    .flatten(),
                time: block.challenge.timestamp,
                active,
                transactions,
            }))
        }

        fn broadcast(&mut self, transaction: &[u8]) -> Result<(), BroadcastError> {
            let transaction = decode_transaction(transaction, self.0.params.network_id)
                .map_err(|error| BroadcastError::Rejected(error.to_string()))?;
            match self.0.submit_transaction(transaction) {
                Ok(_) | Err(NodeError::DuplicateMempoolTransaction(_)) => Ok(()),
                Err(error) => Err(BroadcastError::Rejected(error.to_string())),
            }
        }

        fn mempool_contains(&mut self, txid: [u8; 32]) -> Result<bool, SourceError> {
            Ok(self.0.mempool_entries().any(|entry| entry.txid == txid))
        }
    }

    fn mine(node: &mut Node, destination: [u8; 32]) -> Block {
        let timestamp = DEVNET_GENESIS_TIMESTAMP + node.state.next_height() * 60;
        node.mine_once(destination, timestamp, DEFAULT_MINING_ATTEMPTS)
            .unwrap()
    }

    /// An empty block on `parent`, for building a competing branch.
    fn fork_block(node: &Node, parent: [u8; 32], timestamp: u64, destination: [u8; 32]) -> Block {
        let state = crate::rebuild_state_to(
            &node.log,
            &node.data_dir.join(BLOCK_LOG_FILE),
            &node.index,
            node.params,
            &node.verifier,
            parent,
            None,
        )
        .unwrap();
        let height = state.next_height();
        let allocation = node.params.monetary_policy.allocation(height, 0).unwrap();
        let coinbase = crate::Coinbase::new(height, allocation, destination, node.params.rewards);
        let challenge = crate::BlockChallenge {
            network_id: node.params.network_id,
            previous_block: parent,
            transaction_root: crate::merkle_root(&[coinbase.commitment(node.params.network_id)]),
            height,
            timestamp,
            target: state.expected_target().unwrap(),
        };
        let proof = node
            .verifier
            .mine(&challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        Block {
            version: crate::BLOCK_VERSION,
            challenge,
            proof,
            coinbase,
            transactions: Vec::new(),
        }
    }

    fn sync(wallet: &Mutex<Wallet>, node: &mut Node) {
        let mut next = None;
        loop {
            let progress =
                sync_with(wallet, &mut NodeSource(node), &mut next, 1_000, &|| false).unwrap();
            if progress.caught_up {
                return;
            }
        }
    }

    fn tip_of(node: &Node) -> ChainTip {
        ChainTip {
            height: node.state.next_height() - 1,
            hash: node.state.tip(),
        }
    }

    fn outside_address() -> [u8; 32] {
        let key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        key.verifying_key().to_bytes().into()
    }

    #[test]
    fn derived_addresses_match_their_signing_keys_and_survive_encryption() {
        let node_dir = TestDirectory::new("keys-node");
        let wallet_dir = TestDirectory::new("keys");
        let node = Node::open_with_profile(&node_dir.0, DEVNET_PROFILE).unwrap();
        let network = node.params.network_id;
        let mut wallet = Wallet::create(&wallet_dir.0, network, &tip_of(&node)).unwrap();
        for chain in [KeyChain::Receive, KeyChain::Change] {
            for index in [0, 1, 7, 999] {
                let key = wallet.keys.signing_key(chain, index).unwrap();
                let signer: [u8; 32] = key.verifying_key().to_bytes().into();
                assert_eq!(wallet.keys.address(chain, index), signer);
            }
        }
        let first = wallet.new_address(KeyChain::Receive, "alice").unwrap();
        assert_eq!(wallet.owner(first), Some((KeyChain::Receive, 0)));
        assert_eq!(wallet.label(first), Some("alice"));
        assert!(
            wallet
                .owner(wallet.keys.address(KeyChain::Receive, 1))
                .is_none()
        );

        wallet.encrypt(b"correct horse").unwrap();
        assert!(matches!(
            wallet.keys.signing_key(KeyChain::Receive, 0),
            Err(WalletError::Locked)
        ));
        // Addresses still derive while locked, and match after unlocking.
        let second = wallet.new_address(KeyChain::Receive, "").unwrap();
        assert!(matches!(
            wallet.unlock(b"wrong", 60),
            Err(WalletError::WrongPassphrase)
        ));
        wallet.unlock(b"correct horse", 60).unwrap();
        let key = wallet.keys.signing_key(KeyChain::Receive, 1).unwrap();
        assert_eq!(<[u8; 32]>::from(key.verifying_key().to_bytes()), second);
        wallet
            .change_passphrase(b"correct horse", b"battery staple")
            .unwrap();
        wallet.lock();
        drop(wallet);

        let mut reopened = Wallet::open(&wallet_dir.0, network).unwrap();
        assert!(reopened.is_encrypted());
        assert_eq!(reopened.receive_addresses().len(), 2);
        assert!(reopened.unlock(b"correct horse", 60).is_err());
        reopened.unlock(b"battery staple", 60).unwrap();
        assert!(reopened.can_sign());
    }

    #[test]
    fn wallet_receives_spends_follows_reorganizations_and_reopens() {
        let node_dir = TestDirectory::new("flow-node");
        let wallet_dir = TestDirectory::new("flow");
        let mut node = Node::open_with_profile(&node_dir.0, DEVNET_PROFILE).unwrap();
        let network = node.params.network_id;
        let miner = node.wallet_destination();
        let customer = outside_address();
        let wallet = Mutex::new(Wallet::create(&wallet_dir.0, network, &tip_of(&node)).unwrap());
        let deposit_address = lock(&wallet)
            .new_address(KeyChain::Receive, "user-1")
            .unwrap();

        // A coinbase paid to the wallet is immature for 100 blocks.
        let funding = mine(&mut node, deposit_address);
        let reward = funding.coinbase.outputs[0].value;
        sync(&wallet, &mut node);
        {
            let wallet = lock(&wallet);
            assert_eq!(wallet.balances().immature, reward);
            assert_eq!(wallet.balance(1), 0);
            let tx = wallet.tx(funding.coinbase_outpoint_id()).unwrap();
            assert!(tx.coinbase);
            assert_eq!(wallet.tx_confirmations(tx), 1);
        }
        for _ in 0..COINBASE_MATURITY {
            mine(&mut node, miner);
        }
        sync(&wallet, &mut node);
        assert_eq!(lock(&wallet).balance(1), reward);

        // Pay a customer; the change returns to a fresh change key.
        let prepared = lock(&wallet)
            .prepare_send(
                &[(customer, 100_000_000)],
                &[],
                1,
                Some("withdrawal 7".into()),
                None,
            )
            .unwrap();
        NodeSource(&mut node)
            .broadcast(&prepared.transaction)
            .unwrap();
        {
            let wallet = lock(&wallet);
            assert_eq!(wallet.balance(1), 0, "the spent coin is reserved");
            assert_eq!(wallet.balance(0), reward - 100_000_000 - prepared.fee);
            assert_eq!(wallet.pending_sends().len(), 1);
        }
        let mined = mine(&mut node, miner);
        assert_eq!(mined.transactions.len(), 1);
        sync(&wallet, &mut node);
        let confirmed_height = {
            let wallet = lock(&wallet);
            let tx = wallet.tx(prepared.txid).unwrap();
            assert_eq!(wallet.tx_confirmations(tx), 1);
            assert_eq!(tx.fee(), Some(prepared.fee));
            assert_eq!(tx.payments.len(), 1);
            assert_eq!(tx.payments[0].value, 100_000_000);
            // The only coin was spent, so the change is split for throughput.
            assert_eq!(tx.credits.len(), KEEP_SPENDABLE_COINS);
            assert!(
                tx.credits
                    .iter()
                    .all(|credit| credit.chain == KeyChain::Change)
            );
            assert_eq!(wallet.spendable(1).len(), KEEP_SPENDABLE_COINS);
            assert_eq!(tx.comment.as_deref(), Some("withdrawal 7"));
            assert!(wallet.pending_sends().is_empty());
            assert_eq!(wallet.balance(1), reward - 100_000_000 - prepared.fee);
            tx.block.as_ref().unwrap().height
        };

        // A longer branch without the payment replaces its block.
        let fork_parent = node
            .active_block_id_at_height(confirmed_height - 1)
            .unwrap();
        let base = DEVNET_GENESIS_TIMESTAMP + confirmed_height * 60 + 7;
        let first = fork_block(&node, fork_parent, base, outside_address());
        node.submit_block(first.clone(), base).unwrap();
        let second = fork_block(&node, first.block_id(), base + 60, outside_address());
        node.submit_block(second, base + 60).unwrap();
        sync(&wallet, &mut node);
        {
            let wallet = lock(&wallet);
            let tx = wallet.tx(prepared.txid).unwrap();
            assert!(tx.block.is_none());
            assert_eq!(wallet.tx_confirmations(tx), 0);
            assert!(wallet.orphan(mined.block_id()).is_some());
            assert_eq!(
                wallet.height_of(node.state.tip()),
                Some(confirmed_height + 1)
            );
            assert_eq!(wallet.pending_sends().len(), 1);
            assert_eq!(wallet.balance(1), 0, "the original coin is reserved again");
        }
        // The wallet rebroadcasts; the payment confirms on the new branch.
        for (_, transaction) in lock(&wallet).pending_sends() {
            NodeSource(&mut node).broadcast(&transaction).unwrap();
        }
        mine(&mut node, miner);
        sync(&wallet, &mut node);
        {
            let wallet = lock(&wallet);
            let tx = wallet.tx(prepared.txid).unwrap();
            assert_eq!(tx.block.as_ref().unwrap().height, confirmed_height + 2);
            assert_eq!(wallet.balance(1), reward - 100_000_000 - prepared.fee);
        }

        // After a crash the wallet resumes from its last save and rescans.
        let (height, hash) = lock(&wallet).tip();
        drop(wallet);
        let reopened = Mutex::new(Wallet::open(&wallet_dir.0, network).unwrap());
        assert!(lock(&reopened).tip().0 < height);
        sync(&reopened, &mut node);
        {
            let wallet = lock(&reopened);
            assert_eq!(wallet.tip(), (height, hash));
            assert_eq!(wallet.balance(1), reward - 100_000_000 - prepared.fee);
            assert_eq!(wallet.label(deposit_address), Some("user-1"));
            assert_eq!(wallet.tx_count(), 2);
            assert!(wallet.pending_sends().is_empty());
        }
        // A clean shutdown saves the tip.
        lock(&reopened).save(true).unwrap();
        drop(reopened);
        let reopened = Wallet::open(&wallet_dir.0, network).unwrap();
        assert_eq!(reopened.tip(), (height, hash));
        assert_eq!(reopened.balance(1), reward - 100_000_000 - prepared.fee);
    }

    #[test]
    fn restore_from_backup_rescans_and_finds_later_addresses() {
        let node_dir = TestDirectory::new("restore-node");
        let wallet_dir = TestDirectory::new("restore");
        let restored_dir = TestDirectory::new("restored");
        let mut node = Node::open_with_profile(&node_dir.0, DEVNET_PROFILE).unwrap();
        let network = node.params.network_id;
        let wallet = Mutex::new(Wallet::create(&wallet_dir.0, network, &tip_of(&node)).unwrap());
        // Back up before handing out the address that later receives funds.
        let backup = lock(&wallet).backup(&restored_dir.0).unwrap();
        let later = lock(&wallet).new_address(KeyChain::Receive, "").unwrap();
        let funding = mine(&mut node, later);
        let miner = node.wallet_destination();
        mine(&mut node, miner);
        sync(&wallet, &mut node);
        assert_eq!(backup, restored_dir.0.join(WALLET_FILE));

        let restored = Mutex::new(Wallet::open(&restored_dir.0, network).unwrap());
        assert_eq!(lock(&restored).tip().0, 0);
        sync(&restored, &mut node);
        let restored = restored.into_inner().unwrap();
        assert_eq!(restored.owner(later), Some((KeyChain::Receive, 0)));
        assert!(restored.tx(funding.coinbase_outpoint_id()).is_some());
        assert_eq!(
            restored.balances().immature,
            funding.coinbase.outputs[0].value
        );
    }

    #[test]
    fn sends_respect_locks_limits_and_merge_small_coins() {
        let node_dir = TestDirectory::new("limits-node");
        let wallet_dir = TestDirectory::new("limits");
        let mut node = Node::open_with_profile(&node_dir.0, DEVNET_PROFILE).unwrap();
        let network = node.params.network_id;
        let miner = node.wallet_destination();
        let wallet = Mutex::new(Wallet::create(&wallet_dir.0, network, &tip_of(&node)).unwrap());
        let funding_address = lock(&wallet).new_address(KeyChain::Receive, "").unwrap();
        mine(&mut node, funding_address);
        for _ in 0..COINBASE_MATURITY {
            mine(&mut node, miner);
        }
        sync(&wallet, &mut node);

        // Split the reward into 254 small coins paid to the wallet itself.
        for round in 0..2 {
            let recipients = (0..127)
                .map(|_| {
                    (
                        lock(&wallet).new_address(KeyChain::Receive, "").unwrap(),
                        1_000_000,
                    )
                })
                .collect::<Vec<_>>();
            let prepared = lock(&wallet)
                .prepare_send(&recipients, &[], 1, None, None)
                .unwrap();
            NodeSource(&mut node)
                .broadcast(&prepared.transaction)
                .unwrap();
            if round == 0 {
                // The second split must wait for the first one's change.
                assert!(matches!(
                    lock(&wallet).prepare_send(&recipients, &[], 1, None, None),
                    Err(WalletError::InsufficientFunds(message)) if message.contains("change")
                ));
            }
            mine(&mut node, miner);
            sync(&wallet, &mut node);
        }
        assert_eq!(lock(&wallet).spendable(1).len(), 255);

        // Reserve the big change coin so only the 254 small coins remain.
        let outside = outside_address();
        let big = lock(&wallet)
            .spendable(1)
            .into_iter()
            .map(|coin| coin.value)
            .max()
            .unwrap();
        let reserve = lock(&wallet)
            .prepare_send(&[(outside, big - 1)], &[], 1, None, None)
            .unwrap();
        NodeSource(&mut node)
            .broadcast(&reserve.transaction)
            .unwrap();
        // 200 coins' worth needs more than 128 inputs.
        let large = 200 * 1_000_000;
        assert!(matches!(
            lock(&wallet).prepare_send(&[(outside, large)], &[], 1, None, None),
            Err(WalletError::InsufficientFunds(message)) if message.contains("128")
        ));
        mine(&mut node, miner);
        sync(&wallet, &mut node);
        let merge = lock(&wallet).prepare_consolidation(200).unwrap().unwrap();
        NodeSource(&mut node).broadcast(&merge.transaction).unwrap();
        assert!(lock(&wallet).prepare_consolidation(200).unwrap().is_none());
        mine(&mut node, miner);
        sync(&wallet, &mut node);
        assert_eq!(lock(&wallet).spendable(1).len(), 254 - 128 + 1);
        let paid = lock(&wallet)
            .prepare_send(&[(outside, large)], &[], 1, None, None)
            .unwrap();
        NodeSource(&mut node).broadcast(&paid.transaction).unwrap();
        mine(&mut node, miner);
        sync(&wallet, &mut node);
        {
            let wallet = lock(&wallet);
            assert_eq!(wallet.tx_confirmations(wallet.tx(paid.txid).unwrap()), 1);
        }

        // A locked wallet can neither sign nor merge.
        lock(&wallet).encrypt(b"passphrase").unwrap();
        assert!(matches!(
            lock(&wallet).prepare_send(&[(outside, 1)], &[], 1, None, None),
            Err(WalletError::Locked)
        ));
        assert!(lock(&wallet).prepare_consolidation(1).unwrap().is_none());
    }
}
