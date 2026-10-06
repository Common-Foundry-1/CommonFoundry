//! Bitcoin Core-compatible JSON-RPC daemon for exchanges.
//!
//! Exchanges point their existing Bitcoin wallet integration
//! (`getnewaddress`, `listsinceblock`, `gettransaction`, `sendtoaddress`,
//! `walletpassphrase`, ...) at this daemon. It keeps the exchange's keys on the
//! exchange's server and reads the chain from an exchange RPC endpoint, so the
//! exchange never stores the chain.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::exchange_wallet::{
    BroadcastError, ChainSource, KeyChain, Wallet, WalletError, WalletTx, format_amount,
    parse_address, parse_h32, sync_with,
};
use crate::exchange_wallet_upstream::{CallError, Endpoint, Upstream};

pub const CONFIG_FILE: &str = "cmfd-wallet.conf";
pub const DEFAULT_RPC_PORT: u16 = 39_120;
const MIN_RPC_PASSWORD_CHARS: usize = 16;
const DEFAULT_CONSOLIDATE_THRESHOLD: usize = 200;
const MAX_CONNECTIONS: usize = 16;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCKS_PER_ROUND: usize = 200;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const REBROADCAST_INTERVAL: Duration = Duration::from_secs(120);
const CONNECTED_WITHIN: Duration = Duration::from_secs(120);

// Bitcoin Core RPC error codes.
const RPC_MISC_ERROR: i64 = -1;
const RPC_TYPE_ERROR: i64 = -3;
const RPC_WALLET_ERROR: i64 = -4;
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;
const RPC_WALLET_INSUFFICIENT_FUNDS: i64 = -6;
const RPC_INVALID_PARAMETER: i64 = -8;
const RPC_CLIENT_NOT_CONNECTED: i64 = -9;
const RPC_WALLET_INVALID_LABEL_NAME: i64 = -11;
const RPC_WALLET_UNLOCK_NEEDED: i64 = -13;
const RPC_WALLET_PASSPHRASE_INCORRECT: i64 = -14;
const RPC_WALLET_WRONG_ENC_STATE: i64 = -15;
const RPC_DATABASE_ERROR: i64 = -20;
const RPC_VERIFY_REJECTED: i64 = -26;
const RPC_VERIFY_ALREADY_IN_CHAIN: i64 = -27;
const RPC_METHOD_DEPRECATED: i64 = -32;
const RPC_INVALID_REQUEST: i64 = -32600;
const RPC_METHOD_NOT_FOUND: i64 = -32601;
const RPC_PARSE_ERROR: i64 = -32700;

// ---------------------------------------------------------------------------
// Configuration (bitcoin.conf style).

pub struct WalletConfig {
    rpc_user: String,
    rpc_password: Zeroizing<String>,
    rpc_bind: IpAddr,
    rpc_port: u16,
    rpc_allow: Vec<(IpAddr, u8)>,
    upstream: String,
    upstream_user: String,
    upstream_password: Zeroizing<String>,
    consolidate_threshold: usize,
}

impl WalletConfig {
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read `{}`: {error}", path.display()))?,
        );
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut settings = HashMap::<&str, Zeroizing<String>>::new();
        let mut rpc_allow = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected key=value", number + 1))?;
            let (key, value) = (key.trim(), value.trim());
            match key {
                "rpcallowip" => {
                    rpc_allow.push(parse_allowed_network(value).ok_or_else(|| {
                        format!("line {}: invalid rpcallowip `{value}`", number + 1)
                    })?)
                }
                "rpcuser"
                | "rpcpassword"
                | "rpcbind"
                | "rpcport"
                | "upstream"
                | "upstreamuser"
                | "upstreampassword"
                | "consolidatethreshold" => {
                    if settings
                        .insert(key, Zeroizing::new(value.to_owned()))
                        .is_some()
                    {
                        return Err(format!("line {}: `{key}` is set twice", number + 1));
                    }
                }
                other => return Err(format!("line {}: unknown setting `{other}`", number + 1)),
            }
        }
        let mut required = |key: &str| {
            settings
                .remove(key)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("`{key}` is required"))
        };
        let rpc_user = required("rpcuser")?.to_string();
        let rpc_password = required("rpcpassword")?;
        let upstream = required("upstream")?.to_string();
        let upstream_user = required("upstreamuser")?.to_string();
        let upstream_password = required("upstreampassword")?;
        if rpc_user.contains(':') {
            return Err("rpcuser cannot contain `:`".to_owned());
        }
        if rpc_password.chars().count() < MIN_RPC_PASSWORD_CHARS {
            return Err(format!(
                "rpcpassword must be at least {MIN_RPC_PASSWORD_CHARS} characters"
            ));
        }
        let rpc_bind = match settings.remove("rpcbind") {
            Some(value) => value
                .parse::<IpAddr>()
                .map_err(|_| format!("rpcbind `{}` is not an IP address", value.as_str()))?,
            None => IpAddr::from([127, 0, 0, 1]),
        };
        let rpc_port = match settings.remove("rpcport") {
            Some(value) => value
                .parse::<u16>()
                .map_err(|_| format!("rpcport `{}` is invalid", value.as_str()))?,
            None => DEFAULT_RPC_PORT,
        };
        let consolidate_threshold = match settings.remove("consolidatethreshold") {
            Some(value) => value
                .parse::<usize>()
                .map_err(|_| format!("consolidatethreshold `{}` is invalid", value.as_str()))?,
            None => DEFAULT_CONSOLIDATE_THRESHOLD,
        };
        if !rpc_bind.is_loopback() && rpc_allow.is_empty() {
            return Err(
                "rpcbind is not a loopback address; add rpcallowip=<address or network> for each host that may connect".to_owned(),
            );
        }
        Ok(Self {
            rpc_user,
            rpc_password,
            rpc_bind,
            rpc_port,
            rpc_allow,
            upstream,
            upstream_user,
            upstream_password,
            consolidate_threshold,
        })
    }

    fn allows(&self, address: IpAddr) -> bool {
        let address = match address {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
            v4 => v4,
        };
        address.is_loopback()
            || self
                .rpc_allow
                .iter()
                .any(|&(network, prefix)| in_network(address, network, prefix))
    }
}

fn parse_allowed_network(value: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let address = address.parse::<IpAddr>().ok()?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse::<u8>()
            .ok()
            .filter(|prefix| *prefix <= width)?,
        None => width,
    };
    Some((address, prefix))
}

fn in_network(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    fn masked(bytes: &[u8], prefix: u8) -> Vec<u8> {
        bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                let bits = (u32::from(prefix)).saturating_sub(index as u32 * 8).min(8);
                if bits == 0 {
                    0
                } else {
                    byte & (0xff_u8 << (8 - bits))
                }
            })
            .collect()
    }
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) => {
            masked(&address.octets(), prefix) == masked(&network.octets(), prefix)
        }
        (IpAddr::V6(address), IpAddr::V6(network)) => {
            masked(&address.octets(), prefix) == masked(&network.octets(), prefix)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Errors, amounts and parameters.

#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<WalletError> for RpcError {
    fn from(error: WalletError) -> Self {
        let code = match &error {
            WalletError::Invalid(_) => RPC_INVALID_PARAMETER,
            WalletError::InvalidAddress | WalletError::NotFound(_) => RPC_INVALID_ADDRESS_OR_KEY,
            WalletError::InsufficientFunds(_) => RPC_WALLET_INSUFFICIENT_FUNDS,
            WalletError::Locked => RPC_WALLET_UNLOCK_NEEDED,
            WalletError::WrongPassphrase => RPC_WALLET_PASSPHRASE_INCORRECT,
            WalletError::WrongEncryptionState(_) => RPC_WALLET_WRONG_ENC_STATE,
            WalletError::Wallet(_) => RPC_WALLET_ERROR,
            WalletError::Io { .. } | WalletError::Corrupt { .. } => RPC_DATABASE_ERROR,
        };
        Self::new(code, error.to_string())
    }
}

fn amount_marker() -> &'static str {
    static MARKER: OnceLock<String> = OnceLock::new();
    MARKER.get_or_init(|| {
        let mut nonce = [0_u8; 12];
        let _ = getrandom::fill(&mut nonce);
        format!("\u{0}cmfd-amount-{}:", hex::encode(nonce))
    })
}

/// A JSON number with exactly eight decimals, like Bitcoin Core's amounts.
fn amount(atoms: u64) -> Value {
    Value::String(format!("{}{}", amount_marker(), format_amount(atoms)))
}

fn signed_amount(atoms: i128) -> Value {
    let magnitude = u64::try_from(atoms.unsigned_abs()).unwrap_or(u64::MAX);
    let sign = if atoms < 0 { "-" } else { "" };
    Value::String(format!(
        "{}{sign}{}",
        amount_marker(),
        format_amount(magnitude)
    ))
}

/// Serializes `value`, turning amount markers into bare decimal numbers.
fn render(value: &Value) -> String {
    let text = value.to_string();
    let escaped = serde_json::to_string(amount_marker()).expect("marker serializes");
    let needle = &escaped[..escaped.len() - 1];
    let mut rendered = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(start) = rest.find(needle) {
        rendered.push_str(&rest[..start]);
        let after = &rest[start + needle.len()..];
        let end = after
            .find('"')
            .expect("amount marker strings are terminated");
        rendered.push_str(&after[..end]);
        rest = &after[end + 1..];
    }
    rendered.push_str(rest);
    rendered
}

/// Parses a JSON number or numeric string with at most eight decimals,
/// exactly (Bitcoin Core's ParseFixedPoint).
fn parse_amount(raw: &str) -> Result<u64, RpcError> {
    let invalid = || RpcError::new(RPC_TYPE_ERROR, "Invalid amount");
    let raw = raw.trim();
    let owned;
    let text = if raw.starts_with('"') {
        owned = serde_json::from_str::<String>(raw).map_err(|_| invalid())?;
        owned.as_str()
    } else {
        raw
    };
    if text.starts_with('-') {
        return Err(RpcError::new(RPC_TYPE_ERROR, "Amount out of range"));
    }
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(position) => (
            &text[..position],
            text[position + 1..].parse::<i32>().map_err(|_| invalid())?,
        ),
        None => (text, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if (whole.is_empty() && fraction.is_empty())
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
        || !(-40..=40).contains(&exponent)
    {
        return Err(invalid());
    }
    let digits = format!("{whole}{fraction}");
    let digits = digits.trim_start_matches('0');
    let scale = 8 + exponent - fraction.len() as i32;
    let value = if scale >= 0 {
        if digits.len() + scale as usize > 38 {
            return Err(RpcError::new(RPC_TYPE_ERROR, "Amount out of range"));
        }
        format!("{digits}{}", "0".repeat(scale as usize))
    } else {
        let cut = digits.len().saturating_sub((-scale) as usize);
        if digits[cut..].bytes().any(|byte| byte != b'0') {
            return Err(invalid());
        }
        digits[..cut].to_owned()
    };
    if value.is_empty() {
        return Ok(0);
    }
    value
        .parse::<u64>()
        .map_err(|_| RpcError::new(RPC_TYPE_ERROR, "Amount out of range"))
}

struct Params {
    values: Vec<Option<Box<RawValue>>>,
}

fn missing(name: &str) -> RpcError {
    RpcError::new(
        RPC_MISC_ERROR,
        format!("missing required parameter `{name}`"),
    )
}

fn wrong_type(name: &str, expected: &str) -> RpcError {
    RpcError::new(
        RPC_TYPE_ERROR,
        format!("JSON value for `{name}` is not of expected type {expected}"),
    )
}

impl Params {
    fn parse(raw: Option<&RawValue>, names: &[&str]) -> Result<Self, RpcError> {
        let Some(raw) = raw else {
            return Ok(Self { values: Vec::new() });
        };
        let text = raw.get().trim_start();
        let present = |value: Box<RawValue>| (value.get() != "null").then_some(value);
        let values = if text.starts_with('[') {
            let items = serde_json::from_str::<Vec<Box<RawValue>>>(raw.get()).map_err(|_| {
                RpcError::new(RPC_INVALID_REQUEST, "Params must be an array or object")
            })?;
            if items.len() > names.len() {
                return Err(RpcError::new(
                    RPC_MISC_ERROR,
                    format!("too many parameters (at most {})", names.len()),
                ));
            }
            items.into_iter().map(present).collect()
        } else if text.starts_with('{') {
            let named = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(raw.get())
                .map_err(|_| {
                    RpcError::new(RPC_INVALID_REQUEST, "Params must be an array or object")
                })?;
            let mut values = vec![None; names.len()];
            for (key, value) in named {
                let position = names.iter().position(|name| *name == key).ok_or_else(|| {
                    RpcError::new(
                        RPC_INVALID_PARAMETER,
                        format!("Unknown named parameter {key}"),
                    )
                })?;
                values[position] = present(value);
            }
            values
        } else if text.starts_with("null") {
            Vec::new()
        } else {
            return Err(RpcError::new(
                RPC_INVALID_REQUEST,
                "Params must be an array or object",
            ));
        };
        Ok(Self { values })
    }

    fn raw(&self, index: usize) -> Option<&RawValue> {
        self.values.get(index).and_then(Option::as_deref)
    }

    fn typed<T: serde::de::DeserializeOwned>(
        &self,
        index: usize,
        name: &str,
        expected: &str,
    ) -> Result<Option<T>, RpcError> {
        self.raw(index)
            .map(|raw| serde_json::from_str::<T>(raw.get()).map_err(|_| wrong_type(name, expected)))
            .transpose()
    }

    fn string(&self, index: usize, name: &str) -> Result<Option<String>, RpcError> {
        self.typed(index, name, "string")
    }

    fn secret(&self, index: usize, name: &str) -> Result<Zeroizing<String>, RpcError> {
        self.string(index, name)?
            .map(Zeroizing::new)
            .ok_or_else(|| missing(name))
    }

    fn required_string(&self, index: usize, name: &str) -> Result<String, RpcError> {
        self.string(index, name)?.ok_or_else(|| missing(name))
    }

    fn integer(&self, index: usize, name: &str) -> Result<Option<i64>, RpcError> {
        self.typed(index, name, "integer")
    }

    fn count(&self, index: usize, name: &str, default: u64) -> Result<u64, RpcError> {
        match self.integer(index, name)? {
            None => Ok(default),
            Some(value) => u64::try_from(value).map_err(|_| {
                RpcError::new(
                    RPC_INVALID_PARAMETER,
                    format!("`{name}` cannot be negative"),
                )
            }),
        }
    }

    fn boolean(&self, index: usize, name: &str) -> Result<Option<bool>, RpcError> {
        self.typed(index, name, "bool")
    }

    /// Booleans or 0/1/2, as Bitcoin Core accepts for verbosity flags.
    fn verbosity(&self, index: usize, name: &str, default: u64) -> Result<u64, RpcError> {
        match self.raw(index).map(RawValue::get) {
            None => Ok(default),
            Some("true") => Ok(1),
            Some("false") => Ok(0),
            Some(_) => self.count(index, name, default),
        }
    }

    fn amount(&self, index: usize) -> Result<Option<u64>, RpcError> {
        self.raw(index)
            .map(|raw| parse_amount(raw.get()))
            .transpose()
    }

    fn hash(&self, index: usize, name: &str) -> Result<[u8; 32], RpcError> {
        let text = self.required_string(index, name)?;
        parse_h32(&text).map(|hash| hash.0).ok_or_else(|| {
            RpcError::new(
                RPC_INVALID_PARAMETER,
                format!("{name} must be 64 lowercase hexadecimal characters"),
            )
        })
    }
}

fn param_names(method: &str) -> Option<&'static [&'static str]> {
    Some(match method {
        "abandontransaction" => &["txid"],
        "backupwallet" => &["destination"],
        "encryptwallet" => &["passphrase"],
        "estimatesmartfee" => &["conf_target", "estimate_mode"],
        "getaddressesbylabel" => &["label"],
        "getaddressinfo" => &["address"],
        "getbalance" => &["dummy", "minconf", "include_watchonly", "avoid_reuse"],
        "getbalances"
        | "getbestblockhash"
        | "getblockchaininfo"
        | "getblockcount"
        | "getconnectioncount"
        | "getdifficulty"
        | "getinfo"
        | "getnetworkinfo"
        | "getunconfirmedbalance"
        | "getwalletinfo"
        | "listwallets"
        | "ping"
        | "stop"
        | "uptime"
        | "walletlock" => &[],
        "getblock" => &["blockhash", "verbosity"],
        "getblockhash" => &["height"],
        "getnewaddress" => &["label", "address_type"],
        "getrawchangeaddress" => &["address_type"],
        "getrawmempool" => &["verbose", "mempool_sequence"],
        "getrawtransaction" => &["txid", "verbose", "blockhash"],
        "getreceivedbyaddress" => &["address", "minconf", "include_immature_coinbase"],
        "gettransaction" => &["txid", "include_watchonly", "verbose"],
        "help" => &["command"],
        "keypoolrefill" => &["newsize"],
        "listlabels" => &["purpose"],
        "listreceivedbyaddress" => &[
            "minconf",
            "include_empty",
            "include_watchonly",
            "address_filter",
            "include_immature_coinbase",
        ],
        "listsinceblock" => &[
            "blockhash",
            "target_confirmations",
            "include_watchonly",
            "include_removed",
            "include_change",
            "label",
        ],
        "listtransactions" => &["label", "count", "skip", "include_watchonly"],
        "listunspent" => &[
            "minconf",
            "maxconf",
            "addresses",
            "include_unsafe",
            "query_options",
        ],
        "sendmany" => &[
            "dummy",
            "amounts",
            "minconf",
            "comment",
            "subtractfeefrom",
            "replaceable",
            "conf_target",
            "estimate_mode",
            "fee_rate",
            "verbose",
        ],
        "sendrawtransaction" => &["hexstring", "maxfeerate", "maxburnamount"],
        "sendtoaddress" => &[
            "address",
            "amount",
            "comment",
            "comment_to",
            "subtractfeefromamount",
            "replaceable",
            "conf_target",
            "estimate_mode",
            "avoid_reuse",
            "fee_rate",
            "verbose",
        ],
        "setlabel" => &["address", "label"],
        "settxfee" => &["amount"],
        "validateaddress" => &["address"],
        "walletpassphrase" => &["passphrase", "timeout"],
        "walletpassphrasechange" => &["oldpassphrase", "newpassphrase"],
        _ => return None,
    })
}

const HELP: &str = "Common Foundry exchange wallet (Bitcoin Core-compatible JSON-RPC)

== Blockchain ==
getbestblockhash, getblock \"blockhash\" ( verbosity 1|2 ), getblockchaininfo,
getblockcount, getblockhash height, getdifficulty, getrawmempool ( verbose )

== Network and control ==
getconnectioncount, getinfo, getnetworkinfo, help ( \"command\" ), ping, stop, uptime

== Raw transactions ==
getrawtransaction \"txid\" ( verbose ), sendrawtransaction \"hexstring\"

== Wallet ==
abandontransaction \"txid\", backupwallet \"destination\", encryptwallet \"passphrase\",
estimatesmartfee conf_target, getaddressesbylabel \"label\", getaddressinfo \"address\",
getbalance ( \"*\" minconf ), getbalances, getnewaddress ( \"label\" ), getrawchangeaddress,
getreceivedbyaddress \"address\" ( minconf ), gettransaction \"txid\", getunconfirmedbalance,
getwalletinfo, keypoolrefill, listlabels, listreceivedbyaddress ( minconf include_empty ),
listsinceblock ( \"blockhash\" target_confirmations include_watchonly include_removed ),
listtransactions ( \"label\" count skip ), listunspent ( minconf maxconf [\"address\",...] ),
listwallets, sendmany \"\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] ),
sendtoaddress \"address\" amount ( \"comment\" \"comment_to\" subtractfeefromamount ),
setlabel \"address\" \"label\", settxfee amount, validateaddress \"address\",
walletlock, walletpassphrase \"passphrase\" timeout,
walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"

Addresses are 64 lowercase hexadecimal characters. Amounts are CMFD with eight
decimals. Every transaction pays the network's minimum fee; fee settings are
accepted and ignored. Outputs spend once confirmed (1 block).";

// ---------------------------------------------------------------------------
// Daemon state.

#[derive(Default)]
struct SyncStatus {
    headers: u64,
    last_error: Option<String>,
    scanning_since: Option<(Instant, u64)>,
}

struct Context {
    wallet: Mutex<Wallet>,
    source: Mutex<Upstream>,
    endpoint: Endpoint,
    status: Mutex<SyncStatus>,
    stop: AtomicBool,
    started: Instant,
    config: WalletConfig,
    chain: String,
    pay_tx_fee: Mutex<u64>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Context {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn connections(&self) -> u32 {
        u32::from(
            self.endpoint
                .last_success()
                .is_some_and(|at| at.elapsed() < CONNECTED_WITHIN),
        )
    }

    fn minimum_fee(&self) -> u64 {
        cmfd_consensus::economics::minimum_transaction_fee(lock(&self.wallet).network_id())
    }
}

/// Runs the wallet daemon until `stop` or Ctrl-C.
pub fn run(
    wallet_dir: &Path,
    config_path: &Path,
    network_id: [u8; 32],
    network_name: &str,
) -> Result<(), String> {
    let config = WalletConfig::read(config_path)?;
    let endpoint = Endpoint::new(
        &config.upstream,
        &config.upstream_user,
        &config.upstream_password,
        network_id,
    )?;
    let mut sync_source = Upstream::new(endpoint.clone());
    let wallet = if Wallet::exists(wallet_dir) {
        let wallet = Wallet::open(wallet_dir, network_id).map_err(|error| error.to_string())?;
        tracing::info!(
            dir = %wallet_dir.display(),
            height = wallet.tip().0,
            "opened exchange wallet"
        );
        wallet
    } else {
        let tip = sync_source
            .tip()
            .map_err(|error| format!("creating a wallet needs the upstream endpoint: {error}"))?;
        let wallet =
            Wallet::create(wallet_dir, network_id, &tip).map_err(|error| error.to_string())?;
        tracing::warn!(
            file = %wallet_dir.join(crate::exchange_wallet::WALLET_FILE).display(),
            "created a new exchange wallet; back up wallet.json now (backupwallet or a file copy) - it holds the only copy of the keys"
        );
        wallet
    };
    let listener = TcpListener::bind((config.rpc_bind, config.rpc_port)).map_err(|error| {
        format!(
            "cannot listen on {}:{}: {error}",
            config.rpc_bind, config.rpc_port
        )
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("cannot configure the RPC listener: {error}"))?;
    let chain = if network_name.eq_ignore_ascii_case("mainnet") {
        "main".to_owned()
    } else {
        network_name.to_ascii_lowercase()
    };
    let context = Arc::new(Context {
        wallet: Mutex::new(wallet),
        source: Mutex::new(Upstream::new(endpoint.clone())),
        endpoint,
        status: Mutex::new(SyncStatus::default()),
        stop: AtomicBool::new(false),
        started: Instant::now(),
        config,
        chain,
        pay_tx_fee: Mutex::new(0),
    });
    {
        let context = Arc::clone(&context);
        ctrlc::set_handler(move || context.stop.store(true, Ordering::SeqCst))
            .map_err(|error| format!("cannot install the shutdown handler: {error}"))?;
    }
    tracing::info!(
        bind = %context.config.rpc_bind,
        port = context.config.rpc_port,
        upstream = %context.config.upstream,
        "exchange wallet RPC is listening"
    );
    let server = {
        let context = Arc::clone(&context);
        std::thread::Builder::new()
            .name("cmfd-wallet-rpc".to_owned())
            .spawn(move || serve(&listener, &context))
            .map_err(|error| format!("cannot start the RPC server: {error}"))?
    };
    let sync = {
        let context = Arc::clone(&context);
        std::thread::Builder::new()
            .name("cmfd-wallet-sync".to_owned())
            .spawn(move || sync_loop(&context, sync_source))
            .map_err(|error| format!("cannot start chain synchronization: {error}"))?
    };
    while !context.stopping() {
        std::thread::sleep(Duration::from_millis(200));
    }
    tracing::info!("exchange wallet stopping");
    let _ = sync.join();
    let _ = server.join();
    lock(&context.wallet)
        .save(true)
        .map_err(|error| format!("saving the wallet failed: {error}"))
}

// ---------------------------------------------------------------------------
// Chain synchronization.

fn sleep_unless_stopped(context: &Context, duration: Duration) {
    let until = Instant::now() + duration;
    while !context.stopping() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(200).min(until - Instant::now()));
    }
}

fn sync_loop(context: &Context, mut source: Upstream) {
    let mut expected_next = None;
    let mut rebroadcast_at = HashMap::new();
    let mut last_logged: Option<Instant> = None;
    while !context.stopping() {
        let outcome = sync_round(context, &mut source, &mut expected_next);
        let caught_up = matches!(outcome, Ok(true));
        let pause = match outcome {
            Ok(true) => {
                let mut status = lock(&context.status);
                status.last_error = None;
                status.scanning_since = None;
                POLL_INTERVAL
            }
            Ok(false) => Duration::ZERO,
            Err(message) => {
                if last_logged.is_none_or(|at| at.elapsed() >= Duration::from_secs(60)) {
                    tracing::warn!(error = %message, "chain synchronization failed; retrying");
                    last_logged = Some(Instant::now());
                }
                lock(&context.status).last_error = Some(message);
                RETRY_INTERVAL
            }
        };
        maintenance(context, &mut source, &mut rebroadcast_at, caught_up);
        sleep_unless_stopped(context, pause);
    }
    if let Err(error) = lock(&context.wallet).save(true) {
        tracing::error!(%error, "saving the wallet failed");
    }
}

/// Follows the endpoint's active chain; `Ok(true)` once at its tip.
fn sync_round(
    context: &Context,
    source: &mut impl ChainSource,
    expected_next: &mut Option<[u8; 32]>,
) -> Result<bool, String> {
    let progress = sync_with(
        &context.wallet,
        source,
        expected_next,
        BLOCKS_PER_ROUND,
        &|| context.stopping(),
    )?;
    let mut status = lock(&context.status);
    status.headers = progress.upstream_height;
    if !progress.caught_up {
        status
            .scanning_since
            .get_or_insert((Instant::now(), progress.height));
    }
    Ok(progress.caught_up)
}

fn maintenance(
    context: &Context,
    source: &mut impl ChainSource,
    rebroadcast_at: &mut HashMap<[u8; 32], Instant>,
    caught_up: bool,
) {
    let (pending, consolidation) = {
        let mut wallet = lock(&context.wallet);
        wallet.expire_unlock();
        if let Err(error) = wallet.save(false) {
            tracing::error!(%error, "saving the wallet failed");
        }
        let consolidation = if caught_up {
            wallet
                .prepare_consolidation(context.config.consolidate_threshold)
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "merging small coins failed");
                    None
                })
        } else {
            None
        };
        (wallet.pending_sends(), consolidation)
    };
    let now = Instant::now();
    if let Some(prepared) = consolidation {
        rebroadcast_at.insert(prepared.txid, now);
        match source.broadcast(&prepared.transaction) {
            Ok(()) => tracing::info!(
                txid = %hex::encode(prepared.txid),
                "merged small coins into one (the wallet holds more than consolidatethreshold coins)"
            ),
            Err(BroadcastError::Rejected(message)) => {
                tracing::warn!(%message, "the endpoint refused a coin merge");
                if let Err(error) = lock(&context.wallet).forget_rejected(prepared.txid) {
                    tracing::error!(%error, "saving the wallet failed");
                }
            }
            Err(BroadcastError::Unknown(message)) => {
                tracing::warn!(%message, "coin merge broadcast outcome unknown; it will be retried");
            }
        }
    }
    rebroadcast_at.retain(|txid, _| pending.iter().any(|(pending, _)| pending == txid));
    for (txid, transaction) in pending {
        if rebroadcast_at
            .get(&txid)
            .is_some_and(|at| now.duration_since(*at) < REBROADCAST_INTERVAL)
        {
            continue;
        }
        rebroadcast_at.insert(txid, now);
        if let Err(BroadcastError::Rejected(message)) = source.broadcast(&transaction) {
            tracing::warn!(txid = %hex::encode(txid), %message, "the endpoint refused a pending wallet transaction");
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP server.

fn serve(listener: &TcpListener, context: &Arc<Context>) {
    let active = Arc::new(AtomicUsize::new(0));
    while !context.stopping() {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !context.config.allows(peer.ip()) {
                    tracing::warn!(peer = %peer, "refused an RPC connection from an address outside rpcallowip");
                    let _ = write_response(&mut stream, 403, "Forbidden", "", false);
                    continue;
                }
                if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                    let _ = write_response(&mut stream, 503, "Service Unavailable", "", false);
                    continue;
                }
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let worker_context = Arc::clone(context);
                let worker_active = Arc::clone(&active);
                let spawned = std::thread::Builder::new()
                    .name("cmfd-wallet-rpc-request".to_owned())
                    .spawn(move || {
                        handle_connection(stream, &worker_context);
                        worker_active.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    active.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                tracing::warn!(%error, "accepting an RPC connection failed");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

struct HttpRequest {
    method: String,
    authorization: Option<Zeroizing<String>>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, (u16, &'static str)> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if bytes.len() > MAX_HEADER_BYTES {
            return Err((431, "Request Header Fields Too Large"));
        }
        let mut chunk = [0_u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err((400, "Bad Request")),
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end - 4]).map_err(|_| (400, "Bad Request"))?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or_default().to_owned();
    let _target = request_line.next().ok_or((400, "Bad Request"))?;
    if !matches!(request_line.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err((400, "Bad Request"));
    }
    let mut length = None;
    let mut authorization = None;
    let mut expect_continue = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err((400, "Bad Request"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse::<usize>().map_err(|_| (400, "Bad Request"))?);
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(Zeroizing::new(value.to_owned()));
        } else if name.eq_ignore_ascii_case("expect") {
            expect_continue = value.eq_ignore_ascii_case("100-continue");
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err((501, "Not Implemented"));
        }
    }
    let length = match (method.as_str(), length) {
        ("POST", None) => return Err((411, "Length Required")),
        (_, length) => length.unwrap_or(0),
    };
    if length > MAX_BODY_BYTES {
        return Err((413, "Payload Too Large"));
    }
    let mut body = bytes[header_end..].to_vec();
    if body.len() > length {
        return Err((400, "Bad Request"));
    }
    if expect_continue && body.len() < length {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|_| (400, "Bad Request"))?;
    }
    let start = body.len();
    body.resize(length, 0);
    stream
        .read_exact(&mut body[start..])
        .map_err(|_| (400, "Bad Request"))?;
    Ok(HttpRequest {
        method,
        authorization,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    challenge: bool,
) -> io::Result<()> {
    let challenge = if challenge {
        "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
    } else {
        ""
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{challenge}\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn authorized(config: &WalletConfig, header: Option<&str>) -> bool {
    let Some(token) = header.and_then(|header| {
        let (scheme, token) = header.split_once(' ')?;
        scheme.eq_ignore_ascii_case("basic").then_some(token.trim())
    }) else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) else {
        return false;
    };
    let decoded = Zeroizing::new(decoded);
    let expected = Zeroizing::new(format!(
        "{}:{}",
        config.rpc_user,
        config.rpc_password.as_str()
    ));
    decoded.len() == expected.len()
        && decoded
            .iter()
            .zip(expected.as_bytes())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn handle_connection(mut stream: TcpStream, context: &Context) {
    let _ = stream.set_read_timeout(Some(CONNECTION_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONNECTION_TIMEOUT));
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err((status, reason)) => {
            let _ = write_response(&mut stream, status, reason, "", false);
            return;
        }
    };
    if !authorized(
        &context.config,
        request.authorization.as_ref().map(|value| value.as_str()),
    ) {
        std::thread::sleep(Duration::from_millis(250));
        let _ = write_response(&mut stream, 401, "Unauthorized", "", true);
        return;
    }
    if request.method != "POST" {
        let _ = write_response(&mut stream, 405, "Method Not Allowed", "", false);
        return;
    }
    let (status, body) = process(context, &request.body);
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let _ = write_response(&mut stream, status, reason, &body, false);
}

fn error_document(version_two: bool, id: Value, error: RpcError) -> Value {
    let error = json!({ "code": error.code, "message": error.message });
    if version_two {
        json!({ "jsonrpc": "2.0", "error": error, "id": id })
    } else {
        json!({ "result": Value::Null, "error": error, "id": id })
    }
}

fn process(context: &Context, body: &[u8]) -> (u16, String) {
    let parse_error = || {
        (
            500,
            render(&error_document(
                false,
                Value::Null,
                RpcError::new(RPC_PARSE_ERROR, "Parse error"),
            )),
        )
    };
    let Ok(text) = std::str::from_utf8(body) else {
        return parse_error();
    };
    if text.trim_start().starts_with('[') {
        let Ok(items) = serde_json::from_str::<Vec<&RawValue>>(text) else {
            return parse_error();
        };
        let responses = items
            .into_iter()
            .filter_map(|item| handle_one(context, item).1)
            .collect::<Vec<_>>();
        return (200, render(&Value::Array(responses)));
    }
    let Ok(item) = serde_json::from_str::<&RawValue>(text) else {
        return parse_error();
    };
    match handle_one(context, item) {
        (status, Some(document)) => (status, render(&document)),
        (_, None) => (204, String::new()),
    }
}

fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct WireRequest<'a> {
    #[serde(default)]
    jsonrpc: Option<Value>,
    #[serde(default)]
    method: Option<Value>,
    #[serde(default, borrow)]
    params: Option<&'a RawValue>,
    #[serde(default, deserialize_with = "present")]
    id: Option<Value>,
}

fn handle_one(context: &Context, raw: &RawValue) -> (u16, Option<Value>) {
    let Ok(request) = serde_json::from_str::<WireRequest<'_>>(raw.get()) else {
        return (
            400,
            Some(error_document(
                false,
                Value::Null,
                RpcError::new(RPC_INVALID_REQUEST, "Invalid Request object"),
            )),
        );
    };
    let version_two = request.jsonrpc.as_ref().and_then(Value::as_str) == Some("2.0");
    let id = request.id.clone().unwrap_or(Value::Null);
    let Some(method) = request.method.as_ref().and_then(Value::as_str) else {
        return (
            400,
            Some(error_document(
                version_two,
                id,
                RpcError::new(RPC_INVALID_REQUEST, "Method must be a string"),
            )),
        );
    };
    tracing::debug!(method, "wallet RPC");
    let result = call(context, method, request.params);
    if version_two && request.id.is_none() {
        return (204, None);
    }
    match result {
        Ok(result) if version_two => (
            200,
            Some(json!({ "jsonrpc": "2.0", "result": result, "id": id })),
        ),
        Ok(result) => (
            200,
            Some(json!({ "result": result, "error": Value::Null, "id": id })),
        ),
        Err(error) => {
            let status = match error.code {
                _ if version_two => 200,
                RPC_INVALID_REQUEST => 400,
                RPC_METHOD_NOT_FOUND => 404,
                _ => 500,
            };
            (status, Some(error_document(version_two, id, error)))
        }
    }
}

// ---------------------------------------------------------------------------
// Methods.

fn call(context: &Context, method: &str, raw: Option<&RawValue>) -> Result<Value, RpcError> {
    let names = param_names(method)
        .ok_or_else(|| RpcError::new(RPC_METHOD_NOT_FOUND, "Method not found"))?;
    let params = Params::parse(raw, names)?;
    let wallet = || lock(&context.wallet);
    match method {
        "help" => Ok(json!(HELP)),
        "ping" => Ok(Value::Null),
        "uptime" => Ok(json!(context.started.elapsed().as_secs())),
        "stop" => {
            context.stop.store(true, Ordering::SeqCst);
            Ok(json!("Common Foundry exchange wallet stopping"))
        }
        "getblockcount" => Ok(json!(wallet().tip().0)),
        "getbestblockhash" => Ok(json!(hex::encode(wallet().tip().1))),
        "getdifficulty" => Ok(json!(0)),
        "getconnectioncount" => Ok(json!(context.connections())),
        "getblockchaininfo" => Ok(blockchain_info(context)),
        "getnetworkinfo" => Ok(network_info(context)),
        "getinfo" => Ok(legacy_info(context)),
        "listwallets" => Ok(json!([""])),
        "getblockhash" => {
            let height = params
                .integer(0, "height")?
                .ok_or_else(|| missing("height"))?;
            let height = u64::try_from(height)
                .map_err(|_| RpcError::new(RPC_INVALID_PARAMETER, "Block height out of range"))?;
            if let Some(hash) = wallet().hash_at(height) {
                return Ok(json!(hex::encode(hash)));
            }
            match lock(&context.source).block_hash(height) {
                Ok(Some(hash)) => Ok(json!(hex::encode(hash))),
                Ok(None) => Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    "Block height out of range",
                )),
                Err(error) => Err(RpcError::new(RPC_CLIENT_NOT_CONNECTED, error.to_string())),
            }
        }
        "getblock" => {
            let hash = params.hash(0, "blockhash")?;
            let verbosity = params.verbosity(1, "verbosity", 1)?;
            if verbosity == 0 || verbosity > 2 {
                return Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    "verbosity must be 1 or 2 (raw blocks carry a 12 MB proof and are not served)",
                ));
            }
            forward(
                context,
                "getblock",
                json!([hex::encode(hash), verbosity]),
                "Block not found",
            )
        }
        "getrawmempool" => {
            let verbose = params.verbosity(0, "verbose", 0)? > 0;
            forward(
                context,
                "getrawmempool",
                json!([verbose]),
                "Mempool is not available",
            )
        }
        "getrawtransaction" => {
            let txid = params.hash(0, "txid")?;
            let verbose = params.verbosity(1, "verbose", 0)? > 0;
            if !verbose && let Some(hex) = wallet().tx(txid).and_then(|tx| tx.hex.clone()) {
                return Ok(json!(hex));
            }
            let document = forward(
                context,
                "getrawtransaction",
                json!([hex::encode(txid)]),
                "No such mempool or blockchain transaction",
            )?;
            if verbose {
                Ok(document)
            } else {
                Ok(document.get("hex").cloned().unwrap_or(Value::Null))
            }
        }
        "sendrawtransaction" => {
            let transaction = params.required_string(0, "hexstring")?;
            match lock(&context.source).call("sendrawtransaction", json!([transaction])) {
                Ok(txid) => Ok(txid),
                Err(CallError::Rpc {
                    data_code, message, ..
                }) => Err(RpcError::new(
                    if data_code.as_deref() == Some("transaction_already_confirmed") {
                        RPC_VERIFY_ALREADY_IN_CHAIN
                    } else {
                        RPC_VERIFY_REJECTED
                    },
                    message,
                )),
                Err(error) => Err(RpcError::new(RPC_CLIENT_NOT_CONNECTED, error.to_string())),
            }
        }
        "estimatesmartfee" => {
            let target = params
                .integer(0, "conf_target")?
                .ok_or_else(|| missing("conf_target"))?;
            if target < 1 {
                return Err(RpcError::new(RPC_INVALID_PARAMETER, "Invalid conf_target"));
            }
            Ok(json!({ "feerate": amount(context.minimum_fee()), "blocks": target }))
        }
        "settxfee" => {
            *lock(&context.pay_tx_fee) = params.amount(0)?.ok_or_else(|| missing("amount"))?;
            Ok(json!(true))
        }
        "getwalletinfo" => Ok(wallet_info(context)),
        "getbalance" => {
            if params.string(0, "dummy")?.is_some_and(|dummy| dummy != "*") {
                return Err(RpcError::new(
                    RPC_METHOD_DEPRECATED,
                    "dummy first argument must be excluded or set to \"*\".",
                ));
            }
            let minimum = params.count(1, "minconf", 0)?;
            Ok(amount(wallet().balance(minimum)))
        }
        "getunconfirmedbalance" => Ok(amount(0)),
        "getbalances" => {
            let balances = wallet().balances();
            Ok(json!({ "mine": {
                "trusted": amount(balances.trusted),
                "untrusted_pending": amount(balances.untrusted_pending),
                "immature": amount(balances.immature),
            }}))
        }
        "getnewaddress" => {
            let label = params.string(0, "label")?.unwrap_or_default();
            check_label(&label)?;
            Ok(json!(hex::encode(
                wallet().new_address(KeyChain::Receive, &label)?
            )))
        }
        "getrawchangeaddress" => Ok(json!(hex::encode(
            wallet().new_address(KeyChain::Change, "")?
        ))),
        "keypoolrefill" => Ok(Value::Null),
        "validateaddress" => {
            let text = params.required_string(0, "address")?;
            Ok(match parse_address(&text) {
                Some(address) => json!({
                    "isvalid": true,
                    "address": text,
                    "isscript": false,
                    "iswitness": false,
                    "ismine": wallet().owner(address).is_some(),
                    "iswatchonly": false,
                }),
                None => json!({
                    "isvalid": false,
                    "error": "Invalid address: expected 64 lowercase hexadecimal characters encoding an x-only public key",
                }),
            })
        }
        "getaddressinfo" => {
            let text = params.required_string(0, "address")?;
            let address = parse_address(&text)
                .ok_or_else(|| RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address"))?;
            let wallet = wallet();
            let owner = wallet.owner(address);
            let mut info = json!({
                "address": text,
                "pubkey": text,
                "ismine": owner.is_some(),
                "solvable": owner.is_some(),
                "iswatchonly": false,
                "isscript": false,
                "iswitness": false,
                "ischange": matches!(owner, Some((KeyChain::Change, _))),
                "labels": [],
            });
            if let Some((chain, index)) = owner {
                let label = wallet.label(address).unwrap_or_default();
                info["hdkeypath"] =
                    json!(format!("m/{}/{index}", u8::from(chain == KeyChain::Change)));
                info["timestamp"] = json!(wallet.created_at());
                if chain == KeyChain::Receive {
                    info["label"] = json!(label);
                    info["labels"] = json!([label]);
                }
            }
            Ok(info)
        }
        "setlabel" => {
            let address = address_param(&params, 0)?;
            let label = params.required_string(1, "label")?;
            check_label(&label)?;
            wallet()
                .set_label(address, &label)
                .map_err(|error| match error {
                    WalletError::Invalid(message) => {
                        RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, message)
                    }
                    other => other.into(),
                })?;
            Ok(Value::Null)
        }
        "getaddressesbylabel" => {
            let label = params.required_string(0, "label")?;
            let wallet = wallet();
            let addresses = wallet
                .receive_addresses()
                .into_iter()
                .filter(|(_, address_label)| *address_label == label)
                .map(|(address, _)| (hex::encode(address), json!({ "purpose": "receive" })))
                .collect::<Map<_, _>>();
            if addresses.is_empty() {
                return Err(RpcError::new(
                    RPC_WALLET_INVALID_LABEL_NAME,
                    format!("No addresses with label {label}"),
                ));
            }
            Ok(Value::Object(addresses))
        }
        "listlabels" => {
            let wallet = wallet();
            let labels = wallet
                .receive_addresses()
                .into_iter()
                .map(|(_, label)| label.to_owned())
                .collect::<BTreeSet<_>>();
            Ok(json!(labels))
        }
        "listunspent" => list_unspent(context, &params),
        "listtransactions" => list_transactions(context, &params),
        "listsinceblock" => list_since_block(context, &params),
        "gettransaction" => get_transaction(context, &params),
        "getreceivedbyaddress" => {
            let address = address_param(&params, 0)?;
            let minimum = params.count(1, "minconf", 1)?;
            let wallet = wallet();
            if !matches!(wallet.owner(address), Some((KeyChain::Receive, _))) {
                return Err(RpcError::new(
                    RPC_WALLET_ERROR,
                    "Address not found in wallet",
                ));
            }
            let received = received_by_address(&wallet, minimum)
                .remove(&address)
                .map_or(0, |entry| entry.0);
            Ok(amount(received))
        }
        "listreceivedbyaddress" => {
            let minimum = params.count(0, "minconf", 1)?;
            let include_empty = params.boolean(1, "include_empty")?.unwrap_or(false);
            let filter = match params.string(3, "address_filter")? {
                Some(text) => Some(parse_address(&text).ok_or_else(|| {
                    RpcError::new(RPC_WALLET_ERROR, "address_filter parameter was invalid")
                })?),
                None => None,
            };
            let wallet = wallet();
            let mut received = received_by_address(&wallet, minimum);
            let rows = wallet
                .receive_addresses()
                .into_iter()
                .filter(|(address, _)| filter.is_none_or(|filter| filter == *address))
                .filter_map(|(address, label)| {
                    let (total, confirmations, txids) =
                        received.remove(&address).unwrap_or((0, 0, Vec::new()));
                    (total > 0 || include_empty).then(|| {
                        json!({
                            "address": hex::encode(address),
                            "amount": amount(total),
                            "confirmations": confirmations,
                            "label": label,
                            "txids": txids,
                        })
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!(rows))
        }
        "sendtoaddress" => {
            let address = address_param(&params, 0)?;
            let value = params.amount(1)?.ok_or_else(|| missing("amount"))?;
            if value == 0 {
                return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid amount for send"));
            }
            let comment = comment_param(&params, 2, "comment")?;
            let comment_to = comment_param(&params, 3, "comment_to")?;
            let subtract = params.boolean(4, "subtractfeefromamount")?.unwrap_or(false);
            let verbose = params.boolean(10, "verbose")?.unwrap_or(false);
            let subtract_from: &[usize] = if subtract { &[0] } else { &[] };
            let txid = send(
                context,
                &[(address, value)],
                subtract_from,
                1,
                comment,
                comment_to,
            )?;
            Ok(sent(txid, verbose))
        }
        "sendmany" => {
            if params
                .string(0, "dummy")?
                .is_some_and(|dummy| !dummy.is_empty())
            {
                return Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    "Dummy value must be set to \"\"",
                ));
            }
            let raw = params.raw(1).ok_or_else(|| missing("amounts"))?;
            let amounts = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(raw.get())
                .map_err(|_| wrong_type("amounts", "object"))?;
            if amounts.is_empty() {
                return Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    "Transaction must have at least one recipient",
                ));
            }
            let mut payments = Vec::with_capacity(amounts.len());
            for (text, raw) in &amounts {
                let address = parse_address(text).ok_or_else(|| {
                    RpcError::new(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        format!("Invalid Common Foundry address: {text}"),
                    )
                })?;
                let value = parse_amount(raw.get())?;
                if value == 0 {
                    return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid amount for send"));
                }
                payments.push((address, value));
            }
            let minimum = params.count(2, "minconf", 1)?;
            let comment = comment_param(&params, 3, "comment")?;
            let subtract_from = params
                .typed::<Vec<String>>(4, "subtractfeefrom", "array")?
                .unwrap_or_default()
                .into_iter()
                .map(|text| {
                    amounts.keys().position(|key| *key == text).ok_or_else(|| {
                        RpcError::new(
                            RPC_INVALID_PARAMETER,
                            format!("Invalid parameter for 'subtract fee from output', address not among the recipients: {text}"),
                        )
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()?
                .into_iter()
                .collect::<Vec<_>>();
            let verbose = params.boolean(9, "verbose")?.unwrap_or(false);
            let txid = send(context, &payments, &subtract_from, minimum, comment, None)?;
            Ok(sent(txid, verbose))
        }
        "abandontransaction" => {
            let txid = params.hash(0, "txid")?;
            {
                let wallet = wallet();
                let tx = wallet.tx(txid).ok_or_else(|| {
                    RpcError::new(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Invalid or non-wallet transaction id",
                    )
                })?;
                if tx.block.is_some() || tx.abandoned {
                    return Err(RpcError::new(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Transaction not eligible for abandonment",
                    ));
                }
            }
            let in_mempool = lock(&context.source)
                .mempool_contains(txid)
                .map_err(|error| RpcError::new(RPC_CLIENT_NOT_CONNECTED, error.to_string()))?;
            if in_mempool {
                return Err(RpcError::new(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    "Transaction not eligible for abandonment: it is in the endpoint's mempool",
                ));
            }
            wallet().abandon(txid)?;
            Ok(Value::Null)
        }
        "encryptwallet" => {
            let passphrase = params.secret(0, "passphrase")?;
            wallet().encrypt(passphrase.as_bytes())?;
            Ok(json!(
                "wallet encrypted; back up wallet.json again with backupwallet - backups made before encryption still hold the unencrypted key"
            ))
        }
        "walletpassphrase" => {
            let passphrase = params.secret(0, "passphrase")?;
            let timeout = params
                .integer(1, "timeout")?
                .ok_or_else(|| missing("timeout"))?;
            let timeout = u64::try_from(timeout)
                .map_err(|_| RpcError::new(RPC_INVALID_PARAMETER, "Timeout cannot be negative."))?;
            wallet().unlock(passphrase.as_bytes(), timeout)?;
            Ok(Value::Null)
        }
        "walletlock" => {
            let mut wallet = wallet();
            if !wallet.is_encrypted() {
                return Err(RpcError::new(
                    RPC_WALLET_WRONG_ENC_STATE,
                    "Error: running with an unencrypted wallet, but walletlock was called.",
                ));
            }
            wallet.lock();
            Ok(Value::Null)
        }
        "walletpassphrasechange" => {
            let old = params.secret(0, "oldpassphrase")?;
            let new = params.secret(1, "newpassphrase")?;
            let mut wallet = wallet();
            if !wallet.is_encrypted() {
                return Err(RpcError::new(
                    RPC_WALLET_WRONG_ENC_STATE,
                    "Error: running with an unencrypted wallet, but walletpassphrasechange was called.",
                ));
            }
            wallet.change_passphrase(old.as_bytes(), new.as_bytes())?;
            Ok(Value::Null)
        }
        "backupwallet" => {
            let destination = params.required_string(0, "destination")?;
            wallet().backup(Path::new(&destination)).map_err(|error| {
                RpcError::new(
                    RPC_WALLET_ERROR,
                    format!("Error: Wallet backup failed! {error}"),
                )
            })?;
            Ok(Value::Null)
        }
        _ => Err(RpcError::new(RPC_METHOD_NOT_FOUND, "Method not found")),
    }
}

fn check_label(label: &str) -> Result<(), RpcError> {
    if label == "*" || label.chars().any(char::is_control) {
        return Err(RpcError::new(
            RPC_WALLET_INVALID_LABEL_NAME,
            "Invalid label name",
        ));
    }
    Ok(())
}

fn comment_param(params: &Params, index: usize, name: &str) -> Result<Option<String>, RpcError> {
    let comment = params.string(index, name)?;
    if comment
        .as_deref()
        .is_some_and(|comment| comment.chars().any(char::is_control))
    {
        return Err(RpcError::new(
            RPC_INVALID_PARAMETER,
            format!("{name} cannot contain control characters"),
        ));
    }
    Ok(comment)
}

fn address_param(params: &Params, index: usize) -> Result<[u8; 32], RpcError> {
    let text = params.required_string(index, "address")?;
    parse_address(&text)
        .ok_or_else(|| RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Common Foundry address"))
}

fn sent(txid: [u8; 32], verbose: bool) -> Value {
    if verbose {
        json!({ "txid": hex::encode(txid), "fee_reason": "Network minimum fee" })
    } else {
        json!(hex::encode(txid))
    }
}

/// Signs, records and broadcasts a payment. A payment whose broadcast
/// outcome is unknown stays recorded and is rebroadcast, as in Bitcoin Core.
fn send(
    context: &Context,
    payments: &[([u8; 32], u64)],
    subtract_fee_from: &[usize],
    minimum_confirmations: u64,
    comment: Option<String>,
    comment_to: Option<String>,
) -> Result<[u8; 32], RpcError> {
    let prepared = lock(&context.wallet).prepare_send(
        payments,
        subtract_fee_from,
        minimum_confirmations,
        comment,
        comment_to,
    )?;
    let outcome = lock(&context.source).broadcast_once(&prepared.transaction);
    match outcome {
        Ok(()) => {
            tracing::info!(txid = %hex::encode(prepared.txid), fee = prepared.fee, "sent");
            Ok(prepared.txid)
        }
        Err(BroadcastError::Rejected(message)) => {
            lock(&context.wallet).forget_rejected(prepared.txid)?;
            Err(RpcError::new(RPC_VERIFY_REJECTED, message))
        }
        Err(BroadcastError::Unknown(message)) => {
            tracing::warn!(
                txid = %hex::encode(prepared.txid),
                %message,
                "the payment is recorded but its broadcast outcome is unknown; it will be rebroadcast"
            );
            Ok(prepared.txid)
        }
    }
}

fn forward(
    context: &Context,
    method: &str,
    params: Value,
    not_found: &str,
) -> Result<Value, RpcError> {
    lock(&context.source)
        .call(method, params)
        .map_err(|error| match error {
            CallError::Rpc { code: -32001, .. } => {
                RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, not_found)
            }
            CallError::Rpc { message, .. } => RpcError::new(RPC_MISC_ERROR, message),
            unavailable => RpcError::new(RPC_CLIENT_NOT_CONNECTED, unavailable.to_string()),
        })
}

fn version_number() -> u64 {
    let mut parts = env!("CARGO_PKG_VERSION")
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    let (major, minor, patch) = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );
    major * 1_000_000 + minor * 10_000 + patch * 100
}

fn blockchain_info(context: &Context) -> Value {
    let (height, hash, time) = {
        let wallet = lock(&context.wallet);
        let (height, hash) = wallet.tip();
        (height, hash, wallet.tip_time())
    };
    let status = lock(&context.status);
    let headers = status.headers.max(height);
    json!({
        "chain": context.chain,
        "blocks": height,
        "headers": headers,
        "bestblockhash": hex::encode(hash),
        "difficulty": 0,
        "time": time,
        "mediantime": time,
        "verificationprogress": if headers == 0 { 1.0 } else { height as f64 / headers as f64 },
        "initialblockdownload": height + 1 < headers,
        "chainwork": "",
        "size_on_disk": 0,
        "pruned": false,
        "warnings": status.last_error.clone().unwrap_or_default(),
    })
}

fn network_info(context: &Context) -> Value {
    let connections = context.connections();
    json!({
        "version": version_number(),
        "subversion": format!("/CommonFoundryExchangeWallet:{}/", env!("CARGO_PKG_VERSION")),
        "protocolversion": 1,
        "localservices": "0000000000000000",
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": true,
        "connections": connections,
        "connections_in": 0,
        "connections_out": connections,
        "networks": [],
        "relayfee": amount(context.minimum_fee()),
        "incrementalfee": amount(0),
        "localaddresses": [],
        "warnings": lock(&context.status).last_error.clone().unwrap_or_default(),
    })
}

fn legacy_info(context: &Context) -> Value {
    let pay_tx_fee = *lock(&context.pay_tx_fee);
    let minimum_fee = context.minimum_fee();
    let mut wallet = lock(&context.wallet);
    let mut info = json!({
        "version": version_number(),
        "protocolversion": 1,
        "walletversion": 1,
        "balance": amount(wallet.balance(0)),
        "blocks": wallet.tip().0,
        "timeoffset": 0,
        "connections": context.connections(),
        "proxy": "",
        "difficulty": 0,
        "testnet": context.chain != "main",
        "keypoololdest": wallet.created_at(),
        "keypoolsize": wallet.keypool_size(),
        "paytxfee": amount(pay_tx_fee),
        "relayfee": amount(minimum_fee),
        "errors": "",
    });
    if let Some(until) = wallet.unlocked_until_unix() {
        info["unlocked_until"] = json!(until);
    }
    info
}

fn wallet_info(context: &Context) -> Value {
    let pay_tx_fee = *lock(&context.pay_tx_fee);
    let mut info = {
        let mut wallet = lock(&context.wallet);
        let balances = wallet.balances();
        let mut info = json!({
            "walletname": "",
            "walletversion": 1,
            "format": "cmfd-exchange-wallet-v1",
            "balance": amount(balances.trusted),
            "unconfirmed_balance": amount(balances.untrusted_pending),
            "immature_balance": amount(balances.immature),
            "txcount": wallet.tx_count(),
            "keypoololdest": wallet.created_at(),
            "keypoolsize": wallet.keypool_size(),
            "keypoolsize_hd_internal": wallet.keypool_size(),
            "paytxfee": amount(pay_tx_fee),
            "private_keys_enabled": true,
            "avoid_reuse": false,
            "scanning": false,
            "descriptors": false,
            "external_signer": false,
            "birthheight": wallet.birth_height(),
            "blocks": wallet.tip().0,
        });
        if let Some(until) = wallet.unlocked_until_unix() {
            info["unlocked_until"] = json!(until);
        }
        info
    };
    let status = lock(&context.status);
    if let Some((since, start)) = status.scanning_since {
        let height = info["blocks"].as_u64().unwrap_or(start);
        let span = status.headers.saturating_sub(start).max(1);
        info["scanning"] = json!({
            "duration": since.elapsed().as_secs(),
            "progress": (height.saturating_sub(start) as f64 / span as f64).min(1.0),
        });
    }
    info
}

fn tx_time(tx: &WalletTx) -> u64 {
    tx.block
        .as_ref()
        .map_or(tx.time_received, |block| block.time.min(tx.time_received))
}

/// Bitcoin Core's per-transaction fields (WalletTxToJSON).
fn add_common(wallet: &Wallet, tx: &WalletTx, entry: &mut Map<String, Value>) {
    let confirmations = wallet.tx_confirmations(tx);
    entry.insert("confirmations".to_owned(), json!(confirmations));
    if tx.coinbase {
        entry.insert("generated".to_owned(), json!(true));
    }
    if confirmations == 0 {
        entry.insert("trusted".to_owned(), json!(tx.ours && !tx.abandoned));
    }
    if let Some(block) = &tx.block {
        entry.insert("blockhash".to_owned(), json!(block.hash.to_string()));
        entry.insert("blockheight".to_owned(), json!(block.height));
        entry.insert("blockindex".to_owned(), json!(block.position));
        entry.insert("blocktime".to_owned(), json!(block.time));
    }
    entry.insert("txid".to_owned(), json!(tx.txid.to_string()));
    entry.insert(
        "walletconflicts".to_owned(),
        json!(
            tx.conflicted_by
                .map(|txid| txid.to_string())
                .into_iter()
                .collect::<Vec<_>>()
        ),
    );
    entry.insert("time".to_owned(), json!(tx_time(tx)));
    entry.insert("timereceived".to_owned(), json!(tx.time_received));
    if let Some(comment) = &tx.comment {
        entry.insert("comment".to_owned(), json!(comment));
    }
    if let Some(to) = &tx.comment_to {
        entry.insert("to".to_owned(), json!(to));
    }
    entry.insert("bip125-replaceable".to_owned(), json!("no"));
}

/// Bitcoin Core's `send` / `receive` / `generate` entries for one transaction.
fn tx_entries(
    wallet: &Wallet,
    tx: &WalletTx,
    common: bool,
    include_change: bool,
    label: Option<&str>,
) -> Vec<Value> {
    let confirmations = wallet.tx_confirmations(tx);
    let mut entries = Vec::new();
    if tx.from_me() && label.is_none() {
        let fee = tx.fee().map(|fee| signed_amount(-i128::from(fee)));
        for payment in &tx.payments {
            let mut entry = Map::new();
            entry.insert(
                "address".to_owned(),
                json!(payment.address.map(|address| address.to_string())),
            );
            entry.insert("category".to_owned(), json!("send"));
            entry.insert(
                "amount".to_owned(),
                signed_amount(-i128::from(payment.value)),
            );
            entry.insert("vout".to_owned(), json!(payment.vout));
            if let Some(fee) = &fee {
                entry.insert("fee".to_owned(), fee.clone());
            }
            entry.insert("abandoned".to_owned(), json!(tx.abandoned));
            entries.push(entry);
        }
    }
    for credit in &tx.credits {
        if credit.chain == KeyChain::Change && !include_change {
            continue;
        }
        let address_label = wallet.label(credit.address.0).unwrap_or_default();
        if label.is_some_and(|label| label != address_label) {
            continue;
        }
        let category = if !tx.coinbase {
            "receive"
        } else if confirmations < 1 {
            "orphan"
        } else if !wallet.is_mature(credit.spendable_height) {
            "immature"
        } else {
            "generate"
        };
        let mut entry = Map::new();
        entry.insert("address".to_owned(), json!(credit.address.to_string()));
        entry.insert("category".to_owned(), json!(category));
        entry.insert("amount".to_owned(), amount(credit.value));
        if credit.chain == KeyChain::Receive {
            entry.insert("label".to_owned(), json!(address_label));
        }
        entry.insert("vout".to_owned(), json!(credit.vout));
        entries.push(entry);
    }
    entries
        .into_iter()
        .map(|mut entry| {
            if common {
                add_common(wallet, tx, &mut entry);
            }
            Value::Object(entry)
        })
        .collect()
}

fn list_unspent(context: &Context, params: &Params) -> Result<Value, RpcError> {
    let minimum = params.count(0, "minconf", 1)?;
    let maximum = params.count(1, "maxconf", 9_999_999)?;
    let addresses = match params.typed::<Vec<String>>(2, "addresses", "array")? {
        Some(texts) => {
            let mut wanted = BTreeSet::new();
            for text in texts {
                let address = parse_address(&text).ok_or_else(|| {
                    RpcError::new(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        format!("Invalid Common Foundry address: {text}"),
                    )
                })?;
                if !wanted.insert(address) {
                    return Err(RpcError::new(
                        RPC_INVALID_PARAMETER,
                        format!("Invalid parameter, duplicated address: {text}"),
                    ));
                }
            }
            Some(wanted)
        }
        None => None,
    };
    let wallet = lock(&context.wallet);
    let rows = wallet
        .unspent_coins()
        .into_iter()
        .filter(|(coin, locked)| {
            let confirmations = wallet.confirmations_at(coin.height);
            !locked
                && wallet.is_mature(coin.spendable_height)
                && (minimum..=maximum).contains(&confirmations)
                && addresses
                    .as_ref()
                    .is_none_or(|wanted| wanted.contains(&coin.address.0))
        })
        .map(|(coin, _)| {
            let mut row = json!({
                "txid": coin.txid.to_string(),
                "vout": coin.vout,
                "address": coin.address.to_string(),
                "amount": amount(coin.value),
                "confirmations": wallet.confirmations_at(coin.height),
                "spendable": true,
                "solvable": true,
                "safe": true,
            });
            if coin.chain == KeyChain::Receive {
                row["label"] = json!(wallet.label(coin.address.0).unwrap_or_default());
            }
            row
        })
        .collect::<Vec<_>>();
    Ok(json!(rows))
}

fn list_transactions(context: &Context, params: &Params) -> Result<Value, RpcError> {
    let label = params.string(0, "label")?;
    let label = label.as_deref().filter(|label| *label != "*");
    let count = usize::try_from(params.count(1, "count", 10)?).unwrap_or(usize::MAX);
    let skip = usize::try_from(params.count(2, "skip", 0)?).unwrap_or(usize::MAX);
    let wallet = lock(&context.wallet);
    let entries = wallet
        .transactions()
        .into_iter()
        .flat_map(|tx| tx_entries(&wallet, tx, true, false, label))
        .collect::<Vec<_>>();
    let end = entries.len().saturating_sub(skip);
    let start = end.saturating_sub(count);
    Ok(json!(entries[start..end]))
}

fn list_since_block(context: &Context, params: &Params) -> Result<Value, RpcError> {
    let since_hash = match params
        .string(0, "blockhash")?
        .filter(|text| !text.is_empty())
    {
        Some(text) => Some(parse_h32(&text).map(|hash| hash.0).ok_or_else(|| {
            RpcError::new(
                RPC_INVALID_PARAMETER,
                "blockhash must be 64 lowercase hexadecimal characters",
            )
        })?),
        None => None,
    };
    let target = params.count(1, "target_confirmations", 1)?;
    if target < 1 {
        return Err(RpcError::new(RPC_INVALID_PARAMETER, "Invalid parameter"));
    }
    let include_removed = params.boolean(3, "include_removed")?.unwrap_or(true);
    let include_change = params.boolean(4, "include_change")?.unwrap_or(false);
    let label = params.string(5, "label")?;

    // Where the caller's block sits relative to the wallet's chain.
    let mut resolved = since_hash.map(|hash| {
        let wallet = lock(&context.wallet);
        if let Some(height) = wallet.height_of(hash) {
            return Some((height, Vec::new()));
        }
        let mut removed = Vec::new();
        let mut cursor = hash;
        while let Some(orphan) = wallet.orphan(cursor) {
            removed.extend(orphan.txids.iter().map(|txid| txid.0));
            cursor = orphan.previous.0;
            if let Some(height) = wallet.height_of(cursor) {
                return Some((height, removed));
            }
        }
        None
    });
    if let (Some(hash), Some(None)) = (since_hash, &resolved) {
        // Older than the wallet's own records: ask the endpoint.
        let document = forward(
            context,
            "getblock",
            json!([hex::encode(hash), 1]),
            "Block not found",
        )?;
        if document.get("active").and_then(Value::as_bool) != Some(true) {
            return Err(RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, "Block not found"));
        }
        let height = document
            .get("height")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, "Block not found"))?;
        resolved = Some(Some((height, Vec::new())));
    }
    let (since, removed_txids) = match resolved {
        Some(Some((height, removed))) => (Some(height), removed),
        _ => (None, Vec::new()),
    };

    let wallet = lock(&context.wallet);
    let transactions = wallet
        .transactions()
        .into_iter()
        .filter(|tx| match (&tx.block, since) {
            (Some(block), Some(since)) => block.height > since,
            _ => true,
        })
        .flat_map(|tx| tx_entries(&wallet, tx, true, include_change, label.as_deref()))
        .collect::<Vec<_>>();
    let (tip, _) = wallet.tip();
    let last_height = tip
        .saturating_add(1)
        .saturating_sub(target)
        .max(wallet.birth_height());
    let last_block = wallet
        .hash_at(last_height)
        .map(hex::encode)
        .unwrap_or_default();
    let mut result = json!({ "transactions": transactions, "lastblock": last_block });
    if include_removed {
        let removed = removed_txids
            .iter()
            .filter_map(|txid| wallet.tx(*txid))
            .flat_map(|tx| tx_entries(&wallet, tx, true, include_change, label.as_deref()))
            .collect::<Vec<_>>();
        result["removed"] = json!(removed);
    }
    Ok(result)
}

fn get_transaction(context: &Context, params: &Params) -> Result<Value, RpcError> {
    let txid = params.hash(0, "txid")?;
    let wallet = lock(&context.wallet);
    let tx = wallet.tx(txid).ok_or_else(|| {
        RpcError::new(
            RPC_INVALID_ADDRESS_OR_KEY,
            "Invalid or non-wallet transaction id",
        )
    })?;
    let credit = tx
        .credits
        .iter()
        .map(|credit| i128::from(credit.value))
        .sum::<i128>();
    let net = if tx.from_me() {
        credit - i128::from(tx.output_total)
    } else {
        credit
    };
    let mut document = Map::new();
    document.insert("amount".to_owned(), signed_amount(net));
    if let Some(fee) = tx.fee() {
        document.insert("fee".to_owned(), signed_amount(-i128::from(fee)));
    }
    add_common(&wallet, tx, &mut document);
    document.insert(
        "details".to_owned(),
        json!(tx_entries(&wallet, tx, false, false, None)),
    );
    document.insert("hex".to_owned(), json!(tx.hex.clone().unwrap_or_default()));
    if tx.ours || tx.from_me() {
        document.insert("abandoned".to_owned(), json!(tx.abandoned));
    }
    Ok(Value::Object(document))
}

/// Per receive address: (amount, confirmations of the newest counted
/// transaction, txids), counting transactions with at least `minimum`
/// confirmations and mature coinbase outputs.
fn received_by_address(
    wallet: &Wallet,
    minimum: u64,
) -> HashMap<[u8; 32], (u64, u64, Vec<String>)> {
    let mut received = HashMap::<[u8; 32], (u64, u64, Vec<String>)>::new();
    for tx in wallet.transactions() {
        let confirmations = u64::try_from(wallet.tx_confirmations(tx)).unwrap_or(0);
        if confirmations < minimum {
            continue;
        }
        for credit in &tx.credits {
            if credit.chain != KeyChain::Receive
                || (tx.coinbase && !wallet.is_mature(credit.spendable_height))
            {
                continue;
            }
            let entry = received
                .entry(credit.address.0)
                .or_insert((0, u64::MAX, Vec::new()));
            entry.0 = entry.0.saturating_add(credit.value);
            entry.1 = entry.1.min(confirmations);
            let txid = tx.txid.to_string();
            if !entry.2.contains(&txid) {
                entry.2.push(txid);
            }
        }
    }
    for entry in received.values_mut() {
        if entry.1 == u64::MAX {
            entry.1 = 0;
        }
    }
    received
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_parse_exactly_like_bitcoin_core() {
        assert_eq!(parse_amount("1").unwrap(), 100_000_000);
        assert_eq!(parse_amount("0.1").unwrap(), 10_000_000);
        assert_eq!(parse_amount("\"0.00000001\"").unwrap(), 1);
        assert_eq!(parse_amount("1e-08").unwrap(), 1);
        assert_eq!(parse_amount("1.5E2").unwrap(), 15_000_000_000);
        assert_eq!(
            parse_amount("123456789.12345678").unwrap(),
            12_345_678_912_345_678
        );
        assert_eq!(parse_amount("0.100000000").unwrap(), 10_000_000);
        assert!(parse_amount("0.000000001").is_err());
        assert!(parse_amount("-1").is_err());
        assert!(parse_amount("abc").is_err());
        assert!(parse_amount(".").is_err());
        assert!(parse_amount("1e40").is_err());
    }

    #[test]
    fn amounts_render_as_bare_decimals() {
        let document = json!({
            "a": amount(150_000_000),
            "b": signed_amount(-10_000_000),
            "c": "plain \u{0} text",
            "d": [amount(1)],
        });
        let rendered = render(&document);
        let reparsed: Value = serde_json::from_str(&rendered).unwrap();
        assert!(rendered.contains("\"a\":1.50000000"));
        assert!(rendered.contains("\"b\":-0.10000000"));
        assert!(rendered.contains("[0.00000001]"));
        assert_eq!(reparsed["c"], "plain \u{0} text");
    }

    #[test]
    fn named_and_positional_parameters_resolve_to_the_same_slots() {
        let names = param_names("sendtoaddress").unwrap();
        let positional =
            RawValue::from_string("[\"a\", 1.5, null, null, true]".to_owned()).unwrap();
        let named = RawValue::from_string(
            "{\"amount\": 1.5, \"address\": \"a\", \"subtractfeefromamount\": true}".to_owned(),
        )
        .unwrap();
        for raw in [positional, named] {
            let params = Params::parse(Some(&raw), names).unwrap();
            assert_eq!(params.required_string(0, "address").unwrap(), "a");
            assert_eq!(params.amount(1).unwrap(), Some(150_000_000));
            assert_eq!(params.string(2, "comment").unwrap(), None);
            assert_eq!(
                params.boolean(4, "subtractfeefromamount").unwrap(),
                Some(true)
            );
        }
        let unknown = RawValue::from_string("{\"bogus\": 1}".to_owned()).unwrap();
        assert_eq!(
            Params::parse(Some(&unknown), names).err().unwrap().code,
            RPC_INVALID_PARAMETER
        );
    }

    #[test]
    fn configuration_requires_credentials_and_guards_remote_binding() {
        let base = "rpcuser=exchange\nrpcpassword=0123456789abcdef\nupstream=https://example.com/mainnet\nupstreamuser=x\nupstreampassword=y\n";
        let config = WalletConfig::parse(base).unwrap();
        assert_eq!(config.rpc_port, DEFAULT_RPC_PORT);
        assert!(config.allows("127.0.0.1".parse().unwrap()));
        assert!(!config.allows("10.0.0.5".parse().unwrap()));
        assert!(WalletConfig::parse("rpcuser=x\nrpcpassword=short\n").is_err());
        assert!(WalletConfig::parse(&format!("{base}rpcbind=0.0.0.0\n")).is_err());
        let open = WalletConfig::parse(&format!("{base}rpcbind=0.0.0.0\nrpcallowip=10.0.0.0/8\n"))
            .unwrap();
        assert!(open.allows("10.1.2.3".parse().unwrap()));
        assert!(!open.allows("11.1.2.3".parse().unwrap()));
        assert!(WalletConfig::parse(&format!("{base}bogus=1\n")).is_err());
    }
}
