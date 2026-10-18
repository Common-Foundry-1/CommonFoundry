//! JSON-RPC client for the exchange RPC endpoint that feeds the exchange
//! wallet: the hosted endpoint over HTTPS or the exchange's own node.
//!
//! On a network with a work rule the wallet follows only an endpoint whose
//! node re-executes each block's work itself, and only up to that node's
//! validated height: the endpoint must report the rule as enforced, not
//! halted and with a ready engine, under a release checkpoint at or above the
//! one this binary was built with, and its chain must hold this binary's
//! checkpoint block. Otherwise the wallet stops following it (fails closed)
//! and reports why.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::exchange_wallet::{
    BroadcastError, ChainSource, ChainTip, SourceBlock, SourceError, SourceOutput,
    SourceTransaction, parse_h32,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Stays under the hosted endpoint's 5 requests per second.
const REMOTE_REQUEST_INTERVAL: Duration = Duration::from_millis(250);
const MAX_ATTEMPTS: u32 = 4;

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

#[derive(Clone)]
pub struct Endpoint {
    tls: Option<Arc<rustls::ClientConfig>>,
    host: String,
    port: u16,
    path: String,
    authorization: Arc<Zeroizing<String>>,
    interval: Duration,
    throttle: Arc<Mutex<Instant>>,
    network_id: [u8; 32],
    last_success: Arc<Mutex<Option<Instant>>>,
}

impl Endpoint {
    pub fn new(
        url: &str,
        user: &str,
        password: &str,
        network_id: [u8; 32],
    ) -> Result<Self, String> {
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err("upstream must start with https:// or http://".to_owned());
        };
        let (authority, path) = match rest.find('/') {
            Some(slash) => (&rest[..slash], &rest[slash..]),
            None => (rest, "/"),
        };
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, after) = bracketed
                .split_once(']')
                .ok_or("upstream has an unterminated IPv6 address")?;
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse().map_err(|_| "upstream port is invalid")?,
                None if after.is_empty() => default_port,
                None => return Err("upstream address is malformed".to_owned()),
            };
            (host.to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (
                    host.to_owned(),
                    port.parse().map_err(|_| "upstream port is invalid")?,
                ),
                None => (authority.to_owned(), default_port),
            }
        };
        if host.is_empty() || authority.contains('@') {
            return Err(
                "upstream must be a URL such as https://host/path without credentials".to_owned(),
            );
        }
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if !tls && !loopback {
            return Err(
                "plain http:// is only allowed to this machine (localhost); use https:// for remote endpoints".to_owned(),
            );
        }
        let tls = if tls {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("TLS setup failed: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            ServerName::try_from(host.clone())
                .map_err(|_| format!("`{host}` is not a valid TLS server name"))?;
            Some(Arc::new(config))
        } else {
            None
        };
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        Ok(Self {
            tls,
            host,
            port,
            path: path.to_owned(),
            authorization: Arc::new(Zeroizing::new(token)),
            interval: if loopback {
                Duration::ZERO
            } else {
                REMOTE_REQUEST_INTERVAL
            },
            throttle: Arc::new(Mutex::new(Instant::now())),
            network_id,
            last_success: Arc::new(Mutex::new(None)),
        })
    }

    /// When the endpoint last answered successfully.
    pub fn last_success(&self) -> Option<Instant> {
        *self
            .last_success
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn wait_turn(&self) {
        if self.interval.is_zero() {
            return;
        }
        let wait = {
            let mut next = self
                .throttle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            let start = (*next).max(now);
            *next = start + self.interval;
            start - now
        };
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
    }
}

#[derive(Debug)]
pub enum CallError {
    /// No usable answer (transport failure, busy or overloaded endpoint).
    Unavailable(String),
    /// The endpoint answered with a JSON-RPC error.
    Rpc {
        code: i64,
        message: String,
        data_code: Option<String>,
        retryable: bool,
    },
}

impl std::fmt::Display for CallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "upstream unavailable: {message}"),
            Self::Rpc { message, .. } => formatter.write_str(message),
        }
    }
}

impl CallError {
    fn retryable(&self) -> bool {
        match self {
            Self::Unavailable(_) => true,
            Self::Rpc { retryable, .. } => *retryable,
        }
    }

    fn is_not_found(&self) -> bool {
        matches!(self, Self::Rpc { code: -32001, .. })
    }
}

impl From<CallError> for SourceError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Unavailable(message) => SourceError::Unavailable(message),
            CallError::Rpc { message, .. } => SourceError::Invalid(message),
        }
    }
}

struct Response {
    status: u16,
    body: Vec<u8>,
    close: bool,
}

pub struct Upstream {
    endpoint: Endpoint,
    connection: Option<BufReader<Box<dyn Stream>>>,
    next_id: u64,
    /// This binary's work-rule checkpoint (height, block id), if its network
    /// has one.
    checkpoint: Option<(u64, [u8; 32])>,
    /// The endpoint's chain was seen to hold the checkpoint block, on the
    /// current connection.
    checkpoint_seen: bool,
    /// Why the endpoint was last refused as a chain source, until it next
    /// passes the checks.
    refusal: Option<String>,
}

impl Upstream {
    pub fn new(endpoint: Endpoint) -> Self {
        let checkpoint = cmfd_consensus::forgematrix_v4_work_rule(endpoint.network_id)
            .map(|rule| (rule.checkpoint_height(), rule.checkpoint_block_id()));
        Self::with_checkpoint(endpoint, checkpoint)
    }

    /// An upstream checked against `checkpoint` instead of the compiled one.
    pub(crate) fn with_checkpoint(endpoint: Endpoint, checkpoint: Option<(u64, [u8; 32])>) -> Self {
        Self {
            endpoint,
            connection: None,
            next_id: 1,
            checkpoint,
            checkpoint_seen: false,
            refusal: None,
        }
    }

    /// Why the endpoint was last refused as a chain source, if it was and has
    /// not passed the checks since.
    pub fn refusal(&self) -> Option<&str> {
        self.refusal.as_deref()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Calls `method`, retrying transport failures and busy answers.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, CallError> {
        let mut attempt = 1;
        loop {
            match self.call_once(method, &params) {
                Err(error) if error.retryable() && attempt < MAX_ATTEMPTS => {
                    std::thread::sleep(Duration::from_secs(1 << (attempt - 1)));
                    attempt += 1;
                }
                outcome => return outcome,
            }
        }
    }

    fn call_once(&mut self, method: &str, params: &Value) -> Result<Value, CallError> {
        self.endpoint.wait_turn();
        let id = self.next_id;
        self.next_id += 1;
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .expect("request serializes");
        let response = self.exchange(&body).map_err(|error| {
            self.connection = None;
            CallError::Unavailable(error.to_string())
        })?;
        if response.close {
            self.connection = None;
        }
        match response.status {
            200 => {}
            401 | 403 => {
                return Err(CallError::Unavailable(format!(
                    "the endpoint refused the configured upstreamuser/upstreampassword (HTTP {})",
                    response.status
                )));
            }
            status => {
                let text = String::from_utf8_lossy(&response.body);
                return Err(CallError::Unavailable(format!(
                    "HTTP {status}: {}",
                    text.chars().take(200).collect::<String>()
                )));
            }
        }
        let document: Value = serde_json::from_slice(&response.body)
            .map_err(|error| CallError::Unavailable(format!("unreadable answer: {error}")))?;
        if let Some(error) = document.get("error").filter(|error| !error.is_null()) {
            let data_code = error
                .pointer("/data/code")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if data_code.as_deref() == Some("upstream_busy") {
                return Err(CallError::Unavailable("the endpoint is busy".to_owned()));
            }
            return Err(CallError::Rpc {
                code: error.get("code").and_then(Value::as_i64).unwrap_or(-1),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("upstream error")
                    .to_owned(),
                retryable: error
                    .pointer("/data/retryable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                data_code,
            });
        }
        *self
            .endpoint
            .last_success
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Instant::now());
        Ok(document.get("result").cloned().unwrap_or(Value::Null))
    }

    fn exchange(&mut self, body: &[u8]) -> io::Result<Response> {
        // A reused keep-alive connection may have been closed by the server.
        if self.connection.is_some() {
            if let Ok(response) = self.send(body) {
                return Ok(response);
            }
            self.connection = None;
        }
        self.connect()?;
        self.send(body)
    }

    fn connect(&mut self) -> io::Result<()> {
        let endpoint = &self.endpoint;
        let mut last_error = io::Error::new(io::ErrorKind::NotFound, "the host has no addresses");
        let mut connected = None;
        for address in (endpoint.host.as_str(), endpoint.port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(error) => last_error = error,
            }
        }
        let tcp = connected.ok_or(last_error)?;
        // A new connection may reach another server behind the same name.
        self.checkpoint_seen = false;
        tcp.set_read_timeout(Some(IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(IO_TIMEOUT))?;
        tcp.set_nodelay(true)?;
        let stream: Box<dyn Stream> = match &endpoint.tls {
            Some(config) => {
                let name = ServerName::try_from(endpoint.host.clone())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let connection = rustls::ClientConnection::new(Arc::clone(config), name)
                    .map_err(io::Error::other)?;
                Box::new(rustls::StreamOwned::new(connection, tcp))
            }
            None => Box::new(tcp),
        };
        self.connection = Some(BufReader::new(stream));
        Ok(())
    }

    fn send(&mut self, body: &[u8]) -> io::Result<Response> {
        let endpoint = &self.endpoint;
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "not connected"))?;
        let host = if endpoint.host.contains(':') {
            format!("[{}]", endpoint.host)
        } else {
            endpoint.host.clone()
        };
        let head = Zeroizing::new(format!(
            "POST {} HTTP/1.1\r\nHost: {host}:{}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\nUser-Agent: cmfd-exchange-wallet/{}\r\n\r\n",
            endpoint.path,
            endpoint.port,
            endpoint.authorization.as_str(),
            body.len(),
            env!("CARGO_PKG_VERSION"),
        ));
        let stream = connection.get_mut();
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;

        let status_line = read_line(connection)?;
        let mut parts = status_line.split_whitespace();
        let version = parts.next().unwrap_or_default().to_owned();
        let status = parts
            .next()
            .and_then(|status| status.parse::<u16>().ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP status line")
            })?;
        let mut length = None;
        let mut chunked = false;
        let mut close = version == "HTTP/1.0";
        let mut header_bytes = status_line.len();
        loop {
            let line = read_line(connection)?;
            header_bytes += line.len();
            if header_bytes > MAX_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP headers are too large",
                ));
            }
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")
                })?);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.to_ascii_lowercase().contains("chunked");
            } else if name.eq_ignore_ascii_case("connection") {
                close = value.eq_ignore_ascii_case("close");
            }
        }
        let body = if chunked {
            read_chunked(connection)?
        } else if let Some(length) = length {
            if length > MAX_RESPONSE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response is too large",
                ));
            }
            let mut body = vec![0_u8; length];
            connection.read_exact(&mut body)?;
            body
        } else {
            close = true;
            let mut body = Vec::new();
            connection
                .take(MAX_RESPONSE_BYTES as u64 + 1)
                .read_to_end(&mut body)?;
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response is too large",
                ));
            }
            body
        };
        Ok(Response {
            status,
            body,
            close,
        })
    }

    /// Network identity and tip, checked against the network this binary
    /// was built for.
    pub fn chain_info(&mut self) -> Result<Value, SourceError> {
        let info = self.call("getblockchaininfo", json!([]))?;
        let network = info
            .get("network_id")
            .and_then(Value::as_str)
            .and_then(parse_h32)
            .ok_or_else(|| {
                SourceError::Invalid("getblockchaininfo has no network_id".to_owned())
            })?;
        if network.0 != self.endpoint.network_id {
            return Err(SourceError::Invalid(format!(
                "the upstream endpoint serves network {network}, not the network this binary was built for ({})",
                hex::encode(self.endpoint.network_id)
            )));
        }
        Ok(info)
    }
}

fn read_line(reader: &mut impl BufRead) -> io::Result<String> {
    let mut line = Vec::new();
    reader
        .take(MAX_HEADER_BYTES as u64)
        .read_until(b'\n', &mut line)?;
    if line.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the connection closed mid-response",
        ));
    }
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP header is not UTF-8"))
}

fn read_chunked(reader: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line(reader)?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if size == 0 {
            while !read_line(reader)?.is_empty() {}
            return Ok(body);
        }
        if body.len() + size > MAX_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response is too large",
            ));
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..])?;
        if !read_line(reader)?.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed chunk",
            ));
        }
    }
}

fn hash_field(document: &Value, field: &str) -> Result<[u8; 32], SourceError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .and_then(parse_h32)
        .map(|hash| hash.0)
        .ok_or_else(|| SourceError::Invalid(format!("block document has no valid `{field}`")))
}

fn parse_outputs(outputs: &Value) -> Result<Vec<SourceOutput>, SourceError> {
    let invalid = || SourceError::Invalid("block document has a malformed output".to_owned());
    outputs
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .enumerate()
        .map(|(position, output)| {
            if output.get("n").and_then(Value::as_u64) != Some(position as u64) {
                return Err(invalid());
            }
            let value = output
                .get("value_atoms")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(invalid)?;
            let destination = match output.get("lock_type").and_then(Value::as_str) {
                Some("key") => Some(hash_field(output, "destination_hex")?),
                Some(_) => None,
                None => return Err(invalid()),
            };
            Ok(SourceOutput {
                value,
                destination,
                spendable_height: output
                    .get("spendable_height")
                    .and_then(Value::as_u64)
                    .ok_or_else(invalid)?,
            })
        })
        .collect()
}

/// Parses `getblock <hash> 2`.
pub fn parse_block(document: &Value) -> Result<SourceBlock, SourceError> {
    let invalid =
        |what: &str| SourceError::Invalid(format!("block document has no valid `{what}`"));
    let mut transactions = Vec::new();
    if let Some(coinbase) = document.get("coinbase").filter(|value| !value.is_null()) {
        transactions.push(SourceTransaction {
            txid: hash_field(coinbase, "outpoint_txid")?,
            coinbase: true,
            inputs: Vec::new(),
            outputs: parse_outputs(
                coinbase
                    .get("vout")
                    .ok_or_else(|| invalid("coinbase.vout"))?,
            )?,
            hex: None,
        });
    }
    for transaction in document
        .get("tx")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("tx"))?
    {
        let inputs = transaction
            .get("vin")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("tx.vin"))?
            .iter()
            .map(|input| {
                Ok((
                    hash_field(input, "txid")?,
                    input
                        .get("vout")
                        .and_then(Value::as_u64)
                        .and_then(|vout| u32::try_from(vout).ok())
                        .ok_or_else(|| invalid("tx.vin.vout"))?,
                ))
            })
            .collect::<Result<Vec<_>, SourceError>>()?;
        transactions.push(SourceTransaction {
            txid: hash_field(transaction, "txid")?,
            coinbase: false,
            inputs,
            outputs: parse_outputs(transaction.get("vout").ok_or_else(|| invalid("tx.vout"))?)?,
            hex: transaction
                .get("hex")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    Ok(SourceBlock {
        hash: hash_field(document, "hash")?,
        height: document
            .get("height")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("height"))?,
        previous: match document.get("previousblockhash") {
            Some(Value::Null) | None => [0; 32],
            Some(_) => hash_field(document, "previousblockhash")?,
        },
        next: match document.get("nextblockhash") {
            Some(Value::Null) | None => None,
            Some(_) => Some(hash_field(document, "nextblockhash")?),
        },
        time: document
            .get("time")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("time"))?,
        active: document
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        transactions,
    })
}

/// The height up to which a wallet may follow an endpoint whose
/// `getblockchaininfo` is `info`, given this binary's checkpoint height: the
/// lower of its tip and its validated height. Fails, with the reason, unless
/// the endpoint reports the work rule enforced, not halted and with a ready
/// engine, under a checkpoint at or above `checkpoint_height`.
pub(crate) fn followable_height(info: &Value, checkpoint_height: u64) -> Result<u64, String> {
    let blocks = info
        .get("blocks")
        .and_then(Value::as_u64)
        .ok_or("getblockchaininfo has no blocks")?;
    let rule = info
        .get("work_rule")
        .filter(|rule| rule.is_object())
        .ok_or("the upstream does not report the work rule; it must run a node release that re-executes each block's work")?;
    let flag = |name: &str| rule.get(name).and_then(Value::as_bool);
    if flag("enforced") != Some(true) {
        return Err(
            "the upstream node does not re-execute block work yet (work_rule.enforced is not true)"
                .to_owned(),
        );
    }
    if flag("halted") != Some(false) {
        return Err("the upstream node has halted block admission".to_owned());
    }
    if flag("engine_ready") != Some(true) {
        return Err(format!(
            "the upstream node's work engine is not ready (engine_state {})",
            rule.get("engine_state").unwrap_or(&Value::Null)
        ));
    }
    let upstream_checkpoint = rule
        .get("checkpoint_height")
        .and_then(Value::as_u64)
        .ok_or("the upstream reports no work checkpoint height")?;
    if upstream_checkpoint < checkpoint_height {
        return Err(format!(
            "the upstream node's work checkpoint is height {upstream_checkpoint}, below this release's {checkpoint_height}; it must be upgraded"
        ));
    }
    let validated = rule
        .get("validated_height")
        .and_then(Value::as_u64)
        .ok_or("the upstream reports no validated height")?;
    Ok(blocks.min(validated))
}

impl Upstream {
    fn refuse(&mut self, reason: String) -> SourceError {
        self.checkpoint_seen = false;
        self.refusal = Some(reason.clone());
        SourceError::Unavailable(reason)
    }
}

impl ChainSource for Upstream {
    fn tip(&mut self) -> Result<ChainTip, SourceError> {
        let info = self.chain_info()?;
        let blocks = info
            .get("blocks")
            .and_then(Value::as_u64)
            .ok_or_else(|| SourceError::Invalid("getblockchaininfo has no blocks".to_owned()))?;
        let best = hash_field(&info, "bestblockhash")?;
        let Some((checkpoint_height, checkpoint_id)) = self.checkpoint else {
            return Ok(ChainTip {
                height: blocks,
                hash: best,
            });
        };
        let height =
            followable_height(&info, checkpoint_height).map_err(|reason| self.refuse(reason))?;
        if !self.checkpoint_seen {
            match self.block_hash(checkpoint_height)? {
                Some(id) if id == checkpoint_id => self.checkpoint_seen = true,
                _ => {
                    return Err(self.refuse(format!(
                        "the upstream chain does not hold this release's checkpoint block {} at height {checkpoint_height}",
                        hex::encode(checkpoint_id)
                    )));
                }
            }
        }
        let hash = if height == blocks {
            best
        } else {
            self.block_hash(height)?.ok_or_else(|| {
                SourceError::Unavailable(format!(
                    "the upstream has no block at its validated height {height}"
                ))
            })?
        };
        self.refusal = None;
        Ok(ChainTip { height, hash })
    }

    fn block_hash(&mut self, height: u64) -> Result<Option<[u8; 32]>, SourceError> {
        match self.call("getblockhash", json!([height])) {
            Ok(value) => value
                .as_str()
                .and_then(parse_h32)
                .map(|hash| Some(hash.0))
                .ok_or_else(|| SourceError::Invalid("getblockhash returned no hash".to_owned())),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn block(&mut self, hash: [u8; 32]) -> Result<Option<SourceBlock>, SourceError> {
        match self.call("getblock", json!([hex::encode(hash), 2])) {
            Ok(document) => parse_block(&document).map(Some),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn broadcast(&mut self, transaction: &[u8]) -> Result<(), BroadcastError> {
        broadcast_outcome(self.call("sendrawtransaction", json!([hex::encode(transaction)])))
    }

    fn mempool_contains(&mut self, txid: [u8; 32]) -> Result<bool, SourceError> {
        let wanted = hex::encode(txid);
        Ok(self
            .call("getrawmempool", json!([]))?
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| entry.as_str() == Some(&wanted))))
    }
}

impl Upstream {
    /// One broadcast attempt without retries, for payments an RPC caller is
    /// waiting on. An unknown outcome is retried later by the rebroadcaster.
    pub fn broadcast_once(&mut self, transaction: &[u8]) -> Result<(), BroadcastError> {
        broadcast_outcome(self.call_once("sendrawtransaction", &json!([hex::encode(transaction)])))
    }
}

/// Which endpoint the wallet follows, as the last `tip` decided. The chain
/// synchronization's [`Upstreams`] writes it at every `tip`; other sets of
/// connections read it so that they read only from that endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FollowedEndpoint {
    /// The endpoint the last `tip` accepted; `None` before the first `tip`
    /// and after one that no endpoint passed.
    pub index: Option<usize>,
    /// Why the active endpoint was last refused as a chain source, if it was
    /// and has not passed the checks since.
    pub refusal: Option<String>,
}

/// The configured endpoints, in order of preference: a primary and an
/// optional second one. Calls go to the active endpoint. Only `tip`, which
/// runs the work-rule checks, moves to another endpoint when the active one
/// fails, and the first that passes is used from then on. A broadcast tries
/// the other endpoints for that one transaction without moving. The other
/// chain reads stay on the endpoint `tip` last accepted, so the wallet never
/// reads blocks from an endpoint that has not passed the checks.
pub struct Upstreams {
    upstreams: Vec<Upstream>,
    active: usize,
    followed: Arc<Mutex<FollowedEndpoint>>,
}

impl Upstreams {
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        assert!(!upstreams.is_empty(), "at least one upstream endpoint");
        Self {
            upstreams,
            active: 0,
            followed: Arc::default(),
        }
    }

    /// The endpoint calls go to now.
    pub fn active_endpoint(&self) -> &Endpoint {
        self.upstreams[self.active].endpoint()
    }

    /// Why the endpoint calls go to now was last refused as a chain source,
    /// if it was and has not passed the checks since.
    pub fn refusal(&self) -> Option<&str> {
        self.upstreams[self.active].refusal()
    }

    /// Where every `tip` records the endpoint it accepted.
    pub fn followed(&self) -> Arc<Mutex<FollowedEndpoint>> {
        Arc::clone(&self.followed)
    }

    /// Sends later calls to the endpoint at `index`, so a second set of
    /// connections reads from the endpoint the wallet follows.
    pub fn use_endpoint(&mut self, index: usize) {
        if index < self.upstreams.len() {
            self.active = index;
        }
    }

    /// Moves back to the primary endpoint if it passes the checks with a
    /// followable height of at least `min_height`, the wallet's tip, so the
    /// wallet never moves to an endpoint that would leave it waiting.
    /// Returns whether calls go to the primary; otherwise they stay where
    /// they are.
    pub fn retry_primary(&mut self, min_height: u64) -> bool {
        if self.active == 0 {
            return true;
        }
        match self.upstreams[0].tip() {
            Ok(tip) if tip.height >= min_height => {
                tracing::info!(
                    now = %self.upstreams[0].endpoint().host,
                    height = tip.height,
                    "the primary upstream endpoint passes the checks again; following it"
                );
                self.active = 0;
                true
            }
            Ok(tip) => {
                tracing::info!(
                    primary = %self.upstreams[0].endpoint().host,
                    primary_height = tip.height,
                    wallet_height = min_height,
                    "the primary upstream endpoint is behind the wallet; staying on the second one"
                );
                false
            }
            Err(error) => {
                tracing::debug!(
                    primary = %self.upstreams[0].endpoint().host,
                    %error,
                    "the primary upstream endpoint still fails"
                );
                false
            }
        }
    }

    /// Whether calls go to an endpoint other than the primary.
    pub fn on_fallback(&self) -> bool {
        self.active != 0
    }

    /// Runs `call` on the active endpoint and, while `fail_over` says its
    /// error may not be the others' too, on each other endpoint in turn.
    /// Returns the first success, or the active endpoint's error. Only with
    /// `adopt` does the endpoint that answered become the active one.
    fn with_failover<T, E: std::fmt::Display>(
        &mut self,
        mut call: impl FnMut(&mut Upstream) -> Result<T, E>,
        fail_over: impl Fn(&E) -> bool,
        adopt: bool,
    ) -> Result<T, E> {
        let first = match call(&mut self.upstreams[self.active]) {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if !fail_over(&first) {
            return Err(first);
        }
        let count = self.upstreams.len();
        for step in 1..count {
            let index = (self.active + step) % count;
            match call(&mut self.upstreams[index]) {
                Ok(value) => {
                    if adopt {
                        tracing::warn!(
                            failed = %self.upstreams[self.active].endpoint().host,
                            error = %first,
                            now = %self.upstreams[index].endpoint().host,
                            "the upstream endpoint failed; following the next configured one"
                        );
                        self.active = index;
                    } else {
                        tracing::warn!(
                            failed = %self.upstreams[self.active].endpoint().host,
                            error = %first,
                            answered = %self.upstreams[index].endpoint().host,
                            "the upstream endpoint failed; the next configured one took this call"
                        );
                    }
                    return Ok(value);
                }
                Err(error) => {
                    tracing::debug!(
                        endpoint = %self.upstreams[index].endpoint().host,
                        %error,
                        "the next upstream endpoint failed too"
                    );
                }
            }
        }
        Err(first)
    }

    /// Calls `method`; a transport failure or retryable error tries the
    /// other endpoints for this call only. Only for broadcasts: chain reads
    /// use [`Self::read`].
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, CallError> {
        self.with_failover(
            |upstream| upstream.call(method, params.clone()),
            CallError::retryable,
            false,
        )
    }

    /// Calls `method` on the active endpoint only.
    pub fn read(&mut self, method: &str, params: Value) -> Result<Value, CallError> {
        self.upstreams[self.active].call(method, params)
    }

    /// One broadcast attempt per endpoint, for payments an RPC caller is
    /// waiting on; a definite refusal is not retried elsewhere.
    pub fn broadcast_once(&mut self, transaction: &[u8]) -> Result<(), BroadcastError> {
        self.with_failover(
            |upstream| upstream.broadcast_once(transaction),
            |error| matches!(error, BroadcastError::Unknown(_)),
            false,
        )
    }
}

impl ChainSource for Upstreams {
    fn tip(&mut self) -> Result<ChainTip, SourceError> {
        let outcome = self.with_failover(|upstream| upstream.tip(), |_| true, true);
        let followed = FollowedEndpoint {
            index: outcome.is_ok().then_some(self.active),
            refusal: self.refusal().map(str::to_owned),
        };
        *self
            .followed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = followed;
        outcome
    }

    // Chain reads stay on the endpoint the last `tip` accepted; if it fails,
    // the round ends and the next `tip` picks an endpoint that passes the
    // checks.
    fn block_hash(&mut self, height: u64) -> Result<Option<[u8; 32]>, SourceError> {
        self.upstreams[self.active].block_hash(height)
    }

    fn block(&mut self, hash: [u8; 32]) -> Result<Option<SourceBlock>, SourceError> {
        self.upstreams[self.active].block(hash)
    }

    fn broadcast(&mut self, transaction: &[u8]) -> Result<(), BroadcastError> {
        self.with_failover(
            |upstream| upstream.broadcast(transaction),
            |error| matches!(error, BroadcastError::Unknown(_)),
            false,
        )
    }

    fn mempool_contains(&mut self, txid: [u8; 32]) -> Result<bool, SourceError> {
        self.upstreams[self.active].mempool_contains(txid)
    }
}

fn broadcast_outcome(outcome: Result<Value, CallError>) -> Result<(), BroadcastError> {
    match outcome {
        Ok(_) => Ok(()),
        Err(CallError::Rpc {
            data_code: Some(code),
            ..
        }) if code == "transaction_already_confirmed" => Ok(()),
        Err(CallError::Rpc {
            message,
            retryable: false,
            ..
        }) => Err(BroadcastError::Rejected(message)),
        Err(error) => Err(BroadcastError::Unknown(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;

    const NETWORK: [u8; 32] = [0x11; 32];
    const CHECKPOINT: (u64, [u8; 32]) = (2, [0x02; 32]);

    /// A loopback exchange RPC that answers `getblockchaininfo` with `info`
    /// and `getblockhash` from `hashes`, one request per connection.
    struct FakeEndpoint {
        address: SocketAddr,
        info: Arc<Mutex<Value>>,
        hashes: Arc<Mutex<Vec<[u8; 32]>>>,
        /// While set, `getblockhash` fails with an internal error.
        broken: Arc<AtomicBool>,
        /// While set, `sendrawtransaction` fails with a retryable error.
        send_busy: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl FakeEndpoint {
        fn spawn(info: Value) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let info = Arc::new(Mutex::new(info));
            let hashes = Arc::new(Mutex::new((0..=5_u8).map(|height| [height; 32]).collect()));
            let broken = Arc::new(AtomicBool::new(false));
            let send_busy = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let (info, hashes, broken, send_busy, stop) = (
                    info.clone(),
                    hashes.clone(),
                    broken.clone(),
                    send_busy.clone(),
                    stop.clone(),
                );
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                answer(stream, &info, &hashes, &broken, &send_busy);
                            }
                            Err(_) => std::thread::sleep(Duration::from_millis(5)),
                        }
                    }
                })
            };
            Self {
                address,
                info,
                hashes,
                broken,
                send_busy,
                stop,
                thread: Some(thread),
            }
        }

        fn upstream(&self, checkpoint: Option<(u64, [u8; 32])>) -> Upstream {
            let endpoint =
                Endpoint::new(&format!("http://{}/", self.address), "x", "y", NETWORK).unwrap();
            Upstream::with_checkpoint(endpoint, checkpoint)
        }

        fn set(&self, pointer: &str, value: Value) {
            *self.info.lock().unwrap().pointer_mut(pointer).unwrap() = value;
        }
    }

    impl Drop for FakeEndpoint {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn answer(
        stream: std::net::TcpStream,
        info: &Mutex<Value>,
        hashes: &Mutex<Vec<[u8; 32]>>,
        broken: &AtomicBool,
        send_busy: &AtomicBool,
    ) {
        stream.set_nonblocking(false).unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some(value) = line.strip_prefix("Content-Length: ") {
                length = value.parse().unwrap();
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        let response = match request["method"].as_str().unwrap() {
            "getblockchaininfo" => json!({"result": info.lock().unwrap().clone()}),
            "getblockhash" if broken.load(Ordering::SeqCst) => {
                json!({"error": {"code": -32603, "message": "internal error",
                    "data": {"code": "internal_error", "retryable": false}}})
            }
            "getblockhash" => {
                let height = request["params"][0].as_u64().unwrap() as usize;
                match hashes.lock().unwrap().get(height) {
                    Some(hash) => json!({"result": hex::encode(hash)}),
                    None => json!({"error": {"code": -32001, "message": "not found",
                        "data": {"code": "block_not_found", "retryable": false}}}),
                }
            }
            "sendrawtransaction" if send_busy.load(Ordering::SeqCst) => {
                json!({"error": {"code": -32603, "message": "busy",
                    "data": {"code": "busy", "retryable": true}}})
            }
            "sendrawtransaction" => json!({"result": hex::encode([9_u8; 32])}),
            other => panic!("unexpected method {other}"),
        };
        let mut response = response;
        response["jsonrpc"] = json!("2.0");
        response["id"] = request["id"].clone();
        let body = serde_json::to_vec(&response).unwrap();
        let mut stream = reader.into_inner();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    }

    /// An enforcing upstream at tip 5, validated up to 4, checkpoint 3.
    fn enforcing_info() -> Value {
        json!({
            "network_id": hex::encode(NETWORK),
            "blocks": 5,
            "bestblockhash": hex::encode([5_u8; 32]),
            "work_rule": {
                "enforced": true,
                "engine_ready": true,
                "engine_state": "ready",
                "halted": false,
                "checkpoint_height": 3,
                "validated_height": 4,
            },
        })
    }

    #[test]
    fn followable_height_requires_an_enforcing_upstream_at_or_past_the_checkpoint() {
        let info = enforcing_info();
        assert_eq!(followable_height(&info, 2), Ok(4));
        // A later release's checkpoint is fine; an earlier one is not.
        assert_eq!(followable_height(&info, 3), Ok(4));
        assert!(
            followable_height(&info, 4)
                .unwrap_err()
                .contains("below this release's 4")
        );
        let mut tip_below = info.clone();
        tip_below["work_rule"]["validated_height"] = json!(9);
        assert_eq!(followable_height(&tip_below, 2), Ok(5));

        for (field, value, reason) in [
            ("enforced", json!(false), "does not re-execute"),
            ("halted", json!(true), "halted"),
            ("engine_ready", json!(false), "not ready"),
            ("checkpoint_height", Value::Null, "no work checkpoint"),
            ("validated_height", Value::Null, "no validated height"),
        ] {
            let mut info = info.clone();
            info["work_rule"][field] = value;
            let error = followable_height(&info, 2).unwrap_err();
            assert!(error.contains(reason), "{field}: {error}");
        }
        let mut missing = info.clone();
        missing.as_object_mut().unwrap().remove("work_rule");
        assert!(
            followable_height(&missing, 2)
                .unwrap_err()
                .contains("does not report the work rule")
        );
        missing["work_rule"] = Value::Null;
        assert!(followable_height(&missing, 2).is_err());
    }

    #[test]
    fn an_upstream_is_followed_only_while_it_meets_the_work_rule() {
        let server = FakeEndpoint::spawn(enforcing_info());
        let mut upstream = server.upstream(Some(CHECKPOINT));
        let tip = upstream.tip().unwrap();
        assert_eq!((tip.height, tip.hash), (4, [4; 32]));
        assert_eq!(upstream.refusal(), None);

        server.set("/work_rule/halted", json!(true));
        assert!(matches!(upstream.tip(), Err(SourceError::Unavailable(_))));
        assert!(upstream.refusal().unwrap().contains("halted"));
        server.set("/work_rule/halted", json!(false));
        assert_eq!(upstream.tip().unwrap().height, 4);
        assert_eq!(upstream.refusal(), None);

        // A chain without this release's checkpoint block is refused.
        server.hashes.lock().unwrap()[2] = [9; 32];
        upstream.tip().unwrap_err();
        assert!(upstream.refusal().unwrap().contains("checkpoint block"));
        server.hashes.lock().unwrap()[2] = CHECKPOINT.1;

        // So is a node from before the work rule.
        server
            .info
            .lock()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("work_rule");
        upstream.tip().unwrap_err();
        assert!(
            upstream
                .refusal()
                .unwrap()
                .contains("does not report the work rule")
        );

        // A network without a work rule follows the reported tip.
        let tip = server.upstream(None).tip().unwrap();
        assert_eq!((tip.height, tip.hash), (5, [5; 32]));
    }

    #[test]
    fn a_second_upstream_is_used_while_the_first_fails() {
        let first = FakeEndpoint::spawn(enforcing_info());
        let second = FakeEndpoint::spawn(enforcing_info());
        second.set("/work_rule/validated_height", json!(3));
        first.set("/work_rule/halted", json!(true));
        let mut upstreams = Upstreams::new(vec![
            first.upstream(Some(CHECKPOINT)),
            second.upstream(Some(CHECKPOINT)),
        ]);

        assert_eq!(upstreams.tip().unwrap().height, 3);
        assert_eq!(upstreams.active_endpoint().port, second.address.port());
        assert_eq!(upstreams.refusal(), None);
        // It stays on the second while that one answers.
        first.set("/work_rule/halted", json!(false));
        assert_eq!(upstreams.tip().unwrap().height, 3);
        // And goes back to the first once the second fails.
        second.set("/work_rule/engine_ready", json!(false));
        assert_eq!(upstreams.tip().unwrap().height, 4);
        assert_eq!(upstreams.active_endpoint().port, first.address.port());

        // With both refused, the active one's reason is reported.
        first.set("/work_rule/enforced", json!(false));
        upstreams.tip().unwrap_err();
        assert!(upstreams.refusal().unwrap().contains("does not re-execute"));
    }

    #[test]
    fn chain_reads_never_move_to_an_endpoint_that_has_not_passed_the_checks() {
        let first = FakeEndpoint::spawn(enforcing_info());
        let second = FakeEndpoint::spawn(enforcing_info());
        second
            .info
            .lock()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("work_rule");
        let mut upstreams = Upstreams::new(vec![
            first.upstream(Some(CHECKPOINT)),
            second.upstream(Some(CHECKPOINT)),
        ]);
        assert_eq!(upstreams.tip().unwrap().height, 4);

        // The followed endpoint fails during the round: the read fails
        // instead of being answered by the endpoint without the work rule.
        first.broken.store(true, Ordering::SeqCst);
        assert!(upstreams.block_hash(3).is_err());
        assert!(upstreams.read("getblockhash", json!([3])).is_err());
        assert_eq!(upstreams.active_endpoint().port, first.address.port());

        // The next tip refuses the second endpoint, so the wallet waits.
        first.set("/work_rule/halted", json!(true));
        upstreams.tip().unwrap_err();
        assert_eq!(upstreams.active_endpoint().port, first.address.port());
        assert!(upstreams.refusal().unwrap().contains("halted"));
        let followed = upstreams.followed();
        assert_eq!(followed.lock().unwrap().index, None);
        assert!(
            followed
                .lock()
                .unwrap()
                .refusal
                .as_deref()
                .unwrap()
                .contains("halted")
        );
    }

    #[test]
    fn a_broadcast_answered_by_the_second_endpoint_does_not_move_chain_reads() {
        let first = FakeEndpoint::spawn(enforcing_info());
        let second = FakeEndpoint::spawn(enforcing_info());
        second
            .info
            .lock()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("work_rule");
        let mut upstreams = Upstreams::new(vec![
            first.upstream(Some(CHECKPOINT)),
            second.upstream(Some(CHECKPOINT)),
        ]);
        assert_eq!(upstreams.tip().unwrap().height, 4);
        assert_eq!(
            *upstreams.followed().lock().unwrap(),
            FollowedEndpoint {
                index: Some(0),
                refusal: None
            }
        );

        // The first endpoint is busy for a payment: the second takes it, and
        // reads still go to the first, which passed the checks.
        first.send_busy.store(true, Ordering::SeqCst);
        upstreams.broadcast_once(&[1, 2, 3]).unwrap();
        assert_eq!(upstreams.active_endpoint().port, first.address.port());
        first.broken.store(true, Ordering::SeqCst);
        assert!(upstreams.read("getblockhash", json!([3])).is_err());
        assert!(upstreams.block_hash(3).is_err());
        first.broken.store(false, Ordering::SeqCst);
        assert_eq!(upstreams.block_hash(3).unwrap(), Some([3; 32]));
        assert_eq!(upstreams.followed().lock().unwrap().index, Some(0));

        // A second set of connections reads from the endpoint followed.
        let mut reads = Upstreams::new(vec![
            first.upstream(Some(CHECKPOINT)),
            second.upstream(Some(CHECKPOINT)),
        ]);
        reads.use_endpoint(1);
        assert_eq!(reads.active_endpoint().port, second.address.port());
        reads.use_endpoint(5);
        assert_eq!(reads.active_endpoint().port, second.address.port());
    }

    #[test]
    fn the_primary_is_followed_again_only_once_it_reaches_the_wallet() {
        let first = FakeEndpoint::spawn(enforcing_info());
        let second = FakeEndpoint::spawn(enforcing_info());
        first.set("/work_rule/halted", json!(true));
        let mut upstreams = Upstreams::new(vec![
            first.upstream(Some(CHECKPOINT)),
            second.upstream(Some(CHECKPOINT)),
        ]);
        assert_eq!(upstreams.tip().unwrap().height, 4);
        assert!(upstreams.on_fallback());
        assert_eq!(upstreams.followed().lock().unwrap().index, Some(1));

        // Still refused: stay on the second.
        assert!(!upstreams.retry_primary(4));
        assert!(upstreams.on_fallback());

        // The primary passes again but has checked only up to height 3 while
        // the wallet is at 4: stay on the second, which keeps the wallet
        // moving.
        first.set("/work_rule/halted", json!(false));
        first.set("/work_rule/validated_height", json!(3));
        assert!(!upstreams.retry_primary(4));
        assert!(upstreams.on_fallback());
        assert_eq!(upstreams.tip().unwrap().height, 4);
        assert_eq!(upstreams.followed().lock().unwrap().index, Some(1));

        // Once it reaches the wallet it is followed again.
        first.set("/work_rule/validated_height", json!(4));
        assert!(upstreams.retry_primary(4));
        assert!(!upstreams.on_fallback());
        assert_eq!(upstreams.tip().unwrap().height, 4);
        assert_eq!(upstreams.followed().lock().unwrap().index, Some(0));
        assert!(upstreams.retry_primary(10));
    }
}
