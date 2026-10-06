//! JSON-RPC client for the exchange RPC endpoint that feeds the exchange
//! wallet: the hosted endpoint over HTTPS or the exchange's own node.

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
}

impl Upstream {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            connection: None,
            next_id: 1,
        }
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

impl ChainSource for Upstream {
    fn tip(&mut self) -> Result<ChainTip, SourceError> {
        let info = self.chain_info()?;
        Ok(ChainTip {
            height: info.get("blocks").and_then(Value::as_u64).ok_or_else(|| {
                SourceError::Invalid("getblockchaininfo has no blocks".to_owned())
            })?,
            hash: hash_field(&info, "bestblockhash")?,
        })
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
