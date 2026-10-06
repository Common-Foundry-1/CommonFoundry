//! Authenticated, Bitcoin-shaped RPC for exchange integrations.
//!
//! This surface is deliberately separate from the native development RPC. It
//! exposes chain reads, canonical transaction broadcast, durable deposit
//! events, and an explicitly enabled withdrawal signer with separate
//! credentials.

use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
#[cfg(test)]
use cmfd_consensus::decode_block;
use cmfd_consensus::{
    InputWitness, MAX_TRANSACTION_BYTES, OutputLock, Transaction, TxOutput, decode_transaction,
    encode_transaction,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::exchange_custody_engine::{
    CustodyTerminalActionV3, ExchangeCustodyEngineError, UnsignedApprovalDocumentV3,
};
use crate::exchange_custody_runtime_v3::{
    ExchangeCustodyRuntimeV3, ExchangeCustodyRuntimeV3Error, RuntimeJournalInfoV3,
    RuntimeWithdrawalPhaseV3, RuntimeWithdrawalStatusV3, RuntimeWithdrawalViewV3,
};
use crate::exchange_custody_v3::load_external_secret_document_v3;
use crate::exchange_index::{
    DepositEvent, DepositEventPage, ExchangeDepositIndex, ExchangeIndexError, MAX_ACTIVE_DEPOSITS,
    MAX_DEPOSIT_EVENT_PAGE, MAX_DEPOSIT_EVENTS, MAX_WATCH_DESTINATIONS,
    MAX_WATCH_REGISTRATION_BATCH, RegisterWatchDestinationResult, RegisterWatchDestinationsResult,
    WatchDestinationRegistration, WatchDestinationView,
};
use crate::exchange_queries::{
    MAX_UTXO_PAGE, QueryError, TransactionBody, UtxoCursor, address_balance, address_utxos,
};
use crate::exchange_withdrawal::{
    ExchangeWithdrawalError, ExchangeWithdrawalJournal, WithdrawalJournalAnchor,
    WithdrawalJournalInfo, WithdrawalRequest, WithdrawalView,
};
use crate::wallet_signing_protocol::{
    MAX_SIGNER_RESPONSE_BYTES, ReleaseAuthorizationV1, SignerResponseV1, SigningPackageV1,
    WithdrawalAnchorV1, release_authorization_digest,
};
use crate::{
    BLOCK_LOG_FILE, BlockRecordLocator, DeadlineReader, ExchangeCustodyV3Config, Node, NodeError,
    ProofProfile, RPC_READ_TIMEOUT, RPC_TOTAL_READ_TIMEOUT, RPC_WRITE_TIMEOUT, RpcResponse,
    has_json_content_type, join_rpc_thread, read_rpc_request_body, read_rpc_request_head,
    rpc_stopped, signal_rpc_stop, wait_for_rpc_stop, write_rpc_response,
};

const MINIMUM_PASSWORD_BYTES: usize = 16;
const MAXIMUM_AUTH_FILE_BYTES: usize = 1_024;
const MAXIMUM_USERNAME_BYTES: usize = 64;
const MAXIMUM_CONCURRENT_REQUESTS: usize = 4;
const SYNC_OBSERVATION_MAX_AGE_SECS: u64 = 60;
pub const EXCHANGE_RPC_API_VERSION: &str = "chain-preview-v0.4";
pub const EXCHANGE_CUSTODY_RPC_API_VERSION: &str = "chain-preview-v0.5";

type SharedExchangeDepositIndex = Arc<Mutex<ExchangeDepositIndex>>;
type SharedExchangeWithdrawalJournal = Arc<Mutex<ExchangeWithdrawalJournal>>;
type SharedExchangeCustodyRuntimeV3 = Arc<Mutex<ExchangeCustodyRuntimeV3>>;

#[derive(Clone)]
enum SharedWithdrawalBackend {
    V2(SharedExchangeWithdrawalJournal),
    V3(SharedExchangeCustodyRuntimeV3),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthorizationScope {
    Integration,
    Withdrawal,
}

struct ExchangeAuthorization {
    integration: Zeroizing<Vec<u8>>,
    withdrawal: Option<Zeroizing<Vec<u8>>>,
}

/// A cancellable, separately authenticated exchange RPC listener.
pub struct ExchangeRpcServerHandle {
    local_address: SocketAddr,
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<Result<(), NodeError>>>,
    _ownership: ExchangeRpcOwnership,
}

struct ExchangeRpcOwnership {
    shared: Arc<Mutex<Node>>,
}

impl ExchangeRpcOwnership {
    fn claim(shared: &Arc<Mutex<Node>>) -> Result<Self, NodeError> {
        let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        if node.exchange_rpc_active {
            return Err(NodeError::ExchangeRpcAlreadyActive);
        }
        node.exchange_rpc_active = true;
        drop(node);
        Ok(Self {
            shared: Arc::clone(shared),
        })
    }
}

impl Drop for ExchangeRpcOwnership {
    fn drop(&mut self) {
        let mut node = self
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        node.exchange_rpc_active = false;
    }
}

impl ExchangeRpcServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_address
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }

    pub fn stop(mut self) -> Result<(), NodeError> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), NodeError> {
        signal_rpc_stop(&self.stop)?;
        join_rpc_thread(self.thread.take())
    }
}

impl Drop for ExchangeRpcServerHandle {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

/// Starts the opt-in exchange RPC. The listener is always loopback-only, and
/// each authentication file is read exactly once before the listener starts.
///
/// Each authentication file must contain `username:password`, with a password
/// of at least 16 visible ASCII bytes. On Unix it must be mode 0600 or stricter.
/// The optional withdrawal credential must differ from the integration
/// credential and is accepted only by the withdrawal methods.
pub fn spawn_exchange_rpc_server(
    shared: Arc<Mutex<Node>>,
    bind: SocketAddr,
    authentication_file: &Path,
    withdrawal_authentication_file: Option<&Path>,
) -> Result<ExchangeRpcServerHandle, NodeError> {
    if !bind.ip().is_loopback() {
        return Err(NodeError::NonLoopbackRpc(bind));
    }
    let integration = expected_authorization_token(authentication_file)?;
    let withdrawal = withdrawal_authentication_file
        .map(expected_authorization_token)
        .transpose()?;
    if withdrawal
        .as_ref()
        .is_some_and(|withdrawal| constant_time_equal(withdrawal, &integration))
    {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "withdrawal credential must differ from the integration credential",
        ));
    }
    let withdrawals_enabled = withdrawal.is_some();
    let expected_authorization = Arc::new(ExchangeAuthorization {
        integration,
        withdrawal,
    });
    // Both durable exchange stores are single-writer snapshots. Claim their
    // sole listener owner before either store is opened, and retain it until
    // the listener thread has stopped.
    let ownership = ExchangeRpcOwnership::claim(&shared)?;
    let network_id = shared
        .lock()
        .map_err(|_| NodeError::SharedNodePoisoned)?
        .params
        .network_id;
    let exchange_index = Arc::new(Mutex::new(
        ExchangeDepositIndex::open_and_sync(&shared).map_err(exchange_index_startup_error)?,
    ));
    let withdrawal_backend = withdrawals_enabled
        .then(|| {
            ExchangeWithdrawalJournal::open_and_reconcile(&shared)
                .map(|journal| SharedWithdrawalBackend::V2(Arc::new(Mutex::new(journal))))
                .map_err(exchange_withdrawal_startup_error)
        })
        .transpose()?;
    let listener = TcpListener::bind(bind).map_err(NodeError::RpcIo)?;
    let local_address = listener.local_addr().map_err(NodeError::RpcIo)?;
    if !local_address.ip().is_loopback() {
        return Err(NodeError::NonLoopbackRpc(local_address));
    }
    listener.set_nonblocking(true).map_err(NodeError::RpcIo)?;

    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("cmfd-exchange-rpc-listener".to_owned())
        .spawn(move || {
            exchange_rpc_listener_loop(
                shared,
                exchange_index,
                withdrawal_backend,
                listener,
                thread_stop,
                expected_authorization,
                network_id,
            )
        })
        .map_err(NodeError::RpcIo)?;

    Ok(ExchangeRpcServerHandle {
        local_address,
        stop,
        thread: Some(thread),
        _ownership: ownership,
    })
}

/// Starts the explicit v3 custody listener. Unlike the v0.4 entry point, this
/// mode always requires a distinct withdrawal credential and activates the
/// policy/keyring-backed custody runtime before accepting requests.
pub fn spawn_exchange_rpc_server_v3(
    shared: Arc<Mutex<Node>>,
    bind: SocketAddr,
    authentication_file: &Path,
    withdrawal_authentication_file: &Path,
    custody_config: &ExchangeCustodyV3Config,
    keyring_passphrase_file: &Path,
) -> Result<ExchangeRpcServerHandle, NodeError> {
    if !bind.ip().is_loopback() {
        return Err(NodeError::NonLoopbackRpc(bind));
    }
    let data_dir = shared
        .lock()
        .map_err(|_| NodeError::SharedNodePoisoned)?
        .data_dir()
        .to_path_buf();
    let integration = expected_authorization_token_v3(&data_dir, authentication_file)?;
    let withdrawal = expected_authorization_token_v3(&data_dir, withdrawal_authentication_file)?;
    let expected_authorization =
        Arc::new(distinct_exchange_authorization(integration, withdrawal)?);
    let ownership = ExchangeRpcOwnership::claim(&shared)?;
    let network_id = shared
        .lock()
        .map_err(|_| NodeError::SharedNodePoisoned)?
        .params
        .network_id;
    let exchange_index = Arc::new(Mutex::new(
        ExchangeDepositIndex::open_and_sync(&shared).map_err(exchange_index_startup_error)?,
    ));
    let custody = ExchangeCustodyRuntimeV3::open_from_passphrase_file(
        &shared,
        custody_config,
        keyring_passphrase_file,
    )
    .map_err(exchange_custody_v3_startup_error)?;
    let withdrawal_backend = Some(SharedWithdrawalBackend::V3(Arc::new(Mutex::new(custody))));
    let listener = TcpListener::bind(bind).map_err(NodeError::RpcIo)?;
    let local_address = listener.local_addr().map_err(NodeError::RpcIo)?;
    if !local_address.ip().is_loopback() {
        return Err(NodeError::NonLoopbackRpc(local_address));
    }
    listener.set_nonblocking(true).map_err(NodeError::RpcIo)?;

    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("cmfd-exchange-rpc-v3-listener".to_owned())
        .spawn(move || {
            exchange_rpc_listener_loop(
                shared,
                exchange_index,
                withdrawal_backend,
                listener,
                thread_stop,
                expected_authorization,
                network_id,
            )
        })
        .map_err(NodeError::RpcIo)?;

    Ok(ExchangeRpcServerHandle {
        local_address,
        stop,
        thread: Some(thread),
        _ownership: ownership,
    })
}

fn expected_authorization_token(path: &Path) -> Result<Zeroizing<Vec<u8>>, NodeError> {
    if !path.is_absolute() {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "path must be absolute",
        ));
    }
    let file = File::open(path)
        .map_err(|source| crate::io_error("open exchange RPC authentication", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| crate::io_error("inspect exchange RPC authentication", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "path must name a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(NodeError::InsecureExchangeRpcAuthFilePermissions);
        }
    }
    let mut credential = Zeroizing::new(Vec::new());
    file.take((MAXIMUM_AUTH_FILE_BYTES + 3) as u64)
        .read_to_end(&mut credential)
        .map_err(|source| crate::io_error("read exchange RPC authentication", path, source))?;
    authorization_token_from_credential(credential)
}

fn expected_authorization_token_v3(
    data_dir: &Path,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, NodeError> {
    let credential = load_external_secret_document_v3(
        data_dir,
        path,
        MAXIMUM_AUTH_FILE_BYTES + 2,
        "exchange RPC authentication",
    )
    .map_err(|_| {
        NodeError::InvalidExchangeRpcAuthFile(
            "v3 credential failed external-secret path or permission validation",
        )
    })?;
    authorization_token_from_credential(credential)
}

fn authorization_token_from_credential(
    mut credential: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, NodeError> {
    if credential.last() == Some(&b'\n') {
        credential.pop();
        if credential.last() == Some(&b'\r') {
            credential.pop();
        }
    }
    if credential.len() > MAXIMUM_AUTH_FILE_BYTES {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "credential exceeds 1024 bytes",
        ));
    }
    if !credential.iter().all(u8::is_ascii_graphic) {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "credential must contain visible ASCII without whitespace",
        ));
    }
    let Some(separator) = credential.iter().position(|byte| *byte == b':') else {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "credential must contain username:password",
        ));
    };
    if separator == 0 || separator > MAXIMUM_USERNAME_BYTES {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "username must contain between 1 and 64 bytes",
        ));
    }
    if credential.len().saturating_sub(separator + 1) < MINIMUM_PASSWORD_BYTES {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "password must contain at least 16 bytes",
        ));
    }

    Ok(Zeroizing::new(
        BASE64_STANDARD.encode(credential.as_slice()).into_bytes(),
    ))
}

fn distinct_exchange_authorization(
    integration: Zeroizing<Vec<u8>>,
    withdrawal: Zeroizing<Vec<u8>>,
) -> Result<ExchangeAuthorization, NodeError> {
    if constant_time_equal(&withdrawal, &integration) {
        return Err(NodeError::InvalidExchangeRpcAuthFile(
            "withdrawal credential must differ from the integration credential",
        ));
    }
    Ok(ExchangeAuthorization {
        integration,
        withdrawal: Some(withdrawal),
    })
}

fn exchange_rpc_listener_loop(
    shared: Arc<Mutex<Node>>,
    exchange_index: SharedExchangeDepositIndex,
    withdrawal_backend: Option<SharedWithdrawalBackend>,
    listener: TcpListener,
    stop: Arc<(Mutex<bool>, Condvar)>,
    expected_authorization: Arc<ExchangeAuthorization>,
    network_id: [u8; 32],
) -> Result<(), NodeError> {
    let mut workers = Vec::with_capacity(MAXIMUM_CONCURRENT_REQUESTS);
    let listener_result = loop {
        if let Err(error) = reap_exchange_workers(&mut workers) {
            break Err(error);
        }
        match rpc_stopped(&stop) {
            Ok(true) => break Ok(()),
            Ok(false) => {}
            Err(error) => break Err(error),
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(error) = stream.set_nonblocking(false) {
                    break Err(NodeError::RpcIo(error));
                }
                if workers.len() >= MAXIMUM_CONCURRENT_REQUESTS {
                    let response = RpcResponse::json_error(
                        503,
                        "Service Unavailable",
                        "exchange RPC request capacity is full",
                    );
                    let _ = write_rpc_response(&mut stream, response);
                    continue;
                }
                let worker_node = Arc::clone(&shared);
                let worker_exchange_index = Arc::clone(&exchange_index);
                let worker_withdrawal_backend = withdrawal_backend.clone();
                let worker_authorization = Arc::clone(&expected_authorization);
                let worker = match thread::Builder::new()
                    .name("cmfd-exchange-rpc-request".to_owned())
                    .spawn(move || {
                        if let Err(error) = handle_exchange_connection(
                            &mut stream,
                            &worker_node,
                            &worker_exchange_index,
                            worker_withdrawal_backend.as_ref(),
                            &worker_authorization,
                            network_id,
                        ) {
                            let _ = write_rpc_response(&mut stream, RpcResponse::node_error(error));
                        }
                    }) {
                    Ok(worker) => worker,
                    Err(error) => break Err(NodeError::RpcIo(error)),
                };
                workers.push(worker);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                match wait_for_rpc_stop(&stop) {
                    Ok(true) => break Ok(()),
                    Ok(false) => {}
                    Err(error) => break Err(error),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => break Err(NodeError::RpcIo(error)),
        }
    };
    let cleanup_result = join_exchange_workers(workers);
    match listener_result {
        Err(error) => {
            let _ = cleanup_result;
            Err(error)
        }
        Ok(()) => cleanup_result,
    }
}

fn reap_exchange_workers(workers: &mut Vec<JoinHandle<()>>) -> Result<(), NodeError> {
    let mut index = 0;
    let mut worker_panicked = false;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            worker_panicked |= worker.join().is_err();
        } else {
            index += 1;
        }
    }
    if worker_panicked {
        let _ = join_exchange_workers(std::mem::take(workers));
        Err(exchange_worker_panic_error())
    } else {
        Ok(())
    }
}

fn join_exchange_workers(workers: Vec<JoinHandle<()>>) -> Result<(), NodeError> {
    let mut worker_panicked = false;
    for worker in workers {
        worker_panicked |= worker.join().is_err();
    }
    if worker_panicked {
        Err(exchange_worker_panic_error())
    } else {
        Ok(())
    }
}

fn exchange_worker_panic_error() -> NodeError {
    NodeError::RpcIo(std::io::Error::other(
        "exchange RPC request worker panicked",
    ))
}

fn handle_exchange_connection(
    stream: &mut TcpStream,
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
    withdrawal_backend: Option<&SharedWithdrawalBackend>,
    expected_authorization: &ExchangeAuthorization,
    network_id: [u8; 32],
) -> Result<(), NodeError> {
    stream
        .set_read_timeout(Some(RPC_READ_TIMEOUT))
        .map_err(NodeError::RpcIo)?;
    stream
        .set_write_timeout(Some(RPC_WRITE_TIMEOUT))
        .map_err(NodeError::RpcIo)?;
    let mut reader =
        DeadlineReader::new(stream, RPC_TOTAL_READ_TIMEOUT).map_err(NodeError::RpcIo)?;
    let head = match read_rpc_request_head(&mut reader, network_id) {
        Ok(head) => head,
        Err(error) => return write_rpc_response(stream, RpcResponse::node_error(error)),
    };

    let authorization_scope = authorization_scope(
        head.authorization.as_ref().map(|value| value.as_str()),
        expected_authorization,
    );
    let authorized_scope = authorization_scope.unwrap_or(AuthorizationScope::Integration);
    let response = if authorization_scope.is_none() {
        RpcResponse::json(401, "Unauthorized", json!({ "error": "unauthorized" }))
            .with_basic_auth_challenge()
    } else if head.method != "POST" {
        RpcResponse::json_error(405, "Method Not Allowed", "exchange RPC requires POST")
    } else if head.target != "/" {
        RpcResponse::json_error(404, "Not Found", "exchange RPC endpoint is /")
    } else if !has_json_content_type(head.content_type.as_deref()) {
        RpcResponse::json_error(
            415,
            "Unsupported Media Type",
            "Content-Type must be application/json",
        )
    } else {
        if head.expect_continue {
            reader.write_continue()?;
        }
        let request = match read_rpc_request_body(&mut reader, head) {
            Ok(request) => request,
            Err(error) => return write_rpc_response(stream, RpcResponse::node_error(error)),
        };
        let document = match parse_json_rpc(&request.body) {
            Ok(request) => dispatch_shared_request_scoped_backend(
                request,
                shared,
                exchange_index,
                withdrawal_backend,
                network_id,
                authorized_scope,
            ),
            Err(response) => response,
        };
        RpcResponse::json(200, "OK", document)
    };
    write_rpc_response(stream, response)
}

fn authorization_matches(actual: Option<&str>, expected: &[u8]) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    let mut parts = actual.split_ascii_whitespace();
    let (Some(scheme), Some(token), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let token = token.as_bytes();
    constant_time_equal(token, expected)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn authorization_scope(
    actual: Option<&str>,
    expected: &ExchangeAuthorization,
) -> Option<AuthorizationScope> {
    if expected
        .withdrawal
        .as_ref()
        .is_some_and(|withdrawal| authorization_matches(actual, withdrawal))
    {
        Some(AuthorizationScope::Withdrawal)
    } else if authorization_matches(actual, &expected.integration) {
        Some(AuthorizationScope::Integration)
    } else {
        None
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchRegistrationParameter {
    label: String,
    destination_hex: String,
}

enum BlockReadPlan {
    Virtual(Value),
    Persisted(Box<PersistedBlockReadPlan>),
}

struct PersistedBlockReadPlan {
    node_instance_id: u64,
    log: crate::LogReadHandle,
    log_path: PathBuf,
    locator: BlockRecordLocator,
    network_id: [u8; 32],
    require_v2: bool,
    block_id: [u8; 32],
    confirmations: Option<u64>,
    next_block: Option<[u8; 32]>,
    verbosity: u64,
}

#[derive(Debug)]
struct RpcFault {
    code: i32,
    message: String,
    data_code: &'static str,
    retryable: bool,
}

impl RpcFault {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
            data_code: "invalid_params",
            retryable: false,
        }
    }

    fn not_found(data_code: &'static str, message: &'static str) -> Self {
        Self {
            code: -32001,
            message: message.to_owned(),
            data_code,
            retryable: false,
        }
    }
}

#[cfg(test)]
fn dispatch_json_rpc(body: &[u8], node: &mut Node) -> Value {
    match parse_json_rpc(body) {
        Ok(request) => dispatch_request(request, node),
        Err(response) => response,
    }
}

fn parse_json_rpc(body: &[u8]) -> Result<ExchangeRequest, Value> {
    let document: Value = match serde_json::from_slice(body) {
        Ok(document) => document,
        Err(_) => {
            return Err(rpc_failure(
                Value::Null,
                RpcFault {
                    code: -32700,
                    message: "parse error".to_owned(),
                    data_code: "parse_error",
                    retryable: false,
                },
            ));
        }
    };
    if document.is_array() {
        return Err(rpc_failure(
            Value::Null,
            RpcFault {
                code: -32600,
                message: "batch requests are not supported by this API version".to_owned(),
                data_code: "batch_unsupported",
                retryable: false,
            },
        ));
    }
    let Some(object) = document.as_object() else {
        return Err(invalid_request(
            Value::Null,
            "request must be a JSON object",
            "invalid_request",
        ));
    };
    let Some(id) = object.get("id").cloned() else {
        return Err(invalid_request(
            Value::Null,
            "notifications are not supported by this API version",
            "notification_unsupported",
        ));
    };
    if !(id.is_string() || id.is_number()) {
        return Err(invalid_request(
            Value::Null,
            "id must be a string or number",
            "invalid_request",
        ));
    }
    let request: ExchangeRequest = match serde_json::from_value(document) {
        Ok(request) => request,
        Err(_) => {
            return Err(invalid_request(
                id,
                "request fields are missing or invalid",
                "invalid_request",
            ));
        }
    };
    if request.jsonrpc != "2.0" || request.method.is_empty() {
        return Err(invalid_request(
            request.id,
            "jsonrpc must be 2.0 and method must be nonempty",
            "invalid_request",
        ));
    }
    Ok(request)
}

#[cfg(test)]
fn dispatch_request(request: ExchangeRequest, node: &mut Node) -> Value {
    let prepared_transaction = match prepare_broadcast_transaction(&request, node.params.network_id)
    {
        Ok(transaction) => transaction,
        Err(error) => return rpc_failure(request.id, error),
    };
    let result = route_method(&request.method, &request.params, node, prepared_transaction);
    finish_request(request.id, result)
}

#[cfg(test)]
fn dispatch_shared_request(
    request: ExchangeRequest,
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
    network_id: [u8; 32],
) -> Value {
    dispatch_shared_request_scoped(
        request,
        shared,
        exchange_index,
        None,
        network_id,
        AuthorizationScope::Integration,
    )
}

#[cfg(test)]
fn dispatch_shared_request_scoped(
    request: ExchangeRequest,
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
    withdrawal_journal: Option<&SharedExchangeWithdrawalJournal>,
    network_id: [u8; 32],
    authorization_scope: AuthorizationScope,
) -> Value {
    let backend = withdrawal_journal.cloned().map(SharedWithdrawalBackend::V2);
    dispatch_shared_request_scoped_backend(
        request,
        shared,
        exchange_index,
        backend.as_ref(),
        network_id,
        authorization_scope,
    )
}

fn dispatch_shared_request_scoped_backend(
    request: ExchangeRequest,
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
    withdrawal_backend: Option<&SharedWithdrawalBackend>,
    network_id: [u8; 32],
    authorization_scope: AuthorizationScope,
) -> Value {
    let is_withdrawal = is_withdrawal_method(&request.method);
    if is_withdrawal {
        let result = if authorization_scope != AuthorizationScope::Withdrawal {
            Err(RpcFault {
                code: -32010,
                message: "a separately scoped withdrawal credential is required".to_owned(),
                data_code: "withdrawal_authorization_required",
                retryable: false,
            })
        } else if let Some(backend) = withdrawal_backend {
            route_withdrawal_backend(&request.method, &request.params, shared, backend)
        } else {
            Err(RpcFault {
                code: -32010,
                message: "withdrawal methods are not enabled on this listener".to_owned(),
                data_code: "withdrawals_disabled",
                retryable: false,
            })
        };
        return finish_request(request.id, result);
    }
    if authorization_scope == AuthorizationScope::Withdrawal {
        return rpc_failure(
            request.id,
            RpcFault {
                code: -32010,
                message: "withdrawal credentials authorize only withdrawal methods".to_owned(),
                data_code: "withdrawal_scope_only",
                retryable: false,
            },
        );
    }
    let prepared_transaction = match prepare_broadcast_transaction(&request, network_id) {
        Ok(transaction) => transaction,
        Err(error) => return rpc_failure(request.id, error),
    };
    if request.method == "getblock" {
        let result = route_getblock_shared(&request.params, shared);
        return finish_request(request.id, result);
    }
    if matches!(
        request.method.as_str(),
        "getrawtransaction" | "gettransaction"
    ) {
        let result =
            route_get_transaction(&request.method, &request.params, shared, exchange_index);
        return finish_request(request.id, result);
    }
    let exchange_index_result = match request.method.as_str() {
        "getexchangeinfo" => Some(route_get_exchange_info(
            &request.params,
            shared,
            exchange_index,
            withdrawal_backend,
        )),
        "registerwatchdestination" => Some(route_register_watch_destination(
            &request.params,
            shared,
            exchange_index,
        )),
        "registerwatchdestinations" => Some(route_register_watch_destinations(
            &request.params,
            shared,
            exchange_index,
        )),
        "getwatchdestination" => Some(route_get_watch_destination(&request.params, exchange_index)),
        "getdepositevents" => Some(route_get_deposit_events(
            &request.params,
            shared,
            exchange_index,
        )),
        _ => None,
    };
    if let Some(result) = exchange_index_result {
        return finish_request(request.id, result);
    }
    let result = match shared.lock() {
        Ok(mut node) => route_method(
            &request.method,
            &request.params,
            &mut node,
            prepared_transaction,
        ),
        Err(_) => Err(node_fault(NodeError::SharedNodePoisoned)),
    };
    finish_request(request.id, result)
}

fn is_withdrawal_method(method: &str) -> bool {
    matches!(
        method,
        "preparewithdrawal"
            | "getwithdrawalsigningpackage"
            | "getwithdrawalapprovalpayload"
            | "releasewithdrawal"
            | "cancelwithdrawal"
            | "getwithdrawal"
            | "getwithdrawaljournalinfo"
    )
}

fn route_withdrawal_backend(
    method: &str,
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    backend: &SharedWithdrawalBackend,
) -> Result<Value, RpcFault> {
    match backend {
        SharedWithdrawalBackend::V2(journal) if is_withdrawal_method_v2(method) => {
            route_withdrawal_method(method, params, shared, journal)
        }
        SharedWithdrawalBackend::V2(_) => Err(RpcFault {
            code: -32011,
            message: "withdrawal method requires the explicit v3 custody listener".to_owned(),
            data_code: "withdrawal_method_requires_v3",
            retryable: false,
        }),
        SharedWithdrawalBackend::V3(runtime) => {
            route_withdrawal_method_v3(method, params, shared, runtime)
        }
    }
}

fn is_withdrawal_method_v2(method: &str) -> bool {
    matches!(
        method,
        "preparewithdrawal" | "releasewithdrawal" | "getwithdrawal" | "getwithdrawaljournalinfo"
    )
}

fn route_withdrawal_method(
    method: &str,
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    withdrawal_journal: &SharedExchangeWithdrawalJournal,
) -> Result<Value, RpcFault> {
    match method {
        "preparewithdrawal" => route_prepare_withdrawal(params, shared, withdrawal_journal),
        "releasewithdrawal" => route_release_withdrawal(params, shared, withdrawal_journal),
        "getwithdrawal" => route_get_withdrawal(params, shared, withdrawal_journal),
        "getwithdrawaljournalinfo" => route_get_withdrawal_journal_info(params, withdrawal_journal),
        _ => unreachable!("withdrawal method was classified before routing"),
    }
}

fn route_withdrawal_method_v3(
    method: &str,
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<Value, RpcFault> {
    match method {
        "preparewithdrawal" => route_prepare_withdrawal_v3(params, shared, runtime),
        "getwithdrawalsigningpackage" => {
            route_get_withdrawal_signing_package_v3(params, shared, runtime)
        }
        "getwithdrawalapprovalpayload" => {
            route_get_withdrawal_approval_payload_v3(params, shared, runtime)
        }
        "releasewithdrawal" => route_release_withdrawal_v3(params, shared, runtime),
        "cancelwithdrawal" => route_cancel_withdrawal_v3(params, shared, runtime),
        "getwithdrawal" => route_get_withdrawal_v3(params, shared, runtime),
        "getwithdrawaljournalinfo" => route_get_withdrawal_journal_info_v3(params, shared, runtime),
        _ => unreachable!("v3 withdrawal method was classified before routing"),
    }
}

fn route_prepare_withdrawal_v3(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 4, 4)?;
    let request = WithdrawalRequest {
        request_id: string(&params[0], "request_id")?.to_owned(),
        destination: hash_parameter(&params[1], "destination")?,
        amount_atoms: canonical_decimal_u64_string(&params[2], "amount_atoms")?,
        fee_atoms: canonical_decimal_u64_string(&params[3], "fee_atoms")?,
    };
    let mut runtime = lock_custody_runtime_v3(runtime)?;
    let view = runtime
        .prepare(shared, &request)
        .map_err(exchange_custody_v3_fault)?;
    Ok(withdrawal_document_v3(&view))
}

fn route_get_withdrawal_signing_package_v3(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 2, 2)?;
    let request_id = string(&params[0], "request_id")?;
    let signed_approval = &params[1];
    let signed_approval_bytes = signed_approval_document(signed_approval)?;
    let runtime = lock_custody_runtime_v3(runtime)?;
    let view = runtime
        .authorized_signing_package(shared, request_id, &signed_approval_bytes)
        .map_err(exchange_custody_v3_fault)?;
    let package = view.signer_package_bytes.as_ref().ok_or_else(|| RpcFault {
        code: -32009,
        message: "withdrawal does not have a durable signer package".to_owned(),
        data_code: "withdrawal_signer_package_unavailable",
        retryable: false,
    })?;
    let protocol_package = SigningPackageV1::decode(package).map_err(|_| RpcFault {
        code: -32007,
        message: "durable signer package is invalid".to_owned(),
        data_code: "exchange_custody_v3_signing_protocol",
        retryable: false,
    })?;
    let protocol_digest = protocol_package.digest().map_err(|_| RpcFault {
        code: -32007,
        message: "durable signer package is invalid".to_owned(),
        data_code: "exchange_custody_v3_signing_protocol",
        retryable: false,
    })?;
    let decision_id = view.decision_id.ok_or_else(|| RpcFault {
        code: -32603,
        message: "release-authorized withdrawal is missing its decision id".to_owned(),
        data_code: "exchange_custody_v3_internal",
        retryable: false,
    })?;
    let approval_digest = view.approval_digest.ok_or_else(|| RpcFault {
        code: -32603,
        message: "release-authorized withdrawal is missing its approval digest".to_owned(),
        data_code: "exchange_custody_v3_internal",
        retryable: false,
    })?;
    let approval_action_anchor = view.action_anchor.ok_or_else(|| RpcFault {
        code: -32603,
        message: "release-authorized withdrawal is missing its approval action anchor".to_owned(),
        data_code: "exchange_custody_v3_internal",
        retryable: false,
    })?;
    let release_authorization_digest = release_authorization_digest(
        &protocol_digest,
        ReleaseAuthorizationV1 {
            release_authorized_anchor: WithdrawalAnchorV1 {
                key_id: view.current_anchor.key_id,
                journal_instance_id: view.current_anchor.journal_instance_id,
                generation: view.current_anchor.generation,
                commitment: view.current_anchor.commitment,
            },
            decision_id,
            approval_digest,
        },
    )
    .map_err(|_| RpcFault {
        code: -32603,
        message: "release-authorized signer context is invalid".to_owned(),
        data_code: "exchange_custody_v3_internal",
        retryable: false,
    })?;
    Ok(json!({
        "api_version": EXCHANGE_CUSTODY_RPC_API_VERSION,
        "request_id": view.request_id,
        "request_digest": hex::encode(view.request_digest),
        "current_anchor": withdrawal_anchor_document_v3(&view.current_anchor),
        "prepared_anchor": view.prepared_anchor.as_ref().map(withdrawal_anchor_document_v3),
        "approval_action_anchor": withdrawal_anchor_document_v3(&approval_action_anchor),
        "signing_digest": hex::encode(view.signing_digest),
        "signer_package_digest": hex::encode(protocol_digest),
        "signer_package_bytes_digest": view.signer_package_digest.map(hex::encode),
        "signer_package_base64": BASE64_STANDARD.encode(package),
        "release_authorization": {
            "release_authorized_anchor": withdrawal_anchor_document_v3(&view.current_anchor),
            "decision_id": hex::encode(decision_id),
            "approval_digest": hex::encode(approval_digest),
            "release_authorization_digest": hex::encode(release_authorization_digest),
            "signed_approval": signed_approval,
        },
    }))
}

fn route_get_withdrawal_approval_payload_v3(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 5, 5)?;
    let request_id = string(&params[0], "request_id")?;
    let action = match string(&params[1], "action")? {
        "release" => CustodyTerminalActionV3::Release,
        "cancel" => CustodyTerminalActionV3::Cancel,
        _ => return Err(RpcFault::invalid_params("action must be release or cancel")),
    };
    let decision_id = hash_parameter(&params[2], "decision_id")?;
    let authorized_at = canonical_decimal_u64_string(&params[3], "authorized_at_unix_seconds")?;
    let expires_at = canonical_decimal_u64_string(&params[4], "expires_at_unix_seconds")?;
    let runtime = lock_custody_runtime_v3(runtime)?;
    let payload = runtime
        .approval_payload(
            shared,
            action,
            request_id,
            decision_id,
            authorized_at,
            expires_at,
        )
        .map_err(exchange_custody_v3_fault)?;
    approval_payload_document_v3(&payload)
}

fn route_release_withdrawal_v3(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 2, 3)?;
    let request_id = string(&params[0], "request_id")?;
    let approval = signed_approval_document(&params[1])?;
    let external_responses = params
        .get(2)
        .map(external_signer_response_bytes)
        .transpose()?
        .unwrap_or_default();
    let mut runtime = lock_custody_runtime_v3(runtime)?;
    let view = runtime
        .release_with_current_time(shared, request_id, &approval, &external_responses)
        .map_err(exchange_custody_v3_fault)?;
    Ok(withdrawal_document_v3(&view))
}

fn route_cancel_withdrawal_v3(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 2, 2)?;
    let request_id = string(&params[0], "request_id")?;
    let approval = signed_approval_document(&params[1])?;
    let mut runtime = lock_custody_runtime_v3(runtime)?;
    let view = runtime
        .cancel_with_current_time(shared, request_id, &approval)
        .map_err(exchange_custody_v3_fault)?;
    Ok(withdrawal_document_v3(&view))
}

fn route_get_withdrawal_v3(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 1, 1)?;
    let request_id = string(&params[0], "request_id")?;
    let runtime = lock_custody_runtime_v3(runtime)?;
    let view = runtime
        .get(shared, request_id)
        .map_err(exchange_custody_v3_fault)?
        .ok_or_else(|| {
            RpcFault::not_found("withdrawal_not_found", "withdrawal request was not found")
        })?;
    Ok(withdrawal_document_v3(&view))
}

fn route_get_withdrawal_journal_info_v3(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 0, 0)?;
    let runtime = lock_custody_runtime_v3(runtime)?;
    let info = runtime.info(shared).map_err(exchange_custody_v3_fault)?;
    Ok(withdrawal_journal_info_document_v3(&info))
}

fn lock_custody_runtime_v3(
    runtime: &SharedExchangeCustodyRuntimeV3,
) -> Result<std::sync::MutexGuard<'_, ExchangeCustodyRuntimeV3>, RpcFault> {
    runtime.lock().map_err(|_| RpcFault {
        code: -32603,
        message: "exchange custody v3 runtime is poisoned".to_owned(),
        data_code: "exchange_custody_v3_poisoned",
        retryable: false,
    })
}

fn signed_approval_document(value: &Value) -> Result<Vec<u8>, RpcFault> {
    if !value.is_object() {
        return Err(RpcFault::invalid_params(
            "signed_approval must be a JSON object",
        ));
    }
    serde_json::to_vec(value).map_err(|_| RpcFault::invalid_params("signed_approval is invalid"))
}

fn external_signer_response_bytes(value: &Value) -> Result<Vec<Vec<u8>>, RpcFault> {
    let values = value
        .as_array()
        .ok_or_else(|| RpcFault::invalid_params("external_signer_responses must be an array"))?;
    if values.len() > cmfd_consensus::MAX_TRANSACTION_INPUTS {
        return Err(RpcFault::invalid_params(
            "external_signer_responses exceeds the transaction input limit",
        ));
    }
    let mut responses = Vec::with_capacity(values.len());
    for value in values {
        let encoded = value.as_str().ok_or_else(|| {
            RpcFault::invalid_params(
                "each external_signer_responses entry must be canonical base64",
            )
        })?;
        let bytes = BASE64_STANDARD.decode(encoded).map_err(|_| {
            RpcFault::invalid_params(
                "each external_signer_responses entry must be canonical base64",
            )
        })?;
        if bytes.len() > MAX_SIGNER_RESPONSE_BYTES || BASE64_STANDARD.encode(&bytes) != encoded {
            return Err(RpcFault::invalid_params(
                "each external_signer_responses entry must be canonical base64",
            ));
        }
        let response = SignerResponseV1::decode(&bytes)
            .map_err(|_| RpcFault::invalid_params("external signer response is not canonical"))?;
        if response
            .encode()
            .map_err(|_| RpcFault::invalid_params("external signer response is not canonical"))?
            != bytes
        {
            return Err(RpcFault::invalid_params(
                "external signer response is not canonical",
            ));
        }
        responses.push(bytes);
    }
    Ok(responses)
}

fn route_prepare_withdrawal(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    withdrawal_journal: &SharedExchangeWithdrawalJournal,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 4, 4)?;
    let request = WithdrawalRequest {
        request_id: string(&params[0], "request_id")?.to_owned(),
        destination: hash_parameter(&params[1], "destination")?,
        amount_atoms: canonical_decimal_u64_string(&params[2], "amount_atoms")?,
        fee_atoms: canonical_decimal_u64_string(&params[3], "fee_atoms")?,
    };
    let mut journal = lock_withdrawal_journal(withdrawal_journal)?;
    let view = journal
        .prepare(shared, &request)
        .map_err(exchange_withdrawal_fault)?;
    Ok(withdrawal_document(&view))
}

fn route_release_withdrawal(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    withdrawal_journal: &SharedExchangeWithdrawalJournal,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 1, 1)?;
    let request_id = string(&params[0], "request_id")?;
    let mut journal = lock_withdrawal_journal(withdrawal_journal)?;
    let view = journal
        .release(shared, request_id)
        .map_err(exchange_withdrawal_fault)?;
    Ok(withdrawal_document(&view))
}

fn route_get_withdrawal(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    withdrawal_journal: &SharedExchangeWithdrawalJournal,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 1, 1)?;
    let request_id = string(&params[0], "request_id")?;
    let journal = lock_withdrawal_journal(withdrawal_journal)?;
    let view = journal
        .get(shared, request_id)
        .map_err(exchange_withdrawal_fault)?
        .ok_or_else(|| {
            RpcFault::not_found("withdrawal_not_found", "withdrawal request was not found")
        })?;
    Ok(withdrawal_document(&view))
}

fn route_get_withdrawal_journal_info(
    params: &[Value],
    withdrawal_journal: &SharedExchangeWithdrawalJournal,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 0, 0)?;
    let journal = lock_withdrawal_journal(withdrawal_journal)?;
    let info = journal.journal_info().map_err(exchange_withdrawal_fault)?;
    Ok(withdrawal_journal_info_document(&info))
}

fn lock_withdrawal_journal(
    withdrawal_journal: &SharedExchangeWithdrawalJournal,
) -> Result<std::sync::MutexGuard<'_, ExchangeWithdrawalJournal>, RpcFault> {
    withdrawal_journal.lock().map_err(|_| RpcFault {
        code: -32603,
        message: "exchange withdrawal journal state is poisoned".to_owned(),
        data_code: "exchange_withdrawal_poisoned",
        retryable: false,
    })
}

fn withdrawal_document(view: &WithdrawalView) -> Value {
    let journal_anchor = WithdrawalJournalAnchor {
        key_id: view.journal_key_id,
        journal_instance_id: view.journal_instance_id,
        generation: view.journal_generation,
        commitment: view.journal_commitment,
    };
    json!({
        "api_version": EXCHANGE_RPC_API_VERSION,
        "anchor": withdrawal_anchor_document(&journal_anchor),
        "prepared_anchor": view.prepared_anchor.as_ref().map(withdrawal_anchor_document),
        "journal_key_id": hex::encode(view.journal_key_id),
        "journal_instance_id": hex::encode(view.journal_instance_id),
        "journal_generation": view.journal_generation.to_string(),
        "journal_commitment": hex::encode(view.journal_commitment),
        "request_id": view.request_id,
        "request_digest": hex::encode(view.request_digest),
        "destination_hex": hex::encode(view.destination),
        "amount_atoms": view.amount_atoms.to_string(),
        "fee_atoms": view.fee_atoms.to_string(),
        "change_atoms": view.change_atoms.to_string(),
        "reserved_inputs": view.reserved_inputs.iter().map(|input| json!({
            "txid": hex::encode(input.outpoint.txid),
            "vout": input.outpoint.index,
            "value_atoms": input.value_atoms.to_string(),
        })).collect::<Vec<_>>(),
        "signing_digest": hex::encode(view.signing_digest),
        "txid": view.txid.map(hex::encode),
        "transaction_hex": view.transaction_bytes.as_ref().map(hex::encode),
        "phase": view.phase.as_str(),
        "status": view.status.as_str(),
        "confirmations": view.confirmations,
        "broadcast_retryable": matches!(
            view.status,
            crate::exchange_withdrawal::WithdrawalStatus::BroadcastPending
        ),
        "warning": "preview custody requires an exchange-persisted Prepared anchor before release-time signing and broadcast but still uses one in-process node wallet key; no approval policy, keyring, multisig, HSM, or offline signer is present",
    })
}

fn withdrawal_journal_info_document(info: &WithdrawalJournalInfo) -> Value {
    json!({
        "api_version": EXCHANGE_RPC_API_VERSION,
        "anchor": withdrawal_anchor_document(&info.current_anchor),
        "external_anchor": info.external_anchor.as_ref().map(withdrawal_anchor_document),
        "anchor_relationship": info.relationship.as_str(),
    })
}

fn withdrawal_anchor_document(anchor: &WithdrawalJournalAnchor) -> Value {
    json!({
        "key_id": hex::encode(anchor.key_id),
        "journal_instance_id": hex::encode(anchor.journal_instance_id),
        "generation": anchor.generation.to_string(),
        "commitment": hex::encode(anchor.commitment),
    })
}

fn withdrawal_document_v3(view: &RuntimeWithdrawalViewV3) -> Value {
    let protocol_package_digest = view
        .signer_package_bytes
        .as_ref()
        .and_then(|bytes| SigningPackageV1::decode(bytes).ok())
        .and_then(|package| package.digest().ok())
        .map(hex::encode);
    let phase = match view.phase {
        RuntimeWithdrawalPhaseV3::Intent => "intent",
        RuntimeWithdrawalPhaseV3::Prepared => "prepared",
        RuntimeWithdrawalPhaseV3::ReleaseAuthorized => "release_authorized",
        RuntimeWithdrawalPhaseV3::Released => "released",
        RuntimeWithdrawalPhaseV3::Canceled => "canceled",
    };
    let status = match view.status {
        RuntimeWithdrawalStatusV3::Intent => "intent",
        RuntimeWithdrawalStatusV3::Prepared => "prepared",
        RuntimeWithdrawalStatusV3::ReleaseAuthorized => "release_authorized",
        RuntimeWithdrawalStatusV3::BroadcastPending => "broadcast_pending",
        RuntimeWithdrawalStatusV3::InMempool => "in_mempool",
        RuntimeWithdrawalStatusV3::Confirmed => "confirmed",
        RuntimeWithdrawalStatusV3::Conflicted => "conflicted",
        RuntimeWithdrawalStatusV3::Canceled => "canceled",
    };
    let terminal_action = match view.phase {
        RuntimeWithdrawalPhaseV3::ReleaseAuthorized | RuntimeWithdrawalPhaseV3::Released => {
            Some("release")
        }
        RuntimeWithdrawalPhaseV3::Canceled => Some("cancel"),
        RuntimeWithdrawalPhaseV3::Intent | RuntimeWithdrawalPhaseV3::Prepared => None,
    };
    json!({
        "api_version": EXCHANGE_CUSTODY_RPC_API_VERSION,
        "anchor": withdrawal_anchor_document_v3(&view.current_anchor),
        "prepared_anchor": view.prepared_anchor.as_ref().map(withdrawal_anchor_document_v3),
        "journal_key_id": hex::encode(view.current_anchor.key_id),
        "journal_instance_id": hex::encode(view.current_anchor.journal_instance_id),
        "journal_generation": view.current_anchor.generation.to_string(),
        "journal_commitment": hex::encode(view.current_anchor.commitment),
        "request_id": view.request_id,
        "request_digest": hex::encode(view.request_digest),
        "destination_hex": hex::encode(view.destination),
        "amount_atoms": view.amount_atoms.to_string(),
        "fee_atoms": view.fee_atoms.to_string(),
        "change_atoms": view.change_atoms.to_string(),
        "reserved_inputs": view.reserved_inputs.iter().map(|(outpoint, value_atoms)| json!({
            "txid": hex::encode(outpoint.txid),
            "vout": outpoint.index,
            "value_atoms": value_atoms.to_string(),
        })).collect::<Vec<_>>(),
        "signing_digest": hex::encode(view.signing_digest),
        "signer_package_digest": protocol_package_digest,
        "signer_package_bytes_digest": view.signer_package_digest.map(hex::encode),
        "terminal_action": terminal_action,
        "decision_id": view.decision_id.map(hex::encode),
        "approval_digest": view.approval_digest.map(hex::encode),
        "action_anchor": view.action_anchor.as_ref().map(withdrawal_anchor_document_v3),
        "authorized_at_unix_seconds": view.authorized_at_unix_seconds.map(|value| value.to_string()),
        "accounted_at_unix_seconds": view.accounted_at_unix_seconds.map(|value| value.to_string()),
        "txid": view.txid.map(hex::encode),
        "transaction_hex": view.transaction_bytes.as_ref().map(hex::encode),
        "phase": phase,
        "status": status,
        "confirmations": view.confirmations.map(|value| value.to_string()),
        "broadcast_retryable": matches!(view.status, RuntimeWithdrawalStatusV3::BroadcastPending),
        "custody_model": "keyring-routed local/external signing with action-specific threshold approvals; external signer deployment requires operator qualification",
    })
}

fn withdrawal_journal_info_document_v3(info: &RuntimeJournalInfoV3) -> Value {
    let relationship = match info.relationship {
        crate::exchange_custody_v3::ExternalAnchorRelationshipV3::Current => "current",
        crate::exchange_custody_v3::ExternalAnchorRelationshipV3::Descendant => "descendant",
    };
    json!({
        "api_version": EXCHANGE_CUSTODY_RPC_API_VERSION,
        "anchor": withdrawal_anchor_document_v3(&info.current_anchor),
        "external_anchor": withdrawal_anchor_document_v3(&info.external_anchor),
        "anchor_relationship": relationship,
        "policy_id": hex::encode(info.policy_id),
        "active_keyring": {
            "instance_id": hex::encode(info.active_keyring.instance_id),
            "generation": info.active_keyring.generation.to_string(),
            "commitment": hex::encode(info.active_keyring.commitment),
        },
        "policy_time_watermark_unix_seconds": info.policy_time_watermark_unix_seconds.to_string(),
        "policy_release_event_count": info.policy_release_event_count.to_string(),
        "capacity": {
            "live_record_count": info.live_record_count.to_string(),
            "live_record_limit": info.live_record_limit.to_string(),
            "tombstone_count": info.tombstone_count.to_string(),
            "tombstone_limit": info.tombstone_limit.to_string(),
            "commitment_count": info.commitment_count.to_string(),
            "commitment_limit": info.commitment_limit.to_string(),
            "estimated_full_release_capacity_remaining": info.estimated_full_release_capacity_remaining.to_string(),
            "warning": info.capacity_warning,
            "warning_threshold_full_releases": "1024",
        },
        "redundancy_degraded": info.redundancy_degraded,
        "faulted": info.faulted,
    })
}

fn withdrawal_anchor_document_v3(anchor: &crate::exchange_withdrawal_v3::JournalAnchorV3) -> Value {
    json!({
        "key_id": hex::encode(anchor.key_id),
        "journal_instance_id": hex::encode(anchor.journal_instance_id),
        "generation": anchor.generation.to_string(),
        "commitment": hex::encode(anchor.commitment),
    })
}

fn approval_payload_document_v3(payload: &UnsignedApprovalDocumentV3) -> Result<Value, RpcFault> {
    let document: Value = serde_json::from_slice(&payload.document).map_err(|_| RpcFault {
        code: -32603,
        message: "custody engine produced an invalid approval document".to_owned(),
        data_code: "exchange_custody_v3_internal",
        retryable: false,
    })?;
    let action = match payload.action {
        CustodyTerminalActionV3::Release => "release",
        CustodyTerminalActionV3::Cancel => "cancel",
    };
    Ok(json!({
        "api_version": EXCHANGE_CUSTODY_RPC_API_VERSION,
        "action": action,
        "decision_id": hex::encode(payload.decision_id),
        "action_anchor": withdrawal_anchor_document_v3(&payload.action_anchor),
        "signing_digest": hex::encode(payload.signing_digest),
        "approval_document": document,
        "approval_document_base64": BASE64_STANDARD.encode(&payload.document),
    }))
}

fn route_register_watch_destination(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 2, 2)?;
    let label = string(&params[0], "label")?;
    let destination = hash_parameter(&params[1], "destination")?;
    let mut index = lock_exchange_index(exchange_index)?;
    let registration = index
        .register_watch_destination(shared, label, destination)
        .map_err(exchange_index_fault)?;
    Ok(register_watch_destination_document(&registration))
}

fn route_register_watch_destinations(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 1, 1)?;
    let values = params[0]
        .as_array()
        .ok_or_else(|| RpcFault::invalid_params("registrations must be an array"))?;
    if values.is_empty() || values.len() > MAX_WATCH_REGISTRATION_BATCH {
        return Err(exchange_index_fault(
            ExchangeIndexError::InvalidRegistrationBatch,
        ));
    }
    let mut registrations = Vec::with_capacity(values.len());
    for value in values {
        let parameter: WatchRegistrationParameter =
            serde_json::from_value(value.clone()).map_err(|_| {
                RpcFault::invalid_params(
                    "each registration must contain exactly label and destination_hex strings",
                )
            })?;
        registrations.push(WatchDestinationRegistration {
            label: parameter.label,
            destination: hash_parameter(
                &Value::String(parameter.destination_hex),
                "destination_hex",
            )?,
        });
    }
    let mut index = lock_exchange_index(exchange_index)?;
    let result = index
        .register_watch_destinations(shared, &registrations)
        .map_err(exchange_index_fault)?;
    Ok(register_watch_destinations_document(&result))
}

fn route_get_exchange_info(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
    withdrawal_backend: Option<&SharedWithdrawalBackend>,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 0, 0)?;
    let mut index = lock_exchange_index(exchange_index)?;
    let status = index.synchronize(shared).map_err(exchange_index_fault)?;
    let (custody_mode, custody_api_version, withdrawal_methods): (&str, Option<&str>, &[&str]) =
        match withdrawal_backend {
            None => ("disabled", None, &[]),
            Some(SharedWithdrawalBackend::V2(_)) => (
                "v0.4-preview",
                Some(EXCHANGE_RPC_API_VERSION),
                &[
                    "preparewithdrawal",
                    "releasewithdrawal",
                    "getwithdrawal",
                    "getwithdrawaljournalinfo",
                ],
            ),
            Some(SharedWithdrawalBackend::V3(_)) => (
                "v0.5-policy-keyring",
                Some(EXCHANGE_CUSTODY_RPC_API_VERSION),
                &[
                    "preparewithdrawal",
                    "getwithdrawalsigningpackage",
                    "getwithdrawalapprovalpayload",
                    "releasewithdrawal",
                    "cancelwithdrawal",
                    "getwithdrawal",
                    "getwithdrawaljournalinfo",
                ],
            ),
        };
    Ok(json!({
        "api_version": EXCHANGE_RPC_API_VERSION,
        "service": "common-foundry-exchange-rpc",
        "status": "integration_preview",
        "production_ready": false,
        "network_id": hex::encode(status.network_id),
        "consensus_fingerprint": hex::encode(status.consensus_fingerprint),
        "custody": {
            "mode": custody_mode,
            "api_version": custody_api_version,
            "separate_withdrawal_credential": true,
            "external_signer_protocol": "CMFDSIG1-v1-provider-neutral",
        },
        "encodings": {
            "amounts": "canonical unsigned decimal atom strings",
            "destination": "64 lowercase hexadecimal characters encoding a 32-byte x-only secp256k1 public key",
            "checksummed_address_available": false,
        },
        "methods": {
            "integration": [
                "getexchangeinfo",
                "getblockchaininfo",
                "getblockcount",
                "getbestblockhash",
                "getblockhash",
                "getblock",
                "gettxoutsetinfo",
                "getrawtransaction",
                "gettransaction",
                "getaddressbalance",
                "getaddressutxos",
                "getbalance",
                "getrawmempool",
                "sendrawtransaction",
                "registerwatchdestination",
                "registerwatchdestinations",
                "getwatchdestination",
                "getdepositevents",
            ],
            "withdrawal": withdrawal_methods,
        },
        "deposit_index": {
            "healthy": true,
            "indexed_tip": {
                "height": status.indexed_tip_height,
                "hash": hex::encode(status.indexed_tip),
            },
            "high_watermark": status.high_watermark.to_string(),
            "capacity": {
                "watch_destination_count": status.watch_destination_count.to_string(),
                "watch_destination_limit": MAX_WATCH_DESTINATIONS.to_string(),
                "watch_destination_remaining": MAX_WATCH_DESTINATIONS.saturating_sub(status.watch_destination_count).to_string(),
                "active_deposit_count": status.active_deposit_count.to_string(),
                "active_deposit_limit": MAX_ACTIVE_DEPOSITS.to_string(),
                "deposit_event_limit": MAX_DEPOSIT_EVENTS.to_string(),
                "registration_batch_limit": MAX_WATCH_REGISTRATION_BATCH.to_string(),
                "event_page_limit": MAX_DEPOSIT_EVENT_PAGE.to_string(),
            },
        },
    }))
}

fn route_get_watch_destination(
    params: &[Value],
    exchange_index: &SharedExchangeDepositIndex,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 1, 1)?;
    let label = string(&params[0], "label")?;
    let index = lock_exchange_index(exchange_index)?;
    let watch = index
        .get_watch_destination(label)
        .map_err(exchange_index_fault)?
        .ok_or_else(|| RpcFault::not_found("watch_not_found", "watch destination was not found"))?;
    Ok(watch_destination_document(&watch))
}

fn route_get_deposit_events(
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 1, 2)?;
    let after_cursor = decimal_u64_string(&params[0], "after_cursor")?;
    let limit = match params.get(1) {
        Some(value) => usize::try_from(unsigned_integer(value, "limit")?)
            .map_err(|_| invalid_deposit_event_page_limit())?,
        None => 100,
    };
    if !(1..=MAX_DEPOSIT_EVENT_PAGE).contains(&limit) {
        return Err(invalid_deposit_event_page_limit());
    }

    let mut index = lock_exchange_index(exchange_index)?;
    index.synchronize(shared).map_err(exchange_index_fault)?;
    let page = index
        .get_deposit_events(after_cursor, limit)
        .map_err(exchange_index_fault)?;
    Ok(deposit_event_page_document(&page))
}

fn lock_exchange_index(
    exchange_index: &SharedExchangeDepositIndex,
) -> Result<std::sync::MutexGuard<'_, ExchangeDepositIndex>, RpcFault> {
    exchange_index.lock().map_err(|_| RpcFault {
        code: -32603,
        message: "exchange deposit index state is poisoned".to_owned(),
        data_code: "exchange_index_poisoned",
        retryable: false,
    })
}

fn register_watch_destination_document(registration: &RegisterWatchDestinationResult) -> Value {
    watch_destination_document(&registration.watch)
}

fn register_watch_destinations_document(registration: &RegisterWatchDestinationsResult) -> Value {
    json!({
        "api_version": EXCHANGE_RPC_API_VERSION,
        "registration_count": registration.watches.len(),
        "registrations": registration
            .watches
            .iter()
            .map(watch_destination_document)
            .collect::<Vec<_>>(),
    })
}

fn watch_destination_document(watch: &WatchDestinationView) -> Value {
    json!({
        "api_version": EXCHANGE_RPC_API_VERSION,
        "label": watch.label,
        "destination_hex": hex::encode(watch.destination),
        "registered_at_height": watch.registered_at_height,
        "registered_at_tip": hex::encode(watch.registered_at_tip),
    })
}

fn deposit_event_page_document(page: &DepositEventPage) -> Value {
    json!({
        "api_version": EXCHANGE_RPC_API_VERSION,
        "network_id": hex::encode(page.network_id),
        "consensus_fingerprint": hex::encode(page.consensus_fingerprint),
        "indexed_tip": {
            "height": page.indexed_tip_height,
            "hash": hex::encode(page.indexed_tip),
        },
        "events": page.events.iter().map(deposit_event_document).collect::<Vec<_>>(),
        "next_cursor": page.next_cursor.to_string(),
        "high_watermark": page.high_watermark.to_string(),
        "has_more": page.has_more,
    })
}

fn deposit_event_document(event: &DepositEvent) -> Value {
    let deposit = &event.deposit;
    json!({
        "cursor": event.sequence.to_string(),
        "added_cursor": event.added_sequence.to_string(),
        "kind": event.kind.as_str(),
        "label": deposit.label,
        "destination_hex": hex::encode(deposit.destination),
        "txid": hex::encode(deposit.outpoint.txid),
        "vout": deposit.outpoint.vout,
        "value_atoms": deposit.amount_atoms.to_string(),
        "spendable_height": deposit.spendable_height,
        "coinbase": deposit.coinbase,
        "blockhash": hex::encode(deposit.block_hash),
        "blockheight": deposit.block_height,
        "blocktime": deposit.block_timestamp,
    })
}

fn finish_request(id: Value, result: Result<Value, RpcFault>) -> Value {
    match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => rpc_failure(id, error),
    }
}

fn invalid_request(id: Value, message: &'static str, data_code: &'static str) -> Value {
    rpc_failure(
        id,
        RpcFault {
            code: -32600,
            message: message.to_owned(),
            data_code,
            retryable: false,
        },
    )
}

fn rpc_failure(id: Value, error: RpcFault) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error.code,
            "message": error.message,
            "data": {
                "code": error.data_code,
                "retryable": error.retryable,
            }
        }
    })
}

fn route_method(
    method: &str,
    params: &[Value],
    node: &mut Node,
    prepared_transaction: Option<Transaction>,
) -> Result<Value, RpcFault> {
    match method {
        "getblockchaininfo" => {
            require_parameter_count(params, 0, 0)?;
            blockchain_info(node).map_err(node_fault)
        }
        "getblockcount" => {
            require_parameter_count(params, 0, 0)?;
            let status = node.status().map_err(node_fault)?;
            Ok(json!(status.accepted_height))
        }
        "getbestblockhash" => {
            require_parameter_count(params, 0, 0)?;
            let status = node.status().map_err(node_fault)?;
            Ok(json!(status.tip))
        }
        "getblockhash" => {
            require_parameter_count(params, 1, 1)?;
            let height = unsigned_integer(&params[0], "height")?;
            let block_id = node.active_block_id_at_height(height).ok_or_else(|| {
                RpcFault::not_found("block_not_found", "active-chain height was not found")
            })?;
            Ok(json!(hex::encode(block_id)))
        }
        "getblock" => route_getblock(node, params),
        "gettxoutsetinfo" => {
            require_parameter_count(params, 0, 0)?;
            Ok(txout_set_info(node))
        }
        "getaddressutxos" => route_get_address_utxos(node, params),
        "getaddressbalance" | "getbalance" => {
            require_parameter_count(params, 1, 1)?;
            let destination = hash_parameter(&params[0], "destination_hex")?;
            k256::schnorr::VerifyingKey::from_bytes(&destination).map_err(|_| {
                RpcFault::invalid_params("destination_hex must encode a valid x-only secp256k1 key")
            })?;
            address_balance(node, destination).map_err(node_fault)
        }
        "getrawmempool" => {
            require_parameter_count(params, 0, 1)?;
            let verbose = match params.first() {
                Some(value) => boolean(value, "verbose")?,
                None => false,
            };
            if verbose {
                let mut entries = Map::new();
                for entry in node.mempool_entries() {
                    entries.insert(
                        hex::encode(entry.txid),
                        json!({
                            "size": entry.encoded_bytes,
                            "fee_atoms": entry.fee_burned.to_string(),
                        }),
                    );
                }
                Ok(Value::Object(entries))
            } else {
                Ok(json!(
                    node.mempool_entries()
                        .map(|entry| hex::encode(entry.txid))
                        .collect::<Vec<_>>()
                ))
            }
        }
        "sendrawtransaction" => {
            let transaction = prepared_transaction.ok_or_else(|| RpcFault {
                code: -32603,
                message: "transaction preparation was not performed".to_owned(),
                data_code: "internal_error",
                retryable: false,
            })?;
            let txid = transaction.txid();
            if node.mempool_entries().any(|entry| entry.txid == txid) {
                return Ok(json!(hex::encode(txid)));
            }
            match node.submit_transaction(transaction) {
                Ok(entry) => Ok(json!(hex::encode(entry.txid))),
                Err(NodeError::DuplicateMempoolTransaction(existing)) => {
                    Ok(json!(hex::encode(existing)))
                }
                // A rebroadcast of a mined transaction finds its inputs spent;
                // report the confirmation instead of a missing input.
                Err(NodeError::MempoolUnconfirmedInput(_))
                    if node
                        .index
                        .transactions
                        .active_location(&txid, &node.index)
                        .is_some() =>
                {
                    Err(RpcFault {
                        code: -32005,
                        message: format!(
                            "transaction {} is already confirmed on the active chain",
                            hex::encode(txid)
                        ),
                        data_code: "transaction_already_confirmed",
                        retryable: false,
                    })
                }
                Err(error) => Err(node_fault(error)),
            }
        }
        _ => Err(RpcFault {
            code: -32601,
            message: "method not found".to_owned(),
            data_code: "method_not_found",
            retryable: false,
        }),
    }
}

fn query_fault(error: QueryError) -> RpcFault {
    match error {
        QueryError::Node(error) => node_fault(error),
        QueryError::ChainChanged => RpcFault {
            code: -32020,
            message: "active chain changed during transaction lookup; retry the read".into(),
            data_code: "transaction_query_chain_changed",
            retryable: true,
        },
        QueryError::Capacity => RpcFault {
            code: -32021,
            message: "transaction lookup index capacity reached; supply a block hash".into(),
            data_code: "transaction_query_capacity",
            retryable: false,
        },
        QueryError::UtxoSnapshotChanged => RpcFault {
            code: -32022,
            message: "available outputs changed; restart UTXO pagination without a cursor".into(),
            data_code: "utxo_snapshot_changed",
            retryable: true,
        },
        QueryError::InvalidUtxoCursor => {
            RpcFault::invalid_params("cursor outpoint is not in this UTXO snapshot")
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UtxoCursorParameter {
    snapshot: String,
    txid: String,
    vout: u32,
}

fn route_get_address_utxos(node: &Node, params: &[Value]) -> Result<Value, RpcFault> {
    require_parameter_count(params, 1, 3)?;
    let destination = hash_parameter(&params[0], "destination_hex")?;
    k256::schnorr::VerifyingKey::from_bytes(&destination).map_err(|_| {
        RpcFault::invalid_params("destination_hex must encode a valid x-only secp256k1 key")
    })?;
    let limit = match params.get(1) {
        Some(value) => usize::try_from(unsigned_integer(value, "limit")?)
            .map_err(|_| RpcFault::invalid_params("limit must be between 1 and 1000"))?,
        None => MAX_UTXO_PAGE,
    };
    if !(1..=MAX_UTXO_PAGE).contains(&limit) {
        return Err(RpcFault::invalid_params("limit must be between 1 and 1000"));
    }
    let cursor = match params.get(2) {
        None | Some(Value::Null) => None,
        Some(value) => {
            let parameter: UtxoCursorParameter =
                serde_json::from_value(value.clone()).map_err(|_| {
                    RpcFault::invalid_params("cursor must contain snapshot, txid, and vout")
                })?;
            Some(UtxoCursor {
                snapshot: hash_parameter(&json!(parameter.snapshot), "cursor snapshot")?,
                after: cmfd_consensus::OutPoint {
                    txid: hash_parameter(&json!(parameter.txid), "cursor txid")?,
                    index: parameter.vout,
                },
            })
        }
    };
    address_utxos(node, destination, limit, cursor).map_err(query_fault)
}

fn route_get_transaction(
    method: &str,
    params: &[Value],
    shared: &Arc<Mutex<Node>>,
    exchange_index: &SharedExchangeDepositIndex,
) -> Result<Value, RpcFault> {
    require_parameter_count(params, 1, if method == "getrawtransaction" { 3 } else { 2 })?;
    let txid = hash_parameter(&params[0], "txid")?;
    let verbose = if method == "gettransaction" {
        true
    } else {
        match params.get(1) {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(value) if value.as_u64() == Some(0) => false,
            Some(value) if value.as_u64() == Some(1) => true,
            _ => {
                return Err(RpcFault::invalid_params(
                    "verbose must be true, false, 0, or 1",
                ));
            }
        }
    };
    let hint_position = if method == "getrawtransaction" { 2 } else { 1 };
    let hint = params
        .get(hint_position)
        .map(|value| hash_parameter(value, "blockhash"))
        .transpose()?;
    let read = lock_exchange_index(exchange_index)?
        .transaction_lookup
        .lookup(shared, txid, hint)
        .map_err(query_fault)?
        .ok_or_else(|| {
            RpcFault::not_found(
                "transaction_not_found",
                "transaction was not found in the active chain or local mempool",
            )
        })?;
    let mut document = match read.body {
        TransactionBody::Regular(transaction) => {
            if !verbose {
                return Ok(json!(hex::encode(
                    encode_transaction(&transaction)
                        .map_err(NodeError::from)
                        .map_err(node_fault)?
                )));
            }
            let mut document = transaction_document(
                &transaction,
                read.block_id,
                read.height,
                Some(read.confirmations),
                read.timestamp,
            )
            .map_err(node_fault)?;
            document["coinbase"] = json!(false);
            document
        }
        TransactionBody::Coinbase(block) => {
            if !verbose {
                return Err(RpcFault::invalid_params(
                    "coinbase is a block component with no standalone transaction frame; request verbose output",
                ));
            }
            json!({
                "txid": hex::encode(txid), "hex": Value::Null, "coinbase": true,
                "network_id": hex::encode(block.challenge.network_id),
                "blockhash": read.block_id.map(hex::encode), "blockheight": read.height,
                "confirmations": read.confirmations, "time": read.timestamp,
                "vin": [], "vout": outputs_document(&block.coinbase.outputs),
            })
        }
    };
    document["active"] = json!(read.confirmations > 0);
    document["status"] = json!(if read.confirmations > 0 {
        "confirmed"
    } else if read.confirmations == 0 {
        "mempool"
    } else {
        "inactive"
    });
    document["bestblock"] = json!(hex::encode(read.tip));
    document["height"] = json!(read.tip_height);
    Ok(document)
}

fn prepare_broadcast_transaction(
    request: &ExchangeRequest,
    network_id: [u8; 32],
) -> Result<Option<Transaction>, RpcFault> {
    if request.method != "sendrawtransaction" {
        return Ok(None);
    }
    require_parameter_count(&request.params, 1, 1)?;
    let transaction_hex = string(
        request.params.first().expect("parameter count checked"),
        "transaction",
    )?;
    if transaction_hex.len() > MAX_TRANSACTION_BYTES.saturating_mul(2) {
        return Err(RpcFault::invalid_params(
            "transaction hex exceeds the canonical transaction limit",
        ));
    }
    let raw = hex::decode(transaction_hex).map_err(|_| {
        RpcFault::invalid_params("transaction must be an even-length hexadecimal string")
    })?;
    let transaction = decode_transaction(&raw, network_id).map_err(|_| {
        RpcFault::invalid_params("transaction is not valid canonical wire data for this network")
    })?;
    let canonical = encode_transaction(&transaction).map_err(|_| RpcFault {
        code: -32603,
        message: "transaction canonicalization failed".to_owned(),
        data_code: "internal_error",
        retryable: false,
    })?;
    if canonical != raw {
        return Err(RpcFault::invalid_params(
            "transaction frame is not canonical",
        ));
    }
    Ok(Some(transaction))
}

fn getblock_parameters(params: &[Value]) -> Result<([u8; 32], u64), RpcFault> {
    require_parameter_count(params, 1, 2)?;
    let block_id = hash_parameter(&params[0], "block hash")?;
    let verbosity = match params.get(1) {
        Some(value) => unsigned_integer(value, "verbosity")?,
        None => 1,
    };
    if verbosity > 2 {
        return Err(RpcFault::invalid_params("verbosity must be 0, 1, or 2"));
    }
    Ok((block_id, verbosity))
}

fn route_getblock(node: &mut Node, params: &[Value]) -> Result<Value, RpcFault> {
    let (block_id, verbosity) = getblock_parameters(params)?;
    let planned = plan_block_read(node, block_id, verbosity);
    let plan = node
        .latch_authenticated_storage_failure(planned)
        .map_err(node_fault)?
        .ok_or_else(block_not_found)?;
    node.latch_authenticated_storage_failure(execute_block_read(plan))
        .map_err(node_fault)
}

fn route_getblock_shared(params: &[Value], shared: &Arc<Mutex<Node>>) -> Result<Value, RpcFault> {
    let (block_id, verbosity) = getblock_parameters(params)?;
    let plan = {
        let mut node = shared
            .lock()
            .map_err(|_| node_fault(NodeError::SharedNodePoisoned))?;
        let planned = plan_block_read(&node, block_id, verbosity);
        node.latch_authenticated_storage_failure(planned)
            .map_err(node_fault)?
            .ok_or_else(block_not_found)?
    };
    let node_instance_id = match &plan {
        BlockReadPlan::Virtual(_) => None,
        BlockReadPlan::Persisted(plan) => Some(plan.node_instance_id),
    };
    execute_block_read(plan)
        .map_err(|error| latch_off_lock_block_read_error(shared, node_instance_id, error))
}

fn block_not_found() -> RpcFault {
    RpcFault::not_found(
        "block_not_found",
        "block was not found or has no canonical frame",
    )
}

fn plan_block_read(
    node: &Node,
    block_id: [u8; 32],
    verbosity: u64,
) -> Result<Option<BlockReadPlan>, NodeError> {
    if node.active_block_id_at_height(0) == Some(block_id) {
        return if verbosity == 0 {
            Ok(None)
        } else {
            Ok(Some(BlockReadPlan::Virtual(virtual_genesis_document(node))))
        };
    }
    let Some(indexed) = node.index.blocks.get(&block_id).cloned() else {
        return Ok(None);
    };
    if indexed.block_id() != block_id {
        return Err(NodeError::CorruptLog(
            "fork index key does not match its durable record locator".to_owned(),
        ));
    }
    let confirmations = node.active_chain_confirmations(block_id);
    let next_block = confirmations.and_then(|_| {
        indexed
            .height()
            .checked_add(1)
            .and_then(|height| node.active_block_id_at_height(height))
    });
    let log_path = node.data_dir.join(BLOCK_LOG_FILE);
    let log = node.clone_log_for_read().map_err(|source| {
        crate::io_error(
            "clone retained block log for exchange read",
            &log_path,
            source,
        )
    })?;
    Ok(Some(BlockReadPlan::Persisted(Box::new(
        PersistedBlockReadPlan {
            node_instance_id: node.instance_id,
            log,
            log_path,
            locator: indexed.locator,
            network_id: node.params.network_id,
            require_v2: matches!(node.profile.proof, ProofProfile::ProductionV3),
            block_id,
            confirmations,
            next_block,
            verbosity,
        },
    ))))
}

fn execute_block_read(plan: BlockReadPlan) -> Result<Value, NodeError> {
    let plan = match plan {
        BlockReadPlan::Virtual(document) => return Ok(document),
        BlockReadPlan::Persisted(plan) => plan,
    };
    let (record, block) = crate::read_located_record(
        &plan.log,
        &plan.log_path,
        &plan.locator,
        plan.network_id,
        plan.require_v2,
    )?;
    if block.block_id() != plan.block_id {
        return Err(NodeError::CorruptLog(
            "stored canonical block identity mismatch".to_owned(),
        ));
    }
    if plan.verbosity == 0 {
        if block.is_pruned() {
            return Err(NodeError::BlockProofPruned(plan.block_id));
        }
        return Ok(json!(hex::encode(record.block_bytes)));
    }
    let size = crate::stored_block_size(&record, &block);
    block_document(
        &block,
        size,
        plan.verbosity == 2,
        plan.confirmations,
        plan.next_block,
    )
}

fn latch_off_lock_block_read_error(
    shared: &Arc<Mutex<Node>>,
    node_instance_id: Option<u64>,
    error: NodeError,
) -> RpcFault {
    if crate::is_authenticated_storage_failure(&error) {
        let mut node = match shared.lock() {
            Ok(node) => node,
            Err(_) => return node_fault(NodeError::SharedNodePoisoned),
        };
        if node_instance_id == Some(node.instance_id) {
            node.storage_faulted = true;
        }
    }
    node_fault(error)
}

fn require_parameter_count(
    params: &[Value],
    minimum: usize,
    maximum: usize,
) -> Result<(), RpcFault> {
    if (minimum..=maximum).contains(&params.len()) {
        Ok(())
    } else if minimum == maximum {
        Err(RpcFault::invalid_params(format!(
            "method requires exactly {minimum} positional parameters"
        )))
    } else {
        Err(RpcFault::invalid_params(format!(
            "method requires between {minimum} and {maximum} positional parameters"
        )))
    }
}

fn unsigned_integer(value: &Value, name: &'static str) -> Result<u64, RpcFault> {
    value
        .as_u64()
        .ok_or_else(|| RpcFault::invalid_params(format!("{name} must be an unsigned integer")))
}

fn decimal_u64_string(value: &Value, name: &'static str) -> Result<u64, RpcFault> {
    let encoded = string(value, name)?;
    if encoded.is_empty() || !encoded.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RpcFault::invalid_params(format!(
            "{name} must be an unsigned decimal string"
        )));
    }
    encoded
        .parse()
        .map_err(|_| RpcFault::invalid_params(format!("{name} exceeds the unsigned 64-bit range")))
}

fn canonical_decimal_u64_string(value: &Value, name: &'static str) -> Result<u64, RpcFault> {
    let encoded = string(value, name)?;
    if encoded.is_empty()
        || !encoded.bytes().all(|byte| byte.is_ascii_digit())
        || (encoded.len() > 1 && encoded.starts_with('0'))
    {
        return Err(RpcFault::invalid_params(format!(
            "{name} must be a canonical unsigned decimal string"
        )));
    }
    encoded
        .parse()
        .map_err(|_| RpcFault::invalid_params(format!("{name} exceeds the unsigned 64-bit range")))
}

fn invalid_deposit_event_page_limit() -> RpcFault {
    RpcFault {
        code: -32602,
        message: format!("deposit event page limit must be between 1 and {MAX_DEPOSIT_EVENT_PAGE}"),
        data_code: "invalid_deposit_event_page_limit",
        retryable: false,
    }
}

fn boolean(value: &Value, name: &'static str) -> Result<bool, RpcFault> {
    value
        .as_bool()
        .ok_or_else(|| RpcFault::invalid_params(format!("{name} must be a boolean")))
}

fn string<'a>(value: &'a Value, name: &'static str) -> Result<&'a str, RpcFault> {
    value
        .as_str()
        .ok_or_else(|| RpcFault::invalid_params(format!("{name} must be a string")))
}

fn hash_parameter(value: &Value, name: &'static str) -> Result<[u8; 32], RpcFault> {
    let encoded = string(value, name)?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RpcFault::invalid_params(format!(
            "{name} must be 64 lowercase hexadecimal characters"
        )));
    }
    hex::decode(encoded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| RpcFault::invalid_params(format!("{name} must encode 32 bytes")))
}

fn exchange_index_startup_error(error: ExchangeIndexError) -> NodeError {
    log_exchange_index_failure("startup", &error);
    NodeError::ExchangeDepositIndex {
        code: error.code(),
        retryable: error.retryable(),
        message: error.client_message(),
    }
}

fn exchange_withdrawal_startup_error(error: ExchangeWithdrawalError) -> NodeError {
    log_exchange_withdrawal_failure("startup", &error);
    NodeError::ExchangeWithdrawalJournal {
        code: error.code(),
        retryable: error.retryable(),
        message: error.client_message(),
    }
}

fn exchange_custody_v3_startup_error(error: ExchangeCustodyRuntimeV3Error) -> NodeError {
    tracing::error!(error = %error, "exchange custody v3 startup failed");
    NodeError::ExchangeWithdrawalJournal {
        code: exchange_custody_v3_error_code(&error),
        retryable: exchange_custody_v3_retryable(&error),
        message: exchange_custody_v3_client_message(&error),
    }
}

fn exchange_custody_v3_fault(error: ExchangeCustodyRuntimeV3Error) -> RpcFault {
    let error = match error {
        ExchangeCustodyRuntimeV3Error::Node(error) => {
            return exchange_custody_v3_node_fault(error);
        }
        error => error,
    };
    tracing::error!(error = %error, "exchange custody v3 request failed");
    let data_code = exchange_custody_v3_error_code(&error);
    let code = match data_code {
        "invalid_withdrawal_amount"
        | "withdrawal_amount_overflow"
        | "invalid_exchange_withdrawal_policy"
        | "invalid_withdrawal_approval"
        | "invalid_withdrawal_request" => -32602,
        "withdrawal_not_found" => -32001,
        "wallet_funds_immature"
        | "wallet_insufficient_funds"
        | "wallet_input_limit"
        | "mempool_fee_too_low"
        | "withdrawal_single_amount_limit_exceeded"
        | "withdrawal_single_fee_limit_exceeded"
        | "withdrawal_single_debit_limit_exceeded"
        | "withdrawal_rolling_24h_debit_limit_exceeded"
        | "withdrawal_rolling_24h_count_limit_exceeded" => -32006,
        "withdrawal_request_conflict"
        | "withdrawal_invalid_phase"
        | "withdrawal_terminal_conflict"
        | "withdrawal_canceled"
        | "withdrawal_signer_package_unavailable"
        | "withdrawal_signing_not_authorized"
        | "withdrawal_signer_response_invalid"
        | "withdrawal_plan_revalidation_failed"
        | "exchange_custody_v3_anchor_mismatch" => -32009,
        _ => -32007,
    };
    RpcFault {
        code,
        message: exchange_custody_v3_client_message(&error),
        data_code,
        retryable: exchange_custody_v3_retryable(&error),
    }
}

fn exchange_custody_v3_node_fault(error: NodeError) -> RpcFault {
    let client = error.client_error();
    match client.code {
        "wallet_funds_immature"
        | "wallet_insufficient_funds"
        | "wallet_input_limit"
        | "mempool_fee_too_low" => RpcFault {
            code: -32006,
            message: client.message,
            data_code: client.code,
            retryable: client.retryable,
        },
        _ => node_fault(error),
    }
}

fn exchange_custody_v3_error_code(error: &ExchangeCustodyRuntimeV3Error) -> &'static str {
    match error {
        ExchangeCustodyRuntimeV3Error::Store(error) => match error {
            crate::exchange_custody_v3::ExchangeCustodyV3Error::ExternalAnchorMismatch
            | crate::exchange_custody_v3::ExchangeCustodyV3Error::ExternalAnchorAhead
            | crate::exchange_custody_v3::ExchangeCustodyV3Error::ExternalAnchorNotCurrent => {
                "exchange_custody_v3_anchor_mismatch"
            }
            crate::exchange_custody_v3::ExchangeCustodyV3Error::Busy => "exchange_custody_v3_busy",
            crate::exchange_custody_v3::ExchangeCustodyV3Error::Faulted => {
                "exchange_custody_v3_faulted"
            }
            crate::exchange_custody_v3::ExchangeCustodyV3Error::ExplicitMigrationRequired => {
                "exchange_custody_v3_migration_required"
            }
            _ => "exchange_custody_v3_storage",
        },
        ExchangeCustodyRuntimeV3Error::Engine(error) => match error {
            ExchangeCustodyEngineError::Policy(error) => error.code(),
            ExchangeCustodyEngineError::StaleJournalAnchor => "exchange_custody_v3_anchor_mismatch",
            ExchangeCustodyEngineError::InvalidPlan(_) => "invalid_withdrawal_request",
            ExchangeCustodyEngineError::PlanMismatch => "withdrawal_request_conflict",
            ExchangeCustodyEngineError::UnknownRequest => "withdrawal_not_found",
            ExchangeCustodyEngineError::InvalidPhase => "withdrawal_invalid_phase",
            ExchangeCustodyEngineError::TerminalConflict => "withdrawal_terminal_conflict",
            ExchangeCustodyEngineError::SigningPackageMismatch => {
                "withdrawal_signer_package_unavailable"
            }
            ExchangeCustodyEngineError::Signer(_) => "withdrawal_signer_response_invalid",
            ExchangeCustodyEngineError::PlanRevalidationFailed => {
                "withdrawal_plan_revalidation_failed"
            }
            _ => "exchange_custody_v3_engine",
        },
        ExchangeCustodyRuntimeV3Error::Policy(error) => error.code(),
        ExchangeCustodyRuntimeV3Error::Keyring(_) => "exchange_custody_v3_keyring",
        ExchangeCustodyRuntimeV3Error::SigningProtocol(_) => "exchange_custody_v3_signing_protocol",
        ExchangeCustodyRuntimeV3Error::Node(error) => error.client_error().code,
        ExchangeCustodyRuntimeV3Error::NodePoisoned => "shared_node_poisoned",
        ExchangeCustodyRuntimeV3Error::NodeBindingMismatch => {
            "exchange_custody_v3_binding_mismatch"
        }
        ExchangeCustodyRuntimeV3Error::WalletBindingMismatch => {
            "exchange_custody_v3_wallet_mismatch"
        }
        ExchangeCustodyRuntimeV3Error::RequestConflict => "withdrawal_request_conflict",
        ExchangeCustodyRuntimeV3Error::UnknownRequest => "withdrawal_not_found",
        ExchangeCustodyRuntimeV3Error::MissingSignerPackage => {
            "withdrawal_signer_package_unavailable"
        }
        ExchangeCustodyRuntimeV3Error::SigningNotAuthorized => "withdrawal_signing_not_authorized",
        ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction => {
            "exchange_custody_v3_released_transaction_invalid"
        }
        ExchangeCustodyRuntimeV3Error::Canceled => "withdrawal_canceled",
    }
}

fn exchange_custody_v3_retryable(error: &ExchangeCustodyRuntimeV3Error) -> bool {
    match error {
        ExchangeCustodyRuntimeV3Error::Store(
            crate::exchange_custody_v3::ExchangeCustodyV3Error::Busy,
        ) => true,
        ExchangeCustodyRuntimeV3Error::Node(error) => error.client_error().retryable,
        _ => false,
    }
}

fn exchange_custody_v3_client_message(error: &ExchangeCustodyRuntimeV3Error) -> String {
    match error {
        ExchangeCustodyRuntimeV3Error::Store(
            crate::exchange_custody_v3::ExchangeCustodyV3Error::ExternalAnchorAhead,
        ) => "the external exchange custody v3 anchor is ahead of the authenticated journal"
            .to_owned(),
        ExchangeCustodyRuntimeV3Error::Store(
            crate::exchange_custody_v3::ExchangeCustodyV3Error::ExternalAnchorMismatch,
        ) => "the external exchange custody v3 anchor diverges from the authenticated journal"
            .to_owned(),
        ExchangeCustodyRuntimeV3Error::Store(
            crate::exchange_custody_v3::ExchangeCustodyV3Error::ExternalAnchorNotCurrent,
        ) => "the external exchange custody v3 anchor is behind the authenticated current journal"
            .to_owned(),
        ExchangeCustodyRuntimeV3Error::Store(_) => {
            "exchange custody v3 storage or activation validation failed".to_owned()
        }
        ExchangeCustodyRuntimeV3Error::Keyring(_) => {
            "exchange custody v3 keyring validation failed".to_owned()
        }
        ExchangeCustodyRuntimeV3Error::SigningProtocol(_)
        | ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction => {
            "exchange custody v3 signing evidence is invalid".to_owned()
        }
        ExchangeCustodyRuntimeV3Error::Node(error) => error.to_string(),
        _ => error.to_string(),
    }
}

fn exchange_withdrawal_fault(error: ExchangeWithdrawalError) -> RpcFault {
    log_exchange_withdrawal_failure("request", &error);
    let data_code = error.code();
    let code = match data_code {
        "invalid_withdrawal_request_id"
        | "invalid_withdrawal_destination"
        | "invalid_withdrawal_amount"
        | "withdrawal_amount_overflow" => -32602,
        "withdrawal_request_conflict"
        | "withdrawal_not_prepared"
        | "withdrawal_prepared_anchor_mismatch"
        | "withdrawal_prepared_pending" => -32009,
        "wallet_funds_immature"
        | "wallet_insufficient_funds"
        | "wallet_input_limit"
        | "mempool_fee_too_low" => -32006,
        "exchange_withdrawal_io"
        | "exchange_withdrawal_corrupt"
        | "exchange_withdrawal_binding_mismatch"
        | "exchange_withdrawal_wallet_mismatch"
        | "exchange_withdrawal_faulted"
        | "exchange_withdrawal_capacity"
        | "exchange_withdrawal_security_required"
        | "invalid_exchange_withdrawal_journal_key"
        | "insecure_exchange_withdrawal_journal_key_permissions"
        | "exchange_withdrawal_anchor_inside_data_dir"
        | "invalid_exchange_withdrawal_anchor"
        | "exchange_withdrawal_anchor_mismatch"
        | "exchange_withdrawal_v1_migration_required"
        | "storage_faulted"
        | "corrupt_block_log"
        | "storage_io" => -32007,
        _ => -32603,
    };
    RpcFault {
        code,
        message: error.client_message(),
        data_code,
        retryable: error.retryable(),
    }
}

fn log_exchange_withdrawal_failure(context: &'static str, error: &ExchangeWithdrawalError) {
    match error {
        ExchangeWithdrawalError::Io {
            operation,
            path,
            source,
        } => tracing::error!(
            context,
            operation,
            path = %path.display(),
            error = %source,
            "exchange withdrawal journal storage failure"
        ),
        ExchangeWithdrawalError::Corrupt(reason) => {
            tracing::error!(context, reason, "exchange withdrawal journal corruption")
        }
        ExchangeWithdrawalError::BindingMismatch => {
            tracing::error!(context, "exchange withdrawal journal binding mismatch")
        }
        ExchangeWithdrawalError::WalletBindingMismatch => {
            tracing::error!(context, "exchange withdrawal wallet binding mismatch")
        }
        ExchangeWithdrawalError::SecurityRequired
        | ExchangeWithdrawalError::InvalidJournalKey
        | ExchangeWithdrawalError::InsecureJournalKeyPermissions
        | ExchangeWithdrawalError::AnchorInsideDataDirectory
        | ExchangeWithdrawalError::InvalidAnchor
        | ExchangeWithdrawalError::AnchorMismatch
        | ExchangeWithdrawalError::LegacyV1Unsupported => {
            tracing::error!(context, error = %error, "exchange withdrawal security failure")
        }
        ExchangeWithdrawalError::Capacity(kind) => {
            tracing::error!(
                context,
                kind,
                "exchange withdrawal journal capacity reached"
            )
        }
        ExchangeWithdrawalError::Node(source) => tracing::error!(
            context,
            error = %source,
            "exchange withdrawal journal node failure"
        ),
        ExchangeWithdrawalError::Faulted
        | ExchangeWithdrawalError::InvalidRequestId
        | ExchangeWithdrawalError::InvalidDestination
        | ExchangeWithdrawalError::InvalidAmount
        | ExchangeWithdrawalError::AmountOverflow
        | ExchangeWithdrawalError::RequestConflict
        | ExchangeWithdrawalError::NotPrepared
        | ExchangeWithdrawalError::PreparedAnchorMismatch
        | ExchangeWithdrawalError::PreparedWithdrawalPending => {}
    }
}

fn exchange_index_fault(error: ExchangeIndexError) -> RpcFault {
    log_exchange_index_failure("request", &error);
    let data_code = error.code();
    let code = match data_code {
        "invalid_watch_label"
        | "invalid_watch_destination"
        | "invalid_watch_registration_batch"
        | "duplicate_watch_batch_label"
        | "duplicate_watch_batch_destination"
        | "invalid_deposit_event_page_limit"
        | "deposit_cursor_ahead" => -32602,
        "watch_label_conflict" | "watch_destination_conflict" => -32009,
        "exchange_index_io"
        | "exchange_index_corrupt"
        | "exchange_index_binding_mismatch"
        | "exchange_index_faulted"
        | "exchange_index_capacity"
        | "storage_faulted"
        | "corrupt_block_log"
        | "storage_io" => -32007,
        "exchange_index_chain_changed" => -32008,
        _ => -32603,
    };
    RpcFault {
        code,
        message: error.client_message(),
        data_code,
        retryable: error.retryable(),
    }
}

fn log_exchange_index_failure(context: &'static str, error: &ExchangeIndexError) {
    match error {
        ExchangeIndexError::Io {
            operation,
            path,
            source,
        } => tracing::error!(
            context,
            operation,
            path = %path.display(),
            error = %source,
            "exchange deposit index storage failure"
        ),
        ExchangeIndexError::Corrupt(reason) => {
            tracing::error!(context, reason, "exchange deposit index corruption")
        }
        ExchangeIndexError::BindingMismatch => {
            tracing::error!(context, "exchange deposit index binding mismatch")
        }
        ExchangeIndexError::Capacity(kind) => {
            tracing::error!(context, kind, "exchange deposit index capacity reached")
        }
        ExchangeIndexError::Node(source) => tracing::error!(
            context,
            error = %source,
            "exchange deposit index node failure"
        ),
        ExchangeIndexError::Faulted
        | ExchangeIndexError::InvalidLabel
        | ExchangeIndexError::InvalidDestination
        | ExchangeIndexError::InvalidRegistrationBatch
        | ExchangeIndexError::DuplicateBatchLabel
        | ExchangeIndexError::DuplicateBatchDestination
        | ExchangeIndexError::LabelConflict
        | ExchangeIndexError::DestinationConflict
        | ExchangeIndexError::InvalidCursor
        | ExchangeIndexError::InvalidPageLimit
        | ExchangeIndexError::ChainChanged => {}
    }
}

fn node_fault(error: NodeError) -> RpcFault {
    let client = error.client_error();
    let code = match client.code {
        "storage_faulted" | "corrupt_block_log" | "storage_io" => -32007,
        "mempool_input_conflict"
        | "mempool_unconfirmed_input"
        | "mempool_transaction_limit"
        | "mempool_byte_limit"
        | "mempool_fee_too_low"
        | "duplicate_mempool_transaction"
        | "chain_rejected"
        | "chain_temporarily_rejected" => -32005,
        _ => -32603,
    };
    let retryable = client.retryable && client.code != "mempool_unconfirmed_input";
    RpcFault {
        code,
        message: client.message,
        data_code: client.code,
        retryable,
    }
}

/// Bitcoin Core's `gettxoutsetinfo` for the active chain. `total_amount_atoms`
/// is the total supply: every minted coin minus burned fees.
fn txout_set_info(node: &Node) -> Value {
    json!({
        "height": node.state.next_height().saturating_sub(1),
        "bestblock": hex::encode(node.state.tip()),
        "txouts": node.state.utxos().len(),
        "total_amount_atoms": node.total_supply_atoms().to_string(),
    })
}

fn blockchain_info(node: &Node) -> Result<Value, NodeError> {
    let status = node.status()?;
    let now = crate::unix_time_seconds()?;
    let connections = status.peers.iter().fold(0_usize, |total, peer| {
        total.saturating_add(peer.active_connections)
    });
    let recent_reachable_peers = status
        .peers
        .iter()
        .filter(|peer| {
            peer.last_success.is_some_and(|last_success| {
                last_success <= now && now - last_success <= SYNC_OBSERVATION_MAX_AGE_SECS
            })
        })
        .collect::<Vec<_>>();
    let observed_peer_height = recent_reachable_peers
        .iter()
        .filter_map(|peer| peer.remote_height)
        .max();
    let headers = observed_peer_height
        .unwrap_or(status.accepted_height)
        .max(status.accepted_height);
    let caught_up = observed_peer_height.is_some_and(|height| status.accepted_height >= height);
    let matching_peer_tip = recent_reachable_peers.iter().any(|peer| {
        peer.remote_height == Some(status.accepted_height)
            && peer.remote_tip.as_deref() == Some(status.tip.as_str())
    });
    let verification_progress = match observed_peer_height {
        Some(0) => 1.0,
        Some(height) => (status.accepted_height.min(height) as f64) / (height as f64),
        None => 0.0,
    };
    let mut warnings = Vec::new();
    if !status.storage_healthy {
        warnings.push("authenticated block storage is faulted".to_owned());
    }
    match observed_peer_height {
        None => warnings.push(
            "no recent reachable peer height is available; synchronization cannot be established"
                .to_owned(),
        ),
        Some(height) if status.accepted_height < height => warnings.push(format!(
            "local tip is {} blocks behind the highest recent reachable peer observation",
            height - status.accepted_height
        )),
        Some(_) => {}
    }
    warnings.push(
        "peer height and tip observations are unauthenticated and advisory; exchange readiness requires an external checkpoint or trusted multi-node policy"
            .to_owned(),
    );

    let mut info = json!({
        "api_version": EXCHANGE_RPC_API_VERSION,
        "chain": status.network_short_name,
        "network_id": status.network_id,
        "consensus_fingerprint": status.consensus_fingerprint,
        "blocks": status.accepted_height,
        "headers": headers,
        "bestblockhash": status.tip,
        "chainwork": status.cumulative_work,
        "initialblockdownload": true,
        "verificationprogress": verification_progress,
        "connections": connections,
        "recent_reachable_peers": recent_reachable_peers.len(),
        "peer_observation_caught_up": caught_up,
        "peer_observation_tip_match": matching_peer_tip,
        "storage_healthy": status.storage_healthy,
        "first_block_height": 1,
        "sync_basis": "external_readiness_policy_required",
        "warnings": warnings,
    });
    // As in Bitcoin Core, `pruneheight` is the lowest block whose raw bytes
    // are still stored. Verbose block data stays available for every block.
    let pruned = status.prune_keep_blocks.is_some() || status.pruned_height.is_some();
    info["pruned"] = json!(pruned);
    if pruned {
        info["pruneheight"] = json!(status.pruned_height.map_or(1, |height| height + 1));
        info["prune_keep_blocks"] = json!(status.prune_keep_blocks);
    }
    Ok(info)
}

fn block_document(
    block: &crate::StoredBlock,
    encoded_bytes: usize,
    verbose_transactions: bool,
    active_confirmations: Option<u64>,
    next_block: Option<[u8; 32]>,
) -> Result<Value, NodeError> {
    let block_id = block.block_id();
    let active = active_confirmations.is_some();
    let confirmations = match active_confirmations {
        Some(value) => i64::try_from(value).unwrap_or(i64::MAX),
        None => -1,
    };
    let next_block = next_block.map(hex::encode);
    let transactions = if verbose_transactions {
        block
            .transactions
            .iter()
            .map(|transaction| {
                transaction_document(
                    transaction,
                    Some(block_id),
                    Some(block.challenge.height),
                    Some(confirmations),
                    Some(block.challenge.timestamp),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        block
            .transactions
            .iter()
            .map(|transaction| json!(hex::encode(transaction.txid())))
            .collect()
    };
    let summary = block.proof_summary();
    let (proof_type, nonce, work_digest) =
        (summary.kind_name(), summary.nonce, summary.work_digest);

    Ok(json!({
        "hash": hex::encode(block_id),
        "height": block.challenge.height,
        "confirmations": confirmations,
        "active": active,
        "size": encoded_bytes,
        "version": block.version,
        "time": block.challenge.timestamp,
        "previousblockhash": hex::encode(block.challenge.previous_block),
        "nextblockhash": next_block,
        "merkleroot": hex::encode(block.challenge.transaction_root),
        "target": hex::encode(block.challenge.target),
        "proof": {
            "type": proof_type,
            "nonce": nonce.to_string(),
            "work_digest": hex::encode(work_digest),
        },
        "coinbase": {
            "height": block.coinbase.height,
            "outpoint_txid": hex::encode(block.coinbase_outpoint_id()),
            "vout": outputs_document(&block.coinbase.outputs),
        },
        "tx": transactions,
    }))
}

fn virtual_genesis_document(node: &Node) -> Value {
    let block_id = node.profile.virtual_genesis_hash;
    let confirmations = node
        .active_chain_confirmations(block_id)
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or(1);
    json!({
        "hash": hex::encode(block_id),
        "height": 0,
        "confirmations": confirmations,
        "active": true,
        "virtual": true,
        "size": 0,
        "version": 0,
        "time": node.profile.virtual_genesis_timestamp,
        "previousblockhash": Value::Null,
        "nextblockhash": node.active_block_id_at_height(1).map(hex::encode),
        "merkleroot": Value::Null,
        "target": Value::Null,
        "proof": Value::Null,
        "coinbase": Value::Null,
        "tx": [],
    })
}

fn transaction_document(
    transaction: &Transaction,
    block_id: Option<[u8; 32]>,
    block_height: Option<u64>,
    confirmations: Option<i64>,
    timestamp: Option<u64>,
) -> Result<Value, NodeError> {
    let raw = encode_transaction(transaction)?;
    let inputs = transaction
        .inputs
        .iter()
        .map(|input| {
            let witness_type = match input.witness {
                InputWitness::Key { .. } => "key",
                InputWitness::InferenceSettlement { .. } => "inference_settlement",
                InputWitness::InferenceRefund { .. } => "inference_refund",
            };
            json!({
                "txid": hex::encode(input.previous.txid),
                "vout": input.previous.index,
                "witness_type": witness_type,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "txid": hex::encode(transaction.txid()),
        "hex": hex::encode(&raw),
        "size": raw.len(),
        "version": transaction.version,
        "network_id": hex::encode(transaction.network_id),
        "blockhash": block_id.map(hex::encode),
        "blockheight": block_height,
        "confirmations": confirmations,
        "time": timestamp,
        "vin": inputs,
        "vout": outputs_document(&transaction.outputs),
    }))
}

fn outputs_document(outputs: &[TxOutput]) -> Vec<Value> {
    outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let (lock_type, destination_hex, channel_id) = match output.lock {
                OutputLock::Key(destination) => ("key", Some(hex::encode(destination)), None),
                OutputLock::InferenceChannel { channel_id } => {
                    ("inference_channel", None, Some(hex::encode(channel_id)))
                }
            };
            json!({
                "n": index,
                "value_atoms": output.value.to_string(),
                "spendable_height": output.spendable_height,
                "lock_type": lock_type,
                "destination_hex": destination_hex,
                "channel_id": channel_id,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use serde_json::{Value, json};

    use super::*;
    use crate::{
        DEFAULT_MINING_ATTEMPTS, DEVNET_PROFILE, ExchangeWithdrawalSecurityConfig, PeerDirection,
        unix_time_seconds,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn test_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-exchange-rpc-{name}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_authentication_file(path: &Path) {
        fs::write(path, b"exchange:test-password-0123456789").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn write_withdrawal_authentication_file(path: &Path) {
        fs::write(path, b"withdrawal:another-password-0123456789").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn secured_withdrawal_node(
        directory: &Path,
    ) -> (Node, PathBuf, ExchangeWithdrawalSecurityConfig) {
        let security_directory = directory.with_extension("withdrawal-security");
        let _ = fs::remove_dir_all(&security_directory);
        fs::create_dir_all(&security_directory).unwrap();
        let key_path = security_directory.join("journal.key");
        fs::write(&key_path, [0x5a_u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let security = ExchangeWithdrawalSecurityConfig::new(
            &key_path,
            security_directory.join("journal.anchor"),
        );
        let node = Node::open_with_profile_and_exchange_withdrawal_security(
            directory,
            DEVNET_PROFILE,
            &security,
        )
        .unwrap();
        (node, security_directory, security)
    }

    fn write_external_withdrawal_anchor(
        path: &Path,
        anchor: &crate::exchange_withdrawal::WithdrawalJournalAnchor,
    ) {
        let bytes = crate::exchange_withdrawal::encode_external_anchor(anchor).unwrap();
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn call(body: Value, node: &mut Node) -> Value {
        dispatch_json_rpc(&serde_json::to_vec(&body).unwrap(), node)
    }

    fn shared_call(
        body: Value,
        shared: &Arc<Mutex<Node>>,
        exchange_index: &SharedExchangeDepositIndex,
    ) -> Value {
        let request = parse_json_rpc(&serde_json::to_vec(&body).unwrap()).unwrap();
        dispatch_shared_request(request, shared, exchange_index, DEVNET_PROFILE.network_id)
    }

    fn scoped_shared_call(
        body: Value,
        shared: &Arc<Mutex<Node>>,
        exchange_index: &SharedExchangeDepositIndex,
        withdrawal_journal: Option<&SharedExchangeWithdrawalJournal>,
        scope: AuthorizationScope,
    ) -> Value {
        let request = parse_json_rpc(&serde_json::to_vec(&body).unwrap()).unwrap();
        dispatch_shared_request_scoped(
            request,
            shared,
            exchange_index,
            withdrawal_journal,
            DEVNET_PROFILE.network_id,
            scope,
        )
    }

    #[test]
    fn custody_v3_maps_wallet_capacity_failures_to_actionable_rpc_errors() {
        let cases = [
            (
                NodeError::WalletFundsImmature {
                    immature: 20,
                    required: 30,
                },
                "wallet_funds_immature",
                true,
            ),
            (
                NodeError::WalletInsufficientFunds {
                    available: 20,
                    required: 30,
                },
                "wallet_insufficient_funds",
                false,
            ),
            (
                NodeError::WalletInputLimit {
                    selected: 20,
                    required: 30,
                },
                "wallet_input_limit",
                false,
            ),
            (
                NodeError::MempoolFeeTooLow {
                    required: 20,
                    actual: 10,
                },
                "mempool_fee_too_low",
                false,
            ),
        ];

        for (error, data_code, retryable) in cases {
            let fault = exchange_custody_v3_fault(ExchangeCustodyRuntimeV3Error::Node(error));
            assert_eq!(fault.code, -32006);
            assert_eq!(fault.data_code, data_code);
            assert_eq!(fault.retryable, retryable);
        }

        let storage_fault = exchange_custody_v3_fault(ExchangeCustodyRuntimeV3Error::Node(
            NodeError::StorageFaulted,
        ));
        assert_eq!(storage_fault.code, -32007);
        assert_eq!(storage_fault.data_code, "storage_faulted");
    }

    #[test]
    fn protocol_requires_ids_and_echoes_them_exactly() {
        let directory = test_directory("protocol");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();

        let response = call(
            json!({"jsonrpc":"2.0","id":"height-1","method":"getblockcount","params":[]}),
            &mut node,
        );
        assert_eq!(response["id"], "height-1");
        assert_eq!(response["result"], 0);

        let notification = call(
            json!({"jsonrpc":"2.0","method":"getblockcount","params":[]}),
            &mut node,
        );
        assert_eq!(
            notification["error"]["data"]["code"],
            "notification_unsupported"
        );

        let batch = dispatch_json_rpc(b"[]", &mut node);
        assert_eq!(batch["error"]["data"]["code"], "batch_unsupported");
        drop(node);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn virtual_genesis_has_a_synthetic_document_but_no_raw_frame() {
        let directory = test_directory("genesis");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();

        let hash = call(
            json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[0]}),
            &mut node,
        )["result"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(hash, hex::encode(DEVNET_PROFILE.virtual_genesis_hash));
        let block = call(
            json!({"jsonrpc":"2.0","id":2,"method":"getblock","params":[hash,1]}),
            &mut node,
        );
        assert_eq!(block["result"]["height"], 0);
        assert_eq!(block["result"]["virtual"], true);
        assert_eq!(block["result"]["size"], 0);
        let raw = call(
            json!({"jsonrpc":"2.0","id":3,"method":"getblock","params":[hash,0]}),
            &mut node,
        );
        assert_eq!(raw["error"]["data"]["code"], "block_not_found");
        drop(node);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn gettxoutsetinfo_reports_the_total_supply() {
        let directory = test_directory("txoutset");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let mut minted = 0_u64;
        for height in 1..=3 {
            let block = node
                .mine_once(
                    destination,
                    DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            minted += block
                .coinbase
                .outputs
                .iter()
                .map(|output| output.value)
                .sum::<u64>();
        }
        let info = call(
            json!({"jsonrpc":"2.0","id":1,"method":"gettxoutsetinfo","params":[]}),
            &mut node,
        )["result"]
            .clone();
        assert_eq!(info["height"], 3);
        assert_eq!(info["bestblock"], hex::encode(node.state.tip()));
        assert_eq!(info["txouts"], node.state.utxos().len());
        assert_eq!(info["total_amount_atoms"], minted.to_string());
        let extra = call(
            json!({"jsonrpc":"2.0","id":2,"method":"gettxoutsetinfo","params":["muhash"]}),
            &mut node,
        );
        assert!(extra.get("error").is_some());
        drop(node);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pruned_blocks_keep_verbose_documents_but_no_raw_frame() {
        let directory = test_directory("pruned");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        // The floor is for operators; tests use a short window.
        node.prune_keep_blocks = Some(10);
        for height in 1..=80 {
            node.mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let info = blockchain_info(&node).unwrap();
        assert_eq!(info["pruned"], true);
        assert_eq!(info["pruneheight"], 1);
        let hash = call(
            json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[5]}),
            &mut node,
        )["result"]
            .as_str()
            .unwrap()
            .to_owned();
        let full = call(
            json!({"jsonrpc":"2.0","id":2,"method":"getblock","params":[hash,2]}),
            &mut node,
        )["result"]
            .clone();

        node.prune_block_log().unwrap().unwrap();
        let info = blockchain_info(&node).unwrap();
        assert_eq!(info["pruned"], true);
        assert_eq!(info["pruneheight"], 65);
        assert_eq!(info["prune_keep_blocks"], 10);
        // Everything but the proof bytes survives, including the reported
        // size of the original block.
        let pruned = call(
            json!({"jsonrpc":"2.0","id":3,"method":"getblock","params":[hash,2]}),
            &mut node,
        )["result"]
            .clone();
        assert_eq!(pruned, full);
        let raw = call(
            json!({"jsonrpc":"2.0","id":4,"method":"getblock","params":[hash,0]}),
            &mut node,
        );
        assert_eq!(raw["error"]["data"]["code"], "block_proof_pruned");
        let tip = call(
            json!({"jsonrpc":"2.0","id":5,"method":"getbestblockhash","params":[]}),
            &mut node,
        )["result"]
            .clone();
        let raw = call(
            json!({"jsonrpc":"2.0","id":6,"method":"getblock","params":[tip,0]}),
            &mut node,
        );
        assert!(raw["result"].is_string());
        drop(node);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn deposit_rpc_registration_and_event_contract_is_strict_and_retry_safe() {
        let directory = test_directory("deposit-contract");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let consensus_fingerprint = node.fingerprint;
        let block = node
            .mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let block_id = block.block_id();
        let shared = Arc::new(Mutex::new(node));
        let exchange_index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));
        let label = "account-42";
        let destination_hex = hex::encode(destination);

        let registration = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"register",
                "method":"registerwatchdestination",
                "params":[label, destination_hex]
            }),
            &shared,
            &exchange_index,
        );
        let expected_watch = json!({
            "api_version": EXCHANGE_RPC_API_VERSION,
            "label": label,
            "destination_hex": destination_hex,
            "registered_at_height": 1,
            "registered_at_tip": hex::encode(block_id),
        });
        assert_eq!(registration["result"], expected_watch);

        let retry = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"register-retry",
                "method":"registerwatchdestination",
                "params":[label, destination_hex]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(retry["result"], registration["result"]);

        let watch = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"watch",
                "method":"getwatchdestination",
                "params":[label]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(watch["result"], expected_watch);

        let matching_outputs = block
            .coinbase
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, output)| output.lock == OutputLock::Key(destination))
            .collect::<Vec<_>>();
        assert_eq!(matching_outputs.len(), 1);
        let (vout, output) = matching_outputs[0];
        let events = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"events",
                "method":"getdepositevents",
                "params":["0"]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(
            events["result"],
            json!({
                "api_version": EXCHANGE_RPC_API_VERSION,
                "network_id": hex::encode(DEVNET_PROFILE.network_id),
                "consensus_fingerprint": hex::encode(consensus_fingerprint),
                "indexed_tip": {"height": 1, "hash": hex::encode(block_id)},
                "events": [{
                    "cursor": "1",
                    "added_cursor": "1",
                    "kind": "deposit_added",
                    "label": label,
                    "destination_hex": destination_hex,
                    "txid": hex::encode(block.coinbase_outpoint_id()),
                    "vout": vout,
                    "value_atoms": output.value.to_string(),
                    "spendable_height": output.spendable_height,
                    "coinbase": true,
                    "blockhash": hex::encode(block_id),
                    "blockheight": 1,
                    "blocktime": block.challenge.timestamp,
                }],
                "next_cursor": "1",
                "high_watermark": "1",
                "has_more": false,
            })
        );

        let numeric_cursor = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"numeric-cursor",
                "method":"getdepositevents",
                "params":[0]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(numeric_cursor["error"]["data"]["code"], "invalid_params");
        let invalid_limit = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"invalid-limit",
                "method":"getdepositevents",
                "params":["0", 0]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(
            invalid_limit["error"]["data"]["code"],
            "invalid_deposit_event_page_limit"
        );
        let cursor_ahead = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"cursor-ahead",
                "method":"getdepositevents",
                "params":["2"]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(
            cursor_ahead["error"]["data"]["code"],
            "deposit_cursor_ahead"
        );

        drop(exchange_index);
        drop(shared);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exchange_info_and_batch_registration_are_machine_discoverable() {
        let directory = test_directory("exchange-info-batch");
        let _ = fs::remove_dir_all(&directory);
        let node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let first = node.wallet_destination();
        let second: [u8; 32] =
            k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng)
                .verifying_key()
                .to_bytes()
                .into();
        let shared = Arc::new(Mutex::new(node));
        let exchange_index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));

        let info = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"exchange-info",
                "method":"getexchangeinfo",
                "params":[]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(info["result"]["service"], "common-foundry-exchange-rpc");
        assert_eq!(info["result"]["production_ready"], false);
        assert_eq!(info["result"]["custody"]["mode"], "disabled");
        assert_eq!(
            info["result"]["network_id"],
            hex::encode(DEVNET_PROFILE.network_id)
        );
        assert_eq!(
            info["result"]["deposit_index"]["capacity"]["registration_batch_limit"],
            MAX_WATCH_REGISTRATION_BATCH.to_string()
        );
        assert!(
            info["result"]["methods"]["integration"]
                .as_array()
                .unwrap()
                .iter()
                .any(|method| method == "registerwatchdestinations")
        );

        let request = json!({
            "jsonrpc":"2.0",
            "id":"batch-register",
            "method":"registerwatchdestinations",
            "params":[[
                {"label":"account-001","destination_hex":hex::encode(first)},
                {"label":"account-002","destination_hex":hex::encode(second)}
            ]]
        });
        let registration = shared_call(request.clone(), &shared, &exchange_index);
        assert_eq!(registration["result"]["registration_count"], 2);
        assert_eq!(
            registration["result"]["registrations"][0]["label"],
            "account-001"
        );
        assert_eq!(
            registration["result"]["registrations"][1]["label"],
            "account-002"
        );
        let retry = shared_call(request, &shared, &exchange_index);
        assert_eq!(retry["result"], registration["result"]);

        let updated = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"updated-info",
                "method":"getexchangeinfo",
                "params":[]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(
            updated["result"]["deposit_index"]["capacity"]["watch_destination_count"],
            "2"
        );
        let unknown_field = shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"unknown-field",
                "method":"registerwatchdestinations",
                "params":[[{
                    "label":"account-003",
                    "destination_hex":hex::encode(second),
                    "customer_name":"must-not-be-stored"
                }]]
            }),
            &shared,
            &exchange_index,
        );
        assert_eq!(unknown_field["error"]["data"]["code"], "invalid_params");

        drop(exchange_index);
        drop(shared);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn withdrawal_rpc_prepares_then_releases_an_exact_anchored_transaction() {
        let directory = test_directory("withdrawal-lifecycle");
        let _ = fs::remove_dir_all(&directory);
        let (mut node, security_directory, security) = secured_withdrawal_node(&directory);
        let destination = node.wallet_destination();
        for height in 1..=100 {
            node.mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let destination_hex = hex::encode(destination);
        let shared = Arc::new(Mutex::new(node));
        let exchange_index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));
        let withdrawal_journal = Arc::new(Mutex::new(
            ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap(),
        ));
        let bootstrap_anchor = withdrawal_journal
            .lock()
            .unwrap()
            .journal_info()
            .unwrap()
            .current_anchor;
        let prepare = json!({
            "jsonrpc":"2.0",
            "id":"withdraw-1",
            "method":"preparewithdrawal",
            "params":["order-0001", destination_hex, "1", "1"]
        });

        let wrong_scope = scoped_shared_call(
            prepare.clone(),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Integration,
        );
        assert_eq!(
            wrong_scope["error"]["data"]["code"],
            "withdrawal_authorization_required"
        );
        let withdrawal_scope_is_narrow = scoped_shared_call(
            json!({"jsonrpc":"2.0","id":"scope","method":"getblockcount","params":[]}),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(
            withdrawal_scope_is_narrow["error"]["data"]["code"],
            "withdrawal_scope_only"
        );

        let missing_bootstrap_anchor = scoped_shared_call(
            prepare.clone(),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(
            missing_bootstrap_anchor["error"]["data"]["code"],
            "invalid_exchange_withdrawal_anchor"
        );
        assert_eq!(shared.lock().unwrap().mempool_entries().len(), 0);
        write_external_withdrawal_anchor(security.anchor_file(), &bootstrap_anchor);

        let first = scoped_shared_call(
            prepare.clone(),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(first["result"]["phase"], "prepared");
        assert_eq!(first["result"]["status"], "prepared");
        assert_eq!(first["result"]["amount_atoms"], "1");
        assert_eq!(first["result"]["fee_atoms"], "1");
        assert!(first["result"]["txid"].is_null());
        assert!(first["result"]["transaction_hex"].is_null());
        assert_eq!(
            first["result"]["prepared_anchor"],
            first["result"]["anchor"]
        );
        let anchor = first["result"]["anchor"].as_object().unwrap();
        assert_eq!(anchor.len(), 4);
        for field in ["key_id", "journal_instance_id", "commitment"] {
            let encoded = anchor[field].as_str().unwrap();
            assert_eq!(encoded.len(), 64);
            assert_eq!(encoded, encoded.to_ascii_lowercase());
            assert_eq!(hex::decode(encoded).unwrap().len(), 32);
        }
        let generation = anchor["generation"].as_str().unwrap();
        assert_eq!(generation.parse::<u64>().unwrap().to_string(), generation);
        assert_eq!(shared.lock().unwrap().mempool_entries().len(), 0);
        let prepared_anchor = first["result"]["prepared_anchor"].clone();

        let observed = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"observe-prepared",
                "method":"getwithdrawal",
                "params":["order-0001"]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(observed["result"]["phase"], "prepared");
        assert_eq!(observed["result"]["status"], "prepared");
        assert!(observed["result"]["txid"].is_null());
        assert!(observed["result"]["transaction_hex"].is_null());
        assert_eq!(observed["result"]["anchor"], prepared_anchor);
        assert_eq!(shared.lock().unwrap().mempool_entries().len(), 0);

        let retry = scoped_shared_call(
            prepare,
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(retry["result"], first["result"]);
        assert!(retry["result"]["txid"].is_null());
        assert!(retry["result"]["transaction_hex"].is_null());
        assert_eq!(retry["result"]["prepared_anchor"], prepared_anchor);
        assert_eq!(shared.lock().unwrap().mempool_entries().len(), 0);

        let conflict = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"conflict",
                "method":"preparewithdrawal",
                "params":["order-0001", destination_hex, "2", "1"]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(
            conflict["error"]["data"]["code"],
            "withdrawal_request_conflict"
        );
        let noncanonical = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"noncanonical",
                "method":"preparewithdrawal",
                "params":["order-0002", destination_hex, "01", "1"]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(noncanonical["error"]["data"]["code"], "invalid_params");

        let durable_prepared_anchor = withdrawal_journal
            .lock()
            .unwrap()
            .get(&shared, "order-0001")
            .unwrap()
            .unwrap()
            .prepared_anchor
            .unwrap();
        write_external_withdrawal_anchor(security.anchor_file(), &durable_prepared_anchor);
        let journal_info = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"journal-info",
                "method":"getwithdrawaljournalinfo",
                "params":[]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(journal_info["result"]["anchor"], prepared_anchor);
        assert_eq!(journal_info["result"]["external_anchor"], prepared_anchor);
        assert_eq!(journal_info["result"]["anchor_relationship"], "current");

        let client_supplied_anchor = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"client-anchor",
                "method":"releasewithdrawal",
                "params":["order-0001", prepared_anchor]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(
            client_supplied_anchor["error"]["data"]["code"],
            "invalid_params"
        );
        assert_eq!(shared.lock().unwrap().mempool_entries().len(), 0);

        write_external_withdrawal_anchor(security.anchor_file(), &bootstrap_anchor);
        let refused_release = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"wrong-anchor",
                "method":"releasewithdrawal",
                "params":["order-0001"]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(
            refused_release["error"]["data"]["code"],
            "withdrawal_prepared_anchor_mismatch"
        );
        assert_eq!(shared.lock().unwrap().mempool_entries().len(), 0);
        let still_unsigned = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"observe-refused-release",
                "method":"getwithdrawal",
                "params":["order-0001"]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(still_unsigned["result"]["phase"], "prepared");
        assert!(still_unsigned["result"]["txid"].is_null());
        assert!(still_unsigned["result"]["transaction_hex"].is_null());

        write_external_withdrawal_anchor(security.anchor_file(), &durable_prepared_anchor);
        let released = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"release",
                "method":"releasewithdrawal",
                "params":["order-0001"]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(released["result"]["phase"], "released");
        assert_eq!(released["result"]["status"], "in_mempool");
        let txid = released["result"]["txid"].as_str().unwrap().to_owned();
        let transaction_hex = released["result"]["transaction_hex"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(released["result"]["prepared_anchor"], prepared_anchor);
        assert_ne!(released["result"]["anchor"], prepared_anchor);
        assert_eq!(shared.lock().unwrap().mempool_entries().len(), 1);

        let release_retry = scoped_shared_call(
            json!({
                "jsonrpc":"2.0",
                "id":"release-retry",
                "method":"releasewithdrawal",
                "params":["order-0001"]
            }),
            &shared,
            &exchange_index,
            Some(&withdrawal_journal),
            AuthorizationScope::Withdrawal,
        );
        assert_eq!(release_retry["result"], released["result"]);
        assert_eq!(release_retry["result"]["txid"], txid);
        assert_eq!(release_retry["result"]["transaction_hex"], transaction_hex);
        assert_eq!(shared.lock().unwrap().mempool_entries().len(), 1);

        drop(withdrawal_journal);
        drop(exchange_index);
        drop(shared);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(security_directory).unwrap();
    }

    #[test]
    fn mined_block_round_trips_as_raw_and_explicit_json() {
        let directory = test_directory("block-round-trip");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let block = node
            .mine_once(
                destination,
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let block_id = hex::encode(block.block_id());

        let height_hash = call(
            json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[1]}),
            &mut node,
        );
        assert_eq!(height_hash["result"], block_id);

        let raw = call(
            json!({"jsonrpc":"2.0","id":2,"method":"getblock","params":[block_id,0]}),
            &mut node,
        );
        let raw = hex::decode(raw["result"].as_str().unwrap()).unwrap();
        assert_eq!(
            decode_block(&raw, DEVNET_PROFILE.network_id).unwrap(),
            block
        );

        let verbose = call(
            json!({"jsonrpc":"2.0","id":3,"method":"getblock","params":[block_id,2]}),
            &mut node,
        );
        assert_eq!(verbose["result"]["height"], 1);
        assert_eq!(verbose["result"]["confirmations"], 1);
        assert_eq!(
            verbose["result"]["coinbase"]["outpoint_txid"],
            hex::encode(block.coinbase_outpoint_id())
        );
        assert_eq!(verbose["result"]["coinbase"]["vout"][0]["lock_type"], "key");
        assert!(verbose["result"]["coinbase"]["vout"][0]["value_atoms"].is_string());
        assert!(verbose["result"]["tx"].as_array().unwrap().is_empty());

        let shared = Arc::new(Mutex::new(node));
        let exchange_index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));
        let request = parse_json_rpc(
            &serde_json::to_vec(&json!({
                "jsonrpc":"2.0",
                "id":"shared-getblock",
                "method":"getblock",
                "params":[block_id.clone(),2]
            }))
            .unwrap(),
        )
        .unwrap();
        let shared_verbose =
            dispatch_shared_request(request, &shared, &exchange_index, DEVNET_PROFILE.network_id);
        assert_eq!(shared_verbose["result"]["height"], 1);
        assert_eq!(shared_verbose["result"]["hash"], block_id);

        drop(shared);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn shared_getblock_relatches_off_lock_storage_corruption() {
        let directory = test_directory("shared-block-corruption");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let block = node
            .mine_once(
                destination,
                unix_time_seconds().unwrap(),
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let block_id = block.block_id();
        let shared = Arc::new(Mutex::new(node));
        let exchange_index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));
        Arc::make_mut(
            shared
                .lock()
                .unwrap()
                .index
                .blocks
                .get_mut(&block_id)
                .unwrap(),
        )
        .locator
        .complete_digest[0] ^= 1;
        let request = parse_json_rpc(
            &serde_json::to_vec(&json!({
                "jsonrpc":"2.0",
                "id":"corrupt-getblock",
                "method":"getblock",
                "params":[hex::encode(block_id),1]
            }))
            .unwrap(),
        )
        .unwrap();

        let response =
            dispatch_shared_request(request, &shared, &exchange_index, DEVNET_PROFILE.network_id);
        assert_eq!(response["error"]["data"]["code"], "corrupt_block_log");
        assert!(shared.lock().unwrap().storage_faulted);

        drop(shared);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn raw_transaction_broadcast_is_retry_safe_while_in_the_mempool() {
        let directory = test_directory("transaction-round-trip");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        for height in 1..=100 {
            node.mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let (transaction, _) = node.prepare_dev_wallet_payment(destination, 1, 1).unwrap();
        let txid = hex::encode(transaction.txid());
        let transaction_hex = hex::encode(encode_transaction(&transaction).unwrap());

        for id in ["broadcast", "retry-in-mempool"] {
            let response = call(
                json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "method":"sendrawtransaction",
                    "params":[transaction_hex]
                }),
                &mut node,
            );
            assert_eq!(response["result"], txid);
        }

        let compact = call(
            json!({"jsonrpc":"2.0","id":3,"method":"getrawmempool","params":[]}),
            &mut node,
        );
        assert_eq!(compact["result"], json!([txid]));
        let verbose = call(
            json!({"jsonrpc":"2.0","id":4,"method":"getrawmempool","params":[true]}),
            &mut node,
        );
        assert_eq!(verbose["result"][&txid]["fee_atoms"], "1");
        assert!(verbose["result"][&txid]["size"].is_number());

        let confirmed = node
            .mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + 101 * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        assert_eq!(confirmed.transactions.len(), 1);
        let retry_after_confirmation = call(
            json!({
                "jsonrpc":"2.0",
                "id":"retry-confirmed",
                "method":"sendrawtransaction",
                "params":[transaction_hex]
            }),
            &mut node,
        );
        assert_eq!(
            retry_after_confirmation["error"]["data"]["code"],
            "transaction_already_confirmed"
        );
        assert_eq!(
            retry_after_confirmation["error"]["data"]["retryable"],
            false
        );

        let malformed = call(
            json!({"jsonrpc":"2.0","id":5,"method":"sendrawtransaction","params":["xyz"]}),
            &mut node,
        );
        assert_eq!(malformed["error"]["data"]["code"], "invalid_params");

        drop(node);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn integration_transaction_lookup_and_balance_follow_mempool_confirmation_and_restart() {
        let directory = test_directory("integration-queries");
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let mut first = None;
        for height in 1..=100 {
            let block = node
                .mine_once(
                    destination,
                    DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            if height == 1 {
                first = Some(block);
            }
        }
        let first = first.unwrap();
        let (transaction, _) = node.prepare_dev_wallet_payment(destination, 1, 1).unwrap();
        let txid = hex::encode(transaction.txid());
        let raw = hex::encode(encode_transaction(&transaction).unwrap());
        let shared = Arc::new(Mutex::new(node));
        let index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));
        let query = |method: &str, params: Value| {
            shared_call(
                json!({"jsonrpc":"2.0", "id":"query", "method":method, "params":params}),
                &shared,
                &index,
            )
        };
        let before = query("getaddressbalance", json!([hex::encode(destination)]));
        assert!(
            before["result"]["available_atoms"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
                > 0
        );
        assert!(
            before["result"]["immature_atoms"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
                > 0
        );
        assert_eq!(
            query("getbalance", json!([hex::encode(destination)]))["result"],
            before["result"]
        );
        assert_eq!(query("sendrawtransaction", json!([raw]))["result"], txid);
        assert_eq!(query("sendrawtransaction", json!([raw]))["result"], txid);
        let pending = query("gettransaction", json!([txid]));
        assert_eq!(pending["result"]["confirmations"], 0);
        assert_eq!(pending["result"]["status"], "mempool");
        assert_eq!(query("getrawtransaction", json!([txid]))["result"], raw);
        assert_eq!(
            query("getrawtransaction", json!([txid, 1]))["result"]["hex"],
            raw
        );
        let pending_balance = query("getbalance", json!([hex::encode(destination)]));
        assert_eq!(pending_balance["result"]["unconfirmed_delta_atoms"], "-1");
        assert_eq!(
            pending_balance["result"]["confirmed_atoms"],
            before["result"]["confirmed_atoms"]
        );
        assert_eq!(pending_balance["result"]["available_atoms"], "0");
        let confirmed = shared
            .lock()
            .unwrap()
            .mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + 101 * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let found = query("gettransaction", json!([txid]));
        assert_eq!(found["result"]["confirmations"], 1);
        assert_eq!(
            found["result"]["blockhash"],
            hex::encode(confirmed.block_id())
        );
        assert_eq!(found["result"]["hex"], raw);
        assert_eq!(
            query(
                "getrawtransaction",
                json!([txid, false, hex::encode(confirmed.block_id())])
            )["result"],
            raw
        );
        let coinbase = query(
            "gettransaction",
            json!([hex::encode(first.coinbase_outpoint_id())]),
        );
        assert_eq!(coinbase["result"]["coinbase"], true);
        assert_eq!(coinbase["result"]["confirmations"], 101);
        assert!(coinbase["result"]["hex"].is_null());
        assert_eq!(
            query("gettransaction", json!(["00".repeat(32)]))["error"]["data"]["code"],
            "transaction_not_found"
        );
        for params in [
            json!([]),
            json!(["bad"]),
            json!([txid, "yes"]),
            json!([txid, 2]),
        ] {
            assert_eq!(query("getrawtransaction", params)["error"]["code"], -32602);
        }
        assert_eq!(query("getbalance", json!([]))["error"]["code"], -32602);
        assert_eq!(
            query("getbalance", json!(["ff".repeat(32)]))["error"]["code"],
            -32602
        );
        drop(index);
        drop(shared);
        let node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));
        let restarted = shared_call(
            json!({"jsonrpc":"2.0","id":1,"method":"gettransaction","params":[txid]}),
            &shared,
            &index,
        );
        assert_eq!(
            restarted["result"]["blockhash"],
            found["result"]["blockhash"]
        );
        assert_eq!(restarted["result"]["hex"], raw);
        Arc::make_mut(
            shared
                .lock()
                .unwrap()
                .index
                .blocks
                .get_mut(&confirmed.block_id())
                .unwrap(),
        )
        .locator
        .complete_digest[0] ^= 1;
        let corrupt = shared_call(
            json!({"jsonrpc":"2.0","id":2,"method":"gettransaction","params":[txid]}),
            &shared,
            &index,
        );
        assert_eq!(corrupt["error"]["data"]["code"], "corrupt_block_log");
        assert!(shared.lock().unwrap().storage_faulted);
        drop(index);
        drop(shared);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn transaction_lookup_removes_reorganized_coinbase_and_supports_explicit_side_block() {
        let directory = test_directory("query-reorg");
        let fork_directory = test_directory("query-reorg-fork");
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let old = node
            .mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        let shared = Arc::new(Mutex::new(node));
        let index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));
        let old_id = hex::encode(old.coinbase_outpoint_id());
        let steward = hex::encode(DEVNET_PROFILE.rewards.steward);
        let old_utxos = shared_call(
            json!({"jsonrpc":"2.0","id":"utxos-before","method":"getaddressutxos","params":[steward]}),
            &shared,
            &index,
        );
        assert_eq!(old_utxos["result"]["total_utxos"], 1);
        assert_eq!(old_utxos["result"]["utxos"][0]["txid"], old_id);
        assert_eq!(
            shared_call(
                json!({"jsonrpc":"2.0","id":1,"method":"gettransaction","params":[old_id]}),
                &shared,
                &index
            )["result"]["confirmations"],
            1
        );
        let mut fork = Node::open_with_profile(&fork_directory, DEVNET_PROFILE).unwrap();
        let fork_destination = fork.wallet_destination();
        for height in 1..=3 {
            let block = fork
                .mine_once(
                    fork_destination,
                    DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            shared
                .lock()
                .unwrap()
                .submit_block(
                    block,
                    DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                )
                .unwrap();
        }
        let removed = shared_call(
            json!({"jsonrpc":"2.0","id":2,"method":"gettransaction","params":[old_id]}),
            &shared,
            &index,
        );
        assert_eq!(removed["error"]["data"]["code"], "transaction_not_found");
        let side = shared_call(
            json!({"jsonrpc":"2.0","id":3,"method":"gettransaction","params":[old_id,hex::encode(old.block_id())]}),
            &shared,
            &index,
        );
        assert_eq!(side["result"]["confirmations"], -1);
        assert_eq!(side["result"]["active"], false);
        assert_eq!(side["result"]["status"], "inactive");
        let replacement_utxos = shared_call(
            json!({"jsonrpc":"2.0","id":"utxos-after","method":"getaddressutxos","params":[steward]}),
            &shared,
            &index,
        );
        assert_eq!(replacement_utxos["result"]["total_utxos"], 3);
        assert!(
            !replacement_utxos["result"]["utxos"]
                .as_array()
                .unwrap()
                .iter()
                .any(|output| output["txid"] == old_id)
        );
        assert_eq!(
            shared_call(
                json!({"jsonrpc":"2.0","id":4,"method":"getbalance","params":[hex::encode(destination)]}),
                &shared,
                &index
            )["result"]["balance_atoms"],
            "0"
        );
        drop(index);
        drop(shared);
        drop(fork);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(fork_directory).unwrap();
    }

    #[test]
    fn address_utxos_builds_a_signed_spend_and_pages_consistently() {
        use cmfd_consensus::{OutPoint, TRANSACTION_VERSION, TxInput};
        let directory = test_directory("address-utxos");
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let address = hex::encode(destination);
        for height in 1..=103 {
            node.mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
        let query = |node: &mut Node, params: Value| {
            call(
                json!({
                    "jsonrpc":"2.0","id":1,"method":"getaddressutxos","params":params
                }),
                node,
            )
        };
        let all = query(&mut node, json!([address]));
        assert_eq!(all["result"]["total_utxos"], 4);
        assert_eq!(all["result"]["returned_utxos"], 4);
        assert_eq!(all["result"]["has_more"], false);
        assert!(all["result"]["next_cursor"].is_null());
        let balance = call(
            json!({"jsonrpc":"2.0","id":2,"method":"getbalance","params":[address]}),
            &mut node,
        );
        assert_eq!(
            all["result"]["available_atoms"],
            balance["result"]["available_atoms"]
        );
        let page_one = query(&mut node, json!([address, 1]));
        let mut pages = page_one["result"]["utxos"].as_array().unwrap().clone();
        let mut cursor = page_one["result"]["next_cursor"].clone();
        while !cursor.is_null() {
            let page = query(&mut node, json!([address, 1, cursor]));
            assert_eq!(page["result"]["snapshot"], all["result"]["snapshot"]);
            assert_eq!(page["result"]["total_utxos"], 4);
            pages.extend(page["result"]["utxos"].as_array().unwrap().clone());
            cursor = page["result"]["next_cursor"].clone();
        }
        assert_eq!(pages, *all["result"]["utxos"].as_array().unwrap());

        // Construct and sign using only RPC output fields and the sender's key.
        let selected = &pages[0];
        let previous = OutPoint {
            txid: hex::decode(selected["txid"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            index: selected["vout"].as_u64().unwrap() as u32,
        };
        let value = selected["value_atoms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let mut transaction = Transaction {
            network_id: DEVNET_PROFILE.network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous,
                witness: InputWitness::Key {
                    public_key: [0; 32],
                    signature: Vec::new(),
                },
            }],
            outputs: vec![TxOutput {
                value: value - 1,
                lock: OutputLock::Key(destination),
                spendable_height: 104,
            }],
        };
        transaction.sign_all(&[&node.wallet_signing_key]).unwrap();
        let txid = hex::encode(transaction.txid());
        let raw = hex::encode(encode_transaction(&transaction).unwrap());
        assert_eq!(
            call(
                json!({"jsonrpc":"2.0","id":3,"method":"sendrawtransaction","params":[raw]}),
                &mut node
            )["result"],
            txid
        );
        let pending = query(&mut node, json!([address]));
        assert_eq!(pending["result"]["total_utxos"], 3);
        assert!(
            !pending["result"]["utxos"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["txid"] == selected["txid"] && item["vout"] == selected["vout"])
        );
        assert!(
            !pending["result"]["utxos"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["txid"] == txid)
        );
        assert_eq!(
            query(
                &mut node,
                json!([address, 1, page_one["result"]["next_cursor"]])
            )["error"]["data"]["code"],
            "utxo_snapshot_changed"
        );

        let first_remaining = &pending["result"]["utxos"][0];
        let reserved = OutPoint {
            txid: hex::decode(first_remaining["txid"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            index: first_remaining["vout"].as_u64().unwrap() as u32,
        };
        let before_reservation = query(&mut node, json!([address, 1]));
        node.exchange_withdrawal_reservations
            .insert(reserved, [0x42; 32]);
        assert_eq!(
            query(&mut node, json!([address]))["result"]["total_utxos"],
            2
        );
        assert_eq!(
            query(
                &mut node,
                json!([address, 1, before_reservation["result"]["next_cursor"]])
            )["error"]["data"]["code"],
            "utxo_snapshot_changed"
        );
        node.exchange_withdrawal_reservations.remove(&reserved);

        let mut invalid_cursor = before_reservation["result"]["next_cursor"].clone();
        invalid_cursor["txid"] = json!("00".repeat(32));
        assert_eq!(
            query(&mut node, json!([address, 1, invalid_cursor]))["error"]["code"],
            -32602
        );
        for params in [
            json!([]),
            json!(["bad"]),
            json!(["ff".repeat(32)]),
            json!([address, 0]),
            json!([address, 1001]),
            json!([address, -1]),
            json!([address, 1.5]),
            json!([address, 1, {}]),
            json!([address,1,{"snapshot":"00".repeat(32),"txid":"00".repeat(32),"vout":-1}]),
        ] {
            assert_eq!(query(&mut node, params)["error"]["code"], -32602);
        }
        let other = k256::schnorr::SigningKey::from_bytes(&[77; 32]).unwrap();
        let empty = query(
            &mut node,
            json!([hex::encode(other.verifying_key().to_bytes())]),
        );
        assert_eq!(empty["result"]["utxos"], json!([]));
        assert_eq!(empty["result"]["available_atoms"], "0");
        let mined = node
            .mine_once(
                destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + 104 * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        assert_eq!(mined.transactions.len(), 1);
        let confirmed = query(&mut node, json!([address]));
        assert!(
            confirmed["result"]["utxos"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["txid"] == txid)
        );
        assert!(
            !confirmed["result"]["utxos"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["txid"] == selected["txid"] && item["vout"] == selected["vout"])
        );
        assert_eq!(
            query(
                &mut node,
                json!([address, 1, before_reservation["result"]["next_cursor"]])
            )["error"]["data"]["code"],
            "utxo_snapshot_changed"
        );
        drop(node);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        assert_eq!(
            query(&mut node, json!([address]))["result"],
            confirmed["result"]
        );
        node.storage_faulted = true;
        assert_eq!(
            query(&mut node, json!([address]))["error"]["data"]["code"],
            "storage_faulted"
        );
        drop(node);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recent_reachable_peer_can_establish_sync_without_an_active_socket() {
        let directory = test_directory("reachable-sync");
        let _ = fs::remove_dir_all(&directory);
        let mut node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let now = unix_time_seconds().unwrap();
        let address = "127.0.0.1:18444".to_owned();
        node.record_peer_started(PeerDirection::Outbound, address.clone(), now);
        node.record_peer_succeeded(
            PeerDirection::Outbound,
            address.clone(),
            0,
            DEVNET_PROFILE.virtual_genesis_hash,
            now,
        );
        node.record_peer_ended(PeerDirection::Outbound, address, false, now);

        let info = blockchain_info(&node).unwrap();
        assert_eq!(info["connections"], 0);
        assert_eq!(info["recent_reachable_peers"], 1);
        assert_eq!(info["peer_observation_caught_up"], true);
        assert_eq!(info["peer_observation_tip_match"], true);
        assert_eq!(info["initialblockdownload"], true);
        assert_eq!(info["verificationprogress"], 1.0);
        assert_eq!(info["pruned"], false);
        assert!(info.get("pruneheight").is_none());

        drop(node);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn authentication_file_is_bounded_and_password_is_not_optional() {
        let directory = test_directory("auth-file");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("exchange-rpc.auth");
        write_authentication_file(&path);
        let expected = expected_authorization_token(&path).unwrap();
        let raw = b"exchange:test-password-0123456789";
        assert_eq!(expected.as_slice(), BASE64_STANDARD.encode(raw).as_bytes());

        fs::write(&path, b"exchange:short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            expected_authorization_token(&path),
            Err(NodeError::InvalidExchangeRpcAuthFile(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn v3_authentication_rejects_a_service_owned_or_replaceable_secret() {
        let root = test_directory("v3-auth-independent-control");
        let _ = fs::remove_dir_all(&root);
        let data = root.join("node");
        let controls = root.join("controls");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&controls).unwrap();
        let authentication = controls.join("exchange-rpc.auth");
        write_authentication_file(&authentication);

        assert!(matches!(
            expected_authorization_token_v3(&data, &authentication),
            Err(NodeError::InvalidExchangeRpcAuthFile(
                "v3 credential failed external-secret path or permission validation"
            ))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn integration_and_withdrawal_credentials_have_distinct_scopes() {
        let integration = Zeroizing::new(
            BASE64_STANDARD
                .encode(b"exchange:test-password-0123456789")
                .into_bytes(),
        );
        let withdrawal = Zeroizing::new(
            BASE64_STANDARD
                .encode(b"withdrawal:another-password-0123456789")
                .into_bytes(),
        );
        let expected = ExchangeAuthorization {
            integration,
            withdrawal: Some(withdrawal),
        };
        let integration_header = format!(
            "Basic {}",
            BASE64_STANDARD.encode(b"exchange:test-password-0123456789")
        );
        let withdrawal_header = format!(
            "Basic {}",
            BASE64_STANDARD.encode(b"withdrawal:another-password-0123456789")
        );
        assert_eq!(
            authorization_scope(Some(&integration_header), &expected),
            Some(AuthorizationScope::Integration)
        );
        assert_eq!(
            authorization_scope(Some(&withdrawal_header), &expected),
            Some(AuthorizationScope::Withdrawal)
        );
        assert_eq!(
            authorization_scope(Some("Basic bm90OmF1dGhvcml6ZWQtcGFzc3dvcmQ="), &expected),
            None
        );
    }

    #[test]
    fn withdrawal_scope_classifies_the_complete_v04_contract() {
        for method in [
            "preparewithdrawal",
            "releasewithdrawal",
            "getwithdrawal",
            "getwithdrawaljournalinfo",
        ] {
            assert!(is_withdrawal_method(method), "{method}");
            assert!(is_withdrawal_method_v2(method), "{method}");
        }
        assert!(!is_withdrawal_method("sendwithdrawal"));
        assert!(!is_withdrawal_method("getblockcount"));
        assert!(!is_withdrawal_method_v2("cancelwithdrawal"));
        assert!(!is_withdrawal_method_v2("getwithdrawalapprovalpayload"));
        assert!(!is_withdrawal_method_v2("getwithdrawalsigningpackage"));
    }

    #[test]
    fn withdrawal_scope_classifies_v3_without_compaction_authority() {
        for method in [
            "preparewithdrawal",
            "getwithdrawalsigningpackage",
            "getwithdrawalapprovalpayload",
            "releasewithdrawal",
            "cancelwithdrawal",
            "getwithdrawal",
            "getwithdrawaljournalinfo",
        ] {
            assert!(is_withdrawal_method(method), "{method}");
        }
        for method in [
            "compactwithdrawals",
            "archivewithdrawals",
            "restorewithdrawals",
            "getblockcount",
        ] {
            assert!(!is_withdrawal_method(method), "{method}");
        }
    }

    #[test]
    fn v3_signed_approval_parameter_requires_a_json_object() {
        assert!(signed_approval_document(&json!({"schema": "example"})).is_ok());
        let error = signed_approval_document(&json!("not-an-object")).unwrap_err();
        assert_eq!(error.code, -32602);
        assert_eq!(error.data_code, "invalid_params");
    }

    #[test]
    fn integration_scope_cannot_probe_any_v3_withdrawal_method() {
        let directory = test_directory("v3-method-scope");
        let _ = fs::remove_dir_all(&directory);
        let node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let exchange_index = Arc::new(Mutex::new(
            ExchangeDepositIndex::open_and_sync(&shared).unwrap(),
        ));

        for method in [
            "preparewithdrawal",
            "getwithdrawalsigningpackage",
            "getwithdrawalapprovalpayload",
            "releasewithdrawal",
            "cancelwithdrawal",
            "getwithdrawal",
            "getwithdrawaljournalinfo",
        ] {
            let request = parse_json_rpc(
                &serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "id": method,
                    "method": method,
                    "params": [],
                }))
                .unwrap(),
            )
            .unwrap();
            let response = dispatch_shared_request_scoped(
                request,
                &shared,
                &exchange_index,
                None,
                DEVNET_PROFILE.network_id,
                AuthorizationScope::Integration,
            );
            assert_eq!(
                response["error"]["data"]["code"], "withdrawal_authorization_required",
                "{method}"
            );
        }
        drop(exchange_index);
        drop(shared);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn v2_withdrawal_scope_rejects_v3_only_methods_stably() {
        let directory = test_directory("v2-rejects-v3-methods");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let (node, security_directory, _security) = secured_withdrawal_node(&directory);
        let shared = Arc::new(Mutex::new(node));
        let journal = Arc::new(Mutex::new(
            ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap(),
        ));
        let backend = SharedWithdrawalBackend::V2(journal);

        for method in [
            "getwithdrawalsigningpackage",
            "getwithdrawalapprovalpayload",
            "cancelwithdrawal",
        ] {
            let error = route_withdrawal_backend(method, &[], &shared, &backend).unwrap_err();
            assert_eq!(error.code, -32011, "{method}");
            assert_eq!(error.data_code, "withdrawal_method_requires_v3", "{method}");
            assert!(!error.retryable, "{method}");
        }
        drop(backend);
        drop(shared);
        let _ = fs::remove_dir_all(security_directory);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn v3_authorization_rejects_a_shared_integration_and_withdrawal_credential() {
        let credential = authorization_token_from_credential(Zeroizing::new(
            b"exchange:test-password-0123456789".to_vec(),
        ))
        .unwrap();
        let result = distinct_exchange_authorization(credential.clone(), credential);
        assert!(matches!(
            result,
            Err(NodeError::InvalidExchangeRpcAuthFile(
                "withdrawal credential must differ from the integration credential"
            ))
        ));
    }

    #[test]
    fn v3_anchor_failures_are_operator_distinguishable() {
        use crate::exchange_custody_v3::ExchangeCustodyV3Error;

        let ahead =
            ExchangeCustodyRuntimeV3Error::Store(ExchangeCustodyV3Error::ExternalAnchorAhead);
        let diverged =
            ExchangeCustodyRuntimeV3Error::Store(ExchangeCustodyV3Error::ExternalAnchorMismatch);
        let behind =
            ExchangeCustodyRuntimeV3Error::Store(ExchangeCustodyV3Error::ExternalAnchorNotCurrent);

        assert!(exchange_custody_v3_client_message(&ahead).contains("ahead"));
        assert!(exchange_custody_v3_client_message(&diverged).contains("diverges"));
        assert!(exchange_custody_v3_client_message(&behind).contains("behind"));
    }

    #[test]
    fn v3_status_documents_never_expose_exact_signing_package_bytes() {
        let anchor = crate::exchange_withdrawal_v3::JournalAnchorV3 {
            key_id: [0x11; 32],
            journal_instance_id: [0x12; 32],
            generation: 7,
            commitment: [0x13; 32],
        };
        let view = RuntimeWithdrawalViewV3 {
            current_anchor: anchor,
            phase: RuntimeWithdrawalPhaseV3::Prepared,
            status: RuntimeWithdrawalStatusV3::Prepared,
            request_id: "package-gate-1".to_owned(),
            request_digest: [0x14; 32],
            destination: [0x15; 32],
            amount_atoms: 5,
            fee_atoms: 1,
            change_atoms: 4,
            signing_digest: [0x16; 32],
            signer_package_digest: Some([0x17; 32]),
            signer_package_bytes: Some(vec![0x18; 64]),
            prepared_anchor: Some(anchor),
            reserved_inputs: Vec::new(),
            decision_id: None,
            approval_digest: None,
            action_anchor: None,
            authorized_at_unix_seconds: Some(100),
            accounted_at_unix_seconds: Some(150),
            txid: None,
            transaction_bytes: None,
            confirmations: None,
        };

        let document = withdrawal_document_v3(&view);
        assert!(document.get("signer_package_base64").is_none());
        assert_eq!(
            document["signer_package_bytes_digest"],
            hex::encode([0x17; 32])
        );
        assert_eq!(document["authorized_at_unix_seconds"], "100");
        assert_eq!(document["accounted_at_unix_seconds"], "150");
    }

    #[test]
    fn v3_journal_info_capacity_warning_is_a_consistent_boolean() {
        let anchor = crate::exchange_withdrawal_v3::JournalAnchorV3 {
            key_id: [0x31; 32],
            journal_instance_id: [0x32; 32],
            generation: 7,
            commitment: [0x33; 32],
        };
        let info = RuntimeJournalInfoV3 {
            current_anchor: anchor,
            external_anchor: anchor,
            relationship: crate::exchange_custody_v3::ExternalAnchorRelationshipV3::Current,
            policy_id: [0x34; 32],
            active_keyring: crate::exchange_withdrawal_v3::KeyringAnchorV3 {
                instance_id: [0x35; 32],
                generation: 2,
                commitment: [0x36; 32],
            },
            policy_time_watermark_unix_seconds: 100,
            policy_release_event_count: 1,
            live_record_count: 2,
            live_record_limit: 100_000,
            tombstone_count: 3,
            tombstone_limit: 100_000,
            commitment_count: 4,
            commitment_limit: 1_000_000,
            estimated_full_release_capacity_remaining: 1_024,
            capacity_warning: false,
            redundancy_degraded: false,
            faulted: false,
        };
        let document = withdrawal_journal_info_document_v3(&info);
        assert_eq!(document["capacity"]["warning"], false);
        assert_eq!(
            document["capacity"]["estimated_full_release_capacity_remaining"],
            "1024"
        );

        let warning = withdrawal_journal_info_document_v3(&RuntimeJournalInfoV3 {
            estimated_full_release_capacity_remaining: 1_023,
            capacity_warning: true,
            ..info
        });
        assert_eq!(warning["capacity"]["warning"], true);
    }

    #[test]
    fn external_signer_response_parameter_requires_exact_canonical_frames() {
        use k256::schnorr::{Signature, SigningKey, signature::Signer};

        use crate::wallet_signing_protocol::{InputSignatureV1, SignerId, WalletKeyId};

        let key = SigningKey::from_bytes(&[0x21; 32]).unwrap();
        let signature: Signature = key.sign(&[0x22; 32]);
        let response = SignerResponseV1 {
            package_digest: [0x23; 32],
            release_authorization_digest: [0x27; 32],
            signer_id: SignerId([0x24; 32]),
            capability_digest: [0x25; 32],
            signatures: vec![InputSignatureV1 {
                input_index: 0,
                key_id: WalletKeyId([0x26; 32]),
                transaction_signature: signature.to_bytes(),
                package_authorization_signature: signature.to_bytes(),
            }],
        }
        .encode()
        .unwrap();
        let encoded = BASE64_STANDARD.encode(&response);
        assert_eq!(
            external_signer_response_bytes(&json!([encoded.clone()])).unwrap(),
            vec![response]
        );
        assert!(external_signer_response_bytes(&json!(encoded)).is_err());
        assert!(external_signer_response_bytes(&json!(["not base64!"])).is_err());
        assert!(
            external_signer_response_bytes(&Value::Array(vec![
                Value::String(String::new());
                cmfd_consensus::MAX_TRANSACTION_INPUTS
                    + 1
            ]))
            .is_err()
        );
    }

    #[test]
    fn listener_enforces_withdrawal_method_scope() {
        let directory = test_directory("withdrawal-auth-scope");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let integration_path = directory.join("exchange-rpc.auth");
        let withdrawal_path = directory.join("exchange-withdrawal.auth");
        write_authentication_file(&integration_path);
        write_withdrawal_authentication_file(&withdrawal_path);
        let (node, security_directory, _security) = secured_withdrawal_node(&directory);
        let destination = hex::encode(node.wallet_destination());
        let shared = Arc::new(Mutex::new(node));
        let server = spawn_exchange_rpc_server(
            Arc::clone(&shared),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &integration_path,
            Some(&withdrawal_path),
        )
        .unwrap();
        let integration_credential = format!(
            "Basic {}",
            BASE64_STANDARD.encode(b"exchange:test-password-0123456789")
        );
        let withdrawal_credential = format!(
            "Basic {}",
            BASE64_STANDARD.encode(b"withdrawal:another-password-0123456789")
        );

        let chain_body = r#"{"jsonrpc":"2.0","id":"chain","method":"getblockcount","params":[]}"#;
        let withdrawal_on_chain = send_http(
            server.local_addr(),
            Some(&withdrawal_credential),
            chain_body,
        );
        let response: Value =
            serde_json::from_str(withdrawal_on_chain.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(response["error"]["data"]["code"], "withdrawal_scope_only");

        let withdrawal_body = serde_json::to_string(&json!({
            "jsonrpc":"2.0",
            "id":"withdrawal",
            "method":"preparewithdrawal",
            "params":["scope-test", destination, "1", "1"]
        }))
        .unwrap();
        let integration_on_withdrawal = send_http(
            server.local_addr(),
            Some(&integration_credential),
            &withdrawal_body,
        );
        let response: Value =
            serde_json::from_str(integration_on_withdrawal.split("\r\n\r\n").nth(1).unwrap())
                .unwrap();
        assert_eq!(
            response["error"]["data"]["code"],
            "withdrawal_authorization_required"
        );
        assert!(matches!(
            spawn_exchange_rpc_server(
                Arc::clone(&shared),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                &integration_path,
                Some(&integration_path),
            ),
            Err(NodeError::InvalidExchangeRpcAuthFile(_))
        ));
        assert!(matches!(
            spawn_exchange_rpc_server(
                Arc::clone(&shared),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                &integration_path,
                None,
            ),
            Err(NodeError::ExchangeRpcAlreadyActive)
        ));

        server.stop().unwrap();
        let replacement = spawn_exchange_rpc_server(
            Arc::clone(&shared),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &integration_path,
            None,
        )
        .unwrap();
        replacement.stop().unwrap();
        drop(shared);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(security_directory).unwrap();
    }

    #[test]
    fn worker_panic_cleanup_joins_every_remaining_request() {
        let panicked = std::thread::spawn(|| panic!("expected exchange worker test panic"));
        while !panicked.is_finished() {
            std::thread::yield_now();
        }
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (completed_sender, completed_receiver) = std::sync::mpsc::channel();
        let blocked = std::thread::spawn(move || {
            started_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            completed_sender.send(()).unwrap();
        });
        started_receiver.recv().unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            release_sender.send(()).unwrap();
        });

        let mut workers = vec![panicked, blocked];
        assert!(reap_exchange_workers(&mut workers).is_err());
        assert!(workers.is_empty());
        completed_receiver.try_recv().unwrap();
        releaser.join().unwrap();
    }

    #[test]
    fn listener_rejects_missing_auth_before_serving_json_rpc() {
        let directory = test_directory("listener");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let auth_path = directory.join("exchange-rpc.auth");
        write_authentication_file(&auth_path);
        let node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let server = spawn_exchange_rpc_server(
            Arc::clone(&shared),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &auth_path,
            None,
        )
        .unwrap();

        let body = r#"{"jsonrpc":"2.0","id":"auth","method":"getblockcount","params":[]}"#;
        let unauthorized = send_http(server.local_addr(), None, body);
        assert!(unauthorized.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(unauthorized.contains("WWW-Authenticate: Basic"));
        let unauthorized_expect = send_headers_without_body(server.local_addr(), true, body.len());
        assert!(unauthorized_expect.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(!unauthorized_expect.starts_with("HTTP/1.1 100 Continue\r\n"));

        let credential = format!(
            "Basic {}",
            BASE64_STANDARD.encode(b"exchange:test-password-0123456789")
        );
        let authorized = send_http(server.local_addr(), Some(&credential), body);
        assert!(authorized.starts_with("HTTP/1.1 200 OK\r\n"));
        let response: Value =
            serde_json::from_str(authorized.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(response["id"], "auth");
        assert_eq!(response["result"], 0);

        let continued = send_http_with_continue(server.local_addr(), &credential, body);
        assert!(continued.starts_with("HTTP/1.1 200 OK\r\n"));
        let response: Value =
            serde_json::from_str(continued.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(response["id"], "auth");
        assert_eq!(response["result"], 0);

        server.stop().unwrap();
        drop(shared);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn listener_bounds_concurrent_slow_requests() {
        let directory = test_directory("listener-capacity");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let auth_path = directory.join("exchange-rpc.auth");
        write_authentication_file(&auth_path);
        let node = Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let server = spawn_exchange_rpc_server(
            Arc::clone(&shared),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &auth_path,
            None,
        )
        .unwrap();

        let mut stalled = Vec::new();
        for _ in 0..MAXIMUM_CONCURRENT_REQUESTS {
            let mut stream = TcpStream::connect(server.local_addr()).unwrap();
            stream.write_all(b"POST / HTTP/1.1\r\n").unwrap();
            stream.flush().unwrap();
            stalled.push(stream);
        }
        let body = r#"{"jsonrpc":"2.0","id":"capacity","method":"getblockcount","params":[]}"#;
        let saturated = send_http(server.local_addr(), None, body);
        assert!(saturated.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));

        drop(stalled);
        server.stop().unwrap();
        drop(shared);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn non_loopback_bind_is_refused_before_authentication_file_access() {
        let directory = test_directory("non-loopback");
        let shared = Arc::new(Mutex::new(
            Node::open_with_profile(&directory, DEVNET_PROFILE).unwrap(),
        ));
        assert!(matches!(
            spawn_exchange_rpc_server(
                Arc::clone(&shared),
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                Path::new("missing-auth-file"),
                None,
            ),
            Err(NodeError::NonLoopbackRpc(_))
        ));
        drop(shared);
        fs::remove_dir_all(directory).unwrap();
    }

    fn send_http(address: SocketAddr, authorization: Option<&str>, body: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        let authorization = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        match stream.read_to_string(&mut response) {
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() => {}
            Err(error) => panic!("failed to read HTTP response: {error}"),
        }
        response
    }

    fn send_http_with_continue(address: SocketAddr, authorization: &str, body: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
        let interim = read_http_head(&mut stream);
        assert_eq!(interim, "HTTP/1.1 100 Continue\r\n\r\n");
        stream.write_all(body.as_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn send_headers_without_body(address: SocketAddr, expect: bool, body_length: usize) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let expect = if expect {
            "Expect: 100-continue\r\n"
        } else {
            ""
        };
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: localhost\r\n{expect}Content-Type: application/json\r\nContent-Length: {body_length}\r\n\r\n",
        )
        .unwrap();
        stream.flush().unwrap();
        read_http_head(&mut stream)
    }

    fn read_http_head(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 4096);
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
        }
        String::from_utf8(bytes).unwrap()
    }
}
