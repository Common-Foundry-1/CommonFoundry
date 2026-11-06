//! Strict client for the public service used by `wallet.commonfoundry.ai`.
//!
//! Routes were extracted from the production bundle served on 2026-10-22 and
//! verified with read-only requests. No endpoint is guessed. This client does
//! not retry broadcasts: an ambiguous response must be reconciled by txid.

#![forbid(unsafe_code)]

mod independent;
pub use independent::{IndependentUtxo, IndependentUtxoClient};

use std::time::Duration;

use cmfd_wallet_core::network::MAINNET_NETWORK_ID;
use reqwest::{StatusCode, Url, redirect};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

pub const API_BASE_URL: &str = "https://wallet.commonfoundry.ai/";
pub const EXPLORER_ROUTE: &str = "v1/explorer";
pub const ADDRESS_ROUTE_PREFIX: &str = "v1/explorer/address/";
pub const TRANSACTION_ROUTE_PREFIX: &str = "v1/explorer/transaction/";
pub const UTXO_ROUTE: &str = "v1/wallet/utxos";
pub const TRANSACTION_OUTPUTS_ROUTE: &str = "v1/wallet/transaction";
pub const BROADCAST_ROUTE: &str = "v1/wallet/broadcast";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;
const MAX_SUCCESS_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 1024;

#[derive(Debug, Clone)]
pub struct ApiClient {
    base: Url,
    http: reqwest::Client,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("wallet service configuration is invalid")]
    InvalidConfiguration,
    #[error("wallet service is unreachable")]
    Unreachable,
    #[error("wallet service request timed out")]
    Timeout,
    #[error("wallet service returned HTTP {status}: {code}")]
    Http {
        status: u16,
        code: String,
        message: String,
        retryable: bool,
    },
    #[error("wallet service response is malformed")]
    MalformedResponse,
    #[error("wallet service answered for another network")]
    WrongNetwork,
    #[error("wallet service redirected outside its pinned origin")]
    RedirectRefused,
}

impl ApiError {
    pub fn retryable(&self) -> bool {
        match self {
            Self::Unreachable | Self::Timeout => true,
            Self::Http { retryable, .. } => *retryable,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExplorerSnapshot {
    pub network: String,
    pub network_id: String,
    pub accepted_height: u64,
    pub validated_height: Option<u64>,
    pub tip: String,
    pub mempool_transactions: usize,
    pub mempool_bytes: usize,
    #[serde(default)]
    pub recent_transactions: Vec<RecentTransaction>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RecentTransaction {
    pub txid: String,
    pub status: String,
    pub block_height: Option<u64>,
    pub block_id: Option<String>,
    pub timestamp: Option<u64>,
    pub encoded_bytes: usize,
    pub inputs: usize,
    pub outputs: usize,
    pub output_atoms: String,
    pub fee_burned_atoms: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AddressSnapshot {
    pub address: String,
    pub accepted_height: u64,
    pub validated_height: Option<u64>,
    pub tip: String,
    pub balance_scope: String,
    pub confirmed_atoms: String,
    pub spendable_atoms: String,
    pub immature_atoms: String,
    pub includes_mempool: bool,
    pub utxo_count: usize,
    pub page_limit: usize,
    pub has_more: bool,
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub history: Vec<AddressHistoryEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AddressHistoryEntry {
    pub kind: String,
    pub txid: String,
    pub block_height: u64,
    pub block_id: String,
    pub timestamp: Option<u64>,
    pub confirmations: u64,
    pub received_atoms: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UtxoRequest<'a> {
    pub address: &'a str,
    pub cursor: Option<&'a UtxoCursor>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct UtxoCursor {
    pub snapshot: String,
    pub txid: String,
    pub vout: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UtxoPage {
    pub height: u64,
    pub has_more: bool,
    pub next_cursor: Option<UtxoCursor>,
    #[serde(default)]
    pub utxos: Vec<ApiUtxo>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_atoms: String,
    pub spendable_height: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TransactionOutputsRequest<'a> {
    pub txid: &'a str,
    pub block_id: &'a str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TransactionOutputs {
    #[serde(default)]
    pub vout: Vec<ApiTransactionOutput>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApiTransactionOutput {
    pub value_atoms: String,
    pub destination_hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TransactionStatus {
    pub txid: String,
    pub status: String,
    pub block_height: Option<u64>,
    pub block_id: Option<String>,
    #[serde(default)]
    pub confirmations: u64,
    #[serde(default)]
    pub validated_height: Option<u64>,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BroadcastRequest<'a> {
    pub transaction_hex: &'a str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BroadcastResponse {
    pub txid: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: Option<String>,
    message: Option<String>,
}

impl ApiClient {
    pub fn new() -> Result<Self, ApiError> {
        let base = Url::parse(API_BASE_URL).map_err(|_| ApiError::InvalidConfiguration)?;
        if base.scheme() != "https" || base.host_str() != Some("wallet.commonfoundry.ai") {
            return Err(ApiError::InvalidConfiguration);
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .user_agent("common-foundry-android-wallet/0.1")
            .build()
            .map_err(|_| ApiError::InvalidConfiguration)?;
        Ok(Self { base, http })
    }

    pub async fn explorer(&self) -> Result<ExplorerSnapshot, ApiError> {
        let snapshot: ExplorerSnapshot = self.get(EXPLORER_ROUTE).await?;
        validate_explorer(&snapshot)?;
        Ok(snapshot)
    }

    pub async fn address(&self, destination_hex: &str) -> Result<AddressSnapshot, ApiError> {
        validate_hex32(destination_hex)?;
        let snapshot: AddressSnapshot = self
            .get(&format!("{ADDRESS_ROUTE_PREFIX}{destination_hex}"))
            .await?;
        validate_address(&snapshot, destination_hex)?;
        Ok(snapshot)
    }

    pub async fn transaction(&self, txid: &str) -> Result<Option<TransactionStatus>, ApiError> {
        validate_hex32(txid)?;
        let url = self.url(&format!("{TRANSACTION_ROUTE_PREFIX}{txid}"))?;
        let response = self.send(self.http.get(url)).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let transaction: TransactionStatus = self.decode(response).await?;
        let transaction = normalize_transaction_status(transaction)?;
        validate_transaction_status(&transaction, txid)?;
        Ok(Some(transaction))
    }

    pub async fn utxos(
        &self,
        destination_hex: &str,
        cursor: Option<&UtxoCursor>,
    ) -> Result<UtxoPage, ApiError> {
        validate_hex32(destination_hex)?;
        if let Some(cursor) = cursor {
            validate_utxo_cursor(cursor)?;
        }
        let page: UtxoPage = self
            .post(
                UTXO_ROUTE,
                &UtxoRequest {
                    address: destination_hex,
                    cursor,
                },
            )
            .await?;
        validate_utxo_page(&page)?;
        Ok(page)
    }

    pub async fn transaction_outputs(
        &self,
        txid: &str,
        block_id: &str,
    ) -> Result<TransactionOutputs, ApiError> {
        validate_hex32(txid)?;
        validate_hex32(block_id)?;
        let outputs: TransactionOutputs = self
            .post(
                TRANSACTION_OUTPUTS_ROUTE,
                &TransactionOutputsRequest { txid, block_id },
            )
            .await?;
        for output in &outputs.vout {
            parse_atoms(&output.value_atoms)?;
            if let Some(destination) = &output.destination_hex {
                validate_hex32(destination)?;
            }
        }
        Ok(outputs)
    }

    /// Performs exactly one broadcast attempt. Callers must reconcile `txid`
    /// after any timeout, disconnect or 5xx response before doing anything else.
    pub async fn broadcast(&self, transaction_hex: &str) -> Result<BroadcastResponse, ApiError> {
        if transaction_hex.is_empty()
            || transaction_hex.len() > 2 * 64 * 1024
            || !transaction_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ApiError::MalformedResponse);
        }
        let result: BroadcastResponse = self
            .post(BROADCAST_ROUTE, &BroadcastRequest { transaction_hex })
            .await?;
        validate_hex32(&result.txid)?;
        Ok(result)
    }

    async fn get<T: DeserializeOwned>(&self, route: &str) -> Result<T, ApiError> {
        let response = self.send(self.http.get(self.url(route)?)).await?;
        self.decode(response).await
    }

    async fn post<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        route: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let response = self
            .send(self.http.post(self.url(route)?).json(body))
            .await?;
        self.decode(response).await
    }

    fn url(&self, route: &str) -> Result<Url, ApiError> {
        let url = self
            .base
            .join(route)
            .map_err(|_| ApiError::InvalidConfiguration)?;
        if url.scheme() != self.base.scheme()
            || url.host_str() != self.base.host_str()
            || url.port_or_known_default() != self.base.port_or_known_default()
        {
            return Err(ApiError::InvalidConfiguration);
        }
        Ok(url)
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response, ApiError> {
        let response = request.send().await.map_err(|error| {
            if error.is_timeout() {
                ApiError::Timeout
            } else if error.is_redirect() {
                ApiError::RedirectRefused
            } else {
                ApiError::Unreachable
            }
        })?;
        if response.status().is_redirection() {
            return Err(ApiError::RedirectRefused);
        }
        Ok(response)
    }

    async fn decode<T: DeserializeOwned>(
        &self,
        mut response: reqwest::Response,
    ) -> Result<T, ApiError> {
        let status = response.status();
        let limit = if status.is_success() {
            MAX_SUCCESS_BODY_BYTES
        } else {
            MAX_ERROR_BODY_BYTES
        };
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(body_too_large(status));
        }
        let mut bytes =
            Vec::with_capacity(response.content_length().unwrap_or(0).min(limit as u64) as usize);
        while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Unreachable)? {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > limit)
            {
                return Err(body_too_large(status));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let parsed = serde_json::from_slice::<ErrorResponse>(&bytes).ok();
            let code = parsed
                .as_ref()
                .and_then(|body| body.error.clone())
                .unwrap_or_else(|| "request_failed".to_owned());
            let message = parsed
                .and_then(|body| body.message)
                .unwrap_or_else(|| "The wallet service rejected the request.".to_owned());
            let retryable = status == StatusCode::TOO_MANY_REQUESTS
                || status.is_server_error()
                || code == "work_check_pending";
            return Err(ApiError::Http {
                status: status.as_u16(),
                code,
                message,
                retryable,
            });
        }
        serde_json::from_slice(&bytes).map_err(|_| ApiError::MalformedResponse)
    }
}

pub fn validate_explorer(snapshot: &ExplorerSnapshot) -> Result<(), ApiError> {
    if snapshot.network_id != hex_network_id()
        || snapshot.network != "CommonFoundry Mainnet"
        || snapshot.tip.len() != 64
        || snapshot.validated_height.unwrap_or(0) > snapshot.accepted_height
    {
        return Err(ApiError::WrongNetwork);
    }
    validate_hex32(&snapshot.tip)?;
    for transaction in &snapshot.recent_transactions {
        validate_hex32(&transaction.txid)?;
        if transaction.block_height.is_some() != transaction.block_id.is_some() {
            return Err(ApiError::MalformedResponse);
        }
        if let Some(block_id) = &transaction.block_id {
            validate_hex32(block_id)?;
        }
        parse_atoms(&transaction.output_atoms)?;
        if let Some(fee) = &transaction.fee_burned_atoms {
            parse_atoms(fee)?;
        }
    }
    Ok(())
}

pub fn validate_address(
    snapshot: &AddressSnapshot,
    expected_destination_hex: &str,
) -> Result<(), ApiError> {
    if snapshot.address != expected_destination_hex
        || snapshot.balance_scope != "key_outputs"
        || snapshot.validated_height.unwrap_or(0) > snapshot.accepted_height
        || snapshot.has_more != snapshot.next_cursor.is_some()
        || snapshot
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES)
        || snapshot.page_limit == 0
        || snapshot.page_limit > 10_000
        || snapshot.history.len() > snapshot.page_limit
    {
        return Err(ApiError::MalformedResponse);
    }
    validate_hex32(&snapshot.address)?;
    validate_hex32(&snapshot.tip)?;
    parse_atoms(&snapshot.confirmed_atoms)?;
    parse_atoms(&snapshot.spendable_atoms)?;
    parse_atoms(&snapshot.immature_atoms)?;
    for entry in &snapshot.history {
        validate_hex32(&entry.txid)?;
        validate_hex32(&entry.block_id)?;
        parse_atoms(&entry.received_atoms)?;
        if entry.block_height > snapshot.accepted_height {
            return Err(ApiError::MalformedResponse);
        }
    }
    Ok(())
}

pub fn validate_utxo_page(page: &UtxoPage) -> Result<(), ApiError> {
    if page.has_more != page.next_cursor.is_some() {
        return Err(ApiError::MalformedResponse);
    }
    if let Some(cursor) = &page.next_cursor {
        validate_utxo_cursor(cursor)?;
    }
    let mut seen = std::collections::HashSet::new();
    for utxo in &page.utxos {
        validate_hex32(&utxo.txid)?;
        let value = parse_atoms(&utxo.value_atoms)?;
        if value == 0 || !seen.insert((&utxo.txid, utxo.vout)) {
            return Err(ApiError::MalformedResponse);
        }
    }
    Ok(())
}

fn validate_utxo_cursor(cursor: &UtxoCursor) -> Result<(), ApiError> {
    validate_hex32(&cursor.snapshot)?;
    validate_hex32(&cursor.txid)
}

fn validate_hex32(value: &str) -> Result<(), ApiError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ApiError::MalformedResponse)
    }
}

fn parse_atoms(value: &str) -> Result<u64, ApiError> {
    value
        .parse::<u64>()
        .map_err(|_| ApiError::MalformedResponse)
}

fn validate_transaction_status(
    transaction: &TransactionStatus,
    expected_txid: &str,
) -> Result<(), ApiError> {
    validate_hex32(&transaction.txid)?;
    let has_block = transaction.block_height.is_some() && transaction.block_id.is_some();
    let state_is_consistent = match transaction.status.to_ascii_lowercase().as_str() {
        "confirmed" => transaction.confirmations > 0 && has_block,
        "accepted" | "mempool" | "pending" | "conflicted" | "dropped" | "rejected" => {
            transaction.confirmations == 0 && !has_block
        }
        _ => transaction.confirmations == 0 && !has_block,
    };
    let validated_confirmations_are_consistent = match (
        transaction.status.to_ascii_lowercase().as_str(),
        transaction.block_height,
        transaction.validated_height,
    ) {
        ("confirmed", Some(block_height), Some(validated_height)) => {
            validated_height
                .checked_sub(block_height)
                .and_then(|distance| distance.checked_add(1))
                == Some(transaction.confirmations)
        }
        _ => true,
    };
    if transaction.txid != expected_txid
        || transaction.block_height.is_some() != transaction.block_id.is_some()
        || !state_is_consistent
        || !validated_confirmations_are_consistent
    {
        return Err(ApiError::MalformedResponse);
    }
    if let Some(block_id) = &transaction.block_id {
        validate_hex32(block_id)?;
    }
    Ok(())
}

fn normalize_transaction_status(
    mut transaction: TransactionStatus,
) -> Result<TransactionStatus, ApiError> {
    if transaction.status.eq_ignore_ascii_case("confirmed") && transaction.confirmations == 0 {
        let block_height = transaction
            .block_height
            .ok_or(ApiError::MalformedResponse)?;
        let validated_height = transaction
            .validated_height
            .ok_or(ApiError::MalformedResponse)?;
        transaction.confirmations = validated_height
            .checked_sub(block_height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(ApiError::MalformedResponse)?;
    }
    Ok(transaction)
}

fn body_too_large(status: StatusCode) -> ApiError {
    if status.is_success() {
        ApiError::MalformedResponse
    } else {
        ApiError::Http {
            status: status.as_u16(),
            code: "response_too_large".to_owned(),
            message: "The wallet service returned an oversized error response.".to_owned(),
            retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
        }
    }
}

fn hex_network_id() -> String {
    hex::encode(MAINNET_NETWORK_ID)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    const DESTINATION: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn test_client(base: &str, timeout: Duration) -> ApiClient {
        ApiClient {
            base: Url::parse(base).unwrap(),
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(redirect::Policy::none())
                .timeout(timeout)
                .build()
                .unwrap(),
        }
    }

    fn serve_once(response: String, delay: Duration) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8 * 1024];
            let _ = stream.read(&mut request);
            thread::sleep(delay);
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{address}/"), handle)
    }

    fn json_response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn routes_match_the_production_web_wallet_bundle() {
        let client = ApiClient::new().unwrap();
        assert_eq!(
            client.url(EXPLORER_ROUTE).unwrap().as_str(),
            "https://wallet.commonfoundry.ai/v1/explorer"
        );
        assert_eq!(UTXO_ROUTE, "v1/wallet/utxos");
        assert_eq!(TRANSACTION_OUTPUTS_ROUTE, "v1/wallet/transaction");
        assert_eq!(BROADCAST_ROUTE, "v1/wallet/broadcast");
    }

    #[test]
    fn parses_observed_confirmed_output_shape_without_maturity_height() {
        let response = format!(
            r#"{{"vout":[{{"value_atoms":"100000000","destination_hex":"{}"}}]}}"#,
            DESTINATION
        );
        let outputs: TransactionOutputs = serde_json::from_str(&response).unwrap();
        assert_eq!(outputs.vout.len(), 1);
        assert_eq!(outputs.vout[0].value_atoms, "100000000");
        assert_eq!(
            outputs.vout[0].destination_hex.as_deref(),
            Some(DESTINATION)
        );
    }

    #[test]
    fn parses_channel_output_before_wallet_output() {
        let response = format!(
            r#"{{"vout":[{{"value_atoms":"1","destination_hex":null}},{{"value_atoms":"100000000","destination_hex":"{DESTINATION}"}}]}}"#,
        );
        let outputs: TransactionOutputs = serde_json::from_str(&response).unwrap();
        assert_eq!(outputs.vout[0].destination_hex, None);
        assert_eq!(
            outputs.vout[1].destination_hex.as_deref(),
            Some(DESTINATION)
        );
    }

    #[test]
    fn parses_and_validates_the_observed_empty_address_response() {
        let json = format!(
            r#"{{"accepted_height":27059,"address":"{DESTINATION}","balance_scope":"key_outputs","confirmed_atoms":"0","has_more":false,"history":[],"immature_atoms":"0","includes_mempool":false,"next_cursor":null,"page_limit":20,"spendable_atoms":"0","tip":"{}","utxo_count":0,"validated_height":23669}}"#,
            "11".repeat(32)
        );
        let snapshot: AddressSnapshot = serde_json::from_str(&json).unwrap();
        validate_address(&snapshot, DESTINATION).unwrap();
        assert!(!snapshot.includes_mempool);
        assert_eq!(snapshot.page_limit, 20);
    }

    #[test]
    fn rejects_wrong_network_and_malformed_monetary_data() {
        let snapshot = ExplorerSnapshot {
            network: "CommonFoundry Testnet".to_owned(),
            network_id: "00".repeat(32),
            accepted_height: 5,
            validated_height: Some(5),
            tip: "11".repeat(32),
            mempool_transactions: 0,
            mempool_bytes: 0,
            recent_transactions: vec![],
        };
        assert!(matches!(
            validate_explorer(&snapshot),
            Err(ApiError::WrongNetwork)
        ));
        assert_eq!(
            parse_atoms("1.5").unwrap_err().to_string(),
            "wallet service response is malformed"
        );
    }

    #[test]
    fn pagination_and_duplicate_utxos_fail_closed() {
        let mut page = UtxoPage {
            height: 100,
            has_more: true,
            next_cursor: None,
            utxos: vec![],
        };
        assert!(validate_utxo_page(&page).is_err());
        page.next_cursor = Some(UtxoCursor {
            snapshot: "11".repeat(32),
            txid: "22".repeat(32),
            vout: 0,
        });
        assert!(validate_utxo_page(&page).is_ok());
        page.has_more = false;
        page.next_cursor = None;
        page.utxos = vec![
            ApiUtxo {
                txid: "22".repeat(32),
                vout: 0,
                value_atoms: "1".to_owned(),
                spendable_height: 1,
            },
            ApiUtxo {
                txid: "22".repeat(32),
                vout: 0,
                value_atoms: "1".to_owned(),
                spendable_height: 1,
            },
        ];
        assert!(validate_utxo_page(&page).is_err());
    }

    #[test]
    fn inconsistent_history_and_transaction_confirmations_fail_closed() {
        let mut address = AddressSnapshot {
            address: DESTINATION.to_owned(),
            accepted_height: 100,
            validated_height: Some(90),
            tip: "11".repeat(32),
            balance_scope: "key_outputs".to_owned(),
            confirmed_atoms: "1".to_owned(),
            spendable_atoms: "1".to_owned(),
            immature_atoms: "0".to_owned(),
            includes_mempool: false,
            utxo_count: 1,
            page_limit: 20,
            has_more: true,
            next_cursor: None,
            history: vec![],
        };
        assert!(validate_address(&address, DESTINATION).is_err());
        address.has_more = false;
        assert!(validate_address(&address, DESTINATION).is_ok());

        let transaction = TransactionStatus {
            txid: "22".repeat(32),
            status: "confirmed".to_owned(),
            block_height: None,
            block_id: None,
            confirmations: 2,
            validated_height: Some(100),
            timestamp: None,
        };
        assert!(validate_transaction_status(&transaction, &transaction.txid).is_err());

        let contradictory = TransactionStatus {
            txid: "33".repeat(32),
            status: "conflicted".to_owned(),
            block_height: Some(42),
            block_id: Some("44".repeat(32)),
            confirmations: 1,
            validated_height: Some(42),
            timestamp: None,
        };
        assert!(validate_transaction_status(&contradictory, &contradictory.txid).is_err());
    }

    #[test]
    fn derives_confirmations_from_the_observed_gateway_status_shape() {
        let json = format!(
            r#"{{"block_height":31619,"block_id":"{}","status":"confirmed","timestamp":1792930461,"txid":"{}","validated_height":31620}}"#,
            "44".repeat(32),
            "55".repeat(32)
        );
        let transaction: TransactionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(transaction.confirmations, 0);

        let normalized = normalize_transaction_status(transaction).unwrap();
        assert_eq!(normalized.confirmations, 2);
        validate_transaction_status(&normalized, &"55".repeat(32)).unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_cursor_before_any_network_request() {
        let client = test_client("http://127.0.0.1:1/", Duration::from_millis(10));
        let invalid = UtxoCursor {
            snapshot: "".to_owned(),
            txid: "22".repeat(32),
            vout: 0,
        };
        assert!(matches!(
            client.utxos(DESTINATION, Some(&invalid)).await,
            Err(ApiError::MalformedResponse)
        ));
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets (run with --ignored)"]
    async fn accepts_a_valid_mainnet_response_without_private_data() {
        let body = format!(
            r#"{{"network":"CommonFoundry Mainnet","network_id":"{}","accepted_height":27059,"validated_height":23669,"tip":"{}","mempool_transactions":0,"mempool_bytes":0,"recent_transactions":[]}}"#,
            hex_network_id(),
            "11".repeat(32)
        );
        let (base, server) = serve_once(json_response("200 OK", &body), Duration::from_millis(0));
        let snapshot = test_client(&base, Duration::from_secs(1))
            .explorer()
            .await
            .unwrap();
        assert_eq!(snapshot.accepted_height, 27059);
        server.join().unwrap();
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets (run with --ignored)"]
    async fn maps_unavailable_timeout_redirect_and_rejection_distinctly() {
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable_base = format!("http://{}/", unused.local_addr().unwrap());
        drop(unused);
        let unavailable = test_client(&unavailable_base, Duration::from_secs(1))
            .explorer()
            .await;
        // Some Windows firewall profiles drop a closed loopback SYN instead of
        // refusing it, so this may reach the request timeout.
        assert!(
            matches!(unavailable, Err(ApiError::Unreachable | ApiError::Timeout)),
            "{unavailable:?}"
        );

        let (timeout_base, timeout_server) =
            serve_once(json_response("200 OK", "{}"), Duration::from_millis(100));
        assert!(matches!(
            test_client(&timeout_base, Duration::from_millis(10))
                .explorer()
                .await,
            Err(ApiError::Timeout)
        ));
        timeout_server.join().unwrap();

        let (redirect_base, redirect_server) = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
            Duration::from_millis(0),
        );
        assert!(matches!(
            test_client(&redirect_base, Duration::from_secs(1))
                .explorer()
                .await,
            Err(ApiError::RedirectRefused)
        ));
        redirect_server.join().unwrap();

        let error_body = r#"{"error":"work_check_pending","message":"retry later"}"#;
        let (reject_base, reject_server) = serve_once(
            json_response("422 Unprocessable Entity", error_body),
            Duration::from_millis(0),
        );
        let error = test_client(&reject_base, Duration::from_secs(1))
            .broadcast("00")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ApiError::Http {
                status: 422,
                ref code,
                retryable: true,
                ..
            } if code == "work_check_pending"
        ));
        reject_server.join().unwrap();

        let (server_error_base, server_error) = serve_once(
            json_response(
                "500 Internal Server Error",
                r#"{"error":"temporary_failure","message":"retry"}"#,
            ),
            Duration::from_millis(0),
        );
        assert!(matches!(
            test_client(&server_error_base, Duration::from_secs(1))
                .broadcast("00")
                .await,
            Err(ApiError::Http {
                status: 500,
                retryable: true,
                ..
            })
        ));
        server_error.join().unwrap();
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets (run with --ignored)"]
    async fn rejects_oversized_success_body_without_deserializing_it() {
        let body = "x".repeat(MAX_SUCCESS_BODY_BYTES + 1);
        let (base, server) = serve_once(json_response("200 OK", &body), Duration::from_millis(0));
        assert!(matches!(
            test_client(&base, Duration::from_secs(2)).explorer().await,
            Err(ApiError::MalformedResponse)
        ));
        server.join().unwrap();
    }
}
