//! Narrow read-only client for Germany and Proxmox mainnet proof routes.

use std::time::Duration;

use reqwest::{StatusCode, Url, redirect};
use serde::Deserialize;

use super::{ApiError, hex_network_id, parse_atoms, validate_hex32};

pub const INDEPENDENT_BASE_URL: &str = "https://explorer.commonfoundry.ai/";
const UTXO_ROUTE_PREFIX: &str = "v1/explorer/utxo/";
const BACKUP_UTXO_ROUTE_PREFIX: &str = "v1/explorer/utxo-backup/";
const MAX_UTXO_BODY_BYTES: usize = 4096;
const NETWORK_HEADER: &str = "X-CMFD-Network-Id";

#[derive(Debug, Clone)]
pub struct IndependentUtxoClient {
    base: Url,
    http: reqwest::Client,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IndependentUtxo {
    pub network_id: String,
    pub tip: String,
    pub height: u64,
    pub txid: String,
    pub vout: u32,
    pub value_atoms: String,
    pub destination_hex: String,
    pub spendable_height: u64,
    pub available: bool,
}

impl IndependentUtxoClient {
    pub fn new() -> Result<Self, ApiError> {
        let base = Url::parse(INDEPENDENT_BASE_URL).map_err(|_| ApiError::InvalidConfiguration)?;
        if base.scheme() != "https"
            || base.host_str() != Some("explorer.commonfoundry.ai")
            || base.port_or_known_default() != Some(443)
        {
            return Err(ApiError::InvalidConfiguration);
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .user_agent("common-foundry-android-wallet/0.1")
            .build()
            .map_err(|_| ApiError::InvalidConfiguration)?;
        Ok(Self { base, http })
    }

    /// A missing synthetic outpoint must return an identified 404. This checks
    /// that at least one separate proof route is deployed before Send is enabled.
    pub async fn probe(&self) -> Result<(), ApiError> {
        match self.probe_route(UTXO_ROUTE_PREFIX).await {
            Ok(()) => Ok(()),
            Err(error) if error.retryable() => self.probe_route(BACKUP_UTXO_ROUTE_PREFIX).await,
            Err(error) => Err(error),
        }
    }

    async fn probe_route(&self, prefix: &str) -> Result<(), ApiError> {
        let url = self
            .base
            .join(&format!("{prefix}{}/0", "00".repeat(32)))
            .map_err(|_| ApiError::InvalidConfiguration)?;
        let response = self.http.get(url).send().await.map_err(|error| {
            if error.is_timeout() {
                ApiError::Timeout
            } else {
                ApiError::Unreachable
            }
        })?;
        if response.status().is_redirection() {
            return Err(ApiError::RedirectRefused);
        }
        if response.status().is_server_error() || response.status() == StatusCode::TOO_MANY_REQUESTS
        {
            return Err(ApiError::Http {
                status: response.status().as_u16(),
                code: "independent_proof_unavailable".to_owned(),
                message: "Independent proof route is unavailable.".to_owned(),
                retryable: true,
            });
        }
        if response.status() != StatusCode::NOT_FOUND && response.status() != StatusCode::OK {
            return Err(ApiError::MalformedResponse);
        }
        let expected_network = hex_network_id();
        if response
            .headers()
            .get(NETWORK_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(expected_network.as_str())
        {
            return Err(ApiError::WrongNetwork);
        }
        Ok(())
    }

    /// Use Proxmox only when Germany is unreachable or too far behind the
    /// wallet snapshot. A valid missing, unavailable, or mismatched outpoint
    /// from Germany remains a fail-closed answer.
    pub async fn utxo(
        &self,
        txid: &str,
        vout: u32,
        minimum_height: u64,
    ) -> Result<IndependentUtxo, ApiError> {
        match self.utxo_route(UTXO_ROUTE_PREFIX, txid, vout).await {
            Ok(utxo) if utxo.height >= minimum_height => Ok(utxo),
            Ok(_) => self.fallback_utxo(txid, vout, minimum_height).await,
            Err(error) if error.retryable() => self.fallback_utxo(txid, vout, minimum_height).await,
            Err(error) => Err(error),
        }
    }

    async fn fallback_utxo(
        &self,
        txid: &str,
        vout: u32,
        minimum_height: u64,
    ) -> Result<IndependentUtxo, ApiError> {
        let utxo = self
            .utxo_route(BACKUP_UTXO_ROUTE_PREFIX, txid, vout)
            .await?;
        if utxo.height < minimum_height {
            return Err(ApiError::MalformedResponse);
        }
        Ok(utxo)
    }

    async fn utxo_route(
        &self,
        prefix: &str,
        txid: &str,
        vout: u32,
    ) -> Result<IndependentUtxo, ApiError> {
        validate_hex32(txid)?;
        let url = self
            .base
            .join(&format!("{prefix}{txid}/{vout}"))
            .map_err(|_| ApiError::InvalidConfiguration)?;
        if url.scheme() != self.base.scheme()
            || url.host_str() != self.base.host_str()
            || url.port_or_known_default() != self.base.port_or_known_default()
        {
            return Err(ApiError::InvalidConfiguration);
        }
        let mut response = self.http.get(url).send().await.map_err(|error| {
            if error.is_timeout() {
                ApiError::Timeout
            } else {
                ApiError::Unreachable
            }
        })?;
        if response.status().is_redirection() {
            return Err(ApiError::RedirectRefused);
        }
        if !response.status().is_success() {
            return Err(ApiError::Http {
                status: response.status().as_u16(),
                code: "independent_utxo_unavailable".to_owned(),
                message: "Independent node did not return the outpoint.".to_owned(),
                retryable: response.status().is_server_error()
                    || response.status() == StatusCode::TOO_MANY_REQUESTS,
            });
        }
        let expected_network = hex_network_id();
        if response
            .headers()
            .get(NETWORK_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(expected_network.as_str())
        {
            return Err(ApiError::WrongNetwork);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_UTXO_BODY_BYTES as u64)
        {
            return Err(ApiError::MalformedResponse);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Unreachable)? {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > MAX_UTXO_BODY_BYTES)
            {
                return Err(ApiError::MalformedResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        let utxo: IndependentUtxo =
            serde_json::from_slice(&bytes).map_err(|_| ApiError::MalformedResponse)?;
        utxo.validate(txid, vout)?;
        Ok(utxo)
    }
}

impl IndependentUtxo {
    fn validate(&self, expected_txid: &str, expected_vout: u32) -> Result<(), ApiError> {
        if self.network_id != hex_network_id() {
            return Err(ApiError::WrongNetwork);
        }
        validate_hex32(&self.tip)?;
        validate_hex32(&self.txid)?;
        validate_hex32(&self.destination_hex)?;
        if self.txid != expected_txid
            || self.vout != expected_vout
            || parse_atoms(&self.value_atoms)? == 0
            || (self.available && self.spendable_height > self.height.saturating_add(1))
        {
            return Err(ApiError::MalformedResponse);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    const TXID: &str = "11";

    fn example() -> IndependentUtxo {
        IndependentUtxo {
            network_id: hex_network_id(),
            tip: "22".repeat(32),
            height: 100,
            txid: TXID.repeat(32),
            vout: 2,
            value_atoms: "100000000".to_owned(),
            destination_hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_owned(),
            spendable_height: 101,
            available: true,
        }
    }

    fn serve_once(
        status: &str,
        body: &str,
        network_header: Option<&str>,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let (sender, receiver) = mpsc::channel();
        let header = network_header
            .map(|value| format!("{NETWORK_HEADER}: {value}\r\n"))
            .unwrap_or_default();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let count = stream.read(&mut request).unwrap();
            let _ = sender.send(String::from_utf8_lossy(&request[..count]).into_owned());
            stream.write_all(response.as_bytes()).unwrap();
        });
        (base, receiver, handle)
    }

    fn serve_sequence(
        responses: Vec<(String, String, Option<String>)>,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            for (status, body, network_header) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let count = stream.read(&mut request).unwrap();
                let _ = sender.send(String::from_utf8_lossy(&request[..count]).into_owned());
                let header = network_header
                    .map(|value| format!("{NETWORK_HEADER}: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (base, receiver, handle)
    }

    fn example_body(height: u64) -> String {
        let mut utxo = example();
        utxo.height = height;
        utxo.spendable_height = height + 1;
        serde_json::json!({
            "network_id": utxo.network_id,
            "tip": utxo.tip,
            "height": utxo.height,
            "txid": utxo.txid,
            "vout": utxo.vout,
            "value_atoms": utxo.value_atoms,
            "destination_hex": utxo.destination_hex,
            "spendable_height": utxo.spendable_height,
            "available": utxo.available,
        })
        .to_string()
    }

    fn test_client(base: &str) -> IndependentUtxoClient {
        IndependentUtxoClient {
            base: Url::parse(base).unwrap(),
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
        }
    }

    #[test]
    fn verifies_network_identity_outpoint_and_maturity_shape() {
        let valid = example();
        assert!(valid.validate(&TXID.repeat(32), 2).is_ok());
        let mut wrong = valid.clone();
        wrong.network_id = "33".repeat(32);
        assert!(matches!(
            wrong.validate(&TXID.repeat(32), 2),
            Err(ApiError::WrongNetwork)
        ));
        wrong = valid.clone();
        wrong.value_atoms = "0".to_owned();
        assert!(matches!(
            wrong.validate(&TXID.repeat(32), 2),
            Err(ApiError::MalformedResponse)
        ));
        wrong = valid.clone();
        wrong.spendable_height = 102;
        assert!(matches!(
            wrong.validate(&TXID.repeat(32), 2),
            Err(ApiError::MalformedResponse)
        ));
        assert!(matches!(
            valid.validate(&TXID.repeat(32), 3),
            Err(ApiError::MalformedResponse)
        ));
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets (run with --ignored)"]
    async fn gets_only_the_exact_network_identified_outpoint() {
        let utxo = example();
        let body = serde_json::to_string(&serde_json::json!({
            "network_id": utxo.network_id,
            "tip": utxo.tip,
            "height": utxo.height,
            "txid": utxo.txid,
            "vout": utxo.vout,
            "value_atoms": utxo.value_atoms,
            "destination_hex": utxo.destination_hex,
            "spendable_height": utxo.spendable_height,
            "available": utxo.available,
        }))
        .unwrap();
        let (base, request, server) = serve_once("200 OK", &body, Some(&hex_network_id()));
        let fetched = test_client(&base)
            .utxo(&TXID.repeat(32), 2, 94)
            .await
            .unwrap();
        assert_eq!(fetched, example());
        assert!(request.recv().unwrap().starts_with(&format!(
            "GET /v1/explorer/utxo/{}/2 HTTP/1.1",
            TXID.repeat(32)
        )));
        server.join().unwrap();
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets (run with --ignored)"]
    async fn probe_requires_the_node_identity_even_on_not_found() {
        let (base, _, server) = serve_once("404 Not Found", "{}", Some(&hex_network_id()));
        assert!(test_client(&base).probe().await.is_ok());
        server.join().unwrap();
        let (base, _, server) = serve_once("404 Not Found", "{}", None);
        assert!(matches!(
            test_client(&base).probe().await,
            Err(ApiError::WrongNetwork)
        ));
        server.join().unwrap();
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets (run with --ignored)"]
    async fn stale_germany_outpoint_uses_fresh_proxmox_proof() {
        let expected_network = hex_network_id();
        let (base, requests, server) = serve_sequence(vec![
            (
                "200 OK".to_owned(),
                example_body(90),
                Some(expected_network.clone()),
            ),
            (
                "200 OK".to_owned(),
                example_body(100),
                Some(expected_network),
            ),
        ]);
        let fetched = test_client(&base)
            .utxo(&TXID.repeat(32), 2, 95)
            .await
            .unwrap();
        assert_eq!(fetched.height, 100);
        assert!(requests.recv().unwrap().contains("/v1/explorer/utxo/"));
        assert!(
            requests
                .recv()
                .unwrap()
                .contains("/v1/explorer/utxo-backup/")
        );
        server.join().unwrap();
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets (run with --ignored)"]
    async fn unavailable_primary_probes_proxmox_but_wrong_network_never_falls_back() {
        let (base, requests, server) = serve_sequence(vec![
            ("503 Service Unavailable".to_owned(), "{}".to_owned(), None),
            (
                "404 Not Found".to_owned(),
                "{}".to_owned(),
                Some(hex_network_id()),
            ),
        ]);
        assert!(test_client(&base).probe().await.is_ok());
        assert!(requests.recv().unwrap().contains("/v1/explorer/utxo/"));
        assert!(
            requests
                .recv()
                .unwrap()
                .contains("/v1/explorer/utxo-backup/")
        );
        server.join().unwrap();

        let (base, request, server) =
            serve_once("200 OK", &example_body(100), Some(&"ff".repeat(32)));
        assert!(matches!(
            test_client(&base).utxo(&TXID.repeat(32), 2, 95).await,
            Err(ApiError::WrongNetwork)
        ));
        assert!(request.recv().unwrap().contains("/v1/explorer/utxo/"));
        server.join().unwrap();
    }

    #[tokio::test]
    #[ignore = "requires loopback sockets (run with --ignored)"]
    async fn stale_backup_does_not_allow_a_send() {
        let expected_network = hex_network_id();
        let (base, requests, server) = serve_sequence(vec![
            (
                "200 OK".to_owned(),
                example_body(90),
                Some(expected_network.clone()),
            ),
            (
                "200 OK".to_owned(),
                example_body(91),
                Some(expected_network),
            ),
        ]);
        assert!(matches!(
            test_client(&base).utxo(&TXID.repeat(32), 2, 95).await,
            Err(ApiError::MalformedResponse)
        ));
        assert!(requests.recv().unwrap().contains("/v1/explorer/utxo/"));
        assert!(
            requests
                .recv()
                .unwrap()
                .contains("/v1/explorer/utxo-backup/")
        );
        server.join().unwrap();
    }
}
