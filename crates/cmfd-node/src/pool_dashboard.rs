//! Read-only, loopback-only web dashboard for the authenticated pool.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

use crate::pool::{PoolDashboardSource, PoolError};

pub const DEFAULT_POOL_DASHBOARD_ADDRESS: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22446);

const DASHBOARD_ACCEPT_POLL: Duration = Duration::from_millis(25);
const DASHBOARD_READ_TIMEOUT: Duration = Duration::from_secs(2);
const DASHBOARD_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const DASHBOARD_MAX_HEADER_BYTES: usize = 8 * 1024;
const DASHBOARD_MAX_ASSET_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum PoolDashboardError {
    #[error("pool dashboard bind must be loopback, received {0}")]
    NonLoopback(SocketAddr),
    #[error("pool dashboard URL must be cmfd+tls://NUMERIC_IP:PORT?pin=64_HEX")]
    InvalidPoolUrl,
    #[error("pool dashboard assets are invalid: {0}")]
    InvalidAssets(String),
    #[error("pool dashboard request is invalid: {0}")]
    InvalidRequest(String),
    #[error("pool dashboard I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("pool dashboard snapshot failed: {0}")]
    Pool(#[from] PoolError),
    #[error("pool dashboard JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("pool dashboard thread panicked")]
    ThreadPanicked,
}

#[derive(Debug, Clone)]
pub struct PoolDashboardConfig {
    pub bind: SocketAddr,
    pub assets_directory: PathBuf,
    pub public_pool_url: String,
    pub certificate_sha256: [u8; 32],
}

pub struct PoolDashboardHandle {
    local_address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), PoolDashboardError>>>,
}

impl PoolDashboardHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_address
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }

    pub fn stop(mut self) -> Result<(), PoolDashboardError> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), PoolDashboardError> {
        self.stop.store(true, Ordering::Release);
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| PoolDashboardError::ThreadPanicked)?,
            None => Ok(()),
        }
    }
}

impl Drop for PoolDashboardHandle {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

#[derive(Serialize)]
struct DashboardDocument<'a> {
    public_pool_url: &'a str,
    certificate_sha256: String,
    refresh_interval_seconds: u8,
    pool: crate::pool::PoolDashboardSnapshot,
}

pub fn spawn_pool_dashboard(
    source: PoolDashboardSource,
    config: PoolDashboardConfig,
) -> Result<PoolDashboardHandle, PoolDashboardError> {
    if !config.bind.ip().is_loopback() {
        return Err(PoolDashboardError::NonLoopback(config.bind));
    }
    validate_public_pool_url(&config.public_pool_url, config.certificate_sha256)?;
    let assets_directory = canonical_assets_directory(&config.assets_directory)?;
    let listener = TcpListener::bind(config.bind)?;
    listener.set_nonblocking(true)?;
    let local_address = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("cmfd-pool-dashboard".to_owned())
        .spawn(move || dashboard_loop(listener, source, config, assets_directory, thread_stop))?;
    Ok(PoolDashboardHandle {
        local_address,
        stop,
        thread: Some(thread),
    })
}

fn canonical_assets_directory(path: &Path) -> Result<PathBuf, PoolDashboardError> {
    let directory = fs::canonicalize(path).map_err(|error| {
        PoolDashboardError::InvalidAssets(format!("{}: {error}", path.display()))
    })?;
    if !directory.is_dir() || !directory.join("index.html").is_file() {
        return Err(PoolDashboardError::InvalidAssets(format!(
            "{} must be a directory containing index.html",
            directory.display()
        )));
    }
    Ok(directory)
}

fn validate_public_pool_url(
    value: &str,
    certificate_sha256: [u8; 32],
) -> Result<(), PoolDashboardError> {
    let Some(remainder) = value.strip_prefix("cmfd+tls://") else {
        return Err(PoolDashboardError::InvalidPoolUrl);
    };
    let Some((authority, pin)) = remainder.split_once("?pin=") else {
        return Err(PoolDashboardError::InvalidPoolUrl);
    };
    if authority.parse::<SocketAddr>().is_err()
        || pin.len() != 64
        || !pin.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !pin.eq_ignore_ascii_case(&hex::encode(certificate_sha256))
    {
        return Err(PoolDashboardError::InvalidPoolUrl);
    }
    Ok(())
}

fn dashboard_loop(
    listener: TcpListener,
    source: PoolDashboardSource,
    config: PoolDashboardConfig,
    assets_directory: PathBuf,
    stop: Arc<AtomicBool>,
) -> Result<(), PoolDashboardError> {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let response =
                    match handle_request(&mut stream, &source, &config, &assets_directory) {
                        Ok(response) => response,
                        Err(_) => DashboardResponse::text(
                            400,
                            "Bad Request",
                            "text/plain; charset=utf-8",
                            b"bad request\n".to_vec(),
                        ),
                    };
                let _ = write_response(&mut stream, response);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(DASHBOARD_ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn handle_request(
    stream: &mut TcpStream,
    source: &PoolDashboardSource,
    config: &PoolDashboardConfig,
    assets_directory: &Path,
) -> Result<DashboardResponse, PoolDashboardError> {
    stream.set_read_timeout(Some(DASHBOARD_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(DASHBOARD_WRITE_TIMEOUT))?;
    let request = read_request(stream)?;
    if request.method != "GET" && request.method != "HEAD" {
        return Ok(DashboardResponse::text(
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"method not allowed\n".to_vec(),
        ));
    }
    let mut response = match request.target.as_str() {
        "/health" => {
            DashboardResponse::text(200, "OK", "application/json", b"{\"ok\":true}\n".to_vec())
        }
        "/api/v1/pool" => match source.snapshot() {
            Ok(pool) => DashboardResponse::text(
                200,
                "OK",
                "application/json",
                serde_json::to_vec(&DashboardDocument {
                    public_pool_url: &config.public_pool_url,
                    certificate_sha256: hex::encode(config.certificate_sha256),
                    refresh_interval_seconds: 10,
                    pool,
                })?,
            )
            .no_store(),
            Err(_) => DashboardResponse::text(
                503,
                "Service Unavailable",
                "application/json",
                b"{\"error\":\"pool snapshot unavailable\"}\n".to_vec(),
            )
            .no_store(),
        },
        "/" | "/index.html" => serve_asset(assets_directory, "index.html")?.no_store(),
        target if target.starts_with("/assets/") => {
            let name = &target[8..];
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                DashboardResponse::not_found()
            } else {
                serve_asset(assets_directory, &format!("assets/{name}"))?
            }
        }
        _ => DashboardResponse::not_found(),
    };
    if request.method == "HEAD" {
        response.body.clear();
    }
    Ok(response)
}

struct DashboardRequest {
    method: String,
    target: String,
}

fn read_request(stream: &mut TcpStream) -> Result<DashboardRequest, PoolDashboardError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err(PoolDashboardError::InvalidRequest(
                "connection closed before request headers".to_owned(),
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > DASHBOARD_MAX_HEADER_BYTES {
            return Err(PoolDashboardError::InvalidRequest(
                "request headers exceed 8 KiB".to_owned(),
            ));
        }
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        PoolDashboardError::InvalidRequest("request headers are not UTF-8".to_owned())
    })?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !target.starts_with('/')
        || target.contains('?')
        || version != "HTTP/1.1"
    {
        return Err(PoolDashboardError::InvalidRequest(
            "expected an HTTP/1.1 request with an exact path".to_owned(),
        ));
    }
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(PoolDashboardError::InvalidRequest(
                "malformed request header".to_owned(),
            ));
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err(PoolDashboardError::InvalidRequest(
                "dashboard requests cannot carry a body".to_owned(),
            ));
        }
    }
    Ok(DashboardRequest {
        method: method.to_owned(),
        target: target.to_owned(),
    })
}

struct DashboardResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    cache_control: &'static str,
    body: Vec<u8>,
}

impl DashboardResponse {
    fn text(status: u16, reason: &'static str, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            content_type,
            cache_control: "no-store",
            body,
        }
    }

    fn no_store(mut self) -> Self {
        self.cache_control = "no-store";
        self
    }

    fn immutable(mut self) -> Self {
        self.cache_control = "public, max-age=31536000, immutable";
        self
    }

    fn not_found() -> Self {
        Self::text(
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            b"not found\n".to_vec(),
        )
        .no_store()
    }
}

fn serve_asset(root: &Path, relative: &str) -> Result<DashboardResponse, PoolDashboardError> {
    let path = root.join(relative);
    let canonical = match fs::canonicalize(&path) {
        Ok(path) if path.starts_with(root) && path.is_file() => path,
        Ok(_) => return Ok(DashboardResponse::not_found()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DashboardResponse::not_found());
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = canonical.metadata()?;
    if metadata.len() > DASHBOARD_MAX_ASSET_BYTES {
        return Ok(DashboardResponse::not_found());
    }
    let content_type = match canonical
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    Ok(DashboardResponse::text(200, "OK", content_type, fs::read(canonical)?).immutable())
}

fn write_response(
    stream: &mut TcpStream,
    response: DashboardResponse,
) -> Result<(), PoolDashboardError> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: {}\r\nConnection: close\r\nContent-Security-Policy: default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len(),
        response.cache_control,
    )?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_pool_url_is_bound_to_the_certificate_pin() {
        let pin = [0xab; 32];
        assert!(
            validate_public_pool_url(
                &format!("cmfd+tls://107.214.187.2:22445?pin={}", hex::encode(pin)),
                pin,
            )
            .is_ok()
        );
        assert!(
            validate_public_pool_url(
                &format!("cmfd+tls://107.214.187.2:22445?pin={}", "cd".repeat(32)),
                pin,
            )
            .is_err()
        );
        assert!(
            validate_public_pool_url(
                &format!("stratum+tls://107.214.187.2:22445?pin={}", hex::encode(pin)),
                pin,
            )
            .is_err()
        );
    }

    #[test]
    fn request_parser_rejects_bodies_and_traversal() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .write_all(
                    b"GET /../wallet.key HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx",
                )
                .unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        assert!(read_request(&mut stream).is_err());
        client.join().unwrap();
    }
}
