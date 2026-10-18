//! Loopback HTTP checks that wallet, mining and submission routes only answer
//! local clients, so a page that DNS-rebinds its own hostname to 127.0.0.1
//! cannot read or spend the node wallet or change node state, while public
//! reads (including the explorer origin reached through a tunnel that forwards
//! its public Host) still work.

use std::io::{Read, Write};

use serde_json::json;

use crate::tests::{clean_test_dir, spend_coinbase_output, test_dir};
use crate::*;

const EVIL_HOST: &str = "evil.example";
const EXPLORER_ORIGIN_HOST: &str = "mainnet-explorer-origin.commonfoundry.ai";

fn mine_wallet_to(node: &mut Node, height: u64) {
    while node.state.next_height() <= height {
        let destination = node.wallet_destination();
        let timestamp = DEVNET_GENESIS_TIMESTAMP + node.state.next_height() * 60;
        node.mine_once(destination, timestamp, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
    }
}

struct Reply {
    status: u16,
    head: String,
    body: serde_json::Value,
}

fn exchange(endpoint: SocketAddr, request: &str) -> Reply {
    exchange_with_body(endpoint, request, &[])
}

fn exchange_with_body(endpoint: SocketAddr, head: &str, body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(endpoint).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Reply {
        status,
        head: head.to_owned(),
        body: serde_json::from_str(body).unwrap(),
    }
}

fn get(endpoint: SocketAddr, target: &str, headers: &str) -> Reply {
    exchange(
        endpoint,
        &format!("GET {target} HTTP/1.1\r\n{headers}Connection: close\r\n\r\n"),
    )
}

fn post_json(endpoint: SocketAddr, target: &str, headers: &str, body: &serde_json::Value) -> Reply {
    let body = body.to_string();
    exchange(
        endpoint,
        &format!(
            "POST {target} HTTP/1.1\r\n{headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn post_octets(endpoint: SocketAddr, target: &str, headers: &str, body: &[u8]) -> Reply {
    exchange_with_body(
        endpoint,
        &format!(
            "POST {target} HTTP/1.1\r\n{headers}Content-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ),
        body,
    )
}

fn host(name: &str) -> String {
    format!("Host: {name}\r\n")
}

fn assert_refused(reply: &Reply) {
    assert_eq!(reply.status, 403, "{}\n{}", reply.head, reply.body);
    assert!(reply.head.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(reply.body["error"].as_str().unwrap().contains("local-only"));
}

fn send_request() -> serde_json::Value {
    json!({
        "recipient": hex::encode(insecure_dev_destination(0x5d)),
        "amount": "1.00000000",
        "fee": "0.00000001",
    })
}

#[test]
fn rebound_host_cannot_read_or_spend_the_wallet() {
    let path = test_dir("rpc-host-guard-rebind");
    clean_test_dir(&path);
    let mut node = Node::open(&path).unwrap();
    mine_wallet_to(&mut node, 100);
    let height = node.state.next_height();
    let shared = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = spawn_rpc_server_with_listener(Arc::clone(&shared), listener).unwrap();
    let port = endpoint.port();
    let evil = host(&format!("{EVIL_HOST}:{port}"));

    // What a DNS-rebinding page sends: its own hostname, same-origin.
    let rebound =
        format!("{evil}Origin: http://{EVIL_HOST}:{port}\r\nSec-Fetch-Site: same-origin\r\n");
    assert_refused(&post_json(
        endpoint,
        "/v1/wallet/send",
        &rebound,
        &send_request(),
    ));
    assert_refused(&post_json(
        endpoint,
        "/v1/wallet/send",
        &evil,
        &send_request(),
    ));
    assert_refused(&post_json(
        endpoint,
        "/v1/wallet/consolidate",
        &evil,
        &json!({"fee": "0.00000001", "max_inputs": 2}),
    ));
    assert!(shared.lock().unwrap().mempool.is_empty());
    assert_refused(&get(endpoint, "/v1/wallet", &evil));
    assert_refused(&get(endpoint, "/v1/wallet", &host(EVIL_HOST)));
    // The refusal comes before content-type and body validation.
    assert_refused(&exchange(
        endpoint,
        &format!(
            "POST /v1/wallet/send HTTP/1.1\r\n{evil}Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}"
        ),
    ));
    let miner = hex::encode(default_miner_destination());
    assert_refused(&exchange(
        endpoint,
        &format!(
            "POST /v1/mine?miner={miner}&attempts=1 HTTP/1.1\r\n{evil}Content-Length: 0\r\n\r\n"
        ),
    ));
    // Look-alike names are not loopback names.
    for name in [
        format!("127.0.0.1.{EVIL_HOST}:{port}"),
        format!("localhost.{EVIL_HOST}"),
        format!("{EVIL_HOST}:{port}@127.0.0.1"),
        "128.0.0.1".to_owned(),
        "0.0.0.0".to_owned(),
        "[::2]".to_owned(),
    ] {
        assert_refused(&get(endpoint, "/v1/wallet", &host(&name)));
    }
    assert_eq!(shared.lock().unwrap().state.next_height(), height);
    assert!(shared.lock().unwrap().mempool.is_empty());

    // Local clients (curl, PowerShell, Python urllib, the Vite proxy) keep
    // working with any loopback spelling and port.
    for name in [
        format!("127.0.0.1:{port}"),
        "127.0.0.1".to_owned(),
        "localhost".to_owned(),
        format!("LocalHost:{port}"),
        format!("[::1]:{port}"),
        "127.5.6.7:80".to_owned(),
    ] {
        let reply = get(endpoint, "/v1/wallet", &host(&name));
        assert_eq!(reply.status, 200, "{name}: {}", reply.body);
        assert!(reply.body["balances"]["spendable_atoms"].is_string());
    }
    let sent = post_json(
        endpoint,
        "/v1/wallet/send",
        &host(&format!("127.0.0.1:{port}")),
        &send_request(),
    );
    assert_eq!(sent.status, 200, "{}", sent.body);
    assert_eq!(shared.lock().unwrap().mempool.len(), 1);

    server.stop().unwrap();
    drop(shared);
    clean_test_dir(&path);
}

fn candidate_block(node: &Node, now: u64) -> Block {
    let template = node
        .build_template(default_miner_destination(), now)
        .unwrap();
    let proof = node
        .verifier
        .mine(&template.challenge, 0, DEFAULT_MINING_ATTEMPTS)
        .unwrap();
    Block {
        version: BLOCK_VERSION,
        challenge: template.challenge,
        proof,
        coinbase: template.coinbase,
        transactions: Vec::new(),
    }
}

#[test]
fn rebound_host_cannot_submit_transactions_or_blocks() {
    let path = test_dir("rpc-host-guard-submit");
    clean_test_dir(&path);
    let mut node = Node::open(&path).unwrap();
    let now = unix_time_seconds().unwrap();
    let funding = node
        .mine_once(default_miner_destination(), now, DEFAULT_MINING_ATTEMPTS)
        .unwrap();
    let transaction =
        encode_transaction(&spend_coinbase_output(&node, &funding, 2, 0x12, 0x79, 10)).unwrap();
    let block = encode_block(&candidate_block(&node, now)).unwrap();
    let height = node.state.next_height();
    let shared = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = spawn_rpc_server_with_listener(Arc::clone(&shared), listener).unwrap();
    let port = endpoint.port();
    let evil = host(&format!("{EVIL_HOST}:{port}"));
    let rebound =
        format!("{evil}Origin: http://{EVIL_HOST}:{port}\r\nSec-Fetch-Site: same-origin\r\n");

    // Valid, signed and mined payloads: only the Host decides the answer.
    for headers in [&evil, &rebound] {
        assert_refused(&post_octets(
            endpoint,
            "/v1/transaction",
            headers,
            &transaction,
        ));
        assert_refused(&post_octets(endpoint, "/v1/block", headers, &block));
    }
    assert!(shared.lock().unwrap().mempool.is_empty());
    assert_eq!(shared.lock().unwrap().state.next_height(), height);

    let submitted = post_octets(
        endpoint,
        "/v1/transaction",
        &host(&format!("127.0.0.1:{port}")),
        &transaction,
    );
    assert_eq!(submitted.status, 200, "{}", submitted.body);
    assert_eq!(shared.lock().unwrap().mempool.len(), 1);
    let accepted = post_octets(endpoint, "/v1/block", &host("localhost"), &block);
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(shared.lock().unwrap().state.next_height(), height + 1);

    server.stop().unwrap();
    drop(shared);
    clean_test_dir(&path);
}

#[test]
fn foreign_browser_origins_are_refused_on_wallet_routes() {
    let path = test_dir("rpc-host-guard-origin");
    clean_test_dir(&path);
    let mut node = Node::open(&path).unwrap();
    mine_wallet_to(&mut node, 100);
    let shared = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = spawn_rpc_server_with_listener(Arc::clone(&shared), listener).unwrap();
    let local = host(&format!("127.0.0.1:{}", endpoint.port()));

    for extra in [
        format!("Origin: https://{EVIL_HOST}\r\n"),
        format!("Origin: http://{EVIL_HOST}:{}\r\n", endpoint.port()),
        "Origin: null\r\n".to_owned(),
        "Origin: http://127.0.0.1.evil.example\r\n".to_owned(),
        "Origin: file://\r\n".to_owned(),
        "Sec-Fetch-Site: cross-site\r\n".to_owned(),
    ] {
        let headers = format!("{local}{extra}");
        assert_refused(&post_json(
            endpoint,
            "/v1/wallet/send",
            &headers,
            &send_request(),
        ));
        assert_refused(&get(endpoint, "/v1/wallet", &headers));
    }
    assert!(shared.lock().unwrap().mempool.is_empty());

    // The browser wallet's Vite proxy rewrites Host to the node but forwards
    // the page's loopback Origin unchanged.
    for extra in [
        "Origin: http://127.0.0.1:5173\r\nSec-Fetch-Site: same-origin\r\n",
        "Origin: http://localhost:5173\r\n",
        "Origin: https://[::1]\r\nSec-Fetch-Site: same-site\r\n",
        "Sec-Fetch-Site: none\r\n",
    ] {
        let reply = get(endpoint, "/v1/wallet", &format!("{local}{extra}"));
        assert_eq!(reply.status, 200, "{extra}: {}", reply.body);
    }
    let sent = post_json(
        endpoint,
        "/v1/wallet/send",
        &format!("{local}Origin: http://127.0.0.1:5173\r\nSec-Fetch-Site: same-origin\r\n"),
        &send_request(),
    );
    assert_eq!(sent.status, 200, "{}", sent.body);
    assert_eq!(shared.lock().unwrap().mempool.len(), 1);

    server.stop().unwrap();
    drop(shared);
    clean_test_dir(&path);
}

#[test]
fn public_reads_keep_answering_any_host() {
    let path = test_dir("rpc-host-guard-public");
    clean_test_dir(&path);
    let mut node = Node::open(&path).unwrap();
    mine_wallet_to(&mut node, 1);
    let network = hex::encode(node.params.network_id);
    let paid = hex::encode(node.wallet_destination());
    let shared = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = spawn_rpc_server_with_listener(Arc::clone(&shared), listener).unwrap();

    // cloudflared forwards the public origin hostname as Host.
    let tunnel = format!(
        "{}Origin: https://explorer.commonfoundry.ai\r\nSec-Fetch-Site: cross-site\r\n",
        host(EXPLORER_ORIGIN_HOST)
    );
    let explorer = get(endpoint, "/v1/explorer", &tunnel);
    assert_eq!(explorer.status, 200, "{}", explorer.body);
    assert!(
        explorer
            .head
            .contains(&format!("X-CMFD-Network-Id: {network}"))
    );
    assert_eq!(get(endpoint, "/v1/explorer/block/1", &tunnel).status, 200);
    assert_eq!(
        get(endpoint, &format!("/v1/explorer/address/{paid}"), &tunnel).status,
        200
    );
    // A lookup miss is still answered by the explorer route, not refused.
    let missing = get(
        endpoint,
        &format!("/v1/explorer/transaction/{}", "ab".repeat(32)),
        &tunnel,
    );
    assert_eq!(missing.status, 404, "{}", missing.body);
    let miner = hex::encode(default_miner_destination());
    for target in [
        "/health".to_owned(),
        "/v1/status".to_owned(),
        "/v1/mempool".to_owned(),
        format!("/v1/template?miner={miner}"),
    ] {
        for headers in [host(EVIL_HOST), host(EXPLORER_ORIGIN_HOST), String::new()] {
            let reply = get(endpoint, &target, &headers);
            assert_eq!(reply.status, 200, "{target} {headers}: {}", reply.body);
        }
    }

    server.stop().unwrap();
    drop(shared);
    clean_test_dir(&path);
}

#[test]
fn missing_or_repeated_host_is_refused_only_on_local_routes() {
    let path = test_dir("rpc-host-guard-missing");
    clean_test_dir(&path);
    let shared = Arc::new(Mutex::new(Node::open(&path).unwrap()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = spawn_rpc_server_with_listener(Arc::clone(&shared), listener).unwrap();
    let local = host(&format!("127.0.0.1:{}", endpoint.port()));

    // HTTP/1.1 requires Host; no browser omits it, so a guarded route needs
    // positive evidence of a loopback name. Public routes are unchanged.
    assert_refused(&get(endpoint, "/v1/wallet", ""));
    assert_eq!(get(endpoint, "/health", "").status, 200);

    // Repeated headers are ambiguous: refuse rather than pick one.
    let repeated = format!("{local}{}", host(EVIL_HOST));
    assert_refused(&get(endpoint, "/v1/wallet", &repeated));
    assert_refused(&get(endpoint, "/v1/wallet", &format!("{local}{local}")));
    assert_refused(&get(
        endpoint,
        "/v1/wallet",
        &format!("{local}Origin: http://127.0.0.1\r\nOrigin: http://127.0.0.1\r\n"),
    ));
    assert_eq!(get(endpoint, "/health", &repeated).status, 200);

    // HTTP/1.0 never reaches routing: the parser already requires HTTP/1.1.
    for target in ["/v1/wallet", "/health"] {
        let reply = exchange(endpoint, &format!("GET {target} HTTP/1.0\r\n{local}\r\n"));
        assert_eq!(reply.status, 400, "{}", reply.body);
    }

    server.stop().unwrap();
    drop(shared);
    clean_test_dir(&path);
}

#[test]
fn a_local_only_route_is_refused_before_its_body_is_read() {
    let path = test_dir("rpc-host-guard-head");
    clean_test_dir(&path);
    let shared = Arc::new(Mutex::new(Node::open(&path).unwrap()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = spawn_rpc_server_with_listener(Arc::clone(&shared), listener).unwrap();

    // A large body is announced and never sent: the refusal comes at once,
    // not after the read times out.
    let started = Instant::now();
    let reply = exchange(
        endpoint,
        &format!(
            "POST /v1/block HTTP/1.1\r\n{}Content-Type: application/octet-stream\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n",
            host(EVIL_HOST)
        ),
    );
    assert_refused(&reply);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );

    server.stop().unwrap();
    drop(shared);
    clean_test_dir(&path);
}

#[test]
fn loopback_host_origin_and_route_rules() {
    for authority in [
        "127.0.0.1",
        "127.0.0.1:29443",
        "127.255.255.254:1",
        "localhost",
        "LOCALHOST:18443",
        "[::1]",
        "[::1]:29443",
        "[0:0:0:0:0:0:0:1]:80",
    ] {
        assert!(is_loopback_authority(authority), "{authority}");
    }
    for authority in [
        "",
        "evil.example",
        "evil.example:29443",
        "127.0.0.1.evil.example",
        "localhost.evil.example",
        "localhost.",
        "128.0.0.1",
        "0.0.0.0",
        "127.1",
        "::1",
        "[::1",
        "[::1]x",
        "[::2]",
        "[::ffff:127.0.0.1]",
        "127.0.0.1:",
        "127.0.0.1:abc",
        "localhost:80:80",
        "evil.example:1@127.0.0.1",
        "user@127.0.0.1",
    ] {
        assert!(!is_loopback_authority(authority), "{authority}");
    }

    for origin in [
        "http://127.0.0.1:5173",
        "HTTP://localhost",
        "https://[::1]:4173",
    ] {
        assert!(is_loopback_origin(origin), "{origin}");
    }
    for origin in [
        "null",
        "",
        "https://evil.example",
        "http://127.0.0.1.evil.example",
        "http://127.0.0.1:5173/",
        "file://",
        "tauri://localhost",
        "chrome-extension://localhost",
        "127.0.0.1",
    ] {
        assert!(!is_loopback_origin(origin), "{origin}");
    }

    for target in [
        "/v1/wallet",
        "/v1/wallet?x=1",
        "/v1/wallet/send",
        "/v1/wallet/consolidate",
        "/v1/wallet/future",
        "/v1/mine?miner=00&attempts=1",
        "/v1/mine",
        "/v1/transaction",
        "/v1/block",
        "/v1/block?x=1",
    ] {
        assert!(is_local_only_rpc_target(target), "{target}");
    }
    for target in [
        "/health",
        "/v1/status",
        "/v1/mempool",
        "/v1/explorer",
        "/v1/explorer/address/00",
        "/v1/explorer/block/1",
        "/v1/explorer/transaction/00",
        "/v1/template?miner=00",
        "/v1/transactions",
        "/v1/blocks",
        "/v1/walletx",
        "/v1/miner",
        "/",
    ] {
        assert!(!is_local_only_rpc_target(target), "{target}");
    }
}
