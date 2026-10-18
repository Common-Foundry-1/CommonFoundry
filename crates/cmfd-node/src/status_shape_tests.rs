//! The shape of `/v1/status`, `/v1/wallet` and the exchange
//! `getblockchaininfo` `work_rule` object on a node under the release work
//! rule, as a server reports them: every key, with each value replaced by its
//! JSON type. The fixtures in `fixtures/status-shape/` were captured once;
//! these tests keep the documents to that shape. Set
//! `CMFD_WRITE_STATUS_SHAPE=1` to write the fixtures from the current code
//! instead.
//!
//! The documents also never carry the desktop wallet's catch-up fields
//! (`work_rule.wallet_catch_up`, `available_height`), which only a wallet with
//! the catch-up on reports.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cmfd_consensus::ForgeMatrixV4WorkRule;
use serde_json::{Map, Value, json};

use crate::exchange_rpc::spawn_exchange_rpc_server;
use crate::tests::clean_test_dir;
use crate::work_gate::WorkBankMode;
use crate::work_gate::test_support::{install, set_bank_mode};
use crate::work_gate::tests::{cpu, devnet};
use crate::{submit_shared_block, unix_time_seconds};

const STATUS: &str = include_str!("../fixtures/status-shape/status.json");
const WALLET: &str = include_str!("../fixtures/status-shape/wallet.json");
const EXCHANGE_WORK_RULE: &str = include_str!("../fixtures/status-shape/exchange-work-rule.json");

/// `value` with every leaf replaced by its JSON type name. An array keeps the
/// shape of its first element only.
fn shape(value: &Value) -> Value {
    match value {
        Value::Null => json!("null"),
        Value::Bool(_) => json!("bool"),
        Value::Number(_) => json!("number"),
        Value::String(_) => json!("string"),
        Value::Array(items) => Value::Array(items.first().map(shape).into_iter().collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), shape(value)))
                .collect::<Map<_, _>>(),
        ),
    }
}

/// The keys of a JSON object, sorted.
fn keys(value: &Value) -> Vec<String> {
    let mut keys = value
        .as_object()
        .map(|fields| fields.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    keys.sort();
    keys
}

/// `shape` with the `bank` value a server reports once its CPU engine reads
/// the model bank in a known mode.
fn with_bank_mode(shape: &str, path: &[&str]) -> Value {
    let mut shape: Value = serde_json::from_str(shape).unwrap();
    let mut object = &mut shape;
    for key in path {
        object = &mut object[*key];
    }
    assert_eq!(object["bank"], json!("null"));
    object["bank"] = json!("string");
    shape
}

/// Compares `actual` with the fixture `expected`, or writes it to `name`
/// when asked to.
fn check(name: &str, expected: &str, actual: &Value) {
    if std::env::var_os("CMFD_WRITE_STATUS_SHAPE").is_some() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/status-shape")
            .join(name);
        let mut text = serde_json::to_string_pretty(actual).unwrap();
        text.push('\n');
        std::fs::write(path, text.as_bytes()).unwrap();
        return;
    }
    let expected: Value = serde_json::from_str(expected).unwrap();
    assert_eq!(
        actual, &expected,
        "{name} no longer has the shape it was captured with"
    );
}

/// Calls the exchange RPC `method` with no parameters and returns its result.
fn exchange_call(address: SocketAddr, method: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": "shape", "method": method, "params": []}).to_string();
    let credential = BASE64_STANDARD.encode(b"exchange:test-password-0123456789");
    let mut stream = TcpStream::connect(address).unwrap();
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = String::new();
    match stream.read_to_string(&mut response) {
        Ok(_) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() => {}
        Err(error) => panic!("failed to read the exchange RPC response: {error}"),
    }
    let document: Value = serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    document["result"].clone()
}

#[test]
fn server_status_wallet_and_exchange_work_rule_keep_their_shape() {
    let now = unix_time_seconds().unwrap();
    let (path, mut node) = devnet("status-shape");
    let (source_path, mut source) = devnet("status-shape-source");
    let destination = node.wallet_destination();
    let chain = (0..4)
        .map(|offset| source.mine_once(destination, now + offset, 10_000).unwrap())
        .collect::<Vec<_>>();
    // The checkpoint is the second block, so the two above it are checked.
    let rule = ForgeMatrixV4WorkRule::with_pinned_heights(2, chain[1].block_id(), []).unwrap();
    let engine = cpu();
    for block in &chain {
        engine.answer(block, true);
    }
    install(&mut node, Some(rule), Some(engine.clone()), None);
    let shared = Arc::new(Mutex::new(node));
    for (offset, block) in chain.iter().enumerate() {
        submit_shared_block(&shared, block.clone(), now + offset as u64).unwrap();
    }
    assert_eq!(engine.block_calls(), 2);

    {
        let mut node = shared.lock().unwrap();
        let status = serde_json::to_value(node.status().unwrap()).unwrap();
        assert!(status["work_rule"].is_object());
        assert_eq!(status["work_rule"]["validated_height"], 4);
        assert_eq!(status["accepted_height"], 4);
        assert!(status["work_rule"]["unsettled_height"].is_null());
        assert!(status["work_rule"].get("wallet_catch_up").is_none());
        check("status.json", STATUS, &shape(&status));
        let wallet = serde_json::to_value(node.wallet_snapshot().unwrap()).unwrap();
        assert_eq!(wallet["validated_height"], 4);
        assert_eq!(wallet["accepted_height"], 4);
        assert!(wallet.get("available_height").is_none());
        assert!(
            wallet["history"]
                .as_array()
                .is_some_and(|history| !history.is_empty())
        );
        check("wallet.json", WALLET, &shape(&wallet));
        // The relay inventory is not cut short.
        let (inventory, _) = node.peer_relay_inventory("127.0.0.1:1", chain[0].block_id(), 16);
        assert_eq!(
            inventory,
            chain[1..]
                .iter()
                .map(|block| block.block_id())
                .collect::<Vec<_>>()
        );
    }

    let auth_dir = path.with_file_name(format!(
        "{}-auth",
        path.file_name().unwrap().to_string_lossy()
    ));
    clean_test_dir(&auth_dir);
    std::fs::create_dir_all(&auth_dir).unwrap();
    let auth = auth_dir.join("exchange-rpc.auth");
    std::fs::write(&auth, b"exchange:test-password-0123456789").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let server = spawn_exchange_rpc_server(
        Arc::clone(&shared),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        &auth,
        None,
    )
    .unwrap();
    let info = exchange_call(server.local_addr(), "getblockchaininfo");
    assert!(info["work_rule"].is_object(), "{info}");
    assert_eq!(info["work_rule"]["validated_height"], 4);
    assert!(info["work_rule"].get("wallet_catch_up").is_none());
    assert!(info.get("available_height").is_none());
    check(
        "exchange-work-rule.json",
        EXCHANGE_WORK_RULE,
        &shape(&info["work_rule"]),
    );

    // The fixtures were captured once, before the catch-up existed, and have
    // neither field.
    let fixture = |text: &str| serde_json::from_str::<Value>(text).unwrap();
    assert!(
        fixture(STATUS)["work_rule"]
            .get("wallet_catch_up")
            .is_none()
    );
    assert!(fixture(WALLET).get("available_height").is_none());
    assert_eq!(keys(&info["work_rule"]), keys(&fixture(EXCHANGE_WORK_RULE)));
    assert!(!keys(&fixture(EXCHANGE_WORK_RULE)).contains(&"wallet_catch_up".to_owned()));

    // With the bank mode known, only the `bank` value changes, in both.
    set_bank_mode(&mut shared.lock().unwrap(), WorkBankMode::Streamed);
    let status = serde_json::to_value(shared.lock().unwrap().status().unwrap()).unwrap();
    assert_eq!(status["work_rule"]["bank"], "streamed");
    assert_eq!(shape(&status), with_bank_mode(STATUS, &["work_rule"]));
    let info = exchange_call(server.local_addr(), "getblockchaininfo");
    server.stop().unwrap();
    assert_eq!(info["work_rule"]["bank"], "streamed");
    assert_eq!(
        shape(&info["work_rule"]),
        with_bank_mode(EXCHANGE_WORK_RULE, &[])
    );

    drop((shared, source));
    for path in [path, source_path, auth_dir] {
        clean_test_dir(&path);
    }
}
