#![cfg(not(feature = "production-v3-testnet"))]

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use cmfd_node::canonical_network_info_json;

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

#[test]
fn network_info_is_exact_and_does_not_create_the_data_directory() {
    let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
    let data_dir = std::env::temp_dir().join(format!(
        "cmfd-node-network-info-{}-{sequence}",
        std::process::id()
    ));
    if data_dir.exists() {
        fs::remove_dir_all(&data_dir).unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_cmfd-node"))
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("network-info")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, canonical_network_info_json().unwrap());
    assert!(!data_dir.exists());
}
