//! Real offline CLI recovery with disposable keys and tiny reference proofs.
//! This is not a mainnet package or ProductionV4 proof qualification.
#![cfg(not(any(feature = "production-v3", feature = "production-v4")))]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use cmfd_node::{DEVNET_PROFILE, Node, wallet_backup::create_encrypted_wallet};

struct RecoveryFixture(PathBuf);

impl RecoveryFixture {
    fn new() -> Self {
        let mut identity = [0; 16];
        getrandom::fill(&mut identity).unwrap();
        let root =
            std::env::temp_dir().join(format!("cmfd-offline-recovery-{}", hex::encode(identity)));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}

impl Drop for RecoveryFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}

fn node_command(data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cmfd-node"));
    command.arg("--data-dir").arg(data).stdin(Stdio::null());
    command
}

fn json_success(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn encrypted_wallet_and_chain_recover_through_offline_cli_without_overwrite() {
    let root = RecoveryFixture::new();
    let source = root.0.join("source");
    let restored = root.0.join("restored wallet");
    let passphrase_file = root.0.join("wallet passphrase");
    let passphrase = b"disposable offline recovery test password";
    write_private(&passphrase_file, passphrase);
    let identity = create_encrypted_wallet(
        &source,
        &root.0.join("initial-backup"),
        DEVNET_PROFILE.network_id,
        passphrase,
    )
    .unwrap();
    let mut node = Node::open_with_runtime_security_and_wallet_passphrase(
        &source,
        None,
        None,
        None,
        Some(passphrase),
    )
    .unwrap();
    for offset in 1..=3 {
        node.mine_once(
            identity.destination,
            DEVNET_PROFILE.virtual_genesis_timestamp + offset * 60,
            10_000,
        )
        .unwrap();
    }
    let expected = node.status().unwrap();
    let backup = root.0.join("offline-backup");
    let locked = node_command(&source)
        .arg("wallet-backup")
        .arg("--output")
        .arg(&backup)
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .output()
        .unwrap();
    assert!(!locked.status.success());
    assert!(!backup.exists());
    drop(node);

    let backup_info = json_success(
        node_command(&source)
            .arg("wallet-backup")
            .arg("--output")
            .arg(&backup)
            .arg("--passphrase-file")
            .arg(&passphrase_file)
            .output()
            .unwrap(),
    );
    assert_eq!(
        backup_info["destination"],
        hex::encode(identity.destination)
    );
    assert_eq!(
        backup_info["network_id"],
        hex::encode(DEVNET_PROFILE.network_id)
    );
    let wrong_passphrase = root.0.join("wrong-passphrase");
    write_private(&wrong_passphrase, b"another disposable recovery password");
    let rejected_directory = root.0.join("wrong-password-restore");
    let rejected = node_command(&rejected_directory)
        .arg("wallet-restore")
        .arg("--input")
        .arg(&backup)
        .arg("--passphrase-file")
        .arg(&wrong_passphrase)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(!rejected_directory.exists());

    let recovered = json_success(
        node_command(&restored)
            .arg("wallet-restore")
            .arg("--input")
            .arg(&backup)
            .arg("--passphrase-file")
            .arg(&passphrase_file)
            .output()
            .unwrap(),
    );
    assert_eq!(recovered["destination"], backup_info["destination"]);
    let restored_key = fs::read(restored.join("wallet.key")).unwrap();
    let duplicate = node_command(&restored)
        .arg("wallet-restore")
        .arg("--input")
        .arg(&backup)
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert_eq!(fs::read(restored.join("wallet.key")).unwrap(), restored_key);

    // Restore a consistent stopped-chain copy; deliberately omit cache files
    // so the subsequent status command must perform real block-log replay.
    for filename in ["blocks.log", "network.meta"] {
        fs::copy(source.join(filename), restored.join(filename)).unwrap();
    }
    let log_path = restored.join("blocks.log");
    let retained_log = fs::read(&log_path).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap()
        .write_all(b"CMF")
        .unwrap();
    let failed_start = node_command(&restored)
        .arg("--wallet-passphrase-file")
        .arg(&passphrase_file)
        .arg("status")
        .output()
        .unwrap();
    assert!(!failed_start.status.success());
    let inspection = json_success(
        node_command(&restored)
            .arg("storage-inspect")
            .output()
            .unwrap(),
    );
    assert_eq!(inspection["status"], "recoverable_partial_tail");
    assert_eq!(inspection["inspection"]["records"], 3);
    assert_eq!(
        inspection["inspection"]["recoverable_partial_tail_bytes"],
        3
    );
    let quarantine = root.0.join("tail.quarantine");
    let repair = json_success(
        node_command(&restored)
            .arg("storage-repair-tail")
            .arg("--quarantine-output")
            .arg(&quarantine)
            .output()
            .unwrap(),
    );
    assert_eq!(repair["status"], "repaired");
    assert_eq!(fs::read(quarantine).unwrap(), b"CMF");
    assert_eq!(fs::read(&log_path).unwrap(), retained_log);
    assert_eq!(fs::read(restored.join("wallet.key")).unwrap(), restored_key);
    let status = json_success(
        node_command(&restored)
            .arg("--wallet-passphrase-file")
            .arg(&passphrase_file)
            .arg("status")
            .output()
            .unwrap(),
    );
    assert_eq!(status["accepted_height"], expected.accepted_height);
    assert_eq!(status["tip"], expected.tip);
    assert_eq!(
        status["consensus_fingerprint"],
        expected.consensus_fingerprint
    );
    assert_eq!(status["utxo_count"], expected.utxo_count);
    assert_eq!(status["startup_snapshot_used"], false);
    assert_eq!(fs::read(source.join("blocks.log")).unwrap(), retained_log);
}
