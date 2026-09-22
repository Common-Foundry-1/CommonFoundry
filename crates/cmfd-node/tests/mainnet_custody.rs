#![cfg(feature = "production-v4")]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PASSWORD: &[u8] = b"disposable shared custody fixture password";

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!("cmfd-custody-cli-{}", hex::encode(nonce)));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn command(&self, subcommand: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cmfd-node"));
        command
            .arg("--data-dir")
            .arg(self.root.join("must-not-initialize"))
            .arg(subcommand)
            .arg("--wallets-directory")
            .arg(self.root.join("wallets"))
            .arg("--backups-directory")
            .arg(self.root.join("backups"))
            .arg("--public-directory")
            .arg(self.root.join("public"))
            .arg("--shared-passphrase-stdin");
        command
    }

    fn prepare(&self) -> Command {
        let mut command = self.command("mainnet-custody-prepare");
        command
            .arg("--pow-limit")
            .arg(hex::encode(cmfd_node::RCNET1_PROFILE.pow_limit))
            .arg("--initial-target")
            .arg("000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb");
        command
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run(mut command: Command, password: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let _ = input.write_all(password);
    drop(input);
    child.wait_with_output().unwrap()
}

#[test]
fn cli_shared_stdin_password_creates_and_verifies_without_plaintext_files() {
    let fixture = Fixture::new();
    let output = run(fixture.prepare(), PASSWORD);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output
            .stdout
            .windows(PASSWORD.len())
            .any(|bytes| bytes == PASSWORD)
    );
    assert!(
        !output
            .stderr
            .windows(PASSWORD.len())
            .any(|bytes| bytes == PASSWORD)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["mainnet_activation_authorized"], false);
    assert_eq!(report["backups_authenticated"], true);
    let mut verify = fixture.command("mainnet-custody-verify");
    verify
        .arg("--expected-plan-digest")
        .arg(report["launch_plan_digest"].as_str().unwrap());
    let checked = run(verify, PASSWORD);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert_eq!(checked.stdout, output.stdout);
    assert!(!fixture.root.join("must-not-initialize").exists());
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 3);
    assert_eq!(
        fs::read_dir(fixture.root.join("public")).unwrap().count(),
        2
    );
    assert!(!run(fixture.prepare(), PASSWORD).status.success());
}

#[test]
fn custody_cli_requires_complete_explicit_password_source_and_bounded_stdin() {
    let fixture = Fixture::new();
    for password in [Vec::new(), b"short".to_vec(), vec![b'x'; 1025]] {
        let output = run(fixture.prepare(), &password);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
    }
    let mut mixed = fixture.prepare();
    mixed
        .arg("--steward-passphrase-file")
        .arg(fixture.root.join("unused"));
    assert!(!run(mixed, PASSWORD).status.success());
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
}
