#![cfg(feature = "production-v4")]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PASSWORD: &[u8] = b"disposable shared custody fixture password";
const STEWARD_PASSWORD: &[u8] = b"disposable steward custody fixture password";
const COMMUNITY_PASSWORD: &[u8] = b"disposable community custody fixture password";
const DISTINCT_MAGIC: &[u8] = b"CMFD/REWARD-CUSTODY/TWO-PASSWORDS/V1\0";

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

    fn command_with_mode(&self, subcommand: &str, mode: &str) -> Command {
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
            .arg(mode);
        command
    }

    fn prepare_with_mode(&self, mode: &str) -> Command {
        let mut command = self.command_with_mode("mainnet-custody-prepare", mode);
        command
            .arg("--pow-limit")
            .arg(hex::encode(cmfd_node::RCNET1_PROFILE.pow_limit))
            .arg("--initial-target")
            .arg("000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb");
        command
    }

    fn prepare(&self) -> Command {
        self.prepare_with_mode("--distinct-passphrases-stdin")
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

fn distinct_frame(steward: &[u8], community: &[u8]) -> Vec<u8> {
    let mut frame = DISTINCT_MAGIC.to_vec();
    for password in [steward, community] {
        frame.extend_from_slice(&(password.len() as u16).to_le_bytes());
        frame.extend_from_slice(password);
    }
    frame
}

#[test]
fn cli_distinct_stdin_passwords_create_and_verify_independent_wallets() {
    let fixture = Fixture::new();
    let invalid = run(
        fixture.prepare_with_mode("--distinct-passphrases-stdin"),
        &distinct_frame(STEWARD_PASSWORD, STEWARD_PASSWORD),
    );
    assert!(!invalid.status.success());
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);

    let frame = distinct_frame(STEWARD_PASSWORD, COMMUNITY_PASSWORD);
    let output = run(
        fixture.prepare_with_mode("--distinct-passphrases-stdin"),
        &frame,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["wallets"].as_array().unwrap().len(), 2);
    assert_ne!(
        report["wallets"][0]["destination"],
        report["wallets"][1]["destination"]
    );
    let mut verify =
        fixture.command_with_mode("mainnet-custody-verify", "--distinct-passphrases-stdin");
    verify
        .arg("--expected-plan-digest")
        .arg(report["launch_plan_digest"].as_str().unwrap());
    let checked = run(verify, &frame);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert_eq!(checked.stdout, output.stdout);

    let mut wrong =
        fixture.command_with_mode("mainnet-custody-verify", "--distinct-passphrases-stdin");
    wrong
        .arg("--expected-plan-digest")
        .arg(report["launch_plan_digest"].as_str().unwrap());
    assert!(
        !run(
            wrong,
            &distinct_frame(STEWARD_PASSWORD, b"wrong community password")
        )
        .status
        .success()
    );
    for password in [STEWARD_PASSWORD, COMMUNITY_PASSWORD] {
        assert!(
            !output
                .stdout
                .windows(password.len())
                .any(|part| part == password)
        );
        assert!(
            !output
                .stderr
                .windows(password.len())
                .any(|part| part == password)
        );
    }
    assert!(!fixture.root.join("must-not-initialize").exists());
}

#[test]
fn cli_rejects_the_old_shared_password_mode_before_creating_wallets() {
    let fixture = Fixture::new();
    let output = run(
        fixture.prepare_with_mode("--shared-passphrase-stdin"),
        PASSWORD,
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
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
