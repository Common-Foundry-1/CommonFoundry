#![cfg(feature = "production-v4")]

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use cmfd_node::rcnet_candidate::MainnetLaunchPlan;

#[test]
fn cli_emits_only_a_new_plan_without_opening_node_or_wallet_storage() {
    let root = std::env::temp_dir().join(format!(
        "cmfd-mainnet-plan-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let output = root.join("MAINNET-PLAN.json");
    let data = root.join("must-not-open");
    // RC public keys are fixtures only. The CLI requires both explicit values;
    // it does not approve these addresses for the actual mainnet release.
    let profile = cmfd_node::RCNET1_PROFILE;
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_cmfd-node"))
            .arg("--data-dir")
            .arg(&data)
            .arg("mainnet-plan")
            .arg("--output")
            .arg(&output)
            .arg("--pow-limit")
            .arg(hex::encode(profile.pow_limit))
            .arg("--initial-target")
            .arg("000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb")
            .arg("--steward-reward-destination")
            .arg(hex::encode(profile.rewards.steward))
            .arg("--community-reward-destination")
            .arg(hex::encode(profile.rewards.community))
            .output()
            .unwrap()
    };
    let result = invoke();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["mainnet_activation_authorized"], false);
    let digest: [u8; 32] = hex::decode(report["launch_plan_digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let bytes = fs::read(&output).unwrap();
    let plan = MainnetLaunchPlan::parse_pinned(&bytes, digest).unwrap();
    assert_eq!(
        hex::encode(plan.network_id().unwrap()),
        report["network_id"]
    );
    assert!(!data.exists());
    assert!(!invoke().status.success());
    assert_eq!(fs::read(&output).unwrap(), bytes);
    fs::remove_file(output).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn cli_has_no_implicit_mainnet_reward_destinations() {
    let output = Command::new(env!("CARGO_BIN_EXE_cmfd-node"))
        .args(["mainnet-plan", "--output", "unused.json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("--steward-reward-destination"));
    assert!(message.contains("--community-reward-destination"));
    assert!(message.contains("--pow-limit"));
    assert!(message.contains("--initial-target"));
}
