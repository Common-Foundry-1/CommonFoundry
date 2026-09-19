use std::process::Command;

#[test]
fn schedule_command_prints_the_operator_agreed_dates_and_no_activation_claim() {
    let output = Command::new(env!("CARGO_BIN_EXE_cmfd-launch"))
        .arg("schedule")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["source_release_utc"], "2026-10-02T17:00:00Z");
    assert_eq!(value["mining_start_utc"], "2026-10-03T17:00:00Z");
    assert_eq!(value["beacon_round"], 32_747_812);
    assert_eq!(value["preparation_seconds"], 86_400);
    assert_eq!(value["mainnet_activation_authorized"], false);
}

#[test]
fn verify_command_rejects_replacement_clock_and_key_arguments() {
    for option in ["--now", "--public-key", "--round", "--skip-verification"] {
        let output = Command::new(env!("CARGO_BIN_EXE_cmfd-launch"))
            .args(["verify", option, "1"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
