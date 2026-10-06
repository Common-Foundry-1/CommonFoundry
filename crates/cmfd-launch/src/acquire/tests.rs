use super::*;

fn historical() -> BeaconCertificate {
    BeaconCertificate { round: 123, signature: "b75c69d0b72a5d906e854e808ba7e2accb1542ac355ae486d591aa9d43765482e26cd02df835d3546d23c4b13e0dfc92".into() }
}
fn verify_historical(certificate: &BeaconCertificate) -> Result<AuthenticatedLaunch, LaunchError> {
    let time = crate::QUICKNET_GENESIS + 122 * crate::QUICKNET_PERIOD_SECONDS;
    crate::verify_at_time([1; 32], certificate, time, time)
}

#[test]
fn retries_bad_relays_and_publishes_only_the_verified_canonical_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("LAUNCH-BEACON.json");
    let mut seen = Vec::new();
    try_relays(
        &output,
        &AtomicBool::new(false),
        |url| {
            seen.push(url.to_owned());
            if seen.len() == 1 {
                Err(AcquireError::Timeout)
            } else if seen.len() == 2 {
                Ok(br#"{"round":123,"signature":"00"}"#.to_vec())
            } else {
                Ok(serde_json::to_vec(&historical()).unwrap())
            }
        },
        &verify_historical,
    )
    .unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen,
        RELAYS.map(|relay| { format!("{relay}/v2/beacons/quicknet/rounds/32747812") })
    );
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(parse_certificate(&bytes).unwrap(), historical());
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn old_real_beacon_never_publishes_under_the_mainnet_policy() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("beacon.json");
    let result = try_relays(
        &output,
        &AtomicBool::new(false),
        |_| Ok(serde_json::to_vec(&historical()).unwrap()),
        &|certificate| verify_mainnet_launch([1; 32], certificate, u64::MAX),
    );
    assert!(matches!(result, Err(AcquireError::Unavailable)));
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn cached_valid_beacon_is_reused_and_invalid_existing_file_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("beacon.json");
    publish(
        &output,
        &historical(),
        &AtomicBool::new(false),
        &verify_historical,
    )
    .unwrap();
    try_relays(
        &output,
        &AtomicBool::new(false),
        |_| panic!("valid cache must not download"),
        &verify_historical,
    )
    .unwrap();
    std::fs::write(&output, b"interrupted old download").unwrap();
    assert!(matches!(
        try_relays(
            &output,
            &AtomicBool::new(false),
            |_| panic!("invalid cache is not overwritten"),
            &verify_historical
        ),
        Err(AcquireError::InvalidExisting)
    ));
    assert_eq!(std::fs::read(&output).unwrap(), b"interrupted old download");
}

#[test]
fn cancellation_publishes_nothing_and_no_clobber_handles_racing_writers() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("beacon.json");
    assert!(matches!(
        publish(
            &output,
            &historical(),
            &AtomicBool::new(true),
            &verify_historical
        ),
        Err(AcquireError::Cancelled)
    ));
    assert!(!output.exists());
    publish(
        &output,
        &historical(),
        &AtomicBool::new(false),
        &verify_historical,
    )
    .unwrap();
    publish(
        &output,
        &historical(),
        &AtomicBool::new(false),
        &verify_historical,
    )
    .unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn runtime_identity_rejects_wrong_network_schedule_and_unpinned_plan() {
    let mut info = serde_json::json!({"format":"commonfoundry-mainnet-launch-info","format_version":1,"source_release_utc":SOURCE_RELEASE_UTC,"mining_start_utc":MAINNET_LAUNCH_UTC,"genesis_policy":"requires_verified_launch_beacon","beacon_round":MAINNET_BEACON_ROUND,"launch_plan":{"launch_plan_digest":"01".repeat(32)}});
    assert_eq!(
        runtime_plan_digest(&serde_json::to_vec(&info).unwrap()).unwrap(),
        [1; 32]
    );
    info["beacon_round"] = (MAINNET_BEACON_ROUND - 1).into();
    assert!(runtime_plan_digest(&serde_json::to_vec(&info).unwrap()).is_err());
    info["beacon_round"] = MAINNET_BEACON_ROUND.into();
    info["launch_plan"]["launch_plan_digest"] = "00".repeat(32).into();
    assert!(runtime_plan_digest(&serde_json::to_vec(&info).unwrap()).is_err());
}

#[test]
#[ignore = "subprocess fixture invoked by the timeout/output-bound tests"]
fn child_probe() {
    match std::env::var("CMFD_LAUNCH_TEST_CHILD")
        .unwrap_or_default()
        .as_str()
    {
        "large" => {
            let _ = io::stdout().write_all(&vec![b'x'; 64 * 1024]);
        }
        "stall" => thread::sleep(Duration::from_secs(30)),
        _ => (),
    }
}

fn probe(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "acquire::tests::child_probe",
            "--nocapture",
        ])
        .env("CMFD_LAUNCH_TEST_CHILD", mode);
    command
}

#[test]
fn output_and_deadlines_are_enforced_for_child_processes() {
    let result = bounded_output(
        &mut probe("large"),
        1024,
        Duration::from_secs(2),
        &AtomicBool::new(false),
    );
    assert!(matches!(
        result,
        Err(AcquireError::Oversized)
            | Err(AcquireError::Timeout)
            | Err(AcquireError::ProcessFailed)
    ));
    let start = Instant::now();
    assert!(matches!(
        bounded_output(
            &mut probe("stall"),
            128,
            Duration::from_millis(100),
            &AtomicBool::new(false)
        ),
        Err(AcquireError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn stop_interrupts_wait_and_live_child_without_publication() {
    let cancel = AtomicBool::new(true);
    assert!(matches!(
        wait_for(Duration::from_secs(1), &cancel),
        Err(AcquireError::Cancelled)
    ));
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let other = std::sync::Arc::clone(&cancel);
    let trigger = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        other.store(true, Ordering::Release);
    });
    let result = bounded_output(&mut probe("stall"), 128, Duration::from_secs(5), &cancel);
    trigger.join().unwrap();
    assert!(matches!(result, Err(AcquireError::Cancelled)));
}
