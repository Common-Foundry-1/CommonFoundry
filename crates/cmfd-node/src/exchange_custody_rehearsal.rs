//! Deterministic custody crash-state rehearsal tests.
//!
//! These tests exercise exact durable states and process-reopen behavior on
//! disposable fixtures. They do not claim to simulate a physical power cut or
//! storage-controller behavior.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::exchange_custody_v3::{
    ExchangeCustodyV3Error, ExchangeCustodyV3Store, ExternalAnchorRelationshipV3, MigrationPlanV3,
    MigrationPlanV3Config, StartupReservationPhaseV3, migration_backup_paths,
};
use crate::exchange_withdrawal_v3::{
    AddIntentV3, AttachSignerPackageV3, AuthorizeReleaseV3, CancelWithdrawalV3,
    CompactTerminalRecordsV3, CompleteReleaseV3, ExactBytesV3, ExchangeWithdrawalJournalV3,
    JournalAnchorV3, JournalBindingV3, JournalTransitionV3, KeyringAnchorV3, MigrationOutputV3,
    PolicyWindowStateV3, PrepareWithdrawalV3, ReservedInputV3, ReservedOutpointV3,
    SignerPackageEvidenceV3, TerminalDecisionV3, ValidatedV2MigrationInputV3, WithdrawalActionV3,
    WithdrawalCoreV3, WithdrawalPhaseV3, migrate_validated_v2, validated_v2_snapshot_digest,
};

const JOURNAL_KEY: [u8; 32] = [0xa5; 32];
const LEGACY_VERSION: u32 = 2;
const SNAPSHOT_PREFIX: &str = "exchange-withdrawals";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize)]
struct RehearsalEvidence {
    schema: &'static str,
    simulation: &'static str,
    physical_power_cut: bool,
    migration_checkpoints: Vec<MigrationCheckpointEvidence>,
    journal_boundaries: Vec<JournalBoundaryEvidence>,
    evidence_sha256: String,
}

#[derive(Debug, Serialize)]
struct MigrationCheckpointEvidence {
    checkpoint: &'static str,
    resumed: bool,
    journal_sha256: String,
    custody_files_sha256: String,
    external_anchor_sha256: String,
    keyring_envelope_sha256: String,
    active_keyring_commitment: String,
}

#[derive(Debug, Serialize)]
struct JournalBoundaryEvidence {
    boundary: &'static str,
    pre_publish_interruption_reopened_sha256: String,
    post_publish_reopened_sha256: String,
    post_publish_anchor_relationship: &'static str,
    pinned_anchor_generation: String,
    active_keyring_commitment: String,
    keyring_envelope_sha256: String,
}

struct RehearsalDirectory {
    root: PathBuf,
    data: PathBuf,
    anchor: PathBuf,
    validated_source: PathBuf,
    journal_key: PathBuf,
}

impl RehearsalDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "cmfd-exchange-v3-rehearsal-{label}-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        let data = root.join("data");
        fs::create_dir_all(&data).expect("create disposable rehearsal directory");
        Self {
            anchor: root.join("external-anchor.json"),
            validated_source: root.join("validated-v2.bin"),
            journal_key: root.join("journal.key"),
            root,
            data,
        }
    }
}

impl Drop for RehearsalDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn marker(value: u8) -> [u8; 32] {
    [value; 32]
}

fn legacy_v2_bytes(fill: u8) -> Vec<u8> {
    let mut bytes = Vec::from(*b"CMFDEXW\0");
    bytes.extend_from_slice(&LEGACY_VERSION.to_le_bytes());
    bytes.extend_from_slice(&[fill; 96]);
    bytes
}

fn legacy_marker_bytes() -> Vec<u8> {
    let mut bytes = Vec::from(*b"CMFDEXW\0");
    bytes.extend_from_slice(&LEGACY_VERSION.to_le_bytes());
    bytes.extend_from_slice(&marker(0x72));
    bytes
}

fn write_owner_only(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).expect("write owner-only rehearsal file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("protect owner-only rehearsal file");
    }
}

fn migration_output(source: &[u8]) -> MigrationOutputV3 {
    let source_anchor = JournalAnchorV3 {
        key_id: marker(0x11),
        journal_instance_id: marker(0x12),
        generation: 7,
        commitment: marker(0x13),
    };
    migrate_validated_v2(
        ValidatedV2MigrationInputV3 {
            source_schema_version: LEGACY_VERSION,
            source_snapshot_digest: validated_v2_snapshot_digest(source),
            source_current_anchor: source_anchor,
            source_external_anchor: source_anchor,
            migration_id: marker(0x21),
            migration_decision_id: marker(0x22),
            migration_approval_digest: marker(0x23),
            binding: JournalBindingV3 {
                network_id: marker(0x31),
                consensus_fingerprint: marker(0x32),
                genesis: marker(0x33),
            },
            new_journal_instance_id: marker(0x34),
            policy_id: marker(0x35),
            initial_policy_window: PolicyWindowStateV3::default(),
            active_keyring: KeyringAnchorV3 {
                instance_id: marker(0x36),
                generation: 1,
                commitment: marker(0x37),
            },
            released_records: Vec::new(),
        },
        &JOURNAL_KEY,
    )
    .expect("construct valid v3 migration output")
}

fn install_v2_fixture(
    directory: &RehearsalDirectory,
) -> (
    MigrationPlanV3,
    MigrationOutputV3,
    BTreeMap<String, Vec<u8>>,
) {
    let source = legacy_v2_bytes(0x71);
    let second = legacy_v2_bytes(0x73);
    write_owner_only(&directory.data.join("exchange-withdrawals.0.bin"), &source);
    write_owner_only(&directory.data.join("exchange-withdrawals.1.bin"), second);
    write_owner_only(
        &directory.data.join("exchange-withdrawals.initialized"),
        legacy_marker_bytes(),
    );
    write_owner_only(
        &directory.data.join("exchange-keyring.bin"),
        b"encrypted-keyring-envelope-rehearsal-fixture",
    );
    fs::write(&directory.validated_source, &source).expect("write validated source");
    write_owner_only(&directory.journal_key, JOURNAL_KEY);
    let output = migration_output(&source);
    write_external_anchor(&directory.anchor, output.initial_anchor);
    let plan = MigrationPlanV3::from_rehearsal_fixture(
        MigrationPlanV3Config {
            data_dir: directory.data.clone(),
            journal_key_file: directory.journal_key.clone(),
            validated_v2_snapshot_file: directory.validated_source.clone(),
        },
        output.clone(),
    )
    .expect("construct rehearsal migration plan");
    let baseline = read_tree(&directory.data);
    (plan, output, baseline)
}

fn write_external_anchor(path: &Path, anchor: JournalAnchorV3) {
    let bytes = serde_json::to_vec(&json!({
        "key_id": hex::encode(anchor.key_id),
        "journal_instance_id": hex::encode(anchor.journal_instance_id),
        "generation": anchor.generation.to_string(),
        "commitment": hex::encode(anchor.commitment),
    }))
    .expect("encode external anchor");
    fs::write(path, bytes).expect("write external anchor");
}

fn read_tree(directory: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut output = BTreeMap::new();
    for entry in fs::read_dir(directory).expect("read rehearsal directory") {
        let entry = entry.expect("read rehearsal entry");
        assert!(
            entry
                .file_type()
                .expect("inspect rehearsal entry")
                .is_file()
        );
        output.insert(
            entry.file_name().to_string_lossy().into_owned(),
            fs::read(entry.path()).expect("read rehearsal file"),
        );
    }
    output
}

fn restore_tree(directory: &Path, files: &BTreeMap<String, Vec<u8>>) {
    for entry in fs::read_dir(directory).expect("read tree for reset") {
        let entry = entry.expect("read reset entry");
        if entry.file_type().expect("inspect reset entry").is_dir() {
            fs::remove_dir_all(entry.path()).expect("remove disposable reset directory");
        } else {
            fs::remove_file(entry.path()).expect("remove disposable reset file");
        }
    }
    for (name, bytes) in files {
        write_owner_only(&directory.join(name), bytes);
    }
}

fn custody_tree(directory: &Path) -> BTreeMap<String, Vec<u8>> {
    read_tree(directory)
        .into_iter()
        .filter(|(name, _)| name.starts_with(SNAPSHOT_PREFIX) || name == "exchange-keyring.bin")
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn tree_sha256(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    for (name, bytes) in files {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

fn journal_sha256(journal: &ExchangeWithdrawalJournalV3) -> String {
    sha256(
        &journal
            .encode_authenticated(&JOURNAL_KEY)
            .expect("encode authenticated journal"),
    )
}

fn open_store(
    directory: &RehearsalDirectory,
    output: &MigrationOutputV3,
) -> ExchangeCustodyV3Store {
    ExchangeCustodyV3Store::open_for_rehearsal(
        &directory.data,
        &directory.anchor,
        JOURNAL_KEY,
        output.journal.binding,
        output.journal.policy_id,
        output.journal.active_keyring,
    )
    .expect("reopen rehearsal store")
}

fn core(request_id: &str, seed: u8) -> WithdrawalCoreV3 {
    WithdrawalCoreV3 {
        request_id: request_id.to_owned(),
        request_digest: marker(seed),
        destination: marker(seed.wrapping_add(1)),
        amount_atoms: 700,
        fee_atoms: 20,
        change_atoms: 280,
        output_spendable_height: 44,
        signing_digest: marker(seed.wrapping_add(2)),
        reservations: vec![ReservedInputV3 {
            outpoint: ReservedOutpointV3 {
                txid: marker(seed.wrapping_add(3)),
                index: 0,
            },
            value_atoms: 1_000,
            wallet_key_id: marker(seed.wrapping_add(4)),
            public_key: marker(seed.wrapping_add(5)),
            signer_id: marker(seed.wrapping_add(6)),
        }],
    }
}

fn prepared_state(
    journal: &ExchangeWithdrawalJournalV3,
    request_id: &str,
    seed: u8,
) -> (
    ExchangeWithdrawalJournalV3,
    WithdrawalCoreV3,
    SignerPackageEvidenceV3,
) {
    let core = core(request_id, seed);
    let intent = journal
        .apply_transition(
            &JOURNAL_KEY,
            JournalTransitionV3::AddIntent(AddIntentV3 {
                expected_anchor: journal.anchor(&JOURNAL_KEY).expect("base anchor"),
                core: core.clone(),
            }),
        )
        .expect("add intent");
    let prepared = intent
        .apply_transition(
            &JOURNAL_KEY,
            JournalTransitionV3::Prepare(PrepareWithdrawalV3 {
                expected_anchor: intent.anchor(&JOURNAL_KEY).expect("intent anchor"),
                request_id: request_id.to_owned(),
                request_digest: core.request_digest,
            }),
        )
        .expect("prepare withdrawal");
    let package = SignerPackageEvidenceV3 {
        prepared_anchor: prepared.anchor(&JOURNAL_KEY).expect("prepared anchor"),
        keyring_anchor: journal.active_keyring,
        transaction_signing_digest: core.signing_digest,
        exact_package: ExactBytesV3::signer_package(vec![seed; 48]).expect("valid signer package"),
    };
    let attached = prepared
        .apply_transition(
            &JOURNAL_KEY,
            JournalTransitionV3::AttachSignerPackage(AttachSignerPackageV3 {
                expected_anchor: prepared.anchor(&JOURNAL_KEY).expect("prepared anchor"),
                request_id: request_id.to_owned(),
                request_digest: core.request_digest,
                signer_package: package.clone(),
            }),
        )
        .expect("attach signer package");
    (attached, core, package)
}

fn terminal(
    journal: &ExchangeWithdrawalJournalV3,
    core: &WithdrawalCoreV3,
    action: WithdrawalActionV3,
    decision_seed: u8,
) -> TerminalDecisionV3 {
    TerminalDecisionV3 {
        scope: crate::exchange_withdrawal_v3::DecisionScopeV3::NativeV3,
        action,
        decision_id: marker(decision_seed),
        approval_digest: marker(decision_seed.wrapping_add(1)),
        policy_id: journal.policy_id,
        action_anchor: journal.anchor(&JOURNAL_KEY).expect("action anchor"),
        request_digest: core.request_digest,
        transaction_signing_digest: core.signing_digest,
        decided_at_unix_seconds: u64::from(decision_seed) + 100,
        accounted_at_unix_seconds: u64::from(decision_seed) + 101,
    }
}

fn assert_normal_boundary(
    directory: &RehearsalDirectory,
    output: &MigrationOutputV3,
    base: &ExchangeWithdrawalJournalV3,
    candidate: &ExchangeWithdrawalJournalV3,
    boundary: &'static str,
    evidence: &mut Vec<JournalBoundaryEvidence>,
) {
    let base_anchor = base.anchor(&JOURNAL_KEY).expect("base anchor");
    let candidate_anchor = candidate.anchor(&JOURNAL_KEY).expect("candidate anchor");
    write_external_anchor(&directory.anchor, base_anchor);
    let before_files = custody_tree(&directory.data);
    let mut store = open_store(directory, output);
    assert_eq!(store.journal(), base);
    store.inject_next_persistence_failure();
    assert!(matches!(
        store.commit_candidate(base_anchor, candidate.clone()),
        Err(ExchangeCustodyV3Error::InjectedPersistenceFailure)
    ));
    drop(store);
    assert_eq!(custody_tree(&directory.data), before_files);

    let mut recovered = open_store(directory, output);
    assert_eq!(recovered.journal(), base);
    let pre_publish_sha256 = journal_sha256(recovered.journal());
    assert_eq!(
        recovered
            .commit_candidate(base_anchor, candidate.clone())
            .expect("publish candidate after restart"),
        candidate_anchor
    );
    drop(recovered);

    let behind = open_store(directory, output);
    assert_eq!(behind.journal(), candidate);
    assert_eq!(
        behind
            .external_anchor_relationship()
            .expect("classify post-publish anchor"),
        ExternalAnchorRelationshipV3::Descendant
    );
    let post_publish_sha256 = journal_sha256(behind.journal());
    drop(behind);
    write_external_anchor(&directory.anchor, candidate_anchor);
    let pinned = open_store(directory, output);
    assert_eq!(pinned.journal(), candidate);
    assert_eq!(
        pinned.journal().active_keyring,
        output.journal.active_keyring
    );
    assert_eq!(
        pinned
            .external_anchor_relationship()
            .expect("classify pinned anchor"),
        ExternalAnchorRelationshipV3::Current
    );
    drop(pinned);

    evidence.push(JournalBoundaryEvidence {
        boundary,
        pre_publish_interruption_reopened_sha256: pre_publish_sha256,
        post_publish_reopened_sha256: post_publish_sha256,
        post_publish_anchor_relationship: "descendant",
        pinned_anchor_generation: candidate_anchor.generation.to_string(),
        active_keyring_commitment: hex::encode(output.journal.active_keyring.commitment),
        keyring_envelope_sha256: sha256(
            &fs::read(directory.data.join("exchange-keyring.bin"))
                .expect("read unchanged keyring sentinel"),
        ),
    });
}

fn assert_authorized_completion_boundary(
    directory: &RehearsalDirectory,
    output: &MigrationOutputV3,
    base: &ExchangeWithdrawalJournalV3,
    candidate: &ExchangeWithdrawalJournalV3,
    evidence: &mut Vec<JournalBoundaryEvidence>,
) {
    let base_anchor = base.anchor(&JOURNAL_KEY).expect("authorized anchor");
    let candidate_anchor = candidate.anchor(&JOURNAL_KEY).expect("released anchor");
    write_external_anchor(&directory.anchor, base_anchor);
    let before_files = custody_tree(&directory.data);
    let mut store = open_store(directory, output);
    store.inject_next_persistence_failure();
    assert!(matches!(
        store.commit_authorized_completion(base_anchor, candidate.clone()),
        Err(ExchangeCustodyV3Error::InjectedPersistenceFailure)
    ));
    drop(store);
    assert_eq!(custody_tree(&directory.data), before_files);

    let mut recovered = open_store(directory, output);
    assert_eq!(recovered.journal(), base);
    let pre_publish_sha256 = journal_sha256(recovered.journal());
    assert_eq!(
        recovered
            .commit_authorized_completion(base_anchor, candidate.clone())
            .expect("publish authorized completion after restart"),
        candidate_anchor
    );
    drop(recovered);
    let behind = open_store(directory, output);
    assert_eq!(behind.journal(), candidate);
    assert_eq!(
        behind
            .external_anchor_relationship()
            .expect("classify released anchor"),
        ExternalAnchorRelationshipV3::Descendant
    );
    let post_publish_sha256 = journal_sha256(behind.journal());
    drop(behind);
    write_external_anchor(&directory.anchor, candidate_anchor);
    let pinned = open_store(directory, output);
    assert_eq!(pinned.journal(), candidate);
    assert!(matches!(
        pinned.journal().records["rehearsal-release"].phase,
        WithdrawalPhaseV3::Released(_)
    ));
    assert!(pinned.startup_reservations().iter().any(|reservation| {
        reservation.request_id == "rehearsal-release"
            && reservation.phase == StartupReservationPhaseV3::Released
    }));
    drop(pinned);

    evidence.push(JournalBoundaryEvidence {
        boundary: "release_completed_journal_publish",
        pre_publish_interruption_reopened_sha256: pre_publish_sha256,
        post_publish_reopened_sha256: post_publish_sha256,
        post_publish_anchor_relationship: "descendant",
        pinned_anchor_generation: candidate_anchor.generation.to_string(),
        active_keyring_commitment: hex::encode(output.journal.active_keyring.commitment),
        keyring_envelope_sha256: sha256(
            &fs::read(directory.data.join("exchange-keyring.bin"))
                .expect("read unchanged keyring sentinel"),
        ),
    });
}

#[test]
fn deterministic_crash_recovery_matrix_emits_checksum_evidence() {
    let migration_directory = RehearsalDirectory::new("migration");
    let (migration_plan, migration_output, v2_baseline) = install_v2_fixture(&migration_directory);
    let first_apply = migration_plan
        .apply_for_rehearsal()
        .expect("complete golden migration");
    assert!(!first_apply.resumed);
    let golden = custody_tree(&migration_directory.data);
    let backup_names: Vec<String> = migration_backup_paths(
        &migration_directory.data,
        migration_output.receipt.migration_id,
    )
    .into_iter()
    .map(|path| {
        path.file_name()
            .expect("backup file name")
            .to_string_lossy()
            .into_owned()
    })
    .collect();
    let slot_zero = "exchange-withdrawals.0.bin";
    let slot_one = "exchange-withdrawals.1.bin";
    let marker_name = "exchange-withdrawals.v3.initialized";
    let checkpoints: [(&str, &[&str]); 7] = [
        ("before_first_migration_write", &[]),
        ("after_v2_slot0_backup", &[backup_names[0].as_str()]),
        (
            "after_v2_slot1_backup",
            &[backup_names[0].as_str(), backup_names[1].as_str()],
        ),
        (
            "after_legacy_marker_backup",
            &[
                backup_names[0].as_str(),
                backup_names[1].as_str(),
                backup_names[2].as_str(),
            ],
        ),
        (
            "after_v3_slot0_replace",
            &[
                backup_names[0].as_str(),
                backup_names[1].as_str(),
                backup_names[2].as_str(),
                slot_zero,
            ],
        ),
        (
            "after_v3_slot1_replace",
            &[
                backup_names[0].as_str(),
                backup_names[1].as_str(),
                backup_names[2].as_str(),
                slot_zero,
                slot_one,
            ],
        ),
        (
            "after_v3_activation_marker",
            &[
                backup_names[0].as_str(),
                backup_names[1].as_str(),
                backup_names[2].as_str(),
                slot_zero,
                slot_one,
                marker_name,
            ],
        ),
    ];
    let mut migration_evidence = Vec::new();
    for (checkpoint, overlays) in checkpoints {
        restore_tree(&migration_directory.data, &v2_baseline);
        for name in overlays {
            write_owner_only(
                &migration_directory.data.join(name),
                golden.get(*name).expect("golden checkpoint artifact"),
            );
        }
        let applied = migration_plan
            .apply_for_rehearsal()
            .expect("resume migration checkpoint");
        assert_eq!(custody_tree(&migration_directory.data), golden);
        let reopened = open_store(&migration_directory, &migration_output);
        assert_eq!(reopened.journal(), &migration_output.journal);
        assert_eq!(
            reopened.current_anchor().unwrap(),
            migration_output.initial_anchor
        );
        assert_eq!(
            reopened.journal().active_keyring,
            migration_output.journal.active_keyring
        );
        drop(reopened);
        migration_evidence.push(MigrationCheckpointEvidence {
            checkpoint,
            resumed: applied.resumed,
            journal_sha256: journal_sha256(&migration_output.journal),
            custody_files_sha256: tree_sha256(&golden),
            external_anchor_sha256: sha256(
                &fs::read(&migration_directory.anchor).expect("read external anchor"),
            ),
            keyring_envelope_sha256: sha256(
                &fs::read(migration_directory.data.join("exchange-keyring.bin"))
                    .expect("read keyring sentinel"),
            ),
            active_keyring_commitment: hex::encode(
                migration_output.journal.active_keyring.commitment,
            ),
        });
    }

    let journal_directory = RehearsalDirectory::new("journal");
    let (journal_plan, journal_output, _) = install_v2_fixture(&journal_directory);
    journal_plan
        .apply_for_rehearsal()
        .expect("install journal rehearsal fixture");
    let mut boundaries = Vec::new();

    let initial = journal_output.journal.clone();
    let (prepared_release, release_core, package) =
        prepared_state(&initial, "rehearsal-release", 0x51);
    {
        let mut store = open_store(&journal_directory, &journal_output);
        store
            .commit_candidate(
                initial.anchor(&JOURNAL_KEY).unwrap(),
                prepared_release.clone(),
            )
            .expect("persist release preparation");
    }
    write_external_anchor(
        &journal_directory.anchor,
        prepared_release.anchor(&JOURNAL_KEY).unwrap(),
    );
    let release_terminal = terminal(
        &prepared_release,
        &release_core,
        WithdrawalActionV3::Release,
        0x61,
    );
    let authorized = prepared_release
        .apply_transition(
            &JOURNAL_KEY,
            JournalTransitionV3::AuthorizeRelease(AuthorizeReleaseV3 {
                expected_anchor: prepared_release.anchor(&JOURNAL_KEY).unwrap(),
                request_id: release_core.request_id.clone(),
                request_digest: release_core.request_digest,
                terminal: release_terminal,
            }),
        )
        .expect("build release authorization");
    assert_normal_boundary(
        &journal_directory,
        &journal_output,
        &prepared_release,
        &authorized,
        "release_authorized_journal_publish",
        &mut boundaries,
    );
    let released = authorized
        .apply_transition(
            &JOURNAL_KEY,
            JournalTransitionV3::CompleteRelease(CompleteReleaseV3 {
                expected_anchor: authorized.anchor(&JOURNAL_KEY).unwrap(),
                request_id: release_core.request_id.clone(),
                request_digest: release_core.request_digest,
                decision_id: release_terminal.decision_id,
                approval_digest: release_terminal.approval_digest,
                signer_package_digest: package.exact_package.digest,
                transaction_signing_digest: release_core.signing_digest,
                txid: marker(0x63),
                exact_transaction_bytes: vec![0x64; 64],
            }),
        )
        .expect("build released state");
    assert_authorized_completion_boundary(
        &journal_directory,
        &journal_output,
        &authorized,
        &released,
        &mut boundaries,
    );

    let (prepared_cancel, cancel_core, _) = prepared_state(&released, "rehearsal-cancel", 0x71);
    {
        let mut store = open_store(&journal_directory, &journal_output);
        store
            .commit_candidate(
                released.anchor(&JOURNAL_KEY).unwrap(),
                prepared_cancel.clone(),
            )
            .expect("persist cancel preparation");
    }
    write_external_anchor(
        &journal_directory.anchor,
        prepared_cancel.anchor(&JOURNAL_KEY).unwrap(),
    );
    let cancel_terminal = terminal(
        &prepared_cancel,
        &cancel_core,
        WithdrawalActionV3::Cancel,
        0x72,
    );
    let canceled = prepared_cancel
        .apply_transition(
            &JOURNAL_KEY,
            JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                expected_anchor: prepared_cancel.anchor(&JOURNAL_KEY).unwrap(),
                request_id: cancel_core.request_id.clone(),
                request_digest: cancel_core.request_digest,
                terminal: cancel_terminal,
            }),
        )
        .expect("build canceled state");
    assert_normal_boundary(
        &journal_directory,
        &journal_output,
        &prepared_cancel,
        &canceled,
        "cancel_journal_publish",
        &mut boundaries,
    );
    let after_cancel = open_store(&journal_directory, &journal_output);
    assert!(
        after_cancel
            .startup_reservations()
            .iter()
            .all(|reservation| reservation.request_id != cancel_core.request_id)
    );
    drop(after_cancel);

    let canceled_anchor = canceled.anchor(&JOURNAL_KEY).unwrap();
    let prune = canceled
        .archive_prune_record(&JOURNAL_KEY, &cancel_core.request_id, 0)
        .expect("derive compaction record");
    let compacted = canceled
        .apply_transition(
            &JOURNAL_KEY,
            JournalTransitionV3::Compact(CompactTerminalRecordsV3 {
                expected_anchor: canceled_anchor,
                archive_source_anchor: canceled_anchor,
                archive_id: marker(0x75),
                records: vec![prune],
            }),
        )
        .expect("build compacted state");
    let proposed_anchor = journal_directory
        .root
        .join("compacted-anchor.proposed.json");
    write_external_anchor(&proposed_anchor, compacted.anchor(&JOURNAL_KEY).unwrap());
    let proposed_sha256 = sha256(&fs::read(&proposed_anchor).expect("read proposed anchor"));
    let unchanged = open_store(&journal_directory, &journal_output);
    assert_eq!(unchanged.journal(), &canceled);
    drop(unchanged);
    assert_normal_boundary(
        &journal_directory,
        &journal_output,
        &canceled,
        &compacted,
        "compaction_journal_publish_after_proposed_anchor",
        &mut boundaries,
    );
    let after_compaction = open_store(&journal_directory, &journal_output);
    assert!(
        !after_compaction
            .journal()
            .records
            .contains_key(&cancel_core.request_id)
    );
    assert_eq!(after_compaction.journal().tombstones.len(), 1);
    assert!(
        after_compaction
            .startup_reservations()
            .iter()
            .all(|reservation| reservation.request_id != cancel_core.request_id)
    );
    drop(after_compaction);
    assert_eq!(
        sha256(&fs::read(&proposed_anchor).expect("reread proposed anchor")),
        proposed_sha256
    );

    let mut report = RehearsalEvidence {
        schema: "common-foundry-exchange-custody-crash-rehearsal-v1",
        simulation: "deterministic reconstructed durable checkpoints plus injected pre-publish failures",
        physical_power_cut: false,
        migration_checkpoints: migration_evidence,
        journal_boundaries: boundaries,
        evidence_sha256: String::new(),
    };
    let unsigned = serde_json::to_vec(&report).expect("encode rehearsal evidence");
    report.evidence_sha256 = sha256(&unsigned);
    let encoded = serde_json::to_string(&report).expect("encode final rehearsal evidence");
    let decoded: serde_json::Value = serde_json::from_str(&encoded).expect("decode evidence");
    assert_eq!(decoded["physical_power_cut"], false);
    assert_eq!(
        decoded["migration_checkpoints"].as_array().unwrap().len(),
        7
    );
    assert_eq!(decoded["journal_boundaries"].as_array().unwrap().len(), 4);
    println!("CMFD_EXCHANGE_CUSTODY_REHEARSAL_EVIDENCE={encoded}");
}
