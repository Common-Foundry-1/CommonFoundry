use super::*;

const STEWARD_PASSWORD: &[u8] = b"disposable steward test passphrase";
const COMMUNITY_PASSWORD: &[u8] = b"disposable community test passphrase";

struct Fixture {
    root: PathBuf,
    paths: RewardCustodyPaths,
}

impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!("cmfd-reward-custody-{}", hex::encode(nonce)));
        create_directory(&root).unwrap();
        let steward_passphrase_file = root.join("steward.passphrase");
        let community_passphrase_file = root.join("community.passphrase");
        write_new(&steward_passphrase_file, STEWARD_PASSWORD, true).unwrap();
        write_new(&community_passphrase_file, COMMUNITY_PASSWORD, true).unwrap();
        Self {
            paths: RewardCustodyPaths {
                wallets_directory: root.join("wallets"),
                backups_directory: root.join("backups"),
                public_directory: root.join("public"),
                steward_passphrase_file,
                community_passphrase_file,
            },
            root,
        }
    }

    fn prepare(&self) -> RewardCustodyReport {
        prepare_reward_custody(
            &self.paths,
            crate::RCNET1_PROFILE.pow_limit,
            hex::decode("000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap()
    }

    fn no_outputs(&self) {
        for path in [
            &self.paths.wallets_directory,
            &self.paths.backups_directory,
            &self.paths.public_directory,
        ] {
            assert!(!path.exists(), "unexpected output: {path:?}");
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn digest(report: &RewardCustodyReport) -> [u8; 32] {
    hex::decode(&report.launch_plan_digest)
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn community_replacement_retains_steward_and_rebinds_encrypted_custody() {
    let original = Fixture::new();
    let previous = original.prepare();
    let input = original.paths.backups_directory.join("steward.cmfdwallet");
    let original_bytes = fs::read(&input).unwrap();
    let old_community = fs::read(
        original
            .paths
            .wallets_directory
            .join("community/wallet.key"),
    )
    .unwrap();
    let source = CommunityReplacementSource {
        steward_backup: input.clone(),
        expected_steward_backup_sha256: Sha256::digest(&original_bytes).into(),
        plan: original.paths.public_directory.join(PLAN_FILE),
        expected_plan_digest: digest(&previous),
    };
    let replacement = Fixture::new();
    let new_password = b"disposable replacement community password";
    let report = replace_community_with_distinct_passwords(
        &replacement.paths,
        &source,
        STEWARD_PASSWORD,
        new_password,
    )
    .unwrap();
    assert!(report.retained_steward_key_verified);
    assert!(!report.original_files_changed);
    assert_eq!(
        report.custody.wallets[0].destination,
        previous.wallets[0].destination
    );
    assert_ne!(
        report.custody.wallets[1].destination,
        previous.wallets[1].destination
    );
    assert_ne!(report.custody.network_id, previous.network_id);
    assert_ne!(
        report.custody.launch_plan_digest,
        previous.launch_plan_digest
    );
    assert_eq!(fs::read(&input).unwrap(), original_bytes);
    assert_eq!(
        fs::read(
            original
                .paths
                .wallets_directory
                .join("community/wallet.key")
        )
        .unwrap(),
        old_community
    );
    let mut old_plan: serde_json::Value =
        serde_json::from_slice(&fs::read(&source.plan).unwrap()).unwrap();
    let new_plan: serde_json::Value = serde_json::from_slice(
        &fs::read(replacement.paths.public_directory.join(PLAN_FILE)).unwrap(),
    )
    .unwrap();
    old_plan["payload"]["rules"]["reward_destinations"]["community_xonly_public_key"] =
        new_plan["payload"]["rules"]["reward_destinations"]["community_xonly_public_key"].clone();
    assert_eq!(old_plan["payload"], new_plan["payload"]);
    verify_reward_custody_with_distinct_passwords(
        &replacement.paths,
        digest(&report.custody),
        STEWARD_PASSWORD,
        new_password,
    )
    .unwrap();
    let saved = fs::read(
        replacement
            .paths
            .backups_directory
            .join("steward.cmfdwallet"),
    )
    .unwrap();
    let new_network: [u8; 32] = hex::decode(&report.custody.network_id)
        .unwrap()
        .try_into()
        .unwrap();
    let old_network: [u8; 32] = hex::decode(&previous.network_id)
        .unwrap()
        .try_into()
        .unwrap();
    let (old_key, _) =
        wallet_backup::decrypt_wallet_key_bytes(&original_bytes, old_network, STEWARD_PASSWORD)
            .unwrap();
    let (new_key, _) =
        wallet_backup::decrypt_wallet_key_bytes(&saved, new_network, STEWARD_PASSWORD).unwrap();
    assert_eq!(*old_key, *new_key);
    assert!(
        wallet_backup::decrypt_wallet_key_bytes(&saved, old_network, STEWARD_PASSWORD).is_err()
    );
    assert!(
        replace_community_with_distinct_passwords(
            &replacement.paths,
            &source,
            STEWARD_PASSWORD,
            new_password
        )
        .is_err()
    );
}

#[test]
fn community_replacement_rejects_wrong_password_pins_and_steward_identity_before_outputs() {
    let original = Fixture::new();
    let previous = original.prepare();
    let input = original.paths.backups_directory.join("steward.cmfdwallet");
    let mut source = CommunityReplacementSource {
        steward_backup: input.clone(),
        expected_steward_backup_sha256: Sha256::digest(fs::read(&input).unwrap()).into(),
        plan: original.paths.public_directory.join(PLAN_FILE),
        expected_plan_digest: digest(&previous),
    };
    let fresh = Fixture::new();
    let replacement_password = b"disposable replacement community password";
    assert!(
        replace_community_with_distinct_passwords(
            &fresh.paths,
            &source,
            b"incorrect existing steward password",
            replacement_password
        )
        .is_err()
    );
    fresh.no_outputs();
    assert!(
        replace_community_with_distinct_passwords(
            &fresh.paths,
            &source,
            STEWARD_PASSWORD,
            STEWARD_PASSWORD
        )
        .is_err()
    );
    fresh.no_outputs();
    source.expected_steward_backup_sha256[0] ^= 1;
    assert!(
        replace_community_with_distinct_passwords(
            &fresh.paths,
            &source,
            STEWARD_PASSWORD,
            replacement_password
        )
        .is_err()
    );
    fresh.no_outputs();
    source.expected_steward_backup_sha256[0] ^= 1;
    source.expected_plan_digest[0] ^= 1;
    assert!(
        replace_community_with_distinct_passwords(
            &fresh.paths,
            &source,
            STEWARD_PASSWORD,
            replacement_password
        )
        .is_err()
    );
    fresh.no_outputs();
    source.expected_plan_digest[0] ^= 1;
    source.steward_backup = original
        .paths
        .backups_directory
        .join("community.cmfdwallet");
    source.expected_steward_backup_sha256 =
        Sha256::digest(fs::read(&source.steward_backup).unwrap()).into();
    assert!(
        replace_community_with_distinct_passwords(
            &fresh.paths,
            &source,
            COMMUNITY_PASSWORD,
            replacement_password
        )
        .is_err()
    );
    fresh.no_outputs();
}

#[test]
fn distinct_in_memory_passwords_protect_the_two_wallets_separately() {
    let mut fixture = Fixture::new();
    fixture.paths.steward_passphrase_file = fixture.root.join("unused-steward-password");
    fixture.paths.community_passphrase_file = fixture.root.join("unused-community-password");
    let initial_target =
        hex::decode("000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb")
            .unwrap()
            .try_into()
            .unwrap();
    assert!(
        prepare_reward_custody_with_distinct_passwords(
            &fixture.paths,
            crate::RCNET1_PROFILE.pow_limit,
            initial_target,
            STEWARD_PASSWORD,
            STEWARD_PASSWORD,
        )
        .is_err()
    );
    fixture.no_outputs();

    let prepared = prepare_reward_custody_with_distinct_passwords(
        &fixture.paths,
        crate::RCNET1_PROFILE.pow_limit,
        initial_target,
        STEWARD_PASSWORD,
        COMMUNITY_PASSWORD,
    )
    .unwrap();
    let verified = verify_reward_custody_with_distinct_passwords(
        &fixture.paths,
        digest(&prepared),
        STEWARD_PASSWORD,
        COMMUNITY_PASSWORD,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&prepared).unwrap(),
        serde_json::to_vec(&verified).unwrap()
    );
    assert!(
        verify_reward_custody_with_distinct_passwords(
            &fixture.paths,
            digest(&prepared),
            STEWARD_PASSWORD,
            b"wrong community fixture password",
        )
        .is_err()
    );
    assert!(!fixture.paths.steward_passphrase_file.exists());
    assert!(!fixture.paths.community_passphrase_file.exists());
    let network: [u8; 32] = hex::decode(&prepared.network_id)
        .unwrap()
        .try_into()
        .unwrap();
    for (index, (role, password)) in ROLES
        .iter()
        .zip([STEWARD_PASSWORD, COMMUNITY_PASSWORD])
        .enumerate()
    {
        let restored = fixture.root.join(format!("distinct-restored-{role}"));
        create_directory(&restored).unwrap();
        let info = wallet_backup::restore_encrypted_wallet_backup(
            &fixture
                .paths
                .backups_directory
                .join(format!("{role}.cmfdwallet")),
            &restored,
            network,
            password,
        )
        .unwrap();
        assert_eq!(
            hex::encode(info.destination),
            prepared.wallets[index].destination
        );
    }
}

#[test]
fn protected_password_files_must_not_contain_the_same_password() {
    let fixture = Fixture::new();
    fs::write(&fixture.paths.community_passphrase_file, STEWARD_PASSWORD).unwrap();
    let error = prepare_reward_custody(
        &fixture.paths,
        crate::RCNET1_PROFILE.pow_limit,
        hex::decode("000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("passwords must differ"));
    fixture.no_outputs();
}

#[test]
fn fresh_keys_plan_backups_and_standard_restore_agree_without_activation() {
    let fixture = Fixture::new();
    let report = fixture.prepare();
    let plan_digest = digest(&report);
    let verified = verify_reward_custody(&fixture.paths, plan_digest).unwrap();
    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&verified).unwrap()
    );
    assert!(report.backups_authenticated);
    assert!(!report.mainnet_activation_authorized);
    assert_ne!(report.wallets[0].destination, report.wallets[1].destination);
    let network = hex::decode(&report.network_id).unwrap().try_into().unwrap();
    assert_ne!(network, crate::RCNET1_PROFILE.network_id);
    let plan_bytes = fs::read(fixture.paths.public_directory.join(PLAN_FILE)).unwrap();
    let plan = MainnetLaunchPlan::parse_pinned(&plan_bytes, plan_digest).unwrap();
    assert_eq!(plan.network_id().unwrap(), network);
    let public = fs::read(fixture.paths.public_directory.join(REPORT_FILE)).unwrap();
    assert!(!String::from_utf8_lossy(&public).contains("passphrase"));
    assert!(!String::from_utf8_lossy(&public).contains(&fixture.root.display().to_string()));
    for (index, (role, password)) in ROLES
        .iter()
        .zip([STEWARD_PASSWORD, COMMUNITY_PASSWORD])
        .enumerate()
    {
        let restored = fixture.root.join(format!("restored-{role}"));
        create_directory(&restored).unwrap();
        let info = wallet_backup::restore_encrypted_wallet_backup(
            &fixture
                .paths
                .backups_directory
                .join(format!("{role}.cmfdwallet")),
            &restored,
            network,
            password,
        )
        .unwrap();
        assert_eq!(
            hex::encode(info.destination),
            report.wallets[index].destination
        );
        assert_eq!(
            wallet_backup::authenticate_encrypted_wallet(&restored, network, password).unwrap(),
            info.destination
        );
        assert!(!restored.join(crate::METADATA_FILE).exists());
        assert_ne!(
            report.wallets[index].encrypted_wallet_sha256,
            report.wallets[index].encrypted_backup_sha256
        );
    }
    assert!(
        !fixture
            .paths
            .wallets_directory
            .join(INCOMPLETE_FILE)
            .exists()
    );
    // The only shareable artifacts are public JSON, never encrypted keys/passwords.
    assert_eq!(
        fs::read_dir(&fixture.paths.public_directory)
            .unwrap()
            .count(),
        2
    );
    assert!(matches!(
        prepare_reward_custody(
            &fixture.paths,
            crate::RCNET1_PROFILE.pow_limit,
            crate::RCNET1_PROFILE.pow_limit
        ),
        Err(RewardCustodyError::Exists(_))
    ));
    assert_eq!(
        fs::read(fixture.paths.public_directory.join(PLAN_FILE)).unwrap(),
        plan_bytes
    );
}

#[test]
fn invalid_targets_and_passwords_do_not_create_any_outputs() {
    let fixture = Fixture::new();
    let limit = crate::RCNET1_PROFILE.pow_limit;
    for (maximum, initial) in [([0; 32], limit), (limit, [0; 32]), (limit, [0xff; 32])] {
        assert!(prepare_reward_custody(&fixture.paths, maximum, initial).is_err());
        fixture.no_outputs();
    }
    fs::write(&fixture.paths.community_passphrase_file, b"too short").unwrap();
    assert!(prepare_reward_custody(&fixture.paths, limit, limit).is_err());
    fixture.no_outputs();
    fs::write(
        &fixture.paths.community_passphrase_file,
        vec![b'x'; MAXIMUM_PASSPHRASE_BYTES + 4],
    )
    .unwrap();
    assert!(prepare_reward_custody(&fixture.paths, limit, limit).is_err());
    fixture.no_outputs();
}

#[test]
fn unsafe_paths_and_existing_files_are_rejected_before_key_creation() {
    let mut fixture = Fixture::new();
    let original = fixture.paths.wallets_directory.clone();
    fixture.paths.wallets_directory = PathBuf::from("relative");
    assert!(directories(&fixture.paths, true).is_err());
    fixture.paths.wallets_directory = fixture.paths.public_directory.clone();
    assert!(directories(&fixture.paths, true).is_err());
    fixture.paths.wallets_directory = original;
    write_new(
        &fixture.paths.wallets_directory,
        b"leave this operator file untouched",
        false,
    )
    .unwrap();
    assert!(directories(&fixture.paths, true).is_err());
    assert_eq!(
        fs::read(&fixture.paths.wallets_directory).unwrap(),
        b"leave this operator file untouched"
    );
    fs::remove_file(&fixture.paths.wallets_directory).unwrap();
    create_directory(&fixture.root.join(".git")).unwrap();
    assert!(matches!(
        directories(&fixture.paths, true),
        Err(RewardCustodyError::Path(_))
    ));
    fixture.no_outputs();
}

#[test]
fn verify_rejects_wrong_digest_password_tampering_incomplete_setup_and_active_wallet() {
    let fixture = Fixture::new();
    let report = fixture.prepare();
    let pin = digest(&report);
    assert!(verify_reward_custody(&fixture.paths, [0x44; 32]).is_err());
    fs::write(
        &fixture.paths.steward_passphrase_file,
        b"wrong but long enough password",
    )
    .unwrap();
    assert!(verify_reward_custody(&fixture.paths, pin).is_err());
    fs::write(&fixture.paths.steward_passphrase_file, STEWARD_PASSWORD).unwrap();
    let marker = fixture.paths.wallets_directory.join(INCOMPLETE_FILE);
    fs::write(&marker, b"partial operator attempt").unwrap();
    assert!(verify_reward_custody(&fixture.paths, pin).is_err());
    fs::remove_file(marker).unwrap();
    let lock = DataDirLock::acquire(&fixture.paths.wallets_directory.join(ROLES[0])).unwrap();
    assert!(verify_reward_custody(&fixture.paths, pin).is_err());
    drop(lock);
    let backup = fixture.paths.backups_directory.join("steward.cmfdwallet");
    let original = fs::read(&backup).unwrap();
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&backup, corrupt).unwrap();
    assert!(verify_reward_custody(&fixture.paths, pin).is_err());
    fs::write(&backup, &original).unwrap();
    let manifest = fixture.paths.public_directory.join(REPORT_FILE);
    let bytes = fs::read(&manifest).unwrap();
    let altered = String::from_utf8(bytes.clone()).unwrap().replace(
        "\"mainnet_activation_authorized\": false",
        "\"mainnet_activation_authorized\": true",
    );
    fs::write(&manifest, altered).unwrap();
    assert!(verify_reward_custody(&fixture.paths, pin).is_err());
    fs::write(manifest, bytes).unwrap();
    assert!(verify_reward_custody(&fixture.paths, pin).is_ok());
}

#[test]
fn private_material_is_permission_restricted_and_duplicate_backup_ciphertext_is_refused() {
    let fixture = Fixture::new();
    let report = fixture.prepare();
    for role in ROLES {
        let live = fixture
            .paths
            .wallets_directory
            .join(role)
            .join(WALLET_KEY_FILE);
        let backup = fixture
            .paths
            .backups_directory
            .join(format!("{role}.cmfdwallet"));
        open_read(&live, true).unwrap();
        open_read(&backup, true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&live).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    fs::copy(
        fixture
            .paths
            .wallets_directory
            .join("steward")
            .join(WALLET_KEY_FILE),
        fixture.paths.backups_directory.join("steward.cmfdwallet"),
    )
    .unwrap();
    assert!(verify_reward_custody(&fixture.paths, digest(&report)).is_err());
}

#[cfg(unix)]
#[test]
fn passphrase_symlinks_and_broad_permissions_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    let target = fixture.root.join("target.passphrase");
    fs::rename(&fixture.paths.steward_passphrase_file, &target).unwrap();
    symlink(&target, &fixture.paths.steward_passphrase_file).unwrap();
    assert!(
        passphrase(
            &fixture.paths.steward_passphrase_file,
            &directories(&fixture.paths, true).unwrap()
        )
        .is_err()
    );
    fs::remove_file(&fixture.paths.steward_passphrase_file).unwrap();
    fs::rename(target, &fixture.paths.steward_passphrase_file).unwrap();
    fs::set_permissions(
        &fixture.paths.steward_passphrase_file,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(
        passphrase(
            &fixture.paths.steward_passphrase_file,
            &directories(&fixture.paths, true).unwrap()
        )
        .is_err()
    );
    fixture.no_outputs();
}
