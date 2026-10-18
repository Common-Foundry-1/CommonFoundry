fn main() {
    const COMMANDS: &[&str] = &[
        "get_node_status",
        "get_peer_settings",
        "update_peer_settings",
        "get_wallet_snapshot",
        "get_mempool_snapshot",
        "send_wallet_transaction",
        "consolidate_wallet",
        "mine_devnet_block",
        "get_mining_status",
        "start_mining",
        "stop_mining",
        "get_wallet_custody_status",
        "unlock_wallet",
        "lock_wallet",
        "backup_wallet",
        "create_wallet",
        "choose_wallet_backup_path",
        "migrate_wallet_encryption",
        "restore_wallet",
        "resync_chain",
        "get_update_status",
        "set_update_automatic",
        "check_for_updates",
        "download_update",
        "restart_to_update",
        "retry_update",
        "run_older_anyway",
        "remove_old_versions",
    ];

    same_commands("COMMANDS", COMMANDS, COMMANDS);

    // Handler lines name `commands::<name>` or `updater::commands::<name>`;
    // only those two exact prefixes count, so other `updater::` lines in
    // lib.rs (`updater::forward::...`) never do.
    let registered: Vec<_> = include_str!("src/lib.rs")
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("commands::")
                .or_else(|| line.strip_prefix("updater::commands::"))
        })
        .map(|command| command.trim_end_matches(','))
        .collect();
    same_commands("the invoke handler in lib.rs", &registered, COMMANDS);

    // The allow list of the wallet window, one quoted command per line.
    let wallet_permissions = include_str!("permissions/wallet-commands.toml");
    let allowed: Vec<_> = wallet_permissions
        .lines()
        .skip_while(|line| line.trim() != "commands.allow = [")
        .skip(1)
        .take_while(|line| line.trim() != "]")
        .map(|line| {
            let line = line.trim();
            line.strip_prefix('"')
                .and_then(|line| line.strip_suffix("\","))
                .unwrap_or_else(|| panic!("unexpected wallet-commands allow line {line}"))
        })
        .collect();
    same_commands("the wallet-commands permission", &allowed, COMMANDS);

    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to build the Common Foundry desktop manifest");
}

/// `found` names each command of `expected` exactly once, and nothing else.
fn same_commands(source: &str, found: &[&str], expected: &[&str]) {
    let unique: std::collections::BTreeSet<_> = found.iter().collect();
    assert_eq!(unique.len(), found.len(), "{source} names a command twice");
    let expected: std::collections::BTreeSet<_> = expected.iter().collect();
    assert_eq!(
        unique, expected,
        "{source} drifted from the desktop command inventory"
    );
}
