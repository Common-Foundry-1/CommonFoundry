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
    ];

    let registered: Vec<_> = include_str!("src/lib.rs")
        .lines()
        .filter_map(|line| line.trim().strip_prefix("commands::"))
        .map(|command| command.trim_end_matches(','))
        .collect();
    assert_eq!(
        registered.len(),
        COMMANDS.len(),
        "desktop command inventory drifted"
    );
    for command in registered {
        assert!(
            COMMANDS.contains(&command),
            "desktop manifest is missing {command}"
        );
    }
    let wallet_permissions = include_str!("permissions/wallet-commands.toml");
    for command in COMMANDS {
        let permission = format!("\"{command}\",");
        assert!(
            wallet_permissions
                .lines()
                .any(|line| line.trim() == permission),
            "wallet-commands permission does not allow registered command {command}"
        );
    }

    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to build the Common Foundry desktop manifest");
}
