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
    ];

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
