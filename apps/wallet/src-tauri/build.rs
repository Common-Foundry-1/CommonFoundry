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

    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to build the Common Foundry desktop manifest");
}
