use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cmfd_node::{
    DevMineRequest, DevMineResult, MempoolSnapshot, Node, NodeClientError, NodeError, NodeStatus,
    WalletConsolidateRequest, WalletConsolidateResponse, WalletSendRequest, WalletSendResponse,
    WalletSnapshot,
};
use tauri::State;
use zeroize::Zeroizing;

use crate::address::read_address;
use crate::mining::{MiningStartRequest, MiningStatus};
use crate::runtime::{
    ChainResyncReport, PeerSettings, RuntimeHandle, RuntimeState, UpdatePeerSettingsRequest,
    WalletCustodyStatus, startup_error,
};

#[derive(serde::Deserialize)]
pub struct WalletPassphraseRequest {
    passphrase: String,
}

#[derive(serde::Deserialize)]
pub struct WalletFileRequest {
    path: String,
    passphrase: String,
}

async fn with_runtime<T, F>(handle: RuntimeHandle, operation: F) -> Result<T, NodeClientError>
where
    T: Send + 'static,
    F: FnOnce(RuntimeHandle) -> Result<T, NodeClientError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || operation(handle))
        .await
        .map_err(|_| {
            startup_error(
                "wallet_custody_worker_failed",
                "The wallet security worker stopped unexpectedly. Reopen the wallet.",
                true,
            )
        })?
}

fn request_passphrase(passphrase: String) -> Result<Zeroizing<Vec<u8>>, NodeClientError> {
    let character_count = passphrase.chars().count();
    let passphrase = Zeroizing::new(passphrase.into_bytes());
    if character_count >= 12
        && passphrase.len() <= cmfd_node::wallet_backup::MAXIMUM_PASSPHRASE_BYTES
    {
        Ok(passphrase)
    } else {
        Err(NodeClientError {
            code: "wallet_passphrase_invalid",
            status: 400,
            retryable: false,
            message: "Use a passphrase containing at least 12 characters. Shorten unusually long passphrases."
                .to_owned(),
        })
    }
}

async fn with_node<T, F>(node: Arc<Mutex<Node>>, operation: F) -> Result<T, NodeClientError>
where
    T: Send + 'static,
    F: FnOnce(&mut Node) -> Result<T, NodeError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let mut node = node.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        operation(&mut node)
    })
    .await
    .map_err(|_| {
        startup_error(
            "node_worker_failed",
            "The embedded node worker stopped unexpectedly. Reopen the wallet.",
            true,
        )
    })?
    .map_err(|error| error.client_error())
}

/// Re-encodes an address typed in either form as the hex the node's request
/// parsers take, or explains why it cannot be read.
fn address_as_hex(text: &str, code: &'static str, field: &str) -> Result<String, NodeClientError> {
    read_address(text)
        .map(hex::encode)
        .map_err(|error| NodeClientError {
            code,
            status: 400,
            retryable: false,
            message: format!("invalid {field}: {error}"),
        })
}

#[tauri::command]
pub async fn get_node_status(
    state: State<'_, RuntimeState>,
) -> Result<NodeStatus, NodeClientError> {
    let node = state.node()?;
    with_node(node, |node| node.status()).await
}

#[tauri::command]
pub async fn get_peer_settings(
    state: State<'_, RuntimeState>,
) -> Result<PeerSettings, NodeClientError> {
    state.peers()?.settings()
}

#[tauri::command]
pub async fn update_peer_settings(
    state: State<'_, RuntimeState>,
    request: UpdatePeerSettingsRequest,
) -> Result<PeerSettings, NodeClientError> {
    // Held until the settings are written, so "Restart to update" waits.
    let _operation = state.handle().begin_node_operation()?;
    let peers = state.peers()?;
    tauri::async_runtime::spawn_blocking(move || peers.update(request))
        .await
        .map_err(|_| {
            startup_error(
                "peer_settings_worker_failed",
                "The peer settings worker stopped unexpectedly. Reopen the wallet.",
                true,
            )
        })?
}

/// Removes failed peers from the recent-peer list; returns how many.
#[tauri::command]
pub async fn clear_failed_peers(state: State<'_, RuntimeState>) -> Result<usize, NodeClientError> {
    let node = state.node()?;
    with_node(node, |node| Ok(node.clear_failed_peers())).await
}

/// Runs on the main thread, where the shell call that opens the browser
/// belongs.
#[tauri::command]
pub fn open_transaction_in_explorer(txid: String) -> Result<(), NodeClientError> {
    crate::explorer::open_in_browser(&crate::explorer::transaction_url(&txid)?)
}

#[tauri::command]
pub async fn get_wallet_snapshot(
    state: State<'_, RuntimeState>,
) -> Result<WalletSnapshot, NodeClientError> {
    let node = state.node()?;
    with_node(node, |node| node.wallet_snapshot()).await
}

#[tauri::command]
pub async fn get_mempool_snapshot(
    state: State<'_, RuntimeState>,
) -> Result<MempoolSnapshot, NodeClientError> {
    let node = state.node()?;
    with_node(node, |node| Ok(node.mempool_snapshot())).await
}

#[tauri::command]
pub async fn send_wallet_transaction(
    state: State<'_, RuntimeState>,
    mut request: WalletSendRequest,
) -> Result<WalletSendResponse, NodeClientError> {
    let handle = state.handle();
    // Held until the send is over, so "Restart to update" waits for it.
    let _operation = handle.begin_node_operation()?;
    request.recipient = address_as_hex(
        &request.recipient,
        "invalid_wallet_recipient",
        "wallet recipient",
    )?;
    let node = state.node()?;
    let response = with_node(node, move |node| node.send_from_dev_wallet_request(request)).await?;
    handle.record_send(&response.txid);
    Ok(response)
}

#[tauri::command]
pub async fn consolidate_wallet(
    state: State<'_, RuntimeState>,
    request: WalletConsolidateRequest,
) -> Result<WalletConsolidateResponse, NodeClientError> {
    let handle = state.handle();
    // Held until the consolidation is over, so "Restart to update" waits.
    let _operation = handle.begin_node_operation()?;
    let node = state.node()?;
    let response = with_node(node, move |node| {
        node.consolidate_dev_wallet_request(request)
    })
    .await?;
    handle.record_send(&response.txid);
    Ok(response)
}

#[tauri::command]
pub async fn mine_devnet_block(
    state: State<'_, RuntimeState>,
    mut request: DevMineRequest,
) -> Result<DevMineResult, NodeClientError> {
    request.miner = address_as_hex(
        &request.miner,
        "invalid_miner_destination",
        "miner destination",
    )?;
    let node = state.node()?;
    with_node(node, move |node| node.mine_devnet_request(request)).await
}

#[tauri::command]
pub async fn get_mining_status(
    state: State<'_, RuntimeState>,
) -> Result<MiningStatus, NodeClientError> {
    state.mining()?.status()
}

#[tauri::command]
pub async fn start_mining(
    state: State<'_, RuntimeState>,
    request: MiningStartRequest,
) -> Result<MiningStatus, NodeClientError> {
    // Held until mining started, so "Restart to update" checks for mining
    // only once no start can still be under way.
    let _operation = state.handle().begin_node_operation()?;
    state.mining()?.start(request)
}

#[tauri::command]
pub async fn stop_mining(state: State<'_, RuntimeState>) -> Result<MiningStatus, NodeClientError> {
    let mining = state.mining()?;
    tauri::async_runtime::spawn_blocking(move || mining.stop())
        .await
        .map_err(|_| {
            startup_error(
                "mining_stop_failed",
                "The desktop mining worker could not be stopped cleanly. Reopen the wallet.",
                true,
            )
        })?
}

#[tauri::command]
pub async fn get_wallet_custody_status(
    state: State<'_, RuntimeState>,
) -> Result<WalletCustodyStatus, NodeClientError> {
    state.handle().custody_status()
}

#[tauri::command]
pub async fn unlock_wallet(
    state: State<'_, RuntimeState>,
    request: WalletPassphraseRequest,
) -> Result<WalletCustodyStatus, NodeClientError> {
    let passphrase = request_passphrase(request.passphrase)?;
    with_runtime(state.handle(), move |runtime| runtime.unlock(&passphrase)).await
}

#[tauri::command]
pub async fn resync_chain(
    state: State<'_, RuntimeState>,
) -> Result<ChainResyncReport, NodeClientError> {
    with_runtime(state.handle(), |runtime| runtime.resync_chain()).await
}

#[tauri::command]
pub async fn lock_wallet(
    state: State<'_, RuntimeState>,
) -> Result<WalletCustodyStatus, NodeClientError> {
    with_runtime(state.handle(), |runtime| runtime.lock()).await
}

#[tauri::command]
pub async fn choose_wallet_backup_path(
    window: tauri::WebviewWindow,
    restore: bool,
) -> Result<Option<String>, NodeClientError> {
    use tauri_plugin_dialog::DialogExt;
    let dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .add_filter("Common Foundry encrypted backup", &["cmfd-backup"]);
    tauri::async_runtime::spawn_blocking(move || {
        let selected = if restore {
            dialog.set_title("Open encrypted wallet backup").blocking_pick_file()
        } else {
            dialog.set_title("Save encrypted wallet backup")
                .set_file_name("wallet.cmfd-backup").blocking_save_file()
        };
        selected.map(|file| {
            let path = file.into_path().map_err(|_| startup_error(
                "backup_path_invalid", "Choose a file on a local or mounted drive.", false))?;
            if !restore && path.exists() {
                return Err(startup_error("backup_exists",
                    "That file already exists. Choose a new filename; existing backups are never overwritten.", false));
            }
            path.to_str().map(str::to_owned).ok_or_else(|| startup_error(
                "backup_path_invalid", "Choose a filename that can be displayed as Unicode.", false))
        }).transpose()
    }).await.map_err(|_| startup_error(
        "backup_picker_failed", "The file picker could not open. Please try again.", true))?
}

#[tauri::command]
pub async fn create_wallet(
    state: State<'_, RuntimeState>,
    request: WalletFileRequest,
) -> Result<WalletCustodyStatus, NodeClientError> {
    let path = PathBuf::from(request.path);
    let passphrase = request_passphrase(request.passphrase)?;
    with_runtime(state.handle(), move |runtime| {
        runtime.create(&path, &passphrase)
    })
    .await
}

#[tauri::command]
pub async fn backup_wallet(
    state: State<'_, RuntimeState>,
    request: WalletFileRequest,
) -> Result<WalletCustodyStatus, NodeClientError> {
    let path = PathBuf::from(request.path);
    let passphrase = request_passphrase(request.passphrase)?;
    with_runtime(state.handle(), move |runtime| {
        runtime.backup(&path, &passphrase)
    })
    .await
}

#[tauri::command]
pub async fn migrate_wallet_encryption(
    state: State<'_, RuntimeState>,
    request: WalletFileRequest,
) -> Result<WalletCustodyStatus, NodeClientError> {
    let path = PathBuf::from(request.path);
    let passphrase = request_passphrase(request.passphrase)?;
    with_runtime(state.handle(), move |runtime| {
        runtime.migrate(&path, &passphrase)
    })
    .await
}

#[tauri::command]
pub async fn restore_wallet(
    state: State<'_, RuntimeState>,
    request: WalletFileRequest,
) -> Result<WalletCustodyStatus, NodeClientError> {
    let path = PathBuf::from(request.path);
    let passphrase = request_passphrase(request.passphrase)?;
    with_runtime(state.handle(), move |runtime| {
        runtime.restore(&path, &passphrase)
    })
    .await
}

#[cfg(test)]
mod tests {
    use cmfd_node::address::{MAINNET_HRP, TEST_NETWORK_HRP, encode, hrp_for_network};
    use cmfd_node::{COMPILED_NETWORK_PROFILE, default_miner_destination};

    use super::{address_as_hex, request_passphrase};

    #[test]
    fn typed_addresses_reach_the_node_as_hex() {
        let key = default_miner_destination();
        let own = hrp_for_network(COMPILED_NETWORK_PROFILE.short_name());
        assert_eq!(
            address_as_hex(
                &encode(own, &key),
                "invalid_wallet_recipient",
                "wallet recipient"
            ),
            Ok(hex::encode(key))
        );
        assert_eq!(
            address_as_hex(
                &hex::encode(key),
                "invalid_wallet_recipient",
                "wallet recipient"
            ),
            Ok(hex::encode(key))
        );
        let other = if own == TEST_NETWORK_HRP {
            MAINNET_HRP
        } else {
            TEST_NETWORK_HRP
        };
        let error = address_as_hex(
            &encode(other, &key),
            "invalid_wallet_recipient",
            "wallet recipient",
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_wallet_recipient");
        assert_eq!(error.status, 400);
        assert!(
            error
                .message
                .starts_with("invalid wallet recipient: address is for another network"),
            "{}",
            error.message
        );
    }

    #[test]
    fn wallet_passphrase_minimum_counts_characters() {
        assert!(request_passphrase("é".repeat(6)).is_err());
        assert!(request_passphrase("é".repeat(12)).is_ok());
    }
}
