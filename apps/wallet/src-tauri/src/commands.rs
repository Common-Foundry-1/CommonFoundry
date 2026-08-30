use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cmfd_node::{
    DevMineRequest, DevMineResult, MempoolSnapshot, Node, NodeClientError, NodeError, NodeStatus,
    WalletConsolidateRequest, WalletConsolidateResponse, WalletSendRequest, WalletSendResponse,
    WalletSnapshot,
};
use tauri::State;
use zeroize::Zeroizing;

use crate::mining::{MiningStartRequest, MiningStatus};
use crate::runtime::{
    PeerSettings, RuntimeHandle, RuntimeState, UpdatePeerSettingsRequest, WalletCustodyStatus,
    startup_error,
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
    let passphrase = Zeroizing::new(passphrase.into_bytes());
    if (cmfd_node::wallet_backup::MINIMUM_PASSPHRASE_BYTES
        ..=cmfd_node::wallet_backup::MAXIMUM_PASSPHRASE_BYTES)
        .contains(&passphrase.len())
    {
        Ok(passphrase)
    } else {
        Err(NodeClientError {
            code: "wallet_passphrase_invalid",
            status: 400,
            retryable: false,
            message: "Wallet passphrases must contain between 12 and 1024 bytes.".to_owned(),
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
    request: WalletSendRequest,
) -> Result<WalletSendResponse, NodeClientError> {
    let node = state.node()?;
    with_node(node, move |node| node.send_from_dev_wallet_request(request)).await
}

#[tauri::command]
pub async fn consolidate_wallet(
    state: State<'_, RuntimeState>,
    request: WalletConsolidateRequest,
) -> Result<WalletConsolidateResponse, NodeClientError> {
    let node = state.node()?;
    with_node(node, move |node| {
        node.consolidate_dev_wallet_request(request)
    })
    .await
}

#[tauri::command]
pub async fn mine_devnet_block(
    state: State<'_, RuntimeState>,
    request: DevMineRequest,
) -> Result<DevMineResult, NodeClientError> {
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
pub async fn lock_wallet(
    state: State<'_, RuntimeState>,
) -> Result<WalletCustodyStatus, NodeClientError> {
    with_runtime(state.handle(), |runtime| runtime.lock()).await
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
