use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use cmfd_wallet_engine::{EngineError, WalletEngine};
#[cfg(windows)]
use rfd::FileDialog;
use tauri::{AppHandle, Manager, State, WebviewWindow};
use zeroize::Zeroizing;

use super::{
    PaymentState, PublicWalletStatus, WalletGuard, WalletState, lock_engine, lock_payments,
    wallet_operation_failed, with_engine_status,
};

const DIALOG_CANCELLED: &str = "wallet_file_picker_cancelled";
const FILE_EXTENSION: &str = "cmfd-wallet";

pub(super) fn lock_wallet_directory(directory: &Path) -> io::Result<File> {
    fs::create_dir_all(directory)?;
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::other("wallet data directory is unsafe"));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("instance.lock"))?;
    if let Err(error) = fs2::FileExt::try_lock_exclusive(&file) {
        #[cfg(windows)]
        rfd::MessageDialog::new()
            .set_title("Common Foundry Light Wallet")
            .set_description("Close the other wallet window, then try opening the wallet again.")
            .show();
        return Err(error);
    }
    Ok(file)
}

#[cfg(windows)]
fn choose_backup(window: &WebviewWindow, name: Option<&str>) -> Result<PathBuf, String> {
    let dialog = FileDialog::new().set_parent(window).add_filter(
        "Common Foundry wallet backup",
        &[FILE_EXTENSION, "cmfd-key"],
    );
    match name {
        Some(name) => dialog.set_file_name(name).save_file(),
        None => dialog.pick_file(),
    }
    .ok_or_else(|| DIALOG_CANCELLED.to_owned())
}

#[cfg(target_os = "linux")]
fn choose_backup(window: &WebviewWindow, name: Option<&str>) -> Result<PathBuf, String> {
    use gtk::prelude::{FileChooserExt, NativeDialogExt};

    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let owner = window.clone();
    let name = name.map(str::to_owned);
    window
        .run_on_main_thread(move || {
            let result = owner.gtk_window().map(|parent| {
                let (title, action, accept) = match name {
                    Some(_) => ("Save wallet backup", gtk::FileChooserAction::Save, "Save"),
                    None => ("Open wallet backup", gtk::FileChooserAction::Open, "Open"),
                };
                let dialog = gtk::FileChooserNative::new(
                    Some(title),
                    Some(&parent),
                    action,
                    Some(accept),
                    Some("Cancel"),
                );
                let filter = gtk::FileFilter::new();
                filter.set_name(Some("Common Foundry wallet backup"));
                filter.add_pattern(&format!("*.{FILE_EXTENSION}"));
                filter.add_pattern("*.cmfd-key");
                dialog.add_filter(&filter);
                if let Some(name) = &name {
                    dialog.set_current_name(name);
                }
                if dialog.run() == gtk::ResponseType::Accept {
                    dialog.filename()
                } else {
                    None
                }
            });
            let _ = send.send(result.map_err(|_| wallet_operation_failed()));
        })
        .map_err(|_| wallet_operation_failed())?;
    receive
        .recv()
        .map_err(|_| wallet_operation_failed())??
        .ok_or_else(|| DIALOG_CANCELLED.to_owned())
}

fn current_engine(state: &WalletState, epoch: u64) -> Result<WalletGuard<'_>, String> {
    let engine = lock_engine(state)?;
    if engine.acquired_epoch != epoch {
        return Err("wallet_operation_cancelled".to_owned());
    }
    Ok(engine)
}

async fn with_passphrase<T: Send + 'static>(
    app: AppHandle,
    passphrase: String,
    operation: impl FnOnce(&WalletState, u64, &[u8]) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let passphrase = Zeroizing::new(passphrase);
    let epoch = app
        .state::<WalletState>()
        .lifecycle_epoch
        .load(Ordering::Acquire);
    tauri::async_runtime::spawn_blocking(move || {
        operation(&app.state::<WalletState>(), epoch, passphrase.as_bytes())
    })
    .await
    .map_err(|_| wallet_operation_failed())?
}

#[tauri::command]
pub(super) async fn create_wallet(
    app: AppHandle,
    window: WebviewWindow,
    passphrase: String,
) -> Result<PublicWalletStatus, String> {
    with_passphrase(app, passphrase, move |state, epoch, passphrase| {
        let path = choose_backup(&window, Some("common-foundry-wallet.cmfd-wallet"))?;
        let status = current_engine(state, epoch)?
            .create_wallet(passphrase, path)
            .map_err(|_| "wallet_create_failed".to_owned())?;
        Ok(PublicWalletStatus::from_engine(status, false))
    })
    .await
}

#[tauri::command]
pub(super) async fn restore_wallet(
    app: AppHandle,
    window: WebviewWindow,
    passphrase: String,
) -> Result<PublicWalletStatus, String> {
    with_passphrase(app, passphrase, move |state, epoch, passphrase| {
        let path = choose_backup(&window, None)?;
        let status = current_engine(state, epoch)?
            .restore_wallet(passphrase, path)
            .map_err(|_| "wallet_restore_failed".to_owned())?;
        Ok(PublicWalletStatus::from_engine(status, false))
    })
    .await
}

#[tauri::command]
pub(super) async fn unlock_wallet(
    app: AppHandle,
    passphrase: String,
) -> Result<PublicWalletStatus, String> {
    with_passphrase(app, passphrase, move |state, epoch, passphrase| {
        let status = current_engine(state, epoch)?
            .unlock(passphrase)
            .map_err(|_| "wallet_unlock_failed".to_owned())?;
        Ok(PublicWalletStatus::from_engine(status, false))
    })
    .await
}

#[tauri::command]
pub(super) fn lock_wallet(
    state: State<'_, WalletState>,
    payments: State<'_, PaymentState>,
) -> Result<PublicWalletStatus, String> {
    state.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
    let status = with_engine_status(&state, false, WalletEngine::lock)?;
    lock_payments(&payments)?.clear_prepared();
    Ok(status)
}

#[tauri::command]
pub(super) async fn export_wallet(
    app: AppHandle,
    window: WebviewWindow,
    passphrase: String,
) -> Result<(), String> {
    with_passphrase(app, passphrase, move |state, epoch, passphrase| {
        let path = choose_backup(&window, Some("common-foundry-wallet-export.cmfd-wallet"))?;
        current_engine(state, epoch)?
            .export_backup_authenticated(passphrase, path)
            .map_err(|error| {
                match error {
                    EngineError::Vault(_) => "wallet_unlock_failed",
                    _ => "wallet_export_failed",
                }
                .to_owned()
            })
    })
    .await
}
