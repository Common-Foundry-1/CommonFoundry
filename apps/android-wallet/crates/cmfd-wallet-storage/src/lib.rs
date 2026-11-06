//! Fail-closed persistence for encrypted Common Foundry wallet artifacts.
//!
//! The live wallet file lives in a dedicated application-private directory.
//! Creation persists and fsyncs the user-selected recovery backup first, then
//! creates the live file. Every write uses create-new semantics and therefore
//! refuses to replace an existing wallet or backup.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cmfd_wallet_core::backup::{ENCRYPTED_BACKUP_BYTES, EncryptedBackup, WalletBackupError};
use cmfd_wallet_core::vault::CreatedWallet;
use thiserror::Error;

pub const LIVE_WALLET_FILENAME: &str = "wallet.cmfd-key";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("wallet storage path already exists; refusing to overwrite it")]
    AlreadyExists,
    #[error("wallet storage path is missing")]
    NotFound,
    #[error("wallet storage path is not a safe regular file or directory")]
    UnsafePath,
    #[error("wallet storage I/O failed")]
    Io,
    #[error("wallet file is corrupt or unsupported")]
    InvalidWallet,
}

impl From<WalletBackupError> for StorageError {
    fn from(_: WalletBackupError) -> Self {
        Self::InvalidWallet
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWalletStore {
    private_directory: PathBuf,
}

impl NativeWalletStore {
    /// `private_directory` must be an app-owned directory, never shared storage.
    pub fn new(private_directory: impl Into<PathBuf>) -> Self {
        Self {
            private_directory: private_directory.into(),
        }
    }

    pub fn live_wallet_path(&self) -> PathBuf {
        self.private_directory.join(LIVE_WALLET_FILENAME)
    }

    pub fn has_live_wallet(&self) -> Result<bool, StorageError> {
        match fs::symlink_metadata(self.live_wallet_path()) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    Err(StorageError::UnsafePath)
                } else {
                    Ok(true)
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(StorageError::Io),
        }
    }

    pub fn load_live_wallet(&self) -> Result<EncryptedBackup, StorageError> {
        read_encrypted_file(&self.live_wallet_path())
    }

    pub fn read_recovery_backup(
        &self,
        backup_path: impl AsRef<Path>,
    ) -> Result<EncryptedBackup, StorageError> {
        read_encrypted_file(backup_path.as_ref())
    }

    /// Exports a new encrypted recovery artifact without replacing any file.
    pub fn write_recovery_backup(
        &self,
        backup_path: impl AsRef<Path>,
        encrypted_backup: &EncryptedBackup,
    ) -> Result<(), StorageError> {
        write_new_encrypted_file(backup_path.as_ref(), encrypted_backup)
    }

    /// Makes a new wallet usable only after its independent recovery backup is
    /// durably written. Existing live wallets and backup paths are never replaced.
    pub fn install_created_wallet(
        &self,
        created: &CreatedWallet,
        recovery_path: impl AsRef<Path>,
    ) -> Result<(), StorageError> {
        self.prepare_private_directory()?;
        if self.has_live_wallet()? {
            return Err(StorageError::AlreadyExists);
        }
        write_new_encrypted_file(recovery_path.as_ref(), &created.recovery_backup)?;
        write_new_encrypted_file(&self.live_wallet_path(), &created.live_key)
    }

    /// Installs a freshly re-encrypted live key after a backup was authenticated.
    /// The caller must not pass the original recovery blob directly.
    pub fn install_restored_live_wallet(
        &self,
        reencrypted_live_key: &EncryptedBackup,
    ) -> Result<(), StorageError> {
        self.prepare_private_directory()?;
        write_new_encrypted_file(&self.live_wallet_path(), reencrypted_live_key)
    }

    fn prepare_private_directory(&self) -> Result<(), StorageError> {
        match fs::symlink_metadata(&self.private_directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(StorageError::UnsafePath);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.private_directory).map_err(|_| StorageError::Io)?;
            }
            Err(_) => return Err(StorageError::Io),
        }
        set_private_directory_permissions(&self.private_directory)?;
        Ok(())
    }
}

fn read_encrypted_file(path: &Path) -> Result<EncryptedBackup, StorageError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StorageError::NotFound
        } else {
            StorageError::Io
        }
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(StorageError::UnsafePath);
    }
    let mut file = open_read_without_symlinks(path)?;
    let opened_metadata = file.metadata().map_err(|_| StorageError::Io)?;
    if !opened_metadata.is_file() || opened_metadata.len() != ENCRYPTED_BACKUP_BYTES as u64 {
        return Err(StorageError::UnsafePath);
    }
    let mut bytes = vec![0_u8; ENCRYPTED_BACKUP_BYTES];
    file.read_exact(&mut bytes).map_err(|_| StorageError::Io)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(|_| StorageError::Io)? != 0 {
        return Err(StorageError::InvalidWallet);
    }
    EncryptedBackup::from_bytes(bytes).map_err(StorageError::from)
}

fn write_new_encrypted_file(path: &Path, encrypted: &EncryptedBackup) -> Result<(), StorageError> {
    if encrypted.as_bytes().len() != ENCRYPTED_BACKUP_BYTES {
        return Err(StorageError::InvalidWallet);
    }
    let parent = path.parent().ok_or(StorageError::UnsafePath)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| StorageError::UnsafePath)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::UnsafePath);
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_file_mode(&mut options);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            StorageError::AlreadyExists
        } else {
            StorageError::Io
        }
    })?;
    file.write_all(encrypted.as_bytes())
        .map_err(|_| StorageError::Io)?;
    file.sync_all().map_err(|_| StorageError::Io)?;
    sync_parent_directory(parent)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn set_private_file_mode(_: &mut OpenOptions) {}

#[cfg(unix)]
fn open_read_without_symlinks(path: &Path) -> Result<File, StorageError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Io
            }
        })
}

#[cfg(not(unix))]
fn open_read_without_symlinks(path: &Path) -> Result<File, StorageError> {
    File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StorageError::NotFound
        } else {
            StorageError::Io
        }
    })
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| StorageError::Io)
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_: &Path) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), StorageError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StorageError::Io)
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), StorageError> {
    // Windows cannot open a directory through std::fs::File for sync_all.
    // The newly created wallet file itself is synced before this point.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmfd_wallet_core::vault::WalletVault;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    fn temporary_directory() -> PathBuf {
        let mut suffix = [0_u8; 12];
        getrandom::fill(&mut suffix).unwrap();
        std::env::temp_dir().join(format!("cmfd-wallet-storage-{}", hex_string(&suffix)))
    }

    fn hex_string(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            result.push(DIGITS[(byte >> 4) as usize] as char);
            result.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        result
    }

    #[test]
    fn backup_is_durable_before_live_wallet_and_neither_is_overwritten() {
        let root = temporary_directory();
        let export_directory = root.join("exports");
        fs::create_dir_all(&export_directory).unwrap();
        let recovery = export_directory.join("recovery.cmfd-wallet");
        let store = NativeWalletStore::new(root.join("private"));
        let mut vault = WalletVault::mainnet();
        let created = vault.create(PASSPHRASE, false).unwrap();

        store.install_created_wallet(&created, &recovery).unwrap();
        assert!(store.has_live_wallet().unwrap());
        assert_eq!(store.load_live_wallet().unwrap(), created.live_key);
        assert_eq!(
            store.read_recovery_backup(&recovery).unwrap(),
            created.recovery_backup
        );
        assert!(matches!(
            store.install_created_wallet(&created, &recovery),
            Err(StorageError::AlreadyExists)
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_backup_prevents_live_wallet_installation() {
        let root = temporary_directory();
        let export_directory = root.join("exports");
        fs::create_dir_all(&export_directory).unwrap();
        let recovery = export_directory.join("recovery.cmfd-wallet");
        fs::write(&recovery, b"do not replace").unwrap();
        let store = NativeWalletStore::new(root.join("private"));
        let mut vault = WalletVault::mainnet();
        let created = vault.create(PASSPHRASE, false).unwrap();

        assert!(matches!(
            store.install_created_wallet(&created, &recovery),
            Err(StorageError::AlreadyExists)
        ));
        assert!(!store.has_live_wallet().unwrap());
        assert_eq!(fs::read(&recovery).unwrap(), b"do not replace");

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_artifacts_use_restrictive_unix_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_directory();
        let export_directory = root.join("exports");
        fs::create_dir_all(&export_directory).unwrap();
        let recovery = export_directory.join("recovery.cmfd-wallet");
        let store = NativeWalletStore::new(root.join("private"));
        let mut vault = WalletVault::mainnet();
        let created = vault.create(PASSPHRASE, false).unwrap();
        store.install_created_wallet(&created, &recovery).unwrap();

        let directory_mode = fs::metadata(root.join("private"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let live_mode = fs::metadata(store.live_wallet_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let backup_mode = fs::metadata(&recovery).unwrap().permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(live_mode, 0o600);
        assert_eq!(backup_mode, 0o600);

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_wallet_artifacts() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory();
        let export_directory = root.join("exports");
        fs::create_dir_all(&export_directory).unwrap();
        let recovery = export_directory.join("recovery.cmfd-wallet");
        let link = export_directory.join("linked.cmfd-wallet");
        let store = NativeWalletStore::new(root.join("private"));
        let mut vault = WalletVault::mainnet();
        let created = vault.create(PASSPHRASE, false).unwrap();
        store.install_created_wallet(&created, &recovery).unwrap();
        symlink(&recovery, &link).unwrap();

        assert!(matches!(
            store.read_recovery_backup(&link),
            Err(StorageError::UnsafePath)
        ));

        fs::remove_dir_all(root).unwrap();
    }
}
