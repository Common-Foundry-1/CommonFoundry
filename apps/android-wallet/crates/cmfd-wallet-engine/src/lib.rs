//! Native application boundary for wallet lifecycle operations.
//!
//! A Tauri command layer may hold one `WalletEngine` behind a mutex. It must
//! never return `WalletVault`, an encrypted live-key path, passphrases, or key
//! bytes to JavaScript. Only the public `EngineStatus` crosses that boundary.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use cmfd_wallet_core::backup::EncryptedBackup;
use cmfd_wallet_core::transaction::{PaymentPlan, SignedTransaction};
use cmfd_wallet_core::vault::{VaultError, VaultStatus, WalletVault};
use cmfd_wallet_storage::{NativeWalletStore, StorageError};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineStatus {
    pub configured: bool,
    pub unlocked: bool,
    pub network_name: &'static str,
    pub network_id_hex: String,
    pub destination_hex: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("wallet already exists; refusing to overwrite it")]
    AlreadyExists,
    #[error("wallet is not configured")]
    NotConfigured,
    #[error("wallet authentication does not match the active identity")]
    AuthenticationMismatch,
    #[error("wallet operation failed: {0}")]
    Vault(#[from] VaultError),
    #[error("wallet storage operation failed: {0}")]
    Storage(#[from] StorageError),
}

pub struct WalletEngine {
    vault: WalletVault,
    store: NativeWalletStore,
}

/// Encrypted artifacts prepared for an Android-controlled commit sequence.
///
/// Both byte strings use the official Common Foundry backup format. The
/// recovery copy must be durably written through the Android document provider
/// before the live copy is wrapped by Android Keystore and activated.
pub struct PreparedWallet {
    live_key: EncryptedBackup,
    recovery_backup: EncryptedBackup,
}

impl std::fmt::Debug for PreparedWallet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedWallet")
            .field("live_key_bytes", &self.live_key.as_bytes().len())
            .field(
                "recovery_backup_bytes",
                &self.recovery_backup.as_bytes().len(),
            )
            .finish_non_exhaustive()
    }
}

impl PreparedWallet {
    pub fn live_key_bytes(&self) -> &[u8] {
        self.live_key.as_bytes()
    }

    pub fn recovery_backup_bytes(&self) -> &[u8] {
        self.recovery_backup.as_bytes()
    }
}

impl std::fmt::Debug for WalletEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WalletEngine")
            .field("vault", &self.vault)
            .field("configured", &self.store.has_live_wallet())
            .finish_non_exhaustive()
    }
}

impl WalletEngine {
    pub fn new(private_directory: impl Into<PathBuf>) -> Self {
        Self {
            vault: WalletVault::mainnet(),
            store: NativeWalletStore::new(private_directory),
        }
    }

    pub fn status(&self) -> Result<EngineStatus, EngineError> {
        self.public_status(self.store.has_live_wallet()?)
    }

    /// Creates an encrypted live key only after the independent recovery file
    /// was durably persisted at the user-selected path.
    pub fn create_wallet(
        &mut self,
        passphrase: &[u8],
        recovery_path: impl AsRef<Path>,
    ) -> Result<EngineStatus, EngineError> {
        if self.store.has_live_wallet()? {
            return Err(EngineError::AlreadyExists);
        }
        let created = self.vault.create(passphrase, false)?;
        if let Err(error) = self
            .store
            .install_created_wallet(&created, recovery_path.as_ref())
        {
            self.vault.lock();
            return Err(error.into());
        }
        self.public_status(true)
    }

    /// Authenticates a desktop-compatible backup, verifies its mainnet identity,
    /// then creates a separately randomized encrypted live key.
    pub fn restore_wallet(
        &mut self,
        passphrase: &[u8],
        recovery_path: impl AsRef<Path>,
    ) -> Result<EngineStatus, EngineError> {
        if self.store.has_live_wallet()? {
            return Err(EngineError::AlreadyExists);
        }
        let backup = self.store.read_recovery_backup(recovery_path)?;
        self.vault.restore(&backup, passphrase, false)?;
        let reencrypted_live_key = match self.vault.export_backup(passphrase) {
            Ok(backup) => backup,
            Err(error) => {
                self.vault.lock();
                return Err(error.into());
            }
        };
        if let Err(error) = self
            .store
            .install_restored_live_wallet(&reencrypted_live_key)
        {
            self.vault.lock();
            return Err(error.into());
        }
        self.public_status(true)
    }

    pub fn unlock(&mut self, passphrase: &[u8]) -> Result<EngineStatus, EngineError> {
        if !self.store.has_live_wallet()? {
            return Err(EngineError::NotConfigured);
        }
        let encrypted = self.store.load_live_wallet()?;
        self.vault.unlock(&encrypted, passphrase)?;
        self.public_status(true)
    }

    pub fn lock(&mut self) -> Result<EngineStatus, EngineError> {
        self.vault.lock();
        self.public_status(self.store.has_live_wallet()?)
    }

    pub fn export_backup(
        &self,
        passphrase: &[u8],
        recovery_path: impl AsRef<Path>,
    ) -> Result<(), EngineError> {
        let encrypted = self.vault.export_backup(passphrase)?;
        self.store
            .write_recovery_backup(recovery_path, &encrypted)?;
        Ok(())
    }

    /// Prepares independently randomized recovery and live artifacts without
    /// writing either one. This is used only by the Android SAF/Keystore
    /// orchestrator, which must commit the recovery document first.
    pub fn prepare_external_create(
        &mut self,
        passphrase: &[u8],
        wallet_already_exists: bool,
    ) -> Result<PreparedWallet, EngineError> {
        if wallet_already_exists {
            return Err(EngineError::AlreadyExists);
        }
        let created = self.vault.create(passphrase, false)?;
        Ok(PreparedWallet {
            live_key: created.live_key,
            recovery_backup: created.recovery_backup,
        })
    }

    /// Authenticates an official recovery blob and prepares a separately
    /// randomized live artifact for Android Keystore wrapping.
    pub fn prepare_external_restore(
        &mut self,
        recovery_bytes: &[u8],
        passphrase: &[u8],
        wallet_already_exists: bool,
    ) -> Result<Vec<u8>, EngineError> {
        if wallet_already_exists {
            return Err(EngineError::AlreadyExists);
        }
        let backup =
            EncryptedBackup::from_bytes(recovery_bytes.to_vec()).map_err(VaultError::from)?;
        self.vault.restore(&backup, passphrase, false)?;
        match self.vault.export_backup(passphrase) {
            Ok(live_key) => Ok(live_key.into_bytes()),
            Err(error) => {
                self.vault.lock();
                Err(error.into())
            }
        }
    }

    pub fn unlock_external(
        &mut self,
        encrypted_live_key: &[u8],
        passphrase: &[u8],
    ) -> Result<EngineStatus, EngineError> {
        let encrypted =
            EncryptedBackup::from_bytes(encrypted_live_key.to_vec()).map_err(VaultError::from)?;
        self.vault.unlock(&encrypted, passphrase)?;
        self.public_status(true)
    }

    /// Reauthenticates against the Keystore-unwrapped live backup before
    /// creating a portable recovery artifact. Possession of an unlocked UI
    /// session alone is deliberately insufficient for export.
    pub fn export_external_authenticated(
        &self,
        encrypted_live_key: &[u8],
        passphrase: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        let active_destination = self.vault.destination()?;
        let encrypted =
            EncryptedBackup::from_bytes(encrypted_live_key.to_vec()).map_err(VaultError::from)?;
        let mut verifier = WalletVault::mainnet();
        verifier.unlock(&encrypted, passphrase)?;
        if verifier.destination()? != active_destination {
            return Err(EngineError::AuthenticationMismatch);
        }
        self.vault
            .export_backup(passphrase)
            .map(EncryptedBackup::into_bytes)
            .map_err(Into::into)
    }

    pub fn external_destination(&self) -> Result<[u8; 32], EngineError> {
        self.vault.destination().map_err(Into::into)
    }

    pub fn sign_external(&self, plan: &PaymentPlan) -> Result<SignedTransaction, EngineError> {
        self.vault.sign(plan).map_err(Into::into)
    }

    pub fn external_status(&self, configured: bool) -> Result<EngineStatus, EngineError> {
        self.public_status(configured)
    }

    pub fn lock_external(&mut self, configured: bool) -> Result<EngineStatus, EngineError> {
        self.vault.lock();
        self.public_status(configured)
    }

    /// Clears any key material retained after an interrupted Android commit.
    pub fn abort_external_operation(&mut self) {
        self.vault.lock();
    }

    fn public_status(&self, configured: bool) -> Result<EngineStatus, EngineError> {
        let VaultStatus {
            unlocked,
            network_name,
            network_id_hex,
            destination_hex,
            address,
        } = self.vault.status();
        Ok(EngineStatus {
            configured,
            unlocked,
            network_name,
            network_id_hex,
            destination_hex,
            address,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    #[test]
    fn external_export_requires_fresh_authentication_of_the_active_wallet() {
        let root = std::env::temp_dir().join("cmfd-engine-export-auth");
        let mut engine = WalletEngine::new(root);
        let created = engine.prepare_external_create(PASSPHRASE, false).unwrap();
        let live = created.live_key_bytes().to_vec();

        let exported = engine
            .export_external_authenticated(&live, PASSPHRASE)
            .unwrap();
        let mut restored = WalletVault::mainnet();
        restored
            .restore(
                &EncryptedBackup::from_bytes(exported).unwrap(),
                PASSPHRASE,
                false,
            )
            .unwrap();
        assert_eq!(
            restored.destination().unwrap(),
            engine.external_destination().unwrap()
        );

        assert!(
            engine
                .export_external_authenticated(&live, b"synthetic wrong passphrase")
                .is_err()
        );

        let mut other = WalletEngine::new(std::env::temp_dir().join("cmfd-engine-export-other"));
        let other_live = other
            .prepare_external_create(PASSPHRASE, false)
            .unwrap()
            .live_key_bytes()
            .to_vec();
        assert!(
            engine
                .export_external_authenticated(&other_live, PASSPHRASE)
                .is_err()
        );
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let mut suffix = [0_u8; 12];
        getrandom::fill(&mut suffix).unwrap();
        let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
        std::env::temp_dir().join(format!("cmfd-engine-{label}-{suffix}"))
    }

    #[test]
    fn create_lock_unlock_export_and_restore_preserve_identity() {
        let root = temporary_directory("lifecycle");
        let first_private = root.join("first-private");
        let second_private = root.join("second-private");
        let exports = root.join("exports");
        fs::create_dir_all(&exports).unwrap();
        let initial_backup = exports.join("initial.cmfd-wallet");
        let exported_backup = exports.join("exported.cmfd-wallet");

        let mut first = WalletEngine::new(first_private);
        let created = first.create_wallet(PASSPHRASE, &initial_backup).unwrap();
        assert!(created.configured);
        assert!(created.unlocked);
        assert!(created.address.as_deref().unwrap().starts_with("cmfd1"));
        first.lock().unwrap();
        assert!(!first.status().unwrap().unlocked);
        assert!(first.unlock(PASSPHRASE).unwrap().unlocked);
        first.export_backup(PASSPHRASE, &exported_backup).unwrap();

        let mut restored = WalletEngine::new(second_private);
        let restored_status = restored
            .restore_wallet(PASSPHRASE, &exported_backup)
            .unwrap();
        assert_eq!(restored_status.address, created.address);
        assert_eq!(restored_status.destination_hex, created.destination_hex);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failures_do_not_unlock_or_replace_a_wallet() {
        let root = temporary_directory("fail-closed");
        let exports = root.join("exports");
        fs::create_dir_all(&exports).unwrap();
        let backup = exports.join("wallet.cmfd-wallet");
        let mut engine = WalletEngine::new(root.join("private"));
        let created = engine.create_wallet(PASSPHRASE, &backup).unwrap();
        engine.lock().unwrap();

        assert!(engine.unlock(b"wrong long passphrase").is_err());
        assert!(!engine.status().unwrap().unlocked);
        assert!(matches!(
            engine.restore_wallet(PASSPHRASE, &backup),
            Err(EngineError::AlreadyExists)
        ));
        assert_eq!(engine.unlock(PASSPHRASE).unwrap().address, created.address);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_android_sequence_commits_recovery_before_activation() {
        let root = temporary_directory("android-sequence");
        let mut created_engine = WalletEngine::new(root.join("unused-created"));
        let prepared = created_engine
            .prepare_external_create(PASSPHRASE, false)
            .unwrap();
        assert_ne!(prepared.live_key_bytes(), prepared.recovery_backup_bytes());
        assert_eq!(prepared.live_key_bytes().len(), 176);
        assert_eq!(prepared.recovery_backup_bytes().len(), 176);

        let created_status = created_engine.external_status(true).unwrap();
        assert!(created_status.configured);
        assert!(created_status.unlocked);
        created_engine.lock_external(true).unwrap();
        let unlocked = created_engine
            .unlock_external(prepared.live_key_bytes(), PASSPHRASE)
            .unwrap();
        assert_eq!(unlocked.address, created_status.address);

        let mut restored_engine = WalletEngine::new(root.join("unused-restored"));
        let restored_live = restored_engine
            .prepare_external_restore(prepared.recovery_backup_bytes(), PASSPHRASE, false)
            .unwrap();
        let restored_status = restored_engine.external_status(true).unwrap();
        assert_eq!(restored_status.address, created_status.address);
        restored_engine.lock_external(true).unwrap();
        assert_eq!(
            restored_engine
                .unlock_external(&restored_live, PASSPHRASE)
                .unwrap()
                .address,
            created_status.address
        );

        fs::remove_dir_all(root).ok();
    }
}
