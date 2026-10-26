//! The only owner of plaintext wallet key material.
//!
//! UI and networking layers must hold this type behind a native mutex and may
//! expose only its public status and signed transaction results. The secret is
//! zeroized when the vault is locked, replaced or dropped.

use k256::schnorr::SigningKey;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::address::AddressCodec;
use crate::backup::{
    EncryptedBackup, WalletBackupError, decrypt_secret, encrypt_secret, validate_passphrase,
};
use crate::network::{MAINNET, Network};
use crate::transaction::{PaymentPlan, SignedTransaction, TransactionError, sign_plan};

#[derive(Clone, PartialEq, Eq)]
pub struct CreatedWallet {
    /// Encrypted live key for private application storage.
    pub live_key: EncryptedBackup,
    /// Independently randomized encrypted copy for user-selected backup storage.
    pub recovery_backup: EncryptedBackup,
    pub status: VaultStatus,
}

impl std::fmt::Debug for CreatedWallet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedWallet")
            .field("live_key", &self.live_key)
            .field("recovery_backup", &self.recovery_backup)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStatus {
    pub network_name: &'static str,
    pub network_id_hex: String,
    pub unlocked: bool,
    pub destination_hex: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error(transparent)]
    Backup(#[from] WalletBackupError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("wallet is locked")]
    Locked,
    #[error("wallet already exists; refusing to overwrite it")]
    AlreadyExists,
    #[error("secure random generation failed")]
    RandomGeneration,
}

impl PartialEq for VaultError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Backup(left), Self::Backup(right)) => left == right,
            (Self::Transaction(left), Self::Transaction(right)) => left == right,
            (Self::Locked, Self::Locked)
            | (Self::AlreadyExists, Self::AlreadyExists)
            | (Self::RandomGeneration, Self::RandomGeneration) => true,
            _ => false,
        }
    }
}

pub struct WalletVault {
    network: Network,
    secret: Option<Zeroizing<[u8; 32]>>,
    destination: Option<[u8; 32]>,
}

impl std::fmt::Debug for WalletVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WalletVault")
            .field("network", &self.network.name)
            .field("unlocked", &self.secret.is_some())
            .field("has_destination", &self.destination.is_some())
            .finish()
    }
}

impl Default for WalletVault {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl WalletVault {
    pub const fn mainnet() -> Self {
        Self {
            network: MAINNET,
            secret: None,
            destination: None,
        }
    }

    /// Generates one OS-CSPRNG Schnorr key and encrypts two independent copies.
    ///
    /// The native storage layer must make `recovery_backup` durable before
    /// publishing `live_key`, matching the official desktop fail-closed order.
    pub fn create(
        &mut self,
        passphrase: &[u8],
        wallet_already_exists: bool,
    ) -> Result<CreatedWallet, VaultError> {
        if wallet_already_exists {
            return Err(VaultError::AlreadyExists);
        }
        validate_passphrase(passphrase)?;
        let mut secret = Zeroizing::new([0_u8; 32]);
        let signing_key = loop {
            getrandom::fill(secret.as_mut()).map_err(|_| VaultError::RandomGeneration)?;
            if let Ok(key) = SigningKey::from_bytes((&*secret).into()) {
                break key;
            }
        };
        let destination: [u8; 32] = signing_key.verifying_key().to_bytes().into();
        let (recovery_backup, recovery_info) =
            encrypt_secret(&secret, self.network.id, passphrase)?;
        let (live_key, live_info) = encrypt_secret(&secret, self.network.id, passphrase)?;
        if recovery_info.destination != destination || live_info.destination != destination {
            return Err(WalletBackupError::DestinationMismatch.into());
        }
        self.replace_secret(secret, destination);
        Ok(CreatedWallet {
            live_key,
            recovery_backup,
            status: self.status(),
        })
    }

    /// Authenticates a backup completely before replacing the in-memory state.
    pub fn restore(
        &mut self,
        backup: &EncryptedBackup,
        passphrase: &[u8],
        wallet_already_exists: bool,
    ) -> Result<VaultStatus, VaultError> {
        if wallet_already_exists {
            return Err(VaultError::AlreadyExists);
        }
        let (secret, info) = decrypt_secret(backup, self.network.id, passphrase)?;
        self.replace_secret(secret, info.destination);
        Ok(self.status())
    }

    /// Unlocks an encrypted live key. Failure leaves the previous state intact.
    pub fn unlock(
        &mut self,
        encrypted_live_key: &EncryptedBackup,
        passphrase: &[u8],
    ) -> Result<VaultStatus, VaultError> {
        let (secret, info) = decrypt_secret(encrypted_live_key, self.network.id, passphrase)?;
        self.replace_secret(secret, info.destination);
        Ok(self.status())
    }

    pub fn lock(&mut self) -> VaultStatus {
        self.secret = None;
        self.destination = None;
        self.status()
    }

    pub fn export_backup(&self, passphrase: &[u8]) -> Result<EncryptedBackup, VaultError> {
        let secret = self.secret.as_ref().ok_or(VaultError::Locked)?;
        let (backup, info) = encrypt_secret(secret, self.network.id, passphrase)?;
        if Some(info.destination) != self.destination {
            return Err(WalletBackupError::DestinationMismatch.into());
        }
        Ok(backup)
    }

    pub fn sign(&self, plan: &PaymentPlan) -> Result<SignedTransaction, VaultError> {
        let secret = self.secret.as_ref().ok_or(VaultError::Locked)?;
        let key = SigningKey::from_bytes((&**secret).into())
            .map_err(|_| WalletBackupError::InvalidWalletKey)?;
        Ok(sign_plan(plan, &key)?)
    }

    pub fn status(&self) -> VaultStatus {
        VaultStatus {
            network_name: self.network.name,
            network_id_hex: hex::encode(self.network.id),
            unlocked: self.secret.is_some(),
            destination_hex: self.destination.map(hex::encode),
            address: self
                .destination
                .map(|destination| AddressCodec::mainnet().render(&destination)),
        }
    }

    pub fn destination(&self) -> Result<[u8; 32], VaultError> {
        if self.secret.is_none() {
            return Err(VaultError::Locked);
        }
        self.destination.ok_or(VaultError::Locked)
    }

    fn replace_secret(&mut self, secret: Zeroizing<[u8; 32]>, destination: [u8; 32]) {
        self.secret = None;
        self.secret = Some(secret);
        self.destination = Some(destination);
    }
}

impl Drop for WalletVault {
    fn drop(&mut self) {
        self.secret = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::WalletBackupError;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    #[test]
    fn create_export_restore_and_unlock_preserve_identity() {
        let mut source = WalletVault::mainnet();
        let created = source.create(PASSPHRASE, false).unwrap();
        assert_ne!(created.live_key, created.recovery_backup);
        let source_status = created.status;
        assert!(source_status.unlocked);
        let exported = source.export_backup(PASSPHRASE).unwrap();
        assert_ne!(exported, created.recovery_backup);

        source.lock();
        assert!(!source.status().unlocked);
        source.unlock(&created.live_key, PASSPHRASE).unwrap();
        assert_eq!(source.status().address, source_status.address);

        let mut restored = WalletVault::mainnet();
        restored.restore(&exported, PASSPHRASE, false).unwrap();
        assert_eq!(restored.status().address, source_status.address);
        assert_eq!(
            restored.status().destination_hex,
            source_status.destination_hex
        );
    }

    #[test]
    fn restore_never_overwrites_and_bad_password_does_not_change_state() {
        let mut source = WalletVault::mainnet();
        let created = source.create(PASSPHRASE, false).unwrap();
        let before = source.status();
        assert_eq!(
            source.restore(&created.recovery_backup, PASSPHRASE, true),
            Err(VaultError::AlreadyExists)
        );
        assert_eq!(source.status(), before);
        assert_eq!(
            source.unlock(&created.live_key, b"wrong long passphrase"),
            Err(VaultError::Backup(WalletBackupError::AuthenticationFailed))
        );
        assert_eq!(source.status(), before);
    }

    #[test]
    fn locked_vault_refuses_signing_and_export() {
        let mut vault = WalletVault::mainnet();
        assert_eq!(vault.export_backup(PASSPHRASE), Err(VaultError::Locked));
        assert_eq!(vault.destination(), Err(VaultError::Locked));

        let created = vault.create(PASSPHRASE, false).unwrap();
        assert!(vault.destination().is_ok());
        let locked = vault.lock();
        assert!(!locked.unlocked);
        assert_eq!(locked.destination_hex, None);
        assert_eq!(locked.address, None);
        assert_eq!(vault.destination(), Err(VaultError::Locked));

        vault.unlock(&created.live_key, PASSPHRASE).unwrap();
        assert_eq!(vault.status().address, created.status.address);
    }
}
