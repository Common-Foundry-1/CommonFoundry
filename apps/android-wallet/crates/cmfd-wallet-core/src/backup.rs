//! Common Foundry encrypted wallet backup V1.
//!
//! This is the exact 176-byte layout used by Common Foundry v1.0.16:
//! authenticated header (`CMFDWLT1`, algorithms, Argon2 parameters, salt,
//! nonce, network id and public destination) followed by an encrypted 32-byte
//! secret and the 16-byte Poly1305 tag.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use k256::schnorr::SigningKey;
use thiserror::Error;
use zeroize::Zeroizing;

const BACKUP_MAGIC: [u8; 8] = *b"CMFDWLT1";
const BACKUP_VERSION: u16 = 1;
const KDF_ARGON2ID: u8 = 1;
const CIPHER_XCHACHA20_POLY1305: u8 = 1;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const NETWORK_BYTES: usize = 32;
const DESTINATION_BYTES: usize = 32;
const SECRET_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize =
    8 + 2 + 1 + 1 + 4 + 4 + 4 + SALT_BYTES + NONCE_BYTES + NETWORK_BYTES + DESTINATION_BYTES;

pub const ENCRYPTED_BACKUP_BYTES: usize = HEADER_BYTES + SECRET_BYTES + TAG_BYTES;
pub const MINIMUM_PASSPHRASE_BYTES: usize = 12;
pub const MAXIMUM_PASSPHRASE_BYTES: usize = 1_024;

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedBackup(Vec<u8>);

impl std::fmt::Debug for EncryptedBackup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedBackup")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl EncryptedBackup {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WalletBackupError> {
        validate_header_shape(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletBackupInfo {
    pub network_id: [u8; 32],
    pub destination: [u8; 32],
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WalletBackupError {
    #[error("wallet backup passphrase must contain between 12 and 1024 bytes")]
    InvalidPassphrase,
    #[error("wallet key is invalid")]
    InvalidWalletKey,
    #[error("wallet backup is corrupt or unsupported")]
    InvalidBackup,
    #[error("wallet backup belongs to a different network")]
    WrongNetwork,
    #[error("wallet backup authentication failed")]
    AuthenticationFailed,
    #[error("wallet backup key does not match its authenticated destination")]
    DestinationMismatch,
    #[error("secure random generation failed")]
    RandomGeneration,
}

pub(crate) fn validate_passphrase(passphrase: &[u8]) -> Result<(), WalletBackupError> {
    if (MINIMUM_PASSPHRASE_BYTES..=MAXIMUM_PASSPHRASE_BYTES).contains(&passphrase.len()) {
        Ok(())
    } else {
        Err(WalletBackupError::InvalidPassphrase)
    }
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; 32]>, WalletBackupError> {
    validate_passphrase(passphrase)?;
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|_| WalletBackupError::InvalidBackup)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| WalletBackupError::InvalidPassphrase)?;
    Ok(key)
}

fn header(
    network_id: [u8; 32],
    destination: [u8; 32],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    bytes.extend_from_slice(&BACKUP_MAGIC);
    bytes.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    bytes.push(KDF_ARGON2ID);
    bytes.push(CIPHER_XCHACHA20_POLY1305);
    bytes.extend_from_slice(&ARGON2_MEMORY_KIB.to_le_bytes());
    bytes.extend_from_slice(&ARGON2_ITERATIONS.to_le_bytes());
    bytes.extend_from_slice(&ARGON2_PARALLELISM.to_le_bytes());
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&network_id);
    bytes.extend_from_slice(&destination);
    debug_assert_eq!(bytes.len(), HEADER_BYTES);
    bytes
}

fn validate_header_shape(encrypted: &[u8]) -> Result<(), WalletBackupError> {
    if encrypted.len() != ENCRYPTED_BACKUP_BYTES
        || encrypted[..8] != BACKUP_MAGIC
        || encrypted[8..10] != BACKUP_VERSION.to_le_bytes()
        || encrypted[10] != KDF_ARGON2ID
        || encrypted[11] != CIPHER_XCHACHA20_POLY1305
        || encrypted[12..16] != ARGON2_MEMORY_KIB.to_le_bytes()
        || encrypted[16..20] != ARGON2_ITERATIONS.to_le_bytes()
        || encrypted[20..24] != ARGON2_PARALLELISM.to_le_bytes()
    {
        return Err(WalletBackupError::InvalidBackup);
    }
    Ok(())
}

pub(crate) fn encrypt_secret(
    secret: &[u8; SECRET_BYTES],
    network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<(EncryptedBackup, WalletBackupInfo), WalletBackupError> {
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut salt).map_err(|_| WalletBackupError::RandomGeneration)?;
    getrandom::fill(&mut nonce).map_err(|_| WalletBackupError::RandomGeneration)?;
    encrypt_secret_with_entropy(secret, network_id, passphrase, salt, nonce)
}

fn encrypt_secret_with_entropy(
    secret: &[u8; SECRET_BYTES],
    network_id: [u8; 32],
    passphrase: &[u8],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<(EncryptedBackup, WalletBackupInfo), WalletBackupError> {
    validate_passphrase(passphrase)?;
    let key =
        SigningKey::from_bytes(secret.into()).map_err(|_| WalletBackupError::InvalidWalletKey)?;
    let destination = key.verifying_key().to_bytes().into();
    let authenticated_header = header(network_id, destination, salt, nonce);
    let encryption_key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*encryption_key).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: secret,
                aad: &authenticated_header,
            },
        )
        .map_err(|_| WalletBackupError::AuthenticationFailed)?;
    if ciphertext.len() != SECRET_BYTES + TAG_BYTES {
        return Err(WalletBackupError::InvalidBackup);
    }
    let mut encrypted = authenticated_header;
    encrypted.extend_from_slice(&ciphertext);
    debug_assert_eq!(encrypted.len(), ENCRYPTED_BACKUP_BYTES);
    Ok((
        EncryptedBackup(encrypted),
        WalletBackupInfo {
            network_id,
            destination,
            bytes: ENCRYPTED_BACKUP_BYTES,
        },
    ))
}

pub(crate) fn decrypt_secret(
    backup: &EncryptedBackup,
    expected_network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<(Zeroizing<[u8; SECRET_BYTES]>, WalletBackupInfo), WalletBackupError> {
    validate_passphrase(passphrase)?;
    let encrypted = backup.as_bytes();
    validate_header_shape(encrypted)?;
    let salt: [u8; SALT_BYTES] = encrypted[24..40]
        .try_into()
        .map_err(|_| WalletBackupError::InvalidBackup)?;
    let nonce: [u8; NONCE_BYTES] = encrypted[40..64]
        .try_into()
        .map_err(|_| WalletBackupError::InvalidBackup)?;
    let network_id: [u8; NETWORK_BYTES] = encrypted[64..96]
        .try_into()
        .map_err(|_| WalletBackupError::InvalidBackup)?;
    if network_id != expected_network_id {
        return Err(WalletBackupError::WrongNetwork);
    }
    let destination: [u8; DESTINATION_BYTES] = encrypted[96..128]
        .try_into()
        .map_err(|_| WalletBackupError::InvalidBackup)?;
    let decryption_key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*decryption_key).into());
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &encrypted[HEADER_BYTES..],
                aad: &encrypted[..HEADER_BYTES],
            },
        )
        .map_err(|_| WalletBackupError::AuthenticationFailed)?;
    if plaintext.len() != SECRET_BYTES {
        return Err(WalletBackupError::InvalidBackup);
    }
    let plaintext = Zeroizing::new(plaintext);
    let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
    secret.copy_from_slice(plaintext.as_slice());
    let key =
        SigningKey::from_bytes((&*secret).into()).map_err(|_| WalletBackupError::InvalidBackup)?;
    let restored_destination: [u8; 32] = key.verifying_key().to_bytes().into();
    if restored_destination != destination {
        return Err(WalletBackupError::DestinationMismatch);
    }
    Ok((
        secret,
        WalletBackupInfo {
            network_id,
            destination,
            bytes: encrypted.len(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MAINNET_NETWORK_ID;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    fn secret_one() -> [u8; 32] {
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        secret
    }

    #[test]
    fn official_layout_round_trip_preserves_identity() {
        let secret = secret_one();
        let (backup, created) = encrypt_secret_with_entropy(
            &secret,
            MAINNET_NETWORK_ID,
            PASSPHRASE,
            [0x11; SALT_BYTES],
            [0x22; NONCE_BYTES],
        )
        .unwrap();
        assert_eq!(backup.as_bytes().len(), 176);
        assert_eq!(&backup.as_bytes()[..8], b"CMFDWLT1");
        assert_eq!(&backup.as_bytes()[64..96], &MAINNET_NETWORK_ID);
        assert!(!backup.as_bytes().windows(32).any(|window| window == secret));
        let (restored, info) = decrypt_secret(&backup, MAINNET_NETWORK_ID, PASSPHRASE).unwrap();
        assert_eq!(*restored, secret);
        assert_eq!(info, created);
    }

    #[test]
    fn wrong_password_network_corruption_and_shape_fail_closed() {
        let (backup, _) = encrypt_secret_with_entropy(
            &secret_one(),
            MAINNET_NETWORK_ID,
            PASSPHRASE,
            [0x33; SALT_BYTES],
            [0x44; NONCE_BYTES],
        )
        .unwrap();
        assert_eq!(
            decrypt_secret(&backup, MAINNET_NETWORK_ID, b"wrong long passphrase").unwrap_err(),
            WalletBackupError::AuthenticationFailed
        );
        let mut wrong_network = MAINNET_NETWORK_ID;
        wrong_network[0] ^= 1;
        assert_eq!(
            decrypt_secret(&backup, wrong_network, PASSPHRASE).unwrap_err(),
            WalletBackupError::WrongNetwork
        );
        let mut corrupted = backup.clone().into_bytes();
        corrupted[HEADER_BYTES + 4] ^= 1;
        let corrupted = EncryptedBackup::from_bytes(corrupted).unwrap();
        assert_eq!(
            decrypt_secret(&corrupted, MAINNET_NETWORK_ID, PASSPHRASE).unwrap_err(),
            WalletBackupError::AuthenticationFailed
        );
        assert_eq!(
            EncryptedBackup::from_bytes(vec![0; 175]).unwrap_err(),
            WalletBackupError::InvalidBackup
        );
    }

    #[test]
    fn passphrase_limits_match_official_format() {
        assert_eq!(
            encrypt_secret(&secret_one(), MAINNET_NETWORK_ID, b"too short").unwrap_err(),
            WalletBackupError::InvalidPassphrase
        );
        assert_eq!(
            validate_passphrase(&vec![b'x'; MAXIMUM_PASSPHRASE_BYTES + 1]),
            Err(WalletBackupError::InvalidPassphrase)
        );
    }
}
