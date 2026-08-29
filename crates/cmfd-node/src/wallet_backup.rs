//! Offline, authenticated wallet-key backup and restore.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use k256::schnorr::SigningKey;
use thiserror::Error;
use zeroize::Zeroizing;

use super::{DataDirLock, NodeError, WALLET_KEY_FILE, sync_parent_directory};

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
pub(crate) const ENCRYPTED_WALLET_KEY_BYTES: usize = HEADER_BYTES + SECRET_BYTES + TAG_BYTES;
pub const MINIMUM_PASSPHRASE_BYTES: usize = 12;
pub const MAXIMUM_PASSPHRASE_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletBackupInfo {
    pub network_id: [u8; 32],
    pub destination: [u8; 32],
    pub bytes: usize,
}

#[derive(Debug, Error)]
pub enum WalletBackupError {
    #[error(transparent)]
    Node(#[from] NodeError),
    #[error("{operation} failed for {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("wallet key is missing, corrupt, or unsupported")]
    InvalidWalletKey,
    #[error("wallet backup passphrase must contain between 12 and 1024 bytes")]
    InvalidPassphrase,
    #[error("wallet passphrase file permissions must be 0600 or stricter")]
    InsecurePassphraseFilePermissions,
    #[error("wallet backup is corrupt or unsupported")]
    InvalidBackup,
    #[error("wallet backup belongs to a different network")]
    WrongNetwork,
    #[error("wallet backup authentication failed")]
    AuthenticationFailed,
    #[error("wallet backup key does not match its authenticated destination")]
    DestinationMismatch,
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> WalletBackupError {
    WalletBackupError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), WalletBackupError> {
    if (MINIMUM_PASSPHRASE_BYTES..=MAXIMUM_PASSPHRASE_BYTES).contains(&passphrase.len()) {
        Ok(())
    } else {
        Err(WalletBackupError::InvalidPassphrase)
    }
}

pub fn read_wallet_passphrase_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, WalletBackupError> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| io_error("open wallet passphrase", path, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file
            .metadata()
            .map_err(|source| io_error("inspect wallet passphrase", path, source))?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(WalletBackupError::InsecurePassphraseFilePermissions);
        }
    }
    let mut passphrase = Zeroizing::new(Vec::with_capacity(MAXIMUM_PASSPHRASE_BYTES + 3));
    file.take((MAXIMUM_PASSPHRASE_BYTES + 3) as u64)
        .read_to_end(&mut passphrase)
        .map_err(|source| io_error("read wallet passphrase", path, source))?;
    if passphrase.last() == Some(&b'\n') {
        passphrase.pop();
        if passphrase.last() == Some(&b'\r') {
            passphrase.pop();
        }
    }
    validate_passphrase(&passphrase)?;
    Ok(passphrase)
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

fn read_wallet_secret(
    data_dir: &Path,
    network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), WalletBackupError> {
    let path = data_dir.join(WALLET_KEY_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                WalletBackupError::InvalidWalletKey
            } else {
                io_error("open wallet key", &path, source)
            }
        })?;
    let length = file
        .metadata()
        .map_err(|source| io_error("inspect wallet key", &path, source))?
        .len();
    if length != SECRET_BYTES as u64 && length != ENCRYPTED_WALLET_KEY_BYTES as u64 {
        return Err(WalletBackupError::InvalidWalletKey);
    }
    if length == ENCRYPTED_WALLET_KEY_BYTES as u64 {
        let mut encrypted = vec![0_u8; ENCRYPTED_WALLET_KEY_BYTES];
        file.read_exact(&mut encrypted)
            .map_err(|_| WalletBackupError::InvalidWalletKey)?;
        let (secret, info) = decrypt_wallet_key_bytes(&encrypted, network_id, passphrase)?;
        return Ok((secret, info.destination));
    }
    let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
    file.read_exact(secret.as_mut())
        .map_err(|_| WalletBackupError::InvalidWalletKey)?;
    let key =
        SigningKey::from_bytes(secret.as_ref()).map_err(|_| WalletBackupError::InvalidWalletKey)?;
    let destination = key.verifying_key().to_bytes().into();
    Ok((secret, destination))
}

pub(crate) fn write_private_create_new(path: &Path, bytes: &[u8]) -> Result<(), WalletBackupError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error("create private wallet file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write private wallet file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync private wallet file", path, source))?;
    sync_parent_directory(path).map_err(WalletBackupError::Node)?;
    Ok(())
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

pub(crate) fn encrypt_wallet_key_bytes(
    secret: &[u8; SECRET_BYTES],
    network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<(Vec<u8>, WalletBackupInfo), WalletBackupError> {
    validate_passphrase(passphrase)?;
    let key = SigningKey::from_bytes(secret).map_err(|_| WalletBackupError::InvalidWalletKey)?;
    let destination = key.verifying_key().to_bytes().into();
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut salt).map_err(|source| {
        io_error(
            "generate encrypted wallet salt",
            WALLET_KEY_FILE.as_ref(),
            io::Error::other(source.to_string()),
        )
    })?;
    getrandom::fill(&mut nonce).map_err(|source| {
        io_error(
            "generate encrypted wallet nonce",
            WALLET_KEY_FILE.as_ref(),
            io::Error::other(source.to_string()),
        )
    })?;
    let header = header(network_id, destination, salt, nonce);
    let encryption_key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*encryption_key).into());
    let nonce = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: secret,
                aad: &header,
            },
        )
        .map_err(|_| WalletBackupError::AuthenticationFailed)?;
    if ciphertext.len() != SECRET_BYTES + TAG_BYTES {
        return Err(WalletBackupError::InvalidBackup);
    }
    let mut encrypted = header;
    encrypted.extend_from_slice(&ciphertext);
    debug_assert_eq!(encrypted.len(), ENCRYPTED_WALLET_KEY_BYTES);
    Ok((
        encrypted,
        WalletBackupInfo {
            network_id,
            destination,
            bytes: ENCRYPTED_WALLET_KEY_BYTES,
        },
    ))
}

pub(crate) fn decrypt_wallet_key_bytes(
    encrypted: &[u8],
    expected_network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<(Zeroizing<[u8; SECRET_BYTES]>, WalletBackupInfo), WalletBackupError> {
    validate_passphrase(passphrase)?;
    if encrypted.len() != ENCRYPTED_WALLET_KEY_BYTES
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
    let nonce = XNonce::from(nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
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
        SigningKey::from_bytes(secret.as_ref()).map_err(|_| WalletBackupError::InvalidBackup)?;
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

pub fn create_encrypted_wallet_backup(
    data_dir: &Path,
    output: &Path,
    network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<WalletBackupInfo, WalletBackupError> {
    validate_passphrase(passphrase)?;
    let _data_dir_lock = DataDirLock::acquire(data_dir)?;
    let (secret, _) = read_wallet_secret(data_dir, network_id, passphrase)?;
    let (backup, info) = encrypt_wallet_key_bytes(&secret, network_id, passphrase)?;
    write_private_create_new(output, &backup)?;
    Ok(info)
}

pub fn restore_encrypted_wallet_backup(
    input: &Path,
    data_dir: &Path,
    expected_network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<WalletBackupInfo, WalletBackupError> {
    validate_passphrase(passphrase)?;
    let input_len = fs::metadata(input)
        .map_err(|source| io_error("inspect wallet backup", input, source))?
        .len();
    if input_len != ENCRYPTED_WALLET_KEY_BYTES as u64 {
        return Err(WalletBackupError::InvalidBackup);
    }
    let backup = fs::read(input).map_err(|source| io_error("read wallet backup", input, source))?;
    let (_, info) = decrypt_wallet_key_bytes(&backup, expected_network_id, passphrase)?;
    let _data_dir_lock = DataDirLock::acquire(data_dir)?;
    write_private_create_new(&data_dir.join(WALLET_KEY_FILE), &backup)?;
    Ok(info)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-wallet-backup-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_test_key(data_dir: &Path, byte: u8) -> [u8; 32] {
        fs::create_dir_all(data_dir).unwrap();
        let key = SigningKey::from_bytes(&[byte; 32]).unwrap();
        write_private_create_new(&data_dir.join(WALLET_KEY_FILE), &key.to_bytes()).unwrap();
        key.verifying_key().to_bytes().into()
    }

    #[test]
    fn encrypted_backup_round_trip_preserves_destination() {
        let source = test_dir("round-trip-source");
        let restored = test_dir("round-trip-restored");
        let backup = source.with_extension("cmfd-wallet-backup");
        let destination = write_test_key(&source, 0x31);
        let network_id = [0x52; 32];

        let created = create_encrypted_wallet_backup(
            &source,
            &backup,
            network_id,
            b"correct horse battery staple",
        )
        .unwrap();
        let recovered = restore_encrypted_wallet_backup(
            &backup,
            &restored,
            network_id,
            b"correct horse battery staple",
        )
        .unwrap();

        assert_eq!(created.destination, destination);
        assert_eq!(recovered, created);
        let backup_bytes = fs::read(&backup).unwrap();
        let source_key = fs::read(source.join(WALLET_KEY_FILE)).unwrap();
        assert_eq!(backup_bytes.len(), ENCRYPTED_WALLET_KEY_BYTES);
        assert!(
            !backup_bytes
                .windows(SECRET_BYTES)
                .any(|window| window == source_key.as_slice())
        );
        let restored_bytes = fs::read(restored.join(WALLET_KEY_FILE)).unwrap();
        assert_eq!(restored_bytes.len(), ENCRYPTED_WALLET_KEY_BYTES);
        let (restored_secret, restored_info) =
            decrypt_wallet_key_bytes(&restored_bytes, network_id, b"correct horse battery staple")
                .unwrap();
        assert_eq!(restored_secret.as_slice(), source_key.as_slice());
        assert_eq!(restored_info.destination, destination);
        let _ = fs::remove_file(backup);
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(restored);
    }

    #[test]
    fn encrypted_live_wallet_can_be_backed_up_again() {
        let source = test_dir("encrypted-live-source");
        let restored = test_dir("encrypted-live-restored");
        let first_backup = source.with_extension("first.cmfd-wallet-backup");
        let second_backup = source.with_extension("second.cmfd-wallet-backup");
        let destination = write_test_key(&source, 0x39);
        let network_id = [0x59; 32];
        let passphrase = b"correct horse battery staple";

        create_encrypted_wallet_backup(&source, &first_backup, network_id, passphrase).unwrap();
        restore_encrypted_wallet_backup(&first_backup, &restored, network_id, passphrase).unwrap();
        let second =
            create_encrypted_wallet_backup(&restored, &second_backup, network_id, passphrase)
                .unwrap();
        let second_bytes = fs::read(&second_backup).unwrap();
        let (_, second_info) =
            decrypt_wallet_key_bytes(&second_bytes, network_id, passphrase).unwrap();

        assert_eq!(second.destination, destination);
        assert_eq!(second_info.destination, destination);
        assert_ne!(fs::read(&first_backup).unwrap(), second_bytes);
        let _ = fs::remove_file(first_backup);
        let _ = fs::remove_file(second_backup);
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(restored);
    }

    #[test]
    fn wrong_passphrase_network_and_tampering_fail_closed() {
        let source = test_dir("reject-source");
        let restored = test_dir("reject-restored");
        let backup = source.with_extension("cmfd-wallet-backup");
        write_test_key(&source, 0x41);
        create_encrypted_wallet_backup(
            &source,
            &backup,
            [0x62; 32],
            b"correct horse battery staple",
        )
        .unwrap();

        assert!(matches!(
            restore_encrypted_wallet_backup(
                &backup,
                &restored,
                [0x62; 32],
                b"wrong passphrase value"
            ),
            Err(WalletBackupError::AuthenticationFailed)
        ));
        assert!(matches!(
            restore_encrypted_wallet_backup(
                &backup,
                &restored,
                [0x63; 32],
                b"correct horse battery staple"
            ),
            Err(WalletBackupError::WrongNetwork)
        ));

        let mut bytes = fs::read(&backup).unwrap();
        bytes[HEADER_BYTES + 4] ^= 1;
        fs::write(&backup, bytes).unwrap();
        assert!(matches!(
            restore_encrypted_wallet_backup(
                &backup,
                &restored,
                [0x62; 32],
                b"correct horse battery staple"
            ),
            Err(WalletBackupError::AuthenticationFailed)
        ));
        assert!(!restored.join(WALLET_KEY_FILE).exists());
        let _ = fs::remove_file(backup);
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(restored);
    }

    #[test]
    fn backup_and_restore_never_overwrite() {
        let source = test_dir("no-overwrite-source");
        let restored = test_dir("no-overwrite-restored");
        let backup = source.with_extension("cmfd-wallet-backup");
        write_test_key(&source, 0x51);
        create_encrypted_wallet_backup(&source, &backup, [0x72; 32], b"long enough passphrase")
            .unwrap();
        assert!(matches!(
            create_encrypted_wallet_backup(&source, &backup, [0x72; 32], b"long enough passphrase"),
            Err(WalletBackupError::Io { .. })
        ));
        write_test_key(&restored, 0x61);
        assert!(matches!(
            restore_encrypted_wallet_backup(
                &backup,
                &restored,
                [0x72; 32],
                b"long enough passphrase"
            ),
            Err(WalletBackupError::Io { .. })
        ));
        assert_eq!(
            fs::read(restored.join(WALLET_KEY_FILE)).unwrap(),
            [0x61; 32]
        );
        let _ = fs::remove_file(backup);
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(restored);
    }

    #[test]
    fn backup_refuses_a_running_data_directory() {
        let source = test_dir("locked-source");
        let backup = source.with_extension("cmfd-wallet-backup");
        write_test_key(&source, 0x71);
        let held_lock = DataDirLock::acquire(&source).unwrap();
        assert!(matches!(
            create_encrypted_wallet_backup(&source, &backup, [0x82; 32], b"long enough passphrase"),
            Err(WalletBackupError::Node(NodeError::DataDirLocked(_)))
        ));
        drop(held_lock);
        let _ = fs::remove_dir_all(source);
    }
}
