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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKeyStorage {
    Missing,
    Plaintext,
    Encrypted,
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
    #[error("wallet key is already encrypted")]
    AlreadyEncrypted,
    #[error("wallet key already exists")]
    WalletKeyAlreadyExists,
    #[error("wallet key and backup paths must be distinct")]
    OverlappingPaths,
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

pub fn inspect_wallet_key_storage(data_dir: &Path) -> Result<WalletKeyStorage, WalletBackupError> {
    let path = data_dir.join(WALLET_KEY_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(WalletKeyStorage::Missing);
        }
        Err(source) => return Err(io_error("inspect wallet key", &path, source)),
    };
    if !metadata.file_type().is_file() {
        return Err(WalletBackupError::InvalidWalletKey);
    }
    match metadata.len() as usize {
        SECRET_BYTES => Ok(WalletKeyStorage::Plaintext),
        ENCRYPTED_WALLET_KEY_BYTES => Ok(WalletKeyStorage::Encrypted),
        _ => Err(WalletBackupError::InvalidWalletKey),
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

/// Creates a new encrypted wallet and an independently randomized encrypted
/// backup for an explicit network identity. The backup is made durable before
/// the live wallet is published, so an interrupted live-key write cannot lose
/// the newly generated secret.
pub fn create_encrypted_wallet(
    data_dir: &Path,
    backup_output: &Path,
    network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<WalletBackupInfo, WalletBackupError> {
    validate_passphrase(passphrase)?;
    let _data_dir_lock = DataDirLock::acquire(data_dir)?;
    if inspect_wallet_key_storage(data_dir)? != WalletKeyStorage::Missing {
        return Err(WalletBackupError::WalletKeyAlreadyExists);
    }

    let wallet_path = data_dir.join(WALLET_KEY_FILE);
    let wallet_parent = fs::canonicalize(data_dir)
        .map_err(|source| io_error("resolve wallet directory", data_dir, source))?;
    let backup_parent = backup_output
        .parent()
        .ok_or(WalletBackupError::OverlappingPaths)?;
    let backup_parent = fs::canonicalize(backup_parent)
        .map_err(|source| io_error("resolve wallet backup directory", backup_parent, source))?;
    let backup_name = backup_output
        .file_name()
        .ok_or(WalletBackupError::OverlappingPaths)?;
    if wallet_parent.join(WALLET_KEY_FILE) == backup_parent.join(backup_name) {
        return Err(WalletBackupError::OverlappingPaths);
    }

    let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
    loop {
        getrandom::fill(secret.as_mut()).map_err(|source| {
            io_error(
                "generate wallet secret",
                &wallet_path,
                io::Error::other(source.to_string()),
            )
        })?;
        if SigningKey::from_bytes(secret.as_ref()).is_ok() {
            break;
        }
    }

    let (backup, info) = encrypt_wallet_key_bytes(&secret, network_id, passphrase)?;
    let (live_key, live_info) = encrypt_wallet_key_bytes(&secret, network_id, passphrase)?;
    if live_info.destination != info.destination {
        return Err(WalletBackupError::DestinationMismatch);
    }
    write_private_create_new(backup_output, &backup)?;
    write_private_create_new(&wallet_path, &live_key)?;
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

pub fn migrate_plaintext_wallet_key(
    data_dir: &Path,
    backup_output: &Path,
    network_id: [u8; 32],
    passphrase: &[u8],
) -> Result<WalletBackupInfo, WalletBackupError> {
    validate_passphrase(passphrase)?;
    let _data_dir_lock = DataDirLock::acquire(data_dir)?;
    match inspect_wallet_key_storage(data_dir)? {
        WalletKeyStorage::Plaintext => {}
        WalletKeyStorage::Encrypted => return Err(WalletBackupError::AlreadyEncrypted),
        WalletKeyStorage::Missing => return Err(WalletBackupError::InvalidWalletKey),
    }

    let (secret, _) = read_wallet_secret(data_dir, network_id, passphrase)?;
    let (backup, info) = encrypt_wallet_key_bytes(&secret, network_id, passphrase)?;
    let (encrypted_live_key, live_info) =
        encrypt_wallet_key_bytes(&secret, network_id, passphrase)?;
    if live_info.destination != info.destination {
        return Err(WalletBackupError::DestinationMismatch);
    }

    // The separately randomized backup is durable before the live key changes.
    write_private_create_new(backup_output, &backup)?;

    let wallet_path = data_dir.join(WALLET_KEY_FILE);
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|source| {
        io_error(
            "generate wallet migration path",
            &wallet_path,
            io::Error::other(source.to_string()),
        )
    })?;
    let temporary_path = data_dir.join(format!(
        ".{WALLET_KEY_FILE}.migration-{}",
        hex::encode(suffix)
    ));
    write_private_create_new(&temporary_path, &encrypted_live_key)?;
    if let Err(source) = fs::rename(&temporary_path, &wallet_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(io_error(
            "replace plaintext wallet key",
            &wallet_path,
            source,
        ));
    }
    sync_parent_directory(&wallet_path).map_err(WalletBackupError::Node)?;
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
    fn new_encrypted_wallet_has_independent_recoverable_backup() {
        let source = test_dir("new-wallet-source");
        let backup_dir = test_dir("new-wallet-backup");
        let restored = test_dir("new-wallet-restored");
        fs::create_dir_all(&backup_dir).unwrap();
        let backup = backup_dir.join("wallet.cmfd-backup");
        let network_id = [0x91; 32];
        let passphrase = b"correct horse battery staple";

        let created = create_encrypted_wallet(&source, &backup, network_id, passphrase).unwrap();
        assert_eq!(created.network_id, network_id);
        assert_eq!(
            inspect_wallet_key_storage(&source).unwrap(),
            WalletKeyStorage::Encrypted
        );
        assert_ne!(
            fs::read(source.join(WALLET_KEY_FILE)).unwrap(),
            fs::read(&backup).unwrap()
        );

        let recovered =
            restore_encrypted_wallet_backup(&backup, &restored, network_id, passphrase).unwrap();
        assert_eq!(recovered.destination, created.destination);
        assert_eq!(
            inspect_wallet_key_storage(&restored).unwrap(),
            WalletKeyStorage::Encrypted
        );

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(backup_dir).unwrap();
        fs::remove_dir_all(restored).unwrap();
    }

    #[test]
    fn new_encrypted_wallet_refuses_overwrite_and_overlapping_backup() {
        let source = test_dir("new-wallet-overwrite");
        let backup_dir = test_dir("new-wallet-overwrite-backup");
        fs::create_dir_all(&backup_dir).unwrap();
        let first_backup = backup_dir.join("first.cmfd-backup");
        let second_backup = backup_dir.join("second.cmfd-backup");
        let network_id = [0x92; 32];
        let passphrase = b"correct horse battery staple";

        create_encrypted_wallet(&source, &first_backup, network_id, passphrase).unwrap();
        let original_wallet = fs::read(source.join(WALLET_KEY_FILE)).unwrap();
        assert!(matches!(
            create_encrypted_wallet(&source, &second_backup, network_id, passphrase),
            Err(WalletBackupError::WalletKeyAlreadyExists)
        ));
        assert_eq!(
            fs::read(source.join(WALLET_KEY_FILE)).unwrap(),
            original_wallet
        );
        assert!(!second_backup.exists());

        let overlapping = test_dir("new-wallet-overlap");
        fs::create_dir_all(&overlapping).unwrap();
        assert!(matches!(
            create_encrypted_wallet(
                &overlapping,
                &overlapping.join(WALLET_KEY_FILE),
                network_id,
                passphrase
            ),
            Err(WalletBackupError::OverlappingPaths)
        ));
        assert!(!overlapping.join(WALLET_KEY_FILE).exists());

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(backup_dir).unwrap();
        fs::remove_dir_all(overlapping).unwrap();
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

    #[test]
    fn plaintext_migration_creates_an_independent_backup_before_encrypting_live_key() {
        let source = test_dir("migration-source");
        let restored = test_dir("migration-restored");
        let backup = source.with_extension("migration.cmfd-wallet-backup");
        let destination = write_test_key(&source, 0x79);
        let network_id = [0x92; 32];
        let passphrase = b"correct horse battery staple";
        assert_eq!(
            inspect_wallet_key_storage(&source).unwrap(),
            WalletKeyStorage::Plaintext
        );

        let migrated =
            migrate_plaintext_wallet_key(&source, &backup, network_id, passphrase).unwrap();
        assert_eq!(migrated.destination, destination);
        assert_eq!(
            inspect_wallet_key_storage(&source).unwrap(),
            WalletKeyStorage::Encrypted
        );
        let live_bytes = fs::read(source.join(WALLET_KEY_FILE)).unwrap();
        let backup_bytes = fs::read(&backup).unwrap();
        assert_ne!(live_bytes, backup_bytes);
        let (_, live_info) = decrypt_wallet_key_bytes(&live_bytes, network_id, passphrase).unwrap();
        let (_, backup_info) =
            decrypt_wallet_key_bytes(&backup_bytes, network_id, passphrase).unwrap();
        assert_eq!(live_info.destination, destination);
        assert_eq!(backup_info.destination, destination);

        restore_encrypted_wallet_backup(&backup, &restored, network_id, passphrase).unwrap();
        assert!(matches!(
            migrate_plaintext_wallet_key(&source, &backup, network_id, passphrase),
            Err(WalletBackupError::AlreadyEncrypted)
        ));
        let _ = fs::remove_file(backup);
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(restored);
    }

    #[test]
    fn wallet_storage_inspection_rejects_non_files() {
        let source = test_dir("inspection-source");
        fs::create_dir_all(source.join(WALLET_KEY_FILE)).unwrap();
        assert!(matches!(
            inspect_wallet_key_storage(&source),
            Err(WalletBackupError::InvalidWalletKey)
        ));
        let _ = fs::remove_dir_all(source);
    }
}
