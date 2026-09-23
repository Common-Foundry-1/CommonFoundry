//! Offline preparation of reward keys and their address-bound candidate plan.
//! No node, network, release pin or mainnet activation is opened.

use crate::rcnet_candidate::{MainnetLaunchPlan, RcnetCandidateError};
use crate::wallet_backup::{
    self, ENCRYPTED_WALLET_KEY_BYTES, MAXIMUM_PASSPHRASE_BYTES, MINIMUM_PASSPHRASE_BYTES,
    WalletBackupError,
};
use crate::{DataDirLock, NodeError, WALLET_KEY_FILE, sync_parent_directory};
use cmfd_consensus::FixedRewardDestinations;
use k256::schnorr::SigningKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

const PLAN_FILE: &str = "MAINNET-PLAN.json";
const REPORT_FILE: &str = "REWARD-CUSTODY.json";
const INCOMPLETE_FILE: &str = "SETUP-INCOMPLETE";
const ROLES: [&str; 2] = ["steward", "community"];

pub struct RewardCustodyPaths {
    pub wallets_directory: PathBuf,
    pub backups_directory: PathBuf,
    pub public_directory: PathBuf,
    pub steward_passphrase_file: PathBuf,
    pub community_passphrase_file: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct RewardCustodyReport {
    pub schema: &'static str,
    pub launch_plan_digest: String,
    pub network_id: String,
    pub wallets: Vec<RewardWalletReport>,
    pub backups_authenticated: bool,
    pub mainnet_activation_authorized: bool,
}

#[derive(Debug, Serialize)]
pub struct RewardWalletReport {
    pub role: &'static str,
    pub destination: String,
    pub encrypted_wallet_sha256: String,
    pub encrypted_backup_sha256: String,
}

#[derive(Debug, Error)]
pub enum RewardCustodyError {
    #[error("reward custody path rejected: {0}")]
    Path(&'static str),
    #[error("reward custody output already exists: {0}")]
    Exists(PathBuf),
    #[error("reward custody artifact is invalid: {0}")]
    Artifact(&'static str),
    #[error("reward custody file operation failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wallet(#[from] WalletBackupError),
    #[error(transparent)]
    Plan(#[from] RcnetCandidateError),
    #[error(transparent)]
    Node(#[from] NodeError),
    #[error("reward custody JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[cfg(windows)]
    #[error("reward custody Windows permissions rejected: {0}")]
    Permissions(String),
}

fn absolute_clean(path: &Path) -> Result<(), RewardCustodyError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(RewardCustodyError::Path(
            "use absolute paths without dot components",
        ));
    }
    Ok(())
}

fn outside_repository(path: &Path) -> Result<(), RewardCustodyError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => {
                return Err(RewardCustodyError::Path(
                    "custody files must be outside Git working trees",
                ));
            }
            // The starting path may itself be a regular passphrase file.
            // A .git child cannot exist under it (ENOTDIR on Unix).
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn output_directory(path: &Path, new: bool) -> Result<PathBuf, RewardCustodyError> {
    absolute_clean(path)?;
    outside_repository(path)?;
    let parent = path
        .parent()
        .ok_or(RewardCustodyError::Path("output needs a parent"))?;
    let parent = fs::canonicalize(parent)?;
    let resolved = parent.join(
        path.file_name()
            .ok_or(RewardCustodyError::Path("output needs a directory name"))?,
    );
    outside_repository(&resolved)?;
    match fs::symlink_metadata(&resolved) {
        Ok(_) if new => return Err(RewardCustodyError::Exists(resolved)),
        Ok(metadata)
            if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse(&metadata) =>
        {
            return Err(RewardCustodyError::Path(
                "output must be a direct directory",
            ));
        }
        Ok(_) => (),
        Err(error) if new && error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(resolved)
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn directories(paths: &RewardCustodyPaths, new: bool) -> Result<[PathBuf; 3], RewardCustodyError> {
    let result = [
        output_directory(&paths.wallets_directory, new)?,
        output_directory(&paths.backups_directory, new)?,
        output_directory(&paths.public_directory, new)?,
    ];
    for (index, path) in result.iter().enumerate() {
        if result.iter().enumerate().any(|(other, candidate)| {
            other != index && (path.starts_with(candidate) || candidate.starts_with(path))
        }) {
            return Err(RewardCustodyError::Path(
                "wallet, backup and public output directories must be disjoint",
            ));
        }
    }
    Ok(result)
}

fn open_read(path: &Path, private: bool) -> Result<File, RewardCustodyError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse(&metadata) {
        return Err(RewardCustodyError::Artifact(
            "expected a direct regular file",
        ));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(RewardCustodyError::Path(
                "private files require mode 0600 or stricter",
            ));
        }
    }
    #[cfg(windows)]
    if private {
        crate::exchange_acl::validate_windows_custody_path_acl(
            &file,
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::JournalKey,
        )
        .map_err(|error| RewardCustodyError::Permissions(error.to_string()))?;
    }
    Ok(file)
}

fn read_bounded(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>, RewardCustodyError> {
    let mut bytes = Vec::new();
    open_read(path, private)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(RewardCustodyError::Artifact("file exceeds its size limit"));
    }
    Ok(bytes)
}

fn passphrase(
    path: &Path,
    outputs: &[PathBuf; 3],
) -> Result<Zeroizing<Vec<u8>>, RewardCustodyError> {
    absolute_clean(path)?;
    outside_repository(path)?;
    // Resolve the parent, but open the final component without following links.
    let resolved = fs::canonicalize(
        path.parent()
            .ok_or(RewardCustodyError::Path("passphrase needs a parent"))?,
    )?
    .join(
        path.file_name()
            .ok_or(RewardCustodyError::Path("passphrase needs a filename"))?,
    );
    outside_repository(&resolved)?;
    if outputs
        .iter()
        .any(|directory| resolved.starts_with(directory))
    {
        return Err(RewardCustodyError::Path(
            "passphrases must be stored outside every output directory",
        ));
    }
    let mut value = Zeroizing::new(Vec::with_capacity(MAXIMUM_PASSPHRASE_BYTES + 3));
    open_read(&resolved, true)?
        .take((MAXIMUM_PASSPHRASE_BYTES + 3) as u64)
        .read_to_end(&mut value)?;
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    if !(MINIMUM_PASSPHRASE_BYTES..=MAXIMUM_PASSPHRASE_BYTES).contains(&value.len()) {
        return Err(WalletBackupError::InvalidPassphrase.into());
    }
    Ok(value)
}

fn create_directory(path: &Path) -> Result<(), RewardCustodyError> {
    #[cfg(not(windows))]
    {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.recursive(false).create(path)?;
    }
    #[cfg(windows)]
    crate::exchange_acl::create_private_custody_directory(path)
        .map_err(|error| RewardCustodyError::Permissions(error.to_string()))?;
    sync_parent_directory(path)?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), RewardCustodyError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(windows)]
    if private {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC,
        };
        options.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
    }
    let mut file = options.open(path)?;
    #[cfg(windows)]
    if private {
        crate::exchange_acl::initialize_windows_node_owned_custody_file_acl(
            &file,
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::JournalKey,
        )
        .map_err(|error| RewardCustodyError::Permissions(error.to_string()))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_parent_directory(path)?;
    Ok(())
}

fn fresh_secret() -> Result<Zeroizing<[u8; 32]>, RewardCustodyError> {
    let mut secret = Zeroizing::new([0; 32]);
    for _ in 0..128 {
        getrandom::fill(secret.as_mut()).map_err(|error| io::Error::other(error.to_string()))?;
        if SigningKey::from_bytes(secret.as_ref()).is_ok() {
            return Ok(secret);
        }
    }
    Err(RewardCustodyError::Artifact(
        "OS randomness did not produce a valid signing key",
    ))
}

fn destination(secret: &[u8; 32]) -> Result<[u8; 32], RewardCustodyError> {
    Ok(SigningKey::from_bytes(secret)
        .map_err(|_| WalletBackupError::InvalidWalletKey)?
        .verifying_key()
        .to_bytes()
        .into())
}

/// Generate two independent keys, derive their candidate plan/network, then
/// encrypt both wallets/backups for that exact network. Partial failure preserves
/// created files and leaves SETUP-INCOMPLETE; no operator files are overwritten
/// or recursively removed. No real release pins are applied.
pub fn prepare_reward_custody(
    paths: &RewardCustodyPaths,
    pow_limit: [u8; 32],
    initial_target: [u8; 32],
) -> Result<RewardCustodyReport, RewardCustodyError> {
    prepare_inner(paths, pow_limit, initial_target, None)
}

/// Guided setup with independent passwords for the steward and community keys.
/// No plaintext password file is needed; the caller must use a protected pipe.
pub fn prepare_reward_custody_with_distinct_passwords(
    paths: &RewardCustodyPaths,
    pow_limit: [u8; 32],
    initial_target: [u8; 32],
    steward_password: &[u8],
    community_password: &[u8],
) -> Result<RewardCustodyReport, RewardCustodyError> {
    require_distinct_passwords(steward_password, community_password)?;
    prepare_inner(
        paths,
        pow_limit,
        initial_target,
        Some([steward_password, community_password]),
    )
}

fn require_distinct_passwords(
    steward_password: &[u8],
    community_password: &[u8],
) -> Result<(), RewardCustodyError> {
    if steward_password == community_password {
        return Err(RewardCustodyError::Artifact(
            "steward and community passwords must differ",
        ));
    }
    Ok(())
}

fn passwords(
    paths: &RewardCustodyPaths,
    dirs: &[PathBuf; 3],
    provided: Option<[&[u8]; 2]>,
) -> Result<[Zeroizing<Vec<u8>>; 2], RewardCustodyError> {
    let result = if let Some([steward, community]) = provided {
        if !(MINIMUM_PASSPHRASE_BYTES..=MAXIMUM_PASSPHRASE_BYTES).contains(&steward.len())
            || !(MINIMUM_PASSPHRASE_BYTES..=MAXIMUM_PASSPHRASE_BYTES).contains(&community.len())
        {
            return Err(WalletBackupError::InvalidPassphrase.into());
        }
        [
            Zeroizing::new(steward.to_vec()),
            Zeroizing::new(community.to_vec()),
        ]
    } else {
        [
            passphrase(&paths.steward_passphrase_file, dirs)?,
            passphrase(&paths.community_passphrase_file, dirs)?,
        ]
    };
    require_distinct_passwords(&result[0], &result[1])?;
    Ok(result)
}

fn prepare_inner(
    paths: &RewardCustodyPaths,
    pow_limit: [u8; 32],
    initial_target: [u8; 32],
    provided_passwords: Option<[&[u8]; 2]>,
) -> Result<RewardCustodyReport, RewardCustodyError> {
    if pow_limit == [0; 32] || initial_target == [0; 32] || initial_target > pow_limit {
        return Err(RewardCustodyError::Artifact(
            "invalid initial/easiest targets",
        ));
    }
    let dirs = directories(paths, true)?;
    let passwords = passwords(paths, &dirs, provided_passwords)?;
    let secrets = [fresh_secret()?, fresh_secret()?];
    let rewards = FixedRewardDestinations {
        steward: destination(&secrets[0])?,
        community: destination(&secrets[1])?,
    };
    if rewards.steward == rewards.community {
        return Err(RewardCustodyError::Artifact("reward keys must be distinct"));
    }
    let plan = MainnetLaunchPlan::from_release_artifacts(pow_limit, initial_target, rewards)?;
    let network_id = plan.network_id()?;
    let mut live = Vec::new();
    let mut backups = Vec::new();
    for index in 0..2 {
        backups.push(
            wallet_backup::encrypt_wallet_key_bytes(
                &secrets[index],
                network_id,
                &passwords[index],
            )?
            .0,
        );
        live.push(
            wallet_backup::encrypt_wallet_key_bytes(
                &secrets[index],
                network_id,
                &passwords[index],
            )?
            .0,
        );
    }
    for dir in &dirs {
        create_directory(dir)?;
    }
    write_new(
        &dirs[0].join(INCOMPLETE_FILE),
        b"Not complete. Preserve partial encrypted artifacts; do not use as release evidence.\n",
        false,
    )?;
    for (index, role) in ROLES.iter().enumerate() {
        write_new(
            &dirs[1].join(format!("{role}.cmfdwallet")),
            &backups[index],
            true,
        )?;
    }
    let mut _wallet_locks = Vec::new();
    for role in ROLES {
        let directory = dirs[0].join(role);
        create_directory(&directory)?;
        _wallet_locks.push(DataDirLock::acquire(&directory)?);
    }
    for (index, role) in ROLES.iter().enumerate() {
        write_new(
            &dirs[0].join(role).join(WALLET_KEY_FILE),
            &live[index],
            true,
        )?;
    }
    let report = authenticate_artifacts(&dirs, &passwords, &plan)?;
    // Public output is published locally only after all encrypted files have
    // authenticated. A candidate plan is not a release or activation approval.
    write_new(&dirs[2].join(PLAN_FILE), &plan.canonical_json()?, false)?;
    let mut report_bytes = serde_json::to_vec_pretty(&report)?;
    report_bytes.push(b'\n');
    write_new(&dirs[2].join(REPORT_FILE), &report_bytes, false)?;
    fs::remove_file(dirs[0].join(INCOMPLETE_FILE))?;
    sync_parent_directory(&dirs[0].join(INCOMPLETE_FILE))?;
    Ok(report)
}

fn authenticate_artifacts(
    dirs: &[PathBuf; 3],
    passwords: &[Zeroizing<Vec<u8>>; 2],
    plan: &MainnetLaunchPlan,
) -> Result<RewardCustodyReport, RewardCustodyError> {
    let network_id = plan.network_id()?;
    let rewards = plan.reward_destinations()?;
    let expected = [rewards.steward, rewards.community];
    let mut wallets = Vec::new();
    for (index, role) in ROLES.iter().enumerate() {
        let live = read_bounded(
            &dirs[0].join(role).join(WALLET_KEY_FILE),
            ENCRYPTED_WALLET_KEY_BYTES,
            true,
        )?;
        let backup = read_bounded(
            &dirs[1].join(format!("{role}.cmfdwallet")),
            ENCRYPTED_WALLET_KEY_BYTES,
            true,
        )?;
        let (live_secret, live_info) =
            wallet_backup::decrypt_wallet_key_bytes(&live, network_id, &passwords[index])?;
        let (backup_secret, backup_info) =
            wallet_backup::decrypt_wallet_key_bytes(&backup, network_id, &passwords[index])?;
        if live_info.destination != expected[index]
            || backup_info.destination != expected[index]
            || *live_secret != *backup_secret
            || live == backup
        {
            return Err(RewardCustodyError::Artifact(
                "wallet and independently encrypted backup do not match the plan",
            ));
        }
        wallets.push(RewardWalletReport {
            role,
            destination: hex::encode(expected[index]),
            encrypted_wallet_sha256: hex::encode(Sha256::digest(&live)),
            encrypted_backup_sha256: hex::encode(Sha256::digest(&backup)),
        });
    }
    Ok(RewardCustodyReport {
        schema: "CMFD_MAINNET_REWARD_CUSTODY_V1",
        launch_plan_digest: hex::encode(plan.digest()?),
        network_id: hex::encode(network_id),
        wallets,
        backups_authenticated: true,
        mainnet_activation_authorized: false,
    })
}

/// Authenticate prepared keys/backups against an externally selected plan digest.
/// Ordinary wallet directory locks are taken; keys and chain state are untouched.
pub fn verify_reward_custody(
    paths: &RewardCustodyPaths,
    expected_plan_digest: [u8; 32],
) -> Result<RewardCustodyReport, RewardCustodyError> {
    verify_inner(paths, expected_plan_digest, None)
}

/// Verify both independently protected wallets from separate in-memory passwords.
pub fn verify_reward_custody_with_distinct_passwords(
    paths: &RewardCustodyPaths,
    expected_plan_digest: [u8; 32],
    steward_password: &[u8],
    community_password: &[u8],
) -> Result<RewardCustodyReport, RewardCustodyError> {
    require_distinct_passwords(steward_password, community_password)?;
    verify_inner(
        paths,
        expected_plan_digest,
        Some([steward_password, community_password]),
    )
}

fn verify_inner(
    paths: &RewardCustodyPaths,
    expected_plan_digest: [u8; 32],
    provided_passwords: Option<[&[u8]; 2]>,
) -> Result<RewardCustodyReport, RewardCustodyError> {
    let dirs = directories(paths, false)?;
    if dirs[0].join(INCOMPLETE_FILE).try_exists()? {
        return Err(RewardCustodyError::Artifact(
            "setup is incomplete; preserve and review the partial output",
        ));
    }
    let passwords = passwords(paths, &dirs, provided_passwords)?;
    let plan = MainnetLaunchPlan::parse_pinned(
        &read_bounded(&dirs[2].join(PLAN_FILE), 32 * 1024, false)?,
        expected_plan_digest,
    )?;
    for role in ROLES {
        output_directory(&dirs[0].join(role), false)?;
    }
    let _steward_lock = DataDirLock::acquire(&dirs[0].join(ROLES[0]))?;
    let _community_lock = DataDirLock::acquire(&dirs[0].join(ROLES[1]))?;
    let report = authenticate_artifacts(&dirs, &passwords, &plan)?;
    let mut expected_report = serde_json::to_vec_pretty(&report)?;
    expected_report.push(b'\n');
    if read_bounded(&dirs[2].join(REPORT_FILE), 16 * 1024, false)? != expected_report {
        return Err(RewardCustodyError::Artifact(
            "public custody report differs from authenticated artifacts",
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
