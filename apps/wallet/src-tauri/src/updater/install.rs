//! Side-by-side install of a verified release (UPDATER-DESIGN.md section
//! 2.6, as trimmed by TRIMMED-SCOPE.md).
//!
//! A new version goes into its own sibling folder, `<iroot>/<package name>`,
//! and never over the running one. Everything happens in a private staging
//! dir on the same volume, `<iroot>/.cmfd-update-staging/<version>/`:
//!
//! 1. take `staging.lock`;
//! 2. download the runtime archive there, or reuse one kept from an earlier
//!    attempt if it still matches its signed size and SHA-256;
//! 3. hash the archive through a handle that is held while the system tar
//!    reads it (on Windows that handle denies writes and deletes);
//! 4. list the archive and refuse anything but plain files and folders
//!    under the one expected top-level folder, then extract it into `x/`;
//! 5. hash the archive through the same handle again;
//! 6. read `MAINNET-PACKAGE.json` from the extracted tree, check it against
//!    the signed release and this wallet's network ([`check_package_manifest`]),
//!    and check every file of the tree against it: nothing missing, nothing
//!    extra, no links, the listed size and SHA-256;
//! 7. carry the prepared inputs over ([`inputs::carry_over`]);
//! 8. run the new wallet's `--version` and `runtime-identity`;
//! 9. write `.cmfd-updater/` (the signed SUMS, signature and BUILDINFO, a copy
//!    of the checked package record, and `state.json` saying `staged`);
//! 10. rename the folder into `<iroot>`, which is the only step that makes
//!     it visible. A crash before it leaves only the staging dir; a crash
//!     after it leaves a complete, staged version;
//! 11. record the folder in this user's install registry ([`registry_dir`]).
//!     Only a recorded folder counts as installed, for the next install and
//!     for the launch forwarder. The registry is checked to be writable
//!     before step 2's archive is unpacked ([`check_registry`]), so one that
//!     cannot be written fails fast and keeps the archive. A folder that
//!     still could not be recorded is removed again, and an unrecorded
//!     folder of the same version that this user's updater left (a crash
//!     right after step 10, a lost registry) is moved to the trash before
//!     the next install ([`reclaim_unrecorded`]), so they do not pile up
//!     as `-auto` folders.
//!
//! The marker is written as `staged` right before the rename instead of as
//! `installing` before step 7 (design step 6), so no final-named folder is
//! ever half installed and there is nothing to recover at startup.
//!
//! On Linux every staging dir must belong to the user running the wallet
//! and be closed to everyone else ([`is_private_staging_dir`]).
//!
//! Nothing here knows the wallet's data dir. Failure records
//! (`updates.json.failed`) are written by the caller from [`InstallError`].
//! Before the launch forwarder starts anything from an installed folder, it
//! runs [`verify_installed`].

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::fetch::{self, Child, DownloadError};
use super::inputs::{self, CarriedInputs, InputsError};
use super::release::{
    self, CheckedPackage, MAX_PACKAGE_MANIFEST_BYTES, Platform, ReleaseError, VerifiedRelease,
    Version,
};

pub(crate) const STAGING_DIR_NAME: &str = ".cmfd-update-staging";
pub(crate) const MARKER_DIR_NAME: &str = ".cmfd-updater";
pub(crate) const STATE_FILE_NAME: &str = "state.json";
pub(crate) const PACKAGE_MANIFEST_NAME: &str = "MAINNET-PACKAGE.json";
const LOCK_FILE_NAME: &str = "staging.lock";
/// Under `.cmfd-update-staging`: request bodies while they are read. Not a
/// version name, so [`sweep_staging`] leaves it alone.
const SCRATCH_DIR_NAME: &str = "scratch";
/// A request body in the scratch dir this old was left by a request that
/// ended without deleting it (a crash or a kill): a live one ends within
/// its `--max-time` (minutes), so another wallet's request is never swept.
const STALE_SCRATCH_AGE: Duration = Duration::from_secs(60 * 60);
const EXTRACT_DIR_NAME: &str = "x";
/// Version folders that [`remove_version`] moved under
/// `.cmfd-update-staging` and has not checked yet. The sweep deletes one
/// only if it still holds nothing but its package files.
const TRASH_PREFIX: &str = "trash-";
/// Version folders that passed that check and are being deleted.
const DELETING_PREFIX: &str = "deleting-";
/// Folders that held more than their package files and could not be put
/// back under their name. Nothing ever deletes them.
const KEPT_PREFIX: &str = "kept-";
const STATE_TEMP_FILE_NAME: &str = "state.json.tmp";
const TAR_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SELF_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const TAR_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TOOL_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_TOOL_STDERR_BYTES: usize = 2048;
const MAX_STATE_BYTES: u64 = 64 * 1024;
/// The per-user install registry, under the base dir [`registry_dir`] names.
const REGISTRY_DIR_NAME: &str = "installed";
const MAX_REGISTRY_ENTRY_BYTES: u64 = 16 * 1024;
/// Free space kept beyond what a download or a copy needs.
pub(crate) const SPACE_MARGIN_BYTES: u64 = 1024 * 1024 * 1024;
/// The archive plus its extracted tree, which is a few times the archive.
const DOWNLOAD_SPACE_FACTOR: u64 = 4;
/// The highest `-auto<n>` suffix tried when a package name is taken.
const MAX_NAME_SUFFIX: u32 = 9;
/// Packaged files that must stay executable on Linux, besides `*.sh`.
#[cfg(unix)]
const LINUX_EXECUTABLES: [&str; 5] = [
    "cmfd-launch",
    "cmfd-node",
    "common-foundry-wallet",
    "production-v4/cmfd-v4-replay",
    "production-v4/real_bank0_relations",
];

/// Variables that change what tar lists or unpacks.
const TOOL_ENV_REMOVED: [&str; 4] = [
    "TAR_OPTIONS",
    "TAR_READER_OPTIONS",
    "TAR_WRITER_OPTIONS",
    "POSIXLY_CORRECT",
];

/// Removed for the system tar on Linux too, whose PATH is set to
/// `/usr/bin:/bin`: GNU tar runs `gzip` through PATH, and gzip reads $GZIP.
#[cfg(unix)]
const TAR_ENV_REMOVED_ON_LINUX: [&str; 3] = ["LD_PRELOAD", "LD_LIBRARY_PATH", "GZIP"];

/// What install needs from the system. Tests replace single methods.
pub(crate) trait Host {
    /// Runs `program` without a shell, tied to the wallet's lifetime, with
    /// every `CMFD_UPDATE_*` variable removed and `CMFD_UPDATE_FORWARDED=1`
    /// set, so a wallet started for a self-check never forwards. tar's
    /// option variables are removed too, and `LC_ALL=C` is set. On Linux the
    /// system tar also gets a fixed PATH and no preload or gzip variables.
    fn run(
        &self,
        program: &Path,
        args: &[OsString],
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<ToolOutput, String> {
        run_tool(program, args, timeout, cancel)
    }

    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        fs::hard_link(original, link)
    }

    fn available_space(&self, dir: &Path) -> io::Result<u64> {
        fs2::available_space(dir)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// The real system.
pub(crate) struct SystemHost;

impl Host for SystemHost {}

/// A program that exited by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolOutput {
    /// `None` if a signal ended it.
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl ToolOutput {
    fn describe(&self) -> String {
        let message = String::from_utf8_lossy(&self.stderr);
        let message = message.lines().next().unwrap_or("").trim().to_owned();
        match self.code {
            Some(code) if message.is_empty() => format!("exit code {code}"),
            Some(code) => format!("exit code {code}: {message}"),
            None => "stopped by a signal".into(),
        }
    }
}

fn run_tool(
    program: &Path,
    args: &[OsString],
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<ToolOutput, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("CMFD_UPDATE_") {
            command.env_remove(key);
        }
    }
    // GNU tar puts $TAR_OPTIONS before its arguments, and bsdtar reads
    // its own option variables; the locale changes how names are listed.
    for key in TOOL_ENV_REMOVED {
        command.env_remove(key);
    }
    command.env("LC_ALL", "C");
    #[cfg(unix)]
    if system_tar().as_deref() == Some(program) {
        command.env("PATH", "/usr/bin:/bin");
        for key in TAR_ENV_REMOVED_ON_LINUX {
            command.env_remove(key);
        }
    }
    command.env("CMFD_UPDATE_FORWARDED", "1");
    let name = program.display();
    let (mut child, stdout, stderr) = fetch::spawn_tied_to_wallet(&mut command)
        .map_err(|error| format!("could not start {name}: {error}"))?;
    let readers =
        fetch::bounded_reader(Box::new(stdout), MAX_TOOL_STDOUT_BYTES).and_then(|stdout| {
            Ok((
                stdout,
                fetch::bounded_reader(Box::new(stderr), MAX_TOOL_STDERR_BYTES)?,
            ))
        });
    let (stdout, stderr) = match readers {
        Ok(readers) => readers,
        Err(error) => {
            child.kill();
            return Err(format!("could not read from {name}: {error}"));
        }
    };
    let deadline = Instant::now() + timeout;
    let code = loop {
        if cancel.load(Ordering::Acquire) {
            child.kill();
            break Err("cancelled".to_owned());
        }
        if Instant::now() >= deadline {
            child.kill();
            break Err(format!("{name} did not finish in time"));
        }
        match child.try_wait() {
            Ok(Some(code)) => break Ok(code),
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(error) => {
                child.kill();
                break Err(format!("could not wait for {name}: {error}"));
            }
        }
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    Ok(ToolOutput {
        code: code?,
        stdout,
        stderr,
    })
}

/// The system tar: `tar.exe` in the System32 dir on Windows (bsdtar, which
/// reads .zip), the first of `/usr/bin/tar` and `/bin/tar` on Linux.
pub(crate) fn system_tar() -> Option<PathBuf> {
    #[cfg(windows)]
    let candidates = [fetch::system_directory()?.join("tar.exe")];
    #[cfg(not(windows))]
    let candidates = [PathBuf::from("/usr/bin/tar"), PathBuf::from("/bin/tar")];
    candidates.into_iter().find(|path| path.is_file())
}

fn tar_args(platform: Platform, list: bool, archive: &Path, into: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![if list { "-t" } else { "-x" }.into()];
    if platform == Platform::LinuxX86_64 {
        // GNU tar: gzip; never read `host:file` as a remote archive; keep the
        // packaged modes rather than the user's umask; files owned by us.
        args.extend(["-z", "--force-local"].map(OsString::from));
        if !list {
            args.extend(["-p", "--no-same-owner"].map(OsString::from));
        }
    }
    args.extend(["-f".into(), archive.as_os_str().to_owned()]);
    if !list {
        args.extend(["-C".into(), into.as_os_str().to_owned()]);
    }
    args
}

/// Where new versions go for a package folder whose parent is `root`.
///
/// Normally that is `root` itself. When `root` is cloud-synced (OneDrive),
/// versions go to `%LOCALAPPDATA%\CommonFoundry\versions` instead, so a 100 MB
/// package per update is not uploaded. Linux always uses `root`.
pub(crate) fn install_root(root: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let attributes = fs::metadata(root).map_or(0, |meta| meta.file_attributes());
        install_root_with(root, attributes, &|name| std::env::var_os(name))
    }
    #[cfg(not(windows))]
    {
        root.to_path_buf()
    }
}

#[cfg(windows)]
fn install_root_with(
    root: &Path,
    attributes: u32,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> PathBuf {
    const OFFLINE: u32 = 0x1000;
    const RECALL_ON_OPEN: u32 = 0x4_0000;
    const PINNED: u32 = 0x8_0000;
    const UNPINNED: u32 = 0x10_0000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;
    let synced_attributes =
        attributes & (OFFLINE | RECALL_ON_OPEN | PINNED | UNPINNED | RECALL_ON_DATA_ACCESS) != 0;
    let under_onedrive = ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
        .into_iter()
        .filter_map(env)
        .any(|base| starts_with_ignoring_case(root, Path::new(&base)));
    // A relative LOCALAPPDATA names no folder, as for registry_dir.
    match env("LOCALAPPDATA").filter(|local| Path::new(local).is_absolute()) {
        Some(local) if synced_attributes || under_onedrive => {
            Path::new(&local).join("CommonFoundry").join("versions")
        }
        _ => root.to_path_buf(),
    }
}

#[cfg(windows)]
fn starts_with_ignoring_case(path: &Path, base: &Path) -> bool {
    let lower = |path: &Path| -> Vec<String> {
        path.components()
            .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let (path, base) = (lower(path), lower(base));
    !base.is_empty() && path.len() >= base.len() && path[..base.len()] == base[..]
}

/// The folder name of a runtime package: its archive name without the
/// extension.
pub(crate) fn package_name(platform: Platform, version: Version) -> String {
    format!(
        "commonfoundry-mainnet-runtime-{}-v{version}",
        platform.name()
    )
}

/// Why an install did not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallError {
    Cancelled,
    /// Another wallet is installing this version.
    Busy,
    /// The install root or its staging dir cannot be used.
    Unusable(String),
    NoSpace {
        needed: u64,
        available: u64,
    },
    Download(DownloadError),
    /// The archive no longer matches its signed size and SHA-256. It was
    /// deleted, so the next attempt downloads it again.
    ArchiveChanged,
    /// tar is missing, refused the archive or failed.
    Tar(String),
    /// The archive holds something other than plain paths under the one
    /// expected folder.
    Layout(String),
    /// The package record inside the archive does not match the release,
    /// this platform or this wallet's network.
    Package(ReleaseError),
    /// A file of the extracted tree is missing, changed, extra or not a
    /// plain file. Antivirus quarantine shows up here as `missing`.
    Tree {
        path: String,
        problem: &'static str,
    },
    Inputs(InputsError),
    /// The new wallet answered `--version` or `runtime-identity` wrongly
    /// or failed. One that never answered is [`InstallError::Io`].
    SelfCheck(String),
    Io(String),
}

impl InstallError {
    /// Whether the next round may try the same release again by itself. The
    /// others repeat with the same archive (antivirus, tar, a bad package,
    /// a failing self-check) or wait for the user (copy consent, a manual
    /// install), and are only retried when the user asks.
    pub(crate) fn retry_automatically(&self) -> bool {
        match self {
            Self::Cancelled
            | Self::Busy
            | Self::Unusable(_)
            | Self::NoSpace { .. }
            | Self::Download(_)
            | Self::ArchiveChanged
            | Self::Io(_) => true,
            Self::Inputs(error) => matches!(error, InputsError::Io { .. }),
            Self::Tar(_)
            | Self::Layout(_)
            | Self::Package(_)
            | Self::Tree { .. }
            | Self::SelfCheck(_) => false,
        }
    }
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("the install was cancelled"),
            Self::Busy => f.write_str("another wallet is installing this version"),
            Self::Unusable(detail) => write!(f, "cannot install here: {detail}"),
            Self::NoSpace { needed, available } => write!(
                f,
                "the update needs {needed} bytes free, but only {available} are"
            ),
            Self::Download(error) => error.fmt(f),
            Self::ArchiveChanged => {
                f.write_str("the downloaded archive changed after it was checked")
            }
            Self::Tar(detail) => write!(f, "could not unpack the update: {detail}"),
            Self::Layout(detail) => {
                write!(f, "the update archive is not a runtime package: {detail}")
            }
            Self::Package(error) => error.fmt(f),
            Self::Tree { path, problem } => write!(f, "{path} is {problem} after unpacking"),
            Self::Inputs(error) => error.fmt(f),
            Self::SelfCheck(detail) => write!(f, "the new wallet failed its self-check: {detail}"),
            Self::Io(detail) => write!(f, "could not install the update: {detail}"),
        }
    }
}

impl std::error::Error for InstallError {}

fn io_error(context: &str, path: &Path, error: io::Error) -> InstallError {
    InstallError::Io(format!("{context} {}: {error}", path.display()))
}

/// `.cmfd-updater/state.json` of an installed version. Fields that later
/// steps add (start attempts, failures) are kept on every rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InstallState {
    pub(crate) state: String,
    pub(crate) version: String,
    pub(crate) sums_sha256: String,
    pub(crate) archive_sha256: String,
    pub(crate) staged_at: u64,
    #[serde(flatten)]
    pub(crate) extra: Map<String, Value>,
}

pub(crate) const STATE_STAGED: &str = "staged";
/// Written by the started version once it ran (design section 2.9).
pub(crate) const STATE_STARTED_OK: &str = "started_ok";
/// Written when a version failed to start; it is never the kept fallback.
pub(crate) const STATE_FAILED: &str = "failed";

/// Reads an installed version's state, or `None` if the folder has no
/// readable marker (it was not made by the updater, or is damaged).
pub(crate) fn read_state(package: &Path) -> Option<InstallState> {
    let path = package.join(MARKER_DIR_NAME).join(STATE_FILE_NAME);
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_STATE_BYTES {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

/// Writes `state.json` through a synced temporary sibling and a rename, and
/// flushes `.cmfd-updater/` so the new state survives a power loss.
pub(crate) fn write_state(package: &Path, state: &InstallState) -> io::Result<()> {
    let marker = package.join(MARKER_DIR_NAME);
    let temporary = marker.join(STATE_TEMP_FILE_NAME);
    let _ = fs::remove_file(&temporary);
    let bytes = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
    let result = (|| {
        let mut file = new_file_options().open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, marker.join(STATE_FILE_NAME))?;
        sync_dir(&marker)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// The installed folders of this release, in name order: their kept
/// `SHA256SUMS.txt`, signature and `BUILDINFO.json` are byte for byte the
/// ones `release` was verified from, and their state names the same version
/// and archive; and this user's install registry records them with their
/// package record ([`registry_dir`]). A folder someone else made from the
/// release's public files does not count, so it is never adopted as this
/// install. After a reinstall, a damaged copy and the new one both count;
/// [`check_release_files`] tells them apart.
pub(crate) fn installed_copies(
    iroot: &Path,
    platform: Platform,
    release: &VerifiedRelease,
    registry: &Path,
) -> Vec<PathBuf> {
    let name = package_name(platform, release.version);
    candidate_names(&name)
        .map(|name| iroot.join(name))
        .filter(|dir| {
            is_private_dir(dir)
                && is_private_dir(&dir.join(MARKER_DIR_NAME))
                && read_marker_files(dir).is_some_and(|(sums, signature, buildinfo)| {
                    sums == release.sums
                        && signature == release.signature
                        && buildinfo == release.buildinfo
                })
                && read_state(dir).is_some_and(|state| {
                    state.version == release.version.to_string()
                        && state.sums_sha256 == hex::encode(release.sums_sha256)
                        && state.archive_sha256 == hex::encode(release.asset_sha256)
                })
                && read_bounded(&dir.join(PACKAGE_MANIFEST_NAME), MAX_PACKAGE_MANIFEST_BYTES)
                    .is_ok_and(|record| is_registered(registry, dir, &record, release.sums_sha256))
        })
        .collect()
}

/// Where this user's install registry is: `%LOCALAPPDATA%\CommonFoundry\installed`
/// on Windows, `$XDG_DATA_HOME/CommonFoundry/installed` (else
/// `~/.local/share/CommonFoundry/installed`) on Linux. `None` without an
/// absolute base dir, and then nothing is installed or forwarded to.
///
/// SUMS signs only the archive, which is deleted after the install, and the
/// kept package record (which holds the exe hash) is not signed by itself.
/// Anyone who can create a folder in a shared root (a drive root, a FAT or
/// exFAT drive) could put a release's public signed files beside an exe of
/// their own and a record that lists it. The registry is what ties an
/// installed folder to an archive that matched its signed SHA-256: one file
/// per folder, named by the SHA-256 of the folder's canonical path, holding
/// the SHA-256 of its package record and of its SUMS. Only this user can
/// write it (on Windows by the default ACL of `%LOCALAPPDATA%`; on Linux it
/// is checked to be this user's and closed to writes by others).
///
/// **Frozen across versions** (an older forwarder reads entries a newer
/// updater wrote): the dir above; one `<hex SHA-256 of the canonical folder
/// path's encoded bytes>.json` per folder; a JSON object with
/// `package_record_sha256` and `sums_sha256` (lowercase hex), compared
/// exactly, and `folder`, which is only for people and never compared.
/// Fields may be added; none may be renamed or change meaning.
///
/// The registry ties a folder path to an archive; it does not pin the
/// folder itself. An entry survives a folder deleted by hand, and a folder
/// made again at the same path counts if every listed file is byte for
/// byte the release's ([`verify_installed`] hashes them all). Whoever can
/// change files inside a version folder can still change them after that
/// check, as in the folder the user unpacked by hand.
pub(crate) fn registry_dir(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    #[cfg(windows)]
    let base = PathBuf::from(env("LOCALAPPDATA")?);
    #[cfg(not(windows))]
    let base = match env("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|base| base.is_absolute())
    {
        Some(base) => base,
        None => PathBuf::from(env("HOME")?).join(".local").join("share"),
    };
    base.is_absolute()
        .then(|| base.join("CommonFoundry").join(REGISTRY_DIR_NAME))
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistryEntry {
    /// For people reading the file; the file name is what binds the path.
    /// Never compared.
    folder: String,
    package_record_sha256: String,
    sums_sha256: String,
}

impl RegistryEntry {
    fn new(folder: String, record: &[u8], sums_sha256: [u8; 32]) -> Self {
        Self {
            folder,
            package_record_sha256: hex::encode(sha256(record)),
            sums_sha256: hex::encode(sums_sha256),
        }
    }
}

/// The registry file of a version folder and the folder's canonical path.
fn registry_entry(registry: &Path, package: &Path) -> Option<(PathBuf, String)> {
    let canonical = fs::canonicalize(package).ok()?;
    let name = hex::encode(sha256(canonical.as_os_str().as_encoded_bytes()));
    Some((
        registry.join(format!("{name}.json")),
        canonical.to_string_lossy().into_owned(),
    ))
}

/// On Linux the registry and the folder that holds it must be this user's
/// and closed to writes by others.
fn is_private_registry(registry: &Path) -> bool {
    is_private_dir(registry) && registry.parent().is_some_and(is_private_dir)
}

/// Creates the registry dir if needed (0700 on Linux) and checks that it
/// is private ([`is_private_registry`]).
fn prepare_registry(registry: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(registry)?;
    if !is_private_registry(registry) {
        return Err(io::Error::other(format!(
            "{} is not a private folder of this user",
            registry.display()
        )));
    }
    Ok(())
}

/// Whether an install could be recorded in `registry`: [`prepare_registry`]
/// and a test file written and removed again. [`install`] runs it before
/// it unpacks anything, so a registry that cannot be written costs no
/// extraction or bank copy; a caller may also run it before a download.
pub(crate) fn check_registry(registry: &Path) -> io::Result<()> {
    prepare_registry(registry)?;
    let probe = registry.join(format!(".probe-{}", std::process::id()));
    let _ = fs::remove_file(&probe);
    let written = write_synced(&probe, b"probe");
    let removed = fs::remove_file(&probe);
    written.and(removed)
}

/// Records `package`, at its canonical path, as installed from an archive
/// that matched its signed SHA-256, with this package record and SUMS.
pub(crate) fn register_installed(
    registry: &Path,
    package: &Path,
    record: &[u8],
    sums_sha256: [u8; 32],
) -> io::Result<()> {
    prepare_registry(registry)?;
    let (path, folder) = registry_entry(registry, package)
        .ok_or_else(|| io::Error::other(format!("cannot resolve {}", package.display())))?;
    let bytes = serde_json::to_vec_pretty(&RegistryEntry::new(folder, record, sums_sha256))
        .map_err(io::Error::other)?;
    let temporary = path.with_extension("json.tmp");
    let _ = fs::remove_file(&temporary);
    let result = write_synced(&temporary, &bytes)
        .and_then(|()| fs::rename(&temporary, &path))
        .and_then(|()| sync_dir(registry));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Whether this user's registry records `package`, at its canonical path,
/// with exactly this package record and SUMS (`folder` is not compared).
fn is_registered(registry: &Path, package: &Path, record: &[u8], sums_sha256: [u8; 32]) -> bool {
    let Some((path, _)) = registry_entry(registry, package) else {
        return false;
    };
    let expected = RegistryEntry::new(String::new(), record, sums_sha256);
    is_private_registry(registry)
        && read_bounded(&path, MAX_REGISTRY_ENTRY_BYTES)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<RegistryEntry>(&bytes).ok())
            .is_some_and(|entry| {
                entry.package_record_sha256 == expected.package_record_sha256
                    && entry.sums_sha256 == expected.sums_sha256
            })
}

/// [`is_registered`] with the folder's own package record and kept SUMS.
fn is_registered_folder(registry: &Path, package: &Path) -> bool {
    let record = read_bounded(
        &package.join(PACKAGE_MANIFEST_NAME),
        MAX_PACKAGE_MANIFEST_BYTES,
    );
    let sums = read_bounded(
        &package.join(MARKER_DIR_NAME).join(release::SUMS_NAME),
        release::MAX_SUMS_BYTES,
    );
    match (record, sums) {
        (Ok(record), Ok(sums)) => is_registered(registry, package, &record, sha256(&sums)),
        _ => false,
    }
}

/// The `state.json` field that names the registry an install was made
/// for, so one user's updater never takes another user's folder in a
/// shared root for its own leftover ([`reclaim_unrecorded`]). Frozen with
/// the other state fields: the hex SHA-256 of the registry path's encoded
/// bytes, as [`registry_dir`] built it from the environment. A path spelled
/// differently (another case, a trailing separator) only means no reclaim,
/// and the install takes the next `-auto` name as before.
const INSTALLED_FOR_FIELD: &str = "installed_for";

fn installed_for(registry: &Path) -> String {
    hex::encode(sha256(registry.as_os_str().as_encoded_bytes()))
}

/// Forgets `package`, so a folder made later under the same path is never
/// taken for it.
pub(crate) fn unregister_installed(registry: &Path, package: &Path) -> io::Result<()> {
    let Some((path, _)) = registry_entry(registry, package) else {
        return Ok(());
    };
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// The kept signed files of an installed version.
fn read_marker_files(package: &Path) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let marker = package.join(MARKER_DIR_NAME);
    let read = |name: &str, max: u64| read_bounded(&marker.join(name), max).ok();
    Some((
        read(release::SUMS_NAME, release::MAX_SUMS_BYTES)?,
        read(release::SIGNATURE_NAME, release::MAX_SIGNATURE_BYTES)?,
        read(release::BUILDINFO_NAME, release::MAX_BUILDINFO_BYTES)?,
    ))
}

/// The version an installed folder's name gives (`...-v1.0.17`, or with an
/// `-auto`, `-auto2` ... suffix).
pub(crate) fn folder_version(package: &Path, platform: Platform) -> Option<Version> {
    let name = package.file_name()?.to_str()?;
    let rest = name.strip_prefix(&format!(
        "commonfoundry-mainnet-runtime-{}-v",
        platform.name()
    ))?;
    let version = Version::parse(
        rest.split_once("-auto")
            .map_or(rest, |(version, _)| version),
    )?;
    candidate_names(&package_name(platform, version))
        .any(|candidate| candidate == name)
        .then_some(version)
}

/// Why [`verify_installed`] refused a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MarkerError(pub(crate) String);

/// An installed version that passed [`verify_installed`].
#[derive(Debug)]
pub(crate) struct VerifiedInstall {
    /// From the signed `BUILDINFO.json`, never from `state.json`.
    pub(crate) version: Version,
    pub(crate) exe_path: PathBuf,
    /// The wallet exe, hashed through this handle. On Windows it denies
    /// writes, renames and deletes, so the forwarder holds it until the exe
    /// has been started from `exe_path`.
    pub(crate) exe: File,
}

/// Every offline check of an installed version folder, for the launch
/// forwarder, which must run this before it starts anything from a folder:
/// [`verify_marker`]; the folder recorded in this user's install `registry`
/// with this package record and SUMS ([`registry_dir`]), which ties the
/// record to an archive that matched its signed SHA-256; the record checked
/// again against the signed version, commit and this wallet's network;
/// every listed file present as a plain file of its listed size (an
/// antivirus quarantine or a truncation shows up here); and every listed
/// file hashed against the record, the wallet exe first and through the
/// handle that is returned.
///
/// The listed files are about 150 MB (the 6.4 GB bank is a carried input,
/// not listed), so this reads that much at each forwarded launch. Whoever
/// can change files inside the folder itself (not just create folders
/// beside it) could still swap one after it was hashed, before the wallet
/// or its mining sidecar opens it; the same is true of the package folder
/// the user unpacked by hand.
pub(crate) fn verify_installed(
    package: &Path,
    platform: Platform,
    network_id: Option<[u8; 32]>,
    registry: &Path,
) -> Result<VerifiedInstall, MarkerError> {
    let refuse = |why: &str| MarkerError(format!("{}: {why}", package.display()));
    let (signed, record, sums_sha256) = verify_marker(package, platform)?;
    if !is_registered(registry, package, &record, sums_sha256) {
        return Err(refuse("this user's updater did not install it here"));
    }
    let checked = release::check_kept_package_manifest(&record, platform, &signed, network_id)
        .map_err(|error| refuse(&error.to_string()))?;
    let (exe_path, exe) =
        check_package_files(package, &checked, platform).map_err(|why| refuse(&why))?;
    Ok(VerifiedInstall {
        version: signed.version,
        exe_path,
        exe,
    })
}

/// The checks of [`verify_installed`] that read no file contents: the
/// marker, the registry record, the package record against the signed
/// release, and every listed file present as a plain file of its listed
/// size. An antivirus quarantine or a truncated file shows up here, without
/// hashing about 150 MB; a file changed in place at the same size does not,
/// and the forwarder's full check still refuses it.
pub(crate) fn check_installed_files(
    package: &Path,
    platform: Platform,
    network_id: Option<[u8; 32]>,
    registry: &Path,
) -> Result<(), MarkerError> {
    let refuse = |why: &str| MarkerError(format!("{}: {why}", package.display()));
    let (signed, record, sums_sha256) = verify_marker(package, platform)?;
    if !is_registered(registry, package, &record, sums_sha256) {
        return Err(refuse("this user's updater did not install it here"));
    }
    let checked = release::check_kept_package_manifest(&record, platform, &signed, network_id)
        .map_err(|error| refuse(&error.to_string()))?;
    check_files_present(package, &checked, platform).map_err(|why| refuse(&why))
}

/// [`check_installed_files`] for a folder [`installed_copies`] found for
/// `release`: its signed files already matched the verified release byte
/// for byte, so its package record is checked against that release and
/// every listed file must be present at its listed size.
pub(crate) fn check_release_files(
    package: &Path,
    platform: Platform,
    release: &VerifiedRelease,
    network_id: Option<[u8; 32]>,
) -> Result<(), MarkerError> {
    let refuse = |why: &str| MarkerError(format!("{}: {why}", package.display()));
    let record = read_bounded(
        &package.join(PACKAGE_MANIFEST_NAME),
        MAX_PACKAGE_MANIFEST_BYTES,
    )
    .map_err(|_| refuse("the package record cannot be read"))?;
    let checked = release::check_package_manifest(&record, platform, release, network_id)
        .map_err(|error| refuse(&error.to_string()))?;
    check_files_present(package, &checked, platform).map_err(|why| refuse(&why))
}

/// The cheap checks of [`verify_installed`], without hashing the listed
/// files: [`verify_marker`] and the folder recorded in this user's install
/// `registry`. Enough to take prepared mining caches from a folder, which are
/// matched by their own chunk entry and size, not by the package files.
pub(crate) fn is_registered_install(package: &Path, platform: Platform, registry: &Path) -> bool {
    verify_marker(package, platform).is_ok_and(|(_, record, sums_sha256)| {
        is_registered(registry, package, &record, sums_sha256)
    })
}

/// The marker checks of [`verify_installed`]: a real, private folder; its
/// kept `SHA256SUMS.txt` signed by a pinned key; the version from the
/// signed `BUILDINFO.json` equal to the folder name's and the state's; the
/// state's archive and SUMS hashes equal to the signed ones; and the
/// package record equal to its kept copy. Returns the signed files, the
/// record and the SHA-256 of the kept SUMS.
fn verify_marker(
    package: &Path,
    platform: Platform,
) -> Result<(release::SignedFiles, Vec<u8>, [u8; 32]), MarkerError> {
    let refuse = |why: &str| Err(MarkerError(format!("{}: {why}", package.display())));
    let marker = package.join(MARKER_DIR_NAME);
    if !is_private_dir(package) || !is_private_dir(&marker) {
        return refuse("not a private folder of this user");
    }
    let Some(version) = folder_version(package, platform) else {
        return refuse("not a version folder name");
    };
    let Some((sums, signature, buildinfo)) = read_marker_files(package) else {
        return refuse("the signed files are missing");
    };
    let signed = release::verify_signed_files(platform, version, &sums, &signature, &buildinfo)
        .map_err(|error| MarkerError(format!("{}: {error}", package.display())))?;
    let Some(state) = read_state(package) else {
        return refuse("no readable state");
    };
    let sums_sha256 = sha256(&sums);
    if state.version != signed.version.to_string()
        || state.archive_sha256 != hex::encode(signed.asset_sha256)
        || state.sums_sha256 != hex::encode(sums_sha256)
    {
        return refuse("the state does not match the signed files");
    }
    let record = read_bounded(
        &package.join(PACKAGE_MANIFEST_NAME),
        MAX_PACKAGE_MANIFEST_BYTES,
    );
    let copy = read_bounded(
        &marker.join(PACKAGE_MANIFEST_NAME),
        MAX_PACKAGE_MANIFEST_BYTES,
    );
    match (record, copy) {
        (Ok(record), Ok(copy)) if record == copy => Ok((signed, record, sums_sha256)),
        _ => refuse("the package record does not match its kept copy"),
    }
}

/// Every file `checked` lists must be a plain file of its listed size (and,
/// on Linux, of the right mode) and hash to its listed SHA-256, the wallet
/// exe first. Returns the exe's path and the handle it was hashed through.
fn check_package_files(
    package: &Path,
    checked: &CheckedPackage,
    platform: Platform,
) -> Result<(PathBuf, File), String> {
    check_files_present(package, checked, platform)?;
    let name = wallet_exe_name(platform);
    let listed = checked
        .files()
        .get(name)
        .ok_or_else(|| format!("the package record lists no {name}"))?;
    let path = package.join(name);
    let exe = open_denying_writes(&path).map_err(|error| error.to_string())?;
    if !same_file(&exe, &path) || identify(&exe).ok() != Some((listed.bytes, listed.sha256)) {
        return Err(format!("{name} changed"));
    }
    for (relative, listed) in checked.files() {
        if relative == name {
            continue;
        }
        let file_path = package.join(relative);
        let matches = File::open(&file_path).is_ok_and(|file| {
            same_file(&file, &file_path)
                && identify(&file).ok() == Some((listed.bytes, listed.sha256))
        });
        if !matches {
            return Err(format!("{relative} changed"));
        }
    }
    Ok((path, exe))
}

/// Every file `checked` lists is a plain file of its listed size (and, on
/// Linux, of the right mode).
fn check_files_present(
    package: &Path,
    checked: &CheckedPackage,
    platform: Platform,
) -> Result<(), String> {
    for (relative, listed) in checked.files() {
        let present = fs::symlink_metadata(package.join(relative)).is_ok_and(|meta| {
            meta.is_file()
                && !is_reparse_point(&meta)
                && meta.len() == listed.bytes
                && check_mode(relative, &meta, platform).is_ok()
        });
        if !present {
            return Err(format!("{relative} is missing or changed"));
        }
    }
    Ok(())
}

fn wallet_exe_name(platform: Platform) -> &'static str {
    match platform {
        Platform::WindowsX86_64 => "common-foundry-wallet.exe",
        Platform::LinuxX86_64 => "common-foundry-wallet",
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    digest
}

/// A real dir (see [`is_real_dir`]). On Linux it must also belong to the
/// user running the wallet and not be writable by group or others.
fn is_private_dir(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_dir() && !is_reparse_point(&meta) && is_owned_privately(&meta, 0o022)
}

/// A staging dir: a real dir that, on Linux, belongs to the user running
/// the wallet and that nobody else can even enter. Whoever can create
/// or rename entries in it could swap the tree between its checks and the
/// rename into place. On Windows it inherits the install root's ACL; the
/// DACL check was dropped for 1.0.16 (TRIMMED-SCOPE.md).
fn is_private_staging_dir(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_dir() && !is_reparse_point(&meta) && is_owned_privately(&meta, 0o077)
}

/// Owned by the user running the wallet (the effective uid), with none of
/// the `forbidden` permission bits set. Not the owner of the wallet's exe:
/// the dirs checked here are ones this process made (the registry, staging,
/// installed versions) or must trust as its own user's, and a package
/// unpacked with `sudo` has an exe owned by root or by the uid stored in
/// the archive, which would match none of them.
#[cfg(unix)]
pub(crate) fn is_owned_privately(meta: &fs::Metadata, forbidden: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let user = unsafe { libc::geteuid() };
    meta.uid() == user && meta.mode() & forbidden == 0
}

#[cfg(not(unix))]
pub(crate) fn is_owned_privately(_meta: &fs::Metadata, _forbidden: u32) -> bool {
    true
}

/// The install root must be a real dir. On Linux it must not be writable
/// by everyone unless it has the sticky bit (like /tmp), which stops other
/// users from renaming the staging dir away. A group-writable root is
/// accepted: on Ubuntu that group is the user's own private group.
pub(crate) fn check_install_root(iroot: &Path) -> Result<(), InstallError> {
    let meta = fs::symlink_metadata(iroot)
        .ok()
        .filter(|meta| meta.is_dir() && !is_reparse_point(meta))
        .ok_or_else(|| InstallError::Unusable(format!("{} is not a folder", iroot.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o002 != 0 && meta.mode() & 0o1000 == 0 {
            return Err(InstallError::Unusable(format!(
                "any user can change {}",
                iroot.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(())
}

fn candidate_names(name: &str) -> impl Iterator<Item = String> + '_ {
    std::iter::once(name.to_owned()).chain((1..=MAX_NAME_SUFFIX).map(move |n| match n {
        1 => format!("{name}-auto"),
        n => format!("{name}-auto{n}"),
    }))
}

/// A dir and not a link to one (on Windows, not a junction either).
pub(crate) fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir() && !is_reparse_point(&meta))
}

#[cfg(windows)]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// An exclusive OS lock on `staging.lock`, held while the file is open. The
/// OS releases it when the wallet exits or dies, so a lock file left behind
/// never blocks the next attempt. The file itself is never deleted: a
/// waiter could otherwise lock the deleted file while a third process locks
/// a new one under the same name. The pid and time in it are only
/// diagnostics.
struct StagingLock {
    _file: File,
}

impl StagingLock {
    fn acquire(dir: &Path) -> Result<Option<Self>, InstallError> {
        let path = dir.join(LOCK_FILE_NAME);
        if fs::symlink_metadata(&path).is_ok_and(|meta| !meta.is_file() || is_reparse_point(&meta))
        {
            return Err(InstallError::Unusable(format!(
                "{} is not a plain file",
                path.display()
            )));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options
            .open(&path)
            .map_err(|error| io_error("cannot lock", &path, error))?;
        // A link planted after the check above was followed by the open;
        // the handle must be the plain file the name gives, or nothing is
        // written through it.
        if !file.metadata().is_ok_and(|meta| meta.is_file()) || !same_file(&file, &path) {
            return Err(InstallError::Unusable(format!(
                "{} is not a plain file",
                path.display()
            )));
        }
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => {}
            Err(error) if is_lock_contended(&error) => return Ok(None),
            Err(error) => return Err(io_error("cannot lock", &path, error)),
        }
        let _ = file.set_len(0).and_then(|()| {
            writeln!(
                file,
                "{{\"pid\":{},\"locked_at\":{}}}",
                std::process::id(),
                unix_now()
            )
        });
        Ok(Some(Self { _file: file }))
    }
}

pub(super) fn is_lock_contended(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || error.raw_os_error().is_some()
            && error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

/// The locked staging dir of one version. Dropping it releases the lock
/// and keeps the dir (with any kept archive) for the next attempt.
pub(crate) struct Staging {
    dir: PathBuf,
    _lock: StagingLock,
}

impl Staging {
    /// Creates `<iroot>/.cmfd-update-staging/<version>/` (mode 0700 on
    /// Linux; on Windows it inherits the folder's permissions) and locks it.
    /// On Linux an existing one must be private ([`is_private_staging_dir`]).
    pub(crate) fn open(iroot: &Path, version: Version) -> Result<Self, InstallError> {
        check_install_root(iroot)?;
        let parent = iroot.join(STAGING_DIR_NAME);
        let dir = parent.join(version.to_string());
        for path in [&parent, &dir] {
            create_private_dir(path)?;
        }
        let lock = StagingLock::acquire(&dir)?.ok_or(InstallError::Busy)?;
        sweep_staging(&parent, version);
        Ok(Self { dir, _lock: lock })
    }

    #[cfg(test)]
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The release's archive in the staging dir: one kept from an earlier
    /// attempt if it still matches, otherwise a fresh `download`
    /// (in the wallet, [`fetch::Curl::download_archive`] into this dir).
    pub(crate) fn archive(
        &self,
        release: &VerifiedRelease,
        host: &dyn Host,
        download: impl FnOnce(&Path) -> Result<PathBuf, DownloadError>,
    ) -> Result<PathBuf, InstallError> {
        let archive = self.dir.join(fetch::ARCHIVE_NAME);
        if fs::symlink_metadata(&archive).is_ok() {
            let kept = File::open(&archive)
                .and_then(|file| identify(&file))
                .is_ok_and(|identity| identity == (release.asset_size, release.asset_sha256));
            if kept {
                return Ok(archive);
            }
            fs::remove_file(&archive)
                .map_err(|error| io_error("cannot remove", &archive, error))?;
        }
        let needed = release
            .asset_size
            .saturating_mul(DOWNLOAD_SPACE_FACTOR)
            .saturating_add(SPACE_MARGIN_BYTES);
        if let Ok(available) = host.available_space(&self.dir)
            && available < needed
        {
            return Err(InstallError::NoSpace { needed, available });
        }
        let downloaded = download(&self.dir).map_err(|error| match error {
            DownloadError::Cancelled => InstallError::Cancelled,
            error => InstallError::Download(error),
        })?;
        if downloaded != archive {
            return Err(InstallError::Unusable(
                "the download did not land in the staging dir".into(),
            ));
        }
        Ok(archive)
    }

    /// Empties the staging dir after a finished install. Only the lock file
    /// stays (see [`StagingLock`]).
    fn finish(self) {
        clear_staging_dir(&self.dir);
    }
}

/// `<iroot>/.cmfd-update-staging/scratch/`, created private like a staging
/// dir: where [`fetch::Curl`] keeps request bodies while they are read.
/// Bodies older than [`STALE_SCRATCH_AGE`] are deleted, best effort.
pub(crate) fn scratch_dir(iroot: &Path) -> Result<PathBuf, InstallError> {
    check_install_root(iroot)?;
    let parent = iroot.join(STAGING_DIR_NAME);
    let dir = parent.join(SCRATCH_DIR_NAME);
    for path in [&parent, &dir] {
        create_private_dir(path)?;
    }
    sweep_scratch(&dir, SystemTime::now());
    Ok(dir)
}

/// Deletes the request bodies (`get-*.body` plain files) in `dir` last
/// changed more than [`STALE_SCRATCH_AGE`] before `now`.
fn sweep_scratch(dir: &Path, now: SystemTime) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !(name.starts_with("get-") && name.ends_with(".body")) {
            continue;
        }
        let path = entry.path();
        let stale = fs::symlink_metadata(&path).is_ok_and(|meta| {
            meta.is_file()
                && meta.modified().is_ok_and(|modified| {
                    now.duration_since(modified)
                        .is_ok_and(|age| age > STALE_SCRATCH_AGE)
                })
        });
        if stale {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Cleans what earlier attempts left under `.cmfd-update-staging`: the
/// staging dirs of versions other than `installing` that nobody holds
/// (below it: superseded; above it: a release that is no longer offered),
/// with what they hold (a kept
/// archive, a half-extracted tree, a partial bank copy), and version folders
/// that [`remove_version`] moved to the trash and that still hold only
/// their package files.
fn sweep_staging(parent: &Path, installing: Version) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_real_dir(&path) {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // A trash dir is checked again: its put-back may have failed, or
        // another wallet may still be checking it.
        if name.starts_with(DELETING_PREFIX)
            || (name.starts_with(TRASH_PREFIX) && is_removable_trash(&path))
        {
            let _ = fs::remove_dir_all(&path);
        } else if Version::parse(&name).is_some_and(|version| version != installing)
            && is_private_staging_dir(&path)
            && let Ok(Some(lock)) = StagingLock::acquire(&path)
        {
            clear_staging_dir(&path);
            drop(lock);
        }
    }
}

/// Removes everything in a version's staging dir except its lock file.
fn clear_staging_dir(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name() == LOCK_FILE_NAME {
            continue;
        }
        let path = entry.path();
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() && !is_reparse_point(&meta) => {
                let _ = fs::remove_dir_all(&path);
            }
            Ok(_) => {
                // A link to a dir needs remove_dir on Windows.
                let _ = fs::remove_file(&path).or_else(|_| fs::remove_dir(&path));
            }
            Err(_) => {}
        }
    }
}

fn create_private_dir(path: &Path) -> Result<(), InstallError> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error("cannot create", path, error)),
    }
    // One that was already there, or that replaced ours right after the
    // create, must be private too.
    if !is_private_staging_dir(path) {
        return Err(InstallError::Unusable(format!(
            "{} is not a private folder of this user",
            path.display()
        )));
    }
    Ok(())
}

/// Where and how to install.
pub(crate) struct InstallTarget<'a> {
    /// Where the new version folder goes ([`install_root`]).
    pub(crate) iroot: &'a Path,
    /// The running package folder, which the prepared inputs come from.
    pub(crate) running: &'a Path,
    pub(crate) platform: Platform,
    /// This wallet's network. `None` (no mainnet identity compiled in)
    /// matches no package.
    pub(crate) network_id: Option<[u8; 32]>,
    /// The user agreed to copy the bank if it cannot be hard-linked.
    pub(crate) allow_bank_copy: bool,
    /// This user's install registry ([`registry_dir`]).
    pub(crate) registry: &'a Path,
}

/// A version that is ready to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Installed {
    pub(crate) dir: PathBuf,
    pub(crate) version: Version,
    /// `None` when this release was already installed.
    pub(crate) inputs: Option<CarriedInputs>,
}

/// Installs `release` from the archive in `staging` (see the module doc).
/// On success the staging dir is gone. On failure the extracted tree is
/// removed and the archive is kept for a retry, unless it no longer matched.
pub(crate) fn install(
    staging: Staging,
    release: &VerifiedRelease,
    target: &InstallTarget<'_>,
    host: &dyn Host,
    cancel: &AtomicBool,
) -> Result<Installed, InstallError> {
    // First: an unusable registry records nothing, so without this check
    // every recorded folder would look like a leftover to reclaim.
    check_registry(target.registry).map_err(|error| {
        InstallError::Unusable(format!(
            "cannot record installs in {}: {error}",
            target.registry.display()
        ))
    })?;
    // A copy with files missing is not this install: a reinstall puts a
    // new one beside it, under the next free name.
    if let Some(dir) = installed_copies(target.iroot, target.platform, release, target.registry)
        .into_iter()
        .find(|dir| check_release_files(dir, target.platform, release, target.network_id).is_ok())
    {
        staging.finish();
        return Ok(Installed {
            dir,
            version: release.version,
            inputs: None,
        });
    }
    reclaim_unrecorded(release, target);
    let extract = staging.dir.join(EXTRACT_DIR_NAME);
    let result = install_in(&staging, &extract, release, target, host, cancel);
    match result {
        Ok(installed) => {
            staging.finish();
            Ok(installed)
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&extract);
            if error == InstallError::ArchiveChanged {
                let _ = fs::remove_file(staging.dir.join(fetch::ARCHIVE_NAME));
            }
            Err(error)
        }
    }
}

/// Moves into the trash ([`remove_folder`]) every folder of `release`'s
/// version that this user's updater made (its state names this registry,
/// see [`INSTALLED_FOR_FIELD`]) but that the registry does not record: left
/// by a crash between the rename into place and the recording, by a folder
/// that could not be removed after a failed recording, or by a lost
/// registry (a moved root, a reset profile). Each would otherwise push the
/// install to the next `-auto` name for good. A folder in use, or with
/// anything added, stays; another user's folder in a shared root is never
/// touched. Best effort.
fn reclaim_unrecorded(release: &VerifiedRelease, target: &InstallTarget<'_>) {
    let running = fs::canonicalize(target.running).ok();
    let mine = installed_for(target.registry);
    for name in candidate_names(&package_name(target.platform, release.version)) {
        let dir = target.iroot.join(name);
        if !is_private_dir(&dir) || fs::canonicalize(&dir).ok() == running {
            continue;
        }
        let ours = read_state(&dir).is_some_and(|state| {
            state.version == release.version.to_string()
                && state.extra.get(INSTALLED_FOR_FIELD).and_then(Value::as_str)
                    == Some(mine.as_str())
        });
        if ours && !is_registered_folder(target.registry, &dir) {
            let _ = remove_folder(target.iroot, &dir);
        }
    }
}

fn install_in(
    staging: &Staging,
    extract: &Path,
    release: &VerifiedRelease,
    target: &InstallTarget<'_>,
    host: &dyn Host,
    cancel: &AtomicBool,
) -> Result<Installed, InstallError> {
    let platform = target.platform;
    let name = package_name(platform, release.version);
    if release.asset_name != platform.runtime_asset(release.version) {
        return Err(InstallError::Layout(format!(
            "{} is not this platform's runtime archive",
            release.asset_name
        )));
    }
    let tar = system_tar().ok_or_else(|| InstallError::Tar("tar was not found".into()))?;
    let archive_path = staging.dir.join(fetch::ARCHIVE_NAME);
    let archive = open_denying_writes(&archive_path)?;
    let expected = (release.asset_size, release.asset_sha256);
    if identify(&archive).map_err(|error| io_error("cannot read", &archive_path, error))?
        != expected
    {
        return Err(InstallError::ArchiveChanged);
    }

    match fs::remove_dir_all(extract) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("cannot clear", extract, error)),
    }
    create_private_dir(extract)?;
    // The tree is a few times the archive. A kept archive skipped the check
    // before its download, so it is made here as well.
    let needed = release
        .asset_size
        .saturating_mul(DOWNLOAD_SPACE_FACTOR - 1)
        .saturating_add(SPACE_MARGIN_BYTES);
    if let Ok(available) = host.available_space(&staging.dir)
        && available < needed
    {
        return Err(InstallError::NoSpace { needed, available });
    }

    // The flags below are GNU tar's; busybox or bsdtar as /usr/bin/tar
    // would fail every attempt with a message that explains nothing.
    if platform == Platform::LinuxX86_64 {
        let probe = host.run(&tar, &["--version".into()], TAR_PROBE_TIMEOUT, cancel);
        match probe {
            Err(error) if error == "cancelled" => return Err(InstallError::Cancelled),
            Ok(output) if output.code == Some(0) && output.stdout.starts_with(b"tar (GNU tar)") => {
            }
            _ => {
                return Err(InstallError::Tar(format!(
                    "{} is not GNU tar, which updates need on Linux",
                    tar.display()
                )));
            }
        }
    }

    let tar_run = |list: bool, verbose: bool| -> Result<ToolOutput, InstallError> {
        let mut args = tar_args(platform, list, &archive_path, extract);
        if verbose {
            args.insert(1, "-v".into());
        }
        let output = host
            .run(&tar, &args, TAR_TIMEOUT, cancel)
            .map_err(|error| match error.as_str() {
                "cancelled" => InstallError::Cancelled,
                _ => InstallError::Tar(error),
            })?;
        if output.code != Some(0) {
            // A disk that filled up while unpacking is not a bad archive:
            // it is retried once there is room again.
            if !list
                && let Ok(available) = host.available_space(&staging.dir)
                && available < SPACE_MARGIN_BYTES
            {
                return Err(InstallError::NoSpace { needed, available });
            }
            return Err(InstallError::Tar(output.describe()));
        }
        Ok(output)
    };
    let listing = tar_run(true, false)?;
    let types = tar_run(true, true)?;
    if listing.stdout.len() >= MAX_TOOL_STDOUT_BYTES || types.stdout.len() >= MAX_TOOL_STDOUT_BYTES
    {
        return Err(InstallError::Layout(
            "the archive lists too many entries".into(),
        ));
    }
    let entries = check_listing(&listing.stdout, &name)?;
    check_entry_types(&types.stdout, entries)?;
    tar_run(false, false)?;

    if !same_file(&archive, &archive_path)
        || identify(&archive).map_err(|error| io_error("cannot read", &archive_path, error))?
            != expected
    {
        return Err(InstallError::ArchiveChanged);
    }
    drop(archive);

    let package = extract.join(&name);
    let only_entry = fs::read_dir(extract)
        .map_err(|error| io_error("cannot read", extract, error))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(|error| io_error("cannot read", extract, error))?;
    if only_entry != [OsString::from(&name)] || !is_real_dir(&package) {
        return Err(InstallError::Layout(format!(
            "the archive does not hold exactly one folder named {name}"
        )));
    }
    let manifest_path = package.join(PACKAGE_MANIFEST_NAME);
    let manifest = read_bounded(&manifest_path, MAX_PACKAGE_MANIFEST_BYTES).map_err(|_| {
        InstallError::Tree {
            path: PACKAGE_MANIFEST_NAME.into(),
            problem: "missing or unreadable",
        }
    })?;
    let checked = release::check_package_manifest(&manifest, platform, release, target.network_id)
        .map_err(InstallError::Package)?;
    verify_tree(&package, &checked, platform)?;
    if cancel.load(Ordering::Acquire) {
        return Err(InstallError::Cancelled);
    }

    let carried = inputs::carry_over(target.running, &package, target.allow_bank_copy, host)
        .map_err(InstallError::Inputs)?;
    self_check(&package, platform, checked.version(), host, cancel)?;
    write_marker(&package, release, &manifest, target.registry)?;

    // The inputs added dirs and files the tree walk did not flush.
    for dir in [
        package.join(inputs::PRODUCTION_V4).join("fixed"),
        package.join(inputs::PRODUCTION_V4),
        package.join("production-mainnet"),
        package.clone(),
    ] {
        if is_real_dir(&dir) {
            sync_dir(&dir).map_err(|error| io_error("cannot flush", &dir, error))?;
        }
    }

    let dir = rename_into_place(&package, target.iroot, &name, host)?;
    // What is now under the final name must still be the private folder
    // that was checked; installed_copies would refuse anything else later.
    if !is_private_dir(&dir) || !is_private_dir(&dir.join(MARKER_DIR_NAME)) {
        return Err(InstallError::Unusable(format!(
            "{} changed while it was moved into place",
            dir.display()
        )));
    }
    if let Err(error) = register_installed(target.registry, &dir, &manifest, release.sums_sha256) {
        // Unrecorded, it would never count as installed.
        let _ = remove_folder(target.iroot, &dir);
        return Err(InstallError::Unusable(format!(
            "cannot record {} as installed: {error}",
            dir.display()
        )));
    }
    // Best effort: the version is already in place, so a filesystem that
    // cannot flush a directory must not turn it into a failed install.
    let _ = sync_dir(target.iroot);
    Ok(Installed {
        dir,
        version: checked.version(),
        inputs: Some(carried),
    })
}

#[cfg(windows)]
pub(crate) fn open_denying_writes(path: &Path) -> Result<File, InstallError> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    // Readers only: nobody can write, rename or delete the file while the
    // handle is open (tar reading the archive, the forwarder starting the
    // exe).
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|error| io_error("cannot open", path, error))
}

#[cfg(not(windows))]
pub(crate) fn open_denying_writes(path: &Path) -> Result<File, InstallError> {
    File::open(path).map_err(|error| io_error("cannot open", path, error))
}

/// Whether `path` still names the file behind `handle`. Windows: the
/// archive handle's share mode already forbids a rename or delete, and the
/// lock file relies on the link check before its open.
#[cfg(unix)]
fn same_file(handle: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (handle.metadata(), fs::symlink_metadata(path)) {
        (Ok(held), Ok(named)) => held.dev() == named.dev() && held.ino() == named.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file(_handle: &File, _path: &Path) -> bool {
    true
}

/// The size and SHA-256 of an open file, read from its start.
fn identify(mut file: &File) -> io::Result<(u64, [u8; 32])> {
    file.rewind()?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        context.update(&buffer[..read]);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(context.finish().as_ref());
    Ok((size, digest))
}

/// Every entry `tar -t` printed must be the top-level folder, or a plain
/// relative path inside it. This refuses `..`, absolute paths, a second
/// top-level folder and a wrong name before anything is unpacked. Returns
/// the number of entries.
fn check_listing(listing: &[u8], top: &str) -> Result<usize, InstallError> {
    let text = std::str::from_utf8(listing)
        .map_err(|_| InstallError::Layout("an entry name is not UTF-8".into()))?;
    let mut entries = 0;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        entries += 1;
        let inside = line.trim_end_matches('/');
        let ok = inside == top
            || inside
                .strip_prefix(top)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(release::is_package_path);
        if !ok {
            return Err(InstallError::Layout(format!("unexpected entry {line:?}")));
        }
    }
    if entries == 0 {
        return Err(InstallError::Layout("the archive is empty".into()));
    }
    Ok(entries)
}

/// `tar -tv` starts each entry with its type, as `ls -l` does (GNU tar and
/// bsdtar alike). Only `-` (a file) and `d` (a folder) are allowed, so hard
/// links (`h`), symlinks (`l`), devices and FIFOs are refused before
/// anything is unpacked. Only that first character is read; the names come
/// from the plain listing, whose `entries` this one must match.
fn check_entry_types(verbose: &[u8], entries: usize) -> Result<(), InstallError> {
    let lines: Vec<&[u8]> = verbose
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() != entries {
        return Err(InstallError::Layout(
            "the two listings of the archive differ".into(),
        ));
    }
    match lines.iter().find(|line| !matches!(line[0], b'-' | b'd')) {
        Some(line) => Err(InstallError::Layout(format!(
            "entry {:?} is not a plain file or folder",
            String::from_utf8_lossy(line)
        ))),
        None => Ok(()),
    }
}

/// Checks the extracted package tree against its checked record: every
/// listed file present as a plain file with its size and SHA-256, plus the
/// record itself, and nothing else. Links, junctions and devices are refused
/// and never followed.
fn verify_tree(
    package: &Path,
    checked: &CheckedPackage,
    platform: Platform,
) -> Result<(), InstallError> {
    let files = checked.files();
    let mut dirs = std::collections::BTreeSet::new();
    for path in files.keys() {
        let mut parent = path.as_str();
        while let Some((dir, _)) = parent.rsplit_once('/') {
            dirs.insert(dir.to_owned());
            parent = dir;
        }
    }
    let tree_error = |path: &str, problem: &'static str| InstallError::Tree {
        path: path.to_owned(),
        problem,
    };
    let root = fs::symlink_metadata(package)
        .map_err(|error| io_error("cannot inspect", package, error))?;
    check_dir_mode(".", &root, platform)?;
    let mut seen = 0usize;
    let mut pending = vec![(package.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let entries = fs::read_dir(&dir).map_err(|error| io_error("cannot read", &dir, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| io_error("cannot read", &dir, error))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(tree_error(&name.to_string_lossy(), "not a package file"));
            };
            let relative = format!("{prefix}{name}");
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)
                .map_err(|error| io_error("cannot inspect", &path, error))?;
            if is_reparse_point(&meta) {
                return Err(tree_error(&relative, "a link"));
            }
            if meta.is_dir() {
                if !dirs.contains(&relative) {
                    return Err(tree_error(&relative, "not part of the package"));
                }
                check_dir_mode(&relative, &meta, platform)?;
                pending.push((path, format!("{relative}/")));
                continue;
            }
            if !meta.is_file() {
                return Err(tree_error(&relative, "not a plain file"));
            }
            if relative == PACKAGE_MANIFEST_NAME {
                continue;
            }
            let Some(listed) = files.get(&relative) else {
                return Err(tree_error(&relative, "not part of the package"));
            };
            check_mode(&relative, &meta, platform)?;
            // A file Windows unpacked read-only cannot be opened for the
            // flush; it is still checked.
            let (file, flush) = match open_for_sync(&path) {
                Ok(file) => (file, true),
                Err(_) => (
                    File::open(&path).map_err(|_| tree_error(&relative, "unreadable"))?,
                    false,
                ),
            };
            let identity = identify(&file).map_err(|_| tree_error(&relative, "unreadable"))?;
            if identity != (listed.bytes, listed.sha256) {
                return Err(tree_error(&relative, "changed"));
            }
            // The rename into place is the commit, so the data must be on
            // disk before it, not only in the cache.
            if flush {
                file.sync_all()
                    .map_err(|error| io_error("cannot flush", &path, error))?;
            }
            seen += 1;
        }
        sync_dir(&dir).map_err(|error| io_error("cannot flush", &dir, error))?;
    }
    if seen != files.len() {
        // Something listed was not found; name the first one for the user.
        let missing = files
            .keys()
            .find(|path| fs::symlink_metadata(package.join(path)).is_err())
            .cloned()
            .unwrap_or_default();
        return Err(tree_error(&missing, "missing"));
    }
    Ok(())
}

/// Opens a file so that `sync_all` works on it: Windows flushes only
/// through a handle with write access.
fn open_for_sync(path: &Path) -> io::Result<File> {
    if cfg!(windows) {
        OpenOptions::new().read(true).write(true).open(path)
    } else {
        File::open(path)
    }
}

/// Flushes a directory's entries on Linux. NTFS journals its directories,
/// and Windows cannot flush a directory handle.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Options for a new marker file: never over an existing one, and on Linux
/// not writable by group or others whatever the umask.
fn new_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o644);
    options
}

/// Writes a new file and flushes it.
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = new_file_options().open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// On Linux the packaged executables must stay executable, and nothing may
/// be writable by group or others.
#[cfg(unix)]
fn check_mode(relative: &str, meta: &fs::Metadata, platform: Platform) -> Result<(), InstallError> {
    use std::os::unix::fs::PermissionsExt;
    if platform != Platform::LinuxX86_64 {
        return Ok(());
    }
    let mode = meta.permissions().mode();
    let executable = LINUX_EXECUTABLES.contains(&relative) || relative.ends_with(".sh");
    if mode & 0o022 != 0 || (executable && mode & 0o100 == 0) {
        return Err(InstallError::Tree {
            path: relative.to_owned(),
            problem: "unpacked with the wrong permissions",
        });
    }
    Ok(())
}

/// On Linux no directory of the package may be writable by group or
/// others either.
#[cfg(unix)]
fn check_dir_mode(
    relative: &str,
    meta: &fs::Metadata,
    platform: Platform,
) -> Result<(), InstallError> {
    use std::os::unix::fs::PermissionsExt;
    if platform == Platform::LinuxX86_64 && meta.permissions().mode() & 0o022 != 0 {
        return Err(InstallError::Tree {
            path: relative.to_owned(),
            problem: "unpacked with the wrong permissions",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_mode(
    _relative: &str,
    _meta: &fs::Metadata,
    _platform: Platform,
) -> Result<(), InstallError> {
    Ok(())
}

#[cfg(not(unix))]
fn check_dir_mode(
    _relative: &str,
    _meta: &fs::Metadata,
    _platform: Platform,
) -> Result<(), InstallError> {
    Ok(())
}

/// The new wallet must report its version and its prelaunch identity
/// without starting Tauri or opening any wallet data.
fn self_check(
    package: &Path,
    platform: Platform,
    version: Version,
    host: &dyn Host,
    cancel: &AtomicBool,
) -> Result<(), InstallError> {
    let exe = package.join(wallet_exe_name(platform));
    let run = |argument: &str| -> Result<Vec<u8>, InstallError> {
        let output = host
            .run(&exe, &[argument.into()], SELF_CHECK_TIMEOUT, cancel)
            .map_err(|error| match error.as_str() {
                "cancelled" => InstallError::Cancelled,
                // It never answered (it could not start, or did not finish
                // in time): often a scanner holding a new exe. Only a wrong
                // answer is a failed self-check.
                _ => InstallError::Io(format!("the new wallet's {argument} did not run: {error}")),
            })?;
        if output.code != Some(0) {
            return Err(InstallError::SelfCheck(format!(
                "{argument}: {}",
                output.describe()
            )));
        }
        Ok(output.stdout)
    };
    let expected = version.to_string();
    let printed = run("--version")?;
    let printed = String::from_utf8_lossy(&printed);
    if printed.split_whitespace().last() != Some(expected.as_str()) {
        return Err(InstallError::SelfCheck(format!(
            "--version printed {:?}, not {expected}",
            printed.trim()
        )));
    }
    let identity = run("runtime-identity")?;
    let reported = serde_json::from_slice::<Value>(&identity)
        .ok()
        .and_then(|value| value.get("package_version")?.as_str().map(str::to_owned));
    if reported.as_deref() != Some(expected.as_str()) {
        return Err(InstallError::SelfCheck(format!(
            "runtime-identity did not report version {expected}"
        )));
    }
    Ok(())
}

/// `.cmfd-updater/` with the exact signed bytes the release was verified
/// from, the checked package record, and `state.json`.
///
/// The package record is not signed by itself (SUMS covers only the
/// archive, which is deleted after the install). Later checks of an
/// installed folder can trust this copy only as far as they trust the
/// folder; `archive_sha256` records which signed archive it came from.
fn write_marker(
    package: &Path,
    release: &VerifiedRelease,
    manifest: &[u8],
    registry: &Path,
) -> Result<(), InstallError> {
    let marker = package.join(MARKER_DIR_NAME);
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o755);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    builder
        .create(&marker)
        .map_err(|error| io_error("cannot create", &marker, error))?;
    for (name, bytes) in [
        (release::SUMS_NAME, release.sums.as_slice()),
        (release::SIGNATURE_NAME, release.signature.as_slice()),
        (release::BUILDINFO_NAME, release.buildinfo.as_slice()),
        (PACKAGE_MANIFEST_NAME, manifest),
    ] {
        let path = marker.join(name);
        write_synced(&path, bytes).map_err(|error| io_error("cannot write", &path, error))?;
    }
    let state = InstallState {
        state: STATE_STAGED.into(),
        version: release.version.to_string(),
        sums_sha256: hex::encode(release.sums_sha256),
        archive_sha256: hex::encode(release.asset_sha256),
        staged_at: unix_now(),
        extra: Map::from_iter([(INSTALLED_FOR_FIELD.into(), installed_for(registry).into())]),
    };
    write_state(package, &state).map_err(|error| io_error("cannot write", &marker, error))
}

/// How long to wait between rename attempts that failed because something
/// (antivirus, OneDrive, an indexer) briefly held a file open: 0.25 s,
/// doubling to 8 s, for at least 60 s in all.
fn rename_delays() -> impl Iterator<Item = Duration> {
    let mut next = Duration::from_millis(250);
    let mut total = Duration::ZERO;
    std::iter::from_fn(move || {
        if total >= Duration::from_secs(60) {
            return None;
        }
        let delay = next;
        total += delay;
        next = (next * 2).min(Duration::from_secs(8));
        Some(delay)
    })
}

fn is_sharing_error(error: &io::Error) -> bool {
    // Windows: access denied, sharing violation, lock violation. Linux: busy.
    let codes: &[i32] = if cfg!(windows) { &[5, 32, 33] } else { &[16] };
    error
        .raw_os_error()
        .is_some_and(|code| codes.contains(&code))
}

fn is_name_taken(error: &io::Error) -> bool {
    // Windows: already exists, file exists. Linux: exists, not empty.
    let codes: &[i32] = if cfg!(windows) { &[80, 183] } else { &[17, 39] };
    error.kind() == io::ErrorKind::AlreadyExists
        || error
            .raw_os_error()
            .is_some_and(|code| codes.contains(&code))
}

/// Moves the staged folder to `<iroot>/<name>`, or `<name>-auto`,
/// `-auto2`, … when the name is taken. Never replaces an existing folder
/// with content: Windows refuses a rename onto an existing folder, and
/// Linux onto a non-empty one (a racing empty folder is the only thing it
/// can replace). The staging dir is inside `iroot`, so this never crosses
/// volumes.
fn rename_into_place(
    package: &Path,
    iroot: &Path,
    name: &str,
    host: &dyn Host,
) -> Result<PathBuf, InstallError> {
    for candidate in candidate_names(name) {
        let destination = iroot.join(&candidate);
        if fs::symlink_metadata(&destination).is_ok() {
            continue;
        }
        let mut delays = rename_delays();
        loop {
            match host.rename(package, &destination) {
                Ok(()) => return Ok(destination),
                Err(error) if is_name_taken(&error) => break,
                Err(error) if is_sharing_error(&error) => match delays.next() {
                    Some(delay) => host.sleep(delay),
                    None => return Err(io_error("cannot move into", &destination, error)),
                },
                Err(error) => return Err(io_error("cannot move into", &destination, error)),
            }
        }
    }
    Err(InstallError::Unusable(format!(
        "every name for {name} is taken in {}",
        iroot.display()
    )))
}

/// The installed versions in `iroot` that may be deleted, oldest first.
/// Keeps the running version, everything newer, and the newest version
/// below the running one ("one previous version"). A folder is listed only
/// if the updater made it (it has a readable `.cmfd-updater/state.json`),
/// it is not one of `protected` (the running folder and the folder the user
/// launches, which may differ when forwarded), and it holds nothing but its
/// package files and the known prepared inputs: no wallet data, no `work/`,
/// no links and nothing a user added.
pub(crate) fn removable_versions(
    iroot: &Path,
    platform: Platform,
    running: Version,
    protected: &[&Path],
    registry: &Path,
) -> Vec<PathBuf> {
    let prefix = format!("commonfoundry-mainnet-runtime-{}-v", platform.name());
    let Ok(entries) = fs::read_dir(iroot) else {
        return Vec::new();
    };
    let protected: Vec<PathBuf> = protected
        .iter()
        .filter_map(|path| fs::canonicalize(path).ok())
        .collect();
    let mut versions: Vec<(Version, PathBuf)> = entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .map(|entry| entry.path())
        .filter(|path| is_real_dir(path))
        .filter_map(|path| Some((package_version(&path)?, path)))
        .collect();
    versions.sort();
    // The kept previous version is the fallback, so it must be one that
    // works: the newest older one that started, else the newest older one
    // that is not known to have failed; among those, one in the registry
    // first, since the forwarder starts no other. Without one, nothing is
    // removed.
    let older_in_state = |accept: &dyn Fn(&str) -> bool, recorded: bool| {
        versions
            .iter()
            .filter(|(version, path)| {
                *version < running
                    && read_state(path).is_some_and(|state| accept(state.state.as_str()))
                    && (!recorded || is_registered_folder(registry, path))
            })
            .map(|(version, _)| *version)
            .max()
    };
    let started = |state: &str| state == STATE_STARTED_OK;
    let not_failed = |state: &str| state != STATE_FAILED;
    let Some(previous) = older_in_state(&started, true)
        .or_else(|| older_in_state(&not_failed, true))
        .or_else(|| older_in_state(&started, false))
        .or_else(|| older_in_state(&not_failed, false))
    else {
        return Vec::new();
    };
    versions
        .into_iter()
        .filter(|(version, _)| *version < previous)
        .map(|(_, path)| path)
        .filter(|path| {
            fs::canonicalize(path).is_ok_and(|path| !protected.contains(&path))
                && read_state(path).is_some()
                && holds_only_package_files(path)
        })
        .collect()
}

#[derive(Deserialize)]
struct PackageRecord {
    package_version: String,
    files: std::collections::BTreeMap<String, Value>,
}

fn package_record(package: &Path) -> Option<PackageRecord> {
    let bytes = read_bounded(
        &package.join(PACKAGE_MANIFEST_NAME),
        MAX_PACKAGE_MANIFEST_BYTES,
    )
    .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn package_version(package: &Path) -> Option<Version> {
    Version::parse(&package_record(package)?.package_version)
}

/// Whether a folder holds only its package files plus the allowed extras
/// of design section 2.6, with no links anywhere.
fn holds_only_package_files(package: &Path) -> bool {
    let Some(record) = package_record(package) else {
        return false;
    };
    let Ok(chunks) = inputs::chunk_paths(package) else {
        return false;
    };
    let allowed = |relative: &str| {
        record.files.contains_key(relative)
            || relative == PACKAGE_MANIFEST_NAME
            || is_allowed_extra(relative, &chunks)
    };
    // Directories are allowed only on the way to an allowed file, or inside
    // the two allowed subtrees. An empty `data-mainnet/` or `work/` is not.
    let v4 = inputs::PRODUCTION_V4;
    let fixed_record = inputs::FIXED_RECORD_NAME;
    let extra_files = chunks.iter().map(|path| format!("{v4}/{path}")).chain([
        format!("{v4}/{fixed_record}"),
        format!("{v4}/fixed/{fixed_record}"),
        inputs::BEACON_PATH.to_owned(),
    ]);
    let mut allowed_dirs = std::collections::BTreeSet::new();
    for path in record.files.keys().cloned().chain(extra_files) {
        let mut parent = path.as_str();
        while let Some((dir, _)) = parent.rsplit_once('/') {
            allowed_dirs.insert(dir.to_owned());
            parent = dir;
        }
    }
    let parts = format!("{v4}/.parts");
    let allowed_dir = |relative: &str| {
        allowed_dirs.contains(relative)
            || [MARKER_DIR_NAME, parts.as_str()].iter().any(|tree| {
                relative == *tree
                    || relative
                        .strip_prefix(tree)
                        .is_some_and(|rest| rest.starts_with('/'))
            })
    };
    let mut pending = vec![(package.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return false;
            };
            let relative = format!("{prefix}{name}");
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                return false;
            };
            if is_reparse_point(&meta) {
                return false;
            }
            if meta.is_dir() {
                if !allowed_dir(&relative) {
                    return false;
                }
                pending.push((entry.path(), format!("{relative}/")));
            } else if !meta.is_file() || !allowed(&relative) {
                return false;
            }
        }
    }
    true
}

/// Files the updater, the launchers or the wallet add to an installed
/// version folder beyond its package files.
pub(crate) fn is_allowed_extra(relative: &str, chunk_paths: &[String]) -> bool {
    let fixed_record = inputs::FIXED_RECORD_NAME;
    if relative.starts_with(&format!("{MARKER_DIR_NAME}/")) || relative == inputs::BEACON_PATH {
        return true;
    }
    let Some(inside) = relative.strip_prefix(&format!("{}/", inputs::PRODUCTION_V4)) else {
        return false;
    };
    inside == fixed_record
        || inside == format!("fixed/{fixed_record}")
        // The record copy of a mining-input adoption that was cut off
        // before its rename.
        || inside == format!("fixed/{fixed_record}{}", inputs::COPY_SUFFIX)
        || inside == ".prepare-v4-inputs.lock"
        || inside.starts_with(".parts/")
        || chunk_paths.iter().any(|path| path == inside)
}

/// Deletes an installed version folder of `iroot` found by
/// [`removable_versions`]. Hard-linked inputs stay in the other versions
/// that share them.
///
/// The folder is first renamed into `.cmfd-update-staging/trash-…`. That is
/// atomic, and on Windows it fails while anything inside is in use (an old
/// node or miner started from there), so a version is either kept whole
/// under its name or gone from it. The folder is checked again after the
/// move and put back if something was added to it meanwhile (or, if that
/// fails, kept as `kept-…`, which nothing deletes). A delete that stops
/// partway leaves only checked trash, which the next [`Staging::open`]
/// sweeps.
///
/// The folder leaves the install `registry` first, so a folder made later
/// under the same path is never taken for it. One that is kept because it
/// changed is no longer started by the forwarder; it is older than the
/// kept previous version anyway.
pub(crate) fn remove_version(iroot: &Path, package: &Path, registry: &Path) -> io::Result<()> {
    unregister_installed(registry, package)?;
    remove_folder(iroot, package)
}

/// [`remove_version`] of a folder that is not in the registry.
fn remove_folder(iroot: &Path, package: &Path) -> io::Result<()> {
    let staging = iroot.join(STAGING_DIR_NAME);
    check_install_root(iroot)
        .and_then(|()| create_private_dir(&staging))
        .map_err(|error| io::Error::other(error.to_string()))?;
    let name = package
        .file_name()
        .ok_or_else(|| io::Error::other("not a version folder"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let tag = format!("{}-{}-{nonce}", name.to_string_lossy(), std::process::id());
    let trash = staging.join(format!("{TRASH_PREFIX}{tag}"));
    fs::rename(package, &trash)?;
    if !is_removable_trash(&trash) {
        // Back under its name, or else where nothing deletes it.
        if fs::rename(&trash, package).is_err() {
            let kept = staging.join(format!("{KEPT_PREFIX}{tag}"));
            if fs::rename(&trash, &kept).is_ok() {
                return Err(io::Error::other(format!(
                    "the folder changed; it was kept as {}",
                    kept.display()
                )));
            }
        }
        return Err(io::Error::other("the folder changed; it was kept"));
    }
    // Checked: from here a delete that stops partway leaves only package
    // files, which the sweep finishes.
    let deleting = staging.join(format!("{DELETING_PREFIX}{tag}"));
    fs::rename(&trash, &deleting)?;
    fs::remove_dir_all(&deleting)
}

/// A folder moved to the trash that may be deleted: the updater made it
/// and it holds nothing but its package files and the known inputs.
fn is_removable_trash(path: &Path) -> bool {
    read_state(path).is_some() && holds_only_package_files(path)
}

fn read_bounded(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > max_bytes {
        return Err(io::Error::other("not a regular file of the expected size"));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::other("too large"));
    }
    Ok(bytes)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::updater::inputs::{BANK_NAME, BEACON_PATH, CHUNKS_NAME, PLAN_PATH, PRODUCTION_V4};
    use crate::updater::sshsig::ReleaseKeySlot;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicU32;

    pub(crate) struct TempDir(pub(crate) PathBuf);

    impl TempDir {
        pub(crate) fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "cmfd-update-install-{}-{unique}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const NETWORK: [u8; 32] = [0x5a; 32];
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const BANK: &[u8] = b"the proof bank";
    const V16: Version = Version::new(1, 0, 16);
    const V17: Version = Version::new(1, 0, 17);

    fn platform() -> Platform {
        Platform::current().expect("tests run on windows-x86_64 or linux-x86_64")
    }

    fn wallet_name() -> &'static str {
        match platform() {
            Platform::WindowsX86_64 => "common-foundry-wallet.exe",
            Platform::LinuxX86_64 => "common-foundry-wallet",
        }
    }

    fn chunks() -> String {
        serde_json::json!({
            "files": [{
                "name": BANK_NAME,
                "relative_path": BANK_NAME,
                "bytes": BANK.len(),
                "sha256": hex::encode(sha256(BANK)),
            }],
        })
        .to_string()
    }

    /// The files of a synthetic runtime package.
    fn package_files(version: Version) -> BTreeMap<String, Vec<u8>> {
        [
            (wallet_name(), format!("wallet {version}").into_bytes()),
            ("README.md", b"read me".to_vec()),
            (CHUNKS_NAME, chunks().into_bytes()),
            (inputs::FIXED_RECORD_NAME, b"fixed record".to_vec()),
            (PLAN_PATH, b"the launch plan".to_vec()),
            ("production-v4/cmfd-v4-replay", b"replay worker".to_vec()),
            ("start-wallet.sh", b"#!/bin/sh\n".to_vec()),
        ]
        .into_iter()
        .map(|(name, bytes)| (name.to_owned(), bytes))
        .collect()
    }

    fn manifest(version: Version, files: &BTreeMap<String, Vec<u8>>, network: [u8; 32]) -> Vec<u8> {
        let listed: Map<String, Value> = files
            .iter()
            .map(|(name, bytes)| {
                (
                    name.clone(),
                    serde_json::json!({"bytes": bytes.len(), "sha256": hex::encode(sha256(bytes))}),
                )
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "schema": "CMFD_MAINNET_PACKAGE_ATTESTATION_V1",
            "kind": "runtime",
            "platform": platform().name(),
            "package_version": version.to_string(),
            "network_id": hex::encode(network),
            "source_commit": COMMIT,
            "files": listed,
        }))
        .unwrap()
    }

    /// Writes a package folder `<parent>/<name>` from `files` plus its record.
    fn write_package(
        parent: &Path,
        name: &str,
        files: &BTreeMap<String, Vec<u8>>,
        record: &[u8],
    ) -> PathBuf {
        let dir = parent.join(name);
        for (relative, bytes) in files {
            let path = dir.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if LINUX_EXECUTABLES.contains(&relative.as_str())
                    || relative.ends_with(".sh")
                {
                    0o755
                } else {
                    0o644
                };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        fs::write(dir.join(PACKAGE_MANIFEST_NAME), record).unwrap();
        #[cfg(unix)]
        {
            // Whatever the umask, as the packager writes them.
            use std::os::unix::fs::PermissionsExt;
            let mut pending = vec![dir.clone()];
            while let Some(path) = pending.pop() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                for entry in fs::read_dir(&path).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_type().unwrap().is_dir() {
                        pending.push(entry.path());
                    }
                }
            }
        }
        dir
    }

    /// Packs `<source>/<name>` with the system tar into `output`.
    fn pack(source: &Path, name: &str, output: &Path) {
        let tar = system_tar().expect("system tar");
        let mut args: Vec<OsString> = vec!["-c".into(), "-f".into(), output.into()];
        match platform() {
            Platform::WindowsX86_64 => args.extend(["--format".into(), "zip".into()]),
            Platform::LinuxX86_64 => args.push("-z".into()),
        }
        args.extend(["-C".into(), source.into(), name.into()]);
        let status = Command::new(tar).args(&args).status().unwrap();
        assert!(status.success());
    }

    /// The running package: version 1.0.16 with its prepared bank, plus
    /// wallet data in the folder that must never be touched.
    fn running_package(root: &Path) -> PathBuf {
        let files = package_files(V16);
        let name = package_name(platform(), V16);
        let dir = write_package(root, &name, &files, &manifest(V16, &files, NETWORK));
        fs::create_dir_all(dir.join(PRODUCTION_V4)).unwrap();
        fs::write(dir.join(PRODUCTION_V4).join(BANK_NAME), BANK).unwrap();
        fs::write(dir.join(BEACON_PATH), b"beacon").unwrap();
        fs::create_dir_all(dir.join("data-mainnet")).unwrap();
        fs::write(dir.join("data-mainnet/wallet.dat"), b"keys").unwrap();
        dir
    }

    /// A test install registry, one level inside its temp dir as the real
    /// one is inside `CommonFoundry` (the folder holding it must be private
    /// too, which the system temp dir is not).
    struct Registry {
        _temp: TempDir,
        path: PathBuf,
    }

    impl Registry {
        fn new() -> Self {
            let temp = TempDir::new();
            let path = temp.0.join(REGISTRY_DIR_NAME);
            Self { _temp: temp, path }
        }
    }

    struct Fixture {
        temp: TempDir,
        registry: Registry,
        running: PathBuf,
        release: VerifiedRelease,
        archive: Vec<u8>,
    }

    impl Fixture {
        /// A 1.0.17 release whose archive holds `files`, recorded as `record`.
        fn with(files: &BTreeMap<String, Vec<u8>>, record: &[u8]) -> Self {
            Self::with_tweak(files, record, |_| {})
        }

        /// Like [`Fixture::with`], with `tweak` applied to the package
        /// folder before it is packed.
        fn with_tweak(
            files: &BTreeMap<String, Vec<u8>>,
            record: &[u8],
            tweak: impl FnOnce(&Path),
        ) -> Self {
            let temp = TempDir::new();
            let running = running_package(&temp.0);
            let source = temp.0.join("source");
            fs::create_dir(&source).unwrap();
            let name = package_name(platform(), V17);
            tweak(&write_package(&source, &name, files, record));
            let packed = temp.0.join(platform().runtime_asset(V17));
            pack(&source, &name, &packed);
            let archive = fs::read(&packed).unwrap();
            fs::remove_dir_all(&source).unwrap();
            fs::remove_file(&packed).unwrap();
            let release = release_for(&archive);
            Self {
                temp,
                registry: Registry::new(),
                running,
                release,
                archive,
            }
        }

        fn new() -> Self {
            let files = package_files(V17);
            Self::with(&files, &manifest(V17, &files, NETWORK))
        }

        fn iroot(&self) -> &Path {
            &self.temp.0
        }

        fn registry(&self) -> &Path {
            &self.registry.path
        }

        fn found(&self) -> Option<PathBuf> {
            installed_copies(self.iroot(), platform(), &self.release, self.registry())
                .into_iter()
                .next()
        }

        fn target(&self) -> InstallTarget<'_> {
            InstallTarget {
                iroot: self.iroot(),
                running: &self.running,
                platform: platform(),
                network_id: Some(NETWORK),
                allow_bank_copy: false,
                registry: self.registry(),
            }
        }

        /// A staging dir whose archive was just "downloaded".
        fn staging(&self) -> Staging {
            // A test thread that is starting a child process can still hold
            // a copy of the lock handle for a moment after an earlier
            // install in this test released it.
            let mut tries = 0;
            let staging = loop {
                match Staging::open(self.iroot(), V17) {
                    Err(InstallError::Busy) if tries < 50 => {
                        tries += 1;
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    result => break result.unwrap(),
                }
            };
            let archive = staging
                .archive(&self.release, &SystemHost, |dir| {
                    let path = dir.join(fetch::ARCHIVE_NAME);
                    fs::write(&path, &self.archive).unwrap();
                    Ok(path)
                })
                .unwrap();
            assert_eq!(fs::read(archive).unwrap(), self.archive);
            staging
        }

        fn install_with(&self, host: &dyn Host) -> Result<Installed, InstallError> {
            install(
                self.staging(),
                &self.release,
                &self.target(),
                host,
                &AtomicBool::new(false),
            )
        }

        fn staging_dir(&self) -> PathBuf {
            self.iroot().join(STAGING_DIR_NAME).join(V17.to_string())
        }

        /// The names left in this version's staging dir, sorted.
        fn staging_leftovers(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.staging_dir())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }

        fn version_folders(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.iroot())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .filter(|name| name.starts_with("commonfoundry-"))
                .collect();
            names.sort();
            names
        }
    }

    fn release_for(archive: &[u8]) -> VerifiedRelease {
        VerifiedRelease {
            version: V17,
            repo: release::PRIMARY_REPO,
            commit: COMMIT.into(),
            asset_name: platform().runtime_asset(V17),
            asset_url: "https://example.invalid/archive".into(),
            asset_sha256: sha256(archive),
            asset_size: archive.len() as u64,
            sums_sha256: sha256(b"signed sums"),
            key: ReleaseKeySlot::Current,
            sums: b"signed sums".to_vec(),
            signature: b"signature".to_vec(),
            buildinfo: b"buildinfo".to_vec(),
        }
    }

    /// The system, except that the new wallet's self-check is answered here
    /// (the synthetic package has no real wallet binary).
    struct FakeWallet {
        version: String,
        identity: String,
        calls: RefCell<Vec<String>>,
    }

    impl FakeWallet {
        fn new() -> Self {
            Self::reporting(
                "common-foundry-wallet 1.0.17\n",
                r#"{"package_version":"1.0.17"}"#,
            )
        }

        fn reporting(version: &str, identity: &str) -> Self {
            Self {
                version: version.into(),
                identity: identity.into(),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Host for FakeWallet {
        fn run(
            &self,
            program: &Path,
            args: &[OsString],
            timeout: Duration,
            cancel: &AtomicBool,
        ) -> Result<ToolOutput, String> {
            if program.file_name() != Some(std::ffi::OsStr::new(wallet_name())) {
                return run_tool(program, args, timeout, cancel);
            }
            let argument = args[0].to_string_lossy().into_owned();
            self.calls.borrow_mut().push(argument.clone());
            let stdout = match argument.as_str() {
                "--version" => self.version.clone(),
                "runtime-identity" => self.identity.clone(),
                _ => return Err("unexpected argument".into()),
            };
            Ok(ToolOutput {
                code: Some(0),
                stdout: stdout.into_bytes(),
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn a_release_installs_side_by_side_and_the_staging_dir_is_removed() {
        let fixture = Fixture::new();
        let host = FakeWallet::new();
        let installed = fixture.install_with(&host).unwrap();

        let name = package_name(platform(), V17);
        assert_eq!(installed.dir, fixture.iroot().join(&name));
        assert_eq!(installed.version, V17);
        assert_eq!(
            installed.inputs.as_ref().map(|inputs| inputs.bank),
            Some(inputs::BankCarried::Linked)
        );
        assert_eq!(*host.calls.borrow(), ["--version", "runtime-identity"]);

        let dir = &installed.dir;
        for (relative, bytes) in package_files(V17) {
            assert_eq!(fs::read(dir.join(&relative)).unwrap(), bytes, "{relative}");
        }
        assert_eq!(
            fs::read(dir.join(PRODUCTION_V4).join(BANK_NAME)).unwrap(),
            BANK
        );
        assert_eq!(
            fs::read(dir.join(PRODUCTION_V4).join(inputs::FIXED_RECORD_NAME)).unwrap(),
            b"fixed record"
        );
        assert_eq!(fs::read(dir.join(BEACON_PATH)).unwrap(), b"beacon");

        let marker = dir.join(MARKER_DIR_NAME);
        assert_eq!(
            fs::read(marker.join(release::SUMS_NAME)).unwrap(),
            b"signed sums"
        );
        assert_eq!(
            fs::read(marker.join(release::SIGNATURE_NAME)).unwrap(),
            b"signature"
        );
        assert_eq!(
            fs::read(marker.join(release::BUILDINFO_NAME)).unwrap(),
            b"buildinfo"
        );
        assert_eq!(
            fs::read(marker.join(PACKAGE_MANIFEST_NAME)).unwrap(),
            fs::read(dir.join(PACKAGE_MANIFEST_NAME)).unwrap()
        );
        let state = read_state(dir).unwrap();
        assert_eq!(state.state, STATE_STAGED);
        assert_eq!(state.version, "1.0.17");
        assert_eq!(state.sums_sha256, hex::encode(fixture.release.sums_sha256));
        assert_eq!(
            state.archive_sha256,
            hex::encode(fixture.release.asset_sha256)
        );
        assert!(state.staged_at > 0);

        // The running version and its data are untouched.
        assert_eq!(
            fixture.version_folders(),
            [package_name(platform(), V16), name]
        );
        assert_eq!(
            fs::read(fixture.running.join("data-mainnet/wallet.dat")).unwrap(),
            b"keys"
        );
        assert!(!dir.join("data-mainnet").exists());
        // Only the lock file stays in staging. A just-finished child process
        // may briefly retain a duplicate handle before its reaper closes it.
        assert_eq!(fixture.staging_leftovers(), [LOCK_FILE_NAME]);
        let mut reopened = None;
        for _ in 0..=50 {
            match Staging::open(fixture.iroot(), V17) {
                Ok(staging) => {
                    reopened = Some(staging);
                    break;
                }
                Err(InstallError::Busy) => std::thread::sleep(Duration::from_millis(20)),
                Err(error) => panic!("staging could not reopen after install: {error}"),
            }
        }
        assert!(
            reopened.is_some(),
            "staging lock did not clear after install"
        );
        drop(reopened);
        assert!(holds_only_package_files(dir));
    }

    #[test]
    fn an_installed_release_is_not_installed_again() {
        let fixture = Fixture::new();
        let first = fixture.install_with(&FakeWallet::new()).unwrap();
        let host = FakeWallet::new();
        let second = fixture.install_with(&host).unwrap();
        assert_eq!(second.dir, first.dir);
        assert_eq!(second.inputs, None);
        assert!(host.calls.borrow().is_empty());
        assert_eq!(fixture.version_folders().len(), 2);
        assert_eq!(fixture.staging_leftovers(), [LOCK_FILE_NAME]);
    }

    #[test]
    fn a_damaged_install_is_installed_again_beside_it() {
        let fixture = Fixture::new();
        let first = fixture.install_with(&FakeWallet::new()).unwrap();
        assert_eq!(
            check_release_files(&first.dir, platform(), &fixture.release, Some(NETWORK)),
            Ok(())
        );
        // An antivirus quarantine of the wallet exe.
        let exe = first.dir.join(wallet_exe_name(platform()));
        fs::remove_file(&exe).unwrap();
        assert_eq!(
            check_release_files(&first.dir, platform(), &fixture.release, Some(NETWORK)),
            Err(MarkerError(format!(
                "{}: {} is missing or changed",
                first.dir.display(),
                wallet_exe_name(platform())
            )))
        );
        // Still found as this release's folder, but no longer taken as its
        // install: a new copy goes under the next free name.
        assert_eq!(fixture.found(), Some(first.dir.clone()));
        let second = fixture.install_with(&FakeWallet::new()).unwrap();
        assert_eq!(
            second.dir,
            fixture
                .iroot()
                .join(format!("{}-auto", package_name(platform(), V17)))
        );
        assert_eq!(
            check_release_files(&second.dir, platform(), &fixture.release, Some(NETWORK)),
            Ok(())
        );
        // The damaged folder is left as it is.
        assert!(first.dir.is_dir() && !exe.exists());
    }

    #[test]
    fn a_taken_name_gets_an_auto_suffix() {
        let fixture = Fixture::new();
        let name = package_name(platform(), V17);
        // A manual install of the same version, without the updater's marker.
        fs::create_dir(fixture.iroot().join(&name)).unwrap();
        fs::write(fixture.iroot().join(&name).join("README.md"), "mine").unwrap();
        fs::create_dir(fixture.iroot().join(format!("{name}-auto"))).unwrap();

        let installed = fixture.install_with(&FakeWallet::new()).unwrap();
        assert_eq!(installed.dir, fixture.iroot().join(format!("{name}-auto2")));
        assert_eq!(
            fs::read(fixture.iroot().join(&name).join("README.md")).unwrap(),
            b"mine"
        );
        assert_eq!(fixture.found(), Some(installed.dir));
    }

    #[test]
    fn an_archive_that_no_longer_matches_is_deleted_and_nothing_installed() {
        let fixture = Fixture::new();
        let staging = fixture.staging();
        let archive = staging.dir().join(fetch::ARCHIVE_NAME);
        let mut bytes = fs::read(&archive).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&archive, &bytes).unwrap();
        let result = install(
            staging,
            &fixture.release,
            &fixture.target(),
            &FakeWallet::new(),
            &AtomicBool::new(false),
        );
        assert_eq!(result, Err(InstallError::ArchiveChanged));
        assert!(!archive.exists());
        assert!(!fixture.staging_dir().join(EXTRACT_DIR_NAME).exists());
        assert_eq!(fixture.version_folders().len(), 1);
    }

    #[test]
    fn a_kept_archive_is_reused_and_a_bad_one_is_downloaded_again() {
        let fixture = Fixture::new();
        drop(fixture.staging());
        let staging = Staging::open(fixture.iroot(), V17).unwrap();
        let reused = staging
            .archive(&fixture.release, &SystemHost, |_| {
                panic!("downloaded again")
            })
            .unwrap();
        assert_eq!(fs::read(&reused).unwrap(), fixture.archive);

        fs::write(&reused, b"truncated").unwrap();
        let downloads = Cell::new(0);
        staging
            .archive(&fixture.release, &SystemHost, |dir| {
                downloads.set(downloads.get() + 1);
                assert!(!dir.join(fetch::ARCHIVE_NAME).exists());
                let path = dir.join(fetch::ARCHIVE_NAME);
                fs::write(&path, &fixture.archive).unwrap();
                Ok(path)
            })
            .unwrap();
        assert_eq!(downloads.get(), 1);
    }

    #[test]
    fn a_download_needs_room_for_the_archive_and_its_tree() {
        struct Full;
        impl Host for Full {
            fn available_space(&self, _dir: &Path) -> io::Result<u64> {
                Ok(SPACE_MARGIN_BYTES)
            }
        }
        let fixture = Fixture::new();
        let staging = Staging::open(fixture.iroot(), V17).unwrap();
        let result = staging.archive(&fixture.release, &Full, |_| panic!("downloaded"));
        assert_eq!(
            result,
            Err(InstallError::NoSpace {
                needed: fixture.release.asset_size * 4 + SPACE_MARGIN_BYTES,
                available: SPACE_MARGIN_BYTES,
            })
        );
    }

    /// Creates a dir the way the updater makes its staging dirs: private on
    /// Linux whatever the umask.
    fn private_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_staging_dir_that_others_can_enter_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        let unusable =
            |iroot: &Path| matches!(Staging::open(iroot, V17), Err(InstallError::Unusable(_)));
        let fixture = Fixture::new();
        let iroot = fixture.iroot();
        let dir = fixture.staging_dir();
        let parent = dir.parent().unwrap();
        // Made by another account (or under a loose umask) before the install.
        fs::create_dir_all(&dir).unwrap();
        mode(parent, 0o755);
        mode(&dir, 0o700);
        assert!(unusable(iroot));
        mode(parent, 0o700);
        mode(&dir, 0o770);
        assert!(unusable(iroot));
        mode(&dir, 0o700);
        drop(Staging::open(iroot, V17).unwrap());

        // A root anyone can write to needs the sticky bit.
        mode(iroot, 0o777);
        assert!(unusable(iroot));
        mode(iroot, 0o1777);
        drop(Staging::open(iroot, V17).unwrap());
        mode(iroot, 0o755);

        // A link named staging.lock is never opened for writing.
        let target = iroot.join("victim");
        fs::write(&target, b"keep me").unwrap();
        fs::remove_file(dir.join(LOCK_FILE_NAME)).unwrap();
        std::os::unix::fs::symlink(&target, dir.join(LOCK_FILE_NAME)).unwrap();
        assert!(unusable(iroot));
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
    }

    #[test]
    fn a_second_install_of_the_same_version_waits_for_the_lock() {
        let fixture = Fixture::new();
        let staging = Staging::open(fixture.iroot(), V17).unwrap();
        assert!(matches!(
            Staging::open(fixture.iroot(), V17),
            Err(InstallError::Busy)
        ));
        // Another version is independent.
        assert!(Staging::open(fixture.iroot(), Version::new(1, 0, 18)).is_ok());
        drop(staging);
        assert!(Staging::open(fixture.iroot(), V17).is_ok());
    }

    #[test]
    fn a_lock_file_left_by_a_wallet_that_died_does_not_block() {
        let fixture = Fixture::new();
        let dir = fixture.staging_dir();
        private_dir(dir.parent().unwrap());
        private_dir(&dir);
        // Nobody holds it: the wallet that wrote it is gone.
        fs::write(
            dir.join(LOCK_FILE_NAME),
            b"{\"pid\":1,\"locked_at\":1}
",
        )
        .unwrap();
        let staging = Staging::open(fixture.iroot(), V17).unwrap();
        assert!(matches!(
            Staging::open(fixture.iroot(), V17),
            Err(InstallError::Busy)
        ));
        drop(staging);
        assert!(Staging::open(fixture.iroot(), V17).is_ok());
    }

    #[test]
    fn the_scratch_dir_is_private_and_survives_the_sweep() {
        let fixture = Fixture::new();
        let scratch = scratch_dir(fixture.iroot()).unwrap();
        assert_eq!(
            scratch,
            fixture
                .iroot()
                .join(STAGING_DIR_NAME)
                .join(SCRATCH_DIR_NAME)
        );
        assert!(is_private_staging_dir(&scratch));
        fs::write(scratch.join("get-1-0.body"), b"body").unwrap();
        drop(Staging::open(fixture.iroot(), V17).unwrap());
        assert!(scratch.join("get-1-0.body").exists());
        // Asked for again, the same dir.
        assert_eq!(scratch_dir(fixture.iroot()).unwrap(), scratch);
    }

    #[test]
    fn only_stale_request_bodies_are_swept_from_the_scratch_dir() {
        let fixture = Fixture::new();
        let scratch = scratch_dir(fixture.iroot()).unwrap();
        for name in ["get-1-0.body", "get-2-0.body", "other.body", "get-3-0.tmp"] {
            fs::write(scratch.join(name), b"body").unwrap();
        }
        let now = SystemTime::now();
        let old = now - STALE_SCRATCH_AGE - Duration::from_secs(60);
        for name in ["get-1-0.body", "other.body", "get-3-0.tmp"] {
            fs::File::options()
                .write(true)
                .open(scratch.join(name))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        sweep_scratch(&scratch, now);
        assert!(!scratch.join("get-1-0.body").exists());
        // A fresh body may belong to a request still under way.
        assert!(scratch.join("get-2-0.body").exists());
        // Only request bodies are swept.
        assert!(scratch.join("other.body").exists());
        assert!(scratch.join("get-3-0.tmp").exists());
    }

    #[test]
    fn opening_a_staging_dir_sweeps_older_attempts_and_trash() {
        let fixture = Fixture::new();
        let parent = fixture.iroot().join(STAGING_DIR_NAME);
        let older = parent.join("1.0.15");
        private_dir(&parent);
        private_dir(&older);
        fs::create_dir_all(older.join(EXTRACT_DIR_NAME).join("pkg")).unwrap();
        fs::write(older.join(fetch::ARCHIVE_NAME), b"old archive").unwrap();
        fs::write(older.join("x/pkg/MODEL-V2.bank.cmfd-copy"), b"partial").unwrap();
        fs::write(older.join(LOCK_FILE_NAME), b"{}").unwrap();
        // A higher release that was withdrawn after its download.
        let withdrawn = parent.join("1.0.18");
        private_dir(&withdrawn);
        fs::write(withdrawn.join(fetch::ARCHIVE_NAME), b"withdrawn").unwrap();
        // Another wallet is still installing this one.
        let held = Staging::open(fixture.iroot(), V16).unwrap();
        fs::write(held.dir().join(fetch::ARCHIVE_NAME), b"in use").unwrap();
        // Trash that still holds only package files, a delete that stopped
        // partway, trash with wallet data (its put-back failed), trash
        // the updater did not make, and a kept folder.
        let trash = |version, extras: &[&str], name: &str| {
            let dir = installed_version(fixture.iroot(), Version::new(1, 0, version), extras);
            let moved = parent.join(name);
            fs::rename(dir, &moved).unwrap();
            moved
        };
        let clean = trash(10, &[], "trash-clean");
        let partial = trash(11, &[], "deleting-partial");
        fs::remove_file(partial.join(PACKAGE_MANIFEST_NAME)).unwrap();
        let data = trash(12, &["data-mainnet/wallet.dat"], "trash-data");
        let unknown = parent.join(format!("{TRASH_PREFIX}old-version"));
        fs::create_dir_all(unknown.join("sub")).unwrap();
        fs::write(unknown.join("sub/file"), b"x").unwrap();
        let kept = trash(13, &["data-mainnet/wallet.dat"], "kept-data");

        let staging = Staging::open(fixture.iroot(), V17).unwrap();
        let names = |dir: &Path| -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(&older), [LOCK_FILE_NAME]);
        assert_eq!(names(&withdrawn), [LOCK_FILE_NAME]);
        assert_eq!(names(held.dir()), [fetch::ARCHIVE_NAME, LOCK_FILE_NAME]);
        assert!(!clean.exists() && !partial.exists());
        for dir in [&data, &kept] {
            assert_eq!(
                fs::read(dir.join("data-mainnet/wallet.dat")).unwrap(),
                b"extra"
            );
        }
        assert!(unknown.join("sub/file").exists());
        assert_eq!(
            names(&parent),
            [
                "1.0.15",
                "1.0.16",
                "1.0.17",
                "1.0.18",
                "kept-data",
                "trash-data",
                "trash-old-version"
            ]
        );
        drop((staging, held));

        // A folder that gained data is put back under its name.
        let iroot = fixture.iroot();
        let registry = fixture.registry();
        let with_data = installed_version(iroot, Version::new(1, 0, 9), &[]);
        assert!(remove_version(iroot, &with_data, registry).is_ok());
        let with_data = installed_version(iroot, Version::new(1, 0, 9), &["data-mainnet/x"]);
        assert!(remove_version(iroot, &with_data, registry).is_err());
        assert!(with_data.join("data-mainnet/x").exists());
        assert!(read_state(&with_data).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn a_version_in_use_is_kept_whole_under_its_name() {
        use std::os::windows::fs::OpenOptionsExt;
        let temp = TempDir::new();
        let dir = installed_version(&temp.0, Version::new(1, 0, 13), &[]);
        // Like a running node: open without delete sharing.
        let open = OpenOptions::new()
            .read(true)
            .share_mode(0x1)
            .open(dir.join("README.md"))
            .unwrap();
        let registry = temp.0.join(".registry");
        assert!(remove_version(&temp.0, &dir, &registry).is_err());
        assert!(holds_only_package_files(&dir));
        assert!(read_state(&dir).is_some());
        drop(open);
        remove_version(&temp.0, &dir, &registry).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn a_package_for_another_network_is_never_installed() {
        let files = package_files(V17);
        let fixture = Fixture::with(&files, &manifest(V17, &files, [0x11; 32]));
        let host = FakeWallet::new();
        assert_eq!(
            fixture.install_with(&host),
            Err(InstallError::Package(ReleaseError::NetworkMismatch))
        );
        assert_eq!(fixture.version_folders().len(), 1);
        assert!(host.calls.borrow().is_empty());
        // Retry re-uses the kept archive.
        assert!(fixture.staging_dir().join(fetch::ARCHIVE_NAME).exists());
        assert!(!fixture.staging_dir().join(EXTRACT_DIR_NAME).exists());

        let unknown = InstallTarget {
            network_id: None,
            ..fixture.target()
        };
        let result = install(
            fixture.staging(),
            &fixture.release,
            &unknown,
            &host,
            &AtomicBool::new(false),
        );
        assert_eq!(
            result,
            Err(InstallError::Package(ReleaseError::NetworkMismatch))
        );
    }

    #[test]
    fn a_tree_that_differs_from_its_record_is_refused() {
        let files = package_files(V17);
        let record = manifest(V17, &files, NETWORK);

        let mut extra = files.clone();
        extra.insert("extra.txt".into(), b"extra".to_vec());
        let mut missing = files.clone();
        missing.remove("README.md");
        let mut changed = files.clone();
        changed.insert("README.md".into(), b"read me!".to_vec());
        let mut extra_dir = files.clone();
        extra_dir.insert("tools/extra.txt".into(), b"x".to_vec());

        for (tree, path, problem) in [
            (extra, "extra.txt", "not part of the package"),
            (missing, "README.md", "missing"),
            (changed, "README.md", "changed"),
            (extra_dir, "tools", "not part of the package"),
        ] {
            let fixture = Fixture::with(&tree, &record);
            let result = fixture.install_with(&FakeWallet::new());
            assert_eq!(
                result,
                Err(InstallError::Tree {
                    path: path.into(),
                    problem
                }),
                "{path}"
            );
            assert_eq!(fixture.version_folders().len(), 1);
            assert!(
                !InstallError::Tree {
                    path: path.into(),
                    problem
                }
                .retry_automatically()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_system_tar_that_is_not_gnu_tar_is_named_as_the_problem() {
        struct Busybox;
        impl Host for Busybox {
            fn run(
                &self,
                program: &Path,
                args: &[OsString],
                timeout: Duration,
                cancel: &AtomicBool,
            ) -> Result<ToolOutput, String> {
                if args == [OsString::from("--version")] {
                    return Ok(ToolOutput {
                        code: Some(0),
                        stdout: b"BusyBox v1.36.1 multi-call binary.".to_vec(),
                        stderr: Vec::new(),
                    });
                }
                FakeWallet::new().run(program, args, timeout, cancel)
            }
        }
        let fixture = Fixture::new();
        let error = fixture.install_with(&Busybox).unwrap_err();
        assert!(
            matches!(&error, InstallError::Tar(detail) if detail.ends_with("is not GNU tar, which updates need on Linux")),
            "{error:?}"
        );
        assert_eq!(fixture.version_folders().len(), 1);
    }

    #[test]
    fn the_listing_allows_only_plain_paths_under_the_one_folder() {
        let top = "commonfoundry-mainnet-runtime-windows-x86_64-v1.0.17";
        let ok = format!("{top}/\n{top}/README.md\n{top}/production-v4/\n{top}/production-v4/x\n");
        assert_eq!(check_listing(ok.as_bytes(), top), Ok(4));
        assert_eq!(
            check_listing(ok.replace('\n', "\r\n").as_bytes(), top),
            Ok(4)
        );
        for bad in [
            String::new(),
            format!("{top}/../evil\n"),
            format!("{top}/a/../../evil\n"),
            format!("/{top}/README.md\n"),
            "C:/evil\n".into(),
            format!("{top}-other/README.md\n"),
            format!("other/\n{top}/README.md\n"),
            format!("{top}/.cmfd-updater/state.json\n"),
            format!("{top}\\README.md\n"),
            format!("{top}/README.md\nREADME.md\n"),
        ] {
            assert!(
                matches!(
                    check_listing(bad.as_bytes(), top),
                    Err(InstallError::Layout(_))
                ),
                "{bad:?}"
            );
        }
        assert!(check_listing(&[0xff, b'\n'], top).is_err());
    }

    #[test]
    fn the_verbose_listing_allows_only_files_and_folders() {
        // GNU tar, then bsdtar (Windows tar.exe), as they list 1.0.15.
        let gnu = "drwxr-xr-x 0/0               0 2026-10-13 13:39 pkg/\n\
                   -rw-r--r-- 0/0            1084 2026-10-13 13:39 pkg/LICENSE\n\
                   -rwxr-xr-x 0/0        25172272 2026-10-13 13:39 pkg/common-foundry-wallet\n";
        let bsd = "drwxr-xr-x  0 0      0           0 Oct 13 13:39 pkg/\r\n\
                   -rw-r--r--  0 0      0        1084 Oct 13 13:39 pkg/LICENSE\r\n\
                   -rwxr-xr-x  0 0      0    25172272 Oct 13 13:39 pkg/x.exe\r\n";
        for listing in [gnu, bsd] {
            assert_eq!(check_entry_types(listing.as_bytes(), 3), Ok(()));
            assert!(check_entry_types(listing.as_bytes(), 4).is_err());
        }
        for bad in [
            "hrw-r--r-- 0/0 0 2026-10-13 13:39 pkg/b link to pkg/a\n",
            "lrwxrwxrwx 0/0 0 2026-10-13 13:39 pkg/b -> /etc/passwd\n",
            "crw-r--r-- 0/0 1,3 2026-10-13 13:39 pkg/null\n",
            "prw-r--r-- 0/0 0 2026-10-13 13:39 pkg/fifo\n",
        ] {
            assert!(
                matches!(
                    check_entry_types(bad.as_bytes(), 1),
                    Err(InstallError::Layout(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_link_inside_the_archive_is_refused_before_unpacking() {
        let files = package_files(V17);
        let fixture = Fixture::with_tweak(&files, &manifest(V17, &files, NETWORK), |dir| {
            fs::hard_link(dir.join("README.md"), dir.join("README-copy.md")).unwrap();
        });
        let error = fixture.install_with(&FakeWallet::new()).unwrap_err();
        assert!(
            matches!(&error, InstallError::Layout(detail) if detail.contains("not a plain file or folder")),
            "{error:?}"
        );
        assert!(!fixture.staging_dir().join(EXTRACT_DIR_NAME).exists());
        assert_eq!(fixture.version_folders().len(), 1);
    }

    #[test]
    fn an_archive_with_the_wrong_folder_name_is_refused_before_unpacking() {
        let temp = TempDir::new();
        let running = running_package(&temp.0);
        let source = temp.0.join("source");
        let files = package_files(V17);
        write_package(
            &source,
            "commonfoundry-mainnet-runtime-other",
            &files,
            &manifest(V17, &files, NETWORK),
        );
        let packed = temp.0.join("packed");
        pack(&source, "commonfoundry-mainnet-runtime-other", &packed);
        let bytes = fs::read(&packed).unwrap();
        let fixture = Fixture {
            release: release_for(&bytes),
            archive: bytes,
            running,
            temp,
            registry: Registry::new(),
        };
        let result = fixture.install_with(&FakeWallet::new());
        assert!(matches!(result, Err(InstallError::Layout(_))), "{result:?}");
        assert!(!fixture.staging_dir().join(EXTRACT_DIR_NAME).exists());
    }

    #[test]
    fn a_kept_archive_is_not_unpacked_without_room_for_its_tree() {
        struct Tight(FakeWallet);
        impl Host for Tight {
            fn run(
                &self,
                program: &Path,
                args: &[OsString],
                timeout: Duration,
                cancel: &AtomicBool,
            ) -> Result<ToolOutput, String> {
                self.0.run(program, args, timeout, cancel)
            }
            fn available_space(&self, _dir: &Path) -> io::Result<u64> {
                Ok(SPACE_MARGIN_BYTES)
            }
        }
        let fixture = Fixture::new();
        let host = Tight(FakeWallet::new());
        let result = install(
            fixture.staging(),
            &fixture.release,
            &fixture.target(),
            &host,
            &AtomicBool::new(false),
        );
        let error = InstallError::NoSpace {
            needed: fixture.release.asset_size * 3 + SPACE_MARGIN_BYTES,
            available: SPACE_MARGIN_BYTES,
        };
        assert_eq!(result, Err(error.clone()));
        assert!(error.retry_automatically());
        assert!(fixture.staging_dir().join(fetch::ARCHIVE_NAME).exists());
        assert_eq!(fixture.version_folders().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_group_writable_folder_in_the_package_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let files = package_files(V17);
        let record = manifest(V17, &files, NETWORK);
        for (folder, reported) in [(PRODUCTION_V4, PRODUCTION_V4), ("", ".")] {
            let fixture = Fixture::with_tweak(&files, &record, |package| {
                fs::set_permissions(package.join(folder), fs::Permissions::from_mode(0o775))
                    .unwrap();
            });
            assert_eq!(
                fixture.install_with(&FakeWallet::new()),
                Err(InstallError::Tree {
                    path: reported.into(),
                    problem: "unpacked with the wrong permissions",
                })
            );
            assert_eq!(fixture.version_folders().len(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_inside_the_archive_is_refused() {
        let files = package_files(V17);
        let record = manifest(V17, &files, NETWORK);
        for target in ["/etc", "README.md", "../../outside"] {
            let fixture = Fixture::with_tweak(&files, &record, |package| {
                std::os::unix::fs::symlink(target, package.join("link")).unwrap();
            });
            let result = fixture.install_with(&FakeWallet::new());
            // Refused from the listing, before anything is unpacked.
            assert!(
                matches!(
                    &result,
                    Err(InstallError::Layout(detail)) if detail.contains("not a plain file or folder")
                ),
                "{target}: {result:?}"
            );
            assert_eq!(fixture.version_folders().len(), 1);
            assert!(!fixture.iroot().join("outside").exists());
            assert!(!fixture.staging_dir().join(EXTRACT_DIR_NAME).exists());
        }
    }

    #[test]
    fn a_wallet_that_never_answers_its_self_check_is_retried() {
        struct Silent;
        impl Host for Silent {
            fn run(
                &self,
                program: &Path,
                args: &[OsString],
                timeout: Duration,
                cancel: &AtomicBool,
            ) -> Result<ToolOutput, String> {
                if program.file_name() != Some(std::ffi::OsStr::new(wallet_name())) {
                    return run_tool(program, args, timeout, cancel);
                }
                Err(format!("{} did not finish in time", program.display()))
            }
        }
        let fixture = Fixture::new();
        let error = fixture.install_with(&Silent).unwrap_err();
        assert!(matches!(error, InstallError::Io(_)), "{error:?}");
        assert!(error.retry_automatically());
        assert_eq!(fixture.version_folders().len(), 1);
        assert!(fixture.staging_dir().join(fetch::ARCHIVE_NAME).exists());
        // A wrong answer is not retried by itself.
        let wrong = FakeWallet::reporting("common-foundry-wallet 1.0.16\n", "{}");
        assert!(
            !fixture
                .install_with(&wrong)
                .unwrap_err()
                .retry_automatically()
        );
    }

    #[test]
    fn a_wallet_that_fails_its_self_check_is_not_installed() {
        let fixture = Fixture::new();
        for host in [
            FakeWallet::reporting(
                "common-foundry-wallet 1.0.16\n",
                r#"{"package_version":"1.0.17"}"#,
            ),
            FakeWallet::reporting(
                "common-foundry-wallet 1.0.17\n",
                r#"{"package_version":"1.0.16"}"#,
            ),
            FakeWallet::reporting("common-foundry-wallet 1.0.17\n", "not json"),
        ] {
            let result = fixture.install_with(&host);
            assert!(
                matches!(result, Err(InstallError::SelfCheck(_))),
                "{result:?}"
            );
            assert_eq!(fixture.version_folders().len(), 1);
            assert!(fixture.staging_dir().join(fetch::ARCHIVE_NAME).exists());
        }
    }

    #[test]
    fn a_bank_that_cannot_be_linked_waits_for_consent() {
        struct NoLinks(FakeWallet);
        impl Host for NoLinks {
            fn run(
                &self,
                program: &Path,
                args: &[OsString],
                timeout: Duration,
                cancel: &AtomicBool,
            ) -> Result<ToolOutput, String> {
                self.0.run(program, args, timeout, cancel)
            }
            fn hard_link(&self, _original: &Path, _link: &Path) -> io::Result<()> {
                Err(io::Error::other("not on this volume"))
            }
        }
        let fixture = Fixture::new();
        let host = NoLinks(FakeWallet::new());
        assert_eq!(
            fixture.install_with(&host),
            Err(InstallError::Inputs(InputsError::NeedsCopyConsent {
                bytes: BANK.len() as u64
            }))
        );
        assert_eq!(fixture.version_folders().len(), 1);

        let agreed = InstallTarget {
            allow_bank_copy: true,
            ..fixture.target()
        };
        let installed = install(
            fixture.staging(),
            &fixture.release,
            &agreed,
            &host,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            installed.inputs.map(|inputs| inputs.bank),
            Some(inputs::BankCarried::Copied)
        );
    }

    #[test]
    fn a_cancelled_install_leaves_nothing_behind_but_the_archive() {
        let fixture = Fixture::new();
        let result = install(
            fixture.staging(),
            &fixture.release,
            &fixture.target(),
            &FakeWallet::new(),
            &AtomicBool::new(true),
        );
        assert_eq!(result, Err(InstallError::Cancelled));
        assert_eq!(fixture.version_folders().len(), 1);
        assert_eq!(
            fixture.staging_leftovers(),
            [fetch::ARCHIVE_NAME, LOCK_FILE_NAME]
        );
        // The lock was released.
        assert!(Staging::open(fixture.iroot(), V17).is_ok());
    }

    #[test]
    fn rename_retries_back_off_to_8_seconds_for_at_least_a_minute() {
        let delays: Vec<Duration> = rename_delays().collect();
        assert_eq!(delays[0], Duration::from_millis(250));
        assert_eq!(delays[5], Duration::from_secs(8));
        assert!(delays.iter().all(|delay| *delay <= Duration::from_secs(8)));
        let total: Duration = delays.iter().sum();
        assert!(total >= Duration::from_secs(60));
        assert!(total - *delays.last().unwrap() < Duration::from_secs(60));
    }

    /// Renames fail with a sharing violation `failures` times first.
    struct Held {
        failures: Cell<usize>,
        slept: RefCell<Vec<Duration>>,
    }

    impl Host for Held {
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            if self.failures.get() > 0 {
                self.failures.set(self.failures.get() - 1);
                let code = if cfg!(windows) { 32 } else { 16 };
                return Err(io::Error::from_raw_os_error(code));
            }
            fs::rename(from, to)
        }

        fn sleep(&self, duration: Duration) {
            self.slept.borrow_mut().push(duration);
        }
    }

    #[test]
    fn a_folder_held_open_briefly_is_moved_after_a_retry() {
        let temp = TempDir::new();
        let staged = temp.0.join("staged");
        fs::create_dir(&staged).unwrap();
        let host = Held {
            failures: Cell::new(3),
            slept: RefCell::new(Vec::new()),
        };
        let moved = rename_into_place(&staged, &temp.0, "pkg", &host).unwrap();
        assert_eq!(moved, temp.0.join("pkg"));
        assert_eq!(
            *host.slept.borrow(),
            [250, 500, 1000].map(Duration::from_millis)
        );

        let staged = temp.0.join("staged2");
        fs::create_dir(&staged).unwrap();
        let host = Held {
            failures: Cell::new(usize::MAX),
            slept: RefCell::new(Vec::new()),
        };
        assert!(matches!(
            rename_into_place(&staged, &temp.0, "other", &host),
            Err(InstallError::Io(_))
        ));
        assert!(host.slept.borrow().iter().sum::<Duration>() >= Duration::from_secs(60));
        assert!(staged.exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_cloud_synced_root_installs_under_local_app_data() {
        let env = |name: &str| -> Option<OsString> {
            match name {
                "OneDrive" => Some(r"C:\Users\alice\OneDrive".into()),
                "LOCALAPPDATA" => Some(r"C:\Users\alice\AppData\Local".into()),
                _ => None,
            }
        };
        let local = Path::new(r"C:\Users\alice\AppData\Local")
            .join("CommonFoundry")
            .join("versions");
        let synced = Path::new(r"C:\Users\alice\onedrive\Desktop");
        assert_eq!(install_root_with(synced, 0, &env), local);
        let plain = Path::new(r"D:\CF-Wallet");
        assert_eq!(install_root_with(plain, 0, &env), plain);
        // A sync engine's attributes on the folder itself.
        assert_eq!(install_root_with(plain, 0x40_0000, &env), local);
        assert_eq!(install_root_with(plain, 0x8_0000, &env), local);
        // A path that only starts with the same letters is not inside.
        let lookalike = Path::new(r"C:\Users\alice\OneDrive-old");
        assert_eq!(install_root_with(lookalike, 0, &env), lookalike);
        // Without LOCALAPPDATA there is nowhere else to go.
        assert_eq!(install_root_with(synced, 0, &|_: &str| None), synced);
        let relative = |name: &str| -> Option<OsString> {
            match name {
                "LOCALAPPDATA" => Some("relative".into()),
                _ => env(name),
            }
        };
        assert_eq!(install_root_with(synced, 0, &relative), synced);
    }

    /// An installed version folder made by the updater, plus `extras`.
    fn installed_version(iroot: &Path, version: Version, extras: &[&str]) -> PathBuf {
        let files = package_files(version);
        let name = package_name(platform(), version);
        let dir = write_package(iroot, &name, &files, &manifest(version, &files, NETWORK));
        fs::create_dir(dir.join(MARKER_DIR_NAME)).unwrap();
        let state = InstallState {
            state: STATE_STAGED.into(),
            version: version.to_string(),
            sums_sha256: "00".repeat(32),
            archive_sha256: "00".repeat(32),
            staged_at: 1,
            extra: Map::new(),
        };
        write_state(&dir, &state).unwrap();
        for extra in extras {
            let path = dir.join(extra);
            if extra.ends_with('/') {
                fs::create_dir_all(path).unwrap();
                continue;
            }
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"extra").unwrap();
        }
        dir
    }

    fn set_state(dir: &Path, value: &str) {
        let mut state = read_state(dir).unwrap();
        state.state = value.into();
        write_state(dir, &state).unwrap();
    }

    #[test]
    fn cleanup_keeps_the_newest_older_version_that_works() {
        let temp = TempDir::new();
        let iroot = &temp.0;
        let v = |patch| Version::new(1, 0, patch);
        let oldest = installed_version(iroot, v(14), &[]);
        let older = installed_version(iroot, v(15), &[]);
        let good = installed_version(iroot, v(16), &[]);
        let broken = installed_version(iroot, v(17), &[]);
        let running = installed_version(iroot, v(18), &[]);
        set_state(&good, STATE_STARTED_OK);
        set_state(&broken, STATE_FAILED);
        // 1.0.17 failed to start, so 1.0.16 is the fallback that is kept.
        assert_eq!(
            removable_versions(
                iroot,
                platform(),
                v(18),
                &[&running],
                &iroot.join(".registry")
            ),
            [oldest.clone(), older.clone()]
        );
        // Without a started one, the newest that did not fail is kept.
        set_state(&good, STATE_STAGED);
        set_state(&older, STATE_STARTED_OK);
        assert_eq!(
            removable_versions(
                iroot,
                platform(),
                v(18),
                &[&running],
                &iroot.join(".registry")
            ),
            std::slice::from_ref(&oldest)
        );
        set_state(&older, STATE_STAGED);
        assert_eq!(
            removable_versions(
                iroot,
                platform(),
                v(18),
                &[&running],
                &iroot.join(".registry")
            ),
            [oldest.clone(), older.clone()]
        );
        // Only failed versions below the running one: keep everything.
        for dir in [&oldest, &older, &good] {
            set_state(dir, STATE_FAILED);
        }
        assert!(
            removable_versions(
                iroot,
                platform(),
                v(18),
                &[&running],
                &iroot.join(".registry")
            )
            .is_empty()
        );
    }

    #[test]
    fn cleanup_keeps_a_previous_version_the_forwarder_would_start() {
        let temp = TempDir::new();
        let iroot = &temp.0;
        let registry = temp.0.join(".registry");
        let v = |patch| Version::new(1, 0, patch);
        let record_it = |dir: &Path| {
            let sums = b"kept sums";
            fs::write(dir.join(MARKER_DIR_NAME).join(release::SUMS_NAME), sums).unwrap();
            let record = fs::read(dir.join(PACKAGE_MANIFEST_NAME)).unwrap();
            register_installed(&registry, dir, &record, sha256(sums)).unwrap();
        };
        let oldest = installed_version(iroot, v(14), &[]);
        let recorded = installed_version(iroot, v(15), &[]);
        let unrecorded = installed_version(iroot, v(16), &[]);
        let running = installed_version(iroot, v(18), &[]);
        record_it(&oldest);
        record_it(&recorded);
        set_state(&unrecorded, STATE_STARTED_OK);
        // 1.0.16 started once, but the registry lost it, so the forwarder
        // refuses it: 1.0.15 is the fallback that is kept.
        assert_eq!(
            removable_versions(iroot, platform(), v(18), &[&running], &registry),
            std::slice::from_ref(&oldest)
        );
        // With nothing recorded, the rule is the one without a registry.
        let empty = temp.0.join(".other-registry");
        assert_eq!(
            removable_versions(iroot, platform(), v(18), &[&running], &empty),
            [oldest.clone(), recorded.clone()]
        );
    }

    #[test]
    fn cleanup_keeps_the_running_version_one_previous_and_anything_newer() {
        let temp = TempDir::new();
        let iroot = &temp.0;
        let v = |patch| Version::new(1, 0, patch);
        let inputs = [
            "production-v4/MODEL-V2.bank",
            "production-v4/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json",
            "production-v4/fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json",
            "production-v4/fixed/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json.cmfd-copy",
            "production-v4/.parts/MODEL-V2.bank.part0",
            "production-v4/.prepare-v4-inputs.lock",
            "production-mainnet/LAUNCH-BEACON.json",
        ];
        let oldest = installed_version(iroot, v(13), &inputs);
        let old = installed_version(iroot, v(14), &[]);
        let previous = installed_version(iroot, v(15), &[]);
        let running = installed_version(iroot, v(16), &[]);
        let newer = installed_version(iroot, v(17), &[]);
        let _ = (&previous, &newer);
        assert_eq!(
            removable_versions(
                iroot,
                platform(),
                v(16),
                &[&running],
                &iroot.join(".registry")
            ),
            [oldest.clone(), old.clone()]
        );
        // The folder the user launches is never removed.
        assert_eq!(
            removable_versions(
                iroot,
                platform(),
                v(16),
                &[&running, &old],
                &iroot.join(".registry")
            ),
            std::slice::from_ref(&oldest)
        );
        // It leaves the registry too.
        let registry = temp.0.join(".registry");
        register_installed(&registry, &oldest, b"record", [0; 32]).unwrap();
        let (entry, _) = registry_entry(&registry, &oldest).unwrap();
        assert!(entry.is_file());
        remove_version(iroot, &oldest, &registry).unwrap();
        assert!(!oldest.exists());
        assert!(!entry.exists());
        assert!(
            fs::read_dir(iroot.join(STAGING_DIR_NAME))
                .unwrap()
                .next()
                .is_none()
        );
        assert!(previous.exists() && running.exists() && newer.exists());
    }

    #[test]
    fn cleanup_never_removes_a_folder_with_data_or_anything_unexpected() {
        let temp = TempDir::new();
        let iroot = &temp.0;
        let v = |patch| Version::new(1, 0, patch);
        let with_data = installed_version(iroot, v(10), &["data-mainnet/blocks.log"]);
        let with_work = installed_version(iroot, v(11), &["work/x"]);
        let with_notes = installed_version(iroot, v(12), &["notes.txt"]);
        let empty_data = installed_version(iroot, v(8), &["data-mainnet/"]);
        let empty_work = installed_version(iroot, v(9), &["work/"]);
        let empty_other = installed_version(iroot, v(7), &["production-v4/backup/"]);
        let manual = installed_version(iroot, v(13), &[]);
        fs::remove_dir_all(manual.join(MARKER_DIR_NAME)).unwrap();
        installed_version(iroot, v(14), &[]);
        let running = installed_version(iroot, v(15), &[]);
        assert!(
            removable_versions(
                iroot,
                platform(),
                v(15),
                &[&running],
                &iroot.join(".registry")
            )
            .is_empty()
        );
        for dir in [
            with_data,
            with_work,
            with_notes,
            manual,
            empty_data,
            empty_work,
            empty_other,
        ] {
            assert!(dir.exists());
        }
    }

    macro_rules! real {
        ($path:literal) => {
            include_bytes!(concat!("../../tests/fixtures/updater/v1.0.15/", $path)).as_slice()
        };
    }

    /// A folder as the updater leaves it for the real, signed 1.0.15 release.
    fn real_installed(iroot: &Path, name: &str) -> PathBuf {
        let sums = real!("SHA256SUMS.txt");
        let record: &[u8] = match platform() {
            Platform::WindowsX86_64 => real!("runtime-windows-x86_64-MAINNET-PACKAGE.json"),
            Platform::LinuxX86_64 => real!("runtime-linux-x86_64-MAINNET-PACKAGE.json"),
        };
        let asset = platform().runtime_asset(Version::new(1, 0, 15));
        let row = std::str::from_utf8(sums)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_suffix(&format!("  {asset}")))
            .unwrap()
            .to_owned();
        let dir = iroot.join(name);
        let marker = dir.join(MARKER_DIR_NAME);
        fs::create_dir_all(&marker).unwrap();
        fs::write(dir.join(PACKAGE_MANIFEST_NAME), record).unwrap();
        for (file, bytes) in [
            (release::SUMS_NAME, sums),
            (release::SIGNATURE_NAME, real!("SHA256SUMS.txt.sig")),
            (release::BUILDINFO_NAME, real!("BUILDINFO.json")),
            (PACKAGE_MANIFEST_NAME, record),
        ] {
            fs::write(marker.join(file), bytes).unwrap();
        }
        let state = InstallState {
            state: STATE_STAGED.into(),
            version: "1.0.15".into(),
            sums_sha256: hex::encode(sha256(sums)),
            archive_sha256: row,
            staged_at: 1,
            extra: Map::new(),
        };
        write_state(&dir, &state).unwrap();
        dir
    }

    fn marker_version(dir: &Path) -> Result<Version, MarkerError> {
        verify_marker(dir, platform()).map(|(signed, ..)| signed.version)
    }

    #[test]
    fn a_marker_from_a_real_signed_release_checks_out() {
        let temp = TempDir::new();
        let v15 = Version::new(1, 0, 15);
        let name = package_name(platform(), v15);
        let dir = real_installed(&temp.0, &name);
        assert_eq!(marker_version(&dir), Ok(v15));
        let auto = real_installed(&temp.0, &format!("{name}-auto2"));
        assert_eq!(marker_version(&auto), Ok(v15));

        // A folder named for another version, or not a version name.
        for other in [
            package_name(platform(), Version::new(1, 0, 16)),
            format!("{name}-other"),
            format!("{name}-auto10"),
        ] {
            let dir = real_installed(&temp.0, &other);
            assert!(marker_version(&dir).is_err(), "{other}");
        }

        // Anything changed in the marker is refused.
        let marker = dir.join(MARKER_DIR_NAME);
        type Change = fn(&mut InstallState);
        let changes: [(&str, Change); 3] = [
            ("archive", |state| state.archive_sha256 = "00".repeat(32)),
            ("sums", |state| state.sums_sha256 = "00".repeat(32)),
            ("version", |state| state.version = "1.0.16".into()),
        ];
        for (what, change) in changes {
            let good = read_state(&dir).unwrap();
            let mut bad = good.clone();
            change(&mut bad);
            write_state(&dir, &bad).unwrap();
            assert!(marker_version(&dir).is_err(), "{what}");
            write_state(&dir, &good).unwrap();
        }
        let buildinfo = marker.join(release::BUILDINFO_NAME);
        let mut bytes = fs::read(&buildinfo).unwrap();
        bytes.push(b' ');
        fs::write(&buildinfo, &bytes).unwrap();
        assert!(marker_version(&dir).is_err());
        bytes.pop();
        fs::write(&buildinfo, &bytes).unwrap();
        assert_eq!(marker_version(&dir), Ok(v15));

        let mut record = fs::read(dir.join(PACKAGE_MANIFEST_NAME)).unwrap();
        record.push(b'\n');
        fs::write(dir.join(PACKAGE_MANIFEST_NAME), &record).unwrap();
        assert!(marker_version(&dir).is_err());
    }

    #[test]
    fn a_real_installed_folder_is_checked_down_to_its_wallet_exe() {
        let mainnet = cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID;
        assert!(mainnet.is_some());
        let temp = TempDir::new();
        let v15 = Version::new(1, 0, 15);
        let dir = real_installed(&temp.0, &package_name(platform(), v15));
        let registry = temp.0.join(".registry");
        let refused = |network| {
            verify_installed(&dir, platform(), network, &registry)
                .unwrap_err()
                .0
        };
        // The signed files check out, but this user's updater did not
        // install the folder.
        assert!(refused(mainnet).contains("this user's updater did not install it here"));
        let record = fs::read(dir.join(PACKAGE_MANIFEST_NAME)).unwrap();
        let sums = fs::read(dir.join(MARKER_DIR_NAME).join(release::SUMS_NAME)).unwrap();
        register_installed(&registry, &dir, &record, sha256(&sums)).unwrap();
        // The marker checks out, but no package file is there.
        assert!(refused(mainnet).contains("is missing or changed"));
        assert!(refused(None).contains("network"));
        // Every listed file at its listed size: only the exe hash is left,
        // and these are not the real bytes.
        let record: Value =
            serde_json::from_slice(&fs::read(dir.join(PACKAGE_MANIFEST_NAME)).unwrap()).unwrap();
        for (relative, file) in record["files"].as_object().unwrap() {
            let path = dir.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            File::create(&path)
                .unwrap()
                .set_len(file["bytes"].as_u64().unwrap())
                .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if LINUX_EXECUTABLES.contains(&relative.as_str())
                    || relative.ends_with(".sh")
                {
                    0o755
                } else {
                    0o644
                };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        assert_eq!(
            refused(mainnet),
            format!("{}: {} changed", dir.display(), wallet_name())
        );
    }

    #[test]
    fn an_installed_folder_is_checked_file_by_file_with_its_exe_held_open() {
        let temp = TempDir::new();
        let dir = installed_version(&temp.0, V17, &[]);
        let record = fs::read(dir.join(PACKAGE_MANIFEST_NAME)).unwrap();
        let signed = release::SignedFiles {
            version: V17,
            commit: COMMIT.into(),
            asset_sha256: [0; 32],
            key: ReleaseKeySlot::Current,
        };
        let check = |signed: &release::SignedFiles, network| {
            release::check_kept_package_manifest(&record, platform(), signed, network)
        };
        // The kept record must name the signed commit and this network.
        let other_commit = release::SignedFiles {
            commit: "f".repeat(40),
            ..signed.clone()
        };
        assert!(check(&other_commit, Some(NETWORK)).is_err());
        assert!(check(&signed, Some([0x11; 32])).is_err());
        assert!(check(&signed, None).is_err());
        let checked = check(&signed, Some(NETWORK)).unwrap();

        let (path, exe) = check_package_files(&dir, &checked, platform()).unwrap();
        assert_eq!(path, dir.join(wallet_name()));
        #[cfg(windows)]
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        drop(exe);

        let files = |dir: &Path| check_package_files(dir, &checked, platform()).map(|_| ());
        let original = fs::read(&path).unwrap();
        let mut swapped = original.clone();
        swapped[0] ^= 1;
        fs::write(&path, &swapped).unwrap();
        assert_eq!(files(&dir), Err(format!("{} changed", wallet_name())));
        fs::write(&path, &original).unwrap();
        let readme = dir.join("README.md");
        fs::write(&readme, b"short").unwrap();
        assert_eq!(
            files(&dir),
            Err("README.md is missing or changed".to_owned())
        );
        fs::remove_file(&readme).unwrap();
        assert_eq!(
            files(&dir),
            Err("README.md is missing or changed".to_owned())
        );
        fs::write(&readme, b"read me").unwrap();
        assert_eq!(files(&dir), Ok(()));
        // Every listed file is hashed, not only the exe.
        fs::write(&readme, b"read us").unwrap();
        assert_eq!(files(&dir), Err("README.md changed".to_owned()));
        fs::write(&readme, b"read me").unwrap();
        assert_eq!(files(&dir), Ok(()));
    }

    #[test]
    fn an_installed_folder_counts_only_with_the_releases_own_signed_files() {
        let fixture = Fixture::new();
        let installed = fixture.install_with(&FakeWallet::new()).unwrap();
        let found = || fixture.found();
        assert_eq!(found(), Some(installed.dir.clone()));
        let marker = installed.dir.join(MARKER_DIR_NAME);
        for file in [
            release::SUMS_NAME,
            release::SIGNATURE_NAME,
            release::BUILDINFO_NAME,
        ] {
            let path = marker.join(file);
            let bytes = fs::read(&path).unwrap();
            fs::write(&path, b"other").unwrap();
            assert_eq!(found(), None, "{file}");
            fs::write(&path, &bytes).unwrap();
        }
        let good = read_state(&installed.dir).unwrap();
        let mut bad = good.clone();
        bad.archive_sha256 = "00".repeat(32);
        write_state(&installed.dir, &bad).unwrap();
        assert_eq!(found(), None);
        write_state(&installed.dir, &good).unwrap();
        assert_eq!(found(), Some(installed.dir.clone()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&installed.dir, fs::Permissions::from_mode(0o775)).unwrap();
            assert_eq!(found(), None);
            fs::set_permissions(&installed.dir, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(found(), Some(installed.dir.clone()));
        }
    }

    #[test]
    fn only_a_folder_in_this_users_registry_counts_as_installed() {
        let fixture = Fixture::new();
        let installed = fixture.install_with(&FakeWallet::new()).unwrap();
        let record = fs::read(installed.dir.join(PACKAGE_MANIFEST_NAME)).unwrap();
        let sums = fixture.release.sums_sha256;
        assert!(is_registered(
            fixture.registry(),
            &installed.dir,
            &record,
            sums
        ));
        // Another record or SUMS under the same path does not count.
        assert!(!is_registered(
            fixture.registry(),
            &installed.dir,
            b"another record",
            sums
        ));
        assert!(!is_registered(
            fixture.registry(),
            &installed.dir,
            &record,
            [0; 32]
        ));
        // Nor does the same folder under another path.
        let moved = fixture.iroot().join("moved");
        fs::rename(&installed.dir, &moved).unwrap();
        assert!(!is_registered(fixture.registry(), &moved, &record, sums));
        fs::rename(&moved, &installed.dir).unwrap();
        assert_eq!(fixture.found(), Some(installed.dir.clone()));

        // A folder the registry does not know, like one someone made from
        // the release's public files, is never adopted: the release is
        // installed again beside it.
        unregister_installed(fixture.registry(), &installed.dir).unwrap();
        unregister_installed(fixture.registry(), &installed.dir).unwrap();
        assert_eq!(fixture.found(), None);
        // This user's updater made it (a crash before the recording, a lost
        // registry), so it is moved to the trash, not left to push the
        // install to another name.
        let folders = fixture.version_folders();
        let reinstalled = fixture.install_with(&FakeWallet::new()).unwrap();
        assert_eq!(reinstalled.dir, installed.dir);
        assert_eq!(fixture.version_folders(), folders);
        assert_eq!(fixture.found(), Some(installed.dir.clone()));
        // Another user's install in a shared root is never touched: the
        // release is installed again beside it.
        unregister_installed(fixture.registry(), &installed.dir).unwrap();
        let mut theirs = read_state(&installed.dir).unwrap();
        theirs.extra.insert(
            INSTALLED_FOR_FIELD.into(),
            installed_for(Path::new("another user's registry")).into(),
        );
        write_state(&installed.dir, &theirs).unwrap();
        let again = fixture.install_with(&FakeWallet::new()).unwrap();
        assert_eq!(
            again.dir,
            fixture
                .iroot()
                .join(format!("{}-auto", package_name(platform(), V17)))
        );
        assert!(installed.dir.join(PACKAGE_MANIFEST_NAME).is_file());
        assert_eq!(fixture.found(), Some(again.dir.clone()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let registry = fixture.registry().join(REGISTRY_DIR_NAME);
            register_installed(&registry, &again.dir, &record, sums).unwrap();
            assert_eq!(
                fs::metadata(&registry).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert!(is_registered(&registry, &again.dir, &record, sums));
            fs::set_permissions(&registry, fs::Permissions::from_mode(0o770)).unwrap();
            assert!(!is_registered(&registry, &again.dir, &record, sums));
            assert!(register_installed(&registry, &again.dir, &record, sums).is_err());
        }
    }

    #[test]
    fn a_registry_that_cannot_be_written_fails_before_anything_is_unpacked() {
        let fixture = Fixture::new();
        let blocked = fixture.iroot().join("not-a-dir");
        fs::write(&blocked, b"file").unwrap();
        let registry = blocked.join(REGISTRY_DIR_NAME);
        let target = InstallTarget {
            registry: &registry,
            ..fixture.target()
        };
        let host = FakeWallet::new();
        let result = install(
            fixture.staging(),
            &fixture.release,
            &target,
            &host,
            &AtomicBool::new(false),
        );
        assert!(
            matches!(&result, Err(InstallError::Unusable(why)) if why.contains("cannot record installs in")),
            "{result:?}"
        );
        assert!(result.unwrap_err().retry_automatically());
        // No tar, no self-check, no input copy, no folder.
        assert!(host.calls.borrow().is_empty(), "{:?}", host.calls.borrow());
        assert_eq!(fixture.version_folders().len(), 1);
        // The archive is kept, and with a usable registry it installs.
        let installed = fixture.install_with(&FakeWallet::new()).unwrap();
        assert_eq!(
            installed.dir,
            fixture.iroot().join(package_name(platform(), V17))
        );
    }

    #[test]
    fn a_registry_that_cannot_be_used_never_costs_a_recorded_folder() {
        let fixture = Fixture::new();
        let installed = fixture.install_with(&FakeWallet::new()).unwrap();
        // The registry dir is replaced by a file for a while: nothing is
        // recorded any more, but the folder is not taken for a leftover.
        let registry = fixture.registry().to_path_buf();
        let aside = registry.with_extension("aside");
        fs::rename(&registry, &aside).unwrap();
        fs::write(&registry, b"not a dir").unwrap();
        let result = fixture.install_with(&FakeWallet::new());
        assert!(
            matches!(&result, Err(InstallError::Unusable(why)) if why.contains("cannot record installs in")),
            "{result:?}"
        );
        assert!(installed.dir.join(PACKAGE_MANIFEST_NAME).is_file());
        fs::remove_file(&registry).unwrap();
        fs::rename(&aside, &registry).unwrap();
        assert_eq!(fixture.found(), Some(installed.dir));
    }

    #[test]
    fn the_registry_lives_in_the_users_own_data_dir() {
        let lookup = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            }
        };
        assert_eq!(registry_dir(&lookup(&[])), None);
        #[cfg(windows)]
        {
            assert_eq!(
                registry_dir(&lookup(&[(
                    "LOCALAPPDATA",
                    r"C:\Users\alice\AppData\Local"
                )])),
                Some(PathBuf::from(
                    r"C:\Users\alice\AppData\Local\CommonFoundry\installed"
                ))
            );
            assert_eq!(registry_dir(&lookup(&[("LOCALAPPDATA", "relative")])), None);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(
                registry_dir(&lookup(&[("HOME", "/home/alice")])),
                Some(PathBuf::from(
                    "/home/alice/.local/share/CommonFoundry/installed"
                ))
            );
            assert_eq!(
                registry_dir(&lookup(&[
                    ("HOME", "/home/alice"),
                    ("XDG_DATA_HOME", "/data")
                ])),
                Some(PathBuf::from("/data/CommonFoundry/installed"))
            );
            assert_eq!(
                registry_dir(&lookup(&[
                    ("HOME", "/home/alice"),
                    ("XDG_DATA_HOME", "rel")
                ])),
                Some(PathBuf::from(
                    "/home/alice/.local/share/CommonFoundry/installed"
                ))
            );
            assert_eq!(registry_dir(&lookup(&[("HOME", "relative")])), None);
        }
    }

    #[test]
    fn a_rewrite_of_the_state_keeps_fields_a_later_step_added() {
        let temp = TempDir::new();
        let dir = installed_version(&temp.0, V17, &[]);
        let mut state = read_state(&dir).unwrap();
        state.extra.insert("start_attempts".into(), 2.into());
        write_state(&dir, &state).unwrap();
        let mut reread = read_state(&dir).unwrap();
        assert_eq!(reread.extra["start_attempts"], 2);
        reread.state = "started_ok".into();
        write_state(&dir, &reread).unwrap();
        assert_eq!(read_state(&dir).unwrap().extra["start_attempts"], 2);
        assert!(
            !dir.join(MARKER_DIR_NAME)
                .join(STATE_TEMP_FILE_NAME)
                .exists()
        );
    }
}
