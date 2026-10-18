//! The prepared inputs a new version takes over from the running one when it
//! is installed (UPDATER-DESIGN.md sections 2.6 step 7 and 2.10).
//!
//! - The proof bank (`production-v4/MODEL-V2.bank`, 6.4 GB) is hard-linked
//!   when both packages' `V4-INPUT-CHUNKS.json` list the same bank. When a
//!   link is not possible (another volume, exFAT, a cloud placeholder), it is
//!   copied only after the user agreed. A different bank entry means the
//!   update has to be installed by hand.
//! - The mining caches (`production-v4/fixed/*`, about 55 GB) are only ever
//!   hard-linked, never copied.
//! - The fixed artifact record is copied from the new, verified package.
//! - The launch beacon is copied only when both packages carry a
//!   byte-identical `production-mainnet/MAINNET-PLAN.json`.
//!
//! Every input is linked or copied file by file; `production-v4/` is never
//! linked as a whole, because the package ships versioned binaries inside it.
//! Only these named paths of the running package are read. Nothing here
//! reads or writes the wallet's data dir.
//!
//! The new node re-authenticates the bank against its compiled pins when it
//! opens, so the bank is matched by its chunk entry and its size, never by
//! hashing 6.4 GB here.
//!
//! **Adopting mining caches later** ([`adopt_mining_inputs`]). Users run
//! PREPARE-MINING from the folder they know, which after an update is the
//! anchor (the package folder they unpacked and launch), not the version
//! folder that runs. When a cache file is missing in the running version, it
//! is hard-linked from the anchor or from another version folder this user's
//! updater installed ([`mining_input_sources`]), when that folder lists the
//! same chunk entry and holds a plain file of exactly that size. A cache is
//! never copied. Once every cache is present, the fixed dir also gets its
//! artifact record, copied from the running package's own (listed) record,
//! as PREPARE-MINING leaves it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::install::{self, Host, SPACE_MARGIN_BYTES};
use super::release::{self, Platform};

pub(crate) const PRODUCTION_V4: &str = "production-v4";
pub(crate) const CHUNKS_NAME: &str = "V4-INPUT-CHUNKS.json";
pub(crate) const BANK_NAME: &str = "MODEL-V2.bank";
pub(crate) const FIXED_RECORD_NAME: &str = "FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json";
pub(crate) const PLAN_PATH: &str = "production-mainnet/MAINNET-PLAN.json";
pub(crate) const BEACON_PATH: &str = "production-mainnet/LAUNCH-BEACON.json";
const FIXED_DIR: &str = "fixed";
const MAX_SMALL_FILE_BYTES: u64 = 1024 * 1024;
pub(crate) const COPY_SUFFIX: &str = ".cmfd-copy";
/// At most this many version folders are looked at as cache sources.
const MAX_SOURCE_FOLDERS: usize = 64;

/// One prepared input as `V4-INPUT-CHUNKS.json` lists it. Unknown fields
/// (`parts`) are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ChunkEntry {
    name: String,
    relative_path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Chunks {
    files: Vec<ChunkEntry>,
}

/// The prepared inputs a package expects under `production-v4/`, by
/// relative path.
pub(crate) fn chunk_paths(package: &Path) -> Result<Vec<String>, InputsError> {
    Ok(read_chunks(package)?
        .into_iter()
        .map(|entry| entry.relative_path)
        .collect())
}

fn read_chunks(package: &Path) -> Result<Vec<ChunkEntry>, InputsError> {
    let path = package.join(CHUNKS_NAME);
    let bytes = read_small_file(&path)
        .map_err(|error| InputsError::Chunks(format!("{}: {error}", path.display())))?;
    let chunks: Chunks = serde_json::from_slice(&bytes)
        .map_err(|error| InputsError::Chunks(format!("{}: {error}", path.display())))?;
    for entry in &chunks.files {
        if !release::is_package_path(&entry.relative_path) {
            return Err(InputsError::Chunks(format!(
                "{}: {:?} is not a plain relative path",
                path.display(),
                entry.relative_path
            )));
        }
    }
    Ok(chunks.files)
}

/// How the bank reached the new version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BankCarried {
    Linked,
    Copied,
}

/// What [`carry_over`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CarriedInputs {
    pub(crate) bank: BankCarried,
    /// Mining cache files hard-linked into the new version.
    pub(crate) mining_caches_linked: usize,
    pub(crate) beacon_copied: bool,
}

/// Why the inputs could not be carried over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InputsError {
    /// A package's `V4-INPUT-CHUNKS.json` is missing or malformed.
    Chunks(String),
    /// The new version lists a different proof bank: install it by hand.
    BankChanged,
    /// The running version has no prepared bank of the listed size.
    NoBank,
    /// The bank cannot be hard-linked here. Ask the user before copying.
    NeedsCopyConsent {
        bytes: u64,
    },
    /// Not enough free space for the agreed copy.
    NoSpace {
        needed: u64,
        available: u64,
    },
    Io {
        path: String,
        detail: String,
    },
}

impl std::fmt::Display for InputsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chunks(detail) => write!(f, "the list of prepared inputs is unusable: {detail}"),
            Self::BankChanged => {
                f.write_str("this update changes the proof bank; install it by hand")
            }
            Self::NoBank => {
                f.write_str("this wallet's package has no prepared proof bank to carry over")
            }
            Self::NeedsCopyConsent { bytes } => write!(
                f,
                "this update needs to copy {bytes} bytes of the proof bank because hard links aren't possible here"
            ),
            Self::NoSpace { needed, available } => write!(
                f,
                "copying the proof bank needs {needed} bytes free, but only {available} are"
            ),
            Self::Io { path, detail } => write!(f, "{path}: {detail}"),
        }
    }
}

impl std::error::Error for InputsError {}

fn io_error(path: &Path, error: io::Error) -> InputsError {
    InputsError::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    }
}

/// Carries the prepared inputs from the running package folder `from` into
/// the new, already verified package tree `to`.
///
/// `allow_copy` is the user's answer to "copy the bank?": without it, a bank
/// that cannot be linked gives [`InputsError::NeedsCopyConsent`] and nothing
/// is copied.
pub(crate) fn carry_over(
    from: &Path,
    to: &Path,
    allow_copy: bool,
    host: &dyn Host,
) -> Result<CarriedInputs, InputsError> {
    let old = read_chunks(from)?;
    let new = read_chunks(to)?;
    let target = to.join(PRODUCTION_V4);
    create_dir(&target)?;

    let bank = carry_bank(from, to, &old, &new, allow_copy, host)?;

    // The fixed record comes from the new package, never from the old one.
    copy_file(&to.join(FIXED_RECORD_NAME), &target.join(FIXED_RECORD_NAME))?;

    let mut mining_caches_linked = 0;
    for entry in new.iter().filter(|entry| entry.name != BANK_NAME) {
        if !old.contains(entry) {
            continue;
        }
        let source = from.join(PRODUCTION_V4).join(&entry.relative_path);
        let destination = target.join(&entry.relative_path);
        if is_linkable(&source, entry.bytes)
            && destination
                .parent()
                .is_some_and(|dir| create_dir(dir).is_ok())
            && host.hard_link(&source, &destination).is_ok()
        {
            mining_caches_linked += 1;
        }
    }

    let beacon_copied = carry_beacon(from, to)?;
    Ok(CarriedInputs {
        bank,
        mining_caches_linked,
        beacon_copied,
    })
}

fn carry_bank(
    from: &Path,
    to: &Path,
    old: &[ChunkEntry],
    new: &[ChunkEntry],
    allow_copy: bool,
    host: &dyn Host,
) -> Result<BankCarried, InputsError> {
    let find = |entries: &[ChunkEntry]| {
        entries
            .iter()
            .find(|entry| entry.name == BANK_NAME)
            .cloned()
    };
    let (Some(old_bank), Some(new_bank)) = (find(old), find(new)) else {
        return Err(InputsError::Chunks(format!("no {BANK_NAME} entry")));
    };
    if old_bank != new_bank {
        return Err(InputsError::BankChanged);
    }
    let source = from.join(PRODUCTION_V4).join(&old_bank.relative_path);
    let destination = to.join(PRODUCTION_V4).join(&new_bank.relative_path);
    match fs::symlink_metadata(&source) {
        Ok(meta) if meta.is_file() && meta.len() == old_bank.bytes => {}
        Ok(_) => return Err(InputsError::NoBank),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(InputsError::NoBank),
        Err(error) => return Err(io_error(&source, error)),
    }
    if let Some(dir) = destination.parent() {
        create_dir(dir)?;
    }
    if is_linkable(&source, old_bank.bytes) && host.hard_link(&source, &destination).is_ok() {
        return Ok(BankCarried::Linked);
    }
    if !allow_copy {
        return Err(InputsError::NeedsCopyConsent {
            bytes: old_bank.bytes,
        });
    }
    let needed = old_bank.bytes.saturating_add(SPACE_MARGIN_BYTES);
    if let Ok(available) = host.available_space(to)
        && available < needed
    {
        return Err(InputsError::NoSpace { needed, available });
    }
    copy_file(&source, &destination)?;
    Ok(BankCarried::Copied)
}

/// Copies the launch beacon, without overwriting, only when both packages
/// carry the same launch plan byte for byte.
fn carry_beacon(from: &Path, to: &Path) -> Result<bool, InputsError> {
    let (Ok(old_plan), Ok(new_plan)) = (
        read_small_file(&from.join(PLAN_PATH)),
        read_small_file(&to.join(PLAN_PATH)),
    ) else {
        return Ok(false);
    };
    if old_plan != new_plan {
        return Ok(false);
    }
    let Ok(beacon) = read_small_file(&from.join(BEACON_PATH)) else {
        return Ok(false);
    };
    let destination = to.join(BEACON_PATH);
    match new_file_options().create_new(true).open(&destination) {
        Ok(mut file) => {
            file.write_all(&beacon)
                .and_then(|()| file.sync_all())
                .map_err(|error| io_error(&destination, error))?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(io_error(&destination, error)),
    }
}

/// What [`adopt_mining_inputs`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Adoption {
    /// Mining cache files hard-linked in.
    pub(crate) linked: usize,
    /// The first source folder that holds a prepared cache the running
    /// version still misses but could not link in: a file in OneDrive, or
    /// one on another drive or a file system without hard links (exFAT,
    /// FAT32).
    pub(crate) unlinkable: Option<PathBuf>,
}

/// Hard-links each mining cache under `fixed/` the package of
/// `own_production_v4` lists but does not have yet from the first of
/// `sources` (package folders) that lists the same chunk entry and holds a
/// linkable file of that size (on Linux also this user's and not writable
/// by everyone). Files that exist are never replaced, and a cache is never
/// copied. Once every listed cache is present, a missing `fixed/` artifact
/// record is copied from the package's own record. Anything unusable is
/// skipped.
pub(crate) fn adopt_mining_inputs(
    own_production_v4: &Path,
    sources: &[PathBuf],
    host: &dyn Host,
) -> Adoption {
    let mut adoption = Adoption::default();
    let Some(own) = own_production_v4.parent() else {
        return adoption;
    };
    let Ok(listed) = read_chunks(own) else {
        return adoption;
    };
    let own_canonical = fs::canonicalize(own).ok();
    let sources: Vec<(PathBuf, Vec<ChunkEntry>)> = sources
        .iter()
        .filter(|source| fs::canonicalize(source).ok() != own_canonical)
        .filter_map(|source| Some((source.clone(), read_chunks(source).ok()?)))
        .collect();
    let mut complete = true;
    // Only the prepared caches, never a packaged file a future chunk list
    // might name, come from these unverified folders.
    let caches = listed.iter().filter(|entry| {
        entry.name != BANK_NAME && entry.relative_path.starts_with(&format!("{FIXED_DIR}/"))
    });
    for entry in caches {
        let destination = own_production_v4.join(&entry.relative_path);
        if fs::symlink_metadata(&destination).is_ok() {
            continue;
        }
        let mut unlinkable = None;
        let adopted = sources.iter().any(|(source, entries)| {
            let original = source.join(PRODUCTION_V4).join(&entry.relative_path);
            let prepared = entries.contains(entry)
                && fs::symlink_metadata(&original).is_ok_and(|meta| {
                    meta.is_file()
                        && meta.len() == entry.bytes
                        && install::is_owned_privately(&meta, 0o002)
                });
            if !prepared {
                return false;
            }
            let linked = is_linkable(&original, entry.bytes)
                && destination
                    .parent()
                    .is_some_and(|dir| create_dir(dir).is_ok())
                && host.hard_link(&original, &destination).is_ok()
                && is_plain_link(&destination);
            if !linked {
                unlinkable.get_or_insert_with(|| source.clone());
            }
            linked
        });
        if adopted {
            adoption.linked += 1;
        } else {
            complete = false;
            adoption.unlinkable = adoption.unlinkable.or(unlinkable);
        }
    }
    let record = own_production_v4.join(FIXED_DIR).join(FIXED_RECORD_NAME);
    if complete && fs::symlink_metadata(&record).is_err() {
        let _ = copy_file(&own.join(FIXED_RECORD_NAME), &record);
    }
    adoption
}

/// The package folders [`adopt_mining_inputs`] may link caches from, for the
/// running package `own`: the anchor (the folder of the exe the user
/// launched, `launched_from`), when it is a real folder, then every version
/// folder beside `own` or beside the anchor that passes
/// [`install::is_registered_install`] (the 2.8 ownership checks, the release
/// signature and this user's install `registry`), highest version first.
/// Without a registry only the anchor is used.
pub(crate) fn mining_input_sources(
    own: &Path,
    launched_from: Option<&Path>,
    platform: Platform,
    registry: Option<&Path>,
) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    let anchor = launched_from.and_then(Path::parent);
    if let Some(anchor) = anchor
        && install::is_real_dir(anchor)
    {
        sources.push(anchor.to_path_buf());
    }
    let Some(registry) = registry else {
        return sources;
    };
    let prefix = format!("commonfoundry-mainnet-runtime-{}-v", platform.name());
    let mut roots: Vec<PathBuf> = Vec::new();
    for root in [own.parent(), anchor.and_then(Path::parent)]
        .into_iter()
        .flatten()
    {
        let canonical = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        if !roots.contains(&canonical) {
            roots.push(canonical);
        }
    }
    let mut found = Vec::new();
    for root in &roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix))
            {
                continue;
            }
            let path = entry.path();
            if let Some(version) = install::folder_version(&path, platform) {
                found.push((version, path));
            }
        }
    }
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    found.truncate(MAX_SOURCE_FOLDERS);
    sources.extend(
        found
            .into_iter()
            .map(|(_, path)| path)
            .filter(|path| install::is_registered_install(path, platform, registry)),
    );
    sources
}

/// The new link is a regular file. A link made to a file that was swapped
/// for a symlink after the check (Linux then links the symlink itself) is
/// taken back.
fn is_plain_link(link: &Path) -> bool {
    if fs::symlink_metadata(link).is_ok_and(|meta| meta.is_file()) {
        return true;
    }
    let _ = fs::remove_file(link);
    false
}

/// A regular file of exactly `bytes` that is not a cloud placeholder, so a
/// hard link to it is a complete local copy.
fn is_linkable(path: &Path, bytes: u64) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.is_file() && meta.len() == bytes && !is_cloud_placeholder(&meta),
        Err(_) => false,
    }
}

/// A file a sync engine (OneDrive) manages: not fully on disk, or one it
/// may dehydrate later. Its files in a sync root are reparse points even
/// when fully downloaded, and pinned or unpinned ones carry those flags. A
/// link to one could later turn into a placeholder, so it is copied with
/// consent instead.
#[cfg(windows)]
pub(crate) fn is_cloud_placeholder(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    is_cloud_managed(meta.file_attributes())
}

#[cfg(windows)]
fn is_cloud_managed(attributes: u32) -> bool {
    const REPARSE_POINT: u32 = 0x400;
    const OFFLINE: u32 = 0x1000;
    const RECALL_ON_OPEN: u32 = 0x4_0000;
    const PINNED: u32 = 0x8_0000;
    const UNPINNED: u32 = 0x10_0000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;
    attributes
        & (REPARSE_POINT | OFFLINE | RECALL_ON_OPEN | PINNED | UNPINNED | RECALL_ON_DATA_ACCESS)
        != 0
}

#[cfg(not(windows))]
pub(crate) fn is_cloud_placeholder(_meta: &fs::Metadata) -> bool {
    false
}

/// Creates `path` and its missing parents, on Linux as 0755 whatever the
/// umask, like the package's own folders (install refuses group- or
/// world-writable ones there).
fn create_dir(path: &Path) -> Result<(), InputsError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o755);
    builder.create(path).map_err(|error| io_error(path, error))
}

/// Options for a file written into the new package: on Linux 0644
/// whatever the umask.
fn new_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o644);
    options
}

/// Copies through a temporary sibling, so a cancelled or failed copy never
/// leaves a short file under the real name. Never overwrites.
fn copy_file(source: &Path, destination: &Path) -> Result<(), InputsError> {
    if fs::symlink_metadata(destination).is_ok() {
        return Err(io_error(
            destination,
            io::Error::from(io::ErrorKind::AlreadyExists),
        ));
    }
    let mut temporary = destination.as_os_str().to_owned();
    temporary.push(COPY_SUFFIX);
    let temporary = Path::new(&temporary);
    let result = (|| {
        let mut input = File::open(source)?;
        let mut output = new_file_options()
            .create(true)
            .truncate(true)
            .open(temporary)?;
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        drop(output);
        fs::rename(temporary, destination)
    })();
    result.map_err(|error| {
        let _ = fs::remove_file(temporary);
        io_error(destination, error)
    })
}

/// Reads a regular file of at most 1 MiB, without following a link.
pub(crate) fn read_small_file(path: &Path) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    if meta.len() > MAX_SMALL_FILE_BYTES {
        return Err(io::Error::other("too large"));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_SMALL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SMALL_FILE_BYTES {
        return Err(io::Error::other("too large"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::install::tests::TempDir;
    use super::*;
    use std::cell::Cell;
    use std::path::PathBuf;

    const BANK: &[u8] = b"bank bytes";
    const CODEWORD: &[u8] = b"codeword";
    const TREE: &[u8] = b"tree!";

    fn chunks(bank: &[u8]) -> String {
        let entry = |name: &str, path: &str, bytes: &[u8]| {
            serde_json::json!({
                "name": name,
                "relative_path": path,
                "roles": ["node"],
                "bytes": bytes.len(),
                "sha256": hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes)),
                "parts": 1,
            })
        };
        serde_json::json!({
            "schema_version": 1,
            "files": [
                entry(BANK_NAME, BANK_NAME, bank),
                entry("CODEWORD", "fixed/CODEWORD", CODEWORD),
                entry("TREE", "fixed/TREE", TREE),
            ],
        })
        .to_string()
    }

    /// A package folder with its chunk list, fixed record and launch plan.
    fn package(root: &Path, name: &str, bank: &[u8], plan: &[u8]) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("production-mainnet")).unwrap();
        fs::write(dir.join(CHUNKS_NAME), chunks(bank)).unwrap();
        fs::write(dir.join(FIXED_RECORD_NAME), format!("record of {name}")).unwrap();
        fs::write(dir.join(PLAN_PATH), plan).unwrap();
        dir
    }

    /// The running package, with its bank, caches and beacon prepared.
    fn prepared(root: &Path) -> PathBuf {
        let dir = package(root, "old", BANK, b"plan");
        let inputs = dir.join(PRODUCTION_V4);
        fs::create_dir_all(inputs.join("fixed")).unwrap();
        fs::write(inputs.join(BANK_NAME), BANK).unwrap();
        fs::write(inputs.join("fixed/CODEWORD"), CODEWORD).unwrap();
        fs::write(inputs.join("fixed/TREE"), TREE).unwrap();
        fs::write(inputs.join(FIXED_RECORD_NAME), "old record").unwrap();
        fs::write(dir.join(BEACON_PATH), "beacon").unwrap();
        dir
    }

    struct RealLinks;
    impl Host for RealLinks {}

    /// Hard links always fail, as on another volume or exFAT.
    #[derive(Default)]
    struct NoLinks {
        free: Option<u64>,
        links_tried: Cell<usize>,
    }

    impl Host for NoLinks {
        fn hard_link(&self, _original: &Path, _link: &Path) -> io::Result<()> {
            self.links_tried.set(self.links_tried.get() + 1);
            Err(io::Error::other("cross-device link"))
        }

        fn available_space(&self, _dir: &Path) -> io::Result<u64> {
            self.free.ok_or_else(|| io::Error::other("unknown"))
        }
    }

    #[test]
    fn the_bank_and_caches_are_hard_linked_and_the_record_comes_from_the_new_package() {
        let temp = TempDir::new();
        let old = prepared(&temp.0);
        let new = package(&temp.0, "new", BANK, b"plan");

        let carried = carry_over(&old, &new, false, &RealLinks).unwrap();
        assert_eq!(
            carried,
            CarriedInputs {
                bank: BankCarried::Linked,
                mining_caches_linked: 2,
                beacon_copied: true,
            }
        );
        let inputs = new.join(PRODUCTION_V4);
        assert_eq!(fs::read(inputs.join(BANK_NAME)).unwrap(), BANK);
        assert_eq!(fs::read(inputs.join("fixed/TREE")).unwrap(), TREE);
        assert_eq!(
            fs::read(inputs.join(FIXED_RECORD_NAME)).unwrap(),
            b"record of new"
        );
        assert_eq!(fs::read(new.join(BEACON_PATH)).unwrap(), b"beacon");
        assert!(same_file(
            &old.join(PRODUCTION_V4).join(BANK_NAME),
            &inputs.join(BANK_NAME)
        ));
        assert!(same_file(
            &old.join(PRODUCTION_V4).join("fixed/CODEWORD"),
            &inputs.join("fixed/CODEWORD")
        ));
    }

    #[cfg(unix)]
    fn same_file(a: &Path, b: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let (a, b) = (fs::metadata(a).unwrap(), fs::metadata(b).unwrap());
        a.dev() == b.dev() && a.ino() == b.ino() && a.nlink() == 2
    }

    /// Windows has no stable inode in std; a write through one name shows
    /// through the other only for a hard link.
    #[cfg(windows)]
    fn same_file(a: &Path, b: &Path) -> bool {
        let before = fs::read(b).unwrap();
        let mut marked = before.clone();
        marked.push(b'!');
        fs::write(a, &marked).unwrap();
        let linked = fs::read(b).unwrap() == marked;
        fs::write(a, &before).unwrap();
        linked
    }

    #[test]
    fn a_bank_that_cannot_be_linked_is_copied_only_with_consent() {
        let temp = TempDir::new();
        let old = prepared(&temp.0);
        let new = package(&temp.0, "new", BANK, b"plan");
        let host = NoLinks::default();

        assert_eq!(
            carry_over(&old, &new, false, &host),
            Err(InputsError::NeedsCopyConsent {
                bytes: BANK.len() as u64
            })
        );
        assert!(!new.join(PRODUCTION_V4).join(BANK_NAME).exists());

        let carried = carry_over(&old, &new, true, &host).unwrap();
        assert_eq!(carried.bank, BankCarried::Copied);
        // Mining caches are never copied.
        assert_eq!(carried.mining_caches_linked, 0);
        assert!(!new.join(PRODUCTION_V4).join("fixed/CODEWORD").exists());
        assert_eq!(
            fs::read(new.join(PRODUCTION_V4).join(BANK_NAME)).unwrap(),
            BANK
        );
        let leftovers: Vec<_> = fs::read_dir(new.join(PRODUCTION_V4))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(COPY_SUFFIX))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn an_agreed_copy_needs_room_for_the_bank() {
        let temp = TempDir::new();
        let old = prepared(&temp.0);
        let new = package(&temp.0, "new", BANK, b"plan");
        let host = NoLinks {
            free: Some(SPACE_MARGIN_BYTES),
            ..NoLinks::default()
        };
        assert_eq!(
            carry_over(&old, &new, true, &host),
            Err(InputsError::NoSpace {
                needed: BANK.len() as u64 + SPACE_MARGIN_BYTES,
                available: SPACE_MARGIN_BYTES,
            })
        );
        assert!(!new.join(PRODUCTION_V4).join(BANK_NAME).exists());
    }

    #[test]
    fn a_different_bank_entry_means_a_manual_install() {
        let temp = TempDir::new();
        let old = prepared(&temp.0);
        let new = package(&temp.0, "new", b"another bank", b"plan");
        let host = NoLinks::default();
        assert_eq!(
            carry_over(&old, &new, true, &host),
            Err(InputsError::BankChanged)
        );
        assert_eq!(host.links_tried.get(), 0);
    }

    #[test]
    fn a_missing_or_short_bank_is_not_carried() {
        let temp = TempDir::new();
        let old = prepared(&temp.0);
        let new = package(&temp.0, "new", BANK, b"plan");
        let bank = old.join(PRODUCTION_V4).join(BANK_NAME);
        fs::write(&bank, b"bank").unwrap();
        assert_eq!(
            carry_over(&old, &new, true, &RealLinks),
            Err(InputsError::NoBank)
        );
        fs::remove_file(&bank).unwrap();
        assert_eq!(
            carry_over(&old, &new, true, &RealLinks),
            Err(InputsError::NoBank)
        );
    }

    #[test]
    fn a_cache_of_the_wrong_size_or_listed_differently_is_not_linked() {
        let temp = TempDir::new();
        let old = prepared(&temp.0);
        fs::write(old.join(PRODUCTION_V4).join("fixed/TREE"), b"tree").unwrap();
        let new = package(&temp.0, "new", BANK, b"plan");
        let mut listed: serde_json::Value =
            serde_json::from_slice(&fs::read(new.join(CHUNKS_NAME)).unwrap()).unwrap();
        listed["files"][1]["sha256"] = "00".repeat(32).into();
        fs::write(new.join(CHUNKS_NAME), listed.to_string()).unwrap();

        let carried = carry_over(&old, &new, false, &RealLinks).unwrap();
        assert_eq!(carried.mining_caches_linked, 0);
        assert!(!new.join(PRODUCTION_V4).join("fixed/CODEWORD").exists());
        assert!(!new.join(PRODUCTION_V4).join("fixed/TREE").exists());
    }

    #[test]
    fn the_beacon_is_copied_only_for_a_byte_identical_plan_and_never_overwritten() {
        let temp = TempDir::new();
        let old = prepared(&temp.0);

        let changed = package(&temp.0, "changed", BANK, b"plan ");
        assert!(
            !carry_over(&old, &changed, false, &RealLinks)
                .unwrap()
                .beacon_copied
        );
        assert!(!changed.join(BEACON_PATH).exists());

        let same = package(&temp.0, "same", BANK, b"plan");
        fs::write(same.join(BEACON_PATH), "newer beacon").unwrap();
        assert!(
            !carry_over(&old, &same, false, &RealLinks)
                .unwrap()
                .beacon_copied
        );
        assert_eq!(fs::read(same.join(BEACON_PATH)).unwrap(), b"newer beacon");

        let no_beacon = package(&temp.0, "no-beacon", BANK, b"plan");
        fs::remove_file(old.join(BEACON_PATH)).unwrap();
        assert!(
            !carry_over(&old, &no_beacon, false, &RealLinks)
                .unwrap()
                .beacon_copied
        );
    }

    #[cfg(windows)]
    #[test]
    fn files_a_sync_engine_manages_are_never_linked() {
        // Hydrated in a sync root, pinned, unpinned, or not on disk.
        for attributes in [0x400, 0x8_0000, 0x10_0000, 0x1000, 0x4_0000, 0x40_0000] {
            assert!(is_cloud_managed(attributes | 0x20), "{attributes:#x}");
        }
        // Archive and read-only are plain local files.
        assert!(!is_cloud_managed(0x20 | 0x1));
    }

    #[test]
    fn a_chunk_path_outside_the_inputs_dir_is_refused() {
        let temp = TempDir::new();
        let old = prepared(&temp.0);
        let new = package(&temp.0, "new", BANK, b"plan");
        let mut listed: serde_json::Value =
            serde_json::from_slice(&fs::read(new.join(CHUNKS_NAME)).unwrap()).unwrap();
        listed["files"][2]["relative_path"] = "../TREE".into();
        fs::write(new.join(CHUNKS_NAME), listed.to_string()).unwrap();
        assert!(matches!(
            carry_over(&old, &new, false, &RealLinks),
            Err(InputsError::Chunks(_))
        ));
    }

    /// The running version, installed without caches, beside the anchor
    /// the user prepares mining in afterwards.
    fn running(root: &Path) -> PathBuf {
        let dir = package(root, "new", BANK, b"plan");
        fs::create_dir_all(dir.join(PRODUCTION_V4)).unwrap();
        dir
    }

    #[test]
    fn caches_prepared_in_the_anchor_after_the_update_are_linked_in() {
        let temp = TempDir::new();
        let anchor = prepared(&temp.0);
        let own = running(&temp.0);
        let inputs = own.join(PRODUCTION_V4);

        assert_eq!(
            adopt_mining_inputs(&inputs, std::slice::from_ref(&anchor), &RealLinks).linked,
            2
        );
        assert_eq!(fs::read(inputs.join("fixed/CODEWORD")).unwrap(), CODEWORD);
        assert_eq!(fs::read(inputs.join("fixed/TREE")).unwrap(), TREE);
        assert!(same_file(
            &anchor.join(PRODUCTION_V4).join("fixed/TREE"),
            &inputs.join("fixed/TREE")
        ));
        // The record comes from the running package, never from the anchor.
        assert_eq!(
            fs::read(inputs.join(FIXED_DIR).join(FIXED_RECORD_NAME)).unwrap(),
            b"record of new"
        );
        // The bank is carried at install, not here.
        assert!(!inputs.join(BANK_NAME).exists());

        // Nothing left to adopt.
        assert_eq!(
            adopt_mining_inputs(&inputs, &[anchor], &RealLinks).linked,
            0
        );
    }

    #[test]
    fn files_already_there_are_kept_and_the_record_waits_for_every_cache() {
        let temp = TempDir::new();
        let anchor = prepared(&temp.0);
        fs::remove_file(anchor.join(PRODUCTION_V4).join("fixed/TREE")).unwrap();
        let own = running(&temp.0);
        let inputs = own.join(PRODUCTION_V4);
        fs::create_dir_all(inputs.join("fixed")).unwrap();
        fs::write(inputs.join("fixed/CODEWORD"), b"own codeword").unwrap();

        assert_eq!(
            adopt_mining_inputs(&inputs, std::slice::from_ref(&anchor), &RealLinks).linked,
            0
        );
        assert_eq!(
            fs::read(inputs.join("fixed/CODEWORD")).unwrap(),
            b"own codeword"
        );
        assert!(!inputs.join("fixed/TREE").exists());
        assert!(!inputs.join(FIXED_DIR).join(FIXED_RECORD_NAME).exists());

        // A later source supplies the missing one.
        let other = package(&temp.0, "other", BANK, b"plan");
        fs::create_dir_all(other.join(PRODUCTION_V4).join("fixed")).unwrap();
        fs::write(other.join(PRODUCTION_V4).join("fixed/TREE"), TREE).unwrap();
        assert_eq!(
            adopt_mining_inputs(&inputs, &[anchor, other], &RealLinks).linked,
            1
        );
        assert_eq!(fs::read(inputs.join("fixed/TREE")).unwrap(), TREE);
        assert!(inputs.join(FIXED_DIR).join(FIXED_RECORD_NAME).is_file());
    }

    #[test]
    fn a_cache_of_another_size_or_entry_is_not_adopted() {
        let temp = TempDir::new();
        let anchor = prepared(&temp.0);
        fs::write(anchor.join(PRODUCTION_V4).join("fixed/TREE"), b"tree").unwrap();
        let own = running(&temp.0);
        let mut listed: serde_json::Value =
            serde_json::from_slice(&fs::read(own.join(CHUNKS_NAME)).unwrap()).unwrap();
        listed["files"][1]["sha256"] = "00".repeat(32).into();
        fs::write(own.join(CHUNKS_NAME), listed.to_string()).unwrap();
        let inputs = own.join(PRODUCTION_V4);

        // Files that are not the prepared ones are not reported as unlinkable.
        assert_eq!(
            adopt_mining_inputs(&inputs, &[anchor], &RealLinks),
            Adoption::default()
        );
        assert!(!inputs.join("fixed/CODEWORD").exists());
        assert!(!inputs.join("fixed/TREE").exists());
        assert!(!inputs.join(FIXED_DIR).join(FIXED_RECORD_NAME).exists());
    }

    #[test]
    fn only_entries_under_fixed_are_adopted() {
        let temp = TempDir::new();
        let anchor = prepared(&temp.0);
        let own = running(&temp.0);
        // Both lists name a packaged binary as a chunk, and the anchor has it.
        for package in [&anchor, &own] {
            let mut listed: serde_json::Value =
                serde_json::from_slice(&fs::read(package.join(CHUNKS_NAME)).unwrap()).unwrap();
            let mut binary = listed["files"][1].clone();
            binary["name"] = "REPLAY".into();
            binary["relative_path"] = "cmfd-v4-replay".into();
            listed["files"].as_array_mut().unwrap().push(binary);
            fs::write(package.join(CHUNKS_NAME), listed.to_string()).unwrap();
        }
        fs::write(anchor.join(PRODUCTION_V4).join("cmfd-v4-replay"), CODEWORD).unwrap();
        let inputs = own.join(PRODUCTION_V4);

        assert_eq!(
            adopt_mining_inputs(&inputs, &[anchor], &RealLinks).linked,
            2
        );
        assert!(!inputs.join("cmfd-v4-replay").exists());
        assert!(inputs.join(FIXED_DIR).join(FIXED_RECORD_NAME).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn a_cache_anyone_can_write_or_swapped_for_a_symlink_is_not_adopted() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new();
        let anchor = prepared(&temp.0);
        let tree = anchor.join(PRODUCTION_V4).join("fixed/TREE");
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o666)).unwrap();
        let own = running(&temp.0);
        let inputs = own.join(PRODUCTION_V4);

        assert_eq!(
            adopt_mining_inputs(&inputs, std::slice::from_ref(&anchor), &RealLinks).linked,
            1
        );
        assert!(inputs.join("fixed/CODEWORD").is_file());
        assert!(!inputs.join("fixed/TREE").exists());

        /// Links a symlink, as Linux does when the file was swapped for one.
        struct SymlinkSwap;
        impl Host for SymlinkSwap {
            fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
                std::os::unix::fs::symlink(original, link)
            }
        }
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            adopt_mining_inputs(&inputs, std::slice::from_ref(&anchor), &SymlinkSwap),
            Adoption {
                linked: 0,
                unlinkable: Some(anchor)
            }
        );
        assert!(fs::symlink_metadata(inputs.join("fixed/TREE")).is_err());
    }

    #[test]
    fn a_cache_that_cannot_be_linked_is_never_copied() {
        let temp = TempDir::new();
        let anchor = prepared(&temp.0);
        let own = running(&temp.0);
        let inputs = own.join(PRODUCTION_V4);
        let host = NoLinks::default();

        let adoption = adopt_mining_inputs(&inputs, std::slice::from_ref(&anchor), &host);
        assert_eq!(
            adoption,
            Adoption {
                linked: 0,
                unlinkable: Some(anchor)
            }
        );
        assert_eq!(host.links_tried.get(), 2);
        assert!(!inputs.join("fixed/CODEWORD").exists());
        assert!(!inputs.join("fixed/TREE").exists());
    }

    #[test]
    fn the_running_package_and_unusable_sources_are_skipped() {
        let temp = TempDir::new();
        let own = running(&temp.0);
        let inputs = own.join(PRODUCTION_V4);
        // Its own files, under another spelling, are not a source.
        fs::create_dir_all(inputs.join("fixed")).unwrap();
        fs::write(inputs.join("fixed/CODEWORD.partial"), CODEWORD).unwrap();
        let host = NoLinks::default();
        let missing = temp.0.join("missing");
        let no_list = temp.0.join("no-list");
        fs::create_dir_all(no_list.join(PRODUCTION_V4).join("fixed")).unwrap();
        fs::write(no_list.join(PRODUCTION_V4).join("fixed/CODEWORD"), CODEWORD).unwrap();

        assert_eq!(
            adopt_mining_inputs(&inputs, &[own.join("."), missing, no_list], &host).linked,
            0
        );
        assert_eq!(host.links_tried.get(), 0);
        // A folder without a chunk list adopts nothing.
        assert_eq!(
            adopt_mining_inputs(&temp.0.join("nowhere").join(PRODUCTION_V4), &[], &host).linked,
            0
        );
    }

    #[test]
    fn sources_are_the_anchor_then_registered_versions_highest_first() {
        use super::super::forward::tests::{installed, registry_of};
        let temp = TempDir::new();
        let root = temp.0.join("root");
        fs::create_dir_all(&root).unwrap();
        let platform = Platform::current().unwrap();
        let anchor = root.join("CommonFoundry");
        fs::create_dir_all(&anchor).unwrap();
        let exe = anchor.join("common-foundry-wallet.exe");
        let v13 = installed(&root, 13);
        let v14 = installed(&root, 14);
        let own = installed(&root, 15);
        // A folder of the right name the updater did not install.
        let foreign = root.join(install::package_name(
            platform,
            release::Version::new(1, 0, 12),
        ));
        fs::create_dir_all(&foreign).unwrap();
        let registry = registry_of(&root);

        let sources = mining_input_sources(&own, Some(&exe), platform, Some(&registry));
        let canonical = |paths: &[PathBuf]| -> Vec<PathBuf> {
            paths
                .iter()
                .map(|path| fs::canonicalize(path).unwrap())
                .collect()
        };
        // The running version is listed too; adoption skips it.
        assert_eq!(
            canonical(&sources),
            canonical(&[anchor.clone(), own.clone(), v14, v13])
        );

        // Without a registry only the anchor is used, and a forwarder's
        // anchor that is not a folder is not.
        assert_eq!(
            mining_input_sources(&own, Some(&exe), platform, None),
            vec![anchor]
        );
        assert!(
            mining_input_sources(&own, Some(&root.join("gone").join("x.exe")), platform, None)
                .is_empty()
        );
        assert_eq!(
            canonical(&mining_input_sources(&own, None, platform, Some(&registry))).len(),
            3
        );
    }

    #[test]
    fn a_signed_version_this_registry_does_not_list_is_no_source() {
        use super::super::forward::tests::{installed, registry_of};
        let temp = TempDir::new();
        let root = temp.0.join("root");
        fs::create_dir_all(&root).unwrap();
        let platform = Platform::current().unwrap();
        let registry = registry_of(&root);
        let v14 = installed(&root, 14);
        // Its marker and signature are fine; only the registry decides.
        assert!(install::is_registered_install(&v14, platform, &registry));
        for entry in fs::read_dir(&registry).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        assert!(!install::is_registered_install(&v14, platform, &registry));
        let own = installed(&root, 15);

        let sources = mining_input_sources(&own, None, platform, Some(&registry));
        assert_eq!(
            sources
                .iter()
                .map(|path| fs::canonicalize(path).unwrap())
                .collect::<Vec<_>>(),
            vec![fs::canonicalize(&own).unwrap()]
        );
    }
}
