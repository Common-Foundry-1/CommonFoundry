//! Shared trusted filesystem boundary for production Dory V3 ceremony artifacts.
//!
//! Every artifact is a direct child of an absolute, private directory. The
//! directory and file identities are retained across long scans. Inputs deny
//! concurrent write/delete access on Windows; outputs are create-new, private,
//! exclusive while open, and removed only after their identity is rechecked.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    volume_or_device: u64,
    file_index_or_inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParentSyncOutcome {
    Synced,
    #[cfg(windows)]
    WindowsAccessDenied,
    #[cfg(windows)]
    WindowsUnsupported,
    #[cfg(not(any(unix, windows)))]
    PlatformUnsupported,
}

#[derive(Debug, Error)]
pub(crate) enum CeremonyFsError {
    #[error("artifact path must be an absolute normalized direct child path: {0}")]
    InvalidArtifactPath(PathBuf),
    #[error("artifact parent is not a trusted private directory: {0}")]
    UnsafeParent(PathBuf),
    #[error("failed to inspect trusted parent {path}: {source}")]
    InspectParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("trusted parent path was replaced or its security policy changed: {0}")]
    ParentIdentity(PathBuf),
    #[error("failed to open input {path}: {source}")]
    OpenInput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("input is not a regular file: {0}")]
    InputNotRegular(PathBuf),
    #[error("input is a symbolic link or reparse point: {0}")]
    InputReparsePoint(PathBuf),
    #[error("input has an unexpected hard-link count of {links}: {path}")]
    InputHardLinks { path: PathBuf, links: u64 },
    #[error("input length mismatch: expected {expected} bytes, found {actual}")]
    InputLength { expected: u64, actual: u64 },
    #[error("input path was replaced or no longer names the retained file: {0}")]
    InputIdentity(PathBuf),
    #[error("refusing to overwrite existing output: {0}")]
    OutputExists(PathBuf),
    #[error("failed to create output {path}: {source}")]
    CreateOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set private output permissions on {path}: {source}")]
    SetOutputPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write or synchronize output {path}: {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to reopen or inspect output {path}: {source}")]
    ReopenOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("output is not a regular file: {0}")]
    OutputNotRegular(PathBuf),
    #[error("output is a symbolic link or reparse point: {0}")]
    OutputReparsePoint(PathBuf),
    #[error("output has an unexpected hard-link count of {links}: {path}")]
    OutputHardLinks { path: PathBuf, links: u64 },
    #[error("output path was replaced or no longer names the create-new file: {0}")]
    OutputIdentity(PathBuf),
    #[error("reopened output differs from the bytes that were written")]
    ReopenedOutputMismatch,
    #[error("failed to synchronize output parent {path}: {source}")]
    SyncParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to remove unconfirmed output {path}: {source}")]
    CleanupOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "unconfirmed output remains quarantined at {path}; original failure: {original}; cleanup failure: {cleanup}"
    )]
    QuarantinedOutput {
        path: PathBuf,
        original: String,
        cleanup: String,
    },
}

pub(crate) struct TrustedCeremonyParent {
    path: PathBuf,
    handle: File,
    identity: FileIdentity,
}

impl TrustedCeremonyParent {
    pub(crate) fn for_artifact(path: &Path) -> Result<Self, CeremonyFsError> {
        validate_absolute_artifact_path(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| CeremonyFsError::InvalidArtifactPath(path.to_path_buf()))?;
        Self::open(parent)
    }

    fn open(path: &Path) -> Result<Self, CeremonyFsError> {
        validate_absolute_directory_path(path)?;
        validate_ancestor_chain(path)?;
        let handle =
            open_parent_no_follow(path).map_err(|source| CeremonyFsError::InspectParent {
                path: path.to_path_buf(),
                source,
            })?;
        validate_parent_handle(path, &handle)?;
        let identity = file_identity(&handle).map_err(|source| CeremonyFsError::InspectParent {
            path: path.to_path_buf(),
            source,
        })?;
        let parent = Self {
            path: path.to_path_buf(),
            handle,
            identity,
        };
        parent.recheck()?;
        Ok(parent)
    }

    pub(crate) fn validate_child(&self, path: &Path) -> Result<(), CeremonyFsError> {
        validate_absolute_artifact_path(path)?;
        if path.parent() != Some(self.path.as_path()) {
            return Err(CeremonyFsError::InvalidArtifactPath(path.to_path_buf()));
        }
        Ok(())
    }

    pub(crate) fn preflight_output(&self, path: &Path) -> Result<(), CeremonyFsError> {
        self.validate_child(path)?;
        self.recheck()?;
        finish_with_parent_recheck(reject_existing_output(path), self)
    }

    pub(crate) fn recheck(&self) -> Result<(), CeremonyFsError> {
        validate_absolute_directory_path(&self.path)?;
        validate_ancestor_chain(&self.path)?;
        validate_parent_handle(&self.path, &self.handle)?;
        if file_identity(&self.handle).map_err(|source| CeremonyFsError::InspectParent {
            path: self.path.clone(),
            source,
        })? != self.identity
        {
            return Err(CeremonyFsError::ParentIdentity(self.path.clone()));
        }
        let named =
            open_parent_no_follow(&self.path).map_err(|source| CeremonyFsError::InspectParent {
                path: self.path.clone(),
                source,
            })?;
        validate_parent_handle(&self.path, &named)?;
        if file_identity(&named).map_err(|source| CeremonyFsError::InspectParent {
            path: self.path.clone(),
            source,
        })? != self.identity
        {
            return Err(CeremonyFsError::ParentIdentity(self.path.clone()));
        }
        Ok(())
    }

    pub(crate) fn sync(&self) -> Result<ParentSyncOutcome, CeremonyFsError> {
        self.recheck()?;
        let result = self.handle.sync_all();
        finish_with_parent_recheck(classify_parent_sync(&self.path, result), self)
    }
}

pub(crate) struct AuthenticatedInput {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
}

impl AuthenticatedInput {
    pub(crate) fn open(
        parent: &TrustedCeremonyParent,
        path: &Path,
        expected_bytes: Option<u64>,
    ) -> Result<Self, CeremonyFsError> {
        parent.validate_child(path)?;
        parent.recheck()?;
        let opened = (|| {
            let path_metadata =
                fs::symlink_metadata(path).map_err(|source| CeremonyFsError::OpenInput {
                    path: path.to_path_buf(),
                    source,
                })?;
            if metadata_is_reparse_point(&path_metadata) {
                return Err(CeremonyFsError::InputReparsePoint(path.to_path_buf()));
            }
            let file = open_input_no_follow(path).map_err(|source| CeremonyFsError::OpenInput {
                path: path.to_path_buf(),
                source,
            })?;
            let identity = validate_input_handle(path, &file, expected_bytes)?;
            Ok(Self {
                path: path.to_path_buf(),
                file,
                identity,
            })
        })();
        let input = finish_with_parent_recheck(opened, parent)?;
        input.recheck(parent, expected_bytes)?;
        Ok(input)
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn read_bounded(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, CeremonyFsError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|source| CeremonyFsError::OpenInput {
                path: self.path.clone(),
                source,
            })?;
        let mut bytes = Vec::with_capacity(maximum_bytes.saturating_add(1));
        (&mut self.file)
            .take(
                u64::try_from(maximum_bytes)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .map_err(|source| CeremonyFsError::OpenInput {
                path: self.path.clone(),
                source,
            })?;
        Ok(bytes)
    }

    pub(crate) fn recheck(
        &self,
        parent: &TrustedCeremonyParent,
        expected_bytes: Option<u64>,
    ) -> Result<(), CeremonyFsError> {
        parent.validate_child(&self.path)?;
        parent.recheck()?;
        let checked = (|| {
            if validate_input_handle(&self.path, &self.file, expected_bytes)? != self.identity {
                return Err(CeremonyFsError::InputIdentity(self.path.clone()));
            }
            let named =
                open_input_no_follow(&self.path).map_err(|source| CeremonyFsError::OpenInput {
                    path: self.path.clone(),
                    source,
                })?;
            if validate_input_handle(&self.path, &named, expected_bytes)? != self.identity {
                return Err(CeremonyFsError::InputIdentity(self.path.clone()));
            }
            Ok(())
        })();
        finish_with_parent_recheck(checked, parent)
    }
}

pub(crate) struct PendingOutput {
    path: PathBuf,
    parent_path: PathBuf,
    parent_identity: FileIdentity,
    parent_handle: File,
    identity: FileIdentity,
    writer: Option<File>,
    finished: bool,
    removed: bool,
}

impl PendingOutput {
    pub(crate) fn create(
        parent: &TrustedCeremonyParent,
        path: &Path,
    ) -> Result<Self, CeremonyFsError> {
        parent.preflight_output(path)?;
        let parent_handle = finish_with_parent_recheck(
            parent
                .handle
                .try_clone()
                .map_err(|source| CeremonyFsError::InspectParent {
                    path: parent.path.clone(),
                    source,
                }),
            parent,
        )?;
        let file = match create_new_output(path) {
            Ok(file) => file,
            Err(error) => return finish_with_parent_recheck(Err(error), parent),
        };
        let identity = match file_identity(&file).map_err(|source| CeremonyFsError::ReopenOutput {
            path: path.to_path_buf(),
            source,
        }) {
            Ok(identity) => identity,
            Err(original) => {
                let original = parent.recheck().err().unwrap_or(original);
                let cleanup = remove_unidentified_output(&file, path);
                drop(file);
                return match cleanup {
                    Ok(()) => Err(original),
                    Err(cleanup) => Err(CeremonyFsError::QuarantinedOutput {
                        path: path.to_path_buf(),
                        original: original.to_string(),
                        cleanup: cleanup.to_string(),
                    }),
                };
            }
        };
        let mut output = Self {
            path: path.to_path_buf(),
            parent_path: parent.path.clone(),
            parent_identity: parent.identity,
            parent_handle,
            identity,
            writer: Some(file),
            finished: false,
            removed: false,
        };
        if let Err(original) = parent.recheck() {
            return Err(output.cleanup_or_quarantine(parent, original));
        }
        match validate_output_handle(path, output.writer.as_ref().expect("writer is retained")) {
            Ok(actual) if actual == output.identity => {}
            Ok(_) => {
                let original = CeremonyFsError::OutputIdentity(path.to_path_buf());
                return Err(output.cleanup_or_quarantine(parent, original));
            }
            Err(original) => return Err(output.cleanup_or_quarantine(parent, original)),
        }
        if let Err(source) = make_output_private(
            output
                .writer
                .as_ref()
                .expect("a newly created pending output retains its writer"),
        ) {
            let original = CeremonyFsError::SetOutputPermissions {
                path: path.to_path_buf(),
                source,
            };
            return Err(output.cleanup_or_quarantine(parent, original));
        }
        if let Err(original) = output.recheck(parent) {
            return Err(output.cleanup_or_quarantine(parent, original));
        }
        Ok(output)
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<(), CeremonyFsError> {
        self.writer
            .as_mut()
            .ok_or_else(|| CeremonyFsError::OutputIdentity(self.path.clone()))?
            .write_all(bytes)
            .map_err(|source| CeremonyFsError::WriteOutput {
                path: self.path.clone(),
                source,
            })
    }

    pub(crate) fn sync_file(&self) -> Result<(), CeremonyFsError> {
        self.writer
            .as_ref()
            .ok_or_else(|| CeremonyFsError::OutputIdentity(self.path.clone()))?
            .sync_all()
            .map_err(|source| CeremonyFsError::WriteOutput {
                path: self.path.clone(),
                source,
            })
    }

    pub(crate) fn close_writer(&mut self) {
        self.writer.take();
    }

    pub(crate) fn reopen_exact(
        &mut self,
        parent: &TrustedCeremonyParent,
        expected: &[u8],
    ) -> Result<Vec<u8>, CeremonyFsError> {
        self.close_writer();
        self.recheck_parent(parent)?;
        let reopened = open_authenticated_output(&self.path, self.identity);
        let file = finish_with_parent_recheck(reopened, parent)?;
        self.writer = Some(file);
        let mut bytes = Vec::with_capacity(expected.len().saturating_add(1));
        let read_result = self
            .writer
            .as_mut()
            .expect("the authenticated reopened output remains retained")
            .take(
                u64::try_from(expected.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .map_err(|source| CeremonyFsError::ReopenOutput {
                path: self.path.clone(),
                source,
            });
        let recheck = self.recheck(parent);
        recheck?;
        read_result?;
        if bytes != expected {
            return Err(CeremonyFsError::ReopenedOutputMismatch);
        }
        Ok(bytes)
    }

    pub(crate) fn recheck(&self, parent: &TrustedCeremonyParent) -> Result<(), CeremonyFsError> {
        self.recheck_parent(parent)?;
        let checked = (|| {
            if let Some(writer) = self.writer.as_ref() {
                if validate_output_handle(&self.path, writer)? != self.identity {
                    return Err(CeremonyFsError::OutputIdentity(self.path.clone()));
                }
                validate_private_output_handle(&self.path, writer)?;
                #[cfg(unix)]
                drop(open_authenticated_output(&self.path, self.identity)?);
            } else {
                drop(open_authenticated_output(&self.path, self.identity)?);
            }
            Ok(())
        })();
        finish_with_parent_recheck(checked, parent)
    }

    pub(crate) fn sync_parent(
        &self,
        parent: &TrustedCeremonyParent,
    ) -> Result<ParentSyncOutcome, CeremonyFsError> {
        self.recheck(parent)?;
        let synced = parent.sync();
        let recheck = self.recheck(parent);
        recheck?;
        synced
    }

    pub(crate) fn confirm(
        &mut self,
        parent: &TrustedCeremonyParent,
    ) -> Result<(), CeremonyFsError> {
        self.recheck(parent)?;
        self.writer.take();
        self.finished = true;
        Ok(())
    }

    pub(crate) fn remove_explicit(
        &mut self,
        parent: &TrustedCeremonyParent,
    ) -> Result<(), CeremonyFsError> {
        if self.finished {
            return Ok(());
        }
        let result = self.recheck_parent(parent).and_then(|()| {
            if let Some(file) = self.writer.take() {
                if validate_output_handle(&self.path, &file)? != self.identity {
                    return Err(CeremonyFsError::OutputIdentity(self.path.clone()));
                }
                #[cfg(unix)]
                drop(open_authenticated_output_for_cleanup(
                    &self.path,
                    self.identity,
                )?);
                remove_open_output(Some(&self.parent_handle), &file, &self.path)
            } else {
                let file = open_authenticated_output_for_cleanup(&self.path, self.identity)?;
                remove_open_output(Some(&self.parent_handle), &file, &self.path)
            }
        });
        if result.is_ok() {
            self.removed = true;
        }
        let parent_recheck = parent.recheck();
        self.finished = true;
        match parent_recheck {
            Ok(()) => result,
            Err(error) => Err(error),
        }
    }

    pub(crate) fn cleanup_or_quarantine(
        &mut self,
        parent: &TrustedCeremonyParent,
        original: CeremonyFsError,
    ) -> CeremonyFsError {
        match self.remove_explicit(parent) {
            Ok(()) => original,
            Err(cleanup) if self.removed => cleanup,
            Err(cleanup) => CeremonyFsError::QuarantinedOutput {
                path: self.path.clone(),
                original: original.to_string(),
                cleanup: cleanup.to_string(),
            },
        }
    }

    fn recheck_parent(&self, parent: &TrustedCeremonyParent) -> Result<(), CeremonyFsError> {
        parent.recheck()?;
        if parent.path != self.parent_path || parent.identity != self.parent_identity {
            return Err(CeremonyFsError::ParentIdentity(self.parent_path.clone()));
        }
        parent.validate_child(&self.path)
    }

    pub(crate) const fn was_removed(&self) -> bool {
        self.removed
    }
}

impl Drop for PendingOutput {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(file) = self.writer.take()
            && validate_output_handle(&self.path, &file).ok() == Some(self.identity)
        {
            let _ = remove_open_output(Some(&self.parent_handle), &file, &self.path);
        }
    }
}

fn finish_with_parent_recheck<T>(
    operation: Result<T, CeremonyFsError>,
    parent: &TrustedCeremonyParent,
) -> Result<T, CeremonyFsError> {
    match parent.recheck() {
        Ok(()) => operation,
        Err(error) => Err(error),
    }
}

fn validate_absolute_artifact_path(path: &Path) -> Result<(), CeremonyFsError> {
    validate_absolute_directory_path(path)?;
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| CeremonyFsError::InvalidArtifactPath(path.to_path_buf()))?;
    let parent = path
        .parent()
        .ok_or_else(|| CeremonyFsError::InvalidArtifactPath(path.to_path_buf()))?;
    if parent.join(file_name) != path {
        return Err(CeremonyFsError::InvalidArtifactPath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_absolute_directory_path(path: &Path) -> Result<(), CeremonyFsError> {
    if !path.is_absolute() {
        return Err(CeremonyFsError::InvalidArtifactPath(path.to_path_buf()));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(CeremonyFsError::InvalidArtifactPath(path.to_path_buf()));
        }
        normalized.push(component.as_os_str());
    }
    if normalized.as_os_str() != path.as_os_str() {
        return Err(CeremonyFsError::InvalidArtifactPath(path.to_path_buf()));
    }
    #[cfg(windows)]
    if windows_path_has_disallowed_syntax(path) {
        return Err(CeremonyFsError::InvalidArtifactPath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_ancestor_chain(path: &Path) -> Result<(), CeremonyFsError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|source| CeremonyFsError::InspectParent {
                path: current.clone(),
                source,
            })?;
        if !metadata.file_type().is_dir() || metadata_is_reparse_point(&metadata) {
            return Err(CeremonyFsError::UnsafeParent(current));
        }
    }
    Ok(())
}

fn validate_parent_handle(path: &Path, file: &File) -> Result<(), CeremonyFsError> {
    let metadata = file
        .metadata()
        .map_err(|source| CeremonyFsError::InspectParent {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_dir() || metadata_is_reparse_point(&metadata) {
        return Err(CeremonyFsError::UnsafeParent(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = metadata.mode() & 0o777;
        // SAFETY: `geteuid` has no preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } || mode != 0o700 {
            return Err(CeremonyFsError::UnsafeParent(path.to_path_buf()));
        }
    }
    #[cfg(windows)]
    {
        if !windows_parent_is_local_fixed(path).map_err(|source| {
            CeremonyFsError::InspectParent {
                path: path.to_path_buf(),
                source,
            }
        })? || !windows_operator_dacl_is_valid(file, true).map_err(|source| {
            CeremonyFsError::InspectParent {
                path: path.to_path_buf(),
                source,
            }
        })? {
            return Err(CeremonyFsError::UnsafeParent(path.to_path_buf()));
        }
    }
    Ok(())
}

fn validate_input_handle(
    path: &Path,
    file: &File,
    expected_bytes: Option<u64>,
) -> Result<FileIdentity, CeremonyFsError> {
    let metadata = file
        .metadata()
        .map_err(|source| CeremonyFsError::OpenInput {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata_is_reparse_point(&metadata) {
        return Err(CeremonyFsError::InputReparsePoint(path.to_path_buf()));
    }
    if !metadata.file_type().is_file() {
        return Err(CeremonyFsError::InputNotRegular(path.to_path_buf()));
    }
    let links = hard_link_count(file, &metadata).map_err(|source| CeremonyFsError::OpenInput {
        path: path.to_path_buf(),
        source,
    })?;
    if links != 1 {
        return Err(CeremonyFsError::InputHardLinks {
            path: path.to_path_buf(),
            links,
        });
    }
    if let Some(expected) = expected_bytes
        && metadata.len() != expected
    {
        return Err(CeremonyFsError::InputLength {
            expected,
            actual: metadata.len(),
        });
    }
    file_identity(file).map_err(|source| CeremonyFsError::OpenInput {
        path: path.to_path_buf(),
        source,
    })
}

fn reject_existing_output(path: &Path) -> Result<(), CeremonyFsError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CeremonyFsError::OutputExists(path.to_path_buf())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CeremonyFsError::CreateOutput {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_output_handle(path: &Path, file: &File) -> Result<FileIdentity, CeremonyFsError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|source| CeremonyFsError::ReopenOutput {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata_is_reparse_point(&path_metadata) {
        return Err(CeremonyFsError::OutputReparsePoint(path.to_path_buf()));
    }
    if !path_metadata.file_type().is_file() {
        return Err(CeremonyFsError::OutputNotRegular(path.to_path_buf()));
    }
    let metadata = file
        .metadata()
        .map_err(|source| CeremonyFsError::ReopenOutput {
            path: path.to_path_buf(),
            source,
        })?;
    if metadata_is_reparse_point(&metadata) {
        return Err(CeremonyFsError::OutputReparsePoint(path.to_path_buf()));
    }
    if !metadata.file_type().is_file() {
        return Err(CeremonyFsError::OutputNotRegular(path.to_path_buf()));
    }
    let links =
        hard_link_count(file, &metadata).map_err(|source| CeremonyFsError::ReopenOutput {
            path: path.to_path_buf(),
            source,
        })?;
    if links != 1 {
        return Err(CeremonyFsError::OutputHardLinks {
            path: path.to_path_buf(),
            links,
        });
    }
    let identity = file_identity(file).map_err(|source| CeremonyFsError::ReopenOutput {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let named = FileIdentity {
            volume_or_device: path_metadata.dev(),
            file_index_or_inode: path_metadata.ino(),
        };
        if named != identity {
            return Err(CeremonyFsError::OutputIdentity(path.to_path_buf()));
        }
    }
    Ok(identity)
}

fn validate_private_output_handle(path: &Path, file: &File) -> Result<(), CeremonyFsError> {
    let private = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata =
                file.metadata()
                    .map_err(|source| CeremonyFsError::SetOutputPermissions {
                        path: path.to_path_buf(),
                        source,
                    })?;
            // SAFETY: `geteuid` has no preconditions.
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o777 == 0o600
        }
        #[cfg(windows)]
        {
            windows_operator_dacl_is_valid(file, false).map_err(|source| {
                CeremonyFsError::SetOutputPermissions {
                    path: path.to_path_buf(),
                    source,
                }
            })?
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    };
    if private {
        Ok(())
    } else {
        Err(CeremonyFsError::SetOutputPermissions {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "output permissions are not operator-only",
            ),
        })
    }
}

fn open_authenticated_output(path: &Path, expected: FileIdentity) -> Result<File, CeremonyFsError> {
    let file = open_authenticated_output_for_cleanup(path, expected)?;
    validate_private_output_handle(path, &file)?;
    Ok(file)
}

fn open_authenticated_output_for_cleanup(
    path: &Path,
    expected: FileIdentity,
) -> Result<File, CeremonyFsError> {
    let file =
        open_output_exclusive_no_follow(path).map_err(|source| CeremonyFsError::ReopenOutput {
            path: path.to_path_buf(),
            source,
        })?;
    if validate_output_handle(path, &file)? != expected {
        return Err(CeremonyFsError::OutputIdentity(path.to_path_buf()));
    }
    Ok(file)
}

fn create_new_output(path: &Path) -> Result<File, CeremonyFsError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC},
        };
        options
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            CeremonyFsError::OutputExists(path.to_path_buf())
        } else {
            CeremonyFsError::CreateOutput {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn open_input_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn open_output_exclusive_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC},
        };
        options
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

#[cfg(unix)]
fn open_parent_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_parent_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, READ_CONTROL,
    };
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_parent_no_follow(_path: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "trusted ceremony parents are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn file_identity(file: &File) -> std::io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        volume_or_device: metadata.dev(),
        file_index_or_inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn file_identity(file: &File) -> std::io::Result<FileIdentity> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` is live and the output storage has the exact API layout.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: success initialized the complete structure.
    let information = unsafe { information.assume_init() };
    Ok(FileIdentity {
        volume_or_device: u64::from(information.dwVolumeSerialNumber),
        file_index_or_inode: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File) -> std::io::Result<FileIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "stable file identity is unsupported on this platform",
    ))
}

fn hard_link_count(file: &File, metadata: &Metadata) -> std::io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let _ = file;
        Ok(metadata.nlink())
    }
    #[cfg(windows)]
    {
        use std::{mem::MaybeUninit, os::windows::io::AsRawHandle as _};
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let _ = metadata;
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: `file` is live and the output storage has the exact API layout.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) }
            == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: success initialized the complete structure.
        Ok(u64::from(
            unsafe { information.assume_init() }.nNumberOfLinks,
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, metadata);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hard-link inspection is unsupported on this platform",
        ))
    }
}

#[cfg(unix)]
fn make_output_private(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn make_output_private(file: &File) -> std::io::Result<()> {
    set_windows_operator_only_acl(file, windows_sys::Win32::Security::NO_INHERITANCE)
}

#[cfg(not(any(unix, windows)))]
fn make_output_private(_file: &File) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private output permissions are unsupported on this platform",
    ))
}

#[cfg(windows)]
fn remove_open_output(
    _parent: Option<&File>,
    file: &File,
    path: &Path,
) -> Result<(), CeremonyFsError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `file` is live with DELETE access and the input has the API layout.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(CeremonyFsError::CleanupOutput {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_open_output(
    parent: Option<&File>,
    _file: &File,
    path: &Path,
) -> Result<(), CeremonyFsError> {
    #[cfg(unix)]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt as _, os::unix::io::AsRawFd as _};
        let parent = parent.ok_or_else(|| CeremonyFsError::CleanupOutput {
            path: path.to_path_buf(),
            source: std::io::Error::other("retained parent handle is unavailable"),
        })?;
        let name = path
            .file_name()
            .ok_or_else(|| CeremonyFsError::CleanupOutput {
                path: path.to_path_buf(),
                source: std::io::Error::other("output has no direct-child file name"),
            })?;
        let name = CString::new(name.as_bytes()).map_err(|_| CeremonyFsError::CleanupOutput {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "output file name contains NUL",
            ),
        })?;
        // SAFETY: the retained parent descriptor and NUL-terminated child name are valid.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(CeremonyFsError::CleanupOutput {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        Err(CeremonyFsError::CleanupOutput {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "identity-safe cleanup is unsupported on this platform",
            ),
        })
    }
}

#[cfg(windows)]
fn remove_unidentified_output(file: &File, path: &Path) -> Result<(), CeremonyFsError> {
    remove_open_output(None, file, path)
}

#[cfg(not(windows))]
fn remove_unidentified_output(_file: &File, path: &Path) -> Result<(), CeremonyFsError> {
    Err(CeremonyFsError::CleanupOutput {
        path: path.to_path_buf(),
        source: std::io::Error::other("safe cleanup requires a captured output identity"),
    })
}

#[cfg(unix)]
fn classify_parent_sync(
    path: &Path,
    result: std::io::Result<()>,
) -> Result<ParentSyncOutcome, CeremonyFsError> {
    result.map_err(|source| CeremonyFsError::SyncParent {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(ParentSyncOutcome::Synced)
}

#[cfg(windows)]
fn classify_parent_sync(
    path: &Path,
    result: std::io::Result<()>,
) -> Result<ParentSyncOutcome, CeremonyFsError> {
    match result {
        Ok(()) => Ok(ParentSyncOutcome::Synced),
        Err(source) if source.raw_os_error() == Some(5) => {
            Ok(ParentSyncOutcome::WindowsAccessDenied)
        }
        Err(source)
            if source.kind() == std::io::ErrorKind::Unsupported
                || matches!(source.raw_os_error(), Some(1 | 50)) =>
        {
            Ok(ParentSyncOutcome::WindowsUnsupported)
        }
        Err(source) => Err(CeremonyFsError::SyncParent {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(not(any(unix, windows)))]
fn classify_parent_sync(
    _path: &Path,
    _result: std::io::Result<()>,
) -> Result<ParentSyncOutcome, CeremonyFsError> {
    Ok(ParentSyncOutcome::PlatformUnsupported)
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn windows_path_has_disallowed_syntax(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt as _;
    let mut components = path.components();
    let valid_prefix = matches!(
        components.next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_))
    );
    if !valid_prefix || !matches!(components.next(), Some(Component::RootDir)) {
        return true;
    }
    path.components().any(|component| match component {
        Component::Normal(name) => {
            name.encode_wide().any(|unit| unit == u16::from(b':'))
                || windows_file_name_is_reserved_device(name)
        }
        Component::CurDir | Component::ParentDir => true,
        Component::Prefix(prefix) => !matches!(prefix.kind(), std::path::Prefix::Disk(_)),
        Component::RootDir => false,
    })
}

#[cfg(windows)]
fn windows_file_name_is_reserved_device(file_name: &std::ffi::OsStr) -> bool {
    let name = file_name.to_string_lossy();
    let trimmed = name.trim_end_matches([' ', '.']);
    if trimmed.len() != name.len() {
        return true;
    }
    let stem = trimmed.split('.').next().unwrap_or_default();
    if ["CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    let mut characters = stem.chars();
    let prefix = characters.by_ref().take(3).collect::<String>();
    let suffix = characters.collect::<String>();
    (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
        && matches!(
            suffix.as_str(),
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
}

#[cfg(windows)]
fn windows_parent_is_local_fixed(parent: &Path) -> std::io::Result<bool> {
    use std::{os::windows::ffi::OsStrExt as _, path::Component};
    use windows_sys::Win32::{
        Storage::FileSystem::GetDriveTypeW, System::WindowsProgramming::DRIVE_FIXED,
    };
    let drive = match parent.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            std::path::Prefix::Disk(drive) => drive,
            _ => return Ok(false),
        },
        _ => return Ok(false),
    };
    let root = std::ffi::OsString::from(format!("{}:\\", char::from(drive)))
        .encode_wide()
        .chain([0])
        .collect::<Vec<_>>();
    // SAFETY: `root` is a NUL-terminated UTF-16 drive-root string.
    Ok(unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED)
}

#[cfg(windows)]
struct WindowsTokenUser {
    storage: Vec<usize>,
}

#[cfg(windows)]
impl WindowsTokenUser {
    fn sid(&self) -> windows_sys::Win32::Security::PSID {
        use windows_sys::Win32::Security::TOKEN_USER;
        // SAFETY: storage was initialized for TokenUser.
        unsafe { (*(self.storage.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

#[cfg(windows)]
struct WindowsSid {
    storage: Vec<usize>,
}

#[cfg(windows)]
impl WindowsSid {
    fn as_ptr(&self) -> windows_sys::Win32::Security::PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
struct WindowsLocalAllocation(*mut core::ffi::c_void);

#[cfg(windows)]
impl Drop for WindowsLocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this allocation is owned and was returned by a LocalFree API.
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
    }
}

#[cfg(windows)]
fn windows_current_user() -> std::io::Result<WindowsTokenUser> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::{GetTokenInformation, TOKEN_QUERY, TokenUser},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut raw_token: HANDLE = std::ptr::null_mut();
    // SAFETY: output storage and process pseudo-handle are valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: success returned one owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut required = 0_u32;
    // SAFETY: this is the documented zero-length size probe.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let words = usize::try_from(required)
        .map_err(|_| std::io::Error::other("token-user size overflow"))?
        .div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0_usize; words];
    // SAFETY: storage is aligned and has at least `required` bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let user = WindowsTokenUser { storage };
    // SAFETY: SID points into the initialized token-user buffer.
    if unsafe { windows_sys::Win32::Security::IsValidSid(user.sid()) } == 0 {
        return Err(std::io::Error::other(
            "Windows returned an invalid user SID",
        ));
    }
    Ok(user)
}

#[cfg(windows)]
fn windows_well_known_sid(
    kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> std::io::Result<WindowsSid> {
    use windows_sys::Win32::Security::{CreateWellKnownSid, SECURITY_MAX_SID_SIZE};
    let mut size = SECURITY_MAX_SID_SIZE;
    let words = usize::try_from(size)
        .map_err(|_| std::io::Error::other("well-known SID size overflow"))?
        .div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0_usize; words];
    // SAFETY: storage is aligned and has SECURITY_MAX_SID_SIZE bytes.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(WindowsSid { storage })
}

#[cfg(windows)]
fn windows_error_from_status(status: u32) -> std::io::Error {
    std::io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX))
}

#[cfg(windows)]
fn set_windows_operator_only_acl(
    file: &File,
    inheritance: windows_sys::Win32::Security::ACE_FLAGS,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Foundation::{ERROR_SUCCESS, GENERIC_ALL},
        Security::{
            ACL,
            Authorization::{
                EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
                SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
            },
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
    };
    let current = windows_current_user()?;
    let system = windows_well_known_sid(WinLocalSystemSid)?;
    let administrators = windows_well_known_sid(WinBuiltinAdministratorsSid)?;
    let entry = |sid: windows_sys::Win32::Security::PSID| EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let entries = [
        entry(current.sid()),
        entry(system.as_ptr()),
        entry(administrators.as_ptr()),
    ];
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: SID buffers outlive the call and ACL output storage is writable.
    let status = unsafe { SetEntriesInAclW(3, entries.as_ptr(), std::ptr::null(), &mut acl) };
    if status != ERROR_SUCCESS {
        return Err(windows_error_from_status(status));
    }
    if acl.is_null() {
        return Err(std::io::Error::other(
            "Windows returned a null private DACL",
        ));
    }
    let _acl_guard = WindowsLocalAllocation(acl.cast());
    // SAFETY: file has WRITE_DAC and ACL remains alive for the call.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(windows_error_from_status(status));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_operator_dacl_is_valid(
    file: &File,
    require_object_inherit: bool,
) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, IsValidAcl,
            IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSID,
            WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
        System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
    };
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: outputs are writable and the retained handle has READ_CONTROL.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(windows_error_from_status(status));
    }
    let _descriptor_guard = WindowsLocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Ok(false);
    }
    // SAFETY: both pointers belong to the returned descriptor.
    if unsafe { IsValidSid(owner) } == 0 || unsafe { IsValidAcl(dacl) } == 0 {
        return Ok(false);
    }
    let current = windows_current_user()?;
    let system = windows_well_known_sid(WinLocalSystemSid)?;
    let administrators = windows_well_known_sid(WinBuiltinAdministratorsSid)?;
    // SAFETY: both SIDs are valid during comparison.
    if unsafe { EqualSid(owner, current.sid()) } == 0 {
        return Ok(false);
    }
    let allowed_sid = |sid: PSID| {
        // SAFETY: caller supplies an SID from a validated ACL.
        unsafe {
            IsValidSid(sid) != 0
                && (EqualSid(sid, current.sid()) != 0
                    || EqualSid(sid, system.as_ptr()) != 0
                    || EqualSid(sid, administrators.as_ptr()) != 0)
        }
    };
    // SAFETY: DACL remains backed by descriptor guard.
    let ace_count = unsafe { (*dacl).AceCount };
    let mut trusted_allow = false;
    let mut trusted_object_inherit_allow = false;
    for index in 0..u32::from(ace_count) {
        let mut raw_ace = std::ptr::null_mut();
        // SAFETY: index is within the ACL's advertised count.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: GetAce returned at least an ACE_HEADER.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                if usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                    return Ok(false);
                }
                // SAFETY: size and type establish ACCESS_ALLOWED_ACE layout.
                let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
                if !allowed_sid(sid) {
                    return Ok(false);
                }
                trusted_allow = true;
                if u32::from(header.AceFlags) & OBJECT_INHERIT_ACE != 0 {
                    trusted_object_inherit_allow = true;
                }
                if !require_object_inherit
                    && u32::from(header.AceFlags) & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                        != 0
                {
                    return Ok(false);
                }
            }
            ACCESS_DENIED_ACE_TYPE => return Ok(false),
            _ => return Ok(false),
        }
    }
    Ok(trusted_allow && (!require_object_inherit || trusted_object_inherit_allow))
}

#[cfg(test)]
pub(crate) fn prepare_test_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::{
            Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
                FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
            },
        };
        let directory = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        set_windows_operator_only_acl(&directory, SUB_CONTAINERS_AND_OBJECTS_INHERIT)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-ceremony-fs-test-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            prepare_test_parent(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_relative_parent_traversal_and_nonprivate_parent() {
        assert!(matches!(
            TrustedCeremonyParent::for_artifact(Path::new("relative/input.bin")),
            Err(CeremonyFsError::InvalidArtifactPath(_))
        ));
        let directory = TestDirectory::new();
        let separator = std::path::MAIN_SEPARATOR;
        let dot_alias = PathBuf::from(format!(
            "{}{separator}.{separator}input.bin",
            directory.0.display()
        ));
        let repeated_separator = PathBuf::from(format!(
            "{}{separator}{separator}input.bin",
            directory.0.display()
        ));
        for alias in [dot_alias, repeated_separator] {
            assert!(matches!(
                TrustedCeremonyParent::for_artifact(&alias),
                Err(CeremonyFsError::InvalidArtifactPath(_))
            ));
        }
        let traversal = directory.0.join("child").join("..").join("input.bin");
        assert!(matches!(
            TrustedCeremonyParent::for_artifact(&traversal),
            Err(CeremonyFsError::InvalidArtifactPath(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(matches!(
                TrustedCeremonyParent::for_artifact(&directory.0.join("input.bin")),
                Err(CeremonyFsError::UnsafeParent(_))
            ));
        }
    }

    #[test]
    fn input_is_no_follow_single_link_and_identity_bound() {
        let directory = TestDirectory::new();
        let path = directory.0.join("input.bin");
        fs::write(&path, b"payload").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let input = AuthenticatedInput::open(&parent, &path, Some(7)).unwrap();
        input.recheck(&parent, Some(7)).unwrap();

        let alias = directory.0.join("alias.bin");
        fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(
            input.recheck(&parent, Some(7)),
            Err(CeremonyFsError::InputHardLinks { links: 2, .. })
        ));
    }

    #[test]
    fn output_round_trip_is_create_new_exact_and_private() {
        let directory = TestDirectory::new();
        let path = directory.0.join("output.bin");
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let mut output = PendingOutput::create(&parent, &path).unwrap();
        #[cfg(windows)]
        assert!(windows_operator_dacl_is_valid(output.writer.as_ref().unwrap(), false).unwrap());
        output.write_all(b"artifact").unwrap();
        output.sync_file().unwrap();
        assert_eq!(
            output.reopen_exact(&parent, b"artifact").unwrap(),
            b"artifact"
        );
        let _ = output.sync_parent(&parent).unwrap();
        output.confirm(&parent).unwrap();

        assert!(matches!(
            PendingOutput::create(&parent, &path),
            Err(CeremonyFsError::OutputExists(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn output_permission_drift_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = TestDirectory::new();
        let path = directory.0.join("output.bin");
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let mut output = PendingOutput::create(&parent, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            output.recheck(&parent),
            Err(CeremonyFsError::SetOutputPermissions { .. })
        ));
        output.remove_explicit(&parent).unwrap();
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn reopened_output_remains_exclusive_until_confirmation() {
        let directory = TestDirectory::new();
        let path = directory.0.join("output.bin");
        let renamed = directory.0.join("renamed.bin");
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let mut output = PendingOutput::create(&parent, &path).unwrap();
        output.write_all(b"artifact").unwrap();
        output.sync_file().unwrap();
        output.reopen_exact(&parent, b"artifact").unwrap();

        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::rename(&path, &renamed).is_err());
        output.confirm(&parent).unwrap();
    }

    #[test]
    fn cleanup_preserves_replacement_and_surfaces_quarantine() {
        let directory = TestDirectory::new();
        let path = directory.0.join("output.bin");
        let displaced = directory.0.join("displaced.bin");
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let mut output = PendingOutput::create(&parent, &path).unwrap();
        output.write_all(b"original").unwrap();
        output.close_writer();
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, b"replacement").unwrap();

        let error = output.cleanup_or_quarantine(&parent, CeremonyFsError::ReopenedOutputMismatch);
        assert!(matches!(error, CeremonyFsError::QuarantinedOutput { .. }));
        assert_eq!(fs::read(path).unwrap(), b"replacement");
        assert_eq!(fs::read(displaced).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_ancestor_is_rejected() {
        use std::os::unix::fs::symlink;
        let directory = TestDirectory::new();
        let real = directory.0.join("real");
        fs::create_dir(&real).unwrap();
        prepare_test_parent(&real).unwrap();
        let alias = directory.0.join("alias");
        symlink(&real, &alias).unwrap();
        assert!(matches!(
            TrustedCeremonyParent::for_artifact(&alias.join("input.bin")),
            Err(CeremonyFsError::UnsafeParent(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_alias_syntax_is_rejected() {
        for path in [
            Path::new(r"C:\ceremony\input.bin:stream"),
            Path::new(r"\\server\share\input.bin"),
            Path::new(r"\\?\C:\ceremony\input.bin"),
            Path::new(r"C:\ceremony\NUL.bin"),
            Path::new(r"C:\ceremony.\input.bin"),
        ] {
            assert!(matches!(
                TrustedCeremonyParent::for_artifact(path),
                Err(CeremonyFsError::InvalidArtifactPath(_))
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_parent_requires_an_inheritable_operator_acl() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::{
            Security::NO_INHERITANCE,
            Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
                FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
            },
        };
        let directory = TestDirectory::new();
        let handle = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&directory.0)
            .unwrap();
        set_windows_operator_only_acl(&handle, NO_INHERITANCE).unwrap();
        drop(handle);

        assert!(matches!(
            TrustedCeremonyParent::for_artifact(&directory.0.join("input.bin")),
            Err(CeremonyFsError::UnsafeParent(_))
        ));
    }
}
