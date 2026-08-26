//! Handle-only production-artifact transport for the Windows AppContainer
//! launcher.
//!
//! The trusted parent opens each artifact with read/synchronize access only and
//! sharing that excludes writers and deletion, authenticates that retained
//! handle, and duplicates only that handle into the explicit inherited-handle
//! list. Stable Win32 APIs do not expose the granted-access mask of an existing
//! handle, so the loader accepts only handles owned under that launch contract.

#![cfg_attr(not(feature = "production-v3"), allow(dead_code))]

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    mem::MaybeUninit,
    os::windows::{
        fs::MetadataExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
};

#[cfg(feature = "production-v3")]
use cmfd_consensus::ConsensusPowVerifier;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_TYPE_DISK,
    GetFileInformationByHandle, GetFileType,
};
use windows_sys::Win32::{
    Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle},
    System::Threading::GetCurrentProcess,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowsFileObjectIdentity {
    volume_serial: u32,
    file_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WindowsArtifactContentIdentity {
    bytes: u64,
    blake3: [u8; 32],
    sha256: [u8; 32],
}

/// Trusted launch metadata for one numeric handle inherited by the worker.
///
/// This is transport metadata, not proof that the numeric value is live or
/// owned. The launcher separately constructs an `OwnedHandle` under its
/// explicit inherited-handle ownership contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WindowsArtifactHandleDescriptor {
    raw_handle: usize,
    expected_bytes: u64,
    expected_blake3: [u8; 32],
    expected_sha256: [u8; 32],
    expected_object: WindowsFileObjectIdentity,
}

impl WindowsArtifactHandleDescriptor {
    /// Observe and authenticate a parent-owned artifact handle before launch.
    ///
    /// The returned numeric value remains borrowed in the parent. Only the
    /// explicit handle-list launch transfers an independently owned inherited
    /// instance to the child.
    #[cfg(test)]
    pub(crate) fn observe_parent(
        artifact: &'static str,
        file: &mut File,
        expected: WindowsArtifactContentIdentity,
    ) -> Result<Self, WindowsArtifactHandleError> {
        validate_disk_file(artifact, file, expected.bytes)?;
        let expected_object = query_object_identity(artifact, file)?;
        let actual = hash_open_file(artifact, file, expected.bytes)?;
        if actual != expected {
            return Err(WindowsArtifactHandleError::ContentIdentity { artifact });
        }
        validate_disk_file(artifact, file, expected.bytes)?;
        if query_object_identity(artifact, file)? != expected_object {
            return Err(WindowsArtifactHandleError::ObjectIdentity { artifact });
        }
        Ok(Self {
            raw_handle: file.as_raw_handle() as usize,
            expected_bytes: expected.bytes,
            expected_blake3: expected.blake3,
            expected_sha256: expected.sha256,
            expected_object,
        })
    }

    /// Observe the complete identity of a retained parent handle when the
    /// trusted caller has already selected the artifact path but does not carry
    /// a second copy of its digest tuple. The child independently rechecks this
    /// exact content and the consensus loader authenticates the artifact set.
    pub(crate) fn observe_parent_content(
        artifact: &'static str,
        file: &mut File,
    ) -> Result<Self, WindowsArtifactHandleError> {
        let expected_bytes = file
            .metadata()
            .map_err(|source| WindowsArtifactHandleError::Io {
                artifact,
                operation: "reading parent metadata",
                source,
            })?
            .len();
        validate_disk_file(artifact, file, expected_bytes)?;
        let expected_object = query_object_identity(artifact, file)?;
        let expected = hash_open_file(artifact, file, expected_bytes)?;
        validate_disk_file(artifact, file, expected_bytes)?;
        if query_object_identity(artifact, file)? != expected_object {
            return Err(WindowsArtifactHandleError::ObjectIdentity { artifact });
        }
        Ok(Self {
            raw_handle: file.as_raw_handle() as usize,
            expected_bytes,
            expected_blake3: expected.blake3,
            expected_sha256: expected.sha256,
            expected_object,
        })
    }

    pub(crate) fn for_inherited_handle(&self, raw_handle: usize) -> Self {
        let mut inherited = self.clone();
        inherited.raw_handle = raw_handle;
        inherited
    }

    pub(crate) fn transport_argument(&self) -> String {
        format!(
            "{:x}:{}:{}:{}:{:08x}:{:016x}",
            self.raw_handle,
            self.expected_bytes,
            hex::encode(self.expected_blake3),
            hex::encode(self.expected_sha256),
            self.expected_object.volume_serial,
            self.expected_object.file_index,
        )
    }

    pub(crate) fn parse_transport_argument(
        value: &str,
    ) -> Result<Self, WindowsArtifactHandleError> {
        let fields = value.split(':').collect::<Vec<_>>();
        let lowercase_hex = |field: &str| {
            !field.is_empty()
                && field
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if fields.len() != 6
            || fields[0].is_empty()
            || fields[1].is_empty()
            || fields[2].len() != 64
            || fields[3].len() != 64
            || fields[4].len() != 8
            || fields[5].len() != 16
            || !lowercase_hex(fields[0])
            || !fields[1].bytes().all(|byte| byte.is_ascii_digit())
            || !lowercase_hex(fields[2])
            || !lowercase_hex(fields[3])
            || !lowercase_hex(fields[4])
            || !lowercase_hex(fields[5])
        {
            return Err(WindowsArtifactHandleError::TransportDescriptor);
        }
        let raw_handle = usize::from_str_radix(fields[0], 16)
            .map_err(|_| WindowsArtifactHandleError::TransportDescriptor)?;
        if raw_handle == 0 || raw_handle == usize::MAX {
            return Err(WindowsArtifactHandleError::TransportDescriptor);
        }
        let expected_bytes = fields[1]
            .parse::<u64>()
            .map_err(|_| WindowsArtifactHandleError::TransportDescriptor)?;
        if expected_bytes == 0 {
            return Err(WindowsArtifactHandleError::TransportDescriptor);
        }
        let expected_blake3 = decode_digest(fields[2])?;
        let expected_sha256 = decode_digest(fields[3])?;
        let volume_serial = u32::from_str_radix(fields[4], 16)
            .map_err(|_| WindowsArtifactHandleError::TransportDescriptor)?;
        let file_index = u64::from_str_radix(fields[5], 16)
            .map_err(|_| WindowsArtifactHandleError::TransportDescriptor)?;
        let descriptor = Self {
            raw_handle,
            expected_bytes,
            expected_blake3,
            expected_sha256,
            expected_object: WindowsFileObjectIdentity {
                volume_serial,
                file_index,
            },
        };
        if descriptor.transport_argument() != value {
            return Err(WindowsArtifactHandleError::TransportDescriptor);
        }
        Ok(descriptor)
    }

    fn expected_content(&self) -> WindowsArtifactContentIdentity {
        WindowsArtifactContentIdentity {
            bytes: self.expected_bytes,
            blake3: self.expected_blake3,
            sha256: self.expected_sha256,
        }
    }

    pub(crate) fn matches_file_identity(
        &self,
        expected: &cmfd_consensus::dory_v3_model_ceremony_transcript::FileIdentity,
    ) -> bool {
        self.expected_bytes == expected.bytes
            && self.expected_blake3 == expected.blake3
            && self.expected_sha256 == expected.sha256
    }
}

/// One descriptor bound to a handle whose ownership was established outside
/// this safe loader.
pub(crate) struct OwnedWindowsArtifactHandle {
    descriptor: WindowsArtifactHandleDescriptor,
    handle: OwnedHandle,
}

impl OwnedWindowsArtifactHandle {
    pub(crate) fn bind(
        _artifact: &'static str,
        descriptor: WindowsArtifactHandleDescriptor,
        handle: OwnedHandle,
    ) -> Result<Self, WindowsArtifactHandleError> {
        Ok(Self { descriptor, handle })
    }

    fn take_verified_file(
        self,
        artifact: &'static str,
    ) -> Result<VerifiedOpenArtifact, WindowsArtifactHandleError> {
        verify_claimed_file(artifact, self.descriptor, File::from(self.handle))
    }
}

#[cfg(test)]
pub(crate) struct OwnedWindowsProductionArtifactHandles {
    pub(crate) bank: OwnedWindowsArtifactHandle,
    pub(crate) manifest: OwnedWindowsArtifactHandle,
    pub(crate) record_v2: OwnedWindowsArtifactHandle,
}

/// The verifier-only worker inherits exactly one release-pinned Record V2
/// handle. Model bank and standalone manifest authority never cross the
/// AppContainer boundary.
pub(crate) struct OwnedWindowsProductionRecordHandle {
    record_v2: OwnedWindowsArtifactHandle,
}

impl OwnedWindowsProductionRecordHandle {
    pub(crate) fn from_inherited_descriptor(
        descriptor: WindowsArtifactHandleDescriptor,
    ) -> Result<Self, WindowsArtifactHandleError> {
        let handle = duplicate_borrowed_handle("Record V2", descriptor.raw_handle)?;
        Ok(Self {
            record_v2: OwnedWindowsArtifactHandle::bind("Record V2", descriptor, handle)?,
        })
    }
}

#[cfg(test)]
impl OwnedWindowsProductionArtifactHandles {
    pub(crate) fn from_inherited_descriptors(
        descriptors: [WindowsArtifactHandleDescriptor; 3],
    ) -> Result<Self, WindowsArtifactHandleError> {
        let [bank, manifest, record_v2] = descriptors;
        if bank.raw_handle == manifest.raw_handle
            || bank.raw_handle == record_v2.raw_handle
            || manifest.raw_handle == record_v2.raw_handle
        {
            return Err(WindowsArtifactHandleError::AliasedHandles);
        }
        // Numeric values supplied on the command line are borrowed. Duplicate
        // each live handle before constructing any owner so malformed or stale
        // transport metadata can never close an unrelated/reused raw value.
        let bank_handle = duplicate_borrowed_handle("bank", bank.raw_handle)?;
        let manifest_handle = duplicate_borrowed_handle("manifest", manifest.raw_handle)?;
        let record_handle = duplicate_borrowed_handle("Record V2", record_v2.raw_handle)?;
        Ok(Self {
            bank: OwnedWindowsArtifactHandle::bind("bank", bank, bank_handle)?,
            manifest: OwnedWindowsArtifactHandle::bind("manifest", manifest, manifest_handle)?,
            record_v2: OwnedWindowsArtifactHandle::bind("Record V2", record_v2, record_handle)?,
        })
    }

    fn take_verified_files(
        self,
    ) -> Result<VerifiedProductionArtifacts, WindowsArtifactHandleError> {
        if self.bank.descriptor.raw_handle == self.manifest.descriptor.raw_handle
            || self.bank.descriptor.raw_handle == self.record_v2.descriptor.raw_handle
            || self.manifest.descriptor.raw_handle == self.record_v2.descriptor.raw_handle
        {
            return Err(WindowsArtifactHandleError::AliasedHandles);
        }
        let bank = self.bank.take_verified_file("bank")?;
        let manifest = self.manifest.take_verified_file("manifest")?;
        let record_v2 = self.record_v2.take_verified_file("Record V2")?;
        if bank.object == manifest.object
            || bank.object == record_v2.object
            || manifest.object == record_v2.object
        {
            return Err(WindowsArtifactHandleError::AliasedHandles);
        }
        Ok(VerifiedProductionArtifacts {
            bank,
            manifest,
            record_v2,
        })
    }
}

/// Worker entry point selected only by the explicit AppContainer handle-list
/// launch contract.
#[cfg(feature = "production-v3")]
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn load_production_v3_verifier_from_inherited_handles(
    network_id: [u8; 32],
    handles: OwnedWindowsProductionArtifactHandles,
) -> Result<ConsensusPowVerifier, WindowsArtifactHandleError> {
    let verified = handles.take_verified_files()?;
    let bank_identity = consensus_file_identity(verified.bank.content);
    let manifest_identity = consensus_file_identity(verified.manifest.content);
    let record_v2_identity = consensus_file_identity(verified.record_v2.content);
    cmfd_consensus::dory_v3_model_bank_record_validation::load_production_dory_v3_consensus_verifier_from_open_files(
        network_id,
        verified.bank.file,
        verified.manifest.file,
        verified.record_v2.file,
        bank_identity,
        manifest_identity,
        record_v2_identity,
    )
    .map(|loaded| loaded.into_verifier())
    .map_err(WindowsArtifactHandleError::Consensus)
}

/// Verifier-only worker entry point selected by the one-handle AppContainer
/// launch contract.
#[cfg(feature = "production-v3")]
pub(crate) fn load_production_v3_verifier_from_inherited_record_handle(
    network_id: [u8; 32],
    handle: OwnedWindowsProductionRecordHandle,
) -> Result<ConsensusPowVerifier, WindowsArtifactHandleError> {
    let verified = handle.record_v2.take_verified_file("Record V2")?;
    let record_v2_identity = consensus_file_identity(verified.content);
    cmfd_consensus::dory_v3_model_bank_record_validation::load_release_pinned_production_dory_v3_consensus_verifier_from_open_file(
        network_id,
        verified.file,
        record_v2_identity,
    )
    .map(|loaded| loaded.into_verifier())
    .map_err(WindowsArtifactHandleError::Consensus)
}

struct VerifiedOpenArtifact {
    file: File,
    content: WindowsArtifactContentIdentity,
    #[cfg(test)]
    object: WindowsFileObjectIdentity,
}

#[cfg(test)]
#[allow(dead_code)]
struct VerifiedProductionArtifacts {
    bank: VerifiedOpenArtifact,
    manifest: VerifiedOpenArtifact,
    record_v2: VerifiedOpenArtifact,
}

#[derive(Debug, Error)]
pub(crate) enum WindowsArtifactHandleError {
    #[error("inherited production artifact handle descriptor is not canonical")]
    TransportDescriptor,
    #[error("could not duplicate the borrowed inherited {artifact} handle: {source}")]
    DuplicateTransportHandle {
        artifact: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("inherited {artifact} handle does not refer to a regular disk file")]
    NotDiskFile { artifact: &'static str },
    #[error("inherited {artifact} handle has an unexpected byte length")]
    Length { artifact: &'static str },
    #[error("inherited {artifact} handle does not match the parent-observed file object")]
    ObjectIdentity { artifact: &'static str },
    #[error("inherited {artifact} handle content does not match its trusted digests")]
    ContentIdentity { artifact: &'static str },
    #[cfg(test)]
    #[error("inherited production artifact handles are duplicated or refer to the same file")]
    AliasedHandles,
    #[error("inherited {artifact} handle I/O failed while {operation}: {source}")]
    Io {
        artifact: &'static str,
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[cfg(feature = "production-v3")]
    #[error("could not authenticate the inherited production V3 artifacts: {0}")]
    Consensus(
        #[source]
        cmfd_consensus::dory_v3_model_bank_record_validation::ProductionDoryV3ModelBankRecordValidationError,
    ),
}

fn duplicate_borrowed_handle(
    artifact: &'static str,
    raw_handle: usize,
) -> Result<OwnedHandle, WindowsArtifactHandleError> {
    // SAFETY: the current-process pseudo handle is valid for both process
    // parameters and must not be closed. `raw_handle` remains borrowed even
    // when invalid; DuplicateHandle either returns a fresh owner or fails
    // without transferring/closing the source value.
    let current = unsafe { GetCurrentProcess() };
    let mut duplicate = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            current,
            raw_handle as *mut _,
            current,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(WindowsArtifactHandleError::DuplicateTransportHandle {
            artifact,
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: DuplicateHandle returned one fresh owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate.cast()) })
}

fn decode_digest(value: &str) -> Result<[u8; 32], WindowsArtifactHandleError> {
    let decoded =
        hex::decode(value).map_err(|_| WindowsArtifactHandleError::TransportDescriptor)?;
    decoded
        .try_into()
        .map_err(|_| WindowsArtifactHandleError::TransportDescriptor)
}

fn verify_claimed_file(
    artifact: &'static str,
    descriptor: WindowsArtifactHandleDescriptor,
    mut file: File,
) -> Result<VerifiedOpenArtifact, WindowsArtifactHandleError> {
    validate_disk_file(artifact, &file, descriptor.expected_bytes)?;
    let object = query_object_identity(artifact, &file)?;
    if object != descriptor.expected_object {
        return Err(WindowsArtifactHandleError::ObjectIdentity { artifact });
    }
    let content = hash_open_file(artifact, &mut file, descriptor.expected_bytes)?;
    if content != descriptor.expected_content() {
        return Err(WindowsArtifactHandleError::ContentIdentity { artifact });
    }
    validate_disk_file(artifact, &file, descriptor.expected_bytes)?;
    if query_object_identity(artifact, &file)? != descriptor.expected_object {
        return Err(WindowsArtifactHandleError::ObjectIdentity { artifact });
    }
    Ok(VerifiedOpenArtifact {
        file,
        content,
        #[cfg(test)]
        object,
    })
}

fn validate_disk_file(
    artifact: &'static str,
    file: &File,
    expected_bytes: u64,
) -> Result<(), WindowsArtifactHandleError> {
    // SAFETY: `file` owns a live handle for the duration of this call.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(WindowsArtifactHandleError::NotDiskFile { artifact });
    }
    let metadata = file
        .metadata()
        .map_err(|source| WindowsArtifactHandleError::Io {
            artifact,
            operation: "reading metadata",
            source,
        })?;
    let information = query_file_information(artifact, file)?;
    let information_bytes =
        (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.nNumberOfLinks != 1
    {
        return Err(WindowsArtifactHandleError::NotDiskFile { artifact });
    }
    if metadata.len() != expected_bytes || information_bytes != expected_bytes {
        return Err(WindowsArtifactHandleError::Length { artifact });
    }
    Ok(())
}

fn query_file_information(
    artifact: &'static str,
    file: &File,
) -> Result<BY_HANDLE_FILE_INFORMATION, WindowsArtifactHandleError> {
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` owns a live handle and the output has the exact Win32
    // layout. A successful call initializes the complete structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) } == 0 {
        return Err(WindowsArtifactHandleError::Io {
            artifact,
            operation: "querying file identity",
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: success above initialized every field.
    Ok(unsafe { information.assume_init() })
}

fn query_object_identity(
    artifact: &'static str,
    file: &File,
) -> Result<WindowsFileObjectIdentity, WindowsArtifactHandleError> {
    let information = query_file_information(artifact, file)?;
    Ok(WindowsFileObjectIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

fn hash_open_file(
    artifact: &'static str,
    file: &mut File,
    expected_bytes: u64,
) -> Result<WindowsArtifactContentIdentity, WindowsArtifactHandleError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| WindowsArtifactHandleError::Io {
            artifact,
            operation: "rewinding before hashing",
            source,
        })?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| WindowsArtifactHandleError::Io {
                artifact,
                operation: "hashing contents",
                source,
            })?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(u64::try_from(read).expect("Windows usize fits in u64"))
            .ok_or(WindowsArtifactHandleError::Length { artifact })?;
        if bytes > expected_bytes {
            return Err(WindowsArtifactHandleError::Length { artifact });
        }
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| WindowsArtifactHandleError::Io {
            artifact,
            operation: "rewinding after hashing",
            source,
        })?;
    if bytes != expected_bytes {
        return Err(WindowsArtifactHandleError::Length { artifact });
    }
    Ok(WindowsArtifactContentIdentity {
        bytes,
        blake3: *blake3.finalize().as_bytes(),
        sha256: sha256.finalize().into(),
    })
}

#[cfg(feature = "production-v3")]
fn consensus_file_identity(
    identity: WindowsArtifactContentIdentity,
) -> cmfd_consensus::dory_v3_model_ceremony_transcript::FileIdentity {
    cmfd_consensus::dory_v3_model_ceremony_transcript::FileIdentity {
        bytes: identity.bytes,
        blake3: identity.blake3,
        sha256: identity.sha256,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{Read as _, Seek as _, SeekFrom},
        os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _},
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread,
    };

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    use super::*;

    static NEXT_TEMPORARY_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory(label: &str) -> PathBuf {
        let sequence = NEXT_TEMPORARY_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-windows-artifacts-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }

    fn content_identity(bytes: &[u8]) -> WindowsArtifactContentIdentity {
        let mut sha256 = Sha256::new();
        sha256.update(bytes);
        WindowsArtifactContentIdentity {
            bytes: u64::try_from(bytes.len()).unwrap(),
            blake3: *blake3::hash(bytes).as_bytes(),
            sha256: sha256.finalize().into(),
        }
    }

    fn open_replaceable_file(path: &std::path::Path) -> File {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)
            .unwrap()
    }

    fn bind_file(
        artifact: &'static str,
        file: File,
        descriptor: WindowsArtifactHandleDescriptor,
    ) -> OwnedWindowsArtifactHandle {
        OwnedWindowsArtifactHandle::bind(artifact, descriptor, file.into()).unwrap()
    }

    #[test]
    fn path_replacement_after_parent_observation_cannot_change_consumed_bytes() {
        let root = temporary_directory("path-replacement");
        let path = root.join("artifact.bin");
        let archived = root.join("artifact.original.bin");
        let original = b"parent-observed consensus artifact";
        let replacement = b"pathname replacement must not be consumed";
        fs::write(&path, original).unwrap();

        let mut parent_file = open_replaceable_file(&path);
        let descriptor = WindowsArtifactHandleDescriptor::observe_parent(
            "artifact",
            &mut parent_file,
            content_identity(original),
        )
        .unwrap();
        fs::rename(&path, &archived).unwrap();
        fs::write(&path, replacement).unwrap();
        let handle = bind_file("artifact", parent_file, descriptor);

        let mut verified = handle.take_verified_file("artifact").unwrap();
        let mut consumed = Vec::new();
        verified.file.read_to_end(&mut consumed).unwrap();
        assert_eq!(consumed, original);
        assert_eq!(verified.content, content_identity(original));
        drop(verified);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_transport_value_is_rejected_without_raw_handle_adoption() {
        let root = temporary_directory("malformed-transport");
        let path = root.join("artifact.bin");
        fs::write(&path, b"owned").unwrap();
        let mut file = open_replaceable_file(&path);
        let malformed = format!(
            "{:x}:not-a-canonical-descriptor",
            file.as_raw_handle() as usize
        );
        assert!(matches!(
            WindowsArtifactHandleDescriptor::parse_transport_argument(&malformed),
            Err(WindowsArtifactHandleError::TransportDescriptor)
        ));
        let mut observed = Vec::new();
        file.read_to_end(&mut observed).unwrap();
        assert_eq!(
            observed, b"owned",
            "parsing adopted or closed the raw handle"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_inherited_descriptors_never_close_borrowed_source_handles() {
        let root = temporary_directory("borrowed-source-lifetime");
        let paths = ["bank", "manifest", "record"].map(|name| root.join(name));
        let contents: [&[u8]; 3] = [b"bank", b"manifest", b"record"];
        for (path, content) in paths.iter().zip(contents) {
            fs::write(path, content).unwrap();
        }
        let mut sources = paths.map(|path| open_replaceable_file(&path));
        let mut descriptors = [
            WindowsArtifactHandleDescriptor::observe_parent(
                "bank",
                &mut sources[0],
                content_identity(contents[0]),
            )
            .unwrap(),
            WindowsArtifactHandleDescriptor::observe_parent(
                "manifest",
                &mut sources[1],
                content_identity(contents[1]),
            )
            .unwrap(),
            WindowsArtifactHandleDescriptor::observe_parent(
                "Record V2",
                &mut sources[2],
                content_identity(contents[2]),
            )
            .unwrap(),
        ];
        descriptors[0].expected_blake3[0] ^= 1;
        let inherited =
            OwnedWindowsProductionArtifactHandles::from_inherited_descriptors(descriptors)
                .expect("borrowed live handles can be duplicated");
        assert!(matches!(
            inherited.take_verified_files(),
            Err(WindowsArtifactHandleError::ContentIdentity { artifact: "bank" })
        ));

        for (source, expected) in sources.iter_mut().zip(contents) {
            source.seek(SeekFrom::Start(0)).unwrap();
            let mut observed = Vec::new();
            source.read_to_end(&mut observed).unwrap();
            assert_eq!(
                observed, expected,
                "malformed inherited metadata closed or replaced a borrowed source handle"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_handle_is_rejected_as_a_non_file() {
        let root = temporary_directory("directory-handle");
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&root)
            .unwrap();
        let object = query_object_identity("artifact", &file).unwrap();
        let raw_handle = file.as_raw_handle() as usize;
        let descriptor = WindowsArtifactHandleDescriptor {
            raw_handle,
            expected_bytes: 0,
            expected_blake3: [0_u8; 32],
            expected_sha256: [0_u8; 32],
            expected_object: object,
        };
        let handle = bind_file("artifact", file, descriptor);
        assert!(matches!(
            handle.take_verified_file("artifact"),
            Err(WindowsArtifactHandleError::NotDiskFile { .. })
        ));
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn parent_object_identity_mismatch_is_rejected() {
        let root = temporary_directory("object-mismatch");
        let path = root.join("artifact.bin");
        fs::write(&path, b"identity").unwrap();
        let mut file = open_replaceable_file(&path);
        let mut descriptor = WindowsArtifactHandleDescriptor::observe_parent(
            "artifact",
            &mut file,
            content_identity(b"identity"),
        )
        .unwrap();
        descriptor.expected_object.file_index ^= 1;
        let handle = bind_file("artifact", file, descriptor);
        assert!(matches!(
            handle.take_verified_file("artifact"),
            Err(WindowsArtifactHandleError::ObjectIdentity { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unexpected_content_digest_is_rejected() {
        let root = temporary_directory("digest-mismatch");
        let path = root.join("artifact.bin");
        fs::write(&path, b"trusted content").unwrap();
        let mut file = open_replaceable_file(&path);
        let mut descriptor = WindowsArtifactHandleDescriptor::observe_parent(
            "artifact",
            &mut file,
            content_identity(b"trusted content"),
        )
        .unwrap();
        descriptor.expected_blake3[0] ^= 1;
        let handle = bind_file("artifact", file, descriptor);
        assert!(matches!(
            handle.take_verified_file("artifact"),
            Err(WindowsArtifactHandleError::ContentIdentity { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parent_observation_rejects_unexpected_content() {
        let root = temporary_directory("parent-digest-mismatch");
        let path = root.join("artifact.bin");
        fs::write(&path, b"actual").unwrap();
        let mut file = open_replaceable_file(&path);
        assert!(matches!(
            WindowsArtifactHandleDescriptor::observe_parent(
                "artifact",
                &mut file,
                content_identity(b"expected"),
            ),
            Err(WindowsArtifactHandleError::Length { .. })
                | Err(WindowsArtifactHandleError::ContentIdentity { .. })
        ));
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn distinct_numeric_handles_for_the_same_file_are_rejected_as_aliases() {
        let root = temporary_directory("aliased-files");
        let shared_path = root.join("shared.bin");
        let record_path = root.join("record.bin");
        fs::write(&shared_path, b"shared").unwrap();
        fs::write(&record_path, b"record").unwrap();

        let mut bank_file = open_replaceable_file(&shared_path);
        let bank = WindowsArtifactHandleDescriptor::observe_parent(
            "bank",
            &mut bank_file,
            content_identity(b"shared"),
        )
        .unwrap();
        let mut manifest_file = open_replaceable_file(&shared_path);
        let manifest = WindowsArtifactHandleDescriptor::observe_parent(
            "manifest",
            &mut manifest_file,
            content_identity(b"shared"),
        )
        .unwrap();
        let mut record_file = open_replaceable_file(&record_path);
        let record_v2 = WindowsArtifactHandleDescriptor::observe_parent(
            "Record V2",
            &mut record_file,
            content_identity(b"record"),
        )
        .unwrap();
        let bank = bind_file("bank", bank_file, bank);
        let manifest = bind_file("manifest", manifest_file, manifest);
        let record_v2 = bind_file("Record V2", record_file, record_v2);

        assert!(matches!(
            (OwnedWindowsProductionArtifactHandles {
                bank,
                manifest,
                record_v2,
            })
            .take_verified_files(),
            Err(WindowsArtifactHandleError::AliasedHandles)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_hashing_rewinds_the_consumed_file() {
        let root = temporary_directory("rewind");
        let path = root.join("artifact.bin");
        fs::write(&path, b"rewound").unwrap();
        let mut file = open_replaceable_file(&path);
        let descriptor = WindowsArtifactHandleDescriptor::observe_parent(
            "artifact",
            &mut file,
            content_identity(b"rewound"),
        )
        .unwrap();
        let handle = bind_file("artifact", file, descriptor);
        let mut verified = handle.take_verified_file("artifact").unwrap();
        let mut first = [0_u8; 1];
        verified.file.read_exact(&mut first).unwrap();
        assert_eq!(first[0], b'r');
        drop(verified);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_numeric_transport_cannot_adopt_a_concurrently_reused_handle() {
        let root = temporary_directory("concurrent-reuse");
        let original_path = root.join("original.bin");
        let candidate_path = root.join("candidate.bin");
        let unrelated_path = root.join("unrelated.bin");
        fs::write(&original_path, b"original").unwrap();
        fs::write(&candidate_path, b"candidate").unwrap();
        fs::write(&unrelated_path, b"unrelated still live").unwrap();

        let mut original = open_replaceable_file(&original_path);
        let descriptor = WindowsArtifactHandleDescriptor::observe_parent(
            "artifact",
            &mut original,
            content_identity(b"original"),
        )
        .unwrap();
        let mut stale_descriptor = descriptor;
        let candidate = open_replaceable_file(&candidate_path);
        drop(original);

        let (raw_sender, raw_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let reuse_thread = thread::spawn(move || {
            let mut unrelated = open_replaceable_file(&unrelated_path);
            raw_sender.send(unrelated.as_raw_handle() as usize).unwrap();
            release_receiver.recv().unwrap();
            let mut bytes = Vec::new();
            unrelated.read_to_end(&mut bytes).unwrap();
            bytes == b"unrelated still live"
        });
        // Deterministically install the exact state produced by handle-value
        // reuse: stale trusted metadata now names an unrelated live handle
        // owned by another thread. The loader duplicates the borrowed value;
        // it never converts that value itself into an owner.
        stale_descriptor.raw_handle = raw_receiver.recv().unwrap();
        assert_ne!(
            candidate.as_raw_handle() as usize,
            stale_descriptor.raw_handle
        );
        let borrowed_duplicate =
            duplicate_borrowed_handle("artifact", stale_descriptor.raw_handle).unwrap();
        assert!(matches!(
            OwnedWindowsArtifactHandle::bind("artifact", stale_descriptor, borrowed_duplicate)
                .unwrap()
                .take_verified_file("artifact"),
            Err(WindowsArtifactHandleError::ObjectIdentity { .. })
                | Err(WindowsArtifactHandleError::Length { .. })
                | Err(WindowsArtifactHandleError::ContentIdentity { .. })
        ));
        drop(candidate);
        release_sender.send(()).unwrap();
        assert!(
            reuse_thread.join().unwrap(),
            "stale transport metadata closed or adopted the unrelated live handle"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
