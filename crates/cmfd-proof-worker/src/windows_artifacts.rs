//! Dormant handle-only production-artifact loading for the future Windows
//! AppContainer launcher.
//!
//! Nothing in the current command-line protocol selects this path. Activation
//! requires an atomic `STARTUPINFOEX` launch with an explicit inherited-handle
//! list. That launcher must open each artifact with read/synchronize access
//! only and sharing that excludes writers and deletion: stable Win32 APIs do
//! not expose the granted-access mask of an existing handle for us to verify
//! here.

#![allow(dead_code)]

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    mem::MaybeUninit,
    os::windows::{
        fs::MetadataExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle},
    },
};

#[cfg(feature = "production-v3")]
use cmfd_consensus::ConsensusPowVerifier;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{GetHandleInformation, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_TYPE_DISK,
        GetFileInformationByHandle, GetFileType,
    },
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
/// This is intentionally not `Clone` or `Copy`: after the launcher transfers
/// the handle to the child, consuming this descriptor establishes its single
/// Rust owner. The object identity binds the descriptor to the exact file that
/// the parent observed, while the hashes bind its complete contents.
#[derive(Debug, PartialEq, Eq)]
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
    /// future explicit handle-list launch transfers an independently owned
    /// inherited instance to the child.
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

    fn expected_content(&self) -> WindowsArtifactContentIdentity {
        WindowsArtifactContentIdentity {
            bytes: self.expected_bytes,
            blake3: self.expected_blake3,
            sha256: self.expected_sha256,
        }
    }

    fn take_verified_file(
        self,
        artifact: &'static str,
    ) -> Result<VerifiedOpenArtifact, WindowsArtifactHandleError> {
        validate_raw_handle(artifact, self.raw_handle)?;
        // SAFETY: the descriptor is consumed exactly once, validation above
        // proved the inherited numeric handle is live, and the launch contract
        // transfers ownership of it to this worker before this call.
        let handle = unsafe { OwnedHandle::from_raw_handle(self.raw_handle as RawHandle) };
        verify_claimed_file(artifact, self, File::from(handle))
    }
}

pub(crate) struct WindowsProductionArtifactHandleDescriptors {
    pub(crate) bank: WindowsArtifactHandleDescriptor,
    pub(crate) manifest: WindowsArtifactHandleDescriptor,
    pub(crate) record_v2: WindowsArtifactHandleDescriptor,
}

impl WindowsProductionArtifactHandleDescriptors {
    fn take_verified_files(
        self,
    ) -> Result<VerifiedProductionArtifacts, WindowsArtifactHandleError> {
        let raw_handles = [
            self.bank.raw_handle,
            self.manifest.raw_handle,
            self.record_v2.raw_handle,
        ];
        let labels = ["bank", "manifest", "Record V2"];
        if raw_handles[0] == raw_handles[1]
            || raw_handles[0] == raw_handles[2]
            || raw_handles[1] == raw_handles[2]
        {
            close_unique_valid_handles(&raw_handles);
            return Err(WindowsArtifactHandleError::AliasedHandles);
        }
        for (raw_handle, artifact) in raw_handles.into_iter().zip(labels) {
            if let Err(error) = validate_raw_handle(artifact, raw_handle) {
                close_unique_valid_handles(&raw_handles);
                return Err(error);
            }
        }

        // SAFETY: every value is a distinct, live inherited handle. This
        // consumes the descriptor set and creates exactly one owner per value.
        let [bank_handle, manifest_handle, record_v2_handle] = raw_handles
            .map(|raw_handle| unsafe { OwnedHandle::from_raw_handle(raw_handle as RawHandle) });
        let bank_file = File::from(bank_handle);
        let manifest_file = File::from(manifest_handle);
        let record_v2_file = File::from(record_v2_handle);

        let bank = verify_claimed_file("bank", self.bank, bank_file)?;
        let manifest = verify_claimed_file("manifest", self.manifest, manifest_file)?;
        let record_v2 = verify_claimed_file("Record V2", self.record_v2, record_v2_file)?;
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

/// Dormant worker entry point for the future explicit AppContainer launch.
/// Current Windows ProductionV3 startup remains fail-closed before this can be
/// selected.
#[cfg(feature = "production-v3")]
pub(crate) fn load_production_v3_verifier_from_inherited_handles(
    network_id: [u8; 32],
    descriptors: WindowsProductionArtifactHandleDescriptors,
) -> Result<ConsensusPowVerifier, WindowsArtifactHandleError> {
    let verified = descriptors.take_verified_files()?;
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

struct VerifiedOpenArtifact {
    file: File,
    content: WindowsArtifactContentIdentity,
    object: WindowsFileObjectIdentity,
}

struct VerifiedProductionArtifacts {
    bank: VerifiedOpenArtifact,
    manifest: VerifiedOpenArtifact,
    record_v2: VerifiedOpenArtifact,
}

#[derive(Debug, Error)]
pub(crate) enum WindowsArtifactHandleError {
    #[error("inherited {artifact} handle is missing or invalid")]
    InvalidHandle { artifact: &'static str },
    #[error("inherited {artifact} handle does not refer to a regular disk file")]
    NotDiskFile { artifact: &'static str },
    #[error("inherited {artifact} handle has an unexpected byte length")]
    Length { artifact: &'static str },
    #[error("inherited {artifact} handle does not match the parent-observed file object")]
    ObjectIdentity { artifact: &'static str },
    #[error("inherited {artifact} handle content does not match its trusted digests")]
    ContentIdentity { artifact: &'static str },
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
        object,
    })
}

fn validate_raw_handle(
    artifact: &'static str,
    raw_handle: usize,
) -> Result<(), WindowsArtifactHandleError> {
    if raw_handle == 0 || raw_handle == INVALID_HANDLE_VALUE as usize {
        return Err(WindowsArtifactHandleError::InvalidHandle { artifact });
    }
    let mut flags = 0_u32;
    // SAFETY: this only queries the numeric handle; it does not acquire or
    // release ownership. The output pointer is valid for one `u32`.
    if unsafe { GetHandleInformation(raw_handle as RawHandle, &mut flags) } == 0 {
        return Err(WindowsArtifactHandleError::InvalidHandle { artifact });
    }
    Ok(())
}

fn close_unique_valid_handles(raw_handles: &[usize; 3]) {
    for (index, raw_handle) in raw_handles.iter().copied().enumerate() {
        if raw_handles[..index].contains(&raw_handle)
            || validate_raw_handle("artifact", raw_handle).is_err()
        {
            continue;
        }
        // SAFETY: the descriptor set was consumed by the caller. Each unique
        // live inherited handle is therefore closed exactly once on failure.
        drop(unsafe { OwnedHandle::from_raw_handle(raw_handle as RawHandle) });
    }
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
        io::Read as _,
        os::windows::{
            fs::OpenOptionsExt as _,
            io::{FromRawHandle as _, IntoRawHandle as _, OwnedHandle},
        },
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
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

    fn transfer_to_descriptor(file: File, descriptor: &WindowsArtifactHandleDescriptor) {
        let raw_handle = file.into_raw_handle() as usize;
        assert_eq!(raw_handle, descriptor.raw_handle);
    }

    fn invalid_descriptor(raw_handle: usize) -> WindowsArtifactHandleDescriptor {
        WindowsArtifactHandleDescriptor {
            raw_handle,
            expected_bytes: 0,
            expected_blake3: [0_u8; 32],
            expected_sha256: [0_u8; 32],
            expected_object: WindowsFileObjectIdentity {
                volume_serial: 0,
                file_index: 0,
            },
        }
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
        transfer_to_descriptor(parent_file, &descriptor);

        let mut verified = descriptor.take_verified_file("artifact").unwrap();
        let mut consumed = Vec::new();
        verified.file.read_to_end(&mut consumed).unwrap();
        assert_eq!(consumed, original);
        assert_eq!(verified.content, content_identity(original));
        drop(verified);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_and_closed_numeric_handles_are_rejected_before_ownership() {
        assert!(matches!(
            invalid_descriptor(0).take_verified_file("artifact"),
            Err(WindowsArtifactHandleError::InvalidHandle { .. })
        ));
        assert!(matches!(
            invalid_descriptor(usize::MAX).take_verified_file("artifact"),
            Err(WindowsArtifactHandleError::InvalidHandle { .. })
        ));

        let root = temporary_directory("closed-handle");
        let path = root.join("artifact.bin");
        fs::write(&path, b"closed").unwrap();
        let mut file = open_replaceable_file(&path);
        let descriptor = WindowsArtifactHandleDescriptor::observe_parent(
            "artifact",
            &mut file,
            content_identity(b"closed"),
        )
        .unwrap();
        let raw_handle = file.into_raw_handle();
        // SAFETY: `into_raw_handle` transferred this live handle to the test.
        drop(unsafe { OwnedHandle::from_raw_handle(raw_handle) });
        assert!(matches!(
            descriptor.take_verified_file("artifact"),
            Err(WindowsArtifactHandleError::InvalidHandle { .. })
        ));
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
        let raw_handle = file.into_raw_handle() as usize;
        let descriptor = WindowsArtifactHandleDescriptor {
            raw_handle,
            expected_bytes: 0,
            expected_blake3: [0_u8; 32],
            expected_sha256: [0_u8; 32],
            expected_object: object,
        };
        assert!(matches!(
            descriptor.take_verified_file("artifact"),
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
        transfer_to_descriptor(file, &descriptor);
        assert!(matches!(
            descriptor.take_verified_file("artifact"),
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
        transfer_to_descriptor(file, &descriptor);
        assert!(matches!(
            descriptor.take_verified_file("artifact"),
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
        transfer_to_descriptor(bank_file, &bank);
        transfer_to_descriptor(manifest_file, &manifest);
        transfer_to_descriptor(record_file, &record_v2);

        assert!(matches!(
            (WindowsProductionArtifactHandleDescriptors {
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
        transfer_to_descriptor(file, &descriptor);
        let mut verified = descriptor.take_verified_file("artifact").unwrap();
        let mut first = [0_u8; 1];
        verified.file.read_exact(&mut first).unwrap();
        assert_eq!(first[0], b'r');
        drop(verified);
        fs::remove_dir_all(root).unwrap();
    }
}
