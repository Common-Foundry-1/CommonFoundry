//! Authenticated external storage for an original WHIR multilinear table.
//!
//! `source_id` remains the caller-selected label used by the existing WHIR
//! artifacts. Provenance comes from the separately retained whole-artifact
//! digest in [`WhirInitialSourceArtifactIdentity`]. The writer is sequential,
//! publication is no-overwrite and atomic, and every random read
//! reauthenticates the affected bounded chunks.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use blake3::Hasher;
use thiserror::Error;

use crate::merkle_store::GOLDILOCKS_MODULUS;
use crate::whir_initial::{
    AuthenticatedWhirInitialSource, WHIR_INITIAL_MAX_SOURCE_READ_LIMBS, WHIR_INITIAL_MAX_VARIABLES,
    WHIR_INITIAL_MIN_VARIABLES, WhirInitialSourceError, WhirInitialSourceIdentity,
};

const MAGIC: &[u8; 8] = b"CMFDWIS1";
const VERSION: u32 = 1;
const NATURAL_MLE_LAYOUT: u8 = 1;
const CANONICAL_U64_LE_ENCODING: u8 = 1;
const PREFIX_BYTES: usize = 128;
const DIGEST_BYTES: usize = 32;
const HEADER_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;
const AUTH_CHUNK_ELEMENTS: usize = WHIR_INITIAL_MAX_SOURCE_READ_LIMBS;
const GLOBAL_DOMAIN: &str = "Common Foundry WHIR initial source artifact v1";
const AUTH_DOMAIN: &str = "Common Foundry WHIR initial source chunk v1";

/// Byte offset of the first canonical source limb.
pub const WHIR_INITIAL_SOURCE_HEADER_BYTES: usize = HEADER_BYTES;

/// Externally retained provenance for one exact original source artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirInitialSourceArtifactIdentity {
    pub source: WhirInitialSourceIdentity,
    pub element_count: u64,
    pub artifact_global_digest: [u8; 32],
}

#[derive(Debug, Error)]
pub enum WhirInitialSourceArtifactError {
    #[error("invalid WHIR initial source artifact: {0}")]
    Invalid(&'static str),
    #[error("WHIR initial source artifact research limit exceeded: {0}")]
    ResearchLimit(&'static str),
    #[error("WHIR initial source artifact already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("WHIR initial source artifact I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("WHIR initial source artifact checksum does not match")]
    ChecksumMismatch,
    #[error("WHIR initial source artifact identity does not match")]
    IdentityMismatch,
    #[error("WHIR initial source artifact file lock is poisoned")]
    LockPoisoned,
}

/// Sequential no-overwrite writer for one original source table.
pub struct WhirInitialSourceArtifactWriter {
    final_path: PathBuf,
    partial_path: PathBuf,
    file: Option<File>,
    prefix: [u8; PREFIX_BYTES],
    source: WhirInitialSourceIdentity,
    geometry: Geometry,
    written_elements: usize,
    poisoned: bool,
    cleanup: PartialCleanup,
}

impl std::fmt::Debug for WhirInitialSourceArtifactWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WhirInitialSourceArtifactWriter")
            .field("final_path", &self.final_path)
            .field("source", &self.source)
            .field("written_elements", &self.written_elements)
            .finish_non_exhaustive()
    }
}

impl WhirInitialSourceArtifactWriter {
    /// Create a provisional artifact. Nothing is published until [`Self::finish`].
    pub fn create(
        final_path: impl AsRef<Path>,
        source: WhirInitialSourceIdentity,
    ) -> Result<Self, WhirInitialSourceArtifactError> {
        let final_path = final_path.as_ref().to_path_buf();
        let geometry = validate_source_identity(&source)?;
        if final_path.exists() {
            return Err(WhirInitialSourceArtifactError::AlreadyExists(final_path));
        }
        let partial_path = partial_path_for(&final_path)?;
        let prefix = encode_prefix(&source, &geometry);
        let mut cleanup = PartialCleanup(None);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&partial_path)
            .map_err(|source| {
                if source.kind() == io::ErrorKind::AlreadyExists {
                    WhirInitialSourceArtifactError::AlreadyExists(partial_path.clone())
                } else {
                    io_error("creating", &partial_path, source)
                }
            })?;
        cleanup.0 = Some(partial_path.clone());
        file.write_all(&prefix)
            .and_then(|()| file.write_all(&[0_u8; DIGEST_BYTES]))
            .and_then(|()| file.set_len(HEADER_BYTES as u64 + geometry.data_bytes))
            .map_err(|source| io_error("initializing", &partial_path, source))?;
        Ok(Self {
            final_path,
            partial_path,
            file: Some(file),
            prefix,
            source,
            geometry,
            written_elements: 0,
            poisoned: false,
            cleanup,
        })
    }

    /// Append one bounded chunk of canonical Goldilocks limbs in natural MLE order.
    pub fn write_elements(&mut self, values: &[u64]) -> Result<(), WhirInitialSourceArtifactError> {
        if self.poisoned {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "source writer is poisoned after an earlier I/O failure",
            ));
        }
        if values.is_empty() {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "source write must not be empty",
            ));
        }
        if values.len() > WHIR_INITIAL_MAX_SOURCE_READ_LIMBS {
            return Err(WhirInitialSourceArtifactError::ResearchLimit(
                "source write exceeds the bounded chunk size",
            ));
        }
        let next = self.written_elements.checked_add(values.len()).ok_or(
            WhirInitialSourceArtifactError::ResearchLimit("source element count"),
        )?;
        if next > self.geometry.element_count {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "source write exceeds the declared table length",
            ));
        }
        if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "source contains a noncanonical Goldilocks value",
            ));
        }
        let mut encoded = vec![0_u8; values.len() * 8];
        for (value, bytes) in values.iter().zip(encoded.chunks_exact_mut(8)) {
            bytes.copy_from_slice(&value.to_le_bytes());
        }
        if let Err(source) = self
            .file
            .as_mut()
            .expect("unfinished source writer owns its file")
            .write_all(&encoded)
        {
            self.poisoned = true;
            return Err(io_error("writing", &self.partial_path, source));
        }
        self.written_elements = next;
        Ok(())
    }

    /// Seal, verify, and atomically publish the complete artifact.
    pub fn finish(
        mut self,
    ) -> Result<AuthenticatedWhirInitialSourceFile, WhirInitialSourceArtifactError> {
        if self.poisoned {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "source writer is poisoned after an earlier I/O failure",
            ));
        }
        if self.written_elements != self.geometry.element_count {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "source artifact is incomplete",
            ));
        }
        let mut file = self
            .file
            .take()
            .expect("unfinished source writer owns its file");
        let artifact_global_digest =
            seal_data(&mut file, &self.partial_path, &self.prefix, &self.geometry)?;
        drop(file);

        let expected = WhirInitialSourceArtifactIdentity {
            source: self.source.clone(),
            element_count: self.geometry.element_count as u64,
            artifact_global_digest,
        };
        let staged = AuthenticatedWhirInitialSourceFile::open(&self.partial_path, &expected)?;
        fs::hard_link(&self.partial_path, &self.final_path)
            .map_err(|source| io_error("publishing", &self.final_path, source))?;
        let artifact = match AuthenticatedWhirInitialSourceFile::open(&self.final_path, &expected) {
            Ok(artifact) => artifact,
            Err(error) => {
                let _ = fs::remove_file(&self.final_path);
                return Err(error);
            }
        };
        drop(staged);
        if let Err(source) = fs::remove_file(&self.partial_path) {
            let _ = fs::remove_file(&self.final_path);
            return Err(io_error(
                "removing staging file",
                &self.partial_path,
                source,
            ));
        }
        self.cleanup.0 = None;
        Ok(artifact)
    }
}

/// Fully authenticated random-access original WHIR source table.
pub struct AuthenticatedWhirInitialSourceFile {
    file: Mutex<File>,
    path: PathBuf,
    prefix: [u8; PREFIX_BYTES],
    artifact_identity: WhirInitialSourceArtifactIdentity,
    element_count: usize,
    data_bytes: u64,
    auth_digests: Vec<[u8; DIGEST_BYTES]>,
    cleanup: Option<ArtifactCleanup>,
}

impl std::fmt::Debug for AuthenticatedWhirInitialSourceFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedWhirInitialSourceFile")
            .field("path", &self.path)
            .field("artifact_identity", &self.artifact_identity)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedWhirInitialSourceFile {
    /// Open an artifact and require exact caller-retained provenance.
    pub fn open(
        path: impl AsRef<Path>,
        expected: &WhirInitialSourceArtifactIdentity,
    ) -> Result<Self, WhirInitialSourceArtifactError> {
        let artifact = Self::open_integrity_only(path.as_ref())?;
        if &artifact.artifact_identity != expected {
            return Err(WhirInitialSourceArtifactError::IdentityMismatch);
        }
        Ok(artifact)
    }

    fn open_integrity_only(path: &Path) -> Result<Self, WhirInitialSourceArtifactError> {
        let path = path.to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|source| io_error("opening", &path, source))?;
        let mut prefix = [0_u8; PREFIX_BYTES];
        file.read_exact(&mut prefix)
            .map_err(|source| io_error("reading header from", &path, source))?;
        let mut stored_global = [0_u8; DIGEST_BYTES];
        file.read_exact(&mut stored_global)
            .map_err(|source| io_error("reading digest from", &path, source))?;
        if stored_global == [0_u8; DIGEST_BYTES] {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "artifact digest must be nonzero",
            ));
        }
        let decoded = decode_prefix(&prefix)?;
        let total_bytes = total_file_bytes(&decoded)?;
        let actual_bytes = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();
        if actual_bytes != total_bytes {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "artifact length does not match header",
            ));
        }
        let auth_count = usize::try_from(decoded.auth_count)
            .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("authentication table"))?;
        let mut auth_digests = Vec::new();
        auth_digests
            .try_reserve_exact(auth_count)
            .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("authentication table"))?;
        file.seek(SeekFrom::Start(HEADER_BYTES as u64 + decoded.data_bytes))
            .and_then(|_| {
                for _ in 0..auth_count {
                    let mut digest = [0_u8; DIGEST_BYTES];
                    file.read_exact(&mut digest)?;
                    auth_digests.push(digest);
                }
                Ok(())
            })
            .map_err(|source| io_error("reading authentication table from", &path, source))?;
        authenticate_complete(
            &mut file,
            &path,
            &prefix,
            &decoded,
            &auth_digests,
            stored_global,
        )?;
        let element_count = usize::try_from(decoded.element_count)
            .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("source element count"))?;
        Ok(Self {
            file: Mutex::new(file),
            path,
            prefix,
            artifact_identity: WhirInitialSourceArtifactIdentity {
                source: decoded.source,
                element_count: decoded.element_count,
                artifact_global_digest: stored_global,
            },
            element_count,
            data_bytes: decoded.data_bytes,
            auth_digests,
            cleanup: None,
        })
    }

    pub const fn artifact_identity(&self) -> &WhirInitialSourceArtifactIdentity {
        &self.artifact_identity
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn remove_on_drop(mut self) -> Self {
        self.cleanup = Some(ArtifactCleanup(self.path.clone()));
        self
    }

    /// Typed authenticated read used by tests and higher-level storage code.
    pub fn read_authenticated_elements(
        &self,
        start: usize,
        count: usize,
    ) -> Result<Vec<u64>, WhirInitialSourceArtifactError> {
        if count == 0 {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "source read must not be empty",
            ));
        }
        if count > WHIR_INITIAL_MAX_SOURCE_READ_LIMBS {
            return Err(WhirInitialSourceArtifactError::ResearchLimit(
                "source read exceeds the bounded chunk size",
            ));
        }
        let end = start
            .checked_add(count)
            .ok_or(WhirInitialSourceArtifactError::Invalid(
                "source range overflow",
            ))?;
        if end > self.element_count {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "source range is out of bounds",
            ));
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("source read output"))?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| WhirInitialSourceArtifactError::LockPoisoned)?;
        self.verify_live_header(&mut file)?;

        let first_chunk = start / AUTH_CHUNK_ELEMENTS;
        let last_chunk = (end - 1) / AUTH_CHUNK_ELEMENTS;
        for chunk_index in first_chunk..=last_chunk {
            let chunk_start = chunk_index * AUTH_CHUNK_ELEMENTS;
            let chunk_elements = (self.element_count - chunk_start).min(AUTH_CHUNK_ELEMENTS);
            let bytes = read_data_elements(&mut file, &self.path, chunk_start, chunk_elements)?;
            validate_encoded_elements(&bytes)?;
            let expected_digest = self.auth_digests.get(chunk_index).ok_or(
                WhirInitialSourceArtifactError::Invalid(
                    "source chunk has no authentication digest",
                ),
            )?;
            if &auth_digest(&self.prefix, chunk_index, &bytes) != expected_digest {
                return Err(WhirInitialSourceArtifactError::ChecksumMismatch);
            }
            let on_disk_digest =
                read_auth_digest(&mut file, &self.path, self.data_bytes, chunk_index)?;
            if &on_disk_digest != expected_digest {
                return Err(WhirInitialSourceArtifactError::ChecksumMismatch);
            }

            let copy_start = start.max(chunk_start) - chunk_start;
            let copy_end = end.min(chunk_start + chunk_elements) - chunk_start;
            output.extend(
                bytes[copy_start * 8..copy_end * 8]
                    .chunks_exact(8)
                    .map(|chunk| {
                        u64::from_le_bytes(chunk.try_into().expect("eight-byte source limb"))
                    }),
            );
        }
        if output.len() != count {
            return Err(WhirInitialSourceArtifactError::Invalid(
                "authenticated source read returned the wrong length",
            ));
        }
        Ok(output)
    }

    fn verify_live_header(&self, file: &mut File) -> Result<(), WhirInitialSourceArtifactError> {
        let expected_bytes = (HEADER_BYTES as u64)
            .checked_add(self.data_bytes)
            .and_then(|value| value.checked_add((self.auth_digests.len() * DIGEST_BYTES) as u64))
            .ok_or(WhirInitialSourceArtifactError::Invalid(
                "artifact length overflow",
            ))?;
        let actual_bytes = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &self.path, source))?
            .len();
        if actual_bytes != expected_bytes {
            return Err(WhirInitialSourceArtifactError::ChecksumMismatch);
        }
        let mut header = [0_u8; HEADER_BYTES];
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.read_exact(&mut header))
            .map_err(|source| io_error("reauthenticating header from", &self.path, source))?;
        if header[..PREFIX_BYTES] != self.prefix
            || header[PREFIX_BYTES..] != self.artifact_identity.artifact_global_digest
        {
            return Err(WhirInitialSourceArtifactError::ChecksumMismatch);
        }
        Ok(())
    }
}

impl AuthenticatedWhirInitialSource for AuthenticatedWhirInitialSourceFile {
    fn identity(&self) -> &WhirInitialSourceIdentity {
        &self.artifact_identity.source
    }

    fn len(&self) -> usize {
        self.element_count
    }

    fn read_elements(
        &self,
        start: usize,
        count: usize,
    ) -> Result<Vec<u64>, WhirInitialSourceError> {
        self.read_authenticated_elements(start, count)
            .map_err(|error| WhirInitialSourceError::new(error.to_string()))
    }
}

#[derive(Clone, Copy)]
struct Geometry {
    element_count: usize,
    data_bytes: u64,
    auth_count: u64,
}

fn validate_source_identity(
    source: &WhirInitialSourceIdentity,
) -> Result<Geometry, WhirInitialSourceArtifactError> {
    if source.source_id == [0_u8; 32] {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "source ID must be nonzero",
        ));
    }
    let variables = usize::try_from(source.num_variables)
        .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("variable count"))?;
    if variables < WHIR_INITIAL_MIN_VARIABLES {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "num_variables is smaller than folding",
        ));
    }
    if variables > WHIR_INITIAL_MAX_VARIABLES {
        return Err(WhirInitialSourceArtifactError::ResearchLimit(
            "num_variables exceeds 19",
        ));
    }
    let element_count = 1_usize.checked_shl(source.num_variables).ok_or(
        WhirInitialSourceArtifactError::ResearchLimit("source element count"),
    )?;
    let data_bytes = element_count
        .checked_mul(8)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(WhirInitialSourceArtifactError::ResearchLimit(
            "source artifact byte length",
        ))?;
    let auth_count = u64::try_from(element_count.div_ceil(AUTH_CHUNK_ELEMENTS))
        .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("authentication table"))?;
    Ok(Geometry {
        element_count,
        data_bytes,
        auth_count,
    })
}

fn seal_data(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    geometry: &Geometry,
) -> Result<[u8; 32], WhirInitialSourceArtifactError> {
    file.sync_data()
        .map_err(|source| io_error("synchronizing staged data for", path, source))?;
    let mut global = Hasher::new_derive_key(GLOBAL_DOMAIN);
    global.update(prefix);
    let auth_count = usize::try_from(geometry.auth_count)
        .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("authentication table"))?;
    let mut auth_digests = Vec::new();
    auth_digests
        .try_reserve_exact(auth_count)
        .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("authentication table"))?;
    for (chunk_index, start) in (0..geometry.element_count)
        .step_by(AUTH_CHUNK_ELEMENTS)
        .enumerate()
    {
        let count = (geometry.element_count - start).min(AUTH_CHUNK_ELEMENTS);
        let bytes = read_data_elements(file, path, start, count)?;
        validate_encoded_elements(&bytes)?;
        global.update(&bytes);
        auth_digests.push(auth_digest(prefix, chunk_index, &bytes));
    }
    file.seek(SeekFrom::Start(HEADER_BYTES as u64 + geometry.data_bytes))
        .map_err(|source| io_error("seeking in", path, source))?;
    for digest in &auth_digests {
        file.write_all(digest)
            .map_err(|source| io_error("writing authentication table to", path, source))?;
        global.update(digest);
    }
    let global_digest = *global.finalize().as_bytes();
    file.seek(SeekFrom::Start(PREFIX_BYTES as u64))
        .and_then(|_| file.write_all(&global_digest))
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("sealing", path, source))?;
    Ok(global_digest)
}

fn authenticate_complete(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    decoded: &DecodedPrefix,
    auth_digests: &[[u8; DIGEST_BYTES]],
    expected_global: [u8; DIGEST_BYTES],
) -> Result<(), WhirInitialSourceArtifactError> {
    if auth_digests.len() != decoded.auth_count as usize {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "authentication table length does not match header",
        ));
    }
    let element_count = usize::try_from(decoded.element_count)
        .map_err(|_| WhirInitialSourceArtifactError::ResearchLimit("source element count"))?;
    let mut global = Hasher::new_derive_key(GLOBAL_DOMAIN);
    global.update(prefix);
    for (chunk_index, start) in (0..element_count).step_by(AUTH_CHUNK_ELEMENTS).enumerate() {
        let count = (element_count - start).min(AUTH_CHUNK_ELEMENTS);
        let bytes = read_data_elements(file, path, start, count)?;
        validate_encoded_elements(&bytes)?;
        if auth_digest(prefix, chunk_index, &bytes) != auth_digests[chunk_index] {
            return Err(WhirInitialSourceArtifactError::ChecksumMismatch);
        }
        global.update(&bytes);
    }
    for digest in auth_digests {
        global.update(digest);
    }
    if *global.finalize().as_bytes() != expected_global {
        return Err(WhirInitialSourceArtifactError::ChecksumMismatch);
    }
    Ok(())
}

fn auth_digest(prefix: &[u8; PREFIX_BYTES], chunk_index: usize, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(AUTH_DOMAIN);
    hasher.update(prefix);
    hasher.update(&(chunk_index as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn read_data_elements(
    file: &mut File,
    path: &Path,
    start: usize,
    count: usize,
) -> Result<Vec<u8>, WhirInitialSourceArtifactError> {
    let byte_count = count
        .checked_mul(8)
        .ok_or(WhirInitialSourceArtifactError::Invalid(
            "source byte count overflow",
        ))?;
    let mut bytes = vec![0_u8; byte_count];
    file.seek(SeekFrom::Start(data_offset(start)?))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|source| io_error("reading authenticated source from", path, source))?;
    Ok(bytes)
}

fn read_auth_digest(
    file: &mut File,
    path: &Path,
    data_bytes: u64,
    chunk_index: usize,
) -> Result<[u8; DIGEST_BYTES], WhirInitialSourceArtifactError> {
    let offset = (HEADER_BYTES as u64)
        .checked_add(data_bytes)
        .and_then(|value| value.checked_add((chunk_index * DIGEST_BYTES) as u64))
        .ok_or(WhirInitialSourceArtifactError::Invalid(
            "authentication digest offset overflow",
        ))?;
    let mut digest = [0_u8; DIGEST_BYTES];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut digest))
        .map_err(|source| io_error("reading authentication digest from", path, source))?;
    Ok(digest)
}

fn validate_encoded_elements(bytes: &[u8]) -> Result<(), WhirInitialSourceArtifactError> {
    if !bytes.len().is_multiple_of(8) {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "source bytes are not aligned",
        ));
    }
    if bytes.chunks_exact(8).any(|chunk| {
        u64::from_le_bytes(chunk.try_into().expect("eight-byte source limb")) >= GOLDILOCKS_MODULUS
    }) {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "artifact contains a noncanonical Goldilocks value",
        ));
    }
    Ok(())
}

fn data_offset(element: usize) -> Result<u64, WhirInitialSourceArtifactError> {
    element
        .checked_mul(8)
        .and_then(|offset| offset.checked_add(HEADER_BYTES))
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(WhirInitialSourceArtifactError::Invalid(
            "source offset overflow",
        ))
}

fn total_file_bytes(decoded: &DecodedPrefix) -> Result<u64, WhirInitialSourceArtifactError> {
    (HEADER_BYTES as u64)
        .checked_add(decoded.data_bytes)
        .and_then(|value| value.checked_add(decoded.auth_count * DIGEST_BYTES as u64))
        .ok_or(WhirInitialSourceArtifactError::Invalid(
            "artifact length overflow",
        ))
}

fn encode_prefix(source: &WhirInitialSourceIdentity, geometry: &Geometry) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    prefix[..8].copy_from_slice(MAGIC);
    prefix[8..12].copy_from_slice(&VERSION.to_le_bytes());
    prefix[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    prefix[16..48].copy_from_slice(&source.source_id);
    prefix[48..52].copy_from_slice(&source.num_variables.to_le_bytes());
    prefix[52] = NATURAL_MLE_LAYOUT;
    prefix[53] = CANONICAL_U64_LE_ENCODING;
    prefix[56..64].copy_from_slice(&(geometry.element_count as u64).to_le_bytes());
    prefix[64..72].copy_from_slice(&geometry.data_bytes.to_le_bytes());
    prefix[72..80].copy_from_slice(&geometry.auth_count.to_le_bytes());
    prefix[80..88].copy_from_slice(&(AUTH_CHUNK_ELEMENTS as u64).to_le_bytes());
    prefix
}

struct DecodedPrefix {
    source: WhirInitialSourceIdentity,
    element_count: u64,
    data_bytes: u64,
    auth_count: u64,
}

fn decode_prefix(
    prefix: &[u8; PREFIX_BYTES],
) -> Result<DecodedPrefix, WhirInitialSourceArtifactError> {
    if &prefix[..8] != MAGIC {
        return Err(WhirInitialSourceArtifactError::Invalid("wrong magic"));
    }
    if read_u32(prefix, 8) != VERSION || read_u32(prefix, 12) != HEADER_BYTES as u32 {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "unsupported version or header length",
        ));
    }
    if prefix[52] != NATURAL_MLE_LAYOUT
        || prefix[53] != CANONICAL_U64_LE_ENCODING
        || prefix[54..56] != [0_u8; 2]
        || prefix[88..].iter().any(|byte| *byte != 0)
    {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "source layout, encoding, or reserved bytes are invalid",
        ));
    }
    if read_u64(prefix, 80) != AUTH_CHUNK_ELEMENTS as u64 {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "authentication chunk size is not canonical",
        ));
    }
    let source = WhirInitialSourceIdentity {
        source_id: prefix[16..48].try_into().expect("32-byte source ID"),
        num_variables: read_u32(prefix, 48),
    };
    let geometry = validate_source_identity(&source)?;
    let element_count = read_u64(prefix, 56);
    let data_bytes = read_u64(prefix, 64);
    let auth_count = read_u64(prefix, 72);
    if element_count != geometry.element_count as u64
        || data_bytes != geometry.data_bytes
        || auth_count != geometry.auth_count
    {
        return Err(WhirInitialSourceArtifactError::Invalid(
            "source geometry does not match num_variables",
        ));
    }
    Ok(DecodedPrefix {
        source,
        element_count,
        data_bytes,
        auth_count,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed source u32 slice"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed source u64 slice"),
    )
}

fn partial_path_for(path: &Path) -> Result<PathBuf, WhirInitialSourceArtifactError> {
    let name = path
        .file_name()
        .ok_or(WhirInitialSourceArtifactError::Invalid(
            "artifact path has no file name",
        ))?;
    let mut partial = name.to_os_string();
    partial.push(".partial");
    Ok(path.with_file_name(partial))
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> WhirInitialSourceArtifactError {
    WhirInitialSourceArtifactError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

struct PartialCleanup(Option<PathBuf>);

impl Drop for PartialCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

struct ArtifactCleanup(PathBuf);

impl Drop for ArtifactCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-whir-source-{label}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn source_identity(variables: u32, seed: u8) -> WhirInitialSourceIdentity {
        WhirInitialSourceIdentity {
            source_id: [seed; 32],
            num_variables: variables,
        }
    }

    fn values(variables: u32, salt: u64) -> Vec<u64> {
        (0..1_usize << variables)
            .map(|index| {
                (salt.wrapping_add((index as u64).wrapping_mul(0x9e37_79b9))) % GOLDILOCKS_MODULUS
            })
            .collect()
    }

    fn build(
        path: &Path,
        source: WhirInitialSourceIdentity,
        values: &[u64],
    ) -> AuthenticatedWhirInitialSourceFile {
        let mut writer = WhirInitialSourceArtifactWriter::create(path, source).unwrap();
        for chunk in values.chunks(997) {
            writer.write_elements(chunk).unwrap();
        }
        writer.finish().unwrap()
    }

    #[test]
    fn streamed_artifact_round_trips_and_bounds_random_reads() {
        let path = test_path("round-trip");
        let source = source_identity(14, 0x21);
        let expected_values = values(14, 17);
        let artifact = build(&path, source.clone(), &expected_values);
        assert_eq!(artifact.identity(), &source);
        assert_eq!(artifact.len(), expected_values.len());
        assert_eq!(
            artifact.read_authenticated_elements(7_900, 700).unwrap(),
            expected_values[7_900..8_600]
        );
        assert_eq!(
            artifact
                .read_authenticated_elements(1, WHIR_INITIAL_MAX_SOURCE_READ_LIMBS)
                .unwrap(),
            expected_values[1..1 + WHIR_INITIAL_MAX_SOURCE_READ_LIMBS]
        );
        let identity = artifact.artifact_identity().clone();
        drop(artifact);
        let reopened = AuthenticatedWhirInitialSourceFile::open(&path, &identity).unwrap();
        assert_eq!(
            reopened.read_authenticated_elements(31, 19).unwrap(),
            expected_values[31..50]
        );
        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn retained_digest_rejects_same_label_whole_source_substitution() {
        let original_path = test_path("original");
        let substitute_path = test_path("substitute");
        let source = source_identity(8, 0x31);
        let original = build(&original_path, source.clone(), &values(8, 11));
        let expected = original.artifact_identity().clone();
        let substitute = build(&substitute_path, source, &values(8, 12));
        assert_ne!(
            substitute.artifact_identity().artifact_global_digest,
            expected.artifact_global_digest
        );
        drop(original);
        drop(substitute);
        assert!(matches!(
            AuthenticatedWhirInitialSourceFile::open(&substitute_path, &expected),
            Err(WhirInitialSourceArtifactError::IdentityMismatch)
        ));
        fs::remove_file(original_path).unwrap();
        fs::remove_file(substitute_path).unwrap();
    }

    #[test]
    fn corruption_truncation_append_and_post_open_mutation_fail_closed() {
        let path = test_path("mutation");
        let source = source_identity(8, 0x41);
        let artifact = build(&path, source, &values(8, 21));
        let expected = artifact.artifact_identity().clone();
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        writer
            .seek(SeekFrom::Start(HEADER_BYTES as u64 + 8))
            .unwrap();
        writer.write_all(&123_u64.to_le_bytes()).unwrap();
        writer.sync_all().unwrap();
        assert!(matches!(
            artifact.read_authenticated_elements(0, 4),
            Err(WhirInitialSourceArtifactError::ChecksumMismatch)
        ));
        drop(artifact);
        assert!(matches!(
            AuthenticatedWhirInitialSourceFile::open(&path, &expected),
            Err(WhirInitialSourceArtifactError::ChecksumMismatch)
        ));
        fs::remove_file(&path).unwrap();

        let artifact = build(&path, source_identity(8, 0x42), &values(8, 22));
        let expected = artifact.artifact_identity().clone();
        drop(artifact);
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(HEADER_BYTES as u64 + 8).unwrap();
        drop(file);
        assert!(matches!(
            AuthenticatedWhirInitialSourceFile::open(&path, &expected),
            Err(WhirInitialSourceArtifactError::Invalid(_))
        ));
        fs::remove_file(&path).unwrap();

        let artifact = build(&path, source_identity(8, 0x43), &values(8, 23));
        let expected = artifact.artifact_identity().clone();
        drop(artifact);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert!(matches!(
            AuthenticatedWhirInitialSourceFile::open(&path, &expected),
            Err(WhirInitialSourceArtifactError::Invalid(_))
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn post_open_header_and_auth_table_mutations_are_detected() {
        let path = test_path("live-metadata-mutation");
        let source = source_identity(8, 0x49);
        let artifact = build(&path, source, &values(8, 29));
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        writer.seek(SeekFrom::Start(52)).unwrap();
        writer.write_all(&[NATURAL_MLE_LAYOUT ^ 1]).unwrap();
        writer.sync_all().unwrap();
        assert!(matches!(
            artifact.read_authenticated_elements(0, 1),
            Err(WhirInitialSourceArtifactError::ChecksumMismatch)
        ));
        drop(artifact);
        fs::remove_file(&path).unwrap();

        let artifact = build(&path, source_identity(8, 0x4a), &values(8, 30));
        let auth_offset = HEADER_BYTES as u64 + artifact.data_bytes;
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        writer.seek(SeekFrom::Start(auth_offset)).unwrap();
        writer.write_all(&[0xff]).unwrap();
        writer.sync_all().unwrap();
        assert!(matches!(
            artifact.read_authenticated_elements(0, 1),
            Err(WhirInitialSourceArtifactError::ChecksumMismatch)
        ));
        drop(artifact);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn invalid_writes_reads_and_existing_targets_are_rejected_before_mutation() {
        let path = test_path("invalid");
        fs::write(&path, b"keep").unwrap();
        assert!(matches!(
            WhirInitialSourceArtifactWriter::create(&path, source_identity(4, 0x51)),
            Err(WhirInitialSourceArtifactError::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        fs::remove_file(&path).unwrap();

        let mut first =
            WhirInitialSourceArtifactWriter::create(&path, source_identity(2, 0x50)).unwrap();
        assert!(matches!(
            WhirInitialSourceArtifactWriter::create(&path, source_identity(2, 0x50)),
            Err(WhirInitialSourceArtifactError::AlreadyExists(_))
        ));
        assert!(partial_path_for(&path).unwrap().exists());
        first.write_elements(&[1, 2, 3, 4]).unwrap();
        drop(first.finish().unwrap());
        fs::remove_file(&path).unwrap();

        assert!(matches!(
            WhirInitialSourceArtifactWriter::create(&path, source_identity(20, 0x52)),
            Err(WhirInitialSourceArtifactError::ResearchLimit(_))
        ));
        assert!(!path.exists());

        let mut raced =
            WhirInitialSourceArtifactWriter::create(&path, source_identity(2, 0x55)).unwrap();
        raced.write_elements(&[1, 2, 3, 4]).unwrap();
        fs::write(&path, b"keep-race-winner").unwrap();
        assert!(raced.finish().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep-race-winner");
        fs::remove_file(&path).unwrap();
        assert!(!partial_path_for(&path).unwrap().exists());

        let mut writer =
            WhirInitialSourceArtifactWriter::create(&path, source_identity(2, 0x53)).unwrap();
        assert!(matches!(
            writer.write_elements(&[GOLDILOCKS_MODULUS]),
            Err(WhirInitialSourceArtifactError::Invalid(_))
        ));
        writer.write_elements(&[1, 2]).unwrap();
        assert!(matches!(
            writer.finish(),
            Err(WhirInitialSourceArtifactError::Invalid(_))
        ));
        assert!(!path.exists());
        assert!(!partial_path_for(&path).unwrap().exists());

        let artifact = build(&path, source_identity(4, 0x54), &values(4, 1)).remove_on_drop();
        assert!(matches!(
            artifact.read_authenticated_elements(0, 0),
            Err(WhirInitialSourceArtifactError::Invalid(_))
        ));
        assert!(matches!(
            artifact.read_authenticated_elements(0, WHIR_INITIAL_MAX_SOURCE_READ_LIMBS + 1),
            Err(WhirInitialSourceArtifactError::ResearchLimit(_))
        ));
        assert!(matches!(
            artifact.read_authenticated_elements(15, 2),
            Err(WhirInitialSourceArtifactError::Invalid(_))
        ));
    }
}
