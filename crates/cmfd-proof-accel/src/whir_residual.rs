//! Authenticated ephemeral storage for a WHIR residual product polynomial.
//!
//! Rows are stored in natural suffix order as three canonical Goldilocks limbs
//! for the evaluation followed by three limbs for the weight. The artifact is
//! prover-local scratch: its identity is never absorbed into Fiat-Shamir.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use blake3::Hasher;
use same_file::Handle;
use thiserror::Error;

use crate::merkle_store::GOLDILOCKS_MODULUS;

const MAGIC: &[u8; 8] = b"CMFDWRP1";
const VERSION: u32 = 1;
const NATURAL_SUFFIX_LAYOUT: u8 = 1;
const CANONICAL_U64_LE_ENCODING: u8 = 1;
const PREFIX_BYTES: usize = 128;
const DIGEST_BYTES: usize = 32;
const HEADER_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;
const AUTH_CHUNK_ROWS: u64 = 8 * 1024;
const GLOBAL_DOMAIN: &str = "Common Foundry WHIR residual product artifact v1";
const AUTH_DOMAIN: &str = "Common Foundry WHIR residual product chunk v1";
const CREATE_ATTEMPTS: usize = 256;
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Three evaluation limbs followed by three weight limbs.
pub const WHIR_RESIDUAL_LIMBS_PER_ROW: usize = 6;
/// Largest authenticated row request and writer chunk.
pub const WHIR_RESIDUAL_MAX_IO_ROWS: usize = AUTH_CHUNK_ROWS as usize;
/// The production weight-bank residual after the fixed two-variable fold.
pub const WHIR_RESIDUAL_MAX_VARIABLES: usize = 29;

static NEXT_ARTIFACT: AtomicU64 = AtomicU64::new(0);

/// Transcript-independent local context for one residual generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirResidualArtifactSpec {
    /// Digest of the exact authenticated source/prover capability.
    pub source_digest: [u8; 32],
    /// Digest of the ordered claims and challenges that produced this state.
    pub context_digest: [u8; 32],
    /// Number of unbound variables represented by the rows.
    pub num_variables: u32,
    /// Zero for the initial residual and incremented after each disk fold.
    pub generation: u32,
}

/// Checked file geometry. Computing it never allocates proportional to rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhirResidualGeometry {
    pub row_count: u64,
    pub data_bytes: u64,
    pub authentication_chunks: u64,
    pub artifact_bytes: u64,
}

/// Caller-retained identity required to reopen an exact residual artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirResidualArtifactIdentity {
    pub spec: WhirResidualArtifactSpec,
    pub row_count: u64,
    pub artifact_digest: [u8; 32],
}

#[derive(Debug, Error)]
pub enum WhirResidualArtifactError {
    #[error("invalid WHIR residual artifact: {0}")]
    Invalid(&'static str),
    #[error("WHIR residual artifact research limit exceeded: {0}")]
    ResearchLimit(&'static str),
    #[error("WHIR residual scratch directory must be absolute and already exist: {0}")]
    InvalidScratchDirectory(PathBuf),
    #[error(
        "WHIR residual scratch directory has insufficient free space: need {required} bytes, have {available} bytes"
    )]
    InsufficientSpace { required: u64, available: u64 },
    #[error("could not allocate a unique WHIR residual artifact in {0}")]
    NameExhausted(PathBuf),
    #[error("WHIR residual artifact I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("WHIR residual artifact checksum does not match")]
    ChecksumMismatch,
    #[error("WHIR residual artifact identity does not match")]
    IdentityMismatch,
    #[error("WHIR residual cleanup path no longer names the owned file: {0}")]
    CleanupTargetChanged(PathBuf),
    #[error("WHIR residual artifact file lock is poisoned")]
    LockPoisoned,
}

/// Validate a residual shape without allocating its rows.
pub fn whir_residual_geometry(
    spec: &WhirResidualArtifactSpec,
) -> Result<WhirResidualGeometry, WhirResidualArtifactError> {
    let num_variables = usize::try_from(spec.num_variables)
        .map_err(|_| WhirResidualArtifactError::ResearchLimit("variable count"))?;
    if num_variables > WHIR_RESIDUAL_MAX_VARIABLES {
        return Err(WhirResidualArtifactError::ResearchLimit(
            "residual variable count exceeds 29",
        ));
    }
    let row_count = 1_u64
        .checked_shl(spec.num_variables)
        .ok_or(WhirResidualArtifactError::ResearchLimit("row count"))?;
    let row_bytes = (WHIR_RESIDUAL_LIMBS_PER_ROW as u64)
        .checked_mul(size_of::<u64>() as u64)
        .ok_or(WhirResidualArtifactError::ResearchLimit("row byte width"))?;
    let data_bytes = row_count
        .checked_mul(row_bytes)
        .ok_or(WhirResidualArtifactError::ResearchLimit("data byte length"))?;
    let authentication_chunks = row_count.div_ceil(AUTH_CHUNK_ROWS);
    let authentication_bytes = authentication_chunks
        .checked_mul(DIGEST_BYTES as u64)
        .ok_or(WhirResidualArtifactError::ResearchLimit(
            "authentication byte length",
        ))?;
    let artifact_bytes = (HEADER_BYTES as u64)
        .checked_add(data_bytes)
        .and_then(|bytes| bytes.checked_add(authentication_bytes))
        .ok_or(WhirResidualArtifactError::ResearchLimit(
            "artifact byte length",
        ))?;
    Ok(WhirResidualGeometry {
        row_count,
        data_bytes,
        authentication_chunks,
        artifact_bytes,
    })
}

/// Sequential, no-overwrite writer for one owned scratch artifact.
pub struct WhirResidualArtifactWriter {
    partial_path: PathBuf,
    final_path: PathBuf,
    file: Option<File>,
    spec: WhirResidualArtifactSpec,
    geometry: WhirResidualGeometry,
    prefix: [u8; PREFIX_BYTES],
    rows_written: u64,
    global_hasher: Hasher,
    chunk_hasher: Hasher,
    chunk_rows: u64,
    authentication_digests: Vec<[u8; DIGEST_BYTES]>,
    poisoned: bool,
    published: bool,
}

impl std::fmt::Debug for WhirResidualArtifactWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WhirResidualArtifactWriter")
            .field("partial_path", &self.partial_path)
            .field("final_path", &self.final_path)
            .field("spec", &self.spec)
            .field("rows_written", &self.rows_written)
            .finish_non_exhaustive()
    }
}

impl WhirResidualArtifactWriter {
    /// Create a uniquely named provisional artifact in an existing absolute directory.
    ///
    /// The directory is a local prover scratch namespace. Its generated
    /// `cmfd-whir-residual-*` entries must not be renamed or replaced by other
    /// code while writers or artifacts are live. Cleanup verifies file
    /// identity before deleting as defense in depth, but that check and unlink
    /// are not one portable atomic filesystem operation.
    pub fn create(
        scratch_directory: impl AsRef<Path>,
        spec: WhirResidualArtifactSpec,
    ) -> Result<Self, WhirResidualArtifactError> {
        let scratch_directory = scratch_directory.as_ref();
        if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
            return Err(WhirResidualArtifactError::InvalidScratchDirectory(
                scratch_directory.to_path_buf(),
            ));
        }
        let geometry = whir_residual_geometry(&spec)?;
        let available = fs2::available_space(scratch_directory)
            .map_err(|source| io_error("checking free space in", scratch_directory, source))?;
        if available < geometry.artifact_bytes {
            return Err(WhirResidualArtifactError::InsufficientSpace {
                required: geometry.artifact_bytes,
                available,
            });
        }

        for _ in 0..CREATE_ATTEMPTS {
            let sequence = NEXT_ARTIFACT.fetch_add(1, Ordering::Relaxed);
            let stem = format!("cmfd-whir-residual-{}-{sequence}", std::process::id());
            let partial_path = scratch_directory.join(format!("{stem}.partial"));
            let final_path = scratch_directory.join(format!("{stem}.artifact"));
            if final_path.exists() {
                continue;
            }
            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&partial_path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(io_error("creating", &partial_path, source)),
            };
            return Self::initialize(file, partial_path, final_path, spec, geometry);
        }
        Err(WhirResidualArtifactError::NameExhausted(
            scratch_directory.to_path_buf(),
        ))
    }

    fn initialize(
        mut file: File,
        partial_path: PathBuf,
        final_path: PathBuf,
        spec: WhirResidualArtifactSpec,
        geometry: WhirResidualGeometry,
    ) -> Result<Self, WhirResidualArtifactError> {
        let prefix = encode_prefix(&spec, &geometry);
        if let Err(source) = file
            .write_all(&prefix)
            .and_then(|()| file.write_all(&[0_u8; DIGEST_BYTES]))
        {
            let _ = remove_owned_file(&partial_path, &file);
            return Err(io_error("initializing", &partial_path, source));
        }
        let mut global_hasher = Hasher::new_derive_key(GLOBAL_DOMAIN);
        global_hasher.update(&prefix);
        let chunk_hasher = new_chunk_hasher(&prefix, 0);
        let auth_capacity = usize::try_from(geometry.authentication_chunks)
            .map_err(|_| WhirResidualArtifactError::ResearchLimit("authentication digest count"))?;
        let mut authentication_digests = Vec::new();
        if authentication_digests
            .try_reserve_exact(auth_capacity)
            .is_err()
        {
            let _ = remove_owned_file(&partial_path, &file);
            return Err(WhirResidualArtifactError::ResearchLimit(
                "authentication digest allocation",
            ));
        }
        Ok(Self {
            partial_path,
            final_path,
            file: Some(file),
            spec,
            geometry,
            prefix,
            rows_written: 0,
            global_hasher,
            chunk_hasher,
            chunk_rows: 0,
            authentication_digests,
            poisoned: false,
            published: false,
        })
    }

    pub const fn rows_written(&self) -> u64 {
        self.rows_written
    }

    pub const fn geometry(&self) -> WhirResidualGeometry {
        self.geometry
    }

    /// Append complete canonical rows at the exact next natural-order index.
    pub fn write_rows(
        &mut self,
        row_start: u64,
        rows: &[[u64; WHIR_RESIDUAL_LIMBS_PER_ROW]],
    ) -> Result<(), WhirResidualArtifactError> {
        if self.poisoned {
            return Err(WhirResidualArtifactError::Invalid(
                "writer is poisoned after an earlier I/O failure",
            ));
        }
        if row_start != self.rows_written {
            return Err(WhirResidualArtifactError::Invalid(
                "row start does not match the next expected row",
            ));
        }
        if rows.is_empty() {
            return Err(WhirResidualArtifactError::Invalid(
                "row write must not be empty",
            ));
        }
        if rows.len() > WHIR_RESIDUAL_MAX_IO_ROWS {
            return Err(WhirResidualArtifactError::ResearchLimit(
                "row write exceeds the bounded chunk size",
            ));
        }
        if rows
            .iter()
            .flatten()
            .any(|&value| value >= GOLDILOCKS_MODULUS)
        {
            return Err(WhirResidualArtifactError::Invalid(
                "row contains a noncanonical Goldilocks limb",
            ));
        }
        let row_count = u64::try_from(rows.len())
            .map_err(|_| WhirResidualArtifactError::ResearchLimit("row count"))?;
        let end = row_start
            .checked_add(row_count)
            .ok_or(WhirResidualArtifactError::ResearchLimit("row range"))?;
        if end > self.geometry.row_count {
            return Err(WhirResidualArtifactError::Invalid(
                "row write exceeds the declared artifact",
            ));
        }

        let mut offset = 0_usize;
        while offset < rows.len() {
            let chunk_remaining = usize::try_from(AUTH_CHUNK_ROWS - self.chunk_rows)
                .expect("bounded authentication chunk fits usize");
            let take = chunk_remaining.min(rows.len() - offset);
            if let Err(error) = self.write_encoded_rows(&rows[offset..offset + take]) {
                self.poisoned = true;
                return Err(error);
            }
            self.chunk_rows += take as u64;
            offset += take;
            if self.chunk_rows == AUTH_CHUNK_ROWS {
                self.finish_authentication_chunk();
            }
        }
        self.rows_written = end;
        Ok(())
    }

    fn write_encoded_rows(
        &mut self,
        rows: &[[u64; WHIR_RESIDUAL_LIMBS_PER_ROW]],
    ) -> Result<(), WhirResidualArtifactError> {
        let byte_len = rows
            .len()
            .checked_mul(WHIR_RESIDUAL_LIMBS_PER_ROW)
            .and_then(|limbs| limbs.checked_mul(size_of::<u64>()))
            .ok_or(WhirResidualArtifactError::ResearchLimit(
                "encoded row chunk size",
            ))?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(byte_len)
            .map_err(|_| WhirResidualArtifactError::ResearchLimit("encoded row allocation"))?;
        for row in rows {
            for limb in row {
                encoded.extend_from_slice(&limb.to_le_bytes());
            }
        }
        let file = self.file.as_mut().expect("unfinished writer owns its file");
        file.write_all(&encoded)
            .map_err(|source| io_error("writing", &self.partial_path, source))?;
        self.global_hasher.update(&encoded);
        self.chunk_hasher.update(&encoded);
        Ok(())
    }

    fn finish_authentication_chunk(&mut self) {
        self.authentication_digests
            .push(*self.chunk_hasher.finalize().as_bytes());
        self.chunk_rows = 0;
        self.chunk_hasher =
            new_chunk_hasher(&self.prefix, self.authentication_digests.len() as u64);
    }

    /// Seal, fully verify, publish without overwrite, and return an owned capability.
    pub fn finish(
        mut self,
    ) -> Result<AuthenticatedWhirResidualArtifact, WhirResidualArtifactError> {
        if self.poisoned {
            return Err(WhirResidualArtifactError::Invalid(
                "writer is poisoned after an earlier I/O failure",
            ));
        }
        if self.rows_written != self.geometry.row_count {
            return Err(WhirResidualArtifactError::Invalid(
                "residual artifact is incomplete",
            ));
        }
        if self.chunk_rows != 0 {
            self.finish_authentication_chunk();
        }
        if self.authentication_digests.len() as u64 != self.geometry.authentication_chunks {
            return Err(WhirResidualArtifactError::Invalid(
                "authentication chunk count is inconsistent",
            ));
        }

        let file = self.file.as_mut().expect("unfinished writer owns its file");
        for digest in &self.authentication_digests {
            if let Err(source) = file.write_all(digest) {
                self.poisoned = true;
                return Err(io_error(
                    "writing authentication table to",
                    &self.partial_path,
                    source,
                ));
            }
            self.global_hasher.update(digest);
        }
        let artifact_digest = *self.global_hasher.finalize().as_bytes();
        file.seek(SeekFrom::Start(PREFIX_BYTES as u64))
            .and_then(|_| file.write_all(&artifact_digest))
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error("sealing", &self.partial_path, source))?;
        let expected = WhirResidualArtifactIdentity {
            spec: self.spec.clone(),
            row_count: self.geometry.row_count,
            artifact_digest,
        };
        let staged = AuthenticatedWhirResidualArtifact::open(&self.partial_path, &expected)?;
        drop(staged);
        fs::hard_link(&self.partial_path, &self.final_path)
            .map_err(|source| io_error("publishing", &self.final_path, source))?;
        let writer_file = self.file.as_ref().expect("sealed writer owns its file");
        if let Err(error) = remove_owned_file(&self.partial_path, writer_file) {
            let _ = remove_owned_file(&self.final_path, writer_file);
            return Err(error);
        }
        let mut published =
            match AuthenticatedWhirResidualArtifact::open(&self.final_path, &expected) {
                Ok(artifact) => artifact,
                Err(error) => {
                    let writer_file = self.file.as_ref().expect("sealed writer owns its file");
                    let _ = remove_owned_file(&self.final_path, writer_file);
                    return Err(error);
                }
            };
        self.file.take();
        self.published = true;
        published.cleanup_path = Some(self.final_path.clone());
        Ok(published)
    }
}

impl Drop for WhirResidualArtifactWriter {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let Some(file) = self.file.take() else {
            return;
        };
        let _ = remove_owned_file(&self.partial_path, &file);
    }
}

/// Fully authenticated random-access residual product artifact.
pub struct AuthenticatedWhirResidualArtifact {
    file: Option<Mutex<File>>,
    path: PathBuf,
    prefix: [u8; PREFIX_BYTES],
    identity: WhirResidualArtifactIdentity,
    geometry: WhirResidualGeometry,
    authentication_digests: Vec<[u8; DIGEST_BYTES]>,
    cleanup_path: Option<PathBuf>,
}

impl std::fmt::Debug for AuthenticatedWhirResidualArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedWhirResidualArtifact")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedWhirResidualArtifact {
    /// Open and fully authenticate an artifact against an external identity.
    pub fn open(
        path: impl AsRef<Path>,
        expected: &WhirResidualArtifactIdentity,
    ) -> Result<Self, WhirResidualArtifactError> {
        let artifact = Self::open_integrity_only(path.as_ref())?;
        if &artifact.identity != expected {
            return Err(WhirResidualArtifactError::IdentityMismatch);
        }
        Ok(artifact)
    }

    fn open_integrity_only(path: &Path) -> Result<Self, WhirResidualArtifactError> {
        let path = path.to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|source| io_error("opening", &path, source))?;
        let mut prefix = [0_u8; PREFIX_BYTES];
        file.read_exact(&mut prefix)
            .map_err(|source| io_error("reading header from", &path, source))?;
        let mut stored_digest = [0_u8; DIGEST_BYTES];
        file.read_exact(&mut stored_digest)
            .map_err(|source| io_error("reading digest from", &path, source))?;
        let (spec, geometry) = decode_prefix(&prefix)?;
        let actual_bytes = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();
        if actual_bytes != geometry.artifact_bytes {
            return Err(WhirResidualArtifactError::ChecksumMismatch);
        }

        let mut global_hasher = Hasher::new_derive_key(GLOBAL_DOMAIN);
        global_hasher.update(&prefix);
        let mut remaining = geometry.data_bytes;
        let mut buffer = [0_u8; READ_BUFFER_BYTES];
        while remaining != 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("bounded read size fits usize");
            file.read_exact(&mut buffer[..take])
                .map_err(|source| io_error("authenticating", &path, source))?;
            global_hasher.update(&buffer[..take]);
            remaining -= take as u64;
        }
        let auth_count = usize::try_from(geometry.authentication_chunks)
            .map_err(|_| WhirResidualArtifactError::ResearchLimit("authentication digest count"))?;
        let mut authentication_digests = Vec::new();
        authentication_digests
            .try_reserve_exact(auth_count)
            .map_err(|_| {
                WhirResidualArtifactError::ResearchLimit("authentication digest allocation")
            })?;
        for _ in 0..auth_count {
            let mut digest = [0_u8; DIGEST_BYTES];
            file.read_exact(&mut digest)
                .map_err(|source| io_error("reading authentication table from", &path, source))?;
            global_hasher.update(&digest);
            authentication_digests.push(digest);
        }
        if global_hasher.finalize().as_bytes() != &stored_digest {
            return Err(WhirResidualArtifactError::ChecksumMismatch);
        }
        Ok(Self {
            file: Some(Mutex::new(file)),
            path,
            prefix,
            identity: WhirResidualArtifactIdentity {
                spec,
                row_count: geometry.row_count,
                artifact_digest: stored_digest,
            },
            geometry,
            authentication_digests,
            cleanup_path: None,
        })
    }

    pub const fn identity(&self) -> &WhirResidualArtifactIdentity {
        &self.identity
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }

    pub const fn geometry(&self) -> WhirResidualGeometry {
        self.geometry
    }

    /// Close and remove an owned artifact, surfacing normal cleanup failure.
    ///
    /// Borrowed artifacts have no cleanup path and are simply closed. `Drop`
    /// remains a best-effort fallback for unwind and early-return paths. The
    /// caller must not rename or replace generated artifact paths while a
    /// capability is live; cleanup still verifies that the current path names
    /// the owned open file before removing it.
    pub fn remove(mut self) -> Result<(), WhirResidualArtifactError> {
        let Some(path) = self.cleanup_path.take() else {
            self.file.take();
            return Ok(());
        };
        let mutex = self.file.take().expect("live artifact owns its file");
        let file = mutex
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = remove_owned_file(&path, &file) {
            self.file = Some(Mutex::new(file));
            self.cleanup_path = Some(path.clone());
            return Err(error);
        }
        Ok(())
    }

    /// Authenticate and decode a bounded contiguous natural-order row range.
    pub fn read_rows(
        &self,
        start: u64,
        count: usize,
    ) -> Result<Vec<[u64; WHIR_RESIDUAL_LIMBS_PER_ROW]>, WhirResidualArtifactError> {
        if count == 0 {
            return Err(WhirResidualArtifactError::Invalid(
                "row read must not be empty",
            ));
        }
        if count > WHIR_RESIDUAL_MAX_IO_ROWS {
            return Err(WhirResidualArtifactError::ResearchLimit(
                "row read exceeds the bounded chunk size",
            ));
        }
        let count_u64 = u64::try_from(count)
            .map_err(|_| WhirResidualArtifactError::ResearchLimit("row read count"))?;
        let end = start
            .checked_add(count_u64)
            .ok_or(WhirResidualArtifactError::ResearchLimit("row read range"))?;
        if end > self.geometry.row_count {
            return Err(WhirResidualArtifactError::Invalid(
                "row read exceeds the artifact",
            ));
        }

        let file = self
            .file
            .as_ref()
            .expect("live artifact owns its file")
            .lock()
            .map_err(|_| WhirResidualArtifactError::LockPoisoned)?;
        let mut file = file;
        self.verify_live_header(&mut file)?;

        let first_chunk = start / AUTH_CHUNK_ROWS;
        let last_chunk = (end - 1) / AUTH_CHUNK_ROWS;
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| WhirResidualArtifactError::ResearchLimit("row read allocation"))?;
        for chunk_index in first_chunk..=last_chunk {
            let chunk_start = chunk_index * AUTH_CHUNK_ROWS;
            let chunk_rows = (self.geometry.row_count - chunk_start).min(AUTH_CHUNK_ROWS);
            let chunk_bytes_u64 = chunk_rows
                .checked_mul((WHIR_RESIDUAL_LIMBS_PER_ROW * size_of::<u64>()) as u64)
                .ok_or(WhirResidualArtifactError::ResearchLimit(
                    "chunk byte length",
                ))?;
            let chunk_bytes = usize::try_from(chunk_bytes_u64)
                .map_err(|_| WhirResidualArtifactError::ResearchLimit("chunk read size"))?;
            let mut encoded = Vec::new();
            encoded
                .try_reserve_exact(chunk_bytes)
                .map_err(|_| WhirResidualArtifactError::ResearchLimit("chunk allocation"))?;
            encoded.resize(chunk_bytes, 0);
            let byte_offset = (HEADER_BYTES as u64)
                .checked_add(
                    chunk_start
                        .checked_mul((WHIR_RESIDUAL_LIMBS_PER_ROW * size_of::<u64>()) as u64)
                        .ok_or(WhirResidualArtifactError::ResearchLimit("chunk offset"))?,
                )
                .ok_or(WhirResidualArtifactError::ResearchLimit("chunk offset"))?;
            file.seek(SeekFrom::Start(byte_offset))
                .and_then(|_| file.read_exact(&mut encoded))
                .map_err(|source| io_error("reading rows from", &self.path, source))?;
            let mut hasher = new_chunk_hasher(&self.prefix, chunk_index);
            hasher.update(&encoded);
            let expected_digest = self
                .authentication_digests
                .get(chunk_index as usize)
                .ok_or(WhirResidualArtifactError::ChecksumMismatch)?;
            if hasher.finalize().as_bytes() != expected_digest {
                return Err(WhirResidualArtifactError::ChecksumMismatch);
            }

            let selected_start = start.max(chunk_start) - chunk_start;
            let selected_end = end.min(chunk_start + chunk_rows) - chunk_start;
            let row_bytes = WHIR_RESIDUAL_LIMBS_PER_ROW * size_of::<u64>();
            for row_index in selected_start..selected_end {
                let row_offset = usize::try_from(row_index)
                    .ok()
                    .and_then(|index| index.checked_mul(row_bytes))
                    .ok_or(WhirResidualArtifactError::ResearchLimit("row offset"))?;
                let mut row = [0_u64; WHIR_RESIDUAL_LIMBS_PER_ROW];
                for (limb_index, limb) in row.iter_mut().enumerate() {
                    let limb_offset = row_offset + limb_index * size_of::<u64>();
                    *limb = u64::from_le_bytes(
                        encoded[limb_offset..limb_offset + size_of::<u64>()]
                            .try_into()
                            .expect("fixed limb slice"),
                    );
                }
                if row.iter().any(|&value| value >= GOLDILOCKS_MODULUS) {
                    return Err(WhirResidualArtifactError::ChecksumMismatch);
                }
                output.push(row);
            }
        }
        self.verify_live_header(&mut file)?;
        if output.len() != count {
            return Err(WhirResidualArtifactError::ChecksumMismatch);
        }
        Ok(output)
    }

    fn verify_live_header(&self, file: &mut File) -> Result<(), WhirResidualArtifactError> {
        let actual_bytes = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &self.path, source))?
            .len();
        if actual_bytes != self.geometry.artifact_bytes {
            return Err(WhirResidualArtifactError::ChecksumMismatch);
        }
        let mut header = [0_u8; HEADER_BYTES];
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.read_exact(&mut header))
            .map_err(|source| io_error("reauthenticating header from", &self.path, source))?;
        if header[..PREFIX_BYTES] != self.prefix
            || header[PREFIX_BYTES..] != self.identity.artifact_digest
        {
            return Err(WhirResidualArtifactError::ChecksumMismatch);
        }
        Ok(())
    }
}

impl Drop for AuthenticatedWhirResidualArtifact {
    fn drop(&mut self) {
        let (Some(path), Some(mutex)) = (self.cleanup_path.take(), self.file.take()) else {
            return;
        };
        let file = mutex
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = remove_owned_file(&path, &file);
    }
}

fn remove_owned_file(path: &Path, file: &File) -> Result<(), WhirResidualArtifactError> {
    let owned_handle = Handle::from_file(
        file.try_clone()
            .map_err(|source| io_error("cloning cleanup handle for", path, source))?,
    )
    .map_err(|source| io_error("identifying owned file at", path, source))?;
    let path_handle = Handle::from_path(path)
        .map_err(|source| io_error("identifying cleanup path", path, source))?;
    if owned_handle != path_handle {
        return Err(WhirResidualArtifactError::CleanupTargetChanged(
            path.to_path_buf(),
        ));
    }
    fs::remove_file(path).map_err(|source| io_error("removing", path, source))
}

fn encode_prefix(
    spec: &WhirResidualArtifactSpec,
    geometry: &WhirResidualGeometry,
) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    prefix[..8].copy_from_slice(MAGIC);
    prefix[8..12].copy_from_slice(&VERSION.to_le_bytes());
    prefix[12] = NATURAL_SUFFIX_LAYOUT;
    prefix[13] = CANONICAL_U64_LE_ENCODING;
    prefix[14] = WHIR_RESIDUAL_LIMBS_PER_ROW as u8;
    prefix[16..20].copy_from_slice(&spec.num_variables.to_le_bytes());
    prefix[20..24].copy_from_slice(&spec.generation.to_le_bytes());
    prefix[24..32].copy_from_slice(&geometry.row_count.to_le_bytes());
    prefix[32..40].copy_from_slice(&geometry.data_bytes.to_le_bytes());
    prefix[40..48].copy_from_slice(&geometry.authentication_chunks.to_le_bytes());
    prefix[48..80].copy_from_slice(&spec.source_digest);
    prefix[80..112].copy_from_slice(&spec.context_digest);
    prefix
}

fn decode_prefix(
    prefix: &[u8; PREFIX_BYTES],
) -> Result<(WhirResidualArtifactSpec, WhirResidualGeometry), WhirResidualArtifactError> {
    if &prefix[..8] != MAGIC
        || read_u32(prefix, 8)? != VERSION
        || prefix[12] != NATURAL_SUFFIX_LAYOUT
        || prefix[13] != CANONICAL_U64_LE_ENCODING
        || prefix[14] != WHIR_RESIDUAL_LIMBS_PER_ROW as u8
        || prefix[15] != 0
        || prefix[112..].iter().any(|&byte| byte != 0)
    {
        return Err(WhirResidualArtifactError::Invalid(
            "header marker or reserved bytes",
        ));
    }
    let spec = WhirResidualArtifactSpec {
        source_digest: prefix[48..80]
            .try_into()
            .expect("fixed source digest slice"),
        context_digest: prefix[80..112]
            .try_into()
            .expect("fixed context digest slice"),
        num_variables: read_u32(prefix, 16)?,
        generation: read_u32(prefix, 20)?,
    };
    let geometry = whir_residual_geometry(&spec)?;
    if read_u64(prefix, 24)? != geometry.row_count
        || read_u64(prefix, 32)? != geometry.data_bytes
        || read_u64(prefix, 40)? != geometry.authentication_chunks
    {
        return Err(WhirResidualArtifactError::Invalid(
            "header geometry does not match the specification",
        ));
    }
    Ok((spec, geometry))
}

fn new_chunk_hasher(prefix: &[u8; PREFIX_BYTES], chunk_index: u64) -> Hasher {
    let mut hasher = Hasher::new_derive_key(AUTH_DOMAIN);
    hasher.update(prefix);
    hasher.update(&chunk_index.to_le_bytes());
    hasher
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, WhirResidualArtifactError> {
    bytes
        .get(offset..offset + size_of::<u32>())
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(WhirResidualArtifactError::Invalid("truncated header"))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, WhirResidualArtifactError> {
    bytes
        .get(offset..offset + size_of::<u64>())
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(WhirResidualArtifactError::Invalid("truncated header"))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> WhirResidualArtifactError {
    WhirResidualArtifactError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::{Arc, Barrier};

    use super::*;

    fn test_directory(label: &str) -> PathBuf {
        let sequence = NEXT_ARTIFACT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-whir-residual-test-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn spec(num_variables: u32) -> WhirResidualArtifactSpec {
        WhirResidualArtifactSpec {
            source_digest: [0x31; 32],
            context_digest: [0x72; 32],
            num_variables,
            generation: 3,
        }
    }

    fn row(index: u64) -> [u64; WHIR_RESIDUAL_LIMBS_PER_ROW] {
        core::array::from_fn(|limb| (index * 17 + limb as u64 * 29 + 5) % GOLDILOCKS_MODULUS)
    }

    fn build_artifact(directory: &Path, variables: u32) -> AuthenticatedWhirResidualArtifact {
        let mut writer = WhirResidualArtifactWriter::create(directory, spec(variables)).unwrap();
        let rows = 1_u64 << variables;
        let mut start = 0_u64;
        while start < rows {
            let count = usize::try_from((rows - start).min(5_003)).unwrap();
            let values = (0..count)
                .map(|offset| row(start + offset as u64))
                .collect::<Vec<_>>();
            writer.write_rows(start, &values).unwrap();
            start += count as u64;
        }
        writer.finish().unwrap()
    }

    #[test]
    fn production_geometry_is_checked_without_row_allocation() {
        let geometry = whir_residual_geometry(&spec(29)).unwrap();
        assert_eq!(geometry.row_count, 1_u64 << 29);
        assert_eq!(geometry.data_bytes, 24_u64 * 1024 * 1024 * 1024);
        assert_eq!(geometry.authentication_chunks, 1_u64 << 16);
        assert_eq!(
            geometry.artifact_bytes,
            24_u64 * 1024 * 1024 * 1024 + 2_097_152 + 160
        );

        let mut too_large = spec(30);
        assert!(matches!(
            whir_residual_geometry(&too_large),
            Err(WhirResidualArtifactError::ResearchLimit(_))
        ));
        too_large.num_variables = 2;
        too_large.context_digest = [0; 32];
        assert_eq!(whir_residual_geometry(&too_large).unwrap().row_count, 4);
    }

    #[test]
    fn roundtrip_authenticates_ranges_across_chunk_boundaries() {
        let directory = test_directory("roundtrip");
        let artifact = build_artifact(&directory, 14);
        let path = artifact.path().to_path_buf();
        let identity = artifact.identity().clone();
        assert_eq!(artifact.geometry().authentication_chunks, 2);
        assert_eq!(
            artifact.read_rows(AUTH_CHUNK_ROWS - 7, 19).unwrap(),
            ((AUTH_CHUNK_ROWS - 7)..(AUTH_CHUNK_ROWS + 12))
                .map(row)
                .collect::<Vec<_>>()
        );

        let reopened = AuthenticatedWhirResidualArtifact::open(&path, &identity).unwrap();
        assert_eq!(reopened.read_rows(0, 1).unwrap(), vec![row(0)]);
        assert_eq!(
            reopened.read_rows((1_u64 << 14) - 3, 3).unwrap(),
            ((1_u64 << 14) - 3..1_u64 << 14)
                .map(row)
                .collect::<Vec<_>>()
        );
        drop(reopened);
        assert!(path.exists());
        drop(artifact);
        assert!(!path.exists());
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn incomplete_and_invalid_writes_fail_without_touching_neighbors() {
        let directory = test_directory("cleanup");
        let neighbor = directory.join("keep-me");
        fs::write(&neighbor, b"owned elsewhere").unwrap();
        let mut writer = WhirResidualArtifactWriter::create(&directory, spec(2)).unwrap();
        let partial = writer.partial_path.clone();
        assert!(matches!(
            writer.write_rows(1, &[row(0)]),
            Err(WhirResidualArtifactError::Invalid(_))
        ));
        let mut noncanonical = row(0);
        noncanonical[4] = GOLDILOCKS_MODULUS;
        assert!(matches!(
            writer.write_rows(0, &[noncanonical]),
            Err(WhirResidualArtifactError::Invalid(_))
        ));
        writer.write_rows(0, &[row(0)]).unwrap();
        assert!(matches!(
            writer.finish(),
            Err(WhirResidualArtifactError::Invalid(_))
        ));
        assert!(!partial.exists());
        assert_eq!(fs::read(&neighbor).unwrap(), b"owned elsewhere");
        fs::remove_file(neighbor).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn artifact_cleanup_refuses_a_replaced_path() {
        let directory = test_directory("artifact-replacement");
        let artifact = build_artifact(&directory, 0);
        let path = artifact.path().to_path_buf();
        let moved_owned = directory.join("moved-owned-artifact");
        fs::rename(&path, &moved_owned).unwrap();
        fs::write(&path, b"replacement owned elsewhere").unwrap();

        assert!(matches!(
            artifact.remove(),
            Err(WhirResidualArtifactError::CleanupTargetChanged(changed)) if changed == path
        ));
        assert_eq!(fs::read(&path).unwrap(), b"replacement owned elsewhere");
        assert!(moved_owned.exists());

        fs::remove_file(path).unwrap();
        fs::remove_file(moved_owned).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn writer_drop_refuses_a_replaced_partial_path() {
        let directory = test_directory("writer-replacement");
        let writer = WhirResidualArtifactWriter::create(&directory, spec(0)).unwrap();
        let partial = writer.partial_path.clone();
        let moved_owned = directory.join("moved-owned-partial");
        fs::rename(&partial, &moved_owned).unwrap();
        fs::write(&partial, b"replacement owned elsewhere").unwrap();

        drop(writer);
        assert_eq!(fs::read(&partial).unwrap(), b"replacement owned elsewhere");
        assert!(moved_owned.exists());

        fs::remove_file(partial).unwrap();
        fs::remove_file(moved_owned).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn identity_and_live_mutation_fail_closed() {
        let directory = test_directory("identity-mutation");
        let artifact = build_artifact(&directory, 3);
        let path = artifact.path().to_path_buf();
        let mut wrong = artifact.identity().clone();
        wrong.spec.context_digest[0] ^= 1;
        assert!(matches!(
            AuthenticatedWhirResidualArtifact::open(&path, &wrong),
            Err(WhirResidualArtifactError::IdentityMismatch)
        ));

        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(HEADER_BYTES as u64 + 11))
            .unwrap();
        file.write_all(&[0x80]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(matches!(
            artifact.read_rows(0, 1),
            Err(WhirResidualArtifactError::ChecksumMismatch)
        ));
        assert!(matches!(
            AuthenticatedWhirResidualArtifact::open(&path, artifact.identity()),
            Err(WhirResidualArtifactError::ChecksumMismatch)
        ));
        drop(artifact);
        assert!(!path.exists());
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn truncation_and_trailing_bytes_are_rejected() {
        for trailing in [false, true] {
            let directory = test_directory(if trailing { "append" } else { "truncate" });
            let artifact = build_artifact(&directory, 2);
            let path = artifact.path().to_path_buf();
            let identity = artifact.identity().clone();
            let file = OpenOptions::new().write(true).open(&path).unwrap();
            if trailing {
                drop(file);
                let mut file = OpenOptions::new().append(true).open(&path).unwrap();
                file.write_all(&[1]).unwrap();
                file.sync_all().unwrap();
            } else {
                file.set_len(artifact.geometry().artifact_bytes - 1)
                    .unwrap();
                file.sync_all().unwrap();
            }
            assert!(matches!(
                AuthenticatedWhirResidualArtifact::open(&path, &identity),
                Err(WhirResidualArtifactError::ChecksumMismatch)
            ));
            drop(artifact);
            assert!(!path.exists());
            fs::remove_dir(directory).unwrap();
        }
    }

    #[test]
    fn concurrent_writers_receive_distinct_owned_paths() {
        let directory = Arc::new(test_directory("concurrent"));
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let directory = Arc::clone(&directory);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut writer =
                        WhirResidualArtifactWriter::create(&*directory, spec(0)).unwrap();
                    writer.write_rows(0, &[row(0)]).unwrap();
                    writer.finish().unwrap()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let artifacts = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_ne!(artifacts[0].path(), artifacts[1].path());
        assert_eq!(fs::read_dir(&*directory).unwrap().count(), 2);
        drop(artifacts);
        assert_eq!(fs::read_dir(&*directory).unwrap().count(), 0);
        fs::remove_dir(&*directory).unwrap();
    }

    #[test]
    fn scratch_directory_must_be_existing_and_absolute() {
        assert!(matches!(
            WhirResidualArtifactWriter::create(Path::new("relative"), spec(0)),
            Err(WhirResidualArtifactError::InvalidScratchDirectory(_))
        ));
        let missing = std::env::temp_dir().join(format!(
            "cmfd-whir-residual-missing-{}-{}",
            std::process::id(),
            NEXT_ARTIFACT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(matches!(
            WhirResidualArtifactWriter::create(&missing, spec(0)),
            Err(WhirResidualArtifactError::InvalidScratchDirectory(_))
        ));
    }
}
