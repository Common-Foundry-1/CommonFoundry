//! Bounded external-memory encoding for WHIR's initial Suffix commitment.
//!
//! The pinned protocol uses folding two and starting log inverse rate one.
//! A table with `2^n` values is therefore copied into the first half of a
//! `2^(n-1) x 4` coefficient matrix, zero padded, and transformed column-wise.
//! This module stages that transform on disk and publishes only a completely
//! authenticated natural-row artifact. It is a research prover primitive; it
//! does not alter consensus or raise the production proof limits.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use blake3::Hasher;
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use thiserror::Error;

use crate::merkle_store::{GOLDILOCKS_MODULUS, MerkleRowSource, MerkleStoreError};

/// Smallest table supported by folding two.
pub const WHIR_INITIAL_MIN_VARIABLES: usize = 2;
/// Bounded checkpoint cap. Production weight banks (`n = 31`) remain rejected.
pub const WHIR_INITIAL_MAX_VARIABLES: usize = 19;
/// Fixed row width selected by folding two.
pub const WHIR_INITIAL_WIDTH: usize = 4;
/// Maximum canonical source values requested in one call.
pub const WHIR_INITIAL_MAX_SOURCE_READ_LIMBS: usize = 8 * 1024;
/// Maximum field values held in either butterfly half-buffer.
pub const WHIR_INITIAL_MAX_DFT_BUFFER_LIMBS: usize = 8 * 1024;
/// Maximum rows returned by one authenticated artifact read.
pub const WHIR_INITIAL_MAX_READ_ROWS: usize = 256;

const MAGIC: &[u8; 8] = b"CMFDWIH1";
const VERSION: u32 = 1;
const FOLDING: u8 = 2;
const STARTING_LOG_INV_RATE: u8 = 1;
const NATURAL_ROW_LAYOUT: u8 = 1;
const PREFIX_BYTES: usize = 128;
const DIGEST_BYTES: usize = 32;
const HEADER_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;
const AUTH_CHUNK_ROWS: usize = 256;
const AUTH_DOMAIN: &[u8] = b"CMFD-WHIR-INITIAL-AUTH-V1";

/// Exact external identity of the authenticated table being encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirInitialSourceIdentity {
    pub source_id: [u8; 32],
    pub num_variables: u32,
}

/// Fallible random-access source of canonical Goldilocks values.
///
/// Implementations must authenticate every returned range against the
/// externally retained [`WhirInitialSourceIdentity`] and fail if their backing
/// artifact changes. The encoder never requests more than
/// [`WHIR_INITIAL_MAX_SOURCE_READ_LIMBS`] values at once.
pub trait AuthenticatedWhirInitialSource: Sync {
    fn identity(&self) -> &WhirInitialSourceIdentity;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read_elements(&self, start: usize, count: usize)
    -> Result<Vec<u64>, WhirInitialSourceError>;
}

/// Error surfaced by an authenticated source implementation.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct WhirInitialSourceError {
    message: String,
}

impl WhirInitialSourceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Caller-retained identity required to reopen one natural-row artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirInitialCodewordIdentity {
    pub artifact_id: [u8; 32],
    pub source: WhirInitialSourceIdentity,
    pub height: u64,
    pub width: u32,
    pub artifact_digest: [u8; 32],
}

#[derive(Debug, Error)]
pub enum WhirInitialEncodingError {
    #[error("invalid WHIR initial encoding: {0}")]
    Invalid(&'static str),
    #[error("WHIR initial encoding research limit exceeded: {0}")]
    ResearchLimit(&'static str),
    #[error("WHIR initial source failed: {0}")]
    Source(#[from] WhirInitialSourceError),
    #[error("WHIR initial artifact already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("WHIR initial artifact I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("WHIR initial artifact checksum does not match")]
    ChecksumMismatch,
    #[error("WHIR initial artifact identity does not match")]
    IdentityMismatch,
    #[error("WHIR initial artifact file lock is poisoned")]
    LockPoisoned,
}

/// Fully authenticated natural-row initial WHIR codeword.
pub struct AuthenticatedWhirInitialCodeword {
    file: Mutex<File>,
    path: PathBuf,
    identity: WhirInitialCodewordIdentity,
    height: usize,
    prefix: [u8; PREFIX_BYTES],
    auth_digests: Vec<[u8; DIGEST_BYTES]>,
    cleanup: Option<ArtifactCleanup>,
}

struct ArtifactCleanup(PathBuf);

impl Drop for ArtifactCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl std::fmt::Debug for AuthenticatedWhirInitialCodeword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedWhirInitialCodeword")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedWhirInitialCodeword {
    /// Open an artifact and require exact caller-retained identity.
    pub fn open(
        path: impl AsRef<Path>,
        expected: &WhirInitialCodewordIdentity,
    ) -> Result<Self, WhirInitialEncodingError> {
        let artifact = Self::open_integrity_only(path.as_ref())?;
        if &artifact.identity != expected {
            return Err(WhirInitialEncodingError::IdentityMismatch);
        }
        Ok(artifact)
    }

    fn open_integrity_only(path: &Path) -> Result<Self, WhirInitialEncodingError> {
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
        let decoded = decode_prefix(&prefix)?;
        let total_bytes = (HEADER_BYTES as u64)
            .checked_add(decoded.data_bytes)
            .and_then(|value| value.checked_add(decoded.auth_count * DIGEST_BYTES as u64))
            .ok_or(WhirInitialEncodingError::Invalid(
                "artifact length overflow",
            ))?;
        let actual_bytes = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();
        if actual_bytes != total_bytes {
            return Err(WhirInitialEncodingError::Invalid(
                "artifact length does not match header",
            ));
        }

        let auth_count = usize::try_from(decoded.auth_count)
            .map_err(|_| WhirInitialEncodingError::ResearchLimit("authentication table"))?;
        let mut auth_digests = Vec::new();
        auth_digests
            .try_reserve_exact(auth_count)
            .map_err(|_| WhirInitialEncodingError::ResearchLimit("authentication table"))?;
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
            decoded.height,
            &auth_digests,
            stored_digest,
        )?;
        Ok(Self {
            file: Mutex::new(file),
            path,
            identity: WhirInitialCodewordIdentity {
                artifact_id: decoded.artifact_id,
                source: WhirInitialSourceIdentity {
                    source_id: decoded.source_id,
                    num_variables: decoded.num_variables,
                },
                height: decoded.height as u64,
                width: WHIR_INITIAL_WIDTH as u32,
                artifact_digest: stored_digest,
            },
            height: decoded.height,
            prefix,
            auth_digests,
            cleanup: None,
        })
    }

    pub const fn identity(&self) -> &WhirInitialCodewordIdentity {
        &self.identity
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn remove_on_drop(mut self) -> Self {
        self.cleanup = Some(ArtifactCleanup(self.path.clone()));
        self
    }

    /// Read and independently authenticate consecutive natural rows.
    pub fn read_canonical_rows(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<u64>, WhirInitialEncodingError> {
        let row_end = row_start
            .checked_add(row_count)
            .ok_or(WhirInitialEncodingError::Invalid("row range overflow"))?;
        if row_count == 0 || row_count > WHIR_INITIAL_MAX_READ_ROWS || row_end > self.height {
            return Err(WhirInitialEncodingError::Invalid(
                "row range is outside the bounded artifact",
            ));
        }
        let value_count =
            row_count
                .checked_mul(WHIR_INITIAL_WIDTH)
                .ok_or(WhirInitialEncodingError::Invalid(
                    "row value count overflow",
                ))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(value_count)
            .map_err(|_| WhirInitialEncodingError::ResearchLimit("row output"))?;
        let first_chunk = row_start / AUTH_CHUNK_ROWS;
        let last_chunk = (row_end - 1) / AUTH_CHUNK_ROWS;
        let mut file = self
            .file
            .lock()
            .map_err(|_| WhirInitialEncodingError::LockPoisoned)?;
        for chunk_index in first_chunk..=last_chunk {
            let chunk_start = chunk_index * AUTH_CHUNK_ROWS;
            let chunk_rows = (self.height - chunk_start).min(AUTH_CHUNK_ROWS);
            let bytes = read_encoded_rows(&mut file, &self.path, chunk_start, chunk_rows)?;
            validate_encoded_rows(&bytes)?;
            if auth_digest(&self.prefix, chunk_index, &bytes) != self.auth_digests[chunk_index] {
                return Err(WhirInitialEncodingError::ChecksumMismatch);
            }
            let copy_start = row_start.max(chunk_start);
            let copy_end = row_end.min(chunk_start + chunk_rows);
            let byte_start = (copy_start - chunk_start) * WHIR_INITIAL_WIDTH * 8;
            let byte_end = (copy_end - chunk_start) * WHIR_INITIAL_WIDTH * 8;
            decode_values(&bytes[byte_start..byte_end], &mut output);
        }
        Ok(output)
    }
}

impl Matrix<Goldilocks> for AuthenticatedWhirInitialCodeword {
    fn width(&self) -> usize {
        WHIR_INITIAL_WIDTH
    }

    fn height(&self) -> usize {
        self.height
    }

    unsafe fn row_subseq_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = Goldilocks, IntoIter = impl Iterator<Item = Goldilocks> + Send + Sync>
    {
        debug_assert!(row < self.height);
        debug_assert!(start <= end && end <= WHIR_INITIAL_WIDTH);
        let values = self
            .read_canonical_rows(row, 1)
            .unwrap_or_else(|error| panic!("authenticated WHIR codeword read failed: {error}"));
        values[start..end]
            .iter()
            .copied()
            .map(Goldilocks::new)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl MerkleRowSource for AuthenticatedWhirInitialCodeword {
    fn height(&self) -> usize {
        self.height
    }

    fn width(&self) -> usize {
        WHIR_INITIAL_WIDTH
    }

    fn read_row(&self, row: usize) -> Result<Vec<u64>, MerkleStoreError> {
        self.read_canonical_rows(row, 1)
            .map_err(|error| MerkleStoreError::Source(error.to_string()))
    }

    fn read_rows(&self, row_start: usize, row_count: usize) -> Result<Vec<u64>, MerkleStoreError> {
        self.read_canonical_rows(row_start, row_count)
            .map_err(|error| MerkleStoreError::Source(error.to_string()))
    }
}

/// Encode and atomically publish one exact initial WHIR Suffix codeword.
///
/// Over-cap or malformed geometry is rejected before any source range is read
/// or partial file is created. `artifact_id` and `source.source_id` must be
/// externally selected, nonzero identities.
pub fn encode_whir_initial_suffix(
    final_path: impl AsRef<Path>,
    artifact_id: [u8; 32],
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
) -> Result<AuthenticatedWhirInitialCodeword, WhirInitialEncodingError> {
    encode_with_limits(
        final_path.as_ref(),
        artifact_id,
        expected_source,
        source,
        WHIR_INITIAL_MAX_SOURCE_READ_LIMBS,
        WHIR_INITIAL_MAX_DFT_BUFFER_LIMBS,
    )
}

fn encode_with_limits(
    final_path: &Path,
    artifact_id: [u8; 32],
    expected_source: &WhirInitialSourceIdentity,
    source: &dyn AuthenticatedWhirInitialSource,
    source_read_limbs: usize,
    dft_buffer_limbs: usize,
) -> Result<AuthenticatedWhirInitialCodeword, WhirInitialEncodingError> {
    let geometry = validate_geometry(artifact_id, expected_source)?;
    if source_read_limbs == 0
        || source_read_limbs > WHIR_INITIAL_MAX_SOURCE_READ_LIMBS
        || !source_read_limbs.is_multiple_of(WHIR_INITIAL_WIDTH)
        || !(WHIR_INITIAL_WIDTH..=WHIR_INITIAL_MAX_DFT_BUFFER_LIMBS).contains(&dft_buffer_limbs)
        || !dft_buffer_limbs.is_multiple_of(WHIR_INITIAL_WIDTH)
    {
        return Err(WhirInitialEncodingError::Invalid(
            "internal buffer limit is invalid",
        ));
    }
    if source.identity() != expected_source {
        return Err(WhirInitialEncodingError::IdentityMismatch);
    }
    if source.len() != geometry.source_elements {
        return Err(WhirInitialEncodingError::Invalid(
            "source length does not match num_variables",
        ));
    }
    if final_path.exists() {
        return Err(WhirInitialEncodingError::AlreadyExists(
            final_path.to_path_buf(),
        ));
    }
    let partial_path = partial_path_for(final_path)?;
    let prefix = encode_prefix(artifact_id, expected_source, &geometry);
    let mut cleanup = PartialCleanup(Some(partial_path.clone()));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&partial_path)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                WhirInitialEncodingError::AlreadyExists(partial_path.clone())
            } else {
                io_error("creating", &partial_path, source)
            }
        })?;
    file.write_all(&prefix)
        .and_then(|()| file.write_all(&[0_u8; DIGEST_BYTES]))
        .and_then(|()| file.set_len(HEADER_BYTES as u64 + geometry.data_bytes))
        .map_err(|source| io_error("initializing", &partial_path, source))?;

    scatter_bit_reversed_source(
        &mut file,
        &partial_path,
        source,
        expected_source,
        &geometry,
        source_read_limbs,
    )?;
    dft_in_place(
        &mut file,
        &partial_path,
        geometry.height,
        dft_buffer_limbs / WHIR_INITIAL_WIDTH,
    )?;
    let (auth_digests, artifact_digest) =
        seal_data(&mut file, &partial_path, &prefix, geometry.height)?;
    drop(file);

    let staged_artifact = AuthenticatedWhirInitialCodeword::open_integrity_only(&partial_path)?;
    debug_assert_eq!(staged_artifact.auth_digests, auth_digests);
    debug_assert_eq!(staged_artifact.identity.artifact_digest, artifact_digest);
    let expected_identity = staged_artifact.identity.clone();
    fs::hard_link(&partial_path, final_path)
        .map_err(|source| io_error("publishing", final_path, source))?;
    let artifact = match AuthenticatedWhirInitialCodeword::open(final_path, &expected_identity) {
        Ok(artifact) => artifact,
        Err(error) => {
            let _ = fs::remove_file(final_path);
            return Err(error);
        }
    };
    drop(staged_artifact);
    if let Err(source) = fs::remove_file(&partial_path) {
        let _ = fs::remove_file(final_path);
        return Err(io_error("removing staging file", &partial_path, source));
    }
    cleanup.0 = None;
    Ok(artifact)
}

#[derive(Clone, Copy)]
struct Geometry {
    source_elements: usize,
    height: usize,
    data_bytes: u64,
    auth_count: u64,
}

fn validate_geometry(
    artifact_id: [u8; 32],
    source: &WhirInitialSourceIdentity,
) -> Result<Geometry, WhirInitialEncodingError> {
    if artifact_id == [0; 32] || source.source_id == [0; 32] {
        return Err(WhirInitialEncodingError::Invalid(
            "artifact and source identities must be nonzero",
        ));
    }
    let variables = usize::try_from(source.num_variables)
        .map_err(|_| WhirInitialEncodingError::ResearchLimit("variable count"))?;
    if variables < WHIR_INITIAL_MIN_VARIABLES {
        return Err(WhirInitialEncodingError::Invalid(
            "num_variables is smaller than folding",
        ));
    }
    if variables > WHIR_INITIAL_MAX_VARIABLES {
        return Err(WhirInitialEncodingError::ResearchLimit(
            "num_variables exceeds 19",
        ));
    }
    let source_elements = 1_usize.checked_shl(source.num_variables).ok_or(
        WhirInitialEncodingError::ResearchLimit("source element count"),
    )?;
    let height = 1_usize
        .checked_shl(source.num_variables - 1)
        .ok_or(WhirInitialEncodingError::ResearchLimit("codeword height"))?;
    let data_bytes = height
        .checked_mul(WHIR_INITIAL_WIDTH)
        .and_then(|values| values.checked_mul(8))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(WhirInitialEncodingError::ResearchLimit(
            "artifact byte length",
        ))?;
    let auth_count = u64::try_from(height.div_ceil(AUTH_CHUNK_ROWS))
        .map_err(|_| WhirInitialEncodingError::ResearchLimit("authentication table"))?;
    Ok(Geometry {
        source_elements,
        height,
        data_bytes,
        auth_count,
    })
}

fn scatter_bit_reversed_source(
    file: &mut File,
    path: &Path,
    source: &dyn AuthenticatedWhirInitialSource,
    expected_source: &WhirInitialSourceIdentity,
    geometry: &Geometry,
    source_read_limbs: usize,
) -> Result<(), WhirInitialEncodingError> {
    let log_height = geometry.height.ilog2();
    let mut start = 0_usize;
    while start < geometry.source_elements {
        let count = (geometry.source_elements - start).min(source_read_limbs);
        let values = source.read_elements(start, count)?;
        if source.identity() != expected_source
            || source.len() != geometry.source_elements
            || values.len() != count
        {
            return Err(WhirInitialEncodingError::Invalid(
                "source geometry changed while reading",
            ));
        }
        if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
            return Err(WhirInitialEncodingError::Invalid(
                "source returned a noncanonical Goldilocks value",
            ));
        }
        for (local_row, row) in values.chunks_exact(WHIR_INITIAL_WIDTH).enumerate() {
            let natural_row = start / WHIR_INITIAL_WIDTH + local_row;
            let physical_row = reverse_bits_len(natural_row, log_height);
            write_encoded_row(file, path, physical_row, row)?;
        }
        start += count;
    }
    if source.identity() != expected_source || source.len() != geometry.source_elements {
        return Err(WhirInitialEncodingError::Invalid(
            "source geometry changed after reading",
        ));
    }
    Ok(())
}

fn dft_in_place(
    file: &mut File,
    path: &Path,
    height: usize,
    buffer_rows: usize,
) -> Result<(), WhirInitialEncodingError> {
    let max_values =
        buffer_rows
            .checked_mul(WHIR_INITIAL_WIDTH)
            .ok_or(WhirInitialEncodingError::Invalid(
                "DFT buffer size overflow",
            ))?;
    let mut left = vec![0_u64; max_values];
    let mut right = vec![0_u64; max_values];
    let mut len = 2_usize;
    loop {
        let half = len / 2;
        let root = Goldilocks::two_adic_generator(len.ilog2() as usize);
        for block in (0..height).step_by(len) {
            let mut offset = 0_usize;
            while offset < half {
                let rows = (half - offset).min(buffer_rows);
                let values = rows * WHIR_INITIAL_WIDTH;
                read_values(file, path, block + offset, &mut left[..values])?;
                read_values(file, path, block + half + offset, &mut right[..values])?;
                let mut twiddle = root.exp_u64(offset as u64);
                for row in 0..rows {
                    for column in 0..WHIR_INITIAL_WIDTH {
                        let index = row * WHIR_INITIAL_WIDTH + column;
                        let a = Goldilocks::new(left[index]);
                        let b = Goldilocks::new(right[index]) * twiddle;
                        left[index] = (a + b).as_canonical_u64();
                        right[index] = (a - b).as_canonical_u64();
                    }
                    twiddle *= root;
                }
                write_values(file, path, block + offset, &left[..values])?;
                write_values(file, path, block + half + offset, &right[..values])?;
                offset += rows;
            }
        }
        if len == height {
            break;
        }
        len *= 2;
    }
    Ok(())
}

fn seal_data(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    height: usize,
) -> Result<(Vec<[u8; 32]>, [u8; 32]), WhirInitialEncodingError> {
    file.sync_data()
        .map_err(|source| io_error("synchronizing staged data for", path, source))?;
    let mut global = Hasher::new();
    global.update(prefix);
    let mut auth_digests = Vec::new();
    auth_digests
        .try_reserve_exact(height.div_ceil(AUTH_CHUNK_ROWS))
        .map_err(|_| WhirInitialEncodingError::ResearchLimit("authentication table"))?;
    for chunk_start in (0..height).step_by(AUTH_CHUNK_ROWS) {
        let rows = (height - chunk_start).min(AUTH_CHUNK_ROWS);
        let bytes = read_encoded_rows(file, path, chunk_start, rows)?;
        validate_encoded_rows(&bytes)?;
        global.update(&bytes);
        auth_digests.push(auth_digest(prefix, auth_digests.len(), &bytes));
    }
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error("seeking in", path, source))?;
    for digest in &auth_digests {
        file.write_all(digest)
            .map_err(|source| io_error("writing authentication table to", path, source))?;
        global.update(digest);
    }
    let digest = *global.finalize().as_bytes();
    file.seek(SeekFrom::Start(PREFIX_BYTES as u64))
        .and_then(|_| file.write_all(&digest))
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("sealing", path, source))?;
    Ok((auth_digests, digest))
}

fn authenticate_complete(
    file: &mut File,
    path: &Path,
    prefix: &[u8; PREFIX_BYTES],
    height: usize,
    auth_digests: &[[u8; 32]],
    expected_global: [u8; 32],
) -> Result<(), WhirInitialEncodingError> {
    if auth_digests.len() != height.div_ceil(AUTH_CHUNK_ROWS) {
        return Err(WhirInitialEncodingError::Invalid(
            "authentication count does not match height",
        ));
    }
    let mut global = Hasher::new();
    global.update(prefix);
    for (chunk_index, chunk_start) in (0..height).step_by(AUTH_CHUNK_ROWS).enumerate() {
        let rows = (height - chunk_start).min(AUTH_CHUNK_ROWS);
        let bytes = read_encoded_rows(file, path, chunk_start, rows)?;
        validate_encoded_rows(&bytes)?;
        if auth_digest(prefix, chunk_index, &bytes) != auth_digests[chunk_index] {
            return Err(WhirInitialEncodingError::ChecksumMismatch);
        }
        global.update(&bytes);
    }
    for digest in auth_digests {
        global.update(digest);
    }
    if *global.finalize().as_bytes() != expected_global {
        return Err(WhirInitialEncodingError::ChecksumMismatch);
    }
    Ok(())
}

fn auth_digest(prefix: &[u8; PREFIX_BYTES], chunk_index: usize, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update(prefix);
    hasher.update(&(chunk_index as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn read_values(
    file: &mut File,
    path: &Path,
    row_start: usize,
    output: &mut [u64],
) -> Result<(), WhirInitialEncodingError> {
    let offset = data_offset(row_start)?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| io_error("seeking in", path, source))?;
    let mut encoded = vec![0_u8; output.len() * 8];
    file.read_exact(&mut encoded)
        .map_err(|source| io_error("reading staged rows from", path, source))?;
    for (value, bytes) in output.iter_mut().zip(encoded.chunks_exact(8)) {
        *value = u64::from_le_bytes(bytes.try_into().expect("eight-byte chunk"));
        if *value >= GOLDILOCKS_MODULUS {
            return Err(WhirInitialEncodingError::Invalid(
                "staged DFT row contains a noncanonical Goldilocks value",
            ));
        }
    }
    Ok(())
}

fn write_values(
    file: &mut File,
    path: &Path,
    row_start: usize,
    values: &[u64],
) -> Result<(), WhirInitialEncodingError> {
    let offset = data_offset(row_start)?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| io_error("seeking in", path, source))?;
    let mut encoded = vec![0_u8; values.len() * 8];
    for (value, bytes) in values.iter().zip(encoded.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    file.write_all(&encoded)
        .map_err(|source| io_error("writing staged rows to", path, source))
}

fn write_encoded_row(
    file: &mut File,
    path: &Path,
    row: usize,
    values: &[u64],
) -> Result<(), WhirInitialEncodingError> {
    debug_assert_eq!(values.len(), WHIR_INITIAL_WIDTH);
    let mut encoded = [0_u8; WHIR_INITIAL_WIDTH * 8];
    for (value, bytes) in values.iter().zip(encoded.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    file.seek(SeekFrom::Start(data_offset(row)?))
        .and_then(|_| file.write_all(&encoded))
        .map_err(|source| io_error("scattering source rows into", path, source))
}

fn read_encoded_rows(
    file: &mut File,
    path: &Path,
    row_start: usize,
    row_count: usize,
) -> Result<Vec<u8>, WhirInitialEncodingError> {
    let byte_count = row_count
        .checked_mul(WHIR_INITIAL_WIDTH * 8)
        .ok_or(WhirInitialEncodingError::Invalid("row byte count overflow"))?;
    let mut bytes = vec![0_u8; byte_count];
    file.seek(SeekFrom::Start(data_offset(row_start)?))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|source| io_error("reading authenticated rows from", path, source))?;
    Ok(bytes)
}

fn data_offset(row: usize) -> Result<u64, WhirInitialEncodingError> {
    row.checked_mul(WHIR_INITIAL_WIDTH * 8)
        .and_then(|offset| offset.checked_add(HEADER_BYTES))
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(WhirInitialEncodingError::Invalid("row offset overflow"))
}

fn validate_encoded_rows(bytes: &[u8]) -> Result<(), WhirInitialEncodingError> {
    if !bytes.len().is_multiple_of(8) {
        return Err(WhirInitialEncodingError::Invalid(
            "encoded row length is not aligned",
        ));
    }
    if bytes.chunks_exact(8).any(|chunk| {
        u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk")) >= GOLDILOCKS_MODULUS
    }) {
        return Err(WhirInitialEncodingError::Invalid(
            "artifact contains a noncanonical Goldilocks value",
        ));
    }
    Ok(())
}

fn decode_values(bytes: &[u8], output: &mut Vec<u64>) {
    output.extend(
        bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"))),
    );
}

fn reverse_bits_len(value: usize, bits: u32) -> usize {
    value.reverse_bits() >> (usize::BITS - bits)
}

fn encode_prefix(
    artifact_id: [u8; 32],
    source: &WhirInitialSourceIdentity,
    geometry: &Geometry,
) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    prefix[0..8].copy_from_slice(MAGIC);
    prefix[8..12].copy_from_slice(&VERSION.to_le_bytes());
    prefix[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    prefix[16..48].copy_from_slice(&artifact_id);
    prefix[48..80].copy_from_slice(&source.source_id);
    prefix[80..84].copy_from_slice(&source.num_variables.to_le_bytes());
    prefix[84] = FOLDING;
    prefix[85] = STARTING_LOG_INV_RATE;
    prefix[86] = NATURAL_ROW_LAYOUT;
    prefix[88..92].copy_from_slice(&(WHIR_INITIAL_WIDTH as u32).to_le_bytes());
    prefix[96..104].copy_from_slice(&(geometry.source_elements as u64).to_le_bytes());
    prefix[104..112].copy_from_slice(&(geometry.height as u64).to_le_bytes());
    prefix[112..120].copy_from_slice(&geometry.data_bytes.to_le_bytes());
    prefix[120..128].copy_from_slice(&geometry.auth_count.to_le_bytes());
    prefix
}

struct DecodedPrefix {
    artifact_id: [u8; 32],
    source_id: [u8; 32],
    num_variables: u32,
    height: usize,
    data_bytes: u64,
    auth_count: u64,
}

fn decode_prefix(prefix: &[u8; PREFIX_BYTES]) -> Result<DecodedPrefix, WhirInitialEncodingError> {
    if &prefix[0..8] != MAGIC
        || u32::from_le_bytes(prefix[8..12].try_into().expect("four bytes")) != VERSION
        || u32::from_le_bytes(prefix[12..16].try_into().expect("four bytes")) != HEADER_BYTES as u32
        || prefix[84] != FOLDING
        || prefix[85] != STARTING_LOG_INV_RATE
        || prefix[86] != NATURAL_ROW_LAYOUT
        || prefix[87] != 0
        || prefix[92..96] != [0; 4]
        || u32::from_le_bytes(prefix[88..92].try_into().expect("four bytes"))
            != WHIR_INITIAL_WIDTH as u32
    {
        return Err(WhirInitialEncodingError::Invalid(
            "header suite or layout is not canonical",
        ));
    }
    let artifact_id = prefix[16..48].try_into().expect("32 bytes");
    let source_id = prefix[48..80].try_into().expect("32 bytes");
    let num_variables = u32::from_le_bytes(prefix[80..84].try_into().expect("four bytes"));
    let geometry = validate_geometry(
        artifact_id,
        &WhirInitialSourceIdentity {
            source_id,
            num_variables,
        },
    )?;
    let source_elements = u64::from_le_bytes(prefix[96..104].try_into().expect("eight bytes"));
    let height_u64 = u64::from_le_bytes(prefix[104..112].try_into().expect("eight bytes"));
    let data_bytes = u64::from_le_bytes(prefix[112..120].try_into().expect("eight bytes"));
    let auth_count = u64::from_le_bytes(prefix[120..128].try_into().expect("eight bytes"));
    if source_elements != geometry.source_elements as u64
        || height_u64 != geometry.height as u64
        || data_bytes != geometry.data_bytes
        || auth_count != geometry.auth_count
    {
        return Err(WhirInitialEncodingError::Invalid(
            "header geometry is inconsistent",
        ));
    }
    Ok(DecodedPrefix {
        artifact_id,
        source_id,
        num_variables,
        height: geometry.height,
        data_bytes,
        auth_count,
    })
}

fn partial_path_for(path: &Path) -> Result<PathBuf, WhirInitialEncodingError> {
    let name = path.file_name().ok_or(WhirInitialEncodingError::Invalid(
        "artifact path has no file name",
    ))?;
    let mut partial = name.to_os_string();
    partial.push(".partial");
    Ok(path.with_file_name(partial))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> WhirInitialEncodingError {
    WhirInitialEncodingError::Io {
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

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use p3_blake3::Blake3;
    use p3_commit::Mmcs;
    use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

    use super::*;

    static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

    type FieldHash = SerializingHasher<Blake3>;
    type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
    type WhirMmcs = MerkleTreeMmcs<Goldilocks, u8, FieldHash, Compress, 2, 32>;

    struct DenseSource {
        identity: WhirInitialSourceIdentity,
        values: Vec<u64>,
        reads: AtomicUsize,
        max_read: AtomicUsize,
        fail_at: Option<usize>,
        change_len_after_read: bool,
    }

    impl DenseSource {
        fn new(values: Vec<u64>) -> Self {
            let variables = values.len().ilog2() as usize;
            Self {
                identity: identity(variables),
                values,
                reads: AtomicUsize::new(0),
                max_read: AtomicUsize::new(0),
                fail_at: None,
                change_len_after_read: false,
            }
        }

        fn with_identity(values: Vec<u64>, identity: WhirInitialSourceIdentity) -> Self {
            Self {
                identity,
                values,
                reads: AtomicUsize::new(0),
                max_read: AtomicUsize::new(0),
                fail_at: None,
                change_len_after_read: false,
            }
        }
    }

    impl AuthenticatedWhirInitialSource for DenseSource {
        fn identity(&self) -> &WhirInitialSourceIdentity {
            &self.identity
        }

        fn len(&self) -> usize {
            if self.change_len_after_read && self.reads.load(Ordering::SeqCst) != 0 {
                self.values.len() - 1
            } else {
                self.values.len()
            }
        }

        fn read_elements(
            &self,
            start: usize,
            count: usize,
        ) -> Result<Vec<u64>, WhirInitialSourceError> {
            let call = self.reads.fetch_add(1, Ordering::SeqCst);
            self.max_read.fetch_max(count, Ordering::SeqCst);
            if self.fail_at == Some(call) {
                return Err(WhirInitialSourceError::new("injected source failure"));
            }
            self.values
                .get(start..start + count)
                .map(<[u64]>::to_vec)
                .ok_or_else(|| WhirInitialSourceError::new("out of bounds"))
        }
    }

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-whir-initial-{label}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn identity(variables: usize) -> WhirInitialSourceIdentity {
        WhirInitialSourceIdentity {
            source_id: [variables as u8 + 1; 32],
            num_variables: variables as u32,
        }
    }

    fn table(variables: usize) -> Vec<u64> {
        (0..1_usize << variables)
            .map(|index| {
                ((index as u64).wrapping_mul(0x9e37_79b9).wrapping_add(17)) % GOLDILOCKS_MODULUS
            })
            .collect()
    }

    fn expected_codeword(values: &[u64], variables: usize) -> Vec<u64> {
        let height = 1 << (variables - 1);
        let mut padded = vec![Goldilocks::new(0); height * WHIR_INITIAL_WIDTH];
        for (output, value) in padded.iter_mut().zip(values) {
            *output = Goldilocks::new(*value);
        }
        Radix2DFTSmallBatch::new(height)
            .dft_batch(RowMajorMatrix::new(padded, WHIR_INITIAL_WIDTH))
            .values
            .into_iter()
            .map(|value| value.as_canonical_u64())
            .collect()
    }

    fn read_all(artifact: &AuthenticatedWhirInitialCodeword) -> Vec<u64> {
        let mut values = Vec::new();
        for start in (0..artifact.height).step_by(WHIR_INITIAL_MAX_READ_ROWS) {
            let rows = (artifact.height - start).min(WHIR_INITIAL_MAX_READ_ROWS);
            values.extend(artifact.read_canonical_rows(start, rows).unwrap());
        }
        values
    }

    #[test]
    fn external_dft_matches_small_batch_for_small_shapes_and_partitions() {
        for variables in 2..=9 {
            let values = table(variables);
            let expected = expected_codeword(&values, variables);
            for source_chunk in [4, 12, 256] {
                let source = DenseSource::new(values.clone());
                let path = test_path("differential");
                let artifact = encode_with_limits(
                    &path,
                    [0x41; 32],
                    &identity(variables),
                    &source,
                    source_chunk,
                    32,
                )
                .unwrap()
                .remove_on_drop();
                assert_eq!(read_all(&artifact), expected);
                assert!(source.max_read.load(Ordering::SeqCst) <= source_chunk);
            }
        }
    }

    #[test]
    fn n16_boundary_is_natural_order_and_bounded() {
        let variables = 16;
        let values = table(variables);
        let expected = expected_codeword(&values, variables);
        let source = DenseSource::new(values);
        let path = test_path("n16");
        let artifact = encode_whir_initial_suffix(&path, [0x51; 32], &identity(variables), &source)
            .unwrap()
            .remove_on_drop();
        assert_eq!(artifact.identity.height, 1 << 15);
        assert_eq!(Matrix::<Goldilocks>::width(&artifact), 4);
        assert_eq!(read_all(&artifact), expected);
        let matrix_row = artifact
            .row(12_345)
            .unwrap()
            .into_iter()
            .map(|value| value.as_canonical_u64())
            .collect::<Vec<_>>();
        assert_eq!(
            matrix_row,
            expected[12_345 * WHIR_INITIAL_WIDTH..12_346 * WHIR_INITIAL_WIDTH]
        );
        assert!(source.max_read.load(Ordering::SeqCst) <= WHIR_INITIAL_MAX_SOURCE_READ_LIMBS);
    }

    #[test]
    fn n19_research_cap_matches_small_batch() {
        let variables = WHIR_INITIAL_MAX_VARIABLES;
        let values = table(variables);
        let expected = expected_codeword(&values, variables);
        let source = DenseSource::new(values);
        let path = test_path("n19");
        let artifact = encode_whir_initial_suffix(&path, [0x52; 32], &identity(variables), &source)
            .unwrap()
            .remove_on_drop();
        assert_eq!(artifact.identity.height, 1 << 18);
        let authenticated_values = read_all(&artifact);
        assert_eq!(authenticated_values, expected);
        assert_eq!(
            MerkleRowSource::read_rows(&artifact, (1 << 17) - 3, 7).unwrap(),
            expected[((1 << 17) - 3) * WHIR_INITIAL_WIDTH..((1 << 17) + 4) * WHIR_INITIAL_WIDTH]
        );

        let cpu = WhirMmcs::new(FieldHash::new(Blake3), Compress::new(Blake3), 0);
        let matrix = RowMajorMatrix::new(
            authenticated_values
                .into_iter()
                .map(Goldilocks::new)
                .collect(),
            WHIR_INITIAL_WIDTH,
        );
        let (commitment, prover_data) = cpu.commit(vec![matrix]);
        let tree_path = test_path("n19-tree");
        let store = crate::blake3_merkle_store::build_authenticated_blake3_merkle_store(
            &tree_path,
            [0xa5; 32],
            &[&artifact],
        )
        .unwrap()
        .remove_on_drop();
        assert_eq!(store.root().unwrap(), commitment.roots()[0]);
        for index in [0, 1, 255, 256, 1 << 17, (1 << 18) - 1] {
            assert_eq!(
                store.opening_path(index).unwrap(),
                cpu.open_batch(index, &prover_data).opening_proof
            );
        }
    }

    #[test]
    fn over_cap_and_bad_geometry_fail_before_read_or_file_creation() {
        let source = DenseSource::new(vec![0; 4]);
        for (variables, expected_limit) in [(20, true), (1, false)] {
            let path = test_path("preflight");
            let result =
                encode_whir_initial_suffix(&path, [0x61; 32], &identity(variables), &source);
            assert!(if expected_limit {
                matches!(result, Err(WhirInitialEncodingError::ResearchLimit(_)))
            } else {
                matches!(result, Err(WhirInitialEncodingError::Invalid(_)))
            });
            assert_eq!(source.reads.load(Ordering::SeqCst), 0);
            assert!(!path.exists());
            assert!(!partial_path_for(&path).unwrap().exists());
        }

        let path = test_path("wrong-source-identity");
        let expected = identity(4);
        let mut wrong = expected.clone();
        wrong.source_id[0] ^= 1;
        let source = DenseSource::with_identity(table(4), wrong);
        assert!(matches!(
            encode_whir_initial_suffix(&path, [0x62; 32], &expected, &source),
            Err(WhirInitialEncodingError::IdentityMismatch)
        ));
        assert_eq!(source.reads.load(Ordering::SeqCst), 0);
        assert!(!path.exists());
        assert!(!partial_path_for(&path).unwrap().exists());
    }

    #[test]
    fn source_failures_and_geometry_changes_never_publish() {
        let values = table(6);
        let mut failing = DenseSource::new(values.clone());
        failing.fail_at = Some(1);
        let mut changing = DenseSource::new(values);
        changing.change_len_after_read = true;
        for source in [&failing, &changing] {
            let path = test_path("source-failure");
            assert!(encode_with_limits(&path, [0x71; 32], &identity(6), source, 16, 16).is_err());
            assert!(!path.exists());
            assert!(!partial_path_for(&path).unwrap().exists());
        }
    }

    #[test]
    fn no_overwrite_and_noncanonical_source_fail_closed() {
        let path = test_path("no-overwrite");
        fs::write(&path, b"keep").unwrap();
        let source = DenseSource::new(table(4));
        assert!(matches!(
            encode_whir_initial_suffix(&path, [0x81; 32], &identity(4), &source),
            Err(WhirInitialEncodingError::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        fs::remove_file(&path).unwrap();

        let path = test_path("noncanonical");
        let mut values = table(4);
        values[3] = GOLDILOCKS_MODULUS;
        let source = DenseSource::new(values);
        assert!(matches!(
            encode_whir_initial_suffix(&path, [0x82; 32], &identity(4), &source),
            Err(WhirInitialEncodingError::Invalid(_))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn dft_staging_read_rejects_noncanonical_words() {
        let path = test_path("noncanonical-staging");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len((HEADER_BYTES + WHIR_INITIAL_WIDTH * 8) as u64)
            .unwrap();
        file.seek(SeekFrom::Start(data_offset(0).unwrap())).unwrap();
        file.write_all(&GOLDILOCKS_MODULUS.to_le_bytes()).unwrap();
        let mut values = [0_u64; WHIR_INITIAL_WIDTH];
        assert!(matches!(
            read_values(&mut file, &path, 0, &mut values),
            Err(WhirInitialEncodingError::Invalid(_))
        ));
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn corruption_is_rejected_on_reopen_and_random_read() {
        let path = test_path("corruption");
        let source = DenseSource::new(table(6));
        let artifact =
            encode_whir_initial_suffix(&path, [0x91; 32], &identity(6), &source).unwrap();
        let expected = artifact.identity().clone();
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer
            .seek(SeekFrom::Start(HEADER_BYTES as u64 + 8))
            .unwrap();
        writer.write_all(&123_u64.to_le_bytes()).unwrap();
        writer.sync_all().unwrap();
        assert!(matches!(
            artifact.read_canonical_rows(0, 1),
            Err(WhirInitialEncodingError::ChecksumMismatch)
        ));
        drop(artifact);
        assert!(matches!(
            AuthenticatedWhirInitialCodeword::open(&path, &expected),
            Err(WhirInitialEncodingError::ChecksumMismatch)
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn trusted_identity_rejects_a_self_consistent_artifact_substitution() {
        let original_path = test_path("original");
        let substitute_path = test_path("substitute");
        let source_identity = identity(6);
        let original_source = DenseSource::new(table(6));
        let original = encode_whir_initial_suffix(
            &original_path,
            [0xa1; 32],
            &source_identity,
            &original_source,
        )
        .unwrap();
        let trusted_identity = original.identity().clone();
        drop(original);

        let mut substitute_values = table(6);
        substitute_values[7] += 1;
        let substitute_source = DenseSource::with_identity(substitute_values, source_identity);
        let substitute = encode_whir_initial_suffix(
            &substitute_path,
            [0xa1; 32],
            &trusted_identity.source,
            &substitute_source,
        )
        .unwrap();
        assert_ne!(
            substitute.identity().artifact_digest,
            trusted_identity.artifact_digest
        );
        drop(substitute);

        assert!(matches!(
            AuthenticatedWhirInitialCodeword::open(&substitute_path, &trusted_identity),
            Err(WhirInitialEncodingError::IdentityMismatch)
        ));
        fs::remove_file(original_path).unwrap();
        fs::remove_file(substitute_path).unwrap();
    }
}
