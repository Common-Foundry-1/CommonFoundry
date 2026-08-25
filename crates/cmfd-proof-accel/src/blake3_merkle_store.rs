//! Bounded, authenticated disk storage for WHIR's binary BLAKE3 Merkle tree.
//!
//! This is a prover-side research primitive. It deliberately supports only
//! equal-height, power-of-two matrices and a height-zero cap, which is the
//! initial WHIR commitment shape needed by Common Foundry. Reopening requires
//! an exact identity retained outside the artifact; the checksums stored in the
//! same file provide integrity, not provenance. This module does not change
//! proof activation or the production model-table limits.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use blake3::Hasher;
use same_file::Handle;
use thiserror::Error;

use crate::merkle_store::{GOLDILOCKS_MODULUS, MerkleRowSource};

/// The byte digest used by Common Foundry's WHIR MMCS.
pub type Blake3MerkleDigest = [u8; 32];

/// Maximum matrix height admitted by this bounded research checkpoint.
/// This covers the proposed `n = 19` base-input codeword, not an `n = 31` weight bank.
pub const MAX_BLAKE3_MERKLE_ROWS: usize = 1 << 18;

/// Maximum concatenated leaf-row width admitted by this checkpoint.
pub const MAX_BLAKE3_MERKLE_ROW_WORDS: usize = 1 << 14;

/// Number of tree digests covered by one independently authenticated chunk.
pub const BLAKE3_AUTH_CHUNK_DIGESTS: u64 = 256;

/// Preferred number of matrix rows fetched for one leaf-hashing pass.
///
/// Wide matrices are automatically reduced below this bound so a valid width
/// cannot force a proportional multi-gigabyte temporary allocation.
pub const BLAKE3_LEAF_BATCH_ROWS: usize = 8 * 1024;

/// Maximum bytes authenticated for one random tree-digest read.
pub const MAX_BLAKE3_AUTHENTICATED_READ_BYTES: usize =
    BLAKE3_AUTH_CHUNK_DIGESTS as usize * BLAKE3_DIGEST_BYTES;

const MAGIC: &[u8; 8] = b"CMFDB3M1";
const VERSION: u32 = 1;
const FIXED_HEADER_BYTES: usize = 128;
const MATRIX_RECORD_BYTES: usize = 8;
const MAX_HEADER_BYTES: usize = FIXED_HEADER_BYTES + MAX_MATRICES * MATRIX_RECORD_BYTES;
const GLOBAL_DIGEST_OFFSET: usize = 80;
const GLOBAL_DIGEST_END: usize = GLOBAL_DIGEST_OFFSET + 32;
const BLAKE3_DIGEST_BYTES: usize = 32;
const MAX_MATRICES: usize = 64;
const HEADER_DOMAIN: &[u8] = b"CMFD-BLAKE3-MERKLE-HEADER-V1";
const GLOBAL_DOMAIN: &[u8] = b"CMFD-BLAKE3-MERKLE-GLOBAL-V1";
const CHUNK_DOMAIN: &[u8] = b"CMFD-BLAKE3-MERKLE-CHUNK-V1";
const MAX_LEAF_BATCH_WORDS: usize = 1 << 20;
const CREATE_ATTEMPTS: usize = 256;

static NEXT_STAGING_FILE: AtomicU64 = AtomicU64::new(0);

/// Fallible source for a precomputed, unpadded BLAKE3 leaf-digest layer.
pub trait Blake3DigestSource: Sync {
    fn height(&self) -> usize;

    fn read_digests(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError>;
}

/// Exact caller-trusted identity required to reopen one sealed artifact.
///
/// The descriptor must be retained in trusted configuration or a signed
/// manifest rather than recovered from the same store file it authenticates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake3MerkleStoreIdentity {
    pub store_id: [u8; 32],
    pub height: usize,
    pub ordered_matrix_widths: Vec<usize>,
    pub tree_root: Blake3MerkleDigest,
    pub artifact_global_digest: [u8; 32],
}

/// Exact checked byte geometry for one format-v1 Merkle-store artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake3MerkleStoreGeometry {
    pub height: u64,
    pub matrix_count: u32,
    pub total_row_words: u64,
    pub header_bytes: u64,
    pub total_digests: u64,
    pub digest_bytes: u64,
    pub authentication_chunks: u64,
    pub authentication_bytes: u64,
    pub artifact_bytes: u64,
}

/// One authenticated WHIR MMCS opening using canonical Goldilocks rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedBlake3MerkleOpening {
    pub opened_rows: Vec<Vec<u64>>,
    pub opening_path: Vec<Blake3MerkleDigest>,
}

#[derive(Debug, Error)]
pub enum Blake3MerkleStoreError {
    #[error("invalid BLAKE3 Merkle store: {0}")]
    Invalid(&'static str),
    #[error("BLAKE3 Merkle row source failed: {0}")]
    Source(String),
    #[error("BLAKE3 Merkle research limit exceeded: {0}")]
    ResearchLimit(&'static str),
    #[error("BLAKE3 Merkle store already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("BLAKE3 Merkle store parent directory must already exist: {0}")]
    InvalidParentDirectory(PathBuf),
    #[error(
        "BLAKE3 Merkle store parent directory has insufficient free space: need {required} bytes, have {available} bytes"
    )]
    InsufficientSpace { required: u64, available: u64 },
    #[error("could not allocate a unique BLAKE3 Merkle staging file in {0}")]
    NameExhausted(PathBuf),
    #[error("BLAKE3 Merkle store I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("BLAKE3 Merkle store checksum does not match")]
    ChecksumMismatch,
    #[error("BLAKE3 Merkle store identity does not match the caller-trusted identity")]
    IdentityMismatch,
    #[error("BLAKE3 Merkle opening does not reconstruct the pinned tree root")]
    OpeningMismatch,
    #[error("BLAKE3 Merkle cleanup path no longer names the owned file: {0}")]
    CleanupTargetChanged(PathBuf),
    #[error("BLAKE3 Merkle store file lock is poisoned")]
    LockPoisoned,
}

/// Fully authenticated, immutable disk-backed BLAKE3 tree data.
///
/// Opening authenticates the complete artifact. Each later random tree-digest
/// read reauthenticates its fixed-size chunk, so mutation of values used by an
/// opening fails closed.
pub struct AuthenticatedBlake3MerkleStore {
    file: Option<Mutex<File>>,
    path: PathBuf,
    store_id: [u8; 32],
    height: usize,
    matrix_widths: Vec<usize>,
    header_len: u64,
    total_digests: u64,
    tree_root: Blake3MerkleDigest,
    header_binding: [u8; 32],
    global_digest: [u8; 32],
    auth_chunk_digests: Vec<[u8; 32]>,
    cleanup_path: Option<PathBuf>,
}

impl AuthenticatedBlake3MerkleStore {
    /// Open a sealed store and require its fully authenticated contents to
    /// match an exact identity retained outside the artifact.
    pub fn open(
        path: impl AsRef<Path>,
        expected: &Blake3MerkleStoreIdentity,
    ) -> Result<Self, Blake3MerkleStoreError> {
        Self::open_checked(path.as_ref(), Some(expected))
    }

    /// Open and completely checksum one builder-owned staging artifact.
    ///
    /// This deliberately remains private: checksums embedded in the same file
    /// cannot distinguish an intact artifact from a self-consistent substitute.
    fn open_integrity_only(path: impl AsRef<Path>) -> Result<Self, Blake3MerkleStoreError> {
        Self::open_checked(path.as_ref(), None)
    }

    fn open_checked(
        path: &Path,
        expected: Option<&Blake3MerkleStoreIdentity>,
    ) -> Result<Self, Blake3MerkleStoreError> {
        let path = path.to_path_buf();
        let mut file = File::open(&path).map_err(|source| io_error("opening", &path, source))?;
        let file_len = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();

        let mut fixed = [0_u8; FIXED_HEADER_BYTES];
        file.read_exact(&mut fixed)
            .map_err(|source| io_error("reading header from", &path, source))?;
        if &fixed[..8] != MAGIC {
            return Err(Blake3MerkleStoreError::Invalid("wrong magic"));
        }
        if read_u32(&fixed, 8) != VERSION {
            return Err(Blake3MerkleStoreError::Invalid("unsupported version"));
        }
        let header_len = usize::try_from(read_u32(&fixed, 12))
            .map_err(|_| Blake3MerkleStoreError::Invalid("header length does not fit memory"))?;
        if header_len < FIXED_HEADER_BYTES {
            return Err(Blake3MerkleStoreError::Invalid("header is too short"));
        }
        if header_len > MAX_HEADER_BYTES {
            return Err(Blake3MerkleStoreError::Invalid("header is too large"));
        }
        let mut header = vec![0_u8; header_len];
        header[..FIXED_HEADER_BYTES].copy_from_slice(&fixed);
        file.read_exact(&mut header[FIXED_HEADER_BYTES..])
            .map_err(|source| io_error("reading header from", &path, source))?;

        let store_id: [u8; 32] = header[16..48].try_into().expect("fixed store-ID slice");
        if store_id == [0_u8; 32] {
            return Err(Blake3MerkleStoreError::Invalid("store ID must be nonzero"));
        }
        let height = usize::try_from(read_u64(&header, 48))
            .map_err(|_| Blake3MerkleStoreError::Invalid("height does not fit memory"))?;
        validate_height(height)?;
        let matrix_count = usize::try_from(read_u32(&header, 56))
            .map_err(|_| Blake3MerkleStoreError::Invalid("matrix count does not fit memory"))?;
        if matrix_count == 0 || matrix_count > MAX_MATRICES {
            return Err(Blake3MerkleStoreError::Invalid(
                "matrix count is outside 1..=64",
            ));
        }
        let expected_header_len = FIXED_HEADER_BYTES
            .checked_add(
                matrix_count
                    .checked_mul(MATRIX_RECORD_BYTES)
                    .ok_or(Blake3MerkleStoreError::Invalid("header length overflow"))?,
            )
            .ok_or(Blake3MerkleStoreError::Invalid("header length overflow"))?;
        if header_len != expected_header_len {
            return Err(Blake3MerkleStoreError::Invalid(
                "header length is inconsistent",
            ));
        }
        let total_digests = read_u64(&header, 64);
        if total_digests != total_digest_count(height)? {
            return Err(Blake3MerkleStoreError::Invalid(
                "total digest count is inconsistent",
            ));
        }
        let auth_count = read_u64(&header, 72);
        if auth_count != auth_chunk_count(total_digests)? {
            return Err(Blake3MerkleStoreError::Invalid(
                "authentication count is inconsistent",
            ));
        }
        if read_u32(&header, 60) != height.ilog2() + 1 {
            return Err(Blake3MerkleStoreError::Invalid(
                "layer count is inconsistent",
            ));
        }
        if header[112..FIXED_HEADER_BYTES]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(Blake3MerkleStoreError::Invalid(
                "reserved header bytes must be zero",
            ));
        }
        let global_digest: [u8; 32] = header[GLOBAL_DIGEST_OFFSET..GLOBAL_DIGEST_END]
            .try_into()
            .expect("fixed global-digest slice");
        let matrix_widths = decode_widths(&header, matrix_count)?;
        validate_total_width(&matrix_widths)?;

        let expected_len = (header_len as u64)
            .checked_add(
                total_digests
                    .checked_mul(BLAKE3_DIGEST_BYTES as u64)
                    .ok_or(Blake3MerkleStoreError::Invalid("data length overflow"))?,
            )
            .and_then(|length| {
                auth_count
                    .checked_mul(BLAKE3_DIGEST_BYTES as u64)
                    .and_then(|auth_bytes| length.checked_add(auth_bytes))
            })
            .ok_or(Blake3MerkleStoreError::Invalid("file length overflow"))?;
        if file_len != expected_len {
            return Err(Blake3MerkleStoreError::Invalid(
                "file length is inconsistent",
            ));
        }

        // Reject an intact but untrusted substitute after reading only its
        // bounded header and root digest. Matching identities still take the
        // complete authentication path below before a handle is returned.
        let root_offset = (header_len as u64)
            .checked_add(
                total_digests
                    .checked_sub(1)
                    .and_then(|index| index.checked_mul(BLAKE3_DIGEST_BYTES as u64))
                    .ok_or(Blake3MerkleStoreError::Invalid("root offset overflow"))?,
            )
            .ok_or(Blake3MerkleStoreError::Invalid("root offset overflow"))?;
        file.seek(SeekFrom::Start(root_offset))
            .map_err(|source| io_error("seeking to root in", &path, source))?;
        let mut tree_root = [0_u8; BLAKE3_DIGEST_BYTES];
        file.read_exact(&mut tree_root)
            .map_err(|source| io_error("reading root from", &path, source))?;
        if expected.is_some_and(|identity| {
            identity.store_id != store_id
                || identity.height != height
                || identity.ordered_matrix_widths.as_slice() != matrix_widths
                || identity.tree_root != tree_root
                || identity.artifact_global_digest != global_digest
        }) {
            return Err(Blake3MerkleStoreError::IdentityMismatch);
        }

        let header_binding = compute_header_binding(&header);
        let auth_offset = (header_len as u64)
            .checked_add(total_digests * BLAKE3_DIGEST_BYTES as u64)
            .ok_or(Blake3MerkleStoreError::Invalid("auth offset overflow"))?;
        file.seek(SeekFrom::Start(auth_offset))
            .map_err(|source| io_error("seeking in", &path, source))?;
        let auth_count_usize = usize::try_from(auth_count).map_err(|_| {
            Blake3MerkleStoreError::ResearchLimit("authentication table does not fit memory")
        })?;
        let encoded_auth_len = auth_count_usize.checked_mul(BLAKE3_DIGEST_BYTES).ok_or(
            Blake3MerkleStoreError::Invalid("authentication table length overflow"),
        )?;
        let mut encoded_auth = Vec::new();
        encoded_auth
            .try_reserve_exact(encoded_auth_len)
            .map_err(|_| {
                Blake3MerkleStoreError::ResearchLimit("authentication table allocation failed")
            })?;
        encoded_auth.resize(encoded_auth_len, 0);
        file.read_exact(&mut encoded_auth)
            .map_err(|source| io_error("reading authentication table from", &path, source))?;
        let mut auth_chunk_digests = Vec::new();
        auth_chunk_digests
            .try_reserve_exact(auth_count_usize)
            .map_err(|_| {
                Blake3MerkleStoreError::ResearchLimit("authentication table allocation failed")
            })?;
        auth_chunk_digests.extend(
            encoded_auth
                .chunks_exact(BLAKE3_DIGEST_BYTES)
                .map(|digest| {
                    <[u8; BLAKE3_DIGEST_BYTES]>::try_from(digest)
                        .expect("complete authentication digest")
                }),
        );

        authenticate_all_chunks(
            &mut file,
            &path,
            header_len as u64,
            total_digests,
            &header_binding,
            &auth_chunk_digests,
        )?;
        let mut global = global_hasher(&header_binding);
        for digest in &auth_chunk_digests {
            global.update(digest);
        }
        if global.finalize().as_bytes() != &global_digest {
            return Err(Blake3MerkleStoreError::ChecksumMismatch);
        }

        Ok(Self {
            file: Some(Mutex::new(file)),
            path,
            store_id,
            height,
            matrix_widths,
            header_len: header_len as u64,
            total_digests,
            tree_root,
            header_binding,
            global_digest,
            auth_chunk_digests,
            cleanup_path: None,
        })
    }

    pub const fn store_id(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn height(&self) -> usize {
        self.height
    }

    pub fn matrix_widths(&self) -> &[usize] {
        &self.matrix_widths
    }

    pub const fn global_digest(&self) -> [u8; 32] {
        self.global_digest
    }

    /// Return the exact descriptor a caller must retain before later reopen.
    pub fn identity(&self) -> Result<Blake3MerkleStoreIdentity, Blake3MerkleStoreError> {
        Ok(Blake3MerkleStoreIdentity {
            store_id: self.store_id,
            height: self.height,
            ordered_matrix_widths: self.matrix_widths.clone(),
            tree_root: self.root()?,
            artifact_global_digest: self.global_digest,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn remove_on_drop(mut self) -> Self {
        self.cleanup_path = Some(self.path.clone());
        self
    }

    /// Close and explicitly remove an owned artifact.
    ///
    /// Calling this method is the explicit deletion request. By contrast,
    /// automatic cleanup on drop remains opt-in through
    /// [`Self::remove_on_drop`]. Cleanup checks that the path still names the
    /// opened file and never unlinks a replacement.
    pub fn remove(mut self) -> Result<(), Blake3MerkleStoreError> {
        let path = self
            .cleanup_path
            .take()
            .unwrap_or_else(|| self.path.clone());
        let mutex = self.file.take().expect("live Merkle store owns its file");
        let file = mutex
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = remove_owned_file(&path, &file) {
            self.file = Some(Mutex::new(file));
            self.cleanup_path = Some(path);
            return Err(error);
        }
        Ok(())
    }

    pub fn root(&self) -> Result<Blake3MerkleDigest, Blake3MerkleStoreError> {
        let root = self.read_digest(self.total_digests - 1)?;
        if root != self.tree_root {
            return Err(Blake3MerkleStoreError::ChecksumMismatch);
        }
        Ok(root)
    }

    /// Return sibling digests from the leaf layer upward.
    pub fn opening_path(
        &self,
        index: usize,
    ) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
        if index >= self.height {
            return Err(Blake3MerkleStoreError::Invalid(
                "opening index is out of bounds",
            ));
        }
        let mut proof = Vec::new();
        proof
            .try_reserve_exact(self.height.ilog2() as usize)
            .map_err(|_| Blake3MerkleStoreError::ResearchLimit("opening path allocation failed"))?;
        let mut layer_start = 0_u64;
        let mut layer_len = self.height;
        let mut current = index;
        while layer_len > 1 {
            proof.push(self.read_digest(layer_start + (current ^ 1) as u64)?);
            layer_start = layer_start
                .checked_add(layer_len as u64)
                .ok_or(Blake3MerkleStoreError::Invalid("layer offset overflow"))?;
            layer_len /= 2;
            current /= 2;
        }
        Ok(proof)
    }

    /// Re-read canonical matrix rows and return an opening only after it folds
    /// back to the caller-pinned root authenticated at open time.
    pub fn authenticated_opening(
        &self,
        index: usize,
        sources: &[&dyn MerkleRowSource],
    ) -> Result<AuthenticatedBlake3MerkleOpening, Blake3MerkleStoreError> {
        if index >= self.height {
            return Err(Blake3MerkleStoreError::Invalid(
                "opening index is out of bounds",
            ));
        }
        validate_sources_match(sources, self.height, &self.matrix_widths)?;
        let mut opened_rows = Vec::new();
        opened_rows
            .try_reserve_exact(sources.len())
            .map_err(|_| Blake3MerkleStoreError::ResearchLimit("opening-row allocation failed"))?;
        for (source, width) in sources.iter().zip(&self.matrix_widths) {
            let values = source
                .read_rows(index, 1)
                .map_err(|error| Blake3MerkleStoreError::Source(error.to_string()))?;
            if source.height() != self.height || source.width() != *width {
                return Err(Blake3MerkleStoreError::Invalid(
                    "row source geometry changed during opening",
                ));
            }
            if values.len() != *width {
                return Err(Blake3MerkleStoreError::Invalid(
                    "opened row width does not match its matrix",
                ));
            }
            if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
                return Err(Blake3MerkleStoreError::Invalid(
                    "opened row contains a noncanonical Goldilocks word",
                ));
            }
            opened_rows.push(values);
        }
        let opening_path = self.opening_path(index)?;
        let mut hasher = Hasher::new();
        for row in &opened_rows {
            for value in row {
                hasher.update(&value.to_le_bytes());
            }
        }
        let mut reconstructed = *hasher.finalize().as_bytes();
        let mut current = index;
        for sibling in &opening_path {
            reconstructed = if current & 1 == 0 {
                compress([reconstructed, *sibling])
            } else {
                compress([*sibling, reconstructed])
            };
            current >>= 1;
        }
        if reconstructed != self.tree_root {
            return Err(Blake3MerkleStoreError::OpeningMismatch);
        }
        Ok(AuthenticatedBlake3MerkleOpening {
            opened_rows,
            opening_path,
        })
    }

    fn read_digest(&self, global_index: u64) -> Result<Blake3MerkleDigest, Blake3MerkleStoreError> {
        if global_index >= self.total_digests {
            return Err(Blake3MerkleStoreError::Invalid(
                "digest index is out of bounds",
            ));
        }
        let chunk_index = global_index / BLAKE3_AUTH_CHUNK_DIGESTS;
        let chunk_start = chunk_index * BLAKE3_AUTH_CHUNK_DIGESTS;
        let chunk_count = (self.total_digests - chunk_start).min(BLAKE3_AUTH_CHUNK_DIGESTS);
        let encoded_len = usize::try_from(chunk_count)
            .ok()
            .and_then(|count| count.checked_mul(BLAKE3_DIGEST_BYTES))
            .ok_or(Blake3MerkleStoreError::Invalid("chunk length overflow"))?;
        let mut encoded = [0_u8; MAX_BLAKE3_AUTHENTICATED_READ_BYTES];
        let offset = self
            .header_len
            .checked_add(chunk_start * BLAKE3_DIGEST_BYTES as u64)
            .ok_or(Blake3MerkleStoreError::Invalid("chunk offset overflow"))?;
        let mut file = self
            .file
            .as_ref()
            .expect("live Merkle store has an open file")
            .lock()
            .map_err(|_| Blake3MerkleStoreError::LockPoisoned)?;
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut encoded[..encoded_len]))
            .map_err(|source| io_error("reading digest chunk from", &self.path, source))?;
        let expected =
            self.auth_chunk_digests
                .get(usize::try_from(chunk_index).map_err(|_| {
                    Blake3MerkleStoreError::Invalid("chunk index does not fit memory")
                })?)
                .ok_or(Blake3MerkleStoreError::Invalid(
                    "authentication digest is missing",
                ))?;
        let mut hasher = chunk_hasher(&self.header_binding, chunk_index);
        hasher.update(&encoded[..encoded_len]);
        if hasher.finalize().as_bytes() != expected {
            return Err(Blake3MerkleStoreError::ChecksumMismatch);
        }
        let offset_in_chunk = usize::try_from(global_index - chunk_start)
            .ok()
            .and_then(|position| position.checked_mul(BLAKE3_DIGEST_BYTES))
            .ok_or(Blake3MerkleStoreError::Invalid("digest offset overflow"))?;
        Ok(
            encoded[offset_in_chunk..offset_in_chunk + BLAKE3_DIGEST_BYTES]
                .try_into()
                .expect("validated digest slice"),
        )
    }
}

impl Drop for AuthenticatedBlake3MerkleStore {
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

/// Compute exact format-v1 geometry without creating or reading an artifact.
pub fn blake3_merkle_store_geometry(
    height: usize,
    ordered_matrix_widths: &[usize],
) -> Result<Blake3MerkleStoreGeometry, Blake3MerkleStoreError> {
    validate_height(height)?;
    if ordered_matrix_widths.is_empty() || ordered_matrix_widths.len() > MAX_MATRICES {
        return Err(Blake3MerkleStoreError::Invalid(
            "matrix count is outside 1..=64",
        ));
    }
    if ordered_matrix_widths.contains(&0) {
        return Err(Blake3MerkleStoreError::Invalid(
            "matrix width must be nonzero",
        ));
    }
    let total_row_words = validate_total_width(ordered_matrix_widths)?;
    let header_bytes = FIXED_HEADER_BYTES
        .checked_add(
            ordered_matrix_widths
                .len()
                .checked_mul(MATRIX_RECORD_BYTES)
                .ok_or(Blake3MerkleStoreError::Invalid("header length overflow"))?,
        )
        .ok_or(Blake3MerkleStoreError::Invalid("header length overflow"))?;
    let total_digests = total_digest_count(height)?;
    let authentication_chunks = auth_chunk_count(total_digests)?;
    let digest_bytes = total_digests
        .checked_mul(BLAKE3_DIGEST_BYTES as u64)
        .ok_or(Blake3MerkleStoreError::Invalid(
            "digest byte length overflow",
        ))?;
    let authentication_bytes = authentication_chunks
        .checked_mul(BLAKE3_DIGEST_BYTES as u64)
        .ok_or(Blake3MerkleStoreError::Invalid(
            "authentication byte length overflow",
        ))?;
    let artifact_bytes = u64::try_from(header_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(digest_bytes))
        .and_then(|bytes| bytes.checked_add(authentication_bytes))
        .ok_or(Blake3MerkleStoreError::Invalid(
            "artifact byte length overflow",
        ))?;
    Ok(Blake3MerkleStoreGeometry {
        height: u64::try_from(height)
            .map_err(|_| Blake3MerkleStoreError::Invalid("height does not fit u64"))?,
        matrix_count: u32::try_from(ordered_matrix_widths.len())
            .map_err(|_| Blake3MerkleStoreError::Invalid("matrix count does not fit u32"))?,
        total_row_words: u64::try_from(total_row_words)
            .map_err(|_| Blake3MerkleStoreError::Invalid("row width does not fit u64"))?,
        header_bytes: header_bytes as u64,
        total_digests,
        digest_bytes,
        authentication_chunks,
        authentication_bytes,
        artifact_bytes,
    })
}

/// Build a bounded tree by hashing exact canonical Goldilocks rows.
///
/// The destination's parent is an exclusive prover scratch namespace while
/// construction or opted-in cleanup is live. Publication and cleanup verify
/// open-file identity, but portable path verification and unlink are not one
/// atomic filesystem operation.
pub fn build_authenticated_blake3_merkle_store(
    final_path: impl AsRef<Path>,
    store_id: [u8; 32],
    sources: &[&dyn MerkleRowSource],
) -> Result<AuthenticatedBlake3MerkleStore, Blake3MerkleStoreError> {
    build_store(
        final_path.as_ref(),
        store_id,
        sources,
        None,
        BLAKE3_AUTH_CHUNK_DIGESTS as usize,
    )
}

/// Build from canonical rows using a caller-selected batch bounded to 8192.
///
/// The default builder retains its legacy 256-row source contract. Sources
/// that explicitly support larger reads can opt into fewer I/O calls here.
pub fn build_authenticated_blake3_merkle_store_with_leaf_batch_rows(
    final_path: impl AsRef<Path>,
    store_id: [u8; 32],
    sources: &[&dyn MerkleRowSource],
    leaf_batch_rows: usize,
) -> Result<AuthenticatedBlake3MerkleStore, Blake3MerkleStoreError> {
    build_store(
        final_path.as_ref(),
        store_id,
        sources,
        None,
        leaf_batch_rows,
    )
}

/// Build from a caller-supplied unpadded BLAKE3 leaf-digest layer.
///
/// The supplied digests are not trusted or recomputed here. As with Plonky3's
/// first-layer hook, an unchanged CPU verifier must check any completed proof.
pub fn build_authenticated_blake3_merkle_store_with_first_digest_layer(
    final_path: impl AsRef<Path>,
    store_id: [u8; 32],
    sources: &[&dyn MerkleRowSource],
    first_digests: &dyn Blake3DigestSource,
) -> Result<AuthenticatedBlake3MerkleStore, Blake3MerkleStoreError> {
    build_store(
        final_path.as_ref(),
        store_id,
        sources,
        Some(first_digests),
        BLAKE3_LEAF_BATCH_ROWS,
    )
}

fn build_store(
    final_path: &Path,
    store_id: [u8; 32],
    sources: &[&dyn MerkleRowSource],
    first_digests: Option<&dyn Blake3DigestSource>,
    leaf_batch_rows: usize,
) -> Result<AuthenticatedBlake3MerkleStore, Blake3MerkleStoreError> {
    if store_id == [0_u8; 32] {
        return Err(Blake3MerkleStoreError::Invalid("store ID must be nonzero"));
    }
    if leaf_batch_rows == 0 || leaf_batch_rows > BLAKE3_LEAF_BATCH_ROWS {
        return Err(Blake3MerkleStoreError::Invalid(
            "leaf batch must be in 1..=8192 rows",
        ));
    }
    let (height, matrix_widths) = validate_sources(sources)?;
    if let Some(first_digests) = first_digests {
        validate_digest_source(first_digests, height)?;
    }
    let geometry = blake3_merkle_store_geometry(height, &matrix_widths)?;
    let total_digests = geometry.total_digests;
    let auth_count = geometry.authentication_chunks;
    let header = encode_header(store_id, height, &matrix_widths, total_digests, auth_count)?;
    debug_assert_eq!(header.len() as u64, geometry.header_bytes);
    let header_binding = compute_header_binding(&header);

    let final_path = final_path.to_path_buf();
    let parent = artifact_parent(&final_path)?;
    if final_path
        .try_exists()
        .map_err(|source| io_error("checking publication target", &final_path, source))?
    {
        return Err(Blake3MerkleStoreError::AlreadyExists(final_path));
    }
    let available = fs2::available_space(&parent)
        .map_err(|source| io_error("checking free space in", &parent, source))?;
    ensure_available_space(&geometry, available)?;
    let (partial_path, file) = create_unique_staging(&final_path)?;
    let mut staging = OwnedFileLink::new(partial_path.clone(), file);
    staging
        .file_mut()
        .write_all(&header)
        .map_err(|source| io_error("writing header to", &partial_path, source))?;
    let mut writer = DigestWriter::new(
        staging.file_mut(),
        &partial_path,
        header_binding,
        total_digests,
        auth_count,
    )?;

    let total_width = validate_total_width(&matrix_widths)?;
    let leaf_batch_rows = if first_digests.is_some() {
        leaf_batch_rows.min(height)
    } else {
        bounded_leaf_batch_rows(height, total_width, leaf_batch_rows)
    };
    for row_start in (0..height).step_by(leaf_batch_rows) {
        let row_count = (height - row_start).min(leaf_batch_rows);
        let leaves = if let Some(first_digests) = first_digests {
            validate_sources_match(sources, height, &matrix_widths)?;
            read_first_digests(first_digests, height, row_start, row_count)?
        } else {
            hash_rows(sources, &matrix_widths, height, row_start, row_count)?
        };
        validate_sources_match(sources, height, &matrix_widths)?;
        writer.write_digests(&leaves)?;
    }
    writer.flush()?;

    let mut reader = File::open(&partial_path)
        .map_err(|source| io_error("opening construction reader for", &partial_path, source))?;
    let mut previous_start = header.len() as u64;
    let mut previous_len = height;
    while previous_len > 1 {
        reader
            .seek(SeekFrom::Start(previous_start))
            .map_err(|source| io_error("seeking in", &partial_path, source))?;
        let mut remaining_parents = previous_len / 2;
        while remaining_parents != 0 {
            let parent_count = remaining_parents.min(BLAKE3_LEAF_BATCH_ROWS);
            let children = read_raw_digests(
                &mut reader,
                &partial_path,
                parent_count
                    .checked_mul(2)
                    .ok_or(Blake3MerkleStoreError::Invalid("parent batch overflow"))?,
            )?;
            let mut parents = Vec::new();
            parents.try_reserve_exact(parent_count).map_err(|_| {
                Blake3MerkleStoreError::ResearchLimit("parent digest allocation failed")
            })?;
            parents.extend(
                children
                    .chunks_exact(2)
                    .map(|pair| compress([pair[0], pair[1]])),
            );
            writer.write_digests(&parents)?;
            remaining_parents -= parent_count;
        }
        writer.flush()?;
        previous_start = previous_start
            .checked_add(previous_len as u64 * BLAKE3_DIGEST_BYTES as u64)
            .ok_or(Blake3MerkleStoreError::Invalid("layer offset overflow"))?;
        previous_len /= 2;
    }
    writer.seal()?;
    drop(reader);

    let staged_store = AuthenticatedBlake3MerkleStore::open_integrity_only(&partial_path)?;
    let expected_identity = staged_store.identity()?;
    ensure_path_names_file(&partial_path, staging.file_ref())?;
    let mut published =
        publish_verified_no_overwrite(&partial_path, &final_path, staging.file_ref())?;
    let store = AuthenticatedBlake3MerkleStore::open(&final_path, &expected_identity)?;
    drop(staged_store);
    remove_owned_file(&partial_path, staging.file_ref())?;
    staging.disarm();
    published.disarm();
    Ok(store)
}

fn validate_sources(
    sources: &[&dyn MerkleRowSource],
) -> Result<(usize, Vec<usize>), Blake3MerkleStoreError> {
    if sources.is_empty() || sources.len() > MAX_MATRICES {
        return Err(Blake3MerkleStoreError::Invalid(
            "matrix count is outside 1..=64",
        ));
    }
    let height = sources[0].height();
    validate_height(height)?;
    let mut widths = Vec::new();
    widths
        .try_reserve_exact(sources.len())
        .map_err(|_| Blake3MerkleStoreError::ResearchLimit("matrix metadata allocation failed"))?;
    for source in sources {
        if source.height() != height {
            return Err(Blake3MerkleStoreError::Invalid(
                "all matrices must have equal height",
            ));
        }
        if source.width() == 0 {
            return Err(Blake3MerkleStoreError::Invalid(
                "matrix width must be nonzero",
            ));
        }
        widths.push(source.width());
    }
    validate_total_width(&widths)?;
    Ok((height, widths))
}

fn validate_height(height: usize) -> Result<(), Blake3MerkleStoreError> {
    if height == 0 || !height.is_power_of_two() {
        return Err(Blake3MerkleStoreError::Invalid(
            "matrix height must be a nonzero power of two",
        ));
    }
    if height > MAX_BLAKE3_MERKLE_ROWS {
        return Err(Blake3MerkleStoreError::ResearchLimit(
            "matrix height exceeds the bounded checkpoint",
        ));
    }
    Ok(())
}

fn validate_total_width(widths: &[usize]) -> Result<usize, Blake3MerkleStoreError> {
    let total = widths.iter().try_fold(0_usize, |total, width| {
        total
            .checked_add(*width)
            .ok_or(Blake3MerkleStoreError::Invalid(
                "aggregate matrix width overflow",
            ))
    })?;
    if total == 0 || total > MAX_BLAKE3_MERKLE_ROW_WORDS {
        return Err(Blake3MerkleStoreError::ResearchLimit(
            "aggregate row width exceeds the bounded checkpoint",
        ));
    }
    Ok(total)
}

fn validate_sources_match(
    sources: &[&dyn MerkleRowSource],
    height: usize,
    widths: &[usize],
) -> Result<(), Blake3MerkleStoreError> {
    if sources.len() != widths.len()
        || sources
            .iter()
            .zip(widths)
            .any(|(source, width)| source.height() != height || source.width() != *width)
    {
        return Err(Blake3MerkleStoreError::Invalid(
            "row source geometry changed during construction",
        ));
    }
    Ok(())
}

fn hash_rows(
    sources: &[&dyn MerkleRowSource],
    widths: &[usize],
    height: usize,
    row_start: usize,
    row_count: usize,
) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
    let row_end = row_start
        .checked_add(row_count)
        .ok_or(Blake3MerkleStoreError::Invalid("row range overflow"))?;
    if row_count == 0 || row_end > height || sources.len() != widths.len() {
        return Err(Blake3MerkleStoreError::Invalid(
            "row batch is out of bounds",
        ));
    }
    let mut batches = Vec::new();
    batches
        .try_reserve_exact(sources.len())
        .map_err(|_| Blake3MerkleStoreError::ResearchLimit("row batch allocation failed"))?;
    for (source, width) in sources.iter().zip(widths) {
        if source.height() != height || source.width() != *width {
            return Err(Blake3MerkleStoreError::Invalid(
                "row source geometry changed during construction",
            ));
        }
        let values = source
            .read_rows(row_start, row_count)
            .map_err(|error| Blake3MerkleStoreError::Source(error.to_string()))?;
        if source.height() != height || source.width() != *width {
            return Err(Blake3MerkleStoreError::Invalid(
                "row source geometry changed during construction",
            ));
        }
        let expected = row_count
            .checked_mul(*width)
            .ok_or(Blake3MerkleStoreError::Invalid("row batch length overflow"))?;
        if values.len() != expected {
            return Err(Blake3MerkleStoreError::Invalid(
                "row batch width does not match its matrix",
            ));
        }
        if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
            return Err(Blake3MerkleStoreError::Invalid(
                "row batch contains a noncanonical Goldilocks word",
            ));
        }
        batches.push(values);
    }
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(row_count)
        .map_err(|_| Blake3MerkleStoreError::ResearchLimit("leaf digest allocation failed"))?;
    for row_offset in 0..row_count {
        let mut hasher = Hasher::new();
        for (values, width) in batches.iter().zip(widths) {
            let start = row_offset * width;
            for value in &values[start..start + width] {
                hasher.update(&value.to_le_bytes());
            }
        }
        digests.push(*hasher.finalize().as_bytes());
    }
    Ok(digests)
}

fn validate_digest_source(
    source: &dyn Blake3DigestSource,
    height: usize,
) -> Result<(), Blake3MerkleStoreError> {
    if source.height() != height {
        return Err(Blake3MerkleStoreError::Invalid(
            "first digest layer height must equal the matrix height",
        ));
    }
    Ok(())
}

fn read_first_digests(
    source: &dyn Blake3DigestSource,
    height: usize,
    row_start: usize,
    row_count: usize,
) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
    validate_digest_source(source, height)?;
    let digests = source.read_digests(row_start, row_count)?;
    validate_digest_source(source, height)?;
    if digests.len() != row_count {
        return Err(Blake3MerkleStoreError::Invalid(
            "first digest row count is inconsistent",
        ));
    }
    Ok(digests)
}

fn compress(children: [Blake3MerkleDigest; 2]) -> Blake3MerkleDigest {
    let mut hasher = Hasher::new();
    hasher.update(&children[0]);
    hasher.update(&children[1]);
    *hasher.finalize().as_bytes()
}

fn total_digest_count(height: usize) -> Result<u64, Blake3MerkleStoreError> {
    u64::try_from(height)
        .ok()
        .and_then(|height| height.checked_mul(2))
        .and_then(|count| count.checked_sub(1))
        .ok_or(Blake3MerkleStoreError::Invalid(
            "total digest count overflow",
        ))
}

fn auth_chunk_count(total_digests: u64) -> Result<u64, Blake3MerkleStoreError> {
    total_digests
        .checked_add(BLAKE3_AUTH_CHUNK_DIGESTS - 1)
        .map(|count| count / BLAKE3_AUTH_CHUNK_DIGESTS)
        .ok_or(Blake3MerkleStoreError::Invalid(
            "authentication count overflow",
        ))
}

fn encode_header(
    store_id: [u8; 32],
    height: usize,
    widths: &[usize],
    total_digests: u64,
    auth_count: u64,
) -> Result<Vec<u8>, Blake3MerkleStoreError> {
    let header_len = FIXED_HEADER_BYTES
        .checked_add(
            widths
                .len()
                .checked_mul(MATRIX_RECORD_BYTES)
                .ok_or(Blake3MerkleStoreError::Invalid("header length overflow"))?,
        )
        .ok_or(Blake3MerkleStoreError::Invalid("header length overflow"))?;
    let mut header = vec![0_u8; header_len];
    header[..8].copy_from_slice(MAGIC);
    put_u32(&mut header, 8, VERSION);
    put_u32(
        &mut header,
        12,
        u32::try_from(header_len)
            .map_err(|_| Blake3MerkleStoreError::Invalid("header length does not fit u32"))?,
    );
    header[16..48].copy_from_slice(&store_id);
    put_u64(
        &mut header,
        48,
        u64::try_from(height)
            .map_err(|_| Blake3MerkleStoreError::Invalid("height does not fit u64"))?,
    );
    put_u32(
        &mut header,
        56,
        u32::try_from(widths.len())
            .map_err(|_| Blake3MerkleStoreError::Invalid("matrix count does not fit u32"))?,
    );
    put_u32(&mut header, 60, height.ilog2() + 1);
    put_u64(&mut header, 64, total_digests);
    put_u64(&mut header, 72, auth_count);
    for (index, width) in widths.iter().enumerate() {
        put_u64(
            &mut header,
            FIXED_HEADER_BYTES + index * MATRIX_RECORD_BYTES,
            u64::try_from(*width)
                .map_err(|_| Blake3MerkleStoreError::Invalid("width does not fit u64"))?,
        );
    }
    Ok(header)
}

fn decode_widths(header: &[u8], matrix_count: usize) -> Result<Vec<usize>, Blake3MerkleStoreError> {
    let mut widths = Vec::new();
    widths
        .try_reserve_exact(matrix_count)
        .map_err(|_| Blake3MerkleStoreError::ResearchLimit("matrix metadata allocation failed"))?;
    for index in 0..matrix_count {
        let width = usize::try_from(read_u64(
            header,
            FIXED_HEADER_BYTES + index * MATRIX_RECORD_BYTES,
        ))
        .map_err(|_| Blake3MerkleStoreError::Invalid("width does not fit memory"))?;
        if width == 0 {
            return Err(Blake3MerkleStoreError::Invalid(
                "matrix width must be nonzero",
            ));
        }
        widths.push(width);
    }
    Ok(widths)
}

fn compute_header_binding(header: &[u8]) -> [u8; 32] {
    let mut canonical = header.to_vec();
    canonical[GLOBAL_DIGEST_OFFSET..GLOBAL_DIGEST_END].fill(0);
    let mut hasher = Hasher::new();
    hasher.update(HEADER_DOMAIN);
    hasher.update(&canonical);
    *hasher.finalize().as_bytes()
}

fn global_hasher(header_binding: &[u8; 32]) -> Hasher {
    let mut hasher = Hasher::new();
    hasher.update(GLOBAL_DOMAIN);
    hasher.update(header_binding);
    hasher
}

fn chunk_hasher(header_binding: &[u8; 32], chunk_index: u64) -> Hasher {
    let mut hasher = Hasher::new();
    hasher.update(CHUNK_DOMAIN);
    hasher.update(header_binding);
    hasher.update(&chunk_index.to_le_bytes());
    hasher
}

fn authenticate_all_chunks(
    file: &mut File,
    path: &Path,
    header_len: u64,
    total_digests: u64,
    header_binding: &[u8; 32],
    expected: &[[u8; 32]],
) -> Result<(), Blake3MerkleStoreError> {
    file.seek(SeekFrom::Start(header_len))
        .map_err(|source| io_error("seeking in", path, source))?;
    let mut remaining = total_digests;
    let mut encoded = [0_u8; MAX_BLAKE3_AUTHENTICATED_READ_BYTES];
    for (chunk_index, expected_digest) in expected.iter().enumerate() {
        let chunk_count = remaining.min(BLAKE3_AUTH_CHUNK_DIGESTS);
        let byte_count = usize::try_from(chunk_count)
            .ok()
            .and_then(|count| count.checked_mul(BLAKE3_DIGEST_BYTES))
            .ok_or(Blake3MerkleStoreError::Invalid("chunk length overflow"))?;
        file.read_exact(&mut encoded[..byte_count])
            .map_err(|source| io_error("authenticating digest data in", path, source))?;
        let mut hasher = chunk_hasher(header_binding, chunk_index as u64);
        hasher.update(&encoded[..byte_count]);
        if hasher.finalize().as_bytes() != expected_digest {
            return Err(Blake3MerkleStoreError::ChecksumMismatch);
        }
        remaining -= chunk_count;
    }
    if remaining != 0 {
        return Err(Blake3MerkleStoreError::Invalid(
            "authentication table is incomplete",
        ));
    }
    Ok(())
}

struct DigestWriter<'a> {
    file: &'a mut File,
    path: &'a Path,
    header_binding: [u8; 32],
    total_expected: u64,
    written: u64,
    chunk_hasher: Hasher,
    chunk_fill: u64,
    auth_digests: Vec<[u8; 32]>,
}

impl<'a> DigestWriter<'a> {
    fn new(
        file: &'a mut File,
        path: &'a Path,
        header_binding: [u8; 32],
        total_expected: u64,
        auth_count: u64,
    ) -> Result<Self, Blake3MerkleStoreError> {
        let auth_count = usize::try_from(auth_count).map_err(|_| {
            Blake3MerkleStoreError::ResearchLimit("authentication table does not fit memory")
        })?;
        let mut auth_digests = Vec::new();
        auth_digests.try_reserve_exact(auth_count).map_err(|_| {
            Blake3MerkleStoreError::ResearchLimit("authentication table allocation failed")
        })?;
        Ok(Self {
            file,
            path,
            header_binding,
            total_expected,
            written: 0,
            chunk_hasher: chunk_hasher(&header_binding, 0),
            chunk_fill: 0,
            auth_digests,
        })
    }

    fn write_digests(
        &mut self,
        digests: &[Blake3MerkleDigest],
    ) -> Result<(), Blake3MerkleStoreError> {
        let count = u64::try_from(digests.len())
            .map_err(|_| Blake3MerkleStoreError::Invalid("digest batch does not fit u64"))?;
        if self
            .written
            .checked_add(count)
            .is_none_or(|written| written > self.total_expected)
        {
            return Err(Blake3MerkleStoreError::Invalid(
                "too many digests were written",
            ));
        }
        let encoded_len = digests.len().checked_mul(BLAKE3_DIGEST_BYTES).ok_or(
            Blake3MerkleStoreError::Invalid("digest batch length overflow"),
        )?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encoded_len)
            .map_err(|_| Blake3MerkleStoreError::ResearchLimit("digest batch allocation failed"))?;
        for digest in digests {
            encoded.extend_from_slice(digest);
        }
        self.file
            .write_all(&encoded)
            .map_err(|source| io_error("writing digest data to", self.path, source))?;

        let mut digest_offset = 0_usize;
        while digest_offset < digests.len() {
            let available = usize::try_from(BLAKE3_AUTH_CHUNK_DIGESTS - self.chunk_fill)
                .expect("authentication chunk size fits memory");
            let take = (digests.len() - digest_offset).min(available);
            let byte_start = digest_offset * BLAKE3_DIGEST_BYTES;
            let byte_end = (digest_offset + take) * BLAKE3_DIGEST_BYTES;
            self.chunk_hasher.update(&encoded[byte_start..byte_end]);
            let take_u64 = take as u64;
            self.written += take_u64;
            self.chunk_fill += take_u64;
            digest_offset += take;
            if self.chunk_fill == BLAKE3_AUTH_CHUNK_DIGESTS {
                self.finish_chunk();
            }
        }
        Ok(())
    }

    fn finish_chunk(&mut self) {
        self.auth_digests
            .push(*self.chunk_hasher.finalize().as_bytes());
        self.chunk_fill = 0;
        self.chunk_hasher = chunk_hasher(&self.header_binding, self.auth_digests.len() as u64);
    }

    fn flush(&mut self) -> Result<(), Blake3MerkleStoreError> {
        self.file
            .flush()
            .map_err(|source| io_error("flushing digest data in", self.path, source))
    }

    fn seal(mut self) -> Result<(), Blake3MerkleStoreError> {
        if self.written != self.total_expected {
            return Err(Blake3MerkleStoreError::Invalid("digest data is incomplete"));
        }
        if self.chunk_fill != 0 {
            self.finish_chunk();
        }
        if self.auth_digests.len() as u64 != auth_chunk_count(self.total_expected)? {
            return Err(Blake3MerkleStoreError::Invalid(
                "authentication table is incomplete",
            ));
        }
        let mut encoded_authentication = Vec::new();
        let encoded_authentication_len = self
            .auth_digests
            .len()
            .checked_mul(BLAKE3_DIGEST_BYTES)
            .ok_or(Blake3MerkleStoreError::Invalid(
            "authentication-table encoding length overflow",
        ))?;
        encoded_authentication
            .try_reserve_exact(encoded_authentication_len)
            .map_err(|_| {
                Blake3MerkleStoreError::ResearchLimit(
                    "authentication-table encoding allocation failed",
                )
            })?;
        for digest in &self.auth_digests {
            encoded_authentication.extend_from_slice(digest);
        }
        self.file
            .write_all(&encoded_authentication)
            .map_err(|source| io_error("writing authentication table to", self.path, source))?;
        let mut global = global_hasher(&self.header_binding);
        for digest in &self.auth_digests {
            global.update(digest);
        }
        let global_digest = *global.finalize().as_bytes();
        self.file
            .seek(SeekFrom::Start(GLOBAL_DIGEST_OFFSET as u64))
            .and_then(|_| self.file.write_all(&global_digest))
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_all())
            .map_err(|source| io_error("sealing", self.path, source))
    }
}

fn read_raw_digests(
    file: &mut File,
    path: &Path,
    count: usize,
) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
    let encoded_len =
        count
            .checked_mul(BLAKE3_DIGEST_BYTES)
            .ok_or(Blake3MerkleStoreError::Invalid(
                "digest read length overflow",
            ))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| Blake3MerkleStoreError::ResearchLimit("digest read allocation failed"))?;
    encoded.resize(encoded_len, 0);
    file.read_exact(&mut encoded)
        .map_err(|source| io_error("reading digest data from", path, source))?;
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(count)
        .map_err(|_| Blake3MerkleStoreError::ResearchLimit("digest read allocation failed"))?;
    digests.extend(
        encoded
            .chunks_exact(BLAKE3_DIGEST_BYTES)
            .map(|bytes| <[u8; BLAKE3_DIGEST_BYTES]>::try_from(bytes).expect("complete digest")),
    );
    Ok(digests)
}

fn bounded_leaf_batch_rows(height: usize, total_width: usize, requested: usize) -> usize {
    requested
        .min(height)
        .min((MAX_LEAF_BATCH_WORDS / total_width).max(1))
}

fn ensure_available_space(
    geometry: &Blake3MerkleStoreGeometry,
    available: u64,
) -> Result<(), Blake3MerkleStoreError> {
    if available < geometry.artifact_bytes {
        return Err(Blake3MerkleStoreError::InsufficientSpace {
            required: geometry.artifact_bytes,
            available,
        });
    }
    Ok(())
}

fn artifact_parent(path: &Path) -> Result<PathBuf, Blake3MerkleStoreError> {
    if !path.is_absolute() {
        return Err(Blake3MerkleStoreError::Invalid(
            "store path must be absolute",
        ));
    }
    if path.file_name().is_none() {
        return Err(Blake3MerkleStoreError::Invalid(
            "store path has no file name",
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        parent.to_path_buf()
    };
    if !parent.is_dir() {
        return Err(Blake3MerkleStoreError::InvalidParentDirectory(parent));
    }
    Ok(parent)
}

fn create_unique_staging(final_path: &Path) -> Result<(PathBuf, File), Blake3MerkleStoreError> {
    let parent = artifact_parent(final_path)?;
    let file_name = final_path
        .file_name()
        .ok_or(Blake3MerkleStoreError::Invalid(
            "store path has no file name",
        ))?;
    for _ in 0..CREATE_ATTEMPTS {
        let sequence = NEXT_STAGING_FILE.fetch_add(1, Ordering::Relaxed);
        let mut staging_name = file_name.to_os_string();
        staging_name.push(format!(".{}.{sequence}.partial", std::process::id()));
        let partial_path = parent.join(staging_name);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&partial_path)
        {
            Ok(file) => return Ok((partial_path, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("creating", &partial_path, source)),
        }
    }
    Err(Blake3MerkleStoreError::NameExhausted(parent))
}

fn publish_verified_no_overwrite(
    partial_path: &Path,
    final_path: &Path,
    file: &File,
) -> Result<OwnedFileLink, Blake3MerkleStoreError> {
    let cleanup_file = file
        .try_clone()
        .map_err(|source| io_error("cloning publication handle for", final_path, source))?;
    match fs::hard_link(partial_path, final_path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(Blake3MerkleStoreError::AlreadyExists(
                final_path.to_path_buf(),
            ));
        }
        Err(source) => return Err(io_error("publishing", final_path, source)),
    }
    let published = OwnedFileLink::new(final_path.to_path_buf(), cleanup_file);
    ensure_path_names_file(final_path, published.file_ref())?;
    Ok(published)
}

fn remove_owned_file(path: &Path, file: &File) -> Result<(), Blake3MerkleStoreError> {
    ensure_path_names_file(path, file)?;
    fs::remove_file(path).map_err(|source| io_error("removing", path, source))
}

fn ensure_path_names_file(path: &Path, file: &File) -> Result<(), Blake3MerkleStoreError> {
    let owned_handle = Handle::from_file(
        file.try_clone()
            .map_err(|source| io_error("cloning cleanup handle for", path, source))?,
    )
    .map_err(|source| io_error("identifying owned file at", path, source))?;
    let path_handle = Handle::from_path(path)
        .map_err(|source| io_error("identifying cleanup path", path, source))?;
    if owned_handle != path_handle {
        return Err(Blake3MerkleStoreError::CleanupTargetChanged(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

struct OwnedFileLink {
    cleanup_path: Option<PathBuf>,
    file: Option<File>,
}

impl OwnedFileLink {
    fn new(path: PathBuf, file: File) -> Self {
        Self {
            cleanup_path: Some(path),
            file: Some(file),
        }
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("live Merkle-store staging file")
    }

    fn file_ref(&self) -> &File {
        self.file.as_ref().expect("live Merkle-store staging file")
    }

    fn disarm(&mut self) {
        self.cleanup_path.take();
        self.file.take();
    }
}

impl Drop for OwnedFileLink {
    fn drop(&mut self) {
        let (Some(path), Some(file)) = (self.cleanup_path.take(), self.file.take()) else {
            return;
        };
        let _ = remove_owned_file(&path, &file);
    }
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> Blake3MerkleStoreError {
    Blake3MerkleStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated u32 slice"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated u64 slice"),
    )
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use p3_blake3::Blake3;
    use p3_commit::{BatchOpeningRef, Mmcs};
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::Matrix;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};

    use super::*;

    type FieldHash = SerializingHasher<Blake3>;
    type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
    type WhirMmcs = MerkleTreeMmcs<Goldilocks, u8, FieldHash, Compress, 2, 32>;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone)]
    struct DenseRows {
        height: usize,
        width: usize,
        values: Vec<u64>,
    }

    impl DenseRows {
        fn fixture(height: usize, width: usize, seed: u64) -> Self {
            let values = (0..height * width)
                .map(|index| {
                    seed.wrapping_add((index as u64).wrapping_mul(0x9e37_79b9)) % GOLDILOCKS_MODULUS
                })
                .collect();
            Self {
                height,
                width,
                values,
            }
        }

        fn matrix(&self) -> RowMajorMatrix<Goldilocks> {
            RowMajorMatrix::new(
                self.values
                    .iter()
                    .copied()
                    .map(Goldilocks::from_u64)
                    .collect(),
                self.width,
            )
        }

        fn field_row(&self, row: usize) -> Vec<Goldilocks> {
            self.values[row * self.width..(row + 1) * self.width]
                .iter()
                .copied()
                .map(Goldilocks::from_u64)
                .collect()
        }
    }

    impl MerkleRowSource for DenseRows {
        fn height(&self) -> usize {
            self.height
        }

        fn width(&self) -> usize {
            self.width
        }

        fn read_row(&self, row: usize) -> Result<Vec<u64>, crate::merkle_store::MerkleStoreError> {
            if row >= self.height {
                return Err(crate::merkle_store::MerkleStoreError::Invalid(
                    "row is out of bounds",
                ));
            }
            Ok(self.values[row * self.width..(row + 1) * self.width].to_vec())
        }

        fn read_rows(
            &self,
            row_start: usize,
            row_count: usize,
        ) -> Result<Vec<u64>, crate::merkle_store::MerkleStoreError> {
            let row_end = row_start + row_count;
            if row_count == 0 || row_end > self.height {
                return Err(crate::merkle_store::MerkleStoreError::Invalid(
                    "row batch is out of bounds",
                ));
            }
            Ok(self.values[row_start * self.width..row_end * self.width].to_vec())
        }
    }

    struct CountingRows {
        inner: DenseRows,
        calls: AtomicUsize,
        largest_batch: AtomicUsize,
    }

    impl MerkleRowSource for CountingRows {
        fn height(&self) -> usize {
            self.inner.height()
        }

        fn width(&self) -> usize {
            self.inner.width()
        }

        fn read_row(&self, row: usize) -> Result<Vec<u64>, crate::merkle_store::MerkleStoreError> {
            self.inner.read_row(row)
        }

        fn read_rows(
            &self,
            row_start: usize,
            row_count: usize,
        ) -> Result<Vec<u64>, crate::merkle_store::MerkleStoreError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.largest_batch.fetch_max(row_count, Ordering::Relaxed);
            self.inner.read_rows(row_start, row_count)
        }
    }

    struct DenseDigests(Vec<Blake3MerkleDigest>);

    impl Blake3DigestSource for DenseDigests {
        fn height(&self) -> usize {
            self.0.len()
        }

        fn read_digests(
            &self,
            row_start: usize,
            row_count: usize,
        ) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
            let end = row_start
                .checked_add(row_count)
                .ok_or(Blake3MerkleStoreError::Invalid("digest range overflow"))?;
            self.0
                .get(row_start..end)
                .map(<[Blake3MerkleDigest]>::to_vec)
                .ok_or(Blake3MerkleStoreError::Invalid(
                    "digest range is out of bounds",
                ))
        }
    }

    struct CountingDigests {
        height: usize,
        calls: AtomicUsize,
        largest_batch: AtomicUsize,
    }

    impl Blake3DigestSource for CountingDigests {
        fn height(&self) -> usize {
            self.height
        }

        fn read_digests(
            &self,
            row_start: usize,
            row_count: usize,
        ) -> Result<Vec<Blake3MerkleDigest>, Blake3MerkleStoreError> {
            let row_end = row_start
                .checked_add(row_count)
                .ok_or(Blake3MerkleStoreError::Invalid("digest range overflow"))?;
            if row_count == 0 || row_end > self.height {
                return Err(Blake3MerkleStoreError::Invalid(
                    "digest range is out of bounds",
                ));
            }
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.largest_batch.fetch_max(row_count, Ordering::Relaxed);
            Ok((row_start..row_end)
                .map(|row| *blake3::hash(&(row as u64).to_le_bytes()).as_bytes())
                .collect())
        }
    }

    struct PanicRows {
        height: usize,
    }

    impl MerkleRowSource for PanicRows {
        fn height(&self) -> usize {
            self.height
        }

        fn width(&self) -> usize {
            4
        }

        fn read_row(&self, _row: usize) -> Result<Vec<u64>, crate::merkle_store::MerkleStoreError> {
            panic!("research-limit rejection must happen before reading rows")
        }
    }

    fn mmcs() -> WhirMmcs {
        WhirMmcs::new(FieldHash::new(Blake3), Compress::new(Blake3), 0)
    }

    fn test_path(label: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "cmfd-blake3-merkle-{label}-{}-{sequence}.store",
            std::process::id()
        ))
    }

    fn remove_if_present(path: &Path) {
        let _ = fs::remove_file(path);
    }

    fn staging_files_for(path: &Path) -> Vec<PathBuf> {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            return Vec::new();
        };
        let prefix = format!("{file_name}.{}.", std::process::id());
        let Some(parent) = path.parent() else {
            return Vec::new();
        };
        fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".partial"))
            })
            .collect()
    }

    fn first_digests(matrices: &[RowMajorMatrix<Goldilocks>]) -> DenseDigests {
        let hash = FieldHash::new(Blake3);
        let height = matrices[0].height();
        DenseDigests(
            (0..height)
                .map(|row| {
                    hash.hash_iter(
                        matrices
                            .iter()
                            .flat_map(|matrix| matrix.row(row).unwrap().into_iter()),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn whir_leaf_serialization_and_compression_kats() {
        let rows = DenseRows {
            height: 1,
            width: 3,
            values: vec![0, 1, GOLDILOCKS_MODULUS - 1],
        };
        let leaf = hash_rows(&[&rows], &[3], 1, 0, 1).unwrap()[0];
        assert_eq!(
            leaf,
            [
                0xab, 0x9d, 0xd6, 0x39, 0x81, 0xe1, 0x51, 0xc2, 0xf8, 0x4c, 0x60, 0xe1, 0x2d, 0x54,
                0xcb, 0x66, 0x62, 0xe2, 0x39, 0x02, 0xc2, 0x83, 0x2f, 0xca, 0xc3, 0x9b, 0x05, 0xd3,
                0xf6, 0x44, 0x95, 0x01,
            ]
        );

        let left = core::array::from_fn(|index| index as u8);
        let right = core::array::from_fn(|index| (index + 32) as u8);
        assert_eq!(
            compress([left, right]),
            [
                0x4e, 0xed, 0x71, 0x41, 0xea, 0x4a, 0x5c, 0xd4, 0xb7, 0x88, 0x60, 0x6b, 0xd2, 0x3f,
                0x46, 0xe2, 0x12, 0xaf, 0x9c, 0xac, 0xeb, 0xac, 0xdc, 0x7d, 0x1f, 0x4c, 0x6d, 0xc7,
                0xf2, 0x51, 0x1b, 0x98,
            ]
        );
    }

    #[test]
    fn format_v1_artifact_and_global_digests_are_pinned() {
        let rows = DenseRows::fixture(4, 2, 0x1a2b);
        let path = test_path("format-v1-kat");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store(&path, [0x1c; 32], &[&rows])
            .unwrap()
            .remove_on_drop();
        let artifact_digest = *blake3::hash(&fs::read(&path).unwrap()).as_bytes();
        assert_eq!(
            (store.global_digest(), artifact_digest),
            (
                [
                    0xc7, 0x70, 0xec, 0x72, 0xa7, 0xec, 0x16, 0x0c, 0x05, 0xba, 0x1d, 0xb2, 0x91,
                    0xca, 0xbe, 0x39, 0x47, 0xc8, 0x87, 0xba, 0x42, 0x73, 0xb4, 0x0d, 0x4c, 0x58,
                    0x74, 0x43, 0x03, 0x12, 0xe1, 0xf9,
                ],
                [
                    0xeb, 0x70, 0x6c, 0x9c, 0x4f, 0x93, 0xcb, 0xd0, 0x31, 0xbe, 0x89, 0xb0, 0x0c,
                    0xc1, 0xbe, 0x01, 0xca, 0x6e, 0xcd, 0x44, 0xd7, 0xce, 0x78, 0xb4, 0x5a, 0xeb,
                    0xe9, 0x7e, 0x6b, 0xab, 0x6e, 0x6b,
                ],
            )
        );
    }

    #[test]
    fn disk_root_and_every_path_match_cpu_whir_mmcs() {
        let left = DenseRows::fixture(8, 3, 0x101);
        let right = DenseRows::fixture(8, 5, 0x202);
        let matrices = vec![left.matrix(), right.matrix()];
        let cpu = mmcs();
        let (commitment, prover_data) = cpu.commit(matrices);
        let path = test_path("parity");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store(&path, [0x11; 32], &[&left, &right])
            .unwrap()
            .remove_on_drop();

        assert_eq!(store.matrix_widths(), &[3, 5]);
        assert_eq!(store.root().unwrap(), commitment.roots()[0]);
        for index in 0..8 {
            let cpu_opening = cpu.open_batch(index, &prover_data);
            assert_eq!(
                store.opening_path(index).unwrap(),
                cpu_opening.opening_proof
            );
            let authenticated = store
                .authenticated_opening(index, &[&left, &right])
                .unwrap();
            assert_eq!(
                authenticated.opened_rows[0],
                left.values[index * 3..index * 3 + 3]
            );
            assert_eq!(
                authenticated.opened_rows[1],
                right.values[index * 5..index * 5 + 5]
            );
            assert_eq!(authenticated.opening_path, cpu_opening.opening_proof);
        }
    }

    #[test]
    fn checked_geometry_matches_exact_file_length_and_preflight() {
        let geometry = blake3_merkle_store_geometry(8, &[3, 5]).unwrap();
        assert_eq!(geometry.height, 8);
        assert_eq!(geometry.matrix_count, 2);
        assert_eq!(geometry.total_row_words, 8);
        assert_eq!(geometry.header_bytes, 144);
        assert_eq!(geometry.total_digests, 15);
        assert_eq!(geometry.digest_bytes, 480);
        assert_eq!(geometry.authentication_chunks, 1);
        assert_eq!(geometry.authentication_bytes, 32);
        assert_eq!(geometry.artifact_bytes, 656);
        assert!(matches!(
            ensure_available_space(&geometry, geometry.artifact_bytes - 1),
            Err(Blake3MerkleStoreError::InsufficientSpace {
                required: 656,
                available: 655
            })
        ));

        let left = DenseRows::fixture(8, 3, 0x713);
        let right = DenseRows::fixture(8, 5, 0x714);
        let path = test_path("geometry");
        remove_if_present(&path);
        let store =
            build_authenticated_blake3_merkle_store(&path, [0x71; 32], &[&left, &right]).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), geometry.artifact_bytes);
        store.remove().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn supplied_leaf_layer_is_fetched_in_8192_row_batches() {
        let rows = DenseRows::fixture(1 << 14, 1, 0x814);
        let digests = CountingDigests {
            height: 1 << 14,
            calls: AtomicUsize::new(0),
            largest_batch: AtomicUsize::new(0),
        };
        let path = test_path("leaf-batching");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store_with_first_digest_layer(
            &path,
            [0x81; 32],
            &[&rows],
            &digests,
        )
        .unwrap()
        .remove_on_drop();
        assert_eq!(digests.calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            digests.largest_batch.load(Ordering::Relaxed),
            BLAKE3_LEAF_BATCH_ROWS
        );
        drop(store);
    }

    #[test]
    fn explicit_row_batch_builder_uses_8192_and_rejects_larger_requests() {
        let rows = CountingRows {
            inner: DenseRows::fixture(1 << 14, 1, 0x914),
            calls: AtomicUsize::new(0),
            largest_batch: AtomicUsize::new(0),
        };
        let (cpu_commitment, _) = mmcs().commit(vec![rows.inner.matrix()]);
        let path = test_path("row-batching");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store_with_leaf_batch_rows(
            &path,
            [0x82; 32],
            &[&rows],
            BLAKE3_LEAF_BATCH_ROWS,
        )
        .unwrap()
        .remove_on_drop();
        assert_eq!(store.root().unwrap(), cpu_commitment.roots()[0]);
        assert_eq!(rows.calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            rows.largest_batch.load(Ordering::Relaxed),
            BLAKE3_LEAF_BATCH_ROWS
        );
        drop(store);

        assert!(matches!(
            build_authenticated_blake3_merkle_store_with_leaf_batch_rows(
                &path,
                [0x83; 32],
                &[&rows],
                BLAKE3_LEAF_BATCH_ROWS + 1,
            ),
            Err(Blake3MerkleStoreError::Invalid(
                "leaf batch must be in 1..=8192 rows"
            ))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn n16_whir_geometry_matches_cpu_root_and_selected_paths() {
        // n=16, starting_log_inv_rate=1, folding=2 gives 2^(16+1-2)
        // natural rows of width 2^2 in p3_sumcheck::commit::commit_base.
        let rows = DenseRows::fixture(1 << 15, 4, 0x2f15);
        let matrix = rows.matrix();
        let cpu = mmcs();
        let (commitment, prover_data) = cpu.commit(vec![matrix]);
        let path = test_path("current-max-whir");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store(&path, [0x19; 32], &[&rows])
            .unwrap()
            .remove_on_drop();

        assert_eq!(store.height(), 1 << 15);
        assert_eq!(store.root().unwrap(), commitment.roots()[0]);
        for index in [0, 1, 255, 256, (1 << 14), (1 << 15) - 1] {
            let cpu_opening = cpu.open_batch(index, &prover_data);
            assert_eq!(
                store.opening_path(index).unwrap(),
                cpu_opening.opening_proof
            );
        }
    }

    #[test]
    fn supplied_first_layer_matches_cpu_whir_mmcs() {
        let left = DenseRows::fixture(16, 2, 0x303);
        let right = DenseRows::fixture(16, 4, 0x404);
        let matrices = vec![left.matrix(), right.matrix()];
        let digests = first_digests(&matrices);
        let cpu = mmcs();
        let (commitment, prover_data) = cpu.commit(matrices);
        let path = test_path("supplied");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store_with_first_digest_layer(
            &path,
            [0x22; 32],
            &[&left, &right],
            &digests,
        )
        .unwrap()
        .remove_on_drop();

        assert_eq!(store.root().unwrap(), commitment.roots()[0]);
        for index in 0..16 {
            let cpu_opening = cpu.open_batch(index, &prover_data);
            assert_eq!(
                store.opening_path(index).unwrap(),
                cpu_opening.opening_proof
            );
        }
    }

    #[test]
    fn equal_shape_matrix_order_is_bound_and_replay_fails() {
        let left = DenseRows::fixture(8, 2, 0x505);
        let right = DenseRows::fixture(8, 2, 0x606);
        let original_path = test_path("order-original");
        let swapped_path = test_path("order-swapped");
        remove_if_present(&original_path);
        remove_if_present(&swapped_path);
        let original =
            build_authenticated_blake3_merkle_store(&original_path, [0x33; 32], &[&left, &right])
                .unwrap()
                .remove_on_drop();
        let swapped =
            build_authenticated_blake3_merkle_store(&swapped_path, [0x44; 32], &[&right, &left])
                .unwrap()
                .remove_on_drop();
        assert_ne!(original.root().unwrap(), swapped.root().unwrap());

        let cpu = mmcs();
        let original_matrices = vec![left.matrix(), right.matrix()];
        let dimensions = original_matrices
            .iter()
            .map(Matrix::dimensions)
            .collect::<Vec<_>>();
        let (commitment, _) = cpu.commit(original_matrices);
        let index = 3;
        let swapped_opened = vec![right.field_row(index), left.field_row(index)];
        let swapped_proof = swapped.opening_path(index).unwrap();
        assert!(
            cpu.verify_batch(
                &commitment,
                &dimensions,
                index,
                BatchOpeningRef::new(&swapped_opened, &swapped_proof),
            )
            .is_err()
        );
    }

    #[test]
    fn trusted_identity_reopens_and_rejects_whole_file_substitution() {
        let original_rows = DenseRows::fixture(8, 4, 0xa01);
        let substitute_rows = DenseRows::fixture(8, 4, 0xb02);
        let original_path = test_path("trusted-original");
        let substitute_path = test_path("trusted-substitute");
        remove_if_present(&original_path);
        remove_if_present(&substitute_path);

        let original =
            build_authenticated_blake3_merkle_store(&original_path, [0x91; 32], &[&original_rows])
                .unwrap();
        let trusted_identity = original.identity().unwrap();
        drop(original);
        let reopened =
            AuthenticatedBlake3MerkleStore::open(&original_path, &trusted_identity).unwrap();
        assert_eq!(reopened.identity().unwrap(), trusted_identity);
        drop(reopened);

        let substitute = build_authenticated_blake3_merkle_store(
            &substitute_path,
            [0x91; 32],
            &[&substitute_rows],
        )
        .unwrap();
        let substitute_identity = substitute.identity().unwrap();
        assert_ne!(substitute_identity, trusted_identity);
        drop(substitute);
        fs::copy(&substitute_path, &original_path).unwrap();

        let self_consistent_substitute =
            AuthenticatedBlake3MerkleStore::open_integrity_only(&original_path).unwrap();
        assert_eq!(
            self_consistent_substitute.identity().unwrap(),
            substitute_identity
        );
        drop(self_consistent_substitute);
        assert!(matches!(
            AuthenticatedBlake3MerkleStore::open(&original_path, &trusted_identity),
            Err(Blake3MerkleStoreError::IdentityMismatch)
        ));

        remove_if_present(&original_path);
        remove_if_present(&substitute_path);
    }

    #[test]
    fn identity_mismatch_is_rejected_before_full_digest_scan() {
        let rows = DenseRows::fixture(8, 4, 0xc03);
        let path = test_path("cheap-identity");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store(&path, [0xa3; 32], &[&rows]).unwrap();
        let mut wrong_identity = store.identity().unwrap();
        wrong_identity.store_id[0] ^= 1;
        drop(store);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let data_offset = (FIXED_HEADER_BYTES + MATRIX_RECORD_BYTES) as u64;
        file.seek(SeekFrom::Start(data_offset)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(data_offset)).unwrap();
        file.write_all(&[byte[0] ^ 1]).unwrap();
        file.sync_all().unwrap();

        assert!(matches!(
            AuthenticatedBlake3MerkleStore::open(&path, &wrong_identity),
            Err(Blake3MerkleStoreError::IdentityMismatch)
        ));
        wrong_identity.store_id[0] ^= 1;
        assert!(matches!(
            AuthenticatedBlake3MerkleStore::open(&path, &wrong_identity),
            Err(Blake3MerkleStoreError::ChecksumMismatch)
        ));
        remove_if_present(&path);
    }

    #[test]
    fn authenticated_opening_rejects_changed_canonical_source_row() {
        let committed = DenseRows::fixture(8, 4, 0xd04);
        let mut changed = committed.clone();
        changed.values[3 * changed.width + 1] ^= 1;
        let path = test_path("opening-source-change");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store(&path, [0xd4; 32], &[&committed])
            .unwrap()
            .remove_on_drop();
        assert!(matches!(
            store.authenticated_opening(3, &[&changed]),
            Err(Blake3MerkleStoreError::OpeningMismatch)
        ));
    }

    #[test]
    fn malformed_or_mutated_artifacts_fail_closed_on_open() {
        for mode in ["header", "digest", "truncate", "append"] {
            let rows = DenseRows::fixture(8, 4, 0x707);
            let path = test_path(mode);
            remove_if_present(&path);
            let store =
                build_authenticated_blake3_merkle_store(&path, [0x55; 32], &[&rows]).unwrap();
            let identity = store.identity().unwrap();
            drop(store);
            match mode {
                "header" => {
                    let mut file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&path)
                        .unwrap();
                    file.seek(SeekFrom::Start(20)).unwrap();
                    let mut byte = [0_u8; 1];
                    file.read_exact(&mut byte).unwrap();
                    file.seek(SeekFrom::Start(20)).unwrap();
                    file.write_all(&[byte[0] ^ 1]).unwrap();
                }
                "digest" => {
                    let mut file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&path)
                        .unwrap();
                    file.seek(SeekFrom::Start(
                        (FIXED_HEADER_BYTES + MATRIX_RECORD_BYTES) as u64,
                    ))
                    .unwrap();
                    let mut byte = [0_u8; 1];
                    file.read_exact(&mut byte).unwrap();
                    file.seek(SeekFrom::Current(-1)).unwrap();
                    file.write_all(&[byte[0] ^ 1]).unwrap();
                }
                "truncate" => {
                    let file = OpenOptions::new().write(true).open(&path).unwrap();
                    let len = file.metadata().unwrap().len();
                    file.set_len(len - 1).unwrap();
                }
                "append" => OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(&[0])
                    .unwrap(),
                _ => unreachable!(),
            }
            assert!(AuthenticatedBlake3MerkleStore::open(&path, &identity).is_err());
            remove_if_present(&path);
        }
    }

    #[test]
    fn post_open_digest_mutation_is_rejected_by_bounded_path_read() {
        let rows = DenseRows::fixture(8, 4, 0x808);
        let path = test_path("post-open");
        remove_if_present(&path);
        let store = build_authenticated_blake3_merkle_store(&path, [0x66; 32], &[&rows])
            .unwrap()
            .remove_on_drop();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let data_offset = (FIXED_HEADER_BYTES + MATRIX_RECORD_BYTES) as u64;
        file.seek(SeekFrom::Start(data_offset)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(data_offset)).unwrap();
        file.write_all(&[byte[0] ^ 1]).unwrap();
        file.sync_all().unwrap();

        assert!(matches!(
            store.opening_path(1),
            Err(Blake3MerkleStoreError::ChecksumMismatch)
        ));
    }

    #[test]
    fn research_limit_rejects_before_read_or_file_creation() {
        let rows = PanicRows {
            height: MAX_BLAKE3_MERKLE_ROWS * 2,
        };
        let path = test_path("limit");
        remove_if_present(&path);
        assert!(matches!(
            build_authenticated_blake3_merkle_store(&path, [0x77; 32], &[&rows]),
            Err(Blake3MerkleStoreError::ResearchLimit(_))
        ));
        assert!(!path.exists());
        assert!(staging_files_for(&path).is_empty());
    }

    #[test]
    fn invalid_parent_is_rejected_before_row_reads_or_creation() {
        let rows = PanicRows { height: 8 };
        let missing_parent = test_path("missing-parent").with_extension("directory");
        let path = missing_parent.join("tree.store");
        assert!(!missing_parent.exists());
        assert!(matches!(
            build_authenticated_blake3_merkle_store(&path, [0x79; 32], &[&rows]),
            Err(Blake3MerkleStoreError::InvalidParentDirectory(parent))
                if parent == missing_parent
        ));
        assert!(!path.exists());

        assert!(matches!(
            build_authenticated_blake3_merkle_store(
                Path::new("relative-tree.store"),
                [0x7a; 32],
                &[&rows],
            ),
            Err(Blake3MerkleStoreError::Invalid(
                "store path must be absolute"
            ))
        ));
    }

    #[test]
    fn existing_final_is_never_overwritten() {
        let rows = DenseRows::fixture(4, 4, 0x909);
        let path = test_path("no-overwrite");
        remove_if_present(&path);
        fs::write(&path, b"keep-me").unwrap();
        assert!(matches!(
            build_authenticated_blake3_merkle_store(&path, [0x88; 32], &[&rows]),
            Err(Blake3MerkleStoreError::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"keep-me");
        remove_if_present(&path);
    }

    #[test]
    fn explicit_cleanup_refuses_replacement_and_preserves_neighbors() {
        let rows = DenseRows::fixture(4, 4, 0xe05);
        let path = test_path("cleanup-replacement");
        let moved = path.with_extension("owned-moved");
        let neighbor = path.with_extension("neighbor");
        remove_if_present(&path);
        remove_if_present(&moved);
        remove_if_present(&neighbor);
        fs::write(&neighbor, b"neighbor").unwrap();
        let store = build_authenticated_blake3_merkle_store(&path, [0xe5; 32], &[&rows]).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(matches!(
            store.remove(),
            Err(Blake3MerkleStoreError::CleanupTargetChanged(changed)) if changed == path
        ));
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(fs::read(&neighbor).unwrap(), b"neighbor");
        assert!(moved.exists());
        remove_if_present(&path);
        remove_if_present(&moved);
        remove_if_present(&neighbor);
    }

    #[test]
    fn staging_guard_never_unlinks_a_substituted_path() {
        let path = test_path("staging-substitution");
        let moved = path.with_extension("partial-moved");
        remove_if_present(&path);
        remove_if_present(&moved);
        let (partial, file) = create_unique_staging(&path).unwrap();
        let guard = OwnedFileLink::new(partial.clone(), file);
        fs::rename(&partial, &moved).unwrap();
        fs::write(&partial, b"replacement partial").unwrap();
        drop(guard);
        assert_eq!(fs::read(&partial).unwrap(), b"replacement partial");
        assert!(moved.exists());
        fs::remove_file(partial).unwrap();
        fs::remove_file(moved).unwrap();
    }

    #[test]
    fn late_publication_conflict_preserves_existing_final_and_owned_staging() {
        let path = test_path("late-publication-conflict");
        remove_if_present(&path);
        let (partial, mut file) = create_unique_staging(&path).unwrap();
        file.write_all(b"owned staging").unwrap();
        let guard = OwnedFileLink::new(partial.clone(), file);
        fs::write(&path, b"late existing final").unwrap();

        assert!(matches!(
            publish_verified_no_overwrite(&partial, &path, guard.file_ref()),
            Err(Blake3MerkleStoreError::AlreadyExists(conflict)) if conflict == path
        ));
        assert_eq!(fs::read(&path).unwrap(), b"late existing final");
        assert_eq!(fs::read(&partial).unwrap(), b"owned staging");
        drop(guard);
        assert!(!partial.exists());
        assert_eq!(fs::read(&path).unwrap(), b"late existing final");
        remove_if_present(&path);
    }
}
