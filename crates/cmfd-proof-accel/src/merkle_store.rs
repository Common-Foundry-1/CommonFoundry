//! Authenticated, disk-backed prover data for Common Foundry's binary input MMCS.
//!
//! This module deliberately stops below the Plonky3 trait boundary. It stores
//! only prover-side digest layers and matrix geometry; commitments and opening
//! proofs remain the ordinary four-word Goldilocks values consumed by the
//! unchanged CPU verifier. The caller must still supply the opened matrix rows
//! and must independently verify the completed proof on the CPU.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use blake3::Hasher;
use p3_maybe_rayon::prelude::*;
use thiserror::Error;

/// The four canonical Goldilocks words used by Common Foundry's input MMCS.
pub type MerkleDigest = [u64; 4];

/// Goldilocks' prime modulus, `2^64 - 2^32 + 1`.
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// Number of digests covered by one independently authenticated read chunk.
pub const AUTH_CHUNK_DIGESTS: u64 = 256;

/// Maximum bytes authenticated and copied for one random digest read.
pub const MAX_AUTHENTICATED_READ_BYTES: usize = AUTH_CHUNK_DIGESTS as usize * ENCODED_DIGEST_BYTES;

const MAGIC: &[u8; 8] = b"CMFDMRK1";
const VERSION: u32 = 1;
const FIXED_HEADER_BYTES: usize = 144;
const GLOBAL_DIGEST_OFFSET: usize = 104;
const GLOBAL_DIGEST_END: usize = GLOBAL_DIGEST_OFFSET + 32;
const MATRIX_RECORD_BYTES: usize = 24;
const LAYER_RECORD_BYTES: usize = 40;
const ENCODED_DIGEST_BYTES: usize = 4 * size_of::<u64>();
const MAX_MATRICES: usize = 64;
const MAX_LAYERS: usize = usize::BITS as usize;
const HEADER_DOMAIN: &[u8] = b"CMFD-MERKLE-STORE-HEADER-V1";
const GLOBAL_DOMAIN: &[u8] = b"CMFD-MERKLE-STORE-GLOBAL-V1";
const CHUNK_DOMAIN: &[u8] = b"CMFD-MERKLE-STORE-CHUNK-V1";

/// Ordered public geometry for one matrix retained by the prover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleMatrixDescriptor {
    pub ordinal: usize,
    pub height: usize,
    pub width: usize,
}

/// Physical location and logical shape of one stored Merkle digest layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleLayerDescriptor {
    pub ordinal: usize,
    /// Number of non-padding positions at this layer.
    pub logical_len: usize,
    /// Number of positions stored after Plonky3's binary padding rule.
    pub stored_len: usize,
    /// Global digest index of the layer's first element.
    pub data_start_digest: u64,
    /// Matrix height injected at this layer, or zero when there is none.
    pub injected_height: usize,
}

/// Fallible row source used while constructing the prover-only tree.
///
/// The returned row must contain exactly `width()` canonical Goldilocks words.
pub trait MerkleRowSource: Sync {
    fn height(&self) -> usize;
    fn width(&self) -> usize;
    fn read_row(&self, row: usize) -> Result<Vec<u64>, MerkleStoreError>;

    /// Read consecutive rows in row-major order.
    ///
    /// Disk-backed sources should override this method so one authenticated
    /// storage chunk can supply many Merkle leaves. The default preserves the
    /// simple row-source contract for small in-memory callers.
    fn read_rows(&self, row_start: usize, row_count: usize) -> Result<Vec<u64>, MerkleStoreError> {
        let value_count = row_count
            .checked_mul(self.width())
            .ok_or(MerkleStoreError::Invalid("row batch length overflow"))?;
        let row_end = row_start
            .checked_add(row_count)
            .ok_or(MerkleStoreError::Invalid("row batch range overflow"))?;
        if row_count == 0 || row_end > self.height() {
            return Err(MerkleStoreError::Invalid("row batch is out of bounds"));
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(value_count)
            .map_err(|_| MerkleStoreError::Invalid("row batch allocation failed"))?;
        for row in row_start..row_end {
            values.extend(self.read_row(row)?);
        }
        Ok(values)
    }
}

impl MerkleRowSource for crate::spill::AuthenticatedLdeMatrix {
    fn height(&self) -> usize {
        p3_matrix::Matrix::height(self)
    }

    fn width(&self) -> usize {
        p3_matrix::Matrix::width(self)
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

/// Exact leaf hashing and binary compression used by the verifier's MMCS.
pub trait BinaryMerkleHash: Sync {
    /// Hash one flattened row. Rows from equal-height matrices are concatenated
    /// in original matrix order before this method is called.
    fn hash_row(&self, values: &[u64]) -> MerkleDigest;

    /// Compress `[left, right]` in that order.
    fn compress(&self, children: [MerkleDigest; 2]) -> MerkleDigest;
}

#[derive(Debug, Error)]
pub enum MerkleStoreError {
    #[error("invalid Merkle store: {0}")]
    Invalid(&'static str),
    #[error("Merkle row source failed: {0}")]
    Source(String),
    #[error("Merkle store already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("Merkle store I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Merkle store checksum does not match")]
    ChecksumMismatch,
    #[error("Merkle store file lock is poisoned")]
    LockPoisoned,
}

/// Fully authenticated, immutable disk-backed Merkle prover data.
///
/// Opening this object authenticates the complete artifact. Every later random
/// digest read independently authenticates its fixed-size chunk again, so a
/// post-open mutation cannot silently alter an opening path.
pub struct AuthenticatedMerkleStore {
    file: Mutex<File>,
    path: PathBuf,
    store_id: [u8; 32],
    configured_cap_height: usize,
    matrices: Vec<MerkleMatrixDescriptor>,
    layers: Vec<MerkleLayerDescriptor>,
    header_len: u64,
    total_digests: u64,
    header_binding: [u8; 32],
    global_digest: [u8; 32],
    auth_chunk_digests: Vec<[u8; 32]>,
    cleanup: Option<StoreCleanup>,
}

struct StoreCleanup(PathBuf);

impl Drop for StoreCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl AuthenticatedMerkleStore {
    /// Open and completely authenticate a sealed store before exposing paths.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MerkleStoreError> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path).map_err(|source| io_error("opening", &path, source))?;
        let mut fixed = [0_u8; FIXED_HEADER_BYTES];
        file.read_exact(&mut fixed)
            .map_err(|source| io_error("reading header from", &path, source))?;

        let counts = validate_fixed_header(&fixed)?;
        let header_len = exact_header_len(counts.matrix_count, counts.layer_count)?;
        if counts.header_len != header_len as u64 {
            return Err(MerkleStoreError::Invalid("header length is not canonical"));
        }
        let mut header = Vec::new();
        header
            .try_reserve_exact(header_len)
            .map_err(|_| MerkleStoreError::Invalid("header allocation failed"))?;
        header.extend_from_slice(&fixed);
        header.resize(header_len, 0);
        file.read_exact(&mut header[FIXED_HEADER_BYTES..])
            .map_err(|source| io_error("reading metadata from", &path, source))?;

        let matrices = decode_matrix_descriptors(&header, counts.matrix_count)?;
        let expected_layers = derive_layers(&matrices)?;
        let layers = decode_layer_descriptors(&header, counts.matrix_count, counts.layer_count)?;
        if layers != expected_layers {
            return Err(MerkleStoreError::Invalid(
                "stored layer geometry does not match the matrix heights",
            ));
        }
        if matrices.iter().map(|matrix| matrix.height).max() != Some(counts.max_height) {
            return Err(MerkleStoreError::Invalid(
                "maximum matrix height is inconsistent",
            ));
        }
        let total_digests = layers
            .last()
            .and_then(|layer| layer.data_start_digest.checked_add(layer.stored_len as u64))
            .ok_or(MerkleStoreError::Invalid("store has no digest layers"))?;
        if total_digests != counts.total_digests {
            return Err(MerkleStoreError::Invalid(
                "total digest count is inconsistent",
            ));
        }
        let expected_auth_chunks = auth_chunk_count(total_digests)?;
        if counts.auth_chunk_count != expected_auth_chunks {
            return Err(MerkleStoreError::Invalid(
                "authentication chunk count is inconsistent",
            ));
        }

        let data_bytes = total_digests
            .checked_mul(ENCODED_DIGEST_BYTES as u64)
            .ok_or(MerkleStoreError::Invalid("digest byte length overflow"))?;
        let auth_bytes = expected_auth_chunks
            .checked_mul(32)
            .ok_or(MerkleStoreError::Invalid(
                "authentication table length overflow",
            ))?;
        let expected_file_len = counts
            .header_len
            .checked_add(data_bytes)
            .and_then(|length| length.checked_add(auth_bytes))
            .ok_or(MerkleStoreError::Invalid("file length overflow"))?;
        let actual_file_len = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();
        if actual_file_len != expected_file_len {
            return Err(MerkleStoreError::Invalid(
                "file length does not match the declared store",
            ));
        }

        let header_binding = compute_header_binding(&header);
        let mut global = global_hasher(&header_binding);
        let mut buffer = [0_u8; 64 * 1024];
        let mut remaining = data_bytes;
        while remaining != 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| MerkleStoreError::Invalid("read size does not fit memory"))?;
            file.read_exact(&mut buffer[..take])
                .map_err(|source| io_error("authenticating", &path, source))?;
            global.update(&buffer[..take]);
            remaining -= take as u64;
        }

        let auth_count = usize::try_from(expected_auth_chunks)
            .map_err(|_| MerkleStoreError::Invalid("authentication table is too large"))?;
        let mut auth_chunk_digests = Vec::new();
        auth_chunk_digests
            .try_reserve_exact(auth_count)
            .map_err(|_| MerkleStoreError::Invalid("authentication table allocation failed"))?;
        for _ in 0..auth_count {
            let mut digest = [0_u8; 32];
            file.read_exact(&mut digest)
                .map_err(|source| io_error("reading authentication table from", &path, source))?;
            global.update(&digest);
            auth_chunk_digests.push(digest);
        }

        let global_digest: [u8; 32] = header[GLOBAL_DIGEST_OFFSET..GLOBAL_DIGEST_END]
            .try_into()
            .expect("global digest slice is exact");
        if global.finalize().as_bytes() != &global_digest {
            return Err(MerkleStoreError::ChecksumMismatch);
        }

        Ok(Self {
            file: Mutex::new(file),
            path,
            store_id: counts.store_id,
            configured_cap_height: counts.cap_height,
            matrices,
            layers,
            header_len: counts.header_len,
            total_digests,
            header_binding,
            global_digest,
            auth_chunk_digests,
            cleanup: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn store_id(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn global_digest(&self) -> [u8; 32] {
        self.global_digest
    }

    /// Remove the published store after its final owner drops.
    pub fn remove_on_drop(mut self) -> Self {
        self.cleanup = Some(StoreCleanup(self.path.clone()));
        self
    }

    pub fn matrices(&self) -> &[MerkleMatrixDescriptor] {
        &self.matrices
    }

    pub fn layers(&self) -> &[MerkleLayerDescriptor] {
        &self.layers
    }

    pub const fn configured_cap_height(&self) -> usize {
        self.configured_cap_height
    }

    /// Read the authenticated Merkle root.
    pub fn root(&self) -> Result<MerkleDigest, MerkleStoreError> {
        self.read_digest(self.layers.len() - 1, 0)
    }

    /// Read the configured Merkle cap in the same left-to-right order as Plonky3.
    pub fn cap(&self) -> Result<Vec<MerkleDigest>, MerkleStoreError> {
        let effective = self.effective_cap_height();
        let layer_index = self.layers.len() - 1 - effective;
        let cap_len = 1_usize
            .checked_shl(effective as u32)
            .ok_or(MerkleStoreError::Invalid("cap length overflow"))?
            .min(self.layers[layer_index].stored_len);
        (0..cap_len)
            .map(|index| self.read_digest(layer_index, index))
            .collect()
    }

    /// Read sibling digests from the leaf layer upward, stopping below the cap.
    pub fn opening_path(&self, index: usize) -> Result<Vec<MerkleDigest>, MerkleStoreError> {
        let max_height = self
            .matrices
            .iter()
            .map(|matrix| matrix.height)
            .max()
            .expect("validated store has matrices");
        if index >= max_height {
            return Err(MerkleStoreError::Invalid("opening index is out of bounds"));
        }
        let proof_levels = self.layers.len() - 1 - self.effective_cap_height();
        let mut path = Vec::new();
        path.try_reserve_exact(proof_levels)
            .map_err(|_| MerkleStoreError::Invalid("opening path allocation failed"))?;
        let mut current = index;
        for layer_index in 0..proof_levels {
            path.push(self.read_digest(layer_index, current ^ 1)?);
            current >>= 1;
        }
        Ok(path)
    }

    /// Map a global opening index to the row opened from each source matrix.
    pub fn matrix_row_indices(&self, index: usize) -> Result<Vec<usize>, MerkleStoreError> {
        let max_height = self
            .matrices
            .iter()
            .map(|matrix| matrix.height)
            .max()
            .expect("validated store has matrices");
        if index >= max_height {
            return Err(MerkleStoreError::Invalid("opening index is out of bounds"));
        }
        let log_max_height = log2_ceil(max_height)?;
        self.matrices
            .iter()
            .map(|matrix| {
                let bits_reduced = log_max_height - log2_ceil(matrix.height)?;
                Ok(index >> bits_reduced)
            })
            .collect()
    }

    fn effective_cap_height(&self) -> usize {
        self.configured_cap_height
            .min(self.layers.len().saturating_sub(1))
    }

    fn read_digest(
        &self,
        layer_index: usize,
        index: usize,
    ) -> Result<MerkleDigest, MerkleStoreError> {
        let layer = self
            .layers
            .get(layer_index)
            .ok_or(MerkleStoreError::Invalid(
                "digest layer index is out of bounds",
            ))?;
        if index >= layer.stored_len {
            return Err(MerkleStoreError::Invalid("digest index is out of bounds"));
        }
        let global_index = layer
            .data_start_digest
            .checked_add(index as u64)
            .ok_or(MerkleStoreError::Invalid("digest index overflow"))?;
        let chunk_index = global_index / AUTH_CHUNK_DIGESTS;
        let chunk_start = chunk_index * AUTH_CHUNK_DIGESTS;
        let chunk_count = (self.total_digests - chunk_start).min(AUTH_CHUNK_DIGESTS);
        let chunk_bytes =
            usize::try_from(chunk_count.checked_mul(ENCODED_DIGEST_BYTES as u64).ok_or(
                MerkleStoreError::Invalid("authenticated chunk length overflow"),
            )?)
            .map_err(|_| MerkleStoreError::Invalid("authenticated chunk does not fit memory"))?;
        let file_offset = self
            .header_len
            .checked_add(chunk_start.checked_mul(ENCODED_DIGEST_BYTES as u64).ok_or(
                MerkleStoreError::Invalid("authenticated chunk offset overflow"),
            )?)
            .ok_or(MerkleStoreError::Invalid(
                "authenticated chunk offset overflow",
            ))?;

        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(chunk_bytes)
            .map_err(|_| MerkleStoreError::Invalid("authenticated chunk allocation failed"))?;
        encoded.resize(chunk_bytes, 0);
        let mut file = self
            .file
            .lock()
            .map_err(|_| MerkleStoreError::LockPoisoned)?;
        file.seek(SeekFrom::Start(file_offset))
            .and_then(|_| file.read_exact(&mut encoded))
            .map_err(|source| io_error("reading authenticated chunk from", &self.path, source))?;
        drop(file);

        let expected = self
            .auth_chunk_digests
            .get(
                usize::try_from(chunk_index)
                    .map_err(|_| MerkleStoreError::Invalid("chunk index does not fit memory"))?,
            )
            .ok_or(MerkleStoreError::Invalid(
                "authentication digest is missing",
            ))?;
        let mut hasher = chunk_hasher(&self.header_binding, chunk_index);
        hasher.update(&encoded);
        if hasher.finalize().as_bytes() != expected {
            return Err(MerkleStoreError::ChecksumMismatch);
        }

        let offset_in_chunk = usize::try_from(global_index - chunk_start)
            .ok()
            .and_then(|offset| offset.checked_mul(ENCODED_DIGEST_BYTES))
            .ok_or(MerkleStoreError::Invalid("digest byte offset overflow"))?;
        decode_digest(&encoded[offset_in_chunk..offset_in_chunk + ENCODED_DIGEST_BYTES])
    }
}

/// Build, synchronize, validate, and no-overwrite publish one Merkle store.
pub fn build_authenticated_merkle_store(
    final_path: impl AsRef<Path>,
    store_id: [u8; 32],
    sources: &[&dyn MerkleRowSource],
    configured_cap_height: usize,
    hash: &dyn BinaryMerkleHash,
) -> Result<AuthenticatedMerkleStore, MerkleStoreError> {
    build_authenticated_merkle_store_inner(
        final_path.as_ref(),
        store_id,
        sources,
        None,
        configured_cap_height,
        hash,
    )
}

/// Build a Merkle store from a caller-supplied, unpadded first digest layer.
///
/// `first_digests` must expose exactly one width-4 canonical digest row for
/// every physical row of the tallest matrices. The ordinary zero-digest
/// padding is added here, while all higher compression and shorter-matrix
/// injection remains identical to [`build_authenticated_merkle_store`].
pub fn build_authenticated_merkle_store_with_first_digest_layer(
    final_path: impl AsRef<Path>,
    store_id: [u8; 32],
    sources: &[&dyn MerkleRowSource],
    first_digests: &dyn MerkleRowSource,
    configured_cap_height: usize,
    hash: &dyn BinaryMerkleHash,
) -> Result<AuthenticatedMerkleStore, MerkleStoreError> {
    build_authenticated_merkle_store_inner(
        final_path.as_ref(),
        store_id,
        sources,
        Some(first_digests),
        configured_cap_height,
        hash,
    )
}

fn build_authenticated_merkle_store_inner(
    final_path: &Path,
    store_id: [u8; 32],
    sources: &[&dyn MerkleRowSource],
    first_digests: Option<&dyn MerkleRowSource>,
    configured_cap_height: usize,
    hash: &dyn BinaryMerkleHash,
) -> Result<AuthenticatedMerkleStore, MerkleStoreError> {
    if store_id == [0_u8; 32] {
        return Err(MerkleStoreError::Invalid("store ID must be nonzero"));
    }
    if sources.is_empty() || sources.len() > MAX_MATRICES {
        return Err(MerkleStoreError::Invalid("matrix count is outside 1..=64"));
    }
    let configured_cap_height = u32::try_from(configured_cap_height)
        .map_err(|_| MerkleStoreError::Invalid("cap height does not fit u32"))?
        as usize;
    let matrices = describe_sources(sources)?;
    let first_height = matrices
        .iter()
        .map(|matrix| matrix.height)
        .max()
        .expect("validated matrices are nonempty");
    if let Some(first_digests) = first_digests {
        validate_first_digest_source(first_digests, first_height)?;
    }
    let layers = derive_layers(&matrices)?;
    let total_digests = layers
        .last()
        .and_then(|layer| layer.data_start_digest.checked_add(layer.stored_len as u64))
        .ok_or(MerkleStoreError::Invalid("store has no digest layers"))?;
    let auth_count = auth_chunk_count(total_digests)?;
    let header = encode_header(
        store_id,
        configured_cap_height,
        &matrices,
        &layers,
        total_digests,
        auth_count,
    )?;
    let header_binding = compute_header_binding(&header);

    let final_path = final_path.to_path_buf();
    if final_path.exists() {
        return Err(MerkleStoreError::AlreadyExists(final_path));
    }
    let partial_path = partial_path_for(&final_path)?;
    let mut cleanup = PartialCleanup::new(partial_path.clone());
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&partial_path)
        .map_err(|source| io_error("creating", &partial_path, source))?;
    file.write_all(&header)
        .map_err(|source| io_error("writing header to", &partial_path, source))?;

    let mut data_writer = DigestDataWriter::new(
        &mut file,
        &partial_path,
        header_binding,
        total_digests,
        auth_count,
    )?;

    for row_start in (0..first_height).step_by(AUTH_CHUNK_DIGESTS as usize) {
        let row_count = (first_height - row_start).min(AUTH_CHUNK_DIGESTS as usize);
        let digests = if let Some(first_digests) = first_digests {
            read_first_digest_rows(first_digests, first_height, row_start, row_count)?
        } else {
            hash_group_rows(sources, &matrices, first_height, row_start, row_count, hash)?
        };
        for digest in digests {
            data_writer.write_digest(digest)?;
        }
    }
    for _ in first_height..layers[0].stored_len {
        data_writer.write_digest([0_u64; 4])?;
    }
    data_writer.flush()?;

    let mut reader = File::open(&partial_path)
        .map_err(|source| io_error("opening construction reader for", &partial_path, source))?;
    let max_parent_chunk = AUTH_CHUNK_DIGESTS as usize;
    let mut children = Vec::new();
    children
        .try_reserve_exact(max_parent_chunk * 2)
        .map_err(|_| MerkleStoreError::Invalid("child digest allocation failed"))?;
    let mut parents = Vec::new();
    parents
        .try_reserve_exact(max_parent_chunk)
        .map_err(|_| MerkleStoreError::Invalid("parent digest allocation failed"))?;
    for layer_index in 1..layers.len() {
        let previous = &layers[layer_index - 1];
        let current = &layers[layer_index];
        let previous_offset = (header.len() as u64)
            .checked_add(
                previous
                    .data_start_digest
                    .checked_mul(ENCODED_DIGEST_BYTES as u64)
                    .ok_or(MerkleStoreError::Invalid("previous layer offset overflow"))?,
            )
            .ok_or(MerkleStoreError::Invalid("previous layer offset overflow"))?;
        reader
            .seek(SeekFrom::Start(previous_offset))
            .map_err(|source| io_error("seeking in", &partial_path, source))?;
        for row_start in (0..current.logical_len).step_by(AUTH_CHUNK_DIGESTS as usize) {
            let row_count = (current.logical_len - row_start).min(AUTH_CHUNK_DIGESTS as usize);
            let injected = if current.injected_height == 0 {
                None
            } else {
                Some(hash_group_rows(
                    sources,
                    &matrices,
                    current.injected_height,
                    row_start,
                    row_count,
                    hash,
                )?)
            };
            let child_count = row_count
                .checked_mul(2)
                .ok_or(MerkleStoreError::Invalid("child digest count overflow"))?;
            children.clear();
            for _ in 0..child_count {
                children.push(read_raw_digest(&mut reader, &partial_path)?);
            }
            parents.clear();
            parents.resize(row_count, [0_u64; 4]);
            parents.par_iter_mut().enumerate().try_for_each(
                |(offset, parent)| -> Result<(), MerkleStoreError> {
                    let child_offset = offset * 2;
                    let mut digest = checked_hash_digest(
                        hash.compress([children[child_offset], children[child_offset + 1]]),
                    )?;
                    if let Some(injected) = &injected {
                        digest = checked_hash_digest(hash.compress([digest, injected[offset]]))?;
                    }
                    *parent = digest;
                    Ok(())
                },
            )?;
            for digest in &parents {
                data_writer.write_digest(*digest)?;
            }
        }
        for _ in current.logical_len..current.stored_len {
            data_writer.write_digest([0_u64; 4])?;
        }
        data_writer.flush()?;
    }

    data_writer.seal()?;
    drop(reader);
    drop(file);

    let mut store = AuthenticatedMerkleStore::open(&partial_path)?;
    fs::hard_link(&partial_path, &final_path)
        .map_err(|source| io_error("publishing", &final_path, source))?;
    cleanup.published = true;
    store.path = final_path;
    let _ = fs::remove_file(&partial_path);
    Ok(store)
}

fn validate_first_digest_source(
    source: &dyn MerkleRowSource,
    first_height: usize,
) -> Result<(), MerkleStoreError> {
    if source.height() != first_height {
        return Err(MerkleStoreError::Invalid(
            "first digest layer height must equal the maximum matrix height",
        ));
    }
    if source.width() != 4 {
        return Err(MerkleStoreError::Invalid(
            "first digest layer width must equal four",
        ));
    }
    Ok(())
}

fn read_first_digest_rows(
    source: &dyn MerkleRowSource,
    first_height: usize,
    row_start: usize,
    row_count: usize,
) -> Result<Vec<MerkleDigest>, MerkleStoreError> {
    validate_first_digest_source(source, first_height)?;
    let values = source.read_rows(row_start, row_count)?;
    validate_first_digest_source(source, first_height)?;
    let expected_values = row_count.checked_mul(4).ok_or(MerkleStoreError::Invalid(
        "first digest layer length overflow",
    ))?;
    if values.len() != expected_values {
        return Err(MerkleStoreError::Invalid(
            "first digest layer row count or width is inconsistent",
        ));
    }
    if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
        return Err(MerkleStoreError::Invalid(
            "first digest layer contains a noncanonical Goldilocks word",
        ));
    }
    Ok(values
        .chunks_exact(4)
        .map(|digest| [digest[0], digest[1], digest[2], digest[3]])
        .collect())
}

fn describe_sources(
    sources: &[&dyn MerkleRowSource],
) -> Result<Vec<MerkleMatrixDescriptor>, MerkleStoreError> {
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(sources.len())
        .map_err(|_| MerkleStoreError::Invalid("matrix descriptor allocation failed"))?;
    let mut total_width = 0_usize;
    for (ordinal, source) in sources.iter().enumerate() {
        let height = source.height();
        let width = source.width();
        if height == 0 || width == 0 {
            return Err(MerkleStoreError::Invalid(
                "matrix height and width must be nonzero",
            ));
        }
        total_width = total_width
            .checked_add(width)
            .ok_or(MerkleStoreError::Invalid("aggregate matrix width overflow"))?;
        descriptors.push(MerkleMatrixDescriptor {
            ordinal,
            height,
            width,
        });
    }
    validate_reachable_heights(&descriptors)?;
    Ok(descriptors)
}

fn validate_reachable_heights(
    matrices: &[MerkleMatrixDescriptor],
) -> Result<usize, MerkleStoreError> {
    let max_height = matrices
        .iter()
        .map(|matrix| matrix.height)
        .max()
        .ok_or(MerkleStoreError::Invalid("matrix batch is empty"))?;
    let log_max_height = log2_ceil(max_height)?;
    for matrix in matrices {
        let bits_reduced = log_max_height - log2_ceil(matrix.height)?;
        let expected_height = ((max_height - 1) >> bits_reduced) + 1;
        if matrix.height != expected_height {
            return Err(MerkleStoreError::Invalid(
                "matrix height is not reachable in the binary tree",
            ));
        }
    }
    Ok(max_height)
}

fn derive_layers(
    matrices: &[MerkleMatrixDescriptor],
) -> Result<Vec<MerkleLayerDescriptor>, MerkleStoreError> {
    let max_height = validate_reachable_heights(matrices)?;
    let first_stored_len = padded_len(max_height)?;
    let mut layers = vec![MerkleLayerDescriptor {
        ordinal: 0,
        logical_len: max_height,
        stored_len: first_stored_len,
        data_start_digest: 0,
        injected_height: max_height,
    }];
    while layers.last().expect("first layer exists").stored_len > 1 {
        if layers.len() >= MAX_LAYERS {
            return Err(MerkleStoreError::Invalid("Merkle layer count is too large"));
        }
        let previous = layers.last().expect("first layer exists");
        let logical_len = previous.stored_len / 2;
        let stored_len = padded_len(logical_len)?;
        let target_power = logical_len
            .checked_next_power_of_two()
            .ok_or(MerkleStoreError::Invalid("layer height overflow"))?;
        let injected_height = matrices
            .iter()
            .map(|matrix| matrix.height)
            .find(|height| {
                *height != previous.injected_height
                    && height.checked_next_power_of_two() == Some(target_power)
            })
            .unwrap_or(0);
        if injected_height != 0 && injected_height != logical_len {
            return Err(MerkleStoreError::Invalid(
                "injected matrix height does not match the layer",
            ));
        }
        let data_start_digest = previous
            .data_start_digest
            .checked_add(previous.stored_len as u64)
            .ok_or(MerkleStoreError::Invalid("layer digest offset overflow"))?;
        layers.push(MerkleLayerDescriptor {
            ordinal: layers.len(),
            logical_len,
            stored_len,
            data_start_digest,
            injected_height,
        });
    }
    Ok(layers)
}

fn padded_len(raw_len: usize) -> Result<usize, MerkleStoreError> {
    if raw_len <= 1 {
        return Ok(raw_len);
    }
    raw_len
        .checked_add(1)
        .map(|length| length & !1)
        .ok_or(MerkleStoreError::Invalid("padded layer length overflow"))
}

fn log2_ceil(value: usize) -> Result<usize, MerkleStoreError> {
    if value == 0 {
        return Err(MerkleStoreError::Invalid("zero has no logarithm"));
    }
    Ok((usize::BITS - (value - 1).leading_zeros()) as usize)
}

fn hash_group_rows(
    sources: &[&dyn MerkleRowSource],
    matrices: &[MerkleMatrixDescriptor],
    height: usize,
    row_start: usize,
    row_count: usize,
    hash: &dyn BinaryMerkleHash,
) -> Result<Vec<MerkleDigest>, MerkleStoreError> {
    if row_count == 0
        || row_start
            .checked_add(row_count)
            .is_none_or(|row_end| row_end > height)
    {
        return Err(MerkleStoreError::Invalid("row batch is out of bounds"));
    }
    if sources.len() != matrices.len() {
        return Err(MerkleStoreError::Invalid(
            "row source count does not match matrix metadata",
        ));
    }
    let expected_width = matrices
        .iter()
        .filter(|matrix| matrix.height == height)
        .try_fold(0_usize, |total, matrix| total.checked_add(matrix.width))
        .ok_or(MerkleStoreError::Invalid("row width overflow"))?;
    if expected_width == 0 {
        return Err(MerkleStoreError::Invalid("matrix height group is empty"));
    }
    let mut batches = Vec::new();
    for (source, matrix) in sources
        .iter()
        .zip(matrices)
        .filter(|(_, matrix)| matrix.height == height)
    {
        if source.height() != matrix.height || source.width() != matrix.width {
            return Err(MerkleStoreError::Invalid(
                "row source geometry changed during construction",
            ));
        }
        let values = source.read_rows(row_start, row_count)?;
        if source.height() != matrix.height || source.width() != matrix.width {
            return Err(MerkleStoreError::Invalid(
                "row source geometry changed during construction",
            ));
        }
        let expected_values = row_count
            .checked_mul(matrix.width)
            .ok_or(MerkleStoreError::Invalid("row batch length overflow"))?;
        if values.len() != expected_values {
            return Err(MerkleStoreError::Invalid(
                "row batch width does not match its matrix",
            ));
        }
        if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
            return Err(MerkleStoreError::Invalid(
                "row batch contains a noncanonical Goldilocks word",
            ));
        }
        batches.push((matrix.width, values));
    }
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(row_count)
        .map_err(|_| MerkleStoreError::Invalid("row digest allocation failed"))?;
    let mut row = Vec::new();
    row.try_reserve_exact(expected_width)
        .map_err(|_| MerkleStoreError::Invalid("flattened row allocation failed"))?;
    for offset in 0..row_count {
        row.clear();
        for (width, values) in &batches {
            let start = offset * width;
            row.extend_from_slice(&values[start..start + width]);
        }
        digests.push(checked_hash_digest(hash.hash_row(&row))?);
    }
    Ok(digests)
}

fn checked_hash_digest(digest: MerkleDigest) -> Result<MerkleDigest, MerkleStoreError> {
    if digest.iter().any(|word| *word >= GOLDILOCKS_MODULUS) {
        return Err(MerkleStoreError::Invalid(
            "hash backend returned a noncanonical Goldilocks word",
        ));
    }
    Ok(digest)
}

struct DigestDataWriter<'a> {
    file: &'a mut File,
    path: &'a Path,
    header_binding: [u8; 32],
    total_expected: u64,
    written: u64,
    global: Hasher,
    chunk_hasher: Hasher,
    chunk_fill: u64,
    auth_digests: Vec<[u8; 32]>,
}

impl<'a> DigestDataWriter<'a> {
    fn new(
        file: &'a mut File,
        path: &'a Path,
        header_binding: [u8; 32],
        total_expected: u64,
        auth_count: u64,
    ) -> Result<Self, MerkleStoreError> {
        let auth_count = usize::try_from(auth_count)
            .map_err(|_| MerkleStoreError::Invalid("authentication table is too large"))?;
        let mut auth_digests = Vec::new();
        auth_digests
            .try_reserve_exact(auth_count)
            .map_err(|_| MerkleStoreError::Invalid("authentication table allocation failed"))?;
        Ok(Self {
            file,
            path,
            header_binding,
            total_expected,
            written: 0,
            global: global_hasher(&header_binding),
            chunk_hasher: chunk_hasher(&header_binding, 0),
            chunk_fill: 0,
            auth_digests,
        })
    }

    fn write_digest(&mut self, digest: MerkleDigest) -> Result<(), MerkleStoreError> {
        checked_hash_digest(digest)?;
        if self.written >= self.total_expected {
            return Err(MerkleStoreError::Invalid("too many digests were written"));
        }
        let encoded = encode_digest(digest);
        self.file
            .write_all(&encoded)
            .map_err(|source| io_error("writing digest data to", self.path, source))?;
        self.global.update(&encoded);
        self.chunk_hasher.update(&encoded);
        self.written += 1;
        self.chunk_fill += 1;
        if self.chunk_fill == AUTH_CHUNK_DIGESTS {
            self.finish_chunk();
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), MerkleStoreError> {
        self.file
            .flush()
            .map_err(|source| io_error("flushing digest data in", self.path, source))
    }

    fn finish_chunk(&mut self) {
        self.auth_digests
            .push(*self.chunk_hasher.finalize().as_bytes());
        self.chunk_fill = 0;
        self.chunk_hasher = chunk_hasher(&self.header_binding, self.auth_digests.len() as u64);
    }

    fn seal(mut self) -> Result<(), MerkleStoreError> {
        if self.written != self.total_expected {
            return Err(MerkleStoreError::Invalid("digest data is incomplete"));
        }
        if self.chunk_fill != 0 {
            self.finish_chunk();
        }
        if self.auth_digests.len() as u64 != auth_chunk_count(self.total_expected)? {
            return Err(MerkleStoreError::Invalid(
                "authentication table count is inconsistent",
            ));
        }
        for digest in &self.auth_digests {
            self.file
                .write_all(digest)
                .map_err(|source| io_error("writing authentication table to", self.path, source))?;
            self.global.update(digest);
        }
        let global_digest = *self.global.finalize().as_bytes();
        self.file
            .seek(SeekFrom::Start(GLOBAL_DIGEST_OFFSET as u64))
            .and_then(|_| self.file.write_all(&global_digest))
            .and_then(|()| self.file.sync_all())
            .map_err(|source| io_error("sealing", self.path, source))
    }
}

struct HeaderCounts {
    header_len: u64,
    matrix_count: usize,
    layer_count: usize,
    total_digests: u64,
    auth_chunk_count: u64,
    max_height: usize,
    cap_height: usize,
    store_id: [u8; 32],
}

fn encode_header(
    store_id: [u8; 32],
    cap_height: usize,
    matrices: &[MerkleMatrixDescriptor],
    layers: &[MerkleLayerDescriptor],
    total_digests: u64,
    auth_count: u64,
) -> Result<Vec<u8>, MerkleStoreError> {
    let header_len = exact_header_len(matrices.len(), layers.len())?;
    let mut header = vec![0_u8; header_len];
    header[..8].copy_from_slice(MAGIC);
    put_u32(&mut header, 8, VERSION);
    put_u32(&mut header, 12, FIXED_HEADER_BYTES as u32);
    put_u64(&mut header, 16, header_len as u64);
    put_u32(
        &mut header,
        24,
        u32::try_from(matrices.len())
            .map_err(|_| MerkleStoreError::Invalid("matrix count does not fit u32"))?,
    );
    put_u32(
        &mut header,
        28,
        u32::try_from(layers.len())
            .map_err(|_| MerkleStoreError::Invalid("layer count does not fit u32"))?,
    );
    put_u32(&mut header, 32, AUTH_CHUNK_DIGESTS as u32);
    put_u32(&mut header, 36, 4);
    put_u64(&mut header, 40, total_digests);
    put_u64(&mut header, 48, auth_count);
    put_u64(
        &mut header,
        56,
        matrices
            .iter()
            .map(|matrix| matrix.height as u64)
            .max()
            .expect("validated matrices are nonempty"),
    );
    put_u32(
        &mut header,
        64,
        u32::try_from(cap_height)
            .map_err(|_| MerkleStoreError::Invalid("cap height does not fit u32"))?,
    );
    header[72..104].copy_from_slice(&store_id);

    let mut cursor = FIXED_HEADER_BYTES;
    for matrix in matrices {
        put_u32(
            &mut header,
            cursor,
            u32::try_from(matrix.ordinal)
                .map_err(|_| MerkleStoreError::Invalid("matrix ordinal does not fit u32"))?,
        );
        put_u64(&mut header, cursor + 8, matrix.height as u64);
        put_u64(&mut header, cursor + 16, matrix.width as u64);
        cursor += MATRIX_RECORD_BYTES;
    }
    for layer in layers {
        put_u32(
            &mut header,
            cursor,
            u32::try_from(layer.ordinal)
                .map_err(|_| MerkleStoreError::Invalid("layer ordinal does not fit u32"))?,
        );
        put_u64(&mut header, cursor + 8, layer.logical_len as u64);
        put_u64(&mut header, cursor + 16, layer.stored_len as u64);
        put_u64(&mut header, cursor + 24, layer.data_start_digest);
        put_u64(&mut header, cursor + 32, layer.injected_height as u64);
        cursor += LAYER_RECORD_BYTES;
    }
    debug_assert_eq!(cursor, header_len);
    Ok(header)
}

fn validate_fixed_header(
    header: &[u8; FIXED_HEADER_BYTES],
) -> Result<HeaderCounts, MerkleStoreError> {
    if &header[..8] != MAGIC {
        return Err(MerkleStoreError::Invalid("wrong magic"));
    }
    if read_u32(header, 8) != VERSION {
        return Err(MerkleStoreError::Invalid("unsupported version"));
    }
    if read_u32(header, 12) != FIXED_HEADER_BYTES as u32 {
        return Err(MerkleStoreError::Invalid("wrong fixed header length"));
    }
    if read_u32(header, 32) != AUTH_CHUNK_DIGESTS as u32 || read_u32(header, 36) != 4 {
        return Err(MerkleStoreError::Invalid("unsupported digest layout"));
    }
    if header[68..72] != [0_u8; 4] || header[136..144] != [0_u8; 8] {
        return Err(MerkleStoreError::Invalid(
            "reserved header bytes are nonzero",
        ));
    }
    let matrix_count = read_u32(header, 24) as usize;
    let layer_count = read_u32(header, 28) as usize;
    if matrix_count == 0 || matrix_count > MAX_MATRICES {
        return Err(MerkleStoreError::Invalid("matrix count is outside 1..=64"));
    }
    if layer_count == 0 || layer_count > MAX_LAYERS {
        return Err(MerkleStoreError::Invalid("layer count is invalid"));
    }
    let store_id: [u8; 32] = header[72..104].try_into().expect("store ID slice is exact");
    if store_id == [0_u8; 32] {
        return Err(MerkleStoreError::Invalid("store ID must be nonzero"));
    }
    Ok(HeaderCounts {
        header_len: read_u64(header, 16),
        matrix_count,
        layer_count,
        total_digests: read_u64(header, 40),
        auth_chunk_count: read_u64(header, 48),
        max_height: usize::try_from(read_u64(header, 56))
            .map_err(|_| MerkleStoreError::Invalid("maximum height does not fit memory"))?,
        cap_height: read_u32(header, 64) as usize,
        store_id,
    })
}

fn decode_matrix_descriptors(
    header: &[u8],
    matrix_count: usize,
) -> Result<Vec<MerkleMatrixDescriptor>, MerkleStoreError> {
    let mut matrices = Vec::new();
    matrices
        .try_reserve_exact(matrix_count)
        .map_err(|_| MerkleStoreError::Invalid("matrix descriptor allocation failed"))?;
    let mut cursor = FIXED_HEADER_BYTES;
    for ordinal in 0..matrix_count {
        if read_u32(header, cursor) as usize != ordinal || read_u32(header, cursor + 4) != 0 {
            return Err(MerkleStoreError::Invalid(
                "matrix ordinal or reserved bytes are invalid",
            ));
        }
        let height = usize::try_from(read_u64(header, cursor + 8))
            .map_err(|_| MerkleStoreError::Invalid("matrix height does not fit memory"))?;
        let width = usize::try_from(read_u64(header, cursor + 16))
            .map_err(|_| MerkleStoreError::Invalid("matrix width does not fit memory"))?;
        if height == 0 || width == 0 {
            return Err(MerkleStoreError::Invalid(
                "matrix height and width must be nonzero",
            ));
        }
        matrices.push(MerkleMatrixDescriptor {
            ordinal,
            height,
            width,
        });
        cursor += MATRIX_RECORD_BYTES;
    }
    validate_reachable_heights(&matrices)?;
    Ok(matrices)
}

fn decode_layer_descriptors(
    header: &[u8],
    matrix_count: usize,
    layer_count: usize,
) -> Result<Vec<MerkleLayerDescriptor>, MerkleStoreError> {
    let mut layers = Vec::new();
    layers
        .try_reserve_exact(layer_count)
        .map_err(|_| MerkleStoreError::Invalid("layer descriptor allocation failed"))?;
    let mut cursor = FIXED_HEADER_BYTES + matrix_count * MATRIX_RECORD_BYTES;
    for ordinal in 0..layer_count {
        if read_u32(header, cursor) as usize != ordinal || read_u32(header, cursor + 4) != 0 {
            return Err(MerkleStoreError::Invalid(
                "layer ordinal or reserved bytes are invalid",
            ));
        }
        layers.push(MerkleLayerDescriptor {
            ordinal,
            logical_len: usize::try_from(read_u64(header, cursor + 8)).map_err(|_| {
                MerkleStoreError::Invalid("logical layer length does not fit memory")
            })?,
            stored_len: usize::try_from(read_u64(header, cursor + 16)).map_err(|_| {
                MerkleStoreError::Invalid("stored layer length does not fit memory")
            })?,
            data_start_digest: read_u64(header, cursor + 24),
            injected_height: usize::try_from(read_u64(header, cursor + 32))
                .map_err(|_| MerkleStoreError::Invalid("injected height does not fit memory"))?,
        });
        cursor += LAYER_RECORD_BYTES;
    }
    Ok(layers)
}

fn exact_header_len(matrix_count: usize, layer_count: usize) -> Result<usize, MerkleStoreError> {
    FIXED_HEADER_BYTES
        .checked_add(
            matrix_count
                .checked_mul(MATRIX_RECORD_BYTES)
                .ok_or(MerkleStoreError::Invalid("matrix metadata length overflow"))?,
        )
        .and_then(|length| length.checked_add(layer_count.checked_mul(LAYER_RECORD_BYTES)?))
        .ok_or(MerkleStoreError::Invalid("header length overflow"))
}

fn compute_header_binding(header: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(HEADER_DOMAIN);
    hasher.update(&header[..GLOBAL_DIGEST_OFFSET]);
    hasher.update(&header[GLOBAL_DIGEST_END..]);
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

fn auth_chunk_count(total_digests: u64) -> Result<u64, MerkleStoreError> {
    total_digests
        .checked_add(AUTH_CHUNK_DIGESTS - 1)
        .map(|count| count / AUTH_CHUNK_DIGESTS)
        .ok_or(MerkleStoreError::Invalid(
            "authentication chunk count overflow",
        ))
}

fn encode_digest(digest: MerkleDigest) -> [u8; ENCODED_DIGEST_BYTES] {
    let mut encoded = [0_u8; ENCODED_DIGEST_BYTES];
    for (index, word) in digest.into_iter().enumerate() {
        let offset = index * size_of::<u64>();
        encoded[offset..offset + size_of::<u64>()].copy_from_slice(&word.to_le_bytes());
    }
    encoded
}

fn decode_digest(bytes: &[u8]) -> Result<MerkleDigest, MerkleStoreError> {
    let mut digest = [0_u64; 4];
    for (index, word) in digest.iter_mut().enumerate() {
        let offset = index * size_of::<u64>();
        *word = u64::from_le_bytes(
            bytes[offset..offset + size_of::<u64>()]
                .try_into()
                .expect("digest word slice is exact"),
        );
    }
    checked_hash_digest(digest)
}

fn read_raw_digest(file: &mut File, path: &Path) -> Result<MerkleDigest, MerkleStoreError> {
    let mut encoded = [0_u8; ENCODED_DIGEST_BYTES];
    file.read_exact(&mut encoded)
        .map_err(|source| io_error("reading construction layer from", path, source))?;
    decode_digest(&encoded)
}

fn partial_path_for(final_path: &Path) -> Result<PathBuf, MerkleStoreError> {
    let file_name = final_path
        .file_name()
        .ok_or(MerkleStoreError::Invalid("store path has no file name"))?;
    let mut partial_name = file_name.to_os_string();
    partial_name.push(".partial");
    Ok(final_path.with_file_name(partial_name))
}

struct PartialCleanup {
    path: PathBuf,
    published: bool,
}

impl PartialCleanup {
    const fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }
}

impl Drop for PartialCleanup {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("u32 slice is exact"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("u64 slice is exact"),
    )
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> MerkleStoreError {
    MerkleStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
    use p3_symmetric::{
        CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
    };

    use super::*;

    type LeafHash = PaddingFreeSponge<Poseidon2Goldilocks<8>, 8, 4, 4>;
    type Compress = TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct PoseidonHash {
        leaf: LeafHash,
        compress: Compress,
    }

    impl PoseidonHash {
        fn new() -> Self {
            let permutation = default_goldilocks_poseidon2_8();
            Self {
                leaf: LeafHash::new(permutation.clone()),
                compress: Compress::new(permutation),
            }
        }
    }

    impl BinaryMerkleHash for PoseidonHash {
        fn hash_row(&self, values: &[u64]) -> MerkleDigest {
            let digest: [Goldilocks; 4] = self
                .leaf
                .hash_iter(values.iter().copied().map(Goldilocks::from_u64));
            digest.map(|word| word.as_canonical_u64())
        }

        fn compress(&self, children: [MerkleDigest; 2]) -> MerkleDigest {
            let children = children.map(|digest| digest.map(Goldilocks::from_u64));
            self.compress
                .compress(children)
                .map(|word| word.as_canonical_u64())
        }
    }

    #[derive(Clone)]
    struct DenseRows {
        height: usize,
        width: usize,
        values: Vec<u64>,
    }

    impl DenseRows {
        fn fixture(height: usize, width: usize, salt: u64) -> Self {
            Self {
                height,
                width,
                values: (0..height * width)
                    .map(|index| salt + (index as u64 * 29) + 1)
                    .collect(),
            }
        }
    }

    impl MerkleRowSource for DenseRows {
        fn height(&self) -> usize {
            self.height
        }

        fn width(&self) -> usize {
            self.width
        }

        fn read_row(&self, row: usize) -> Result<Vec<u64>, MerkleStoreError> {
            let start = row
                .checked_mul(self.width)
                .ok_or(MerkleStoreError::Source("row offset overflow".to_owned()))?;
            let end = start + self.width;
            self.values
                .get(start..end)
                .map(<[u64]>::to_vec)
                .ok_or(MerkleStoreError::Source("row is out of bounds".to_owned()))
        }
    }

    struct CountingRows {
        rows: DenseRows,
        rows_read: AtomicU64,
    }

    impl CountingRows {
        fn new(rows: DenseRows) -> Self {
            Self {
                rows,
                rows_read: AtomicU64::new(0),
            }
        }

        fn rows_read(&self) -> u64 {
            self.rows_read.load(Ordering::Relaxed)
        }
    }

    impl MerkleRowSource for CountingRows {
        fn height(&self) -> usize {
            self.rows.height
        }

        fn width(&self) -> usize {
            self.rows.width
        }

        fn read_row(&self, row: usize) -> Result<Vec<u64>, MerkleStoreError> {
            self.rows_read.fetch_add(1, Ordering::Relaxed);
            self.rows.read_row(row)
        }

        fn read_rows(
            &self,
            row_start: usize,
            row_count: usize,
        ) -> Result<Vec<u64>, MerkleStoreError> {
            self.rows_read
                .fetch_add(row_count as u64, Ordering::Relaxed);
            MerkleRowSource::read_rows(&self.rows, row_start, row_count)
        }
    }

    fn first_digest_rows(matrices: &[DenseRows], hash: &PoseidonHash) -> DenseRows {
        let height = matrices.iter().map(|matrix| matrix.height).max().unwrap();
        DenseRows {
            height,
            width: 4,
            values: (0..height)
                .flat_map(|row| {
                    let flattened = matrices
                        .iter()
                        .filter(|matrix| matrix.height == height)
                        .flat_map(|matrix| matrix.read_row(row).unwrap())
                        .collect::<Vec<_>>();
                    hash.hash_row(&flattened)
                })
                .collect(),
        }
    }

    struct DenseReference {
        layers: Vec<Vec<MerkleDigest>>,
        cap_height: usize,
        max_height: usize,
        matrix_heights: Vec<usize>,
    }

    impl DenseReference {
        fn root(&self) -> MerkleDigest {
            self.layers.last().unwrap()[0]
        }

        fn cap(&self) -> Vec<MerkleDigest> {
            let effective = self.cap_height.min(self.layers.len() - 1);
            let layer = &self.layers[self.layers.len() - 1 - effective];
            layer[..(1 << effective).min(layer.len())].to_vec()
        }

        fn path(&self, index: usize) -> Vec<MerkleDigest> {
            let effective = self.cap_height.min(self.layers.len() - 1);
            let mut current = index;
            (0..self.layers.len() - 1 - effective)
                .map(|layer| {
                    let sibling = self.layers[layer][current ^ 1];
                    current >>= 1;
                    sibling
                })
                .collect()
        }

        fn row_indices(&self, index: usize) -> Vec<usize> {
            let log_max = (usize::BITS - (self.max_height - 1).leading_zeros()) as usize;
            self.matrix_heights
                .iter()
                .map(|height| {
                    let log_height = (usize::BITS - (height - 1).leading_zeros()) as usize;
                    index >> (log_max - log_height)
                })
                .collect()
        }
    }

    fn dense_reference(
        matrices: &[DenseRows],
        cap_height: usize,
        hash: &PoseidonHash,
    ) -> DenseReference {
        let max_height = matrices.iter().map(|matrix| matrix.height).max().unwrap();
        let hash_rows_at_height = |height: usize| {
            (0..height)
                .map(|row| {
                    let flattened = matrices
                        .iter()
                        .filter(|matrix| matrix.height == height)
                        .flat_map(|matrix| matrix.read_row(row).unwrap())
                        .collect::<Vec<_>>();
                    hash.hash_row(&flattened)
                })
                .collect::<Vec<_>>()
        };

        let mut first = hash_rows_at_height(max_height);
        if first.len() > 1 && first.len() % 2 != 0 {
            first.push([0_u64; 4]);
        }
        let mut layers = vec![first];
        while layers.last().unwrap().len() > 1 {
            let previous = layers.last().unwrap();
            let logical_len = previous.len() / 2;
            let target_power = logical_len.next_power_of_two();
            let injected_height = matrices
                .iter()
                .map(|matrix| matrix.height)
                .find(|height| *height != max_height && height.next_power_of_two() == target_power)
                .unwrap_or(0);
            let injected_rows =
                (injected_height != 0).then(|| hash_rows_at_height(injected_height));
            let mut next = (0..logical_len)
                .map(|index| {
                    let parent = hash.compress([previous[2 * index], previous[2 * index + 1]]);
                    injected_rows
                        .as_ref()
                        .map_or(parent, |rows| hash.compress([parent, rows[index]]))
                })
                .collect::<Vec<_>>();
            if next.len() > 1 && next.len() % 2 != 0 {
                next.push([0_u64; 4]);
            }
            layers.push(next);
        }
        DenseReference {
            layers,
            cap_height,
            max_height,
            matrix_heights: matrices.iter().map(|matrix| matrix.height).collect(),
        }
    }

    fn test_dir(label: &str) -> PathBuf {
        let nonce = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-merkle-store-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn assert_case(label: &str, matrices: Vec<DenseRows>, cap_height: usize) {
        let directory = test_dir(label);
        let path = directory.join("tree.merkle");
        let hash = PoseidonHash::new();
        let expected = dense_reference(&matrices, cap_height, &hash);
        let sources = matrices
            .iter()
            .map(|matrix| matrix as &dyn MerkleRowSource)
            .collect::<Vec<_>>();
        let store =
            build_authenticated_merkle_store(&path, [0x5a; 32], &sources, cap_height, &hash)
                .unwrap();
        assert_eq!(store.root().unwrap(), expected.root());
        assert_eq!(store.cap().unwrap(), expected.cap());
        for index in 0..expected.max_height {
            assert_eq!(store.opening_path(index).unwrap(), expected.path(index));
            assert_eq!(
                store.matrix_row_indices(index).unwrap(),
                expected.row_indices(index)
            );
        }
        assert!(!path.with_file_name("tree.merkle.partial").exists());
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn single_matrix_root_and_paths_match_dense_poseidon2() {
        assert_case("single", vec![DenseRows::fixture(8, 3, 10)], 0);
    }

    #[test]
    fn equal_height_matrix_order_root_and_paths_match_dense_poseidon2() {
        assert_case(
            "equal",
            vec![
                DenseRows::fixture(8, 1, 20),
                DenseRows::fixture(8, 2, 2_000),
                DenseRows::fixture(8, 3, 20_000),
            ],
            1,
        );
    }

    #[test]
    fn mixed_reachable_heights_root_and_paths_match_dense_poseidon2() {
        assert_case(
            "mixed",
            vec![
                DenseRows::fixture(7, 2, 30),
                DenseRows::fixture(4, 1, 3_000),
                DenseRows::fixture(4, 2, 30_000),
                DenseRows::fixture(2, 3, 300_000),
                DenseRows::fixture(1, 1, 3_000_000),
            ],
            2,
        );
    }

    #[test]
    fn parallel_upper_layers_match_dense_order_across_chunk_boundaries() {
        let directory = test_dir("parallel-chunks");
        let path = directory.join("tree.merkle");
        let hash = PoseidonHash::new();
        let matrices = vec![
            DenseRows::fixture(1_025, 2, 40),
            DenseRows::fixture(513, 1, 4_000),
            DenseRows::fixture(257, 3, 40_000),
        ];
        let expected = dense_reference(&matrices, 3, &hash);
        let sources = matrices
            .iter()
            .map(|matrix| matrix as &dyn MerkleRowSource)
            .collect::<Vec<_>>();

        let store =
            build_authenticated_merkle_store(&path, [0x6c; 32], &sources, 3, &hash).unwrap();

        assert_eq!(store.root().unwrap(), expected.root());
        assert_eq!(store.cap().unwrap(), expected.cap());
        for index in [0, 1, 255, 256, 511, 512, 1_024] {
            assert_eq!(store.opening_path(index).unwrap(), expected.path(index));
            assert_eq!(
                store.matrix_row_indices(index).unwrap(),
                expected.row_indices(index)
            );
        }

        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn supplied_first_layer_matches_mixed_tree_without_reading_tallest_rows() {
        let directory = test_dir("supplied-mixed");
        let path = directory.join("tree.merkle");
        let hash = PoseidonHash::new();
        let matrices = vec![
            DenseRows::fixture(7, 2, 50),
            DenseRows::fixture(4, 1, 5_000),
            DenseRows::fixture(7, 3, 50_000),
            DenseRows::fixture(2, 2, 500_000),
            DenseRows::fixture(1, 1, 5_000_000),
        ];
        let expected = dense_reference(&matrices, 2, &hash);
        let first_digests = first_digest_rows(&matrices, &hash);
        let counted = matrices
            .into_iter()
            .map(CountingRows::new)
            .collect::<Vec<_>>();
        let sources = counted
            .iter()
            .map(|matrix| matrix as &dyn MerkleRowSource)
            .collect::<Vec<_>>();

        let store = build_authenticated_merkle_store_with_first_digest_layer(
            &path,
            [0x7c; 32],
            &sources,
            &first_digests,
            2,
            &hash,
        )
        .unwrap();

        assert_eq!(store.root().unwrap(), expected.root());
        assert_eq!(store.cap().unwrap(), expected.cap());
        for index in 0..expected.max_height {
            assert_eq!(store.opening_path(index).unwrap(), expected.path(index));
            assert_eq!(
                store.matrix_row_indices(index).unwrap(),
                expected.row_indices(index)
            );
        }
        assert_eq!(
            counted
                .iter()
                .map(CountingRows::rows_read)
                .collect::<Vec<_>>(),
            vec![0, 4, 0, 2, 1]
        );

        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn supplied_first_layer_rejects_bad_geometry_and_noncanonical_words() {
        let directory = test_dir("bad-supplied");
        let matrix = DenseRows::fixture(7, 2, 60);
        let sources = [&matrix as &dyn MerkleRowSource];
        let hash = PoseidonHash::new();

        let wrong_height = DenseRows::fixture(8, 4, 6_000);
        assert!(matches!(
            build_authenticated_merkle_store_with_first_digest_layer(
                directory.join("wrong-height.merkle"),
                [0x8d; 32],
                &sources,
                &wrong_height,
                0,
                &hash,
            ),
            Err(MerkleStoreError::Invalid(
                "first digest layer height must equal the maximum matrix height"
            ))
        ));

        let wrong_width = DenseRows::fixture(7, 3, 60_000);
        assert!(matches!(
            build_authenticated_merkle_store_with_first_digest_layer(
                directory.join("wrong-width.merkle"),
                [0x9e; 32],
                &sources,
                &wrong_width,
                0,
                &hash,
            ),
            Err(MerkleStoreError::Invalid(
                "first digest layer width must equal four"
            ))
        ));

        let mut noncanonical = first_digest_rows(std::slice::from_ref(&matrix), &hash);
        noncanonical.values[0] = GOLDILOCKS_MODULUS;
        assert!(matches!(
            build_authenticated_merkle_store_with_first_digest_layer(
                directory.join("noncanonical.merkle"),
                [0xaf; 32],
                &sources,
                &noncanonical,
                0,
                &hash,
            ),
            Err(MerkleStoreError::Invalid(
                "first digest layer contains a noncanonical Goldilocks word"
            ))
        ));
        assert!(!directory.join("noncanonical.merkle.partial").exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn post_open_digest_mutation_is_rejected_by_bounded_path_read() {
        let directory = test_dir("mutation");
        let path = directory.join("tree.merkle");
        let matrix = DenseRows::fixture(512, 2, 40);
        let sources = [&matrix as &dyn MerkleRowSource];
        let store =
            build_authenticated_merkle_store(&path, [0x6b; 32], &sources, 0, &PoseidonHash::new())
                .unwrap();

        let mutated_offset = store.header_len + ENCODED_DIGEST_BYTES as u64;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(mutated_offset)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(mutated_offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(
            store.opening_path(0),
            Err(MerkleStoreError::ChecksumMismatch)
        ));
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }
}
