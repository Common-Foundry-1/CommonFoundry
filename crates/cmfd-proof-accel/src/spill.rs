//! Fail-closed storage for out-of-core proof matrices.
//!
//! A writer accepts rows exactly once and in global physical order, binds the
//! matrix metadata and canonical field bytes into a BLAKE3 digest, and exposes
//! the final path only after the complete artifact has been synchronized and
//! sealed. Readers validate the entire artifact before allowing random row
//! access. These digests protect worker storage integrity; consensus acceptance
//! still comes from the parent process's independent CPU proof verification.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use blake3::Hasher;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use thiserror::Error;

use crate::{CudaProofStream, CudaProofStreamCanonicalRows, ProofAccelError};

const GOLDILOCKS_MODULUS: u64 = Goldilocks::ORDER_U64;

const MAGIC: &[u8; 8] = b"CMFDLDE1";
const VERSION: u32 = 1;
const LAYOUT_PHYSICAL_BIT_REVERSED_ROW_MAJOR: u8 = 1;
const HEADER_PREFIX_BYTES: usize = 128;
const DIGEST_BYTES: usize = 32;
const HEADER_BYTES: usize = HEADER_PREFIX_BYTES + DIGEST_BYTES;
const ENCODE_VALUES: usize = 4096;
const AUTH_CHUNK_ROWS: u64 = 256;
const AUTH_CHUNK_CACHE_BYTES: usize = 64 * 1024 * 1024;
const STREAM_MANIFEST_DOMAIN: &[u8] = b"CMFD-PROOF-STREAM-MANIFEST-V1";
const AUTH_CHUNK_DOMAIN: &[u8] = b"CMFD-LDE-AUTH-CHUNK-V1";

/// Immutable identity and geometry for one spilled LDE matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdeArtifactSpec {
    pub job_id: [u8; 32],
    pub source_height: u64,
    pub height: u64,
    pub width: u32,
    pub added_bits: u8,
    /// BLAKE3 commitment to the ordered source-matrix widths and coset shifts.
    pub stream_manifest: [u8; 32],
}

impl LdeArtifactSpec {
    fn validate(&self) -> Result<u64, SpillError> {
        if self.source_height == 0 || !self.source_height.is_power_of_two() {
            return Err(SpillError::InvalidSpec(
                "source height must be a nonzero power of two",
            ));
        }
        if self.added_bits > 31 {
            return Err(SpillError::InvalidSpec("added bits exceed 31"));
        }
        let blowup = 1_u64
            .checked_shl(u32::from(self.added_bits))
            .ok_or(SpillError::InvalidSpec("expanded height overflow"))?;
        let expected_height = self
            .source_height
            .checked_mul(blowup)
            .ok_or(SpillError::InvalidSpec("expanded height overflow"))?;
        if self.height != expected_height {
            return Err(SpillError::InvalidSpec(
                "height does not equal source height times the blowup",
            ));
        }
        if self.width == 0 {
            return Err(SpillError::InvalidSpec("width must be nonzero"));
        }
        if self.stream_manifest == [0_u8; 32] {
            return Err(SpillError::InvalidSpec("stream manifest must be nonzero"));
        }
        self.height
            .checked_mul(u64::from(self.width))
            .and_then(|limbs| limbs.checked_mul(size_of::<u64>() as u64))
            .ok_or(SpillError::InvalidSpec("matrix byte length overflow"))
    }
}

#[derive(Debug, Error)]
pub enum SpillError {
    #[error("invalid LDE artifact specification: {0}")]
    InvalidSpec(&'static str),
    #[error("invalid LDE row chunk: {0}")]
    InvalidChunk(&'static str),
    #[error("LDE artifact already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("LDE artifact I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid sealed LDE artifact: {0}")]
    Corrupt(&'static str),
    #[error("sealed LDE artifact checksum does not match")]
    ChecksumMismatch,
    #[error("CUDA proof stream failed: {0}")]
    ProofStream(#[from] ProofAccelError),
}

/// Sequential fail-closed writer for one physical-bit-reversed row-major LDE.
pub struct LdeArtifactWriter {
    file: Option<File>,
    partial_path: PathBuf,
    final_path: PathBuf,
    spec: LdeArtifactSpec,
    header_prefix: [u8; HEADER_PREFIX_BYTES],
    rows_written: u64,
    hasher: Hasher,
    auth_chunk_hasher: Hasher,
    auth_chunk_rows: u64,
    auth_chunk_digests: Vec<[u8; DIGEST_BYTES]>,
    sealed: bool,
}

impl LdeArtifactWriter {
    /// Create a unique partial artifact next to `final_path`.
    pub fn create(final_path: impl AsRef<Path>, spec: LdeArtifactSpec) -> Result<Self, SpillError> {
        let final_path = final_path.as_ref().to_path_buf();
        if final_path.exists() {
            return Err(SpillError::AlreadyExists(final_path));
        }
        let data_bytes = spec.validate()?;
        let partial_path = partial_path_for(&final_path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial_path)
            .map_err(|source| io_error("creating", &partial_path, source))?;
        let chunk_count = auth_chunk_count(spec.height)?;
        let prefix = encode_header_prefix(&spec, data_bytes, chunk_count);
        file.write_all(&prefix)
            .and_then(|()| file.write_all(&[0_u8; DIGEST_BYTES]))
            .map_err(|source| io_error("writing header to", &partial_path, source))?;

        let mut hasher = Hasher::new();
        hasher.update(&prefix);
        Ok(Self {
            file: Some(file),
            partial_path,
            final_path,
            spec,
            header_prefix: prefix,
            rows_written: 0,
            hasher,
            auth_chunk_hasher: auth_chunk_hasher(&prefix, 0),
            auth_chunk_rows: 0,
            auth_chunk_digests: Vec::new(),
            sealed: false,
        })
    }

    pub const fn rows_written(&self) -> u64 {
        self.rows_written
    }

    pub const fn spec(&self) -> &LdeArtifactSpec {
        &self.spec
    }

    /// Append canonical rows at the exact next global physical row index.
    pub fn write_rows(&mut self, row_start: u64, values: &[u64]) -> Result<(), SpillError> {
        if row_start != self.rows_written {
            return Err(SpillError::InvalidChunk(
                "row start does not match the next expected row",
            ));
        }
        let width = self.spec.width as usize;
        if values.is_empty() || !values.len().is_multiple_of(width) {
            return Err(SpillError::InvalidChunk(
                "value count must contain one or more complete rows",
            ));
        }
        if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
            return Err(SpillError::InvalidChunk(
                "row chunk contains a noncanonical Goldilocks element",
            ));
        }
        let row_count = u64::try_from(values.len() / width)
            .map_err(|_| SpillError::InvalidChunk("row count does not fit u64"))?;
        let end = row_start
            .checked_add(row_count)
            .ok_or(SpillError::InvalidChunk("row range overflow"))?;
        if end > self.spec.height {
            return Err(SpillError::InvalidChunk(
                "row chunk exceeds the declared matrix height",
            ));
        }

        let mut value_offset = 0_usize;
        let mut rows_remaining = row_count;
        while rows_remaining != 0 {
            let rows_until_boundary = AUTH_CHUNK_ROWS - self.auth_chunk_rows;
            let take_rows = rows_remaining.min(rows_until_boundary);
            let take_values = usize::try_from(take_rows)
                .ok()
                .and_then(|rows| rows.checked_mul(width))
                .ok_or(SpillError::InvalidChunk("row chunk size overflow"))?;
            let value_end = value_offset
                .checked_add(take_values)
                .ok_or(SpillError::InvalidChunk("row chunk offset overflow"))?;
            self.write_encoded_values(&values[value_offset..value_end])?;
            value_offset = value_end;
            rows_remaining -= take_rows;
            self.auth_chunk_rows += take_rows;
            if self.auth_chunk_rows == AUTH_CHUNK_ROWS {
                self.finish_auth_chunk();
            }
        }
        self.rows_written = end;
        Ok(())
    }

    fn write_encoded_values(&mut self, values: &[u64]) -> Result<(), SpillError> {
        let path = self.partial_path.clone();
        let file = self
            .file
            .as_mut()
            .ok_or(SpillError::InvalidChunk("writer is already sealed"))?;
        let mut encoded = [0_u8; ENCODE_VALUES * size_of::<u64>()];
        for chunk in values.chunks(ENCODE_VALUES) {
            for (index, value) in chunk.iter().enumerate() {
                let start = index * size_of::<u64>();
                encoded[start..start + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
            }
            let bytes = &encoded[..std::mem::size_of_val(chunk)];
            file.write_all(bytes)
                .map_err(|source| io_error("writing rows to", &path, source))?;
            self.hasher.update(bytes);
            self.auth_chunk_hasher.update(bytes);
        }
        Ok(())
    }

    fn finish_auth_chunk(&mut self) {
        let digest = *self.auth_chunk_hasher.finalize().as_bytes();
        self.auth_chunk_digests.push(digest);
        self.auth_chunk_rows = 0;
        self.auth_chunk_hasher =
            auth_chunk_hasher(&self.header_prefix, self.auth_chunk_digests.len() as u64);
    }

    /// Synchronize and atomically publish the complete artifact without overwrite.
    pub fn seal(mut self) -> Result<SealedLdeArtifact, SpillError> {
        if self.rows_written != self.spec.height {
            return Err(SpillError::InvalidChunk(
                "cannot seal an incomplete LDE artifact",
            ));
        }
        if self.auth_chunk_rows != 0 {
            self.finish_auth_chunk();
        }
        let expected_chunk_count = usize::try_from(auth_chunk_count(self.spec.height)?)
            .map_err(|_| SpillError::InvalidSpec("authentication chunk count is too large"))?;
        if self.auth_chunk_digests.len() != expected_chunk_count {
            return Err(SpillError::Corrupt(
                "authentication chunk count does not match the matrix",
            ));
        }
        let mut file = self
            .file
            .take()
            .ok_or(SpillError::InvalidChunk("writer is already sealed"))?;
        for chunk_digest in &self.auth_chunk_digests {
            file.write_all(chunk_digest).map_err(|source| {
                io_error(
                    "writing authentication table to",
                    &self.partial_path,
                    source,
                )
            })?;
            self.hasher.update(chunk_digest);
        }
        let digest = *self.hasher.finalize().as_bytes();
        file.seek(SeekFrom::Start(HEADER_PREFIX_BYTES as u64))
            .and_then(|_| file.write_all(&digest))
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error("sealing", &self.partial_path, source))?;
        drop(file);

        let mut artifact = SealedLdeArtifact::open(&self.partial_path)?;
        fs::hard_link(&self.partial_path, &self.final_path)
            .map_err(|source| io_error("publishing", &self.final_path, source))?;
        self.sealed = true;
        artifact.path = self.final_path.clone();
        let _ = fs::remove_file(&self.partial_path);
        Ok(artifact)
    }
}

trait CanonicalProofRowStream {
    fn source_height(&self) -> u64;
    fn expanded_rows(&self) -> u64;
    fn total_width(&self) -> usize;
    fn added_bits(&self) -> usize;
    fn stream_manifest(&self) -> [u8; DIGEST_BYTES];
    fn cursor(&self) -> u64;
    fn next_canonical_rows(
        &mut self,
        requested_rows: usize,
    ) -> Result<CudaProofStreamCanonicalRows, ProofAccelError>;
}

impl CanonicalProofRowStream for CudaProofStream {
    fn source_height(&self) -> u64 {
        self.source_height()
    }

    fn expanded_rows(&self) -> u64 {
        self.expanded_rows()
    }

    fn total_width(&self) -> usize {
        self.total_width()
    }

    fn added_bits(&self) -> usize {
        self.added_bits()
    }

    fn stream_manifest(&self) -> [u8; DIGEST_BYTES] {
        cuda_proof_stream_manifest(self)
    }

    fn cursor(&self) -> u64 {
        self.cursor()
    }

    fn next_canonical_rows(
        &mut self,
        requested_rows: usize,
    ) -> Result<CudaProofStreamCanonicalRows, ProofAccelError> {
        self.next_rows(requested_rows, true)
            .map(|rows| rows.into_canonical_values())
    }
}

/// Drain one fresh CUDA proof stream into a sealed LDE artifact.
///
/// The digest callback receives the matching width-4 Poseidon2 rows before the
/// next chunk is requested. Any callback, storage, or accelerator failure
/// aborts the artifact; callers must start a new stream rather than resume it.
pub fn drain_cuda_proof_stream<F>(
    stream: &mut CudaProofStream,
    writer: LdeArtifactWriter,
    chunk_rows: usize,
    digest_sink: F,
) -> Result<SealedLdeArtifact, SpillError>
where
    F: FnMut(u64, usize, &[u64]) -> Result<(), SpillError>,
{
    drain_proof_stream(stream, writer, chunk_rows, digest_sink)
}

fn drain_proof_stream<S, F>(
    stream: &mut S,
    mut writer: LdeArtifactWriter,
    chunk_rows: usize,
    mut digest_sink: F,
) -> Result<SealedLdeArtifact, SpillError>
where
    S: CanonicalProofRowStream,
    F: FnMut(u64, usize, &[u64]) -> Result<(), SpillError>,
{
    if stream.cursor() != 0 || writer.rows_written() != 0 {
        return Err(SpillError::InvalidChunk(
            "proof stream and artifact writer must both be fresh",
        ));
    }
    let source_height = usize::try_from(stream.source_height())
        .map_err(|_| SpillError::InvalidChunk("source height does not fit usize"))?;
    if chunk_rows == 0
        || !chunk_rows.is_power_of_two()
        || chunk_rows > source_height
        || !source_height.is_multiple_of(chunk_rows)
    {
        return Err(SpillError::InvalidChunk(
            "chunk rows must be a power of two that divides the source height",
        ));
    }
    let spec = writer.spec();
    if spec.source_height != stream.source_height()
        || spec.height != stream.expanded_rows()
        || spec.width as usize != stream.total_width()
        || usize::from(spec.added_bits) != stream.added_bits()
        || spec.stream_manifest != stream.stream_manifest()
    {
        return Err(SpillError::InvalidSpec(
            "artifact identity or geometry does not match the CUDA proof stream",
        ));
    }

    while stream.cursor() < stream.expanded_rows() {
        let chunk = stream.next_canonical_rows(chunk_rows)?;
        if chunk.global_physical_row != writer.rows_written()
            || chunk.row_count != chunk_rows
            || chunk.digest_width != 4
            || chunk.lde_width != stream.total_width()
        {
            return Err(SpillError::InvalidChunk(
                "CUDA proof stream returned inconsistent chunk metadata",
            ));
        }
        let lde = chunk.lde.as_deref().ok_or(SpillError::InvalidChunk(
            "CUDA proof stream omitted requested LDE rows",
        ))?;
        writer.write_rows(chunk.global_physical_row, lde)?;
        digest_sink(chunk.global_physical_row, chunk.row_count, &chunk.digests)?;
    }
    writer.seal()
}

impl Drop for LdeArtifactWriter {
    fn drop(&mut self) {
        self.file.take();
        if !self.sealed {
            let _ = fs::remove_file(&self.partial_path);
        }
    }
}

struct AuthenticatedChunkCache {
    chunks: HashMap<u64, Arc<[u64]>>,
    insertion_order: VecDeque<u64>,
    cached_bytes: usize,
    max_bytes: usize,
}

impl AuthenticatedChunkCache {
    fn new(max_bytes: usize) -> Self {
        Self {
            chunks: HashMap::new(),
            insertion_order: VecDeque::new(),
            cached_bytes: 0,
            max_bytes,
        }
    }

    fn get(&self, chunk_index: u64) -> Option<Arc<[u64]>> {
        self.chunks.get(&chunk_index).cloned()
    }

    fn insert(&mut self, chunk_index: u64, chunk: Arc<[u64]>) -> Result<Arc<[u64]>, SpillError> {
        if let Some(existing) = self.get(chunk_index) {
            return Ok(existing);
        }
        let chunk_bytes = chunk
            .len()
            .checked_mul(size_of::<u64>())
            .ok_or(SpillError::Corrupt(
                "authenticated chunk cache size overflow",
            ))?;
        if chunk_bytes > self.max_bytes {
            return Ok(chunk);
        }
        while self
            .cached_bytes
            .checked_add(chunk_bytes)
            .ok_or(SpillError::Corrupt(
                "authenticated chunk cache size overflow",
            ))?
            > self.max_bytes
        {
            let oldest = self.insertion_order.pop_front().ok_or(SpillError::Corrupt(
                "authenticated chunk cache eviction order is inconsistent",
            ))?;
            let evicted = self.chunks.remove(&oldest).ok_or(SpillError::Corrupt(
                "authenticated chunk cache entry is missing",
            ))?;
            let evicted_bytes =
                evicted
                    .len()
                    .checked_mul(size_of::<u64>())
                    .ok_or(SpillError::Corrupt(
                        "authenticated chunk cache size overflow",
                    ))?;
            self.cached_bytes =
                self.cached_bytes
                    .checked_sub(evicted_bytes)
                    .ok_or(SpillError::Corrupt(
                        "authenticated chunk cache accounting underflow",
                    ))?;
        }
        self.cached_bytes =
            self.cached_bytes
                .checked_add(chunk_bytes)
                .ok_or(SpillError::Corrupt(
                    "authenticated chunk cache size overflow",
                ))?;
        self.insertion_order.push_back(chunk_index);
        if self
            .chunks
            .insert(chunk_index, Arc::clone(&chunk))
            .is_some()
        {
            return Err(SpillError::Corrupt(
                "authenticated chunk cache entry was replaced",
            ));
        }
        Ok(chunk)
    }
}

/// Fully validated sealed LDE artifact with bounded random row access.
///
/// Authenticated chunks are decoded once into immutable snapshots and retained
/// in a per-artifact FIFO cache capped at 64 MiB of canonical field payload.
/// A chunk larger than that limit is authenticated for each read but not cached.
pub struct SealedLdeArtifact {
    file: Mutex<File>,
    chunk_cache: Mutex<AuthenticatedChunkCache>,
    path: PathBuf,
    spec: LdeArtifactSpec,
    digest: [u8; DIGEST_BYTES],
    header_prefix: [u8; HEADER_PREFIX_BYTES],
    auth_chunk_digests: Vec<[u8; DIGEST_BYTES]>,
    #[cfg(test)]
    authenticated_chunk_reads: AtomicU64,
    cleanup: Option<ArtifactCleanup>,
}

struct ArtifactCleanup(PathBuf);

impl Drop for ArtifactCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl SealedLdeArtifact {
    /// Open and fully authenticate a sealed artifact before exposing any rows.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SpillError> {
        Self::open_with_cache_bytes(path, AUTH_CHUNK_CACHE_BYTES)
    }

    fn open_with_cache_bytes(
        path: impl AsRef<Path>,
        cache_bytes: usize,
    ) -> Result<Self, SpillError> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path).map_err(|source| io_error("opening", &path, source))?;
        let mut header = [0_u8; HEADER_BYTES];
        file.read_exact(&mut header)
            .map_err(|source| io_error("reading header from", &path, source))?;
        let (spec, data_bytes, chunk_count, digest) = decode_header(&header)?;
        let auth_table_bytes = chunk_count
            .checked_mul(DIGEST_BYTES as u64)
            .ok_or(SpillError::Corrupt("authentication table length overflow"))?;
        let expected_len = (HEADER_BYTES as u64)
            .checked_add(data_bytes)
            .and_then(|bytes| bytes.checked_add(auth_table_bytes))
            .ok_or(SpillError::Corrupt("artifact length overflow"))?;
        let actual_len = file
            .metadata()
            .map_err(|source| io_error("reading metadata for", &path, source))?
            .len();
        if actual_len != expected_len {
            return Err(SpillError::Corrupt(
                "artifact length does not match its declared matrix",
            ));
        }

        let mut hasher = Hasher::new();
        hasher.update(&header[..HEADER_PREFIX_BYTES]);
        let mut buffer = [0_u8; 64 * 1024];
        let mut remaining = data_bytes;
        while remaining != 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| SpillError::Corrupt("read size does not fit usize"))?;
            file.read_exact(&mut buffer[..take])
                .map_err(|source| io_error("authenticating", &path, source))?;
            hasher.update(&buffer[..take]);
            remaining -= take as u64;
        }
        let chunk_count_usize = usize::try_from(chunk_count)
            .map_err(|_| SpillError::Corrupt("authentication chunk count does not fit memory"))?;
        let mut auth_chunk_digests = Vec::new();
        auth_chunk_digests
            .try_reserve_exact(chunk_count_usize)
            .map_err(|_| SpillError::Corrupt("authentication table allocation failed"))?;
        for _ in 0..chunk_count_usize {
            let mut chunk_digest = [0_u8; DIGEST_BYTES];
            file.read_exact(&mut chunk_digest)
                .map_err(|source| io_error("reading authentication table from", &path, source))?;
            hasher.update(&chunk_digest);
            auth_chunk_digests.push(chunk_digest);
        }
        if hasher.finalize().as_bytes() != &digest {
            return Err(SpillError::ChecksumMismatch);
        }

        Ok(Self {
            file: Mutex::new(file),
            chunk_cache: Mutex::new(AuthenticatedChunkCache::new(cache_bytes)),
            path,
            spec,
            digest,
            header_prefix: header[..HEADER_PREFIX_BYTES]
                .try_into()
                .expect("header prefix slice is exact"),
            auth_chunk_digests,
            #[cfg(test)]
            authenticated_chunk_reads: AtomicU64::new(0),
            cleanup: None,
        })
    }

    pub const fn spec(&self) -> &LdeArtifactSpec {
        &self.spec
    }

    pub const fn digest(&self) -> [u8; DIGEST_BYTES] {
        self.digest
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the published artifact after its final in-process owner drops.
    ///
    /// The validated file handle is declared before the cleanup guard and is
    /// therefore closed first. Cloned matrix views keep this owner alive.
    pub fn remove_on_drop(mut self) -> Self {
        self.cleanup = Some(ArtifactCleanup(self.path.clone()));
        self
    }

    /// Read complete rows by global physical index.
    pub fn read_rows(&self, row_start: u64, row_count: u64) -> Result<Vec<u64>, SpillError> {
        if row_count == 0 {
            return Err(SpillError::InvalidChunk("row count must be nonzero"));
        }
        let row_end = row_start
            .checked_add(row_count)
            .ok_or(SpillError::InvalidChunk("row range overflow"))?;
        if row_end > self.spec.height {
            return Err(SpillError::InvalidChunk(
                "requested rows exceed the declared matrix height",
            ));
        }
        let mut values = Vec::new();
        let value_count_u64 = row_count
            .checked_mul(u64::from(self.spec.width))
            .ok_or(SpillError::InvalidChunk("requested value count overflow"))?;
        let value_count = usize::try_from(value_count_u64)
            .map_err(|_| SpillError::InvalidChunk("requested value count does not fit memory"))?;
        values
            .try_reserve_exact(value_count)
            .map_err(|_| SpillError::InvalidChunk("requested row allocation failed"))?;
        let first_chunk = row_start / AUTH_CHUNK_ROWS;
        let last_chunk = (row_end - 1) / AUTH_CHUNK_ROWS;
        for chunk_index in first_chunk..=last_chunk {
            let chunk = self.authenticated_chunk(chunk_index)?;
            let chunk_row_start = chunk_index
                .checked_mul(AUTH_CHUNK_ROWS)
                .ok_or(SpillError::Corrupt("authentication chunk row overflow"))?;
            let chunk_row_end = self.spec.height.min(
                chunk_row_start
                    .checked_add(AUTH_CHUNK_ROWS)
                    .ok_or(SpillError::Corrupt("authentication chunk row overflow"))?,
            );
            let wanted_start = row_start.max(chunk_row_start);
            let wanted_end = row_end.min(chunk_row_end);
            let first_value = usize::try_from(wanted_start - chunk_row_start)
                .ok()
                .and_then(|rows| rows.checked_mul(self.spec.width as usize))
                .ok_or(SpillError::InvalidChunk("requested row offset overflow"))?;
            let wanted_values = usize::try_from(wanted_end - wanted_start)
                .ok()
                .and_then(|rows| rows.checked_mul(self.spec.width as usize))
                .ok_or(SpillError::InvalidChunk("requested value count overflow"))?;
            let last_value = first_value
                .checked_add(wanted_values)
                .ok_or(SpillError::InvalidChunk("requested value range overflow"))?;
            values.extend_from_slice(chunk.get(first_value..last_value).ok_or(
                SpillError::Corrupt("authenticated chunk geometry is inconsistent"),
            )?);
        }
        debug_assert_eq!(values.len(), value_count);
        Ok(values)
    }

    fn cached_chunk(&self, chunk_index: u64) -> Result<Option<Arc<[u64]>>, SpillError> {
        let cache = self
            .chunk_cache
            .lock()
            .map_err(|_| SpillError::Corrupt("authenticated chunk cache lock is poisoned"))?;
        Ok(cache.get(chunk_index))
    }

    fn authenticated_chunk(&self, chunk_index: u64) -> Result<Arc<[u64]>, SpillError> {
        if let Some(chunk) = self.cached_chunk(chunk_index)? {
            return Ok(chunk);
        }

        let mut file = self
            .file
            .lock()
            .map_err(|_| SpillError::Corrupt("artifact file lock is poisoned"))?;
        // Another reader may have populated the shared cache while this read
        // waited for the serialized file cursor.
        if let Some(chunk) = self.cached_chunk(chunk_index)? {
            return Ok(chunk);
        }

        let chunk_row_start = chunk_index
            .checked_mul(AUTH_CHUNK_ROWS)
            .ok_or(SpillError::Corrupt("authentication chunk row overflow"))?;
        if chunk_row_start >= self.spec.height {
            return Err(SpillError::Corrupt(
                "authentication chunk index exceeds the matrix",
            ));
        }
        let chunk_row_end = self.spec.height.min(
            chunk_row_start
                .checked_add(AUTH_CHUNK_ROWS)
                .ok_or(SpillError::Corrupt("authentication chunk row overflow"))?,
        );
        let chunk_rows = chunk_row_end - chunk_row_start;
        let chunk_values_u64 = chunk_rows
            .checked_mul(u64::from(self.spec.width))
            .ok_or(SpillError::Corrupt("authentication chunk length overflow"))?;
        let chunk_values = usize::try_from(chunk_values_u64)
            .map_err(|_| SpillError::Corrupt("authentication chunk does not fit memory"))?;
        let chunk_bytes = chunk_values
            .checked_mul(size_of::<u64>())
            .ok_or(SpillError::Corrupt("authentication chunk length overflow"))?;
        let data_offset = chunk_row_start
            .checked_mul(u64::from(self.spec.width))
            .and_then(|limbs| limbs.checked_mul(size_of::<u64>() as u64))
            .and_then(|bytes| bytes.checked_add(HEADER_BYTES as u64))
            .ok_or(SpillError::Corrupt("authentication chunk offset overflow"))?;
        file.seek(SeekFrom::Start(data_offset))
            .map_err(|source| io_error("seeking in", &self.path, source))?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(chunk_bytes)
            .map_err(|_| SpillError::Corrupt("authentication chunk allocation failed"))?;
        encoded.resize(chunk_bytes, 0);
        file.read_exact(&mut encoded)
            .map_err(|source| io_error("reading rows from", &self.path, source))?;
        #[cfg(test)]
        self.authenticated_chunk_reads
            .fetch_add(1, Ordering::Relaxed);

        let expected_digest = self
            .auth_chunk_digests
            .get(usize::try_from(chunk_index).map_err(|_| {
                SpillError::Corrupt("authentication chunk index does not fit memory")
            })?)
            .ok_or(SpillError::Corrupt(
                "authentication chunk digest is missing",
            ))?;
        let mut hasher = auth_chunk_hasher(&self.header_prefix, chunk_index);
        hasher.update(&encoded);
        if hasher.finalize().as_bytes() != expected_digest {
            return Err(SpillError::ChecksumMismatch);
        }

        let mut decoded = Vec::new();
        decoded
            .try_reserve_exact(chunk_values)
            .map_err(|_| SpillError::Corrupt("authentication chunk allocation failed"))?;
        for bytes in encoded.chunks_exact(size_of::<u64>()) {
            let value = u64::from_le_bytes(bytes.try_into().expect("u64 chunk is exact"));
            if value >= GOLDILOCKS_MODULUS {
                return Err(SpillError::Corrupt(
                    "artifact chunk contains a noncanonical Goldilocks element",
                ));
            }
            decoded.push(value);
        }
        debug_assert_eq!(decoded.len(), chunk_values);
        let chunk = Arc::<[u64]>::from(decoded);
        let mut cache = self
            .chunk_cache
            .lock()
            .map_err(|_| SpillError::Corrupt("authenticated chunk cache lock is poisoned"))?;
        cache.insert(chunk_index, chunk)
    }
}

/// Authenticated physical-bit-reversed rows exposed through Plonky3's matrix API.
///
/// Clones retain the same validated file handle and authenticated-chunk cache.
/// The first access authenticates a complete storage chunk; later accesses use
/// its immutable decoded snapshot while it remains in the bounded cache.
#[derive(Clone)]
pub struct AuthenticatedLdeMatrix {
    artifact: Arc<SealedLdeArtifact>,
    column_start: usize,
    width: usize,
    height: usize,
}

impl std::fmt::Debug for AuthenticatedLdeMatrix {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedLdeMatrix")
            .field("path", &self.artifact.path())
            .field("digest", &self.artifact.digest())
            .field("column_start", &self.column_start)
            .field("width", &self.width)
            .field("height", &self.height)
            .finish()
    }
}

impl AuthenticatedLdeMatrix {
    /// Expose the complete concatenated LDE stored in `artifact`.
    pub fn new(artifact: Arc<SealedLdeArtifact>) -> Result<Self, SpillError> {
        let width = artifact.spec().width as usize;
        Self::column_view(artifact, 0, width)
    }

    /// Expose one contiguous column range without reopening the artifact path.
    pub fn column_view(
        artifact: Arc<SealedLdeArtifact>,
        column_start: usize,
        width: usize,
    ) -> Result<Self, SpillError> {
        if width == 0 {
            return Err(SpillError::InvalidSpec(
                "matrix column view width must be nonzero",
            ));
        }
        let column_end = column_start
            .checked_add(width)
            .ok_or(SpillError::InvalidSpec("matrix column view overflow"))?;
        if column_end > artifact.spec().width as usize {
            return Err(SpillError::InvalidSpec(
                "matrix column view exceeds the sealed artifact width",
            ));
        }
        let height = usize::try_from(artifact.spec().height)
            .map_err(|_| SpillError::InvalidSpec("matrix height does not fit usize"))?;
        Ok(Self {
            artifact,
            column_start,
            width,
            height,
        })
    }

    /// Split the concatenated stream into its original ordered components.
    ///
    /// The component manifest and total width must exactly match the sealed
    /// artifact. This prevents a caller from relabeling or reordering columns
    /// after the stream has been authenticated.
    pub fn from_stream_components(
        artifact: Arc<SealedLdeArtifact>,
        components: &[crate::CudaProofStreamComponent],
    ) -> Result<Vec<Self>, SpillError> {
        if components.is_empty() {
            return Err(SpillError::InvalidSpec(
                "matrix component list must be nonempty",
            ));
        }
        for (expected_ordinal, component) in components.iter().enumerate() {
            if component.ordinal() != expected_ordinal {
                return Err(SpillError::InvalidSpec(
                    "matrix component ordinals must be contiguous and ordered",
                ));
            }
            if component.width() == 0 || component.coset_shift() >= GOLDILOCKS_MODULUS {
                return Err(SpillError::InvalidSpec(
                    "matrix component metadata is invalid",
                ));
            }
        }
        let manifest = stream_manifest(
            artifact.spec().source_height,
            usize::from(artifact.spec().added_bits),
            components.iter().map(|component| {
                (
                    component.ordinal(),
                    component.width(),
                    component.coset_shift(),
                )
            }),
        );
        if manifest != artifact.spec().stream_manifest {
            return Err(SpillError::InvalidSpec(
                "matrix components do not match the sealed stream manifest",
            ));
        }

        let mut column_start = 0_usize;
        let mut matrices = Vec::new();
        matrices
            .try_reserve_exact(components.len())
            .map_err(|_| SpillError::InvalidSpec("matrix component allocation failed"))?;
        for component in components {
            matrices.push(Self::column_view(
                Arc::clone(&artifact),
                column_start,
                component.width(),
            )?);
            column_start = column_start
                .checked_add(component.width())
                .ok_or(SpillError::InvalidSpec("matrix component width overflow"))?;
        }
        if column_start != artifact.spec().width as usize {
            return Err(SpillError::InvalidSpec(
                "matrix component widths do not fill the sealed artifact",
            ));
        }
        Ok(matrices)
    }

    pub fn artifact(&self) -> &Arc<SealedLdeArtifact> {
        &self.artifact
    }

    pub const fn column_start(&self) -> usize {
        self.column_start
    }

    /// Read and authenticate several complete rows from this column view.
    ///
    /// The backing artifact authenticates each overlapping storage chunk on its
    /// first cache miss, allowing sequential Merkle construction and cloned
    /// column views to reuse the same immutable decoded snapshot.
    pub fn read_canonical_rows(
        &self,
        row_start: usize,
        row_count: usize,
    ) -> Result<Vec<u64>, SpillError> {
        let stored = self.artifact.read_rows(
            u64::try_from(row_start)
                .map_err(|_| SpillError::InvalidChunk("row start does not fit u64"))?,
            u64::try_from(row_count)
                .map_err(|_| SpillError::InvalidChunk("row count does not fit u64"))?,
        )?;
        let stored_width = self.artifact.spec().width as usize;
        if self.column_start == 0 && self.width == stored_width {
            return Ok(stored);
        }
        let output_len = row_count
            .checked_mul(self.width)
            .ok_or(SpillError::InvalidChunk("column-view row count overflow"))?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| SpillError::InvalidChunk("column-view row allocation failed"))?;
        for row in stored.chunks_exact(stored_width) {
            output.extend_from_slice(&row[self.column_start..self.column_start + self.width]);
        }
        debug_assert_eq!(output.len(), output_len);
        Ok(output)
    }
}

impl Matrix<Goldilocks> for AuthenticatedLdeMatrix {
    fn width(&self) -> usize {
        self.width
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
        debug_assert!(start <= end && end <= self.width);
        let stored = self
            .read_canonical_rows(row, 1)
            .unwrap_or_else(|error| panic!("authenticated LDE matrix read failed: {error}"));
        stored[start..end]
            .iter()
            .copied()
            .map(Goldilocks::new)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

fn partial_path_for(final_path: &Path) -> Result<PathBuf, SpillError> {
    let file_name = final_path
        .file_name()
        .ok_or(SpillError::InvalidSpec("artifact path has no file name"))?;
    let mut partial_name = file_name.to_os_string();
    partial_name.push(".partial");
    Ok(final_path.with_file_name(partial_name))
}

/// Bind the exact ordered CUDA stream components to an artifact specification.
pub fn cuda_proof_stream_manifest(stream: &CudaProofStream) -> [u8; DIGEST_BYTES] {
    stream_manifest(
        stream.source_height(),
        stream.added_bits(),
        stream.components().iter().map(|component| {
            (
                component.ordinal(),
                component.width(),
                component.coset_shift(),
            )
        }),
    )
}

fn stream_manifest<I>(source_height: u64, added_bits: usize, components: I) -> [u8; DIGEST_BYTES]
where
    I: IntoIterator<Item = (usize, usize, u64)>,
{
    let components = components.into_iter().collect::<Vec<_>>();
    let mut hasher = Hasher::new();
    hasher.update(STREAM_MANIFEST_DOMAIN);
    hasher.update(&source_height.to_le_bytes());
    hasher.update(&(added_bits as u64).to_le_bytes());
    hasher.update(&(components.len() as u64).to_le_bytes());
    for (ordinal, width, coset_shift) in components {
        hasher.update(&(ordinal as u64).to_le_bytes());
        hasher.update(&(width as u64).to_le_bytes());
        hasher.update(&coset_shift.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn auth_chunk_count(height: u64) -> Result<u64, SpillError> {
    height
        .checked_add(AUTH_CHUNK_ROWS - 1)
        .map(|rows| rows / AUTH_CHUNK_ROWS)
        .ok_or(SpillError::InvalidSpec(
            "authentication chunk count overflow",
        ))
}

fn auth_chunk_hasher(prefix: &[u8; HEADER_PREFIX_BYTES], chunk_index: u64) -> Hasher {
    let mut hasher = Hasher::new();
    hasher.update(AUTH_CHUNK_DOMAIN);
    hasher.update(prefix);
    hasher.update(&chunk_index.to_le_bytes());
    hasher
}

fn encode_header_prefix(
    spec: &LdeArtifactSpec,
    data_bytes: u64,
    chunk_count: u64,
) -> [u8; HEADER_PREFIX_BYTES] {
    let mut bytes = [0_u8; HEADER_PREFIX_BYTES];
    let mut cursor = 0;
    put(&mut bytes, &mut cursor, MAGIC);
    put(&mut bytes, &mut cursor, &VERSION.to_le_bytes());
    put(
        &mut bytes,
        &mut cursor,
        &(HEADER_BYTES as u32).to_le_bytes(),
    );
    put(&mut bytes, &mut cursor, &spec.job_id);
    put(&mut bytes, &mut cursor, &spec.source_height.to_le_bytes());
    put(&mut bytes, &mut cursor, &spec.height.to_le_bytes());
    put(&mut bytes, &mut cursor, &spec.width.to_le_bytes());
    put(&mut bytes, &mut cursor, &[spec.added_bits]);
    put(&mut bytes, &mut cursor, &[0_u8; 3]);
    put(&mut bytes, &mut cursor, &spec.stream_manifest);
    put(
        &mut bytes,
        &mut cursor,
        &[LAYOUT_PHYSICAL_BIT_REVERSED_ROW_MAJOR],
    );
    put(&mut bytes, &mut cursor, &[0_u8; 3]);
    put(
        &mut bytes,
        &mut cursor,
        &(AUTH_CHUNK_ROWS as u32).to_le_bytes(),
    );
    put(&mut bytes, &mut cursor, &chunk_count.to_le_bytes());
    put(&mut bytes, &mut cursor, &data_bytes.to_le_bytes());
    debug_assert_eq!(cursor, HEADER_PREFIX_BYTES);
    bytes
}

fn decode_header(
    bytes: &[u8; HEADER_BYTES],
) -> Result<(LdeArtifactSpec, u64, u64, [u8; DIGEST_BYTES]), SpillError> {
    if &bytes[..8] != MAGIC {
        return Err(SpillError::Corrupt("wrong artifact magic"));
    }
    if read_u32(bytes, 8) != VERSION {
        return Err(SpillError::Corrupt("unsupported artifact version"));
    }
    if read_u32(bytes, 12) != HEADER_BYTES as u32 {
        return Err(SpillError::Corrupt("wrong artifact header length"));
    }
    if bytes[69..72] != [0_u8; 3] || bytes[105..108] != [0_u8; 3] {
        return Err(SpillError::Corrupt("artifact reserved bytes are nonzero"));
    }
    if bytes[104] != LAYOUT_PHYSICAL_BIT_REVERSED_ROW_MAJOR {
        return Err(SpillError::Corrupt("unsupported artifact row layout"));
    }
    if read_u32(bytes, 108) != AUTH_CHUNK_ROWS as u32 {
        return Err(SpillError::Corrupt(
            "unsupported artifact authentication chunk size",
        ));
    }
    let spec = LdeArtifactSpec {
        job_id: bytes[16..48].try_into().expect("job ID slice is exact"),
        source_height: read_u64(bytes, 48),
        height: read_u64(bytes, 56),
        width: read_u32(bytes, 64),
        added_bits: bytes[68],
        stream_manifest: bytes[72..104]
            .try_into()
            .expect("stream manifest slice is exact"),
    };
    let expected_data_bytes = spec.validate()?;
    let chunk_count = read_u64(bytes, 112);
    if chunk_count != auth_chunk_count(spec.height)? {
        return Err(SpillError::Corrupt(
            "authentication chunk count does not match the matrix",
        ));
    }
    let data_bytes = read_u64(bytes, 120);
    if data_bytes != expected_data_bytes {
        return Err(SpillError::Corrupt(
            "artifact data length does not match its matrix specification",
        ));
    }
    let digest = bytes[HEADER_PREFIX_BYTES..HEADER_BYTES]
        .try_into()
        .expect("digest slice is exact");
    Ok((spec, data_bytes, chunk_count, digest))
}

fn put<const N: usize>(output: &mut [u8; N], cursor: &mut usize, value: &[u8]) {
    let end = *cursor + value.len();
    output[*cursor..end].copy_from_slice(value);
    *cursor = end;
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

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> SpillError {
    SpillError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::{
        Barrier,
        atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_dir(label: &str) -> PathBuf {
        let nonce = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-proof-spill-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn spec() -> LdeArtifactSpec {
        LdeArtifactSpec {
            job_id: [0x5a; 32],
            source_height: 2,
            height: 8,
            width: 3,
            added_bits: 2,
            stream_manifest: stream_manifest(2, 2, [(0, 3, 7)]),
        }
    }

    fn values() -> Vec<u64> {
        (0..24).map(|value| value + 1).collect()
    }

    fn two_chunk_artifact(path: &Path) -> (SealedLdeArtifact, Vec<u64>) {
        let spec = LdeArtifactSpec {
            job_id: [0x3c; 32],
            source_height: 128,
            height: 512,
            width: 2,
            added_bits: 2,
            stream_manifest: stream_manifest(128, 2, [(0, 2, 7)]),
        };
        let expected = (0..1024).map(|value| value + 1).collect::<Vec<_>>();
        let mut writer = LdeArtifactWriter::create(path, spec).unwrap();
        writer.write_rows(0, &expected).unwrap();
        (writer.seal().unwrap(), expected)
    }

    fn overwrite_artifact_value(path: &Path, row: u64, column: u64, value: u64) {
        let offset = HEADER_BYTES as u64 + (row * 2 + column) * size_of::<u64>() as u64;
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&value.to_le_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    struct FakeProofRowStream {
        source_height: u64,
        expanded_rows: u64,
        width: usize,
        cursor: u64,
        lde: Vec<u64>,
        digests: Vec<u64>,
    }

    impl FakeProofRowStream {
        fn new() -> Self {
            let source_height = 8;
            let expanded_rows = 32;
            let width = 3;
            Self {
                source_height,
                expanded_rows,
                width,
                cursor: 0,
                lde: (0..expanded_rows * width as u64)
                    .map(|value| value + 1)
                    .collect(),
                digests: (0..expanded_rows * 4).map(|value| 10_000 + value).collect(),
            }
        }
    }

    impl CanonicalProofRowStream for FakeProofRowStream {
        fn source_height(&self) -> u64 {
            self.source_height
        }

        fn expanded_rows(&self) -> u64 {
            self.expanded_rows
        }

        fn total_width(&self) -> usize {
            self.width
        }

        fn added_bits(&self) -> usize {
            2
        }

        fn stream_manifest(&self) -> [u8; DIGEST_BYTES] {
            stream_manifest(self.source_height, self.added_bits(), [(0, self.width, 7)])
        }

        fn cursor(&self) -> u64 {
            self.cursor
        }

        fn next_canonical_rows(
            &mut self,
            requested_rows: usize,
        ) -> Result<CudaProofStreamCanonicalRows, ProofAccelError> {
            let start = self.cursor as usize;
            let end = start + requested_rows;
            self.cursor = end as u64;
            Ok(CudaProofStreamCanonicalRows {
                global_physical_row: start as u64,
                row_count: requested_rows,
                digest_width: 4,
                lde_width: self.width,
                digests: self.digests[start * 4..end * 4].to_vec(),
                lde: Some(self.lde[start * self.width..end * self.width].to_vec()),
            })
        }
    }

    #[test]
    fn partitioned_rows_round_trip_and_bind_metadata() {
        for partition in [1_u64, 2, 3, 8] {
            let dir = test_dir("round-trip");
            let path = dir.join("matrix.lde");
            let expected = values();
            let mut writer = LdeArtifactWriter::create(&path, spec()).unwrap();
            let mut row = 0;
            while row < 8 {
                let count = partition.min(8 - row);
                let start = (row * 3) as usize;
                let end = ((row + count) * 3) as usize;
                writer.write_rows(row, &expected[start..end]).unwrap();
                row += count;
            }
            let artifact = writer.seal().unwrap();
            assert_eq!(artifact.spec(), &spec());
            assert_eq!(artifact.read_rows(0, 8).unwrap(), expected);
            assert_eq!(artifact.read_rows(3, 2).unwrap(), values()[9..15]);
            assert_ne!(artifact.digest(), [0_u8; 32]);
            drop(artifact);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn authenticated_matrix_exposes_exact_rows_and_ordered_component_views() {
        let dir = test_dir("matrix-view");
        let path = dir.join("matrix.lde");
        let matrix_spec = LdeArtifactSpec {
            stream_manifest: stream_manifest(2, 2, [(0, 1, 7), (1, 2, 9)]),
            ..spec()
        };
        let mut writer = LdeArtifactWriter::create(&path, matrix_spec).unwrap();
        writer.write_rows(0, &values()).unwrap();
        let artifact = Arc::new(writer.seal().unwrap());
        let complete = AuthenticatedLdeMatrix::new(Arc::clone(&artifact)).unwrap();
        assert_eq!(complete.width(), 3);
        assert_eq!(complete.height(), 8);
        assert_eq!(
            complete.row(2).unwrap().into_iter().collect::<Vec<_>>(),
            values()[6..9]
                .iter()
                .copied()
                .map(Goldilocks::new)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            unsafe {
                complete
                    .row_subseq_unchecked(4, 1, 3)
                    .into_iter()
                    .collect::<Vec<_>>()
            },
            values()[13..15]
                .iter()
                .copied()
                .map(Goldilocks::new)
                .collect::<Vec<_>>()
        );

        let components = [
            crate::CudaProofStreamComponent {
                ordinal: 0,
                width: 1,
                coset_shift: 7,
            },
            crate::CudaProofStreamComponent {
                ordinal: 1,
                width: 2,
                coset_shift: 9,
            },
        ];
        let matrices =
            AuthenticatedLdeMatrix::from_stream_components(Arc::clone(&artifact), &components)
                .unwrap();
        assert_eq!(matrices.len(), 2);
        assert_eq!(matrices[0].column_start(), 0);
        assert_eq!(matrices[1].column_start(), 1);
        assert_eq!(
            matrices[0].row(3).unwrap().into_iter().collect::<Vec<_>>(),
            vec![Goldilocks::new(10)]
        );
        assert_eq!(
            matrices[1].row(3).unwrap().into_iter().collect::<Vec<_>>(),
            vec![Goldilocks::new(11), Goldilocks::new(12)]
        );

        let wrong_shift = [
            components[0],
            crate::CudaProofStreamComponent {
                coset_shift: 10,
                ..components[1]
            },
        ];
        assert!(
            AuthenticatedLdeMatrix::from_stream_components(Arc::clone(&artifact), &wrong_shift)
                .is_err()
        );
        let wrong_order = [components[1], components[0]];
        assert!(AuthenticatedLdeMatrix::from_stream_components(artifact, &wrong_order).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authenticated_matrix_panics_instead_of_exposing_mutated_rows() {
        let dir = test_dir("matrix-view-mutation");
        let path = dir.join("matrix.lde");
        let mut writer = LdeArtifactWriter::create(&path, spec()).unwrap();
        writer.write_rows(0, &values()).unwrap();
        let matrix = AuthenticatedLdeMatrix::new(Arc::new(writer.seal().unwrap())).unwrap();

        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(HEADER_BYTES as u64 + 8)).unwrap();
        file.write_all(&99_u64.to_le_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(std::panic::catch_unwind(|| matrix.row(0)).is_err());
        drop(matrix);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authenticated_matrix_rejects_invalid_column_views() {
        let dir = test_dir("matrix-view-bounds");
        let path = dir.join("matrix.lde");
        let mut writer = LdeArtifactWriter::create(&path, spec()).unwrap();
        writer.write_rows(0, &values()).unwrap();
        let artifact = Arc::new(writer.seal().unwrap());
        assert!(AuthenticatedLdeMatrix::column_view(Arc::clone(&artifact), 0, 0).is_err());
        assert!(AuthenticatedLdeMatrix::column_view(Arc::clone(&artifact), 2, 2).is_err());
        assert!(AuthenticatedLdeMatrix::column_view(artifact, usize::MAX, 1).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ephemeral_artifact_survives_matrix_clones_then_removes_its_file() {
        let dir = test_dir("matrix-view-cleanup");
        let path = dir.join("matrix.lde");
        let mut writer = LdeArtifactWriter::create(&path, spec()).unwrap();
        writer.write_rows(0, &values()).unwrap();
        let artifact = Arc::new(writer.seal().unwrap().remove_on_drop());
        let matrix = AuthenticatedLdeMatrix::new(Arc::clone(&artifact)).unwrap();
        let clone = matrix.clone();
        drop(artifact);
        drop(matrix);
        assert!(path.exists());
        assert_eq!(clone.row(0).unwrap().into_iter().count(), 3);
        drop(clone);
        assert!(!path.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn gaps_duplicates_noncanonical_and_incomplete_artifacts_fail_closed() {
        let dir = test_dir("invalid-chunks");
        let path = dir.join("matrix.lde");
        let mut writer = LdeArtifactWriter::create(&path, spec()).unwrap();
        assert!(matches!(
            writer.write_rows(1, &[1, 2, 3]),
            Err(SpillError::InvalidChunk(_))
        ));
        writer.write_rows(0, &[1, 2, 3]).unwrap();
        assert!(matches!(
            writer.write_rows(0, &[4, 5, 6]),
            Err(SpillError::InvalidChunk(_))
        ));
        assert!(matches!(
            writer.write_rows(1, &[GOLDILOCKS_MODULUS, 5, 6]),
            Err(SpillError::InvalidChunk(_))
        ));
        assert!(matches!(writer.seal(), Err(SpillError::InvalidChunk(_))));
        assert!(!path.exists());
        assert!(!partial_path_for(&path).unwrap().exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn expanded_height_overflow_is_rejected() {
        let dir = test_dir("height-overflow");
        let path = dir.join("matrix.lde");
        let result = LdeArtifactWriter::create(
            &path,
            LdeArtifactSpec {
                job_id: [0x5a; 32],
                source_height: 1_u64 << 63,
                height: 0,
                width: 1,
                added_bits: 1,
                stream_manifest: stream_manifest(1_u64 << 63, 1, [(0, 1, 7)]),
            },
        );
        assert!(matches!(result, Err(SpillError::InvalidSpec(_))));
        assert!(!path.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corruption_truncation_and_trailing_bytes_are_rejected() {
        for mode in ["corrupt", "truncate", "append"] {
            let dir = test_dir(mode);
            let path = dir.join("matrix.lde");
            let mut writer = LdeArtifactWriter::create(&path, spec()).unwrap();
            writer.write_rows(0, &values()).unwrap();
            drop(writer.seal().unwrap());

            match mode {
                "corrupt" => {
                    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
                    file.seek(SeekFrom::Start(HEADER_BYTES as u64 + 8)).unwrap();
                    file.write_all(&99_u64.to_le_bytes()).unwrap();
                }
                "truncate" => {
                    let file = OpenOptions::new().write(true).open(&path).unwrap();
                    file.set_len(HEADER_BYTES as u64 + 8).unwrap();
                }
                "append" => {
                    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
                    file.write_all(&0_u64.to_le_bytes()).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(SealedLdeArtifact::open(&path).is_err());
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn metadata_mutation_is_rejected_before_rows_are_exposed() {
        let dir = test_dir("metadata");
        let path = dir.join("matrix.lde");
        let mut writer = LdeArtifactWriter::create(&path, spec()).unwrap();
        writer.write_rows(0, &values()).unwrap();
        drop(writer.seal().unwrap());

        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(72)).unwrap();
        file.write_all(&[0x44]).unwrap();
        drop(file);
        assert!(matches!(
            SealedLdeArtifact::open(&path),
            Err(SpillError::ChecksumMismatch)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rows_are_reauthenticated_after_open() {
        let dir = test_dir("post-open-mutation");
        let path = dir.join("matrix.lde");
        let mut writer = LdeArtifactWriter::create(&path, spec()).unwrap();
        writer.write_rows(0, &values()).unwrap();
        let artifact = writer.seal().unwrap();

        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(HEADER_BYTES as u64 + 8)).unwrap();
        file.write_all(&99_u64.to_le_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(
            artifact.read_rows(0, 1),
            Err(SpillError::ChecksumMismatch)
        ));
        assert!(
            artifact.chunk_cache.lock().unwrap().chunks.is_empty(),
            "a failed authentication must not populate the cache"
        );
        drop(artifact);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authenticated_cache_is_shared_by_column_views_and_keeps_its_snapshot() {
        let dir = test_dir("shared-auth-cache");
        let path = dir.join("matrix.lde");
        let (artifact, expected) = two_chunk_artifact(&path);
        let artifact = Arc::new(artifact);
        let first_column =
            AuthenticatedLdeMatrix::column_view(Arc::clone(&artifact), 0, 1).unwrap();
        let second_column =
            AuthenticatedLdeMatrix::column_view(Arc::clone(&artifact), 1, 1).unwrap();

        assert_eq!(first_column.read_canonical_rows(10, 1).unwrap(), [21]);
        assert_eq!(
            artifact.authenticated_chunk_reads.load(Ordering::Relaxed),
            1
        );
        overwrite_artifact_value(&path, 10, 0, 42);
        overwrite_artifact_value(&path, 10, 1, 43);

        assert_eq!(second_column.read_canonical_rows(10, 1).unwrap(), [22]);
        assert_eq!(first_column.read_canonical_rows(10, 1).unwrap(), [21]);
        assert_eq!(
            artifact.authenticated_chunk_reads.load(Ordering::Relaxed),
            1,
            "both column views must reuse the same immutable cached chunk"
        );
        let cache = artifact.chunk_cache.lock().unwrap();
        assert_eq!(cache.max_bytes, AUTH_CHUNK_CACHE_BYTES);
        assert_eq!(cache.chunks.len(), 1);
        assert_eq!(cache.cached_bytes, 256 * 2 * size_of::<u64>());
        drop(cache);

        assert_eq!(expected[20..22], [21, 22]);
        drop(first_column);
        drop(second_column);
        drop(artifact);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bounded_cache_evicts_fifo_and_reauthenticates_evicted_chunks() {
        let dir = test_dir("bounded-auth-cache");
        let path = dir.join("matrix.lde");
        let (sealed, expected) = two_chunk_artifact(&path);
        drop(sealed);
        let one_chunk_bytes = 256 * 2 * size_of::<u64>();
        let artifact = SealedLdeArtifact::open_with_cache_bytes(&path, one_chunk_bytes).unwrap();

        assert_eq!(artifact.read_rows(0, 1).unwrap(), expected[..2]);
        assert_eq!(artifact.read_rows(300, 1).unwrap(), expected[600..602]);
        {
            let cache = artifact.chunk_cache.lock().unwrap();
            assert_eq!(cache.cached_bytes, one_chunk_bytes);
            assert!(cache.cached_bytes <= cache.max_bytes);
            assert_eq!(cache.chunks.len(), 1);
            assert!(!cache.chunks.contains_key(&0));
            assert!(cache.chunks.contains_key(&1));
        }

        overwrite_artifact_value(&path, 0, 0, 42);
        assert!(matches!(
            artifact.read_rows(0, 1),
            Err(SpillError::ChecksumMismatch)
        ));
        let cache = artifact.chunk_cache.lock().unwrap();
        assert_eq!(cache.cached_bytes, one_chunk_bytes);
        assert_eq!(cache.chunks.len(), 1);
        assert!(cache.chunks.contains_key(&1));
        drop(cache);
        drop(artifact);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn oversized_chunks_remain_uncached_without_evicting_residents() {
        let mut cache = AuthenticatedChunkCache::new(2 * size_of::<u64>());
        let resident = Arc::<[u64]>::from(vec![1_u64]);
        cache.insert(0, Arc::clone(&resident)).unwrap();
        let oversized = Arc::<[u64]>::from(vec![2_u64, 3, 4]);
        let returned = cache.insert(1, Arc::clone(&oversized)).unwrap();

        assert!(Arc::ptr_eq(&returned, &oversized));
        assert_eq!(cache.cached_bytes, size_of::<u64>());
        assert_eq!(cache.chunks.len(), 1);
        assert!(cache.chunks.contains_key(&0));
        assert!(!cache.chunks.contains_key(&1));
    }

    #[test]
    fn concurrent_same_chunk_misses_perform_one_authenticated_file_read() {
        let dir = test_dir("concurrent-auth-cache");
        let path = dir.join("matrix.lde");
        let (artifact, expected) = two_chunk_artifact(&path);
        let artifact = Arc::new(artifact);
        let barrier = Arc::new(Barrier::new(9));
        let threads = (0..8)
            .map(|row| {
                let artifact = Arc::clone(&artifact);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    artifact.read_rows(row, 1).unwrap()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for (row, thread) in threads.into_iter().enumerate() {
            assert_eq!(thread.join().unwrap(), expected[row * 2..row * 2 + 2]);
        }
        assert_eq!(
            artifact.authenticated_chunk_reads.load(Ordering::Relaxed),
            1,
            "the post-file-lock cache recheck must prevent duplicate I/O"
        );
        let cache = artifact.chunk_cache.lock().unwrap();
        assert_eq!(cache.chunks.len(), 1);
        assert!(cache.cached_bytes <= AUTH_CHUNK_CACHE_BYTES);
        drop(cache);
        drop(artifact);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stream_manifest_binds_component_order_widths_and_shifts() {
        let ordered = stream_manifest(8, 2, [(0, 1, 7), (1, 2, 9)]);
        assert_ne!(ordered, stream_manifest(8, 2, [(0, 2, 9), (1, 1, 7)]));
        assert_ne!(ordered, stream_manifest(8, 2, [(0, 1, 7), (1, 2, 10)]));
        assert_ne!(ordered, stream_manifest(16, 1, [(0, 1, 7), (1, 2, 9)]));
    }

    #[test]
    fn proof_stream_partitions_produce_the_same_sealed_rows_and_digest_order() {
        for chunk_rows in [1, 2, 4, 8] {
            let dir = test_dir("proof-stream");
            let path = dir.join("matrix.lde");
            let mut stream = FakeProofRowStream::new();
            let expected_lde = stream.lde.clone();
            let expected_digests = stream.digests.clone();
            let writer = LdeArtifactWriter::create(
                &path,
                LdeArtifactSpec {
                    job_id: [0xa5; 32],
                    source_height: 8,
                    height: 32,
                    width: 3,
                    added_bits: 2,
                    stream_manifest: stream.stream_manifest(),
                },
            )
            .unwrap();
            let mut digests = Vec::new();
            let artifact =
                drain_proof_stream(&mut stream, writer, chunk_rows, |start, rows, values| {
                    assert_eq!(start as usize * 4, digests.len());
                    assert_eq!(values.len(), rows * 4);
                    digests.extend_from_slice(values);
                    Ok(())
                })
                .unwrap();
            assert_eq!(artifact.read_rows(0, 32).unwrap(), expected_lde);
            assert_eq!(digests, expected_digests);
            drop(artifact);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn invalid_partition_or_digest_sink_failure_aborts_the_artifact() {
        for mode in ["partition", "sink"] {
            let dir = test_dir(mode);
            let path = dir.join("matrix.lde");
            let mut stream = FakeProofRowStream::new();
            let writer = LdeArtifactWriter::create(
                &path,
                LdeArtifactSpec {
                    job_id: [0xa5; 32],
                    source_height: 8,
                    height: 32,
                    width: 3,
                    added_bits: 2,
                    stream_manifest: stream.stream_manifest(),
                },
            )
            .unwrap();
            let result = drain_proof_stream(
                &mut stream,
                writer,
                if mode == "partition" { 3 } else { 4 },
                |_, _, _| Err(SpillError::InvalidChunk("injected digest sink failure")),
            );
            assert!(result.is_err());
            assert!(!path.exists());
            assert!(!partial_path_for(&path).unwrap().exists());
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn mismatched_stream_manifest_aborts_before_advancing_or_publishing() {
        let dir = test_dir("stream-manifest");
        let path = dir.join("matrix.lde");
        let mut stream = FakeProofRowStream::new();
        let writer = LdeArtifactWriter::create(
            &path,
            LdeArtifactSpec {
                job_id: [0xa5; 32],
                source_height: 8,
                height: 32,
                width: 3,
                added_bits: 2,
                stream_manifest: stream_manifest(8, 2, [(0, 3, 8)]),
            },
        )
        .unwrap();
        assert!(matches!(
            drain_proof_stream(&mut stream, writer, 4, |_, _, _| Ok(())),
            Err(SpillError::InvalidSpec(_))
        ));
        assert_eq!(stream.cursor(), 0);
        assert!(!path.exists());
        assert!(!partial_path_for(&path).unwrap().exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
