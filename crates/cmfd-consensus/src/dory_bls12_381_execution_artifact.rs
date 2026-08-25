//! Authenticated production execution-accumulator artifacts.
//!
//! The production ForgeMatrix execution witness is stored as signed little-
//! endian `i32` values in one canonical column-major order: the initialization
//! accumulator column first, followed by bank-major, layer-major accumulator
//! columns. The file is prover-local and never enters the consensus transcript.
//! Every value is covered by a fixed-size chunk digest, and the ordered digest
//! list is covered by root and final digests before any value is exposed.

use std::{
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use thiserror::Error;

#[cfg(test)]
use std::fs::OpenOptions;

use crate::{
    PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    PRODUCTION_V2_LAYERS_PER_BANK, dory_scratch_telemetry::TrackedScratchFile,
};

const ARTIFACT_MAGIC: [u8; 8] = *b"CFDBLSE1";
pub const BLS_DORY_EXECUTION_ACCUMULATOR_FORMAT_VERSION: u16 = 1;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_COLUMN_ORDER_VERSION: u16 = 1;
const SIGNED_I32_LE_ENCODING_VERSION: u16 = 1;
const HEADER_BYTES: u64 = 208;
const VALUE_BYTES: u64 = 4;
const DIGEST_BYTES: u64 = 32;
const FOOTER_DIGESTS: u64 = 2;
const IO_BUFFER_BYTES: usize = 1024 * 1024;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_ROWS: usize = PRODUCTION_V2_BATCH as usize;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS_PER_ROW: usize =
    PRODUCTION_V2_DIMENSION as usize;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_CELLS: usize =
    BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_ROWS
        * BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS_PER_ROW;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_BANKS: usize = PRODUCTION_V2_BANKS as usize;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_LAYERS_PER_BANK: usize =
    PRODUCTION_V2_LAYERS_PER_BANK as usize;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS: usize =
    1 + PRODUCTION_V2_LAYERS as usize;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS: u32 = 64_000_000;
pub const BLS_DORY_EXECUTION_ACCUMULATOR_AUTHENTICATION_CHUNK_CELLS: usize = 1 << 17;
const CONTEXT_HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryExecutionAccumulatorContext/v1";
const CHUNK_HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryExecutionAccumulatorChunk/v1";
const ORDERED_ROOT_HASH_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/BlsDoryExecutionAccumulatorOrderedRoot/v1";
const FINAL_HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryExecutionAccumulatorFinal/v1";
static ARTIFACT_NONCE: AtomicU64 = AtomicU64::new(1);

const _: () = {
    assert!(BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_ROWS == 128);
    assert!(BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS_PER_ROW == 4096);
    assert!(BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_CELLS == 1 << 19);
    assert!(
        BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_BANKS
            * BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_LAYERS_PER_BANK
            == PRODUCTION_V2_LAYERS as usize
    );
    assert!(BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS == 385);
    assert!(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS <= i32::MAX as u32);
};

/// Exact identities and layout bound into an execution-accumulator artifact.
///
/// Public construction admits only the production geometry. Tests use a
/// private constructor to exercise the identical format with bounded fixtures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryExecutionAccumulatorArtifactContext {
    network_identity: [u8; 32],
    model_record_identity: [u8; 32],
    setup_identity: [u8; 32],
    challenge_identity: [u8; 32],
    format_version: u16,
    column_order_version: u16,
    value_encoding_version: u16,
    canonical_rows: usize,
    canonical_columns: usize,
    banks: usize,
    layers_per_bank: usize,
    authentication_chunk_cells: usize,
}

impl BlsDoryExecutionAccumulatorArtifactContext {
    pub fn production(
        network_identity: [u8; 32],
        model_record_identity: [u8; 32],
        setup_identity: [u8; 32],
        challenge_identity: [u8; 32],
    ) -> Result<Self, BlsDoryExecutionAccumulatorArtifactError> {
        let context = Self {
            network_identity,
            model_record_identity,
            setup_identity,
            challenge_identity,
            format_version: BLS_DORY_EXECUTION_ACCUMULATOR_FORMAT_VERSION,
            column_order_version: BLS_DORY_EXECUTION_ACCUMULATOR_COLUMN_ORDER_VERSION,
            value_encoding_version: SIGNED_I32_LE_ENCODING_VERSION,
            canonical_rows: BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_ROWS,
            canonical_columns: BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS_PER_ROW,
            banks: BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_BANKS,
            layers_per_bank: BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_LAYERS_PER_BANK,
            authentication_chunk_cells: BLS_DORY_EXECUTION_ACCUMULATOR_AUTHENTICATION_CHUNK_CELLS,
        };
        context.validate()?;
        Ok(context)
    }

    #[must_use]
    pub const fn network_identity(&self) -> [u8; 32] {
        self.network_identity
    }

    #[must_use]
    pub const fn model_record_identity(&self) -> [u8; 32] {
        self.model_record_identity
    }

    #[must_use]
    pub const fn setup_identity(&self) -> [u8; 32] {
        self.setup_identity
    }

    #[must_use]
    pub const fn challenge_identity(&self) -> [u8; 32] {
        self.challenge_identity
    }

    #[must_use]
    pub const fn cells_per_column(&self) -> usize {
        self.canonical_rows * self.canonical_columns
    }

    #[must_use]
    pub const fn canonical_rows(&self) -> usize {
        self.canonical_rows
    }

    #[must_use]
    pub const fn canonical_columns(&self) -> usize {
        self.canonical_columns
    }

    #[must_use]
    pub fn columns(&self) -> usize {
        1 + self.banks * self.layers_per_bank
    }

    #[must_use]
    pub const fn banks(&self) -> usize {
        self.banks
    }

    #[must_use]
    pub const fn layers_per_bank(&self) -> usize {
        self.layers_per_bank
    }

    #[must_use]
    pub const fn authentication_chunk_cells(&self) -> usize {
        self.authentication_chunk_cells
    }

    pub fn projected_file_bytes(&self) -> Result<u64, BlsDoryExecutionAccumulatorArtifactError> {
        Ok(self.geometry()?.total_bytes)
    }

    fn validate(&self) -> Result<(), BlsDoryExecutionAccumulatorArtifactError> {
        if [
            self.network_identity,
            self.model_record_identity,
            self.setup_identity,
            self.challenge_identity,
        ]
        .contains(&[0; 32])
            || self.format_version != BLS_DORY_EXECUTION_ACCUMULATOR_FORMAT_VERSION
            || self.column_order_version != BLS_DORY_EXECUTION_ACCUMULATOR_COLUMN_ORDER_VERSION
            || self.value_encoding_version != SIGNED_I32_LE_ENCODING_VERSION
        {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidContext);
        }
        self.geometry()?;
        Ok(())
    }

    fn geometry(&self) -> Result<ArtifactGeometry, BlsDoryExecutionAccumulatorArtifactError> {
        validate_geometry(
            self.canonical_rows,
            self.canonical_columns,
            self.banks,
            self.layers_per_bank,
            self.authentication_chunk_cells,
        )
    }

    fn encode_header(
        &self,
    ) -> Result<[u8; HEADER_BYTES as usize], BlsDoryExecutionAccumulatorArtifactError> {
        self.validate()?;
        let geometry = self.geometry()?;
        let mut header = [0u8; HEADER_BYTES as usize];
        header[..8].copy_from_slice(&ARTIFACT_MAGIC);
        header[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        header[10..12].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        header[12..14].copy_from_slice(&self.column_order_version.to_le_bytes());
        header[14..16].copy_from_slice(&self.value_encoding_version.to_le_bytes());
        header[16..24].copy_from_slice(&usize_to_u64(self.canonical_rows)?.to_le_bytes());
        header[24..32].copy_from_slice(&usize_to_u64(self.canonical_columns)?.to_le_bytes());
        header[32..40].copy_from_slice(&usize_to_u64(self.cells_per_column())?.to_le_bytes());
        header[40..44].copy_from_slice(&usize_to_u32(geometry.columns)?.to_le_bytes());
        header[44..46].copy_from_slice(&usize_to_u16(self.banks)?.to_le_bytes());
        header[46..48].copy_from_slice(&usize_to_u16(self.layers_per_bank)?.to_le_bytes());
        header[48..56]
            .copy_from_slice(&usize_to_u64(self.authentication_chunk_cells)?.to_le_bytes());
        header[56..64].copy_from_slice(&usize_to_u64(geometry.chunks_per_column)?.to_le_bytes());
        header[64..72].copy_from_slice(&geometry.data_bytes.to_le_bytes());
        header[72..80].copy_from_slice(&usize_to_u64(geometry.chunk_digest_count)?.to_le_bytes());
        header[80..112].copy_from_slice(&self.network_identity);
        header[112..144].copy_from_slice(&self.model_record_identity);
        header[144..176].copy_from_slice(&self.setup_identity);
        header[176..208].copy_from_slice(&self.challenge_identity);
        Ok(header)
    }

    fn digest(&self) -> Result<[u8; 32], BlsDoryExecutionAccumulatorArtifactError> {
        let header = self.encode_header()?;
        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_HASH_DOMAIN);
        hasher.update(&header);
        Ok(*hasher.finalize().as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        identities: [[u8; 32]; 4],
        canonical_rows: usize,
        canonical_columns: usize,
        banks: usize,
        layers_per_bank: usize,
        authentication_chunk_cells: usize,
    ) -> Result<Self, BlsDoryExecutionAccumulatorArtifactError> {
        let [
            network_identity,
            model_record_identity,
            setup_identity,
            challenge_identity,
        ] = identities;
        let context = Self {
            network_identity,
            model_record_identity,
            setup_identity,
            challenge_identity,
            format_version: BLS_DORY_EXECUTION_ACCUMULATOR_FORMAT_VERSION,
            column_order_version: BLS_DORY_EXECUTION_ACCUMULATOR_COLUMN_ORDER_VERSION,
            value_encoding_version: SIGNED_I32_LE_ENCODING_VERSION,
            canonical_rows,
            canonical_columns,
            banks,
            layers_per_bank,
            authentication_chunk_cells,
        };
        context.validate()?;
        Ok(context)
    }
}

/// Canonical execution-accumulator column identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlsDoryExecutionAccumulatorColumn {
    Initialization,
    BankLayer { bank: usize, layer: usize },
}

impl BlsDoryExecutionAccumulatorColumn {
    fn index(
        self,
        context: &BlsDoryExecutionAccumulatorArtifactContext,
    ) -> Result<usize, BlsDoryExecutionAccumulatorArtifactError> {
        match self {
            Self::Initialization => Ok(0),
            Self::BankLayer { bank, layer }
                if bank < context.banks && layer < context.layers_per_bank =>
            {
                bank.checked_mul(context.layers_per_bank)
                    .and_then(|index| index.checked_add(layer))
                    .and_then(|index| index.checked_add(1))
                    .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)
            }
            Self::BankLayer { .. } => Err(BlsDoryExecutionAccumulatorArtifactError::InvalidOrder),
        }
    }
}

/// Exact framed size of the production artifact without creating or allocating it.
pub fn projected_bls_dory_execution_accumulator_artifact_bytes()
-> Result<u64, BlsDoryExecutionAccumulatorArtifactError> {
    Ok(validate_geometry(
        BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_ROWS,
        BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS_PER_ROW,
        BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_BANKS,
        BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_LAYERS_PER_BANK,
        BLS_DORY_EXECUTION_ACCUMULATOR_AUTHENTICATION_CHUNK_CELLS,
    )?
    .total_bytes)
}

#[derive(Debug, Error)]
pub enum BlsDoryExecutionAccumulatorArtifactError {
    #[error("execution-accumulator artifact context is invalid")]
    InvalidContext,
    #[error("execution-accumulator artifact geometry or request is invalid")]
    InvalidShape,
    #[error("execution-accumulator columns were not supplied in canonical order")]
    InvalidOrder,
    #[error("execution accumulator is outside the production signed bound")]
    ValueOutOfRange,
    #[error("execution-accumulator artifact is incomplete")]
    Incomplete,
    #[error("execution-accumulator artifact context does not match")]
    WrongContext,
    #[error("execution-accumulator artifact has not authenticated")]
    NotAuthenticated,
    #[error("execution-accumulator artifact authentication failed")]
    Authentication,
    #[error("execution-accumulator artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy)]
struct ArtifactGeometry {
    columns: usize,
    chunks_per_column: usize,
    chunk_digest_count: usize,
    data_bytes: u64,
    chunk_digest_bytes: u64,
    total_bytes: u64,
}

pub struct BlsDoryExecutionAccumulatorArtifactWriter {
    path: Option<PathBuf>,
    file: Option<BufWriter<TrackedScratchFile>>,
    context: BlsDoryExecutionAccumulatorArtifactContext,
    context_digest: [u8; 32],
    geometry: ArtifactGeometry,
    next_column: usize,
    next_cell: usize,
    chunk_digests: Vec<[u8; 32]>,
    failed: bool,
}

impl BlsDoryExecutionAccumulatorArtifactWriter {
    pub fn create_new(
        directory: &Path,
        context: BlsDoryExecutionAccumulatorArtifactContext,
    ) -> Result<Self, BlsDoryExecutionAccumulatorArtifactError> {
        context.validate()?;
        if !directory.is_absolute() || !directory.is_dir() {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
        }
        let geometry = context.geometry()?;
        let header = context.encode_header()?;
        let context_digest = context.digest()?;
        let mut chunk_digests = Vec::new();
        chunk_digests
            .try_reserve_exact(geometry.chunk_digest_count)
            .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        let nonce = ARTIFACT_NONCE.fetch_add(1, Ordering::Relaxed);
        let context_prefix = hex::encode(&context_digest[..8]);
        let path = directory.join(format!(
            "cmfd-dory-execution-accumulators-{context_prefix}-{}-{nonce}.tmp",
            std::process::id()
        ));
        let file = TrackedScratchFile::create_new(&path)?;
        let mut writer = Self {
            path: Some(path),
            file: Some(BufWriter::with_capacity(IO_BUFFER_BYTES, file)),
            context,
            context_digest,
            geometry,
            next_column: 0,
            next_cell: 0,
            chunk_digests,
            failed: false,
        };
        writer.file_mut()?.write_all(&header)?;
        Ok(writer)
    }

    /// Append exactly one authentication chunk in canonical column order.
    pub fn write_column_chunk(
        &mut self,
        column: BlsDoryExecutionAccumulatorColumn,
        values: &[i32],
    ) -> Result<(), BlsDoryExecutionAccumulatorArtifactError> {
        if self.failed {
            return Err(BlsDoryExecutionAccumulatorArtifactError::Incomplete);
        }
        if self.next_column >= self.geometry.columns {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
        }
        if column.index(&self.context)? != self.next_column {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidOrder);
        }
        let expected_cells = self
            .context
            .cells_per_column()
            .checked_sub(self.next_cell)
            .map(|remaining| remaining.min(self.context.authentication_chunk_cells))
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        if values.len() != expected_cells || values.is_empty() {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
        }
        if values
            .iter()
            .any(|value| value.unsigned_abs() > BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS)
        {
            return Err(BlsDoryExecutionAccumulatorArtifactError::ValueOutOfRange);
        }
        let chunk_index = self.next_cell / self.context.authentication_chunk_cells;
        let mut hasher = chunk_hasher(
            self.context_digest,
            self.geometry,
            self.next_column,
            chunk_index,
            self.next_cell,
            values.len(),
        )?;
        let result = (|| {
            for value in values {
                let encoded = value.to_le_bytes();
                self.file_mut()?.write_all(&encoded)?;
                hasher.update(&encoded);
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
            return result;
        }
        self.chunk_digests.push(*hasher.finalize().as_bytes());
        self.next_cell = self
            .next_cell
            .checked_add(values.len())
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        if self.next_cell == self.context.cells_per_column() {
            self.next_column = self
                .next_column
                .checked_add(1)
                .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
            self.next_cell = 0;
        }
        Ok(())
    }

    pub fn finish(
        mut self,
    ) -> Result<BlsDoryExecutionAccumulatorArtifact, BlsDoryExecutionAccumulatorArtifactError> {
        if self.failed
            || self.next_column != self.geometry.columns
            || self.next_cell != 0
            || self.chunk_digests.len() != self.geometry.chunk_digest_count
        {
            return Err(BlsDoryExecutionAccumulatorArtifactError::Incomplete);
        }
        let root_digest =
            ordered_root_digest(self.context_digest, self.geometry, &self.chunk_digests)?;
        let header = self.context.encode_header()?;
        let final_digest = final_digest(&header, &self.chunk_digests, root_digest)?;
        let expected_len = self.geometry.total_bytes;
        let (file, chunk_digests) = (&mut self.file, &self.chunk_digests);
        let file = file
            .as_mut()
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::Incomplete)?;
        for digest in chunk_digests {
            file.write_all(digest)?;
        }
        file.write_all(&root_digest)?;
        file.write_all(&final_digest)?;
        file.flush()?;
        file.get_ref().sync_all()?;
        if file.get_ref().metadata()?.len() != expected_len {
            return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
        }

        let authentication_buffer = zeroed_bytes(
            self.context
                .authentication_chunk_cells
                .checked_mul(VALUE_BYTES as usize)
                .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?,
        )?;
        let mut segment_buffer = Vec::new();
        segment_buffer
            .try_reserve_exact(authentication_buffer.len())
            .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        let path = self
            .path
            .take()
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::Incomplete)?;
        let artifact_file = self
            .file
            .take()
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::Incomplete)?
            .into_inner()
            .map_err(|error| error.into_error())?;
        let context = self.context;
        let mut artifact = BlsDoryExecutionAccumulatorArtifact {
            path,
            file: artifact_file,
            context,
            context_digest: self.context_digest,
            geometry: self.geometry,
            chunk_digests: std::mem::take(&mut self.chunk_digests),
            root_digest,
            final_digest,
            authentication_buffer,
            segment_buffer,
            authenticated: false,
        };
        artifact.authenticate(&context)?;
        Ok(artifact)
    }

    fn file_mut(
        &mut self,
    ) -> Result<&mut BufWriter<TrackedScratchFile>, BlsDoryExecutionAccumulatorArtifactError> {
        self.file
            .as_mut()
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::Incomplete)
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        self.path.as_deref().unwrap()
    }
}

impl Drop for BlsDoryExecutionAccumulatorArtifactWriter {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let (mut file, buffered) = file.into_parts();
            drop(buffered);
            let _ = file.remove_if_owned();
        }
        self.path.take();
    }
}

pub struct BlsDoryExecutionAccumulatorArtifact {
    path: PathBuf,
    file: TrackedScratchFile,
    context: BlsDoryExecutionAccumulatorArtifactContext,
    context_digest: [u8; 32],
    geometry: ArtifactGeometry,
    chunk_digests: Vec<[u8; 32]>,
    root_digest: [u8; 32],
    final_digest: [u8; 32],
    authentication_buffer: Vec<u8>,
    segment_buffer: Vec<u8>,
    authenticated: bool,
}

impl BlsDoryExecutionAccumulatorArtifact {
    #[must_use]
    pub const fn context(&self) -> BlsDoryExecutionAccumulatorArtifactContext {
        self.context
    }

    #[must_use]
    pub const fn root_digest(&self) -> [u8; 32] {
        self.root_digest
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.final_digest
    }

    pub fn file_bytes(&self) -> Result<u64, BlsDoryExecutionAccumulatorArtifactError> {
        Ok(self.file.metadata()?.len())
    }

    /// Authenticate the complete artifact against the caller's exact context.
    /// A failed attempt clears prior authentication state.
    pub fn authenticate(
        &mut self,
        expected_context: &BlsDoryExecutionAccumulatorArtifactContext,
    ) -> Result<(), BlsDoryExecutionAccumulatorArtifactError> {
        self.authenticated = false;
        if expected_context != &self.context {
            return Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext);
        }
        let snapshot = authenticate_file(
            &mut self.file,
            &self.context,
            &mut self.authentication_buffer,
        )?;
        if snapshot.context_digest != self.context_digest
            || snapshot.chunk_digests != self.chunk_digests
            || snapshot.root_digest != self.root_digest
            || snapshot.final_digest != self.final_digest
        {
            return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
        }
        self.authenticated = true;
        Ok(())
    }

    /// Copy one bounded segment after re-authenticating every touched chunk.
    /// Requests may cross a chunk boundary but cannot exceed one chunk in size.
    pub fn read_column_segment(
        &mut self,
        column: BlsDoryExecutionAccumulatorColumn,
        start_cell: usize,
        output: &mut [i32],
    ) -> Result<usize, BlsDoryExecutionAccumulatorArtifactError> {
        let mut copied = 0usize;
        self.with_authenticated_segment(column, start_cell, output.len(), |encoded| {
            for value in encoded.chunks_exact(VALUE_BYTES as usize) {
                output[copied] = i32::from_le_bytes(
                    value
                        .try_into()
                        .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?,
                );
                copied += 1;
            }
            Ok(())
        })?;
        if copied != output.len() {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
        }
        Ok(copied)
    }

    /// Visit one bounded segment after re-authenticating every touched chunk.
    pub fn visit_column_segment(
        &mut self,
        column: BlsDoryExecutionAccumulatorColumn,
        start_cell: usize,
        cell_count: usize,
        mut visitor: impl FnMut(i32) -> Result<(), BlsDoryExecutionAccumulatorArtifactError>,
    ) -> Result<usize, BlsDoryExecutionAccumulatorArtifactError> {
        let mut visited = 0usize;
        self.with_authenticated_segment(column, start_cell, cell_count, |encoded| {
            for value in encoded.chunks_exact(VALUE_BYTES as usize) {
                visitor(i32::from_le_bytes(value.try_into().map_err(|_| {
                    BlsDoryExecutionAccumulatorArtifactError::InvalidShape
                })?))?;
                visited += 1;
            }
            Ok(())
        })?;
        if visited != cell_count {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
        }
        Ok(visited)
    }

    fn with_authenticated_segment(
        &mut self,
        column: BlsDoryExecutionAccumulatorColumn,
        start_cell: usize,
        cell_count: usize,
        mut consume: impl FnMut(&[u8]) -> Result<(), BlsDoryExecutionAccumulatorArtifactError>,
    ) -> Result<(), BlsDoryExecutionAccumulatorArtifactError> {
        if !self.authenticated {
            return Err(BlsDoryExecutionAccumulatorArtifactError::NotAuthenticated);
        }
        let column_index = column.index(&self.context)?;
        let end_cell = start_cell
            .checked_add(cell_count)
            .filter(|end| *end <= self.context.cells_per_column())
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        if cell_count == 0 || cell_count > self.context.authentication_chunk_cells {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
        }
        if let Err(error) = validate_live_envelope(
            &mut self.file,
            &self.context,
            self.root_digest,
            self.final_digest,
        ) {
            if is_live_authentication_failure(&error) {
                self.authenticated = false;
            }
            return Err(error);
        }
        self.segment_buffer.clear();
        let first_chunk = start_cell / self.context.authentication_chunk_cells;
        let last_chunk = (end_cell - 1) / self.context.authentication_chunk_cells;
        for chunk_index in first_chunk..=last_chunk {
            let chunk_start = chunk_index
                .checked_mul(self.context.authentication_chunk_cells)
                .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
            let chunk_cells = self
                .context
                .cells_per_column()
                .saturating_sub(chunk_start)
                .min(self.context.authentication_chunk_cells);
            let encoded = match read_authenticated_chunk(
                &mut self.file,
                &self.context,
                self.context_digest,
                self.geometry,
                &self.chunk_digests,
                &mut self.authentication_buffer,
                column_index,
                chunk_index,
                chunk_start,
                chunk_cells,
            ) {
                Ok(encoded) => encoded,
                Err(error) => {
                    if is_live_authentication_failure(&error) {
                        self.authenticated = false;
                    }
                    return Err(error);
                }
            };
            let copy_start = start_cell.max(chunk_start);
            let copy_end = end_cell.min(
                chunk_start
                    .checked_add(chunk_cells)
                    .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?,
            );
            let byte_start = copy_start
                .checked_sub(chunk_start)
                .and_then(|cells| cells.checked_mul(VALUE_BYTES as usize))
                .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
            let byte_end = copy_end
                .checked_sub(chunk_start)
                .and_then(|cells| cells.checked_mul(VALUE_BYTES as usize))
                .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
            self.segment_buffer
                .extend_from_slice(&encoded[byte_start..byte_end]);
        }
        let expected_bytes = cell_count
            .checked_mul(VALUE_BYTES as usize)
            .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
        if self.segment_buffer.len() != expected_bytes {
            return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
        }
        consume(&self.segment_buffer)
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BlsDoryExecutionAccumulatorArtifact {
    fn drop(&mut self) {
        debug_assert_eq!(self.file.path(), self.path);
        let _ = self.file.remove_if_owned();
    }
}

struct AuthenticationSnapshot {
    context_digest: [u8; 32],
    chunk_digests: Vec<[u8; 32]>,
    root_digest: [u8; 32],
    final_digest: [u8; 32],
}

fn validate_geometry(
    canonical_rows: usize,
    canonical_columns: usize,
    banks: usize,
    layers_per_bank: usize,
    authentication_chunk_cells: usize,
) -> Result<ArtifactGeometry, BlsDoryExecutionAccumulatorArtifactError> {
    if canonical_rows == 0
        || !canonical_rows.is_power_of_two()
        || canonical_rows > BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_ROWS
        || canonical_columns == 0
        || !canonical_columns.is_power_of_two()
        || canonical_columns > BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS_PER_ROW
        || banks == 0
        || banks > BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_BANKS
        || layers_per_bank == 0
        || layers_per_bank > BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_LAYERS_PER_BANK
        || authentication_chunk_cells == 0
        || !authentication_chunk_cells.is_power_of_two()
    {
        return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
    }
    let cells_per_column = canonical_rows
        .checked_mul(canonical_columns)
        .filter(|cells| {
            *cells <= BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_CELLS
                && authentication_chunk_cells <= *cells
                && cells.is_multiple_of(authentication_chunk_cells)
        })
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    let columns = banks
        .checked_mul(layers_per_bank)
        .and_then(|columns| columns.checked_add(1))
        .filter(|columns| *columns <= BLS_DORY_EXECUTION_ACCUMULATOR_PRODUCTION_COLUMNS)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    let chunks_per_column = cells_per_column / authentication_chunk_cells;
    let chunk_digest_count = columns
        .checked_mul(chunks_per_column)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    let value_count = columns
        .checked_mul(cells_per_column)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    let data_bytes = usize_to_u64(value_count)?
        .checked_mul(VALUE_BYTES)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    let chunk_digest_bytes = usize_to_u64(chunk_digest_count)?
        .checked_mul(DIGEST_BYTES)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    let total_bytes = HEADER_BYTES
        .checked_add(data_bytes)
        .and_then(|bytes| bytes.checked_add(chunk_digest_bytes))
        .and_then(|bytes| bytes.checked_add(FOOTER_DIGESTS * DIGEST_BYTES))
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    Ok(ArtifactGeometry {
        columns,
        chunks_per_column,
        chunk_digest_count,
        data_bytes,
        chunk_digest_bytes,
        total_bytes,
    })
}

fn authenticate_file(
    file: &mut TrackedScratchFile,
    context: &BlsDoryExecutionAccumulatorArtifactContext,
    buffer: &mut [u8],
) -> Result<AuthenticationSnapshot, BlsDoryExecutionAccumulatorArtifactError> {
    context.validate()?;
    let geometry = context.geometry()?;
    validate_header_and_length(file, context, geometry)?;
    let required_buffer = context
        .authentication_chunk_cells
        .checked_mul(VALUE_BYTES as usize)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    if buffer.len() < required_buffer {
        return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
    }
    let context_digest = context.digest()?;
    let mut chunk_digests = Vec::new();
    chunk_digests
        .try_reserve_exact(geometry.chunk_digest_count)
        .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    let mut reader = BufReader::with_capacity(IO_BUFFER_BYTES, file.try_clone_reader()?);
    reader.seek(SeekFrom::Start(HEADER_BYTES))?;
    for column in 0..geometry.columns {
        for chunk in 0..geometry.chunks_per_column {
            let start_cell = chunk
                .checked_mul(context.authentication_chunk_cells)
                .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
            let chunk_cells = context
                .cells_per_column()
                .saturating_sub(start_cell)
                .min(context.authentication_chunk_cells);
            let chunk_bytes = chunk_cells
                .checked_mul(VALUE_BYTES as usize)
                .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
            reader.read_exact(&mut buffer[..chunk_bytes])?;
            chunk_digests.push(chunk_digest_encoded(
                context_digest,
                geometry,
                column,
                chunk,
                start_cell,
                chunk_cells,
                &buffer[..chunk_bytes],
            )?);
        }
    }
    if chunk_digests.len() != geometry.chunk_digest_count {
        return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
    }
    for expected in &chunk_digests {
        let mut stored = [0u8; DIGEST_BYTES as usize];
        reader.read_exact(&mut stored)?;
        if &stored != expected {
            return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
        }
    }
    let mut stored_root = [0u8; DIGEST_BYTES as usize];
    let mut stored_final = [0u8; DIGEST_BYTES as usize];
    reader.read_exact(&mut stored_root)?;
    reader.read_exact(&mut stored_final)?;
    let root_digest = ordered_root_digest(context_digest, geometry, &chunk_digests)?;
    let header = context.encode_header()?;
    let final_digest = final_digest(&header, &chunk_digests, root_digest)?;
    if stored_root != root_digest || stored_final != final_digest {
        return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
    }
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
    }
    Ok(AuthenticationSnapshot {
        context_digest,
        chunk_digests,
        root_digest,
        final_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn read_authenticated_chunk<'a>(
    file: &mut TrackedScratchFile,
    context: &BlsDoryExecutionAccumulatorArtifactContext,
    context_digest: [u8; 32],
    geometry: ArtifactGeometry,
    expected_digests: &[[u8; 32]],
    buffer: &'a mut [u8],
    column: usize,
    chunk: usize,
    start_cell: usize,
    chunk_cells: usize,
) -> Result<&'a [u8], BlsDoryExecutionAccumulatorArtifactError> {
    let chunk_bytes = chunk_cells
        .checked_mul(VALUE_BYTES as usize)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    if chunk_bytes == 0 || chunk_bytes > buffer.len() {
        return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
    }
    let value_index = column
        .checked_mul(context.cells_per_column())
        .and_then(|index| index.checked_add(start_cell))
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    file.seek(SeekFrom::Start(data_offset(value_index)?))?;
    file.read_exact(&mut buffer[..chunk_bytes])?;
    let computed = chunk_digest_encoded(
        context_digest,
        geometry,
        column,
        chunk,
        start_cell,
        chunk_cells,
        &buffer[..chunk_bytes],
    )?;
    let digest_index = column
        .checked_mul(geometry.chunks_per_column)
        .and_then(|index| index.checked_add(chunk))
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    let expected = expected_digests
        .get(digest_index)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::Authentication)?;
    let mut stored = [0u8; DIGEST_BYTES as usize];
    file.seek(SeekFrom::Start(chunk_digest_offset(
        geometry,
        digest_index,
    )?))?;
    file.read_exact(&mut stored)?;
    if computed != *expected || stored != *expected {
        return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
    }
    Ok(&buffer[..chunk_bytes])
}

fn validate_header_and_length(
    file: &mut TrackedScratchFile,
    context: &BlsDoryExecutionAccumulatorArtifactContext,
    geometry: ArtifactGeometry,
) -> Result<(), BlsDoryExecutionAccumulatorArtifactError> {
    if file.metadata()?.len() != geometry.total_bytes {
        return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
    }
    let mut header = [0u8; HEADER_BYTES as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    if header != context.encode_header()? {
        return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
    }
    Ok(())
}

fn validate_live_envelope(
    file: &mut TrackedScratchFile,
    context: &BlsDoryExecutionAccumulatorArtifactContext,
    expected_root: [u8; 32],
    expected_final: [u8; 32],
) -> Result<(), BlsDoryExecutionAccumulatorArtifactError> {
    let geometry = context.geometry()?;
    validate_header_and_length(file, context, geometry)?;
    let mut root = [0u8; DIGEST_BYTES as usize];
    let mut final_digest = [0u8; DIGEST_BYTES as usize];
    file.seek(SeekFrom::Start(root_offset(geometry)?))?;
    file.read_exact(&mut root)?;
    file.read_exact(&mut final_digest)?;
    if root != expected_root || final_digest != expected_final {
        return Err(BlsDoryExecutionAccumulatorArtifactError::Authentication);
    }
    Ok(())
}

fn chunk_hasher(
    context_digest: [u8; 32],
    geometry: ArtifactGeometry,
    column: usize,
    chunk: usize,
    start_cell: usize,
    chunk_cells: usize,
) -> Result<blake3::Hasher, BlsDoryExecutionAccumulatorArtifactError> {
    let mut hasher = blake3::Hasher::new_derive_key(CHUNK_HASH_DOMAIN);
    hasher.update(&context_digest);
    for value in [
        usize_to_u64(geometry.columns)?,
        usize_to_u64(geometry.chunks_per_column)?,
        usize_to_u64(column)?,
        usize_to_u64(chunk)?,
        usize_to_u64(start_cell)?,
        usize_to_u64(chunk_cells)?,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    Ok(hasher)
}

#[allow(clippy::too_many_arguments)]
fn chunk_digest_encoded(
    context_digest: [u8; 32],
    geometry: ArtifactGeometry,
    column: usize,
    chunk: usize,
    start_cell: usize,
    chunk_cells: usize,
    encoded: &[u8],
) -> Result<[u8; 32], BlsDoryExecutionAccumulatorArtifactError> {
    let expected_bytes = chunk_cells
        .checked_mul(VALUE_BYTES as usize)
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    if encoded.len() != expected_bytes {
        return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
    }
    let mut hasher = chunk_hasher(
        context_digest,
        geometry,
        column,
        chunk,
        start_cell,
        chunk_cells,
    )?;
    hasher.update(encoded);
    Ok(*hasher.finalize().as_bytes())
}

fn ordered_root_digest(
    context_digest: [u8; 32],
    geometry: ArtifactGeometry,
    chunk_digests: &[[u8; 32]],
) -> Result<[u8; 32], BlsDoryExecutionAccumulatorArtifactError> {
    if chunk_digests.len() != geometry.chunk_digest_count {
        return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
    }
    let mut hasher = blake3::Hasher::new_derive_key(ORDERED_ROOT_HASH_DOMAIN);
    hasher.update(&context_digest);
    hasher.update(&usize_to_u64(chunk_digests.len())?.to_le_bytes());
    for (index, digest) in chunk_digests.iter().enumerate() {
        hasher.update(&usize_to_u64(index)?.to_le_bytes());
        hasher.update(digest);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn final_digest(
    header: &[u8; HEADER_BYTES as usize],
    chunk_digests: &[[u8; 32]],
    root_digest: [u8; 32],
) -> Result<[u8; 32], BlsDoryExecutionAccumulatorArtifactError> {
    let mut hasher = blake3::Hasher::new_derive_key(FINAL_HASH_DOMAIN);
    hasher.update(header);
    hasher.update(&usize_to_u64(chunk_digests.len())?.to_le_bytes());
    for digest in chunk_digests {
        hasher.update(digest);
    }
    hasher.update(&root_digest);
    Ok(*hasher.finalize().as_bytes())
}

fn data_offset(value_index: usize) -> Result<u64, BlsDoryExecutionAccumulatorArtifactError> {
    HEADER_BYTES
        .checked_add(
            usize_to_u64(value_index)?
                .checked_mul(VALUE_BYTES)
                .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?,
        )
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)
}

fn chunk_digest_offset(
    geometry: ArtifactGeometry,
    digest_index: usize,
) -> Result<u64, BlsDoryExecutionAccumulatorArtifactError> {
    if digest_index >= geometry.chunk_digest_count {
        return Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape);
    }
    HEADER_BYTES
        .checked_add(geometry.data_bytes)
        .and_then(|offset| {
            usize_to_u64(digest_index)
                .ok()
                .and_then(|index| index.checked_mul(DIGEST_BYTES))
                .and_then(|bytes| offset.checked_add(bytes))
        })
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)
}

fn root_offset(
    geometry: ArtifactGeometry,
) -> Result<u64, BlsDoryExecutionAccumulatorArtifactError> {
    HEADER_BYTES
        .checked_add(geometry.data_bytes)
        .and_then(|offset| offset.checked_add(geometry.chunk_digest_bytes))
        .ok_or(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)
}

fn usize_to_u64(value: usize) -> Result<u64, BlsDoryExecutionAccumulatorArtifactError> {
    u64::try_from(value).map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)
}

fn usize_to_u32(value: usize) -> Result<u32, BlsDoryExecutionAccumulatorArtifactError> {
    u32::try_from(value).map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)
}

fn usize_to_u16(value: usize) -> Result<u16, BlsDoryExecutionAccumulatorArtifactError> {
    u16::try_from(value).map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)
}

fn zeroed_bytes(len: usize) -> Result<Vec<u8>, BlsDoryExecutionAccumulatorArtifactError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| BlsDoryExecutionAccumulatorArtifactError::InvalidShape)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

fn is_live_authentication_failure(error: &BlsDoryExecutionAccumulatorArtifactError) -> bool {
    matches!(
        error,
        BlsDoryExecutionAccumulatorArtifactError::Authentication
            | BlsDoryExecutionAccumulatorArtifactError::Io(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-execution-accumulator-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_context(challenge: u8) -> BlsDoryExecutionAccumulatorArtifactContext {
        BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x11; 32], [0x22; 32], [0x33; 32], [challenge; 32]],
            2,
            4,
            2,
            2,
            4,
        )
        .unwrap()
    }

    fn column(
        context: &BlsDoryExecutionAccumulatorArtifactContext,
        index: usize,
    ) -> BlsDoryExecutionAccumulatorColumn {
        if index == 0 {
            BlsDoryExecutionAccumulatorColumn::Initialization
        } else {
            let relative = index - 1;
            BlsDoryExecutionAccumulatorColumn::BankLayer {
                bank: relative / context.layers_per_bank,
                layer: relative % context.layers_per_bank,
            }
        }
    }

    fn value(column: usize, cell: usize) -> i32 {
        let magnitude = i32::try_from(column * 100 + cell + 1).unwrap();
        if (column + cell).is_multiple_of(2) {
            magnitude
        } else {
            -magnitude
        }
    }

    fn write_fixture(
        directory: &Path,
        context: BlsDoryExecutionAccumulatorArtifactContext,
    ) -> BlsDoryExecutionAccumulatorArtifact {
        let mut writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(directory, context).unwrap();
        for column_index in 0..context.columns() {
            for chunk in 0..(context.cells_per_column() / context.authentication_chunk_cells) {
                let start = chunk * context.authentication_chunk_cells;
                let values = (start..start + context.authentication_chunk_cells)
                    .map(|cell| value(column_index, cell))
                    .collect::<Vec<_>>();
                writer
                    .write_column_chunk(column(&context, column_index), &values)
                    .unwrap();
            }
        }
        writer.finish().unwrap()
    }

    #[test]
    fn production_projection_is_exact_and_nonallocating() {
        assert!(matches!(
            BlsDoryExecutionAccumulatorArtifactContext::production(
                [0; 32], [2; 32], [3; 32], [4; 32]
            ),
            Err(BlsDoryExecutionAccumulatorArtifactError::InvalidContext)
        ));
        let context = BlsDoryExecutionAccumulatorArtifactContext::production(
            [1; 32], [2; 32], [3; 32], [4; 32],
        )
        .unwrap();
        assert_eq!(context.canonical_rows(), 128);
        assert_eq!(context.canonical_columns(), 4096);
        assert_eq!(context.cells_per_column(), 1 << 19);
        assert_eq!(context.columns(), 385);
        assert_eq!(context.banks(), 3);
        assert_eq!(context.layers_per_bank(), 128);
        assert_eq!(context.authentication_chunk_cells(), 1 << 17);
        assert_eq!(context.geometry().unwrap().chunks_per_column, 4);
        assert_eq!(context.geometry().unwrap().chunk_digest_count, 1_540);
        assert_eq!(context.projected_file_bytes().unwrap(), 807_453_072);
        assert_eq!(
            projected_bls_dory_execution_accumulator_artifact_bytes().unwrap(),
            807_453_072
        );
        let header = context.encode_header().unwrap();
        assert_eq!(header.len(), 208);
        assert_eq!(u16::from_le_bytes(header[10..12].try_into().unwrap()), 208);
        assert_eq!(u64::from_le_bytes(header[16..24].try_into().unwrap()), 128);
        assert_eq!(u64::from_le_bytes(header[24..32].try_into().unwrap()), 4096);
        assert_eq!(
            u64::from_le_bytes(header[32..40].try_into().unwrap()),
            1 << 19
        );
        assert_eq!(u32::from_le_bytes(header[40..44].try_into().unwrap()), 385);
        assert_eq!(u16::from_le_bytes(header[44..46].try_into().unwrap()), 3);
        assert_eq!(u16::from_le_bytes(header[46..48].try_into().unwrap()), 128);
        assert_eq!(
            u64::from_le_bytes(header[48..56].try_into().unwrap()),
            1 << 17
        );
        assert_eq!(u64::from_le_bytes(header[56..64].try_into().unwrap()), 4);
        assert_eq!(
            u64::from_le_bytes(header[64..72].try_into().unwrap()),
            807_403_520
        );
        assert_eq!(
            u64::from_le_bytes(header[72..80].try_into().unwrap()),
            1_540
        );
        assert_eq!(&header[80..112], &[1; 32]);
        assert_eq!(&header[112..144], &[2; 32]);
        assert_eq!(&header[144..176], &[3; 32]);
        assert_eq!(&header[176..208], &[4; 32]);
        let shape =
            crate::structured_proof::StructuredForgeMatrixResearchShape::production_candidate();
        assert!(shape.matrix_statements.iter().all(|statement| {
            statement.max_abs_accumulator == u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS)
        }));
        assert!(shape.transition_statements.iter().all(|statement| {
            statement.max_abs_accumulator == u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS)
        }));
        assert!(
            shape.initialization_statement.max_abs_accumulator
                <= u64::from(BLS_DORY_EXECUTION_ACCUMULATOR_MAX_ABS)
        );
    }

    #[test]
    fn canonical_rows_and_columns_are_bound_independently() {
        let identities = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
        let canonical =
            BlsDoryExecutionAccumulatorArtifactContext::for_test(identities, 2, 4, 1, 2, 2)
                .unwrap();
        let transposed =
            BlsDoryExecutionAccumulatorArtifactContext::for_test(identities, 4, 2, 1, 2, 2)
                .unwrap();
        assert_eq!(canonical.cells_per_column(), transposed.cells_per_column());
        assert_ne!(
            canonical.encode_header().unwrap(),
            transposed.encode_header().unwrap()
        );
        assert_ne!(canonical.digest().unwrap(), transposed.digest().unwrap());

        let directory = TestDirectory::create();
        let mut artifact = write_fixture(&directory.0, canonical);
        assert!(matches!(
            artifact.authenticate(&transposed),
            Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext)
        ));
    }

    #[test]
    fn signed_columns_round_trip_in_canonical_order_and_are_deterministic() {
        let directory = TestDirectory::create();
        let context = test_context(0x44);
        let mut first = write_fixture(&directory.0, context);
        let first_bytes = std::fs::read(first.path()).unwrap();
        let first_root = first.root_digest();
        let first_digest = first.digest();

        for column_index in 0..context.columns() {
            let mut actual = Vec::new();
            for start in [0, 4] {
                let mut segment = [0; 4];
                assert_eq!(
                    first
                        .read_column_segment(column(&context, column_index), start, &mut segment,)
                        .unwrap(),
                    4
                );
                actual.extend_from_slice(&segment);
            }
            assert_eq!(
                actual,
                (0..8)
                    .map(|cell| value(column_index, cell))
                    .collect::<Vec<_>>()
            );
        }

        let mut crossing = Vec::new();
        assert_eq!(
            first
                .visit_column_segment(
                    BlsDoryExecutionAccumulatorColumn::BankLayer { bank: 1, layer: 0 },
                    2,
                    4,
                    |value| {
                        crossing.push(value);
                        Ok(())
                    },
                )
                .unwrap(),
            4
        );
        assert_eq!(
            crossing,
            (2..6).map(|cell| value(3, cell)).collect::<Vec<_>>()
        );

        let second = write_fixture(&directory.0, context);
        assert_eq!(std::fs::read(second.path()).unwrap(), first_bytes);
        assert_eq!(second.root_digest(), first_root);
        assert_eq!(second.digest(), first_digest);
        assert_eq!(
            first.file_bytes().unwrap(),
            context.projected_file_bytes().unwrap()
        );
    }

    #[test]
    fn writer_rejects_wrong_order_and_incomplete_output_and_cleans_up() {
        let directory = TestDirectory::create();
        let context = test_context(0x55);
        let mut writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(&directory.0, context).unwrap();
        assert!(writer.path().exists());
        assert!(matches!(
            writer.write_column_chunk(
                BlsDoryExecutionAccumulatorColumn::BankLayer { bank: 0, layer: 0 },
                &[1, 2, 3, 4]
            ),
            Err(BlsDoryExecutionAccumulatorArtifactError::InvalidOrder)
        ));
        assert!(matches!(
            writer.write_column_chunk(
                BlsDoryExecutionAccumulatorColumn::Initialization,
                &[1, 2, 3]
            ),
            Err(BlsDoryExecutionAccumulatorArtifactError::InvalidShape)
        ));
        assert!(matches!(
            writer.write_column_chunk(
                BlsDoryExecutionAccumulatorColumn::Initialization,
                &[64_000_001, 2, 3, 4]
            ),
            Err(BlsDoryExecutionAccumulatorArtifactError::ValueOutOfRange)
        ));
        writer
            .write_column_chunk(
                BlsDoryExecutionAccumulatorColumn::Initialization,
                &[1, 2, 3, 4],
            )
            .unwrap();
        assert!(matches!(
            writer.write_column_chunk(
                BlsDoryExecutionAccumulatorColumn::BankLayer { bank: 0, layer: 0 },
                &[5, 6, 7, 8]
            ),
            Err(BlsDoryExecutionAccumulatorArtifactError::InvalidOrder)
        ));
        assert!(matches!(
            writer.finish(),
            Err(BlsDoryExecutionAccumulatorArtifactError::Incomplete)
        ));
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);

        let writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(&directory.0, context).unwrap();
        drop(writer);
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn corrupted_chunk_is_rejected_before_copy_or_visit() {
        let directory = TestDirectory::create();
        let context = test_context(0x66);
        let mut artifact = write_fixture(&directory.0, context);
        let changed_column = 2;
        let changed_cell = 5;
        let offset =
            data_offset(changed_column * context.cells_per_column() + changed_cell).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(artifact.path())
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[byte[0] ^ 0x80]).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        let mut output = [i32::MAX; 4];
        assert!(matches!(
            artifact.read_column_segment(column(&context, changed_column), 2, &mut output),
            Err(BlsDoryExecutionAccumulatorArtifactError::Authentication)
        ));
        assert_eq!(output, [i32::MAX; 4]);
        assert!(matches!(
            artifact.read_column_segment(column(&context, changed_column), 2, &mut output),
            Err(BlsDoryExecutionAccumulatorArtifactError::NotAuthenticated)
        ));

        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();
        artifact.authenticate(&context).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[byte[0] ^ 0x80]).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();
        let mut visited = 0;
        assert!(matches!(
            artifact.visit_column_segment(column(&context, changed_column), 2, 4, |_| {
                visited += 1;
                Ok(())
            }),
            Err(BlsDoryExecutionAccumulatorArtifactError::Authentication)
        ));
        assert_eq!(visited, 0);
        assert!(matches!(
            artifact.visit_column_segment(column(&context, changed_column), 2, 4, |_| {
                visited += 1;
                Ok(())
            }),
            Err(BlsDoryExecutionAccumulatorArtifactError::NotAuthenticated)
        ));
        assert_eq!(visited, 0);
    }

    #[test]
    fn truncation_and_wrong_context_fail_closed() {
        let directory = TestDirectory::create();
        let context = test_context(0x77);
        let wrong_context = test_context(0x78);
        let mut artifact = write_fixture(&directory.0, context);
        assert!(matches!(
            artifact.authenticate(&wrong_context),
            Err(BlsDoryExecutionAccumulatorArtifactError::WrongContext)
        ));
        assert!(matches!(
            artifact.read_column_segment(
                BlsDoryExecutionAccumulatorColumn::Initialization,
                0,
                &mut [0; 1]
            ),
            Err(BlsDoryExecutionAccumulatorArtifactError::NotAuthenticated)
        ));
        artifact.authenticate(&context).unwrap();
        let file = OpenOptions::new()
            .write(true)
            .open(artifact.path())
            .unwrap();
        file.set_len(artifact.file_bytes().unwrap() - 1).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            artifact.authenticate(&context),
            Err(BlsDoryExecutionAccumulatorArtifactError::Authentication)
        ));
    }

    #[test]
    fn cleanup_deletes_the_owned_file_and_preserves_siblings() {
        let directory = TestDirectory::create();
        let owned_path = directory.0.join("owned.tmp");
        let unrelated_path = directory.0.join("unrelated.tmp");
        let mut owned = TrackedScratchFile::create_new(&owned_path).unwrap();
        std::fs::write(&unrelated_path, b"preserve me").unwrap();

        owned.remove_if_owned().unwrap();
        assert_eq!(std::fs::read(&unrelated_path).unwrap(), b"preserve me");
        assert!(!owned_path.exists());
    }
}
