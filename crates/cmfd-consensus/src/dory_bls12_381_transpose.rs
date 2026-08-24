//! Bounded row-to-column transposition for fixed-width Dory word sources.
//!
//! BLAKE3 produces trace rows, while a selector-packed Dory source consumes
//! complete tables. This artifact writes row chunks into a canonical
//! column-major file without retaining the full matrix in memory. The final
//! digest authenticates the exact shape and every word before any column is
//! exposed to the commitment path.

use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use same_file::Handle;
use thiserror::Error;

use crate::dory_scratch_telemetry::{
    register_scratch_artifact_reservation, release_scratch_artifact_reservation,
};

const MAGIC: [u8; 8] = *b"CFDBLST1";
const VERSION: u16 = 1;
const HEADER_BYTES: u64 = 72;
const DIGEST_OFFSET: u64 = 40;
const WORD_BYTES: u64 = 8;
const HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryWordTranspose/v1";
const BLOCK_HASH_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/BlsDoryWordTransposeAuthenticatedBlock/v1";
const IO_BUFFER_BYTES: usize = 1024 * 1024;
const AUTHENTICATION_BLOCK_ROWS: usize = 1 << 17;
/// Preferred authentication-block row cap used by bounded transpose streams.
pub(crate) const BLS_DORY_TRANSPOSE_AUTHENTICATION_BLOCK_ROWS: usize = AUTHENTICATION_BLOCK_ROWS;
pub const BLS_DORY_TRANSPOSE_MAX_ROWS: usize = 1 << 20;
pub const BLS_DORY_TRANSPOSE_MAX_COLUMNS: usize = 1 << 9;
pub const BLS_DORY_TRANSPOSE_MAX_DATA_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const BLS_DORY_TRANSPOSE_MAX_CHUNK_BUFFER_BYTES: usize = 512 * 1024 * 1024;
static ARTIFACT_NONCE: AtomicU64 = AtomicU64::new(1);

/// Exact framed size of a valid transpose artifact without creating it.
pub fn projected_bls_dory_transpose_artifact_bytes(
    rows: usize,
    columns: usize,
) -> Result<u64, BlsDoryTransposeError> {
    Ok(validate_geometry(rows, columns, 1)?.total_bytes)
}

struct TransposeGeometry {
    data_bytes: u64,
    total_bytes: u64,
    row_buffer_words: usize,
}

struct AuthenticationSnapshot {
    digest: [u8; 32],
    block_digests: Vec<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum BlsDoryTransposeError {
    #[error("transpose geometry or row shape is invalid")]
    InvalidShape,
    #[error("transpose row stream is incomplete")]
    Incomplete,
    #[error("transpose artifact authentication failed")]
    Authentication,
    #[error("transpose artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub struct BlsDoryWordTransposeWriter {
    path: Option<PathBuf>,
    file: File,
    rows: usize,
    columns: usize,
    chunk_rows: usize,
    written_rows: usize,
    buffered_rows: usize,
    row_buffer: Vec<u64>,
}

impl BlsDoryWordTransposeWriter {
    pub fn create(
        directory: &Path,
        rows: usize,
        columns: usize,
        chunk_rows: usize,
    ) -> Result<Self, BlsDoryTransposeError> {
        if !directory.is_absolute() || !directory.is_dir() {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        let geometry = validate_geometry(rows, columns, chunk_rows)?;
        let mut row_buffer = Vec::new();
        row_buffer
            .try_reserve_exact(geometry.row_buffer_words)
            .map_err(|_| BlsDoryTransposeError::InvalidShape)?;
        let nonce = ARTIFACT_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            "cmfd-dory-word-transpose-{}-{nonce}.bin",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        if let Err(error) = register_scratch_artifact_reservation(&path, geometry.total_bytes) {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(error.into());
        }
        let mut writer = Self {
            path: Some(path),
            file,
            rows,
            columns,
            chunk_rows,
            written_rows: 0,
            buffered_rows: 0,
            row_buffer,
        };
        writer.file.set_len(geometry.total_bytes)?;
        let header = encode_header(rows, columns, geometry.data_bytes, [0; 32])?;
        writer.file.seek(SeekFrom::Start(0))?;
        writer.file.write_all(&header)?;
        Ok(writer)
    }

    pub fn write_row(&mut self, row: &[u64]) -> Result<(), BlsDoryTransposeError> {
        if row.len() != self.columns
            || self
                .written_rows
                .checked_add(self.buffered_rows)
                .is_none_or(|written| written >= self.rows)
        {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        self.row_buffer.extend_from_slice(row);
        self.buffered_rows += 1;
        if self.buffered_rows == self.chunk_rows {
            self.flush_chunk()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<BlsDoryWordTransposeArtifact, BlsDoryTransposeError> {
        self.flush_chunk()?;
        if self.written_rows != self.rows {
            return Err(BlsDoryTransposeError::Incomplete);
        }
        self.file.flush()?;
        let snapshot = authenticate_file(&mut self.file, self.rows, self.columns)?;
        self.file.seek(SeekFrom::Start(DIGEST_OFFSET))?;
        self.file.write_all(&snapshot.digest)?;
        self.file.flush()?;
        let authentication_buffer_len = self
            .rows
            .min(AUTHENTICATION_BLOCK_ROWS)
            .checked_mul(WORD_BYTES as usize)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        let authentication_buffer = zeroed_bytes(authentication_buffer_len)?;
        let file = self.file.try_clone()?;
        let path = self
            .path
            .take()
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        Ok(BlsDoryWordTransposeArtifact {
            path,
            file,
            rows: self.rows,
            columns: self.columns,
            digest: snapshot.digest,
            block_digests: snapshot.block_digests,
            authentication_buffer,
        })
    }

    fn flush_chunk(&mut self) -> Result<(), BlsDoryTransposeError> {
        if self.buffered_rows == 0 {
            return Ok(());
        }
        let encoded_capacity = self
            .buffered_rows
            .checked_mul(WORD_BYTES as usize)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encoded_capacity)
            .map_err(|_| BlsDoryTransposeError::InvalidShape)?;
        for column in 0..self.columns {
            encoded.clear();
            for row in 0..self.buffered_rows {
                let index = row
                    .checked_mul(self.columns)
                    .and_then(|start| start.checked_add(column))
                    .ok_or(BlsDoryTransposeError::InvalidShape)?;
                encoded.extend_from_slice(&self.row_buffer[index].to_le_bytes());
            }
            let word_index = column
                .checked_mul(self.rows)
                .and_then(|start| start.checked_add(self.written_rows))
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            let offset = HEADER_BYTES
                .checked_add(
                    u64::try_from(word_index)
                        .map_err(|_| BlsDoryTransposeError::InvalidShape)?
                        .checked_mul(WORD_BYTES)
                        .ok_or(BlsDoryTransposeError::InvalidShape)?,
                )
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(&encoded)?;
        }
        self.written_rows = self
            .written_rows
            .checked_add(self.buffered_rows)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        self.buffered_rows = 0;
        self.row_buffer.clear();
        Ok(())
    }
}

impl Drop for BlsDoryWordTransposeWriter {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            remove_if_owned(path, &self.file);
        }
    }
}

pub struct BlsDoryWordTransposeArtifact {
    path: PathBuf,
    file: File,
    rows: usize,
    columns: usize,
    digest: [u8; 32],
    block_digests: Vec<[u8; 32]>,
    authentication_buffer: Vec<u8>,
}

impl BlsDoryWordTransposeArtifact {
    #[cfg(feature = "whir-prototype")]
    #[must_use]
    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[cfg(feature = "whir-prototype")]
    pub(crate) fn file_bytes(&self) -> Result<u64, BlsDoryTransposeError> {
        Ok(self.file.metadata()?.len())
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn columns(&self) -> usize {
        self.columns
    }

    /// Preferred row batch for callers that consume authenticated column
    /// segments. One batch reuses the artifact's existing authentication
    /// buffer without retaining a complete column or matrix in memory.
    #[cfg(feature = "whir-prototype")]
    pub(crate) const fn preferred_authenticated_segment_rows(&self) -> usize {
        if self.rows < AUTHENTICATION_BLOCK_ROWS {
            self.rows
        } else {
            AUTHENTICATION_BLOCK_ROWS
        }
    }

    pub fn read_column(
        &mut self,
        column: usize,
        output: &mut [u64],
    ) -> Result<usize, BlsDoryTransposeError> {
        if column >= self.columns || output.len() != self.rows {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        self.read_column_segment(column, 0, output)
    }

    /// Read one bounded contiguous segment from an authenticated column.
    ///
    /// Production Dory layouts split each million-row logical trace table into
    /// smaller physical rows. Segment reads avoid allocating the complete
    /// logical column merely to expose one physical row.
    pub fn read_column_segment(
        &mut self,
        column: usize,
        start_row: usize,
        output: &mut [u64],
    ) -> Result<usize, BlsDoryTransposeError> {
        let end_row = start_row
            .checked_add(output.len())
            .filter(|end| *end <= self.rows)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        if column >= self.columns || output.is_empty() {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        validate_authenticated_header(&mut self.file, self.rows, self.columns, self.digest)?;
        let blocks_per_column = authentication_blocks_per_column(self.rows);
        let first_block = start_row / AUTHENTICATION_BLOCK_ROWS;
        let last_block = (end_row - 1) / AUTHENTICATION_BLOCK_ROWS;
        let mut copied = 0usize;
        for block in first_block..=last_block {
            let block_start = block
                .checked_mul(AUTHENTICATION_BLOCK_ROWS)
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            let block_rows = self
                .rows
                .saturating_sub(block_start)
                .min(AUTHENTICATION_BLOCK_ROWS);
            let block_bytes = block_rows
                .checked_mul(WORD_BYTES as usize)
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            if block_rows == 0 || block_bytes > self.authentication_buffer.len() {
                return Err(BlsDoryTransposeError::InvalidShape);
            }
            let word_index = column
                .checked_mul(self.rows)
                .and_then(|index| index.checked_add(block_start))
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            let offset = data_offset(word_index)?;
            self.file.seek(SeekFrom::Start(offset))?;
            self.file
                .read_exact(&mut self.authentication_buffer[..block_bytes])?;
            let digest = authentication_block_digest(
                self.rows,
                self.columns,
                column,
                block,
                block_start,
                block_rows,
                &self.authentication_buffer[..block_bytes],
            )?;
            let digest_index = column
                .checked_mul(blocks_per_column)
                .and_then(|index| index.checked_add(block))
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            if self.block_digests.get(digest_index) != Some(&digest) {
                return Err(BlsDoryTransposeError::Authentication);
            }

            let copy_start = start_row.max(block_start);
            let block_end = block_start
                .checked_add(block_rows)
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            let copy_end = end_row.min(block_end);
            let source_start = copy_start
                .checked_sub(block_start)
                .and_then(|words| words.checked_mul(WORD_BYTES as usize))
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            let copy_words = copy_end
                .checked_sub(copy_start)
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            let source_end = source_start
                .checked_add(
                    copy_words
                        .checked_mul(WORD_BYTES as usize)
                        .ok_or(BlsDoryTransposeError::InvalidShape)?,
                )
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            let destination_end = copied
                .checked_add(copy_words)
                .filter(|end| *end <= output.len())
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            for (word, encoded) in output[copied..destination_end]
                .iter_mut()
                .zip(self.authentication_buffer[source_start..source_end].chunks_exact(8))
            {
                *word = u64::from_le_bytes(
                    encoded
                        .try_into()
                        .map_err(|_| BlsDoryTransposeError::InvalidShape)?,
                );
            }
            copied = destination_end;
        }
        if copied != output.len() {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        Ok(output.len())
    }

    pub fn authenticate(&mut self) -> Result<(), BlsDoryTransposeError> {
        validate_authenticated_header(&mut self.file, self.rows, self.columns, self.digest)?;
        let snapshot = authenticate_file(&mut self.file, self.rows, self.columns)?;
        if snapshot.digest != self.digest || snapshot.block_digests != self.block_digests {
            return Err(BlsDoryTransposeError::Authentication);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BlsDoryWordTransposeArtifact {
    fn drop(&mut self) {
        remove_if_owned(&self.path, &self.file);
    }
}

fn validate_geometry(
    rows: usize,
    columns: usize,
    chunk_rows: usize,
) -> Result<TransposeGeometry, BlsDoryTransposeError> {
    if rows == 0
        || !rows.is_power_of_two()
        || rows > BLS_DORY_TRANSPOSE_MAX_ROWS
        || columns == 0
        || columns > BLS_DORY_TRANSPOSE_MAX_COLUMNS
        || chunk_rows == 0
        || chunk_rows > rows
    {
        return Err(BlsDoryTransposeError::InvalidShape);
    }
    let data_bytes = data_bytes(rows, columns)?;
    if data_bytes > BLS_DORY_TRANSPOSE_MAX_DATA_BYTES {
        return Err(BlsDoryTransposeError::InvalidShape);
    }
    let row_buffer_words = chunk_rows
        .checked_mul(columns)
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    let row_buffer_bytes = row_buffer_words
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    if row_buffer_bytes > BLS_DORY_TRANSPOSE_MAX_CHUNK_BUFFER_BYTES {
        return Err(BlsDoryTransposeError::InvalidShape);
    }
    let total_bytes = HEADER_BYTES
        .checked_add(data_bytes)
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    Ok(TransposeGeometry {
        data_bytes,
        total_bytes,
        row_buffer_words,
    })
}

fn zeroed_bytes(len: usize) -> Result<Vec<u8>, BlsDoryTransposeError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| BlsDoryTransposeError::InvalidShape)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

fn authentication_blocks_per_column(rows: usize) -> usize {
    rows.div_ceil(AUTHENTICATION_BLOCK_ROWS)
}

fn data_offset(word_index: usize) -> Result<u64, BlsDoryTransposeError> {
    HEADER_BYTES
        .checked_add(
            u64::try_from(word_index)
                .map_err(|_| BlsDoryTransposeError::InvalidShape)?
                .checked_mul(WORD_BYTES)
                .ok_or(BlsDoryTransposeError::InvalidShape)?,
        )
        .ok_or(BlsDoryTransposeError::InvalidShape)
}

fn authentication_block_digest(
    rows: usize,
    columns: usize,
    column: usize,
    block: usize,
    start_row: usize,
    block_rows: usize,
    encoded: &[u8],
) -> Result<[u8; 32], BlsDoryTransposeError> {
    let expected_bytes = block_rows
        .checked_mul(WORD_BYTES as usize)
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    if encoded.len() != expected_bytes {
        return Err(BlsDoryTransposeError::InvalidShape);
    }
    let mut hasher = blake3::Hasher::new_derive_key(BLOCK_HASH_DOMAIN);
    for value in [rows, columns, column, block, start_row, block_rows] {
        hasher.update(
            &u64::try_from(value)
                .map_err(|_| BlsDoryTransposeError::InvalidShape)?
                .to_le_bytes(),
        );
    }
    hasher.update(encoded);
    Ok(*hasher.finalize().as_bytes())
}

fn validate_authenticated_header(
    file: &mut File,
    rows: usize,
    columns: usize,
    digest: [u8; 32],
) -> Result<(), BlsDoryTransposeError> {
    let expected_data_bytes = data_bytes(rows, columns)?;
    let expected_len = HEADER_BYTES
        .checked_add(expected_data_bytes)
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    if file.metadata()?.len() != expected_len {
        return Err(BlsDoryTransposeError::Authentication);
    }
    let expected_header = encode_header(rows, columns, expected_data_bytes, digest)?;
    let mut header = [0u8; HEADER_BYTES as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    if header != expected_header {
        return Err(BlsDoryTransposeError::Authentication);
    }
    Ok(())
}

fn data_bytes(rows: usize, columns: usize) -> Result<u64, BlsDoryTransposeError> {
    u64::try_from(rows)
        .ok()
        .and_then(|rows| {
            u64::try_from(columns)
                .ok()
                .and_then(|columns| rows.checked_mul(columns))
        })
        .and_then(|words| words.checked_mul(WORD_BYTES))
        .ok_or(BlsDoryTransposeError::InvalidShape)
}

fn encode_header(
    rows: usize,
    columns: usize,
    data_bytes: u64,
    digest: [u8; 32],
) -> Result<[u8; HEADER_BYTES as usize], BlsDoryTransposeError> {
    let mut header = [0u8; HEADER_BYTES as usize];
    header[..8].copy_from_slice(&MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_le_bytes());
    header[16..24].copy_from_slice(
        &u64::try_from(rows)
            .map_err(|_| BlsDoryTransposeError::InvalidShape)?
            .to_le_bytes(),
    );
    header[24..32].copy_from_slice(
        &u64::try_from(columns)
            .map_err(|_| BlsDoryTransposeError::InvalidShape)?
            .to_le_bytes(),
    );
    header[32..40].copy_from_slice(&data_bytes.to_le_bytes());
    header[40..72].copy_from_slice(&digest);
    Ok(header)
}

fn authenticate_file(
    file: &mut File,
    rows: usize,
    columns: usize,
) -> Result<AuthenticationSnapshot, BlsDoryTransposeError> {
    let expected_data_bytes = data_bytes(rows, columns)?;
    let expected_len = HEADER_BYTES
        .checked_add(expected_data_bytes)
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    if file.metadata()?.len() != expected_len {
        return Err(BlsDoryTransposeError::Authentication);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut prefix = [0u8; DIGEST_OFFSET as usize];
    file.read_exact(&mut prefix)?;
    let expected_prefix = encode_header(rows, columns, expected_data_bytes, [0; 32])?;
    if prefix != expected_prefix[..DIGEST_OFFSET as usize] {
        return Err(BlsDoryTransposeError::Authentication);
    }
    let mut hasher = blake3::Hasher::new_derive_key(HASH_DOMAIN);
    hasher.update(&prefix);
    let mut reader = BufReader::with_capacity(IO_BUFFER_BYTES, file.try_clone()?);
    reader.seek(SeekFrom::Start(HEADER_BYTES))?;
    let buffer_len = rows
        .min(AUTHENTICATION_BLOCK_ROWS)
        .checked_mul(WORD_BYTES as usize)
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    let mut buffer = zeroed_bytes(buffer_len)?;
    let blocks_per_column = authentication_blocks_per_column(rows);
    let digest_count = columns
        .checked_mul(blocks_per_column)
        .ok_or(BlsDoryTransposeError::InvalidShape)?;
    let mut block_digests = Vec::new();
    block_digests
        .try_reserve_exact(digest_count)
        .map_err(|_| BlsDoryTransposeError::InvalidShape)?;
    for column in 0..columns {
        for block in 0..blocks_per_column {
            let start_row = block
                .checked_mul(AUTHENTICATION_BLOCK_ROWS)
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            let block_rows = rows
                .saturating_sub(start_row)
                .min(AUTHENTICATION_BLOCK_ROWS);
            let block_bytes = block_rows
                .checked_mul(WORD_BYTES as usize)
                .ok_or(BlsDoryTransposeError::InvalidShape)?;
            if block_rows == 0 || block_bytes > buffer.len() {
                return Err(BlsDoryTransposeError::InvalidShape);
            }
            reader.read_exact(&mut buffer[..block_bytes])?;
            hasher.update(&buffer[..block_bytes]);
            block_digests.push(authentication_block_digest(
                rows,
                columns,
                column,
                block,
                start_row,
                block_rows,
                &buffer[..block_bytes],
            )?);
        }
    }
    if block_digests.len() != digest_count {
        return Err(BlsDoryTransposeError::Authentication);
    }
    Ok(AuthenticationSnapshot {
        digest: *hasher.finalize().as_bytes(),
        block_digests,
    })
}

fn remove_if_owned(path: &Path, file: &File) {
    let Ok(held) = file.try_clone().and_then(Handle::from_file) else {
        return;
    };
    let Ok(live) = Handle::from_path(path) else {
        return;
    };
    if held == live && std::fs::remove_file(path).is_ok() {
        release_scratch_artifact_reservation(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-transpose-test-{}-{nonce}",
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

    #[test]
    fn chunked_rows_round_trip_as_authenticated_columns() {
        let directory = TestDirectory::create();
        let rows = 8;
        let columns = 5;
        let matrix = (0..rows)
            .map(|row| {
                (0..columns)
                    .map(|column| (row * 100 + column * 7 + 3) as u64)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut writer =
            BlsDoryWordTransposeWriter::create(&directory.0, rows, columns, 3).unwrap();
        for row in &matrix {
            writer.write_row(row).unwrap();
        }
        let mut artifact = writer.finish().unwrap();
        artifact.authenticate().unwrap();
        assert_eq!(artifact.rows(), rows);
        assert_eq!(artifact.columns(), columns);
        assert_eq!(
            std::fs::metadata(artifact.path()).unwrap().len(),
            HEADER_BYTES + (rows * columns) as u64 * WORD_BYTES
        );
        for column in 0..columns {
            let mut output = vec![0; rows];
            assert_eq!(artifact.read_column(column, &mut output).unwrap(), rows);
            let expected = matrix.iter().map(|row| row[column]).collect::<Vec<_>>();
            assert_eq!(output, expected);

            let mut segmented = Vec::with_capacity(rows);
            for (start, len) in [(0, 3), (3, 3), (6, 2)] {
                let mut segment = vec![0; len];
                assert_eq!(
                    artifact
                        .read_column_segment(column, start, &mut segment)
                        .unwrap(),
                    len
                );
                segmented.extend_from_slice(&segment);
            }
            assert_eq!(segmented, expected);
        }
        assert!(matches!(
            artifact.read_column_segment(columns, 0, &mut [0]),
            Err(BlsDoryTransposeError::InvalidShape)
        ));
        assert!(matches!(
            artifact.read_column_segment(0, rows, &mut [0]),
            Err(BlsDoryTransposeError::InvalidShape)
        ));
        assert!(matches!(
            artifact.read_column_segment(0, 0, &mut []),
            Err(BlsDoryTransposeError::InvalidShape)
        ));
        let path = artifact.path().to_path_buf();
        drop(artifact);
        assert!(!path.exists());
    }

    #[test]
    fn post_authentication_mutation_is_rejected_by_segment_and_commit_reads() {
        let directory = TestDirectory::create();
        let rows = 8;
        let columns = 2;
        let mut writer =
            BlsDoryWordTransposeWriter::create(&directory.0, rows, columns, 3).unwrap();
        for row in 0..rows {
            writer
                .write_row(&[row as u64 + 3, row as u64 + 101])
                .unwrap();
        }
        let mut artifact = writer.finish().unwrap();
        artifact.authenticate().unwrap();

        let changed_column = 1;
        let changed_row = 4;
        let changed_offset = data_offset(changed_column * rows + changed_row).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(artifact.path())
            .unwrap();
        file.seek(SeekFrom::Start(changed_offset)).unwrap();
        let mut original = [0u8; 1];
        file.read_exact(&mut original).unwrap();
        file.seek(SeekFrom::Start(changed_offset)).unwrap();
        file.write_all(&[original[0] ^ 0x80]).unwrap();
        file.flush().unwrap();

        let mut segment = [u64::MAX; 3];
        assert!(matches!(
            artifact.read_column_segment(changed_column, 3, &mut segment),
            Err(BlsDoryTransposeError::Authentication)
        ));
        assert_eq!(segment, [u64::MAX; 3]);

        let mut column = vec![0; rows];
        let commit_read = (0..columns).try_for_each(|column_index| {
            artifact.read_column(column_index, &mut column).map(|_| ())
        });
        assert!(matches!(
            commit_read,
            Err(BlsDoryTransposeError::Authentication)
        ));
        drop(file);
        drop(artifact);
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn authentication_blocks_preserve_two_to_the_seventeenth_segment_reads() {
        let directory = TestDirectory::create();
        let rows = 2 * AUTHENTICATION_BLOCK_ROWS;
        let mut writer = BlsDoryWordTransposeWriter::create(&directory.0, rows, 1, 1024).unwrap();
        for row in 0..rows {
            writer.write_row(&[row as u64 * 3 + 7]).unwrap();
        }
        let mut artifact = writer.finish().unwrap();
        artifact.authenticate().unwrap();

        let mut segment = vec![0; AUTHENTICATION_BLOCK_ROWS];
        artifact
            .read_column_segment(0, AUTHENTICATION_BLOCK_ROWS, &mut segment)
            .unwrap();
        assert_eq!(segment[0], AUTHENTICATION_BLOCK_ROWS as u64 * 3 + 7);
        assert_eq!(segment[segment.len() - 1], (rows as u64 - 1) * 3 + 7);

        let mut crossing = [0; 4];
        artifact
            .read_column_segment(0, AUTHENTICATION_BLOCK_ROWS - 2, &mut crossing)
            .unwrap();
        assert_eq!(
            crossing,
            [
                (AUTHENTICATION_BLOCK_ROWS as u64 - 2) * 3 + 7,
                (AUTHENTICATION_BLOCK_ROWS as u64 - 1) * 3 + 7,
                AUTHENTICATION_BLOCK_ROWS as u64 * 3 + 7,
                (AUTHENTICATION_BLOCK_ROWS as u64 + 1) * 3 + 7,
            ]
        );
        drop(artifact);
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn production_geometry_is_preserved_and_over_cap_shapes_create_no_file() {
        let production =
            validate_geometry(BLS_DORY_TRANSPOSE_MAX_ROWS, 288, AUTHENTICATION_BLOCK_ROWS).unwrap();
        assert!(production.data_bytes <= BLS_DORY_TRANSPOSE_MAX_DATA_BYTES);
        assert_eq!(
            projected_bls_dory_transpose_artifact_bytes(BLS_DORY_TRANSPOSE_MAX_ROWS, 288).unwrap(),
            2_415_919_176
        );
        assert_eq!(
            projected_bls_dory_transpose_artifact_bytes(BLS_DORY_TRANSPOSE_MAX_ROWS, 84).unwrap(),
            704_643_144
        );
        assert!(
            production.row_buffer_words * std::mem::size_of::<u64>()
                <= BLS_DORY_TRANSPOSE_MAX_CHUNK_BUFFER_BYTES
        );

        let directory = TestDirectory::create();
        for (rows, columns, chunk_rows) in [
            (BLS_DORY_TRANSPOSE_MAX_ROWS * 2, 1, 1),
            (8, BLS_DORY_TRANSPOSE_MAX_COLUMNS + 1, 1),
            (
                BLS_DORY_TRANSPOSE_MAX_ROWS,
                BLS_DORY_TRANSPOSE_MAX_COLUMNS,
                BLS_DORY_TRANSPOSE_MAX_ROWS,
            ),
        ] {
            assert!(matches!(
                BlsDoryWordTransposeWriter::create(&directory.0, rows, columns, chunk_rows,),
                Err(BlsDoryTransposeError::InvalidShape)
            ));
            assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
        }
    }

    #[test]
    fn incomplete_malformed_and_corrupt_artifacts_fail_closed() {
        let directory = TestDirectory::create();
        assert!(matches!(
            BlsDoryWordTransposeWriter::create(Path::new("relative"), 8, 2, 2),
            Err(BlsDoryTransposeError::InvalidShape)
        ));
        let mut incomplete = BlsDoryWordTransposeWriter::create(&directory.0, 8, 2, 2).unwrap();
        incomplete.write_row(&[1, 2]).unwrap();
        assert!(matches!(
            incomplete.finish(),
            Err(BlsDoryTransposeError::Incomplete)
        ));
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);

        let mut writer = BlsDoryWordTransposeWriter::create(&directory.0, 8, 2, 3).unwrap();
        assert!(matches!(
            writer.write_row(&[1]),
            Err(BlsDoryTransposeError::InvalidShape)
        ));
        for row in 0..8 {
            writer.write_row(&[row, row + 1]).unwrap();
        }
        let mut artifact = writer.finish().unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .open(artifact.path())
            .unwrap();
        file.seek(SeekFrom::Start(HEADER_BYTES + 3)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.flush().unwrap();
        assert!(matches!(
            artifact.authenticate(),
            Err(BlsDoryTransposeError::Authentication)
        ));
    }
}
