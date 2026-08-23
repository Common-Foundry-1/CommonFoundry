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

const MAGIC: [u8; 8] = *b"CFDBLST1";
const VERSION: u16 = 1;
const HEADER_BYTES: u64 = 72;
const DIGEST_OFFSET: u64 = 40;
const WORD_BYTES: u64 = 8;
const HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryWordTranspose/v1";
const IO_BUFFER_BYTES: usize = 1024 * 1024;
static ARTIFACT_NONCE: AtomicU64 = AtomicU64::new(1);

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
        if !directory.is_absolute()
            || rows == 0
            || !rows.is_power_of_two()
            || columns == 0
            || chunk_rows == 0
            || chunk_rows > rows
        {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        let data_bytes = data_bytes(rows, columns)?;
        let total_bytes = HEADER_BYTES
            .checked_add(data_bytes)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        let nonce = ARTIFACT_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            "cmfd-dory-word-transpose-{}-{nonce}.bin",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        file.set_len(total_bytes)?;
        let header = encode_header(rows, columns, data_bytes, [0; 32])?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header)?;
        let capacity = chunk_rows
            .checked_mul(columns)
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        Ok(Self {
            path: Some(path),
            file,
            rows,
            columns,
            chunk_rows,
            written_rows: 0,
            buffered_rows: 0,
            row_buffer: Vec::with_capacity(capacity),
        })
    }

    pub fn write_row(&mut self, row: &[u64]) -> Result<(), BlsDoryTransposeError> {
        if row.len() != self.columns || self.written_rows + self.buffered_rows >= self.rows {
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
        let digest = authenticate_file(&mut self.file, self.rows, self.columns)?;
        self.file.seek(SeekFrom::Start(DIGEST_OFFSET))?;
        self.file.write_all(&digest)?;
        self.file.flush()?;
        let path = self
            .path
            .take()
            .ok_or(BlsDoryTransposeError::InvalidShape)?;
        Ok(BlsDoryWordTransposeArtifact {
            path,
            file: self.file.try_clone()?,
            rows: self.rows,
            columns: self.columns,
            digest,
        })
    }

    fn flush_chunk(&mut self) -> Result<(), BlsDoryTransposeError> {
        if self.buffered_rows == 0 {
            return Ok(());
        }
        let mut encoded = Vec::with_capacity(self.buffered_rows * WORD_BYTES as usize);
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
        self.written_rows += self.buffered_rows;
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
}

impl BlsDoryWordTransposeArtifact {
    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn columns(&self) -> usize {
        self.columns
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
        if column >= self.columns
            || output.is_empty()
            || start_row
                .checked_add(output.len())
                .is_none_or(|end| end > self.rows)
        {
            return Err(BlsDoryTransposeError::InvalidShape);
        }
        let word_index = column
            .checked_mul(self.rows)
            .and_then(|index| index.checked_add(start_row))
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
        let mut encoded = [0u8; 8];
        for word in output.iter_mut() {
            self.file.read_exact(&mut encoded)?;
            *word = u64::from_le_bytes(encoded);
        }
        Ok(output.len())
    }

    pub fn authenticate(&mut self) -> Result<(), BlsDoryTransposeError> {
        self.file.seek(SeekFrom::Start(DIGEST_OFFSET))?;
        let mut stored_digest = [0u8; 32];
        self.file.read_exact(&mut stored_digest)?;
        let digest = authenticate_file(&mut self.file, self.rows, self.columns)?;
        if stored_digest != self.digest || digest != self.digest {
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
) -> Result<[u8; 32], BlsDoryTransposeError> {
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
    file.seek(SeekFrom::Start(HEADER_BYTES))?;
    let mut reader = BufReader::with_capacity(IO_BUFFER_BYTES, file.try_clone()?);
    let mut remaining = expected_data_bytes;
    let mut buffer = vec![0u8; IO_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(IO_BUFFER_BYTES as u64))
            .map_err(|_| BlsDoryTransposeError::InvalidShape)?;
        reader.read_exact(&mut buffer[..take])?;
        hasher.update(&buffer[..take]);
        remaining -= take as u64;
    }
    Ok(*hasher.finalize().as_bytes())
}

fn remove_if_owned(path: &Path, file: &File) {
    let Ok(held) = file.try_clone().and_then(Handle::from_file) else {
        return;
    };
    let Ok(live) = Handle::from_path(path) else {
        return;
    };
    if held == live {
        let _ = std::fs::remove_file(path);
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
