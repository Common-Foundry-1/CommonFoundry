//! Self-authenticating compressed artifacts for the first four LogUp and
//! paired aggregate folds.
//!
//! Regular transition selectors store one canonical scalar because their
//! inverse lane is identically zero. Range selectors retain the original
//! radix-16 digits behind each folded cell in one, two, four, or eight bytes.
//! Readers reconstruct the exact folded transition and mapped values using the
//! bound challenges and role-specific lineage.

use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    serialization::{Compress, Validate},
};
use thiserror::Error;

#[cfg(test)]
use std::fs::OpenOptions;

use crate::{
    dory_bls12_381_prototype::BlsDoryFr,
    dory_scratch_telemetry::{TrackedScratchFile, TrackedScratchReader},
};

const ARTIFACT_MAGIC: [u8; 8] = *b"CFDBLSL1";
const ARTIFACT_VERSION: u16 = 1;
const ARTIFACT_HEADER_BYTES: usize = 140;
const ARTIFACT_DIGEST_BYTES: usize = 32;
const ARTIFACT_SCALAR_BYTES: usize = 32;
const ARTIFACT_IO_BUFFER_BYTES: usize = 1024 * 1024;
const ARTIFACT_HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryLogUpArtifact/v1";
static ARTIFACT_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryLogUpArtifactSpec {
    pub context_digest: [u8; 32],
    pub parent_digest: [u8; 32],
    pub reconstruction_digest: [u8; 32],
    pub generation: u32,
    pub selector_rows: u64,
    pub current_cells: u64,
    pub regular_selectors: u32,
    pub range_selectors: u32,
}

impl BlsDoryLogUpArtifactSpec {
    pub(crate) fn encoded_bytes(self) -> Result<u64, BlsDoryLogUpArtifactError> {
        self.validate()?;
        artifact_file_bytes(self)
    }

    pub(crate) fn code_bytes(self) -> Result<usize, BlsDoryLogUpArtifactError> {
        match self.generation {
            1 => Ok(1),
            2 => Ok(2),
            3 => Ok(4),
            4 => Ok(8),
            _ => Err(BlsDoryLogUpArtifactError::InvalidSpec),
        }
    }

    fn regular_value_count(self) -> Result<u64, BlsDoryLogUpArtifactError> {
        u64::from(self.regular_selectors)
            .checked_mul(self.current_cells)
            .ok_or(BlsDoryLogUpArtifactError::InvalidSpec)
    }

    fn range_value_count(self) -> Result<u64, BlsDoryLogUpArtifactError> {
        u64::from(self.range_selectors)
            .checked_mul(self.current_cells)
            .ok_or(BlsDoryLogUpArtifactError::InvalidSpec)
    }

    fn validate(self) -> Result<(), BlsDoryLogUpArtifactError> {
        let used_selectors = u64::from(self.regular_selectors)
            .checked_add(u64::from(self.range_selectors))
            .ok_or(BlsDoryLogUpArtifactError::InvalidSpec)?;
        if self.context_digest == [0; 32]
            || self.parent_digest == [0; 32]
            || self.reconstruction_digest == [0; 32]
            || self.code_bytes().is_err()
            || self.selector_rows == 0
            || !self.selector_rows.is_power_of_two()
            || self.current_cells == 0
            || !self.current_cells.is_power_of_two()
            || self.regular_selectors == 0
            || self.range_selectors == 0
            || used_selectors > self.selector_rows
        {
            return Err(BlsDoryLogUpArtifactError::InvalidSpec);
        }
        artifact_file_bytes(self)?;
        Ok(())
    }

    fn encode(self) -> Result<[u8; ARTIFACT_HEADER_BYTES], BlsDoryLogUpArtifactError> {
        self.validate()?;
        let mut header = [0u8; ARTIFACT_HEADER_BYTES];
        header[..8].copy_from_slice(&ARTIFACT_MAGIC);
        header[8..10].copy_from_slice(&ARTIFACT_VERSION.to_le_bytes());
        header[12..44].copy_from_slice(&self.context_digest);
        header[44..76].copy_from_slice(&self.parent_digest);
        header[76..108].copy_from_slice(&self.reconstruction_digest);
        header[108..112].copy_from_slice(&self.generation.to_le_bytes());
        header[112..120].copy_from_slice(&self.selector_rows.to_le_bytes());
        header[120..128].copy_from_slice(&self.current_cells.to_le_bytes());
        header[128..132].copy_from_slice(&self.regular_selectors.to_le_bytes());
        header[132..136].copy_from_slice(&self.range_selectors.to_le_bytes());
        header[136..138].copy_from_slice(&(self.code_bytes()? as u16).to_le_bytes());
        Ok(header)
    }
}

#[derive(Debug, Error)]
pub enum BlsDoryLogUpArtifactError {
    #[error("invalid compressed BLS Dory LogUp artifact specification")]
    InvalidSpec,
    #[error("compressed BLS Dory LogUp artifact has invalid length or framing")]
    InvalidArtifact,
    #[error("compressed BLS Dory LogUp artifact contains a non-canonical scalar")]
    InvalidScalar,
    #[error("compressed BLS Dory LogUp artifact authentication failed")]
    Authentication,
    #[error("compressed BLS Dory LogUp artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlsDoryLogUpArtifactValue {
    Regular(BlsDoryFr),
    Range(u64),
}

pub struct BlsDoryLogUpArtifactWriter {
    path: Option<PathBuf>,
    file: Option<BufWriter<TrackedScratchFile>>,
    spec: BlsDoryLogUpArtifactSpec,
    hasher: blake3::Hasher,
    written_regular: u64,
    written_range: u64,
}

impl BlsDoryLogUpArtifactWriter {
    pub fn create(
        scratch_directory: &Path,
        spec: BlsDoryLogUpArtifactSpec,
    ) -> Result<Self, BlsDoryLogUpArtifactError> {
        spec.validate()?;
        if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
            return Err(BlsDoryLogUpArtifactError::InvalidSpec);
        }
        let nonce = ARTIFACT_NONCE.fetch_add(1, Ordering::Relaxed);
        let context = hex::encode(&spec.context_digest[..8]);
        let path = scratch_directory.join(format!(
            "cmfd-dory-logup-{context}-{}-{}-{nonce}.tmp",
            spec.generation,
            std::process::id(),
        ));
        let file = TrackedScratchFile::create_new(&path)?;
        let header = spec.encode()?;
        let mut writer = Self {
            path: Some(path),
            file: Some(BufWriter::with_capacity(ARTIFACT_IO_BUFFER_BYTES, file)),
            spec,
            hasher: blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN),
            written_regular: 0,
            written_range: 0,
        };
        writer.file_mut()?.write_all(&header)?;
        writer.hasher.update(&header);
        Ok(writer)
    }

    pub fn write_regular_scalars(
        &mut self,
        scalars: &[BlsDoryFr],
    ) -> Result<(), BlsDoryLogUpArtifactError> {
        if self.written_range != 0 {
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        let count =
            u64::try_from(scalars.len()).map_err(|_| BlsDoryLogUpArtifactError::InvalidArtifact)?;
        let next = self
            .written_regular
            .checked_add(count)
            .ok_or(BlsDoryLogUpArtifactError::InvalidArtifact)?;
        if next > self.spec.regular_value_count()? {
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        for scalar in scalars {
            let encoded = encode_scalar(scalar)?;
            self.file_mut()?.write_all(&encoded)?;
            self.hasher.update(&encoded);
        }
        self.written_regular = next;
        Ok(())
    }

    pub fn write_range_codes(&mut self, codes: &[u64]) -> Result<(), BlsDoryLogUpArtifactError> {
        if self.written_regular != self.spec.regular_value_count()? {
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        let count =
            u64::try_from(codes.len()).map_err(|_| BlsDoryLogUpArtifactError::InvalidArtifact)?;
        let next = self
            .written_range
            .checked_add(count)
            .ok_or(BlsDoryLogUpArtifactError::InvalidArtifact)?;
        let code_bytes = self.spec.code_bytes()?;
        let maximum_code = if code_bytes == std::mem::size_of::<u64>() {
            u64::MAX
        } else {
            (1u64 << (code_bytes * 8)) - 1
        };
        if next > self.spec.range_value_count()? || codes.iter().any(|code| *code > maximum_code) {
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        let mut encoded = Vec::with_capacity(codes.len().saturating_mul(code_bytes));
        for code in codes {
            encoded.extend_from_slice(&code.to_le_bytes()[..code_bytes]);
        }
        self.file_mut()?.write_all(&encoded)?;
        self.hasher.update(&encoded);
        self.written_range = next;
        Ok(())
    }

    pub fn finish(mut self) -> Result<BlsDoryLogUpArtifact, BlsDoryLogUpArtifactError> {
        if self.written_regular != self.spec.regular_value_count()?
            || self.written_range != self.spec.range_value_count()?
        {
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        let digest = *self.hasher.finalize().as_bytes();
        let expected_len = artifact_file_bytes(self.spec)?;
        let file = self.file_mut()?;
        file.write_all(&digest)?;
        file.flush()?;
        file.get_ref().sync_all()?;
        if file.get_ref().metadata()?.len() != expected_len {
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        let path = self
            .path
            .take()
            .ok_or(BlsDoryLogUpArtifactError::InvalidArtifact)?;
        let file = self
            .file
            .take()
            .ok_or(BlsDoryLogUpArtifactError::InvalidArtifact)?
            .into_inner()
            .map_err(|error| error.into_error())?;
        Ok(BlsDoryLogUpArtifact {
            path,
            file,
            spec: self.spec,
            digest,
        })
    }

    fn file_mut(
        &mut self,
    ) -> Result<&mut BufWriter<TrackedScratchFile>, BlsDoryLogUpArtifactError> {
        self.file
            .as_mut()
            .ok_or(BlsDoryLogUpArtifactError::InvalidArtifact)
    }
}

impl Drop for BlsDoryLogUpArtifactWriter {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let (mut file, buffered) = file.into_parts();
            drop(buffered);
            let _ = file.remove_if_owned();
        }
        self.path.take();
    }
}

pub struct BlsDoryLogUpArtifact {
    path: PathBuf,
    file: TrackedScratchFile,
    spec: BlsDoryLogUpArtifactSpec,
    digest: [u8; 32],
}

impl BlsDoryLogUpArtifact {
    #[must_use]
    pub const fn spec(&self) -> BlsDoryLogUpArtifactSpec {
        self.spec
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn for_each_value(
        &self,
        mut visitor: impl FnMut(BlsDoryLogUpArtifactValue) -> Result<(), BlsDoryLogUpArtifactError>,
    ) -> Result<(), BlsDoryLogUpArtifactError> {
        self.validate_live_file(|reader, hasher| {
            let mut scalar = [0u8; ARTIFACT_SCALAR_BYTES];
            for _ in 0..self.spec.regular_value_count()? {
                reader.read_exact(&mut scalar)?;
                hasher.update(&scalar);
                visitor(BlsDoryLogUpArtifactValue::Regular(decode_scalar(scalar)?))?;
            }
            let code_bytes = self.spec.code_bytes()?;
            let values_per_chunk = ARTIFACT_IO_BUFFER_BYTES / code_bytes;
            let mut buffer = vec![0u8; values_per_chunk * code_bytes];
            let mut remaining = self.spec.range_value_count()?;
            while remaining > 0 {
                let values = usize::try_from(remaining.min(values_per_chunk as u64))
                    .map_err(|_| BlsDoryLogUpArtifactError::InvalidArtifact)?;
                let bytes = values
                    .checked_mul(code_bytes)
                    .ok_or(BlsDoryLogUpArtifactError::InvalidArtifact)?;
                reader.read_exact(&mut buffer[..bytes])?;
                hasher.update(&buffer[..bytes]);
                for encoded in buffer[..bytes].chunks_exact(code_bytes) {
                    let mut word = [0u8; std::mem::size_of::<u64>()];
                    word[..code_bytes].copy_from_slice(encoded);
                    let code = u64::from_le_bytes(word);
                    visitor(BlsDoryLogUpArtifactValue::Range(code))?;
                }
                remaining -= values as u64;
            }
            Ok(())
        })
    }

    fn validate_live_file(
        &self,
        consume: impl FnOnce(
            &mut BufReader<TrackedScratchReader>,
            &mut blake3::Hasher,
        ) -> Result<(), BlsDoryLogUpArtifactError>,
    ) -> Result<(), BlsDoryLogUpArtifactError> {
        if self.file.metadata()?.len() != artifact_file_bytes(self.spec)? {
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        let mut file = self.file.try_clone_reader()?;
        file.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::with_capacity(ARTIFACT_IO_BUFFER_BYTES, file);
        let mut header = [0u8; ARTIFACT_HEADER_BYTES];
        reader.read_exact(&mut header)?;
        if header != self.spec.encode()? {
            return Err(BlsDoryLogUpArtifactError::Authentication);
        }
        let mut hasher = blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN);
        hasher.update(&header);
        consume(&mut reader, &mut hasher)?;
        let mut stored_digest = [0u8; ARTIFACT_DIGEST_BYTES];
        reader.read_exact(&mut stored_digest)?;
        if stored_digest != self.digest || stored_digest != *hasher.finalize().as_bytes() {
            return Err(BlsDoryLogUpArtifactError::Authentication);
        }
        let mut trailing = [0u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(BlsDoryLogUpArtifactError::InvalidArtifact);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BlsDoryLogUpArtifact {
    fn drop(&mut self) {
        debug_assert_eq!(self.file.path(), self.path);
        let _ = self.file.remove_if_owned();
    }
}

fn artifact_file_bytes(spec: BlsDoryLogUpArtifactSpec) -> Result<u64, BlsDoryLogUpArtifactError> {
    let regular_bytes = spec
        .regular_value_count()?
        .checked_mul(ARTIFACT_SCALAR_BYTES as u64)
        .ok_or(BlsDoryLogUpArtifactError::InvalidSpec)?;
    let code_bytes =
        u64::try_from(spec.code_bytes()?).map_err(|_| BlsDoryLogUpArtifactError::InvalidSpec)?;
    let range_bytes = spec
        .range_value_count()?
        .checked_mul(code_bytes)
        .ok_or(BlsDoryLogUpArtifactError::InvalidSpec)?;
    (ARTIFACT_HEADER_BYTES as u64)
        .checked_add(regular_bytes)
        .and_then(|bytes| bytes.checked_add(range_bytes))
        .and_then(|bytes| bytes.checked_add(ARTIFACT_DIGEST_BYTES as u64))
        .ok_or(BlsDoryLogUpArtifactError::InvalidSpec)
}

fn encode_scalar(scalar: &BlsDoryFr) -> Result<[u8; 32], BlsDoryLogUpArtifactError> {
    let mut encoded = Vec::with_capacity(ARTIFACT_SCALAR_BYTES);
    scalar
        .serialize_compressed(&mut encoded)
        .map_err(|_| BlsDoryLogUpArtifactError::InvalidScalar)?;
    encoded
        .try_into()
        .map_err(|_| BlsDoryLogUpArtifactError::InvalidScalar)
}

fn decode_scalar(encoded: [u8; 32]) -> Result<BlsDoryFr, BlsDoryLogUpArtifactError> {
    let mut reader = Cursor::new(encoded.as_slice());
    let scalar = BlsDoryFr::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryLogUpArtifactError::InvalidScalar)?;
    if reader.position() != ARTIFACT_SCALAR_BYTES as u64 {
        return Err(BlsDoryLogUpArtifactError::InvalidScalar);
    }
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dory_pcs::primitives::arithmetic::Field;

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-logup-artifact-test-{}-{nonce}",
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

    fn spec(generation: u32) -> BlsDoryLogUpArtifactSpec {
        BlsDoryLogUpArtifactSpec {
            context_digest: [3; 32],
            parent_digest: [5; 32],
            reconstruction_digest: [7; 32],
            generation,
            selector_rows: 8,
            current_cells: 4,
            regular_selectors: 2,
            range_selectors: 3,
        }
    }

    fn artifact(
        directory: &Path,
        generation: u32,
    ) -> Result<BlsDoryLogUpArtifact, BlsDoryLogUpArtifactError> {
        let artifact_spec = spec(generation);
        let regular = (0..artifact_spec.regular_value_count()?)
            .map(|value| BlsDoryFr::from_u64(value * 17 + 1))
            .collect::<Vec<_>>();
        let range = (0..artifact_spec.range_value_count()?)
            .map(|value| match generation {
                1 => value.wrapping_mul(19) & 0xff,
                2 => value.wrapping_mul(4_099) & 0xffff,
                3 => value.wrapping_mul(1_000_003) & 0xffff_ffff,
                4 => value.wrapping_mul(1_000_000_007),
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        let mut writer = BlsDoryLogUpArtifactWriter::create(directory, artifact_spec)?;
        writer.write_regular_scalars(&regular)?;
        writer.write_range_codes(&range)?;
        writer.finish()
    }

    #[test]
    fn every_generation_round_trips_and_cleans_on_drop() {
        for generation in [1, 2, 3, 4] {
            let directory = TestDirectory::create();
            let artifact = artifact(&directory.0, generation).unwrap();
            let path = artifact.path().to_path_buf();
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                spec(generation).encoded_bytes().unwrap()
            );
            let mut regular = Vec::new();
            let mut range = Vec::new();
            artifact
                .for_each_value(|value| {
                    match value {
                        BlsDoryLogUpArtifactValue::Regular(scalar) => {
                            regular.push(scalar);
                        }
                        BlsDoryLogUpArtifactValue::Range(code) => {
                            range.push(code);
                        }
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(regular.len(), 8);
            assert_eq!(range.len(), 12);
            drop(artifact);
            assert!(!path.exists());
        }
    }

    #[test]
    fn corruption_and_truncation_abort_without_leaking_files() {
        for generation in [1, 2, 3, 4] {
            for truncate in [false, true] {
                let directory = TestDirectory::create();
                let artifact = artifact(&directory.0, generation).unwrap();
                let path = artifact.path().to_path_buf();
                if truncate {
                    let file = OpenOptions::new().write(true).open(&path).unwrap();
                    file.set_len(std::fs::metadata(&path).unwrap().len() - 1)
                        .unwrap();
                } else {
                    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
                    file.seek(SeekFrom::Start(ARTIFACT_HEADER_BYTES as u64 + 3))
                        .unwrap();
                    file.write_all(&[0xa5]).unwrap();
                    file.flush().unwrap();
                }
                assert!(artifact.for_each_value(|_| Ok(())).is_err());
                drop(artifact);
                assert!(!path.exists());
            }
        }
    }

    #[test]
    fn noncanonical_regular_scalar_fails_before_value_exposure() {
        let directory = TestDirectory::create();
        let artifact = artifact(&directory.0, 1).unwrap();
        let path = artifact.path().to_path_buf();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(ARTIFACT_HEADER_BYTES as u64))
            .unwrap();
        file.write_all(&[0xff; ARTIFACT_SCALAR_BYTES]).unwrap();
        file.flush().unwrap();
        let mut exposed = false;
        assert!(matches!(
            artifact.for_each_value(|_| {
                exposed = true;
                Ok(())
            }),
            Err(BlsDoryLogUpArtifactError::InvalidScalar)
        ));
        assert!(!exposed);
        drop(artifact);
        assert!(!path.exists());
    }

    #[test]
    fn incomplete_or_out_of_phase_writer_cleans_up() {
        let directory = TestDirectory::create();
        let mut writer = BlsDoryLogUpArtifactWriter::create(&directory.0, spec(1)).unwrap();
        assert!(writer.write_range_codes(&[1]).is_err());
        writer
            .write_regular_scalars(&vec![BlsDoryFr::one(); 8])
            .unwrap();
        assert!(writer.write_range_codes(&[u64::MAX]).is_err());
        drop(writer);
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn generation_code_widths_are_canonical_and_bounded() {
        for (generation, code_bytes) in [(1, 1usize), (2, 2), (3, 4), (4, 8)] {
            assert_eq!(spec(generation).code_bytes().unwrap(), code_bytes);
            let directory = TestDirectory::create();
            let mut writer =
                BlsDoryLogUpArtifactWriter::create(&directory.0, spec(generation)).unwrap();
            writer
                .write_regular_scalars(&vec![BlsDoryFr::one(); 8])
                .unwrap();
            if code_bytes < std::mem::size_of::<u64>() {
                assert!(
                    writer
                        .write_range_codes(&[1u64 << (code_bytes * 8)])
                        .is_err()
                );
            } else {
                writer.write_range_codes(&[u64::MAX]).unwrap();
            }
            drop(writer);
            assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
        }
        assert!(spec(0).validate().is_err());
        assert!(spec(5).validate().is_err());
    }
}
