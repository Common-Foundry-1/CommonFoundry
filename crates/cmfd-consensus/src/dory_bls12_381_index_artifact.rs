//! Self-authenticating indexed scalar artifacts for BLS12-381 polynomials.
//!
//! A canonical literal-scalar prefix is followed by a small dictionary and one
//! authenticated byte per remaining explicit coefficient. These prover-local
//! files never enter Fiat-Shamir; any framing, scalar, code, digest, or I/O
//! failure aborts proving.

use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::Field,
    serialization::{Compress, Validate},
};
use thiserror::Error;

#[cfg(test)]
use std::fs::OpenOptions;

use crate::{
    dory_bls12_381_prototype::BlsDoryFr,
    dory_scratch_telemetry::{TrackedScratchFile, TrackedScratchReader},
};

const ARTIFACT_MAGIC: [u8; 8] = *b"CFDBLSI1";
const ARTIFACT_VERSION: u16 = 2;
const ARTIFACT_HEADER_BYTES: usize = 72;
const ARTIFACT_DIGEST_BYTES: usize = 32;
const ARTIFACT_SCALAR_BYTES: usize = 32;
const ARTIFACT_IO_BUFFER_BYTES: usize = 1024 * 1024;
const ARTIFACT_HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryIndexArtifact/v1";
static ARTIFACT_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryIndexArtifactSpec {
    pub context_digest: [u8; 32],
    /// Logical power-of-two table length, including the implicit zero tail.
    pub scalar_count: u64,
    /// Canonically stored prefix length. Remaining logical scalars are zero.
    pub explicit_scalar_count: u64,
    /// Initial explicit scalars stored canonically at 32 bytes each. The
    /// remaining explicit coefficients are one-byte dictionary codes.
    pub literal_scalar_count: u64,
}

impl BlsDoryIndexArtifactSpec {
    fn validate(self, dictionary_len: usize) -> Result<(), BlsDoryIndexArtifactError> {
        if self.context_digest == [0; 32]
            || self.scalar_count == 0
            || !self.scalar_count.is_power_of_two()
            || self.explicit_scalar_count == 0
            || self.explicit_scalar_count > self.scalar_count
            || self.literal_scalar_count > self.explicit_scalar_count
            || !(1..=256).contains(&dictionary_len)
        {
            return Err(BlsDoryIndexArtifactError::InvalidSpec);
        }
        artifact_file_bytes(self, dictionary_len)?;
        Ok(())
    }

    fn encode(
        self,
        dictionary_len: usize,
    ) -> Result<[u8; ARTIFACT_HEADER_BYTES], BlsDoryIndexArtifactError> {
        self.validate(dictionary_len)?;
        let dictionary_len =
            u16::try_from(dictionary_len).map_err(|_| BlsDoryIndexArtifactError::InvalidSpec)?;
        let mut header = [0u8; ARTIFACT_HEADER_BYTES];
        header[..8].copy_from_slice(&ARTIFACT_MAGIC);
        header[8..10].copy_from_slice(&ARTIFACT_VERSION.to_le_bytes());
        header[12..44].copy_from_slice(&self.context_digest);
        header[44..52].copy_from_slice(&self.scalar_count.to_le_bytes());
        header[52..60].copy_from_slice(&self.explicit_scalar_count.to_le_bytes());
        header[60..68].copy_from_slice(&self.literal_scalar_count.to_le_bytes());
        header[68..70].copy_from_slice(&dictionary_len.to_le_bytes());
        Ok(header)
    }
}

#[derive(Debug, Error)]
pub enum BlsDoryIndexArtifactError {
    #[error("invalid BLS Dory indexed artifact specification")]
    InvalidSpec,
    #[error("BLS Dory indexed artifact has invalid length, dictionary, or code")]
    InvalidArtifact,
    #[error("BLS Dory indexed artifact scalar encoding failed")]
    InvalidScalar,
    #[error("BLS Dory indexed artifact authentication failed")]
    Authentication,
    #[error("BLS Dory indexed artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub struct BlsDoryIndexArtifactWriter {
    path: Option<PathBuf>,
    file: Option<BufWriter<TrackedScratchFile>>,
    spec: BlsDoryIndexArtifactSpec,
    dictionary: Vec<BlsDoryFr>,
    hasher: blake3::Hasher,
    written_literals: u64,
    written_codes: u64,
}

impl BlsDoryIndexArtifactWriter {
    pub fn create(
        scratch_directory: &Path,
        spec: BlsDoryIndexArtifactSpec,
        dictionary: Vec<BlsDoryFr>,
    ) -> Result<Self, BlsDoryIndexArtifactError> {
        validate_dictionary(&dictionary)?;
        spec.validate(dictionary.len())?;
        if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
            return Err(BlsDoryIndexArtifactError::InvalidSpec);
        }
        let nonce = ARTIFACT_NONCE.fetch_add(1, Ordering::Relaxed);
        let context = hex::encode(&spec.context_digest[..8]);
        let path = scratch_directory.join(format!(
            "cmfd-dory-index-{context}-{}-{nonce}.tmp",
            std::process::id(),
        ));
        let mut file = TrackedScratchFile::create_new(&path)?;
        let header = spec.encode(dictionary.len())?;
        file.write_all(&header)?;
        let mut hasher = blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN);
        hasher.update(&header);
        for scalar in &dictionary {
            let encoded = encode_scalar(scalar)?;
            file.write_all(&encoded)?;
            hasher.update(&encoded);
        }
        Ok(Self {
            path: Some(path),
            file: Some(BufWriter::with_capacity(ARTIFACT_IO_BUFFER_BYTES, file)),
            spec,
            dictionary,
            hasher,
            written_literals: 0,
            written_codes: 0,
        })
    }

    pub fn write_scalars(
        &mut self,
        scalars: &[BlsDoryFr],
    ) -> Result<(), BlsDoryIndexArtifactError> {
        if self.written_codes != 0 {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        let count =
            u64::try_from(scalars.len()).map_err(|_| BlsDoryIndexArtifactError::InvalidArtifact)?;
        let next_written = self
            .written_literals
            .checked_add(count)
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?;
        if next_written > self.spec.literal_scalar_count {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        for scalar in scalars {
            let encoded = encode_scalar(scalar)?;
            self.file_mut()?.write_all(&encoded)?;
            self.hasher.update(&encoded);
        }
        self.written_literals = next_written;
        Ok(())
    }

    pub fn write_codes(&mut self, codes: &[u8]) -> Result<(), BlsDoryIndexArtifactError> {
        if self.written_literals != self.spec.literal_scalar_count {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        let count =
            u64::try_from(codes.len()).map_err(|_| BlsDoryIndexArtifactError::InvalidArtifact)?;
        let next_written = self
            .written_codes
            .checked_add(count)
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?;
        let code_count = self
            .spec
            .explicit_scalar_count
            .checked_sub(self.spec.literal_scalar_count)
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?;
        if next_written > code_count
            || codes
                .iter()
                .any(|code| usize::from(*code) >= self.dictionary.len())
        {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        self.file_mut()?.write_all(codes)?;
        self.hasher.update(codes);
        self.written_codes = next_written;
        Ok(())
    }

    pub fn finish(mut self) -> Result<BlsDoryIndexArtifact, BlsDoryIndexArtifactError> {
        if self.written_literals != self.spec.literal_scalar_count
            || self.written_codes
                != self
                    .spec
                    .explicit_scalar_count
                    .checked_sub(self.spec.literal_scalar_count)
                    .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?
        {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        let digest = *self.hasher.finalize().as_bytes();
        let expected_len = artifact_file_bytes(self.spec, self.dictionary.len())?;
        let file = self.file_mut()?;
        file.write_all(&digest)?;
        file.flush()?;
        file.get_ref().sync_all()?;
        if file.get_ref().metadata()?.len() != expected_len {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        let path = self
            .path
            .take()
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?;
        let file = self
            .file
            .take()
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?
            .into_inner()
            .map_err(|error| error.into_error())?;
        Ok(BlsDoryIndexArtifact {
            path,
            file,
            spec: self.spec,
            dictionary: std::mem::take(&mut self.dictionary),
            digest,
        })
    }

    fn file_mut(
        &mut self,
    ) -> Result<&mut BufWriter<TrackedScratchFile>, BlsDoryIndexArtifactError> {
        self.file
            .as_mut()
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)
    }
}

impl Drop for BlsDoryIndexArtifactWriter {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let (mut file, buffered) = file.into_parts();
            drop(buffered);
            let _ = file.remove_if_owned();
        }
        self.path.take();
    }
}

pub struct BlsDoryIndexArtifact {
    path: PathBuf,
    file: TrackedScratchFile,
    spec: BlsDoryIndexArtifactSpec,
    dictionary: Vec<BlsDoryFr>,
    digest: [u8; 32],
}

impl BlsDoryIndexArtifact {
    #[must_use]
    pub const fn spec(&self) -> BlsDoryIndexArtifactSpec {
        self.spec
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn for_each_scalar(
        &self,
        mut visitor: impl FnMut(BlsDoryFr) -> Result<(), BlsDoryIndexArtifactError>,
    ) -> Result<(), BlsDoryIndexArtifactError> {
        self.validate_live_file(|reader, hasher| {
            let mut encoded = [0u8; ARTIFACT_SCALAR_BYTES];
            for _ in 0..self.spec.literal_scalar_count {
                reader.read_exact(&mut encoded)?;
                hasher.update(&encoded);
                visitor(decode_scalar(encoded)?)?;
            }
            let mut remaining = self
                .spec
                .explicit_scalar_count
                .checked_sub(self.spec.literal_scalar_count)
                .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?;
            let mut codes = vec![0u8; ARTIFACT_IO_BUFFER_BYTES];
            while remaining > 0 {
                let take = usize::try_from(remaining.min(codes.len() as u64))
                    .map_err(|_| BlsDoryIndexArtifactError::InvalidArtifact)?;
                reader.read_exact(&mut codes[..take])?;
                hasher.update(&codes[..take]);
                for code in &codes[..take] {
                    let scalar = self
                        .dictionary
                        .get(usize::from(*code))
                        .copied()
                        .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?;
                    visitor(scalar)?;
                }
                remaining -= take as u64;
            }
            Ok(())
        })
    }

    pub fn for_each_pair(
        &self,
        mut visitor: impl FnMut(BlsDoryFr, BlsDoryFr) -> Result<(), BlsDoryIndexArtifactError>,
    ) -> Result<(), BlsDoryIndexArtifactError> {
        if self.spec.scalar_count < 2 {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        let mut pending = None;
        self.for_each_scalar(|scalar| {
            if let Some(lower) = pending.take() {
                visitor(lower, scalar)
            } else {
                pending = Some(scalar);
                Ok(())
            }
        })?;
        if let Some(lower) = pending {
            visitor(lower, BlsDoryFr::zero())?;
        }
        Ok(())
    }

    fn validate_live_file(
        &self,
        consume: impl FnOnce(
            &mut BufReader<TrackedScratchReader>,
            &mut blake3::Hasher,
        ) -> Result<(), BlsDoryIndexArtifactError>,
    ) -> Result<(), BlsDoryIndexArtifactError> {
        let expected_len = artifact_file_bytes(self.spec, self.dictionary.len())?;
        if self.file.metadata()?.len() != expected_len {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        let mut file = self.file.try_clone_reader()?;
        file.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::with_capacity(ARTIFACT_IO_BUFFER_BYTES, file);
        let mut header = [0u8; ARTIFACT_HEADER_BYTES];
        reader.read_exact(&mut header)?;
        if header != self.spec.encode(self.dictionary.len())? {
            return Err(BlsDoryIndexArtifactError::Authentication);
        }
        let mut hasher = blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN);
        hasher.update(&header);
        for scalar in &self.dictionary {
            let expected = encode_scalar(scalar)?;
            let mut encoded = [0u8; ARTIFACT_SCALAR_BYTES];
            reader.read_exact(&mut encoded)?;
            hasher.update(&encoded);
            if encoded != expected {
                return Err(BlsDoryIndexArtifactError::Authentication);
            }
        }
        consume(&mut reader, &mut hasher)?;
        let mut stored_digest = [0u8; ARTIFACT_DIGEST_BYTES];
        reader.read_exact(&mut stored_digest)?;
        if stored_digest != self.digest || stored_digest != *hasher.finalize().as_bytes() {
            return Err(BlsDoryIndexArtifactError::Authentication);
        }
        let mut trailing = [0u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BlsDoryIndexArtifact {
    fn drop(&mut self) {
        debug_assert_eq!(self.file.path(), self.path);
        let _ = self.file.remove_if_owned();
    }
}

fn validate_dictionary(dictionary: &[BlsDoryFr]) -> Result<(), BlsDoryIndexArtifactError> {
    if dictionary.is_empty()
        || dictionary.len() > 256
        || dictionary[0] != BlsDoryFr::zero()
        || dictionary
            .iter()
            .enumerate()
            .any(|(index, scalar)| dictionary[..index].contains(scalar))
    {
        return Err(BlsDoryIndexArtifactError::InvalidSpec);
    }
    Ok(())
}

fn artifact_file_bytes(
    spec: BlsDoryIndexArtifactSpec,
    dictionary_len: usize,
) -> Result<u64, BlsDoryIndexArtifactError> {
    let dictionary_bytes = u64::try_from(dictionary_len)
        .ok()
        .and_then(|count| count.checked_mul(ARTIFACT_SCALAR_BYTES as u64))
        .ok_or(BlsDoryIndexArtifactError::InvalidSpec)?;
    let literal_bytes = spec
        .literal_scalar_count
        .checked_mul(ARTIFACT_SCALAR_BYTES as u64)
        .ok_or(BlsDoryIndexArtifactError::InvalidSpec)?;
    let code_bytes = spec
        .explicit_scalar_count
        .checked_sub(spec.literal_scalar_count)
        .ok_or(BlsDoryIndexArtifactError::InvalidSpec)?;
    (ARTIFACT_HEADER_BYTES as u64)
        .checked_add(dictionary_bytes)
        .and_then(|bytes| bytes.checked_add(literal_bytes))
        .and_then(|bytes| bytes.checked_add(code_bytes))
        .and_then(|bytes| bytes.checked_add(ARTIFACT_DIGEST_BYTES as u64))
        .ok_or(BlsDoryIndexArtifactError::InvalidSpec)
}

fn encode_scalar(scalar: &BlsDoryFr) -> Result<[u8; 32], BlsDoryIndexArtifactError> {
    let mut encoded = Vec::with_capacity(ARTIFACT_SCALAR_BYTES);
    scalar
        .serialize_compressed(&mut encoded)
        .map_err(|_| BlsDoryIndexArtifactError::InvalidScalar)?;
    encoded
        .try_into()
        .map_err(|_| BlsDoryIndexArtifactError::InvalidScalar)
}

fn decode_scalar(encoded: [u8; 32]) -> Result<BlsDoryFr, BlsDoryIndexArtifactError> {
    let mut reader = Cursor::new(encoded.as_slice());
    let scalar = BlsDoryFr::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryIndexArtifactError::InvalidScalar)?;
    if reader.position() != ARTIFACT_SCALAR_BYTES as u64 {
        return Err(BlsDoryIndexArtifactError::InvalidScalar);
    }
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-index-test-{}-{nonce}",
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

    fn spec(explicit: u64) -> BlsDoryIndexArtifactSpec {
        BlsDoryIndexArtifactSpec {
            context_digest: [7; 32],
            scalar_count: 16,
            explicit_scalar_count: explicit,
            literal_scalar_count: 0,
        }
    }

    #[test]
    fn indexed_artifact_round_trips_authenticates_and_cleans_up() {
        let directory = TestDirectory::create();
        let dictionary = vec![
            BlsDoryFr::zero(),
            BlsDoryFr::from_u64(11),
            BlsDoryFr::from_u64(29),
        ];
        let codes = [1, 2, 0, 1, 1, 2, 0, 2, 1];
        let mut writer =
            BlsDoryIndexArtifactWriter::create(&directory.0, spec(9), dictionary.clone()).unwrap();
        writer.write_codes(&codes[..4]).unwrap();
        writer.write_codes(&codes[4..]).unwrap();
        let artifact = writer.finish().unwrap();
        let path = artifact.path().to_path_buf();
        let mut decoded = Vec::new();
        artifact
            .for_each_scalar(|scalar| {
                decoded.push(scalar);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            decoded,
            codes
                .iter()
                .map(|code| dictionary[usize::from(*code)])
                .collect::<Vec<_>>()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            artifact_file_bytes(spec(9), dictionary.len()).unwrap()
        );

        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(
            (ARTIFACT_HEADER_BYTES + dictionary.len() * ARTIFACT_SCALAR_BYTES + 3) as u64,
        ))
        .unwrap();
        file.write_all(&[2]).unwrap();
        file.flush().unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryIndexArtifactError::Authentication)
        ));
        drop(artifact);
        assert!(!path.exists());
    }

    #[test]
    fn indexed_artifact_round_trips_a_canonical_literal_prefix() {
        let directory = TestDirectory::create();
        let dictionary = vec![
            BlsDoryFr::zero(),
            BlsDoryFr::from_u64(1),
            BlsDoryFr::from_u64(2),
        ];
        let literals = [
            BlsDoryFr::from_u64(101),
            BlsDoryFr::from_u64(103),
            BlsDoryFr::from_u64(107),
        ];
        let hybrid_spec = BlsDoryIndexArtifactSpec {
            literal_scalar_count: literals.len() as u64,
            ..spec(8)
        };
        let mut writer =
            BlsDoryIndexArtifactWriter::create(&directory.0, hybrid_spec, dictionary.clone())
                .unwrap();
        assert!(matches!(
            writer.write_codes(&[1]),
            Err(BlsDoryIndexArtifactError::InvalidArtifact)
        ));
        writer.write_scalars(&literals[..2]).unwrap();
        writer.write_scalars(&literals[2..]).unwrap();
        writer.write_codes(&[0, 1, 2, 1, 0]).unwrap();
        assert!(matches!(
            writer.write_scalars(&[BlsDoryFr::one()]),
            Err(BlsDoryIndexArtifactError::InvalidArtifact)
        ));
        let artifact = writer.finish().unwrap();
        let path = artifact.path().to_path_buf();
        let mut decoded = Vec::new();
        artifact
            .for_each_scalar(|scalar| {
                decoded.push(scalar);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            decoded,
            literals
                .into_iter()
                .chain([0usize, 1, 2, 1, 0].map(|code| dictionary[code]))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            artifact_file_bytes(hybrid_spec, dictionary.len()).unwrap()
        );
        drop(artifact);
        assert!(!path.exists());
    }

    #[test]
    fn indexed_artifact_rejects_invalid_dictionary_codes_and_incomplete_writes() {
        let directory = TestDirectory::create();
        assert!(matches!(
            BlsDoryIndexArtifactWriter::create(&directory.0, spec(2), vec![BlsDoryFr::from_u64(1)]),
            Err(BlsDoryIndexArtifactError::InvalidSpec)
        ));
        let mut writer = BlsDoryIndexArtifactWriter::create(
            &directory.0,
            spec(2),
            vec![BlsDoryFr::zero(), BlsDoryFr::one()],
        )
        .unwrap();
        assert!(matches!(
            writer.write_codes(&[2]),
            Err(BlsDoryIndexArtifactError::InvalidArtifact)
        ));
        writer.write_codes(&[1]).unwrap();
        assert!(matches!(
            writer.finish(),
            Err(BlsDoryIndexArtifactError::InvalidArtifact)
        ));
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn indexed_artifact_rejects_dictionary_corruption_truncation_and_forged_codes() {
        let directory = TestDirectory::create();
        let dictionary = vec![BlsDoryFr::zero(), BlsDoryFr::one()];

        let mut writer =
            BlsDoryIndexArtifactWriter::create(&directory.0, spec(2), dictionary.clone()).unwrap();
        writer.write_codes(&[0, 1]).unwrap();
        let artifact = writer.finish().unwrap();
        let path = artifact.path().to_path_buf();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(ARTIFACT_HEADER_BYTES as u64))
            .unwrap();
        file.write_all(&[1]).unwrap();
        file.flush().unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryIndexArtifactError::Authentication)
        ));
        drop(artifact);
        assert!(!path.exists());

        let mut writer =
            BlsDoryIndexArtifactWriter::create(&directory.0, spec(2), dictionary.clone()).unwrap();
        writer.write_codes(&[0, 1]).unwrap();
        let artifact = writer.finish().unwrap();
        let path = artifact.path().to_path_buf();
        let length = std::fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(length - 1)
            .unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryIndexArtifactError::InvalidArtifact)
        ));
        drop(artifact);
        assert!(!path.exists());

        let hybrid_spec = BlsDoryIndexArtifactSpec {
            literal_scalar_count: 1,
            ..spec(2)
        };
        let mut writer = BlsDoryIndexArtifactWriter::create(
            &directory.0,
            hybrid_spec,
            vec![BlsDoryFr::zero(), BlsDoryFr::one()],
        )
        .unwrap();
        writer.write_scalars(&[BlsDoryFr::one()]).unwrap();
        writer.write_codes(&[0]).unwrap();
        let artifact = writer.finish().unwrap();
        let path = artifact.path().to_path_buf();
        let mut bytes = std::fs::read(&path).unwrap();
        let literal_offset = ARTIFACT_HEADER_BYTES + 2 * ARTIFACT_SCALAR_BYTES;
        bytes[literal_offset..literal_offset + ARTIFACT_SCALAR_BYTES].fill(0xff);
        let digest_offset = bytes.len() - ARTIFACT_DIGEST_BYTES;
        let mut hasher = blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN);
        hasher.update(&bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(hasher.finalize().as_bytes());
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryIndexArtifactError::InvalidScalar)
        ));
        drop(artifact);
        assert!(!path.exists());

        let mut writer =
            BlsDoryIndexArtifactWriter::create(&directory.0, spec(2), dictionary).unwrap();
        writer.write_codes(&[0, 1]).unwrap();
        let artifact = writer.finish().unwrap();
        let path = artifact.path().to_path_buf();
        let mut bytes = std::fs::read(&path).unwrap();
        let code_offset = ARTIFACT_HEADER_BYTES + 2 * ARTIFACT_SCALAR_BYTES;
        bytes[code_offset] = 2;
        let digest_offset = bytes.len() - ARTIFACT_DIGEST_BYTES;
        let mut hasher = blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN);
        hasher.update(&bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(hasher.finalize().as_bytes());
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryIndexArtifactError::InvalidArtifact)
        ));
        drop(artifact);
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }
}
