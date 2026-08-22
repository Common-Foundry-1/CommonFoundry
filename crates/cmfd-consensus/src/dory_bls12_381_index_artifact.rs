//! Self-authenticating indexed scalar artifacts for BLS12-381 polynomials.
//!
//! A small canonical dictionary is stored once and each explicit coefficient
//! is represented by one authenticated byte. These prover-local files never
//! enter Fiat-Shamir; any framing, code, digest, or I/O failure aborts proving.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use dory_pcs::primitives::{DorySerialize, arithmetic::Field};
use same_file::Handle;
use thiserror::Error;

use crate::dory_bls12_381_prototype::BlsDoryFr;

const ARTIFACT_MAGIC: [u8; 8] = *b"CFDBLSI1";
const ARTIFACT_VERSION: u16 = 1;
const ARTIFACT_HEADER_BYTES: usize = 64;
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
}

impl BlsDoryIndexArtifactSpec {
    fn validate(self, dictionary_len: usize) -> Result<(), BlsDoryIndexArtifactError> {
        if self.context_digest == [0; 32]
            || self.scalar_count == 0
            || !self.scalar_count.is_power_of_two()
            || self.explicit_scalar_count == 0
            || self.explicit_scalar_count > self.scalar_count
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
        header[60..62].copy_from_slice(&dictionary_len.to_le_bytes());
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
    file: Option<BufWriter<File>>,
    spec: BlsDoryIndexArtifactSpec,
    dictionary: Vec<BlsDoryFr>,
    hasher: blake3::Hasher,
    written: u64,
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
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
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
            written: 0,
        })
    }

    pub fn write_codes(&mut self, codes: &[u8]) -> Result<(), BlsDoryIndexArtifactError> {
        let count =
            u64::try_from(codes.len()).map_err(|_| BlsDoryIndexArtifactError::InvalidArtifact)?;
        let next_written = self
            .written
            .checked_add(count)
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?;
        if next_written > self.spec.explicit_scalar_count
            || codes
                .iter()
                .any(|code| usize::from(*code) >= self.dictionary.len())
        {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        self.file_mut()?.write_all(codes)?;
        self.hasher.update(codes);
        self.written = next_written;
        Ok(())
    }

    pub fn finish(mut self) -> Result<BlsDoryIndexArtifact, BlsDoryIndexArtifactError> {
        if self.written != self.spec.explicit_scalar_count {
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
        let file = self
            .file
            .as_ref()
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?
            .get_ref()
            .try_clone()?;
        let path = self
            .path
            .take()
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)?;
        drop(self.file.take());
        Ok(BlsDoryIndexArtifact {
            path,
            file,
            spec: self.spec,
            dictionary: std::mem::take(&mut self.dictionary),
            digest,
        })
    }

    fn file_mut(&mut self) -> Result<&mut BufWriter<File>, BlsDoryIndexArtifactError> {
        self.file
            .as_mut()
            .ok_or(BlsDoryIndexArtifactError::InvalidArtifact)
    }
}

impl Drop for BlsDoryIndexArtifactWriter {
    fn drop(&mut self) {
        if let (Some(path), Some(file)) = (&self.path, &self.file) {
            remove_if_owned(path, file.get_ref());
        }
    }
}

pub struct BlsDoryIndexArtifact {
    path: PathBuf,
    file: File,
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
            let mut remaining = self.spec.explicit_scalar_count;
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
            &mut BufReader<File>,
            &mut blake3::Hasher,
        ) -> Result<(), BlsDoryIndexArtifactError>,
    ) -> Result<(), BlsDoryIndexArtifactError> {
        let expected_len = artifact_file_bytes(self.spec, self.dictionary.len())?;
        if self.file.metadata()?.len() != expected_len {
            return Err(BlsDoryIndexArtifactError::InvalidArtifact);
        }
        let mut file = self.file.try_clone()?;
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
        remove_if_owned(&self.path, &self.file);
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
    (ARTIFACT_HEADER_BYTES as u64)
        .checked_add(dictionary_bytes)
        .and_then(|bytes| bytes.checked_add(spec.explicit_scalar_count))
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
