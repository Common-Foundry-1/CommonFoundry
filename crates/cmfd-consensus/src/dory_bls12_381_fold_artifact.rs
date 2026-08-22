//! Self-authenticating scratch artifacts for BLS12-381 polynomial folds.
//!
//! These files are prover-local capabilities. Their metadata and digest never
//! enter Fiat-Shamir. A read, decode, length, or digest failure aborts the proof
//! attempt; callers must not retry from an unauthenticated or dense fallback.

use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use dory_pcs::primitives::{
    DoryDeserialize, DorySerialize,
    arithmetic::Field,
    serialization::{Compress, Validate},
};
use same_file::Handle;
use thiserror::Error;

use crate::dory_bls12_381_prototype::BlsDoryFr;

const ARTIFACT_MAGIC: [u8; 8] = *b"CFDBLSF2";
const ARTIFACT_VERSION: u16 = 2;
const ARTIFACT_HEADER_BYTES: usize = 100;
const ARTIFACT_DIGEST_BYTES: usize = 32;
const ARTIFACT_SCALAR_BYTES: usize = 32;
const ARTIFACT_HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryFoldArtifact/v2";
static ARTIFACT_NONCE: AtomicU64 = AtomicU64::new(1);

/// A fold retains only the current decoded scalar pair plus one 32-byte buffer.
pub const BLS_DORY_FOLD_ARTIFACT_MAX_WORKING_SCALARS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryFoldArtifactSpec {
    pub context_digest: [u8; 32],
    pub table_index: u32,
    pub generation: u32,
    /// Logical power-of-two table length, including the implicit zero tail.
    pub scalar_count: u64,
    /// Canonically stored prefix length. Remaining logical scalars are zero.
    pub explicit_scalar_count: u64,
    pub parent_digest: [u8; 32],
}

impl BlsDoryFoldArtifactSpec {
    fn validate(self) -> Result<(), BlsDoryFoldArtifactError> {
        if self.context_digest == [0; 32]
            || self.parent_digest == [0; 32]
            || self.generation == 0
            || self.scalar_count == 0
            || !self.scalar_count.is_power_of_two()
            || self.explicit_scalar_count == 0
            || self.explicit_scalar_count > self.scalar_count
        {
            return Err(BlsDoryFoldArtifactError::InvalidSpec);
        }
        artifact_file_bytes(self.scalar_count)?;
        Ok(())
    }

    fn encode(self) -> Result<[u8; ARTIFACT_HEADER_BYTES], BlsDoryFoldArtifactError> {
        self.validate()?;
        let mut header = [0u8; ARTIFACT_HEADER_BYTES];
        header[..8].copy_from_slice(&ARTIFACT_MAGIC);
        header[8..10].copy_from_slice(&ARTIFACT_VERSION.to_le_bytes());
        header[12..44].copy_from_slice(&self.context_digest);
        header[44..48].copy_from_slice(&self.table_index.to_le_bytes());
        header[48..52].copy_from_slice(&self.generation.to_le_bytes());
        header[52..60].copy_from_slice(&self.scalar_count.to_le_bytes());
        header[60..68].copy_from_slice(&self.explicit_scalar_count.to_le_bytes());
        header[68..100].copy_from_slice(&self.parent_digest);
        Ok(header)
    }
}

#[derive(Debug, Error)]
pub enum BlsDoryFoldArtifactError {
    #[error("invalid BLS Dory fold artifact specification")]
    InvalidSpec,
    #[error("BLS Dory fold artifact has invalid length or framing")]
    InvalidArtifact,
    #[error("BLS Dory fold artifact contains a non-canonical scalar")]
    InvalidScalar,
    #[error("BLS Dory fold artifact authentication failed")]
    Authentication,
    #[error("BLS Dory fold artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub struct BlsDoryFoldArtifactWriter {
    path: Option<PathBuf>,
    file: Option<File>,
    spec: BlsDoryFoldArtifactSpec,
    hasher: blake3::Hasher,
    written: u64,
}

impl BlsDoryFoldArtifactWriter {
    pub fn create(
        scratch_directory: &Path,
        spec: BlsDoryFoldArtifactSpec,
    ) -> Result<Self, BlsDoryFoldArtifactError> {
        spec.validate()?;
        if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
            return Err(BlsDoryFoldArtifactError::InvalidSpec);
        }
        let nonce = ARTIFACT_NONCE.fetch_add(1, Ordering::Relaxed);
        let context = hex::encode(&spec.context_digest[..8]);
        let path = scratch_directory.join(format!(
            "cmfd-dory-fold-{context}-{}-{}-{}-{nonce}.tmp",
            spec.table_index,
            spec.generation,
            std::process::id(),
        ));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        let header = spec.encode()?;
        file.write_all(&header)?;
        let mut hasher = blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN);
        hasher.update(&header);
        Ok(Self {
            path: Some(path),
            file: Some(file),
            spec,
            hasher,
            written: 0,
        })
    }

    pub fn write_scalar(&mut self, scalar: &BlsDoryFr) -> Result<(), BlsDoryFoldArtifactError> {
        if self.written >= self.spec.explicit_scalar_count {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let encoded = encode_scalar(scalar)?;
        self.file_mut()?.write_all(&encoded)?;
        self.hasher.update(&encoded);
        self.written += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<BlsDoryFoldArtifact, BlsDoryFoldArtifactError> {
        if self.written != self.spec.explicit_scalar_count {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let digest = *self.hasher.finalize().as_bytes();
        let file = self.file_mut()?;
        file.write_all(&digest)?;
        file.flush()?;
        file.sync_all()?;
        if file.metadata()?.len() != artifact_file_bytes(self.spec.explicit_scalar_count)? {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let file = self
            .file
            .take()
            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)?;
        let path = self
            .path
            .take()
            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)?;
        Ok(BlsDoryFoldArtifact {
            path,
            file,
            spec: self.spec,
            digest,
        })
    }

    fn file_mut(&mut self) -> Result<&mut File, BlsDoryFoldArtifactError> {
        self.file
            .as_mut()
            .ok_or(BlsDoryFoldArtifactError::InvalidArtifact)
    }
}

impl Drop for BlsDoryFoldArtifactWriter {
    fn drop(&mut self) {
        if let (Some(path), Some(file)) = (&self.path, &self.file) {
            remove_if_owned(path, file);
        }
    }
}

pub struct BlsDoryFoldArtifact {
    path: PathBuf,
    file: File,
    spec: BlsDoryFoldArtifactSpec,
    digest: [u8; 32],
}

impl BlsDoryFoldArtifact {
    #[must_use]
    pub const fn spec(&self) -> BlsDoryFoldArtifactSpec {
        self.spec
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn for_each_scalar(
        &self,
        mut visitor: impl FnMut(BlsDoryFr) -> Result<(), BlsDoryFoldArtifactError>,
    ) -> Result<(), BlsDoryFoldArtifactError> {
        self.validate_live_file(|reader, hasher| {
            let mut encoded = [0u8; ARTIFACT_SCALAR_BYTES];
            for _ in 0..self.spec.explicit_scalar_count {
                reader.read_exact(&mut encoded)?;
                hasher.update(&encoded);
                visitor(decode_scalar(encoded)?)?;
            }
            Ok(())
        })
    }

    pub fn for_each_pair(
        &self,
        mut visitor: impl FnMut(BlsDoryFr, BlsDoryFr) -> Result<(), BlsDoryFoldArtifactError>,
    ) -> Result<(), BlsDoryFoldArtifactError> {
        if self.spec.scalar_count < 2 {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
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
        consume: impl FnOnce(&mut File, &mut blake3::Hasher) -> Result<(), BlsDoryFoldArtifactError>,
    ) -> Result<(), BlsDoryFoldArtifactError> {
        let expected_len = artifact_file_bytes(self.spec.explicit_scalar_count)?;
        if self.file.metadata()?.len() != expected_len {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        let mut reader = self.file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; ARTIFACT_HEADER_BYTES];
        reader.read_exact(&mut header)?;
        if header != self.spec.encode()? {
            return Err(BlsDoryFoldArtifactError::Authentication);
        }
        let mut hasher = blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN);
        hasher.update(&header);
        consume(&mut reader, &mut hasher)?;
        let mut stored_digest = [0u8; ARTIFACT_DIGEST_BYTES];
        reader.read_exact(&mut stored_digest)?;
        if stored_digest != self.digest || stored_digest != *hasher.finalize().as_bytes() {
            return Err(BlsDoryFoldArtifactError::Authentication);
        }
        let mut trailing = [0u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(BlsDoryFoldArtifactError::InvalidArtifact);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BlsDoryFoldArtifact {
    fn drop(&mut self) {
        remove_if_owned(&self.path, &self.file);
    }
}

fn artifact_file_bytes(scalar_count: u64) -> Result<u64, BlsDoryFoldArtifactError> {
    scalar_count
        .checked_mul(ARTIFACT_SCALAR_BYTES as u64)
        .and_then(|bytes| bytes.checked_add(ARTIFACT_HEADER_BYTES as u64))
        .and_then(|bytes| bytes.checked_add(ARTIFACT_DIGEST_BYTES as u64))
        .ok_or(BlsDoryFoldArtifactError::InvalidSpec)
}

fn encode_scalar(scalar: &BlsDoryFr) -> Result<[u8; 32], BlsDoryFoldArtifactError> {
    let mut encoded = Vec::with_capacity(ARTIFACT_SCALAR_BYTES);
    scalar
        .serialize_compressed(&mut encoded)
        .map_err(|_| BlsDoryFoldArtifactError::InvalidScalar)?;
    encoded
        .try_into()
        .map_err(|_| BlsDoryFoldArtifactError::InvalidScalar)
}

fn decode_scalar(encoded: [u8; 32]) -> Result<BlsDoryFr, BlsDoryFoldArtifactError> {
    let mut reader = Cursor::new(encoded.as_slice());
    let scalar = BlsDoryFr::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)
        .map_err(|_| BlsDoryFoldArtifactError::InvalidScalar)?;
    if reader.position() != ARTIFACT_SCALAR_BYTES as u64 {
        return Err(BlsDoryFoldArtifactError::InvalidScalar);
    }
    Ok(scalar)
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
    use dory_pcs::primitives::arithmetic::Field;

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-fold-test-{}-{nonce}",
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

    fn spec(count: u64) -> BlsDoryFoldArtifactSpec {
        BlsDoryFoldArtifactSpec {
            context_digest: [3; 32],
            table_index: 7,
            generation: 2,
            scalar_count: count,
            explicit_scalar_count: count,
            parent_digest: [9; 32],
        }
    }

    fn artifact(
        directory: &Path,
        values: &[BlsDoryFr],
    ) -> Result<BlsDoryFoldArtifact, BlsDoryFoldArtifactError> {
        let mut writer = BlsDoryFoldArtifactWriter::create(
            directory,
            spec(u64::try_from(values.len()).unwrap()),
        )?;
        for value in values {
            writer.write_scalar(value)?;
        }
        writer.finish()
    }

    #[test]
    fn artifact_round_trips_pairs_and_cleans_on_drop() {
        let directory = TestDirectory::create();
        let values = (0..8)
            .map(|index| BlsDoryFr::from_u64(index * 17 + 5))
            .collect::<Vec<_>>();
        let artifact = artifact(&directory.0, &values).unwrap();
        let path = artifact.path().to_path_buf();
        let mut decoded = Vec::new();
        artifact
            .for_each_pair(|lower, upper| {
                decoded.push(lower);
                decoded.push(upper);
                Ok(())
            })
            .unwrap();
        assert_eq!(decoded, values);
        assert_eq!(BLS_DORY_FOLD_ARTIFACT_MAX_WORKING_SCALARS, 2);
        drop(artifact);
        assert!(!path.exists());
    }

    #[test]
    fn implicit_zero_suffix_is_not_stored_and_odd_prefix_pairs_with_zero() {
        let directory = TestDirectory::create();
        let mut sparse_spec = spec(8);
        sparse_spec.explicit_scalar_count = 3;
        let values = [
            BlsDoryFr::from_u64(5),
            BlsDoryFr::from_u64(7),
            BlsDoryFr::from_u64(11),
        ];
        let mut writer = BlsDoryFoldArtifactWriter::create(&directory.0, sparse_spec).unwrap();
        for value in &values {
            writer.write_scalar(value).unwrap();
        }
        let artifact = writer.finish().unwrap();
        assert_eq!(artifact.spec().scalar_count, 8);
        assert_eq!(artifact.spec().explicit_scalar_count, 3);
        assert_eq!(
            std::fs::metadata(artifact.path()).unwrap().len(),
            artifact_file_bytes(3).unwrap()
        );
        let mut pairs = Vec::new();
        artifact
            .for_each_pair(|lower, upper| {
                pairs.push((lower, upper));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            pairs,
            vec![(values[0], values[1]), (values[2], BlsDoryFr::zero())]
        );
    }

    #[test]
    fn corruption_and_length_changes_fail_authentication() {
        let directory = TestDirectory::create();
        let values = (0..4)
            .map(|index| BlsDoryFr::from_u64(index + 1))
            .collect::<Vec<_>>();
        let artifact = artifact(&directory.0, &values).unwrap();
        let mut mutation = OpenOptions::new()
            .write(true)
            .open(artifact.path())
            .unwrap();
        let footer_offset = artifact_file_bytes(values.len() as u64).unwrap() - 1;
        mutation.seek(SeekFrom::Start(footer_offset)).unwrap();
        mutation.write_all(&[0x5a]).unwrap();
        mutation.flush().unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryFoldArtifactError::Authentication)
        ));
        mutation.set_len(footer_offset).unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryFoldArtifactError::InvalidArtifact)
        ));
        mutation
            .set_len(artifact_file_bytes(values.len() as u64).unwrap() + 1)
            .unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryFoldArtifactError::InvalidArtifact)
        ));
    }

    #[test]
    fn noncanonical_scalars_fail_before_value_exposure() {
        let directory = TestDirectory::create();
        let artifact = artifact(&directory.0, &[BlsDoryFr::one(), BlsDoryFr::from_u64(2)]).unwrap();
        let mut mutation = OpenOptions::new()
            .write(true)
            .open(artifact.path())
            .unwrap();
        mutation
            .seek(SeekFrom::Start(ARTIFACT_HEADER_BYTES as u64))
            .unwrap();
        mutation.write_all(&[0xff; ARTIFACT_SCALAR_BYTES]).unwrap();
        mutation.flush().unwrap();
        assert!(matches!(
            artifact.for_each_scalar(|_| Ok(())),
            Err(BlsDoryFoldArtifactError::InvalidScalar)
        ));
    }

    #[test]
    fn incomplete_writer_and_invalid_specs_publish_nothing() {
        let directory = TestDirectory::create();
        assert!(matches!(
            BlsDoryFoldArtifactWriter::create(&directory.0, spec(3)),
            Err(BlsDoryFoldArtifactError::InvalidSpec)
        ));
        let mut invalid_explicit = spec(4);
        invalid_explicit.explicit_scalar_count = 5;
        assert!(matches!(
            BlsDoryFoldArtifactWriter::create(&directory.0, invalid_explicit),
            Err(BlsDoryFoldArtifactError::InvalidSpec)
        ));
        let mut writer = BlsDoryFoldArtifactWriter::create(&directory.0, spec(4)).unwrap();
        writer.write_scalar(&BlsDoryFr::one()).unwrap();
        let path = writer.path.as_ref().unwrap().clone();
        drop(writer);
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }
}
