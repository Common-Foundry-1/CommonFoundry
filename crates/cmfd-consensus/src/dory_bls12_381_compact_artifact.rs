//! Self-authenticating mixed-width coefficient artifacts for BLS12-381.
//!
//! A canonical prefix is represented by little-endian 64-bit words. A bound
//! selector mask determines whether each word is decoded as `i64` or `u64`.
//! The remaining explicit coefficients are authenticated one-byte indices into
//! a small scalar dictionary. Prover-local metadata never enters Fiat-Shamir;
//! any framing, scalar, code, digest, or I/O failure aborts proving.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dory_pcs::primitives::{DorySerialize, arithmetic::Field};
use same_file::Handle;
use thiserror::Error;

use crate::dory_bls12_381_prototype::BlsDoryFr;

const ARTIFACT_MAGIC: [u8; 8] = *b"CFDBLSC1";
const ARTIFACT_VERSION: u16 = 1;
const ARTIFACT_HEADER_BYTES: usize = 88;
const ARTIFACT_DIGEST_BYTES: usize = 32;
const ARTIFACT_SCALAR_BYTES: usize = 32;
const ARTIFACT_WORD_BYTES: usize = 8;
const ARTIFACT_IO_BUFFER_BYTES: usize = 1024 * 1024;
const ARTIFACT_HASH_DOMAIN: &str = "CommonFoundry/ForgeMatrix/BlsDoryCompactArtifact/v1";
const MAPPED_ARTIFACT_HASH_DOMAIN: &str =
    "CommonFoundry/ForgeMatrix/BlsDoryMappedCompactArtifact/v1";
static ARTIFACT_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(crate) enum CompactEncodedScalar {
    Word { value: u64, signed: bool },
    Code(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsDoryCompactArtifactSpec {
    pub context_digest: [u8; 32],
    /// Logical power-of-two coefficient count including the implicit zero tail.
    pub scalar_count: u64,
    /// Canonically stored coefficient prefix length.
    pub explicit_scalar_count: u64,
    /// Initial coefficients stored as canonical 64-bit words.
    pub word_scalar_count: u64,
    /// Coefficients per selector in the word prefix.
    pub word_group_len: u64,
    /// Bit `i` is one when selector `i` decodes its words as signed `i64`.
    pub signed_word_selectors: u64,
}

impl BlsDoryCompactArtifactSpec {
    pub(crate) fn encoded_bytes(
        self,
        dictionary_len: usize,
    ) -> Result<u64, BlsDoryCompactArtifactError> {
        self.validate(dictionary_len)?;
        artifact_file_bytes(self, dictionary_len)
    }

    fn validate(self, dictionary_len: usize) -> Result<(), BlsDoryCompactArtifactError> {
        let word_selectors = self
            .word_scalar_count
            .checked_div(self.word_group_len.max(1))
            .ok_or(BlsDoryCompactArtifactError::InvalidSpec)?;
        let allowed_mask = if word_selectors == 64 {
            u64::MAX
        } else if word_selectors < 64 {
            1u64.checked_shl(word_selectors as u32)
                .and_then(|value| value.checked_sub(1))
                .ok_or(BlsDoryCompactArtifactError::InvalidSpec)?
        } else {
            return Err(BlsDoryCompactArtifactError::InvalidSpec);
        };
        if self.context_digest == [0; 32]
            || self.scalar_count == 0
            || !self.scalar_count.is_power_of_two()
            || self.explicit_scalar_count == 0
            || self.explicit_scalar_count > self.scalar_count
            || self.word_scalar_count == 0
            || self.word_scalar_count > self.explicit_scalar_count
            || self.word_group_len == 0
            || !self.word_group_len.is_power_of_two()
            || !self.word_scalar_count.is_multiple_of(self.word_group_len)
            || word_selectors == 0
            || self.signed_word_selectors & !allowed_mask != 0
            || !(1..=256).contains(&dictionary_len)
        {
            return Err(BlsDoryCompactArtifactError::InvalidSpec);
        }
        artifact_file_bytes(self, dictionary_len)?;
        Ok(())
    }

    fn encode(
        self,
        dictionary_len: usize,
    ) -> Result<[u8; ARTIFACT_HEADER_BYTES], BlsDoryCompactArtifactError> {
        self.validate(dictionary_len)?;
        let dictionary_len =
            u16::try_from(dictionary_len).map_err(|_| BlsDoryCompactArtifactError::InvalidSpec)?;
        let mut header = [0u8; ARTIFACT_HEADER_BYTES];
        header[..8].copy_from_slice(&ARTIFACT_MAGIC);
        header[8..10].copy_from_slice(&ARTIFACT_VERSION.to_le_bytes());
        header[12..44].copy_from_slice(&self.context_digest);
        header[44..52].copy_from_slice(&self.scalar_count.to_le_bytes());
        header[52..60].copy_from_slice(&self.explicit_scalar_count.to_le_bytes());
        header[60..68].copy_from_slice(&self.word_scalar_count.to_le_bytes());
        header[68..76].copy_from_slice(&self.word_group_len.to_le_bytes());
        header[76..84].copy_from_slice(&self.signed_word_selectors.to_le_bytes());
        header[84..86].copy_from_slice(&dictionary_len.to_le_bytes());
        Ok(header)
    }
}

#[derive(Debug, Error)]
pub enum BlsDoryCompactArtifactError {
    #[error("invalid compact BLS Dory artifact specification")]
    InvalidSpec,
    #[error("compact BLS Dory artifact has invalid length, dictionary, or code")]
    InvalidArtifact,
    #[error("compact BLS Dory artifact scalar encoding failed")]
    InvalidScalar,
    #[error("compact BLS Dory artifact authentication failed")]
    Authentication,
    #[error("compact BLS Dory artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub struct BlsDoryCompactArtifactWriter {
    path: Option<PathBuf>,
    file: Option<BufWriter<File>>,
    spec: BlsDoryCompactArtifactSpec,
    dictionary: Vec<BlsDoryFr>,
    hasher: blake3::Hasher,
    written_words: u64,
    written_codes: u64,
}

impl BlsDoryCompactArtifactWriter {
    pub fn create(
        scratch_directory: &Path,
        spec: BlsDoryCompactArtifactSpec,
        dictionary: Vec<BlsDoryFr>,
    ) -> Result<Self, BlsDoryCompactArtifactError> {
        validate_dictionary(&dictionary)?;
        spec.validate(dictionary.len())?;
        if !scratch_directory.is_absolute() || !scratch_directory.is_dir() {
            return Err(BlsDoryCompactArtifactError::InvalidSpec);
        }
        let nonce = ARTIFACT_NONCE.fetch_add(1, Ordering::Relaxed);
        let context = hex::encode(&spec.context_digest[..8]);
        let path = scratch_directory.join(format!(
            "cmfd-dory-compact-{context}-{}-{nonce}.tmp",
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
            written_words: 0,
            written_codes: 0,
        })
    }

    pub fn write_words(&mut self, words: &[u64]) -> Result<(), BlsDoryCompactArtifactError> {
        if self.written_codes != 0 {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        let count =
            u64::try_from(words.len()).map_err(|_| BlsDoryCompactArtifactError::InvalidArtifact)?;
        let next = self
            .written_words
            .checked_add(count)
            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
        if next > self.spec.word_scalar_count {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        let words_per_chunk = ARTIFACT_IO_BUFFER_BYTES / ARTIFACT_WORD_BYTES;
        let mut encoded = Vec::with_capacity(ARTIFACT_IO_BUFFER_BYTES);
        for chunk in words.chunks(words_per_chunk) {
            encoded.clear();
            for word in chunk {
                encoded.extend_from_slice(&word.to_le_bytes());
            }
            self.file_mut()?.write_all(&encoded)?;
            self.hasher.update(&encoded);
        }
        self.written_words = next;
        Ok(())
    }

    pub fn write_codes(&mut self, codes: &[u8]) -> Result<(), BlsDoryCompactArtifactError> {
        if self.written_words != self.spec.word_scalar_count {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        let count =
            u64::try_from(codes.len()).map_err(|_| BlsDoryCompactArtifactError::InvalidArtifact)?;
        let next = self
            .written_codes
            .checked_add(count)
            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
        let code_count = self
            .spec
            .explicit_scalar_count
            .checked_sub(self.spec.word_scalar_count)
            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
        if next > code_count
            || codes
                .iter()
                .any(|code| usize::from(*code) >= self.dictionary.len())
        {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        self.file_mut()?.write_all(codes)?;
        self.hasher.update(codes);
        self.written_codes = next;
        Ok(())
    }

    pub fn finish(mut self) -> Result<BlsDoryCompactArtifact, BlsDoryCompactArtifactError> {
        let expected_codes = self
            .spec
            .explicit_scalar_count
            .checked_sub(self.spec.word_scalar_count)
            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
        if self.written_words != self.spec.word_scalar_count || self.written_codes != expected_codes
        {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        let digest = *self.hasher.finalize().as_bytes();
        let expected_len = artifact_file_bytes(self.spec, self.dictionary.len())?;
        let file = self.file_mut()?;
        file.write_all(&digest)?;
        file.flush()?;
        file.get_ref().sync_all()?;
        if file.get_ref().metadata()?.len() != expected_len {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        let file = self
            .file
            .as_ref()
            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?
            .get_ref()
            .try_clone()?;
        let path = self
            .path
            .take()
            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
        drop(self.file.take());
        Ok(BlsDoryCompactArtifact {
            path,
            file,
            spec: self.spec,
            dictionary: std::mem::take(&mut self.dictionary),
            digest,
        })
    }

    fn file_mut(&mut self) -> Result<&mut BufWriter<File>, BlsDoryCompactArtifactError> {
        self.file
            .as_mut()
            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)
    }
}

impl Drop for BlsDoryCompactArtifactWriter {
    fn drop(&mut self) {
        if let (Some(path), Some(file)) = (&self.path, &self.file) {
            remove_if_owned(path, file.get_ref());
        }
    }
}

pub struct BlsDoryCompactArtifact {
    path: PathBuf,
    file: File,
    spec: BlsDoryCompactArtifactSpec,
    dictionary: Vec<BlsDoryFr>,
    digest: [u8; 32],
}

/// An authenticated coefficient view derived from a compact source without a
/// second coefficient file. A prefix maps to zero; each remaining canonical
/// source digit selects the corresponding scalar in `mapped_dictionary`.
pub struct BlsDoryMappedCompactArtifact {
    source: Arc<BlsDoryCompactArtifact>,
    zero_prefix_count: u64,
    mapped_dictionary: Vec<BlsDoryFr>,
    digest: [u8; 32],
}

impl BlsDoryCompactArtifact {
    #[must_use]
    pub const fn spec(&self) -> BlsDoryCompactArtifactSpec {
        self.spec
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn dictionary(&self) -> &[BlsDoryFr] {
        &self.dictionary
    }

    pub fn for_each_scalar(
        &self,
        mut visitor: impl FnMut(BlsDoryFr) -> Result<(), BlsDoryCompactArtifactError>,
    ) -> Result<(), BlsDoryCompactArtifactError> {
        self.for_each_encoded_scalar(|_index, encoded| {
            let scalar = match encoded {
                CompactEncodedScalar::Word { value, signed } => {
                    if signed {
                        BlsDoryFr::from_i64(i64::from_le_bytes(value.to_le_bytes()))
                    } else {
                        BlsDoryFr::from_u64(value)
                    }
                }
                CompactEncodedScalar::Code(code) => self
                    .dictionary
                    .get(usize::from(code))
                    .copied()
                    .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?,
            };
            visitor(scalar)
        })
    }

    pub(crate) fn for_each_encoded_scalar(
        &self,
        mut visitor: impl FnMut(u64, CompactEncodedScalar) -> Result<(), BlsDoryCompactArtifactError>,
    ) -> Result<(), BlsDoryCompactArtifactError> {
        self.validate_live_file(|reader, hasher| {
            let words_per_chunk = ARTIFACT_IO_BUFFER_BYTES / ARTIFACT_WORD_BYTES;
            let mut encoded_words = vec![0u8; ARTIFACT_IO_BUFFER_BYTES];
            let mut remaining = self.spec.word_scalar_count;
            let mut word_index = 0u64;
            while remaining > 0 {
                let words = usize::try_from(remaining.min(words_per_chunk as u64))
                    .map_err(|_| BlsDoryCompactArtifactError::InvalidArtifact)?;
                let bytes = words
                    .checked_mul(ARTIFACT_WORD_BYTES)
                    .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
                reader.read_exact(&mut encoded_words[..bytes])?;
                hasher.update(&encoded_words[..bytes]);
                for encoded in encoded_words[..bytes].chunks_exact(ARTIFACT_WORD_BYTES) {
                    let bytes: [u8; ARTIFACT_WORD_BYTES] = encoded
                        .try_into()
                        .map_err(|_| BlsDoryCompactArtifactError::InvalidArtifact)?;
                    let selector = word_index / self.spec.word_group_len;
                    let signed = self.spec.signed_word_selectors & (1u64 << selector) != 0;
                    visitor(
                        word_index,
                        CompactEncodedScalar::Word {
                            value: u64::from_le_bytes(bytes),
                            signed,
                        },
                    )?;
                    word_index += 1;
                }
                remaining -= words as u64;
            }
            let mut remaining = self
                .spec
                .explicit_scalar_count
                .checked_sub(self.spec.word_scalar_count)
                .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
            let mut codes = vec![0u8; ARTIFACT_IO_BUFFER_BYTES];
            while remaining > 0 {
                let take = usize::try_from(remaining.min(codes.len() as u64))
                    .map_err(|_| BlsDoryCompactArtifactError::InvalidArtifact)?;
                reader.read_exact(&mut codes[..take])?;
                hasher.update(&codes[..take]);
                for code in &codes[..take] {
                    let index = self
                        .spec
                        .explicit_scalar_count
                        .checked_sub(remaining)
                        .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?;
                    visitor(index, CompactEncodedScalar::Code(*code))?;
                    remaining -= 1;
                }
            }
            Ok(())
        })
    }

    pub fn for_each_pair(
        &self,
        mut visitor: impl FnMut(BlsDoryFr, BlsDoryFr) -> Result<(), BlsDoryCompactArtifactError>,
    ) -> Result<(), BlsDoryCompactArtifactError> {
        if self.spec.scalar_count < 2 {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
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
        ) -> Result<(), BlsDoryCompactArtifactError>,
    ) -> Result<(), BlsDoryCompactArtifactError> {
        if self.file.metadata()?.len() != artifact_file_bytes(self.spec, self.dictionary.len())? {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::with_capacity(ARTIFACT_IO_BUFFER_BYTES, file);
        let mut header = [0u8; ARTIFACT_HEADER_BYTES];
        reader.read_exact(&mut header)?;
        if header != self.spec.encode(self.dictionary.len())? {
            return Err(BlsDoryCompactArtifactError::Authentication);
        }
        let mut hasher = blake3::Hasher::new_derive_key(ARTIFACT_HASH_DOMAIN);
        hasher.update(&header);
        for scalar in &self.dictionary {
            let expected = encode_scalar(scalar)?;
            let mut encoded = [0u8; ARTIFACT_SCALAR_BYTES];
            reader.read_exact(&mut encoded)?;
            hasher.update(&encoded);
            if encoded != expected {
                return Err(BlsDoryCompactArtifactError::Authentication);
            }
        }
        consume(&mut reader, &mut hasher)?;
        let mut stored_digest = [0u8; ARTIFACT_DIGEST_BYTES];
        reader.read_exact(&mut stored_digest)?;
        if stored_digest != self.digest || stored_digest != *hasher.finalize().as_bytes() {
            return Err(BlsDoryCompactArtifactError::Authentication);
        }
        let mut trailing = [0u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl BlsDoryMappedCompactArtifact {
    pub(crate) fn new(
        source: Arc<BlsDoryCompactArtifact>,
        zero_prefix_count: u64,
        mapped_dictionary: Vec<BlsDoryFr>,
    ) -> Result<Self, BlsDoryCompactArtifactError> {
        if zero_prefix_count == 0
            || zero_prefix_count > source.spec.word_scalar_count
            || zero_prefix_count >= source.spec.explicit_scalar_count
            || mapped_dictionary.len() != source.dictionary.len()
            || source
                .dictionary
                .iter()
                .enumerate()
                .any(|(index, scalar)| *scalar != BlsDoryFr::from_u64(index as u64))
            || mapped_dictionary
                .iter()
                .enumerate()
                .any(|(index, scalar)| mapped_dictionary[..index].contains(scalar))
        {
            return Err(BlsDoryCompactArtifactError::InvalidSpec);
        }
        let mut hasher = blake3::Hasher::new_derive_key(MAPPED_ARTIFACT_HASH_DOMAIN);
        hasher.update(&source.digest);
        hasher.update(&zero_prefix_count.to_le_bytes());
        hasher.update(&(mapped_dictionary.len() as u64).to_le_bytes());
        for scalar in &mapped_dictionary {
            hasher.update(&encode_scalar(scalar)?);
        }
        let digest = *hasher.finalize().as_bytes();
        Ok(Self {
            source,
            zero_prefix_count,
            mapped_dictionary,
            digest,
        })
    }

    #[must_use]
    pub fn scalar_count(&self) -> u64 {
        self.source.spec.scalar_count
    }

    #[must_use]
    pub fn explicit_scalar_count(&self) -> u64 {
        self.source.spec.explicit_scalar_count
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn source(&self) -> &Arc<BlsDoryCompactArtifact> {
        &self.source
    }

    pub(crate) const fn zero_prefix_count(&self) -> u64 {
        self.zero_prefix_count
    }

    pub(crate) fn mapped_dictionary(&self) -> &[BlsDoryFr] {
        &self.mapped_dictionary
    }

    pub fn for_each_scalar(
        &self,
        mut visitor: impl FnMut(BlsDoryFr) -> Result<(), BlsDoryCompactArtifactError>,
    ) -> Result<(), BlsDoryCompactArtifactError> {
        self.source
            .for_each_encoded_scalar(|index, encoded| visitor(self.mapped_scalar(index, encoded)?))
    }

    pub fn for_each_chunk(
        &self,
        chunk_scalars: usize,
        mut visitor: impl FnMut(&[BlsDoryFr]) -> Result<(), BlsDoryCompactArtifactError>,
    ) -> Result<(), BlsDoryCompactArtifactError> {
        if chunk_scalars == 0 {
            return Err(BlsDoryCompactArtifactError::InvalidSpec);
        }
        let capacity = chunk_scalars.min(
            usize::try_from(self.explicit_scalar_count())
                .map_err(|_| BlsDoryCompactArtifactError::InvalidSpec)?,
        );
        let mut chunk = Vec::with_capacity(capacity);
        self.source.for_each_encoded_scalar(|index, encoded| {
            chunk.push(self.mapped_scalar(index, encoded)?);
            if chunk.len() == chunk_scalars {
                visitor(&chunk)?;
                chunk.clear();
            }
            Ok(())
        })?;
        if !chunk.is_empty() {
            visitor(&chunk)?;
        }
        Ok(())
    }

    pub fn for_each_pair(
        &self,
        mut visitor: impl FnMut(BlsDoryFr, BlsDoryFr) -> Result<(), BlsDoryCompactArtifactError>,
    ) -> Result<(), BlsDoryCompactArtifactError> {
        if self.scalar_count() < 2 {
            return Err(BlsDoryCompactArtifactError::InvalidArtifact);
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

    fn mapped_scalar(
        &self,
        index: u64,
        encoded: CompactEncodedScalar,
    ) -> Result<BlsDoryFr, BlsDoryCompactArtifactError> {
        if index < self.zero_prefix_count {
            return Ok(BlsDoryFr::zero());
        }
        let digit = match encoded {
            CompactEncodedScalar::Word {
                value,
                signed: false,
            } => usize::try_from(value)
                .ok()
                .filter(|digit| *digit < self.mapped_dictionary.len())
                .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)?,
            CompactEncodedScalar::Word { signed: true, .. } => {
                return Err(BlsDoryCompactArtifactError::InvalidArtifact);
            }
            CompactEncodedScalar::Code(code) => usize::from(code),
        };
        self.mapped_dictionary
            .get(digit)
            .copied()
            .ok_or(BlsDoryCompactArtifactError::InvalidArtifact)
    }

    #[cfg(test)]
    pub(crate) fn source_path(&self) -> &Path {
        &self.source.path
    }
}

impl Drop for BlsDoryCompactArtifact {
    fn drop(&mut self) {
        remove_if_owned(&self.path, &self.file);
    }
}

fn validate_dictionary(dictionary: &[BlsDoryFr]) -> Result<(), BlsDoryCompactArtifactError> {
    if dictionary.is_empty()
        || dictionary.len() > 256
        || dictionary[0] != BlsDoryFr::zero()
        || dictionary
            .iter()
            .enumerate()
            .any(|(index, scalar)| dictionary[..index].contains(scalar))
    {
        return Err(BlsDoryCompactArtifactError::InvalidSpec);
    }
    Ok(())
}

fn artifact_file_bytes(
    spec: BlsDoryCompactArtifactSpec,
    dictionary_len: usize,
) -> Result<u64, BlsDoryCompactArtifactError> {
    let dictionary_bytes = u64::try_from(dictionary_len)
        .ok()
        .and_then(|count| count.checked_mul(ARTIFACT_SCALAR_BYTES as u64))
        .ok_or(BlsDoryCompactArtifactError::InvalidSpec)?;
    let word_bytes = spec
        .word_scalar_count
        .checked_mul(ARTIFACT_WORD_BYTES as u64)
        .ok_or(BlsDoryCompactArtifactError::InvalidSpec)?;
    let code_bytes = spec
        .explicit_scalar_count
        .checked_sub(spec.word_scalar_count)
        .ok_or(BlsDoryCompactArtifactError::InvalidSpec)?;
    (ARTIFACT_HEADER_BYTES as u64)
        .checked_add(dictionary_bytes)
        .and_then(|bytes| bytes.checked_add(word_bytes))
        .and_then(|bytes| bytes.checked_add(code_bytes))
        .and_then(|bytes| bytes.checked_add(ARTIFACT_DIGEST_BYTES as u64))
        .ok_or(BlsDoryCompactArtifactError::InvalidSpec)
}

fn encode_scalar(scalar: &BlsDoryFr) -> Result<[u8; 32], BlsDoryCompactArtifactError> {
    let mut encoded = Vec::with_capacity(ARTIFACT_SCALAR_BYTES);
    scalar
        .serialize_compressed(&mut encoded)
        .map_err(|_| BlsDoryCompactArtifactError::InvalidScalar)?;
    encoded
        .try_into()
        .map_err(|_| BlsDoryCompactArtifactError::InvalidScalar)
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

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-compact-test-{}-{nonce}",
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

    fn spec() -> BlsDoryCompactArtifactSpec {
        BlsDoryCompactArtifactSpec {
            context_digest: [3; 32],
            scalar_count: 32,
            explicit_scalar_count: 24,
            word_scalar_count: 16,
            word_group_len: 4,
            signed_word_selectors: 0b0101,
        }
    }

    #[test]
    fn signed_unsigned_words_and_codes_round_trip_and_clean_up() {
        let directory = TestDirectory::create();
        let words = [
            (-9i64) as u64,
            (-1i64) as u64,
            0,
            7,
            11,
            u64::MAX,
            19,
            23,
            (-31i64) as u64,
            37,
            (-41i64) as u64,
            43,
            47,
            53,
            59,
            61,
        ];
        let codes = [0, 1, 2, 3, 3, 2, 1, 0];
        let dictionary = (0..4).map(BlsDoryFr::from_u64).collect::<Vec<_>>();
        let mut writer =
            BlsDoryCompactArtifactWriter::create(&directory.0, spec(), dictionary).unwrap();
        writer.write_words(&words).unwrap();
        writer.write_codes(&codes).unwrap();
        let artifact = writer.finish().unwrap();
        let path = artifact.path().to_path_buf();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            spec().encoded_bytes(4).unwrap()
        );
        let mut decoded = Vec::new();
        artifact
            .for_each_scalar(|scalar| {
                decoded.push(scalar);
                Ok(())
            })
            .unwrap();
        let expected_words = words.iter().enumerate().map(|(index, word)| {
            if spec().signed_word_selectors & (1 << (index / 4)) != 0 {
                BlsDoryFr::from_i64(*word as i64)
            } else {
                BlsDoryFr::from_u64(*word)
            }
        });
        let expected = expected_words
            .chain(
                codes
                    .iter()
                    .map(|code| BlsDoryFr::from_u64(u64::from(*code))),
            )
            .collect::<Vec<_>>();
        assert_eq!(decoded, expected);
        drop(artifact);
        assert!(!path.exists());
    }

    #[test]
    fn corruption_truncation_invalid_codes_and_incomplete_writes_fail_closed() {
        let directory = TestDirectory::create();
        let dictionary = (0..4).map(BlsDoryFr::from_u64).collect::<Vec<_>>();
        let mut writer =
            BlsDoryCompactArtifactWriter::create(&directory.0, spec(), dictionary).unwrap();
        assert!(writer.write_codes(&[0]).is_err());
        writer.write_words(&[0; 16]).unwrap();
        assert!(writer.write_codes(&[4]).is_err());
        drop(writer);
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);

        for truncate in [false, true] {
            let dictionary = (0..4).map(BlsDoryFr::from_u64).collect::<Vec<_>>();
            let mut writer =
                BlsDoryCompactArtifactWriter::create(&directory.0, spec(), dictionary).unwrap();
            writer.write_words(&[0; 16]).unwrap();
            writer.write_codes(&[0; 8]).unwrap();
            let artifact = writer.finish().unwrap();
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
            assert!(artifact.for_each_scalar(|_| Ok(())).is_err());
            drop(artifact);
            assert!(!path.exists());
        }
    }

    #[test]
    fn mapped_view_reuses_authenticated_codes_binds_mapping_and_owns_lifetime() {
        let directory = TestDirectory::create();
        let words = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 1, 2, 3];
        let codes = [3, 2, 1, 0, 0, 1, 2, 3];
        let dictionary = (0..4).map(BlsDoryFr::from_u64).collect::<Vec<_>>();
        let mut writer =
            BlsDoryCompactArtifactWriter::create(&directory.0, spec(), dictionary).unwrap();
        writer.write_words(&words).unwrap();
        writer.write_codes(&codes).unwrap();
        let source = Arc::new(writer.finish().unwrap());
        let path = source.path().to_path_buf();
        let mapped_dictionary = (100..104).map(BlsDoryFr::from_u64).collect::<Vec<_>>();
        let mapped =
            BlsDoryMappedCompactArtifact::new(Arc::clone(&source), 12, mapped_dictionary.clone())
                .unwrap();
        let other_mapping = BlsDoryMappedCompactArtifact::new(
            Arc::clone(&source),
            12,
            (200..204).map(BlsDoryFr::from_u64).collect(),
        )
        .unwrap();
        assert_ne!(mapped.digest(), other_mapping.digest());

        let mut decoded = Vec::new();
        mapped
            .for_each_chunk(5, |chunk| {
                decoded.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        let expected = std::iter::repeat_n(BlsDoryFr::zero(), 12)
            .chain([0usize, 1, 2, 3, 3, 2, 1, 0, 0, 1, 2, 3].map(|digit| mapped_dictionary[digit]))
            .collect::<Vec<_>>();
        assert_eq!(decoded, expected);
        assert!(
            BlsDoryMappedCompactArtifact::new(Arc::clone(&source), 12, vec![BlsDoryFr::one(); 4],)
                .is_err()
        );
        let signed_suffix =
            BlsDoryMappedCompactArtifact::new(Arc::clone(&source), 8, mapped_dictionary).unwrap();
        assert!(signed_suffix.for_each_scalar(|_| Ok(())).is_err());

        let code_offset = ARTIFACT_HEADER_BYTES as u64
            + 4 * ARTIFACT_SCALAR_BYTES as u64
            + 16 * ARTIFACT_WORD_BYTES as u64;
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(code_offset)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.flush().unwrap();
        assert!(mapped.for_each_scalar(|_| Ok(())).is_err());

        drop(file);
        drop(mapped);
        drop(other_mapping);
        drop(signed_suffix);
        assert!(path.exists());
        drop(source);
        assert!(!path.exists());
    }
}
