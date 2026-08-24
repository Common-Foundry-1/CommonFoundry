//! Identity-bound streaming combiner for production Dory V3 model contributions.
//!
//! The public entry point accepts only the ordered contribution paths and one
//! create-new output path. It authenticates every full-length input before the
//! combine pass, computes the canonical bytewise sum modulo 251 from retained
//! file handles, and authenticates all inputs and the reopened output again
//! before success. The JSON report is operational output, not a signed ceremony
//! artifact and not a substitute for the ceremony transcript.
//!
//! The ceremony's filesystem boundary remains mandatory: run in a local,
//! operator-owned directory that no untrusted account can write. On Windows,
//! the production entry point enforces a fixed local volume and a simple parent
//! DACL owned by the current user with every allow ACE limited to that user,
//! LocalSystem, or Administrators. The create-new output therefore inherits no
//! untrusted read grant before its protected final DACL is applied. Retained
//! identities and repeated hashes
//! detect replacement and ordinary mutation; pathname checks cannot make a
//! hostile shared directory race-proof. A crash may leave an unconfirmed
//! partial create-new output for operator quarantine.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use same_file::Handle as SameFileHandle;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    MAX_MODEL_BYTE,
    dory_v3_suite::{DORY_V3_BATCH, DORY_V3_DIMENSION, DORY_V3_LAYERS, Digest32},
};

const MIN_CONTRIBUTIONS: usize = 3;
const MAX_CONTRIBUTIONS: usize = 16;
const FROZEN_PRODUCTION_CONTRIBUTION_BYTES: u64 = 6_442_975_232;
const COMBINE_CHUNK_BYTES: usize = 1_048_576;

/// One ordered input authenticated before, during, and after combination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionDoryV3ModelCombinerInputReport {
    pub path: PathBuf,
    pub contribution_bytes: u64,
    pub contribution_blake3: Digest32,
    pub contribution_sha256: Digest32,
}

/// What the platform could durably synchronize for the create-new output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionDoryV3ModelCombinerDurability {
    /// Both the file contents and its containing directory were synchronized.
    FileAndParentDirectorySynced,
    /// Windows could not open or flush the parent directory on this filesystem.
    FileSyncedParentDirectorySyncUnsupportedOnWindows,
    /// Windows denied opening or flushing the parent directory.
    FileSyncedParentDirectorySyncAccessDeniedOnWindows,
    /// The target is neither Unix nor Windows, so directory sync is unsupported.
    FileSyncedParentDirectorySyncUnsupportedOnPlatform,
}

/// Audit-only report emitted after all retained identities and bytes reproduce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionDoryV3ModelCombinerReport {
    pub ordered_inputs: Vec<ProductionDoryV3ModelCombinerInputReport>,
    pub output: PathBuf,
    pub output_bytes: u64,
    pub output_blake3: Digest32,
    pub output_sha256: Digest32,
    pub bytes_processed: u64,
    pub elapsed_micros: u64,
    pub durability: ProductionDoryV3ModelCombinerDurability,
}

/// Fail-closed errors from the production streaming modular combiner.
#[derive(Debug, Error)]
pub enum ProductionDoryV3ModelCombinerError {
    #[error("expected 3 through 16 ordered contribution files, received {actual}")]
    ContributionCount { actual: usize },
    #[error("the compiled production contribution geometry overflowed")]
    GeometryOverflow,
    #[error("the compiled contribution geometry is not the frozen production geometry")]
    ProductionGeometryMismatch,
    #[error("refusing to run because the output path already exists: {0}")]
    OutputExists(PathBuf),
    #[error("artifact path is not an ordinary local file path: {0}")]
    InvalidArtifactPath(PathBuf),
    #[error("artifact parent is not a real, local, non-reparse directory: {0}")]
    UnsafeArtifactParent(PathBuf),
    #[error("artifact parent does not have an operator-owned Windows DACL: {0}")]
    UnsafeWindowsParentDacl(PathBuf),
    #[error("failed to inspect Windows parent security at {path}: {source}")]
    InspectWindowsParentSecurity {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect output path {path}: {source}")]
    InspectOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect contribution {index} at {path}: {source}")]
    InspectInput {
        index: usize,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open contribution {index} at {path}: {source}")]
    OpenInput {
        index: usize,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("contribution {index} is not a regular, non-link file: {path}")]
    InputNotRegular { index: usize, path: PathBuf },
    #[error("contribution {index} is a reparse point and is rejected: {path}")]
    InputReparsePoint { index: usize, path: PathBuf },
    #[error("contribution {index} has an unexpected hard-link count of {links}: {path}")]
    InputHardLinks {
        index: usize,
        path: PathBuf,
        links: u64,
    },
    #[error(
        "contribution {index} length mismatch at {path}: expected {expected} bytes, observed {actual}"
    )]
    InputLength {
        index: usize,
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error("contribution {index} path was replaced after opening: {path}")]
    InputIdentityMismatch { index: usize, path: PathBuf },
    #[error(
        "contribution {second_index} aliases ordered contribution {first_index}: {second_path}"
    )]
    DuplicateInput {
        first_index: usize,
        second_index: usize,
        second_path: PathBuf,
    },
    #[error("failed to read contribution {index} at {path}: {source}")]
    ReadInput {
        index: usize,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("contribution {index} byte {value} at offset {offset} exceeds 250: {path}")]
    InputByteOutOfRange {
        index: usize,
        path: PathBuf,
        offset: u64,
        value: u8,
    },
    #[error("contribution {index} changed after initial authentication: {path}")]
    InputDigestMismatch { index: usize, path: PathBuf },
    #[error("the checked u32 combination accumulator overflowed")]
    AccumulatorOverflow,
    #[error("combiner byte accounting overflowed")]
    CountOverflow,
    #[error("failed to create new output file {path}: {source}")]
    CreateOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to make the new output private at {path}: {source}")]
    SetOutputPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write new output file {path}: {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to flush new output file {path}: {source}")]
    FlushOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to synchronize new output file {path}: {source}")]
    SyncOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to reopen or read output file {path}: {source}")]
    ReadOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("output path is not a regular, non-link file: {0}")]
    OutputNotRegular(PathBuf),
    #[error("output path is a reparse point and is rejected: {0}")]
    OutputReparsePoint(PathBuf),
    #[error("output path has an unexpected hard-link count of {links}: {path}")]
    OutputHardLinks { path: PathBuf, links: u64 },
    #[error("output path was replaced or no longer names the retained file: {0}")]
    OutputIdentityMismatch(PathBuf),
    #[error("output length mismatch: expected {expected} bytes, observed {actual}")]
    OutputLength { expected: u64, actual: u64 },
    #[error("output byte {value} at offset {offset} exceeds 250")]
    OutputByteOutOfRange { offset: u64, value: u8 },
    #[error("the reopened output differs from the stream that was written")]
    OutputDigestMismatch,
    #[error("failed to synchronize output parent {path}: {source}")]
    SyncParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to remove unconfirmed output {path}: {source}")]
    Cleanup {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy)]
struct CombineGeometry {
    contribution_bytes: u64,
    chunk_bytes: usize,
}

impl CombineGeometry {
    fn production() -> Result<Self, ProductionDoryV3ModelCombinerError> {
        let base_input_bytes = u64::from(DORY_V3_BATCH)
            .checked_mul(u64::from(DORY_V3_DIMENSION))
            .ok_or(ProductionDoryV3ModelCombinerError::GeometryOverflow)?;
        let bytes_per_layer = u64::from(DORY_V3_DIMENSION)
            .checked_mul(u64::from(DORY_V3_DIMENSION))
            .ok_or(ProductionDoryV3ModelCombinerError::GeometryOverflow)?;
        let contribution_bytes = u64::from(DORY_V3_LAYERS)
            .checked_mul(bytes_per_layer)
            .and_then(|weight_bytes| weight_bytes.checked_add(base_input_bytes))
            .ok_or(ProductionDoryV3ModelCombinerError::GeometryOverflow)?;
        let geometry = Self {
            contribution_bytes,
            chunk_bytes: COMBINE_CHUNK_BYTES,
        };
        if contribution_bytes != FROZEN_PRODUCTION_CONTRIBUTION_BYTES
            || MAX_MODEL_BYTE != 250
            || geometry.chunk_bytes == 0
            || geometry.chunk_bytes > COMBINE_CHUNK_BYTES
        {
            return Err(ProductionDoryV3ModelCombinerError::ProductionGeometryMismatch);
        }
        Ok(geometry)
    }

    fn validate(self) -> Result<(), ProductionDoryV3ModelCombinerError> {
        if self.contribution_bytes == 0
            || self.chunk_bytes == 0
            || self.chunk_bytes > COMBINE_CHUNK_BYTES
            || MAX_MODEL_BYTE != 250
        {
            return Err(ProductionDoryV3ModelCombinerError::ProductionGeometryMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileDigest {
    bytes: u64,
    blake3: [u8; 32],
    sha256: [u8; 32],
}

struct AuthenticatedInput {
    index: usize,
    path: PathBuf,
    retained: SameFileHandle,
    initial: FileDigest,
}

trait CombinerIo {
    fn write_output(
        &mut self,
        output_path: &Path,
        output: &mut File,
        bytes: &[u8],
    ) -> std::io::Result<()>;

    fn flush_output(&mut self, output: &mut File) -> std::io::Result<()>;

    fn sync_output(&mut self, output: &File) -> std::io::Result<()>;

    fn after_inputs_authenticated(&mut self, _inputs: &[PathBuf], _output: &Path) {}

    fn after_output_closed(&mut self, _inputs: &[PathBuf], _output: &Path) {}

    fn before_final_input_authentication(&mut self, _inputs: &[PathBuf], _output: &Path) {}
}

struct SystemCombinerIo;

impl CombinerIo for SystemCombinerIo {
    fn write_output(
        &mut self,
        _output_path: &Path,
        output: &mut File,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        output.write_all(bytes)
    }

    fn flush_output(&mut self, output: &mut File) -> std::io::Result<()> {
        output.flush()
    }

    fn sync_output(&mut self, output: &File) -> std::io::Result<()> {
        output.sync_all()
    }
}

/// Combine the ordered full-length production contributions bytewise modulo
/// 251. The order is preserved in the report; the API accepts no caller-owned
/// geometry, seed, digest, root, operator index, or model identity.
pub fn combine_production_dory_v3_model_contributions(
    ordered_contribution_paths: &[PathBuf],
    output_path: &Path,
) -> Result<ProductionDoryV3ModelCombinerReport, ProductionDoryV3ModelCombinerError> {
    if !(MIN_CONTRIBUTIONS..=MAX_CONTRIBUTIONS).contains(&ordered_contribution_paths.len()) {
        return Err(ProductionDoryV3ModelCombinerError::ContributionCount {
            actual: ordered_contribution_paths.len(),
        });
    }
    preflight_combiner_paths(ordered_contribution_paths, output_path)?;
    combine_with_io(
        ordered_contribution_paths,
        output_path,
        CombineGeometry::production()?,
        &mut SystemCombinerIo,
    )
}

fn combine_with_io<I: CombinerIo>(
    ordered_contribution_paths: &[PathBuf],
    output_path: &Path,
    geometry: CombineGeometry,
    io: &mut I,
) -> Result<ProductionDoryV3ModelCombinerReport, ProductionDoryV3ModelCombinerError> {
    geometry.validate()?;
    if !(MIN_CONTRIBUTIONS..=MAX_CONTRIBUTIONS).contains(&ordered_contribution_paths.len()) {
        return Err(ProductionDoryV3ModelCombinerError::ContributionCount {
            actual: ordered_contribution_paths.len(),
        });
    }
    reject_existing_output(output_path)?;

    let started = Instant::now();
    let mut inputs = Vec::with_capacity(ordered_contribution_paths.len());
    for (index, path) in ordered_contribution_paths.iter().enumerate() {
        let input = authenticate_input(index, path, geometry)?;
        if let Some(first) = inputs
            .iter()
            .find(|first: &&AuthenticatedInput| first.retained == input.retained)
        {
            return Err(ProductionDoryV3ModelCombinerError::DuplicateInput {
                first_index: first.index,
                second_index: index,
                second_path: path.clone(),
            });
        }
        inputs.push(input);
    }

    io.after_inputs_authenticated(ordered_contribution_paths, output_path);
    let (mut output_file, mut published) = create_private_output(output_path)?;
    let combination = combine_streams(&inputs, output_path, &mut output_file, geometry, io);
    let combined = match combination {
        Ok(combined) => combined,
        Err(error) => {
            drop(output_file);
            return Err(cleanup_after_error(&mut published, error));
        }
    };
    if let Err(source) = io.flush_output(&mut output_file) {
        drop(output_file);
        let error = ProductionDoryV3ModelCombinerError::FlushOutput {
            path: output_path.to_path_buf(),
            source,
        };
        return Err(cleanup_after_error(&mut published, error));
    }
    if let Err(source) = io.sync_output(&output_file) {
        drop(output_file);
        let error = ProductionDoryV3ModelCombinerError::SyncOutput {
            path: output_path.to_path_buf(),
            source,
        };
        return Err(cleanup_after_error(&mut published, error));
    }
    drop(output_file);
    io.after_output_closed(ordered_contribution_paths, output_path);

    let completion = (|| {
        io.before_final_input_authentication(ordered_contribution_paths, output_path);
        for input in &inputs {
            reauthenticate_input(input, geometry)?;
        }
        // Output verification is deliberately last among the long byte passes.
        // Otherwise an in-place mutation during final input authentication could
        // leave a successful report carrying stale output hashes.
        let verified_output = verify_output(&published, geometry)?;
        if verified_output != combined.output {
            return Err(ProductionDoryV3ModelCombinerError::OutputDigestMismatch);
        }
        let durability = sync_output_parent(output_path)?;
        let ordered_inputs = inputs
            .iter()
            .map(|input| ProductionDoryV3ModelCombinerInputReport {
                path: input.path.clone(),
                contribution_bytes: input.initial.bytes,
                contribution_blake3: Digest32::new(input.initial.blake3),
                contribution_sha256: Digest32::new(input.initial.sha256),
            })
            .collect();
        Ok(ProductionDoryV3ModelCombinerReport {
            ordered_inputs,
            output: output_path.to_path_buf(),
            output_bytes: verified_output.bytes,
            output_blake3: Digest32::new(verified_output.blake3),
            output_sha256: Digest32::new(verified_output.sha256),
            bytes_processed: combined.bytes_processed,
            elapsed_micros: elapsed_micros(started.elapsed()),
            durability,
        })
    })();
    finish_or_cleanup_output(&mut published, completion)
}

struct CombinedStream {
    output: FileDigest,
    bytes_processed: u64,
}

fn combine_streams<I: CombinerIo>(
    inputs: &[AuthenticatedInput],
    output_path: &Path,
    output_file: &mut File,
    geometry: CombineGeometry,
    io: &mut I,
) -> Result<CombinedStream, ProductionDoryV3ModelCombinerError> {
    let mut readers = Vec::with_capacity(inputs.len());
    for input in inputs {
        readers.push(clone_input_reader(input)?);
    }
    let mut input_blake3 = (0..inputs.len())
        .map(|_| blake3::Hasher::new())
        .collect::<Vec<_>>();
    let mut input_sha256 = (0..inputs.len()).map(|_| Sha256::new()).collect::<Vec<_>>();
    let mut input_buffer = vec![0_u8; geometry.chunk_bytes];
    let mut accumulator = vec![0_u32; geometry.chunk_bytes];
    let mut output_buffer = vec![0_u8; geometry.chunk_bytes];
    let mut output_blake3 = blake3::Hasher::new();
    let mut output_sha256 = Sha256::new();
    let mut offset = 0_u64;

    while offset < geometry.contribution_bytes {
        let remaining = geometry.contribution_bytes - offset;
        let chunk_len = usize::try_from(remaining.min(geometry.chunk_bytes as u64))
            .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?;
        accumulator[..chunk_len].fill(0);
        for (input_index, (input, reader)) in inputs.iter().zip(&mut readers).enumerate() {
            let input_path = index_path(input.index, &input.path);
            read_exact_input_chunk(reader, input_path, &mut input_buffer[..chunk_len], offset)?;
            validate_input_range(input_path, &input_buffer[..chunk_len], offset)?;
            input_blake3[input_index].update(&input_buffer[..chunk_len]);
            input_sha256[input_index].update(&input_buffer[..chunk_len]);
            for (sum, value) in accumulator[..chunk_len]
                .iter_mut()
                .zip(&input_buffer[..chunk_len])
            {
                *sum = sum
                    .checked_add(u32::from(*value))
                    .ok_or(ProductionDoryV3ModelCombinerError::AccumulatorOverflow)?;
            }
        }
        for (target, sum) in output_buffer[..chunk_len]
            .iter_mut()
            .zip(&accumulator[..chunk_len])
        {
            *target = u8::try_from(*sum % 251)
                .map_err(|_| ProductionDoryV3ModelCombinerError::AccumulatorOverflow)?;
        }
        io.write_output(output_path, output_file, &output_buffer[..chunk_len])
            .map_err(|source| ProductionDoryV3ModelCombinerError::WriteOutput {
                path: output_path.to_path_buf(),
                source,
            })?;
        output_blake3.update(&output_buffer[..chunk_len]);
        output_sha256.update(&output_buffer[..chunk_len]);
        offset = offset
            .checked_add(
                u64::try_from(chunk_len)
                    .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?,
            )
            .ok_or(ProductionDoryV3ModelCombinerError::CountOverflow)?;
    }

    for (input_index, (input, reader)) in inputs.iter().zip(&mut readers).enumerate() {
        require_input_eof(
            reader,
            index_path(input.index, &input.path),
            geometry.contribution_bytes,
        )?;
        let observed = FileDigest {
            bytes: geometry.contribution_bytes,
            blake3: *input_blake3[input_index].finalize().as_bytes(),
            sha256: finalize_sha256(input_sha256[input_index].clone()),
        };
        if observed != input.initial {
            return Err(ProductionDoryV3ModelCombinerError::InputDigestMismatch {
                index: input.index,
                path: input.path.clone(),
            });
        }
    }

    Ok(CombinedStream {
        output: FileDigest {
            bytes: offset,
            blake3: *output_blake3.finalize().as_bytes(),
            sha256: finalize_sha256(output_sha256),
        },
        bytes_processed: offset,
    })
}

fn authenticate_input(
    index: usize,
    path: &Path,
    geometry: CombineGeometry,
) -> Result<AuthenticatedInput, ProductionDoryV3ModelCombinerError> {
    validate_input_path_type(index, path)?;
    let file = OpenOptions::new().read(true).open(path).map_err(|source| {
        ProductionDoryV3ModelCombinerError::OpenInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    let metadata =
        file.metadata()
            .map_err(|source| ProductionDoryV3ModelCombinerError::InspectInput {
                index,
                path: path.to_path_buf(),
                source,
            })?;
    validate_open_input_metadata(index, path, &file, &metadata, geometry)?;
    let retained = SameFileHandle::from_file(file).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    ensure_input_path_identity(index, path, &retained)?;
    let initial = scan_input(index, path, &retained, geometry)?;
    ensure_input_path_identity(index, path, &retained)?;
    Ok(AuthenticatedInput {
        index,
        path: path.to_path_buf(),
        retained,
        initial,
    })
}

fn reauthenticate_input(
    input: &AuthenticatedInput,
    geometry: CombineGeometry,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    ensure_input_path_identity(input.index, &input.path, &input.retained)?;
    let observed = scan_input(input.index, &input.path, &input.retained, geometry)?;
    if observed != input.initial {
        return Err(ProductionDoryV3ModelCombinerError::InputDigestMismatch {
            index: input.index,
            path: input.path.clone(),
        });
    }
    ensure_input_path_identity(input.index, &input.path, &input.retained)
}

fn scan_input(
    index: usize,
    path: &Path,
    retained: &SameFileHandle,
    geometry: CombineGeometry,
) -> Result<FileDigest, ProductionDoryV3ModelCombinerError> {
    let metadata = retained.as_file().metadata().map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    validate_open_input_metadata(index, path, retained.as_file(), &metadata, geometry)?;
    let mut reader = retained.as_file().try_clone().map_err(|source| {
        ProductionDoryV3ModelCombinerError::ReadInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|source| {
        ProductionDoryV3ModelCombinerError::ReadInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    let mut buffer = vec![0_u8; geometry.chunk_bytes];
    let mut offset = 0_u64;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    while offset < geometry.contribution_bytes {
        let remaining = geometry.contribution_bytes - offset;
        let chunk_len = usize::try_from(remaining.min(geometry.chunk_bytes as u64))
            .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?;
        read_exact_input_chunk(
            &mut reader,
            index_path(index, path),
            &mut buffer[..chunk_len],
            offset,
        )?;
        validate_input_range(index_path(index, path), &buffer[..chunk_len], offset)?;
        blake3.update(&buffer[..chunk_len]);
        sha256.update(&buffer[..chunk_len]);
        offset = offset
            .checked_add(
                u64::try_from(chunk_len)
                    .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?,
            )
            .ok_or(ProductionDoryV3ModelCombinerError::CountOverflow)?;
    }
    require_input_eof(
        &mut reader,
        index_path(index, path),
        geometry.contribution_bytes,
    )?;
    Ok(FileDigest {
        bytes: offset,
        blake3: *blake3.finalize().as_bytes(),
        sha256: finalize_sha256(sha256),
    })
}

fn index_path<'a>(index: usize, path: &'a Path) -> InputPath<'a> {
    InputPath { index, path }
}

#[derive(Clone, Copy)]
struct InputPath<'a> {
    index: usize,
    path: &'a Path,
}

fn clone_input_reader(
    input: &AuthenticatedInput,
) -> Result<File, ProductionDoryV3ModelCombinerError> {
    let mut reader = input.retained.as_file().try_clone().map_err(|source| {
        ProductionDoryV3ModelCombinerError::ReadInput {
            index: input.index,
            path: input.path.clone(),
            source,
        }
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|source| {
        ProductionDoryV3ModelCombinerError::ReadInput {
            index: input.index,
            path: input.path.clone(),
            source,
        }
    })?;
    Ok(reader)
}

fn read_exact_input_chunk(
    reader: &mut File,
    input: InputPath<'_>,
    mut target: &mut [u8],
    offset: u64,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    let original_len = target.len();
    let mut observed = 0_u64;
    while !target.is_empty() {
        let read = reader.read(target).map_err(|source| {
            ProductionDoryV3ModelCombinerError::ReadInput {
                index: input.index,
                path: input.path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            return Err(ProductionDoryV3ModelCombinerError::InputLength {
                index: input.index,
                path: input.path.to_path_buf(),
                expected: offset.saturating_add(original_len as u64),
                actual: offset.saturating_add(observed),
            });
        }
        observed = observed
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?,
            )
            .ok_or(ProductionDoryV3ModelCombinerError::CountOverflow)?;
        target = &mut target[read..];
    }
    Ok(())
}

fn validate_input_range(
    input: InputPath<'_>,
    bytes: &[u8],
    offset: u64,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    if let Some((position, value)) = bytes
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value > MAX_MODEL_BYTE)
    {
        let position = u64::try_from(position)
            .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?;
        return Err(ProductionDoryV3ModelCombinerError::InputByteOutOfRange {
            index: input.index,
            path: input.path.to_path_buf(),
            offset: offset
                .checked_add(position)
                .ok_or(ProductionDoryV3ModelCombinerError::CountOverflow)?,
            value,
        });
    }
    Ok(())
}

fn require_input_eof(
    reader: &mut File,
    input: InputPath<'_>,
    expected: u64,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).map_err(|source| {
        ProductionDoryV3ModelCombinerError::ReadInput {
            index: input.index,
            path: input.path.to_path_buf(),
            source,
        }
    })? != 0
    {
        return Err(ProductionDoryV3ModelCombinerError::InputLength {
            index: input.index,
            path: input.path.to_path_buf(),
            expected,
            actual: expected.saturating_add(1),
        });
    }
    let actual = reader
        .metadata()
        .map_err(|source| ProductionDoryV3ModelCombinerError::InspectInput {
            index: input.index,
            path: input.path.to_path_buf(),
            source,
        })?
        .len();
    if actual != expected {
        return Err(ProductionDoryV3ModelCombinerError::InputLength {
            index: input.index,
            path: input.path.to_path_buf(),
            expected,
            actual,
        });
    }
    Ok(())
}

fn verify_output(
    output: &PublishedCombinedOutput,
    geometry: CombineGeometry,
) -> Result<FileDigest, ProductionDoryV3ModelCombinerError> {
    let mut reader = output.reopen_reader()?;
    let initial_length = reader
        .metadata()
        .map_err(|source| ProductionDoryV3ModelCombinerError::ReadOutput {
            path: output.path.clone(),
            source,
        })?
        .len();
    if initial_length != geometry.contribution_bytes {
        return Err(ProductionDoryV3ModelCombinerError::OutputLength {
            expected: geometry.contribution_bytes,
            actual: initial_length,
        });
    }
    let mut buffer = vec![0_u8; geometry.chunk_bytes];
    let mut offset = 0_u64;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    while offset < geometry.contribution_bytes {
        let remaining = geometry.contribution_bytes - offset;
        let chunk_len = usize::try_from(remaining.min(geometry.chunk_bytes as u64))
            .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?;
        read_exact_output_chunk(&mut reader, &output.path, &mut buffer[..chunk_len], offset)?;
        if let Some((position, value)) = buffer[..chunk_len]
            .iter()
            .copied()
            .enumerate()
            .find(|(_, value)| *value > MAX_MODEL_BYTE)
        {
            let position = u64::try_from(position)
                .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?;
            return Err(ProductionDoryV3ModelCombinerError::OutputByteOutOfRange {
                offset: offset
                    .checked_add(position)
                    .ok_or(ProductionDoryV3ModelCombinerError::CountOverflow)?,
                value,
            });
        }
        blake3.update(&buffer[..chunk_len]);
        sha256.update(&buffer[..chunk_len]);
        offset = offset
            .checked_add(
                u64::try_from(chunk_len)
                    .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?,
            )
            .ok_or(ProductionDoryV3ModelCombinerError::CountOverflow)?;
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).map_err(|source| {
        ProductionDoryV3ModelCombinerError::ReadOutput {
            path: output.path.clone(),
            source,
        }
    })? != 0
    {
        return Err(ProductionDoryV3ModelCombinerError::OutputLength {
            expected: geometry.contribution_bytes,
            actual: geometry.contribution_bytes.saturating_add(1),
        });
    }
    let final_length = reader
        .metadata()
        .map_err(|source| ProductionDoryV3ModelCombinerError::ReadOutput {
            path: output.path.clone(),
            source,
        })?
        .len();
    if final_length != geometry.contribution_bytes {
        return Err(ProductionDoryV3ModelCombinerError::OutputLength {
            expected: geometry.contribution_bytes,
            actual: final_length,
        });
    }
    Ok(FileDigest {
        bytes: offset,
        blake3: *blake3.finalize().as_bytes(),
        sha256: finalize_sha256(sha256),
    })
}

fn read_exact_output_chunk(
    reader: &mut File,
    path: &Path,
    mut target: &mut [u8],
    offset: u64,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    let original_len = target.len();
    let mut observed = 0_u64;
    while !target.is_empty() {
        let read = reader.read(target).map_err(|source| {
            ProductionDoryV3ModelCombinerError::ReadOutput {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            return Err(ProductionDoryV3ModelCombinerError::OutputLength {
                expected: offset.saturating_add(original_len as u64),
                actual: offset.saturating_add(observed),
            });
        }
        observed = observed
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| ProductionDoryV3ModelCombinerError::CountOverflow)?,
            )
            .ok_or(ProductionDoryV3ModelCombinerError::CountOverflow)?;
        target = &mut target[read..];
    }
    Ok(())
}

fn create_private_output(
    output_path: &Path,
) -> Result<(File, PublishedCombinedOutput), ProductionDoryV3ModelCombinerError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::{READ_CONTROL, WRITE_DAC},
        };

        options.access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC);
    }
    let file = options.open(output_path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            ProductionDoryV3ModelCombinerError::OutputExists(output_path.to_path_buf())
        } else {
            ProductionDoryV3ModelCombinerError::CreateOutput {
                path: output_path.to_path_buf(),
                source,
            }
        }
    })?;
    let identity_file = match file.try_clone() {
        Ok(retained) => retained,
        Err(source) => {
            // Without retained identity, pathname cleanup could delete a
            // replacement. Leave the file for explicit operator inspection.
            drop(file);
            return Err(ProductionDoryV3ModelCombinerError::CreateOutput {
                path: output_path.to_path_buf(),
                source,
            });
        }
    };
    let retained = match retained_output_identity(identity_file, output_path) {
        Ok(retained) => retained,
        Err(error) => {
            drop(file);
            return Err(error);
        }
    };
    let mut published = PublishedCombinedOutput {
        path: output_path.to_path_buf(),
        retained: Some(retained),
        finished: false,
    };
    if let Err(source) = make_output_private(&file) {
        drop(file);
        let error = ProductionDoryV3ModelCombinerError::SetOutputPermissions {
            path: output_path.to_path_buf(),
            source,
        };
        return Err(cleanup_after_error(&mut published, error));
    }
    Ok((file, published))
}

#[cfg(unix)]
fn make_output_private(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn make_output_private(file: &File) -> std::io::Result<()> {
    set_windows_operator_only_acl(file, windows_sys::Win32::Security::NO_INHERITANCE)
}

#[cfg(not(any(unix, windows)))]
fn make_output_private(_file: &File) -> std::io::Result<()> {
    Ok(())
}

fn preflight_combiner_paths(
    ordered_contribution_paths: &[PathBuf],
    output_path: &Path,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    for path in ordered_contribution_paths {
        preflight_artifact_path(path)?;
    }
    preflight_artifact_path(output_path)
}

fn preflight_artifact_path(path: &Path) -> Result<(), ProductionDoryV3ModelCombinerError> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            ProductionDoryV3ModelCombinerError::InvalidArtifactPath(path.to_path_buf())
        })?;

    #[cfg(windows)]
    if windows_artifact_path_has_disallowed_syntax(path) {
        return Err(ProductionDoryV3ModelCombinerError::InvalidArtifactPath(
            path.to_path_buf(),
        ));
    }

    let _ = file_name;
    let parent = output_parent(path);
    let metadata = fs::symlink_metadata(parent).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectOutput {
            path: parent.to_path_buf(),
            source,
        }
    })?;
    if !metadata.file_type().is_dir() || metadata_is_reparse_point(&metadata) {
        return Err(ProductionDoryV3ModelCombinerError::UnsafeArtifactParent(
            parent.to_path_buf(),
        ));
    }

    #[cfg(windows)]
    {
        if !windows_parent_is_local_fixed(parent).map_err(|source| {
            ProductionDoryV3ModelCombinerError::InspectWindowsParentSecurity {
                path: parent.to_path_buf(),
                source,
            }
        })? {
            return Err(ProductionDoryV3ModelCombinerError::UnsafeArtifactParent(
                parent.to_path_buf(),
            ));
        }
        if !windows_parent_dacl_is_operator_owned(parent).map_err(|source| {
            ProductionDoryV3ModelCombinerError::InspectWindowsParentSecurity {
                path: parent.to_path_buf(),
                source,
            }
        })? {
            return Err(ProductionDoryV3ModelCombinerError::UnsafeWindowsParentDacl(
                parent.to_path_buf(),
            ));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn windows_artifact_path_has_disallowed_syntax(path: &Path) -> bool {
    use std::{os::windows::ffi::OsStrExt as _, path::Component};

    let has_disallowed_component = path.components().any(|component| {
        matches!(component, Component::Normal(name)
            if name.encode_wide().any(|unit| unit == u16::from(b':'))
                || windows_file_name_is_reserved_device(name))
    });
    let has_nonlocal_prefix = matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if !matches!(prefix.kind(), std::path::Prefix::Disk(_)) || !path.is_absolute()
    );
    has_disallowed_component || has_nonlocal_prefix
}

#[cfg(windows)]
fn windows_file_name_is_reserved_device(file_name: &std::ffi::OsStr) -> bool {
    let name = file_name.to_string_lossy();
    let trimmed = name.trim_end_matches([' ', '.']);
    if trimmed.len() != name.len() {
        return true;
    }
    let stem = trimmed.split('.').next().unwrap_or_default();
    if ["CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    let mut characters = stem.chars();
    let prefix = characters.by_ref().take(3).collect::<String>();
    let suffix = characters.collect::<String>();
    (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
        && matches!(
            suffix.as_str(),
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
}

#[cfg(windows)]
fn windows_parent_is_local_fixed(parent: &Path) -> std::io::Result<bool> {
    use std::{os::windows::ffi::OsStrExt as _, path::Component};
    use windows_sys::Win32::{
        Storage::FileSystem::GetDriveTypeW, System::WindowsProgramming::DRIVE_FIXED,
    };

    let canonical = fs::canonicalize(parent)?;
    let drive = match canonical.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            std::path::Prefix::Disk(drive) | std::path::Prefix::VerbatimDisk(drive) => drive,
            _ => return Ok(false),
        },
        _ => return Ok(false),
    };
    let root = std::ffi::OsString::from(format!("{}:\\", char::from(drive)))
        .encode_wide()
        .chain([0])
        .collect::<Vec<_>>();
    // SAFETY: `root` is a NUL-terminated UTF-16 drive-root string.
    Ok(unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED)
}

#[cfg(windows)]
struct WindowsTokenUser {
    storage: Vec<usize>,
}

#[cfg(windows)]
impl WindowsTokenUser {
    fn sid(&self) -> windows_sys::Win32::Security::PSID {
        use windows_sys::Win32::Security::TOKEN_USER;

        // SAFETY: `storage` is word-aligned and was initialized by
        // `GetTokenInformation` for the `TokenUser` information class.
        unsafe { (*(self.storage.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

#[cfg(windows)]
struct WindowsSid {
    storage: Vec<usize>,
}

#[cfg(windows)]
impl WindowsSid {
    fn as_ptr(&self) -> windows_sys::Win32::Security::PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
struct WindowsLocalAllocation(*mut core::ffi::c_void);

#[cfg(windows)]
impl Drop for WindowsLocalAllocation {
    fn drop(&mut self) {
        // SAFETY: the guarded pointer was allocated by a Win32 API documented
        // to require `LocalFree`, and this guard owns that allocation.
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0);
        }
    }
}

#[cfg(windows)]
fn windows_current_user() -> std::io::Result<WindowsTokenUser> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::{GetTokenInformation, TOKEN_QUERY, TokenUser},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut raw_token: HANDLE = std::ptr::null_mut();
    // SAFETY: `raw_token` points to writable handle storage and the pseudo
    // process handle is valid for the duration of the call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful `OpenProcessToken` returned one owned kernel handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut required = 0_u32;
    // SAFETY: the zero-length probe intentionally supplies no output buffer.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let word_bytes = std::mem::size_of::<usize>();
    let required_usize = usize::try_from(required)
        .map_err(|_| std::io::Error::other("token-user buffer length overflow"))?;
    let word_count = required_usize
        .checked_add(word_bytes - 1)
        .and_then(|value| value.checked_div(word_bytes))
        .ok_or_else(|| std::io::Error::other("token-user buffer length overflow"))?;
    let mut storage = vec![0_usize; word_count];
    // SAFETY: `storage` is aligned, writable, and at least `required` bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let user = WindowsTokenUser { storage };
    // SAFETY: the SID pointer is part of the validated token-user buffer.
    if unsafe { windows_sys::Win32::Security::IsValidSid(user.sid()) } == 0 {
        return Err(std::io::Error::other(
            "Windows returned an invalid current-user SID",
        ));
    }
    Ok(user)
}

#[cfg(windows)]
fn windows_well_known_sid(
    kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> std::io::Result<WindowsSid> {
    use windows_sys::Win32::Security::{CreateWellKnownSid, SECURITY_MAX_SID_SIZE};

    let word_bytes = std::mem::size_of::<usize>();
    let mut size = SECURITY_MAX_SID_SIZE;
    let word_count = usize::try_from(size)
        .map_err(|_| std::io::Error::other("well-known SID length overflow"))?
        .div_ceil(word_bytes);
    let mut storage = vec![0_usize; word_count];
    // SAFETY: `storage` is aligned and has `SECURITY_MAX_SID_SIZE` writable bytes.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(WindowsSid { storage })
}

#[cfg(windows)]
fn windows_error_from_status(status: u32) -> std::io::Error {
    std::io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX))
}

#[cfg(windows)]
fn set_windows_operator_only_acl(
    file: &File,
    inheritance: windows_sys::Win32::Security::ACE_FLAGS,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Foundation::{ERROR_SUCCESS, GENERIC_ALL},
        Security::{
            ACL,
            Authorization::{
                EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
                SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
            },
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
    };

    let current = windows_current_user()?;
    let system = windows_well_known_sid(WinLocalSystemSid)?;
    let administrators = windows_well_known_sid(WinBuiltinAdministratorsSid)?;
    let entry = |sid: windows_sys::Win32::Security::PSID| EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let entries = [
        entry(current.sid()),
        entry(system.as_ptr()),
        entry(administrators.as_ptr()),
    ];
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: all three SID buffers outlive this call and `acl` is writable.
    let status = unsafe { SetEntriesInAclW(3, entries.as_ptr(), std::ptr::null(), &mut acl) };
    if status != ERROR_SUCCESS {
        return Err(windows_error_from_status(status));
    }
    if acl.is_null() {
        return Err(std::io::Error::other(
            "Windows returned a null operator-only DACL",
        ));
    }
    let _acl_guard = WindowsLocalAllocation(acl.cast());
    // SAFETY: `file` is a live handle opened with `WRITE_DAC`; `acl` remains
    // owned by `_acl_guard` for the entire call.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(windows_error_from_status(status));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_parent_dacl_is_operator_owned(parent: &Path) -> std::io::Result<bool> {
    use std::os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _};
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, IsValidAcl, IsValidSid,
            OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSID, WinBuiltinAdministratorsSid,
            WinLocalSystemSid,
        },
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        },
        System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
    };

    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(parent)?;
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir() || metadata_is_reparse_point(&metadata) {
        return Ok(false);
    }

    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: the output pointers are writable and `directory` carries
    // `READ_CONTROL`. Win32 owns the returned descriptor until `LocalFree`.
    let status = unsafe {
        GetSecurityInfo(
            directory.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(windows_error_from_status(status));
    }
    let _descriptor_guard = WindowsLocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Ok(false);
    }
    // SAFETY: owner and DACL point into the descriptor returned above.
    if unsafe { IsValidSid(owner) } == 0 || unsafe { IsValidAcl(dacl) } == 0 {
        return Ok(false);
    }

    let current = windows_current_user()?;
    let system = windows_well_known_sid(WinLocalSystemSid)?;
    let administrators = windows_well_known_sid(WinBuiltinAdministratorsSid)?;
    // SAFETY: both SIDs are valid for the lifetime of this comparison.
    if unsafe { EqualSid(owner, current.sid()) } == 0 {
        return Ok(false);
    }
    let allowed_sid = |sid: PSID| {
        // SAFETY: the caller supplies an SID located inside a validated ACL.
        unsafe {
            IsValidSid(sid) != 0
                && (EqualSid(sid, current.sid()) != 0
                    || EqualSid(sid, system.as_ptr()) != 0
                    || EqualSid(sid, administrators.as_ptr()) != 0)
        }
    };
    // SAFETY: `dacl` was validated and remains backed by `_descriptor_guard`.
    let ace_count = unsafe { (*dacl).AceCount };
    let mut trusted_file_inherit_allow = false;
    for index in 0..u32::from(ace_count) {
        let mut raw_ace = std::ptr::null_mut();
        // SAFETY: `index` is within the validated ACL's advertised ACE count.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful `GetAce` returned at least one `ACE_HEADER`.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                if usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                    return Ok(false);
                }
                // SAFETY: size and ACE type establish the basic allowed-ACE layout.
                let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
                // Output creation inherits this DACL before the file's final
                // protected DACL is applied. Reject every untrusted allow ACE,
                // including read-only grants, so no untrusted process can
                // race-open and retain a handle during that short interval.
                if !allowed_sid(sid) {
                    return Ok(false);
                }
                if u32::from(header.AceFlags) & OBJECT_INHERIT_ACE != 0 {
                    trusted_file_inherit_allow = true;
                }
            }
            ACCESS_DENIED_ACE_TYPE => {}
            // A simple ceremony DACL is intentional. Reject object/callback and
            // other uncommon ACE layouts rather than misinterpreting them.
            _ => return Ok(false),
        }
    }
    // Windows falls back to the creator token's default DACL when no explicit
    // descriptor and no applicable inherited ACE exist. Require a trusted
    // file-inheritable allow ACE so the create-time DACL is proven to come
    // from the validated parent rather than that uninspected fallback.
    Ok(trusted_file_inherit_allow)
}

fn reject_existing_output(output_path: &Path) -> Result<(), ProductionDoryV3ModelCombinerError> {
    match fs::symlink_metadata(output_path) {
        Ok(_) => Err(ProductionDoryV3ModelCombinerError::OutputExists(
            output_path.to_path_buf(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ProductionDoryV3ModelCombinerError::InspectOutput {
            path: output_path.to_path_buf(),
            source,
        }),
    }
}

fn validate_input_path_type(
    index: usize,
    path: &Path,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    if metadata_is_reparse_point(&metadata) {
        return Err(ProductionDoryV3ModelCombinerError::InputReparsePoint {
            index,
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(ProductionDoryV3ModelCombinerError::InputNotRegular {
            index,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_open_input_metadata(
    index: usize,
    path: &Path,
    file: &File,
    metadata: &Metadata,
    geometry: CombineGeometry,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    if metadata_is_reparse_point(metadata) {
        return Err(ProductionDoryV3ModelCombinerError::InputReparsePoint {
            index,
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(ProductionDoryV3ModelCombinerError::InputNotRegular {
            index,
            path: path.to_path_buf(),
        });
    }
    validate_input_single_link(index, path, file, metadata)?;
    if metadata.len() != geometry.contribution_bytes {
        return Err(ProductionDoryV3ModelCombinerError::InputLength {
            index,
            path: path.to_path_buf(),
            expected: geometry.contribution_bytes,
            actual: metadata.len(),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    windows_attributes_are_reparse(metadata.file_attributes())
}

#[cfg(windows)]
fn windows_attributes_are_reparse(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

fn hard_link_count(file: &File, metadata: &Metadata) -> std::io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let _ = file;
        Ok(metadata.nlink())
    }

    #[cfg(windows)]
    {
        use std::{mem::MaybeUninit, os::windows::io::AsRawHandle as _};
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };

        let _ = metadata;
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: `file` owns a live kernel handle and `information` points to
        // writable storage of the exact structure required by the Win32 API.
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if succeeded == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a nonzero return guarantees that Win32 initialized the structure.
        Ok(u64::from(
            unsafe { information.assume_init() }.nNumberOfLinks,
        ))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, metadata);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hard-link count inspection is not implemented for this platform",
        ))
    }
}

fn validate_input_single_link(
    index: usize,
    path: &Path,
    file: &File,
    metadata: &Metadata,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    let links = hard_link_count(file, metadata).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    if links != 1 {
        return Err(ProductionDoryV3ModelCombinerError::InputHardLinks {
            index,
            path: path.to_path_buf(),
            links,
        });
    }
    Ok(())
}

fn validate_output_single_link(
    path: &Path,
    file: &File,
    metadata: &Metadata,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    let links = hard_link_count(file, metadata).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if links != 1 {
        return Err(ProductionDoryV3ModelCombinerError::OutputHardLinks {
            path: path.to_path_buf(),
            links,
        });
    }
    Ok(())
}

fn regular_output_path_identity(
    path: &Path,
) -> Result<SameFileHandle, ProductionDoryV3ModelCombinerError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if metadata_is_reparse_point(&metadata) {
        return Err(ProductionDoryV3ModelCombinerError::OutputReparsePoint(
            path.to_path_buf(),
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(ProductionDoryV3ModelCombinerError::OutputNotRegular(
            path.to_path_buf(),
        ));
    }
    let retained = SameFileHandle::from_path(path).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let reopened_metadata = retained.as_file().metadata().map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    validate_output_single_link(path, retained.as_file(), &reopened_metadata)?;
    Ok(retained)
}

fn regular_input_path_identity(
    index: usize,
    path: &Path,
) -> Result<SameFileHandle, ProductionDoryV3ModelCombinerError> {
    validate_input_path_type(index, path)?;
    let retained = SameFileHandle::from_path(path).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    let metadata = retained.as_file().metadata().map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectInput {
            index,
            path: path.to_path_buf(),
            source,
        }
    })?;
    validate_input_single_link(index, path, retained.as_file(), &metadata)?;
    Ok(retained)
}

fn retained_output_identity(
    file: File,
    path: &Path,
) -> Result<SameFileHandle, ProductionDoryV3ModelCombinerError> {
    let metadata =
        file.metadata()
            .map_err(|source| ProductionDoryV3ModelCombinerError::InspectOutput {
                path: path.to_path_buf(),
                source,
            })?;
    if metadata_is_reparse_point(&metadata) {
        return Err(ProductionDoryV3ModelCombinerError::OutputReparsePoint(
            path.to_path_buf(),
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(ProductionDoryV3ModelCombinerError::OutputNotRegular(
            path.to_path_buf(),
        ));
    }
    validate_output_single_link(path, &file, &metadata)?;
    SameFileHandle::from_file(file).map_err(|source| {
        ProductionDoryV3ModelCombinerError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn ensure_input_path_identity(
    index: usize,
    path: &Path,
    expected: &SameFileHandle,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    if &regular_input_path_identity(index, path)? != expected {
        return Err(ProductionDoryV3ModelCombinerError::InputIdentityMismatch {
            index,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn ensure_output_path_identity(
    path: &Path,
    expected: &SameFileHandle,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    if &regular_output_path_identity(path)? != expected {
        return Err(ProductionDoryV3ModelCombinerError::OutputIdentityMismatch(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn remove_output_if_identity(
    path: &Path,
    expected: &SameFileHandle,
) -> Result<(), ProductionDoryV3ModelCombinerError> {
    // Rust has no portable handle-relative unlink that can atomically bind this
    // pathname to `expected`. The production preflight therefore enforces the
    // ceremony's operator-owned parent boundary on Windows, and all platforms
    // preserve the current pathname on any identity mismatch. Do not use this
    // cleanup path in a directory writable by an untrusted account.
    ensure_output_path_identity(path, expected)
        .map_err(|error| cleanup_error(path, error.to_string()))?;
    fs::remove_file(path).map_err(|source| ProductionDoryV3ModelCombinerError::Cleanup {
        path: path.to_path_buf(),
        source,
    })
}

fn cleanup_error(path: &Path, message: impl Into<String>) -> ProductionDoryV3ModelCombinerError {
    ProductionDoryV3ModelCombinerError::Cleanup {
        path: path.to_path_buf(),
        source: std::io::Error::other(message.into()),
    }
}

fn finish_or_cleanup_output<T>(
    output: &mut PublishedCombinedOutput,
    completion: Result<T, ProductionDoryV3ModelCombinerError>,
) -> Result<T, ProductionDoryV3ModelCombinerError> {
    match completion {
        Ok(value) => match output.ensure_current_path() {
            Ok(()) => {
                output.confirm();
                Ok(value)
            }
            Err(error) => Err(cleanup_after_error(output, error)),
        },
        Err(error) => Err(cleanup_after_error(output, error)),
    }
}

fn cleanup_after_error(
    output: &mut PublishedCombinedOutput,
    error: ProductionDoryV3ModelCombinerError,
) -> ProductionDoryV3ModelCombinerError {
    match output.remove_explicit() {
        Ok(()) => error,
        Err(cleanup) => cleanup,
    }
}

fn finalize_sha256(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn elapsed_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_output_parent(
    path: &Path,
) -> Result<ProductionDoryV3ModelCombinerDurability, ProductionDoryV3ModelCombinerError> {
    let parent = output_parent(path);
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ProductionDoryV3ModelCombinerError::SyncParent {
            path: parent.to_path_buf(),
            source,
        })?;
    Ok(ProductionDoryV3ModelCombinerDurability::FileAndParentDirectorySynced)
}

#[cfg(windows)]
fn sync_output_parent(
    path: &Path,
) -> Result<ProductionDoryV3ModelCombinerDurability, ProductionDoryV3ModelCombinerError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let parent = output_parent(path);
    let sync_result = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent)
        .and_then(|directory| directory.sync_all());
    classify_windows_parent_sync(parent, sync_result)
}

#[cfg(windows)]
fn classify_windows_parent_sync(
    parent: &Path,
    sync_result: std::io::Result<()>,
) -> Result<ProductionDoryV3ModelCombinerDurability, ProductionDoryV3ModelCombinerError> {
    match sync_result {
        Ok(()) => Ok(
            ProductionDoryV3ModelCombinerDurability::FileAndParentDirectorySynced,
        ),
        Err(source) if source.raw_os_error() == Some(5) => Ok(
            ProductionDoryV3ModelCombinerDurability::FileSyncedParentDirectorySyncAccessDeniedOnWindows,
        ),
        Err(source)
            if source.kind() == std::io::ErrorKind::Unsupported
                || matches!(source.raw_os_error(), Some(1 | 50)) => {
            Ok(ProductionDoryV3ModelCombinerDurability::FileSyncedParentDirectorySyncUnsupportedOnWindows)
        }
        Err(source) => Err(ProductionDoryV3ModelCombinerError::SyncParent {
            path: parent.to_path_buf(),
            source,
        }),
    }
}

#[cfg(all(not(unix), not(windows)))]
fn sync_output_parent(
    _path: &Path,
) -> Result<ProductionDoryV3ModelCombinerDurability, ProductionDoryV3ModelCombinerError> {
    Ok(ProductionDoryV3ModelCombinerDurability::FileSyncedParentDirectorySyncUnsupportedOnPlatform)
}

struct PublishedCombinedOutput {
    path: PathBuf,
    retained: Option<SameFileHandle>,
    finished: bool,
}

impl PublishedCombinedOutput {
    fn identity(&self) -> Result<&SameFileHandle, ProductionDoryV3ModelCombinerError> {
        self.retained.as_ref().ok_or_else(|| {
            ProductionDoryV3ModelCombinerError::OutputIdentityMismatch(self.path.clone())
        })
    }

    fn reopen_reader(&self) -> Result<File, ProductionDoryV3ModelCombinerError> {
        ensure_output_path_identity(&self.path, self.identity()?)?;
        let file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| ProductionDoryV3ModelCombinerError::ReadOutput {
                path: self.path.clone(),
                source,
            })?;
        let identity_file =
            file.try_clone()
                .map_err(|source| ProductionDoryV3ModelCombinerError::ReadOutput {
                    path: self.path.clone(),
                    source,
                })?;
        let reopened = retained_output_identity(identity_file, &self.path)?;
        if &reopened != self.identity()? {
            return Err(ProductionDoryV3ModelCombinerError::OutputIdentityMismatch(
                self.path.clone(),
            ));
        }
        Ok(file)
    }

    fn ensure_current_path(&self) -> Result<(), ProductionDoryV3ModelCombinerError> {
        ensure_output_path_identity(&self.path, self.identity()?)
    }

    fn remove_explicit(&mut self) -> Result<(), ProductionDoryV3ModelCombinerError> {
        if self.finished {
            return Ok(());
        }
        let identity = self
            .retained
            .as_ref()
            .ok_or_else(|| cleanup_error(&self.path, "output identity is unavailable"))?;
        remove_output_if_identity(&self.path, identity)?;
        self.retained.take();
        self.finished = true;
        Ok(())
    }

    fn confirm(&mut self) {
        self.retained.take();
        self.finished = true;
    }
}

impl Drop for PublishedCombinedOutput {
    fn drop(&mut self) {
        if !self.finished
            && let Some(identity) = self.retained.as_ref()
        {
            let _ = remove_output_if_identity(&self.path, identity);
        }
        self.retained.take();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::Write as _,
        sync::{Arc, Mutex},
    };

    use super::*;

    fn tiny_geometry() -> CombineGeometry {
        CombineGeometry {
            contribution_bytes: 6,
            chunk_bytes: 3,
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        let unique = format!(
            "cmfd-dory-v3-combiner-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    fn create_inputs(label: &str, values: &[&[u8]]) -> Vec<PathBuf> {
        values
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let path = temp_path(&format!("{label}-{index}"));
                fs::write(&path, bytes).unwrap();
                path
            })
            .collect()
    }

    fn remove_paths(paths: impl IntoIterator<Item = PathBuf>) {
        for path in paths {
            if path.is_dir() {
                fs::remove_dir(path).unwrap();
            } else if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }

    type StageHook = Box<dyn FnMut(&[PathBuf], &Path)>;

    #[derive(Default)]
    struct TestIo {
        fail_write: bool,
        fail_flush: bool,
        fail_sync: bool,
        after_auth: Option<StageHook>,
        after_close: Option<StageHook>,
        before_final: Option<StageHook>,
    }

    impl CombinerIo for TestIo {
        fn write_output(
            &mut self,
            _output_path: &Path,
            output: &mut File,
            bytes: &[u8],
        ) -> std::io::Result<()> {
            if self.fail_write {
                return Err(std::io::Error::other("injected write failure"));
            }
            output.write_all(bytes)
        }

        fn flush_output(&mut self, output: &mut File) -> std::io::Result<()> {
            if self.fail_flush {
                return Err(std::io::Error::other("injected flush failure"));
            }
            output.flush()
        }

        fn sync_output(&mut self, output: &File) -> std::io::Result<()> {
            if self.fail_sync {
                return Err(std::io::Error::other("injected sync failure"));
            }
            output.sync_all()
        }

        fn after_inputs_authenticated(&mut self, inputs: &[PathBuf], output: &Path) {
            if let Some(hook) = &mut self.after_auth {
                hook(inputs, output);
            }
        }

        fn after_output_closed(&mut self, inputs: &[PathBuf], output: &Path) {
            if let Some(hook) = &mut self.after_close {
                hook(inputs, output);
            }
        }

        fn before_final_input_authentication(&mut self, inputs: &[PathBuf], output: &Path) {
            if let Some(hook) = &mut self.before_final {
                hook(inputs, output);
            }
        }
    }

    fn combine_tiny(
        inputs: &[PathBuf],
        output: &Path,
        io: &mut TestIo,
    ) -> Result<ProductionDoryV3ModelCombinerReport, ProductionDoryV3ModelCombinerError> {
        combine_with_io(inputs, output, tiny_geometry(), io)
    }

    #[test]
    fn production_geometry_and_count_bounds_are_frozen() {
        let geometry = CombineGeometry::production().unwrap();
        assert_eq!(geometry.contribution_bytes, 6_442_975_232);
        assert_eq!(geometry.chunk_bytes, 1_048_576);

        let output = temp_path("count-output");
        for count in [0, 1, 2, 17] {
            let inputs = (0..count)
                .map(|index| PathBuf::from(format!("unused-{index}")))
                .collect::<Vec<_>>();
            assert!(matches!(
                combine_with_io(&inputs, &output, tiny_geometry(), &mut TestIo::default()),
                Err(ProductionDoryV3ModelCombinerError::ContributionCount { actual }) if actual == count
            ));
        }
    }

    #[test]
    fn modulo_251_kat_preserves_ordered_report_and_external_hashes() {
        let inputs = create_inputs(
            "kat",
            &[
                &[0, 1, 2, 249, 250, 250],
                &[250, 250, 249, 2, 1, 250],
                &[1, 2, 3, 4, 5, 250],
            ],
        );
        let output = temp_path("kat-output");
        let report = combine_tiny(&inputs, &output, &mut TestIo::default()).unwrap();
        let expected = [0, 2, 3, 4, 5, 248];
        assert_eq!(fs::read(&output).unwrap(), expected);
        assert_eq!(
            report
                .ordered_inputs
                .iter()
                .map(|item| &item.path)
                .collect::<Vec<_>>(),
            inputs.iter().collect::<Vec<_>>()
        );
        assert_eq!(report.bytes_processed, 6);
        assert_eq!(
            hex::encode(report.output_blake3.into_bytes()),
            "d256495d06d49773ec8aac338050786bddf071fec661f07d766bfd2c7b23979f"
        );
        assert_eq!(
            hex::encode(report.output_sha256.into_bytes()),
            "6b675b3bf6561e7e5bbc47b1ac9eb32d956fe1c45dea926dd62ea6ab1f75673a"
        );
        remove_paths(inputs.into_iter().chain([output]));
    }

    #[test]
    fn maximum_sixteen_input_sum_uses_checked_u32_before_reduction() {
        let input_bytes = [250_u8; 6];
        let values = (0..16).map(|_| input_bytes.as_slice()).collect::<Vec<_>>();
        let inputs = create_inputs("max-sum", &values);
        let output = temp_path("max-sum-output");
        combine_tiny(&inputs, &output, &mut TestIo::default()).unwrap();
        assert_eq!(fs::read(&output).unwrap(), [235_u8; 6]);
        remove_paths(inputs.into_iter().chain([output]));
    }

    #[test]
    fn existing_output_is_never_overwritten() {
        let inputs = create_inputs("existing", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("existing-output");
        fs::write(&output, b"keep me").unwrap();
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut TestIo::default()),
            Err(ProductionDoryV3ModelCombinerError::OutputExists(ref path)) if path == &output
        ));
        assert_eq!(fs::read(&output).unwrap(), b"keep me");
        remove_paths(inputs.into_iter().chain([output]));
    }

    #[test]
    fn duplicate_paths_and_hard_link_aliases_are_rejected() {
        let mut inputs = create_inputs("duplicate", &[&[1; 6], &[2; 6]]);
        inputs.push(inputs[0].clone());
        let output = temp_path("duplicate-output");
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut TestIo::default()),
            Err(ProductionDoryV3ModelCombinerError::DuplicateInput {
                first_index: 0,
                second_index: 2,
                ..
            })
        ));
        inputs.pop();

        let alias = temp_path("hard-link-alias");
        fs::hard_link(&inputs[0], &alias).unwrap();
        let aliased = vec![inputs[0].clone(), inputs[1].clone(), alias.clone()];
        assert!(matches!(
            combine_tiny(&aliased, &output, &mut TestIo::default()),
            Err(ProductionDoryV3ModelCombinerError::InputHardLinks {
                index: 0,
                links: 2,
                ..
            })
        ));
        remove_paths(inputs.into_iter().chain([alias]));
    }

    #[test]
    fn short_trailing_and_out_of_range_inputs_are_rejected() {
        let cases = [
            ("short", vec![vec![1; 5], vec![2; 6], vec![3; 6]], "length"),
            (
                "trailing",
                vec![vec![1; 7], vec![2; 6], vec![3; 6]],
                "length",
            ),
            ("range", vec![vec![251; 6], vec![2; 6], vec![3; 6]], "range"),
        ];
        for (label, values, expected) in cases {
            let refs = values.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let inputs = create_inputs(label, &refs);
            let output = temp_path(&format!("{label}-output"));
            let error = combine_tiny(&inputs, &output, &mut TestIo::default()).unwrap_err();
            match expected {
                "length" => assert!(matches!(
                    error,
                    ProductionDoryV3ModelCombinerError::InputLength { .. }
                )),
                "range" => assert!(matches!(
                    error,
                    ProductionDoryV3ModelCombinerError::InputByteOutOfRange { .. }
                )),
                _ => unreachable!(),
            }
            assert!(!output.exists());
            remove_paths(inputs);
        }
    }

    #[test]
    fn same_length_tamper_between_authentication_and_combine_is_rejected() {
        let inputs = create_inputs("tamper", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("tamper-output");
        let mut io = TestIo {
            after_auth: Some(Box::new(|paths, _| {
                fs::write(&paths[1], [9_u8; 6]).unwrap()
            })),
            ..TestIo::default()
        };
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut io),
            Err(ProductionDoryV3ModelCombinerError::InputDigestMismatch { index: 1, .. })
        ));
        assert!(!output.exists());
        remove_paths(inputs);
    }

    #[test]
    fn same_length_tamper_after_combine_is_rejected() {
        let inputs = create_inputs("late-tamper", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("late-tamper-output");
        let mut io = TestIo {
            before_final: Some(Box::new(|paths, _| {
                fs::write(&paths[2], [8_u8; 6]).unwrap()
            })),
            ..TestIo::default()
        };
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut io),
            Err(ProductionDoryV3ModelCombinerError::InputDigestMismatch { index: 2, .. })
        ));
        assert!(!output.exists());
        remove_paths(inputs);
    }

    #[test]
    fn in_place_output_tamper_during_final_input_authentication_is_rejected() {
        let inputs = create_inputs("final-output-tamper", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("final-output-tamper-output");
        let mut io = TestIo {
            before_final: Some(Box::new(|_, output| fs::write(output, [9_u8; 6]).unwrap())),
            ..TestIo::default()
        };
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut io),
            Err(ProductionDoryV3ModelCombinerError::OutputDigestMismatch)
        ));
        assert!(!output.exists());
        remove_paths(inputs);
    }

    #[test]
    fn input_replacement_is_detected_and_replacement_is_preserved() {
        let inputs = create_inputs("input-replace", &[&[1; 6], &[2; 6], &[3; 6]]);
        let displaced = temp_path("input-replace-displaced");
        let displaced_for_hook = displaced.clone();
        let output = temp_path("input-replace-output");
        let mut io = TestIo {
            after_auth: Some(Box::new(move |paths, _| {
                fs::rename(&paths[0], &displaced_for_hook).unwrap();
                fs::write(&paths[0], [7_u8; 6]).unwrap();
            })),
            ..TestIo::default()
        };
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut io),
            Err(ProductionDoryV3ModelCombinerError::InputIdentityMismatch { index: 0, .. })
        ));
        assert_eq!(fs::read(&inputs[0]).unwrap(), [7_u8; 6]);
        assert!(!output.exists());
        remove_paths(inputs.into_iter().chain([displaced]));
    }

    #[test]
    fn write_flush_and_sync_failures_remove_partial_outputs() {
        for (label, mut io, expected) in [
            (
                "write",
                TestIo {
                    fail_write: true,
                    ..TestIo::default()
                },
                "write",
            ),
            (
                "flush",
                TestIo {
                    fail_flush: true,
                    ..TestIo::default()
                },
                "flush",
            ),
            (
                "sync",
                TestIo {
                    fail_sync: true,
                    ..TestIo::default()
                },
                "sync",
            ),
        ] {
            let inputs = create_inputs(label, &[&[1; 6], &[2; 6], &[3; 6]]);
            let output = temp_path(&format!("{label}-output"));
            let error = combine_tiny(&inputs, &output, &mut io).unwrap_err();
            match expected {
                "write" => assert!(matches!(
                    error,
                    ProductionDoryV3ModelCombinerError::WriteOutput { .. }
                )),
                "flush" => assert!(matches!(
                    error,
                    ProductionDoryV3ModelCombinerError::FlushOutput { .. }
                )),
                "sync" => assert!(matches!(
                    error,
                    ProductionDoryV3ModelCombinerError::SyncOutput { .. }
                )),
                _ => unreachable!(),
            }
            assert!(!output.exists());
            remove_paths(inputs);
        }
    }

    #[test]
    fn output_replacement_and_cleanup_failure_preserve_replacement() {
        let inputs = create_inputs("output-replace", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("output-replace-output");
        let displaced = temp_path("output-replace-displaced");
        let displaced_for_hook = displaced.clone();
        let mut io = TestIo {
            after_close: Some(Box::new(move |_, output| {
                fs::rename(output, &displaced_for_hook).unwrap();
                fs::write(output, b"replacement").unwrap();
            })),
            ..TestIo::default()
        };
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut io),
            Err(ProductionDoryV3ModelCombinerError::Cleanup { .. })
        ));
        assert_eq!(fs::read(&output).unwrap(), b"replacement");
        remove_paths(inputs.into_iter().chain([output, displaced]));
    }

    #[test]
    fn same_length_output_tamper_is_detected_and_removed() {
        let inputs = create_inputs("output-tamper", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("output-tamper-output");
        let mut io = TestIo {
            after_close: Some(Box::new(|_, output| fs::write(output, [9_u8; 6]).unwrap())),
            ..TestIo::default()
        };
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut io),
            Err(ProductionDoryV3ModelCombinerError::OutputDigestMismatch)
        ));
        assert!(!output.exists());
        remove_paths(inputs);
    }

    #[test]
    fn unexpected_output_hard_link_is_rejected_without_deleting_either_name() {
        let inputs = create_inputs("output-link", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("output-link-output");
        let alias = temp_path("output-link-alias");
        let alias_for_hook = alias.clone();
        let mut io = TestIo {
            after_close: Some(Box::new(move |_, output| {
                fs::hard_link(output, &alias_for_hook).unwrap();
            })),
            ..TestIo::default()
        };
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut io),
            Err(ProductionDoryV3ModelCombinerError::Cleanup { .. })
        ));
        assert!(output.exists());
        assert_eq!(fs::read(&output).unwrap(), fs::read(&alias).unwrap());
        remove_paths(inputs.into_iter().chain([output, alias]));
    }

    #[test]
    fn output_path_is_reauthenticated_immediately_before_success() {
        let inputs = create_inputs("final-output-id", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("final-output-id-output");
        let displaced = temp_path("final-output-id-displaced");
        let displaced_for_hook = displaced.clone();
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let events_for_hook = Arc::clone(&events);
        let mut io = TestIo {
            before_final: Some(Box::new(move |_, output| {
                events_for_hook
                    .lock()
                    .unwrap()
                    .push_back("input-reauth-hook");
                fs::rename(output, &displaced_for_hook).unwrap();
                fs::write(output, b"replacement").unwrap();
            })),
            ..TestIo::default()
        };
        assert!(matches!(
            combine_tiny(&inputs, &output, &mut io),
            Err(ProductionDoryV3ModelCombinerError::Cleanup { .. })
        ));
        assert_eq!(
            events.lock().unwrap().pop_front(),
            Some("input-reauth-hook")
        );
        assert_eq!(fs::read(&output).unwrap(), b"replacement");
        remove_paths(inputs.into_iter().chain([output, displaced]));
    }

    #[cfg(windows)]
    #[test]
    fn windows_ads_device_unc_and_reserved_names_are_rejected_lexically() {
        for path in [
            Path::new(r"C:\ceremony\contribution.bin:stream"),
            Path::new(r"\\server\share\contribution.bin"),
            Path::new(r"\\.\PhysicalDrive0"),
            Path::new(r"\\?\C:\ceremony\contribution.bin"),
            Path::new(r"C:\ceremony\NUL.bin"),
            Path::new(r"C:\NUL\contribution.bin"),
            Path::new(r"C:\ceremony.\contribution.bin"),
            Path::new(r"C:\ceremony\COM¹.bin"),
            Path::new(r"C:\LPT²\contribution.bin"),
            Path::new(r"C:\ceremony\com³"),
        ] {
            assert!(windows_artifact_path_has_disallowed_syntax(path));
        }
        assert!(!windows_artifact_path_has_disallowed_syntax(Path::new(
            r"C:\ceremony\contribution.bin"
        )));
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_parent_and_sync_access_denied_are_distinct() {
        assert!(windows_attributes_are_reparse(0x0000_0410));
        assert!(!windows_attributes_are_reparse(0x0000_0010));

        let parent = Path::new(r"C:\ceremony");
        assert_eq!(
            classify_windows_parent_sync(
                parent,
                Err(std::io::Error::from_raw_os_error(5)),
            )
            .unwrap(),
            ProductionDoryV3ModelCombinerDurability::FileSyncedParentDirectorySyncAccessDeniedOnWindows
        );
        assert_eq!(
            classify_windows_parent_sync(
                parent,
                Err(std::io::Error::from_raw_os_error(50)),
            )
            .unwrap(),
            ProductionDoryV3ModelCombinerDurability::FileSyncedParentDirectorySyncUnsupportedOnWindows
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_operator_owned_local_parent_preflight_is_enforced() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::{
            Security::{NO_INHERITANCE, SUB_CONTAINERS_AND_OBJECTS_INHERIT},
            Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
                FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
            },
        };

        let parent = temp_path("secure-parent");
        fs::create_dir(&parent).unwrap();
        let directory = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&parent)
            .unwrap();
        set_windows_operator_only_acl(&directory, SUB_CONTAINERS_AND_OBJECTS_INHERIT).unwrap();
        assert!(windows_parent_dacl_is_operator_owned(&parent).unwrap());

        let inputs = (0..3)
            .map(|index| {
                let path = parent.join(format!("input-{index}.bin"));
                fs::write(&path, [u8::try_from(index).unwrap(); 6]).unwrap();
                path
            })
            .collect::<Vec<_>>();
        let output = parent.join("output.bin");
        preflight_combiner_paths(&inputs, &output).unwrap();

        let noninheriting_parent = temp_path("noninheriting-parent");
        fs::create_dir(&noninheriting_parent).unwrap();
        let noninheriting_directory = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&noninheriting_parent)
            .unwrap();
        set_windows_operator_only_acl(&noninheriting_directory, NO_INHERITANCE).unwrap();
        assert!(!windows_parent_dacl_is_operator_owned(&noninheriting_parent).unwrap());

        drop(directory);
        drop(noninheriting_directory);
        remove_paths(inputs.into_iter().chain([parent]));
        fs::remove_dir(noninheriting_parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_output_mode_is_exactly_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let inputs = create_inputs("mode", &[&[1; 6], &[2; 6], &[3; 6]]);
        let output = temp_path("mode-output");
        combine_tiny(&inputs, &output, &mut TestIo::default()).unwrap();
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        remove_paths(inputs.into_iter().chain([output]));
    }
}
