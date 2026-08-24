//! Two-pass production ceremony for the canonical Dory V3 model Record V2.
//!
//! The ceremony validates the separately trusted production manifest and the
//! compiled n=33 setup before opening the model bank. Pass one derives the
//! four ordered commitments from one fully authenticated reader. Pass two
//! independently reopens the bank, rederives every commitment through the
//! Record V2 validation path, and only then writes and reopens the canonical
//! audit record. Success requires exact record bytes and digest reproduction.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use same_file::Handle as SameFileHandle;
use serde::Serialize;
use thiserror::Error;

use crate::{
    ModelBankError, ModelBankFieldStreamError, ModelBankManifest,
    dory_bls12_381_layout::{
        BlsDoryFixedModelStreamError, derive_bls_dory_model_commitments_from_verified_layout,
    },
    dory_bls12_381_prototype::{BlsDoryPrototypeError, deterministic_bls_dory_setup},
    dory_v3_model::{DoryV3ModelIdentityError, DoryV3ModelIdentityV1},
    dory_v3_model_record::{
        DoryV3ModelCommitmentRecordError, DoryV3ModelCommitmentRecordV2,
        derive_bank_authenticated_dory_v3_model_commitment_record_v2,
    },
    dory_v3_suite::{
        DORY_V3_BANKS, DORY_V3_BATCH, DORY_V3_DIMENSION, DORY_V3_LAYERS, DORY_V3_LAYERS_PER_BANK,
        DORY_V3_MODEL_RECORD_CANONICAL_BYTES, DORY_V3_MODEL_VERSION, DORY_V3_PADDED_VARIABLES,
        DORY_V3_PRODUCTION_SUITE_MANIFEST, Digest32,
    },
};

/// Machine-readable result emitted only after both complete bank passes agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionDoryV3ModelRecordV2CeremonyReport {
    pub output: PathBuf,
    pub record_digest: Digest32,
    pub model_identity_digest: Digest32,
    pub manifest_digest: Digest32,
    pub model_byte_root: Digest32,
    pub layer_roots_aggregate: Digest32,
    pub commitment_root: Digest32,
    pub setup_identity: Digest32,
    pub padded_variables: u32,
    pub record_json_bytes: u64,
    pub record_canonical_bytes: u32,
    pub setup_elapsed_micros: u64,
    pub pass_1_elapsed_micros: u64,
    pub pass_2_elapsed_micros: u64,
}

/// Fail-closed errors from the two-pass production ceremony.
#[derive(Debug, Error)]
pub enum ProductionDoryV3ModelRecordV2CeremonyError {
    #[error("refusing to run because the output path already exists: {0}")]
    OutputExists(PathBuf),
    #[error("failed to inspect output path {path}: {source}")]
    InspectOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid model-bank manifest: {0}")]
    InvalidManifest(#[source] ModelBankError),
    #[error("the trusted manifest is not the canonical production Dory V3 manifest: {0}")]
    ProductionManifestMismatch(&'static str),
    #[error("failed to derive the pinned n=33 Dory setup: {0}")]
    Setup(#[source] BlsDoryPrototypeError),
    #[error("the derived n=33 setup does not match the compiled production suite")]
    PinnedSetupMismatch,
    #[error("failed to open the model bank for pass {pass} at {path}: {source}")]
    OpenBank {
        pass: u8,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("pass 1 failed while authenticating and committing the production model bank: {0}")]
    PassOneDerivation(#[source] ModelBankFieldStreamError<BlsDoryFixedModelStreamError>),
    #[error("pass 1 produced an invalid Dory V3 model identity: {0}")]
    ModelIdentity(#[source] DoryV3ModelIdentityError),
    #[error("Record V2 construction or pass 2 reproduction failed: {0}")]
    Record(#[source] DoryV3ModelCommitmentRecordError),
    #[error("failed to serialize Record V2: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("failed to create new output file {path}: {source}")]
    CreateOutput {
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
    #[error("failed to sync new output file {path}: {source}")]
    SyncOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to reopen Record V2 at {path}: {source}")]
    ReadOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("output path is not a regular file: {0}")]
    OutputNotRegular(PathBuf),
    #[error("output path was replaced or no longer names the retained file: {0}")]
    OutputIdentityMismatch(PathBuf),
    #[error("the reopened Record V2 is not the exact newly written canonical JSON")]
    NonCanonicalRecordBytes,
    #[error("the independently reproduced Record V2 bytes or digests do not match pass 1")]
    ReproductionMismatch,
    #[error("Record V2 byte length does not fit the report format")]
    RecordLengthOverflow,
    #[error("failed to remove unconfirmed output {path}: {source}")]
    Cleanup {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to sync output parent {path}: {source}")]
    SyncParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Validate the trusted manifest's exact production geometry and suite-owned
/// fields without opening the multi-gigabyte bank or constructing the setup.
pub fn preflight_production_dory_v3_model_bank_manifest(
    manifest: &ModelBankManifest,
) -> Result<Digest32, ProductionDoryV3ModelRecordV2CeremonyError> {
    let manifest_digest = manifest
        .digest()
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::InvalidManifest)?;
    let suite = &*DORY_V3_PRODUCTION_SUITE_MANIFEST;
    suite.validate().map_err(|_| {
        ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(
            "the compiled production suite is invalid",
        )
    })?;

    if manifest.model_version != DORY_V3_MODEL_VERSION
        || manifest.batch != DORY_V3_BATCH
        || manifest.dimension != DORY_V3_DIMENSION
        || manifest.layers != DORY_V3_LAYERS
    {
        return Err(
            ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(
                "model geometry differs from the compiled production suite",
            ),
        );
    }

    let expected_base_input_bytes = u64::from(DORY_V3_BATCH)
        .checked_mul(u64::from(DORY_V3_DIMENSION))
        .ok_or(
            ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(
                "compiled production base-input size overflowed",
            ),
        )?;
    let expected_bytes_per_layer = u64::from(DORY_V3_DIMENSION)
        .checked_mul(u64::from(DORY_V3_DIMENSION))
        .ok_or(
            ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(
                "compiled production layer size overflowed",
            ),
        )?;
    let expected_payload_bytes = u64::from(DORY_V3_LAYERS)
        .checked_mul(expected_bytes_per_layer)
        .and_then(|layers| layers.checked_add(expected_base_input_bytes))
        .ok_or(
            ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(
                "compiled production payload size overflowed",
            ),
        )?;
    if manifest.base_input_bytes != expected_base_input_bytes
        || manifest.bytes_per_layer != expected_bytes_per_layer
        || manifest.payload_bytes != expected_payload_bytes
    {
        return Err(
            ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(
                "model byte lengths differ from the compiled production suite",
            ),
        );
    }
    if manifest.raw_blake3_root == [0; 32]
        || manifest.layer_roots_aggregate == [0; 32]
        || manifest.pcs_commitment_root == [0; 32]
    {
        return Err(
            ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(
                "model roots and the commitment root must be specified",
            ),
        );
    }
    if manifest.pcs_parameter_digest != suite.digest().into_bytes() {
        return Err(
            ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(
                "PCS parameter digest differs from the compiled production suite",
            ),
        );
    }

    Ok(Digest32::new(manifest_digest))
}

/// Run the canonical production ceremony. Existing outputs are rejected and
/// never overwritten. Once retained file identity has been acquired, a newly
/// created output is removed unless both complete passes and the reopened
/// canonical record reproduce exactly. If identity acquisition itself fails,
/// the path is left for explicit operator inspection instead of risking blind
/// deletion of a concurrent replacement.
pub fn run_production_dory_v3_model_record_v2_ceremony(
    bank_path: &Path,
    trusted_manifest: &ModelBankManifest,
    output_path: &Path,
) -> Result<ProductionDoryV3ModelRecordV2CeremonyReport, ProductionDoryV3ModelRecordV2CeremonyError>
{
    reject_existing_output(output_path)?;
    let manifest_digest = preflight_production_dory_v3_model_bank_manifest(trusted_manifest)?;

    let setup_started = Instant::now();
    let setup = deterministic_bls_dory_setup(DORY_V3_PADDED_VARIABLES as usize)
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Setup)?;
    setup
        .validate()
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Setup)?;
    let suite = &*DORY_V3_PRODUCTION_SUITE_MANIFEST;
    if setup.max_log_n() != DORY_V3_PADDED_VARIABLES as usize
        || setup.identity() != suite.setup_identity.into_bytes()
    {
        return Err(ProductionDoryV3ModelRecordV2CeremonyError::PinnedSetupMismatch);
    }
    let setup_elapsed = setup_started.elapsed();

    let pass_one_started = Instant::now();
    let pass_one_reader = open_bank(bank_path, 1)?;
    let derived = derive_bls_dory_model_commitments_from_verified_layout(
        pass_one_reader,
        trusted_manifest,
        DORY_V3_BATCH,
        DORY_V3_DIMENSION,
        DORY_V3_LAYERS_PER_BANK,
        DORY_V3_BANKS,
        DORY_V3_PADDED_VARIABLES as usize,
        &setup,
    )
    .map_err(ProductionDoryV3ModelRecordV2CeremonyError::PassOneDerivation)?;
    let identity = DoryV3ModelIdentityV1::new(
        suite,
        trusted_manifest.model_version,
        trusted_manifest.batch,
        trusted_manifest.dimension,
        DORY_V3_LAYERS_PER_BANK,
        trusted_manifest.raw_blake3_root,
        trusted_manifest.layer_roots_aggregate,
        DORY_V3_PADDED_VARIABLES,
        &setup,
        derived.base_input,
        derived.weight_banks,
    )
    .map_err(ProductionDoryV3ModelRecordV2CeremonyError::ModelIdentity)?;
    let _ = identity
        .validate_production_structure(trusted_manifest, &setup)
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::ModelIdentity)?;
    let first_record = DoryV3ModelCommitmentRecordV2::new(*trusted_manifest, identity)
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Record)?;
    first_record
        .validate_production(&setup)
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Record)?;
    let first_bytes = encode_record(&first_record)?;
    let pass_one_elapsed = pass_one_started.elapsed();

    let pass_two_started = Instant::now();
    let decoded_record: DoryV3ModelCommitmentRecordV2 = serde_json::from_slice(&first_bytes)
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Serialize)?;
    decoded_record
        .validate_production(&setup)
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Record)?;
    if decoded_record != first_record
        || decoded_record.canonical_bytes() != first_record.canonical_bytes()
        || decoded_record.record_digest() != first_record.record_digest()
    {
        return Err(ProductionDoryV3ModelRecordV2CeremonyError::ReproductionMismatch);
    }
    let pass_two_structural = decoded_record
        .model_identity()
        .validate_production_structure(decoded_record.manifest(), &setup)
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::ModelIdentity)?;

    let pass_two_reader = open_bank(bank_path, 2)?;
    let second_record = derive_bank_authenticated_dory_v3_model_commitment_record_v2(
        pass_two_reader,
        &pass_two_structural,
        &setup,
    )
    .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Record)?
    .into_record();
    let second_bytes = encode_record(&second_record)?;
    if second_record != first_record
        || second_record.canonical_bytes() != first_record.canonical_bytes()
        || second_record.record_digest() != first_record.record_digest()
        || second_bytes != first_bytes
    {
        return Err(ProductionDoryV3ModelRecordV2CeremonyError::ReproductionMismatch);
    }
    let pass_two_elapsed = pass_two_started.elapsed();

    let record_json_bytes = u64::try_from(first_bytes.len())
        .map_err(|_| ProductionDoryV3ModelRecordV2CeremonyError::RecordLengthOverflow)?;

    // The final pathname is created only after both authenticated bank passes
    // agree. Keep the created inode open, reread that retained handle, and do
    // not confirm success unless the pathname still names the same regular
    // file after the parent-directory durability step where the platform
    // supports syncing directory entries.
    let mut output = write_new_output(output_path, &first_bytes)?;
    let completion = (|| {
        let reopened_bytes = read_exact_output(&output, &first_bytes)?;
        let reopened_record: DoryV3ModelCommitmentRecordV2 =
            serde_json::from_slice(&reopened_bytes)
                .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Serialize)?;
        reopened_record
            .validate_production(&setup)
            .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Record)?;
        if reopened_record != first_record
            || reopened_record != second_record
            || reopened_record.canonical_bytes() != first_record.canonical_bytes()
            || reopened_record.record_digest() != first_record.record_digest()
        {
            return Err(ProductionDoryV3ModelRecordV2CeremonyError::ReproductionMismatch);
        }
        sync_output_parent(output_path)?;

        Ok(ProductionDoryV3ModelRecordV2CeremonyReport {
            output: output_path.to_path_buf(),
            record_digest: first_record.record_digest(),
            model_identity_digest: first_record.model_identity_digest(),
            manifest_digest,
            model_byte_root: Digest32::new(trusted_manifest.raw_blake3_root),
            layer_roots_aggregate: Digest32::new(trusted_manifest.layer_roots_aggregate),
            commitment_root: first_record.commitment_root(),
            setup_identity: first_record.setup_identity(),
            padded_variables: first_record.padded_variables(),
            record_json_bytes,
            record_canonical_bytes: DORY_V3_MODEL_RECORD_CANONICAL_BYTES,
            setup_elapsed_micros: elapsed_micros(setup_elapsed),
            pass_1_elapsed_micros: elapsed_micros(pass_one_elapsed),
            pass_2_elapsed_micros: elapsed_micros(pass_two_elapsed),
        })
    })();
    finish_or_cleanup_output(&mut output, completion)
}

fn reject_existing_output(
    output_path: &Path,
) -> Result<(), ProductionDoryV3ModelRecordV2CeremonyError> {
    match fs::symlink_metadata(output_path) {
        Ok(_) => Err(ProductionDoryV3ModelRecordV2CeremonyError::OutputExists(
            output_path.to_path_buf(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ProductionDoryV3ModelRecordV2CeremonyError::InspectOutput {
            path: output_path.to_path_buf(),
            source,
        }),
    }
}

fn open_bank(
    bank_path: &Path,
    pass: u8,
) -> Result<File, ProductionDoryV3ModelRecordV2CeremonyError> {
    File::open(bank_path).map_err(
        |source| ProductionDoryV3ModelRecordV2CeremonyError::OpenBank {
            pass,
            path: bank_path.to_path_buf(),
            source,
        },
    )
}

fn encode_record(
    record: &DoryV3ModelCommitmentRecordV2,
) -> Result<Vec<u8>, ProductionDoryV3ModelRecordV2CeremonyError> {
    let mut encoded = serde_json::to_vec_pretty(record)
        .map_err(ProductionDoryV3ModelRecordV2CeremonyError::Serialize)?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn write_new_output(
    output_path: &Path,
    bytes: &[u8],
) -> Result<PublishedRecordOutput, ProductionDoryV3ModelRecordV2CeremonyError> {
    write_new_output_with(output_path, |file| file.write_all(bytes))
}

fn write_new_output_with(
    output_path: &Path,
    write: impl FnOnce(&mut File) -> std::io::Result<()>,
) -> Result<PublishedRecordOutput, ProductionDoryV3ModelRecordV2CeremonyError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                ProductionDoryV3ModelRecordV2CeremonyError::OutputExists(output_path.to_path_buf())
            } else {
                ProductionDoryV3ModelRecordV2CeremonyError::CreateOutput {
                    path: output_path.to_path_buf(),
                    source,
                }
            }
        })?;
    let retained = match file.try_clone() {
        Ok(retained) => retained,
        Err(source) => {
            // Without a retained identity, deleting by pathname could remove
            // a concurrent replacement. Leave the newly created file for
            // operator inspection rather than perform a blind cleanup.
            return Err(abandon_unidentified_output(
                file,
                ProductionDoryV3ModelRecordV2CeremonyError::CreateOutput {
                    path: output_path.to_path_buf(),
                    source,
                },
            ));
        }
    };
    let retained = match retained_file_identity(retained, output_path) {
        Ok(retained) => retained,
        Err(error) => return Err(abandon_unidentified_output(file, error)),
    };
    let mut output = PublishedRecordOutput {
        path: output_path.to_path_buf(),
        retained: Some(retained),
        finished: false,
    };
    if let Err(source) = write(&mut file) {
        drop(file);
        let error = ProductionDoryV3ModelRecordV2CeremonyError::WriteOutput {
            path: output_path.to_path_buf(),
            source,
        };
        return Err(cleanup_after_error(&mut output, error));
    }
    if let Err(source) = file.sync_all() {
        drop(file);
        let error = ProductionDoryV3ModelRecordV2CeremonyError::SyncOutput {
            path: output_path.to_path_buf(),
            source,
        };
        return Err(cleanup_after_error(&mut output, error));
    }
    drop(file);
    Ok(output)
}

fn abandon_unidentified_output(
    file: File,
    error: ProductionDoryV3ModelRecordV2CeremonyError,
) -> ProductionDoryV3ModelRecordV2CeremonyError {
    drop(file);
    error
}

fn read_exact_output(
    output: &PublishedRecordOutput,
    expected: &[u8],
) -> Result<Vec<u8>, ProductionDoryV3ModelRecordV2CeremonyError> {
    let mut file = output.reader()?;
    let expected_len = u64::try_from(expected.len())
        .map_err(|_| ProductionDoryV3ModelRecordV2CeremonyError::RecordLengthOverflow)?;
    if file
        .metadata()
        .map_err(
            |source| ProductionDoryV3ModelRecordV2CeremonyError::ReadOutput {
                path: output.path.clone(),
                source,
            },
        )?
        .len()
        != expected_len
    {
        return Err(ProductionDoryV3ModelRecordV2CeremonyError::NonCanonicalRecordBytes);
    }
    let read_limit = expected_len
        .checked_add(1)
        .ok_or(ProductionDoryV3ModelRecordV2CeremonyError::RecordLengthOverflow)?;
    let mut bytes = Vec::with_capacity(expected.len());
    Read::take(&mut file, read_limit)
        .read_to_end(&mut bytes)
        .map_err(
            |source| ProductionDoryV3ModelRecordV2CeremonyError::ReadOutput {
                path: output.path.clone(),
                source,
            },
        )?;
    if bytes != expected {
        return Err(ProductionDoryV3ModelRecordV2CeremonyError::NonCanonicalRecordBytes);
    }
    Ok(bytes)
}

fn finish_or_cleanup_output<T>(
    output: &mut PublishedRecordOutput,
    completion: Result<T, ProductionDoryV3ModelRecordV2CeremonyError>,
) -> Result<T, ProductionDoryV3ModelRecordV2CeremonyError> {
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
    output: &mut PublishedRecordOutput,
    error: ProductionDoryV3ModelRecordV2CeremonyError,
) -> ProductionDoryV3ModelRecordV2CeremonyError {
    match output.remove_explicit() {
        Ok(()) => error,
        Err(cleanup) => cleanup,
    }
}

fn retained_file_identity(
    file: File,
    path: &Path,
) -> Result<SameFileHandle, ProductionDoryV3ModelRecordV2CeremonyError> {
    let metadata = file.metadata().map_err(|source| {
        ProductionDoryV3ModelRecordV2CeremonyError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(
            ProductionDoryV3ModelRecordV2CeremonyError::OutputNotRegular(path.to_path_buf()),
        );
    }
    SameFileHandle::from_file(file).map_err(|source| {
        ProductionDoryV3ModelRecordV2CeremonyError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn regular_path_identity(
    path: &Path,
) -> Result<SameFileHandle, ProductionDoryV3ModelRecordV2CeremonyError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        ProductionDoryV3ModelRecordV2CeremonyError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(
            ProductionDoryV3ModelRecordV2CeremonyError::OutputNotRegular(path.to_path_buf()),
        );
    }
    SameFileHandle::from_path(path).map_err(|source| {
        ProductionDoryV3ModelRecordV2CeremonyError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn ensure_path_identity(
    path: &Path,
    expected: &SameFileHandle,
) -> Result<(), ProductionDoryV3ModelRecordV2CeremonyError> {
    if &regular_path_identity(path)? != expected {
        return Err(
            ProductionDoryV3ModelRecordV2CeremonyError::OutputIdentityMismatch(path.to_path_buf()),
        );
    }
    Ok(())
}

fn remove_file_if_identity(
    path: &Path,
    expected: &SameFileHandle,
) -> Result<(), ProductionDoryV3ModelRecordV2CeremonyError> {
    ensure_path_identity(path, expected).map_err(|error| cleanup_error(path, error.to_string()))?;
    fs::remove_file(path).map_err(
        |source| ProductionDoryV3ModelRecordV2CeremonyError::Cleanup {
            path: path.to_path_buf(),
            source,
        },
    )
}

fn cleanup_error(
    path: &Path,
    message: impl Into<String>,
) -> ProductionDoryV3ModelRecordV2CeremonyError {
    ProductionDoryV3ModelRecordV2CeremonyError::Cleanup {
        path: path.to_path_buf(),
        source: std::io::Error::other(message.into()),
    }
}

fn clone_rewound_file(
    file: &SameFileHandle,
    path: &Path,
) -> Result<File, ProductionDoryV3ModelRecordV2CeremonyError> {
    let mut cloned = file.as_file().try_clone().map_err(|source| {
        ProductionDoryV3ModelRecordV2CeremonyError::ReadOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    cloned.seek(SeekFrom::Start(0)).map_err(|source| {
        ProductionDoryV3ModelRecordV2CeremonyError::ReadOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(cloned)
}

fn elapsed_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(unix)]
fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_output_parent(path: &Path) -> Result<(), ProductionDoryV3ModelRecordV2CeremonyError> {
    let parent = output_parent(path);
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(
            |source| ProductionDoryV3ModelRecordV2CeremonyError::SyncParent {
                path: parent.to_path_buf(),
                source,
            },
        )
}

#[cfg(not(unix))]
fn sync_output_parent(_path: &Path) -> Result<(), ProductionDoryV3ModelRecordV2CeremonyError> {
    Ok(())
}

struct PublishedRecordOutput {
    path: PathBuf,
    retained: Option<SameFileHandle>,
    finished: bool,
}

impl PublishedRecordOutput {
    fn identity(&self) -> Result<&SameFileHandle, ProductionDoryV3ModelRecordV2CeremonyError> {
        self.retained.as_ref().ok_or_else(|| {
            ProductionDoryV3ModelRecordV2CeremonyError::OutputIdentityMismatch(self.path.clone())
        })
    }

    fn reader(&self) -> Result<File, ProductionDoryV3ModelRecordV2CeremonyError> {
        clone_rewound_file(self.identity()?, &self.path)
    }

    fn ensure_current_path(&self) -> Result<(), ProductionDoryV3ModelRecordV2CeremonyError> {
        ensure_path_identity(&self.path, self.identity()?)
    }

    fn remove_explicit(&mut self) -> Result<(), ProductionDoryV3ModelRecordV2CeremonyError> {
        if self.finished {
            return Ok(());
        }
        let identity = self
            .retained
            .as_ref()
            .ok_or_else(|| cleanup_error(&self.path, "output identity is unavailable"))?;
        remove_file_if_identity(&self.path, identity)?;
        self.retained.take();
        self.finished = true;
        Ok(())
    }

    fn confirm(&mut self) {
        self.retained.take();
        self.finished = true;
    }
}

impl Drop for PublishedRecordOutput {
    fn drop(&mut self) {
        if !self.finished
            && let Some(identity) = self.retained.as_ref()
        {
            let _ = remove_file_if_identity(&self.path, identity);
        }
        self.retained.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let unique = format!(
            "cmfd-dory-v3-ceremony-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    fn production_manifest() -> ModelBankManifest {
        let suite = &*DORY_V3_PRODUCTION_SUITE_MANIFEST;
        let base_input_bytes = u64::from(DORY_V3_BATCH) * u64::from(DORY_V3_DIMENSION);
        let bytes_per_layer = u64::from(DORY_V3_DIMENSION) * u64::from(DORY_V3_DIMENSION);
        ModelBankManifest {
            model_version: DORY_V3_MODEL_VERSION,
            dimension: DORY_V3_DIMENSION,
            batch: DORY_V3_BATCH,
            layers: DORY_V3_LAYERS,
            base_input_bytes,
            bytes_per_layer,
            payload_bytes: u64::from(DORY_V3_LAYERS) * bytes_per_layer + base_input_bytes,
            raw_blake3_root: [0x11; 32],
            layer_roots_aggregate: [0x22; 32],
            pcs_parameter_digest: suite.digest().into_bytes(),
            pcs_commitment_root: [0x33; 32],
        }
    }

    #[test]
    fn production_manifest_preflight_accepts_only_exact_geometry_and_suite_digest() {
        let manifest = production_manifest();
        assert_eq!(
            preflight_production_dory_v3_model_bank_manifest(&manifest)
                .unwrap()
                .into_bytes(),
            manifest.digest().unwrap()
        );

        let mut wrong_geometry = manifest;
        wrong_geometry.layers /= 2;
        wrong_geometry.payload_bytes = u64::from(wrong_geometry.layers)
            * wrong_geometry.bytes_per_layer
            + wrong_geometry.base_input_bytes;
        assert!(matches!(
            preflight_production_dory_v3_model_bank_manifest(&wrong_geometry),
            Err(ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(_))
        ));

        let mut wrong_suite = manifest;
        wrong_suite.pcs_parameter_digest[0] ^= 1;
        assert!(matches!(
            preflight_production_dory_v3_model_bank_manifest(&wrong_suite),
            Err(ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(_))
        ));

        let mut missing_root = manifest;
        missing_root.raw_blake3_root = [0; 32];
        assert!(matches!(
            preflight_production_dory_v3_model_bank_manifest(&missing_root),
            Err(ProductionDoryV3ModelRecordV2CeremonyError::ProductionManifestMismatch(_))
        ));
    }

    #[test]
    fn existing_output_rejects_before_setup_or_bank_access() {
        let output = temp_path("existing");
        fs::write(&output, b"do not overwrite").unwrap();
        let missing_bank = output.with_extension("missing-bank");

        let error = run_production_dory_v3_model_record_v2_ceremony(
            &missing_bank,
            &production_manifest(),
            &output,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3ModelRecordV2CeremonyError::OutputExists(path) if path == output
        ));
        assert_eq!(fs::read(&output).unwrap(), b"do not overwrite");
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn explicit_cleanup_removes_only_unconfirmed_owned_output() {
        let unconfirmed = temp_path("unconfirmed");
        let mut guard = write_new_output(&unconfirmed, b"unconfirmed").unwrap();
        assert!(unconfirmed.is_file());
        guard.remove_explicit().unwrap();
        drop(guard);
        assert!(!unconfirmed.exists());

        let confirmed = temp_path("confirmed");
        let mut guard = write_new_output(&confirmed, b"confirmed").unwrap();
        guard.confirm();
        drop(guard);
        assert_eq!(fs::read(&confirmed).unwrap(), b"confirmed");
        fs::remove_file(confirmed).unwrap();
    }

    #[test]
    fn write_failure_explicitly_removes_the_owned_output() {
        let output = temp_path("write-failure");
        let error = match write_new_output_with(&output, |_file| {
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "injected write failure",
            ))
        }) {
            Ok(_) => panic!("injected write failure must reject"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ProductionDoryV3ModelRecordV2CeremonyError::WriteOutput { path, source }
                if path == output && source.kind() == std::io::ErrorKind::WriteZero
        ));
        assert!(!output.exists());
    }

    #[test]
    fn corrupted_owned_output_is_rejected_and_explicitly_removed() {
        let output = temp_path("corrupted");
        let expected = b"record-v2";
        let mut guard = write_new_output(&output, expected).unwrap();
        fs::write(&output, b"record-v3").unwrap();

        let completion = read_exact_output(&guard, expected).map(|_| ());
        let error = finish_or_cleanup_output(&mut guard, completion).unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3ModelRecordV2CeremonyError::NonCanonicalRecordBytes
        ));
        assert!(!output.exists());
    }

    #[test]
    fn create_new_never_overwrites_an_existing_output() {
        let output = temp_path("create-new-existing");
        fs::write(&output, b"keep me").unwrap();

        let error = match write_new_output(&output, b"replacement") {
            Ok(_) => panic!("create-new output must not overwrite"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ProductionDoryV3ModelRecordV2CeremonyError::OutputExists(path) if path == output
        ));
        assert_eq!(fs::read(&output).unwrap(), b"keep me");
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn replacement_is_preserved_and_cleanup_failure_is_surfaced() {
        let output = temp_path("replacement");
        let mut guard = write_new_output(&output, b"owned output").unwrap();
        fs::remove_file(&output).unwrap();
        fs::write(&output, b"replacement").unwrap();

        // The retained descriptor still reads the original inode, but the
        // final pathname check must reject the replacement before success.
        let completion = read_exact_output(&guard, b"owned output").map(|_| ());
        let error = finish_or_cleanup_output(&mut guard, completion).unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3ModelRecordV2CeremonyError::Cleanup { path, .. }
                if path == output
        ));
        assert_eq!(fs::read(&output).unwrap(), b"replacement");
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn nonregular_replacement_is_preserved_and_never_reported_as_success() {
        let output = temp_path("nonregular-replacement");
        let mut guard = write_new_output(&output, b"owned output").unwrap();
        fs::remove_file(&output).unwrap();
        fs::create_dir(&output).unwrap();

        let error = finish_or_cleanup_output(&mut guard, Ok(())).unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3ModelRecordV2CeremonyError::Cleanup { path, .. }
                if path == output
        ));
        assert!(output.is_dir());
        fs::remove_dir(output).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_replacement_is_preserved_and_never_followed_for_cleanup() {
        use std::os::unix::fs::symlink;

        let output = temp_path("symlink-replacement");
        let target = temp_path("symlink-target");
        fs::write(&target, b"target").unwrap();
        let mut guard = write_new_output(&output, b"owned output").unwrap();
        fs::remove_file(&output).unwrap();
        symlink(&target, &output).unwrap();

        let error = finish_or_cleanup_output(&mut guard, Ok(())).unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3ModelRecordV2CeremonyError::Cleanup { path, .. }
                if path == output
        ));
        assert!(
            fs::symlink_metadata(&output)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"target");
        fs::remove_file(output).unwrap();
        fs::remove_file(target).unwrap();
    }
}
