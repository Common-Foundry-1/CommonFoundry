//! Dormant, production-only bootstrap for a seedless ForgeMatrix V2 model bank.
//!
//! This module never generates entropy and accepts no caller-supplied root or
//! commitment. It consumes one already-generated canonical payload, derives
//! every byte root and ordered Dory commitment, writes a final header and
//! strict manifest to temporary files, and publishes create-new outputs only
//! after the temporary bank verifies. The published bank is then reopened and
//! authenticated through Record V2 before success is reported.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use same_file::Handle as SameFileHandle;
use serde::Serialize;
use thiserror::Error;

use crate::{
    MAX_MODEL_BYTE, MODEL_BANK_HEADER_BYTES, ModelBankError, ModelBankFieldStreamError,
    ModelBankManifest,
    dory_bls12_381_layout::{
        BlsDoryDerivedModelCommitments, BlsDoryFixedModelStreamError,
        derive_bls_dory_model_commitments_from_verified_layout,
    },
    dory_bls12_381_prototype::{
        BlsDoryPrototypeError, DeterministicBlsDorySetup, deterministic_bls_dory_setup,
    },
    dory_v3_model::{
        CanonicalBlsDoryGtHex, DoryV3ModelIdentityError, DoryV3ModelIdentityV1,
        ordered_dory_v3_model_commitment_root,
    },
    dory_v3_model_record::{
        DoryV3ModelCommitmentRecordError, DoryV3ModelCommitmentRecordV2,
        derive_bank_authenticated_dory_v3_model_commitment_record_v2,
    },
    dory_v3_suite::{
        DORY_V3_BANKS, DORY_V3_BATCH, DORY_V3_DIMENSION, DORY_V3_LAYERS, DORY_V3_LAYERS_PER_BANK,
        DORY_V3_MODEL_IDENTITY_VERSION, DORY_V3_MODEL_VERSION, DORY_V3_PADDED_VARIABLES,
        DORY_V3_PRODUCTION_SUITE_MANIFEST, Digest32,
    },
    model_bank::{
        add_layer_root, canonical_model_bank_manifest_json, encode_model_bank_header,
        start_layer_aggregate,
    },
    verify_model_bank,
};

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const PROVISIONAL_COMMITMENT_ROOT: [u8; 32] = [0xa5; 32];
static TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionDoryV3ModelBankBootstrapReport {
    pub payload: PathBuf,
    pub bank_output: PathBuf,
    pub manifest_output: PathBuf,
    pub payload_bytes: u64,
    pub bank_bytes: u64,
    pub manifest_digest: Digest32,
    pub raw_blake3_root: Digest32,
    pub layer_roots_aggregate: Digest32,
    pub commitment_root: Digest32,
    pub base_input_commitment: CanonicalBlsDoryGtHex,
    pub weight_bank_commitments: Vec<CanonicalBlsDoryGtHex>,
    pub model_identity_digest: Digest32,
    pub record_v2_digest: Digest32,
    pub setup_identity: Digest32,
    pub padded_variables: u32,
    pub setup_elapsed_micros: u64,
    pub payload_copy_elapsed_micros: u64,
    pub commitment_derivation_elapsed_micros: u64,
    pub final_reauthentication_elapsed_micros: u64,
    /// Two separately named files cannot be published atomically with portable
    /// Rust filesystem APIs. Every visible output is already fully formed, and
    /// the manifest is linked last, but a process or power failure can leave
    /// only the valid bank. A successful report means both were reopened and
    /// checked.
    pub publication_is_multi_file_crash_atomic: bool,
}

#[derive(Debug, Error)]
pub enum ProductionDoryV3ModelBankBootstrapError {
    #[error("bank and manifest output paths must be different")]
    SameOutputPath,
    #[error("refusing to overwrite existing output: {0}")]
    OutputExists(PathBuf),
    #[error("failed to inspect output path {path}: {source}")]
    InspectOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("artifact path is not a regular file: {0}")]
    ArtifactNotRegular(PathBuf),
    #[error("artifact path was replaced or no longer names the retained file: {0}")]
    FileIdentityMismatch(PathBuf),
    #[error("output parent is not an existing directory: {0}")]
    OutputParent(PathBuf),
    #[error("failed to inspect payload {path}: {source}")]
    InspectPayload {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("payload must be a regular file: {0}")]
    PayloadNotFile(PathBuf),
    #[error("payload length mismatch: expected {expected} bytes, found {actual}")]
    PayloadLength { expected: u64, actual: u64 },
    #[error("production geometry overflowed")]
    GeometryOverflow,
    #[error("compiled production bank partition does not equal 384 layers")]
    ProductionGeometryMismatch,
    #[error("failed to derive or validate the pinned n=33 setup: {0}")]
    Setup(#[source] BlsDoryPrototypeError),
    #[error("the compiled production Dory V3 suite is invalid")]
    InvalidProductionSuite,
    #[error("derived setup does not match the compiled production suite")]
    PinnedSetupMismatch,
    #[error("failed to create temporary artifact {path}: {source}")]
    CreateTemporary {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write or sync {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("raw payload validation failed: {0}")]
    Payload(#[source] ModelBankError),
    #[error("Dory commitment derivation failed: {0}")]
    CommitmentDerivation(#[source] ModelBankFieldStreamError<BlsDoryFixedModelStreamError>),
    #[error("Dory model identity failed: {0}")]
    ModelIdentity(#[source] DoryV3ModelIdentityError),
    #[error("Record V2 validation failed: {0}")]
    Record(#[source] DoryV3ModelCommitmentRecordError),
    #[error("manifest serialization failed: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("temporary or final bank verification failed: {0}")]
    VerifyBank(#[source] ModelBankError),
    #[error("rederived commitments differ from the bootstrap commitments")]
    CommitmentMismatch,
    #[error("the reopened Record V2 bytes or digests differ from the bootstrap record")]
    RecordMismatch,
    #[error("manifest bytes or decoded value changed during publication")]
    ManifestMismatch,
    #[error("failed to publish create-new output {path}: {source}")]
    Publish {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to remove verified temporary artifact {path}: {source}")]
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

#[derive(Debug, Clone, Copy)]
struct BootstrapGeometry {
    model_version: u32,
    batch: u32,
    dimension: u32,
    layers_per_bank: u32,
    banks: u32,
    padded_variables: u32,
    pcs_parameter_digest: [u8; 32],
}

impl BootstrapGeometry {
    fn production() -> Self {
        let suite = &*DORY_V3_PRODUCTION_SUITE_MANIFEST;
        Self {
            model_version: DORY_V3_MODEL_VERSION,
            batch: DORY_V3_BATCH,
            dimension: DORY_V3_DIMENSION,
            layers_per_bank: DORY_V3_LAYERS_PER_BANK,
            banks: DORY_V3_BANKS,
            padded_variables: DORY_V3_PADDED_VARIABLES,
            pcs_parameter_digest: suite.digest().into_bytes(),
        }
    }

    fn layers(self) -> Result<u32, ProductionDoryV3ModelBankBootstrapError> {
        self.layers_per_bank
            .checked_mul(self.banks)
            .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)
    }

    fn base_input_bytes(self) -> Result<u64, ProductionDoryV3ModelBankBootstrapError> {
        u64::from(self.batch)
            .checked_mul(u64::from(self.dimension))
            .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)
    }

    fn bytes_per_layer(self) -> Result<u64, ProductionDoryV3ModelBankBootstrapError> {
        u64::from(self.dimension)
            .checked_mul(u64::from(self.dimension))
            .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)
    }

    fn payload_bytes(self) -> Result<u64, ProductionDoryV3ModelBankBootstrapError> {
        let layer_bytes = u64::from(self.layers()?)
            .checked_mul(self.bytes_per_layer()?)
            .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?;
        layer_bytes
            .checked_add(self.base_input_bytes()?)
            .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)
    }
}

struct PreparedBootstrap {
    bank_temp: TemporaryArtifact,
    manifest_temp: TemporaryArtifact,
    manifest: ModelBankManifest,
    manifest_bytes: Vec<u8>,
    commitments: BlsDoryDerivedModelCommitments,
    payload_copy_elapsed: Duration,
    commitment_derivation_elapsed: Duration,
}

impl PreparedBootstrap {
    fn remove_temporary_paths(&mut self) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
        self.bank_temp.remove_explicit()?;
        self.manifest_temp.remove_explicit()
    }
}

/// Bootstrap a final production bank from already-generated, seedless payload
/// bytes. This function does not generate entropy and has no root or commitment
/// arguments.
pub fn run_production_dory_v3_model_bank_bootstrap(
    payload_path: &Path,
    bank_output: &Path,
    manifest_output: &Path,
) -> Result<ProductionDoryV3ModelBankBootstrapReport, ProductionDoryV3ModelBankBootstrapError> {
    preflight_outputs(bank_output, manifest_output)?;
    let suite = &*DORY_V3_PRODUCTION_SUITE_MANIFEST;
    suite
        .validate()
        .map_err(|_| ProductionDoryV3ModelBankBootstrapError::InvalidProductionSuite)?;
    let geometry = BootstrapGeometry::production();
    if geometry.layers()? != DORY_V3_LAYERS {
        return Err(ProductionDoryV3ModelBankBootstrapError::ProductionGeometryMismatch);
    }
    preflight_payload(payload_path, geometry.payload_bytes()?)?;

    let setup_started = Instant::now();
    let setup = deterministic_bls_dory_setup(geometry.padded_variables as usize)
        .map_err(ProductionDoryV3ModelBankBootstrapError::Setup)?;
    setup
        .validate()
        .map_err(ProductionDoryV3ModelBankBootstrapError::Setup)?;
    let setup_elapsed = setup_started.elapsed();
    if setup.max_log_n() != geometry.padded_variables as usize
        || setup.identity() != suite.setup_identity.into_bytes()
    {
        return Err(ProductionDoryV3ModelBankBootstrapError::PinnedSetupMismatch);
    }

    let mut prepared =
        prepare_bootstrap(payload_path, bank_output, manifest_output, geometry, &setup)?;
    let identity = DoryV3ModelIdentityV1::new(
        suite,
        geometry.model_version,
        geometry.batch,
        geometry.dimension,
        geometry.layers_per_bank,
        prepared.manifest.raw_blake3_root,
        prepared.manifest.layer_roots_aggregate,
        geometry.padded_variables,
        &setup,
        prepared.commitments.base_input,
        prepared.commitments.weight_banks.clone(),
    )
    .map_err(ProductionDoryV3ModelBankBootstrapError::ModelIdentity)?;
    if identity
        .commitment_root()
        .map_err(ProductionDoryV3ModelBankBootstrapError::ModelIdentity)?
        != prepared.manifest.pcs_commitment_root
    {
        return Err(ProductionDoryV3ModelBankBootstrapError::CommitmentMismatch);
    }
    let prospective_record = DoryV3ModelCommitmentRecordV2::new(prepared.manifest, identity)
        .map_err(ProductionDoryV3ModelBankBootstrapError::Record)?;
    prospective_record
        .validate_production(&setup)
        .map_err(ProductionDoryV3ModelBankBootstrapError::Record)?;

    let (mut bank_guard, mut manifest_guard) =
        publish_prepared(&prepared, bank_output, manifest_output)?;
    let completion = (|| {
        let final_reauthentication_started = Instant::now();
        let reopened_manifest = verify_published_manifest(&prepared, &manifest_guard)?;
        let prospective_record_bytes = serde_json::to_vec(&prospective_record)
            .map_err(ProductionDoryV3ModelBankBootstrapError::Serialize)?;
        let reopened_record: DoryV3ModelCommitmentRecordV2 =
            serde_json::from_slice(&prospective_record_bytes)
                .map_err(ProductionDoryV3ModelBankBootstrapError::Serialize)?;
        reopened_record
            .validate_production(&setup)
            .map_err(ProductionDoryV3ModelBankBootstrapError::Record)?;
        if reopened_record.manifest() != &reopened_manifest
            || reopened_record != prospective_record
            || reopened_record.canonical_bytes() != prospective_record.canonical_bytes()
            || reopened_record.record_digest() != prospective_record.record_digest()
        {
            return Err(ProductionDoryV3ModelBankBootstrapError::RecordMismatch);
        }
        let structural = reopened_record
            .model_identity()
            .validate_production_structure(&reopened_manifest, &setup)
            .map_err(ProductionDoryV3ModelBankBootstrapError::ModelIdentity)?;
        let authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2(
            bank_guard.reader()?,
            &structural,
            &setup,
        )
        .map_err(ProductionDoryV3ModelBankBootstrapError::Record)?;
        if authenticated.record() != &reopened_record
            || authenticated.record().canonical_bytes() != reopened_record.canonical_bytes()
            || authenticated.record().record_digest() != reopened_record.record_digest()
        {
            return Err(ProductionDoryV3ModelBankBootstrapError::RecordMismatch);
        }
        // The commitment pass is long. Reread both retained published-file handles
        // so a late content mutation cannot be hidden by the earlier reads.
        verify_published_manifest(&prepared, &manifest_guard)?;
        verify_model_bank(bank_guard.reader()?, &reopened_manifest)
            .map_err(ProductionDoryV3ModelBankBootstrapError::VerifyBank)?;
        let final_reauthentication_elapsed = final_reauthentication_started.elapsed();
        let bank_bytes = geometry
            .payload_bytes()?
            .checked_add(MODEL_BANK_HEADER_BYTES as u64)
            .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?;
        let report = ProductionDoryV3ModelBankBootstrapReport {
            payload: payload_path.to_path_buf(),
            bank_output: bank_output.to_path_buf(),
            manifest_output: manifest_output.to_path_buf(),
            payload_bytes: geometry.payload_bytes()?,
            bank_bytes,
            manifest_digest: Digest32::new(
                prepared
                    .manifest
                    .digest()
                    .map_err(ProductionDoryV3ModelBankBootstrapError::VerifyBank)?,
            ),
            raw_blake3_root: Digest32::new(prepared.manifest.raw_blake3_root),
            layer_roots_aggregate: Digest32::new(prepared.manifest.layer_roots_aggregate),
            commitment_root: Digest32::new(prepared.manifest.pcs_commitment_root),
            base_input_commitment: *prospective_record
                .model_identity()
                .encoded_base_input_commitment(),
            weight_bank_commitments: prospective_record
                .model_identity()
                .encoded_weight_bank_commitments()
                .to_vec(),
            model_identity_digest: prospective_record.model_identity_digest(),
            record_v2_digest: prospective_record.record_digest(),
            setup_identity: Digest32::new(setup.identity()),
            padded_variables: geometry.padded_variables,
            setup_elapsed_micros: elapsed_micros(setup_elapsed),
            payload_copy_elapsed_micros: elapsed_micros(prepared.payload_copy_elapsed),
            commitment_derivation_elapsed_micros: elapsed_micros(
                prepared.commitment_derivation_elapsed,
            ),
            final_reauthentication_elapsed_micros: elapsed_micros(final_reauthentication_elapsed),
            publication_is_multi_file_crash_atomic: false,
        };
        prepared.remove_temporary_paths()?;
        sync_output_parents(bank_output, manifest_output)?;
        bank_guard.ensure_current_path()?;
        manifest_guard.ensure_current_path()?;
        Ok(report)
    })();
    let report =
        finish_or_cleanup_published_outputs(&mut bank_guard, &mut manifest_guard, completion)?;
    bank_guard.confirm();
    manifest_guard.confirm();
    Ok(report)
}

fn prepare_bootstrap(
    payload_path: &Path,
    bank_output: &Path,
    manifest_output: &Path,
    geometry: BootstrapGeometry,
    setup: &DeterministicBlsDorySetup,
) -> Result<PreparedBootstrap, ProductionDoryV3ModelBankBootstrapError> {
    let (mut bank_file, bank_temp) = create_temporary_near(bank_output, "bank")?;
    write_all(
        &mut bank_file,
        bank_temp.path(),
        &[0; MODEL_BANK_HEADER_BYTES],
    )?;

    let payload_copy_started = Instant::now();
    let payload_file = open_file(payload_path)?;
    let roots = copy_and_hash_payload(payload_file, &mut bank_file, bank_temp.path(), geometry)?;
    let payload_copy_elapsed = payload_copy_started.elapsed();

    let provisional_manifest = manifest_from_roots(geometry, roots, PROVISIONAL_COMMITMENT_ROOT)?;
    rewrite_header(&mut bank_file, bank_temp.path(), &provisional_manifest)?;
    drop(bank_file);

    let commitment_derivation_started = Instant::now();
    let commitments = derive_bls_dory_model_commitments_from_verified_layout(
        bank_temp.reader()?,
        &provisional_manifest,
        geometry.batch,
        geometry.dimension,
        geometry.layers_per_bank,
        geometry.banks,
        geometry.padded_variables as usize,
        setup,
    )
    .map_err(ProductionDoryV3ModelBankBootstrapError::CommitmentDerivation)?;
    let encoded_base = CanonicalBlsDoryGtHex::from_commitment(commitments.base_input)
        .map_err(ProductionDoryV3ModelBankBootstrapError::ModelIdentity)?;
    let encoded_weights = commitments
        .weight_banks
        .iter()
        .copied()
        .map(CanonicalBlsDoryGtHex::from_commitment)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ProductionDoryV3ModelBankBootstrapError::ModelIdentity)?;
    let commitment_root = ordered_dory_v3_model_commitment_root(
        DORY_V3_MODEL_IDENTITY_VERSION,
        geometry.pcs_parameter_digest,
        setup.identity(),
        geometry.padded_variables,
        &encoded_base,
        &encoded_weights,
    )
    .map_err(ProductionDoryV3ModelBankBootstrapError::ModelIdentity)?;
    let commitment_derivation_elapsed = commitment_derivation_started.elapsed();
    let manifest = manifest_from_roots(geometry, roots, commitment_root)?;

    let mut bank_file = bank_temp.reader()?;
    rewrite_header(&mut bank_file, bank_temp.path(), &manifest)?;
    drop(bank_file);
    verify_model_bank(bank_temp.reader()?, &manifest)
        .map_err(ProductionDoryV3ModelBankBootstrapError::VerifyBank)?;

    let manifest_bytes = canonical_model_bank_manifest_json(&manifest)
        .map_err(ProductionDoryV3ModelBankBootstrapError::Serialize)?;
    let (mut manifest_file, manifest_temp) = create_temporary_near(manifest_output, "manifest")?;
    write_all(&mut manifest_file, manifest_temp.path(), &manifest_bytes)?;
    sync_file(&manifest_file, manifest_temp.path())?;
    drop(manifest_file);

    Ok(PreparedBootstrap {
        bank_temp,
        manifest_temp,
        manifest,
        manifest_bytes,
        commitments,
        payload_copy_elapsed,
        commitment_derivation_elapsed,
    })
}

#[derive(Debug, Clone, Copy)]
struct PayloadRoots {
    raw: [u8; 32],
    layers: [u8; 32],
}

fn copy_and_hash_payload<R: Read, W: Write>(
    mut reader: R,
    writer: &mut W,
    destination_path: &Path,
    geometry: BootstrapGeometry,
) -> Result<PayloadRoots, ProductionDoryV3ModelBankBootstrapError> {
    let mut raw_hasher = blake3::Hasher::new();
    let mut payload_offset = 0_u64;
    copy_section(
        &mut reader,
        writer,
        destination_path,
        geometry.base_input_bytes()?,
        &mut payload_offset,
        &mut raw_hasher,
        None,
    )?;
    let layers = geometry.layers()?;
    let mut layer_aggregate = start_layer_aggregate(layers);
    for index in 0..layers {
        let mut layer_hasher = blake3::Hasher::new();
        copy_section(
            &mut reader,
            writer,
            destination_path,
            geometry.bytes_per_layer()?,
            &mut payload_offset,
            &mut raw_hasher,
            Some(&mut layer_hasher),
        )?;
        add_layer_root(&mut layer_aggregate, index, layer_hasher.finalize());
    }
    if payload_offset != geometry.payload_bytes()? {
        return Err(ProductionDoryV3ModelBankBootstrapError::Payload(
            ModelBankError::NonCanonicalLengths,
        ));
    }
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => {
            return Err(ProductionDoryV3ModelBankBootstrapError::Payload(
                ModelBankError::TrailingBytes,
            ));
        }
        Err(error) => {
            return Err(ProductionDoryV3ModelBankBootstrapError::Payload(
                ModelBankError::Io(error),
            ));
        }
    }
    Ok(PayloadRoots {
        raw: *raw_hasher.finalize().as_bytes(),
        layers: *layer_aggregate.finalize().as_bytes(),
    })
}

fn copy_section<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    destination_path: &Path,
    bytes: u64,
    payload_offset: &mut u64,
    raw_hasher: &mut blake3::Hasher,
    mut section_hasher: Option<&mut blake3::Hasher>,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    let mut remaining = bytes;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining != 0 {
        let take = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
            .map_err(|_| ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?;
        if let Err(error) = reader.read_exact(&mut buffer[..take]) {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                return Err(ProductionDoryV3ModelBankBootstrapError::Payload(
                    ModelBankError::Truncated,
                ));
            }
            return Err(ProductionDoryV3ModelBankBootstrapError::Payload(
                ModelBankError::Io(error),
            ));
        }
        if let Some((index, value)) = buffer[..take]
            .iter()
            .copied()
            .enumerate()
            .find(|(_, value)| *value > MAX_MODEL_BYTE)
        {
            let offset = payload_offset
                .checked_add(
                    u64::try_from(index)
                        .map_err(|_| ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?,
                )
                .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?;
            return Err(ProductionDoryV3ModelBankBootstrapError::Payload(
                ModelBankError::OutOfRange { offset, value },
            ));
        }
        writer.write_all(&buffer[..take]).map_err(|source| {
            ProductionDoryV3ModelBankBootstrapError::Write {
                path: destination_path.to_path_buf(),
                source,
            }
        })?;
        raw_hasher.update(&buffer[..take]);
        if let Some(hasher) = section_hasher.as_deref_mut() {
            hasher.update(&buffer[..take]);
        }
        let take_u64 = u64::try_from(take)
            .map_err(|_| ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?;
        *payload_offset = payload_offset
            .checked_add(take_u64)
            .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?;
        remaining -= take_u64;
    }
    Ok(())
}

fn manifest_from_roots(
    geometry: BootstrapGeometry,
    roots: PayloadRoots,
    commitment_root: [u8; 32],
) -> Result<ModelBankManifest, ProductionDoryV3ModelBankBootstrapError> {
    Ok(ModelBankManifest {
        model_version: geometry.model_version,
        dimension: geometry.dimension,
        batch: geometry.batch,
        layers: geometry.layers()?,
        base_input_bytes: geometry.base_input_bytes()?,
        bytes_per_layer: geometry.bytes_per_layer()?,
        payload_bytes: geometry.payload_bytes()?,
        raw_blake3_root: roots.raw,
        layer_roots_aggregate: roots.layers,
        pcs_parameter_digest: geometry.pcs_parameter_digest,
        pcs_commitment_root: commitment_root,
    })
}

fn rewrite_header(
    file: &mut File,
    path: &Path,
    manifest: &ModelBankManifest,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    file.seek(SeekFrom::Start(0)).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::Write {
            path: path.to_path_buf(),
            source,
        }
    })?;
    write_all(file, path, &encode_model_bank_header(manifest))?;
    sync_file(file, path)
}

fn publish_prepared(
    prepared: &PreparedBootstrap,
    bank_output: &Path,
    manifest_output: &Path,
) -> Result<(PublishedOutput, PublishedOutput), ProductionDoryV3ModelBankBootstrapError> {
    prepared.bank_temp.ensure_current_path()?;
    prepared.manifest_temp.ensure_current_path()?;
    let mut bank_guard = publish_one(&prepared.bank_temp, bank_output)?;
    match publish_one(&prepared.manifest_temp, manifest_output) {
        Ok(manifest_guard) => Ok((bank_guard, manifest_guard)),
        Err(error) => match bank_guard.remove_explicit() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(cleanup),
        },
    }
}

fn publish_one(
    temporary: &TemporaryArtifact,
    output: &Path,
) -> Result<PublishedOutput, ProductionDoryV3ModelBankBootstrapError> {
    let identity = temporary.identity()?;
    fs::hard_link(temporary.path(), output).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::Publish {
            path: output.to_path_buf(),
            source,
        }
    })?;
    let mut published = match PublishedOutput::capture(output) {
        Ok(published) => published,
        Err(error) => {
            return match remove_file_if_identity(output, identity) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }
    };
    let matches_temporary = published
        .retained
        .as_ref()
        .is_some_and(|published_identity| published_identity == identity);
    if !matches_temporary {
        let mismatch =
            ProductionDoryV3ModelBankBootstrapError::FileIdentityMismatch(output.to_path_buf());
        return match published.remove_explicit() {
            Ok(()) => Err(mismatch),
            Err(cleanup) => Err(cleanup),
        };
    }
    Ok(published)
}

fn finish_or_cleanup_published_outputs<T>(
    bank: &mut PublishedOutput,
    manifest: &mut PublishedOutput,
    completion: Result<T, ProductionDoryV3ModelBankBootstrapError>,
) -> Result<T, ProductionDoryV3ModelBankBootstrapError> {
    match completion {
        Ok(value) => Ok(value),
        Err(error) => match cleanup_published_outputs(bank, manifest) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(cleanup),
        },
    }
}

fn cleanup_published_outputs(
    bank: &mut PublishedOutput,
    manifest: &mut PublishedOutput,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    let bank_cleanup = bank.remove_explicit();
    let manifest_cleanup = manifest.remove_explicit();
    bank_cleanup.and(manifest_cleanup)
}

fn verify_published_manifest(
    prepared: &PreparedBootstrap,
    manifest_output: &PublishedOutput,
) -> Result<ModelBankManifest, ProductionDoryV3ModelBankBootstrapError> {
    let expected_len = u64::try_from(prepared.manifest_bytes.len())
        .map_err(|_| ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?;
    let mut file = manifest_output.reader()?;
    if file
        .metadata()
        .map_err(|source| ProductionDoryV3ModelBankBootstrapError::Open {
            path: manifest_output.path().to_path_buf(),
            source,
        })?
        .len()
        != expected_len
    {
        return Err(ProductionDoryV3ModelBankBootstrapError::ManifestMismatch);
    }
    let read_limit = expected_len
        .checked_add(1)
        .ok_or(ProductionDoryV3ModelBankBootstrapError::GeometryOverflow)?;
    let mut bytes = Vec::with_capacity(prepared.manifest_bytes.len());
    Read::take(&mut file, read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| ProductionDoryV3ModelBankBootstrapError::Open {
            path: manifest_output.path().to_path_buf(),
            source,
        })?;
    if bytes != prepared.manifest_bytes {
        return Err(ProductionDoryV3ModelBankBootstrapError::ManifestMismatch);
    }
    let decoded: ModelBankManifest = serde_json::from_slice(&bytes)
        .map_err(ProductionDoryV3ModelBankBootstrapError::Serialize)?;
    if decoded != prepared.manifest {
        return Err(ProductionDoryV3ModelBankBootstrapError::ManifestMismatch);
    }
    Ok(decoded)
}

fn preflight_payload(
    payload: &Path,
    expected_bytes: u64,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    let metadata = fs::metadata(payload).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::InspectPayload {
            path: payload.to_path_buf(),
            source,
        }
    })?;
    if !metadata.is_file() {
        return Err(ProductionDoryV3ModelBankBootstrapError::PayloadNotFile(
            payload.to_path_buf(),
        ));
    }
    if metadata.len() != expected_bytes {
        return Err(ProductionDoryV3ModelBankBootstrapError::PayloadLength {
            expected: expected_bytes,
            actual: metadata.len(),
        });
    }
    Ok(())
}

fn preflight_outputs(
    bank_output: &Path,
    manifest_output: &Path,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    let bank_absolute = std::path::absolute(bank_output).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::InspectOutput {
            path: bank_output.to_path_buf(),
            source,
        }
    })?;
    let manifest_absolute = std::path::absolute(manifest_output).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::InspectOutput {
            path: manifest_output.to_path_buf(),
            source,
        }
    })?;
    if bank_absolute == manifest_absolute {
        return Err(ProductionDoryV3ModelBankBootstrapError::SameOutputPath);
    }
    for output in [bank_output, manifest_output] {
        reject_existing(output)?;
        let parent = output_parent(output);
        if !parent.is_dir() {
            return Err(ProductionDoryV3ModelBankBootstrapError::OutputParent(
                parent.to_path_buf(),
            ));
        }
        if output.file_name().is_none() {
            return Err(ProductionDoryV3ModelBankBootstrapError::OutputParent(
                parent.to_path_buf(),
            ));
        }
    }
    Ok(())
}

fn reject_existing(path: &Path) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ProductionDoryV3ModelBankBootstrapError::OutputExists(
            path.to_path_buf(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ProductionDoryV3ModelBankBootstrapError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn create_temporary_near(
    output: &Path,
    label: &str,
) -> Result<(File, TemporaryArtifact), ProductionDoryV3ModelBankBootstrapError> {
    let parent = output_parent(output);
    let file_name = output
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "artifact".into());
    for _ in 0..128 {
        let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = parent.join(format!(
            ".{file_name}.{label}.bootstrap.{}.{}.{nonce}.tmp",
            std::process::id(),
            nanos
        ));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                let retained = match file.try_clone() {
                    Ok(retained) => retained,
                    Err(source) => {
                        // Without a retained identity, deleting by pathname
                        // could remove a concurrent replacement.
                        return Err(abandon_unidentified_temporary(
                            file,
                            ProductionDoryV3ModelBankBootstrapError::CreateTemporary {
                                path,
                                source,
                            },
                        ));
                    }
                };
                let retained = match retained_file_identity(retained, &path) {
                    Ok(identity) => identity,
                    Err(error) => {
                        // Identity acquisition failed, so there is no safe
                        // pathname-based cleanup for this hidden artifact.
                        return Err(abandon_unidentified_temporary(file, error));
                    }
                };
                return Ok((
                    file,
                    TemporaryArtifact {
                        path,
                        retained: Some(retained),
                        removed: false,
                    },
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ProductionDoryV3ModelBankBootstrapError::CreateTemporary {
                    path,
                    source,
                });
            }
        }
    }
    let path = parent.join(format!(".{file_name}.{label}.bootstrap.tmp"));
    Err(ProductionDoryV3ModelBankBootstrapError::CreateTemporary {
        path,
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temporary filename attempts exhausted",
        ),
    })
}

fn open_file(path: &Path) -> Result<File, ProductionDoryV3ModelBankBootstrapError> {
    File::open(path).map_err(|source| ProductionDoryV3ModelBankBootstrapError::Open {
        path: path.to_path_buf(),
        source,
    })
}

fn abandon_unidentified_temporary(
    file: File,
    error: ProductionDoryV3ModelBankBootstrapError,
) -> ProductionDoryV3ModelBankBootstrapError {
    drop(file);
    error
}

fn write_all(
    file: &mut File,
    path: &Path,
    bytes: &[u8],
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    file.write_all(bytes)
        .map_err(|source| ProductionDoryV3ModelBankBootstrapError::Write {
            path: path.to_path_buf(),
            source,
        })
}

fn sync_file(file: &File, path: &Path) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    file.sync_all()
        .map_err(|source| ProductionDoryV3ModelBankBootstrapError::Write {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(unix)]
fn sync_output_parents(
    bank_output: &Path,
    manifest_output: &Path,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    let bank_parent = output_parent(bank_output);
    sync_parent(bank_parent)?;
    let manifest_parent = output_parent(manifest_output);
    if manifest_parent != bank_parent {
        sync_parent(manifest_parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(
            |source| ProductionDoryV3ModelBankBootstrapError::SyncParent {
                path: path.to_path_buf(),
                source,
            },
        )
}

#[cfg(not(unix))]
fn sync_output_parents(
    _bank_output: &Path,
    _manifest_output: &Path,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    Ok(())
}

fn elapsed_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn retained_file_identity(
    file: File,
    path: &Path,
) -> Result<SameFileHandle, ProductionDoryV3ModelBankBootstrapError> {
    let metadata = file.metadata().map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(ProductionDoryV3ModelBankBootstrapError::ArtifactNotRegular(
            path.to_path_buf(),
        ));
    }
    SameFileHandle::from_file(file).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn regular_path_identity(
    path: &Path,
) -> Result<SameFileHandle, ProductionDoryV3ModelBankBootstrapError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(ProductionDoryV3ModelBankBootstrapError::ArtifactNotRegular(
            path.to_path_buf(),
        ));
    }
    SameFileHandle::from_path(path).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::InspectOutput {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn ensure_path_identity(
    path: &Path,
    expected: &SameFileHandle,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    if &regular_path_identity(path)? != expected {
        return Err(
            ProductionDoryV3ModelBankBootstrapError::FileIdentityMismatch(path.to_path_buf()),
        );
    }
    Ok(())
}

fn remove_file_if_identity(
    path: &Path,
    expected: &SameFileHandle,
) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
    ensure_path_identity(path, expected).map_err(|error| cleanup_error(path, error.to_string()))?;
    fs::remove_file(path).map_err(|source| ProductionDoryV3ModelBankBootstrapError::Cleanup {
        path: path.to_path_buf(),
        source,
    })
}

fn cleanup_error(
    path: &Path,
    message: impl Into<String>,
) -> ProductionDoryV3ModelBankBootstrapError {
    ProductionDoryV3ModelBankBootstrapError::Cleanup {
        path: path.to_path_buf(),
        source: std::io::Error::other(message.into()),
    }
}

fn clone_rewound_file(
    file: &SameFileHandle,
    path: &Path,
) -> Result<File, ProductionDoryV3ModelBankBootstrapError> {
    let mut cloned = file.as_file().try_clone().map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::Open {
            path: path.to_path_buf(),
            source,
        }
    })?;
    cloned.seek(SeekFrom::Start(0)).map_err(|source| {
        ProductionDoryV3ModelBankBootstrapError::Open {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(cloned)
}

struct TemporaryArtifact {
    path: PathBuf,
    retained: Option<SameFileHandle>,
    removed: bool,
}

impl TemporaryArtifact {
    fn path(&self) -> &Path {
        &self.path
    }

    fn identity(&self) -> Result<&SameFileHandle, ProductionDoryV3ModelBankBootstrapError> {
        self.retained.as_ref().ok_or_else(|| {
            ProductionDoryV3ModelBankBootstrapError::FileIdentityMismatch(self.path.clone())
        })
    }

    fn reader(&self) -> Result<File, ProductionDoryV3ModelBankBootstrapError> {
        clone_rewound_file(self.identity()?, &self.path)
    }

    fn ensure_current_path(&self) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
        ensure_path_identity(&self.path, self.identity()?)
    }

    fn remove_explicit(&mut self) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
        self.ensure_current_path()?;
        remove_file_if_identity(&self.path, self.identity()?)?;
        self.retained.take();
        self.removed = true;
        Ok(())
    }
}

impl Drop for TemporaryArtifact {
    fn drop(&mut self) {
        if !self.removed
            && let Some(identity) = self.retained.as_ref()
        {
            let _ = remove_file_if_identity(&self.path, identity);
        }
        self.retained.take();
    }
}

struct PublishedOutput {
    path: PathBuf,
    retained: Option<SameFileHandle>,
    finished: bool,
}

impl PublishedOutput {
    fn capture(path: &Path) -> Result<Self, ProductionDoryV3ModelBankBootstrapError> {
        let path_identity = regular_path_identity(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            retained: Some(path_identity),
            finished: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn reader(&self) -> Result<File, ProductionDoryV3ModelBankBootstrapError> {
        clone_rewound_file(self.identity()?, &self.path)
    }

    fn identity(&self) -> Result<&SameFileHandle, ProductionDoryV3ModelBankBootstrapError> {
        self.retained.as_ref().ok_or_else(|| {
            ProductionDoryV3ModelBankBootstrapError::FileIdentityMismatch(self.path.clone())
        })
    }

    fn ensure_current_path(&self) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
        ensure_path_identity(&self.path, self.identity()?)
    }

    fn remove_explicit(&mut self) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
        if self.finished {
            return Ok(());
        }
        let identity = self
            .retained
            .as_ref()
            .ok_or_else(|| cleanup_error(&self.path, "published output identity is unavailable"))?;
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

impl Drop for PublishedOutput {
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

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-model-bootstrap-test-{}-{}",
                std::process::id(),
                TEMP_NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_geometry(setup: &DeterministicBlsDorySetup) -> BootstrapGeometry {
        BootstrapGeometry {
            model_version: 2,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            banks: 2,
            padded_variables: 3,
            pcs_parameter_digest: *blake3::hash(&setup.identity()).as_bytes(),
        }
    }

    fn fixture_payload() -> Vec<u8> {
        vec![
            0, 125, 250, 126, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ]
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected destination failure",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn run_fixture(
        payload_path: &Path,
        bank_output: &Path,
        manifest_output: &Path,
    ) -> Result<ModelBankManifest, ProductionDoryV3ModelBankBootstrapError> {
        preflight_outputs(bank_output, manifest_output)?;
        let setup = deterministic_bls_dory_setup(3)
            .map_err(ProductionDoryV3ModelBankBootstrapError::Setup)?;
        let geometry = fixture_geometry(&setup);
        preflight_payload(payload_path, geometry.payload_bytes()?)?;
        let mut prepared =
            prepare_bootstrap(payload_path, bank_output, manifest_output, geometry, &setup)?;
        let expected = prepared.commitments.clone();
        let (mut bank_guard, mut manifest_guard) =
            publish_prepared(&prepared, bank_output, manifest_output)?;
        let completion = (|| {
            authenticate_fixture_outputs(
                &prepared,
                &bank_guard,
                &manifest_guard,
                geometry,
                &setup,
                &expected,
            )?;
            let manifest = prepared.manifest;
            prepared.remove_temporary_paths()?;
            bank_guard.ensure_current_path()?;
            manifest_guard.ensure_current_path()?;
            Ok(manifest)
        })();
        let manifest =
            finish_or_cleanup_published_outputs(&mut bank_guard, &mut manifest_guard, completion)?;
        bank_guard.confirm();
        manifest_guard.confirm();
        Ok(manifest)
    }

    #[test]
    fn production_entrypoint_preflights_the_exact_payload_size() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, [0_u8]).unwrap();

        assert!(matches!(
            run_production_dory_v3_model_bank_bootstrap(&payload, &bank, &manifest),
            Err(ProductionDoryV3ModelBankBootstrapError::PayloadLength {
                expected: 6_442_975_232,
                actual: 1,
            })
        ));
        assert!(!bank.exists());
        assert!(!manifest.exists());
        let remaining = fs::read_dir(&directory.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(remaining, [std::ffi::OsString::from("payload.bin")]);
    }

    #[test]
    fn payload_copy_maps_writer_failure_to_the_destination_path() {
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let destination = PathBuf::from("bank-output.tmp");
        let mut writer = FailingWriter;
        let error = copy_and_hash_payload(
            std::io::Cursor::new(fixture_payload()),
            &mut writer,
            &destination,
            geometry,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3ModelBankBootstrapError::Write { path, source }
                if path == destination && source.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn unidentified_temporary_failure_does_not_delete_by_path() {
        let directory = TestDirectory::new();
        let path = directory.join("unidentified.tmp");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(7).unwrap();
        let error = ProductionDoryV3ModelBankBootstrapError::CreateTemporary {
            path: path.clone(),
            source: std::io::Error::other("injected identity failure"),
        };

        assert!(matches!(
            abandon_unidentified_temporary(file, error),
            ProductionDoryV3ModelBankBootstrapError::CreateTemporary {
                path: error_path,
                ..
            } if error_path == path
        ));
        assert_eq!(fs::metadata(path).unwrap().len(), 7);
    }

    fn authenticate_fixture_outputs(
        prepared: &PreparedBootstrap,
        bank_output: &PublishedOutput,
        manifest_output: &PublishedOutput,
        geometry: BootstrapGeometry,
        setup: &DeterministicBlsDorySetup,
        expected: &BlsDoryDerivedModelCommitments,
    ) -> Result<(), ProductionDoryV3ModelBankBootstrapError> {
        let reopened_manifest = verify_published_manifest(prepared, manifest_output)?;
        let actual = derive_bls_dory_model_commitments_from_verified_layout(
            bank_output.reader()?,
            &reopened_manifest,
            geometry.batch,
            geometry.dimension,
            geometry.layers_per_bank,
            geometry.banks,
            geometry.padded_variables as usize,
            setup,
        )
        .map_err(ProductionDoryV3ModelBankBootstrapError::CommitmentDerivation)?;
        if &actual != expected {
            return Err(ProductionDoryV3ModelBankBootstrapError::CommitmentMismatch);
        }
        verify_model_bank(bank_output.reader()?, &reopened_manifest)
            .map_err(ProductionDoryV3ModelBankBootstrapError::VerifyBank)
    }

    #[test]
    fn bounded_bootstrap_round_trips_and_authenticates_final_outputs() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();

        let expected = run_fixture(&payload, &bank, &manifest).unwrap();
        assert_eq!(
            fs::metadata(&bank).unwrap().len(),
            MODEL_BANK_HEADER_BYTES as u64 + expected.payload_bytes
        );
        let decoded: ModelBankManifest =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        assert_eq!(decoded, expected);
        verify_model_bank(File::open(bank).unwrap(), &decoded).unwrap();
    }

    #[test]
    fn bounded_bootstrap_rejects_forbidden_payload_byte_without_outputs() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        let mut bytes = fixture_payload();
        bytes[7] = 251;
        fs::write(&payload, bytes).unwrap();

        assert!(matches!(
            run_fixture(&payload, &bank, &manifest),
            Err(ProductionDoryV3ModelBankBootstrapError::Payload(
                ModelBankError::OutOfRange {
                    offset: 7,
                    value: 251
                }
            ))
        ));
        assert!(!bank.exists());
        assert!(!manifest.exists());
        let remaining = fs::read_dir(&directory.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(remaining, [std::ffi::OsString::from("payload.bin")]);
    }

    #[test]
    fn bounded_bootstrap_rejects_truncated_and_trailing_payloads() {
        for (label, bytes) in [
            ("truncated", fixture_payload()[..19].to_vec()),
            ("trailing", {
                let mut bytes = fixture_payload();
                bytes.push(1);
                bytes
            }),
        ] {
            let directory = TestDirectory::new();
            let payload = directory.join(&format!("{label}.bin"));
            let bank = directory.join("bank.bin");
            let manifest = directory.join("manifest.json");
            fs::write(&payload, bytes).unwrap();
            assert!(matches!(
                run_fixture(&payload, &bank, &manifest),
                Err(ProductionDoryV3ModelBankBootstrapError::PayloadLength { .. })
            ));
            assert!(!bank.exists());
            assert!(!manifest.exists());
        }
    }

    #[test]
    fn bounded_bootstrap_never_overwrites_existing_output() {
        for existing_is_bank in [true, false] {
            let directory = TestDirectory::new();
            let payload = directory.join("payload.bin");
            let bank = directory.join("bank.bin");
            let manifest = directory.join("manifest.json");
            fs::write(&payload, fixture_payload()).unwrap();
            let existing = if existing_is_bank { &bank } else { &manifest };
            fs::write(existing, b"keep me").unwrap();

            assert!(matches!(
                run_fixture(&payload, &bank, &manifest),
                Err(ProductionDoryV3ModelBankBootstrapError::OutputExists(path))
                    if path.as_path() == existing.as_path()
            ));
            assert_eq!(fs::read(existing).unwrap(), b"keep me");
            let absent = if existing_is_bank { &manifest } else { &bank };
            assert!(!absent.exists());
        }
    }

    #[test]
    fn retained_temporary_identity_rejects_replacement_without_deleting_it() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let prepared = prepare_bootstrap(&payload, &bank, &manifest, geometry, &setup).unwrap();
        let replaced_path = prepared.bank_temp.path().to_path_buf();
        fs::remove_file(&replaced_path).unwrap();
        fs::write(&replaced_path, b"replacement").unwrap();

        assert!(matches!(
            publish_prepared(&prepared, &bank, &manifest),
            Err(ProductionDoryV3ModelBankBootstrapError::FileIdentityMismatch(path))
                if path == replaced_path
        ));
        drop(prepared);
        assert_eq!(fs::read(&replaced_path).unwrap(), b"replacement");
        assert!(!bank.exists());
        assert!(!manifest.exists());
    }

    #[test]
    fn retained_final_identity_rejects_replacement_and_guard_preserves_it() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let prepared = prepare_bootstrap(&payload, &bank, &manifest, geometry, &setup).unwrap();
        let (bank_guard, manifest_guard) = publish_prepared(&prepared, &bank, &manifest).unwrap();
        fs::remove_file(&bank).unwrap();
        fs::write(&bank, b"replacement").unwrap();

        assert!(matches!(
            bank_guard.ensure_current_path(),
            Err(ProductionDoryV3ModelBankBootstrapError::FileIdentityMismatch(path))
                if path == bank
        ));
        drop(bank_guard);
        drop(manifest_guard);
        drop(prepared);
        assert_eq!(fs::read(&bank).unwrap(), b"replacement");
        assert!(!manifest.exists());
    }

    #[test]
    fn explicit_final_cleanup_surfaces_failure_and_still_cleans_the_other_output() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let prepared = prepare_bootstrap(&payload, &bank, &manifest, geometry, &setup).unwrap();
        let (mut bank_guard, mut manifest_guard) =
            publish_prepared(&prepared, &bank, &manifest).unwrap();
        fs::remove_file(&bank).unwrap();
        fs::write(&bank, b"replacement").unwrap();

        let error = cleanup_published_outputs(&mut bank_guard, &mut manifest_guard).unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3ModelBankBootstrapError::Cleanup { path, .. } if path == bank
        ));
        assert_eq!(fs::read(&bank).unwrap(), b"replacement");
        assert!(!manifest.exists());
    }

    #[test]
    fn second_publication_failure_explicitly_removes_the_first_output() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let prepared = prepare_bootstrap(&payload, &bank, &manifest, geometry, &setup).unwrap();
        fs::write(&manifest, b"existing").unwrap();

        assert!(matches!(
            publish_prepared(&prepared, &bank, &manifest),
            Err(ProductionDoryV3ModelBankBootstrapError::Publish { path, source })
                if path == manifest && source.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert!(!bank.exists());
        assert_eq!(fs::read(&manifest).unwrap(), b"existing");
    }

    #[test]
    fn retained_final_path_must_remain_a_regular_file() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let prepared = prepare_bootstrap(&payload, &bank, &manifest, geometry, &setup).unwrap();
        let (bank_guard, manifest_guard) = publish_prepared(&prepared, &bank, &manifest).unwrap();
        fs::remove_file(&bank).unwrap();
        fs::create_dir(&bank).unwrap();

        assert!(matches!(
            bank_guard.ensure_current_path(),
            Err(ProductionDoryV3ModelBankBootstrapError::ArtifactNotRegular(path))
                if path == bank
        ));
        drop(bank_guard);
        drop(manifest_guard);
        drop(prepared);
        assert!(bank.is_dir());
        assert!(!manifest.exists());
    }

    #[test]
    fn explicit_success_cleanup_removes_only_same_file_temporary_links() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let mut prepared = prepare_bootstrap(&payload, &bank, &manifest, geometry, &setup).unwrap();
        let bank_temp = prepared.bank_temp.path().to_path_buf();
        let manifest_temp = prepared.manifest_temp.path().to_path_buf();
        let (mut bank_guard, mut manifest_guard) =
            publish_prepared(&prepared, &bank, &manifest).unwrap();
        assert_eq!(
            regular_path_identity(&bank_temp).unwrap(),
            regular_path_identity(&bank).unwrap()
        );
        assert_eq!(
            regular_path_identity(&manifest_temp).unwrap(),
            regular_path_identity(&manifest).unwrap()
        );

        prepared.remove_temporary_paths().unwrap();
        assert!(!bank_temp.exists());
        assert!(!manifest_temp.exists());
        bank_guard.ensure_current_path().unwrap();
        manifest_guard.ensure_current_path().unwrap();
        bank_guard.confirm();
        manifest_guard.confirm();
        assert!(bank.is_file());
        assert!(manifest.is_file());
    }

    #[test]
    fn retained_temporary_path_must_remain_a_regular_file() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let prepared = prepare_bootstrap(&payload, &bank, &manifest, geometry, &setup).unwrap();
        let replaced_path = prepared.bank_temp.path().to_path_buf();
        fs::remove_file(&replaced_path).unwrap();
        fs::create_dir(&replaced_path).unwrap();

        assert!(matches!(
            publish_prepared(&prepared, &bank, &manifest),
            Err(ProductionDoryV3ModelBankBootstrapError::ArtifactNotRegular(path))
                if path == replaced_path
        ));
        drop(prepared);
        assert!(replaced_path.is_dir());
        assert!(!bank.exists());
        assert!(!manifest.exists());
    }

    #[cfg(unix)]
    #[test]
    fn retained_temporary_path_rejects_a_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let prepared = prepare_bootstrap(&payload, &bank, &manifest, geometry, &setup).unwrap();
        let replaced_path = prepared.bank_temp.path().to_path_buf();
        fs::remove_file(&replaced_path).unwrap();
        symlink(&payload, &replaced_path).unwrap();

        assert!(matches!(
            publish_prepared(&prepared, &bank, &manifest),
            Err(ProductionDoryV3ModelBankBootstrapError::ArtifactNotRegular(path))
                if path == replaced_path
        ));
        drop(prepared);
        assert!(
            fs::symlink_metadata(&replaced_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn bounded_bootstrap_rejects_corruption_and_removes_unconfirmed_outputs() {
        let directory = TestDirectory::new();
        let payload = directory.join("payload.bin");
        let bank = directory.join("bank.bin");
        let manifest_path = directory.join("manifest.json");
        fs::write(&payload, fixture_payload()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let geometry = fixture_geometry(&setup);
        let prepared =
            prepare_bootstrap(&payload, &bank, &manifest_path, geometry, &setup).unwrap();
        let expected = prepared.commitments.clone();
        let (bank_guard, manifest_guard) =
            publish_prepared(&prepared, &bank, &manifest_path).unwrap();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&bank)
            .unwrap();
        file.seek(SeekFrom::Start(MODEL_BANK_HEADER_BYTES as u64 + 6))
            .unwrap();
        file.write_all(&[42]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let completion = authenticate_fixture_outputs(
            &prepared,
            &bank_guard,
            &manifest_guard,
            geometry,
            &setup,
            &expected,
        );
        assert!(completion.is_err());
        let mut bank_guard = bank_guard;
        let mut manifest_guard = manifest_guard;
        assert!(
            finish_or_cleanup_published_outputs(&mut bank_guard, &mut manifest_guard, completion,)
                .is_err()
        );
        // The final links are gone before guard destruction; cleanup is not
        // delegated to Drop on this ordinary authentication-error path.
        assert!(!bank.exists());
        assert!(!manifest_path.exists());
    }
}
