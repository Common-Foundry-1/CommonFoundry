//! Retained-handle validation for an existing production bank, manifest, and
//! Record V2 chain.
//!
//! The public result is an opaque, non-serializable capability. It retains all
//! three authenticated inputs and their trusted parents so downstream type-6
//! preparation can keep the validated filesystem identities alive.

use std::{
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[cfg(feature = "dory-v3-consensus-adapter")]
use crate::{ConsensusPowVerifier, PowError};
use crate::{
    MODEL_BANK_HEADER_BYTES, ModelBankManifest,
    dory_bls12_381_prototype::{
        BlsDoryPrototypeError, DeterministicBlsDorySetup, deterministic_bls_dory_setup,
    },
    dory_v3_model::DoryV3ModelIdentityError,
    dory_v3_model_ceremony::{
        ProductionDoryV3ModelRecordV2CeremonyError,
        preflight_production_dory_v3_model_bank_manifest,
    },
    dory_v3_model_ceremony_fs::{
        AuthenticatedInput, CeremonyFsError, FileIdentity as CeremonyFilesystemIdentity,
        TrustedCeremonyParent,
    },
    dory_v3_model_ceremony_transcript::{FileIdentity, PRODUCTION_BANK_BYTES},
    dory_v3_model_record::{
        BankAuthenticatedDoryV3ModelCommitmentRecordV2, DoryV3ModelCommitmentRecordError,
        DoryV3ModelCommitmentRecordV2, canonical_dory_v3_model_record_v2_json,
        derive_bank_authenticated_dory_v3_model_commitment_record_v2,
    },
    dory_v3_suite::{DORY_V3_PADDED_VARIABLES, DORY_V3_PRODUCTION_SUITE_MANIFEST},
    model_bank::canonical_model_bank_manifest_json,
};

const MAX_MANIFEST_JSON_BYTES: usize = 16 * 1024;
const MAX_RECORD_V2_JSON_BYTES: usize = 64 * 1024;

/// Opaque authority proving that one existing production bank, manifest, and
/// Record V2 chain passed the complete retained-handle validator.
///
/// This type deliberately implements neither `Clone` nor serialization. Its
/// filesystem guards and parents remain private and live until the capability
/// is dropped.
#[must_use]
pub struct ValidatedProductionDoryV3ModelBankRecordChain {
    bank: AuthenticatedInput,
    bank_parent: TrustedCeremonyParent,
    manifest_input: AuthenticatedInput,
    manifest_parent: TrustedCeremonyParent,
    record_v2_input: AuthenticatedInput,
    record_v2_parent: TrustedCeremonyParent,
    authenticated_record: BankAuthenticatedDoryV3ModelCommitmentRecordV2,
    bank_file: FileIdentity,
    manifest_file: FileIdentity,
    record_v2_file: FileIdentity,
    pass_one_elapsed_micros: u64,
    pass_two_elapsed_micros: u64,
}

impl ValidatedProductionDoryV3ModelBankRecordChain {
    pub(crate) fn retained_filesystem_entries(&self) -> [(PathBuf, CeremonyFilesystemIdentity); 3] {
        [
            (self.bank.path().to_path_buf(), self.bank.identity()),
            (
                self.manifest_input.path().to_path_buf(),
                self.manifest_input.identity(),
            ),
            (
                self.record_v2_input.path().to_path_buf(),
                self.record_v2_input.identity(),
            ),
        ]
    }

    pub(crate) fn retained_bank_filesystem_identity(
        &self,
    ) -> crate::dory_v3_model_ceremony_fs::FileIdentity {
        self.bank.identity()
    }

    pub const fn authenticated_record(&self) -> &BankAuthenticatedDoryV3ModelCommitmentRecordV2 {
        &self.authenticated_record
    }

    pub const fn record(&self) -> &DoryV3ModelCommitmentRecordV2 {
        self.authenticated_record.record()
    }

    pub const fn manifest(&self) -> &ModelBankManifest {
        self.authenticated_record.record().manifest()
    }

    pub const fn bank_file(&self) -> &FileIdentity {
        &self.bank_file
    }

    pub const fn manifest_file(&self) -> &FileIdentity {
        &self.manifest_file
    }

    pub const fn record_v2_file(&self) -> &FileIdentity {
        &self.record_v2_file
    }

    pub const fn pass_one_elapsed_micros(&self) -> u64 {
        self.pass_one_elapsed_micros
    }

    pub const fn pass_two_elapsed_micros(&self) -> u64 {
        self.pass_two_elapsed_micros
    }

    /// Recheck every retained file and trusted parent without rereading the
    /// multi-gigabyte bank. Type-6 preparation must still consume a freshly
    /// produced capability from the complete validator below.
    pub fn recheck_retained_files(
        &self,
    ) -> Result<(), ProductionDoryV3ModelBankRecordValidationError> {
        recheck_inputs(
            RetainedInputCheck::new(&self.bank, &self.bank_parent, self.bank_file.bytes),
            RetainedInputCheck::new(
                &self.manifest_input,
                &self.manifest_parent,
                self.manifest_file.bytes,
            ),
            RetainedInputCheck::new(
                &self.record_v2_input,
                &self.record_v2_parent,
                self.record_v2_file.bytes,
            ),
        )
    }
}

/// Fail-closed errors from existing production bank-chain validation.
#[derive(Debug, Error)]
pub enum ProductionDoryV3ModelBankRecordValidationError {
    #[error("bank, manifest, and Record V2 paths must be pairwise distinct")]
    PathsNotDistinct,
    #[error("bank, manifest, and Record V2 inputs resolve to the same retained file")]
    AliasedInputs,
    #[error("trusted filesystem validation failed: {0}")]
    TrustedFilesystem(String),
    #[error("manifest JSON exceeds the {MAX_MANIFEST_JSON_BYTES}-byte bound")]
    ManifestTooLarge,
    #[error("Record V2 JSON exceeds the {MAX_RECORD_V2_JSON_BYTES}-byte bound")]
    RecordV2TooLarge,
    #[error("failed to decode manifest JSON: {0}")]
    ManifestJson(#[source] serde_json::Error),
    #[error("failed to decode Record V2 JSON: {0}")]
    RecordV2Json(#[source] serde_json::Error),
    #[error("manifest bytes are not exact canonical pretty JSON followed by one line feed")]
    NonCanonicalManifest,
    #[error("Record V2 bytes are not exact canonical pretty JSON followed by one line feed")]
    NonCanonicalRecordV2,
    #[error("manifest is not the pinned production manifest: {0}")]
    ProductionManifest(#[source] ProductionDoryV3ModelRecordV2CeremonyError),
    #[error("failed to derive or validate the pinned n=33 setup: {0}")]
    Setup(#[source] BlsDoryPrototypeError),
    #[error("derived setup does not match the compiled production suite")]
    PinnedSetupMismatch,
    #[error("Record V2 is not a valid production record: {0}")]
    Record(#[source] DoryV3ModelCommitmentRecordError),
    #[error("Record V2 model identity is not a valid production identity: {0}")]
    ModelIdentity(#[source] DoryV3ModelIdentityError),
    #[error("Record V2 embeds a manifest different from the retained manifest file")]
    EmbeddedManifestMismatch,
    #[error("failed to seek or finish reading the retained bank: {0}")]
    BankIo(#[source] io::Error),
    #[error("bank pass read {actual} bytes instead of the exact {expected} bytes")]
    BankLength { expected: u64, actual: u64 },
    #[error("manifest payload length plus the bank header is not the exact production bank size")]
    ManifestBankLength,
    #[error("bank contains data after its exact production length")]
    BankTrailingData,
    #[error("the two complete bank passes produced different dual content identities")]
    BankPassIdentityMismatch,
    #[error("the two complete bank passes or retained Record V2 disagree")]
    RecordReproductionMismatch,
    #[error("a final retained small-file reread no longer matches the validated chain")]
    FinalSmallFileMismatch,
    #[cfg(feature = "dory-v3-consensus-adapter")]
    #[error("failed to construct the production V3 consensus verifier: {0}")]
    ConsensusVerifier(#[source] PowError),
}

/// Authenticated production V3 verifier together with the exact filesystem
/// identities observed while its bank, manifest, and Record V2 were retained.
/// A network launcher must compare these identities with its compiled pins
/// before accepting the verifier as consensus authority.
#[must_use]
#[cfg(feature = "dory-v3-consensus-adapter")]
pub struct LoadedProductionDoryV3ConsensusVerifier {
    verifier: ConsensusPowVerifier,
    bank_file: FileIdentity,
    manifest_file: FileIdentity,
    record_v2_file: FileIdentity,
}

#[cfg(feature = "dory-v3-consensus-adapter")]
impl LoadedProductionDoryV3ConsensusVerifier {
    pub const fn bank_file(&self) -> &FileIdentity {
        &self.bank_file
    }

    pub const fn manifest_file(&self) -> &FileIdentity {
        &self.manifest_file
    }

    pub const fn record_v2_file(&self) -> &FileIdentity {
        &self.record_v2_file
    }

    pub fn into_verifier(self) -> ConsensusPowVerifier {
        self.verifier
    }
}

/// Validate one existing production bank, canonical manifest, and canonical
/// Record V2 using retained trusted-file handles.
///
/// All three inputs are opened before any input is parsed. The bank is then
/// fully authenticated and all commitments are rederived twice through the
/// same retained handle. No redundant `verify_model_bank` scan is performed.
pub fn validate_existing_production_dory_v3_model_bank_record_chain(
    bank_path: &Path,
    manifest_path: &Path,
    record_v2_path: &Path,
) -> Result<
    ValidatedProductionDoryV3ModelBankRecordChain,
    ProductionDoryV3ModelBankRecordValidationError,
> {
    ensure_distinct_paths(bank_path, manifest_path, record_v2_path)?;
    validate_existing_dory_v3_model_bank_record_chain_core(
        bank_path,
        manifest_path,
        record_v2_path,
        PRODUCTION_BANK_BYTES,
        |manifest, record| {
            preflight_production_dory_v3_model_bank_manifest(manifest)
                .map_err(ProductionDoryV3ModelBankRecordValidationError::ProductionManifest)?;
            let setup = pinned_production_setup()?;
            record
                .validate_production(&setup)
                .map_err(ProductionDoryV3ModelBankRecordValidationError::Record)?;
            let structural = record
                .model_identity()
                .validate_production_structure(manifest, &setup)
                .map_err(ProductionDoryV3ModelBankRecordValidationError::ModelIdentity)?;
            Ok((setup, structural))
        },
        |manifest, record, (setup, structural)| {
            preflight_production_dory_v3_model_bank_manifest(manifest)
                .map_err(ProductionDoryV3ModelBankRecordValidationError::ProductionManifest)?;
            record
                .validate_production(setup)
                .map_err(ProductionDoryV3ModelBankRecordValidationError::Record)?;
            let reproduced = record
                .model_identity()
                .validate_production_structure(manifest, setup)
                .map_err(ProductionDoryV3ModelBankRecordValidationError::ModelIdentity)?;
            if &reproduced != structural {
                return Err(ProductionDoryV3ModelBankRecordValidationError::Record(
                    DoryV3ModelCommitmentRecordError::StructuralCapabilityMismatch,
                ));
            }
            Ok(())
        },
        |reader, (setup, structural)| {
            derive_bank_authenticated_dory_v3_model_commitment_record_v2(reader, structural, setup)
                .map_err(ProductionDoryV3ModelBankRecordValidationError::Record)
        },
    )
}

/// Load the exact production bank, manifest, and Record V2 and construct the
/// corresponding fail-closed consensus verifier.
///
/// The retained-handle validator authenticates the complete bank twice and
/// bounds both JSON inputs before this function can mint verifier authority.
/// Paths and file bytes never become consensus parameters; only the identities
/// derived from the authenticated Record V2 are retained by the verifier.
#[cfg(feature = "dory-v3-consensus-adapter")]
pub fn load_production_dory_v3_consensus_verifier(
    network_id: [u8; 32],
    bank_path: &Path,
    manifest_path: &Path,
    record_v2_path: &Path,
) -> Result<LoadedProductionDoryV3ConsensusVerifier, ProductionDoryV3ModelBankRecordValidationError>
{
    let validated = validate_existing_production_dory_v3_model_bank_record_chain(
        bank_path,
        manifest_path,
        record_v2_path,
    )?;
    let setup = pinned_production_setup()?;
    let bank_file = validated.bank_file().clone();
    let manifest_file = validated.manifest_file().clone();
    let record_v2_file = validated.record_v2_file().clone();
    let ValidatedProductionDoryV3ModelBankRecordChain {
        authenticated_record,
        ..
    } = validated;
    let verifier = ConsensusPowVerifier::v3_candidate(network_id, authenticated_record, setup)
        .map_err(ProductionDoryV3ModelBankRecordValidationError::ConsensusVerifier)?;
    Ok(LoadedProductionDoryV3ConsensusVerifier {
        verifier,
        bank_file,
        manifest_file,
        record_v2_file,
    })
}

fn validate_existing_dory_v3_model_bank_record_chain_core<C>(
    bank_path: &Path,
    manifest_path: &Path,
    record_v2_path: &Path,
    expected_bank_bytes: u64,
    mut prepare_chain: impl FnMut(
        &ModelBankManifest,
        &DoryV3ModelCommitmentRecordV2,
    ) -> Result<C, ProductionDoryV3ModelBankRecordValidationError>,
    mut revalidate_final: impl FnMut(
        &ModelBankManifest,
        &DoryV3ModelCommitmentRecordV2,
        &C,
    ) -> Result<(), ProductionDoryV3ModelBankRecordValidationError>,
    mut derive_record: impl FnMut(
        &mut dyn Read,
        &C,
    ) -> Result<
        BankAuthenticatedDoryV3ModelCommitmentRecordV2,
        ProductionDoryV3ModelBankRecordValidationError,
    >,
) -> Result<
    ValidatedProductionDoryV3ModelBankRecordChain,
    ProductionDoryV3ModelBankRecordValidationError,
> {
    ensure_distinct_paths(bank_path, manifest_path, record_v2_path)?;

    let bank_parent = TrustedCeremonyParent::for_artifact(bank_path).map_err(map_fs)?;
    let manifest_parent = TrustedCeremonyParent::for_artifact(manifest_path).map_err(map_fs)?;
    let record_v2_parent = TrustedCeremonyParent::for_artifact(record_v2_path).map_err(map_fs)?;

    // Open every input before parsing any caller-controlled bytes.
    let mut bank = AuthenticatedInput::open(&bank_parent, bank_path, Some(expected_bank_bytes))
        .map_err(map_fs)?;
    let mut manifest_input =
        AuthenticatedInput::open(&manifest_parent, manifest_path, None).map_err(map_fs)?;
    let mut record_v2_input =
        AuthenticatedInput::open(&record_v2_parent, record_v2_path, None).map_err(map_fs)?;
    ensure_distinct_inputs(&bank, &manifest_input, &record_v2_input)?;

    let (manifest, manifest_bytes) = read_canonical_manifest(&mut manifest_input)?;
    if manifest
        .payload_bytes
        .checked_add(MODEL_BANK_HEADER_BYTES as u64)
        != Some(expected_bank_bytes)
    {
        return Err(ProductionDoryV3ModelBankRecordValidationError::ManifestBankLength);
    }

    let (record, record_v2_bytes) = read_canonical_record_v2(&mut record_v2_input)?;
    if record.manifest() != &manifest {
        return Err(ProductionDoryV3ModelBankRecordValidationError::EmbeddedManifestMismatch);
    }
    let validation_context = prepare_chain(&manifest, &record)?;
    let manifest_bytes_len = manifest_bytes.len() as u64;
    let record_v2_bytes_len = record_v2_bytes.len() as u64;

    let (pass_one, pass_two, bank_file, pass_one_elapsed, pass_two_elapsed) = run_two_bank_passes(
        &mut bank,
        &bank_parent,
        expected_bank_bytes,
        |reader| derive_record(reader, &validation_context),
        || {
            recheck_small_inputs(
                RetainedInputCheck::new(&manifest_input, &manifest_parent, manifest_bytes_len),
                RetainedInputCheck::new(&record_v2_input, &record_v2_parent, record_v2_bytes_len),
            )
        },
    )?;
    if pass_one.record() != &record || pass_two.record() != &record {
        return Err(ProductionDoryV3ModelBankRecordValidationError::RecordReproductionMismatch);
    }

    let final_manifest_result = read_canonical_manifest(&mut manifest_input);
    let final_record_result = read_canonical_record_v2(&mut record_v2_input);
    let final_manifest_recheck = manifest_input
        .recheck(&manifest_parent, Some(manifest_bytes_len))
        .map_err(map_fs);
    let final_record_recheck = record_v2_input
        .recheck(&record_v2_parent, Some(record_v2_bytes_len))
        .map_err(map_fs);
    // Bank last: no later retained-file operation can hide a pathname change.
    let final_bank_recheck = bank
        .recheck(&bank_parent, Some(expected_bank_bytes))
        .map_err(map_fs);
    final_manifest_recheck?;
    final_record_recheck?;
    final_bank_recheck?;
    let (final_manifest, final_manifest_bytes) = final_manifest_result?;
    let (final_record, final_record_v2_bytes) = final_record_result?;
    if final_manifest != manifest
        || final_manifest_bytes != manifest_bytes
        || final_record != record
        || final_record_v2_bytes != record_v2_bytes
        || final_record.manifest() != &final_manifest
    {
        return Err(ProductionDoryV3ModelBankRecordValidationError::FinalSmallFileMismatch);
    }
    revalidate_final(&final_manifest, &final_record, &validation_context)?;

    Ok(ValidatedProductionDoryV3ModelBankRecordChain {
        bank,
        bank_parent,
        manifest_input,
        manifest_parent,
        record_v2_input,
        record_v2_parent,
        authenticated_record: pass_two,
        bank_file,
        manifest_file: content_identity(&final_manifest_bytes),
        record_v2_file: content_identity(&final_record_v2_bytes),
        pass_one_elapsed_micros: elapsed_micros(pass_one_elapsed),
        pass_two_elapsed_micros: elapsed_micros(pass_two_elapsed),
    })
}

fn ensure_distinct_paths(
    bank_path: &Path,
    manifest_path: &Path,
    record_v2_path: &Path,
) -> Result<(), ProductionDoryV3ModelBankRecordValidationError> {
    if bank_path == manifest_path || bank_path == record_v2_path || manifest_path == record_v2_path
    {
        return Err(ProductionDoryV3ModelBankRecordValidationError::PathsNotDistinct);
    }
    Ok(())
}

fn ensure_distinct_inputs(
    bank: &AuthenticatedInput,
    manifest: &AuthenticatedInput,
    record_v2: &AuthenticatedInput,
) -> Result<(), ProductionDoryV3ModelBankRecordValidationError> {
    let bank = bank.identity();
    let manifest = manifest.identity();
    let record_v2 = record_v2.identity();
    if bank == manifest || bank == record_v2 || manifest == record_v2 {
        return Err(ProductionDoryV3ModelBankRecordValidationError::AliasedInputs);
    }
    Ok(())
}

fn read_canonical_manifest(
    input: &mut AuthenticatedInput,
) -> Result<(ModelBankManifest, Vec<u8>), ProductionDoryV3ModelBankRecordValidationError> {
    let bytes = input
        .read_bounded(MAX_MANIFEST_JSON_BYTES)
        .map_err(map_fs)?;
    if bytes.len() > MAX_MANIFEST_JSON_BYTES {
        return Err(ProductionDoryV3ModelBankRecordValidationError::ManifestTooLarge);
    }
    parse_canonical_manifest(&bytes).map(|manifest| (manifest, bytes))
}

fn parse_canonical_manifest(
    bytes: &[u8],
) -> Result<ModelBankManifest, ProductionDoryV3ModelBankRecordValidationError> {
    let manifest = serde_json::from_slice::<ModelBankManifest>(bytes)
        .map_err(ProductionDoryV3ModelBankRecordValidationError::ManifestJson)?;
    let canonical = canonical_model_bank_manifest_json(&manifest)
        .map_err(ProductionDoryV3ModelBankRecordValidationError::ManifestJson)?;
    if canonical != bytes {
        return Err(ProductionDoryV3ModelBankRecordValidationError::NonCanonicalManifest);
    }
    Ok(manifest)
}

fn read_canonical_record_v2(
    input: &mut AuthenticatedInput,
) -> Result<(DoryV3ModelCommitmentRecordV2, Vec<u8>), ProductionDoryV3ModelBankRecordValidationError>
{
    let bytes = input
        .read_bounded(MAX_RECORD_V2_JSON_BYTES)
        .map_err(map_fs)?;
    if bytes.len() > MAX_RECORD_V2_JSON_BYTES {
        return Err(ProductionDoryV3ModelBankRecordValidationError::RecordV2TooLarge);
    }
    parse_canonical_record_v2(&bytes).map(|record| (record, bytes))
}

fn parse_canonical_record_v2(
    bytes: &[u8],
) -> Result<DoryV3ModelCommitmentRecordV2, ProductionDoryV3ModelBankRecordValidationError> {
    let record = serde_json::from_slice::<DoryV3ModelCommitmentRecordV2>(bytes)
        .map_err(ProductionDoryV3ModelBankRecordValidationError::RecordV2Json)?;
    let canonical = canonical_dory_v3_model_record_v2_json(&record)
        .map_err(ProductionDoryV3ModelBankRecordValidationError::RecordV2Json)?;
    if canonical != bytes {
        return Err(ProductionDoryV3ModelBankRecordValidationError::NonCanonicalRecordV2);
    }
    Ok(record)
}

fn pinned_production_setup()
-> Result<DeterministicBlsDorySetup, ProductionDoryV3ModelBankRecordValidationError> {
    let setup = deterministic_bls_dory_setup(DORY_V3_PADDED_VARIABLES as usize)
        .map_err(ProductionDoryV3ModelBankRecordValidationError::Setup)?;
    setup
        .validate()
        .map_err(ProductionDoryV3ModelBankRecordValidationError::Setup)?;
    if setup.max_log_n() != DORY_V3_PADDED_VARIABLES as usize
        || setup.identity()
            != DORY_V3_PRODUCTION_SUITE_MANIFEST
                .setup_identity
                .into_bytes()
    {
        return Err(ProductionDoryV3ModelBankRecordValidationError::PinnedSetupMismatch);
    }
    Ok(setup)
}

fn run_two_bank_passes<T>(
    bank: &mut AuthenticatedInput,
    bank_parent: &TrustedCeremonyParent,
    expected_bytes: u64,
    mut derive: impl FnMut(&mut dyn Read) -> Result<T, ProductionDoryV3ModelBankRecordValidationError>,
    mut recheck_small_inputs: impl FnMut() -> Result<(), ProductionDoryV3ModelBankRecordValidationError>,
) -> Result<(T, T, FileIdentity, Duration, Duration), ProductionDoryV3ModelBankRecordValidationError>
{
    let first_started = Instant::now();
    let first_result = run_bank_pass(bank, expected_bytes, &mut derive);
    let first_elapsed = first_started.elapsed();
    let first_bank_recheck = bank
        .recheck(bank_parent, Some(expected_bytes))
        .map_err(map_fs);
    let first_small_recheck = recheck_small_inputs();
    first_bank_recheck?;
    first_small_recheck?;
    let (pass_one, first_identity) = first_result?;

    let second_started = Instant::now();
    let second_result = run_bank_pass(bank, expected_bytes, &mut derive);
    let second_elapsed = second_started.elapsed();
    let second_bank_recheck = bank
        .recheck(bank_parent, Some(expected_bytes))
        .map_err(map_fs);
    let second_small_recheck = recheck_small_inputs();
    second_bank_recheck?;
    second_small_recheck?;
    let (pass_two, second_identity) = second_result?;
    if first_identity != second_identity {
        return Err(ProductionDoryV3ModelBankRecordValidationError::BankPassIdentityMismatch);
    }
    Ok((
        pass_one,
        pass_two,
        second_identity,
        first_elapsed,
        second_elapsed,
    ))
}

fn run_bank_pass<T>(
    bank: &mut AuthenticatedInput,
    expected_bytes: u64,
    derive: &mut impl FnMut(&mut dyn Read) -> Result<T, ProductionDoryV3ModelBankRecordValidationError>,
) -> Result<(T, FileIdentity), ProductionDoryV3ModelBankRecordValidationError> {
    bank.file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(ProductionDoryV3ModelBankRecordValidationError::BankIo)?;
    let mut reader = DualHashCountingReader::new(bank.file_mut());
    let output = derive(&mut reader)?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(ProductionDoryV3ModelBankRecordValidationError::BankIo)?
        != 0
    {
        return Err(ProductionDoryV3ModelBankRecordValidationError::BankTrailingData);
    }
    let identity = reader.finish();
    if identity.bytes != expected_bytes {
        return Err(ProductionDoryV3ModelBankRecordValidationError::BankLength {
            expected: expected_bytes,
            actual: identity.bytes,
        });
    }
    Ok((output, identity))
}

#[derive(Clone, Copy)]
struct RetainedInputCheck<'a> {
    input: &'a AuthenticatedInput,
    parent: &'a TrustedCeremonyParent,
    expected_bytes: u64,
}

impl<'a> RetainedInputCheck<'a> {
    const fn new(
        input: &'a AuthenticatedInput,
        parent: &'a TrustedCeremonyParent,
        expected_bytes: u64,
    ) -> Self {
        Self {
            input,
            parent,
            expected_bytes,
        }
    }

    fn run(self) -> Result<(), ProductionDoryV3ModelBankRecordValidationError> {
        self.input
            .recheck(self.parent, Some(self.expected_bytes))
            .map_err(map_fs)
    }
}

fn recheck_inputs(
    bank: RetainedInputCheck<'_>,
    manifest: RetainedInputCheck<'_>,
    record_v2: RetainedInputCheck<'_>,
) -> Result<(), ProductionDoryV3ModelBankRecordValidationError> {
    let bank_recheck = bank.run();
    let manifest_recheck = manifest.run();
    let record_recheck = record_v2.run();
    bank_recheck?;
    manifest_recheck?;
    record_recheck
}

fn recheck_small_inputs(
    manifest: RetainedInputCheck<'_>,
    record_v2: RetainedInputCheck<'_>,
) -> Result<(), ProductionDoryV3ModelBankRecordValidationError> {
    let manifest_recheck = manifest.run();
    let record_recheck = record_v2.run();
    manifest_recheck?;
    record_recheck
}

fn elapsed_micros(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

struct DualHashCountingReader<R> {
    inner: R,
    blake3: blake3::Hasher,
    sha256: Sha256,
    bytes: u64,
}

impl<R> DualHashCountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            blake3: blake3::Hasher::new(),
            sha256: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> FileIdentity {
        FileIdentity {
            bytes: self.bytes,
            blake3: *self.blake3.finalize().as_bytes(),
            sha256: self.sha256.finalize().into(),
        }
    }
}

impl<R: Read> Read for DualHashCountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("bank byte counter overflow"))?;
        self.blake3.update(&buffer[..read]);
        self.sha256.update(&buffer[..read]);
        Ok(read)
    }
}

fn content_identity(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        bytes: bytes.len() as u64,
        blake3: *blake3::hash(bytes).as_bytes(),
        sha256: Sha256::digest(bytes).into(),
    }
}

fn map_fs(error: CeremonyFsError) -> ProductionDoryV3ModelBankRecordValidationError {
    ProductionDoryV3ModelBankRecordValidationError::TrustedFilesystem(error.to_string())
}

#[cfg(test)]
mod tests {
    use dory_pcs::primitives::arithmetic::Field;
    use serde_json::json;
    use std::{
        fs,
        io::{Cursor, Read as _},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{
        dory_bls12_381_aggregate::commit_bls_dory_polynomial,
        dory_bls12_381_prototype::{BlsDoryFr, BlsDoryGt},
        dory_v3_model::{CanonicalBlsDoryGtHex, DoryV3ModelIdentityV1},
        dory_v3_model_ceremony_fs::prepare_test_parent,
        dory_v3_model_record::derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test,
        dory_v3_suite::{DORY_V3_MODEL_IDENTITY_VERSION, DORY_V3_PRODUCTION_SUITE_DIGEST},
        model_bank::{SmallModelBankFixture, build_small_model_bank},
    };

    static NONCE: AtomicU64 = AtomicU64::new(1);
    const TEST_VARIABLES: usize = 5;
    const TEST_MODEL_VERSION: u32 = 2;
    const TEST_BATCH: u32 = 2;
    const TEST_DIMENSION: u32 = 2;
    const TEST_LAYERS_PER_BANK: u32 = 2;
    const TEST_BASE: [u8; 4] = [125, 126, 124, 130];
    const TEST_LAYERS: [[u8; 4]; 4] = [
        [125, 127, 129, 131],
        [124, 122, 120, 118],
        [126, 128, 130, 132],
        [123, 121, 119, 117],
    ];

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-bank-record-validator-test-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            prepare_test_parent(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_manifest() -> ModelBankManifest {
        let layers = [vec![2_u8; 4]];
        let layer_refs = layers.iter().map(Vec::as_slice).collect::<Vec<_>>();
        build_small_model_bank(SmallModelBankFixture {
            model_version: 3,
            dimension: 2,
            batch: 1,
            base_input: &[0, 1],
            layers: &layer_refs,
            pcs_parameter_digest: [3; 32],
            pcs_commitment_root: [4; 32],
        })
        .unwrap()
        .manifest
    }

    struct CompleteFixture {
        bank: Vec<u8>,
        manifest: ModelBankManifest,
        setup: DeterministicBlsDorySetup,
        record: DoryV3ModelCommitmentRecordV2,
    }

    fn commit_test_bytes(bytes: &[u8], setup: &DeterministicBlsDorySetup) -> BlsDoryGt {
        let mut coefficients = bytes
            .iter()
            .map(|value| BlsDoryFr::from_i64(i64::from(*value) - 125))
            .collect::<Vec<_>>();
        coefficients.resize(1 << TEST_VARIABLES, BlsDoryFr::from_i64(0));
        commit_bls_dory_polynomial(
            coefficients,
            TEST_VARIABLES / 2,
            TEST_VARIABLES - TEST_VARIABLES / 2,
            setup,
        )
        .unwrap()
        .commitment()
    }

    fn complete_fixture() -> CompleteFixture {
        let setup = deterministic_bls_dory_setup(TEST_VARIABLES).unwrap();
        let layer_slices = TEST_LAYERS
            .iter()
            .map(<[u8; 4]>::as_slice)
            .collect::<Vec<_>>();
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: TEST_MODEL_VERSION,
            dimension: TEST_DIMENSION,
            batch: TEST_BATCH,
            base_input: &TEST_BASE,
            layers: &layer_slices,
            pcs_parameter_digest: DORY_V3_PRODUCTION_SUITE_DIGEST.into_bytes(),
            pcs_commitment_root: [0; 32],
        })
        .unwrap();
        let encoded = |commitment| {
            CanonicalBlsDoryGtHex::from_commitment(commitment)
                .unwrap()
                .to_hex()
                .unwrap()
        };
        let weight_bank_commitments = TEST_LAYERS
            .chunks_exact(TEST_LAYERS_PER_BANK as usize)
            .map(|bank| {
                let bytes = bank.iter().flatten().copied().collect::<Vec<_>>();
                encoded(commit_test_bytes(&bytes, &setup))
            })
            .collect::<Vec<_>>();
        let identity: DoryV3ModelIdentityV1 = serde_json::from_value(json!({
            "identity_version": DORY_V3_MODEL_IDENTITY_VERSION,
            "model_version": TEST_MODEL_VERSION,
            "batch": TEST_BATCH,
            "dimension": TEST_DIMENSION,
            "layers_per_bank": TEST_LAYERS_PER_BANK,
            "model_byte_root": provisional.manifest.raw_blake3_root,
            "layer_roots_aggregate": provisional.manifest.layer_roots_aggregate,
            "suite_parameter_digest": DORY_V3_PRODUCTION_SUITE_DIGEST.into_bytes(),
            "setup_identity": setup.identity(),
            "padded_variables": TEST_VARIABLES,
            "base_input_commitment": encoded(commit_test_bytes(&TEST_BASE, &setup)),
            "weight_bank_commitments": weight_bank_commitments,
        }))
        .unwrap();
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: TEST_MODEL_VERSION,
            dimension: TEST_DIMENSION,
            batch: TEST_BATCH,
            base_input: &TEST_BASE,
            layers: &layer_slices,
            pcs_parameter_digest: DORY_V3_PRODUCTION_SUITE_DIGEST.into_bytes(),
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        identity.verify_manifest(&built.manifest).unwrap();
        let record = derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test(
            Cursor::new(&built.bytes),
            &built.manifest,
            &identity,
            &setup,
        )
        .unwrap()
        .into_record();
        CompleteFixture {
            bank: built.bytes,
            manifest: built.manifest,
            setup,
            record,
        }
    }

    #[test]
    fn manifest_parser_requires_exact_pretty_json_and_one_lf() {
        let canonical = canonical_model_bank_manifest_json(&fixture_manifest()).unwrap();
        assert_eq!(
            parse_canonical_manifest(&canonical).unwrap(),
            fixture_manifest()
        );

        let mut no_lf = canonical.clone();
        no_lf.pop();
        assert!(matches!(
            parse_canonical_manifest(&no_lf),
            Err(ProductionDoryV3ModelBankRecordValidationError::NonCanonicalManifest)
        ));
        let mut trailing = canonical.clone();
        trailing.push(b'\n');
        assert!(matches!(
            parse_canonical_manifest(&trailing),
            Err(ProductionDoryV3ModelBankRecordValidationError::NonCanonicalManifest)
        ));
        let mut corrupt = canonical;
        corrupt[0] = b'!';
        assert!(matches!(
            parse_canonical_manifest(&corrupt),
            Err(ProductionDoryV3ModelBankRecordValidationError::ManifestJson(_))
        ));
    }

    #[test]
    fn record_v2_parser_rejects_noncanonical_and_over_bound_artifacts() {
        let fixture = complete_fixture();
        let canonical = canonical_dory_v3_model_record_v2_json(&fixture.record).unwrap();
        assert_eq!(
            parse_canonical_record_v2(&canonical).unwrap(),
            fixture.record
        );

        let mut no_lf = canonical.clone();
        no_lf.pop();
        assert!(matches!(
            parse_canonical_record_v2(&no_lf),
            Err(ProductionDoryV3ModelBankRecordValidationError::NonCanonicalRecordV2)
        ));
        let mut extra_lf = canonical.clone();
        extra_lf.push(b'\n');
        assert!(matches!(
            parse_canonical_record_v2(&extra_lf),
            Err(ProductionDoryV3ModelBankRecordValidationError::NonCanonicalRecordV2)
        ));
        let compact = serde_json::to_vec(&fixture.record).unwrap();
        assert!(matches!(
            parse_canonical_record_v2(&compact),
            Err(ProductionDoryV3ModelBankRecordValidationError::NonCanonicalRecordV2)
        ));
        let mut malformed = canonical;
        malformed[0] = b'!';
        assert!(matches!(
            parse_canonical_record_v2(&malformed),
            Err(ProductionDoryV3ModelBankRecordValidationError::RecordV2Json(_))
        ));

        let directory = TestDirectory::new();
        let path = directory.0.join("oversize-record-v2.json");
        fs::write(&path, vec![b' '; MAX_RECORD_V2_JSON_BYTES + 1]).unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let mut input = AuthenticatedInput::open(&parent, &path, None).unwrap();
        assert!(matches!(
            read_canonical_record_v2(&mut input),
            Err(ProductionDoryV3ModelBankRecordValidationError::RecordV2TooLarge)
        ));
    }

    #[test]
    fn bounded_core_exercises_complete_retained_chain_orchestration() {
        let fixture = complete_fixture();
        let manifest_bytes = canonical_model_bank_manifest_json(&fixture.manifest).unwrap();
        let record_bytes = canonical_dory_v3_model_record_v2_json(&fixture.record).unwrap();
        let directory = TestDirectory::new();
        let bank_path = directory.0.join("bank.bin");
        let manifest_path = directory.0.join("manifest.json");
        let record_path = directory.0.join("record-v2.json");
        fs::write(&bank_path, &fixture.bank).unwrap();
        fs::write(&manifest_path, &manifest_bytes).unwrap();
        fs::write(&record_path, &record_bytes).unwrap();

        let validated = validate_existing_dory_v3_model_bank_record_chain_core(
            &bank_path,
            &manifest_path,
            &record_path,
            fixture.bank.len() as u64,
            |manifest, record| {
                record
                    .validate()
                    .map_err(ProductionDoryV3ModelBankRecordValidationError::Record)?;
                record
                    .model_identity()
                    .verify_manifest(manifest)
                    .map_err(ProductionDoryV3ModelBankRecordValidationError::ModelIdentity)?;
                Ok((*manifest, record.model_identity().clone()))
            },
            |manifest, record, (prepared_manifest, identity)| {
                record
                    .validate()
                    .map_err(ProductionDoryV3ModelBankRecordValidationError::Record)?;
                record
                    .model_identity()
                    .verify_manifest(manifest)
                    .map_err(ProductionDoryV3ModelBankRecordValidationError::ModelIdentity)?;
                if manifest != prepared_manifest || record.model_identity() != identity {
                    return Err(
                        ProductionDoryV3ModelBankRecordValidationError::FinalSmallFileMismatch,
                    );
                }
                Ok(())
            },
            |reader, (manifest, identity)| {
                derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test(
                    reader,
                    manifest,
                    identity,
                    &fixture.setup,
                )
                .map_err(ProductionDoryV3ModelBankRecordValidationError::Record)
            },
        )
        .unwrap();

        assert_eq!(validated.record(), &fixture.record);
        assert_eq!(validated.manifest(), &fixture.manifest);
        assert_eq!(validated.authenticated_record().record(), &fixture.record);
        assert_eq!(
            validated.bank_file().bytes,
            204,
            "small bank wire length changed"
        );
        assert_eq!(
            hex::encode(validated.bank_file().blake3),
            "047b9e20b2afd95e3a010021e4b3cfbe32b02a6f6167a069907e1df8dd3e9991"
        );
        assert_eq!(
            hex::encode(validated.bank_file().sha256),
            "521167cfac46197366cdd18a34b776fcbac8627c71c2f5e35b2b6c69c5da84a5"
        );
        assert_eq!(validated.manifest_file().bytes, 1_366);
        assert_eq!(
            hex::encode(validated.manifest_file().blake3),
            "e06cf2cb5dcaeaa561ff452bfb54403c4251984c903df1057054cc3c455e961f"
        );
        assert_eq!(
            hex::encode(validated.manifest_file().sha256),
            "7c43d8372cf58fb6a4b9130a1ec67dbe2e198e637403dd74d7fc4fdcbb9d08bd"
        );
        assert_eq!(validated.record_v2_file().bytes, 7_469);
        assert_eq!(
            hex::encode(validated.record_v2_file().blake3),
            "3f8bfbc1f1184144788ddc7c9c4dba3e7f0740e1a29bc5142e804cb95a813eb3"
        );
        assert_eq!(
            hex::encode(validated.record_v2_file().sha256),
            "63db64d63c61c3e432b0f0f3cc9164839a8d5dd9d6aed45d2d18fe69e7d58895"
        );
        assert!(
            manifest_bytes.starts_with(b"{\n  \"model_version\": 2,\n"),
            "manifest serde pretty-JSON prefix changed"
        );
        assert!(
            record_bytes.starts_with(b"{\n  \"record_version\": 2,\n"),
            "Record V2 serde pretty-JSON prefix changed"
        );
        assert_eq!(
            validated.retained_filesystem_entries(),
            [
                (bank_path.clone(), validated.bank.identity()),
                (manifest_path.clone(), validated.manifest_input.identity()),
                (record_path.clone(), validated.record_v2_input.identity()),
            ]
        );
        validated.recheck_retained_files().unwrap();
        let _ = validated.pass_one_elapsed_micros();
        let _ = validated.pass_two_elapsed_micros();
    }

    #[test]
    fn dual_hash_counting_reader_has_known_answers_and_exact_eof() {
        let bytes = b"retained bank bytes";
        let mut reader = DualHashCountingReader::new(Cursor::new(bytes));
        let mut observed = Vec::new();
        reader.read_to_end(&mut observed).unwrap();
        assert_eq!(reader.read(&mut [0_u8; 1]).unwrap(), 0);
        let identity = reader.finish();
        assert_eq!(observed, bytes);
        assert_eq!(identity.bytes, 19);
        assert_eq!(
            hex::encode(identity.blake3),
            "a0ae413ddc7161973dd153bb50c7caeb192157d09cf0dae1048899474f22f57f"
        );
        assert_eq!(
            hex::encode(identity.sha256),
            "d3b384ff2d3e5201cc1e45f68a930ed30ce962f4bec16f980a60be66c53e4ca2"
        );
    }

    #[test]
    fn two_pass_helper_reuses_one_retained_handle_and_agrees() {
        let directory = TestDirectory::new();
        let path = directory.0.join("bank.bin");
        fs::write(&path, b"bounded-bank").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let mut input = AuthenticatedInput::open(&parent, &path, Some(12)).unwrap();
        let mut passes = 0_u8;
        let (first, second, identity, _first_elapsed, _second_elapsed) = run_two_bank_passes(
            &mut input,
            &parent,
            12,
            |reader| {
                passes += 1;
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .map_err(ProductionDoryV3ModelBankRecordValidationError::BankIo)?;
                Ok(bytes)
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(passes, 2);
        assert_eq!(first, b"bounded-bank");
        assert_eq!(second, first);
        assert_eq!(identity, content_identity(b"bounded-bank"));
    }

    #[test]
    fn pass_error_runs_small_recheck_and_identity_error_takes_precedence() {
        let directory = TestDirectory::new();
        let path = directory.0.join("bank.bin");
        let small_path = directory.0.join("manifest.json");
        fs::write(&path, b"bounded-bank").unwrap();
        fs::write(&small_path, b"stable").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let small_parent = TrustedCeremonyParent::for_artifact(&small_path).unwrap();
        let mut input = AuthenticatedInput::open(&parent, &path, Some(12)).unwrap();
        let small_input = AuthenticatedInput::open(&small_parent, &small_path, Some(6)).unwrap();
        let mut rechecks = 0_u8;
        let error = run_two_bank_passes(
            &mut input,
            &parent,
            12,
            |_reader| {
                Err::<(), _>(ProductionDoryV3ModelBankRecordValidationError::BankIo(
                    io::Error::other("synthetic derivation failure"),
                ))
            },
            || {
                rechecks += 1;
                small_input.recheck(&small_parent, Some(7)).map_err(map_fs)
            },
        )
        .unwrap_err();
        assert_eq!(rechecks, 1);
        assert!(matches!(
            error,
            ProductionDoryV3ModelBankRecordValidationError::TrustedFilesystem(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn two_pass_helper_detects_same_inode_content_mutation() {
        let directory = TestDirectory::new();
        let path = directory.0.join("bank.bin");
        fs::write(&path, b"bounded-bank").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let mut input = AuthenticatedInput::open(&parent, &path, Some(12)).unwrap();
        let error = run_two_bank_passes(
            &mut input,
            &parent,
            12,
            |reader| {
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .map_err(ProductionDoryV3ModelBankRecordValidationError::BankIo)?;
                Ok(bytes)
            },
            || {
                fs::write(&path, b"changed-bank").unwrap();
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3ModelBankRecordValidationError::BankPassIdentityMismatch
        ));
    }

    #[test]
    fn retained_open_rejects_short_trailing_alias_and_symlink_inputs() {
        let directory = TestDirectory::new();
        let short = directory.0.join("short.bin");
        fs::write(&short, b"123").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&short).unwrap();
        assert!(AuthenticatedInput::open(&parent, &short, Some(4)).is_err());

        let trailing = directory.0.join("trailing.bin");
        fs::write(&trailing, b"12345").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&trailing).unwrap();
        assert!(AuthenticatedInput::open(&parent, &trailing, Some(4)).is_err());

        let original = directory.0.join("original.bin");
        let alias = directory.0.join("alias.bin");
        fs::write(&original, b"1234").unwrap();
        fs::hard_link(&original, &alias).unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&original).unwrap();
        assert!(AuthenticatedInput::open(&parent, &original, Some(4)).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = directory.0.join("target.bin");
            let link = directory.0.join("link.bin");
            fs::write(&target, b"1234").unwrap();
            symlink(&target, &link).unwrap();
            let parent = TrustedCeremonyParent::for_artifact(&link).unwrap();
            assert!(AuthenticatedInput::open(&parent, &link, Some(4)).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_input_denies_same_length_mutation() {
        use std::fs::OpenOptions;

        let directory = TestDirectory::new();
        let path = directory.0.join("input.bin");
        fs::write(&path, b"original").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let input = AuthenticatedInput::open(&parent, &path, Some(8)).unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        input.recheck(&parent, Some(8)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn final_bounded_reread_detects_same_inode_small_file_mutation() {
        let directory = TestDirectory::new();
        let path = directory.0.join("manifest.json");
        let canonical = canonical_model_bank_manifest_json(&fixture_manifest()).unwrap();
        fs::write(&path, &canonical).unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let mut input =
            AuthenticatedInput::open(&parent, &path, Some(canonical.len() as u64)).unwrap();
        assert_eq!(read_canonical_manifest(&mut input).unwrap().1, canonical);

        let mut corrupt = canonical;
        corrupt[0] = b'!';
        fs::write(&path, &corrupt).unwrap();
        input.recheck(&parent, Some(corrupt.len() as u64)).unwrap();
        assert!(matches!(
            read_canonical_manifest(&mut input),
            Err(ProductionDoryV3ModelBankRecordValidationError::ManifestJson(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn retained_recheck_detects_named_path_replacement() {
        let directory = TestDirectory::new();
        let path = directory.0.join("input.bin");
        let displaced = directory.0.join("displaced.bin");
        fs::write(&path, b"original").unwrap();
        let parent = TrustedCeremonyParent::for_artifact(&path).unwrap();
        let input = AuthenticatedInput::open(&parent, &path, Some(8)).unwrap();

        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, b"replaced").unwrap();
        assert!(input.recheck(&parent, Some(8)).is_err());
    }

    #[test]
    fn path_preflight_rejects_duplicates_before_filesystem_access() {
        type ValidatorFn = fn(
            &Path,
            &Path,
            &Path,
        ) -> Result<
            ValidatedProductionDoryV3ModelBankRecordChain,
            ProductionDoryV3ModelBankRecordValidationError,
        >;
        let _: ValidatorFn = validate_existing_production_dory_v3_model_bank_record_chain;

        let same = Path::new("not-even-absolute");
        assert!(matches!(
            validate_existing_production_dory_v3_model_bank_record_chain(same, same, same),
            Err(ProductionDoryV3ModelBankRecordValidationError::PathsNotDistinct)
        ));
    }

    #[test]
    #[ignore = "requires a release build and a real 6.0 GiB production bank chain"]
    fn release_only_real_production_bank_chain() {
        require_release_build();
        let bank = std::env::var_os("CMFD_PRODUCTION_BANK")
            .map(PathBuf::from)
            .expect("CMFD_PRODUCTION_BANK must name the real bank");
        let manifest = std::env::var_os("CMFD_PRODUCTION_MANIFEST")
            .map(PathBuf::from)
            .expect("CMFD_PRODUCTION_MANIFEST must name the real manifest");
        let record_v2 = std::env::var_os("CMFD_PRODUCTION_RECORD_V2")
            .map(PathBuf::from)
            .expect("CMFD_PRODUCTION_RECORD_V2 must name the real Record V2");

        let validated = validate_existing_production_dory_v3_model_bank_record_chain(
            &bank, &manifest, &record_v2,
        )
        .unwrap();
        assert_eq!(validated.bank_file().bytes, PRODUCTION_BANK_BYTES);
        assert_eq!(validated.manifest(), validated.record().manifest());
        assert_ne!(validated.bank_file().blake3, [0; 32]);
        assert_ne!(validated.bank_file().sha256, [0; 32]);
        validated.recheck_retained_files().unwrap();
    }

    fn require_release_build() {
        #[cfg(debug_assertions)]
        panic!("run this ignored integration test with cargo test --release");
    }
}
