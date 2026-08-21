//! Transactional model-bank staging into authenticated WHIR source artifacts.
//!
//! The public pointer is the only discovery boundary. Role artifacts and a
//! canonical manifest are sealed first, then published under no-overwrite
//! content-addressed paths. A no-overwrite hard link publishes the
//! manifest last. A process crash before that link can leave unreachable
//! objects, but never a discoverable partial bundle. Directory-entry power-loss
//! durability remains an operator/filesystem requirement; reopening always
//! fails closed if any linked object is absent.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use blake3::Hasher;
use cmfd_proof_accel::whir_initial::{WHIR_INITIAL_MIN_VARIABLES, WhirInitialSourceIdentity};
use cmfd_proof_accel::whir_initial_source::{
    AuthenticatedWhirInitialSourceFile, WHIR_INITIAL_SOURCE_MAX_VARIABLES,
    WhirInitialSourceArtifactError, WhirInitialSourceArtifactIdentity,
    WhirInitialSourceArtifactWriter,
};
use thiserror::Error;

use crate::model_bank::{
    MAX_MODEL_PCS_WEIGHT_BANKS, ModelBankError, ModelBankFieldStreamError, ModelBankManifest,
    ModelFieldChunk, ModelPcsIdentity, ModelPcsRole, StagedModelFieldSink,
    VerifiedModelBankReceipt, verify_model_bank_into_staged_field_sink,
};
use crate::whir_proof::structured_whir_suite_parameter_digest;

const SOURCE_ID_DOMAIN: &str = "CMFD/FORGEMATRIX/V2/MODEL-WHIR-SOURCE/V1";
const BUNDLE_DIGEST_DOMAIN: &str = "CMFD/FORGEMATRIX/V2/MODEL-WHIR-SOURCE-BUNDLE/V1";
const BUNDLE_MAGIC: &[u8; 8] = b"CMFDMWS1";
const BUNDLE_IDENTITY_MAGIC: &[u8; 8] = b"CMFDMWI1";
const BUNDLE_VERSION: u32 = 1;
pub const MODEL_WHIR_SOURCE_BUNDLE_IDENTITY_BYTES: usize = 8 + 4 + 32 + 32 + 32;
const BUNDLE_HEADER_BYTES: usize = 112;
const BUNDLE_ROLE_BYTES: usize = 112;
const MAX_BUNDLE_ROLES: usize = 1 + MAX_MODEL_PCS_WEIGHT_BANKS;
const MAX_BUNDLE_BYTES: usize = BUNDLE_HEADER_BYTES + MAX_BUNDLE_ROLES * BUNDLE_ROLE_BYTES;
const MANIFEST_OBJECT_NAME: &str = "bundle.cmfdmws";

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(0);

/// Failure while staging, publishing, or reopening fixed-model WHIR sources.
#[derive(Debug, Error)]
pub enum ModelWhirSourceError {
    #[error("model-bank verification failed: {0}")]
    ModelBank(#[from] ModelBankError),
    #[error("WHIR source artifact failed: {0}")]
    Artifact(#[from] WhirInitialSourceArtifactError),
    #[error("invalid model WHIR source bundle: {0}")]
    Invalid(&'static str),
    #[error("trusted model identity selects a different WHIR suite")]
    SuiteMismatch,
    #[error("published model WHIR source bundle does not match this verified model")]
    PublishedBundleMismatch,
    #[error("model WHIR source bundle I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Independently retained cryptographic identity for one published source bundle.
///
/// Reopening requires this value because the publication pointer and its object
/// files are untrusted storage. The bundle digest authenticates every ordered
/// role, source geometry, expected commitment alias, and artifact digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelWhirSourceBundleIdentity {
    model_digest: [u8; 32],
    manifest_digest: [u8; 32],
    bundle_digest: [u8; 32],
}

impl ModelWhirSourceBundleIdentity {
    pub const fn model_digest(self) -> [u8; 32] {
        self.model_digest
    }

    pub const fn manifest_digest(self) -> [u8; 32] {
        self.manifest_digest
    }

    pub const fn bundle_digest(self) -> [u8; 32] {
        self.bundle_digest
    }

    /// Canonical fixed-width form suitable for independently retained storage.
    pub fn to_bytes(self) -> [u8; MODEL_WHIR_SOURCE_BUNDLE_IDENTITY_BYTES] {
        let mut encoded = [0_u8; MODEL_WHIR_SOURCE_BUNDLE_IDENTITY_BYTES];
        encoded[..8].copy_from_slice(BUNDLE_IDENTITY_MAGIC);
        encoded[8..12].copy_from_slice(&BUNDLE_VERSION.to_le_bytes());
        encoded[12..44].copy_from_slice(&self.model_digest);
        encoded[44..76].copy_from_slice(&self.manifest_digest);
        encoded[76..108].copy_from_slice(&self.bundle_digest);
        encoded
    }

    /// Decode the exact canonical retained identity. Publication files never
    /// supply this value; callers load it from their separate trusted state.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, ModelWhirSourceError> {
        if encoded.len() != MODEL_WHIR_SOURCE_BUNDLE_IDENTITY_BYTES
            || encoded.get(..8) != Some(BUNDLE_IDENTITY_MAGIC.as_slice())
            || read_u32(encoded, 8)? != BUNDLE_VERSION
        {
            return Err(ModelWhirSourceError::Invalid(
                "retained bundle identity is not canonical",
            ));
        }
        let identity = Self {
            model_digest: take_array(encoded, 12)?,
            manifest_digest: take_array(encoded, 44)?,
            bundle_digest: take_array(encoded, 76)?,
        };
        if identity.bundle_digest == [0; 32] {
            return Err(ModelWhirSourceError::Invalid(
                "retained bundle digest is unspecified",
            ));
        }
        Ok(identity)
    }
}

/// One authenticated role in a published fixed-model source bundle.
pub struct PublishedModelWhirSourceRole {
    role: ModelPcsRole,
    expected_commitment: [u8; 32],
    source: AuthenticatedWhirInitialSourceFile,
}

impl std::fmt::Debug for PublishedModelWhirSourceRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublishedModelWhirSourceRole")
            .field("role", &self.role)
            .field("expected_commitment", &self.expected_commitment)
            .field("artifact_identity", self.source.artifact_identity())
            .field("path", &self.source.path())
            .finish()
    }
}

impl PublishedModelWhirSourceRole {
    pub const fn role(&self) -> ModelPcsRole {
        self.role
    }

    /// Commitment alias that the later codeword/tree checkpoint must derive
    /// from this exact source before it may construct a prover identity.
    pub const fn expected_commitment(&self) -> [u8; 32] {
        self.expected_commitment
    }

    pub const fn artifact_identity(&self) -> &WhirInitialSourceArtifactIdentity {
        self.source.artifact_identity()
    }

    pub fn path(&self) -> &Path {
        self.source.path()
    }

    pub const fn source(&self) -> &AuthenticatedWhirInitialSourceFile {
        &self.source
    }
}

/// Fully authenticated bundle selected by one atomically published manifest.
///
/// This is a source-staging capability, not an `InitialWhirProverIdentity`.
/// In particular, `n = 31` weight sources remain unusable until the later
/// codeword, tree, sumcheck, and folding stages support that geometry.
pub struct PublishedModelWhirSourceBundle {
    publication_path: PathBuf,
    bundle_identity: ModelWhirSourceBundleIdentity,
    manifest: ModelBankManifest,
    identity: ModelPcsIdentity,
    roles: Vec<PublishedModelWhirSourceRole>,
}

impl std::fmt::Debug for PublishedModelWhirSourceBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublishedModelWhirSourceBundle")
            .field("publication_path", &self.publication_path)
            .field("bundle_identity", &self.bundle_identity)
            .field("roles", &self.roles)
            .finish_non_exhaustive()
    }
}

impl PublishedModelWhirSourceBundle {
    pub fn publication_path(&self) -> &Path {
        &self.publication_path
    }

    pub const fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_identity.bundle_digest
    }

    /// Identity that must be retained independently of the publication path
    /// and supplied to every later reopen.
    pub const fn bundle_identity(&self) -> ModelWhirSourceBundleIdentity {
        self.bundle_identity
    }

    pub const fn manifest(&self) -> &ModelBankManifest {
        &self.manifest
    }

    pub const fn identity(&self) -> &ModelPcsIdentity {
        &self.identity
    }

    pub fn roles(&self) -> &[PublishedModelWhirSourceRole] {
        &self.roles
    }
}

/// Verify one model-bank stream and publish its exact base/weight source
/// artifacts under a single no-overwrite manifest pointer.
pub fn build_verified_model_whir_sources<R: Read>(
    reader: R,
    trusted_manifest: &ModelBankManifest,
    trusted_identity: &ModelPcsIdentity,
    publication_path: impl AsRef<Path>,
) -> Result<PublishedModelWhirSourceBundle, ModelWhirSourceError> {
    let sink = ModelWhirSourceSink::new(
        publication_path.as_ref(),
        trusted_manifest,
        trusted_identity,
    )?;
    match verify_model_bank_into_staged_field_sink(reader, trusted_manifest, trusted_identity, sink)
    {
        Ok(bundle) => Ok(bundle),
        Err(ModelBankFieldStreamError::ModelBank(error)) => Err(error.into()),
        Err(ModelBankFieldStreamError::Sink(error)) => Err(error),
    }
}

/// Reopen an already published bundle against independently retained trusted
/// model metadata. The pointer and every role artifact are authenticated.
pub fn open_published_model_whir_sources(
    publication_path: impl AsRef<Path>,
    trusted_manifest: &ModelBankManifest,
    trusted_identity: &ModelPcsIdentity,
    expected_bundle: &ModelWhirSourceBundleIdentity,
) -> Result<PublishedModelWhirSourceBundle, ModelWhirSourceError> {
    let publication_path = publication_path.as_ref().to_path_buf();
    let plans = plan_roles(trusted_manifest, trusted_identity)?;
    let model_digest = trusted_identity.digest()?;
    let manifest_digest = trusted_manifest.digest()?;
    if expected_bundle.model_digest != model_digest
        || expected_bundle.manifest_digest != manifest_digest
        || expected_bundle.bundle_digest == [0; 32]
    {
        return Err(ModelWhirSourceError::PublishedBundleMismatch);
    }
    let bytes = read_bounded(&publication_path, MAX_BUNDLE_BYTES)?;
    let decoded = decode_bundle(&bytes)?;
    if !decoded_matches_plan(&decoded, &plans, model_digest, manifest_digest)
        || decoded.bundle_digest != expected_bundle.bundle_digest
    {
        return Err(ModelWhirSourceError::PublishedBundleMismatch);
    }

    let layout = publication_layout(&publication_path)?;
    let object_dir = layout.objects.join(hex::encode(decoded.bundle_digest));
    let manifest_object = object_dir.join(MANIFEST_OBJECT_NAME);
    if read_bounded(&manifest_object, MAX_BUNDLE_BYTES)? != bytes {
        return Err(ModelWhirSourceError::PublishedBundleMismatch);
    }

    let mut roles = Vec::with_capacity(plans.len());
    for (index, (descriptor, plan)) in decoded.roles.iter().zip(plans).enumerate() {
        let path = object_dir.join(role_file_name(index));
        let expected = WhirInitialSourceArtifactIdentity {
            source: descriptor.source.clone(),
            element_count: descriptor.element_count,
            artifact_global_digest: descriptor.artifact_global_digest,
        };
        let source = AuthenticatedWhirInitialSourceFile::open(path, &expected)?;
        roles.push(PublishedModelWhirSourceRole {
            role: plan.role,
            expected_commitment: plan.expected_commitment,
            source,
        });
    }

    Ok(PublishedModelWhirSourceBundle {
        publication_path,
        bundle_identity: *expected_bundle,
        manifest: *trusted_manifest,
        identity: trusted_identity.clone(),
        roles,
    })
}

struct ModelWhirSourceSink {
    publication_path: PathBuf,
    expected_manifest: ModelBankManifest,
    expected_identity: ModelPcsIdentity,
    model_digest: [u8; 32],
    manifest_digest: [u8; 32],
    layout: PublicationLayout,
    attempt: AttemptCleanup,
    roles: Vec<PendingRole>,
    next_role: usize,
}

struct PendingRole {
    plan: RolePlan,
    staged_path: PathBuf,
    writer: WhirInitialSourceArtifactWriter,
    written: u64,
}

impl ModelWhirSourceSink {
    fn new(
        publication_path: &Path,
        expected_manifest: &ModelBankManifest,
        expected_identity: &ModelPcsIdentity,
    ) -> Result<Self, ModelWhirSourceError> {
        let plans = plan_roles(expected_manifest, expected_identity)?;
        let model_digest = expected_identity.digest()?;
        let manifest_digest = expected_manifest.digest()?;
        let layout = publication_layout(publication_path)?;
        preflight_existing_publication(&layout, &plans, model_digest, manifest_digest)?;
        fs::create_dir_all(&layout.staging)
            .map_err(|source| io_error("creating staging root", &layout.staging, source))?;
        let attempt_path = create_attempt_dir(&layout.staging)?;
        let attempt = AttemptCleanup(Some(attempt_path.clone()));
        preflight_hard_links(&attempt_path, &layout)?;
        let mut roles = Vec::with_capacity(plans.len());
        for (index, plan) in plans.into_iter().enumerate() {
            let staged_path = attempt_path.join(role_file_name(index));
            let writer =
                WhirInitialSourceArtifactWriter::create(&staged_path, plan.source.clone())?;
            roles.push(PendingRole {
                plan,
                staged_path,
                writer,
                written: 0,
            });
        }
        Ok(Self {
            publication_path: publication_path.to_path_buf(),
            expected_manifest: *expected_manifest,
            expected_identity: expected_identity.clone(),
            model_digest,
            manifest_digest,
            layout,
            attempt,
            roles,
            next_role: 0,
        })
    }
}

impl StagedModelFieldSink for ModelWhirSourceSink {
    type Error = ModelWhirSourceError;
    type Output = PublishedModelWhirSourceBundle;

    fn write_chunk(&mut self, chunk: ModelFieldChunk<'_>) -> Result<(), Self::Error> {
        let index = role_index(chunk.role)?;
        if index != self.next_role || index >= self.roles.len() {
            return Err(ModelWhirSourceError::Invalid(
                "model roles are not in canonical base-then-bank order",
            ));
        }
        let pending = &mut self.roles[index];
        if chunk.role != pending.plan.role
            || chunk.role_elements != pending.plan.element_count
            || chunk.role_offset != pending.written
        {
            return Err(ModelWhirSourceError::Invalid(
                "model role offset or declared length is not canonical",
            ));
        }
        pending.writer.write_elements(chunk.elements)?;
        pending.written = pending
            .written
            .checked_add(u64::try_from(chunk.elements.len()).map_err(|_| {
                ModelWhirSourceError::Invalid("model source chunk length does not fit u64")
            })?)
            .ok_or(ModelWhirSourceError::Invalid(
                "model role element count overflow",
            ))?;
        if pending.written > pending.plan.element_count {
            return Err(ModelWhirSourceError::Invalid(
                "model role contains too many elements",
            ));
        }
        if pending.written == pending.plan.element_count {
            self.next_role += 1;
        }
        Ok(())
    }

    fn finish_verified(
        mut self,
        receipt: VerifiedModelBankReceipt,
    ) -> Result<Self::Output, Self::Error> {
        if receipt.manifest() != &self.expected_manifest
            || receipt.identity() != &self.expected_identity
            || usize::try_from(receipt.layout().weight_bank_count())
                .ok()
                .and_then(|count| count.checked_add(1))
                != Some(self.roles.len())
            || self.next_role != self.roles.len()
            || self
                .roles
                .iter()
                .any(|role| role.written != role.plan.element_count)
        {
            return Err(ModelWhirSourceError::Invalid(
                "verified model receipt does not match the staged role set",
            ));
        }

        let pending_roles = mem::take(&mut self.roles);
        let mut sealed = Vec::with_capacity(pending_roles.len());
        for pending in pending_roles {
            let artifact = pending.writer.finish()?;
            if artifact.artifact_identity().source != pending.plan.source
                || artifact.artifact_identity().element_count != pending.plan.element_count
                || artifact.path() != pending.staged_path
            {
                return Err(ModelWhirSourceError::Invalid(
                    "sealed source artifact does not match its role plan",
                ));
            }
            sealed.push(SealedRole {
                plan: pending.plan,
                staged_path: pending.staged_path,
                artifact_identity: artifact.artifact_identity().clone(),
            });
            drop(artifact);
        }

        let (bundle_digest, manifest_bytes) =
            encode_bundle(self.model_digest, self.manifest_digest, &sealed)?;
        let bundle_identity = ModelWhirSourceBundleIdentity {
            model_digest: self.model_digest,
            manifest_digest: self.manifest_digest,
            bundle_digest,
        };
        publish_bundle(&self.layout, &sealed, bundle_digest, &manifest_bytes)?;
        self.attempt.cleanup_now();
        open_published_model_whir_sources(
            &self.publication_path,
            &self.expected_manifest,
            &self.expected_identity,
            &bundle_identity,
        )
    }
}

#[derive(Clone)]
struct RolePlan {
    role: ModelPcsRole,
    expected_commitment: [u8; 32],
    source: WhirInitialSourceIdentity,
    element_count: u64,
}

struct SealedRole {
    plan: RolePlan,
    staged_path: PathBuf,
    artifact_identity: WhirInitialSourceArtifactIdentity,
}

struct DecodedBundle {
    model_digest: [u8; 32],
    manifest_digest: [u8; 32],
    bundle_digest: [u8; 32],
    roles: Vec<DecodedRole>,
}

struct DecodedRole {
    role: ModelPcsRole,
    expected_commitment: [u8; 32],
    source: WhirInitialSourceIdentity,
    element_count: u64,
    artifact_global_digest: [u8; 32],
}

fn decoded_matches_plan(
    decoded: &DecodedBundle,
    plans: &[RolePlan],
    model_digest: [u8; 32],
    manifest_digest: [u8; 32],
) -> bool {
    decoded.model_digest == model_digest
        && decoded.manifest_digest == manifest_digest
        && decoded.roles.len() == plans.len()
        && decoded.roles.iter().zip(plans).all(|(decoded, plan)| {
            decoded.role == plan.role
                && decoded.expected_commitment == plan.expected_commitment
                && decoded.source == plan.source
                && decoded.element_count == plan.element_count
        })
}

#[derive(Clone)]
struct PublicationLayout {
    publication: PathBuf,
    objects: PathBuf,
    staging: PathBuf,
}

fn plan_roles(
    manifest: &ModelBankManifest,
    identity: &ModelPcsIdentity,
) -> Result<Vec<RolePlan>, ModelWhirSourceError> {
    manifest.verify_pcs_identity(identity)?;
    if identity.pcs_suite_parameter_digest != structured_whir_suite_parameter_digest() {
        return Err(ModelWhirSourceError::SuiteMismatch);
    }
    let model_digest = identity.digest()?;
    let manifest_digest = manifest.digest()?;
    let dimension = u64::from(identity.dimension);
    let base_elements = u64::from(identity.batch)
        .checked_mul(dimension)
        .ok_or(ModelWhirSourceError::Invalid("base source length overflow"))?;
    let weight_elements = u64::from(identity.layers_per_bank)
        .checked_mul(dimension)
        .and_then(|value| value.checked_mul(dimension))
        .ok_or(ModelWhirSourceError::Invalid(
            "weight-bank source length overflow",
        ))?;
    let mut roles = Vec::with_capacity(1 + identity.weight_bank_commitments.len());
    roles.push(plan_role(
        ModelPcsRole::BaseInput,
        identity.base_input_commitment,
        base_elements,
        model_digest,
        manifest_digest,
    )?);
    for (index, &commitment) in identity.weight_bank_commitments.iter().enumerate() {
        roles.push(plan_role(
            ModelPcsRole::WeightBank {
                index: u32::try_from(index)
                    .map_err(|_| ModelWhirSourceError::Invalid("weight-bank index overflow"))?,
            },
            commitment,
            weight_elements,
            model_digest,
            manifest_digest,
        )?);
    }
    Ok(roles)
}

fn plan_role(
    role: ModelPcsRole,
    expected_commitment: [u8; 32],
    element_count: u64,
    model_digest: [u8; 32],
    manifest_digest: [u8; 32],
) -> Result<RolePlan, ModelWhirSourceError> {
    if !element_count.is_power_of_two() {
        return Err(ModelWhirSourceError::Invalid(
            "model role length is not a power of two",
        ));
    }
    let num_variables = element_count.ilog2();
    if !(WHIR_INITIAL_MIN_VARIABLES as u32..=WHIR_INITIAL_SOURCE_MAX_VARIABLES as u32)
        .contains(&num_variables)
    {
        return Err(ModelWhirSourceError::Invalid(
            "model role exceeds the authenticated source geometry",
        ));
    }
    let role_tag = role_tag(role)?;
    let mut hasher = Hasher::new_derive_key(SOURCE_ID_DOMAIN);
    hasher.update(&BUNDLE_VERSION.to_le_bytes());
    hasher.update(&model_digest);
    hasher.update(&manifest_digest);
    hasher.update(&role_tag.to_le_bytes());
    hasher.update(&expected_commitment);
    hasher.update(&element_count.to_le_bytes());
    hasher.update(&num_variables.to_le_bytes());
    let source_id = *hasher.finalize().as_bytes();
    Ok(RolePlan {
        role,
        expected_commitment,
        source: WhirInitialSourceIdentity {
            source_id,
            num_variables,
        },
        element_count,
    })
}

fn encode_bundle(
    model_digest: [u8; 32],
    manifest_digest: [u8; 32],
    roles: &[SealedRole],
) -> Result<([u8; 32], Vec<u8>), ModelWhirSourceError> {
    if roles.is_empty() || roles.len() > MAX_BUNDLE_ROLES {
        return Err(ModelWhirSourceError::Invalid("invalid bundle role count"));
    }
    let role_count = u32::try_from(roles.len())
        .map_err(|_| ModelWhirSourceError::Invalid("bundle role count overflow"))?;
    let mut records = Vec::with_capacity(roles.len() * BUNDLE_ROLE_BYTES);
    for sealed in roles {
        encode_role_record(
            &mut records,
            sealed.plan.role,
            sealed.plan.expected_commitment,
            &sealed.artifact_identity,
        )?;
    }
    let bundle_digest = bundle_digest(model_digest, manifest_digest, role_count, &records);
    let mut encoded = Vec::with_capacity(BUNDLE_HEADER_BYTES + records.len());
    encoded.extend_from_slice(BUNDLE_MAGIC);
    encoded.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
    encoded.extend_from_slice(&role_count.to_le_bytes());
    encoded.extend_from_slice(&model_digest);
    encoded.extend_from_slice(&manifest_digest);
    encoded.extend_from_slice(&bundle_digest);
    encoded.extend_from_slice(&records);
    Ok((bundle_digest, encoded))
}

fn encode_role_record(
    encoded: &mut Vec<u8>,
    role: ModelPcsRole,
    expected_commitment: [u8; 32],
    identity: &WhirInitialSourceArtifactIdentity,
) -> Result<(), ModelWhirSourceError> {
    encoded.extend_from_slice(&role_tag(role)?.to_le_bytes());
    encoded.extend_from_slice(&expected_commitment);
    encoded.extend_from_slice(&identity.source.source_id);
    encoded.extend_from_slice(&identity.source.num_variables.to_le_bytes());
    encoded.extend_from_slice(&identity.element_count.to_le_bytes());
    encoded.extend_from_slice(&identity.artifact_global_digest);
    Ok(())
}

fn bundle_digest(
    model_digest: [u8; 32],
    manifest_digest: [u8; 32],
    role_count: u32,
    records: &[u8],
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(BUNDLE_DIGEST_DOMAIN);
    hasher.update(&BUNDLE_VERSION.to_le_bytes());
    hasher.update(&role_count.to_le_bytes());
    hasher.update(&model_digest);
    hasher.update(&manifest_digest);
    hasher.update(records);
    *hasher.finalize().as_bytes()
}

fn decode_bundle(encoded: &[u8]) -> Result<DecodedBundle, ModelWhirSourceError> {
    if encoded.len() < BUNDLE_HEADER_BYTES
        || encoded.len() > MAX_BUNDLE_BYTES
        || encoded.get(..8) != Some(BUNDLE_MAGIC.as_slice())
        || read_u32(encoded, 8)? != BUNDLE_VERSION
    {
        return Err(ModelWhirSourceError::Invalid(
            "bundle header or version is invalid",
        ));
    }
    let role_count = read_u32(encoded, 12)?;
    let role_count_usize = usize::try_from(role_count)
        .map_err(|_| ModelWhirSourceError::Invalid("bundle role count overflow"))?;
    if role_count_usize == 0
        || role_count_usize > MAX_BUNDLE_ROLES
        || encoded.len() != BUNDLE_HEADER_BYTES + role_count_usize * BUNDLE_ROLE_BYTES
    {
        return Err(ModelWhirSourceError::Invalid(
            "bundle role count or length is invalid",
        ));
    }
    let model_digest = take_array::<32>(encoded, 16)?;
    let manifest_digest = take_array::<32>(encoded, 48)?;
    let expected_bundle_digest = take_array::<32>(encoded, 80)?;
    let records = &encoded[BUNDLE_HEADER_BYTES..];
    if bundle_digest(model_digest, manifest_digest, role_count, records) != expected_bundle_digest {
        return Err(ModelWhirSourceError::Invalid(
            "bundle digest does not authenticate its role records",
        ));
    }
    let mut roles = Vec::with_capacity(role_count_usize);
    for index in 0..role_count_usize {
        let offset = BUNDLE_HEADER_BYTES + index * BUNDLE_ROLE_BYTES;
        let tag = read_u32(encoded, offset)?;
        if usize::try_from(tag).ok() != Some(index) {
            return Err(ModelWhirSourceError::Invalid(
                "bundle roles are not canonically ordered",
            ));
        }
        let source = WhirInitialSourceIdentity {
            source_id: take_array::<32>(encoded, offset + 36)?,
            num_variables: read_u32(encoded, offset + 68)?,
        };
        let element_count = read_u64(encoded, offset + 72)?;
        if source.source_id == [0; 32]
            || source.num_variables > WHIR_INITIAL_SOURCE_MAX_VARIABLES as u32
            || element_count.checked_ilog2() != Some(source.num_variables)
            || element_count != 1_u64 << source.num_variables
        {
            return Err(ModelWhirSourceError::Invalid(
                "bundle source geometry is invalid",
            ));
        }
        let artifact_global_digest = take_array::<32>(encoded, offset + 80)?;
        if artifact_global_digest == [0; 32] {
            return Err(ModelWhirSourceError::Invalid(
                "bundle source digest is unspecified",
            ));
        }
        roles.push(DecodedRole {
            role: role_from_tag(tag),
            expected_commitment: take_array::<32>(encoded, offset + 4)?,
            source,
            element_count,
            artifact_global_digest,
        });
    }
    Ok(DecodedBundle {
        model_digest,
        manifest_digest,
        bundle_digest: expected_bundle_digest,
        roles,
    })
}

fn publish_bundle(
    layout: &PublicationLayout,
    roles: &[SealedRole],
    bundle_digest: [u8; 32],
    manifest_bytes: &[u8],
) -> Result<(), ModelWhirSourceError> {
    fs::create_dir_all(&layout.objects)
        .map_err(|source| io_error("creating object root", &layout.objects, source))?;
    let object_dir = layout.objects.join(hex::encode(bundle_digest));
    match fs::create_dir(&object_dir) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            if !object_dir.is_dir() {
                return Err(ModelWhirSourceError::PublishedBundleMismatch);
            }
        }
        Err(source) => return Err(io_error("creating object directory", &object_dir, source)),
    }

    for (index, role) in roles.iter().enumerate() {
        let object_path = object_dir.join(role_file_name(index));
        match fs::hard_link(&role.staged_path, &object_path) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                let existing = AuthenticatedWhirInitialSourceFile::open(
                    &object_path,
                    &role.artifact_identity,
                )?;
                drop(existing);
            }
            Err(source) => {
                return Err(io_error("hard-linking role object", &object_path, source));
            }
        }
    }

    let attempt_dir = roles
        .first()
        .and_then(|role| role.staged_path.parent())
        .ok_or(ModelWhirSourceError::Invalid(
            "staged role has no attempt directory",
        ))?;
    let staged_manifest = attempt_dir.join(MANIFEST_OBJECT_NAME);
    write_new_synced(&staged_manifest, manifest_bytes)?;
    let manifest_object = object_dir.join(MANIFEST_OBJECT_NAME);
    publish_exact_link(&staged_manifest, &manifest_object, manifest_bytes)?;
    publish_exact_link(&manifest_object, &layout.publication, manifest_bytes)
}

fn publish_exact_link(
    source_path: &Path,
    target_path: &Path,
    expected: &[u8],
) -> Result<(), ModelWhirSourceError> {
    match fs::hard_link(source_path, target_path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            if read_bounded(target_path, MAX_BUNDLE_BYTES)? == expected {
                Ok(())
            } else {
                Err(ModelWhirSourceError::PublishedBundleMismatch)
            }
        }
        Err(source) => Err(io_error(
            "publishing no-overwrite manifest link",
            target_path,
            source,
        )),
    }
}

fn publication_layout(publication_path: &Path) -> Result<PublicationLayout, ModelWhirSourceError> {
    let file_name = publication_path
        .file_name()
        .ok_or(ModelWhirSourceError::Invalid(
            "publication path has no file name",
        ))?;
    let parent = publication_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(ModelWhirSourceError::Invalid(
            "publication parent is not an existing directory",
        ));
    }
    let mut objects_name = OsString::from(file_name);
    objects_name.push(".objects");
    let mut staging_name = OsString::from(file_name);
    staging_name.push(".staging");
    Ok(PublicationLayout {
        publication: publication_path.to_path_buf(),
        objects: parent.join(objects_name),
        staging: parent.join(staging_name),
    })
}

fn create_attempt_dir(staging_root: &Path) -> Result<PathBuf, ModelWhirSourceError> {
    for _ in 0..1024 {
        let sequence = NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed);
        let path = staging_root.join(format!("attempt-{}-{sequence}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("creating attempt directory", &path, source)),
        }
    }
    Err(ModelWhirSourceError::Invalid(
        "could not allocate a unique staging attempt",
    ))
}

fn preflight_existing_publication(
    layout: &PublicationLayout,
    plans: &[RolePlan],
    model_digest: [u8; 32],
    manifest_digest: [u8; 32],
) -> Result<(), ModelWhirSourceError> {
    match fs::symlink_metadata(&layout.publication) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(io_error("inspecting", &layout.publication, source)),
        Ok(_) => {}
    }
    let bytes = read_bounded(&layout.publication, MAX_BUNDLE_BYTES)?;
    let decoded =
        decode_bundle(&bytes).map_err(|_| ModelWhirSourceError::PublishedBundleMismatch)?;
    if !decoded_matches_plan(&decoded, plans, model_digest, manifest_digest) {
        return Err(ModelWhirSourceError::PublishedBundleMismatch);
    }
    let manifest_object = layout
        .objects
        .join(hex::encode(decoded.bundle_digest))
        .join(MANIFEST_OBJECT_NAME);
    if read_bounded(&manifest_object, MAX_BUNDLE_BYTES)? != bytes {
        return Err(ModelWhirSourceError::PublishedBundleMismatch);
    }
    Ok(())
}

fn preflight_hard_links(
    attempt_path: &Path,
    layout: &PublicationLayout,
) -> Result<(), ModelWhirSourceError> {
    let sequence = NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed);
    let probe_name = format!(".hard-link-probe-{}-{sequence}", std::process::id());
    preflight_hard_links_named(attempt_path, layout, &probe_name)
}

fn preflight_hard_links_named(
    attempt_path: &Path,
    layout: &PublicationLayout,
    probe_name: &str,
) -> Result<(), ModelWhirSourceError> {
    fs::create_dir_all(&layout.objects)
        .map_err(|source| io_error("creating object root", &layout.objects, source))?;
    let source_path = attempt_path.join(probe_name);
    let object_path = layout.objects.join(probe_name);
    let publication_sibling = layout.publication.with_file_name(probe_name);
    let mut cleanup = ProbeCleanup::default();
    write_new_synced(&source_path, b"CMFD")?;
    cleanup.0[0] = Some(source_path.clone());
    fs::hard_link(&source_path, &object_path)
        .map_err(|source| io_error("testing staging-to-object hard link", &object_path, source))?;
    cleanup.0[1] = Some(object_path.clone());
    fs::hard_link(&object_path, &publication_sibling).map_err(|source| {
        io_error(
            "testing object-to-publication hard link",
            &publication_sibling,
            source,
        )
    })?;
    cleanup.0[2] = Some(publication_sibling);
    Ok(())
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), ModelWhirSourceError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("creating new file", path, source))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("writing new file", path, source))
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ModelWhirSourceError> {
    let file = File::open(path).map_err(|source| io_error("opening", path, source))?;
    let mut bytes = Vec::with_capacity(maximum.min(1024));
    file.take(
        u64::try_from(maximum)
            .map_err(|_| ModelWhirSourceError::Invalid("read limit does not fit u64"))?
            + 1,
    )
    .read_to_end(&mut bytes)
    .map_err(|source| io_error("reading", path, source))?;
    if bytes.len() > maximum {
        return Err(ModelWhirSourceError::Invalid(
            "published manifest exceeds its byte cap",
        ));
    }
    Ok(bytes)
}

fn role_file_name(index: usize) -> String {
    format!("role-{index:02}.cmfdwis")
}

fn role_tag(role: ModelPcsRole) -> Result<u32, ModelWhirSourceError> {
    match role {
        ModelPcsRole::BaseInput => Ok(0),
        ModelPcsRole::WeightBank { index } => index
            .checked_add(1)
            .ok_or(ModelWhirSourceError::Invalid("weight-bank role overflow")),
    }
}

fn role_index(role: ModelPcsRole) -> Result<usize, ModelWhirSourceError> {
    usize::try_from(role_tag(role)?)
        .map_err(|_| ModelWhirSourceError::Invalid("model role index does not fit usize"))
}

fn role_from_tag(tag: u32) -> ModelPcsRole {
    if tag == 0 {
        ModelPcsRole::BaseInput
    } else {
        ModelPcsRole::WeightBank { index: tag - 1 }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ModelWhirSourceError> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ModelWhirSourceError> {
    Ok(u64::from_le_bytes(take_array(bytes, offset)?))
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ModelWhirSourceError> {
    bytes
        .get(offset..offset + N)
        .ok_or(ModelWhirSourceError::Invalid("bundle is truncated"))?
        .try_into()
        .map_err(|_| ModelWhirSourceError::Invalid("bundle field has the wrong width"))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> ModelWhirSourceError {
    ModelWhirSourceError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Default)]
struct ProbeCleanup([Option<PathBuf>; 3]);

impl Drop for ProbeCleanup {
    fn drop(&mut self) {
        for path in self.0.iter_mut().rev().filter_map(Option::take) {
            let _ = fs::remove_file(path);
        }
    }
}

struct AttemptCleanup(Option<PathBuf>);

impl AttemptCleanup {
    fn cleanup_now(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

impl Drop for AttemptCleanup {
    fn drop(&mut self) {
        self.cleanup_now();
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::{Arc, Barrier};

    use cmfd_proof_accel::whir_initial::AuthenticatedWhirInitialSource;

    use super::*;
    use crate::forgematrix_v2::{
        PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
        PRODUCTION_V2_LAYERS_PER_BANK,
    };
    use crate::model_bank::{
        MODEL_BANK_HEADER_BYTES, SmallModelBankFixture, build_small_model_bank,
    };
    use crate::sumcheck::GOLDILOCKS_MODULUS;

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "cmfd-model-whir-{label}-{}-{}",
            std::process::id(),
            NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    fn fixture() -> (crate::model_bank::BuiltModelBankFixture, ModelPcsIdentity) {
        let base = [0, 125, 250, 126];
        let layers = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];
        let layer_slices = layers
            .iter()
            .map(|layer| layer.as_slice())
            .collect::<Vec<_>>();
        let suite = structured_whir_suite_parameter_digest();
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let identity = ModelPcsIdentity {
            model_version: 2,
            batch: 2,
            dimension: 2,
            layers_per_bank: 2,
            model_byte_root: provisional.manifest.raw_blake3_root,
            pcs_suite_parameter_digest: suite,
            base_input_commitment: [0x61; 32],
            weight_bank_commitments: vec![[0x71; 32], [0x72; 32]],
        };
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &base,
            layers: &layer_slices,
            pcs_parameter_digest: suite,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        (built, identity)
    }

    #[test]
    fn verified_model_stream_publishes_and_reopens_exact_ordered_sources() {
        let root = test_root("round-trip");
        let pointer = root.join("model.sources");
        let (built, identity) = fixture();
        let bundle = build_verified_model_whir_sources(
            Cursor::new(&built.bytes),
            &built.manifest,
            &identity,
            &pointer,
        )
        .unwrap();
        assert_eq!(bundle.roles().len(), 3);
        assert_eq!(bundle.roles()[0].role(), ModelPcsRole::BaseInput);
        assert_eq!(
            bundle
                .roles()
                .iter()
                .map(PublishedModelWhirSourceRole::role)
                .collect::<Vec<_>>(),
            [
                ModelPcsRole::BaseInput,
                ModelPcsRole::WeightBank { index: 0 },
                ModelPcsRole::WeightBank { index: 1 },
            ]
        );
        assert_eq!(
            bundle
                .roles()
                .iter()
                .map(PublishedModelWhirSourceRole::expected_commitment)
                .collect::<Vec<_>>(),
            [
                identity.base_input_commitment,
                identity.weight_bank_commitments[0],
                identity.weight_bank_commitments[1],
            ]
        );
        let source_ids = bundle
            .roles()
            .iter()
            .map(|role| role.artifact_identity().source.source_id)
            .collect::<Vec<_>>();
        assert!(source_ids.iter().all(|source_id| *source_id != [0; 32]));
        assert_ne!(source_ids[0], source_ids[1]);
        assert_ne!(source_ids[0], source_ids[2]);
        assert_ne!(source_ids[1], source_ids[2]);
        assert_eq!(
            bundle.roles()[0].source().read_elements(0, 4).unwrap(),
            [GOLDILOCKS_MODULUS - 125, 0, 125, 1]
        );
        assert_eq!(
            bundle.roles()[1].source().read_elements(0, 8).unwrap(),
            (1_u64..=8)
                .map(|value| GOLDILOCKS_MODULUS - (125 - value))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            bundle.roles()[2].source().read_elements(0, 8).unwrap(),
            (9_u64..=16)
                .map(|value| GOLDILOCKS_MODULUS - (125 - value))
                .collect::<Vec<_>>()
        );
        let first_identity = bundle.bundle_identity();
        let retained_bytes = first_identity.to_bytes();
        assert_eq!(
            ModelWhirSourceBundleIdentity::from_bytes(&retained_bytes).unwrap(),
            first_identity
        );
        let first_digest = first_identity.bundle_digest();
        drop(bundle);

        let reopened = open_published_model_whir_sources(
            &pointer,
            &built.manifest,
            &identity,
            &first_identity,
        )
        .unwrap();
        assert_eq!(reopened.bundle_digest(), first_digest);
        drop(reopened);
        let repeated = build_verified_model_whir_sources(
            Cursor::new(&built.bytes),
            &built.manifest,
            &identity,
            &pointer,
        )
        .unwrap();
        assert_eq!(repeated.bundle_digest(), first_digest);
        drop(repeated);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_authentication_and_existing_mismatch_never_replace_the_pointer() {
        let root = test_root("fail-closed");
        let pointer = root.join("model.sources");
        let (built, identity) = fixture();
        let mut corrupted = built.bytes.clone();
        corrupted[MODEL_BANK_HEADER_BYTES + 5] ^= 1;
        assert!(matches!(
            build_verified_model_whir_sources(
                Cursor::new(corrupted),
                &built.manifest,
                &identity,
                &pointer,
            ),
            Err(ModelWhirSourceError::ModelBank(
                ModelBankError::RawRootMismatch
            ))
        ));
        assert!(!pointer.exists());
        let staging = publication_layout(&pointer).unwrap().staging;
        assert_eq!(fs::read_dir(staging).unwrap().count(), 0);

        fs::write(&pointer, b"keep-existing-pointer").unwrap();
        assert!(matches!(
            build_verified_model_whir_sources(
                Cursor::new(&built.bytes),
                &built.manifest,
                &identity,
                &pointer,
            ),
            Err(ModelWhirSourceError::PublishedBundleMismatch)
        ));
        assert_eq!(fs::read(&pointer).unwrap(), b"keep-existing-pointer");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hard_link_preflight_never_removes_preexisting_targets() {
        let root = test_root("preflight-ownership");
        let pointer = root.join("model.sources");
        let layout = publication_layout(&pointer).unwrap();
        fs::create_dir_all(&layout.staging).unwrap();
        fs::create_dir_all(&layout.objects).unwrap();
        let attempt = create_attempt_dir(&layout.staging).unwrap();

        let object_name = ".hard-link-probe-existing-object";
        let object_target = layout.objects.join(object_name);
        fs::write(&object_target, b"keep-object").unwrap();
        assert!(preflight_hard_links_named(&attempt, &layout, object_name).is_err());
        assert_eq!(fs::read(&object_target).unwrap(), b"keep-object");
        assert!(!attempt.join(object_name).exists());

        let publication_name = ".hard-link-probe-existing-publication";
        let publication_target = pointer.with_file_name(publication_name);
        fs::write(&publication_target, b"keep-publication").unwrap();
        assert!(preflight_hard_links_named(&attempt, &layout, publication_name).is_err());
        assert_eq!(fs::read(&publication_target).unwrap(), b"keep-publication");
        assert!(!attempt.join(publication_name).exists());
        assert!(!layout.objects.join(publication_name).exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn simultaneous_identical_publishers_converge_on_one_bundle() {
        let root = test_root("publisher-race");
        let pointer = root.join("model.sources");
        let (built, identity) = fixture();
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let built = built.clone();
            let identity = identity.clone();
            let pointer = pointer.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                let bundle = build_verified_model_whir_sources(
                    Cursor::new(&built.bytes),
                    &built.manifest,
                    &identity,
                    pointer,
                )
                .unwrap();
                bundle.bundle_identity()
            }));
        }
        let identities = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(identities[0], identities[1]);
        let reopened =
            open_published_model_whir_sources(&pointer, &built.manifest, &identity, &identities[0])
                .unwrap();
        assert_eq!(reopened.bundle_digest(), identities[0].bundle_digest());
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn role_replay_and_manifest_tampering_fail_against_retained_identity() {
        let root = test_root("tamper");
        let (built, identity) = fixture();

        let replay_pointer = root.join("replay.sources");
        let replay_bundle = build_verified_model_whir_sources(
            Cursor::new(&built.bytes),
            &built.manifest,
            &identity,
            &replay_pointer,
        )
        .unwrap();
        let replay_identity = replay_bundle.bundle_identity();
        let role_paths = replay_bundle
            .roles()
            .iter()
            .map(|role| role.path().to_path_buf())
            .collect::<Vec<_>>();
        drop(replay_bundle);
        fs::copy(&role_paths[1], &role_paths[2]).unwrap();
        assert!(matches!(
            open_published_model_whir_sources(
                &replay_pointer,
                &built.manifest,
                &identity,
                &replay_identity,
            ),
            Err(ModelWhirSourceError::Artifact(
                WhirInitialSourceArtifactError::IdentityMismatch
            ))
        ));

        let manifest_pointer = root.join("manifest.sources");
        let manifest_bundle = build_verified_model_whir_sources(
            Cursor::new(&built.bytes),
            &built.manifest,
            &identity,
            &manifest_pointer,
        )
        .unwrap();
        let manifest_identity = manifest_bundle.bundle_identity();
        drop(manifest_bundle);
        let mut manifest_bytes = fs::read(&manifest_pointer).unwrap();
        manifest_bytes[BUNDLE_HEADER_BYTES + 4] ^= 1;
        fs::write(&manifest_pointer, manifest_bytes).unwrap();
        assert!(matches!(
            open_published_model_whir_sources(
                &manifest_pointer,
                &built.manifest,
                &identity,
                &manifest_identity,
            ),
            Err(ModelWhirSourceError::Invalid(_))
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_bundle_identity_rejects_a_self_consistent_storage_substitution() {
        let root = test_root("whole-bundle-substitution");
        let pointer = root.join("model.sources");
        let (built, identity) = fixture();
        let legitimate = build_verified_model_whir_sources(
            Cursor::new(&built.bytes),
            &built.manifest,
            &identity,
            &pointer,
        )
        .unwrap();
        let retained_identity = legitimate.bundle_identity();
        drop(legitimate);
        fs::remove_file(&pointer).unwrap();

        let layout = publication_layout(&pointer).unwrap();
        fs::create_dir_all(&layout.staging).unwrap();
        let attempt_path = create_attempt_dir(&layout.staging).unwrap();
        let plans = plan_roles(&built.manifest, &identity).unwrap();
        let mut sealed = Vec::with_capacity(plans.len());
        for (index, plan) in plans.into_iter().enumerate() {
            let staged_path = attempt_path.join(role_file_name(index));
            let mut writer =
                WhirInitialSourceArtifactWriter::create(&staged_path, plan.source.clone()).unwrap();
            let replacement = vec![
                u64::try_from(index + 17).unwrap();
                usize::try_from(plan.element_count).unwrap()
            ];
            writer.write_elements(&replacement).unwrap();
            let artifact = writer.finish().unwrap();
            sealed.push(SealedRole {
                plan,
                staged_path,
                artifact_identity: artifact.artifact_identity().clone(),
            });
            drop(artifact);
        }
        let (substitute_digest, substitute_manifest) = encode_bundle(
            retained_identity.model_digest(),
            retained_identity.manifest_digest(),
            &sealed,
        )
        .unwrap();
        assert_ne!(substitute_digest, retained_identity.bundle_digest());
        publish_bundle(&layout, &sealed, substitute_digest, &substitute_manifest).unwrap();
        fs::remove_dir_all(attempt_path).unwrap();

        assert!(matches!(
            open_published_model_whir_sources(
                &pointer,
                &built.manifest,
                &identity,
                &retained_identity,
            ),
            Err(ModelWhirSourceError::PublishedBundleMismatch)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_bundle_manifest_has_stable_known_answers() {
        let root = test_root("known-answer");
        let pointer = root.join("model.sources");
        let (built, identity) = fixture();
        let bundle = build_verified_model_whir_sources(
            Cursor::new(&built.bytes),
            &built.manifest,
            &identity,
            &pointer,
        )
        .unwrap();
        let bytes = fs::read(&pointer).unwrap();
        assert_eq!(bytes.len(), BUNDLE_HEADER_BYTES + 3 * BUNDLE_ROLE_BYTES);
        assert_eq!(
            hex::encode(bundle.bundle_digest()),
            "101da7aaad576db4bcadf336ae508d64b5afae8e4c6ee9f488f1bb60360dfac7"
        );
        assert_eq!(
            hex::encode(blake3::hash(&bytes).as_bytes()),
            "d5a8a1e33a0a7c5684b4b83798bd0dd4199715226fa941a20a7405716cad5d7a"
        );
        drop(bundle);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_source_plan_creates_only_header_sized_provisional_files() {
        let relative_layout = publication_layout(Path::new("model.sources")).unwrap();
        assert_eq!(relative_layout.publication, Path::new("model.sources"));
        assert_eq!(
            relative_layout.objects,
            Path::new(".").join("model.sources.objects")
        );

        let root = test_root("production-plan");
        let pointer = root.join("model.sources");
        let suite = structured_whir_suite_parameter_digest();
        let identity = ModelPcsIdentity {
            model_version: 2,
            batch: PRODUCTION_V2_BATCH,
            dimension: PRODUCTION_V2_DIMENSION,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model_byte_root: [0x11; 32],
            pcs_suite_parameter_digest: suite,
            base_input_commitment: [0x31; 32],
            weight_bank_commitments: vec![[0x41; 32], [0x42; 32], [0x43; 32]],
        };
        let dimension = u64::from(PRODUCTION_V2_DIMENSION);
        let base_input_bytes = u64::from(PRODUCTION_V2_BATCH) * dimension;
        let bytes_per_layer = dimension * dimension;
        let manifest = ModelBankManifest {
            model_version: 2,
            dimension: PRODUCTION_V2_DIMENSION,
            batch: PRODUCTION_V2_BATCH,
            layers: PRODUCTION_V2_LAYERS,
            base_input_bytes,
            bytes_per_layer,
            payload_bytes: base_input_bytes + u64::from(PRODUCTION_V2_LAYERS) * bytes_per_layer,
            raw_blake3_root: identity.model_byte_root,
            layer_roots_aggregate: [0x21; 32],
            pcs_parameter_digest: suite,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        };
        let sink = ModelWhirSourceSink::new(&pointer, &manifest, &identity).unwrap();
        assert_eq!(sink.roles[0].plan.source.num_variables, 19);
        assert!(
            sink.roles[1..]
                .iter()
                .all(|role| role.plan.source.num_variables == 31)
        );
        for role in &sink.roles {
            let mut partial_name = role.staged_path.file_name().unwrap().to_os_string();
            partial_name.push(".partial");
            let partial = role.staged_path.with_file_name(partial_name);
            assert_eq!(
                fs::metadata(partial).unwrap().len(),
                cmfd_proof_accel::whir_initial_source::WHIR_INITIAL_SOURCE_HEADER_BYTES as u64
            );
        }
        assert_eq!(
            cmfd_proof_accel::whir_initial::WHIR_INITIAL_MAX_VARIABLES,
            19
        );
        assert_eq!(WHIR_INITIAL_SOURCE_MAX_VARIABLES, 31);
        drop(sink);
        fs::remove_dir_all(root).unwrap();
    }
}
