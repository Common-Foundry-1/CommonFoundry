//! Explicit offline operator tools for exchange-custody v3.
//!
//! Every mutating workflow is split into plan/apply, requires an exact public
//! confirmation value, and writes operator artifacts with create-new
//! semantics. These functions never start RPC/P2P services, sign withdrawals,
//! broadcast transactions, invent policy identities, or overwrite an archive.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use blake3::Hasher;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::Node;
use crate::exchange_archive::{
    WithdrawalArchiveEnvelopeV3, WithdrawalArchiveManifestPinV3, archive_request_id_tag,
    build_canceled_archive, verify_archive_for_restore,
};
use crate::exchange_custody_v3::{
    ExchangeCustodyV3OpenConfig, ExchangeCustodyV3Store, MigrationPlanV3, MigrationPlanV3Config,
    journal_anchor_v3_from_v2, keyring_anchor_v3_from_v1, load_external_control_document_v3,
    load_journal_key_v3, load_keyring_anchor_v3, load_keyring_envelope_v3,
    load_keyring_passphrase_v3, load_policy_document_v3, load_provisioning_passphrase_v3,
    load_wallet_passphrase_v3, migration_backup_paths,
};
use crate::exchange_local_signer::local_signer_profile;
use crate::exchange_policy::{
    ApprovalAnchor, ExpectedApproval, PolicyWindowState, WithdrawalAction, WithdrawalApproval,
    WithdrawalPolicy, WithdrawalPolicyBinding,
};
use crate::exchange_withdrawal::{
    ExchangeWithdrawalJournal, ValidatedV2MigrationExport, WithdrawalJournalAnchor,
};
use crate::exchange_withdrawal_v3::{
    CompactTerminalRecordsV3, DecisionScopeV3, JournalAnchorV3, JournalBindingV3,
    JournalTransitionV3, PolicyReleaseEventV3, PolicyWindowStateV3, ReservedInputV3,
    ReservedOutpointV3, RotateKeyringV3, TerminalDecisionV3, ValidatedV2MigrationInputV3,
    ValidatedV2ReleasedRecordV3, WithdrawalActionV3, WithdrawalCoreV3, migrate_validated_v2,
    validated_v2_snapshot_digest,
};
#[cfg(test)]
use crate::wallet_backup::read_wallet_passphrase_file;
use crate::wallet_backup::{ENCRYPTED_WALLET_KEY_BYTES, decrypt_wallet_key_bytes};
use crate::wallet_keyring::{
    KeyLifecycle, KeyLifecycleUpdate, KeyRoles, KeyStorageBinding, KeyringAnchorV1,
    KeyringRuntimeBinding, WalletKeyEntry, WalletKeySummary, WalletKeyring,
    stage_legacy_single_key_import,
};
use crate::wallet_signing_protocol::{SignerId, wallet_key_id};

const NODE_LOCK_FILE: &str = "node.lock";
const KEYRING_PLAN_SCHEMA: &str = "common-foundry-exchange-keyring-import-plan-v1";
const KEYRING_EXTERNAL_TRANSITION_PLAN_SCHEMA: &str =
    "common-foundry-exchange-keyring-external-transition-plan-v1";
const KEYRING_EXTERNAL_FINALIZATION_PLAN_SCHEMA: &str =
    "common-foundry-exchange-keyring-external-finalization-plan-v1";
const LEGACY_KEY_DECOMMISSION_EVIDENCE_SCHEMA: &str =
    "common-foundry-exchange-legacy-key-decommission-evidence-v1";
pub const V3_MIGRATION_EVIDENCE_SCHEMA: &str = "common-foundry-exchange-v3-migration-evidence-v2";
const MIGRATION_PLAN_SCHEMA: &str = "common-foundry-exchange-v3-migration-plan-v2";
const LEGACY_KEY_DIGEST_DOMAIN: &str = "CMFD/NODE/EXCHANGE-LEGACY-KEY/PLAN/V1";
const KEYRING_ENVELOPE_DIGEST_DOMAIN: &str = "CMFD/NODE/EXCHANGE-KEYRING-ENVELOPE/PLAN/V1";
const KEYRING_EXTERNAL_TRANSITION_DIGEST_DOMAIN: &str =
    "CMFD/NODE/EXCHANGE-KEYRING-EXTERNAL-TRANSITION/CONFIRMATION/V1";
const KEYRING_EXTERNAL_FINALIZATION_DIGEST_DOMAIN: &str =
    "CMFD/NODE/EXCHANGE-KEYRING-EXTERNAL-FINALIZATION/CONFIRMATION/V1";
const LEGACY_KEY_DECOMMISSION_EVIDENCE_DIGEST_DOMAIN: &str =
    "CMFD/NODE/EXCHANGE-LEGACY-KEY-DECOMMISSION-EVIDENCE/V1";
const EVIDENCE_DIGEST_DOMAIN: &str = "CMFD/NODE/EXCHANGE-MIGRATION-EVIDENCE/PLAN/V1";
const MIGRATION_PLAN_DIGEST_DOMAIN: &str = "CMFD/NODE/EXCHANGE-MIGRATION-PLAN/CONFIRMATION/V2";
const MAX_TOOL_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const MIGRATION_CUTOVER_MAX_HORIZON_SECONDS: u64 = 15 * 60;
const WITHDRAWAL_SNAPSHOT_MAGIC: [u8; 8] = *b"CMFDEXW\0";
const V3_WITHDRAWAL_SNAPSHOT_VERSION: u32 = 3;
// A conservative software safety floor for this workflow, not economic finality.
const MINIMUM_LEGACY_SWEEP_CONFIRMATIONS: u64 = 720;

#[derive(Debug, Error)]
pub enum ExchangeCustodyToolError {
    #[error("operator tool paths must be absolute: {0}")]
    RelativePath(&'static str),
    #[error("operator tool path is invalid: {0}")]
    InvalidPath(&'static str),
    #[error("operator output already exists: {0}")]
    OutputExists(PathBuf),
    #[error("operator-controlled artifact must be outside the node data directory: {0}")]
    ControlInsideDataDirectory(PathBuf),
    #[error("the node must be stopped before running this operator command")]
    NodeMustBeOffline,
    #[error("operator confirmation does not match the exact plan")]
    ConfirmationMismatch,
    #[error("operator plan or evidence is invalid: {0}")]
    InvalidDocument(&'static str),
    #[error("operator operation failed: {0}")]
    Operation(String),
    #[error("{action} failed for {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Loads the legacy live-wallet passphrase under the external-secret policy
/// required when exchange custody v3 exclusively owns that wallet.
pub fn load_exchange_custody_v3_wallet_passphrase(
    data_dir: &Path,
    passphrase_file: &Path,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyToolError> {
    load_wallet_passphrase_v3(data_dir, passphrase_file).map_err(operation)
}

/// Reports whether persisted custody state requires the v3 wallet security
/// boundary even when the current invocation omitted the v3 activation flags.
pub fn persisted_exchange_custody_v3_wallet_security_required(data_dir: &Path) -> bool {
    crate::exchange_custody_v3::persisted_v3_wallet_claim_required(data_dir)
}

/// Creates a raw journal-authentication key with the same protected
/// node-owned-file policy used by the v3 loader. Existing files are never
/// opened for writing.
pub fn create_exchange_journal_key_create_new(
    output: &Path,
) -> Result<(), ExchangeCustodyToolError> {
    let output = resolve_output(output, "withdrawal journal key")?;
    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(key.as_mut()).map_err(operation)?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(ExchangeCustodyToolError::Operation(
            "secure random generator returned an invalid zero key".to_owned(),
        ));
    }
    write_create_new(&output, key.as_slice(), true)
}

#[derive(Debug, Clone)]
pub struct LegacyKeyringPlanConfig {
    pub data_dir: PathBuf,
    pub legacy_key_file: PathBuf,
    /// Required when `legacy_key_file` is the encrypted RCNet wallet format.
    pub legacy_wallet_passphrase_file: Option<PathBuf>,
    pub keyring_instance_id: [u8; 32],
    pub plan_output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LegacyKeyringApplyConfig {
    pub data_dir: PathBuf,
    pub plan_file: PathBuf,
    pub expected_confirmation_digest: [u8; 32],
    pub passphrase_file: PathBuf,
    pub keyring_output: PathBuf,
    pub anchor_output: PathBuf,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyKeyringPlanReport {
    pub status: &'static str,
    pub plan_file: PathBuf,
    pub confirmation_digest: String,
    pub candidate_anchor: KeyringAnchorReport,
    pub legacy_key_id: String,
    pub legacy_public_key: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LegacyKeyringApplyReport {
    pub status: &'static str,
    pub keyring_file: PathBuf,
    pub anchor_file: PathBuf,
    pub anchor: KeyringAnchorReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyringAnchorReport {
    pub network_id: String,
    pub consensus_fingerprint: String,
    pub genesis_hash: String,
    pub instance_id: String,
    pub generation: String,
    pub commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyKeyringPlanDocument {
    schema: String,
    legacy_key_file: PathBuf,
    legacy_wallet_passphrase_file: Option<PathBuf>,
    legacy_key_digest: String,
    keyring_instance_id: String,
    legacy_key_id: String,
    legacy_public_key: String,
    candidate_anchor: KeyringAnchorReport,
    confirmation_digest: String,
}

pub fn plan_legacy_keyring_import(
    config: &LegacyKeyringPlanConfig,
) -> Result<LegacyKeyringPlanReport, ExchangeCustodyToolError> {
    let data_dir = canonical_data_dir(&config.data_dir)?;
    let _offline = OfflineNodeLock::acquire(&data_dir)?;
    let legacy_path = resolve_existing_file(&config.legacy_key_file, "legacy wallet key")?;
    let plan_path = resolve_output(&config.plan_output, "keyring import plan")?;
    ensure_outside_data_dir(&data_dir, &plan_path)?;
    if config.keyring_instance_id == [0; 32] {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "keyring_instance_id is zero",
        ));
    }
    let legacy_bytes = Zeroizing::new(read_bounded(
        &legacy_path,
        ENCRYPTED_WALLET_KEY_BYTES,
        "legacy wallet key",
    )?);
    let legacy_passphrase_path = config
        .legacy_wallet_passphrase_file
        .as_ref()
        .map(|path| resolve_existing_file(path, "legacy wallet passphrase"))
        .transpose()?;
    if let Some(path) = &legacy_passphrase_path {
        ensure_outside_data_dir(&data_dir, path)?;
    }
    let legacy_secret = decrypt_legacy_wallet_key(
        &data_dir,
        legacy_bytes.as_slice(),
        legacy_passphrase_path.as_deref(),
        stored_keyring_binding(&data_dir)?.network_id,
    )?;
    let legacy_digest = digest(LEGACY_KEY_DIGEST_DOMAIN, legacy_bytes.as_slice());
    let staging = stage_legacy_single_key_import(
        stored_keyring_binding(&data_dir)?,
        config.keyring_instance_id,
        legacy_secret,
    )
    .map_err(operation)?;
    let key = staging.legacy_key();
    let anchor = staging.candidate_anchor();
    let confirmation = staging.confirmation_digest();
    let document = LegacyKeyringPlanDocument {
        schema: KEYRING_PLAN_SCHEMA.to_owned(),
        legacy_key_file: legacy_path,
        legacy_wallet_passphrase_file: legacy_passphrase_path,
        legacy_key_digest: hex::encode(legacy_digest),
        keyring_instance_id: hex::encode(config.keyring_instance_id),
        legacy_key_id: hex::encode(key.key_id.0),
        legacy_public_key: hex::encode(key.public_key),
        candidate_anchor: keyring_anchor_report(anchor),
        confirmation_digest: hex::encode(confirmation),
    };
    write_create_new(
        &plan_path,
        &serde_json::to_vec_pretty(&document).map_err(operation)?,
        false,
    )?;
    Ok(LegacyKeyringPlanReport {
        status: "planned",
        plan_file: plan_path,
        confirmation_digest: hex::encode(confirmation),
        candidate_anchor: keyring_anchor_report(anchor),
        legacy_key_id: hex::encode(key.key_id.0),
        legacy_public_key: hex::encode(key.public_key),
    })
}

pub fn apply_legacy_keyring_import(
    config: &LegacyKeyringApplyConfig,
) -> Result<LegacyKeyringApplyReport, ExchangeCustodyToolError> {
    let data_dir = canonical_data_dir(&config.data_dir)?;
    let _offline = OfflineNodeLock::acquire(&data_dir)?;
    let plan_path = resolve_existing_file(&config.plan_file, "keyring import plan")?;
    ensure_outside_data_dir(&data_dir, &plan_path)?;
    let plan: LegacyKeyringPlanDocument = read_json(&plan_path, "keyring import plan")?;
    if plan.schema != KEYRING_PLAN_SCHEMA
        || decode_hex32(&plan.confirmation_digest, "confirmation_digest")?
            != config.expected_confirmation_digest
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let legacy_path = resolve_existing_file(&plan.legacy_key_file, "legacy wallet key")?;
    let legacy_bytes = Zeroizing::new(read_bounded(
        &legacy_path,
        ENCRYPTED_WALLET_KEY_BYTES,
        "legacy wallet key",
    )?);
    if digest(LEGACY_KEY_DIGEST_DOMAIN, legacy_bytes.as_slice())
        != decode_hex32(&plan.legacy_key_digest, "legacy_key_digest")?
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "legacy key changed after planning",
        ));
    }
    let legacy_secret = decrypt_legacy_wallet_key(
        &data_dir,
        legacy_bytes.as_slice(),
        plan.legacy_wallet_passphrase_file.as_deref(),
        stored_keyring_binding(&data_dir)?.network_id,
    )?;
    let instance_id = decode_hex32(&plan.keyring_instance_id, "keyring_instance_id")?;
    let staging = stage_legacy_single_key_import(
        stored_keyring_binding(&data_dir)?,
        instance_id,
        legacy_secret,
    )
    .map_err(operation)?;
    let key = staging.legacy_key();
    let anchor = staging.candidate_anchor();
    if staging.confirmation_digest() != config.expected_confirmation_digest
        || hex::encode(key.key_id.0) != plan.legacy_key_id
        || hex::encode(key.public_key) != plan.legacy_public_key
        || keyring_anchor_report(anchor) != plan.candidate_anchor
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }

    let keyring_output = resolve_output_or_existing_file(&config.keyring_output, "wallet keyring")?;
    let anchor_output =
        resolve_output_or_existing_file(&config.anchor_output, "wallet keyring anchor")?;
    ensure_outside_data_dir(&data_dir, &anchor_output)?;
    let passphrase_path = resolve_existing_file(&config.passphrase_file, "keyring passphrase")?;
    ensure_outside_data_dir(&data_dir, &passphrase_path)?;
    let passphrase = load_provisioning_passphrase_v3(
        &data_dir,
        &passphrase_path,
        "keyring provisioning passphrase",
    )
    .map_err(operation)?;
    let keyring = staging
        .activate(config.expected_confirmation_digest)
        .map_err(operation)?;
    let anchor_bytes = anchor.encode().map_err(operation)?;
    if keyring_output.exists() {
        let existing = load_keyring_envelope_v3(&keyring_output).map_err(operation)?;
        WalletKeyring::decode_live(
            &existing,
            stored_keyring_binding(&data_dir)?,
            &passphrase,
            anchor,
        )
        .map_err(operation)?;
    } else {
        let envelope = keyring.encode_live(&passphrase).map_err(operation)?;
        write_create_new(&keyring_output, &envelope, true)?;
    }
    create_or_verify_exact(&anchor_output, &anchor_bytes, false)?;
    Ok(LegacyKeyringApplyReport {
        status: "applied_to_create_new_artifacts; pin anchor_file independently before use",
        keyring_file: keyring_output,
        anchor_file: anchor_output,
        anchor: keyring_anchor_report(anchor),
    })
}

#[derive(Debug, Clone)]
pub struct ExternalKeyringTransitionPlanConfig {
    pub data_dir: PathBuf,
    pub source_keyring_file: PathBuf,
    pub source_anchor_file: PathBuf,
    pub source_keyring_passphrase_file: PathBuf,
    pub external_public_key: [u8; 32],
    pub external_signer_id: [u8; 32],
    pub keyring_output: PathBuf,
    pub anchor_output: PathBuf,
    pub plan_output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ExternalKeyringTransitionApplyConfig {
    pub data_dir: PathBuf,
    pub plan_file: PathBuf,
    pub expected_confirmation_digest: [u8; 32],
    pub source_keyring_passphrase_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExternalKeyringTransitionPlanReport {
    pub status: &'static str,
    pub plan_file: PathBuf,
    pub confirmation_digest: String,
    pub source_anchor: KeyringAnchorReport,
    pub candidate_anchor: KeyringAnchorReport,
    pub legacy_key_id: String,
    pub legacy_public_key: String,
    pub external_key_id: String,
    pub external_public_key: String,
    pub external_signer_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExternalKeyringTransitionApplyReport {
    pub status: &'static str,
    pub keyring_file: PathBuf,
    pub anchor_file: PathBuf,
    pub anchor: KeyringAnchorReport,
    pub legacy_key_id: String,
    pub external_key_id: String,
    pub external_signer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalKeyringTransitionPlanDocument {
    schema: String,
    data_dir: PathBuf,
    plan_file: PathBuf,
    source_keyring_file: PathBuf,
    source_anchor_file: PathBuf,
    source_keyring_digest: String,
    source_anchor: KeyringAnchorReport,
    legacy_key_id: String,
    legacy_public_key: String,
    external_key_id: String,
    external_public_key: String,
    external_signer_id: String,
    candidate_anchor: KeyringAnchorReport,
    keyring_output: PathBuf,
    anchor_output: PathBuf,
    confirmation_digest: String,
}

fn external_keyring_transition_confirmation_digest(
    plan: &ExternalKeyringTransitionPlanDocument,
) -> Result<[u8; 32], ExchangeCustodyToolError> {
    let mut canonical = plan.clone();
    canonical.confirmation_digest = hex::encode([0_u8; 32]);
    let bytes = serde_json::to_vec(&canonical).map_err(operation)?;
    Ok(digest(KEYRING_EXTERNAL_TRANSITION_DIGEST_DOMAIN, &bytes))
}

fn validate_external_keyring_transition_confirmation(
    plan: &ExternalKeyringTransitionPlanDocument,
    expected_confirmation_digest: [u8; 32],
    expected_data_dir: &Path,
    expected_plan_file: &Path,
) -> Result<(), ExchangeCustodyToolError> {
    let calculated = external_keyring_transition_confirmation_digest(plan)?;
    let embedded = decode_hex32(&plan.confirmation_digest, "confirmation_digest")
        .map_err(|_| ExchangeCustodyToolError::ConfirmationMismatch)?;
    if plan.schema != KEYRING_EXTERNAL_TRANSITION_PLAN_SCHEMA
        || plan.data_dir != expected_data_dir
        || plan.plan_file != expected_plan_file
        || embedded != calculated
        || expected_confirmation_digest != calculated
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    Ok(())
}

fn transition_imported_keyring_to_external(
    keyring: WalletKeyring,
    external_public_key: [u8; 32],
    external_signer_id: [u8; 32],
) -> Result<(WalletKeySummary, WalletKeySummary, WalletKeyring), ExchangeCustodyToolError> {
    let summaries = keyring.summaries();
    let legacy = keyring.active_change_key();
    let deposit_and_change = KeyRoles::DEPOSIT.union(KeyRoles::CHANGE);
    if summaries.len() != 1
        || summaries[0] != legacy
        || legacy.lifecycle != KeyLifecycle::Active
        || legacy.storage != KeyStorageBinding::Local
        || legacy.roles.bits() != deposit_and_change.bits()
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "source keyring is not an imported single local DEPOSIT+CHANGE key",
        ));
    }
    let external = WalletKeyEntry::external(
        external_public_key,
        deposit_and_change,
        KeyLifecycle::Active,
        SignerId(external_signer_id),
    )
    .map_err(operation)?;
    let external_summary = external.summary();
    let source_anchor = keyring.anchor();
    let candidate = keyring
        .transition(
            source_anchor,
            &[KeyLifecycleUpdate {
                key_id: legacy.key_id,
                lifecycle: KeyLifecycle::Retired,
            }],
            vec![external],
        )
        .map_err(operation)?;
    Ok((legacy, external_summary, candidate))
}

pub fn plan_external_keyring_transition(
    config: &ExternalKeyringTransitionPlanConfig,
) -> Result<ExternalKeyringTransitionPlanReport, ExchangeCustodyToolError> {
    let data_dir = canonical_data_dir(&config.data_dir)?;
    let _offline = OfflineNodeLock::acquire(&data_dir)?;
    let source_keyring =
        resolve_existing_file(&config.source_keyring_file, "source wallet keyring")?;
    let source_anchor =
        resolve_existing_file(&config.source_anchor_file, "source wallet keyring anchor")?;
    let source_passphrase = resolve_existing_file(
        &config.source_keyring_passphrase_file,
        "source wallet keyring passphrase",
    )?;
    let keyring_output = resolve_output(&config.keyring_output, "candidate wallet keyring")?;
    let anchor_output = resolve_output(&config.anchor_output, "candidate wallet keyring anchor")?;
    let plan_output = resolve_output(&config.plan_output, "external keyring transition plan")?;
    for path in [
        &source_anchor,
        &source_passphrase,
        &anchor_output,
        &plan_output,
    ] {
        ensure_outside_data_dir(&data_dir, path)?;
    }
    if keyring_output == source_keyring
        || anchor_output == source_anchor
        || keyring_output == anchor_output
        || plan_output == keyring_output
        || plan_output == anchor_output
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "keyring transition inputs and outputs overlap",
        ));
    }

    let envelope = load_keyring_envelope_v3(&source_keyring).map_err(operation)?;
    let source_anchor_bytes = read_bounded(
        &source_anchor,
        crate::wallet_keyring::KEYRING_ANCHOR_BYTES,
        "source wallet keyring anchor",
    )?;
    let trusted_anchor = KeyringAnchorV1::decode(&source_anchor_bytes).map_err(operation)?;
    let passphrase = load_provisioning_passphrase_v3(
        &data_dir,
        &source_passphrase,
        "source wallet keyring provisioning passphrase",
    )
    .map_err(operation)?;
    let keyring = WalletKeyring::decode_live(
        &envelope,
        stored_keyring_binding(&data_dir)?,
        &passphrase,
        trusted_anchor,
    )
    .map_err(operation)?;
    let (legacy, external, candidate) = transition_imported_keyring_to_external(
        keyring,
        config.external_public_key,
        config.external_signer_id,
    )?;
    let candidate_anchor = candidate.anchor();
    let mut document = ExternalKeyringTransitionPlanDocument {
        schema: KEYRING_EXTERNAL_TRANSITION_PLAN_SCHEMA.to_owned(),
        data_dir,
        plan_file: plan_output.clone(),
        source_keyring_file: source_keyring,
        source_anchor_file: source_anchor,
        source_keyring_digest: hex::encode(digest(
            KEYRING_ENVELOPE_DIGEST_DOMAIN,
            envelope.as_slice(),
        )),
        source_anchor: keyring_anchor_report(trusted_anchor),
        legacy_key_id: hex::encode(legacy.key_id.0),
        legacy_public_key: hex::encode(legacy.public_key),
        external_key_id: hex::encode(external.key_id.0),
        external_public_key: hex::encode(external.public_key),
        external_signer_id: hex::encode(config.external_signer_id),
        candidate_anchor: keyring_anchor_report(candidate_anchor),
        keyring_output,
        anchor_output,
        confirmation_digest: hex::encode([0_u8; 32]),
    };
    let confirmation = external_keyring_transition_confirmation_digest(&document)?;
    document.confirmation_digest = hex::encode(confirmation);
    write_create_new(
        &plan_output,
        &serde_json::to_vec_pretty(&document).map_err(operation)?,
        false,
    )?;
    Ok(ExternalKeyringTransitionPlanReport {
        status: "planned; source keyring remains unchanged",
        plan_file: plan_output,
        confirmation_digest: hex::encode(confirmation),
        source_anchor: keyring_anchor_report(trusted_anchor),
        candidate_anchor: keyring_anchor_report(candidate_anchor),
        legacy_key_id: hex::encode(legacy.key_id.0),
        legacy_public_key: hex::encode(legacy.public_key),
        external_key_id: hex::encode(external.key_id.0),
        external_public_key: hex::encode(external.public_key),
        external_signer_id: hex::encode(config.external_signer_id),
    })
}

pub fn apply_external_keyring_transition(
    config: &ExternalKeyringTransitionApplyConfig,
) -> Result<ExternalKeyringTransitionApplyReport, ExchangeCustodyToolError> {
    let data_dir = canonical_data_dir(&config.data_dir)?;
    let _offline = OfflineNodeLock::acquire(&data_dir)?;
    let plan_file = resolve_existing_file(&config.plan_file, "external keyring transition plan")?;
    ensure_outside_data_dir(&data_dir, &plan_file)?;
    let plan: ExternalKeyringTransitionPlanDocument =
        read_json(&plan_file, "external keyring transition plan")?;
    validate_external_keyring_transition_confirmation(
        &plan,
        config.expected_confirmation_digest,
        &data_dir,
        &plan_file,
    )?;

    let source_keyring = resolve_existing_file(&plan.source_keyring_file, "source wallet keyring")?;
    let source_anchor =
        resolve_existing_file(&plan.source_anchor_file, "source wallet keyring anchor")?;
    if source_keyring != plan.source_keyring_file || source_anchor != plan.source_anchor_file {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    ensure_outside_data_dir(&data_dir, &source_anchor)?;
    let source_passphrase = resolve_existing_file(
        &config.source_keyring_passphrase_file,
        "source wallet keyring passphrase",
    )?;
    ensure_outside_data_dir(&data_dir, &source_passphrase)?;
    let envelope = load_keyring_envelope_v3(&source_keyring).map_err(operation)?;
    if digest(KEYRING_ENVELOPE_DIGEST_DOMAIN, envelope.as_slice())
        != decode_hex32(&plan.source_keyring_digest, "source_keyring_digest")?
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "source wallet keyring changed after planning",
        ));
    }
    let source_anchor_bytes = read_bounded(
        &source_anchor,
        crate::wallet_keyring::KEYRING_ANCHOR_BYTES,
        "source wallet keyring anchor",
    )?;
    let trusted_anchor = KeyringAnchorV1::decode(&source_anchor_bytes).map_err(operation)?;
    if keyring_anchor_report(trusted_anchor) != plan.source_anchor {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "source wallet keyring anchor changed after planning",
        ));
    }
    let passphrase = load_provisioning_passphrase_v3(
        &data_dir,
        &source_passphrase,
        "source wallet keyring provisioning passphrase",
    )
    .map_err(operation)?;
    let keyring = WalletKeyring::decode_live(
        &envelope,
        stored_keyring_binding(&data_dir)?,
        &passphrase,
        trusted_anchor,
    )
    .map_err(operation)?;
    let external_public_key =
        decode_nonzero_hex32(&plan.external_public_key, "external_public_key")?;
    let external_signer_id = decode_nonzero_hex32(&plan.external_signer_id, "external_signer_id")?;
    let (legacy, external, candidate) =
        transition_imported_keyring_to_external(keyring, external_public_key, external_signer_id)?;
    let candidate_anchor = candidate.anchor();
    if hex::encode(legacy.key_id.0) != plan.legacy_key_id
        || hex::encode(legacy.public_key) != plan.legacy_public_key
        || hex::encode(external.key_id.0) != plan.external_key_id
        || keyring_anchor_report(candidate_anchor) != plan.candidate_anchor
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }

    let keyring_output =
        resolve_output_or_existing_file(&plan.keyring_output, "candidate wallet keyring")?;
    let anchor_output =
        resolve_output_or_existing_file(&plan.anchor_output, "candidate wallet keyring anchor")?;
    if keyring_output != plan.keyring_output || anchor_output != plan.anchor_output {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    ensure_outside_data_dir(&data_dir, &anchor_output)?;
    let anchor_bytes = candidate_anchor.encode().map_err(operation)?;
    if anchor_output.exists() {
        create_or_verify_exact(&anchor_output, &anchor_bytes, false)?;
    }
    if keyring_output.exists() {
        let existing = load_keyring_envelope_v3(&keyring_output).map_err(operation)?;
        WalletKeyring::decode_live(
            &existing,
            stored_keyring_binding(&data_dir)?,
            &passphrase,
            candidate_anchor,
        )
        .map_err(operation)?;
    } else {
        let encoded = candidate.encode_live(&passphrase).map_err(operation)?;
        write_create_new(&keyring_output, &encoded, true)?;
    }
    create_or_verify_exact(&anchor_output, &anchor_bytes, false)?;
    Ok(ExternalKeyringTransitionApplyReport {
        status: "applied_to_create_new_artifacts; source retained; pin candidate anchor independently before migration",
        keyring_file: keyring_output,
        anchor_file: anchor_output,
        anchor: keyring_anchor_report(candidate_anchor),
        legacy_key_id: hex::encode(legacy.key_id.0),
        external_key_id: hex::encode(external.key_id.0),
        external_signer_id: hex::encode(external_signer_id),
    })
}

#[derive(Debug, Clone)]
pub struct ExternalKeyringFinalizationPlanConfig {
    pub data_dir: PathBuf,
    pub controls: V3OfflineControlConfig,
    pub legacy_public_key: [u8; 32],
    pub decommission_evidence_file: PathBuf,
    pub rotation_decision_id: [u8; 32],
    pub approval_digest: [u8; 32],
    pub keyring_output: PathBuf,
    pub keyring_anchor_output: PathBuf,
    pub journal_anchor_output: PathBuf,
    pub plan_output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ExternalKeyringFinalizationApplyConfig {
    pub data_dir: PathBuf,
    pub journal_key_file: PathBuf,
    pub external_anchor_file: PathBuf,
    pub plan_file: PathBuf,
    pub expected_confirmation_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyKeyUtxoEvidenceReport {
    pub active_chain_tip: String,
    pub next_height: String,
    pub unspent_count: String,
    pub unspent_atoms: String,
    pub spendable_count: String,
    pub spendable_atoms: String,
    pub local_mempool_output_count: String,
    pub local_mempool_output_atoms: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LegacyKeyDecommissionEvidence {
    schema: String,
    legacy_public_key: String,
    confirmed_sweep_txid: String,
    minimum_sweep_confirmations: String,
    deposit_address_retirement_assertion_digest: String,
    external_mempool_quiescence_assertion_digest: String,
    post_apply_wallet_key_disposition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyKeySweepEvidenceReport {
    pub txid: String,
    pub block_id: String,
    pub height: String,
    pub confirmations: String,
    pub legacy_input_count: String,
    pub legacy_output_count: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExternalKeyringFinalizationPlanReport {
    pub status: &'static str,
    pub plan_file: PathBuf,
    pub confirmation_digest: String,
    pub source_anchor: KeyringAnchorReport,
    pub candidate_anchor: KeyringAnchorReport,
    pub source_journal_anchor: JournalAnchorReport,
    pub candidate_journal_anchor: JournalAnchorReport,
    pub legacy_key_id: String,
    pub external_key_id: String,
    pub external_signer_id: String,
    pub legacy_utxo_evidence: LegacyKeyUtxoEvidenceReport,
    pub confirmed_sweep: LegacyKeySweepEvidenceReport,
    pub post_apply_wallet_key_disposition: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExternalKeyringFinalizationApplyReport {
    pub status: &'static str,
    pub keyring_file: PathBuf,
    pub anchor_file: PathBuf,
    pub journal_anchor_file: PathBuf,
    pub anchor: KeyringAnchorReport,
    pub journal_anchor: JournalAnchorReport,
    pub legacy_key_id: String,
    pub external_key_id: String,
    pub external_signer_id: String,
    pub legacy_utxo_evidence: LegacyKeyUtxoEvidenceReport,
    pub confirmed_sweep: LegacyKeySweepEvidenceReport,
    pub post_apply_wallet_key_disposition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalKeyringFinalizationPlanDocument {
    schema: String,
    data_dir: PathBuf,
    plan_file: PathBuf,
    journal_key_file: PathBuf,
    external_journal_anchor_file: PathBuf,
    policy_file: PathBuf,
    source_keyring_file: PathBuf,
    source_anchor_file: PathBuf,
    source_keyring_passphrase_file: PathBuf,
    source_keyring_digest: String,
    source_anchor: KeyringAnchorReport,
    legacy_key_id: String,
    legacy_public_key: String,
    external_key_id: String,
    external_public_key: String,
    external_signer_id: String,
    legacy_utxo_evidence: LegacyKeyUtxoEvidenceReport,
    decommission_evidence_file: PathBuf,
    decommission_evidence_digest: String,
    decommission_evidence: LegacyKeyDecommissionEvidence,
    confirmed_sweep: LegacyKeySweepEvidenceReport,
    rotation_decision_id: String,
    approval_digest: String,
    source_journal_anchor: JournalAnchorReport,
    candidate_anchor: KeyringAnchorReport,
    candidate_journal_anchor: JournalAnchorReport,
    keyring_output: PathBuf,
    keyring_anchor_output: PathBuf,
    journal_anchor_output: PathBuf,
    confirmation_digest: String,
}

fn external_keyring_finalization_confirmation_digest(
    plan: &ExternalKeyringFinalizationPlanDocument,
) -> Result<[u8; 32], ExchangeCustodyToolError> {
    let mut canonical = plan.clone();
    canonical.confirmation_digest = hex::encode([0_u8; 32]);
    let bytes = serde_json::to_vec(&canonical).map_err(operation)?;
    Ok(digest(KEYRING_EXTERNAL_FINALIZATION_DIGEST_DOMAIN, &bytes))
}

fn validate_external_keyring_finalization_confirmation(
    plan: &ExternalKeyringFinalizationPlanDocument,
    expected_confirmation_digest: [u8; 32],
    expected_data_dir: &Path,
    expected_plan_file: &Path,
) -> Result<(), ExchangeCustodyToolError> {
    let calculated = external_keyring_finalization_confirmation_digest(plan)?;
    let embedded = decode_hex32(&plan.confirmation_digest, "confirmation_digest")
        .map_err(|_| ExchangeCustodyToolError::ConfirmationMismatch)?;
    if plan.schema != KEYRING_EXTERNAL_FINALIZATION_PLAN_SCHEMA
        || plan.data_dir != expected_data_dir
        || plan.plan_file != expected_plan_file
        || embedded != calculated
        || expected_confirmation_digest != calculated
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    Ok(())
}

fn finalize_mixed_keyring_external_only(
    keyring: WalletKeyring,
    legacy_public_key: [u8; 32],
) -> Result<(WalletKeySummary, WalletKeySummary, WalletKeyring), ExchangeCustodyToolError> {
    let summaries = keyring.summaries();
    let deposit_and_change = KeyRoles::DEPOSIT.union(KeyRoles::CHANGE);
    let legacy = keyring.key(wallet_key_id(&legacy_public_key)).ok_or(
        ExchangeCustodyToolError::InvalidDocument(
            "mixed keyring does not contain the selected legacy key",
        ),
    )?;
    let external = keyring.active_change_key();
    if summaries.len() != 2
        || legacy.public_key != legacy_public_key
        || legacy.lifecycle != KeyLifecycle::Retired
        || legacy.storage != KeyStorageBinding::Local
        || legacy.roles.bits() != deposit_and_change.bits()
        || external.lifecycle != KeyLifecycle::Active
        || !matches!(external.storage, KeyStorageBinding::External { .. })
        || external.roles.bits() != deposit_and_change.bits()
        || external.key_id == legacy.key_id
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "source keyring is not the exact mixed external-migration stage",
        ));
    }
    let source_anchor = keyring.anchor();
    let candidate = keyring
        .decommission_retired_local_key(source_anchor, legacy.key_id)
        .map_err(operation)?;
    Ok((legacy, external, candidate))
}

fn legacy_key_utxo_evidence(
    node: &Node,
    legacy_public_key: [u8; 32],
) -> Result<LegacyKeyUtxoEvidenceReport, ExchangeCustodyToolError> {
    let summary = node
        .exchange_custody_destination_utxo_summary(legacy_public_key)
        .map_err(operation)?;
    Ok(LegacyKeyUtxoEvidenceReport {
        active_chain_tip: hex::encode(summary.tip),
        next_height: summary.next_height.to_string(),
        unspent_count: summary.unspent_count.to_string(),
        unspent_atoms: summary.unspent_atoms.to_string(),
        spendable_count: summary.spendable_count.to_string(),
        spendable_atoms: summary.spendable_atoms.to_string(),
        local_mempool_output_count: summary.local_mempool_output_count.to_string(),
        local_mempool_output_atoms: summary.local_mempool_output_atoms.to_string(),
    })
}

fn require_no_legacy_key_utxos(
    evidence: &LegacyKeyUtxoEvidenceReport,
) -> Result<(), ExchangeCustodyToolError> {
    decode_hex32(&evidence.active_chain_tip, "active_chain_tip")?;
    parse_canonical_u64(&evidence.next_height, "next_height")?;
    let unspent_count = parse_canonical_u64(&evidence.unspent_count, "unspent_count")?;
    let unspent_atoms = parse_canonical_u64(&evidence.unspent_atoms, "unspent_atoms")?;
    let spendable_count = parse_canonical_u64(&evidence.spendable_count, "spendable_count")?;
    let spendable_atoms = parse_canonical_u64(&evidence.spendable_atoms, "spendable_atoms")?;
    let local_mempool_output_count = parse_canonical_u64(
        &evidence.local_mempool_output_count,
        "local_mempool_output_count",
    )?;
    let local_mempool_output_atoms = parse_canonical_u64(
        &evidence.local_mempool_output_atoms,
        "local_mempool_output_atoms",
    )?;
    if unspent_count != 0
        || unspent_atoms != 0
        || spendable_count != 0
        || spendable_atoms != 0
        || local_mempool_output_count != 0
        || local_mempool_output_atoms != 0
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "legacy key still has active-chain UTXOs or UTXO evidence is invalid",
        ));
    }
    Ok(())
}

fn validate_legacy_key_decommission_evidence(
    node: &mut Node,
    legacy_public_key: [u8; 32],
    evidence: &LegacyKeyDecommissionEvidence,
) -> Result<LegacyKeySweepEvidenceReport, ExchangeCustodyToolError> {
    if evidence.schema != LEGACY_KEY_DECOMMISSION_EVIDENCE_SCHEMA
        || decode_nonzero_hex32(&evidence.legacy_public_key, "legacy_public_key")?
            != legacy_public_key
        || evidence.post_apply_wallet_key_disposition != "offline_quarantine_after_apply"
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "legacy key decommission evidence identity or disposition",
        ));
    }
    let sweep_txid = decode_nonzero_hex32(&evidence.confirmed_sweep_txid, "confirmed_sweep_txid")?;
    let minimum_confirmations = parse_canonical_u64(
        &evidence.minimum_sweep_confirmations,
        "minimum_sweep_confirmations",
    )?;
    if minimum_confirmations < MINIMUM_LEGACY_SWEEP_CONFIRMATIONS {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "minimum_sweep_confirmations is below the compiled conservative software safety floor",
        ));
    }
    decode_nonzero_hex32(
        &evidence.deposit_address_retirement_assertion_digest,
        "deposit_address_retirement_assertion_digest",
    )?;
    decode_nonzero_hex32(
        &evidence.external_mempool_quiescence_assertion_digest,
        "external_mempool_quiescence_assertion_digest",
    )?;
    let sweep = node
        .exchange_custody_confirmed_legacy_sweep(sweep_txid, legacy_public_key)
        .map_err(operation)?
        .ok_or(ExchangeCustodyToolError::InvalidDocument(
            "confirmed sweep transaction is absent from the active chain",
        ))?;
    if sweep.confirmations < minimum_confirmations
        || sweep.legacy_input_count == 0
        || sweep.legacy_output_count != 0
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "sweep transaction depth or legacy input/output shape",
        ));
    }
    Ok(LegacyKeySweepEvidenceReport {
        txid: hex::encode(sweep.txid),
        block_id: hex::encode(sweep.block_id),
        height: sweep.height.to_string(),
        confirmations: sweep.confirmations.to_string(),
        legacy_input_count: sweep.legacy_input_count.to_string(),
        legacy_output_count: sweep.legacy_output_count.to_string(),
    })
}

pub fn plan_external_keyring_finalization(
    node: &mut Node,
    config: &ExternalKeyringFinalizationPlanConfig,
) -> Result<ExternalKeyringFinalizationPlanReport, ExchangeCustodyToolError> {
    let data_dir = require_node_data_dir(node, &config.data_dir)?;
    if canonical_data_dir(&config.controls.data_dir)? != data_dir {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "finalization controls use another data directory",
        ));
    }
    let (store, _policy) = open_v3_store(&config.controls, &data_dir)?;
    let source_journal_anchor = store.require_external_anchor_current().map_err(operation)?;
    let source_keyring =
        resolve_existing_file(&config.controls.keyring_file, "source mixed wallet keyring")?;
    let source_anchor = resolve_existing_file(
        &config.controls.keyring_anchor_file,
        "source mixed wallet keyring anchor",
    )?;
    let source_passphrase = resolve_existing_file(
        &config.controls.keyring_passphrase_file,
        "source mixed wallet keyring passphrase",
    )?;
    let journal_key_file = resolve_existing_file(&config.controls.journal_key_file, "journal key")?;
    let external_journal_anchor_file = resolve_existing_file(
        &config.controls.external_anchor_file,
        "external journal anchor",
    )?;
    let policy_file = resolve_existing_file(&config.controls.policy_file, "withdrawal policy")?;
    let decommission_evidence_file = resolve_existing_file(
        &config.decommission_evidence_file,
        "legacy key decommission evidence",
    )?;
    let keyring_output = resolve_output(&config.keyring_output, "finalized wallet keyring")?;
    let keyring_anchor_output = resolve_output(
        &config.keyring_anchor_output,
        "finalized wallet keyring anchor",
    )?;
    let journal_anchor_output =
        resolve_output(&config.journal_anchor_output, "finalized journal anchor")?;
    let plan_output = resolve_output(&config.plan_output, "external keyring finalization plan")?;
    for path in [
        &source_anchor,
        &source_passphrase,
        &external_journal_anchor_file,
        &policy_file,
        &decommission_evidence_file,
        &keyring_anchor_output,
        &journal_anchor_output,
        &plan_output,
    ] {
        ensure_outside_data_dir(&data_dir, path)?;
    }
    if keyring_output == source_keyring
        || keyring_anchor_output == source_anchor
        || journal_anchor_output == external_journal_anchor_file
        || keyring_output == keyring_anchor_output
        || keyring_output == journal_anchor_output
        || keyring_anchor_output == journal_anchor_output
        || plan_output == keyring_output
        || plan_output == keyring_anchor_output
        || plan_output == journal_anchor_output
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "keyring finalization inputs and outputs overlap",
        ));
    }

    let envelope = load_keyring_envelope_v3(&source_keyring).map_err(operation)?;
    let trusted_anchor = load_keyring_anchor_v3(&data_dir, &source_anchor).map_err(operation)?;
    let passphrase =
        load_keyring_passphrase_v3(&data_dir, &source_passphrase).map_err(operation)?;
    let keyring = WalletKeyring::decode_live(
        &envelope,
        stored_keyring_binding(&data_dir)?,
        &passphrase,
        trusted_anchor,
    )
    .map_err(operation)?;
    let (legacy, external, candidate) =
        finalize_mixed_keyring_external_only(keyring, config.legacy_public_key)?;
    let legacy_utxo_evidence = legacy_key_utxo_evidence(node, legacy.public_key)?;
    require_no_legacy_key_utxos(&legacy_utxo_evidence)?;
    let decommission_evidence_bytes = load_external_control_document_v3(
        &data_dir,
        &decommission_evidence_file,
        MAX_TOOL_DOCUMENT_BYTES,
        "legacy key decommission evidence",
    )
    .map_err(operation)?;
    let decommission_evidence: LegacyKeyDecommissionEvidence =
        serde_json::from_slice(&decommission_evidence_bytes).map_err(|_| {
            ExchangeCustodyToolError::InvalidDocument("legacy key decommission evidence JSON")
        })?;
    let confirmed_sweep =
        validate_legacy_key_decommission_evidence(node, legacy.public_key, &decommission_evidence)?;
    let external_signer_id = match external.storage {
        KeyStorageBinding::External { signer_id } => signer_id,
        _ => unreachable!("external key was validated"),
    };
    let candidate_anchor = candidate.anchor();
    let candidate_keyring_anchor =
        keyring_anchor_v3_from_v1(candidate_anchor, stored_journal_binding(&data_dir)?)
            .map_err(operation)?;
    let journal_candidate = store
        .journal()
        .apply_transition(
            store.journal_key(),
            JournalTransitionV3::RotateKeyring(RotateKeyringV3 {
                expected_anchor: source_journal_anchor,
                new_keyring: candidate_keyring_anchor,
                rotation_decision_id: config.rotation_decision_id,
                approval_digest: config.approval_digest,
            }),
        )
        .map_err(operation)?;
    let candidate_journal_anchor = journal_candidate
        .anchor(store.journal_key())
        .map_err(operation)?;
    let mut document = ExternalKeyringFinalizationPlanDocument {
        schema: KEYRING_EXTERNAL_FINALIZATION_PLAN_SCHEMA.to_owned(),
        data_dir,
        plan_file: plan_output.clone(),
        journal_key_file,
        external_journal_anchor_file,
        policy_file,
        source_keyring_file: source_keyring,
        source_anchor_file: source_anchor,
        source_keyring_passphrase_file: source_passphrase,
        source_keyring_digest: hex::encode(digest(
            KEYRING_ENVELOPE_DIGEST_DOMAIN,
            envelope.as_slice(),
        )),
        source_anchor: keyring_anchor_report(trusted_anchor),
        legacy_key_id: hex::encode(legacy.key_id.0),
        legacy_public_key: hex::encode(legacy.public_key),
        external_key_id: hex::encode(external.key_id.0),
        external_public_key: hex::encode(external.public_key),
        external_signer_id: hex::encode(external_signer_id.0),
        legacy_utxo_evidence: legacy_utxo_evidence.clone(),
        decommission_evidence_file,
        decommission_evidence_digest: hex::encode(digest(
            LEGACY_KEY_DECOMMISSION_EVIDENCE_DIGEST_DOMAIN,
            &decommission_evidence_bytes,
        )),
        decommission_evidence: decommission_evidence.clone(),
        confirmed_sweep: confirmed_sweep.clone(),
        rotation_decision_id: hex::encode(config.rotation_decision_id),
        approval_digest: hex::encode(config.approval_digest),
        source_journal_anchor: journal_anchor_report(source_journal_anchor),
        candidate_anchor: keyring_anchor_report(candidate_anchor),
        candidate_journal_anchor: journal_anchor_report(candidate_journal_anchor),
        keyring_output,
        keyring_anchor_output,
        journal_anchor_output,
        confirmation_digest: hex::encode([0_u8; 32]),
    };
    let confirmation = external_keyring_finalization_confirmation_digest(&document)?;
    document.confirmation_digest = hex::encode(confirmation);
    write_create_new(
        &plan_output,
        &serde_json::to_vec_pretty(&document).map_err(operation)?,
        false,
    )?;
    Ok(ExternalKeyringFinalizationPlanReport {
        status: "planned; local active-chain, sweep-depth, and local-mempool guards passed; retirement and external-mempool records are unverified operator assertions",
        plan_file: plan_output,
        confirmation_digest: hex::encode(confirmation),
        source_anchor: keyring_anchor_report(trusted_anchor),
        candidate_anchor: keyring_anchor_report(candidate_anchor),
        source_journal_anchor: journal_anchor_report(source_journal_anchor),
        candidate_journal_anchor: journal_anchor_report(candidate_journal_anchor),
        legacy_key_id: hex::encode(legacy.key_id.0),
        external_key_id: hex::encode(external.key_id.0),
        external_signer_id: hex::encode(external_signer_id.0),
        legacy_utxo_evidence,
        confirmed_sweep,
        post_apply_wallet_key_disposition: decommission_evidence.post_apply_wallet_key_disposition,
    })
}

pub fn apply_external_keyring_finalization(
    node: &mut Node,
    config: &ExternalKeyringFinalizationApplyConfig,
) -> Result<ExternalKeyringFinalizationApplyReport, ExchangeCustodyToolError> {
    let data_dir = require_node_data_dir(node, &config.data_dir)?;
    let plan_file = resolve_existing_file(&config.plan_file, "external keyring finalization plan")?;
    ensure_outside_data_dir(&data_dir, &plan_file)?;
    let plan: ExternalKeyringFinalizationPlanDocument =
        read_json(&plan_file, "external keyring finalization plan")?;
    validate_external_keyring_finalization_confirmation(
        &plan,
        config.expected_confirmation_digest,
        &data_dir,
        &plan_file,
    )?;

    let selected_journal_key = resolve_existing_file(&config.journal_key_file, "journal key")?;
    let selected_external_anchor =
        resolve_existing_file(&config.external_anchor_file, "external journal anchor")?;
    if selected_journal_key != plan.journal_key_file
        || selected_external_anchor != plan.external_journal_anchor_file
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let controls = V3OfflineControlConfig {
        data_dir: data_dir.clone(),
        journal_key_file: plan.journal_key_file.clone(),
        external_anchor_file: plan.external_journal_anchor_file.clone(),
        policy_file: plan.policy_file.clone(),
        keyring_file: plan.source_keyring_file.clone(),
        keyring_anchor_file: plan.source_anchor_file.clone(),
        keyring_passphrase_file: plan.source_keyring_passphrase_file.clone(),
    };
    let (mut store, _policy) = open_v3_store(&controls, &data_dir)?;
    let source_journal_anchor = store.require_external_anchor_current().map_err(operation)?;
    if journal_anchor_report(source_journal_anchor) != plan.source_journal_anchor {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "source journal changed after keyring finalization planning",
        ));
    }

    let source_keyring =
        resolve_existing_file(&plan.source_keyring_file, "source mixed wallet keyring")?;
    let source_anchor = resolve_existing_file(
        &plan.source_anchor_file,
        "source mixed wallet keyring anchor",
    )?;
    let source_passphrase = resolve_existing_file(
        &plan.source_keyring_passphrase_file,
        "source mixed wallet keyring passphrase",
    )?;
    if source_keyring != plan.source_keyring_file
        || source_anchor != plan.source_anchor_file
        || source_passphrase != plan.source_keyring_passphrase_file
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let envelope = load_keyring_envelope_v3(&source_keyring).map_err(operation)?;
    if digest(KEYRING_ENVELOPE_DIGEST_DOMAIN, envelope.as_slice())
        != decode_hex32(&plan.source_keyring_digest, "source_keyring_digest")?
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "source mixed wallet keyring changed after planning",
        ));
    }
    let trusted_anchor = load_keyring_anchor_v3(&data_dir, &source_anchor).map_err(operation)?;
    if keyring_anchor_report(trusted_anchor) != plan.source_anchor {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "source mixed wallet keyring anchor changed after planning",
        ));
    }
    let passphrase =
        load_keyring_passphrase_v3(&data_dir, &source_passphrase).map_err(operation)?;
    let keyring = WalletKeyring::decode_live(
        &envelope,
        stored_keyring_binding(&data_dir)?,
        &passphrase,
        trusted_anchor,
    )
    .map_err(operation)?;
    let legacy_public_key = decode_nonzero_hex32(&plan.legacy_public_key, "legacy_public_key")?;
    let (legacy, external, candidate) =
        finalize_mixed_keyring_external_only(keyring, legacy_public_key)?;
    let legacy_utxo_evidence = legacy_key_utxo_evidence(node, legacy.public_key)?;
    require_no_legacy_key_utxos(&legacy_utxo_evidence)?;
    if legacy_utxo_evidence != plan.legacy_utxo_evidence {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "active chain changed after keyring finalization planning",
        ));
    }
    let decommission_evidence_file = resolve_existing_file(
        &plan.decommission_evidence_file,
        "legacy key decommission evidence",
    )?;
    if decommission_evidence_file != plan.decommission_evidence_file {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let decommission_evidence_bytes = load_external_control_document_v3(
        &data_dir,
        &decommission_evidence_file,
        MAX_TOOL_DOCUMENT_BYTES,
        "legacy key decommission evidence",
    )
    .map_err(operation)?;
    if digest(
        LEGACY_KEY_DECOMMISSION_EVIDENCE_DIGEST_DOMAIN,
        &decommission_evidence_bytes,
    ) != decode_hex32(
        &plan.decommission_evidence_digest,
        "decommission_evidence_digest",
    )? {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "legacy key decommission evidence changed after planning",
        ));
    }
    let decommission_evidence: LegacyKeyDecommissionEvidence =
        serde_json::from_slice(&decommission_evidence_bytes).map_err(|_| {
            ExchangeCustodyToolError::InvalidDocument("legacy key decommission evidence JSON")
        })?;
    if decommission_evidence != plan.decommission_evidence {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let confirmed_sweep =
        validate_legacy_key_decommission_evidence(node, legacy.public_key, &decommission_evidence)?;
    if confirmed_sweep != plan.confirmed_sweep {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "confirmed legacy sweep changed after finalization planning",
        ));
    }
    let external_signer_id = match external.storage {
        KeyStorageBinding::External { signer_id } => signer_id,
        _ => unreachable!("external key was validated"),
    };
    let candidate_anchor = candidate.anchor();
    let candidate_keyring_anchor =
        keyring_anchor_v3_from_v1(candidate_anchor, stored_journal_binding(&data_dir)?)
            .map_err(operation)?;
    let rotation_decision_id =
        decode_nonzero_hex32(&plan.rotation_decision_id, "rotation_decision_id")?;
    let approval_digest = decode_nonzero_hex32(&plan.approval_digest, "approval_digest")?;
    let journal_candidate = store
        .journal()
        .apply_transition(
            store.journal_key(),
            JournalTransitionV3::RotateKeyring(RotateKeyringV3 {
                expected_anchor: source_journal_anchor,
                new_keyring: candidate_keyring_anchor,
                rotation_decision_id,
                approval_digest,
            }),
        )
        .map_err(operation)?;
    let candidate_journal_anchor = journal_candidate
        .anchor(store.journal_key())
        .map_err(operation)?;
    if hex::encode(legacy.key_id.0) != plan.legacy_key_id
        || hex::encode(external.key_id.0) != plan.external_key_id
        || hex::encode(external.public_key) != plan.external_public_key
        || hex::encode(external_signer_id.0) != plan.external_signer_id
        || keyring_anchor_report(candidate_anchor) != plan.candidate_anchor
        || journal_anchor_report(candidate_journal_anchor) != plan.candidate_journal_anchor
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }

    let keyring_output =
        resolve_output_or_existing_file(&plan.keyring_output, "finalized wallet keyring")?;
    let keyring_anchor_output = resolve_output_or_existing_file(
        &plan.keyring_anchor_output,
        "finalized wallet keyring anchor",
    )?;
    let journal_anchor_output =
        resolve_output_or_existing_file(&plan.journal_anchor_output, "finalized journal anchor")?;
    if keyring_output != plan.keyring_output
        || keyring_anchor_output != plan.keyring_anchor_output
        || journal_anchor_output != plan.journal_anchor_output
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    ensure_outside_data_dir(&data_dir, &keyring_anchor_output)?;
    ensure_outside_data_dir(&data_dir, &journal_anchor_output)?;
    let keyring_anchor_bytes = candidate_anchor.encode().map_err(operation)?;
    let journal_anchor_bytes = encode_journal_anchor(candidate_journal_anchor)?;
    if keyring_anchor_output.exists() {
        create_or_verify_exact(&keyring_anchor_output, &keyring_anchor_bytes, false)?;
    }
    if journal_anchor_output.exists() {
        create_or_verify_exact(&journal_anchor_output, &journal_anchor_bytes, false)?;
    }
    if keyring_output.exists() {
        let existing = load_keyring_envelope_v3(&keyring_output).map_err(operation)?;
        WalletKeyring::decode_live(
            &existing,
            stored_keyring_binding(&data_dir)?,
            &passphrase,
            candidate_anchor,
        )
        .map_err(operation)?;
    } else {
        let encoded = candidate.encode_live(&passphrase).map_err(operation)?;
        write_create_new(&keyring_output, &encoded, true)?;
    }
    create_or_verify_exact(&keyring_anchor_output, &keyring_anchor_bytes, false)?;
    create_or_verify_exact(&journal_anchor_output, &journal_anchor_bytes, false)?;
    let committed = store
        .commit_candidate(source_journal_anchor, journal_candidate)
        .map_err(operation)?;
    if committed != candidate_journal_anchor {
        return Err(ExchangeCustodyToolError::Operation(
            "committed keyring rotation anchor differs from its confirmed candidate".to_owned(),
        ));
    }
    Ok(ExternalKeyringFinalizationApplyReport {
        status: "external_only_runtime_candidate; legacy secret removed from candidate; install both proposed anchors and complete offline wallet.key quarantine; retirement and external-mempool records remain operator assertions, not consensus guarantees",
        keyring_file: keyring_output,
        anchor_file: keyring_anchor_output,
        journal_anchor_file: journal_anchor_output,
        anchor: keyring_anchor_report(candidate_anchor),
        journal_anchor: journal_anchor_report(candidate_journal_anchor),
        legacy_key_id: hex::encode(legacy.key_id.0),
        external_key_id: hex::encode(external.key_id.0),
        external_signer_id: hex::encode(external_signer_id.0),
        legacy_utxo_evidence,
        confirmed_sweep,
        post_apply_wallet_key_disposition: decommission_evidence.post_apply_wallet_key_disposition,
    })
}

#[derive(Debug, Clone)]
pub struct V3MigrationPlanConfig {
    pub data_dir: PathBuf,
    pub journal_key_file: PathBuf,
    pub evidence_file: PathBuf,
    pub policy_file: PathBuf,
    pub keyring_file: PathBuf,
    pub keyring_anchor_file: PathBuf,
    pub keyring_passphrase_file: PathBuf,
    pub validated_snapshot_output: PathBuf,
    pub v3_anchor_output: PathBuf,
    pub plan_output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct V3MigrationApprovalPayloadConfig {
    pub data_dir: PathBuf,
    pub policy_file: PathBuf,
    pub keyring_file: PathBuf,
    pub keyring_anchor_file: PathBuf,
    pub keyring_passphrase_file: PathBuf,
    pub request_id: String,
    pub decision_id: [u8; 32],
    pub authorized_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub output: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct V3MigrationApprovalPayloadReport {
    pub status: &'static str,
    pub output_file: PathBuf,
    pub request_id: String,
    pub source_anchor: JournalAnchorReport,
    pub policy_id: String,
    pub signing_digest: String,
}

#[derive(Debug, Clone)]
pub struct V3MigrationApplyConfig {
    pub data_dir: PathBuf,
    pub plan_file: PathBuf,
    pub expected_plan_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize)]
pub struct V3MigrationPlanReport {
    pub status: &'static str,
    pub plan_file: PathBuf,
    pub validated_snapshot_file: PathBuf,
    pub plan_digest: String,
    pub migration_input_digest: String,
    pub initial_anchor: JournalAnchorReport,
    pub released_record_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct V3MigrationApplyReport {
    pub status: &'static str,
    pub migration_id: String,
    pub initial_anchor: JournalAnchorReport,
    pub external_anchor_file: PathBuf,
    pub backup_files: Vec<PathBuf>,
    pub resumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalAnchorReport {
    pub key_id: String,
    pub journal_instance_id: String,
    pub generation: String,
    pub commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3MigrationEvidenceDocument {
    pub schema: String,
    pub migration_id: String,
    pub migration_decision_id: String,
    pub migration_approval_digest: String,
    pub new_journal_instance_id: String,
    pub initial_policy_time_watermark_unix_seconds: String,
    pub released_records: Vec<V3MigrationReleasedEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3MigrationReleasedEvidence {
    pub signed_approval: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationPlanDocument {
    schema: String,
    plan_digest: String,
    plan_file: PathBuf,
    data_dir: PathBuf,
    journal_key_file: PathBuf,
    journal_key_id: String,
    evidence_file: PathBuf,
    evidence_digest: String,
    policy_file: PathBuf,
    keyring_file: PathBuf,
    keyring_anchor_file: PathBuf,
    keyring_passphrase_file: PathBuf,
    validated_snapshot_file: PathBuf,
    v3_anchor_output: PathBuf,
    backup_files: Vec<PathBuf>,
    source_snapshot_digest: String,
    source_anchor: JournalAnchorReport,
    policy_id: String,
    keyring_anchor: KeyringAnchorReport,
    migration_input_digest: String,
    initial_anchor: JournalAnchorReport,
    released_record_count: usize,
}

fn migration_plan_digest(
    plan: &MigrationPlanDocument,
) -> Result<[u8; 32], ExchangeCustodyToolError> {
    let mut canonical = plan.clone();
    canonical.plan_digest = hex::encode([0_u8; 32]);
    let bytes = serde_json::to_vec(&canonical).map_err(operation)?;
    Ok(digest(MIGRATION_PLAN_DIGEST_DOMAIN, &bytes))
}

/// This is the first validation performed after parsing the CLI-selected plan
/// file. It is deliberately pure so no path supplied by an unconfirmed plan
/// can be resolved, opened, created, or replaced before operator confirmation.
fn validate_migration_plan_confirmation(
    plan: &MigrationPlanDocument,
    expected_plan_digest: [u8; 32],
    expected_data_dir: &Path,
    expected_plan_file: &Path,
) -> Result<[u8; 32], ExchangeCustodyToolError> {
    let calculated = migration_plan_digest(plan)?;
    let embedded = decode_hex32(&plan.plan_digest, "plan_digest")
        .map_err(|_| ExchangeCustodyToolError::ConfirmationMismatch)?;
    if plan.schema != MIGRATION_PLAN_SCHEMA
        || plan.data_dir != expected_data_dir
        || plan.plan_file != expected_plan_file
        || embedded != calculated
        || expected_plan_digest != calculated
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    Ok(calculated)
}

/// Emits the canonical migration-scoped approval payload for one already
/// Released, authenticated v2 withdrawal. The command runs before cutover;
/// it never signs, mutates the v2 journal, or creates v3 state.
pub fn write_v3_migration_approval_payload(
    node: &Node,
    config: &V3MigrationApprovalPayloadConfig,
) -> Result<V3MigrationApprovalPayloadReport, ExchangeCustodyToolError> {
    let data_dir = require_node_data_dir(node, &config.data_dir)?;
    let export =
        ExchangeWithdrawalJournal::export_validated_v2_for_v3_migration(node).map_err(operation)?;
    let binding = journal_binding_from_node(node);
    let controls = load_migration_controls(
        &data_dir,
        binding,
        &config.policy_file,
        &config.keyring_file,
        &config.keyring_anchor_file,
        &config.keyring_passphrase_file,
        Some(export.wallet_destination),
    )?;
    let approval = build_v3_migration_approval_payload(
        &export,
        &controls.policy,
        &config.request_id,
        config.decision_id,
        config.authorized_at_unix_seconds,
        config.expires_at_unix_seconds,
    )?;
    let source_anchor = journal_anchor_v3_from_v2(export.source_anchor);
    let canonical = approval.canonical_document();
    let canonical_bytes = serde_json::to_vec(&canonical).map_err(operation)?;
    if WithdrawalApproval::parse(&canonical_bytes).map_err(operation)? != approval {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "canonical migration approval payload",
        ));
    }
    let output = resolve_output(&config.output, "migration approval payload output")?;
    ensure_outside_data_dir(&data_dir, &output)?;
    write_create_new(
        &output,
        &serde_json::to_vec_pretty(&canonical).map_err(operation)?,
        false,
    )?;
    let signing_digest = approval.signing_digest();
    Ok(V3MigrationApprovalPayloadReport {
        status: "unsigned_payload_created; add strictly sorted threshold signatures and embed the exact signed JSON in migration evidence v2",
        output_file: output,
        request_id: approval.request_id,
        source_anchor: journal_anchor_report(source_anchor),
        policy_id: hex::encode(approval.policy_id),
        signing_digest: hex::encode(signing_digest),
    })
}

fn build_v3_migration_approval_payload(
    export: &ValidatedV2MigrationExport,
    policy: &WithdrawalPolicy,
    request_id: &str,
    decision_id: [u8; 32],
    authorized_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> Result<WithdrawalApproval, ExchangeCustodyToolError> {
    let source = export
        .released_records
        .iter()
        .find(|record| record.request.request_id == request_id)
        .ok_or(ExchangeCustodyToolError::InvalidDocument(
            "migration approval request is not a Released v2 record",
        ))?;
    if decision_id == [0; 32]
        || authorized_at_unix_seconds == 0
        || authorized_at_unix_seconds >= expires_at_unix_seconds
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "migration approval decision or validity interval",
        ));
    }
    policy
        .check_static_limits(source.request.amount_atoms, source.request.fee_atoms)
        .map_err(operation)?;
    let source_anchor = journal_anchor_v3_from_v2(export.source_anchor);
    Ok(WithdrawalApproval {
        action: WithdrawalAction::Release,
        decision_id,
        policy_id: policy.policy_id(),
        action_anchor: ApprovalAnchor {
            key_id: source_anchor.key_id,
            journal_instance_id: source_anchor.journal_instance_id,
            generation: source_anchor.generation,
            commitment: source_anchor.commitment,
        },
        request_id: source.request.request_id.clone(),
        request_digest: source.request_digest,
        transaction_signing_digest: source.signing_digest,
        authorized_at_unix_seconds,
        expires_at_unix_seconds,
        signatures: Vec::new(),
    })
}

pub fn plan_v3_migration(
    node: &Node,
    config: &V3MigrationPlanConfig,
) -> Result<V3MigrationPlanReport, ExchangeCustodyToolError> {
    let data_dir = require_node_data_dir(node, &config.data_dir)?;
    let evidence_path = resolve_existing_file(&config.evidence_file, "migration evidence")?;
    ensure_outside_data_dir(&data_dir, &evidence_path)?;
    let evidence_bytes = read_bounded(
        &evidence_path,
        MAX_TOOL_DOCUMENT_BYTES,
        "migration evidence",
    )?;
    let evidence: V3MigrationEvidenceDocument = serde_json::from_slice(&evidence_bytes)
        .map_err(|_| ExchangeCustodyToolError::InvalidDocument("migration evidence JSON"))?;
    validate_migration_cutover_horizon(&evidence, current_unix_seconds()?)?;
    let export =
        ExchangeWithdrawalJournal::export_validated_v2_for_v3_migration(node).map_err(operation)?;
    let controls = load_migration_controls(
        &data_dir,
        journal_binding_from_node(node),
        &config.policy_file,
        &config.keyring_file,
        &config.keyring_anchor_file,
        &config.keyring_passphrase_file,
        Some(export.wallet_destination),
    )?;
    let input = build_migration_input(&export, &evidence, &controls)?;
    let journal_key_path = resolve_existing_file(&config.journal_key_file, "journal key")?;
    let journal_key = load_journal_key_v3(&journal_key_path).map_err(operation)?;
    let output = migrate_validated_v2(input, journal_key.bytes()).map_err(operation)?;

    let snapshot_path = resolve_output(
        &config.validated_snapshot_output,
        "validated v2 snapshot output",
    )?;
    let plan_path = resolve_output(&config.plan_output, "v3 migration plan")?;
    let anchor_path = resolve_output(&config.v3_anchor_output, "v3 external anchor output")?;
    for path in [&snapshot_path, &plan_path, &anchor_path] {
        ensure_outside_data_dir(&data_dir, path)?;
    }
    let backup_files = migration_backup_paths(&data_dir, output.receipt.migration_id);
    let mut document = MigrationPlanDocument {
        schema: MIGRATION_PLAN_SCHEMA.to_owned(),
        plan_digest: hex::encode([0_u8; 32]),
        plan_file: plan_path.clone(),
        data_dir,
        journal_key_file: journal_key_path,
        journal_key_id: hex::encode(output.journal.journal_key_id),
        evidence_file: evidence_path,
        evidence_digest: hex::encode(digest(EVIDENCE_DIGEST_DOMAIN, &evidence_bytes)),
        policy_file: resolve_existing_file(&config.policy_file, "withdrawal policy")?,
        keyring_file: resolve_existing_file(&config.keyring_file, "wallet keyring")?,
        keyring_anchor_file: resolve_existing_file(
            &config.keyring_anchor_file,
            "wallet keyring anchor",
        )?,
        keyring_passphrase_file: resolve_existing_file(
            &config.keyring_passphrase_file,
            "wallet keyring passphrase",
        )?,
        validated_snapshot_file: snapshot_path.clone(),
        v3_anchor_output: anchor_path,
        backup_files,
        source_snapshot_digest: hex::encode(output.receipt.source_snapshot_digest),
        source_anchor: journal_anchor_report(output.receipt.source_anchor),
        policy_id: hex::encode(output.journal.policy_id),
        keyring_anchor: keyring_anchor_report(controls.keyring.anchor()),
        migration_input_digest: hex::encode(output.receipt.migration_input_digest),
        initial_anchor: journal_anchor_report(output.initial_anchor),
        released_record_count: export.released_records.len(),
    };
    let plan_digest = migration_plan_digest(&document)?;
    document.plan_digest = hex::encode(plan_digest);
    write_create_new(&snapshot_path, &export.exact_snapshot_bytes, false)?;
    write_create_new(
        &plan_path,
        &serde_json::to_vec_pretty(&document).map_err(operation)?,
        false,
    )?;
    Ok(V3MigrationPlanReport {
        status: "planned",
        plan_file: plan_path,
        validated_snapshot_file: snapshot_path,
        plan_digest: hex::encode(plan_digest),
        migration_input_digest: hex::encode(output.receipt.migration_input_digest),
        initial_anchor: journal_anchor_report(output.initial_anchor),
        released_record_count: export.released_records.len(),
    })
}

pub fn apply_v3_migration(
    node: Node,
    config: &V3MigrationApplyConfig,
) -> Result<V3MigrationApplyReport, ExchangeCustodyToolError> {
    let data_dir = require_node_data_dir(&node, &config.data_dir)?;
    let plan_path = resolve_existing_file(&config.plan_file, "v3 migration plan")?;
    ensure_outside_data_dir(&data_dir, &plan_path)?;
    let plan: MigrationPlanDocument = read_json(&plan_path, "v3 migration plan")?;
    validate_migration_plan_confirmation(
        &plan,
        config.expected_plan_digest,
        &data_dir,
        &plan_path,
    )?;
    let planned_migration_input_digest =
        decode_hex32(&plan.migration_input_digest, "migration_input_digest")?;
    let planned_journal_key_id = decode_hex32(&plan.journal_key_id, "journal_key_id")?;
    let planned_source_snapshot_digest =
        decode_hex32(&plan.source_snapshot_digest, "source_snapshot_digest")?;
    let planned_source_anchor = withdrawal_anchor_from_report(&plan.source_anchor)?;
    let evidence_path = resolve_existing_file(&plan.evidence_file, "migration evidence")?;
    if evidence_path != plan.evidence_file {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let evidence_bytes = read_bounded(
        &evidence_path,
        MAX_TOOL_DOCUMENT_BYTES,
        "migration evidence",
    )?;
    if digest(EVIDENCE_DIGEST_DOMAIN, &evidence_bytes)
        != decode_hex32(&plan.evidence_digest, "evidence_digest")?
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "migration evidence changed after planning",
        ));
    }
    let evidence: V3MigrationEvidenceDocument = serde_json::from_slice(&evidence_bytes)
        .map_err(|_| ExchangeCustodyToolError::InvalidDocument("migration evidence JSON"))?;
    validate_migration_cutover_horizon(&evidence, current_unix_seconds()?)?;
    let snapshot_path =
        resolve_existing_file(&plan.validated_snapshot_file, "validated v2 snapshot")?;
    if snapshot_path != plan.validated_snapshot_file {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let snapshot_bytes = read_bounded(
        &snapshot_path,
        MAX_TOOL_DOCUMENT_BYTES * 16,
        "validated v2 snapshot",
    )?;
    if validated_v2_snapshot_digest(&snapshot_bytes) != planned_source_snapshot_digest {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "validated v2 snapshot changed after planning",
        ));
    }
    let export = migration_source_export_for_apply(
        &node,
        &data_dir,
        &snapshot_bytes,
        planned_source_anchor,
    )?;
    let controls = load_migration_controls(
        &data_dir,
        journal_binding_from_node(&node),
        &plan.policy_file,
        &plan.keyring_file,
        &plan.keyring_anchor_file,
        &plan.keyring_passphrase_file,
        Some(export.wallet_destination),
    )?;
    let input = build_migration_input(&export, &evidence, &controls)?;
    let migration = MigrationPlanV3::build(
        MigrationPlanV3Config {
            data_dir: data_dir.clone(),
            journal_key_file: plan.journal_key_file.clone(),
            validated_v2_snapshot_file: snapshot_path,
        },
        input,
    )
    .map_err(operation)?;
    if migration.receipt().migration_input_digest != planned_migration_input_digest
        || journal_anchor_report(migration.initial_anchor()) != plan.initial_anchor
        || migration.initial_anchor().key_id != planned_journal_key_id
        || migration_backup_paths(&data_dir, migration.receipt().migration_id) != plan.backup_files
    {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let anchor_output =
        resolve_output_or_existing_file(&plan.v3_anchor_output, "v3 external anchor output")?;
    if anchor_output != plan.v3_anchor_output {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    ensure_outside_data_dir(&data_dir, &anchor_output)?;
    // All potentially slow validation and decryption work is complete. Check
    // the locally observed cutover horizon again before publishing any v3
    // control artifact, then once more immediately before slot activation.
    validate_migration_cutover_horizon(&evidence, current_unix_seconds()?)?;
    // Pin the exact planned initial state before activating it. This makes the
    // final activation commit point recoverable even if the process exits
    // before it can print the report; an exact pre-existing file is accepted
    // only for resuming this same confirmed plan.
    create_or_verify_exact(
        &anchor_output,
        &encode_journal_anchor(migration.initial_anchor())?,
        false,
    )?;
    validate_migration_cutover_horizon(&evidence, current_unix_seconds()?)?;
    // Keep the validated v2 Node (and therefore node.lock) alive through the
    // entire cutover. Releasing it here would let a second v2 process mutate
    // the shared slots after validation but before v3 activation.
    let applied = migration.apply().map_err(operation)?;
    if applied.initial_anchor != migration.initial_anchor() {
        return Err(ExchangeCustodyToolError::Operation(
            "applied migration anchor differs from its confirmed plan".to_owned(),
        ));
    }
    Ok(V3MigrationApplyReport {
        status: "applied; pin external_anchor_file independently before restart",
        migration_id: hex::encode(applied.migration_id),
        initial_anchor: journal_anchor_report(applied.initial_anchor),
        external_anchor_file: anchor_output,
        backup_files: applied.backup_files,
        resumed: applied.resumed,
    })
}

#[derive(Debug, Clone)]
pub struct V3OfflineControlConfig {
    pub data_dir: PathBuf,
    pub journal_key_file: PathBuf,
    pub external_anchor_file: PathBuf,
    pub policy_file: PathBuf,
    pub keyring_file: PathBuf,
    pub keyring_anchor_file: PathBuf,
    pub keyring_passphrase_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CanceledArchivePlanConfig {
    pub controls: V3OfflineControlConfig,
    pub request_ids: Vec<String>,
    pub archive_output: PathBuf,
    pub manifest_pin_output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CanceledArchiveApplyConfig {
    pub controls: V3OfflineControlConfig,
    pub archive_file: PathBuf,
    pub manifest_pin_file: PathBuf,
    pub expected_archive_id: [u8; 32],
    /// Create-new proposed replacement for the independently managed anchor.
    pub proposed_anchor_output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ArchiveRestoreVerifyConfig {
    pub data_dir: PathBuf,
    pub journal_key_file: PathBuf,
    pub archive_file: PathBuf,
    pub manifest_pin_file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct CanceledArchivePlanReport {
    pub status: &'static str,
    pub archive_file: PathBuf,
    pub manifest_pin_file: PathBuf,
    pub confirmation_archive_id: String,
    pub source_anchor: JournalAnchorReport,
    pub record_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CanceledArchiveApplyReport {
    pub status: &'static str,
    pub archive_id: String,
    pub prior_anchor: JournalAnchorReport,
    pub compacted_anchor: JournalAnchorReport,
    pub proposed_anchor_file: PathBuf,
    pub compacted_record_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveRestoreVerifyReport {
    pub status: &'static str,
    pub archive_id: String,
    pub source_anchor: JournalAnchorReport,
    pub policy_id: String,
    pub record_count: u64,
}

/// Creates an authenticated archive and matching manifest-pin artifact but does
/// not prune the live journal. The operator must transfer the pin to an
/// independently controlled path before apply. Request IDs are normalized into
/// their canonical keyed-tag order before the archive is built.
pub fn plan_canceled_archive(
    config: &CanceledArchivePlanConfig,
) -> Result<CanceledArchivePlanReport, ExchangeCustodyToolError> {
    let data_dir = canonical_data_dir(&config.controls.data_dir)?;
    let _offline = OfflineNodeLock::acquire(&data_dir)?;
    let (store, _policy) = open_v3_store(&config.controls, &data_dir)?;
    let source = store.require_external_anchor_current().map_err(operation)?;
    let mut request_ids = config.request_ids.clone();
    request_ids.sort_unstable_by_key(|request_id| {
        archive_request_id_tag(store.journal_key(), request_id).unwrap_or([0; 32])
    });
    // Invalid identifiers are rejected here rather than being silently grouped
    // under the sorting fallback above.
    for request_id in &request_ids {
        archive_request_id_tag(store.journal_key(), request_id).map_err(operation)?;
    }
    let archive =
        build_canceled_archive(store.journal(), store.journal_key(), source, &request_ids)
            .map_err(operation)?;
    let archive_bytes = archive
        .encode_authenticated(store.journal_key())
        .map_err(operation)?;
    let pin = archive.manifest_pin();
    let pin_bytes = pin.encode().map_err(operation)?;
    let archive_path = resolve_output_or_existing_file(&config.archive_output, "canceled archive")?;
    let pin_path =
        resolve_output_or_existing_file(&config.manifest_pin_output, "archive manifest pin")?;
    ensure_outside_data_dir(&data_dir, &archive_path)?;
    ensure_outside_data_dir(&data_dir, &pin_path)?;
    create_or_verify_exact(&archive_path, &archive_bytes, false)?;
    create_or_verify_exact(&pin_path, &pin_bytes, false)?;
    Ok(CanceledArchivePlanReport {
        status: "archive_and_manifest_created; transfer_manifest_pin_to_independent_control_before_apply; journal_not_compacted",
        archive_file: archive_path,
        manifest_pin_file: pin_path,
        confirmation_archive_id: hex::encode(pin.manifest.archive_id),
        source_anchor: journal_anchor_report(source),
        record_count: pin.manifest.record_count,
    })
}

/// Reauthenticates an exact archive and independent manifest pin against the
/// still-current journal, then commits one atomic compaction candidate. The
/// configured external anchor is never overwritten; a create-new proposed
/// successor is emitted for the operator to pin independently.
pub fn apply_canceled_archive_compaction(
    config: &CanceledArchiveApplyConfig,
) -> Result<CanceledArchiveApplyReport, ExchangeCustodyToolError> {
    let data_dir = canonical_data_dir(&config.controls.data_dir)?;
    let _offline = OfflineNodeLock::acquire(&data_dir)?;
    let (mut store, _policy) = open_v3_store(&config.controls, &data_dir)?;
    let source = store.require_external_anchor_current().map_err(operation)?;
    let archive_path = resolve_existing_file(&config.archive_file, "canceled archive")?;
    ensure_outside_data_dir(&data_dir, &archive_path)?;
    let archive_bytes = read_bounded(
        &archive_path,
        crate::exchange_withdrawal_v3::MAX_V3_SNAPSHOT_BYTES,
        "canceled archive",
    )?;
    let pin_bytes = load_external_control_document_v3(
        &data_dir,
        &config.manifest_pin_file,
        MAX_TOOL_DOCUMENT_BYTES,
        "archive manifest pin",
    )
    .map_err(operation)?;
    let pin = WithdrawalArchiveManifestPinV3::parse(&pin_bytes).map_err(operation)?;
    if pin.manifest.archive_id != config.expected_archive_id {
        return Err(ExchangeCustodyToolError::ConfirmationMismatch);
    }
    let pin_source = journal_anchor_from_archive_source(pin.manifest.source);
    if pin_source != source {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "archive pin does not bind the current external anchor",
        ));
    }
    let archive = WithdrawalArchiveEnvelopeV3::decode_authenticated(
        &archive_bytes,
        store.journal_key(),
        source,
    )
    .map_err(operation)?;
    if archive.manifest != pin.manifest {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "archive and independent manifest pin differ",
        ));
    }
    let records = archive
        .verify_source_membership_and_prepare_prune(store.journal(), store.journal_key(), source)
        .map_err(operation)?;
    let candidate = store
        .journal()
        .apply_transition(
            store.journal_key(),
            JournalTransitionV3::Compact(CompactTerminalRecordsV3 {
                expected_anchor: source,
                archive_source_anchor: source,
                archive_id: pin.manifest.archive_id,
                records,
            }),
        )
        .map_err(operation)?;
    let compacted = candidate.anchor(store.journal_key()).map_err(operation)?;
    let proposed_path = resolve_output_or_existing_file(
        &config.proposed_anchor_output,
        "proposed compacted external anchor",
    )?;
    ensure_outside_data_dir(&data_dir, &proposed_path)?;
    create_or_verify_exact(&proposed_path, &encode_journal_anchor(compacted)?, false)?;
    let committed = store
        .commit_candidate(source, candidate)
        .map_err(operation)?;
    if committed != compacted {
        return Err(ExchangeCustodyToolError::Operation(
            "committed compaction anchor differs from candidate".to_owned(),
        ));
    }
    Ok(CanceledArchiveApplyReport {
        status: "journal_compacted; pin proposed_anchor_file independently before restart",
        archive_id: hex::encode(pin.manifest.archive_id),
        prior_anchor: journal_anchor_report(source),
        compacted_anchor: journal_anchor_report(compacted),
        proposed_anchor_file: proposed_path,
        compacted_record_count: archive.records().len(),
    })
}

/// Authenticates an archive and exact external pin without restoring or
/// overwriting any journal file.
pub fn verify_archive_restore_offline(
    config: &ArchiveRestoreVerifyConfig,
) -> Result<ArchiveRestoreVerifyReport, ExchangeCustodyToolError> {
    let data_dir = canonical_data_dir(&config.data_dir)?;
    let _offline = OfflineNodeLock::acquire(&data_dir)?;
    let archive_path = resolve_existing_file(&config.archive_file, "withdrawal archive")?;
    ensure_outside_data_dir(&data_dir, &archive_path)?;
    let key_path = resolve_existing_file(&config.journal_key_file, "journal key")?;
    let key = load_journal_key_v3(&key_path).map_err(operation)?;
    let archive = read_bounded(
        &archive_path,
        crate::exchange_withdrawal_v3::MAX_V3_SNAPSHOT_BYTES,
        "withdrawal archive",
    )?;
    let pin = load_external_control_document_v3(
        &data_dir,
        &config.manifest_pin_file,
        MAX_TOOL_DOCUMENT_BYTES,
        "archive manifest pin",
    )
    .map_err(operation)?;
    let verified = verify_archive_for_restore(&archive, key.bytes(), &pin).map_err(operation)?;
    Ok(ArchiveRestoreVerifyReport {
        status: "verified_only; no journal files were written",
        archive_id: hex::encode(verified.manifest.archive_id),
        source_anchor: journal_anchor_report(journal_anchor_from_archive_source(
            verified.manifest.source,
        )),
        policy_id: hex::encode(verified.manifest.source.policy_id),
        record_count: verified.manifest.record_count,
    })
}

struct LoadedMigrationControls {
    binding: JournalBindingV3,
    policy: WithdrawalPolicy,
    keyring: WalletKeyring,
}

fn load_migration_controls(
    data_dir: &Path,
    binding: JournalBindingV3,
    policy_file: &Path,
    keyring_file: &Path,
    keyring_anchor_file: &Path,
    keyring_passphrase_file: &Path,
    legacy_wallet_destination: Option<[u8; 32]>,
) -> Result<LoadedMigrationControls, ExchangeCustodyToolError> {
    let anchor = load_keyring_anchor_v3(data_dir, keyring_anchor_file).map_err(operation)?;
    let passphrase_path = resolve_existing_file(keyring_passphrase_file, "keyring passphrase")?;
    ensure_outside_data_dir(data_dir, &passphrase_path)?;
    let passphrase = load_keyring_passphrase_v3(data_dir, &passphrase_path).map_err(operation)?;
    let envelope = load_keyring_envelope_v3(keyring_file).map_err(operation)?;
    let keyring = WalletKeyring::decode_live(
        &envelope,
        keyring_binding_from_journal(binding),
        &passphrase,
        anchor,
    )
    .map_err(operation)?;
    let active_change_destination = keyring.active_change_key().public_key;
    let policy_bytes = load_policy_document_v3(data_dir, policy_file).map_err(operation)?;
    let policy = WithdrawalPolicy::parse(
        &policy_bytes,
        WithdrawalPolicyBinding {
            network_id: binding.network_id,
            consensus_fingerprint: binding.consensus_fingerprint,
            genesis_hash: binding.genesis,
            wallet_destination: active_change_destination,
        },
    )
    .map_err(operation)?;
    if let Some(legacy_wallet_destination) = legacy_wallet_destination {
        let expected_key_id = wallet_key_id(&legacy_wallet_destination);
        let key = keyring
            .key(expected_key_id)
            .ok_or(ExchangeCustodyToolError::InvalidDocument(
                "keyring does not contain the legacy wallet public key",
            ))?;
        if key.public_key != legacy_wallet_destination
            || key.lifecycle == KeyLifecycle::Disabled
            || key.storage != KeyStorageBinding::Local
        {
            return Err(ExchangeCustodyToolError::InvalidDocument(
                "legacy wallet key is not locally signable in the supplied keyring",
            ));
        }
    }
    Ok(LoadedMigrationControls {
        binding,
        policy,
        keyring,
    })
}

fn current_unix_seconds() -> Result<u64, ExchangeCustodyToolError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(operation)
}

fn validate_migration_cutover_horizon(
    evidence: &V3MigrationEvidenceDocument,
    now_unix_seconds: u64,
) -> Result<u64, ExchangeCustodyToolError> {
    let watermark = parse_canonical_u64(
        &evidence.initial_policy_time_watermark_unix_seconds,
        "initial_policy_time_watermark_unix_seconds",
    )?;
    if watermark < now_unix_seconds
        || watermark.saturating_sub(now_unix_seconds) > MIGRATION_CUTOVER_MAX_HORIZON_SECONDS
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "migration policy watermark must be between current time and 15 minutes ahead",
        ));
    }
    Ok(watermark)
}

fn build_migration_input(
    export: &ValidatedV2MigrationExport,
    evidence: &V3MigrationEvidenceDocument,
    controls: &LoadedMigrationControls,
) -> Result<ValidatedV2MigrationInputV3, ExchangeCustodyToolError> {
    if evidence.schema != V3_MIGRATION_EVIDENCE_SCHEMA {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "migration evidence schema",
        ));
    }
    let migration_id = decode_nonzero_hex32(&evidence.migration_id, "migration_id")?;
    let migration_decision_id =
        decode_nonzero_hex32(&evidence.migration_decision_id, "migration_decision_id")?;
    let migration_approval_digest = decode_nonzero_hex32(
        &evidence.migration_approval_digest,
        "migration_approval_digest",
    )?;
    let new_journal_instance_id =
        decode_nonzero_hex32(&evidence.new_journal_instance_id, "new_journal_instance_id")?;
    let watermark = parse_canonical_u64(
        &evidence.initial_policy_time_watermark_unix_seconds,
        "initial_policy_time_watermark_unix_seconds",
    )?;
    if watermark == 0 || evidence.released_records.len() != export.released_records.len() {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "migration evidence record count or watermark",
        ));
    }
    let source_anchor = journal_anchor_v3_from_v2(export.source_anchor);
    if new_journal_instance_id == source_anchor.journal_instance_id {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "v3 journal instance id must be fresh",
        ));
    }
    let key = controls
        .keyring
        .key(wallet_key_id(&export.wallet_destination))
        .ok_or(ExchangeCustodyToolError::InvalidDocument(
            "legacy wallet key missing from keyring",
        ))?;
    if key.public_key != export.wallet_destination
        || key.lifecycle == KeyLifecycle::Disabled
        || key.storage != KeyStorageBinding::Local
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "legacy wallet key is not locally signable in the supplied keyring",
        ));
    }
    let signer_id = local_signer_profile(&controls.keyring)
        .map_err(operation)?
        .signer_id
        .0;
    let policy_id = controls.policy.policy_id();
    let mut evidence_by_request = HashMap::with_capacity(evidence.released_records.len());
    let mut decision_ids = HashSet::with_capacity(evidence.released_records.len());
    let mut approval_digests = HashSet::with_capacity(evidence.released_records.len());
    for record in &evidence.released_records {
        let approval_bytes = serde_json::to_vec(&record.signed_approval).map_err(operation)?;
        let approval = WithdrawalApproval::parse(&approval_bytes).map_err(operation)?;
        if record.signed_approval != approval.canonical_document()
            || evidence_by_request
                .insert(approval.request_id.clone(), approval)
                .is_some()
        {
            return Err(ExchangeCustodyToolError::InvalidDocument(
                "migration signed approval is non-canonical or duplicated",
            ));
        }
    }

    let mut released_records = Vec::with_capacity(export.released_records.len());
    let mut release_events = Vec::with_capacity(export.released_records.len());
    for source in &export.released_records {
        let approval = evidence_by_request
            .remove(&source.request.request_id)
            .ok_or(ExchangeCustodyToolError::InvalidDocument(
                "migration evidence does not match released v2 request ids",
            ))?;
        let verified = controls
            .policy
            .verify_approval(
                &approval,
                ExpectedApproval {
                    action: WithdrawalAction::Release,
                    action_anchor: ApprovalAnchor {
                        key_id: source_anchor.key_id,
                        journal_instance_id: source_anchor.journal_instance_id,
                        generation: source_anchor.generation,
                        commitment: source_anchor.commitment,
                    },
                    request_id: &source.request.request_id,
                    request_digest: source.request_digest,
                    transaction_signing_digest: source.signing_digest,
                },
                &PolicyWindowState::default(),
                approval.authorized_at_unix_seconds,
            )
            .map_err(operation)?;
        if verified.authorized_at_unix_seconds > watermark
            || !decision_ids.insert(verified.decision_id)
            || !approval_digests.insert(verified.signing_digest)
        {
            return Err(ExchangeCustodyToolError::InvalidDocument(
                "migration signed approval is duplicated or newer than the watermark",
            ));
        }
        let debit_atoms = controls
            .policy
            .check_static_limits(source.request.amount_atoms, source.request.fee_atoms)
            .map_err(operation)?;
        let mut reservations: Vec<_> = source
            .reserved_inputs
            .iter()
            .map(|input| ReservedInputV3 {
                outpoint: ReservedOutpointV3 {
                    txid: input.outpoint.txid,
                    index: input.outpoint.index,
                },
                value_atoms: input.value_atoms,
                wallet_key_id: key.key_id.0,
                public_key: key.public_key,
                signer_id,
            })
            .collect();
        reservations.sort_unstable_by_key(|input| input.outpoint);
        let core = WithdrawalCoreV3 {
            request_id: source.request.request_id.clone(),
            request_digest: source.request_digest,
            destination: source.request.destination,
            amount_atoms: source.request.amount_atoms,
            fee_atoms: source.request.fee_atoms,
            change_atoms: source.change_atoms,
            output_spendable_height: source.output_spendable_height,
            signing_digest: source.signing_digest,
            reservations,
        };
        let terminal = TerminalDecisionV3 {
            scope: DecisionScopeV3::ValidatedV2Migration,
            action: WithdrawalActionV3::Release,
            decision_id: verified.decision_id,
            approval_digest: verified.signing_digest,
            policy_id,
            action_anchor: source_anchor,
            request_digest: source.request_digest,
            transaction_signing_digest: source.signing_digest,
            decided_at_unix_seconds: verified.authorized_at_unix_seconds,
            accounted_at_unix_seconds: watermark,
        };
        released_records.push(ValidatedV2ReleasedRecordV3 {
            core,
            source_prepared_generation: source.prepared_generation,
            source_record_digest: source.source_record_digest,
            terminal,
            txid: source.txid,
            exact_transaction_bytes: source.exact_transaction_bytes.clone(),
            debit_atoms,
        });
        // v2 retained only caller-signed authorization time, not a trusted
        // local submission time. Conservatively charge every imported release
        // at cutover so a backdated approval cannot age debit out of v3 policy.
        release_events.push(PolicyReleaseEventV3 {
            request_digest: source.request_digest,
            released_at_unix_seconds: watermark,
            debit_atoms,
        });
    }
    if !evidence_by_request.is_empty() {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "migration evidence contains unknown request ids",
        ));
    }
    release_events
        .sort_unstable_by_key(|event| (event.released_at_unix_seconds, event.request_digest));
    let rolling_debit = release_events.iter().try_fold(0_u64, |sum, event| {
        sum.checked_add(event.debit_atoms)
            .ok_or(ExchangeCustodyToolError::InvalidDocument(
                "migration rolling debit overflow",
            ))
    })?;
    if release_events.len() as u64 > controls.policy.max_rolling_24h_release_count
        || rolling_debit > controls.policy.max_rolling_24h_debit_atoms
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "migrated releases exceed the supplied rolling policy",
        ));
    }
    Ok(ValidatedV2MigrationInputV3 {
        source_schema_version: 2,
        source_snapshot_digest: validated_v2_snapshot_digest(&export.exact_snapshot_bytes),
        source_current_anchor: source_anchor,
        source_external_anchor: source_anchor,
        migration_id,
        migration_decision_id,
        migration_approval_digest,
        binding: controls.binding,
        new_journal_instance_id,
        policy_id,
        initial_policy_window: PolicyWindowStateV3 {
            time_watermark_unix_seconds: watermark,
            release_events,
        },
        active_keyring: keyring_anchor_v3_from_v1(controls.keyring.anchor(), controls.binding)
            .map_err(operation)?,
        released_records,
    })
}

fn open_v3_store(
    controls: &V3OfflineControlConfig,
    data_dir: &Path,
) -> Result<(ExchangeCustodyV3Store, WithdrawalPolicy), ExchangeCustodyToolError> {
    let loaded = load_migration_controls(
        data_dir,
        stored_journal_binding(data_dir)?,
        &controls.policy_file,
        &controls.keyring_file,
        &controls.keyring_anchor_file,
        &controls.keyring_passphrase_file,
        None,
    )?;
    let active_keyring =
        keyring_anchor_v3_from_v1(loaded.keyring.anchor(), loaded.binding).map_err(operation)?;
    let store = ExchangeCustodyV3Store::open(&ExchangeCustodyV3OpenConfig {
        data_dir: data_dir.to_path_buf(),
        journal_key_file: controls.journal_key_file.clone(),
        external_anchor_file: controls.external_anchor_file.clone(),
        expected_binding: loaded.binding,
        expected_policy_id: loaded.policy.policy_id(),
        expected_active_keyring: active_keyring,
    })
    .map_err(operation)?;
    Ok((store, loaded.policy))
}

struct OfflineNodeLock(File);

impl OfflineNodeLock {
    fn acquire(data_dir: &Path) -> Result<Self, ExchangeCustodyToolError> {
        let path = data_dir.join(NODE_LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&path)
            .map_err(|source| ExchangeCustodyToolError::Io {
                action: "open node offline lock",
                path,
                source,
            })?;
        file.try_lock_exclusive()
            .map_err(|_| ExchangeCustodyToolError::NodeMustBeOffline)?;
        Ok(Self(file))
    }
}

impl Drop for OfflineNodeLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn journal_binding_from_node(node: &Node) -> JournalBindingV3 {
    JournalBindingV3 {
        network_id: node.params.network_id,
        consensus_fingerprint: node.fingerprint,
        genesis: node.params.genesis_hash,
    }
}

fn stored_journal_binding(data_dir: &Path) -> Result<JournalBindingV3, ExchangeCustodyToolError> {
    let metadata_path = resolve_existing_file(
        &data_dir.join(crate::METADATA_FILE),
        "node network metadata",
    )?;
    let bytes = read_bounded(
        &metadata_path,
        crate::METADATA_BYTES,
        "node network metadata",
    )?;
    if bytes.len() != crate::METADATA_BYTES
        || bytes[..4] != crate::METADATA_MAGIC
        || u16::from_le_bytes([bytes[4], bytes[5]]) != crate::METADATA_VERSION
        || u16::from_le_bytes([bytes[6], bytes[7]]) & !crate::METADATA_WALLET_KEY_FLAG != 0
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "node network metadata",
        ));
    }
    let mut consensus_fingerprint = [0_u8; 32];
    consensus_fingerprint.copy_from_slice(&bytes[8..40]);
    if consensus_fingerprint == [0; 32] {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "node consensus fingerprint is zero",
        ));
    }
    Ok(JournalBindingV3 {
        network_id: crate::COMPILED_NETWORK_PROFILE.network_id,
        consensus_fingerprint,
        genesis: crate::COMPILED_NETWORK_PROFILE.virtual_genesis_hash,
    })
}

fn keyring_binding_from_journal(binding: JournalBindingV3) -> KeyringRuntimeBinding {
    KeyringRuntimeBinding {
        network_id: binding.network_id,
        consensus_fingerprint: binding.consensus_fingerprint,
        genesis_hash: binding.genesis,
    }
}

fn stored_keyring_binding(
    data_dir: &Path,
) -> Result<KeyringRuntimeBinding, ExchangeCustodyToolError> {
    Ok(keyring_binding_from_journal(stored_journal_binding(
        data_dir,
    )?))
}

fn decrypt_legacy_wallet_key(
    data_dir: &Path,
    source: &[u8],
    passphrase_file: Option<&Path>,
    network_id: [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, ExchangeCustodyToolError> {
    if source.len() == 32 {
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(source);
        return Ok(key);
    }
    if source.len() != ENCRYPTED_WALLET_KEY_BYTES {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "legacy wallet key length",
        ));
    }
    let path = passphrase_file.ok_or(ExchangeCustodyToolError::InvalidDocument(
        "encrypted legacy wallet requires its passphrase file",
    ))?;
    let passphrase = load_provisioning_passphrase_v3(data_dir, path, "legacy wallet passphrase")
        .map_err(operation)?;
    let (secret, _) =
        decrypt_wallet_key_bytes(source, network_id, &passphrase).map_err(operation)?;
    Ok(secret)
}

fn require_node_data_dir(
    node: &Node,
    configured: &Path,
) -> Result<PathBuf, ExchangeCustodyToolError> {
    let configured = canonical_data_dir(configured)?;
    let actual =
        fs::canonicalize(node.data_dir()).map_err(|source| ExchangeCustodyToolError::Io {
            action: "canonicalize open node data directory",
            path: node.data_dir().to_path_buf(),
            source,
        })?;
    if configured != actual {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "open node and migration data directories differ",
        ));
    }
    Ok(configured)
}

fn v3_migration_slot_present(data_dir: &Path) -> Result<bool, ExchangeCustodyToolError> {
    for slot in 0..=1 {
        let path = data_dir.join(format!("exchange-withdrawals.{slot}.bin"));
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(ExchangeCustodyToolError::Io {
                    action: "inspect migration withdrawal slot",
                    path,
                    source,
                });
            }
        };
        if !metadata.file_type().is_file() || metadata_is_symlink_or_reparse(&metadata) {
            return Err(ExchangeCustodyToolError::InvalidPath(
                "migration withdrawal slot",
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|source| ExchangeCustodyToolError::Io {
                action: "open migration withdrawal slot",
                path: path.clone(),
                source,
            })?;
        let mut header = [0_u8; 12];
        match file.read_exact(&mut header) {
            Ok(())
                if header[..8] == WITHDRAWAL_SNAPSHOT_MAGIC
                    && header[8..12] == V3_WITHDRAWAL_SNAPSHOT_VERSION.to_le_bytes() =>
            {
                return Ok(true);
            }
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(source) => {
                return Err(ExchangeCustodyToolError::Io {
                    action: "read migration withdrawal slot header",
                    path,
                    source,
                });
            }
        }
    }
    Ok(false)
}

fn migration_source_export_for_apply(
    node: &Node,
    data_dir: &Path,
    snapshot_bytes: &[u8],
    planned_source_anchor: WithdrawalJournalAnchor,
) -> Result<ValidatedV2MigrationExport, ExchangeCustodyToolError> {
    let export = if v3_migration_slot_present(data_dir)? {
        ExchangeWithdrawalJournal::export_exact_v2_for_v3_migration_resume(
            node,
            snapshot_bytes,
            planned_source_anchor,
        )
        .map_err(operation)?
    } else {
        ExchangeWithdrawalJournal::export_validated_v2_for_v3_migration(node).map_err(operation)?
    };
    if export.source_anchor != planned_source_anchor
        || export.exact_snapshot_bytes != snapshot_bytes
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "validated v2 source differs from the confirmed migration plan",
        ));
    }
    Ok(export)
}

fn canonical_data_dir(path: &Path) -> Result<PathBuf, ExchangeCustodyToolError> {
    if !path.is_absolute() {
        return Err(ExchangeCustodyToolError::RelativePath("data directory"));
    }
    let resolved = fs::canonicalize(path).map_err(|source| ExchangeCustodyToolError::Io {
        action: "canonicalize data directory",
        path: path.to_path_buf(),
        source,
    })?;
    if !resolved.is_dir() {
        return Err(ExchangeCustodyToolError::InvalidPath("data directory"));
    }
    Ok(resolved)
}

fn resolve_existing_file(
    path: &Path,
    label: &'static str,
) -> Result<PathBuf, ExchangeCustodyToolError> {
    if !path.is_absolute() {
        return Err(ExchangeCustodyToolError::RelativePath(label));
    }
    let unresolved = fs::symlink_metadata(path).map_err(|source| ExchangeCustodyToolError::Io {
        action: "inspect input path",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata_is_symlink_or_reparse(&unresolved) {
        return Err(ExchangeCustodyToolError::InvalidPath(label));
    }
    let resolved = fs::canonicalize(path).map_err(|source| ExchangeCustodyToolError::Io {
        action: "canonicalize input",
        path: path.to_path_buf(),
        source,
    })?;
    if !resolved.is_file() {
        return Err(ExchangeCustodyToolError::InvalidPath(label));
    }
    Ok(resolved)
}

fn metadata_is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn resolve_output(path: &Path, label: &'static str) -> Result<PathBuf, ExchangeCustodyToolError> {
    if !path.is_absolute() {
        return Err(ExchangeCustodyToolError::RelativePath(label));
    }
    if path.exists() {
        return Err(ExchangeCustodyToolError::OutputExists(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or(ExchangeCustodyToolError::InvalidPath(label))?;
    let parent = fs::canonicalize(parent).map_err(|source| ExchangeCustodyToolError::Io {
        action: "canonicalize output parent",
        path: parent.to_path_buf(),
        source,
    })?;
    if !parent.is_dir() {
        return Err(ExchangeCustodyToolError::InvalidPath(label));
    }
    let name = path
        .file_name()
        .ok_or(ExchangeCustodyToolError::InvalidPath(label))?;
    Ok(parent.join(name))
}

fn resolve_output_or_existing_file(
    path: &Path,
    label: &'static str,
) -> Result<PathBuf, ExchangeCustodyToolError> {
    if path.exists() {
        resolve_existing_file(path, label)
    } else {
        resolve_output(path, label)
    }
}

fn ensure_outside_data_dir(data_dir: &Path, path: &Path) -> Result<(), ExchangeCustodyToolError> {
    if path.starts_with(data_dir) {
        Err(ExchangeCustodyToolError::ControlInsideDataDirectory(
            path.to_path_buf(),
        ))
    } else {
        Ok(())
    }
}

fn read_bounded(
    path: &Path,
    limit: usize,
    label: &'static str,
) -> Result<Vec<u8>, ExchangeCustodyToolError> {
    let metadata = fs::metadata(path).map_err(|source| ExchangeCustodyToolError::Io {
        action: "inspect input",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > limit as u64 {
        return Err(ExchangeCustodyToolError::InvalidDocument(label));
    }
    let bytes = fs::read(path).map_err(|source| ExchangeCustodyToolError::Io {
        action: "read input",
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() > limit {
        return Err(ExchangeCustodyToolError::InvalidDocument(label));
    }
    Ok(bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    label: &'static str,
) -> Result<T, ExchangeCustodyToolError> {
    serde_json::from_slice(&read_bounded(path, MAX_TOOL_DOCUMENT_BYTES, label)?)
        .map_err(|_| ExchangeCustodyToolError::InvalidDocument(label))
}

fn write_create_new(
    path: &Path,
    bytes: &[u8],
    secret: bool,
) -> Result<(), ExchangeCustodyToolError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(not(unix))]
    let _ = secret;
    #[cfg(unix)]
    if secret {
        options.mode(0o600);
    }
    #[cfg(windows)]
    if secret {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC,
        };
        options.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
    }
    let mut file = options.open(path).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            ExchangeCustodyToolError::OutputExists(path.to_path_buf())
        } else {
            ExchangeCustodyToolError::Io {
                action: "create operator artifact",
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    #[cfg(windows)]
    if secret
        && let Err(error) = crate::exchange_acl::initialize_windows_node_owned_custody_file_acl(
            &file,
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::JournalKey,
        )
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(operation(error));
    }
    if let Err(source) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(ExchangeCustodyToolError::Io {
            action: "write operator artifact",
            path: path.to_path_buf(),
            source,
        });
    }
    sync_artifact_parent(path)?;
    Ok(())
}

fn create_or_verify_exact(
    path: &Path,
    bytes: &[u8],
    secret: bool,
) -> Result<(), ExchangeCustodyToolError> {
    match write_create_new(path, bytes, secret) {
        Ok(()) => Ok(()),
        Err(ExchangeCustodyToolError::OutputExists(_)) => {
            let existing = read_bounded(path, bytes.len(), "existing operator artifact")?;
            if existing == bytes {
                Ok(())
            } else {
                Err(ExchangeCustodyToolError::OutputExists(path.to_path_buf()))
            }
        }
        Err(error) => Err(error),
    }
}

fn keyring_anchor_report(anchor: KeyringAnchorV1) -> KeyringAnchorReport {
    KeyringAnchorReport {
        network_id: hex::encode(anchor.binding.network_id),
        consensus_fingerprint: hex::encode(anchor.binding.consensus_fingerprint),
        genesis_hash: hex::encode(anchor.binding.genesis_hash),
        instance_id: hex::encode(anchor.instance_id),
        generation: anchor.generation.to_string(),
        commitment: hex::encode(anchor.commitment),
    }
}

fn journal_anchor_report(anchor: JournalAnchorV3) -> JournalAnchorReport {
    JournalAnchorReport {
        key_id: hex::encode(anchor.key_id),
        journal_instance_id: hex::encode(anchor.journal_instance_id),
        generation: anchor.generation.to_string(),
        commitment: hex::encode(anchor.commitment),
    }
}

fn withdrawal_anchor_from_report(
    report: &JournalAnchorReport,
) -> Result<WithdrawalJournalAnchor, ExchangeCustodyToolError> {
    let anchor = WithdrawalJournalAnchor {
        key_id: decode_nonzero_hex32(&report.key_id, "source_anchor.key_id")?,
        journal_instance_id: decode_nonzero_hex32(
            &report.journal_instance_id,
            "source_anchor.journal_instance_id",
        )?,
        generation: parse_canonical_u64(&report.generation, "source_anchor.generation")?,
        commitment: decode_nonzero_hex32(&report.commitment, "source_anchor.commitment")?,
    };
    if anchor.generation == 0 {
        return Err(ExchangeCustodyToolError::InvalidDocument(
            "source_anchor.generation",
        ));
    }
    Ok(anchor)
}

fn journal_anchor_from_archive_source(
    source: crate::exchange_archive::ArchiveSource,
) -> JournalAnchorV3 {
    JournalAnchorV3 {
        key_id: source.key_id,
        journal_instance_id: source.journal_instance_id,
        generation: source.generation,
        commitment: source.commitment,
    }
}

fn encode_journal_anchor(anchor: JournalAnchorV3) -> Result<Vec<u8>, ExchangeCustodyToolError> {
    serde_json::to_vec_pretty(&journal_anchor_report(anchor)).map_err(operation)
}

fn decode_hex32(value: &str, label: &'static str) -> Result<[u8; 32], ExchangeCustodyToolError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ExchangeCustodyToolError::InvalidDocument(label));
    }
    let mut output = [0; 32];
    hex::decode_to_slice(value, &mut output)
        .map_err(|_| ExchangeCustodyToolError::InvalidDocument(label))?;
    Ok(output)
}

fn decode_nonzero_hex32(
    value: &str,
    label: &'static str,
) -> Result<[u8; 32], ExchangeCustodyToolError> {
    let output = decode_hex32(value, label)?;
    if output == [0; 32] {
        return Err(ExchangeCustodyToolError::InvalidDocument(label));
    }
    Ok(output)
}

fn parse_canonical_u64(value: &str, label: &'static str) -> Result<u64, ExchangeCustodyToolError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| value == parsed.to_string())
        .ok_or(ExchangeCustodyToolError::InvalidDocument(label))
}

fn digest(domain: &'static str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn operation(error: impl std::fmt::Display) -> ExchangeCustodyToolError {
    ExchangeCustodyToolError::Operation(error.to_string())
}

#[cfg(unix)]
fn sync_artifact_parent(path: &Path) -> Result<(), ExchangeCustodyToolError> {
    let parent = path
        .parent()
        .ok_or(ExchangeCustodyToolError::InvalidPath("artifact parent"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ExchangeCustodyToolError::Io {
            action: "sync operator artifact parent",
            path: parent.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_artifact_parent(_path: &Path) -> Result<(), ExchangeCustodyToolError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use cmfd_consensus::OutPoint;
    use k256::schnorr::{Signature, SigningKey, signature::Signer};
    use zeroize::Zeroizing;

    use super::*;
    use crate::exchange_policy::{ApprovalRule, ApprovalSignature};
    use crate::exchange_withdrawal::{
        ValidatedV2ReleasedRecordExport, WithdrawalJournalAnchor, WithdrawalRequest,
        WithdrawalReservedInput, encode_external_anchor,
    };
    use crate::wallet_keyring::{KeyRoles, WalletKeyEntry};
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_PROFILE, ExchangeWithdrawalSecurityConfig};

    fn test_directory() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "cmfd-exchange-custody-tools-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        directory
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        {
            let identity = std::process::Command::new("whoami.exe").output().unwrap();
            assert!(identity.status.success());
            let identity = String::from_utf8(identity.stdout).unwrap();
            let grant = format!("{}:(F)", identity.trim());
            let status = std::process::Command::new("icacls.exe")
                .arg(path)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(grant)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    fn write_test_network_metadata(data_dir: &Path) {
        let mut bytes = Vec::with_capacity(crate::METADATA_BYTES);
        bytes.extend_from_slice(&crate::METADATA_MAGIC);
        bytes.extend_from_slice(&crate::METADATA_VERSION.to_le_bytes());
        bytes.extend_from_slice(&crate::METADATA_WALLET_KEY_FLAG.to_le_bytes());
        bytes.extend_from_slice(&[0xA1; 32]);
        write_private(&data_dir.join(crate::METADATA_FILE), &bytes);
    }

    fn marker(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn signing_key(value: u8) -> SigningKey {
        SigningKey::from_bytes(&marker(value)).expect("test scalar is valid")
    }

    fn public_key(value: u8) -> [u8; 32] {
        signing_key(value).verifying_key().to_bytes().into()
    }

    fn migration_fixture() -> (LoadedMigrationControls, ValidatedV2MigrationExport) {
        let binding = JournalBindingV3 {
            network_id: marker(1),
            consensus_fingerprint: marker(2),
            genesis: marker(3),
        };
        let legacy_wallet_destination = public_key(7);
        let keyring = WalletKeyring::new_genesis(
            KeyringRuntimeBinding {
                network_id: binding.network_id,
                consensus_fingerprint: binding.consensus_fingerprint,
                genesis_hash: binding.genesis,
            },
            marker(4),
            vec![
                WalletKeyEntry::local(
                    Zeroizing::new(marker(7)),
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Retired,
                )
                .unwrap(),
                WalletKeyEntry::external(
                    public_key(8),
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Active,
                    SignerId(marker(9)),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let wallet_destination = keyring.active_change_key().public_key;
        let policy = WithdrawalPolicy {
            binding: WithdrawalPolicyBinding {
                network_id: binding.network_id,
                consensus_fingerprint: binding.consensus_fingerprint,
                genesis_hash: binding.genesis,
                wallet_destination,
            },
            max_single_amount_atoms: 1_000,
            max_single_fee_atoms: 25,
            max_single_debit_atoms: 1_025,
            max_rolling_24h_debit_atoms: 5_000,
            max_rolling_24h_release_count: 8,
            release_approval: ApprovalRule {
                threshold: 1,
                public_keys: vec![public_key(0x11)],
            },
            cancel_approval: ApprovalRule {
                threshold: 1,
                public_keys: vec![public_key(0x22)],
            },
        };
        let export = ValidatedV2MigrationExport {
            source_anchor: WithdrawalJournalAnchor {
                key_id: marker(0x31),
                journal_instance_id: marker(0x32),
                generation: 7,
                commitment: marker(0x33),
            },
            exact_snapshot_bytes: vec![0x34],
            wallet_destination: legacy_wallet_destination,
            released_records: vec![ValidatedV2ReleasedRecordExport {
                request: WithdrawalRequest {
                    request_id: "migrated-withdrawal-0001".to_owned(),
                    destination: public_key(0x23),
                    amount_atoms: 700,
                    fee_atoms: 20,
                },
                request_digest: marker(0x35),
                change_atoms: 280,
                output_spendable_height: 44,
                signing_digest: marker(0x36),
                reserved_inputs: vec![WithdrawalReservedInput {
                    outpoint: OutPoint {
                        txid: marker(0x37),
                        index: 0,
                    },
                    value_atoms: 1_000,
                }],
                prepared_generation: 6,
                txid: marker(0x38),
                exact_transaction_bytes: vec![0x39],
                source_record_digest: marker(0x3a),
            }],
        };
        (
            LoadedMigrationControls {
                binding,
                policy,
                keyring,
            },
            export,
        )
    }

    fn signed_migration_approval(
        controls: &LoadedMigrationControls,
        export: &ValidatedV2MigrationExport,
    ) -> Value {
        let source = &export.released_records[0];
        let source_anchor = journal_anchor_v3_from_v2(export.source_anchor);
        let mut approval = WithdrawalApproval {
            action: WithdrawalAction::Release,
            decision_id: marker(0x41),
            policy_id: controls.policy.policy_id(),
            action_anchor: ApprovalAnchor {
                key_id: source_anchor.key_id,
                journal_instance_id: source_anchor.journal_instance_id,
                generation: source_anchor.generation,
                commitment: source_anchor.commitment,
            },
            request_id: source.request.request_id.clone(),
            request_digest: source.request_digest,
            transaction_signing_digest: source.signing_digest,
            authorized_at_unix_seconds: 90,
            expires_at_unix_seconds: 190,
            signatures: Vec::new(),
        };
        let signature: Signature = signing_key(0x11).sign(&approval.signing_digest());
        approval.signatures.push(ApprovalSignature {
            public_key: public_key(0x11),
            signature: signature.to_bytes(),
        });
        approval.canonical_document()
    }

    fn migration_plan_confirmation_fixture() -> (MigrationPlanDocument, [u8; 32]) {
        let plan_file = PathBuf::from("C:/controls/migration-plan.json");
        let mut plan = MigrationPlanDocument {
            schema: MIGRATION_PLAN_SCHEMA.to_owned(),
            plan_digest: hex::encode([0_u8; 32]),
            plan_file: plan_file.clone(),
            data_dir: PathBuf::from("C:/node"),
            journal_key_file: PathBuf::from("C:/controls/journal.key"),
            journal_key_id: hex::encode(marker(0x51)),
            evidence_file: PathBuf::from("C:/controls/migration-evidence.json"),
            evidence_digest: hex::encode(marker(0x52)),
            policy_file: PathBuf::from("C:/controls/policy.json"),
            keyring_file: PathBuf::from("C:/node/keyring.bin"),
            keyring_anchor_file: PathBuf::from("C:/controls/keyring.anchor"),
            keyring_passphrase_file: PathBuf::from("C:/controls/keyring.passphrase"),
            validated_snapshot_file: PathBuf::from("C:/controls/validated-v2.bin"),
            v3_anchor_output: PathBuf::from("C:/controls/v3-anchor.json"),
            backup_files: vec![
                PathBuf::from("C:/node/v2-backup.0.bin"),
                PathBuf::from("C:/node/v2-backup.1.bin"),
                PathBuf::from("C:/node/v2-backup.initialized"),
            ],
            source_snapshot_digest: hex::encode(marker(0x53)),
            source_anchor: JournalAnchorReport {
                key_id: hex::encode(marker(0x54)),
                journal_instance_id: hex::encode(marker(0x55)),
                generation: "7".to_owned(),
                commitment: hex::encode(marker(0x56)),
            },
            policy_id: hex::encode(marker(0x57)),
            keyring_anchor: KeyringAnchorReport {
                network_id: hex::encode(marker(1)),
                consensus_fingerprint: hex::encode(marker(2)),
                genesis_hash: hex::encode(marker(3)),
                instance_id: hex::encode(marker(0x58)),
                generation: "1".to_owned(),
                commitment: hex::encode(marker(0x59)),
            },
            migration_input_digest: hex::encode(marker(0x5a)),
            initial_anchor: JournalAnchorReport {
                key_id: hex::encode(marker(0x51)),
                journal_instance_id: hex::encode(marker(0x5b)),
                generation: "1".to_owned(),
                commitment: hex::encode(marker(0x5c)),
            },
            released_record_count: 1,
        };
        let digest = migration_plan_digest(&plan).unwrap();
        plan.plan_digest = hex::encode(digest);
        (plan, digest)
    }

    #[cfg(windows)]
    fn protect_node_owned_directory(path: &Path) {
        let identity = std::process::Command::new("whoami.exe").output().unwrap();
        assert!(identity.status.success());
        let identity = String::from_utf8(identity.stdout).unwrap();
        let grant = format!("{}:(OI)(CI)(F)", identity.trim());
        let status = std::process::Command::new("icacls.exe")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(grant)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(not(windows))]
    fn protect_node_owned_directory(_path: &Path) {}

    #[test]
    fn archive_manifest_pin_rejects_node_controlled_authority() {
        let root = test_directory();
        let data = root.join("node");
        let controls = root.join("controls");
        fs::create_dir(&data).unwrap();
        fs::create_dir(&controls).unwrap();
        let pin = controls.join("archive.pin");
        write_private(&pin, b"independent pin test");

        assert!(
            load_external_control_document_v3(
                &data,
                &pin,
                MAX_TOOL_DOCUMENT_BYTES,
                "archive manifest pin",
            )
            .is_err(),
            "a pin owned or replaceable by the apply identity is not independent"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn archive_manifest_pin_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let root = test_directory();
        let data = root.join("node");
        fs::create_dir(&data).unwrap();
        let target = root.join("archive-pin-target");
        let pin = root.join("archive.pin");
        write_private(&target, b"independent pin test");
        symlink(&target, &pin).unwrap();

        assert!(
            load_external_control_document_v3(
                &data,
                &pin,
                MAX_TOOL_DOCUMENT_BYTES,
                "archive manifest pin",
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn archive_manifest_pin_rejects_reparse_target_when_supported() {
        use std::os::windows::fs::symlink_file;

        let root = test_directory();
        let data = root.join("node");
        fs::create_dir(&data).unwrap();
        let target = root.join("archive-pin-target");
        let pin = root.join("archive.pin");
        write_private(&target, b"independent pin test");
        match symlink_file(&target, &pin) {
            Ok(()) => assert!(
                load_external_control_document_v3(
                    &data,
                    &pin,
                    MAX_TOOL_DOCUMENT_BYTES,
                    "archive manifest pin",
                )
                .is_err()
            ),
            Err(error) if error.raw_os_error() == Some(1314) => {}
            Err(error) => panic!("create test reparse point: {error}"),
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plaintext_legacy_import_requires_exact_confirmation_and_is_create_new() {
        let root = test_directory();
        let data = root.join("node");
        let controls = root.join("controls");
        fs::create_dir(&data).unwrap();
        fs::create_dir(&controls).unwrap();
        protect_node_owned_directory(&data);
        protect_node_owned_directory(&controls);
        write_test_network_metadata(&data);
        let legacy = data.join("wallet.key");
        let passphrase = controls.join("keyring.passphrase");
        write_private(&legacy, &[7; 32]);
        write_private(&passphrase, b"correct horse battery staple\n");
        let plan = controls.join("import-plan.json");
        let planned = plan_legacy_keyring_import(&LegacyKeyringPlanConfig {
            data_dir: data.clone(),
            legacy_key_file: legacy,
            legacy_wallet_passphrase_file: None,
            keyring_instance_id: [8; 32],
            plan_output: plan.clone(),
        })
        .unwrap();
        assert_eq!(planned.status, "planned");
        assert!(
            plan_legacy_keyring_import(&LegacyKeyringPlanConfig {
                data_dir: data.clone(),
                legacy_key_file: data.join("wallet.key"),
                legacy_wallet_passphrase_file: None,
                keyring_instance_id: [8; 32],
                plan_output: plan.clone(),
            })
            .is_err()
        );

        let keyring = data.join("wallet-keyring.bin");
        let anchor = controls.join("wallet-keyring.anchor");
        let mut confirmation = decode_hex32(&planned.confirmation_digest, "test").unwrap();
        confirmation[0] ^= 1;
        assert!(matches!(
            apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
                data_dir: data.clone(),
                plan_file: plan.clone(),
                expected_confirmation_digest: confirmation,
                passphrase_file: passphrase.clone(),
                keyring_output: keyring.clone(),
                anchor_output: anchor.clone(),
            }),
            Err(ExchangeCustodyToolError::ConfirmationMismatch)
        ));
        assert!(!keyring.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&passphrase, fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(windows)]
        {
            assert!(
                std::process::Command::new("icacls.exe")
                    .arg(&passphrase)
                    .arg("/grant")
                    .arg("*S-1-1-0:(R)")
                    .status()
                    .unwrap()
                    .success()
            );
        }
        assert!(
            apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
                data_dir: data.clone(),
                plan_file: plan.clone(),
                expected_confirmation_digest: decode_hex32(
                    &planned.confirmation_digest,
                    "test confirmation",
                )
                .unwrap(),
                passphrase_file: passphrase.clone(),
                keyring_output: keyring.clone(),
                anchor_output: anchor.clone(),
            })
            .is_err()
        );
        assert!(!keyring.exists());
        assert!(!anchor.exists());
        fs::remove_file(&passphrase).unwrap();
        write_private(&passphrase, b"correct horse battery staple\n");

        let report = apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
            data_dir: data.clone(),
            plan_file: plan,
            expected_confirmation_digest: decode_hex32(
                &planned.confirmation_digest,
                "test confirmation",
            )
            .unwrap(),
            passphrase_file: passphrase.clone(),
            keyring_output: keyring.clone(),
            anchor_output: anchor.clone(),
        })
        .unwrap();
        assert_eq!(
            report.status,
            "applied_to_create_new_artifacts; pin anchor_file independently before use"
        );
        let decoded_anchor = KeyringAnchorV1::decode(&fs::read(anchor).unwrap()).unwrap();
        let passphrase_bytes = read_wallet_passphrase_file(&passphrase).unwrap();
        let decoded = WalletKeyring::decode_live(
            &fs::read(&keyring).unwrap(),
            stored_keyring_binding(&data).unwrap(),
            &passphrase_bytes,
            decoded_anchor,
        )
        .unwrap();
        assert_eq!(
            decoded.active_change_key().public_key,
            hex32(&planned.legacy_public_key)
        );
        let keyring_before_retry = fs::read(&keyring).unwrap();
        apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
            data_dir: data.clone(),
            plan_file: controls.join("import-plan.json"),
            expected_confirmation_digest: decode_hex32(
                &planned.confirmation_digest,
                "test confirmation",
            )
            .unwrap(),
            passphrase_file: passphrase.clone(),
            keyring_output: keyring.clone(),
            anchor_output: controls.join("wallet-keyring.anchor"),
        })
        .unwrap();
        assert_eq!(fs::read(&keyring).unwrap(), keyring_before_retry);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keyring, fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(windows)]
        {
            let status = std::process::Command::new("icacls.exe")
                .arg(&keyring)
                .arg("/grant")
                .arg("*S-1-1-0:(R)")
                .status()
                .unwrap();
            assert!(status.success());
        }
        assert!(
            apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
                data_dir: data,
                plan_file: controls.join("import-plan.json"),
                expected_confirmation_digest: decode_hex32(
                    &planned.confirmation_digest,
                    "test confirmation",
                )
                .unwrap(),
                passphrase_file: passphrase,
                keyring_output: keyring,
                anchor_output: controls.join("wallet-keyring.anchor"),
            })
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn imported_keyring_transitions_to_external_without_overwriting_source() {
        let root = test_directory();
        let data = root.join("node");
        let controls = root.join("controls");
        fs::create_dir(&data).unwrap();
        fs::create_dir(&controls).unwrap();
        protect_node_owned_directory(&data);
        protect_node_owned_directory(&controls);
        write_test_network_metadata(&data);
        let legacy = data.join("wallet.key");
        let passphrase = controls.join("keyring.passphrase");
        write_private(&legacy, &[7; 32]);
        write_private(&passphrase, b"correct horse battery staple\n");
        let import_plan = controls.join("import-plan.json");
        let imported = plan_legacy_keyring_import(&LegacyKeyringPlanConfig {
            data_dir: data.clone(),
            legacy_key_file: legacy,
            legacy_wallet_passphrase_file: None,
            keyring_instance_id: marker(8),
            plan_output: import_plan.clone(),
        })
        .unwrap();
        let source_keyring = data.join("imported-keyring.bin");
        let source_anchor = controls.join("imported-keyring.anchor");
        apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
            data_dir: data.clone(),
            plan_file: import_plan,
            expected_confirmation_digest: hex32(&imported.confirmation_digest),
            passphrase_file: passphrase.clone(),
            keyring_output: source_keyring.clone(),
            anchor_output: source_anchor.clone(),
        })
        .unwrap();
        let source_keyring_bytes = fs::read(&source_keyring).unwrap();
        let source_anchor_bytes = fs::read(&source_anchor).unwrap();

        let candidate_keyring = data.join("external-keyring.bin");
        let candidate_anchor = controls.join("external-keyring.anchor");
        let transition_plan = controls.join("external-transition-plan.json");
        let external_public_key = public_key(12);
        let external_signer_id = marker(13);
        let planned = plan_external_keyring_transition(&ExternalKeyringTransitionPlanConfig {
            data_dir: data.clone(),
            source_keyring_file: source_keyring.clone(),
            source_anchor_file: source_anchor.clone(),
            source_keyring_passphrase_file: passphrase.clone(),
            external_public_key,
            external_signer_id,
            keyring_output: candidate_keyring.clone(),
            anchor_output: candidate_anchor.clone(),
            plan_output: transition_plan.clone(),
        })
        .unwrap();
        assert_eq!(planned.status, "planned; source keyring remains unchanged");
        assert_eq!(planned.source_anchor.generation, "1");
        assert_eq!(planned.candidate_anchor.generation, "2");
        let mut wrong_confirmation = hex32(&planned.confirmation_digest);
        wrong_confirmation[0] ^= 1;
        assert!(matches!(
            apply_external_keyring_transition(&ExternalKeyringTransitionApplyConfig {
                data_dir: data.clone(),
                plan_file: transition_plan.clone(),
                expected_confirmation_digest: wrong_confirmation,
                source_keyring_passphrase_file: passphrase.clone(),
            }),
            Err(ExchangeCustodyToolError::ConfirmationMismatch)
        ));
        assert!(!candidate_keyring.exists());
        assert!(!candidate_anchor.exists());

        let applied = apply_external_keyring_transition(&ExternalKeyringTransitionApplyConfig {
            data_dir: data.clone(),
            plan_file: transition_plan.clone(),
            expected_confirmation_digest: hex32(&planned.confirmation_digest),
            source_keyring_passphrase_file: passphrase.clone(),
        })
        .unwrap();
        assert!(applied.status.contains("source retained"));
        assert_eq!(fs::read(&source_keyring).unwrap(), source_keyring_bytes);
        assert_eq!(fs::read(&source_anchor).unwrap(), source_anchor_bytes);
        let candidate_keyring_before_retry = fs::read(&candidate_keyring).unwrap();
        let trusted_candidate_anchor =
            KeyringAnchorV1::decode(&fs::read(&candidate_anchor).unwrap()).unwrap();
        let passphrase_bytes = read_wallet_passphrase_file(&passphrase).unwrap();
        let decoded = WalletKeyring::decode_live(
            &candidate_keyring_before_retry,
            stored_keyring_binding(&data).unwrap(),
            &passphrase_bytes,
            trusted_candidate_anchor,
        )
        .unwrap();
        let legacy = decoded
            .key(wallet_key_id(&hex32(&planned.legacy_public_key)))
            .unwrap();
        assert_eq!(legacy.lifecycle, KeyLifecycle::Retired);
        assert_eq!(legacy.storage, KeyStorageBinding::Local);
        let external = decoded.active_change_key();
        assert_eq!(external.public_key, external_public_key);
        assert_eq!(
            external.storage,
            KeyStorageBinding::External {
                signer_id: SignerId(external_signer_id)
            }
        );

        apply_external_keyring_transition(&ExternalKeyringTransitionApplyConfig {
            data_dir: data.clone(),
            plan_file: transition_plan,
            expected_confirmation_digest: hex32(&planned.confirmation_digest),
            source_keyring_passphrase_file: passphrase,
        })
        .unwrap();
        assert_eq!(
            fs::read(candidate_keyring).unwrap(),
            candidate_keyring_before_retry
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mixed_keyring_finalization_is_irreversible_and_utxo_guarded() {
        let imported = WalletKeyring::new_genesis(
            KeyringRuntimeBinding {
                network_id: marker(1),
                consensus_fingerprint: marker(2),
                genesis_hash: marker(3),
            },
            marker(4),
            vec![
                WalletKeyEntry::local(
                    Zeroizing::new(marker(7)),
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Active,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let legacy_public_key = imported.active_change_key().public_key;
        let (_, _, mixed) =
            transition_imported_keyring_to_external(imported, public_key(12), marker(13)).unwrap();
        let (_, external, finalized) =
            finalize_mixed_keyring_external_only(mixed, legacy_public_key).unwrap();
        assert_eq!(finalized.generation(), 3);
        assert_eq!(external, finalized.active_change_key());
        let legacy = finalized.key(wallet_key_id(&legacy_public_key)).unwrap();
        assert_eq!(legacy.lifecycle, KeyLifecycle::Disabled);
        assert_eq!(legacy.storage, KeyStorageBinding::WatchOnly);
        assert!(matches!(
            finalized.sign_local_digest(legacy.key_id, &marker(14)),
            Err(crate::wallet_keyring::WalletKeyringError::DisabledKey)
        ));
        let final_anchor = finalized.anchor();
        let final_envelope = finalized
            .encode_live(b"correct horse battery staple")
            .unwrap();
        let reopened = WalletKeyring::decode_live(
            &final_envelope,
            final_anchor.binding,
            b"correct horse battery staple",
            final_anchor,
        )
        .unwrap();
        assert!(
            reopened
                .summaries()
                .iter()
                .all(|entry| entry.storage != KeyStorageBinding::Local)
        );
        assert!(matches!(
            local_signer_profile(&reopened),
            Err(crate::exchange_local_signer::ExchangeLocalSignerError::NoLocallySignableKeys)
        ));

        let clear = LegacyKeyUtxoEvidenceReport {
            active_chain_tip: hex::encode(marker(15)),
            next_height: "100".to_owned(),
            unspent_count: "0".to_owned(),
            unspent_atoms: "0".to_owned(),
            spendable_count: "0".to_owned(),
            spendable_atoms: "0".to_owned(),
            local_mempool_output_count: "0".to_owned(),
            local_mempool_output_atoms: "0".to_owned(),
        };
        require_no_legacy_key_utxos(&clear).unwrap();
        let mut blocked = clear;
        blocked.unspent_count = "1".to_owned();
        blocked.unspent_atoms = "50".to_owned();
        assert!(require_no_legacy_key_utxos(&blocked).is_err());
    }

    #[test]
    fn encrypted_rcnet_legacy_import_binds_ciphertext_and_passphrase_path() {
        let root = test_directory();
        let data = root.join("node");
        let controls = root.join("controls");
        fs::create_dir(&data).unwrap();
        fs::create_dir(&controls).unwrap();
        protect_node_owned_directory(&data);
        protect_node_owned_directory(&controls);
        write_test_network_metadata(&data);
        let source_passphrase = controls.join("legacy.passphrase");
        let keyring_passphrase = controls.join("keyring.passphrase");
        write_private(&source_passphrase, b"legacy correct horse\n");
        write_private(&keyring_passphrase, b"new correct horse staple\n");
        let binding = stored_keyring_binding(&data).unwrap();
        let (encrypted, _) = crate::wallet_backup::encrypt_wallet_key_bytes(
            &[9; 32],
            binding.network_id,
            b"legacy correct horse",
        )
        .unwrap();
        let legacy = data.join("wallet.key");
        write_private(&legacy, &encrypted);
        let plan_path = controls.join("encrypted-import-plan.json");
        let planned = plan_legacy_keyring_import(&LegacyKeyringPlanConfig {
            data_dir: data.clone(),
            legacy_key_file: legacy,
            legacy_wallet_passphrase_file: Some(source_passphrase.clone()),
            keyring_instance_id: [10; 32],
            plan_output: plan_path.clone(),
        })
        .unwrap();
        let plan_document: LegacyKeyringPlanDocument = read_json(&plan_path, "test plan").unwrap();
        assert_eq!(
            plan_document.legacy_wallet_passphrase_file,
            Some(fs::canonicalize(&source_passphrase).unwrap())
        );
        assert_eq!(
            plan_document.legacy_key_digest,
            hex::encode(digest(LEGACY_KEY_DIGEST_DOMAIN, &encrypted))
        );

        write_private(&source_passphrase, b"incorrect passphrase\n");
        assert!(
            apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
                data_dir: data.clone(),
                plan_file: plan_path.clone(),
                expected_confirmation_digest: hex32(&planned.confirmation_digest),
                passphrase_file: keyring_passphrase.clone(),
                keyring_output: data.join("keyring.bin"),
                anchor_output: controls.join("keyring.anchor"),
            })
            .is_err()
        );
        assert!(!data.join("keyring.bin").exists());
        write_private(&source_passphrase, b"legacy correct horse\n");
        apply_legacy_keyring_import(&LegacyKeyringApplyConfig {
            data_dir: data.clone(),
            plan_file: plan_path,
            expected_confirmation_digest: hex32(&planned.confirmation_digest),
            passphrase_file: keyring_passphrase,
            keyring_output: data.join("keyring.bin"),
            anchor_output: controls.join("keyring.anchor"),
        })
        .unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn migration_evidence_is_strict_and_confirmation_hex_is_canonical() {
        let valid = serde_json::json!({
            "schema": V3_MIGRATION_EVIDENCE_SCHEMA,
            "migration_id": hex::encode([1; 32]),
            "migration_decision_id": hex::encode([2; 32]),
            "migration_approval_digest": hex::encode([3; 32]),
            "new_journal_instance_id": hex::encode([4; 32]),
            "initial_policy_time_watermark_unix_seconds": "1",
            "released_records": []
        });
        assert!(serde_json::from_value::<V3MigrationEvidenceDocument>(valid.clone()).is_ok());
        let mut invalid = valid;
        invalid["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<V3MigrationEvidenceDocument>(invalid).is_err());
        assert!(decode_hex32(&"AB".repeat(32), "uppercase").is_err());
        assert!(parse_canonical_u64("01", "number").is_err());
    }

    #[test]
    fn migration_cutover_watermark_is_a_bounded_future_horizon() {
        let mut evidence = V3MigrationEvidenceDocument {
            schema: V3_MIGRATION_EVIDENCE_SCHEMA.to_owned(),
            migration_id: hex::encode(marker(1)),
            migration_decision_id: hex::encode(marker(2)),
            migration_approval_digest: hex::encode(marker(3)),
            new_journal_instance_id: hex::encode(marker(4)),
            initial_policy_time_watermark_unix_seconds: "1000".to_owned(),
            released_records: Vec::new(),
        };
        assert_eq!(
            validate_migration_cutover_horizon(&evidence, 100).unwrap(),
            1000
        );
        assert!(validate_migration_cutover_horizon(&evidence, 99).is_err());
        assert!(validate_migration_cutover_horizon(&evidence, 1001).is_err());
        evidence.initial_policy_time_watermark_unix_seconds = "1001".to_owned();
        assert!(validate_migration_cutover_horizon(&evidence, 100).is_err());
    }

    #[test]
    fn migration_payload_is_bound_to_the_exact_released_v2_record() {
        let (controls, export) = migration_fixture();
        assert_ne!(
            controls.policy.binding.wallet_destination,
            export.wallet_destination
        );
        let legacy = controls
            .keyring
            .key(wallet_key_id(&export.wallet_destination))
            .unwrap();
        assert_eq!(legacy.lifecycle, KeyLifecycle::Retired);
        assert_eq!(legacy.storage, KeyStorageBinding::Local);
        assert_eq!(
            controls.policy.binding.wallet_destination,
            controls.keyring.active_change_key().public_key
        );
        let approval = build_v3_migration_approval_payload(
            &export,
            &controls.policy,
            "migrated-withdrawal-0001",
            marker(0x40),
            90,
            190,
        )
        .unwrap();
        let source = &export.released_records[0];
        let source_anchor = journal_anchor_v3_from_v2(export.source_anchor);
        assert_eq!(approval.action, WithdrawalAction::Release);
        assert_eq!(approval.request_id, source.request.request_id);
        assert_eq!(approval.request_digest, source.request_digest);
        assert_eq!(approval.transaction_signing_digest, source.signing_digest);
        assert_eq!(
            approval.action_anchor,
            ApprovalAnchor {
                key_id: source_anchor.key_id,
                journal_instance_id: source_anchor.journal_instance_id,
                generation: source_anchor.generation,
                commitment: source_anchor.commitment,
            }
        );
        assert_eq!(
            WithdrawalApproval::parse(&serde_json::to_vec(&approval.canonical_document()).unwrap())
                .unwrap(),
            approval
        );
        assert!(
            build_v3_migration_approval_payload(
                &export,
                &controls.policy,
                "unknown-withdrawal",
                marker(0x40),
                90,
                190,
            )
            .is_err()
        );
    }

    #[test]
    fn second_apply_source_load_resumes_after_first_v3_slot_replacement() {
        let root = test_directory();
        let data = root.join("node");
        let security = root.join("v2-security");
        fs::create_dir(&security).unwrap();
        let v2_key = security.join("journal.key");
        let v2_anchor = security.join("journal.anchor");
        write_private(&v2_key, &[0x5a; 32]);
        let v2_security = ExchangeWithdrawalSecurityConfig::new(&v2_key, &v2_anchor);
        let node = Node::open_with_profile_and_exchange_withdrawal_security(
            &data,
            DEVNET_PROFILE,
            &v2_security,
        )
        .unwrap();
        let shared = Arc::new(Mutex::new(node));
        let mut journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        let bootstrap = journal.journal_info().unwrap().current_anchor;
        write_private(&v2_anchor, &encode_external_anchor(&bootstrap).unwrap());
        {
            let mut node = shared.lock().unwrap();
            let destination = node.wallet_destination();
            for height in 1..=100 {
                node.mine_once(
                    destination,
                    DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                    DEFAULT_MINING_ATTEMPTS,
                )
                .unwrap();
            }
        }
        let request = WithdrawalRequest {
            request_id: "migration-resume-withdrawal-0001".to_owned(),
            destination: public_key(0x23),
            amount_atoms: 1,
            fee_atoms: 1,
        };
        let prepared = journal.prepare(&shared, &request).unwrap();
        write_private(
            &v2_anchor,
            &encode_external_anchor(&prepared.prepared_anchor.unwrap()).unwrap(),
        );
        journal.release(&shared, &request.request_id).unwrap();
        let released_anchor = journal.journal_info().unwrap().current_anchor;
        write_private(
            &v2_anchor,
            &encode_external_anchor(&released_anchor).unwrap(),
        );
        let export = ExchangeWithdrawalJournal::export_validated_v2_for_v3_migration(
            &shared.lock().unwrap(),
        )
        .unwrap();
        let (binding, wallet_secret) = {
            let node = shared.lock().unwrap();
            (
                journal_binding_from_node(&node),
                Zeroizing::new(node.wallet_signing_key.to_bytes().into()),
            )
        };
        let keyring = WalletKeyring::new_genesis(
            keyring_binding_from_journal(binding),
            marker(0x24),
            vec![
                WalletKeyEntry::local(
                    wallet_secret,
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Active,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let controls = LoadedMigrationControls {
            binding,
            policy: WithdrawalPolicy {
                binding: WithdrawalPolicyBinding {
                    network_id: binding.network_id,
                    consensus_fingerprint: binding.consensus_fingerprint,
                    genesis_hash: binding.genesis,
                    wallet_destination: export.wallet_destination,
                },
                max_single_amount_atoms: 1_000,
                max_single_fee_atoms: 25,
                max_single_debit_atoms: 1_025,
                max_rolling_24h_debit_atoms: 5_000,
                max_rolling_24h_release_count: 8,
                release_approval: ApprovalRule {
                    threshold: 1,
                    public_keys: vec![public_key(0x11)],
                },
                cancel_approval: ApprovalRule {
                    threshold: 1,
                    public_keys: vec![public_key(0x22)],
                },
            },
            keyring,
        };
        let evidence = V3MigrationEvidenceDocument {
            schema: V3_MIGRATION_EVIDENCE_SCHEMA.to_owned(),
            migration_id: hex::encode(marker(0x42)),
            migration_decision_id: hex::encode(marker(0x43)),
            migration_approval_digest: hex::encode(marker(0x44)),
            new_journal_instance_id: hex::encode(marker(0x45)),
            initial_policy_time_watermark_unix_seconds: "100".to_owned(),
            released_records: vec![V3MigrationReleasedEvidence {
                signed_approval: signed_migration_approval(&controls, &export),
            }],
        };
        let migration = migrate_validated_v2(
            build_migration_input(&export, &evidence, &controls).unwrap(),
            &marker(0x46),
        )
        .unwrap();
        {
            let node = shared.lock().unwrap();
            assert_eq!(
                migration_source_export_for_apply(
                    &node,
                    &data,
                    &export.exact_snapshot_bytes,
                    released_anchor,
                )
                .unwrap(),
                export
            );
        }
        drop(journal);
        drop(shared);

        fs::write(
            data.join("exchange-withdrawals.0.bin"),
            &migration.authenticated_snapshot,
        )
        .unwrap();
        let resumed_node = Node::open_with_profile_and_exchange_withdrawal_security(
            &data,
            DEVNET_PROFILE,
            &v2_security,
        )
        .unwrap();
        assert_eq!(
            migration_source_export_for_apply(
                &resumed_node,
                &data,
                &export.exact_snapshot_bytes,
                released_anchor,
            )
            .unwrap(),
            export
        );
        drop(resumed_node);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_confirmation_rejects_changed_key_and_initial_anchor_before_paths() {
        let (original, expected_digest) = migration_plan_confirmation_fixture();
        validate_migration_plan_confirmation(
            &original,
            expected_digest,
            &original.data_dir,
            &original.plan_file,
        )
        .unwrap();

        let mut changed = original.clone();
        changed.journal_key_file = PathBuf::from("C:/controls/replacement-journal.key");
        changed.journal_key_id = hex::encode(marker(0x61));
        changed.initial_anchor.key_id = hex::encode(marker(0x61));
        changed.initial_anchor.commitment = hex::encode(marker(0x62));
        changed.plan_digest = hex::encode(migration_plan_digest(&changed).unwrap());
        assert!(matches!(
            validate_migration_plan_confirmation(
                &changed,
                expected_digest,
                &original.data_dir,
                &original.plan_file,
            ),
            Err(ExchangeCustodyToolError::ConfirmationMismatch)
        ));
    }

    #[test]
    fn migration_confirmation_rejects_changed_anchor_output_before_paths() {
        let (original, expected_digest) = migration_plan_confirmation_fixture();
        let mut changed = original.clone();
        changed.v3_anchor_output = PathBuf::from("C:/controls/attacker-v3-anchor.json");
        changed.plan_digest = hex::encode(migration_plan_digest(&changed).unwrap());
        assert!(matches!(
            validate_migration_plan_confirmation(
                &changed,
                expected_digest,
                &original.data_dir,
                &original.plan_file,
            ),
            Err(ExchangeCustodyToolError::ConfirmationMismatch)
        ));
    }

    #[test]
    fn migration_derives_terminal_evidence_from_a_verified_signed_approval() {
        let (controls, export) = migration_fixture();
        let signed_approval = signed_migration_approval(&controls, &export);
        let parsed = WithdrawalApproval::parse(&serde_json::to_vec(&signed_approval).unwrap())
            .expect("test approval is canonical");
        let evidence = V3MigrationEvidenceDocument {
            schema: V3_MIGRATION_EVIDENCE_SCHEMA.to_owned(),
            migration_id: hex::encode(marker(0x42)),
            migration_decision_id: hex::encode(marker(0x43)),
            migration_approval_digest: hex::encode(marker(0x44)),
            new_journal_instance_id: hex::encode(marker(0x45)),
            initial_policy_time_watermark_unix_seconds: "100".to_owned(),
            released_records: vec![V3MigrationReleasedEvidence { signed_approval }],
        };

        let input = build_migration_input(&export, &evidence, &controls).unwrap();
        let terminal = &input.released_records[0].terminal;
        assert_eq!(terminal.decision_id, parsed.decision_id);
        assert_eq!(terminal.approval_digest, parsed.signing_digest());
        assert_eq!(
            terminal.decided_at_unix_seconds,
            parsed.authorized_at_unix_seconds
        );
        assert_eq!(terminal.accounted_at_unix_seconds, 100);
        assert_eq!(input.initial_policy_window.release_events.len(), 1);
        assert_eq!(
            input.initial_policy_window.release_events[0].released_at_unix_seconds,
            100
        );
        assert_eq!(
            terminal.action_anchor,
            journal_anchor_v3_from_v2(export.source_anchor)
        );
        assert_eq!(
            terminal.request_digest,
            export.released_records[0].request_digest
        );
        assert_eq!(
            terminal.transaction_signing_digest,
            export.released_records[0].signing_digest
        );
        migrate_validated_v2(input, &marker(0x46)).unwrap();
    }

    #[test]
    fn migration_charges_backdated_releases_at_cutover_instead_of_aging_them_out() {
        let (controls, export) = migration_fixture();
        let signed_approval = signed_migration_approval(&controls, &export);
        let cutover = 90 + 86_400 + 1;
        let evidence = V3MigrationEvidenceDocument {
            schema: V3_MIGRATION_EVIDENCE_SCHEMA.to_owned(),
            migration_id: hex::encode(marker(0x52)),
            migration_decision_id: hex::encode(marker(0x53)),
            migration_approval_digest: hex::encode(marker(0x54)),
            new_journal_instance_id: hex::encode(marker(0x55)),
            initial_policy_time_watermark_unix_seconds: cutover.to_string(),
            released_records: vec![V3MigrationReleasedEvidence { signed_approval }],
        };

        let input = build_migration_input(&export, &evidence, &controls).unwrap();
        assert_eq!(
            input.initial_policy_window.time_watermark_unix_seconds,
            cutover
        );
        assert_eq!(input.initial_policy_window.release_events.len(), 1);
        assert_eq!(
            input.initial_policy_window.release_events[0].released_at_unix_seconds,
            cutover
        );
        assert_eq!(
            input.released_records[0].terminal.accounted_at_unix_seconds,
            cutover
        );
    }

    #[test]
    fn migration_rejects_historical_totals_above_the_new_rolling_policy() {
        let (mut controls, export) = migration_fixture();
        controls.policy.max_rolling_24h_debit_atoms = 719;
        let signed_approval = signed_migration_approval(&controls, &export);
        let evidence = V3MigrationEvidenceDocument {
            schema: V3_MIGRATION_EVIDENCE_SCHEMA.to_owned(),
            migration_id: hex::encode(marker(0x62)),
            migration_decision_id: hex::encode(marker(0x63)),
            migration_approval_digest: hex::encode(marker(0x64)),
            new_journal_instance_id: hex::encode(marker(0x65)),
            initial_policy_time_watermark_unix_seconds: "100".to_owned(),
            released_records: vec![V3MigrationReleasedEvidence { signed_approval }],
        };

        assert!(matches!(
            build_migration_input(&export, &evidence, &controls),
            Err(ExchangeCustodyToolError::InvalidDocument(
                "migrated releases exceed the supplied rolling policy"
            ))
        ));
    }

    #[test]
    fn migration_rejects_tampered_or_parallel_approval_evidence() {
        let (controls, export) = migration_fixture();
        let mut tampered = signed_migration_approval(&controls, &export);
        tampered["signatures"][0]["signature"] = serde_json::json!(hex::encode([0xa5; 64]));
        let evidence = V3MigrationEvidenceDocument {
            schema: V3_MIGRATION_EVIDENCE_SCHEMA.to_owned(),
            migration_id: hex::encode(marker(0x47)),
            migration_decision_id: hex::encode(marker(0x48)),
            migration_approval_digest: hex::encode(marker(0x49)),
            new_journal_instance_id: hex::encode(marker(0x4a)),
            initial_policy_time_watermark_unix_seconds: "100".to_owned(),
            released_records: vec![V3MigrationReleasedEvidence {
                signed_approval: tampered,
            }],
        };
        assert!(matches!(
            build_migration_input(&export, &evidence, &controls),
            Err(ExchangeCustodyToolError::Operation(message))
                if message.contains("approval signature")
        ));

        let old_parallel_fields = serde_json::json!({
            "schema": "common-foundry-exchange-v3-migration-evidence-v1",
            "migration_id": hex::encode(marker(0x47)),
            "migration_decision_id": hex::encode(marker(0x48)),
            "migration_approval_digest": hex::encode(marker(0x49)),
            "new_journal_instance_id": hex::encode(marker(0x4a)),
            "initial_policy_time_watermark_unix_seconds": "100",
            "released_records": [{
                "request_id": export.released_records[0].request.request_id,
                "decision_id": hex::encode(marker(0x41)),
                "approval_digest": hex::encode(marker(0x4b)),
                "decided_at_unix_seconds": "90"
            }]
        });
        assert!(
            serde_json::from_value::<V3MigrationEvidenceDocument>(old_parallel_fields).is_err()
        );
    }

    fn hex32(value: &str) -> [u8; 32] {
        decode_hex32(value, "test hex").unwrap()
    }
}
