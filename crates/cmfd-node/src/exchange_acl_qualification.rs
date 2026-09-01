//! Packaged-host ACL qualification for exchange custody v0.5.
//!
//! Live qualification calls the same retained-handle production validators as
//! the custody runtime and must execute as the configured service identity.
//! Fixture qualification evaluates only normalized dry evidence and is never a
//! host qualification.

#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::exchange_custody_v3::{AclQualificationClassV3, qualify_acl_path_v3};

pub const ACL_QUALIFICATION_CONFIG_SCHEMA: &str = "common-foundry-exchange-custody-acl-config-v1";
pub const ACL_QUALIFICATION_FIXTURE_SCHEMA: &str = "common-foundry-exchange-custody-acl-fixture-v1";
pub const ACL_QUALIFICATION_EVIDENCE_SCHEMA: &str =
    "common-foundry-exchange-custody-acl-qualification-v1";

const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_BYTES: usize = 512;
const MAX_DETAIL_BYTES: usize = 4096;
#[cfg(unix)]
const MAX_UNIX_ACCOUNT_RECORDS: usize = 65_536;

const ARTIFACT_CONTRACT: [(&str, &str, &str); 10] = [
    ("data_directory", "node_directory", "service"),
    ("journal_key", "node_secret", "service"),
    ("withdrawal_anchor", "external_control", "anchor"),
    ("policy", "external_control", "operator"),
    ("keyring", "node_secret", "service"),
    ("keyring_anchor", "external_control", "anchor"),
    ("wallet_passphrase", "external_secret", "operator"),
    ("keyring_passphrase", "external_secret", "operator"),
    ("integration_rpc_auth", "external_secret", "operator"),
    ("withdrawal_rpc_auth", "external_secret", "operator"),
];

#[derive(Debug, Error)]
pub enum AclQualificationError {
    #[error("{operation} `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid ACL qualification document: {0}")]
    InvalidDocument(&'static str),
    #[error("exchange custody ACL validation failed: {0}")]
    Custody(String),
}

impl From<crate::exchange_custody_v3::ExchangeCustodyV3Error> for AclQualificationError {
    fn from(source: crate::exchange_custody_v3::ExchangeCustodyV3Error) -> Self {
        Self::Custody(source.to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveConfig {
    schema: String,
    package_root: PathBuf,
    identities: IdentityConfig,
    windows_additional_authorities: WindowsAdditionalAuthorityConfig,
    #[serde(default)]
    unix_authority_groups: UnixAuthorityGroupConfig,
    artifacts: ArtifactConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityConfig {
    service: String,
    operator: String,
    anchor: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsAdditionalAuthorityConfig {
    package: Vec<String>,
    data_directory: Vec<String>,
    journal_key: Vec<String>,
    withdrawal_anchor: Vec<String>,
    policy: Vec<String>,
    keyring: Vec<String>,
    keyring_anchor: Vec<String>,
    wallet_passphrase: Vec<String>,
    keyring_passphrase: Vec<String>,
    integration_rpc_auth: Vec<String>,
    withdrawal_rpc_auth: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixAuthorityGroupConfig {
    #[serde(default)]
    package: Vec<String>,
    #[serde(default)]
    data_directory: Vec<String>,
    #[serde(default)]
    journal_key: Vec<String>,
    #[serde(default)]
    withdrawal_anchor: Vec<String>,
    #[serde(default)]
    policy: Vec<String>,
    #[serde(default)]
    keyring: Vec<String>,
    #[serde(default)]
    keyring_anchor: Vec<String>,
    #[serde(default)]
    wallet_passphrase: Vec<String>,
    #[serde(default)]
    keyring_passphrase: Vec<String>,
    #[serde(default)]
    integration_rpc_auth: Vec<String>,
    #[serde(default)]
    withdrawal_rpc_auth: Vec<String>,
}

impl WindowsAdditionalAuthorityConfig {
    fn names(&self, name: &str) -> &[String] {
        match name {
            "package" => &self.package,
            "data_directory" => &self.data_directory,
            "journal_key" => &self.journal_key,
            "withdrawal_anchor" => &self.withdrawal_anchor,
            "policy" => &self.policy,
            "keyring" => &self.keyring,
            "keyring_anchor" => &self.keyring_anchor,
            "wallet_passphrase" => &self.wallet_passphrase,
            "keyring_passphrase" => &self.keyring_passphrase,
            "integration_rpc_auth" => &self.integration_rpc_auth,
            "withdrawal_rpc_auth" => &self.withdrawal_rpc_auth,
            _ => unreachable!("fixed Windows authority contract"),
        }
    }

    fn all(&self) -> impl Iterator<Item = &[String]> {
        std::iter::once(self.package.as_slice()).chain(
            ARTIFACT_CONTRACT
                .into_iter()
                .map(|(name, _, _)| self.names(name)),
        )
    }
}

impl UnixAuthorityGroupConfig {
    fn names(&self, name: &str) -> &[String] {
        match name {
            "package" => &self.package,
            "data_directory" => &self.data_directory,
            "journal_key" => &self.journal_key,
            "withdrawal_anchor" => &self.withdrawal_anchor,
            "policy" => &self.policy,
            "keyring" => &self.keyring,
            "keyring_anchor" => &self.keyring_anchor,
            "wallet_passphrase" => &self.wallet_passphrase,
            "keyring_passphrase" => &self.keyring_passphrase,
            "integration_rpc_auth" => &self.integration_rpc_auth,
            "withdrawal_rpc_auth" => &self.withdrawal_rpc_auth,
            _ => unreachable!("fixed Unix authority-group contract"),
        }
    }

    fn all(&self) -> impl Iterator<Item = &[String]> {
        std::iter::once(self.package.as_slice()).chain(
            ARTIFACT_CONTRACT
                .into_iter()
                .map(|(name, _, _)| self.names(name)),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactConfig {
    data_directory: PathBuf,
    journal_key: PathBuf,
    withdrawal_anchor: PathBuf,
    policy: PathBuf,
    keyring: PathBuf,
    keyring_anchor: PathBuf,
    wallet_passphrase: PathBuf,
    keyring_passphrase: PathBuf,
    integration_rpc_auth: PathBuf,
    withdrawal_rpc_auth: PathBuf,
}

impl ArtifactConfig {
    fn path(&self, name: &str) -> &Path {
        match name {
            "data_directory" => &self.data_directory,
            "journal_key" => &self.journal_key,
            "withdrawal_anchor" => &self.withdrawal_anchor,
            "policy" => &self.policy,
            "keyring" => &self.keyring,
            "keyring_anchor" => &self.keyring_anchor,
            "wallet_passphrase" => &self.wallet_passphrase,
            "keyring_passphrase" => &self.keyring_passphrase,
            "integration_rpc_auth" => &self.integration_rpc_auth,
            "withdrawal_rpc_auth" => &self.withdrawal_rpc_auth,
            _ => unreachable!("fixed artifact contract"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityFact {
    pub configured: String,
    pub exists: bool,
    pub resolved_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityFacts {
    pub service: IdentityFact,
    pub operator: IdentityFact,
    pub anchor: IdentityFact,
    pub current_process_id: String,
    pub current_process_is_service: bool,
    pub current_process_is_privileged: bool,
}

impl IdentityFacts {
    fn fact(&self, role: &str) -> &IdentityFact {
        match role {
            "service" => &self.service,
            "operator" => &self.operator,
            "anchor" => &self.anchor,
            _ => unreachable!("fixed identity role"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageFact {
    pub root: PathBuf,
    pub node: PathBuf,
    pub present: bool,
    pub layout_matches: bool,
    pub running_from_package: bool,
    pub owner_id: String,
    pub owner_matches_operator: bool,
    pub allowed_authority_ids: Vec<String>,
    pub authority_allowlist_valid: bool,
    pub runtime_acl_valid: bool,
    pub node_sha256: String,
    pub version: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFact {
    pub name: String,
    pub path: PathBuf,
    pub kind: String,
    pub authority: String,
    pub present: bool,
    pub layout_valid: bool,
    pub owner_id: String,
    pub owner_matches_authority: bool,
    pub allowed_authority_ids: Vec<String>,
    pub authority_allowlist_valid: bool,
    pub runtime_acl_valid: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualificationFixture {
    pub schema: String,
    pub platform: String,
    pub identities: IdentityFacts,
    pub package: PackageFact,
    pub artifacts: Vec<ArtifactFact>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QualificationCheck {
    pub id: String,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QualificationEvidence {
    pub schema: &'static str,
    pub qualification_scope: &'static str,
    pub evaluated_at_unix_seconds: u64,
    pub input_document_sha256: String,
    pub platform: String,
    pub result: &'static str,
    pub host_qualified: bool,
    pub fixture_qualified: bool,
    pub identities: IdentityFacts,
    pub package: PackageFact,
    pub artifacts: Vec<ArtifactFact>,
    pub checks: Vec<QualificationCheck>,
    pub limitations: Vec<&'static str>,
}

pub fn qualify_installed_host(
    config_file: &Path,
    output: &Path,
) -> Result<QualificationEvidence, AclQualificationError> {
    let (config, input_document_sha256): (LiveConfig, String) =
        read_document(config_file, "ACL qualification config")?;
    if config.schema != ACL_QUALIFICATION_CONFIG_SCHEMA {
        return Err(AclQualificationError::InvalidDocument(
            "unsupported live config schema",
        ));
    }
    validate_config(&config)?;
    let identities = collect_identity_facts(&config.identities, config_file);
    let package = collect_package_fact(&config, &identities);
    let artifacts = collect_artifact_facts(&config, &identities);
    let fixture = QualificationFixture {
        schema: ACL_QUALIFICATION_FIXTURE_SCHEMA.to_owned(),
        platform: current_platform().to_owned(),
        identities,
        package,
        artifacts,
    };
    let evidence = evaluate(fixture, false, input_document_sha256)?;
    write_evidence_create_new(output, &evidence)?;
    Ok(evidence)
}

pub fn qualify_fixture(
    fixture_file: &Path,
    output: &Path,
) -> Result<QualificationEvidence, AclQualificationError> {
    let (fixture, input_document_sha256): (QualificationFixture, String) =
        read_document(fixture_file, "ACL fixture snapshot")?;
    let evidence = evaluate(fixture, true, input_document_sha256)?;
    write_evidence_create_new(output, &evidence)?;
    Ok(evidence)
}

fn validate_config(config: &LiveConfig) -> Result<(), AclQualificationError> {
    if !config.package_root.is_absolute()
        || [
            &config.identities.service,
            &config.identities.operator,
            &config.identities.anchor,
        ]
        .into_iter()
        .any(|value| {
            value.is_empty()
                || value.len() > MAX_IDENTITY_BYTES
                || value.contains('\0')
                || value
                    .chars()
                    .any(|character| matches!(character, '\r' | '\n'))
        })
    {
        return Err(AclQualificationError::InvalidDocument(
            "package root and identities must be absolute/bounded",
        ));
    }
    let mut paths = Vec::with_capacity(ARTIFACT_CONTRACT.len());
    for (name, _, _) in ARTIFACT_CONTRACT {
        let path = config.artifacts.path(name);
        if !path.is_absolute() {
            return Err(AclQualificationError::InvalidDocument(
                "all artifact paths must be absolute",
            ));
        }
        if paths.contains(&path) {
            return Err(AclQualificationError::InvalidDocument(
                "artifact paths must be unique",
            ));
        }
        paths.push(path);
    }
    for names in config
        .windows_additional_authorities
        .all()
        .chain(config.unix_authority_groups.all())
    {
        if names.len() > 16
            || names.iter().any(|name| {
                name.is_empty()
                    || name.len() > MAX_IDENTITY_BYTES
                    || name
                        .chars()
                        .any(|character| matches!(character, '\r' | '\n' | '\0'))
            })
            || names
                .iter()
                .enumerate()
                .any(|(index, name)| names[..index].contains(name))
        {
            return Err(AclQualificationError::InvalidDocument(
                "additional-authority lists must be bounded and unique",
            ));
        }
    }
    #[cfg(not(windows))]
    if config
        .windows_additional_authorities
        .all()
        .any(|names| !names.is_empty())
    {
        return Err(AclQualificationError::InvalidDocument(
            "Windows additional authorities must be empty on this platform",
        ));
    }
    #[cfg(windows)]
    if config
        .unix_authority_groups
        .all()
        .any(|names| !names.is_empty())
    {
        return Err(AclQualificationError::InvalidDocument(
            "Unix authority groups must be empty on this platform",
        ));
    }
    Ok(())
}

fn collect_identity_facts(config: &IdentityConfig, context: &Path) -> IdentityFacts {
    let service = resolve_identity(&config.service, context);
    let operator = resolve_identity(&config.operator, context);
    let anchor = resolve_identity(&config.anchor, context);
    let (current_process_id, privileged) =
        current_process_identity(context).unwrap_or_else(|_| (String::new(), true));
    let current_process_is_service = service.exists
        && !current_process_id.is_empty()
        && current_process_id == service.resolved_id;
    IdentityFacts {
        service,
        operator,
        anchor,
        current_process_id,
        current_process_is_service,
        current_process_is_privileged: privileged,
    }
}

fn resolve_identity(configured: &str, context: &Path) -> IdentityFact {
    match platform_identity_id(configured, context) {
        Ok(resolved_id) => IdentityFact {
            configured: configured.to_owned(),
            exists: true,
            resolved_id,
        },
        Err(_) => IdentityFact {
            configured: configured.to_owned(),
            exists: false,
            resolved_id: String::new(),
        },
    }
}

fn collect_package_fact(config: &LiveConfig, identities: &IdentityFacts) -> PackageFact {
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let node = config.package_root.join(format!("cmfd-node{suffix}"));
    let expected_root = format!("commonfoundry-rc-runtime-{}-x86_64", current_platform());
    let layout_matches = config
        .package_root
        .file_name()
        .and_then(|value| value.to_str())
        == Some(expected_root.as_str())
        && node.parent() == Some(config.package_root.as_path());
    let present = direct_directory(&config.package_root) && direct_file(&node);
    let running_from_package = canonical_matches_current_executable(&node);
    let (allowed_authority_ids, authorities_resolved) = expected_authority_ids(
        identities,
        &["service", "operator"],
        config.windows_additional_authorities.names("package"),
        config.unix_authority_groups.names("package"),
        &node,
    );
    let mut fact = PackageFact {
        root: config.package_root.clone(),
        node: node.clone(),
        present,
        layout_matches,
        running_from_package,
        owner_id: String::new(),
        owner_matches_operator: false,
        allowed_authority_ids,
        authority_allowlist_valid: false,
        runtime_acl_valid: false,
        node_sha256: String::new(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        detail: "installed package is absent or invalid".to_owned(),
    };
    if !present {
        return fact;
    }
    if !authorities_resolved {
        fact.detail =
            "one or more configured package authorities did not resolve uniquely".to_owned();
        return fact;
    }
    match qualify_acl_path_v3(
        &config.artifacts.data_directory,
        &node,
        AclQualificationClassV3::ExternalControl,
        &fact.allowed_authority_ids,
    ) {
        Ok(owner_id) => {
            fact.owner_matches_operator =
                identities.operator.exists && owner_id == identities.operator.resolved_id;
            fact.owner_id = owner_id;
            fact.authority_allowlist_valid = true;
            fact.runtime_acl_valid = true;
            match sha256_file(&node) {
                Ok(digest) => {
                    fact.node_sha256 = digest;
                    fact.detail =
                        "packaged node passed the production external-control validator".to_owned();
                }
                Err(error) => {
                    fact.runtime_acl_valid = false;
                    fact.detail = bounded_detail(&error.to_string());
                }
            }
        }
        Err(error) => fact.detail = bounded_detail(&error.to_string()),
    }
    fact
}

fn collect_artifact_facts(config: &LiveConfig, identities: &IdentityFacts) -> Vec<ArtifactFact> {
    ARTIFACT_CONTRACT
        .into_iter()
        .map(|(name, kind, authority)| {
            let path = config.artifacts.path(name);
            let present = if kind == "node_directory" {
                direct_directory(path)
            } else {
                direct_file(path)
            };
            let layout_valid = artifact_layout_valid(name, path, &config.artifacts.data_directory);
            let base_roles: &[&str] = if authority == "service" {
                &["service"]
            } else {
                &["service", authority]
            };
            let (allowed_authority_ids, authorities_resolved) = expected_authority_ids(
                identities,
                base_roles,
                config.windows_additional_authorities.names(name),
                config.unix_authority_groups.names(name),
                path,
            );
            let mut fact = ArtifactFact {
                name: name.to_owned(),
                path: path.to_path_buf(),
                kind: kind.to_owned(),
                authority: authority.to_owned(),
                present,
                layout_valid,
                owner_id: String::new(),
                owner_matches_authority: false,
                allowed_authority_ids,
                authority_allowlist_valid: false,
                runtime_acl_valid: false,
                detail: "configured custody path is absent or invalid".to_owned(),
            };
            if !present || !layout_valid {
                return fact;
            }
            if !authorities_resolved {
                fact.detail =
                    "one or more configured artifact authorities did not resolve uniquely"
                        .to_owned();
                return fact;
            }
            let class = match kind {
                "node_directory" => AclQualificationClassV3::NodeDataDirectory,
                "node_secret" => AclQualificationClassV3::NodeSecret,
                "external_control" => AclQualificationClassV3::ExternalControl,
                "external_secret" => AclQualificationClassV3::ExternalSecret,
                _ => unreachable!("fixed artifact class"),
            };
            match qualify_acl_path_v3(
                &config.artifacts.data_directory,
                path,
                class,
                &fact.allowed_authority_ids,
            ) {
                Ok(owner_id) => {
                    fact.owner_matches_authority = identities.fact(authority).exists
                        && owner_id == identities.fact(authority).resolved_id;
                    fact.owner_id = owner_id;
                    fact.authority_allowlist_valid = true;
                    fact.runtime_acl_valid = true;
                    fact.detail =
                        "production retained-handle ACL validator accepted the path".to_owned();
                }
                Err(error) => fact.detail = bounded_detail(&error.to_string()),
            }
            fact
        })
        .collect()
}

fn artifact_layout_valid(name: &str, path: &Path, data_dir: &Path) -> bool {
    let Ok(path) = fs::canonicalize(path) else {
        return false;
    };
    let Ok(data_dir) = fs::canonicalize(data_dir) else {
        return false;
    };
    match name {
        "data_directory" => path == data_dir,
        "keyring" => path.starts_with(&data_dir),
        _ => !path.starts_with(&data_dir),
    }
}

fn evaluate(
    fixture: QualificationFixture,
    fixture_mode: bool,
    input_document_sha256: String,
) -> Result<QualificationEvidence, AclQualificationError> {
    validate_fixture(&fixture)?;
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "identity.service_exists",
        fixture.identities.service.exists,
        "configured service identity resolves",
    );
    push_check(
        &mut checks,
        "identity.operator_exists",
        fixture.identities.operator.exists,
        "configured operator identity resolves",
    );
    push_check(
        &mut checks,
        "identity.anchor_exists",
        fixture.identities.anchor.exists,
        "configured anchor identity resolves",
    );
    let ids = [
        fixture.identities.service.resolved_id.as_str(),
        fixture.identities.operator.resolved_id.as_str(),
        fixture.identities.anchor.resolved_id.as_str(),
    ];
    push_check(
        &mut checks,
        "identity.roles_distinct",
        ids.iter().all(|value| !value.is_empty())
            && ids[0] != ids[1]
            && ids[0] != ids[2]
            && ids[1] != ids[2],
        "service, operator, and anchor identities are distinct",
    );
    push_check(
        &mut checks,
        "identity.current_process",
        fixture.identities.current_process_is_service,
        "qualification executes as the configured service process identity",
    );
    push_check(
        &mut checks,
        "identity.unprivileged",
        !fixture.identities.current_process_is_privileged,
        "service process is non-root/non-elevated and has no privileged credential state",
    );
    for (id, passed, detail) in [
        (
            "package.present",
            fixture.package.present,
            "installed package root and node exist",
        ),
        (
            "package.layout",
            fixture.package.layout_matches,
            "package uses the fixed release root and node location",
        ),
        (
            "package.running",
            fixture.package.running_from_package,
            "the qualifying process is the configured packaged node",
        ),
        (
            "package.owner",
            fixture.package.owner_matches_operator,
            "packaged node owner is the configured operator identity",
        ),
        (
            "package.runtime_acl",
            fixture.package.runtime_acl_valid,
            "packaged node passed the production retained-handle ACL validator",
        ),
        (
            "package.authority_allowlist",
            authority_allowlist_fact_valid(
                fixture.package.authority_allowlist_valid,
                &fixture.package.allowed_authority_ids,
                &fixture.package.owner_id,
            ),
            "packaged node and ancestor authority is confined to the explicit authority-ID allowlist",
        ),
        (
            "package.sha256",
            is_lower_hex_256(&fixture.package.node_sha256),
            "packaged node SHA-256 is present",
        ),
    ] {
        push_check(&mut checks, id, passed, detail);
    }
    for ((name, kind, authority), artifact) in ARTIFACT_CONTRACT.into_iter().zip(&fixture.artifacts)
    {
        let prefix = format!("artifact.{name}");
        push_check(
            &mut checks,
            &format!("{prefix}.contract"),
            artifact.name == name && artifact.kind == kind && artifact.authority == authority,
            "artifact name, security class, and authority match the fixed contract",
        );
        push_check(
            &mut checks,
            &format!("{prefix}.present"),
            artifact.present,
            "configured artifact exists as a direct object",
        );
        push_check(
            &mut checks,
            &format!("{prefix}.layout"),
            artifact.layout_valid,
            "artifact is on the required side of the node data-directory boundary",
        );
        push_check(
            &mut checks,
            &format!("{prefix}.owner"),
            artifact.owner_matches_authority,
            "artifact owner matches its configured service/operator/anchor authority",
        );
        push_check(
            &mut checks,
            &format!("{prefix}.authority_allowlist"),
            authority_allowlist_fact_valid(
                artifact.authority_allowlist_valid,
                &artifact.allowed_authority_ids,
                &artifact.owner_id,
            ),
            "protected file and ancestor access is confined to the explicit authority-ID allowlist",
        );
        push_check(
            &mut checks,
            &format!("{prefix}.runtime_acl"),
            artifact.runtime_acl_valid,
            "production runtime validator accepted protected access and the complete required ancestor chain",
        );
    }
    let passed = checks.iter().all(|check| check.status == "pass");
    Ok(QualificationEvidence {
        schema: ACL_QUALIFICATION_EVIDENCE_SCHEMA,
        qualification_scope: if fixture_mode {
            "fixture"
        } else {
            "installed_host"
        },
        evaluated_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AclQualificationError::InvalidDocument("system clock is before epoch"))?
            .as_secs(),
        input_document_sha256,
        platform: fixture.platform,
        result: if passed {
            if fixture_mode {
                "fixture_qualified"
            } else {
                "host_qualified"
            }
        } else {
            "rejected"
        },
        host_qualified: passed && !fixture_mode,
        fixture_qualified: passed && fixture_mode,
        identities: fixture.identities,
        package: fixture.package,
        artifacts: fixture.artifacts,
        checks,
        limitations: vec![
            if fixture_mode {
                "Fixture qualification never establishes an installed-host result."
            } else {
                "ACL qualification is necessary but successful v0.5 startup remains the final retained-state gate."
            },
            "Administrator, LocalSystem, root, kernel, and physical-host compromise are outside this boundary.",
            "ACL qualification does not establish filesystem locality, storage durability, or power-loss behavior.",
        ],
    })
}

fn validate_fixture(fixture: &QualificationFixture) -> Result<(), AclQualificationError> {
    if fixture.schema != ACL_QUALIFICATION_FIXTURE_SCHEMA
        || !matches!(fixture.platform.as_str(), "windows" | "linux")
        || fixture.artifacts.len() != ARTIFACT_CONTRACT.len()
    {
        return Err(AclQualificationError::InvalidDocument(
            "fixture schema, platform, or artifact count is invalid",
        ));
    }
    for identity in [
        &fixture.identities.service,
        &fixture.identities.operator,
        &fixture.identities.anchor,
    ] {
        if identity.configured.is_empty()
            || identity.configured.len() > MAX_IDENTITY_BYTES
            || identity
                .configured
                .chars()
                .any(|character| matches!(character, '\r' | '\n' | '\0'))
            || identity.exists == identity.resolved_id.is_empty()
        {
            return Err(AclQualificationError::InvalidDocument(
                "fixture identity is invalid",
            ));
        }
    }
    if fixture.identities.current_process_id.is_empty()
        || fixture.package.version.is_empty()
        || has_duplicates(&fixture.package.allowed_authority_ids)
        || fixture.package.detail.len() > MAX_DETAIL_BYTES
        || fixture.artifacts.iter().any(|artifact| {
            artifact.detail.len() > MAX_DETAIL_BYTES
                || has_duplicates(&artifact.allowed_authority_ids)
        })
    {
        return Err(AclQualificationError::InvalidDocument(
            "fixture contains an empty or oversized field",
        ));
    }
    for ((name, kind, authority), artifact) in ARTIFACT_CONTRACT.into_iter().zip(&fixture.artifacts)
    {
        if artifact.name != name || artifact.kind != kind || artifact.authority != authority {
            return Err(AclQualificationError::InvalidDocument(
                "fixture artifact contract or ordering is invalid",
            ));
        }
    }
    Ok(())
}

fn push_check(checks: &mut Vec<QualificationCheck>, id: &str, passed: bool, detail: &str) {
    checks.push(QualificationCheck {
        id: id.to_owned(),
        status: if passed { "pass" } else { "fail" },
        detail: detail.to_owned(),
    });
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn authority_allowlist_fact_valid(declared: bool, values: &[String], owner_id: &str) -> bool {
    declared
        && !values.is_empty()
        && !owner_id.is_empty()
        && !has_duplicates(values)
        && values.iter().any(|value| value == owner_id)
}

fn expected_authority_ids(
    identities: &IdentityFacts,
    base_roles: &[&str],
    windows_additional_names: &[String],
    unix_group_names: &[String],
    context: &Path,
) -> (Vec<String>, bool) {
    let mut resolved = true;
    let mut ids = Vec::with_capacity(
        base_roles.len() + windows_additional_names.len() + unix_group_names.len() + 1,
    );
    for role in base_roles {
        let fact = identities.fact(role);
        if fact.exists {
            ids.push(fact.resolved_id.clone());
        } else {
            resolved = false;
        }
    }
    #[cfg(windows)]
    for name in windows_additional_names {
        match platform_identity_id(name, context) {
            Ok(id) => ids.push(id),
            Err(_) => resolved = false,
        }
    }
    #[cfg(unix)]
    {
        if !windows_additional_names.is_empty() {
            resolved = false;
        }
        ids.push(unix_uid_id(0));
        let allowed_uids = ids
            .iter()
            .filter_map(|id| parse_unix_authority_id(id, "uid:"))
            .collect::<BTreeSet<_>>();
        for name in unix_group_names {
            match resolve_unix_group_authority(name, &allowed_uids, context) {
                Ok(id) => ids.push(id),
                Err(_) => resolved = false,
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (windows_additional_names, unix_group_names, context);
        resolved = false;
    }
    #[cfg(windows)]
    if !unix_group_names.is_empty() {
        resolved = false;
    }
    ids.sort();
    let before = ids.len();
    ids.dedup();
    if ids.len() != before {
        resolved = false;
    }
    (ids, resolved)
}

fn current_platform() -> &'static str {
    if cfg!(windows) { "windows" } else { "linux" }
}

fn direct_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_file() && !metadata_is_reparse(&metadata))
}

fn direct_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_dir() && !metadata_is_reparse(&metadata))
}

fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn canonical_matches_current_executable(path: &Path) -> bool {
    fs::canonicalize(path)
        .ok()
        .zip(
            std::env::current_exe()
                .ok()
                .and_then(|value| fs::canonicalize(value).ok()),
        )
        .is_some_and(|(configured, current)| configured == current)
}

fn sha256_file(path: &Path) -> Result<String, AclQualificationError> {
    let mut file = File::open(path)
        .map_err(|source| io_error("open packaged node for hashing", path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| io_error("hash packaged node", path, source))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn is_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bounded_detail(value: &str) -> String {
    value.chars().take(MAX_DETAIL_BYTES).collect()
}

fn read_document<T: for<'de> Deserialize<'de>>(
    path: &Path,
    kind: &'static str,
) -> Result<(T, String), AclQualificationError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error("open qualification input", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect qualification input", path, source))?;
    if !metadata.file_type().is_file()
        || metadata_is_reparse(&metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_DOCUMENT_BYTES as u64
    {
        return Err(AclQualificationError::InvalidDocument(kind));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read qualification input", path, source))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(AclQualificationError::InvalidDocument(kind));
    }
    let digest = hex::encode(Sha256::digest(&bytes));
    let document =
        serde_json::from_slice(&bytes).map_err(|_| AclQualificationError::InvalidDocument(kind))?;
    Ok((document, digest))
}

fn write_evidence_create_new(
    path: &Path,
    evidence: &QualificationEvidence,
) -> Result<(), AclQualificationError> {
    if !path.is_absolute() {
        return Err(AclQualificationError::InvalidDocument(
            "evidence output path must be absolute",
        ));
    }
    let mut bytes = serde_json::to_vec(evidence)
        .map_err(|_| AclQualificationError::InvalidDocument("evidence encoding failed"))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create ACL qualification evidence", path, source))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|source| io_error("write ACL qualification evidence", path, source))
}

#[cfg(unix)]
fn platform_identity_id(name: &str, _context: &Path) -> Result<String, AclQualificationError> {
    unix_passwd_record(name).map(|(uid, _)| unix_uid_id(uid))
}

#[cfg(unix)]
fn unix_passwd_record(name: &str) -> Result<(libc::uid_t, libc::gid_t), AclQualificationError> {
    if name.is_empty() || name.len() > MAX_IDENTITY_BYTES || name.contains('\0') {
        return Err(AclQualificationError::InvalidDocument(
            "invalid Unix identity",
        ));
    }
    let encoded = CString::new(name)
        .map_err(|_| AclQualificationError::InvalidDocument("invalid Unix identity"))?;
    let mut capacity = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if capacity < 1024 {
        capacity = 16 * 1024;
    }
    let mut buffer = vec![
        0_u8;
        usize::try_from(capacity)
            .unwrap_or(16 * 1024)
            .min(1024 * 1024)
    ];
    loop {
        let mut record = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwnam_r(
                encoded.as_ptr(),
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == 0 && !result.is_null() {
            return Ok((record.pw_uid, record.pw_gid));
        }
        if status == 0 || status != libc::ERANGE || buffer.len() >= 1024 * 1024 {
            return Err(AclQualificationError::InvalidDocument(
                "configured Unix identity does not resolve",
            ));
        }
        buffer.resize((buffer.len() * 2).min(1024 * 1024), 0);
    }
}

#[cfg(unix)]
fn unix_uid_id(uid: libc::uid_t) -> String {
    format!("uid:{uid}")
}

#[cfg(unix)]
fn unix_gid_id(gid: libc::gid_t) -> String {
    format!("gid:{gid}")
}

#[cfg(unix)]
fn parse_unix_authority_id(value: &str, prefix: &str) -> Option<u32> {
    let digits = value.strip_prefix(prefix)?;
    if digits.is_empty() || digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
}

#[cfg(unix)]
fn resolve_unix_group_authority(
    name: &str,
    allowed_uids: &BTreeSet<libc::uid_t>,
    _context: &Path,
) -> Result<String, AclQualificationError> {
    if name.is_empty() || name.len() > MAX_IDENTITY_BYTES || name.contains('\0') {
        return Err(AclQualificationError::InvalidDocument(
            "invalid Unix authority group",
        ));
    }
    let encoded = CString::new(name)
        .map_err(|_| AclQualificationError::InvalidDocument("invalid Unix authority group"))?;
    let mut capacity = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    if capacity < 1024 {
        capacity = 16 * 1024;
    }
    let mut buffer = vec![
        0_u8;
        usize::try_from(capacity)
            .unwrap_or(16 * 1024)
            .min(1024 * 1024)
    ];
    loop {
        let mut record = unsafe { std::mem::zeroed::<libc::group>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getgrnam_r(
                encoded.as_ptr(),
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == 0 && !result.is_null() {
            let mut member_uids = unix_supplementary_group_members(&record)?;
            member_uids.extend(unix_primary_group_members(record.gr_gid)?);
            validate_unix_group_members(&member_uids, allowed_uids)?;
            return Ok(unix_gid_id(record.gr_gid));
        }
        if status == 0 || status != libc::ERANGE || buffer.len() >= 1024 * 1024 {
            return Err(AclQualificationError::InvalidDocument(
                "configured Unix authority group does not resolve",
            ));
        }
        buffer.resize((buffer.len() * 2).min(1024 * 1024), 0);
    }
}

#[cfg(unix)]
fn unix_supplementary_group_members(
    record: &libc::group,
) -> Result<BTreeSet<libc::uid_t>, AclQualificationError> {
    let mut members = BTreeSet::new();
    if record.gr_mem.is_null() {
        return Ok(members);
    }
    for index in 0..MAX_UNIX_ACCOUNT_RECORDS {
        // SAFETY: getgrnam_r returned a null-terminated gr_mem vector whose
        // backing buffer remains alive for this entire call.
        let member = unsafe { *record.gr_mem.add(index) };
        if member.is_null() {
            return Ok(members);
        }
        // SAFETY: each non-null gr_mem element is a NUL-terminated account name.
        let name = unsafe { CStr::from_ptr(member) }
            .to_str()
            .map_err(|_| AclQualificationError::InvalidDocument("non-UTF-8 Unix group member"))?;
        let (uid, _) = unix_passwd_record(name)?;
        if !members.insert(uid) {
            return Err(AclQualificationError::InvalidDocument(
                "Unix authority group contains duplicate members",
            ));
        }
    }
    Err(AclQualificationError::InvalidDocument(
        "Unix authority group member count exceeds the bound",
    ))
}

#[cfg(unix)]
static PASSWD_ENUMERATION_LOCK: Mutex<()> = Mutex::new(());

#[cfg(unix)]
fn unix_primary_group_members(
    gid: libc::gid_t,
) -> Result<BTreeSet<libc::uid_t>, AclQualificationError> {
    let _lock = PASSWD_ENUMERATION_LOCK
        .lock()
        .map_err(|_| AclQualificationError::InvalidDocument("Unix account enumeration lock"))?;
    // SAFETY: access to the process-global passwd enumeration cursor is
    // serialized by PASSWD_ENUMERATION_LOCK.
    unsafe { libc::setpwent() };
    struct EndPasswdEnumeration;
    impl Drop for EndPasswdEnumeration {
        fn drop(&mut self) {
            // SAFETY: closes the process-global cursor opened above.
            unsafe { libc::endpwent() };
        }
    }
    let _end = EndPasswdEnumeration;
    let mut members = BTreeSet::new();
    for _ in 0..MAX_UNIX_ACCOUNT_RECORDS {
        // SAFETY: errno is thread-local on supported Unix targets.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: getpwent returns a pointer valid until the next passwd call;
        // uid/gid are copied immediately while enumeration remains locked.
        let record = unsafe { libc::getpwent() };
        if record.is_null() {
            // SAFETY: errno is thread-local on supported Unix targets.
            let error = unsafe { *libc::__errno_location() };
            if error == 0 {
                return Ok(members);
            }
            return Err(AclQualificationError::InvalidDocument(
                "Unix account enumeration failed",
            ));
        }
        // SAFETY: non-null getpwent result points to an initialized passwd record.
        let record = unsafe { &*record };
        if record.pw_gid == gid {
            members.insert(record.pw_uid);
        }
    }
    Err(AclQualificationError::InvalidDocument(
        "Unix account count exceeds the bound",
    ))
}

#[cfg(unix)]
fn validate_unix_group_members(
    members: &BTreeSet<libc::uid_t>,
    allowed_uids: &BTreeSet<libc::uid_t>,
) -> Result<(), AclQualificationError> {
    if members.is_subset(allowed_uids) {
        Ok(())
    } else {
        Err(AclQualificationError::InvalidDocument(
            "Unix authority group contains an unlisted user",
        ))
    }
}

#[cfg(windows)]
fn platform_identity_id(name: &str, context: &Path) -> Result<String, AclQualificationError> {
    crate::exchange_acl::resolve_windows_account_sid(name, context)
        .map_err(|source| AclQualificationError::Custody(source.to_string()))
}

#[cfg(unix)]
fn current_process_identity(_context: &Path) -> Result<(String, bool), AclQualificationError> {
    let effective = unsafe { libc::geteuid() };
    Ok((
        unix_uid_id(effective),
        effective == 0 || linux_process_privilege_state(effective)?,
    ))
}

#[cfg(target_os = "linux")]
fn linux_process_privilege_state(
    expected_effective_uid: libc::uid_t,
) -> Result<bool, AclQualificationError> {
    const MAX_STATUS_BYTES: usize = 64 * 1024;
    let path = Path::new("/proc/self/status");
    let bytes = fs::read(path)
        .map_err(|source| io_error("inspect Linux process privilege state", path, source))?;
    if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
        return Err(AclQualificationError::InvalidDocument(
            "Linux process privilege state is unavailable",
        ));
    }
    let status = std::str::from_utf8(&bytes).map_err(|_| {
        AclQualificationError::InvalidDocument("Linux process privilege state is invalid")
    })?;
    linux_status_is_privileged(status, expected_effective_uid)
}

#[cfg(target_os = "linux")]
fn linux_status_is_privileged(
    status: &str,
    expected_effective_uid: libc::uid_t,
) -> Result<bool, AclQualificationError> {
    let uids = linux_status_decimal_ids(status, "Uid:")?;
    let gids = linux_status_decimal_ids(status, "Gid:")?;
    let capability_fields = ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"];
    let capabilities_present =
        capability_fields
            .into_iter()
            .try_fold(false, |present, field| {
                let value = linux_status_field(status, field)?;
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(AclQualificationError::InvalidDocument(
                        "Linux process capability state is invalid",
                    ));
                }
                Ok::<_, AclQualificationError>(present || value.bytes().any(|byte| byte != b'0'))
            })?;
    Ok(uids.iter().any(|uid| *uid != expected_effective_uid)
        || gids.iter().any(|gid| *gid != gids[0])
        || capabilities_present)
}

#[cfg(target_os = "linux")]
fn linux_status_decimal_ids(
    status: &str,
    field: &'static str,
) -> Result<[u32; 4], AclQualificationError> {
    let value = linux_status_field(status, field)?;
    let parsed = value
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            AclQualificationError::InvalidDocument("Linux process credential state is invalid")
        })?;
    parsed.try_into().map_err(|_| {
        AclQualificationError::InvalidDocument("Linux process credential state is invalid")
    })
}

#[cfg(target_os = "linux")]
fn linux_status_field<'a>(
    status: &'a str,
    field: &'static str,
) -> Result<&'a str, AclQualificationError> {
    let mut matches = status
        .lines()
        .filter_map(|line| line.strip_prefix(field).map(str::trim));
    let value = matches
        .next()
        .ok_or(AclQualificationError::InvalidDocument(
            "Linux process privilege field is missing",
        ))?;
    if matches.next().is_some() {
        return Err(AclQualificationError::InvalidDocument(
            "Linux process privilege field is duplicated",
        ));
    }
    Ok(value)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn linux_process_privilege_state(
    _expected_effective_uid: libc::uid_t,
) -> Result<bool, AclQualificationError> {
    Ok(true)
}

#[cfg(windows)]
fn current_process_identity(context: &Path) -> Result<(String, bool), AclQualificationError> {
    crate::exchange_acl::current_windows_process_identity(context)
        .map_err(|source| AclQualificationError::Custody(source.to_string()))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> AclQualificationError {
    AclQualificationError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(configured: &str, id: &str) -> IdentityFact {
        IdentityFact {
            configured: configured.to_owned(),
            exists: true,
            resolved_id: id.to_owned(),
        }
    }

    fn accepted_fixture() -> QualificationFixture {
        let identities = IdentityFacts {
            service: identity("cmfd-node", "service-id"),
            operator: identity("cmfd-operator", "operator-id"),
            anchor: identity("cmfd-anchor", "anchor-id"),
            current_process_id: "service-id".to_owned(),
            current_process_is_service: true,
            current_process_is_privileged: false,
        };
        let root = if cfg!(windows) {
            PathBuf::from(r"C:\Program Files\commonfoundry-rc-runtime-windows-x86_64")
        } else {
            PathBuf::from("/opt/commonfoundry-rc-runtime-linux-x86_64")
        };
        let node = root.join(if cfg!(windows) {
            "cmfd-node.exe"
        } else {
            "cmfd-node"
        });
        let package = PackageFact {
            root,
            node,
            present: true,
            layout_matches: true,
            running_from_package: true,
            owner_id: "operator-id".to_owned(),
            owner_matches_operator: true,
            allowed_authority_ids: vec!["operator-id".to_owned(), "service-id".to_owned()],
            authority_allowlist_valid: true,
            runtime_acl_valid: true,
            node_sha256: "ab".repeat(32),
            version: "0.1.0-test".to_owned(),
            detail: "fixture package accepted".to_owned(),
        };
        let artifacts = ARTIFACT_CONTRACT
            .into_iter()
            .map(|(name, kind, authority)| ArtifactFact {
                name: name.to_owned(),
                path: PathBuf::from(format!("/fixture/{name}")),
                kind: kind.to_owned(),
                authority: authority.to_owned(),
                present: true,
                layout_valid: true,
                owner_id: identities.fact(authority).resolved_id.clone(),
                owner_matches_authority: true,
                allowed_authority_ids: if authority == "service" {
                    vec!["service-id".to_owned()]
                } else {
                    vec![
                        identities.fact(authority).resolved_id.clone(),
                        "service-id".to_owned(),
                    ]
                },
                authority_allowlist_valid: true,
                runtime_acl_valid: true,
                detail: "fixture runtime validator accepted".to_owned(),
            })
            .collect();
        QualificationFixture {
            schema: ACL_QUALIFICATION_FIXTURE_SCHEMA.to_owned(),
            platform: current_platform().to_owned(),
            identities,
            package,
            artifacts,
        }
    }

    #[test]
    fn accepted_fixture_never_claims_host_qualification() {
        let evidence = evaluate(accepted_fixture(), true, "ab".repeat(32)).unwrap();
        assert_eq!(evidence.result, "fixture_qualified");
        assert!(evidence.fixture_qualified);
        assert!(!evidence.host_qualified);
    }

    #[test]
    fn missing_package_or_identity_fails_closed() {
        let mut fixture = accepted_fixture();
        fixture.package.present = false;
        fixture.identities.anchor.exists = false;
        fixture.identities.anchor.resolved_id.clear();
        let evidence = evaluate(fixture, true, "ab".repeat(32)).unwrap();
        assert_eq!(evidence.result, "rejected");
        assert!(!evidence.host_qualified);
        assert!(!evidence.fixture_qualified);
    }

    #[test]
    fn shared_authority_identity_and_unsafe_acl_fail_closed() {
        let mut fixture = accepted_fixture();
        fixture.identities.anchor.resolved_id = fixture.identities.operator.resolved_id.clone();
        fixture.artifacts[2].runtime_acl_valid = false;
        fixture.artifacts[2].authority_allowlist_valid = false;
        let evidence = evaluate(fixture, true, "ab".repeat(32)).unwrap();
        assert_eq!(evidence.result, "rejected");
        assert!(
            evidence
                .checks
                .iter()
                .any(|check| check.id == "identity.roles_distinct" && check.status == "fail")
        );
        assert!(evidence.checks.iter().any(|check| {
            check.id == "artifact.withdrawal_anchor.runtime_acl" && check.status == "fail"
        }));
    }

    #[test]
    fn fixture_contract_is_ordered_and_strict() {
        let mut fixture = accepted_fixture();
        fixture.artifacts.swap(0, 1);
        assert!(matches!(
            evaluate(fixture, true, "ab".repeat(32)),
            Err(AclQualificationError::InvalidDocument(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_group_authority_rejects_unlisted_member() {
        let allowed = BTreeSet::from([0, 1001, 1002]);
        assert!(validate_unix_group_members(&BTreeSet::from([1001, 1002]), &allowed).is_ok());
        assert!(matches!(
            validate_unix_group_members(&BTreeSet::from([1001, 9001]), &allowed),
            Err(AclQualificationError::InvalidDocument(
                "Unix authority group contains an unlisted user"
            ))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_privilege_audit_rejects_capabilities_and_saved_root() {
        let status = "Uid:\t1001\t1001\t1001\t1001\n\
                      Gid:\t1001\t1001\t1001\t1001\n\
                      CapInh:\t0000000000000000\n\
                      CapPrm:\t0000000000000000\n\
                      CapEff:\t0000000000000000\n\
                      CapAmb:\t0000000000000000\n";
        assert!(!linux_status_is_privileged(status, 1001).unwrap());

        let with_saved_root = status.replacen(
            "Uid:\t1001\t1001\t1001\t1001",
            "Uid:\t1001\t1001\t0\t1001",
            1,
        );
        assert!(linux_status_is_privileged(&with_saved_root, 1001).unwrap());

        let with_capability =
            status.replacen("CapEff:\t0000000000000000", "CapEff:\t0000000000000008", 1);
        assert!(linux_status_is_privileged(&with_capability, 1001).unwrap());
    }

    #[test]
    fn absent_live_package_and_identities_write_only_rejected_evidence() {
        let tag = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(format!("cmfd-acl-qualification-{tag}"));
        fs::create_dir(&directory).unwrap();
        let missing = directory.join("missing");
        let config_file = directory.join("config.json");
        let evidence_file = directory.join("evidence.json");
        let package_name = format!("commonfoundry-rc-runtime-{}-x86_64", current_platform());
        let config = serde_json::json!({
            "schema": ACL_QUALIFICATION_CONFIG_SCHEMA,
            "package_root": missing.join(package_name),
            "identities": {
                "service": format!("cmfd-missing-service-{tag}"),
                "operator": format!("cmfd-missing-operator-{tag}"),
                "anchor": format!("cmfd-missing-anchor-{tag}"),
            },
            "windows_additional_authorities": {
                "package": [],
                "data_directory": [],
                "journal_key": [],
                "withdrawal_anchor": [],
                "policy": [],
                "keyring": [],
                "keyring_anchor": [],
                "wallet_passphrase": [],
                "keyring_passphrase": [],
                "integration_rpc_auth": [],
                "withdrawal_rpc_auth": []
            },
            "artifacts": {
                "data_directory": missing.join("data"),
                "journal_key": missing.join("journal.key"),
                "withdrawal_anchor": missing.join("withdrawal.anchor"),
                "policy": missing.join("policy.json"),
                "keyring": missing.join("data").join("keyring.bin"),
                "keyring_anchor": missing.join("keyring.anchor"),
                "wallet_passphrase": missing.join("wallet.passphrase"),
                "keyring_passphrase": missing.join("keyring.passphrase"),
                "integration_rpc_auth": missing.join("integration.auth"),
                "withdrawal_rpc_auth": missing.join("withdrawal.auth"),
            }
        });
        fs::write(&config_file, serde_json::to_vec(&config).unwrap()).unwrap();

        let evidence = qualify_installed_host(&config_file, &evidence_file).unwrap();
        assert_eq!(evidence.result, "rejected");
        assert!(!evidence.host_qualified);
        assert!(!evidence.fixture_qualified);
        assert!(!evidence.identities.service.exists);
        assert!(!evidence.package.present);
        assert!(evidence_file.is_file());
        assert!(qualify_installed_host(&config_file, &evidence_file).is_err());

        fs::remove_file(evidence_file).unwrap();
        fs::remove_file(config_file).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
