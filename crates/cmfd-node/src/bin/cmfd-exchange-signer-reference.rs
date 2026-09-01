//! Provider-neutral reference implementation for the CMFDSIG1 signer protocol.
//!
//! This binary is an integration and conformance aid. It reads a raw software
//! key and therefore is not an HSM, remote-signing transport, or production
//! custody recommendation.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use blake3::Hasher;
use clap::Parser;
use cmfd_consensus::OutputLock;
use cmfd_node::wallet_signing_protocol::{
    InputSignatureV1, KeyringAnchorV1, ReleaseAuthorizationV1, SignerCapabilitiesV1, SignerId,
    SignerResponseV1, SigningAlgorithmV1, SigningPackageV1, WalletKeyId, WithdrawalAnchorV1,
    package_authorization_digest, release_authorization_digest, signer_key_set_digest,
    wallet_key_id,
};
use k256::schnorr::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const CUSTODY_API_VERSION: &str = "chain-preview-v0.5";
const TRUSTED_CONTEXT_SCHEMA: &str = "CMFD_EXCHANGE_SIGNER_TRUSTED_CONTEXT_V1";
const TRUSTED_CONTEXT_ENVELOPE_SCHEMA: &str = "CMFD_EXCHANGE_SIGNER_TRUSTED_CONTEXT_ENVELOPE_V1";
const TRUSTED_CONTEXT_DOMAIN: &str = "CMFD/REFERENCE-SIGNER/TRUSTED-CONTEXT/V1";
const SIGNER_PACKAGE_BYTES_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-SIGNER-PACKAGE/V3";
const APPROVAL_SCHEMA: &str = "common-foundry-exchange-withdrawal-approval-v1";
const APPROVAL_DIGEST_DOMAIN: &[u8] = b"CMFD/NODE/EXCHANGE-WITHDRAWAL-ACTION/V1\0";
const MAX_APPROVAL_VALIDITY_SECONDS: u64 = 15 * 60;
const MAX_APPROVER_KEYS: usize = 32;

#[derive(Debug, Parser)]
#[command(
    name = "cmfd-exchange-signer-reference",
    about = "Validate and sign one authorized CMFDSIG1 package with a software test key"
)]
struct Cli {
    /// JSON result returned by getwithdrawalsigningpackage.
    #[arg(long)]
    package_document: PathBuf,
    /// Independently produced, BIP340-signed signer context envelope.
    #[arg(long)]
    trusted_context_document: PathBuf,
    /// Out-of-band pinned BIP340 public key authenticating the trusted context.
    #[arg(long, value_parser = parse_hex32)]
    context_authority_public_key: [u8; 32],
    /// Absolute, non-symlink file containing exactly one raw 32-byte scalar.
    #[arg(long)]
    secret_key_file: PathBuf,
    /// Absolute create-new path for the canonical binary SignerResponseV1.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningPackageDocument {
    api_version: String,
    request_id: String,
    request_digest: String,
    current_anchor: WithdrawalAnchorDocument,
    prepared_anchor: Option<WithdrawalAnchorDocument>,
    approval_action_anchor: WithdrawalAnchorDocument,
    signing_digest: String,
    signer_package_digest: String,
    signer_package_bytes_digest: Option<String>,
    signer_package_base64: String,
    release_authorization: ReleaseAuthorizationDocument,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAuthorizationDocument {
    release_authorized_anchor: WithdrawalAnchorDocument,
    decision_id: String,
    approval_digest: String,
    release_authorization_digest: String,
    signed_approval: SignedApprovalDocument,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WithdrawalAnchorDocument {
    key_id: String,
    journal_instance_id: String,
    generation: String,
    commitment: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedApprovalDocument {
    schema: String,
    action: String,
    decision_id: String,
    policy_id: String,
    action_anchor: WithdrawalAnchorDocument,
    request_id: String,
    request_digest: String,
    transaction_signing_digest: String,
    authorized_at_unix_seconds: String,
    expires_at_unix_seconds: String,
    signatures: Vec<ApprovalSignatureDocument>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalSignatureDocument {
    public_key: String,
    signature: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedContextEnvelope {
    schema: String,
    context_base64: String,
    context_digest: String,
    signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedContextDocument {
    schema: String,
    network_id: String,
    consensus_fingerprint: String,
    genesis: String,
    request_id: String,
    request_digest: String,
    policy_id: String,
    prepared_anchor: WithdrawalAnchorDocument,
    approval_action_anchor: WithdrawalAnchorDocument,
    keyring_anchor: KeyringAnchorDocument,
    signing_digest: String,
    signer_package_digest: String,
    signer_package_bytes_digest: String,
    signer: TrustedSignerDocument,
    transaction: TrustedTransactionDocument,
    release_authorized_anchor: WithdrawalAnchorDocument,
    decision_id: String,
    approval_digest: String,
    release_authorization_digest: String,
    approval_rule: TrustedApprovalRuleDocument,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyringAnchorDocument {
    instance_id: String,
    generation: String,
    commitment: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedSignerDocument {
    signer_id: String,
    algorithm: String,
    max_signatures_per_request: u16,
    max_package_bytes: u32,
    key_ids: Vec<String>,
    capability_digest: String,
    signing_public_key: String,
    signing_key_id: String,
    assigned_input_indices: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedTransactionDocument {
    recipient_destination: String,
    amount_atoms: String,
    fee_atoms: String,
    change_destination: Option<String>,
    change_atoms: String,
    spendable_height: String,
    input_count: u32,
    input_total_atoms: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedApprovalRuleDocument {
    threshold: u16,
    public_keys: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    require_distinct_inputs(&[
        &cli.package_document,
        &cli.trusted_context_document,
        &cli.secret_key_file,
        &cli.output,
    ])?;
    let context_envelope: TrustedContextEnvelope = serde_json::from_slice(&read_bounded_file(
        &cli.trusted_context_document,
        MAX_DOCUMENT_BYTES,
    )?)?;
    let (context, trusted_context_digest) =
        authenticate_trusted_context(&context_envelope, cli.context_authority_public_key)?;
    let document: SigningPackageDocument = serde_json::from_slice(&read_bounded_file(
        &cli.package_document,
        MAX_DOCUMENT_BYTES,
    )?)?;
    if document.api_version != CUSTODY_API_VERSION {
        return Err("signing package document uses an unsupported custody API version".into());
    }
    let package_bytes = BASE64_STANDARD.decode(&document.signer_package_base64)?;
    let package = SigningPackageV1::decode(&package_bytes)?;
    let package_digest = package.digest()?;
    if parse_hex32(&document.signer_package_digest)? != package_digest {
        return Err("signing package digest does not match the canonical package bytes".into());
    }
    validate_expected_package(
        &document,
        &package,
        &package_bytes,
        package_digest,
        &context,
    )?;
    let signer_context = validate_signer_context(&package, &package_bytes, &context)?;
    validate_transaction_intent(&package, &context)?;
    let release_digest =
        validate_release_authorization(&document, &package, package_digest, &context)?;

    // The raw test key is opened only after every independently authenticated
    // policy, package, authorization, and transaction-intent check succeeds.
    let secret = read_secret_key(&cli.secret_key_file)?;
    let signing_key = SigningKey::from_bytes(secret.as_ref())
        .map_err(|_| "secret key file does not contain a valid nonzero secp256k1 scalar")?;
    let signing_public_key: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    if signing_public_key != signer_context.signing_public_key
        || wallet_key_id(&signing_public_key) != signer_context.signing_key_id
    {
        return Err("software signing key does not match the authenticated signer context".into());
    }
    let response = sign_response(
        &package,
        package_digest,
        release_digest,
        signer_context.signer_id,
        signer_context.capability_digest,
        &signing_key,
    )?;
    let response_bytes = response.encode()?;
    write_create_new_atomic(&cli.output, &response_bytes)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "CMFD_REFERENCE_SIGNER_RESULT_V1",
            "production_hsm": false,
            "stateless_reference_only": true,
            "persistent_anti_replay_service_required": true,
            "input_values_verified_against_chain": false,
            "request_id": package.request_id,
            "signer_id": hex::encode(signer_context.signer_id.0),
            "package_digest": hex::encode(package_digest),
            "trusted_context_digest": hex::encode(trusted_context_digest),
            "context_authority_public_key": hex::encode(cli.context_authority_public_key),
            "release_authorization_digest": hex::encode(release_digest),
            "signature_count": response.signatures.len(),
            "response_digest": hex::encode(response.digest()?),
            "output": cli.output,
        }))?
    );
    Ok(())
}

struct ValidatedSignerContext {
    signer_id: SignerId,
    capability_digest: [u8; 32],
    signing_public_key: [u8; 32],
    signing_key_id: WalletKeyId,
}

fn validate_expected_package(
    document: &SigningPackageDocument,
    package: &SigningPackageV1,
    package_bytes: &[u8],
    package_digest: [u8; 32],
    context: &TrustedContextDocument,
) -> Result<(), Box<dyn std::error::Error>> {
    if context.schema != TRUSTED_CONTEXT_SCHEMA {
        return Err("trusted signer context schema is unsupported".into());
    }
    if package.network_id != parse_hex32(&context.network_id)? {
        return Err("signing package network id does not match the independent pin".into());
    }
    if package.consensus_fingerprint != parse_hex32(&context.consensus_fingerprint)? {
        return Err(
            "signing package consensus fingerprint does not match the independent pin".into(),
        );
    }
    if package.genesis != parse_hex32(&context.genesis)? {
        return Err("signing package genesis does not match the independent pin".into());
    }
    if package.policy_id != parse_hex32(&context.policy_id)? {
        return Err("signing package policy does not match the independent pin".into());
    }
    if package.request_id != context.request_id || document.request_id != context.request_id {
        return Err(
            "canonical signing package request id does not match the independent pin".into(),
        );
    }
    let request_digest = parse_hex32(&context.request_digest)?;
    if package.request_digest != request_digest
        || parse_hex32(&document.request_digest)? != request_digest
    {
        return Err("signing package request digest does not match the independent pin".into());
    }
    let signing_digest = parse_hex32(&context.signing_digest)?;
    if package.signing_digest != signing_digest
        || parse_hex32(&document.signing_digest)? != signing_digest
    {
        return Err("transaction signing digest does not match the independent pin".into());
    }
    if package_digest != parse_hex32(&context.signer_package_digest)? {
        return Err("canonical signing package digest does not match the independent pin".into());
    }
    let bytes_digest = exact_bytes_digest(SIGNER_PACKAGE_BYTES_DOMAIN, package_bytes);
    let document_bytes_digest = document
        .signer_package_bytes_digest
        .as_deref()
        .ok_or("signing package document omitted its exact-bytes digest")?;
    if bytes_digest != parse_hex32(document_bytes_digest)?
        || bytes_digest != parse_hex32(&context.signer_package_bytes_digest)?
    {
        return Err("signing package exact-bytes digest does not match the independent pin".into());
    }
    if package.prepared_anchor != parse_withdrawal_anchor(&context.prepared_anchor)? {
        return Err("Prepared anchor does not match the independent signer context".into());
    }
    let prepared_document = document
        .prepared_anchor
        .as_ref()
        .ok_or("signing package document omitted its Prepared anchor")?;
    if parse_withdrawal_anchor(prepared_document)? != package.prepared_anchor {
        return Err("signing package document Prepared anchor is inconsistent".into());
    }
    if package.keyring_anchor != parse_keyring_anchor(&context.keyring_anchor)? {
        return Err("keyring anchor does not match the independent signer context".into());
    }
    Ok(())
}

fn validate_release_authorization(
    document: &SigningPackageDocument,
    package: &SigningPackageV1,
    package_digest: [u8; 32],
    context: &TrustedContextDocument,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let expected_anchor = parse_withdrawal_anchor(&context.release_authorized_anchor)?;
    let document_anchor = parse_withdrawal_anchor(&document.current_anchor)?;
    let authorization_anchor =
        parse_withdrawal_anchor(&document.release_authorization.release_authorized_anchor)?;
    if document_anchor != expected_anchor || authorization_anchor != expected_anchor {
        return Err("ReleaseAuthorized anchor does not match the independent pin".into());
    }
    let expected_action_anchor = parse_withdrawal_anchor(&context.approval_action_anchor)?;
    let document_action_anchor = parse_withdrawal_anchor(&document.approval_action_anchor)?;
    if document_action_anchor != expected_action_anchor {
        return Err("approval action anchor does not match the independent pin".into());
    }
    if expected_action_anchor.key_id != package.prepared_anchor.key_id
        || expected_action_anchor.journal_instance_id != package.prepared_anchor.journal_instance_id
        || expected_action_anchor.generation <= package.prepared_anchor.generation
    {
        return Err("approval action anchor does not descend from the Prepared anchor".into());
    }
    if expected_anchor.key_id != expected_action_anchor.key_id
        || expected_anchor.journal_instance_id != expected_action_anchor.journal_instance_id
        || expected_action_anchor.generation.checked_add(1) != Some(expected_anchor.generation)
    {
        return Err("ReleaseAuthorized anchor is not the next approval-action generation".into());
    }
    let approval_digest = validate_signed_approval(
        &document.release_authorization.signed_approval,
        package,
        context,
    )?;
    let decision_id = parse_hex32(&context.decision_id)?;
    if parse_hex32(&document.release_authorization.decision_id)? != decision_id
        || parse_hex32(&document.release_authorization.approval_digest)? != approval_digest
        || parse_hex32(&context.approval_digest)? != approval_digest
    {
        return Err("release decision or verified approval digest does not match its pin".into());
    }
    let authorization = ReleaseAuthorizationV1 {
        release_authorized_anchor: expected_anchor,
        decision_id,
        approval_digest,
    };
    let computed = release_authorization_digest(&package_digest, authorization)?;
    if computed != parse_hex32(&document.release_authorization.release_authorization_digest)?
        || computed != parse_hex32(&context.release_authorization_digest)?
    {
        return Err("release authorization digest does not match its canonical fields".into());
    }
    Ok(computed)
}

fn authenticate_trusted_context(
    envelope: &TrustedContextEnvelope,
    authority_public_key: [u8; 32],
) -> Result<(TrustedContextDocument, [u8; 32]), Box<dyn std::error::Error>> {
    if envelope.schema != TRUSTED_CONTEXT_ENVELOPE_SCHEMA {
        return Err("trusted signer context envelope schema is unsupported".into());
    }
    let context_bytes = BASE64_STANDARD.decode(&envelope.context_base64)?;
    if context_bytes.len() as u64 > MAX_DOCUMENT_BYTES
        || BASE64_STANDARD.encode(&context_bytes) != envelope.context_base64
    {
        return Err("trusted signer context is not bounded canonical base64".into());
    }
    let context: TrustedContextDocument = serde_json::from_slice(&context_bytes)?;
    if context.schema != TRUSTED_CONTEXT_SCHEMA {
        return Err("trusted signer context schema is unsupported".into());
    }
    let digest = exact_bytes_digest(TRUSTED_CONTEXT_DOMAIN, &context_bytes);
    if digest != parse_hex32(&envelope.context_digest)? {
        return Err("trusted signer context digest does not match its canonical fields".into());
    }
    let verifying_key = VerifyingKey::from_bytes(&authority_public_key)
        .map_err(|_| "context authority public key is not a valid BIP340 key")?;
    let signature = Signature::try_from(parse_hex64(&envelope.signature)?.as_slice())
        .map_err(|_| "trusted signer context signature is invalid")?;
    verifying_key
        .verify(&digest, &signature)
        .map_err(|_| "trusted signer context authority signature did not verify")?;
    Ok((context, digest))
}

fn validate_signer_context(
    package: &SigningPackageV1,
    package_bytes: &[u8],
    context: &TrustedContextDocument,
) -> Result<ValidatedSignerContext, Box<dyn std::error::Error>> {
    let signer = &context.signer;
    if signer.algorithm != "bip340-secp256k1" {
        return Err("trusted signer context uses an unsupported algorithm".into());
    }
    let signer_id = SignerId(parse_nonzero_hex32(&signer.signer_id, "signer_id")?);
    let capability_digest = parse_nonzero_hex32(&signer.capability_digest, "capability_digest")?;
    let signing_public_key = parse_nonzero_hex32(&signer.signing_public_key, "signing_public_key")?;
    VerifyingKey::from_bytes(&signing_public_key)
        .map_err(|_| "trusted signing public key is not a valid BIP340 key")?;
    let signing_key_id = WalletKeyId(parse_nonzero_hex32(
        &signer.signing_key_id,
        "signing_key_id",
    )?);
    if wallet_key_id(&signing_public_key) != signing_key_id {
        return Err("trusted signer public key and wallet key id disagree".into());
    }
    let mut key_ids = Vec::with_capacity(signer.key_ids.len());
    for value in &signer.key_ids {
        key_ids.push(WalletKeyId(parse_nonzero_hex32(value, "signer key id")?));
    }
    if key_ids.is_empty() || key_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("trusted signer key ids must be nonempty, unique, and sorted".into());
    }
    if key_ids.binary_search(&signing_key_id).is_err() {
        return Err("software signing key id is absent from the authenticated key set".into());
    }
    let algorithm = SigningAlgorithmV1::Bip340Secp256k1;
    let capabilities = SignerCapabilitiesV1 {
        signer_id,
        algorithm,
        max_signatures_per_request: signer.max_signatures_per_request,
        max_package_bytes: signer.max_package_bytes,
        key_set_digest: signer_key_set_digest(signer_id, algorithm, &key_ids)?,
    };
    if capabilities.digest()? != capability_digest {
        return Err("trusted signer capability digest does not match its exact fields".into());
    }
    if package_bytes.len() > signer.max_package_bytes as usize {
        return Err("signing package exceeds the authenticated signer byte limit".into());
    }
    if signer.assigned_input_indices.is_empty()
        || signer
            .assigned_input_indices
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err("assigned input indices must be nonempty, unique, and sorted".into());
    }
    let assigned = package
        .inputs
        .iter()
        .filter(|input| input.signer_id == signer_id)
        .collect::<Vec<_>>();
    let actual_indices = assigned
        .iter()
        .map(|input| input.input_index)
        .collect::<Vec<_>>();
    if actual_indices != signer.assigned_input_indices {
        return Err(
            "package input assignment does not match the authenticated signer context".into(),
        );
    }
    if assigned.len() > usize::from(signer.max_signatures_per_request) {
        return Err("package exceeds the authenticated signer signature limit".into());
    }
    for input in assigned {
        if input.capability_digest != capability_digest
            || key_ids.binary_search(&input.key_id).is_err()
            || input.key_id != signing_key_id
            || input.public_key != signing_public_key
        {
            return Err(
                "assigned input does not match the authenticated signer/key context".into(),
            );
        }
    }
    Ok(ValidatedSignerContext {
        signer_id,
        capability_digest,
        signing_public_key,
        signing_key_id,
    })
}

fn validate_transaction_intent(
    package: &SigningPackageV1,
    context: &TrustedContextDocument,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = &context.transaction;
    let transaction = package.transaction()?;
    let recipient = parse_nonzero_hex32(
        &expected.recipient_destination,
        "transaction recipient_destination",
    )?;
    VerifyingKey::from_bytes(&recipient)
        .map_err(|_| "transaction recipient is not a valid BIP340 key")?;
    let amount_atoms = parse_canonical_u64(&expected.amount_atoms)?;
    let fee_atoms = parse_canonical_u64(&expected.fee_atoms)?;
    let change_atoms = parse_canonical_u64(&expected.change_atoms)?;
    let spendable_height = parse_canonical_u64(&expected.spendable_height)?;
    let expected_input_total = parse_canonical_u64(&expected.input_total_atoms)?;
    if expected.input_count as usize != package.inputs.len()
        || expected.input_count as usize != transaction.inputs.len()
    {
        return Err("transaction input count does not match the authenticated intent".into());
    }
    let input_total = package.inputs.iter().try_fold(0_u64, |total, input| {
        total
            .checked_add(input.value_atoms)
            .ok_or("input total overflow")
    })?;
    if input_total != expected_input_total {
        return Err("package input total does not match the authenticated intent".into());
    }
    let expected_output_count = if change_atoms == 0 { 1 } else { 2 };
    if transaction.outputs.len() != expected_output_count {
        return Err("transaction output count does not match the authenticated intent".into());
    }
    let payment = &transaction.outputs[0];
    if payment.value != amount_atoms
        || payment.lock != OutputLock::Key(recipient)
        || payment.spendable_height != spendable_height
    {
        return Err("payment output does not match the authenticated intent".into());
    }
    if change_atoms == 0 {
        if expected.change_destination.is_some() {
            return Err("zero-change intent must not name a change destination".into());
        }
    } else {
        let change_destination = expected
            .change_destination
            .as_deref()
            .ok_or("nonzero-change intent omitted the change destination")?;
        let change_destination = parse_nonzero_hex32(change_destination, "change_destination")?;
        VerifyingKey::from_bytes(&change_destination)
            .map_err(|_| "change destination is not a valid BIP340 key")?;
        let change = &transaction.outputs[1];
        if change.value != change_atoms
            || change.lock != OutputLock::Key(change_destination)
            || change.spendable_height != spendable_height
        {
            return Err("change output does not match the authenticated intent".into());
        }
    }
    let output_total = amount_atoms
        .checked_add(change_atoms)
        .ok_or("transaction output total overflow")?;
    if input_total.checked_sub(output_total) != Some(fee_atoms) {
        return Err("transaction fee does not match the authenticated intent".into());
    }
    Ok(())
}

fn validate_signed_approval(
    approval: &SignedApprovalDocument,
    package: &SigningPackageV1,
    context: &TrustedContextDocument,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if approval.schema != APPROVAL_SCHEMA || approval.action != "release" {
        return Err("signed approval does not authorize a release action".into());
    }
    let decision_id = parse_nonzero_hex32(&approval.decision_id, "approval decision_id")?;
    if decision_id != parse_nonzero_hex32(&context.decision_id, "context decision_id")? {
        return Err("signed approval decision does not match the authenticated context".into());
    }
    if parse_nonzero_hex32(&approval.policy_id, "approval policy_id")? != package.policy_id
        || approval.request_id != package.request_id
        || parse_nonzero_hex32(&approval.request_digest, "approval request_digest")?
            != package.request_digest
        || parse_nonzero_hex32(
            &approval.transaction_signing_digest,
            "approval transaction_signing_digest",
        )? != package.signing_digest
        || parse_withdrawal_anchor(&approval.action_anchor)?
            != parse_withdrawal_anchor(&context.approval_action_anchor)?
    {
        return Err("signed approval does not match the exact Prepared package".into());
    }
    let authorized_at = parse_positive_canonical_u64(
        &approval.authorized_at_unix_seconds,
        "approval authorized_at_unix_seconds",
    )?;
    let expires_at = parse_positive_canonical_u64(
        &approval.expires_at_unix_seconds,
        "approval expires_at_unix_seconds",
    )?;
    if authorized_at >= expires_at || expires_at - authorized_at > MAX_APPROVAL_VALIDITY_SECONDS {
        return Err("signed approval has an invalid original time window".into());
    }
    let digest = approval_signing_digest(approval)?;
    let rule = &context.approval_rule;
    if rule.threshold == 0
        || usize::from(rule.threshold) > rule.public_keys.len()
        || rule.public_keys.len() > MAX_APPROVER_KEYS
    {
        return Err("authenticated release-approval rule has an invalid threshold".into());
    }
    let mut approved_keys = Vec::with_capacity(rule.public_keys.len());
    for value in &rule.public_keys {
        let key = parse_nonzero_hex32(value, "approval rule public key")?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| "approval rule contains an invalid BIP340 key")?;
        approved_keys.push(key);
    }
    if approved_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("approval rule public keys must be unique and sorted".into());
    }
    if approval.signatures.len() < usize::from(rule.threshold)
        || approval.signatures.len() > approved_keys.len()
    {
        return Err("signed approval does not meet the authenticated threshold".into());
    }
    let mut previous = None;
    for entry in &approval.signatures {
        let public_key = parse_nonzero_hex32(&entry.public_key, "approval signature public key")?;
        if previous.is_some_and(|previous| previous >= public_key)
            || approved_keys.binary_search(&public_key).is_err()
        {
            return Err("approval signatures are unordered, duplicate, or unauthorized".into());
        }
        let signature = Signature::try_from(parse_hex64(&entry.signature)?.as_slice())
            .map_err(|_| "approval signature encoding is invalid")?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| "approval signature public key is invalid")?
            .verify(&digest, &signature)
            .map_err(|_| "approval signature did not verify")?;
        previous = Some(public_key);
    }
    Ok(digest)
}

fn approval_signing_digest(
    approval: &SignedApprovalDocument,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let policy_id = parse_nonzero_hex32(&approval.policy_id, "approval policy_id")?;
    let action_anchor = parse_withdrawal_anchor(&approval.action_anchor)?;
    let request_digest = parse_nonzero_hex32(&approval.request_digest, "approval request_digest")?;
    let signing_digest = parse_nonzero_hex32(
        &approval.transaction_signing_digest,
        "approval transaction_signing_digest",
    )?;
    let decision_id = parse_nonzero_hex32(&approval.decision_id, "approval decision_id")?;
    let authorized_at = parse_positive_canonical_u64(
        &approval.authorized_at_unix_seconds,
        "approval authorized_at_unix_seconds",
    )?;
    let expires_at = parse_positive_canonical_u64(
        &approval.expires_at_unix_seconds,
        "approval expires_at_unix_seconds",
    )?;
    let request_length = u16::try_from(approval.request_id.len())
        .map_err(|_| "approval request id exceeds the protocol bound")?;
    let mut hasher = Hasher::new();
    hasher.update(APPROVAL_DIGEST_DOMAIN);
    hasher.update(&[1]);
    hasher.update(&policy_id);
    hasher.update(&action_anchor.key_id);
    hasher.update(&action_anchor.journal_instance_id);
    hasher.update(&action_anchor.generation.to_le_bytes());
    hasher.update(&action_anchor.commitment);
    hasher.update(&request_length.to_le_bytes());
    hasher.update(approval.request_id.as_bytes());
    hasher.update(&request_digest);
    hasher.update(&signing_digest);
    hasher.update(&decision_id);
    hasher.update(&authorized_at.to_le_bytes());
    hasher.update(&expires_at.to_le_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn parse_withdrawal_anchor(
    document: &WithdrawalAnchorDocument,
) -> Result<WithdrawalAnchorV1, Box<dyn std::error::Error>> {
    Ok(WithdrawalAnchorV1 {
        key_id: parse_nonzero_hex32(&document.key_id, "anchor key_id")?,
        journal_instance_id: parse_nonzero_hex32(
            &document.journal_instance_id,
            "anchor journal_instance_id",
        )?,
        generation: parse_positive_canonical_u64(&document.generation, "anchor generation")?,
        commitment: parse_nonzero_hex32(&document.commitment, "anchor commitment")?,
    })
}

fn parse_keyring_anchor(
    document: &KeyringAnchorDocument,
) -> Result<KeyringAnchorV1, Box<dyn std::error::Error>> {
    Ok(KeyringAnchorV1 {
        instance_id: parse_nonzero_hex32(&document.instance_id, "keyring instance_id")?,
        generation: parse_positive_canonical_u64(&document.generation, "keyring generation")?,
        commitment: parse_nonzero_hex32(&document.commitment, "keyring commitment")?,
    })
}

fn exact_bytes_digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn sign_response(
    package: &SigningPackageV1,
    package_digest: [u8; 32],
    release_authorization_digest: [u8; 32],
    signer_id: SignerId,
    expected_capability_digest: [u8; 32],
    signing_key: &SigningKey,
) -> Result<SignerResponseV1, Box<dyn std::error::Error>> {
    let public_key: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    let key_id = wallet_key_id(&public_key);
    let assigned = package
        .inputs
        .iter()
        .filter(|input| input.signer_id == signer_id)
        .collect::<Vec<_>>();
    if assigned.is_empty() {
        return Err("signing package assigns no inputs to the expected signer".into());
    }
    let capability_digest = expected_capability_digest;
    let mut signatures = Vec::with_capacity(assigned.len());
    for input in assigned {
        if input.public_key != public_key || input.key_id != key_id {
            return Err(
                "software reference key does not cover every input assigned to the signer".into(),
            );
        }
        if input.capability_digest != capability_digest {
            return Err("assigned signer input does not match the authenticated capability".into());
        }
        let transaction_signature: Signature = signing_key.sign(&package.signing_digest);
        let transaction_signature = transaction_signature.to_bytes();
        let authorization_digest = package_authorization_digest(
            &package_digest,
            &release_authorization_digest,
            input.input_index,
            input.key_id,
            signer_id,
            &input.capability_digest,
            &transaction_signature,
        );
        let package_authorization_signature: Signature = signing_key.sign(&authorization_digest);
        signatures.push(InputSignatureV1 {
            input_index: input.input_index,
            key_id: input.key_id,
            transaction_signature,
            package_authorization_signature: package_authorization_signature.to_bytes(),
        });
    }
    signatures.sort_unstable_by_key(|signature| signature.input_index);
    let response = SignerResponseV1 {
        package_digest,
        release_authorization_digest,
        signer_id,
        capability_digest,
        signatures,
    };
    Ok(SignerResponseV1::decode(&response.encode()?)?)
}

fn require_distinct_inputs(paths: &[&Path]) -> Result<(), Box<dyn std::error::Error>> {
    let mut identities = Vec::with_capacity(paths.len());
    for (position, path) in paths.iter().enumerate() {
        if !path.is_absolute() {
            return Err("every signer input and output path must be absolute".into());
        }
        let allow_missing_leaf = position + 1 == paths.len();
        reject_reparse_ancestors(path, allow_missing_leaf)?;
        let identity = if allow_missing_leaf {
            if path.exists() {
                return Err("signer output path already exists".into());
            }
            let parent = path
                .parent()
                .ok_or("signer output has no parent directory")?;
            fs::canonicalize(parent)?
                .join(path.file_name().ok_or("signer output has no file name")?)
        } else {
            fs::canonicalize(path)?
        };
        if identities.contains(&identity) {
            return Err("signer input and output paths must be pairwise distinct".into());
        }
        identities.push(identity);
    }
    Ok(())
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("input path must be absolute".into());
    }
    reject_reparse_ancestors(path, false)?;
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err("input is not a bounded regular file".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err("input changed size while it was being read".into());
    }
    Ok(bytes)
}

fn read_secret_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("secret key path must be absolute".into());
    }
    reject_reparse_ancestors(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err("secret key file must be a 32-byte regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(
                "secret key file must be owner-held, mode 0600-or-stricter, and single-link".into(),
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("secret key handle identifies a Windows reparse point".into());
        }
    }
    let mut secret = Zeroizing::new(Vec::with_capacity(32));
    Read::by_ref(&mut file).take(33).read_to_end(&mut secret)?;
    if secret.len() != 32 || file.metadata()?.len() != 32 {
        return Err("secret key file changed while it was being read".into());
    }
    Ok(secret)
}

fn write_create_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("output path must be absolute".into());
    }
    if path.exists() {
        return Err("refusing to overwrite an existing signer response".into());
    }
    reject_reparse_ancestors(path, true)?;
    let parent = path.parent().ok_or("output path has no parent directory")?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("output file name is not valid Unicode")?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.new",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        fs::hard_link(&temporary, path)?;
        sync_parent_directory(parent)?;
        Ok(())
    })();
    if temporary.exists() {
        fs::remove_file(&temporary)?;
        sync_parent_directory(parent)?;
    }
    result
}

fn reject_reparse_ancestors(
    path: &Path,
    allow_missing_leaf: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut current = if allow_missing_leaf && !path.exists() {
        path.parent()
    } else {
        Some(path)
    };
    while let Some(candidate) = current {
        let metadata = fs::symlink_metadata(candidate)?;
        if metadata.file_type().is_symlink() {
            return Err("signer path traverses a symbolic link".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;

            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err("signer path traverses a Windows reparse point".into());
            }
        }
        current = candidate.parent();
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

fn parse_hex32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("value must be 64 lowercase hexadecimal characters".to_owned());
    }
    let bytes = hex::decode(value).map_err(|_| "value is not hexadecimal".to_owned())?;
    bytes
        .try_into()
        .map_err(|_| "value must encode exactly 32 bytes".to_owned())
}

fn parse_canonical_u64(value: &str) -> Result<u64, Box<dyn std::error::Error>> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("generation must be a canonical unsigned decimal string".into());
    }
    Ok(value.parse()?)
}

fn parse_positive_canonical_u64(
    value: &str,
    label: &'static str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let parsed = parse_canonical_u64(value)?;
    if parsed == 0 {
        return Err(format!("{label} must be positive").into());
    }
    Ok(parsed)
}

fn parse_nonzero_hex32(
    value: &str,
    label: &'static str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let parsed = parse_hex32(value)?;
    if parsed == [0; 32] {
        return Err(format!("{label} must be nonzero").into());
    }
    Ok(parsed)
}

fn parse_hex64(value: &str) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("value must be 128 lowercase hexadecimal characters".into());
    }
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "value must encode exactly 64 bytes")?)
}

#[cfg(test)]
mod tests {
    use cmfd_consensus::{
        CONSENSUS_SIGNATURE_BYTES, InputWitness, OutPoint, OutputLock, TRANSACTION_VERSION,
        Transaction, TxInput, TxOutput, encode_transaction,
    };
    use cmfd_node::wallet_signing_protocol::{
        KeyringAnchorV1, MAX_SIGNING_PACKAGE_BYTES, SignerCapabilitiesV1, SigningAlgorithmV1,
        SigningInputV1, WalletKeyId, signer_key_set_digest,
    };
    use k256::schnorr::signature::Verifier;

    use super::*;

    fn fixture() -> (SigningKey, SignerCapabilitiesV1, SigningPackageV1) {
        let key = SigningKey::from_bytes(&[7; 32]).unwrap();
        let public_key: [u8; 32] = key.verifying_key().to_bytes().into();
        let key_id = wallet_key_id(&public_key);
        let signer_id = SignerId([8; 32]);
        let algorithm = SigningAlgorithmV1::Bip340Secp256k1;
        let capabilities = SignerCapabilitiesV1 {
            signer_id,
            algorithm,
            max_signatures_per_request: 16,
            max_package_bytes: MAX_SIGNING_PACKAGE_BYTES as u32,
            key_set_digest: signer_key_set_digest(signer_id, algorithm, &[key_id]).unwrap(),
        };
        let transaction = Transaction {
            network_id: [1; 32],
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: OutPoint {
                    txid: [2; 32],
                    index: 0,
                },
                witness: InputWitness::Key {
                    public_key,
                    signature: vec![0; CONSENSUS_SIGNATURE_BYTES],
                },
            }],
            outputs: vec![TxOutput {
                value: 90,
                lock: OutputLock::Key(public_key),
                spendable_height: 10,
            }],
        };
        let package = SigningPackageV1 {
            network_id: transaction.network_id,
            consensus_fingerprint: [3; 32],
            genesis: [4; 32],
            prepared_anchor: WithdrawalAnchorV1 {
                key_id: [5; 32],
                journal_instance_id: [6; 32],
                generation: 1,
                commitment: [7; 32],
            },
            request_id: "withdrawal-1".to_owned(),
            request_digest: [9; 32],
            policy_id: [10; 32],
            keyring_anchor: KeyringAnchorV1 {
                instance_id: [11; 32],
                generation: 1,
                commitment: [12; 32],
            },
            unsigned_transaction: encode_transaction(&transaction).unwrap(),
            signing_digest: transaction.signing_digest(),
            inputs: vec![SigningInputV1 {
                input_index: 0,
                outpoint: transaction.inputs[0].previous,
                value_atoms: 100,
                key_id,
                public_key,
                signer_id,
                capability_digest: capabilities.digest().unwrap(),
            }],
        };
        (key, capabilities, package)
    }

    struct TrustedFixture {
        signing_key: SigningKey,
        authority_public_key: [u8; 32],
        package: SigningPackageV1,
        package_bytes: Vec<u8>,
        document: SigningPackageDocument,
        context: TrustedContextDocument,
        envelope: TrustedContextEnvelope,
    }

    fn anchor_document(anchor: WithdrawalAnchorV1) -> WithdrawalAnchorDocument {
        WithdrawalAnchorDocument {
            key_id: hex::encode(anchor.key_id),
            journal_instance_id: hex::encode(anchor.journal_instance_id),
            generation: anchor.generation.to_string(),
            commitment: hex::encode(anchor.commitment),
        }
    }

    fn trusted_fixture() -> TrustedFixture {
        let (signing_key, capabilities, package) = fixture();
        let package_bytes = package.encode().unwrap();
        let package_digest = package.digest().unwrap();
        let package_bytes_digest = exact_bytes_digest(SIGNER_PACKAGE_BYTES_DOMAIN, &package_bytes);
        let signing_public_key: [u8; 32] = signing_key.verifying_key().to_bytes().into();
        let signing_key_id = wallet_key_id(&signing_public_key);
        let approval_action_anchor = WithdrawalAnchorV1 {
            key_id: package.prepared_anchor.key_id,
            journal_instance_id: package.prepared_anchor.journal_instance_id,
            // Deliberately leave room for unrelated journal transitions between
            // package attachment and this approval action.
            generation: package.prepared_anchor.generation + 7,
            commitment: [15; 32],
        };
        let release_authorized_anchor = WithdrawalAnchorV1 {
            key_id: approval_action_anchor.key_id,
            journal_instance_id: approval_action_anchor.journal_instance_id,
            generation: approval_action_anchor.generation + 1,
            commitment: [16; 32],
        };
        let decision_id = [17; 32];
        let approver = SigningKey::from_bytes(&[18; 32]).unwrap();
        let approver_public_key: [u8; 32] = approver.verifying_key().to_bytes().into();
        let mut approval = SignedApprovalDocument {
            schema: APPROVAL_SCHEMA.to_owned(),
            action: "release".to_owned(),
            decision_id: hex::encode(decision_id),
            policy_id: hex::encode(package.policy_id),
            action_anchor: anchor_document(approval_action_anchor),
            request_id: package.request_id.clone(),
            request_digest: hex::encode(package.request_digest),
            transaction_signing_digest: hex::encode(package.signing_digest),
            // This is intentionally long expired relative to wall-clock time.
            // ReleaseAuthorized recovery must validate the original interval,
            // not apply expiry a second time after the decision was persisted.
            authorized_at_unix_seconds: "100".to_owned(),
            expires_at_unix_seconds: "200".to_owned(),
            signatures: Vec::new(),
        };
        let approval_digest = approval_signing_digest(&approval).unwrap();
        let approval_signature: Signature = approver.sign(&approval_digest);
        approval.signatures.push(ApprovalSignatureDocument {
            public_key: hex::encode(approver_public_key),
            signature: hex::encode(approval_signature.to_bytes()),
        });
        let release_authorization_digest = release_authorization_digest(
            &package_digest,
            ReleaseAuthorizationV1 {
                release_authorized_anchor,
                decision_id,
                approval_digest,
            },
        )
        .unwrap();
        let context = TrustedContextDocument {
            schema: TRUSTED_CONTEXT_SCHEMA.to_owned(),
            network_id: hex::encode(package.network_id),
            consensus_fingerprint: hex::encode(package.consensus_fingerprint),
            genesis: hex::encode(package.genesis),
            request_id: package.request_id.clone(),
            request_digest: hex::encode(package.request_digest),
            policy_id: hex::encode(package.policy_id),
            prepared_anchor: anchor_document(package.prepared_anchor),
            approval_action_anchor: anchor_document(approval_action_anchor),
            keyring_anchor: KeyringAnchorDocument {
                instance_id: hex::encode(package.keyring_anchor.instance_id),
                generation: package.keyring_anchor.generation.to_string(),
                commitment: hex::encode(package.keyring_anchor.commitment),
            },
            signing_digest: hex::encode(package.signing_digest),
            signer_package_digest: hex::encode(package_digest),
            signer_package_bytes_digest: hex::encode(package_bytes_digest),
            signer: TrustedSignerDocument {
                signer_id: hex::encode(capabilities.signer_id.0),
                algorithm: "bip340-secp256k1".to_owned(),
                max_signatures_per_request: capabilities.max_signatures_per_request,
                max_package_bytes: capabilities.max_package_bytes,
                key_ids: vec![hex::encode(signing_key_id.0)],
                capability_digest: hex::encode(capabilities.digest().unwrap()),
                signing_public_key: hex::encode(signing_public_key),
                signing_key_id: hex::encode(signing_key_id.0),
                assigned_input_indices: vec![0],
            },
            transaction: TrustedTransactionDocument {
                recipient_destination: hex::encode(signing_public_key),
                amount_atoms: "90".to_owned(),
                fee_atoms: "10".to_owned(),
                change_destination: None,
                change_atoms: "0".to_owned(),
                spendable_height: "10".to_owned(),
                input_count: 1,
                input_total_atoms: "100".to_owned(),
            },
            release_authorized_anchor: anchor_document(release_authorized_anchor),
            decision_id: hex::encode(decision_id),
            approval_digest: hex::encode(approval_digest),
            release_authorization_digest: hex::encode(release_authorization_digest),
            approval_rule: TrustedApprovalRuleDocument {
                threshold: 1,
                public_keys: vec![hex::encode(approver_public_key)],
            },
        };
        let authority = SigningKey::from_bytes(&[19; 32]).unwrap();
        let authority_public_key: [u8; 32] = authority.verifying_key().to_bytes().into();
        let context_bytes = serde_json::to_vec(&context).unwrap();
        let context_digest = exact_bytes_digest(TRUSTED_CONTEXT_DOMAIN, &context_bytes);
        let context_signature: Signature = authority.sign(&context_digest);
        let envelope = TrustedContextEnvelope {
            schema: TRUSTED_CONTEXT_ENVELOPE_SCHEMA.to_owned(),
            context_base64: BASE64_STANDARD.encode(&context_bytes),
            context_digest: hex::encode(context_digest),
            signature: hex::encode(context_signature.to_bytes()),
        };
        let document = SigningPackageDocument {
            api_version: CUSTODY_API_VERSION.to_owned(),
            request_id: package.request_id.clone(),
            request_digest: hex::encode(package.request_digest),
            current_anchor: anchor_document(release_authorized_anchor),
            prepared_anchor: Some(anchor_document(package.prepared_anchor)),
            approval_action_anchor: anchor_document(approval_action_anchor),
            signing_digest: hex::encode(package.signing_digest),
            signer_package_digest: hex::encode(package_digest),
            signer_package_bytes_digest: Some(hex::encode(package_bytes_digest)),
            signer_package_base64: BASE64_STANDARD.encode(&package_bytes),
            release_authorization: ReleaseAuthorizationDocument {
                release_authorized_anchor: anchor_document(release_authorized_anchor),
                decision_id: hex::encode(decision_id),
                approval_digest: hex::encode(approval_digest),
                release_authorization_digest: hex::encode(release_authorization_digest),
                signed_approval: approval,
            },
        };
        TrustedFixture {
            signing_key,
            authority_public_key,
            package,
            package_bytes,
            document,
            context,
            envelope,
        }
    }

    #[test]
    fn response_signs_transaction_and_release_bound_authorization() {
        let (key, capabilities, package) = fixture();
        let package_digest = package.digest().unwrap();
        let release_digest = [13; 32];
        let response = sign_response(
            &package,
            package_digest,
            release_digest,
            capabilities.signer_id,
            capabilities.digest().unwrap(),
            &key,
        )
        .unwrap();
        assert_eq!(response.signatures.len(), 1);
        let signature = &response.signatures[0];
        key.verifying_key()
            .verify(
                &package.signing_digest,
                &Signature::try_from(signature.transaction_signature.as_slice()).unwrap(),
            )
            .unwrap();
        let authorization_digest = package_authorization_digest(
            &package_digest,
            &release_digest,
            0,
            signature.key_id,
            capabilities.signer_id,
            &capabilities.digest().unwrap(),
            &signature.transaction_signature,
        );
        key.verifying_key()
            .verify(
                &authorization_digest,
                &Signature::try_from(signature.package_authorization_signature.as_slice()).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn signer_rejects_an_unassigned_or_mismatched_key() {
        let (key, capabilities, package) = fixture();
        assert!(
            sign_response(
                &package,
                package.digest().unwrap(),
                [13; 32],
                SignerId([99; 32]),
                capabilities.digest().unwrap(),
                &key
            )
            .is_err()
        );
        let other = SigningKey::from_bytes(&[14; 32]).unwrap();
        assert!(
            sign_response(
                &package,
                package.digest().unwrap(),
                [13; 32],
                package.inputs[0].signer_id,
                capabilities.digest().unwrap(),
                &other
            )
            .is_err()
        );
        assert!(
            sign_response(
                &package,
                package.digest().unwrap(),
                [13; 32],
                package.inputs[0].signer_id,
                [0x55; 32],
                &key
            )
            .is_err()
        );
    }

    #[test]
    fn authenticated_context_validates_interleaving_and_expired_recovery() {
        let fixture = trusted_fixture();
        let (authenticated_context, _) =
            authenticate_trusted_context(&fixture.envelope, fixture.authority_public_key).unwrap();
        assert_eq!(
            serde_json::to_vec(&authenticated_context).unwrap(),
            serde_json::to_vec(&fixture.context).unwrap()
        );
        let package_digest = fixture.package.digest().unwrap();
        validate_expected_package(
            &fixture.document,
            &fixture.package,
            &fixture.package_bytes,
            package_digest,
            &fixture.context,
        )
        .unwrap();
        validate_signer_context(&fixture.package, &fixture.package_bytes, &fixture.context)
            .unwrap();
        validate_transaction_intent(&fixture.package, &fixture.context).unwrap();
        let release_digest = validate_release_authorization(
            &fixture.document,
            &fixture.package,
            package_digest,
            &fixture.context,
        )
        .unwrap();
        let response = sign_response(
            &fixture.package,
            package_digest,
            release_digest,
            fixture.package.inputs[0].signer_id,
            fixture.package.inputs[0].capability_digest,
            &fixture.signing_key,
        )
        .unwrap();
        assert_eq!(response.signatures.len(), 1);
    }

    #[test]
    fn context_and_release_tampering_fail_closed() {
        let fixture = trusted_fixture();
        let mut changed_context = fixture.envelope.clone();
        let mut decoded_context = fixture.context.clone();
        decoded_context.decision_id = hex::encode([0x41; 32]);
        changed_context.context_base64 =
            BASE64_STANDARD.encode(serde_json::to_vec(&decoded_context).unwrap());
        assert!(
            authenticate_trusted_context(&changed_context, fixture.authority_public_key).is_err()
        );

        let mut changed_signature = fixture.envelope.clone();
        changed_signature.signature = "00".repeat(64);
        assert!(
            authenticate_trusted_context(&changed_signature, fixture.authority_public_key).is_err()
        );

        let mut changed_release = fixture.document.clone();
        changed_release.approval_action_anchor.commitment = hex::encode([0x42; 32]);
        assert!(
            validate_release_authorization(
                &changed_release,
                &fixture.package,
                fixture.package.digest().unwrap(),
                &fixture.context,
            )
            .is_err()
        );

        let mut changed_approval = fixture.document.clone();
        changed_approval
            .release_authorization
            .signed_approval
            .signatures[0]
            .signature = "00".repeat(64);
        assert!(
            validate_release_authorization(
                &changed_approval,
                &fixture.package,
                fixture.package.digest().unwrap(),
                &fixture.context,
            )
            .is_err()
        );
    }

    #[test]
    fn signer_context_and_transaction_intent_tampering_fail_closed() {
        let fixture = trusted_fixture();
        let mut changed_context = fixture.context.clone();
        changed_context.signer.capability_digest = hex::encode([0x43; 32]);
        assert!(
            validate_signer_context(&fixture.package, &fixture.package_bytes, &changed_context)
                .is_err()
        );

        let mut changed_context = fixture.context.clone();
        changed_context.transaction.amount_atoms = "89".to_owned();
        assert!(validate_transaction_intent(&fixture.package, &changed_context).is_err());
        changed_context.transaction.amount_atoms = "90".to_owned();
        changed_context.transaction.fee_atoms = "9".to_owned();
        assert!(validate_transaction_intent(&fixture.package, &changed_context).is_err());
    }

    #[test]
    fn invalid_approval_interval_and_anchor_order_fail_closed() {
        let fixture = trusted_fixture();
        let mut invalid_interval = fixture.document.clone();
        invalid_interval
            .release_authorization
            .signed_approval
            .expires_at_unix_seconds = "1001".to_owned();
        assert!(
            validate_release_authorization(
                &invalid_interval,
                &fixture.package,
                fixture.package.digest().unwrap(),
                &fixture.context,
            )
            .is_err()
        );

        let mut invalid_anchor_context = fixture.context.clone();
        invalid_anchor_context.approval_action_anchor.generation =
            fixture.package.prepared_anchor.generation.to_string();
        assert!(
            validate_release_authorization(
                &fixture.document,
                &fixture.package,
                fixture.package.digest().unwrap(),
                &invalid_anchor_context,
            )
            .is_err()
        );
    }

    #[test]
    fn approval_threshold_requires_two_distinct_authorized_signatures() {
        let fixture = trusted_fixture();
        let mut context = fixture.context.clone();
        let mut approval = fixture
            .document
            .release_authorization
            .signed_approval
            .clone();
        let mut approvers = [
            SigningKey::from_bytes(&[21; 32]).unwrap(),
            SigningKey::from_bytes(&[22; 32]).unwrap(),
            SigningKey::from_bytes(&[23; 32]).unwrap(),
        ]
        .into_iter()
        .map(|key| {
            let public_key: [u8; 32] = key.verifying_key().to_bytes().into();
            (public_key, key)
        })
        .collect::<Vec<_>>();
        approvers.sort_unstable_by_key(|(public_key, _)| *public_key);
        context.approval_rule = TrustedApprovalRuleDocument {
            threshold: 2,
            public_keys: approvers
                .iter()
                .map(|(public_key, _)| hex::encode(public_key))
                .collect(),
        };
        approval.signatures.clear();
        let digest = approval_signing_digest(&approval).unwrap();
        for (public_key, key) in approvers.iter().take(2) {
            let signature: Signature = key.sign(&digest);
            approval.signatures.push(ApprovalSignatureDocument {
                public_key: hex::encode(public_key),
                signature: hex::encode(signature.to_bytes()),
            });
        }
        assert_eq!(
            validate_signed_approval(&approval, &fixture.package, &context).unwrap(),
            digest
        );

        let mut insufficient = approval.clone();
        insufficient.signatures.pop();
        assert!(validate_signed_approval(&insufficient, &fixture.package, &context).is_err());

        let mut duplicated = approval.clone();
        duplicated.signatures[1] = duplicated.signatures[0].clone();
        assert!(validate_signed_approval(&duplicated, &fixture.package, &context).is_err());
    }

    #[test]
    fn parsers_reject_noncanonical_values() {
        assert!(parse_hex32(&("AA".repeat(32))).is_err());
        assert!(parse_canonical_u64("01").is_err());
        assert_eq!(parse_canonical_u64("0").unwrap(), 0);
        let _: WalletKeyId = wallet_key_id(&[2; 32]);
    }
}
