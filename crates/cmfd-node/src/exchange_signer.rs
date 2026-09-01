//! Keyring-bound coordination for local and externally produced wallet signatures.
//!
//! The node never trusts a transport or signer claim by itself. Every response
//! is canonically decoded, matched to the independently authenticated keyring,
//! and verified by the provider-neutral signing protocol before transaction
//! bytes are returned. An external signer may be an HSM bridge, a remote
//! service, or a threshold service whose aggregate public key is stored in the
//! keyring; private material never enters this module for external keys.

use std::collections::{BTreeMap, BTreeSet};

use cmfd_consensus::MAX_TRANSACTION_INPUTS;
use thiserror::Error;

use crate::exchange_local_signer::{
    ExchangeLocalSignerError, LocalSigningExpectationV1, local_signer_id,
    sign_and_assemble_local_package,
};
use crate::wallet_keyring::{
    KeyLifecycle, KeyStorageBinding, WalletKeySummary, WalletKeyring, WalletKeyringError,
};
use crate::wallet_signing_protocol::{
    AssembledTransactionV1, ExpectedSignerBindingV1, ExpectedSigningContextV1, InputSignatureV1,
    MAX_SIGNING_PACKAGE_BYTES, SignerCapabilitiesV1, SignerId, SignerResponseV1,
    SigningAlgorithmV1, SigningPackageV1, SigningProtocolError, WithdrawalAnchorV1,
    package_authorization_digest, signer_key_set_digest,
};

#[derive(Debug, Error)]
pub(crate) enum ExchangeSignerError {
    #[error(transparent)]
    Protocol(#[from] SigningProtocolError),
    #[error(transparent)]
    Keyring(#[from] WalletKeyringError),
    #[error(transparent)]
    Local(#[from] ExchangeLocalSignerError),
    #[error("wallet key is not assigned to a signable provider")]
    UnsignableKey,
    #[error("wallet key signer binding collides with another provider class")]
    SignerBindingCollision,
    #[error("signing package belongs to another keyring runtime binding: {0}")]
    BindingMismatch(&'static str),
    #[error("signing package belongs to another keyring generation")]
    KeyringAnchorMismatch,
    #[error("signing package belongs to another withdrawal policy")]
    PolicyMismatch,
    #[error("signing package prepared anchor is not the independently expected anchor")]
    PreparedAnchorMismatch,
    #[error("signing package digest is not the independently expected digest")]
    PackageDigestMismatch,
    #[error("external signer responses are not strictly ordered by signer id")]
    ResponseOrdering,
    #[error("external signer response is duplicated")]
    DuplicateResponse,
    #[error("external signer response came from an unknown or local signer")]
    UnexpectedResponse,
    #[error("one or more external signer responses are missing")]
    MissingResponse,
    #[error("external signer response does not cover exactly its assigned inputs")]
    ResponseCoverage,
    #[error("signing protocol bound cannot be represented")]
    ProtocolBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SigningExpectationV1 {
    pub package_digest: [u8; 32],
    pub policy_id: [u8; 32],
    pub prepared_anchor: WithdrawalAnchorV1,
    pub release_authorization_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyringSignerProfileV1 {
    pub capabilities: SignerCapabilitiesV1,
    pub key_ids: Vec<crate::wallet_signing_protocol::WalletKeyId>,
    pub local: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoordinatedSignedPackageV1 {
    pub assembled: AssembledTransactionV1,
    /// Canonical responses in signer-id order, including any local response.
    /// Callers may retain these exact public evidence bytes independently.
    pub canonical_responses: Vec<Vec<u8>>,
}

/// Returns the canonical signer profile for one authenticated keyring key.
pub(crate) fn signer_profile_for_key(
    keyring: &WalletKeyring,
    key: WalletKeySummary,
) -> Result<KeyringSignerProfileV1, ExchangeSignerError> {
    keyring_signer_profiles(keyring)?
        .into_iter()
        .find(|profile| profile.key_ids.binary_search(&key.key_id).is_ok())
        .ok_or(ExchangeSignerError::UnsignableKey)
}

/// Derives all signer capabilities solely from the authenticated keyring. The
/// package cannot expand a provider's key set or choose its own limits.
pub(crate) fn keyring_signer_profiles(
    keyring: &WalletKeyring,
) -> Result<Vec<KeyringSignerProfileV1>, ExchangeSignerError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ProviderClass {
        Local,
        External,
    }

    let local_id = local_signer_id(keyring.anchor())?;
    let mut grouped: BTreeMap<SignerId, (ProviderClass, Vec<_>)> = BTreeMap::new();
    for key in keyring.summaries() {
        if key.lifecycle == KeyLifecycle::Disabled {
            continue;
        }
        let (signer_id, class) = match key.storage {
            KeyStorageBinding::Local => (local_id, ProviderClass::Local),
            KeyStorageBinding::External { signer_id } => (signer_id, ProviderClass::External),
            KeyStorageBinding::WatchOnly => continue,
        };
        let entry = grouped.entry(signer_id).or_insert((class, Vec::new()));
        if entry.0 != class {
            return Err(ExchangeSignerError::SignerBindingCollision);
        }
        entry.1.push(key.key_id);
    }

    let max_signatures_per_request =
        u16::try_from(MAX_TRANSACTION_INPUTS).map_err(|_| ExchangeSignerError::ProtocolBound)?;
    let max_package_bytes =
        u32::try_from(MAX_SIGNING_PACKAGE_BYTES).map_err(|_| ExchangeSignerError::ProtocolBound)?;
    let algorithm = SigningAlgorithmV1::Bip340Secp256k1;
    let mut profiles = Vec::with_capacity(grouped.len());
    for (signer_id, (class, mut key_ids)) in grouped {
        key_ids.sort_unstable();
        key_ids.dedup();
        let capabilities = SignerCapabilitiesV1 {
            signer_id,
            algorithm,
            max_signatures_per_request,
            max_package_bytes,
            key_set_digest: signer_key_set_digest(signer_id, algorithm, &key_ids)?,
        };
        // Round-trip validation freezes the same bounds used by transport.
        let capabilities = SignerCapabilitiesV1::decode(&capabilities.encode()?)?;
        profiles.push(KeyringSignerProfileV1 {
            capabilities,
            key_ids,
            local: class == ProviderClass::Local,
        });
    }
    if profiles.is_empty() {
        return Err(ExchangeSignerError::UnsignableKey);
    }
    Ok(profiles)
}

pub(crate) fn expected_keyring_signing_context(
    keyring: &WalletKeyring,
    package: &SigningPackageV1,
    expected: SigningExpectationV1,
) -> Result<ExpectedSigningContextV1, ExchangeSignerError> {
    validate_package_binding(keyring, package, expected)?;
    let profiles = keyring_signer_profiles(keyring)?;
    for input in &package.inputs {
        let key = keyring
            .key(input.key_id)
            .ok_or(ExchangeSignerError::UnsignableKey)?;
        if key.public_key != input.public_key || key.lifecycle == KeyLifecycle::Disabled {
            return Err(ExchangeSignerError::UnsignableKey);
        }
        let profile = profiles
            .iter()
            .find(|profile| profile.key_ids.binary_search(&input.key_id).is_ok())
            .ok_or(ExchangeSignerError::UnsignableKey)?;
        if input.signer_id != profile.capabilities.signer_id
            || input.capability_digest != profile.capabilities.digest()?
        {
            return Err(ExchangeSignerError::UnsignableKey);
        }
    }
    let context = ExpectedSigningContextV1 {
        package_digest: expected.package_digest,
        release_authorization_digest: expected.release_authorization_digest,
        signers: profiles
            .into_iter()
            .map(|profile| ExpectedSignerBindingV1 {
                capabilities: profile.capabilities,
                key_ids: profile.key_ids,
            })
            .collect(),
    };
    context.validate_package(package)?;
    Ok(context)
}

/// Combines an optional local-key response with one canonical response from
/// each external signer referenced by the package. The external response byte
/// order is itself canonical and duplicates are rejected before verification.
pub(crate) fn sign_and_assemble_keyring_package(
    keyring: &WalletKeyring,
    package: &SigningPackageV1,
    expected: SigningExpectationV1,
    external_response_bytes: &[Vec<u8>],
) -> Result<CoordinatedSignedPackageV1, ExchangeSignerError> {
    let context = expected_keyring_signing_context(keyring, package, expected)?;
    let profiles = keyring_signer_profiles(keyring)?;
    let referenced: BTreeSet<_> = package.inputs.iter().map(|input| input.signer_id).collect();
    let local_profile = profiles
        .iter()
        .find(|profile| profile.local && referenced.contains(&profile.capabilities.signer_id));
    let external_expected: BTreeSet<_> = profiles
        .iter()
        .filter(|profile| !profile.local && referenced.contains(&profile.capabilities.signer_id))
        .map(|profile| profile.capabilities.signer_id)
        .collect();

    if external_expected.is_empty() {
        if !external_response_bytes.is_empty() {
            return Err(ExchangeSignerError::UnexpectedResponse);
        }
        let signed = sign_and_assemble_local_package(
            keyring,
            package,
            LocalSigningExpectationV1 {
                package_digest: expected.package_digest,
                policy_id: expected.policy_id,
                prepared_anchor: expected.prepared_anchor,
                release_authorization_digest: expected.release_authorization_digest,
            },
        )?;
        return Ok(CoordinatedSignedPackageV1 {
            assembled: signed.assembled,
            canonical_responses: vec![signed.response.encode()?],
        });
    }

    let mut responses =
        Vec::with_capacity(external_response_bytes.len() + usize::from(local_profile.is_some()));
    if let Some(profile) = local_profile {
        responses.push(sign_local_response(
            keyring,
            package,
            profile,
            expected.release_authorization_digest,
        )?);
    }

    let mut prior = None;
    let mut received = BTreeSet::new();
    for exact in external_response_bytes {
        let response = SignerResponseV1::decode(exact)?;
        if prior.is_some_and(|value| value >= response.signer_id) {
            return Err(ExchangeSignerError::ResponseOrdering);
        }
        prior = Some(response.signer_id);
        if !external_expected.contains(&response.signer_id) {
            return Err(ExchangeSignerError::UnexpectedResponse);
        }
        if !received.insert(response.signer_id) {
            return Err(ExchangeSignerError::DuplicateResponse);
        }
        let assigned: Vec<_> = package
            .inputs
            .iter()
            .filter(|input| input.signer_id == response.signer_id)
            .map(|input| (input.input_index, input.key_id))
            .collect();
        let supplied: Vec<_> = response
            .signatures
            .iter()
            .map(|signature| (signature.input_index, signature.key_id))
            .collect();
        if supplied != assigned {
            return Err(ExchangeSignerError::ResponseCoverage);
        }
        responses.push(response);
    }
    if received != external_expected {
        return Err(ExchangeSignerError::MissingResponse);
    }
    responses.sort_unstable_by_key(|response| response.signer_id);
    let assembled =
        crate::wallet_signing_protocol::assemble_signed_transaction(package, &context, &responses)?;
    let canonical_responses = responses
        .iter()
        .map(SignerResponseV1::encode)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CoordinatedSignedPackageV1 {
        assembled,
        canonical_responses,
    })
}

fn sign_local_response(
    keyring: &WalletKeyring,
    package: &SigningPackageV1,
    profile: &KeyringSignerProfileV1,
    release_authorization_digest: [u8; 32],
) -> Result<SignerResponseV1, ExchangeSignerError> {
    let package_digest = package.digest()?;
    let capability_digest = profile.capabilities.digest()?;
    let mut signatures = Vec::new();
    for input in &package.inputs {
        if input.signer_id != profile.capabilities.signer_id {
            continue;
        }
        let transaction_signature =
            keyring.sign_local_digest(input.key_id, &package.signing_digest)?;
        let authorization_digest = package_authorization_digest(
            &package_digest,
            &release_authorization_digest,
            input.input_index,
            input.key_id,
            profile.capabilities.signer_id,
            &capability_digest,
            &transaction_signature,
        );
        let package_authorization_signature =
            keyring.sign_local_digest(input.key_id, &authorization_digest)?;
        signatures.push(InputSignatureV1 {
            input_index: input.input_index,
            key_id: input.key_id,
            transaction_signature,
            package_authorization_signature,
        });
    }
    let response = SignerResponseV1 {
        package_digest,
        release_authorization_digest,
        signer_id: profile.capabilities.signer_id,
        capability_digest,
        signatures,
    };
    Ok(SignerResponseV1::decode(&response.encode()?)?)
}

fn validate_package_binding(
    keyring: &WalletKeyring,
    package: &SigningPackageV1,
    expected: SigningExpectationV1,
) -> Result<(), ExchangeSignerError> {
    let binding = keyring.binding();
    if package.network_id != binding.network_id {
        return Err(ExchangeSignerError::BindingMismatch("network_id"));
    }
    if package.consensus_fingerprint != binding.consensus_fingerprint {
        return Err(ExchangeSignerError::BindingMismatch(
            "consensus_fingerprint",
        ));
    }
    if package.genesis != binding.genesis_hash {
        return Err(ExchangeSignerError::BindingMismatch("genesis_hash"));
    }
    if package.keyring_anchor != keyring.anchor().signing_protocol_anchor() {
        return Err(ExchangeSignerError::KeyringAnchorMismatch);
    }
    if package.policy_id != expected.policy_id {
        return Err(ExchangeSignerError::PolicyMismatch);
    }
    if package.prepared_anchor != expected.prepared_anchor {
        return Err(ExchangeSignerError::PreparedAnchorMismatch);
    }
    if package.digest()? != expected.package_digest {
        return Err(ExchangeSignerError::PackageDigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cmfd_consensus::{
        CONSENSUS_SIGNATURE_BYTES, InputWitness, OutPoint, OutputLock, TRANSACTION_VERSION,
        Transaction, TxInput, TxOutput, encode_transaction,
    };
    use k256::schnorr::{Signature, SigningKey, signature::Signer};
    use zeroize::Zeroizing;

    use super::*;
    use crate::wallet_keyring::{KeyRoles, KeyringRuntimeBinding, WalletKeyEntry};
    use crate::wallet_signing_protocol::{
        KeyringAnchorV1, SigningInputV1, WithdrawalAnchorV1, wallet_key_id,
    };

    fn signing_key(marker: u8) -> SigningKey {
        SigningKey::from_bytes(&[marker; 32]).unwrap()
    }

    fn public_key(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes().into()
    }

    fn fixture() -> (
        WalletKeyring,
        SigningKey,
        SigningPackageV1,
        SigningExpectationV1,
    ) {
        let local = signing_key(1);
        let external = signing_key(2);
        let external_id = SignerId([0x52; 32]);
        let keyring = WalletKeyring::new_genesis(
            KeyringRuntimeBinding {
                network_id: [0x11; 32],
                consensus_fingerprint: [0x12; 32],
                genesis_hash: [0x13; 32],
            },
            [0x21; 32],
            vec![
                WalletKeyEntry::local(
                    Zeroizing::new(local.to_bytes().into()),
                    KeyRoles::DEPOSIT,
                    KeyLifecycle::Active,
                )
                .unwrap(),
                WalletKeyEntry::external(
                    public_key(&external),
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Active,
                    external_id,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let local_summary = keyring.key(wallet_key_id(&public_key(&local))).unwrap();
        let external_summary = keyring.key(wallet_key_id(&public_key(&external))).unwrap();
        let local_profile = signer_profile_for_key(&keyring, local_summary).unwrap();
        let external_profile = signer_profile_for_key(&keyring, external_summary).unwrap();
        let transaction = Transaction {
            network_id: [0x11; 32],
            version: TRANSACTION_VERSION,
            inputs: vec![
                TxInput {
                    previous: OutPoint {
                        txid: [0x31; 32],
                        index: 0,
                    },
                    witness: InputWitness::Key {
                        public_key: local_summary.public_key,
                        signature: vec![0; CONSENSUS_SIGNATURE_BYTES],
                    },
                },
                TxInput {
                    previous: OutPoint {
                        txid: [0x32; 32],
                        index: 1,
                    },
                    witness: InputWitness::Key {
                        public_key: external_summary.public_key,
                        signature: vec![0; CONSENSUS_SIGNATURE_BYTES],
                    },
                },
            ],
            outputs: vec![TxOutput {
                value: 975,
                lock: OutputLock::Key(external_summary.public_key),
                spendable_height: 9,
            }],
        };
        let signing_digest = transaction.signing_digest();
        let prepared_anchor = WithdrawalAnchorV1 {
            key_id: [0x41; 32],
            journal_instance_id: [0x42; 32],
            generation: 7,
            commitment: [0x43; 32],
        };
        let package = SigningPackageV1 {
            network_id: [0x11; 32],
            consensus_fingerprint: [0x12; 32],
            genesis: [0x13; 32],
            prepared_anchor,
            request_id: "external-signer-1".to_owned(),
            request_digest: [0x44; 32],
            policy_id: [0x45; 32],
            keyring_anchor: KeyringAnchorV1 {
                instance_id: keyring.instance_id(),
                generation: keyring.generation(),
                commitment: keyring.commitment(),
            },
            unsigned_transaction: encode_transaction(&transaction).unwrap(),
            signing_digest,
            inputs: vec![
                SigningInputV1 {
                    input_index: 0,
                    outpoint: transaction.inputs[0].previous,
                    value_atoms: 400,
                    key_id: local_summary.key_id,
                    public_key: local_summary.public_key,
                    signer_id: local_profile.capabilities.signer_id,
                    capability_digest: local_profile.capabilities.digest().unwrap(),
                },
                SigningInputV1 {
                    input_index: 1,
                    outpoint: transaction.inputs[1].previous,
                    value_atoms: 600,
                    key_id: external_summary.key_id,
                    public_key: external_summary.public_key,
                    signer_id: external_profile.capabilities.signer_id,
                    capability_digest: external_profile.capabilities.digest().unwrap(),
                },
            ],
        };
        let expected = SigningExpectationV1 {
            package_digest: package.digest().unwrap(),
            policy_id: package.policy_id,
            prepared_anchor,
            release_authorization_digest: [0x71; 32],
        };
        (keyring, external, package, expected)
    }

    fn external_response(package: &SigningPackageV1, key: &SigningKey) -> SignerResponseV1 {
        let input = &package.inputs[1];
        let transaction_signature: Signature = key.sign(&package.signing_digest);
        let transaction_signature = transaction_signature.to_bytes();
        let authorization_digest = package_authorization_digest(
            &package.digest().unwrap(),
            &[0x71; 32],
            input.input_index,
            input.key_id,
            input.signer_id,
            &input.capability_digest,
            &transaction_signature,
        );
        let package_authorization_signature: Signature = key.sign(&authorization_digest);
        SignerResponseV1 {
            package_digest: package.digest().unwrap(),
            release_authorization_digest: [0x71; 32],
            signer_id: input.signer_id,
            capability_digest: input.capability_digest,
            signatures: vec![InputSignatureV1 {
                input_index: input.input_index,
                key_id: input.key_id,
                transaction_signature,
                package_authorization_signature: package_authorization_signature.to_bytes(),
            }],
        }
    }

    #[test]
    fn mixed_local_and_external_responses_assemble_exact_transaction() {
        let (keyring, external, package, expected) = fixture();
        let response = external_response(&package, &external).encode().unwrap();
        let signed =
            sign_and_assemble_keyring_package(&keyring, &package, expected, &[response]).unwrap();
        assert_eq!(
            signed.assembled.transaction.signing_digest(),
            package.signing_digest
        );
        assert_eq!(signed.canonical_responses.len(), 2);
        assert_eq!(signed.assembled.transaction.inputs.len(), 2);
        for input in signed.assembled.transaction.inputs {
            let InputWitness::Key { signature, .. } = input.witness else {
                panic!("fixture contains key witnesses")
            };
            assert_eq!(signature.len(), CONSENSUS_SIGNATURE_BYTES);
            assert!(signature.iter().any(|byte| *byte != 0));
        }
    }

    #[test]
    fn external_response_is_required_exact_and_non_replayable() {
        let (keyring, external, package, expected) = fixture();
        assert!(matches!(
            sign_and_assemble_keyring_package(&keyring, &package, expected, &[]),
            Err(ExchangeSignerError::MissingResponse)
        ));

        let mut response = external_response(&package, &external);
        response.package_digest[0] ^= 1;
        let response = response.encode().unwrap();
        assert!(matches!(
            sign_and_assemble_keyring_package(&keyring, &package, expected, &[response]),
            Err(ExchangeSignerError::Protocol(
                SigningProtocolError::PackageDigestMismatch
            ))
        ));

        let mut response = external_response(&package, &external);
        response.release_authorization_digest[0] ^= 1;
        let response = response.encode().unwrap();
        assert!(matches!(
            sign_and_assemble_keyring_package(&keyring, &package, expected, &[response]),
            Err(ExchangeSignerError::Protocol(
                SigningProtocolError::ReleaseAuthorizationMismatch
            ))
        ));
    }

    #[test]
    fn response_must_cover_every_input_assigned_to_its_signer() {
        let (keyring, external, package, expected) = fixture();
        let mut response = external_response(&package, &external);
        response.signatures[0].input_index = 0;
        response.signatures[0].key_id = package.inputs[0].key_id;
        let response = response.encode().unwrap();
        assert!(matches!(
            sign_and_assemble_keyring_package(&keyring, &package, expected, &[response]),
            Err(ExchangeSignerError::ResponseCoverage)
        ));
    }

    #[test]
    fn package_policy_anchor_and_keyring_are_independently_bound() {
        let (keyring, external, package, expected) = fixture();
        let response = external_response(&package, &external).encode().unwrap();
        let mut wrong = expected;
        wrong.policy_id[0] ^= 1;
        assert!(matches!(
            sign_and_assemble_keyring_package(&keyring, &package, wrong, &[response]),
            Err(ExchangeSignerError::PolicyMismatch)
        ));
    }
}
