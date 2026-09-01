//! In-process adapter between the encrypted wallet keyring and the canonical
//! provider-neutral signing protocol.
//!
//! This is a bootstrap adapter for locally stored keys. It is not an HSM,
//! remote signer, quorum, or custody-service claim. The caller must obtain the
//! expected package digest, policy id, and prepared anchor from independently
//! authenticated journal/policy state before invoking it.

use blake3::Hasher;
use cmfd_consensus::MAX_TRANSACTION_INPUTS;
use thiserror::Error;

use crate::wallet_keyring::{
    KeyLifecycle, KeyStorageBinding, KeyringAnchorV1 as StorageKeyringAnchorV1, WalletKeySummary,
    WalletKeyring, WalletKeyringError,
};
use crate::wallet_signing_protocol::{
    AssembledTransactionV1, ExpectedSignerBindingV1, ExpectedSigningContextV1, InputSignatureV1,
    MAX_SIGNING_PACKAGE_BYTES, SignerCapabilitiesV1, SignerId, SignerResponseV1,
    SigningAlgorithmV1, SigningPackageV1, SigningProtocolError, WithdrawalAnchorV1,
    assemble_signed_transaction, package_authorization_digest, signer_key_set_digest,
};

const LOCAL_SIGNER_ID_DOMAIN: &str = "CMFD/NODE/EXCHANGE-LOCAL-SIGNER-ID/V1";

#[derive(Debug, Error)]
pub enum ExchangeLocalSignerError {
    #[error(transparent)]
    Keyring(#[from] WalletKeyringError),
    #[error(transparent)]
    Protocol(#[from] SigningProtocolError),
    #[error("wallet keyring contains no locally signable keys")]
    NoLocallySignableKeys,
    #[error("derived local signer id is invalid")]
    InvalidLocalSignerId,
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
    #[error("signing package input {0} is not a locally signable key")]
    InputNotLocallySignable(u32),
    #[error("signing package input {0} public key does not match the trusted keyring")]
    InputPublicKeyMismatch(u32),
    #[error("local signer protocol bound cannot be represented")]
    ProtocolBound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSignerProfileV1 {
    pub signer_id: SignerId,
    pub capabilities: SignerCapabilitiesV1,
    pub key_ids: Vec<crate::wallet_signing_protocol::WalletKeyId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalSigningExpectationV1 {
    /// Exact digest pinned by authenticated withdrawal journal state.
    pub package_digest: [u8; 32],
    /// Exact policy selected before the signing package was issued.
    pub policy_id: [u8; 32],
    /// Exact Prepared journal anchor authorized to issue the package.
    pub prepared_anchor: WithdrawalAnchorV1,
    /// Exact post-transition authorization digest independently authenticated
    /// by the signer after ReleaseAuthorized is durably pinned.
    pub release_authorization_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSignedPackageV1 {
    pub profile: LocalSignerProfileV1,
    pub expected_context: ExpectedSigningContextV1,
    pub response: SignerResponseV1,
    pub assembled: AssembledTransactionV1,
}

/// Derives a stable identifier for the in-process signer from the random,
/// immutable keyring instance id. Key rotations retain the same signer id.
pub fn local_signer_id(
    keyring_anchor: StorageKeyringAnchorV1,
) -> Result<SignerId, ExchangeLocalSignerError> {
    // Validate all public anchor fields before deriving an identity from them.
    // The encoded bytes are intentionally discarded; the canonical validator
    // is shared with persistence and external rollback-anchor handling.
    keyring_anchor.encode()?;
    let mut hasher = Hasher::new_derive_key(LOCAL_SIGNER_ID_DOMAIN);
    hasher.update(&keyring_anchor.instance_id);
    let signer_id = SignerId(*hasher.finalize().as_bytes());
    if signer_id.0 == [0; 32] {
        return Err(ExchangeLocalSignerError::InvalidLocalSignerId);
    }
    Ok(signer_id)
}

/// Builds the complete authenticated capability key set from local Active and
/// Retired entries. Disabled, external, and watch-only keys are excluded.
pub fn local_signer_profile(
    keyring: &WalletKeyring,
) -> Result<LocalSignerProfileV1, ExchangeLocalSignerError> {
    let signer_id = local_signer_id(keyring.anchor())?;
    let key_ids: Vec<_> = keyring
        .summaries()
        .into_iter()
        .filter(is_locally_signable)
        .map(|key| key.key_id)
        .collect();
    if key_ids.is_empty() {
        return Err(ExchangeLocalSignerError::NoLocallySignableKeys);
    }
    let algorithm = SigningAlgorithmV1::Bip340Secp256k1;
    let max_signatures_per_request = u16::try_from(MAX_TRANSACTION_INPUTS)
        .map_err(|_| ExchangeLocalSignerError::ProtocolBound)?;
    let max_package_bytes = u32::try_from(MAX_SIGNING_PACKAGE_BYTES)
        .map_err(|_| ExchangeLocalSignerError::ProtocolBound)?;
    let key_set_digest = signer_key_set_digest(signer_id, algorithm, &key_ids)?;
    let capabilities = SignerCapabilitiesV1 {
        signer_id,
        algorithm,
        max_signatures_per_request,
        max_package_bytes,
        key_set_digest,
    };
    // Exercise canonical capability validation before returning it as trusted
    // context rather than relying on later signing-package validation.
    SignerCapabilitiesV1::decode(&capabilities.encode()?)?;
    Ok(LocalSignerProfileV1 {
        signer_id,
        capabilities,
        key_ids,
    })
}

/// Constructs independently trusted signing expectations after checking every
/// package binding against keyring and caller-pinned state.
pub fn expected_local_signing_context(
    keyring: &WalletKeyring,
    package: &SigningPackageV1,
    expected: LocalSigningExpectationV1,
) -> Result<(LocalSignerProfileV1, ExpectedSigningContextV1), ExchangeLocalSignerError> {
    validate_package_binding(keyring, package, expected)?;
    let profile = local_signer_profile(keyring)?;
    let capability_digest = profile.capabilities.digest()?;

    for input in &package.inputs {
        let key = keyring
            .key(input.key_id)
            .filter(is_locally_signable)
            .ok_or(ExchangeLocalSignerError::InputNotLocallySignable(
                input.input_index,
            ))?;
        if key.public_key != input.public_key {
            return Err(ExchangeLocalSignerError::InputPublicKeyMismatch(
                input.input_index,
            ));
        }
        if input.signer_id != profile.signer_id || input.capability_digest != capability_digest {
            return Err(ExchangeLocalSignerError::InputNotLocallySignable(
                input.input_index,
            ));
        }
    }

    let context = ExpectedSigningContextV1 {
        package_digest: expected.package_digest,
        release_authorization_digest: expected.release_authorization_digest,
        signers: vec![ExpectedSignerBindingV1 {
            capabilities: profile.capabilities.clone(),
            key_ids: profile.key_ids.clone(),
        }],
    };
    context.validate_package(package)?;
    Ok((profile, context))
}

/// Produces one complete canonical response and immediately verifies both of
/// its signatures per input by assembling the transaction through the shared
/// protocol verifier. No secret bytes leave [`WalletKeyring`].
pub fn sign_and_assemble_local_package(
    keyring: &WalletKeyring,
    package: &SigningPackageV1,
    expected: LocalSigningExpectationV1,
) -> Result<LocalSignedPackageV1, ExchangeLocalSignerError> {
    let (profile, expected_context) = expected_local_signing_context(keyring, package, expected)?;
    let capability_digest = profile.capabilities.digest()?;
    let mut signatures = Vec::with_capacity(package.inputs.len());
    for input in &package.inputs {
        let transaction_signature =
            keyring.sign_local_digest(input.key_id, &package.signing_digest)?;
        let authorization_digest = package_authorization_digest(
            &expected.package_digest,
            &expected.release_authorization_digest,
            input.input_index,
            input.key_id,
            profile.signer_id,
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
        package_digest: expected.package_digest,
        release_authorization_digest: expected.release_authorization_digest,
        signer_id: profile.signer_id,
        capability_digest,
        signatures,
    };
    // The serialized response is what a provider boundary would transport.
    // Re-decoding it ensures this local path follows that exact canonical wire
    // contract before the common assembler verifies all signatures.
    let response = SignerResponseV1::decode(&response.encode()?)?;
    let assembled =
        assemble_signed_transaction(package, &expected_context, std::slice::from_ref(&response))?;
    Ok(LocalSignedPackageV1 {
        profile,
        expected_context,
        response,
        assembled,
    })
}

fn validate_package_binding(
    keyring: &WalletKeyring,
    package: &SigningPackageV1,
    expected: LocalSigningExpectationV1,
) -> Result<(), ExchangeLocalSignerError> {
    let binding = keyring.binding();
    if package.network_id != binding.network_id {
        return Err(ExchangeLocalSignerError::BindingMismatch("network_id"));
    }
    if package.consensus_fingerprint != binding.consensus_fingerprint {
        return Err(ExchangeLocalSignerError::BindingMismatch(
            "consensus_fingerprint",
        ));
    }
    if package.genesis != binding.genesis_hash {
        return Err(ExchangeLocalSignerError::BindingMismatch("genesis_hash"));
    }
    if package.keyring_anchor != keyring.anchor().signing_protocol_anchor() {
        return Err(ExchangeLocalSignerError::KeyringAnchorMismatch);
    }
    if package.policy_id != expected.policy_id {
        return Err(ExchangeLocalSignerError::PolicyMismatch);
    }
    if package.prepared_anchor != expected.prepared_anchor {
        return Err(ExchangeLocalSignerError::PreparedAnchorMismatch);
    }
    if package.digest()? != expected.package_digest {
        return Err(ExchangeLocalSignerError::PackageDigestMismatch);
    }
    Ok(())
}

fn is_locally_signable(key: &WalletKeySummary) -> bool {
    key.storage == KeyStorageBinding::Local && key.lifecycle != KeyLifecycle::Disabled
}

#[cfg(test)]
mod tests {
    use cmfd_consensus::{
        CONSENSUS_SIGNATURE_BYTES, InputWitness, OutPoint, OutputLock, TRANSACTION_VERSION,
        Transaction, TxInput, TxOutput, decode_transaction, encode_transaction,
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::wallet_keyring::{
        KeyLifecycleUpdate, KeyRoles, KeyringRuntimeBinding, WalletKeyEntry,
    };
    use crate::wallet_signing_protocol::{SigningInputV1, WalletKeyId};

    fn binding() -> KeyringRuntimeBinding {
        KeyringRuntimeBinding {
            network_id: [0x11; 32],
            consensus_fingerprint: [0x12; 32],
            genesis_hash: [0x13; 32],
        }
    }

    fn local(marker: u8, roles: KeyRoles, lifecycle: KeyLifecycle) -> WalletKeyEntry {
        WalletKeyEntry::local(Zeroizing::new([marker; 32]), roles, lifecycle).unwrap()
    }

    fn public_key(marker: u8) -> [u8; 32] {
        let key = k256::schnorr::SigningKey::from_bytes(&[marker; 32]).unwrap();
        key.verifying_key().to_bytes().into()
    }

    fn keyring() -> WalletKeyring {
        WalletKeyring::new_genesis(
            binding(),
            [0x42; 32],
            vec![
                local(
                    1,
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Active,
                ),
                local(2, KeyRoles::DEPOSIT, KeyLifecycle::Retired),
                local(3, KeyRoles::DEPOSIT, KeyLifecycle::Disabled),
                WalletKeyEntry::external(
                    public_key(4),
                    KeyRoles::DEPOSIT,
                    KeyLifecycle::Active,
                    SignerId([0x94; 32]),
                )
                .unwrap(),
                WalletKeyEntry::watch_only(public_key(5), KeyRoles::DEPOSIT, KeyLifecycle::Retired)
                    .unwrap(),
            ],
        )
        .unwrap()
    }

    fn summary(keyring: &WalletKeyring, marker: u8) -> WalletKeySummary {
        let expected_public = public_key(marker);
        keyring
            .summaries()
            .into_iter()
            .find(|key| key.public_key == expected_public)
            .unwrap()
    }

    fn package_for(keyring: &WalletKeyring, keys: &[WalletKeySummary]) -> SigningPackageV1 {
        let profile = local_signer_profile(keyring).unwrap();
        let capability_digest = profile.capabilities.digest().unwrap();
        let transaction = Transaction {
            network_id: binding().network_id,
            version: TRANSACTION_VERSION,
            inputs: keys
                .iter()
                .enumerate()
                .map(|(index, key)| TxInput {
                    previous: OutPoint {
                        txid: [0x20 + index as u8; 32],
                        index: index as u32,
                    },
                    witness: InputWitness::Key {
                        public_key: key.public_key,
                        signature: vec![0; CONSENSUS_SIGNATURE_BYTES],
                    },
                })
                .collect(),
            outputs: vec![TxOutput {
                value: 900,
                lock: OutputLock::Key(keyring.active_change_key().public_key),
                spendable_height: 50,
            }],
        };
        let unsigned_transaction = encode_transaction(&transaction).unwrap();
        let signing_digest = transaction.signing_digest();
        SigningPackageV1 {
            network_id: binding().network_id,
            consensus_fingerprint: binding().consensus_fingerprint,
            genesis: binding().genesis_hash,
            prepared_anchor: WithdrawalAnchorV1 {
                key_id: [0x31; 32],
                journal_instance_id: [0x32; 32],
                generation: 7,
                commitment: [0x33; 32],
            },
            request_id: "exchange-withdrawal-local-0001".to_owned(),
            request_digest: [0x41; 32],
            policy_id: [0x44; 32],
            keyring_anchor: keyring.anchor().signing_protocol_anchor(),
            unsigned_transaction,
            signing_digest,
            inputs: keys
                .iter()
                .enumerate()
                .map(|(index, key)| SigningInputV1 {
                    input_index: index as u32,
                    outpoint: transaction.inputs[index].previous,
                    value_atoms: 500 + index as u64,
                    key_id: key.key_id,
                    public_key: key.public_key,
                    signer_id: profile.signer_id,
                    capability_digest,
                })
                .collect(),
        }
    }

    fn expectation(package: &SigningPackageV1) -> LocalSigningExpectationV1 {
        LocalSigningExpectationV1 {
            package_digest: package.digest().unwrap(),
            policy_id: package.policy_id,
            prepared_anchor: package.prepared_anchor,
            release_authorization_digest: [0x45; 32],
        }
    }

    #[test]
    fn two_local_keys_sign_canonical_response_and_assemble() {
        let keyring = keyring();
        let package = package_for(&keyring, &[summary(&keyring, 1), summary(&keyring, 2)]);
        let signed =
            sign_and_assemble_local_package(&keyring, &package, expectation(&package)).unwrap();

        assert_eq!(signed.response.signatures.len(), 2);
        assert_eq!(signed.response.package_digest, package.digest().unwrap());
        assert_eq!(signed.response.signer_id, signed.profile.signer_id);
        assert_eq!(
            SignerResponseV1::decode(&signed.response.encode().unwrap()).unwrap(),
            signed.response
        );
        assert_eq!(
            signed.assembled.transaction.signing_digest(),
            package.signing_digest
        );
        assert_eq!(
            decode_transaction(&signed.assembled.transaction_bytes, package.network_id).unwrap(),
            signed.assembled.transaction
        );
        for input in &signed.assembled.transaction.inputs {
            let InputWitness::Key { signature, .. } = &input.witness else {
                panic!("local adapter assembled a non-key witness");
            };
            assert_ne!(signature.as_slice(), [0_u8; CONSENSUS_SIGNATURE_BYTES]);
        }
    }

    #[test]
    fn one_key_bootstrap_package_is_supported() {
        let keyring = WalletKeyring::new_genesis(
            binding(),
            [0x42; 32],
            vec![local(
                1,
                KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                KeyLifecycle::Active,
            )],
        )
        .unwrap();
        let package = package_for(&keyring, &[keyring.active_change_key()]);
        let signed =
            sign_and_assemble_local_package(&keyring, &package, expectation(&package)).unwrap();
        assert_eq!(signed.response.signatures.len(), 1);
    }

    #[test]
    fn profile_is_deterministic_excludes_nonlocal_and_disabled_keys() {
        let keyring = keyring();
        let first = local_signer_profile(&keyring).unwrap();
        let second = local_signer_profile(&keyring).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.key_ids.len(), 2);
        assert!(first.key_ids.contains(&summary(&keyring, 1).key_id));
        assert!(first.key_ids.contains(&summary(&keyring, 2).key_id));
        assert!(!first.key_ids.contains(&summary(&keyring, 3).key_id));
        assert!(!first.key_ids.contains(&summary(&keyring, 4).key_id));
        assert!(!first.key_ids.contains(&summary(&keyring, 5).key_id));
        assert_eq!(
            hex::encode(first.signer_id.0),
            "f1b47d97b1eeb90fef85533e636eadc6af6488b9b81f557266ac91807c1587f7"
        );
        assert_eq!(
            hex::encode(first.capabilities.key_set_digest),
            "222322efb8858c69aaa242f2b57d0c01e88028cca2fdcfc1eb0327cd5e8a8693"
        );
    }

    #[test]
    fn signer_id_survives_key_rotation_while_capability_digest_changes() {
        let keyring = keyring();
        let original_profile = local_signer_profile(&keyring).unwrap();
        let anchor = keyring.anchor();
        let old_change = keyring.active_change_key();
        let next = keyring
            .transition(
                anchor,
                &[KeyLifecycleUpdate {
                    key_id: old_change.key_id,
                    lifecycle: KeyLifecycle::Retired,
                }],
                vec![local(6, KeyRoles::CHANGE, KeyLifecycle::Active)],
            )
            .unwrap();
        let next_profile = local_signer_profile(&next).unwrap();
        assert_eq!(original_profile.signer_id, next_profile.signer_id);
        assert_ne!(
            original_profile.capabilities.key_set_digest,
            next_profile.capabilities.key_set_digest
        );
    }

    #[test]
    fn binding_anchor_policy_prepared_and_package_expectations_fail_closed() {
        let keyring = keyring();
        let package = package_for(&keyring, &[summary(&keyring, 1)]);

        let mut wrong_binding = package.clone();
        wrong_binding.genesis[0] ^= 1;
        let mut expected = expectation(&wrong_binding);
        assert!(matches!(
            expected_local_signing_context(&keyring, &wrong_binding, expected),
            Err(ExchangeLocalSignerError::BindingMismatch("genesis_hash"))
        ));

        let mut wrong_anchor = package.clone();
        wrong_anchor.keyring_anchor.generation += 1;
        expected = expectation(&wrong_anchor);
        assert!(matches!(
            expected_local_signing_context(&keyring, &wrong_anchor, expected),
            Err(ExchangeLocalSignerError::KeyringAnchorMismatch)
        ));

        let mut wrong_policy = expectation(&package);
        wrong_policy.policy_id[0] ^= 1;
        assert!(matches!(
            expected_local_signing_context(&keyring, &package, wrong_policy),
            Err(ExchangeLocalSignerError::PolicyMismatch)
        ));

        let mut wrong_prepared = expectation(&package);
        wrong_prepared.prepared_anchor.commitment[0] ^= 1;
        assert!(matches!(
            expected_local_signing_context(&keyring, &package, wrong_prepared),
            Err(ExchangeLocalSignerError::PreparedAnchorMismatch)
        ));

        let mut wrong_package = expectation(&package);
        wrong_package.package_digest[0] ^= 1;
        assert!(matches!(
            expected_local_signing_context(&keyring, &package, wrong_package),
            Err(ExchangeLocalSignerError::PackageDigestMismatch)
        ));
    }

    #[test]
    fn external_watch_only_and_disabled_package_inputs_are_refused() {
        for marker in [3_u8, 4, 5] {
            let keyring = keyring();
            let package = package_for(&keyring, &[summary(&keyring, marker)]);
            assert!(matches!(
                sign_and_assemble_local_package(&keyring, &package, expectation(&package)),
                Err(ExchangeLocalSignerError::InputNotLocallySignable(0))
            ));
        }
    }

    #[test]
    fn package_cannot_self_assert_an_alternate_local_capability() {
        let keyring = keyring();
        let mut package = package_for(&keyring, &[summary(&keyring, 1)]);
        package.inputs[0].capability_digest[0] ^= 1;
        let expected = expectation(&package);
        assert!(matches!(
            sign_and_assemble_local_package(&keyring, &package, expected),
            Err(ExchangeLocalSignerError::InputNotLocallySignable(0))
        ));

        let mut package = package_for(&keyring, &[summary(&keyring, 1)]);
        package.inputs[0].signer_id = SignerId([0xa0; 32]);
        let expected = expectation(&package);
        assert!(matches!(
            sign_and_assemble_local_package(&keyring, &package, expected),
            Err(ExchangeLocalSignerError::InputNotLocallySignable(0))
        ));
    }

    #[test]
    fn a_keyring_without_local_keys_has_no_local_signer_profile() {
        let keyring = WalletKeyring::new_genesis(
            binding(),
            [0x42; 32],
            vec![
                WalletKeyEntry::external(
                    public_key(4),
                    KeyRoles::CHANGE,
                    KeyLifecycle::Active,
                    SignerId([0x94; 32]),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert!(matches!(
            local_signer_profile(&keyring),
            Err(ExchangeLocalSignerError::NoLocallySignableKeys)
        ));
    }

    #[test]
    fn package_response_signatures_are_bound_to_exact_package() {
        let keyring = keyring();
        let package = package_for(&keyring, &[summary(&keyring, 1)]);
        let signed =
            sign_and_assemble_local_package(&keyring, &package, expectation(&package)).unwrap();
        let mut other_package = package.clone();
        other_package.request_digest[0] ^= 1;
        let other_expected = LocalSigningExpectationV1 {
            package_digest: other_package.digest().unwrap(),
            policy_id: other_package.policy_id,
            prepared_anchor: other_package.prepared_anchor,
            release_authorization_digest: [0x45; 32],
        };
        let (_, other_context) =
            expected_local_signing_context(&keyring, &other_package, other_expected).unwrap();
        assert!(
            assemble_signed_transaction(&other_package, &other_context, &[signed.response])
                .is_err()
        );
    }

    #[test]
    fn key_ids_in_profile_are_strictly_sorted() {
        let keyring = keyring();
        let profile = local_signer_profile(&keyring).unwrap();
        assert!(profile.key_ids.windows(2).all(|keys| keys[0] < keys[1]));
        assert!(
            profile
                .key_ids
                .iter()
                .all(|key| *key != WalletKeyId([0; 32]))
        );
    }
}
