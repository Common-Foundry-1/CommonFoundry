//! Canonical, provider-neutral signing messages for the v0.5 multi-key wallet.
//!
//! This module is deliberately independent of node, RPC, journal, and file
//! state. It defines only public-data messages and pure verification/assembly;
//! the live v0.5 custody engine supplies independently authenticated context.

use std::collections::HashSet;

use blake3::Hasher;
use cmfd_consensus::{
    CONSENSUS_SIGNATURE_BYTES, InputWitness, MAX_TRANSACTION_BYTES, MAX_TRANSACTION_INPUTS,
    MAX_TRANSACTION_OUTPUTS, OutPoint, TRANSACTION_VERSION, Transaction, WireError,
    decode_transaction, encode_transaction,
};
use k256::schnorr::{Signature, VerifyingKey, signature::Verifier};
use thiserror::Error;

pub const SIGNING_PROTOCOL_MAGIC: [u8; 8] = *b"CMFDSIG1";
pub const SIGNING_PROTOCOL_VERSION: u16 = 1;
pub const MAX_SIGNING_REQUEST_ID_BYTES: usize = 128;
pub const MAX_SIGNING_PACKAGE_BYTES: usize = MAX_TRANSACTION_BYTES + 64 * 1024;
pub const MAX_SIGNER_CAPABILITIES_BYTES: usize = 1024;
pub const MAX_SIGNER_RESPONSE_BYTES: usize = 32 * 1024;
pub const MAX_SIGNER_KEY_IDS: usize = 65_536;

const ENVELOPE_HEADER_BYTES: usize = 16;
const CAPABILITIES_KIND: u8 = 1;
const PACKAGE_KIND: u8 = 2;
const RESPONSE_KIND: u8 = 3;
const BIP340_SECP256K1_ALGORITHM: u8 = 1;
const WALLET_KEY_ID_DOMAIN: &str = "CMFD/NODE/WALLET-KEY-ID/V1";
const CAPABILITY_DIGEST_DOMAIN: &str = "CMFD/NODE/SIGNER-CAPABILITY/V1";
const PACKAGE_DIGEST_DOMAIN: &str = "CMFD/NODE/SIGNING-PACKAGE/V1";
const RESPONSE_DIGEST_DOMAIN: &str = "CMFD/NODE/SIGNER-RESPONSE/V1";
const PACKAGE_AUTHORIZATION_DOMAIN: &str = "CMFD/NODE/SIGNING-PACKAGE-AUTHORIZATION/V1";
const RELEASE_AUTHORIZATION_DOMAIN: &str = "CMFD/NODE/SIGNING-RELEASE-AUTHORIZATION/V1";
const SIGNER_KEY_SET_DOMAIN: &str = "CMFD/NODE/SIGNER-KEY-SET/V1";

#[derive(Debug, Error)]
pub enum SigningProtocolError {
    #[error("signing protocol message exceeds the {0} capacity")]
    Capacity(&'static str),
    #[error("signing protocol message is truncated")]
    Truncated,
    #[error("signing protocol magic is invalid")]
    InvalidMagic,
    #[error("unsupported signing protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("wrong signing protocol message kind: expected {expected}, received {actual}")]
    WrongMessageKind { expected: u8, actual: u8 },
    #[error("signing protocol reserved header byte is nonzero")]
    ReservedHeader,
    #[error("signing protocol payload length is invalid")]
    InvalidPayloadLength,
    #[error("signing protocol message contains trailing bytes")]
    TrailingBytes,
    #[error("signing protocol message is not canonically encoded")]
    NonCanonical,
    #[error("invalid signing protocol field: {0}")]
    InvalidField(&'static str),
    #[error("unsupported signing algorithm {0}")]
    UnsupportedAlgorithm(u8),
    #[error("transaction encoding is invalid: {0}")]
    Transaction(#[from] WireError),
    #[error("signer response is for another signing package")]
    PackageDigestMismatch,
    #[error("signer response is for another release authorization")]
    ReleaseAuthorizationMismatch,
    #[error("signing package does not match the independently expected package digest")]
    ExpectedPackageDigestMismatch,
    #[error("expected signing context is invalid: {0}")]
    InvalidExpectedContext(&'static str),
    #[error("input {0} has no authenticated signer binding")]
    UntrustedSigner(u32),
    #[error("input {0} does not match the authenticated signer capability")]
    UntrustedCapability(u32),
    #[error("input {0} key is not a member of the authenticated signer key set")]
    UntrustedWalletKey(u32),
    #[error("signing package exceeds an authenticated signer package-size limit")]
    SignerPackageLimit,
    #[error("signing package exceeds an authenticated signer signature-count limit")]
    SignerSignatureLimit,
    #[error("signature for input {0} was supplied more than once")]
    DuplicateSignature(u32),
    #[error("signature refers to unknown input {0}")]
    UnexpectedSignature(u32),
    #[error("signature for input {0} came from the wrong signer")]
    SignerMismatch(u32),
    #[error("signature for input {0} uses the wrong signer capability")]
    CapabilityMismatch(u32),
    #[error("signature for input {0} uses the wrong wallet key")]
    WalletKeyMismatch(u32),
    #[error("transaction signature for input {0} is invalid")]
    InvalidTransactionSignature(u32),
    #[error("package authorization signature for input {0} is invalid")]
    InvalidPackageAuthorization(u32),
    #[error("signature for input {0} is missing")]
    MissingSignature(u32),
    #[error("assembling signatures changed the transaction signing digest")]
    SigningDigestChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalletKeyId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignerId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithmV1 {
    Bip340Secp256k1,
}

impl SigningAlgorithmV1 {
    fn tag(self) -> u8 {
        match self {
            Self::Bip340Secp256k1 => BIP340_SECP256K1_ALGORITHM,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SigningProtocolError> {
        match tag {
            BIP340_SECP256K1_ALGORITHM => Ok(Self::Bip340Secp256k1),
            other => Err(SigningProtocolError::UnsupportedAlgorithm(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalAnchorV1 {
    pub key_id: [u8; 32],
    pub journal_instance_id: [u8; 32],
    pub generation: u64,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyringAnchorV1 {
    pub instance_id: [u8; 32],
    pub generation: u64,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerCapabilitiesV1 {
    pub signer_id: SignerId,
    pub algorithm: SigningAlgorithmV1,
    pub max_signatures_per_request: u16,
    pub max_package_bytes: u32,
    pub key_set_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningInputV1 {
    pub input_index: u32,
    pub outpoint: OutPoint,
    /// Claimed previous-output value used for policy display. The package does
    /// not prove this value or ownership. Trusted chain state must revalidate
    /// both before package issuance and again before release.
    pub value_atoms: u64,
    pub key_id: WalletKeyId,
    pub public_key: [u8; 32],
    pub signer_id: SignerId,
    pub capability_digest: [u8; 32],
}

/// A consensus transaction frame whose key-witness signatures are exactly 64
/// zero bytes is used as the canonical unsigned representation. Consensus wire
/// encoding requires the fixed signature width, while the signing digest
/// intentionally excludes those bytes.
///
/// Input values are authenticated as package claims but are not UTXO proofs.
/// An offline signer needs an independent chain source or proof if it intends
/// to enforce fee policy from input values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPackageV1 {
    pub network_id: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
    pub genesis: [u8; 32],
    pub prepared_anchor: WithdrawalAnchorV1,
    pub request_id: String,
    pub request_digest: [u8; 32],
    /// Exact withdrawal policy whose limits and approval roster authorize the
    /// terminal action for this package.
    pub policy_id: [u8; 32],
    pub keyring_anchor: KeyringAnchorV1,
    pub unsigned_transaction: Vec<u8>,
    pub signing_digest: [u8; 32],
    pub inputs: Vec<SigningInputV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSignatureV1 {
    pub input_index: u32,
    pub key_id: WalletKeyId,
    pub transaction_signature: [u8; CONSENSUS_SIGNATURE_BYTES],
    pub package_authorization_signature: [u8; CONSENSUS_SIGNATURE_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerResponseV1 {
    pub package_digest: [u8; 32],
    /// Digest of the durable ReleaseAuthorized anchor and terminal approval.
    /// This cannot be known from the Prepared signing package alone.
    pub release_authorization_digest: [u8; 32],
    pub signer_id: SignerId,
    pub capability_digest: [u8; 32],
    pub signatures: Vec<InputSignatureV1>,
}

/// An authenticated signer capability and its complete canonical wallet-key
/// membership list. The caller, not the signing package, establishes trust in
/// this binding from the keyring or another independently authenticated source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSignerBindingV1 {
    pub capabilities: SignerCapabilitiesV1,
    pub key_ids: Vec<WalletKeyId>,
}

/// Independently trusted expectations supplied to pure assembly. Constructing
/// this value from the package itself does not establish a security boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSigningContextV1 {
    pub package_digest: [u8; 32],
    pub release_authorization_digest: [u8; 32],
    pub signers: Vec<ExpectedSignerBindingV1>,
}

/// Public fields a signer must independently authenticate after the durable
/// ReleaseAuthorized transition. The anchor is the resulting journal anchor,
/// not the Prepared anchor already embedded in [`SigningPackageV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseAuthorizationV1 {
    pub release_authorized_anchor: WithdrawalAnchorV1,
    pub decision_id: [u8; 32],
    pub approval_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledTransactionV1 {
    pub transaction: Transaction,
    pub transaction_bytes: Vec<u8>,
    pub txid: [u8; 32],
}

pub fn wallet_key_id(public_key: &[u8; 32]) -> WalletKeyId {
    let mut hasher = Hasher::new_derive_key(WALLET_KEY_ID_DOMAIN);
    hasher.update(&[BIP340_SECP256K1_ALGORITHM]);
    hasher.update(public_key);
    WalletKeyId(*hasher.finalize().as_bytes())
}

pub fn signer_key_set_digest(
    signer_id: SignerId,
    algorithm: SigningAlgorithmV1,
    key_ids: &[WalletKeyId],
) -> Result<[u8; 32], SigningProtocolError> {
    require_nonzero(&signer_id.0, "signer_id")?;
    if key_ids.is_empty() || key_ids.len() > MAX_SIGNER_KEY_IDS {
        return Err(SigningProtocolError::InvalidExpectedContext(
            "signer key-set size",
        ));
    }
    let mut previous = None;
    for key_id in key_ids {
        require_nonzero(&key_id.0, "signer key_id")?;
        if previous.is_some_and(|previous| previous >= *key_id) {
            return Err(SigningProtocolError::InvalidExpectedContext(
                "signer key-set ordering",
            ));
        }
        previous = Some(*key_id);
    }
    let key_count = u32::try_from(key_ids.len())
        .map_err(|_| SigningProtocolError::InvalidExpectedContext("signer key-set size"))?;
    let mut hasher = Hasher::new_derive_key(SIGNER_KEY_SET_DOMAIN);
    hasher.update(&signer_id.0);
    hasher.update(&[algorithm.tag()]);
    hasher.update(&key_count.to_le_bytes());
    for key_id in key_ids {
        hasher.update(&key_id.0);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Digest signed by the same input key in addition to the consensus
/// transaction signature. This authenticates the request, anchors, signer
/// identity, capability, and exact consensus signature through package_digest.
pub fn package_authorization_digest(
    package_digest: &[u8; 32],
    release_authorization_digest: &[u8; 32],
    input_index: u32,
    key_id: WalletKeyId,
    signer_id: SignerId,
    capability_digest: &[u8; 32],
    transaction_signature: &[u8; CONSENSUS_SIGNATURE_BYTES],
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(PACKAGE_AUTHORIZATION_DOMAIN);
    hasher.update(package_digest);
    hasher.update(release_authorization_digest);
    hasher.update(&input_index.to_le_bytes());
    hasher.update(&key_id.0);
    hasher.update(&signer_id.0);
    hasher.update(capability_digest);
    hasher.update(transaction_signature);
    *hasher.finalize().as_bytes()
}

/// Binds signer approval to the post-authorization journal state and exact
/// terminal decision, preventing a Prepared package from being pre-signed and
/// replayed after an unrelated authorization.
pub fn release_authorization_digest(
    package_digest: &[u8; 32],
    authorization: ReleaseAuthorizationV1,
) -> Result<[u8; 32], SigningProtocolError> {
    require_nonzero(package_digest, "package_digest")?;
    validate_withdrawal_anchor(authorization.release_authorized_anchor)?;
    require_nonzero(&authorization.decision_id, "decision_id")?;
    require_nonzero(&authorization.approval_digest, "approval_digest")?;
    let mut hasher = Hasher::new_derive_key(RELEASE_AUTHORIZATION_DOMAIN);
    hasher.update(package_digest);
    let mut anchor_bytes = Vec::new();
    encode_withdrawal_anchor(&mut anchor_bytes, authorization.release_authorized_anchor);
    hasher.update(&anchor_bytes);
    hasher.update(&authorization.decision_id);
    hasher.update(&authorization.approval_digest);
    Ok(*hasher.finalize().as_bytes())
}

/// Encodes a key-only transaction with canonical fixed-width zero signature
/// placeholders. Empty signatures are accepted as an in-memory unsigned plan;
/// any nonzero signature is rejected rather than silently discarded.
pub fn encode_unsigned_key_transaction(
    transaction: &Transaction,
) -> Result<Vec<u8>, SigningProtocolError> {
    if transaction.version != TRANSACTION_VERSION {
        return Err(SigningProtocolError::InvalidField("transaction version"));
    }
    if transaction.inputs.is_empty() || transaction.inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(SigningProtocolError::Capacity("package input"));
    }
    if transaction.outputs.is_empty() {
        return Err(SigningProtocolError::InvalidField(
            "transaction output count",
        ));
    }
    if transaction.outputs.len() > MAX_TRANSACTION_OUTPUTS {
        return Err(SigningProtocolError::Capacity("transaction output"));
    }
    for input in &transaction.inputs {
        let InputWitness::Key { signature, .. } = &input.witness else {
            return Err(SigningProtocolError::InvalidField("input witness"));
        };
        if !signature.is_empty() && signature.len() != CONSENSUS_SIGNATURE_BYTES {
            return Err(SigningProtocolError::InvalidField(
                "unsigned signature shape",
            ));
        }
        if signature.iter().any(|byte| *byte != 0) {
            return Err(SigningProtocolError::InvalidField(
                "transaction is already signed",
            ));
        }
    }
    let mut canonical = transaction.clone();
    for input in &mut canonical.inputs {
        let InputWitness::Key { signature, .. } = &mut input.witness else {
            unreachable!("all witnesses were checked before cloning");
        };
        *signature = vec![0; CONSENSUS_SIGNATURE_BYTES];
    }
    encode_transaction(&canonical).map_err(SigningProtocolError::from)
}

impl SignerCapabilitiesV1 {
    pub fn encode(&self) -> Result<Vec<u8>, SigningProtocolError> {
        self.validate()?;
        let mut payload = Vec::with_capacity(32 + 1 + 2 + 4 + 32);
        payload.extend_from_slice(&self.signer_id.0);
        payload.push(self.algorithm.tag());
        payload.extend_from_slice(&self.max_signatures_per_request.to_le_bytes());
        payload.extend_from_slice(&self.max_package_bytes.to_le_bytes());
        payload.extend_from_slice(&self.key_set_digest);
        encode_envelope(CAPABILITIES_KIND, payload, MAX_SIGNER_CAPABILITIES_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SigningProtocolError> {
        let payload = decode_envelope(bytes, CAPABILITIES_KIND, MAX_SIGNER_CAPABILITIES_BYTES)?;
        let mut decoder = Decoder::new(payload);
        let value = Self {
            signer_id: SignerId(decoder.array()?),
            algorithm: SigningAlgorithmV1::from_tag(decoder.byte()?)?,
            max_signatures_per_request: decoder.u16()?,
            max_package_bytes: decoder.u32()?,
            key_set_digest: decoder.array()?,
        };
        decoder.finish()?;
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(SigningProtocolError::NonCanonical);
        }
        Ok(value)
    }

    pub fn digest(&self) -> Result<[u8; 32], SigningProtocolError> {
        digest_encoded(CAPABILITY_DIGEST_DOMAIN, &self.encode()?)
    }

    fn validate(&self) -> Result<(), SigningProtocolError> {
        require_nonzero(&self.signer_id.0, "signer_id")?;
        if self.max_signatures_per_request == 0
            || usize::from(self.max_signatures_per_request) > MAX_TRANSACTION_INPUTS
        {
            return Err(SigningProtocolError::InvalidField(
                "max_signatures_per_request",
            ));
        }
        let max_package_bytes = usize::try_from(self.max_package_bytes)
            .map_err(|_| SigningProtocolError::InvalidField("max_package_bytes"))?;
        if !(ENVELOPE_HEADER_BYTES..=MAX_SIGNING_PACKAGE_BYTES).contains(&max_package_bytes) {
            return Err(SigningProtocolError::InvalidField("max_package_bytes"));
        }
        require_nonzero(&self.key_set_digest, "key_set_digest")
    }
}

impl SigningPackageV1 {
    pub fn encode(&self) -> Result<Vec<u8>, SigningProtocolError> {
        self.validated_transaction()?;
        let request_len = u16::try_from(self.request_id.len())
            .map_err(|_| SigningProtocolError::Capacity("request_id"))?;
        let input_count = u16::try_from(self.inputs.len())
            .map_err(|_| SigningProtocolError::Capacity("package input"))?;
        let transaction_len = u32::try_from(self.unsigned_transaction.len())
            .map_err(|_| SigningProtocolError::Capacity("unsigned transaction"))?;

        let mut payload = Vec::new();
        payload.extend_from_slice(&self.network_id);
        payload.extend_from_slice(&self.consensus_fingerprint);
        payload.extend_from_slice(&self.genesis);
        encode_withdrawal_anchor(&mut payload, self.prepared_anchor);
        payload.extend_from_slice(&request_len.to_le_bytes());
        payload.extend_from_slice(self.request_id.as_bytes());
        payload.extend_from_slice(&self.request_digest);
        payload.extend_from_slice(&self.policy_id);
        encode_keyring_anchor(&mut payload, self.keyring_anchor);
        payload.extend_from_slice(&transaction_len.to_le_bytes());
        payload.extend_from_slice(&self.unsigned_transaction);
        payload.extend_from_slice(&self.signing_digest);
        payload.extend_from_slice(&input_count.to_le_bytes());
        for input in &self.inputs {
            encode_signing_input(&mut payload, input);
        }
        encode_envelope(PACKAGE_KIND, payload, MAX_SIGNING_PACKAGE_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SigningProtocolError> {
        let payload = decode_envelope(bytes, PACKAGE_KIND, MAX_SIGNING_PACKAGE_BYTES)?;
        let mut decoder = Decoder::new(payload);
        let network_id = decoder.array()?;
        let consensus_fingerprint = decoder.array()?;
        let genesis = decoder.array()?;
        let prepared_anchor = decode_withdrawal_anchor(&mut decoder)?;
        let request_length = decoder.bounded_u16(MAX_SIGNING_REQUEST_ID_BYTES, "request_id")?;
        let request_id = std::str::from_utf8(decoder.take(request_length)?)
            .map_err(|_| SigningProtocolError::InvalidField("request_id"))?
            .to_owned();
        let request_digest = decoder.array()?;
        let policy_id = decoder.array()?;
        let keyring_anchor = decode_keyring_anchor(&mut decoder)?;
        let transaction_length =
            decoder.bounded_u32(MAX_TRANSACTION_BYTES, "unsigned transaction")?;
        let unsigned_transaction = decoder.take(transaction_length)?.to_vec();
        let signing_digest = decoder.array()?;
        let input_count = decoder.bounded_u16(MAX_TRANSACTION_INPUTS, "package input")?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(decode_signing_input(&mut decoder)?);
        }
        decoder.finish()?;
        let value = Self {
            network_id,
            consensus_fingerprint,
            genesis,
            prepared_anchor,
            request_id,
            request_digest,
            policy_id,
            keyring_anchor,
            unsigned_transaction,
            signing_digest,
            inputs,
        };
        value.validated_transaction()?;
        if value.encode()?.as_slice() != bytes {
            return Err(SigningProtocolError::NonCanonical);
        }
        Ok(value)
    }

    pub fn digest(&self) -> Result<[u8; 32], SigningProtocolError> {
        digest_encoded(PACKAGE_DIGEST_DOMAIN, &self.encode()?)
    }

    pub fn transaction(&self) -> Result<Transaction, SigningProtocolError> {
        self.validated_transaction()
    }

    fn validated_transaction(&self) -> Result<Transaction, SigningProtocolError> {
        require_nonzero(&self.network_id, "network_id")?;
        require_nonzero(&self.consensus_fingerprint, "consensus_fingerprint")?;
        require_nonzero(&self.genesis, "genesis")?;
        validate_withdrawal_anchor(self.prepared_anchor)?;
        validate_request_id(&self.request_id)?;
        require_nonzero(&self.request_digest, "request_digest")?;
        require_nonzero(&self.policy_id, "policy_id")?;
        validate_keyring_anchor(self.keyring_anchor)?;
        if self.unsigned_transaction.len() > MAX_TRANSACTION_BYTES {
            return Err(SigningProtocolError::Capacity("unsigned transaction"));
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_TRANSACTION_INPUTS {
            return Err(SigningProtocolError::Capacity("package input"));
        }

        let transaction = decode_transaction(&self.unsigned_transaction, self.network_id)?;
        if transaction.version != TRANSACTION_VERSION {
            return Err(SigningProtocolError::InvalidField("transaction version"));
        }
        if encode_transaction(&transaction)? != self.unsigned_transaction {
            return Err(SigningProtocolError::NonCanonical);
        }
        if transaction.signing_digest() != self.signing_digest {
            return Err(SigningProtocolError::InvalidField("signing_digest"));
        }
        if transaction.inputs.len() != self.inputs.len() {
            return Err(SigningProtocolError::InvalidField("package input count"));
        }

        let mut outpoints = HashSet::with_capacity(self.inputs.len());
        for (position, (transaction_input, input)) in
            transaction.inputs.iter().zip(&self.inputs).enumerate()
        {
            let expected_index = u32::try_from(position)
                .map_err(|_| SigningProtocolError::Capacity("package input"))?;
            if input.input_index != expected_index {
                return Err(SigningProtocolError::InvalidField("input_index"));
            }
            if input.outpoint != transaction_input.previous || !outpoints.insert(input.outpoint) {
                return Err(SigningProtocolError::InvalidField("input outpoint"));
            }
            if input.value_atoms == 0 {
                return Err(SigningProtocolError::InvalidField("input value_atoms"));
            }
            let InputWitness::Key {
                public_key,
                signature,
            } = &transaction_input.witness
            else {
                return Err(SigningProtocolError::InvalidField("input witness"));
            };
            if public_key != &input.public_key {
                return Err(SigningProtocolError::InvalidField("input public_key"));
            }
            if signature.as_slice() != [0_u8; CONSENSUS_SIGNATURE_BYTES] {
                return Err(SigningProtocolError::InvalidField(
                    "unsigned signature placeholder",
                ));
            }
            VerifyingKey::from_bytes(&input.public_key)
                .map_err(|_| SigningProtocolError::InvalidField("input public_key"))?;
            if input.key_id != wallet_key_id(&input.public_key) {
                return Err(SigningProtocolError::InvalidField("input key_id"));
            }
            require_nonzero(&input.signer_id.0, "input signer_id")?;
            require_nonzero(&input.capability_digest, "input capability_digest")?;
        }
        Ok(transaction)
    }
}

impl SignerResponseV1 {
    pub fn encode(&self) -> Result<Vec<u8>, SigningProtocolError> {
        self.validate()?;
        let signature_count = u16::try_from(self.signatures.len())
            .map_err(|_| SigningProtocolError::Capacity("response signature"))?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.package_digest);
        payload.extend_from_slice(&self.release_authorization_digest);
        payload.extend_from_slice(&self.signer_id.0);
        payload.extend_from_slice(&self.capability_digest);
        payload.extend_from_slice(&signature_count.to_le_bytes());
        for signature in &self.signatures {
            payload.extend_from_slice(&signature.input_index.to_le_bytes());
            payload.extend_from_slice(&signature.key_id.0);
            payload.extend_from_slice(&signature.transaction_signature);
            payload.extend_from_slice(&signature.package_authorization_signature);
        }
        encode_envelope(RESPONSE_KIND, payload, MAX_SIGNER_RESPONSE_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SigningProtocolError> {
        let payload = decode_envelope(bytes, RESPONSE_KIND, MAX_SIGNER_RESPONSE_BYTES)?;
        let mut decoder = Decoder::new(payload);
        let package_digest = decoder.array()?;
        let release_authorization_digest = decoder.array()?;
        let signer_id = SignerId(decoder.array()?);
        let capability_digest = decoder.array()?;
        let signature_count = decoder.bounded_u16(MAX_TRANSACTION_INPUTS, "response signature")?;
        let mut signatures = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            signatures.push(InputSignatureV1 {
                input_index: decoder.u32()?,
                key_id: WalletKeyId(decoder.array()?),
                transaction_signature: decoder.array()?,
                package_authorization_signature: decoder.array()?,
            });
        }
        decoder.finish()?;
        let value = Self {
            package_digest,
            release_authorization_digest,
            signer_id,
            capability_digest,
            signatures,
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(SigningProtocolError::NonCanonical);
        }
        Ok(value)
    }

    pub fn digest(&self) -> Result<[u8; 32], SigningProtocolError> {
        digest_encoded(RESPONSE_DIGEST_DOMAIN, &self.encode()?)
    }

    fn validate(&self) -> Result<(), SigningProtocolError> {
        require_nonzero(&self.package_digest, "package_digest")?;
        require_nonzero(
            &self.release_authorization_digest,
            "release_authorization_digest",
        )?;
        require_nonzero(&self.signer_id.0, "signer_id")?;
        require_nonzero(&self.capability_digest, "capability_digest")?;
        if self.signatures.is_empty() || self.signatures.len() > MAX_TRANSACTION_INPUTS {
            return Err(SigningProtocolError::Capacity("response signature"));
        }
        let mut previous = None;
        for signature in &self.signatures {
            if usize::try_from(signature.input_index)
                .ok()
                .is_none_or(|index| index >= MAX_TRANSACTION_INPUTS)
            {
                return Err(SigningProtocolError::InvalidField("signature input_index"));
            }
            if previous.is_some_and(|previous| previous >= signature.input_index) {
                return Err(SigningProtocolError::InvalidField(
                    "signature input ordering",
                ));
            }
            previous = Some(signature.input_index);
            require_nonzero(&signature.key_id.0, "signature key_id")?;
            Signature::try_from(signature.transaction_signature.as_slice()).map_err(|_| {
                SigningProtocolError::InvalidField("transaction signature encoding")
            })?;
            Signature::try_from(signature.package_authorization_signature.as_slice()).map_err(
                |_| SigningProtocolError::InvalidField("package authorization signature encoding"),
            )?;
        }
        Ok(())
    }
}

impl ExpectedSigningContextV1 {
    pub fn validate_package(&self, package: &SigningPackageV1) -> Result<(), SigningProtocolError> {
        self.validated_package_digest(package).map(|_| ())
    }

    fn validated_package_digest(
        &self,
        package: &SigningPackageV1,
    ) -> Result<[u8; 32], SigningProtocolError> {
        require_nonzero(&self.package_digest, "expected package_digest")?;
        require_nonzero(
            &self.release_authorization_digest,
            "expected release_authorization_digest",
        )?;
        if self.signers.is_empty() || self.signers.len() > MAX_TRANSACTION_INPUTS {
            return Err(SigningProtocolError::InvalidExpectedContext(
                "signer binding count",
            ));
        }
        let package_bytes = package.encode()?;
        let package_digest = digest_encoded(PACKAGE_DIGEST_DOMAIN, &package_bytes)?;
        if package_digest != self.package_digest {
            return Err(SigningProtocolError::ExpectedPackageDigestMismatch);
        }

        let mut previous_signer = None;
        for binding in &self.signers {
            binding.capabilities.validate()?;
            if binding.capabilities.algorithm != SigningAlgorithmV1::Bip340Secp256k1 {
                return Err(SigningProtocolError::InvalidExpectedContext(
                    "signer algorithm",
                ));
            }
            if previous_signer.is_some_and(|previous| previous >= binding.capabilities.signer_id) {
                return Err(SigningProtocolError::InvalidExpectedContext(
                    "signer binding ordering",
                ));
            }
            previous_signer = Some(binding.capabilities.signer_id);
            if signer_key_set_digest(
                binding.capabilities.signer_id,
                binding.capabilities.algorithm,
                &binding.key_ids,
            )? != binding.capabilities.key_set_digest
            {
                return Err(SigningProtocolError::InvalidExpectedContext(
                    "signer key_set_digest",
                ));
            }
        }

        let mut signer_input_counts = vec![0_usize; self.signers.len()];
        for input in &package.inputs {
            let signer_position = self
                .signers
                .binary_search_by_key(&input.signer_id, |binding| binding.capabilities.signer_id)
                .map_err(|_| SigningProtocolError::UntrustedSigner(input.input_index))?;
            let binding = &self.signers[signer_position];
            if input.capability_digest != binding.capabilities.digest()? {
                return Err(SigningProtocolError::UntrustedCapability(input.input_index));
            }
            if binding.key_ids.binary_search(&input.key_id).is_err() {
                return Err(SigningProtocolError::UntrustedWalletKey(input.input_index));
            }
            if package_bytes.len() > binding.capabilities.max_package_bytes as usize {
                return Err(SigningProtocolError::SignerPackageLimit);
            }
            signer_input_counts[signer_position] = signer_input_counts[signer_position]
                .checked_add(1)
                .ok_or(SigningProtocolError::SignerSignatureLimit)?;
            if signer_input_counts[signer_position]
                > usize::from(binding.capabilities.max_signatures_per_request)
            {
                return Err(SigningProtocolError::SignerSignatureLimit);
            }
        }
        Ok(package_digest)
    }
}

/// Verifies authenticated signing expectations and both signatures for every
/// input before assembling the exact consensus transaction. The caller must
/// still revalidate each input owner and value against trusted chain state at
/// package issuance and release; package metadata is not a UTXO proof.
pub fn assemble_signed_transaction(
    package: &SigningPackageV1,
    expected: &ExpectedSigningContextV1,
    responses: &[SignerResponseV1],
) -> Result<AssembledTransactionV1, SigningProtocolError> {
    let package_digest = expected.validated_package_digest(package)?;
    let release_authorization_digest = expected.release_authorization_digest;
    let mut transaction = package.validated_transaction()?;
    if responses.len() > package.inputs.len() {
        return Err(SigningProtocolError::Capacity("signer response"));
    }
    let mut signatures = vec![None; package.inputs.len()];

    for response in responses {
        response.validate()?;
        if response.package_digest != package_digest {
            return Err(SigningProtocolError::PackageDigestMismatch);
        }
        if response.release_authorization_digest != release_authorization_digest {
            return Err(SigningProtocolError::ReleaseAuthorizationMismatch);
        }
        for supplied in &response.signatures {
            let index = usize::try_from(supplied.input_index)
                .map_err(|_| SigningProtocolError::UnexpectedSignature(supplied.input_index))?;
            let expected =
                package
                    .inputs
                    .get(index)
                    .ok_or(SigningProtocolError::UnexpectedSignature(
                        supplied.input_index,
                    ))?;
            if expected.signer_id != response.signer_id {
                return Err(SigningProtocolError::SignerMismatch(supplied.input_index));
            }
            if expected.capability_digest != response.capability_digest {
                return Err(SigningProtocolError::CapabilityMismatch(
                    supplied.input_index,
                ));
            }
            if expected.key_id != supplied.key_id {
                return Err(SigningProtocolError::WalletKeyMismatch(
                    supplied.input_index,
                ));
            }
            if signatures[index].is_some() {
                return Err(SigningProtocolError::DuplicateSignature(
                    supplied.input_index,
                ));
            }
            let public_key = VerifyingKey::from_bytes(&expected.public_key)
                .map_err(|_| SigningProtocolError::InvalidField("input public_key"))?;
            let authorization_signature = Signature::try_from(
                supplied.package_authorization_signature.as_slice(),
            )
            .map_err(|_| SigningProtocolError::InvalidPackageAuthorization(supplied.input_index))?;
            let authorization_digest = package_authorization_digest(
                &package_digest,
                &release_authorization_digest,
                supplied.input_index,
                supplied.key_id,
                response.signer_id,
                &response.capability_digest,
                &supplied.transaction_signature,
            );
            public_key
                .verify(&authorization_digest, &authorization_signature)
                .map_err(|_| {
                    SigningProtocolError::InvalidPackageAuthorization(supplied.input_index)
                })?;
            let transaction_signature =
                Signature::try_from(supplied.transaction_signature.as_slice()).map_err(|_| {
                    SigningProtocolError::InvalidTransactionSignature(supplied.input_index)
                })?;
            public_key
                .verify(&package.signing_digest, &transaction_signature)
                .map_err(|_| {
                    SigningProtocolError::InvalidTransactionSignature(supplied.input_index)
                })?;
            signatures[index] = Some(supplied.transaction_signature);
        }
    }

    for (position, (transaction_input, signature)) in
        transaction.inputs.iter_mut().zip(signatures).enumerate()
    {
        let input_index =
            u32::try_from(position).map_err(|_| SigningProtocolError::Capacity("package input"))?;
        let signature = signature.ok_or(SigningProtocolError::MissingSignature(input_index))?;
        let InputWitness::Key {
            signature: witness_signature,
            ..
        } = &mut transaction_input.witness
        else {
            return Err(SigningProtocolError::InvalidField("input witness"));
        };
        *witness_signature = signature.to_vec();
    }

    if transaction.signing_digest() != package.signing_digest {
        return Err(SigningProtocolError::SigningDigestChanged);
    }
    let transaction_bytes = encode_transaction(&transaction)?;
    let txid = transaction.txid();
    Ok(AssembledTransactionV1 {
        transaction,
        transaction_bytes,
        txid,
    })
}

fn validate_request_id(request_id: &str) -> Result<(), SigningProtocolError> {
    if request_id.is_empty()
        || request_id.len() > MAX_SIGNING_REQUEST_ID_BYTES
        || !request_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(SigningProtocolError::InvalidField("request_id"));
    }
    Ok(())
}

fn validate_withdrawal_anchor(anchor: WithdrawalAnchorV1) -> Result<(), SigningProtocolError> {
    require_nonzero(&anchor.key_id, "prepared anchor key_id")?;
    require_nonzero(
        &anchor.journal_instance_id,
        "prepared anchor journal_instance_id",
    )?;
    if anchor.generation == 0 {
        return Err(SigningProtocolError::InvalidField(
            "prepared anchor generation",
        ));
    }
    require_nonzero(&anchor.commitment, "prepared anchor commitment")
}

fn validate_keyring_anchor(anchor: KeyringAnchorV1) -> Result<(), SigningProtocolError> {
    require_nonzero(&anchor.instance_id, "keyring anchor instance_id")?;
    if anchor.generation == 0 {
        return Err(SigningProtocolError::InvalidField(
            "keyring anchor generation",
        ));
    }
    require_nonzero(&anchor.commitment, "keyring anchor commitment")
}

fn require_nonzero(value: &[u8; 32], field: &'static str) -> Result<(), SigningProtocolError> {
    if *value == [0; 32] {
        return Err(SigningProtocolError::InvalidField(field));
    }
    Ok(())
}

fn digest_encoded(domain: &str, bytes: &[u8]) -> Result<[u8; 32], SigningProtocolError> {
    if bytes.is_empty() {
        return Err(SigningProtocolError::InvalidField("encoded message"));
    }
    let mut hasher = Hasher::new_derive_key(domain);
    hasher.update(bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn encode_envelope(
    kind: u8,
    payload: Vec<u8>,
    maximum: usize,
) -> Result<Vec<u8>, SigningProtocolError> {
    let total = ENVELOPE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(SigningProtocolError::Capacity("message"))?;
    if total > maximum {
        return Err(SigningProtocolError::Capacity("message"));
    }
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| SigningProtocolError::Capacity("message"))?;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&SIGNING_PROTOCOL_MAGIC);
    bytes.extend_from_slice(&SIGNING_PROTOCOL_VERSION.to_le_bytes());
    bytes.push(kind);
    bytes.push(0);
    bytes.extend_from_slice(&payload_length.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode_envelope(
    bytes: &[u8],
    expected_kind: u8,
    maximum: usize,
) -> Result<&[u8], SigningProtocolError> {
    if bytes.len() > maximum {
        return Err(SigningProtocolError::Capacity("message"));
    }
    if bytes.len() < ENVELOPE_HEADER_BYTES {
        return Err(SigningProtocolError::Truncated);
    }
    if bytes[..8] != SIGNING_PROTOCOL_MAGIC {
        return Err(SigningProtocolError::InvalidMagic);
    }
    let version = u16::from_le_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| SigningProtocolError::Truncated)?,
    );
    if version != SIGNING_PROTOCOL_VERSION {
        return Err(SigningProtocolError::UnsupportedVersion(version));
    }
    let actual_kind = bytes[10];
    if actual_kind != expected_kind {
        return Err(SigningProtocolError::WrongMessageKind {
            expected: expected_kind,
            actual: actual_kind,
        });
    }
    if bytes[11] != 0 {
        return Err(SigningProtocolError::ReservedHeader);
    }
    let payload_length = usize::try_from(u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| SigningProtocolError::Truncated)?,
    ))
    .map_err(|_| SigningProtocolError::InvalidPayloadLength)?;
    if payload_length != bytes.len() - ENVELOPE_HEADER_BYTES {
        return Err(SigningProtocolError::InvalidPayloadLength);
    }
    Ok(&bytes[ENVELOPE_HEADER_BYTES..])
}

fn encode_withdrawal_anchor(bytes: &mut Vec<u8>, anchor: WithdrawalAnchorV1) {
    bytes.extend_from_slice(&anchor.key_id);
    bytes.extend_from_slice(&anchor.journal_instance_id);
    bytes.extend_from_slice(&anchor.generation.to_le_bytes());
    bytes.extend_from_slice(&anchor.commitment);
}

fn decode_withdrawal_anchor(
    decoder: &mut Decoder<'_>,
) -> Result<WithdrawalAnchorV1, SigningProtocolError> {
    Ok(WithdrawalAnchorV1 {
        key_id: decoder.array()?,
        journal_instance_id: decoder.array()?,
        generation: decoder.u64()?,
        commitment: decoder.array()?,
    })
}

fn encode_keyring_anchor(bytes: &mut Vec<u8>, anchor: KeyringAnchorV1) {
    bytes.extend_from_slice(&anchor.instance_id);
    bytes.extend_from_slice(&anchor.generation.to_le_bytes());
    bytes.extend_from_slice(&anchor.commitment);
}

fn decode_keyring_anchor(
    decoder: &mut Decoder<'_>,
) -> Result<KeyringAnchorV1, SigningProtocolError> {
    Ok(KeyringAnchorV1 {
        instance_id: decoder.array()?,
        generation: decoder.u64()?,
        commitment: decoder.array()?,
    })
}

fn encode_signing_input(bytes: &mut Vec<u8>, input: &SigningInputV1) {
    bytes.extend_from_slice(&input.input_index.to_le_bytes());
    bytes.extend_from_slice(&input.outpoint.txid);
    bytes.extend_from_slice(&input.outpoint.index.to_le_bytes());
    bytes.extend_from_slice(&input.value_atoms.to_le_bytes());
    bytes.extend_from_slice(&input.key_id.0);
    bytes.extend_from_slice(&input.public_key);
    bytes.extend_from_slice(&input.signer_id.0);
    bytes.extend_from_slice(&input.capability_digest);
}

fn decode_signing_input(decoder: &mut Decoder<'_>) -> Result<SigningInputV1, SigningProtocolError> {
    Ok(SigningInputV1 {
        input_index: decoder.u32()?,
        outpoint: OutPoint {
            txid: decoder.array()?,
            index: decoder.u32()?,
        },
        value_atoms: decoder.u64()?,
        key_id: WalletKeyId(decoder.array()?),
        public_key: decoder.array()?,
        signer_id: SignerId(decoder.array()?),
        capability_digest: decoder.array()?,
    })
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SigningProtocolError> {
        if self.remaining.len() < length {
            return Err(SigningProtocolError::Truncated);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SigningProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SigningProtocolError::Truncated)
    }

    fn byte(&mut self) -> Result<u8, SigningProtocolError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, SigningProtocolError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, SigningProtocolError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, SigningProtocolError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn bounded_u16(
        &mut self,
        maximum: usize,
        kind: &'static str,
    ) -> Result<usize, SigningProtocolError> {
        let value = usize::from(self.u16()?);
        if value > maximum {
            return Err(SigningProtocolError::Capacity(kind));
        }
        Ok(value)
    }

    fn bounded_u32(
        &mut self,
        maximum: usize,
        kind: &'static str,
    ) -> Result<usize, SigningProtocolError> {
        let value =
            usize::try_from(self.u32()?).map_err(|_| SigningProtocolError::Capacity(kind))?;
        if value > maximum {
            return Err(SigningProtocolError::Capacity(kind));
        }
        Ok(value)
    }

    fn finish(self) -> Result<(), SigningProtocolError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(SigningProtocolError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use cmfd_consensus::{OutputLock, TxInput, TxOutput};
    use k256::schnorr::{SigningKey, signature::Signer};

    use super::*;

    struct Fixture {
        first_key: SigningKey,
        second_key: SigningKey,
        first_capabilities: SignerCapabilitiesV1,
        second_capabilities: SignerCapabilitiesV1,
        package: SigningPackageV1,
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32]).expect("fixed test scalar must be valid")
    }

    fn public_key(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes().into()
    }

    fn capabilities(signer_byte: u8, key_ids: &[WalletKeyId]) -> SignerCapabilitiesV1 {
        let signer_id = SignerId([signer_byte; 32]);
        let algorithm = SigningAlgorithmV1::Bip340Secp256k1;
        SignerCapabilitiesV1 {
            signer_id,
            algorithm,
            max_signatures_per_request: MAX_TRANSACTION_INPUTS as u16,
            max_package_bytes: MAX_SIGNING_PACKAGE_BYTES as u32,
            key_set_digest: signer_key_set_digest(signer_id, algorithm, key_ids).unwrap(),
        }
    }

    fn fixture() -> Fixture {
        let first_key = key(1);
        let second_key = key(2);
        let recipient = public_key(&key(3));
        let first_public_key = public_key(&first_key);
        let second_public_key = public_key(&second_key);
        let first_key_id = wallet_key_id(&first_public_key);
        let second_key_id = wallet_key_id(&second_public_key);
        let first_capabilities = capabilities(0x51, &[first_key_id]);
        let second_capabilities = capabilities(0x52, &[second_key_id]);
        let network_id = [0x11; 32];
        let transaction = Transaction {
            network_id,
            version: TRANSACTION_VERSION,
            inputs: vec![
                TxInput {
                    previous: OutPoint {
                        txid: [0x21; 32],
                        index: 0,
                    },
                    witness: InputWitness::Key {
                        public_key: first_public_key,
                        signature: vec![0; CONSENSUS_SIGNATURE_BYTES],
                    },
                },
                TxInput {
                    previous: OutPoint {
                        txid: [0x22; 32],
                        index: 1,
                    },
                    witness: InputWitness::Key {
                        public_key: second_public_key,
                        signature: vec![0; CONSENSUS_SIGNATURE_BYTES],
                    },
                },
            ],
            outputs: vec![
                TxOutput {
                    value: 700,
                    lock: OutputLock::Key(recipient),
                    spendable_height: 44,
                },
                TxOutput {
                    value: 275,
                    lock: OutputLock::Key(first_public_key),
                    spendable_height: 44,
                },
            ],
        };
        let signing_digest = transaction.signing_digest();
        let unsigned_transaction = encode_transaction(&transaction).unwrap();
        let package = SigningPackageV1 {
            network_id,
            consensus_fingerprint: [0x12; 32],
            genesis: [0x13; 32],
            prepared_anchor: WithdrawalAnchorV1 {
                key_id: [0x31; 32],
                journal_instance_id: [0x32; 32],
                generation: 7,
                commitment: [0x33; 32],
            },
            request_id: "exchange-withdrawal-0001".to_owned(),
            request_digest: [0x41; 32],
            policy_id: [0x44; 32],
            keyring_anchor: KeyringAnchorV1 {
                instance_id: [0x42; 32],
                generation: 3,
                commitment: [0x43; 32],
            },
            unsigned_transaction,
            signing_digest,
            inputs: vec![
                SigningInputV1 {
                    input_index: 0,
                    outpoint: transaction.inputs[0].previous,
                    value_atoms: 400,
                    key_id: first_key_id,
                    public_key: first_public_key,
                    signer_id: first_capabilities.signer_id,
                    capability_digest: first_capabilities.digest().unwrap(),
                },
                SigningInputV1 {
                    input_index: 1,
                    outpoint: transaction.inputs[1].previous,
                    value_atoms: 600,
                    key_id: second_key_id,
                    public_key: second_public_key,
                    signer_id: second_capabilities.signer_id,
                    capability_digest: second_capabilities.digest().unwrap(),
                },
            ],
        };
        Fixture {
            first_key,
            second_key,
            first_capabilities,
            second_capabilities,
            package,
        }
    }

    fn response(
        package: &SigningPackageV1,
        capabilities: &SignerCapabilitiesV1,
        key: &SigningKey,
        input_index: usize,
    ) -> SignerResponseV1 {
        let package_digest = package.digest().unwrap();
        let release_authorization_digest = release_authorization_digest(
            &package_digest,
            ReleaseAuthorizationV1 {
                release_authorized_anchor: WithdrawalAnchorV1 {
                    key_id: [0x61; 32],
                    journal_instance_id: [0x62; 32],
                    generation: 8,
                    commitment: [0x63; 32],
                },
                decision_id: [0x64; 32],
                approval_digest: [0x65; 32],
            },
        )
        .unwrap();
        let capability_digest = capabilities.digest().unwrap();
        let input_index = input_index as u32;
        let key_id = package.inputs[input_index as usize].key_id;
        let transaction_signature: Signature = key.sign(&package.signing_digest);
        let transaction_signature = transaction_signature.to_bytes();
        let authorization_digest = package_authorization_digest(
            &package_digest,
            &release_authorization_digest,
            input_index,
            key_id,
            capabilities.signer_id,
            &capability_digest,
            &transaction_signature,
        );
        let package_authorization_signature: Signature = key.sign(&authorization_digest);
        SignerResponseV1 {
            package_digest,
            release_authorization_digest,
            signer_id: capabilities.signer_id,
            capability_digest,
            signatures: vec![InputSignatureV1 {
                input_index,
                key_id,
                transaction_signature,
                package_authorization_signature: package_authorization_signature.to_bytes(),
            }],
        }
    }

    fn reauthorize(response: &mut SignerResponseV1, signature_index: usize, key: &SigningKey) {
        let signature = &mut response.signatures[signature_index];
        let digest = package_authorization_digest(
            &response.package_digest,
            &response.release_authorization_digest,
            signature.input_index,
            signature.key_id,
            response.signer_id,
            &response.capability_digest,
            &signature.transaction_signature,
        );
        let authorization: Signature = key.sign(&digest);
        signature.package_authorization_signature = authorization.to_bytes();
    }

    fn responses(fixture: &Fixture) -> [SignerResponseV1; 2] {
        [
            response(
                &fixture.package,
                &fixture.first_capabilities,
                &fixture.first_key,
                0,
            ),
            response(
                &fixture.package,
                &fixture.second_capabilities,
                &fixture.second_key,
                1,
            ),
        ]
    }

    fn expected_context(fixture: &Fixture) -> ExpectedSigningContextV1 {
        let release_authorization_digest = responses(fixture)[0].release_authorization_digest;
        ExpectedSigningContextV1 {
            package_digest: fixture.package.digest().unwrap(),
            release_authorization_digest,
            signers: vec![
                ExpectedSignerBindingV1 {
                    capabilities: fixture.first_capabilities.clone(),
                    key_ids: vec![fixture.package.inputs[0].key_id],
                },
                ExpectedSignerBindingV1 {
                    capabilities: fixture.second_capabilities.clone(),
                    key_ids: vec![fixture.package.inputs[1].key_id],
                },
            ],
        }
    }

    #[test]
    fn messages_round_trip_canonically() {
        let fixture = fixture();
        let first_response = responses(&fixture)[0].clone();

        let capabilities = fixture.first_capabilities.encode().unwrap();
        assert_eq!(
            SignerCapabilitiesV1::decode(&capabilities).unwrap(),
            fixture.first_capabilities
        );
        let package = fixture.package.encode().unwrap();
        assert_eq!(SigningPackageV1::decode(&package).unwrap(), fixture.package);
        let response = first_response.encode().unwrap();
        assert_eq!(SignerResponseV1::decode(&response).unwrap(), first_response);
    }

    #[test]
    fn signer_response_cannot_cross_release_authorizations() {
        let fixture = fixture();
        let expected = expected_context(&fixture);
        let mut stale = responses(&fixture);
        stale[0].release_authorization_digest[0] ^= 1;
        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected, &stale),
            Err(SigningProtocolError::ReleaseAuthorizationMismatch)
        ));

        let package_digest = fixture.package.digest().unwrap();
        let original = ReleaseAuthorizationV1 {
            release_authorized_anchor: WithdrawalAnchorV1 {
                key_id: [0x61; 32],
                journal_instance_id: [0x62; 32],
                generation: 8,
                commitment: [0x63; 32],
            },
            decision_id: [0x64; 32],
            approval_digest: [0x65; 32],
        };
        let mut changed = original;
        changed.release_authorized_anchor.generation += 1;
        assert_ne!(
            release_authorization_digest(&package_digest, original).unwrap(),
            release_authorization_digest(&package_digest, changed).unwrap()
        );
    }

    #[test]
    fn expected_context_authenticates_signers_key_sets_and_aggregate_limits() {
        let fixture = fixture();
        let expected = expected_context(&fixture);
        expected.validate_package(&fixture.package).unwrap();

        let mut wrong_digest = expected.clone();
        wrong_digest.package_digest[0] ^= 1;
        assert!(matches!(
            wrong_digest.validate_package(&fixture.package),
            Err(SigningProtocolError::ExpectedPackageDigestMismatch)
        ));

        let mut unordered = expected.clone();
        unordered.signers.swap(0, 1);
        assert!(matches!(
            unordered.validate_package(&fixture.package),
            Err(SigningProtocolError::InvalidExpectedContext(
                "signer binding ordering"
            ))
        ));

        let mut wrong_key_set_digest = expected.clone();
        wrong_key_set_digest.signers[0].key_ids[0] = fixture.package.inputs[1].key_id;
        assert!(matches!(
            wrong_key_set_digest.validate_package(&fixture.package),
            Err(SigningProtocolError::InvalidExpectedContext(
                "signer key_set_digest"
            ))
        ));

        let mut wrong_capability_package = fixture.package.clone();
        wrong_capability_package.inputs[0].capability_digest[0] ^= 1;
        let mut wrong_capability_expected = expected.clone();
        wrong_capability_expected.package_digest = wrong_capability_package.digest().unwrap();
        assert!(matches!(
            wrong_capability_expected.validate_package(&wrong_capability_package),
            Err(SigningProtocolError::UntrustedCapability(0))
        ));

        let mut unknown_signer_package = fixture.package.clone();
        unknown_signer_package.inputs[0].signer_id = SignerId([0x77; 32]);
        let mut unknown_signer_expected = expected.clone();
        unknown_signer_expected.package_digest = unknown_signer_package.digest().unwrap();
        assert!(matches!(
            unknown_signer_expected.validate_package(&unknown_signer_package),
            Err(SigningProtocolError::UntrustedSigner(0))
        ));

        let alternate_key_id = wallet_key_id(&public_key(&key(4)));
        let alternate_capabilities = capabilities(0x51, &[alternate_key_id]);
        let mut untrusted_key_package = fixture.package.clone();
        untrusted_key_package.inputs[0].capability_digest =
            alternate_capabilities.digest().unwrap();
        let mut untrusted_key_expected = expected.clone();
        untrusted_key_expected.package_digest = untrusted_key_package.digest().unwrap();
        untrusted_key_expected.signers[0] = ExpectedSignerBindingV1 {
            capabilities: alternate_capabilities,
            key_ids: vec![alternate_key_id],
        };
        assert!(matches!(
            untrusted_key_expected.validate_package(&untrusted_key_package),
            Err(SigningProtocolError::UntrustedWalletKey(0))
        ));

        let mut size_limited_capabilities = fixture.first_capabilities.clone();
        size_limited_capabilities.max_package_bytes =
            u32::try_from(fixture.package.encode().unwrap().len() - 1).unwrap();
        let mut size_limited_package = fixture.package.clone();
        size_limited_package.inputs[0].capability_digest =
            size_limited_capabilities.digest().unwrap();
        let mut size_limited_expected = expected.clone();
        size_limited_expected.package_digest = size_limited_package.digest().unwrap();
        size_limited_expected.signers[0].capabilities = size_limited_capabilities;
        assert!(matches!(
            size_limited_expected.validate_package(&size_limited_package),
            Err(SigningProtocolError::SignerPackageLimit)
        ));

        let mut shared_key_ids = vec![
            fixture.package.inputs[0].key_id,
            fixture.package.inputs[1].key_id,
        ];
        shared_key_ids.sort_unstable();
        let mut count_limited_capabilities = capabilities(0x51, &shared_key_ids);
        count_limited_capabilities.max_signatures_per_request = 1;
        let count_limited_digest = count_limited_capabilities.digest().unwrap();
        let mut count_limited_package = fixture.package.clone();
        for input in &mut count_limited_package.inputs {
            input.signer_id = count_limited_capabilities.signer_id;
            input.capability_digest = count_limited_digest;
        }
        let count_limited_expected = ExpectedSigningContextV1 {
            package_digest: count_limited_package.digest().unwrap(),
            release_authorization_digest: expected.release_authorization_digest,
            signers: vec![ExpectedSignerBindingV1 {
                capabilities: count_limited_capabilities,
                key_ids: shared_key_ids,
            }],
        };
        assert!(matches!(
            count_limited_expected.validate_package(&count_limited_package),
            Err(SigningProtocolError::SignerSignatureLimit)
        ));
    }

    #[test]
    fn golden_digests_and_signed_transaction_are_stable() {
        let fixture = fixture();
        let responses = responses(&fixture);
        let expected = expected_context(&fixture);
        let assembled =
            assemble_signed_transaction(&fixture.package, &expected, &responses).unwrap();

        assert_eq!(
            hex::encode(fixture.first_capabilities.key_set_digest),
            "3865a443ae9644782a44a07377071cd4df01ce613160ac2fe8235764368bb7e4"
        );
        assert_eq!(
            hex::encode(fixture.first_capabilities.digest().unwrap()),
            "fc8aea3e18c9125214624e19fa0426bdd512bb7337f1da56fbde4a2ae411f555"
        );
        assert_eq!(
            hex::encode(fixture.package.digest().unwrap()),
            "e349e9e9a01caab82b04ad0ed5a4da768c248675c20525d096c6e04a21ab9379"
        );
        assert_eq!(
            hex::encode(package_authorization_digest(
                &responses[0].package_digest,
                &responses[0].release_authorization_digest,
                responses[0].signatures[0].input_index,
                responses[0].signatures[0].key_id,
                responses[0].signer_id,
                &responses[0].capability_digest,
                &responses[0].signatures[0].transaction_signature,
            )),
            "c6a521beb768661cbcf5ad678a01e74c7bd05581f1fa5ee525cf9ee81054502d"
        );
        assert_eq!(
            hex::encode(responses[0].digest().unwrap()),
            "ffe964fbde15905b04b6193fd53639cfac7f6a10e021b2e5dc3205576ac03e26"
        );
        assert_eq!(
            hex::encode(assembled.txid),
            "aef4eb393d684957443ef6d4edd9f2b2efaf7439b091a1ef73370ad493623d59"
        );
        assert_eq!(
            &fixture.package.encode().unwrap()[..16],
            b"CMFDSIG1\x01\0\x02\0\x98\x04\0\0"
        );
    }

    #[test]
    fn two_keys_and_response_order_assemble_identically() {
        let fixture = fixture();
        let responses = responses(&fixture);
        let expected = expected_context(&fixture);
        let forward = assemble_signed_transaction(&fixture.package, &expected, &responses).unwrap();
        let reverse = assemble_signed_transaction(
            &fixture.package,
            &expected,
            &[responses[1].clone(), responses[0].clone()],
        )
        .unwrap();

        assert_eq!(forward, reverse);
        assert_eq!(
            forward.transaction.signing_digest(),
            fixture.package.signing_digest
        );
        assert_eq!(
            decode_transaction(&forward.transaction_bytes, fixture.package.network_id).unwrap(),
            forward.transaction
        );
        for input in &forward.transaction.inputs {
            let InputWitness::Key { signature, .. } = &input.witness else {
                panic!("assembled transaction must contain key witnesses");
            };
            assert_eq!(signature.len(), CONSENSUS_SIGNATURE_BYTES);
            assert_ne!(signature.as_slice(), [0_u8; CONSENSUS_SIGNATURE_BYTES]);
        }
    }

    #[test]
    fn zero_signature_placeholders_are_wire_width_only_and_do_not_change_the_intent() {
        let fixture = fixture();
        let placeholder_transaction = fixture.package.transaction().unwrap();
        for input in &placeholder_transaction.inputs {
            let InputWitness::Key { signature, .. } = &input.witness else {
                panic!("signing package must contain only key witnesses");
            };
            assert_eq!(signature.as_slice(), [0_u8; CONSENSUS_SIGNATURE_BYTES]);
        }

        let mut blank_transaction = placeholder_transaction.clone();
        for input in &mut blank_transaction.inputs {
            let InputWitness::Key { signature, .. } = &mut input.witness else {
                unreachable!();
            };
            signature.clear();
        }
        assert_eq!(
            placeholder_transaction.signing_digest(),
            blank_transaction.signing_digest()
        );
        assert!(encode_transaction(&blank_transaction).is_err());
        assert_eq!(
            encode_unsigned_key_transaction(&blank_transaction).unwrap(),
            fixture.package.unsigned_transaction
        );
        let mut nonzero_transaction = placeholder_transaction.clone();
        let InputWitness::Key { signature, .. } = &mut nonzero_transaction.inputs[0].witness else {
            unreachable!();
        };
        signature[0] = 1;
        assert!(matches!(
            encode_unsigned_key_transaction(&nonzero_transaction),
            Err(SigningProtocolError::InvalidField(
                "transaction is already signed"
            ))
        ));

        let assembled = assemble_signed_transaction(
            &fixture.package,
            &expected_context(&fixture),
            &responses(&fixture),
        )
        .unwrap();
        assert_eq!(
            assembled.transaction.signing_digest(),
            placeholder_transaction.signing_digest()
        );
    }

    #[test]
    fn unsigned_encoder_bounds_outputs_and_signature_buffers_before_cloning() {
        let fixture = fixture();
        let transaction = fixture.package.transaction().unwrap();

        let mut no_outputs = transaction.clone();
        no_outputs.outputs.clear();
        assert!(matches!(
            encode_unsigned_key_transaction(&no_outputs),
            Err(SigningProtocolError::InvalidField(
                "transaction output count"
            ))
        ));

        let mut too_many_outputs = transaction.clone();
        too_many_outputs.outputs =
            vec![transaction.outputs[0].clone(); MAX_TRANSACTION_OUTPUTS + 1];
        assert!(matches!(
            encode_unsigned_key_transaction(&too_many_outputs),
            Err(SigningProtocolError::Capacity("transaction output"))
        ));

        let mut malformed_signature = transaction;
        let InputWitness::Key { signature, .. } = &mut malformed_signature.inputs[1].witness else {
            unreachable!();
        };
        *signature = vec![0; MAX_TRANSACTION_BYTES + 1];
        assert!(matches!(
            encode_unsigned_key_transaction(&malformed_signature),
            Err(SigningProtocolError::InvalidField(
                "unsigned signature shape"
            ))
        ));
    }

    #[test]
    fn envelope_rejects_magic_version_kind_reserved_length_and_trailing_changes() {
        let fixture = fixture();
        let encoded = fixture.package.encode().unwrap();

        let mut invalid = encoded.clone();
        invalid[0] ^= 1;
        assert!(matches!(
            SigningPackageV1::decode(&invalid),
            Err(SigningProtocolError::InvalidMagic)
        ));
        let mut invalid = encoded.clone();
        invalid[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            SigningPackageV1::decode(&invalid),
            Err(SigningProtocolError::UnsupportedVersion(2))
        ));
        let mut invalid = encoded.clone();
        invalid[10] = RESPONSE_KIND;
        assert!(matches!(
            SigningPackageV1::decode(&invalid),
            Err(SigningProtocolError::WrongMessageKind { .. })
        ));
        let mut invalid = encoded.clone();
        invalid[11] = 1;
        assert!(matches!(
            SigningPackageV1::decode(&invalid),
            Err(SigningProtocolError::ReservedHeader)
        ));
        let mut invalid = encoded.clone();
        invalid[12..16].copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            SigningPackageV1::decode(&invalid),
            Err(SigningProtocolError::InvalidPayloadLength)
        ));
        let mut invalid = encoded;
        invalid.push(0);
        assert!(matches!(
            SigningPackageV1::decode(&invalid),
            Err(SigningProtocolError::InvalidPayloadLength)
        ));
        assert!(matches!(
            SigningPackageV1::decode(&invalid[..8]),
            Err(SigningProtocolError::Truncated)
        ));

        let mut unsupported_algorithm = fixture.first_capabilities.encode().unwrap();
        unsupported_algorithm[ENVELOPE_HEADER_BYTES + 32] = 2;
        assert!(matches!(
            SignerCapabilitiesV1::decode(&unsupported_algorithm),
            Err(SigningProtocolError::UnsupportedAlgorithm(2))
        ));
    }

    #[test]
    fn package_rejects_noncanonical_or_mismatched_transaction_bindings() {
        let fixture = fixture();

        let mut changed = fixture.package.clone();
        changed.policy_id = [0; 32];
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField("policy_id"))
        ));

        let mut changed = fixture.package.clone();
        changed.signing_digest[0] ^= 1;
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField("signing_digest"))
        ));

        let mut changed = fixture.package.clone();
        changed.inputs[0].input_index = 1;
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField("input_index"))
        ));

        let mut changed = fixture.package.clone();
        changed.inputs[0].outpoint.index ^= 1;
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField("input outpoint"))
        ));

        let mut changed = fixture.package.clone();
        changed.inputs[0].key_id = fixture.package.inputs[1].key_id;
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField("input key_id"))
        ));

        let mut transaction = fixture.package.transaction().unwrap();
        let InputWitness::Key { signature, .. } = &mut transaction.inputs[0].witness else {
            unreachable!();
        };
        signature[0] = 1;
        let mut changed = fixture.package.clone();
        changed.unsigned_transaction = encode_transaction(&transaction).unwrap();
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField(
                "unsigned signature placeholder"
            ))
        ));
    }

    #[test]
    fn message_bounds_and_identifiers_are_enforced_before_allocation() {
        let fixture = fixture();

        let mut capabilities = fixture.first_capabilities.clone();
        capabilities.max_signatures_per_request = MAX_TRANSACTION_INPUTS as u16 + 1;
        assert!(matches!(
            capabilities.encode(),
            Err(SigningProtocolError::InvalidField(
                "max_signatures_per_request"
            ))
        ));
        let mut capabilities = fixture.first_capabilities.clone();
        capabilities.max_package_bytes = (MAX_SIGNING_PACKAGE_BYTES + 1) as u32;
        assert!(matches!(
            capabilities.encode(),
            Err(SigningProtocolError::InvalidField("max_package_bytes"))
        ));

        let mut package = fixture.package.clone();
        package.request_id = "x".repeat(MAX_SIGNING_REQUEST_ID_BYTES + 1);
        assert!(matches!(
            package.encode(),
            Err(SigningProtocolError::InvalidField("request_id"))
        ));
        let mut package = fixture.package.clone();
        package.request_id = "x".repeat(MAX_SIGNING_REQUEST_ID_BYTES);
        assert_eq!(
            SigningPackageV1::decode(&package.encode().unwrap()).unwrap(),
            package
        );
        let mut package = fixture.package.clone();
        package.inputs = vec![package.inputs[0].clone(); MAX_TRANSACTION_INPUTS + 1];
        assert!(matches!(
            package.encode(),
            Err(SigningProtocolError::Capacity("package input"))
        ));
        let mut package = fixture.package.clone();
        package.request_id = "contains space".to_owned();
        assert!(matches!(
            package.encode(),
            Err(SigningProtocolError::InvalidField("request_id"))
        ));

        let mut response = responses(&fixture)[0].clone();
        response.signatures = vec![response.signatures[0].clone(); MAX_TRANSACTION_INPUTS + 1];
        assert!(matches!(
            response.encode(),
            Err(SigningProtocolError::Capacity("response signature"))
        ));

        assert!(matches!(
            SigningPackageV1::decode(&vec![0; MAX_SIGNING_PACKAGE_BYTES + 1]),
            Err(SigningProtocolError::Capacity("message"))
        ));
        assert!(matches!(
            SignerResponseV1::decode(&vec![0; MAX_SIGNER_RESPONSE_BYTES + 1]),
            Err(SigningProtocolError::Capacity("message"))
        ));
    }

    #[test]
    fn zero_package_request_signer_and_wallet_key_ids_fail_closed() {
        let fixture = fixture();

        let mut capabilities = fixture.first_capabilities.clone();
        capabilities.signer_id = SignerId([0; 32]);
        assert!(matches!(
            capabilities.encode(),
            Err(SigningProtocolError::InvalidField("signer_id"))
        ));
        let mut capabilities = fixture.first_capabilities.clone();
        capabilities.key_set_digest = [0; 32];
        assert!(matches!(
            capabilities.encode(),
            Err(SigningProtocolError::InvalidField("key_set_digest"))
        ));

        let mut package = fixture.package.clone();
        package.request_digest = [0; 32];
        assert!(matches!(
            package.encode(),
            Err(SigningProtocolError::InvalidField("request_digest"))
        ));
        let mut package = fixture.package.clone();
        package.inputs[0].key_id = WalletKeyId([0; 32]);
        assert!(matches!(
            package.encode(),
            Err(SigningProtocolError::InvalidField("input key_id"))
        ));

        let original = responses(&fixture)[0].clone();
        let mut response = original.clone();
        response.package_digest = [0; 32];
        assert!(matches!(
            response.encode(),
            Err(SigningProtocolError::InvalidField("package_digest"))
        ));
        let mut response = original.clone();
        response.signer_id = SignerId([0; 32]);
        assert!(matches!(
            response.encode(),
            Err(SigningProtocolError::InvalidField("signer_id"))
        ));
        let mut response = original.clone();
        response.capability_digest = [0; 32];
        assert!(matches!(
            response.encode(),
            Err(SigningProtocolError::InvalidField("capability_digest"))
        ));
        let mut response = original;
        response.signatures[0].key_id = WalletKeyId([0; 32]);
        assert!(matches!(
            response.encode(),
            Err(SigningProtocolError::InvalidField("signature key_id"))
        ));
    }

    #[test]
    fn response_encoding_rejects_empty_unsorted_and_malformed_signatures() {
        let fixture = fixture();
        let first = responses(&fixture)[0].clone();

        let mut changed = first.clone();
        changed.signatures.clear();
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::Capacity("response signature"))
        ));

        let mut changed = first.clone();
        let mut higher = changed.signatures[0].clone();
        higher.input_index = 1;
        changed.signatures = vec![higher, changed.signatures[0].clone()];
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField(
                "signature input ordering"
            ))
        ));

        let mut changed = first.clone();
        changed.signatures[0].transaction_signature = [0xff; CONSENSUS_SIGNATURE_BYTES];
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField(
                "transaction signature encoding"
            ))
        ));

        let mut changed = first;
        changed.signatures[0].package_authorization_signature = [0xff; CONSENSUS_SIGNATURE_BYTES];
        assert!(matches!(
            changed.encode(),
            Err(SigningProtocolError::InvalidField(
                "package authorization signature encoding"
            ))
        ));
    }

    #[test]
    fn assembly_rejects_missing_duplicate_and_unexpected_signatures() {
        let fixture = fixture();
        let responses = responses(&fixture);
        let expected = expected_context(&fixture);

        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected, &[]),
            Err(SigningProtocolError::MissingSignature(0))
        ));
        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected, &responses[..1]),
            Err(SigningProtocolError::MissingSignature(1))
        ));
        assert!(matches!(
            assemble_signed_transaction(
                &fixture.package,
                &expected,
                &[responses[0].clone(), responses[0].clone()]
            ),
            Err(SigningProtocolError::DuplicateSignature(0))
        ));

        let mut unexpected = responses[0].clone();
        unexpected.signatures[0].input_index = 2;
        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected, &[unexpected]),
            Err(SigningProtocolError::UnexpectedSignature(2))
        ));
    }

    #[test]
    fn assembly_rejects_package_signer_capability_and_key_mismatches() {
        let fixture = fixture();
        let first = responses(&fixture)[0].clone();
        let expected = expected_context(&fixture);

        let mut changed = first.clone();
        changed.package_digest[0] ^= 1;
        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected, &[changed]),
            Err(SigningProtocolError::PackageDigestMismatch)
        ));

        let mut changed = first.clone();
        changed.signer_id = fixture.second_capabilities.signer_id;
        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected, &[changed]),
            Err(SigningProtocolError::SignerMismatch(0))
        ));

        let mut changed = first.clone();
        changed.capability_digest[0] ^= 1;
        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected, &[changed]),
            Err(SigningProtocolError::CapabilityMismatch(0))
        ));

        let mut changed = first;
        changed.signatures[0].key_id = fixture.package.inputs[1].key_id;
        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected, &[changed]),
            Err(SigningProtocolError::WalletKeyMismatch(0))
        ));
    }

    #[test]
    fn assembly_rejects_a_well_formed_signature_from_the_wrong_key() {
        let fixture = fixture();
        let mut first = responses(&fixture)[0].clone();
        let wrong_signature: Signature = fixture.second_key.sign(&fixture.package.signing_digest);
        first.signatures[0].transaction_signature = wrong_signature.to_bytes();
        reauthorize(&mut first, 0, &fixture.first_key);

        assert!(matches!(
            assemble_signed_transaction(&fixture.package, &expected_context(&fixture), &[first]),
            Err(SigningProtocolError::InvalidTransactionSignature(0))
        ));
    }

    #[test]
    fn a_response_cannot_be_relabelled_to_another_package_with_the_same_transaction() {
        let fixture = fixture();
        let original_package_digest = fixture.package.digest().unwrap();
        let mut other_package = fixture.package.clone();
        other_package.request_id = "exchange-withdrawal-0002".to_owned();
        other_package.request_digest = [0x44; 32];
        other_package.prepared_anchor.generation += 1;
        other_package.prepared_anchor.commitment = [0x34; 32];
        let other_package_digest = other_package.digest().unwrap();
        assert_eq!(fixture.package.signing_digest, other_package.signing_digest);
        assert_ne!(original_package_digest, other_package_digest);

        let mut relabelled = responses(&fixture)[0].clone();
        relabelled.package_digest = other_package_digest;
        let mut other_expected = expected_context(&fixture);
        other_expected.package_digest = other_package_digest;
        assert!(matches!(
            assemble_signed_transaction(&other_package, &other_expected, &[relabelled]),
            Err(SigningProtocolError::InvalidPackageAuthorization(0))
        ));

        let mut changed_transaction_signature = responses(&fixture)[0].clone();
        changed_transaction_signature.signatures[0].transaction_signature =
            responses(&fixture)[1].signatures[0].transaction_signature;
        assert!(matches!(
            assemble_signed_transaction(
                &fixture.package,
                &expected_context(&fixture),
                &[changed_transaction_signature]
            ),
            Err(SigningProtocolError::InvalidPackageAuthorization(0))
        ));
    }

    #[test]
    fn decode_rejects_trailing_payload_fields_even_with_adjusted_length() {
        let fixture = fixture();
        let mut encoded = fixture.first_capabilities.encode().unwrap();
        encoded.push(0);
        let payload_length = u32::try_from(encoded.len() - ENVELOPE_HEADER_BYTES).unwrap();
        encoded[12..16].copy_from_slice(&payload_length.to_le_bytes());
        assert!(matches!(
            SignerCapabilitiesV1::decode(&encoded),
            Err(SigningProtocolError::TrailingBytes)
        ));
    }
}
