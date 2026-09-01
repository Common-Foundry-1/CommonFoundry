//! Authenticated, encrypted multi-key wallet storage primitives.
//!
//! This module deliberately performs no file I/O. Callers must provide atomic,
//! private-file persistence and keep the independently trusted rollback anchor
//! outside the node's writable custody boundary. Loading live state and
//! restoring a backup both require an exact trusted anchor; there is no
//! unanchored or automatic legacy-migration path.

use std::cmp::Ordering;

use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use k256::schnorr::signature::Signer;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::wallet_signing_protocol::{SignerId, WalletKeyId, wallet_key_id};

pub const KEYRING_STORAGE_MAGIC: [u8; 8] = *b"CMFDKRG1";
pub const KEYRING_BACKUP_MAGIC: [u8; 8] = *b"CMFDKRB1";
pub const KEYRING_ANCHOR_MAGIC: [u8; 8] = *b"CMFDKRA1";
pub const KEYRING_STORAGE_VERSION: u16 = 1;
pub const KEYRING_ANCHOR_VERSION: u16 = 1;
pub const MAX_KEYRING_ENTRIES: usize = 4_096;
pub const MAX_KEYRING_PLAINTEXT_BYTES: usize = 512 * 1024;
pub const MINIMUM_KEYRING_PASSPHRASE_BYTES: usize = 12;
pub const MAXIMUM_KEYRING_PASSPHRASE_BYTES: usize = 1_024;
pub const KEYRING_ANCHOR_BYTES: usize = 210;
pub const MAX_KEYRING_ENVELOPE_BYTES: usize = 268 + MAX_KEYRING_PLAINTEXT_BYTES + 16;

const KEYRING_PAYLOAD_MAGIC: [u8; 8] = *b"CMFDKRP1";
const KDF_ARGON2ID: u8 = 1;
const CIPHER_XCHACHA20_POLY1305: u8 = 1;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const ENVELOPE_HEADER_BYTES: usize = 268;
const PAYLOAD_FIXED_BYTES: usize = 182;

const LOCAL_STORAGE_TAG: u8 = 1;
const EXTERNAL_STORAGE_TAG: u8 = 2;
const WATCH_ONLY_STORAGE_TAG: u8 = 3;
const COMMITMENT_DOMAIN: &str = "CMFD/NODE/WALLET-KEYRING/COMMITMENT/V1";
const ANCHOR_CHECKSUM_DOMAIN: &str = "CMFD/NODE/WALLET-KEYRING/ANCHOR-CHECKSUM/V1";
const LEGACY_CONFIRMATION_DOMAIN: &str = "CMFD/NODE/WALLET-KEYRING/LEGACY-IMPORT-CONFIRMATION/V1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WalletKeyringError {
    #[error("wallet keyring passphrase must contain between 12 and 1024 bytes")]
    InvalidPassphrase,
    #[error("wallet keyring binding field is zero: {0}")]
    ZeroBinding(&'static str),
    #[error("wallet keyring instance id is zero")]
    ZeroInstanceId,
    #[error("wallet keyring generation overflow")]
    GenerationOverflow,
    #[error("wallet keyring generation and prior commitment are inconsistent")]
    InvalidPriorCommitment,
    #[error("wallet keyring contains no keys or exceeds its key capacity")]
    InvalidKeyCount,
    #[error("wallet keyring key entries are not unique and strictly ordered")]
    NonCanonicalKeyOrder,
    #[error("wallet keyring role bits are invalid")]
    InvalidKeyRoles,
    #[error("wallet keyring public key is invalid")]
    InvalidPublicKey,
    #[error("wallet keyring local secret is invalid")]
    InvalidLocalSecret,
    #[error("wallet keyring local secret does not match its public key")]
    LocalSecretMismatch,
    #[error("wallet keyring key id does not match its public key")]
    KeyIdMismatch,
    #[error("wallet keyring external signer id is zero")]
    ZeroSignerId,
    #[error("wallet keyring must contain exactly one active change key")]
    ActiveChangeKeyCount,
    #[error("the active change key cannot be watch-only")]
    WatchOnlyActiveChangeKey,
    #[error("wallet keyring envelope exceeds its byte capacity")]
    EnvelopeTooLarge,
    #[error("wallet keyring plaintext exceeds its byte capacity")]
    PlaintextTooLarge,
    #[error("wallet keyring envelope is truncated")]
    Truncated,
    #[error("wallet keyring envelope contains trailing bytes")]
    TrailingBytes,
    #[error("wallet keyring magic is invalid")]
    InvalidMagic,
    #[error("unsupported wallet keyring version {0}")]
    UnsupportedVersion(u16),
    #[error("wallet keyring envelope KDF or cipher is unsupported")]
    UnsupportedCryptography,
    #[error("wallet keyring envelope parameters are not canonical")]
    NonCanonicalCryptography,
    #[error("wallet keyring reserved byte is nonzero")]
    ReservedByte,
    #[error("wallet keyring envelope length is invalid")]
    InvalidEnvelopeLength,
    #[error("wallet keyring belongs to another runtime binding: {0}")]
    BindingMismatch(&'static str),
    #[error("wallet keyring authentication failed")]
    AuthenticationFailed,
    #[error("wallet keyring plaintext is not canonically encoded")]
    NonCanonicalPlaintext,
    #[error("wallet keyring commitment does not match its plaintext")]
    CommitmentMismatch,
    #[error("wallet keyring rollback anchor is corrupt or unsupported")]
    InvalidRollbackAnchor,
    #[error("wallet keyring rollback anchor does not match live state: {0}")]
    RollbackAnchorMismatch(&'static str),
    #[error("wallet keyring transition used a stale anchor")]
    StaleTransitionAnchor,
    #[error("wallet keyring lifecycle updates are not unique and strictly ordered")]
    NonCanonicalLifecycleUpdates,
    #[error("wallet keyring lifecycle transition is invalid")]
    InvalidLifecycleTransition,
    #[error("wallet keyring lifecycle update refers to an unknown key")]
    UnknownLifecycleKey,
    #[error("wallet keyring decommission requires a Retired local key")]
    KeyDecommissionNotRetiredLocal,
    #[error("wallet keyring cannot sign with a watch-only or external key")]
    KeyNotLocallySignable,
    #[error("wallet keyring disabled key cannot sign")]
    DisabledKey,
    #[error("wallet keyring key id is unknown")]
    UnknownKey,
    #[error("legacy wallet import confirmation does not match the staged import")]
    LegacyConfirmationMismatch,
    #[error("secure random generation failed")]
    RandomGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyringRuntimeBinding {
    pub network_id: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
    pub genesis_hash: [u8; 32],
}

impl KeyringRuntimeBinding {
    pub fn validate(self) -> Result<(), WalletKeyringError> {
        require_nonzero(&self.network_id, "network_id")?;
        require_nonzero(&self.consensus_fingerprint, "consensus_fingerprint")?;
        require_nonzero(&self.genesis_hash, "genesis_hash")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyringAnchorV1 {
    pub binding: KeyringRuntimeBinding,
    pub instance_id: [u8; 32],
    pub generation: u64,
    pub commitment: [u8; 32],
}

impl KeyringAnchorV1 {
    /// Encodes the externally pinned rollback anchor. Its checksum detects
    /// corruption and non-canonical encoding; it is not a MAC. Authenticity
    /// comes from storing these exact bytes beyond the node's write authority.
    pub fn encode(self) -> Result<Vec<u8>, WalletKeyringError> {
        self.validate_fields()?;
        let mut bytes = Vec::with_capacity(KEYRING_ANCHOR_BYTES);
        bytes.extend_from_slice(&KEYRING_ANCHOR_MAGIC);
        bytes.extend_from_slice(&KEYRING_ANCHOR_VERSION.to_le_bytes());
        encode_binding(&mut bytes, self.binding);
        bytes.extend_from_slice(&self.instance_id);
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.commitment);
        let checksum = anchor_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        debug_assert_eq!(bytes.len(), KEYRING_ANCHOR_BYTES);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WalletKeyringError> {
        if bytes.len() != KEYRING_ANCHOR_BYTES {
            return Err(WalletKeyringError::InvalidRollbackAnchor);
        }
        let expected_checksum = anchor_checksum(&bytes[..KEYRING_ANCHOR_BYTES - 32]);
        if bytes[KEYRING_ANCHOR_BYTES - 32..] != expected_checksum {
            return Err(WalletKeyringError::InvalidRollbackAnchor);
        }
        let mut decoder = Decoder::new(&bytes[..KEYRING_ANCHOR_BYTES - 32]);
        if decoder.array::<8>()? != KEYRING_ANCHOR_MAGIC {
            return Err(WalletKeyringError::InvalidRollbackAnchor);
        }
        if decoder.u16()? != KEYRING_ANCHOR_VERSION {
            return Err(WalletKeyringError::InvalidRollbackAnchor);
        }
        let anchor = Self {
            binding: decode_binding(&mut decoder)?,
            instance_id: decoder.array()?,
            generation: decoder.u64()?,
            commitment: decoder.array()?,
        };
        decoder.finish()?;
        anchor.validate_fields()?;
        if anchor.encode()?.as_slice() != bytes {
            return Err(WalletKeyringError::InvalidRollbackAnchor);
        }
        Ok(anchor)
    }

    pub fn verify_keyring(self, keyring: &WalletKeyring) -> Result<(), WalletKeyringError> {
        verify_anchor_fields(self, keyring.anchor())
    }

    pub fn signing_protocol_anchor(self) -> crate::wallet_signing_protocol::KeyringAnchorV1 {
        crate::wallet_signing_protocol::KeyringAnchorV1 {
            instance_id: self.instance_id,
            generation: self.generation,
            commitment: self.commitment,
        }
    }

    fn validate_fields(self) -> Result<(), WalletKeyringError> {
        self.binding.validate()?;
        if is_zero(&self.instance_id) {
            return Err(WalletKeyringError::ZeroInstanceId);
        }
        if self.generation == 0 {
            return Err(WalletKeyringError::InvalidRollbackAnchor);
        }
        if is_zero(&self.commitment) {
            return Err(WalletKeyringError::InvalidRollbackAnchor);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRoles(u8);

impl KeyRoles {
    pub const DEPOSIT: Self = Self(1 << 0);
    pub const CHANGE: Self = Self(1 << 1);
    const VALID_BITS: u8 = Self::DEPOSIT.0 | Self::CHANGE.0;

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, role: Self) -> bool {
        self.0 & role.0 == role.0
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub fn from_bits(bits: u8) -> Result<Self, WalletKeyringError> {
        if bits == 0 || bits & !Self::VALID_BITS != 0 {
            return Err(WalletKeyringError::InvalidKeyRoles);
        }
        Ok(Self(bits))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycle {
    Active,
    Retired,
    Disabled,
}

impl KeyLifecycle {
    fn tag(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Retired => 2,
            Self::Disabled => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, WalletKeyringError> {
        match tag {
            1 => Ok(Self::Active),
            2 => Ok(Self::Retired),
            3 => Ok(Self::Disabled),
            _ => Err(WalletKeyringError::NonCanonicalPlaintext),
        }
    }

    fn may_transition_to(self, next: Self) -> bool {
        match self {
            Self::Active => matches!(next, Self::Active | Self::Retired | Self::Disabled),
            Self::Retired => next == Self::Retired,
            Self::Disabled => next == Self::Disabled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStorageBinding {
    Local,
    External { signer_id: SignerId },
    WatchOnly,
}

enum KeyMaterial {
    Local(Zeroizing<[u8; 32]>),
    External(SignerId),
    WatchOnly,
}

/// A key entry owns local secret material when its storage binding is local.
/// It intentionally implements neither `Debug` nor `Clone`.
pub struct WalletKeyEntry {
    key_id: WalletKeyId,
    public_key: [u8; 32],
    roles: KeyRoles,
    lifecycle: KeyLifecycle,
    material: KeyMaterial,
}

impl WalletKeyEntry {
    pub fn local(
        secret: Zeroizing<[u8; 32]>,
        roles: KeyRoles,
        lifecycle: KeyLifecycle,
    ) -> Result<Self, WalletKeyringError> {
        validate_roles(roles)?;
        let signing_key = SigningKey::from_bytes(secret.as_ref())
            .map_err(|_| WalletKeyringError::InvalidLocalSecret)?;
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes().into();
        Ok(Self {
            key_id: wallet_key_id(&public_key),
            public_key,
            roles,
            lifecycle,
            material: KeyMaterial::Local(secret),
        })
    }

    pub fn external(
        public_key: [u8; 32],
        roles: KeyRoles,
        lifecycle: KeyLifecycle,
        signer_id: SignerId,
    ) -> Result<Self, WalletKeyringError> {
        validate_roles(roles)?;
        validate_public_key(&public_key)?;
        if is_zero(&signer_id.0) {
            return Err(WalletKeyringError::ZeroSignerId);
        }
        Ok(Self {
            key_id: wallet_key_id(&public_key),
            public_key,
            roles,
            lifecycle,
            material: KeyMaterial::External(signer_id),
        })
    }

    pub fn watch_only(
        public_key: [u8; 32],
        roles: KeyRoles,
        lifecycle: KeyLifecycle,
    ) -> Result<Self, WalletKeyringError> {
        validate_roles(roles)?;
        validate_public_key(&public_key)?;
        Ok(Self {
            key_id: wallet_key_id(&public_key),
            public_key,
            roles,
            lifecycle,
            material: KeyMaterial::WatchOnly,
        })
    }

    pub fn summary(&self) -> WalletKeySummary {
        WalletKeySummary {
            key_id: self.key_id,
            public_key: self.public_key,
            roles: self.roles,
            lifecycle: self.lifecycle,
            storage: self.storage_binding(),
        }
    }

    fn storage_binding(&self) -> KeyStorageBinding {
        match &self.material {
            KeyMaterial::Local(_) => KeyStorageBinding::Local,
            KeyMaterial::External(signer_id) => KeyStorageBinding::External {
                signer_id: *signer_id,
            },
            KeyMaterial::WatchOnly => KeyStorageBinding::WatchOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletKeySummary {
    pub key_id: WalletKeyId,
    pub public_key: [u8; 32],
    pub roles: KeyRoles,
    pub lifecycle: KeyLifecycle,
    pub storage: KeyStorageBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLifecycleUpdate {
    pub key_id: WalletKeyId,
    pub lifecycle: KeyLifecycle,
}

/// Decrypted wallet state. This type intentionally implements neither `Debug`
/// nor `Clone`, preventing accidental formatting or duplication of local keys.
pub struct WalletKeyring {
    binding: KeyringRuntimeBinding,
    instance_id: [u8; 32],
    generation: u64,
    prior_commitment: [u8; 32],
    commitment: [u8; 32],
    entries: Vec<WalletKeyEntry>,
}

impl WalletKeyring {
    pub fn new_genesis(
        binding: KeyringRuntimeBinding,
        instance_id: [u8; 32],
        mut entries: Vec<WalletKeyEntry>,
    ) -> Result<Self, WalletKeyringError> {
        binding.validate()?;
        if is_zero(&instance_id) {
            return Err(WalletKeyringError::ZeroInstanceId);
        }
        entries.sort_unstable_by_key(|entry| entry.key_id);
        let mut keyring = Self {
            binding,
            instance_id,
            generation: 1,
            prior_commitment: [0; 32],
            commitment: [0; 32],
            entries,
        };
        keyring.validate_structure()?;
        keyring.recompute_commitment()?;
        Ok(keyring)
    }

    pub fn binding(&self) -> KeyringRuntimeBinding {
        self.binding
    }

    pub fn instance_id(&self) -> [u8; 32] {
        self.instance_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn prior_commitment(&self) -> [u8; 32] {
        self.prior_commitment
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub fn anchor(&self) -> KeyringAnchorV1 {
        KeyringAnchorV1 {
            binding: self.binding,
            instance_id: self.instance_id,
            generation: self.generation,
            commitment: self.commitment,
        }
    }

    pub fn summaries(&self) -> Vec<WalletKeySummary> {
        self.entries.iter().map(WalletKeyEntry::summary).collect()
    }

    pub fn key(&self, key_id: WalletKeyId) -> Option<WalletKeySummary> {
        self.find_entry(key_id).ok().map(WalletKeyEntry::summary)
    }

    pub fn active_change_key(&self) -> WalletKeySummary {
        self.entries
            .iter()
            .find(|entry| {
                entry.lifecycle == KeyLifecycle::Active && entry.roles.contains(KeyRoles::CHANGE)
            })
            .expect("validated keyring has one active change key")
            .summary()
    }

    /// Signs a 32-byte protocol digest only when the selected key is local and
    /// not disabled. Callers remain responsible for action/package policy.
    pub fn sign_local_digest(
        &self,
        key_id: WalletKeyId,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], WalletKeyringError> {
        let entry = self
            .find_entry(key_id)
            .map_err(|_| WalletKeyringError::UnknownKey)?;
        if entry.lifecycle == KeyLifecycle::Disabled {
            return Err(WalletKeyringError::DisabledKey);
        }
        let KeyMaterial::Local(secret) = &entry.material else {
            return Err(WalletKeyringError::KeyNotLocallySignable);
        };
        let signing_key = SigningKey::from_bytes(secret.as_ref())
            .map_err(|_| WalletKeyringError::InvalidLocalSecret)?;
        let signature: Signature = signing_key.sign(digest);
        Ok(signature.to_bytes())
    }

    /// Advances exactly one generation. Existing key identity, roles, public
    /// key, and signer binding cannot be edited: only an explicit irreversible
    /// lifecycle update is allowed, and additions are append-only logically.
    pub fn transition(
        mut self,
        expected_current_anchor: KeyringAnchorV1,
        lifecycle_updates: &[KeyLifecycleUpdate],
        mut additions: Vec<WalletKeyEntry>,
    ) -> Result<Self, WalletKeyringError> {
        if verify_anchor_fields(expected_current_anchor, self.anchor()).is_err() {
            return Err(WalletKeyringError::StaleTransitionAnchor);
        }
        validate_lifecycle_updates(lifecycle_updates)?;
        for update in lifecycle_updates {
            let entry = self
                .find_entry_mut(update.key_id)
                .map_err(|_| WalletKeyringError::UnknownLifecycleKey)?;
            if !entry.lifecycle.may_transition_to(update.lifecycle) {
                return Err(WalletKeyringError::InvalidLifecycleTransition);
            }
            entry.lifecycle = update.lifecycle;
        }

        additions.sort_unstable_by_key(|entry| entry.key_id);
        if !additions.is_empty() {
            let mut combined = Vec::with_capacity(
                self.entries
                    .len()
                    .checked_add(additions.len())
                    .ok_or(WalletKeyringError::InvalidKeyCount)?,
            );
            combined.append(&mut self.entries);
            combined.append(&mut additions);
            combined.sort_unstable_by_key(|entry| entry.key_id);
            self.entries = combined;
        }

        let previous_commitment = self.commitment;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(WalletKeyringError::GenerationOverflow)?;
        self.prior_commitment = previous_commitment;
        self.commitment = [0; 32];
        self.validate_structure()?;
        self.recompute_commitment()?;
        Ok(self)
    }

    /// Irreversibly removes one Retired local secret while preserving only its
    /// Disabled public metadata. This is intentionally separate from general
    /// transitions: callers must first prove that the key owns no UTXOs and
    /// atomically rotate the journal's active keyring anchor.
    pub fn decommission_retired_local_key(
        mut self,
        expected_current_anchor: KeyringAnchorV1,
        key_id: WalletKeyId,
    ) -> Result<Self, WalletKeyringError> {
        if verify_anchor_fields(expected_current_anchor, self.anchor()).is_err() {
            return Err(WalletKeyringError::StaleTransitionAnchor);
        }
        let entry = self
            .find_entry_mut(key_id)
            .map_err(|_| WalletKeyringError::UnknownLifecycleKey)?;
        if entry.lifecycle != KeyLifecycle::Retired
            || !matches!(entry.material, KeyMaterial::Local(_))
        {
            return Err(WalletKeyringError::KeyDecommissionNotRetiredLocal);
        }
        entry.lifecycle = KeyLifecycle::Disabled;
        entry.material = KeyMaterial::WatchOnly;

        let previous_commitment = self.commitment;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(WalletKeyringError::GenerationOverflow)?;
        self.prior_commitment = previous_commitment;
        self.commitment = [0; 32];
        self.validate_structure()?;
        self.recompute_commitment()?;
        Ok(self)
    }

    pub fn encode_live(&self, passphrase: &[u8]) -> Result<Vec<u8>, WalletKeyringError> {
        encode_envelope(self, passphrase, EnvelopeKind::Live, None)
    }

    pub fn encode_backup(&self, passphrase: &[u8]) -> Result<Vec<u8>, WalletKeyringError> {
        encode_envelope(self, passphrase, EnvelopeKind::Backup, None)
    }

    pub fn decode_live(
        bytes: &[u8],
        expected_binding: KeyringRuntimeBinding,
        passphrase: &[u8],
        trusted_anchor: KeyringAnchorV1,
    ) -> Result<Self, WalletKeyringError> {
        let keyring = decode_envelope(bytes, expected_binding, passphrase, EnvelopeKind::Live)?;
        trusted_anchor.verify_keyring(&keyring)?;
        Ok(keyring)
    }

    fn find_entry(&self, key_id: WalletKeyId) -> Result<&WalletKeyEntry, ()> {
        self.entries
            .binary_search_by_key(&key_id, |entry| entry.key_id)
            .map(|index| &self.entries[index])
            .map_err(|_| ())
    }

    fn find_entry_mut(&mut self, key_id: WalletKeyId) -> Result<&mut WalletKeyEntry, ()> {
        self.entries
            .binary_search_by_key(&key_id, |entry| entry.key_id)
            .map(|index| &mut self.entries[index])
            .map_err(|_| ())
    }

    fn validate_structure(&self) -> Result<(), WalletKeyringError> {
        self.binding.validate()?;
        if is_zero(&self.instance_id) {
            return Err(WalletKeyringError::ZeroInstanceId);
        }
        match (self.generation, is_zero(&self.prior_commitment)) {
            (1, true) | (2.., false) => {}
            _ => return Err(WalletKeyringError::InvalidPriorCommitment),
        }
        if self.entries.is_empty() || self.entries.len() > MAX_KEYRING_ENTRIES {
            return Err(WalletKeyringError::InvalidKeyCount);
        }
        let mut previous = None;
        let mut active_change_count = 0_usize;
        for entry in &self.entries {
            validate_entry(entry)?;
            if previous.is_some_and(|value| value >= entry.key_id) {
                return Err(WalletKeyringError::NonCanonicalKeyOrder);
            }
            previous = Some(entry.key_id);
            if entry.lifecycle == KeyLifecycle::Active && entry.roles.contains(KeyRoles::CHANGE) {
                active_change_count += 1;
                if matches!(entry.material, KeyMaterial::WatchOnly) {
                    return Err(WalletKeyringError::WatchOnlyActiveChangeKey);
                }
            }
        }
        if active_change_count != 1 {
            return Err(WalletKeyringError::ActiveChangeKeyCount);
        }
        Ok(())
    }

    fn recompute_commitment(&mut self) -> Result<(), WalletKeyringError> {
        let plaintext = encode_plaintext(self)?;
        self.commitment = plaintext_commitment(&plaintext);
        Ok(())
    }
}

/// A verified backup owns its decrypted keyring and intentionally implements
/// neither `Debug` nor `Clone`. `restore` consumes the verification result.
pub struct VerifiedKeyringBackup {
    keyring: WalletKeyring,
}

impl VerifiedKeyringBackup {
    pub fn anchor(&self) -> KeyringAnchorV1 {
        self.keyring.anchor()
    }

    pub fn summaries(&self) -> Vec<WalletKeySummary> {
        self.keyring.summaries()
    }

    pub fn restore(self) -> WalletKeyring {
        self.keyring
    }
}

pub fn verify_keyring_backup(
    bytes: &[u8],
    expected_binding: KeyringRuntimeBinding,
    passphrase: &[u8],
    trusted_anchor: KeyringAnchorV1,
) -> Result<VerifiedKeyringBackup, WalletKeyringError> {
    let keyring = decode_envelope(bytes, expected_binding, passphrase, EnvelopeKind::Backup)?;
    trusted_anchor.verify_keyring(&keyring)?;
    Ok(VerifiedKeyringBackup { keyring })
}

/// Explicit, in-memory staging for the legacy single-key format. Staging does
/// not encode, persist, replace, or delete anything. Activation consumes the
/// stage and requires its exact public confirmation digest.
pub struct LegacySingleKeyImportStaging {
    keyring: WalletKeyring,
    legacy_key: WalletKeySummary,
    confirmation_digest: [u8; 32],
}

impl LegacySingleKeyImportStaging {
    pub fn legacy_key(&self) -> WalletKeySummary {
        self.legacy_key
    }

    pub fn candidate_anchor(&self) -> KeyringAnchorV1 {
        self.keyring.anchor()
    }

    pub fn confirmation_digest(&self) -> [u8; 32] {
        self.confirmation_digest
    }

    pub fn activate(
        self,
        expected_confirmation_digest: [u8; 32],
    ) -> Result<WalletKeyring, WalletKeyringError> {
        if expected_confirmation_digest != self.confirmation_digest {
            return Err(WalletKeyringError::LegacyConfirmationMismatch);
        }
        Ok(self.keyring)
    }
}

pub fn stage_legacy_single_key_import(
    binding: KeyringRuntimeBinding,
    instance_id: [u8; 32],
    legacy_secret: Zeroizing<[u8; 32]>,
) -> Result<LegacySingleKeyImportStaging, WalletKeyringError> {
    let roles = KeyRoles::DEPOSIT.union(KeyRoles::CHANGE);
    let entry = WalletKeyEntry::local(legacy_secret, roles, KeyLifecycle::Active)?;
    let legacy_key = entry.summary();
    let keyring = WalletKeyring::new_genesis(binding, instance_id, vec![entry])?;
    let mut hasher = Hasher::new_derive_key(LEGACY_CONFIRMATION_DOMAIN);
    encode_anchor_fields(&mut hasher, keyring.anchor());
    hasher.update(&legacy_key.key_id.0);
    hasher.update(&legacy_key.public_key);
    hasher.update(&[legacy_key.roles.bits(), legacy_key.lifecycle.tag()]);
    let confirmation_digest = *hasher.finalize().as_bytes();
    Ok(LegacySingleKeyImportStaging {
        keyring,
        legacy_key,
        confirmation_digest,
    })
}

#[derive(Clone, Copy)]
enum EnvelopeKind {
    Live,
    Backup,
}

impl EnvelopeKind {
    fn magic(self) -> [u8; 8] {
        match self {
            Self::Live => KEYRING_STORAGE_MAGIC,
            Self::Backup => KEYRING_BACKUP_MAGIC,
        }
    }
}

#[derive(Clone, Copy)]
struct EnvelopeHeader {
    binding: KeyringRuntimeBinding,
    instance_id: [u8; 32],
    generation: u64,
    prior_commitment: [u8; 32],
    commitment: [u8; 32],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext_bytes: u32,
}

fn encode_envelope(
    keyring: &WalletKeyring,
    passphrase: &[u8],
    kind: EnvelopeKind,
    deterministic_randomness: Option<([u8; SALT_BYTES], [u8; NONCE_BYTES])>,
) -> Result<Vec<u8>, WalletKeyringError> {
    validate_passphrase(passphrase)?;
    keyring.validate_structure()?;
    let plaintext = encode_plaintext(keyring)?;
    if plaintext.len() > MAX_KEYRING_PLAINTEXT_BYTES {
        return Err(WalletKeyringError::PlaintextTooLarge);
    }
    let plaintext_commitment = plaintext_commitment(&plaintext);
    if plaintext_commitment != keyring.commitment {
        return Err(WalletKeyringError::CommitmentMismatch);
    }
    let (salt, nonce) = match deterministic_randomness {
        Some(values) => values,
        None => {
            let mut salt = [0_u8; SALT_BYTES];
            let mut nonce = [0_u8; NONCE_BYTES];
            getrandom::fill(&mut salt).map_err(|_| WalletKeyringError::RandomGeneration)?;
            getrandom::fill(&mut nonce).map_err(|_| WalletKeyringError::RandomGeneration)?;
            (salt, nonce)
        }
    };
    let ciphertext_bytes = plaintext
        .len()
        .checked_add(TAG_BYTES)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(WalletKeyringError::PlaintextTooLarge)?;
    let header = EnvelopeHeader {
        binding: keyring.binding,
        instance_id: keyring.instance_id,
        generation: keyring.generation,
        prior_commitment: keyring.prior_commitment,
        commitment: keyring.commitment,
        salt,
        nonce,
        ciphertext_bytes,
    };
    let header_bytes = encode_envelope_header(header, kind);
    let encryption_key = derive_encryption_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*encryption_key).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| WalletKeyringError::AuthenticationFailed)?;
    if ciphertext.len() != ciphertext_bytes as usize {
        return Err(WalletKeyringError::InvalidEnvelopeLength);
    }
    let total = header_bytes
        .len()
        .checked_add(ciphertext.len())
        .ok_or(WalletKeyringError::EnvelopeTooLarge)?;
    if total > MAX_KEYRING_ENVELOPE_BYTES {
        return Err(WalletKeyringError::EnvelopeTooLarge);
    }
    let mut envelope = Vec::with_capacity(total);
    envelope.extend_from_slice(&header_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decode_envelope(
    bytes: &[u8],
    expected_binding: KeyringRuntimeBinding,
    passphrase: &[u8],
    kind: EnvelopeKind,
) -> Result<WalletKeyring, WalletKeyringError> {
    validate_passphrase(passphrase)?;
    expected_binding.validate()?;
    if bytes.len() > MAX_KEYRING_ENVELOPE_BYTES {
        return Err(WalletKeyringError::EnvelopeTooLarge);
    }
    if bytes.len() < ENVELOPE_HEADER_BYTES + TAG_BYTES {
        return Err(WalletKeyringError::Truncated);
    }
    let header = decode_envelope_header(&bytes[..ENVELOPE_HEADER_BYTES], kind)?;
    verify_binding(expected_binding, header.binding)?;
    let ciphertext_bytes = usize::try_from(header.ciphertext_bytes)
        .map_err(|_| WalletKeyringError::InvalidEnvelopeLength)?;
    if !(TAG_BYTES..=MAX_KEYRING_PLAINTEXT_BYTES + TAG_BYTES).contains(&ciphertext_bytes) {
        return Err(WalletKeyringError::InvalidEnvelopeLength);
    }
    let expected_total = ENVELOPE_HEADER_BYTES
        .checked_add(ciphertext_bytes)
        .ok_or(WalletKeyringError::InvalidEnvelopeLength)?;
    match bytes.len().cmp(&expected_total) {
        Ordering::Less => return Err(WalletKeyringError::Truncated),
        Ordering::Greater => return Err(WalletKeyringError::TrailingBytes),
        Ordering::Equal => {}
    }
    let decryption_key = derive_encryption_key(passphrase, &header.salt)?;
    let cipher = XChaCha20Poly1305::new((&*decryption_key).into());
    let plaintext = cipher
        .decrypt(
            &XNonce::from(header.nonce),
            Payload {
                msg: &bytes[ENVELOPE_HEADER_BYTES..],
                aad: &bytes[..ENVELOPE_HEADER_BYTES],
            },
        )
        .map_err(|_| WalletKeyringError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    if plaintext.len() > MAX_KEYRING_PLAINTEXT_BYTES {
        return Err(WalletKeyringError::PlaintextTooLarge);
    }
    if plaintext_commitment(&plaintext) != header.commitment {
        return Err(WalletKeyringError::CommitmentMismatch);
    }
    let keyring = decode_plaintext(&plaintext)?;
    verify_binding(header.binding, keyring.binding)?;
    if keyring.instance_id != header.instance_id {
        return Err(WalletKeyringError::CommitmentMismatch);
    }
    if keyring.generation != header.generation
        || keyring.prior_commitment != header.prior_commitment
        || keyring.commitment != header.commitment
    {
        return Err(WalletKeyringError::CommitmentMismatch);
    }
    Ok(keyring)
}

fn encode_envelope_header(header: EnvelopeHeader, kind: EnvelopeKind) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ENVELOPE_HEADER_BYTES);
    bytes.extend_from_slice(&kind.magic());
    bytes.extend_from_slice(&KEYRING_STORAGE_VERSION.to_le_bytes());
    bytes.push(KDF_ARGON2ID);
    bytes.push(CIPHER_XCHACHA20_POLY1305);
    bytes.extend_from_slice(&ARGON2_MEMORY_KIB.to_le_bytes());
    bytes.extend_from_slice(&ARGON2_ITERATIONS.to_le_bytes());
    bytes.extend_from_slice(&ARGON2_PARALLELISM.to_le_bytes());
    bytes.extend_from_slice(&header.salt);
    bytes.extend_from_slice(&header.nonce);
    bytes.extend_from_slice(&header.ciphertext_bytes.to_le_bytes());
    encode_binding(&mut bytes, header.binding);
    bytes.extend_from_slice(&header.instance_id);
    bytes.extend_from_slice(&header.generation.to_le_bytes());
    bytes.extend_from_slice(&header.prior_commitment);
    bytes.extend_from_slice(&header.commitment);
    debug_assert_eq!(bytes.len(), ENVELOPE_HEADER_BYTES);
    bytes
}

fn decode_envelope_header(
    bytes: &[u8],
    kind: EnvelopeKind,
) -> Result<EnvelopeHeader, WalletKeyringError> {
    if bytes.len() != ENVELOPE_HEADER_BYTES {
        return Err(WalletKeyringError::Truncated);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.array::<8>()? != kind.magic() {
        return Err(WalletKeyringError::InvalidMagic);
    }
    let version = decoder.u16()?;
    if version != KEYRING_STORAGE_VERSION {
        return Err(WalletKeyringError::UnsupportedVersion(version));
    }
    if decoder.u8()? != KDF_ARGON2ID || decoder.u8()? != CIPHER_XCHACHA20_POLY1305 {
        return Err(WalletKeyringError::UnsupportedCryptography);
    }
    if decoder.u32()? != ARGON2_MEMORY_KIB
        || decoder.u32()? != ARGON2_ITERATIONS
        || decoder.u32()? != ARGON2_PARALLELISM
    {
        return Err(WalletKeyringError::NonCanonicalCryptography);
    }
    let header = EnvelopeHeader {
        salt: decoder.array()?,
        nonce: decoder.array()?,
        ciphertext_bytes: decoder.u32()?,
        binding: decode_binding(&mut decoder)?,
        instance_id: decoder.array()?,
        generation: decoder.u64()?,
        prior_commitment: decoder.array()?,
        commitment: decoder.array()?,
    };
    decoder.finish()?;
    header.binding.validate()?;
    if is_zero(&header.instance_id) || is_zero(&header.commitment) {
        return Err(WalletKeyringError::NonCanonicalPlaintext);
    }
    match (header.generation, is_zero(&header.prior_commitment)) {
        (1, true) | (2.., false) => Ok(header),
        _ => Err(WalletKeyringError::InvalidPriorCommitment),
    }
}

fn encode_plaintext(keyring: &WalletKeyring) -> Result<Zeroizing<Vec<u8>>, WalletKeyringError> {
    keyring.validate_structure()?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        PAYLOAD_FIXED_BYTES + keyring.entries.len() * 100,
    ));
    bytes.extend_from_slice(&KEYRING_PAYLOAD_MAGIC);
    bytes.extend_from_slice(&KEYRING_STORAGE_VERSION.to_le_bytes());
    encode_binding(&mut bytes, keyring.binding);
    bytes.extend_from_slice(&keyring.instance_id);
    bytes.extend_from_slice(&keyring.generation.to_le_bytes());
    bytes.extend_from_slice(&keyring.prior_commitment);
    let count =
        u32::try_from(keyring.entries.len()).map_err(|_| WalletKeyringError::InvalidKeyCount)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for entry in &keyring.entries {
        encode_entry(&mut bytes, entry);
    }
    if bytes.len() > MAX_KEYRING_PLAINTEXT_BYTES {
        return Err(WalletKeyringError::PlaintextTooLarge);
    }
    Ok(bytes)
}

fn decode_plaintext(bytes: &[u8]) -> Result<WalletKeyring, WalletKeyringError> {
    if bytes.len() > MAX_KEYRING_PLAINTEXT_BYTES {
        return Err(WalletKeyringError::PlaintextTooLarge);
    }
    if bytes.len() < PAYLOAD_FIXED_BYTES {
        return Err(WalletKeyringError::Truncated);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.array::<8>()? != KEYRING_PAYLOAD_MAGIC {
        return Err(WalletKeyringError::NonCanonicalPlaintext);
    }
    if decoder.u16()? != KEYRING_STORAGE_VERSION {
        return Err(WalletKeyringError::NonCanonicalPlaintext);
    }
    let binding = decode_binding(&mut decoder)?;
    let instance_id = decoder.array()?;
    let generation = decoder.u64()?;
    let prior_commitment = decoder.array()?;
    let count = usize::try_from(decoder.u32()?).map_err(|_| WalletKeyringError::InvalidKeyCount)?;
    if count == 0 || count > MAX_KEYRING_ENTRIES {
        return Err(WalletKeyringError::InvalidKeyCount);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(decode_entry(&mut decoder)?);
    }
    decoder.finish()?;
    let commitment = plaintext_commitment(bytes);
    let keyring = WalletKeyring {
        binding,
        instance_id,
        generation,
        prior_commitment,
        commitment,
        entries,
    };
    keyring.validate_structure()?;
    if encode_plaintext(&keyring)?.as_slice() != bytes {
        return Err(WalletKeyringError::NonCanonicalPlaintext);
    }
    Ok(keyring)
}

fn encode_entry(bytes: &mut Vec<u8>, entry: &WalletKeyEntry) {
    bytes.extend_from_slice(&entry.key_id.0);
    bytes.extend_from_slice(&entry.public_key);
    bytes.push(entry.roles.bits());
    bytes.push(entry.lifecycle.tag());
    match &entry.material {
        KeyMaterial::Local(secret) => {
            bytes.push(LOCAL_STORAGE_TAG);
            bytes.push(0);
            bytes.extend_from_slice(secret.as_ref());
        }
        KeyMaterial::External(signer_id) => {
            bytes.push(EXTERNAL_STORAGE_TAG);
            bytes.push(0);
            bytes.extend_from_slice(&signer_id.0);
        }
        KeyMaterial::WatchOnly => {
            bytes.push(WATCH_ONLY_STORAGE_TAG);
            bytes.push(0);
        }
    }
}

fn decode_entry(decoder: &mut Decoder<'_>) -> Result<WalletKeyEntry, WalletKeyringError> {
    let encoded_key_id = WalletKeyId(decoder.array()?);
    let public_key = decoder.array()?;
    let roles = KeyRoles::from_bits(decoder.u8()?)?;
    let lifecycle = KeyLifecycle::from_tag(decoder.u8()?)?;
    let storage_tag = decoder.u8()?;
    if decoder.u8()? != 0 {
        return Err(WalletKeyringError::ReservedByte);
    }
    let entry = match storage_tag {
        LOCAL_STORAGE_TAG => {
            let secret = Zeroizing::new(decoder.array()?);
            let signing_key = SigningKey::from_bytes(secret.as_ref())
                .map_err(|_| WalletKeyringError::InvalidLocalSecret)?;
            let actual_public_key: [u8; 32] = signing_key.verifying_key().to_bytes().into();
            if actual_public_key != public_key {
                return Err(WalletKeyringError::LocalSecretMismatch);
            }
            WalletKeyEntry {
                key_id: encoded_key_id,
                public_key,
                roles,
                lifecycle,
                material: KeyMaterial::Local(secret),
            }
        }
        EXTERNAL_STORAGE_TAG => {
            let signer_id = SignerId(decoder.array()?);
            WalletKeyEntry {
                key_id: encoded_key_id,
                public_key,
                roles,
                lifecycle,
                material: KeyMaterial::External(signer_id),
            }
        }
        WATCH_ONLY_STORAGE_TAG => WalletKeyEntry {
            key_id: encoded_key_id,
            public_key,
            roles,
            lifecycle,
            material: KeyMaterial::WatchOnly,
        },
        _ => return Err(WalletKeyringError::NonCanonicalPlaintext),
    };
    validate_entry(&entry)?;
    Ok(entry)
}

fn validate_entry(entry: &WalletKeyEntry) -> Result<(), WalletKeyringError> {
    validate_roles(entry.roles)?;
    validate_public_key(&entry.public_key)?;
    if wallet_key_id(&entry.public_key) != entry.key_id {
        return Err(WalletKeyringError::KeyIdMismatch);
    }
    match &entry.material {
        KeyMaterial::Local(secret) => {
            let key = SigningKey::from_bytes(secret.as_ref())
                .map_err(|_| WalletKeyringError::InvalidLocalSecret)?;
            let public_key: [u8; 32] = key.verifying_key().to_bytes().into();
            if public_key != entry.public_key {
                return Err(WalletKeyringError::LocalSecretMismatch);
            }
        }
        KeyMaterial::External(signer_id) if is_zero(&signer_id.0) => {
            return Err(WalletKeyringError::ZeroSignerId);
        }
        KeyMaterial::External(_) | KeyMaterial::WatchOnly => {}
    }
    Ok(())
}

fn validate_roles(roles: KeyRoles) -> Result<(), WalletKeyringError> {
    KeyRoles::from_bits(roles.bits()).map(|_| ())
}

fn validate_public_key(public_key: &[u8; 32]) -> Result<(), WalletKeyringError> {
    VerifyingKey::from_bytes(public_key)
        .map(|_| ())
        .map_err(|_| WalletKeyringError::InvalidPublicKey)
}

fn validate_lifecycle_updates(updates: &[KeyLifecycleUpdate]) -> Result<(), WalletKeyringError> {
    let mut previous = None;
    for update in updates {
        if previous.is_some_and(|value| value >= update.key_id) {
            return Err(WalletKeyringError::NonCanonicalLifecycleUpdates);
        }
        previous = Some(update.key_id);
    }
    Ok(())
}

fn encode_binding(bytes: &mut Vec<u8>, binding: KeyringRuntimeBinding) {
    bytes.extend_from_slice(&binding.network_id);
    bytes.extend_from_slice(&binding.consensus_fingerprint);
    bytes.extend_from_slice(&binding.genesis_hash);
}

fn decode_binding(decoder: &mut Decoder<'_>) -> Result<KeyringRuntimeBinding, WalletKeyringError> {
    Ok(KeyringRuntimeBinding {
        network_id: decoder.array()?,
        consensus_fingerprint: decoder.array()?,
        genesis_hash: decoder.array()?,
    })
}

fn verify_binding(
    expected: KeyringRuntimeBinding,
    actual: KeyringRuntimeBinding,
) -> Result<(), WalletKeyringError> {
    if actual.network_id != expected.network_id {
        return Err(WalletKeyringError::BindingMismatch("network_id"));
    }
    if actual.consensus_fingerprint != expected.consensus_fingerprint {
        return Err(WalletKeyringError::BindingMismatch("consensus_fingerprint"));
    }
    if actual.genesis_hash != expected.genesis_hash {
        return Err(WalletKeyringError::BindingMismatch("genesis_hash"));
    }
    Ok(())
}

fn verify_anchor_fields(
    expected: KeyringAnchorV1,
    actual: KeyringAnchorV1,
) -> Result<(), WalletKeyringError> {
    verify_binding(expected.binding, actual.binding)
        .map_err(|_| WalletKeyringError::RollbackAnchorMismatch("runtime binding"))?;
    if expected.instance_id != actual.instance_id {
        return Err(WalletKeyringError::RollbackAnchorMismatch("instance_id"));
    }
    if expected.generation != actual.generation {
        return Err(WalletKeyringError::RollbackAnchorMismatch("generation"));
    }
    if expected.commitment != actual.commitment {
        return Err(WalletKeyringError::RollbackAnchorMismatch("commitment"));
    }
    Ok(())
}

fn encode_anchor_fields(hasher: &mut Hasher, anchor: KeyringAnchorV1) {
    hasher.update(&anchor.binding.network_id);
    hasher.update(&anchor.binding.consensus_fingerprint);
    hasher.update(&anchor.binding.genesis_hash);
    hasher.update(&anchor.instance_id);
    hasher.update(&anchor.generation.to_le_bytes());
    hasher.update(&anchor.commitment);
}

fn plaintext_commitment(plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(COMMITMENT_DOMAIN);
    hasher.update(plaintext);
    *hasher.finalize().as_bytes()
}

fn anchor_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(ANCHOR_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), WalletKeyringError> {
    if (MINIMUM_KEYRING_PASSPHRASE_BYTES..=MAXIMUM_KEYRING_PASSPHRASE_BYTES)
        .contains(&passphrase.len())
    {
        Ok(())
    } else {
        Err(WalletKeyringError::InvalidPassphrase)
    }
}

fn derive_encryption_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; 32]>, WalletKeyringError> {
    validate_passphrase(passphrase)?;
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|_| WalletKeyringError::NonCanonicalCryptography)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| WalletKeyringError::InvalidPassphrase)?;
    Ok(key)
}

fn require_nonzero(bytes: &[u8; 32], field: &'static str) -> Result<(), WalletKeyringError> {
    if is_zero(bytes) {
        Err(WalletKeyringError::ZeroBinding(field))
    } else {
        Ok(())
    }
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], WalletKeyringError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(WalletKeyringError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(WalletKeyringError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WalletKeyringError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WalletKeyringError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, WalletKeyringError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, WalletKeyringError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, WalletKeyringError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WalletKeyringError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), WalletKeyringError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WalletKeyringError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use k256::schnorr::signature::Verifier;

    use super::*;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    fn binding() -> KeyringRuntimeBinding {
        KeyringRuntimeBinding {
            network_id: [0x11; 32],
            consensus_fingerprint: [0x22; 32],
            genesis_hash: [0x33; 32],
        }
    }

    fn secret(marker: u8) -> Zeroizing<[u8; 32]> {
        Zeroizing::new([marker; 32])
    }

    fn public_key(marker: u8) -> [u8; 32] {
        let key = SigningKey::from_bytes(&[marker; 32]).unwrap();
        key.verifying_key().to_bytes().into()
    }

    fn local_entry(marker: u8, roles: KeyRoles, lifecycle: KeyLifecycle) -> WalletKeyEntry {
        WalletKeyEntry::local(secret(marker), roles, lifecycle).unwrap()
    }

    fn fixture() -> WalletKeyring {
        WalletKeyring::new_genesis(
            binding(),
            [0x44; 32],
            vec![
                WalletKeyEntry::watch_only(public_key(3), KeyRoles::DEPOSIT, KeyLifecycle::Retired)
                    .unwrap(),
                WalletKeyEntry::external(
                    public_key(2),
                    KeyRoles::DEPOSIT,
                    KeyLifecycle::Active,
                    SignerId([0x92; 32]),
                )
                .unwrap(),
                local_entry(
                    1,
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Active,
                ),
            ],
        )
        .unwrap()
    }

    fn deterministic_envelope(keyring: &WalletKeyring, kind: EnvelopeKind) -> Vec<u8> {
        encode_envelope(
            keyring,
            PASSPHRASE,
            kind,
            Some(([0x55; SALT_BYTES], [0x66; NONCE_BYTES])),
        )
        .unwrap()
    }

    #[test]
    fn canonical_live_envelope_and_anchor_round_trip() {
        let keyring = fixture();
        let anchor = keyring.anchor();
        let envelope = deterministic_envelope(&keyring, EnvelopeKind::Live);
        let decoded = WalletKeyring::decode_live(&envelope, binding(), PASSPHRASE, anchor).unwrap();
        assert_eq!(decoded.anchor(), anchor);
        assert_eq!(decoded.summaries(), keyring.summaries());
        assert_eq!(&envelope[..8], &KEYRING_STORAGE_MAGIC);

        let anchor_bytes = anchor.encode().unwrap();
        assert_eq!(anchor_bytes.len(), KEYRING_ANCHOR_BYTES);
        assert_eq!(KeyringAnchorV1::decode(&anchor_bytes).unwrap(), anchor);
        assert_eq!(anchor.encode().unwrap(), anchor_bytes);
        assert_eq!(
            anchor.signing_protocol_anchor(),
            crate::wallet_signing_protocol::KeyringAnchorV1 {
                instance_id: anchor.instance_id,
                generation: anchor.generation,
                commitment: anchor.commitment,
            }
        );
    }

    #[test]
    fn input_order_is_normalized_without_exposing_plaintext_secrets() {
        let first = WalletKeyring::new_genesis(
            binding(),
            [0x44; 32],
            vec![
                local_entry(1, KeyRoles::CHANGE, KeyLifecycle::Active),
                WalletKeyEntry::external(
                    public_key(2),
                    KeyRoles::DEPOSIT,
                    KeyLifecycle::Active,
                    SignerId([0x92; 32]),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let second = WalletKeyring::new_genesis(
            binding(),
            [0x44; 32],
            vec![
                WalletKeyEntry::external(
                    public_key(2),
                    KeyRoles::DEPOSIT,
                    KeyLifecycle::Active,
                    SignerId([0x92; 32]),
                )
                .unwrap(),
                local_entry(1, KeyRoles::CHANGE, KeyLifecycle::Active),
            ],
        )
        .unwrap();
        assert_eq!(first.anchor(), second.anchor());

        let envelope = deterministic_envelope(&first, EnvelopeKind::Live);
        assert!(!envelope.windows(32).any(|window| window == [1_u8; 32]));
    }

    #[test]
    fn canonical_commitment_anchor_and_envelope_have_stable_goldens() {
        let keyring = fixture();
        let anchor_bytes = keyring.anchor().encode().unwrap();
        let live = deterministic_envelope(&keyring, EnvelopeKind::Live);
        assert_eq!(
            hex::encode(keyring.commitment()),
            "b83cc54470993f6f4525f4d8c1b22b81d5929a1277f834fda9584948807fd954"
        );
        assert_eq!(
            hex::encode(&anchor_bytes[KEYRING_ANCHOR_BYTES - 32..]),
            "54e5892695ae8780d67ee471be1655f83a649b2c3c0e73c1a04e66461c1759d5"
        );
        assert_eq!(
            hex::encode(blake3::hash(&live).as_bytes()),
            "72b28860d5c4816336915f9522ea9fc42f17adedec24728f803c2b1c40c6473d"
        );
        assert_eq!(
            &live[..24],
            b"CMFDKRG1\x01\0\x01\x01\0\0\x01\0\x03\0\0\0\x01\0\0\0"
        );
    }

    #[test]
    fn backup_is_domain_separated_verified_and_consumed_for_restore() {
        let keyring = fixture();
        let anchor = keyring.anchor();
        let backup = deterministic_envelope(&keyring, EnvelopeKind::Backup);
        assert_eq!(&backup[..8], &KEYRING_BACKUP_MAGIC);
        assert!(matches!(
            WalletKeyring::decode_live(&backup, binding(), PASSPHRASE, anchor),
            Err(WalletKeyringError::InvalidMagic)
        ));

        let verified = verify_keyring_backup(&backup, binding(), PASSPHRASE, anchor).unwrap();
        assert_eq!(verified.anchor(), anchor);
        assert_eq!(verified.summaries(), keyring.summaries());
        let restored = verified.restore();
        assert_eq!(restored.anchor(), anchor);

        let live = restored.encode_live(PASSPHRASE).unwrap();
        let reopened = WalletKeyring::decode_live(&live, binding(), PASSPHRASE, anchor).unwrap();
        assert_eq!(reopened.anchor(), anchor);
    }

    #[test]
    fn authentication_binding_anchor_and_length_fail_closed() {
        let keyring = fixture();
        let anchor = keyring.anchor();
        let envelope = deterministic_envelope(&keyring, EnvelopeKind::Live);

        assert!(matches!(
            WalletKeyring::decode_live(
                &envelope,
                binding(),
                b"wrong passphrase but long enough",
                anchor,
            ),
            Err(WalletKeyringError::AuthenticationFailed)
        ));

        let mut wrong_binding = binding();
        wrong_binding.genesis_hash[0] ^= 1;
        assert!(matches!(
            WalletKeyring::decode_live(&envelope, wrong_binding, PASSPHRASE, anchor),
            Err(WalletKeyringError::BindingMismatch("genesis_hash"))
        ));

        let mut wrong_anchor = anchor;
        wrong_anchor.commitment[0] ^= 1;
        assert!(matches!(
            WalletKeyring::decode_live(&envelope, binding(), PASSPHRASE, wrong_anchor),
            Err(WalletKeyringError::RollbackAnchorMismatch("commitment"))
        ));

        let mut tampered = envelope.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            WalletKeyring::decode_live(&tampered, binding(), PASSPHRASE, anchor),
            Err(WalletKeyringError::AuthenticationFailed)
        ));

        assert!(matches!(
            WalletKeyring::decode_live(
                &envelope[..envelope.len() - 1],
                binding(),
                PASSPHRASE,
                anchor,
            ),
            Err(WalletKeyringError::Truncated)
        ));
        let mut trailing = envelope;
        trailing.push(0);
        assert!(matches!(
            WalletKeyring::decode_live(&trailing, binding(), PASSPHRASE, anchor),
            Err(WalletKeyringError::TrailingBytes)
        ));
    }

    #[test]
    fn exactly_one_spendable_active_change_key_is_required() {
        assert!(matches!(
            WalletKeyring::new_genesis(
                binding(),
                [0x44; 32],
                vec![local_entry(1, KeyRoles::DEPOSIT, KeyLifecycle::Active,)],
            ),
            Err(WalletKeyringError::ActiveChangeKeyCount)
        ));

        assert!(matches!(
            WalletKeyring::new_genesis(
                binding(),
                [0x44; 32],
                vec![
                    local_entry(1, KeyRoles::CHANGE, KeyLifecycle::Active),
                    local_entry(2, KeyRoles::CHANGE, KeyLifecycle::Active),
                ],
            ),
            Err(WalletKeyringError::ActiveChangeKeyCount)
        ));

        assert!(matches!(
            WalletKeyring::new_genesis(
                binding(),
                [0x44; 32],
                vec![
                    WalletKeyEntry::watch_only(
                        public_key(1),
                        KeyRoles::CHANGE,
                        KeyLifecycle::Active,
                    )
                    .unwrap()
                ],
            ),
            Err(WalletKeyringError::WatchOnlyActiveChangeKey)
        ));
    }

    #[test]
    fn transition_rotates_change_atomically_and_chains_commitments() {
        let keyring = fixture();
        let prior_anchor = keyring.anchor();
        let old_change = keyring.active_change_key();
        let new_change = local_entry(4, KeyRoles::CHANGE, KeyLifecycle::Active);
        let new_change_id = new_change.key_id;
        let next = keyring
            .transition(
                prior_anchor,
                &[KeyLifecycleUpdate {
                    key_id: old_change.key_id,
                    lifecycle: KeyLifecycle::Retired,
                }],
                vec![new_change],
            )
            .unwrap();

        assert_eq!(next.generation(), 2);
        assert_eq!(next.prior_commitment(), prior_anchor.commitment);
        assert_ne!(next.commitment(), prior_anchor.commitment);
        assert_eq!(next.active_change_key().key_id, new_change_id);
        assert_eq!(
            next.key(old_change.key_id).unwrap().lifecycle,
            KeyLifecycle::Retired
        );
        assert!(matches!(
            next.transition(prior_anchor, &[], Vec::new()),
            Err(WalletKeyringError::StaleTransitionAnchor)
        ));
    }

    #[test]
    fn transition_rejects_duplicates_unknown_keys_and_lifecycle_reversal() {
        let keyring = fixture();
        let anchor = keyring.anchor();
        let old_change = keyring.active_change_key();
        assert!(matches!(
            keyring.transition(
                anchor,
                &[
                    KeyLifecycleUpdate {
                        key_id: old_change.key_id,
                        lifecycle: KeyLifecycle::Retired,
                    },
                    KeyLifecycleUpdate {
                        key_id: old_change.key_id,
                        lifecycle: KeyLifecycle::Retired,
                    },
                ],
                vec![local_entry(4, KeyRoles::CHANGE, KeyLifecycle::Active)],
            ),
            Err(WalletKeyringError::NonCanonicalLifecycleUpdates)
        ));

        let keyring = fixture();
        let anchor = keyring.anchor();
        assert!(matches!(
            keyring.transition(
                anchor,
                &[KeyLifecycleUpdate {
                    key_id: WalletKeyId([0xfe; 32]),
                    lifecycle: KeyLifecycle::Retired,
                }],
                Vec::new(),
            ),
            Err(WalletKeyringError::UnknownLifecycleKey)
        ));

        let retired_change = local_entry(1, KeyRoles::CHANGE, KeyLifecycle::Retired);
        let retired_id = retired_change.key_id;
        let keyring = WalletKeyring::new_genesis(
            binding(),
            [0x44; 32],
            vec![
                retired_change,
                local_entry(2, KeyRoles::CHANGE, KeyLifecycle::Active),
            ],
        )
        .unwrap();
        let anchor = keyring.anchor();
        assert!(matches!(
            keyring.transition(
                anchor,
                &[KeyLifecycleUpdate {
                    key_id: retired_id,
                    lifecycle: KeyLifecycle::Active,
                }],
                Vec::new(),
            ),
            Err(WalletKeyringError::InvalidLifecycleTransition)
        ));
    }

    #[test]
    fn retired_local_key_can_be_irreversibly_decommissioned_to_watch_only() {
        let retired_change = local_entry(1, KeyRoles::CHANGE, KeyLifecycle::Retired);
        let retired_id = retired_change.key_id;
        let keyring = WalletKeyring::new_genesis(
            binding(),
            [0x44; 32],
            vec![
                retired_change,
                local_entry(2, KeyRoles::CHANGE, KeyLifecycle::Active),
            ],
        )
        .unwrap();
        let anchor = keyring.anchor();
        let disabled = keyring
            .decommission_retired_local_key(anchor, retired_id)
            .unwrap();
        let summary = disabled.key(retired_id).unwrap();
        assert_eq!(summary.lifecycle, KeyLifecycle::Disabled);
        assert_eq!(summary.storage, KeyStorageBinding::WatchOnly);
        assert!(matches!(
            disabled.sign_local_digest(retired_id, &[0x55; 32]),
            Err(WalletKeyringError::DisabledKey)
        ));
        let anchor = disabled.anchor();
        assert!(matches!(
            disabled.transition(
                anchor,
                &[KeyLifecycleUpdate {
                    key_id: retired_id,
                    lifecycle: KeyLifecycle::Retired,
                }],
                Vec::new(),
            ),
            Err(WalletKeyringError::InvalidLifecycleTransition)
        ));
    }

    #[test]
    fn transition_cannot_duplicate_or_modify_existing_identity() {
        let keyring = fixture();
        let anchor = keyring.anchor();
        assert!(matches!(
            keyring.transition(
                anchor,
                &[],
                vec![local_entry(1, KeyRoles::DEPOSIT, KeyLifecycle::Active,)],
            ),
            Err(WalletKeyringError::NonCanonicalKeyOrder)
        ));
    }

    #[test]
    fn local_signing_is_scoped_and_disabled_external_or_watch_keys_fail() {
        let keyring = fixture();
        let digest = [0xa5; 32];
        let local = keyring.active_change_key();
        let signature_bytes = keyring.sign_local_digest(local.key_id, &digest).unwrap();
        let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&local.public_key).unwrap();
        verifying_key.verify(&digest, &signature).unwrap();

        let external = keyring
            .summaries()
            .into_iter()
            .find(|entry| matches!(entry.storage, KeyStorageBinding::External { .. }))
            .unwrap();
        assert!(matches!(
            keyring.sign_local_digest(external.key_id, &digest),
            Err(WalletKeyringError::KeyNotLocallySignable)
        ));
        let watch = keyring
            .summaries()
            .into_iter()
            .find(|entry| entry.storage == KeyStorageBinding::WatchOnly)
            .unwrap();
        assert!(matches!(
            keyring.sign_local_digest(watch.key_id, &digest),
            Err(WalletKeyringError::KeyNotLocallySignable)
        ));

        let disabled = WalletKeyring::new_genesis(
            binding(),
            [0x44; 32],
            vec![
                local_entry(1, KeyRoles::DEPOSIT, KeyLifecycle::Disabled),
                local_entry(2, KeyRoles::CHANGE, KeyLifecycle::Active),
            ],
        )
        .unwrap();
        let disabled_key = disabled
            .summaries()
            .into_iter()
            .find(|entry| entry.lifecycle == KeyLifecycle::Disabled)
            .unwrap();
        assert!(matches!(
            disabled.sign_local_digest(disabled_key.key_id, &digest),
            Err(WalletKeyringError::DisabledKey)
        ));
    }

    #[test]
    fn legacy_import_requires_exact_explicit_confirmation() {
        let staging = stage_legacy_single_key_import(binding(), [0x77; 32], secret(7)).unwrap();
        let confirmation = staging.confirmation_digest();
        let legacy = staging.legacy_key();
        assert!(legacy.roles.contains(KeyRoles::DEPOSIT));
        assert!(legacy.roles.contains(KeyRoles::CHANGE));
        let keyring = staging.activate(confirmation).unwrap();
        assert_eq!(keyring.generation(), 1);
        assert_eq!(keyring.active_change_key().key_id, legacy.key_id);

        let staging = stage_legacy_single_key_import(binding(), [0x77; 32], secret(7)).unwrap();
        let mut wrong = staging.confirmation_digest();
        wrong[0] ^= 1;
        assert!(matches!(
            staging.activate(wrong),
            Err(WalletKeyringError::LegacyConfirmationMismatch)
        ));
    }

    #[test]
    fn plaintext_decoder_rejects_order_id_reserved_and_trailing_tampering() {
        let keyring = fixture();
        let plaintext = encode_plaintext(&keyring).unwrap();
        let first_entry_offset = PAYLOAD_FIXED_BYTES;

        let mut wrong_id = plaintext.clone();
        wrong_id[first_entry_offset] ^= 1;
        assert!(matches!(
            decode_plaintext(&wrong_id),
            Err(WalletKeyringError::KeyIdMismatch)
        ));

        let mut reserved = plaintext.clone();
        reserved[first_entry_offset + 67] = 1;
        assert!(matches!(
            decode_plaintext(&reserved),
            Err(WalletKeyringError::ReservedByte)
        ));

        let mut trailing = plaintext;
        trailing.push(0);
        assert!(matches!(
            decode_plaintext(&trailing),
            Err(WalletKeyringError::TrailingBytes)
        ));
    }

    #[test]
    fn count_and_crypto_parameter_bounds_are_checked_before_allocation_or_kdf() {
        let keyring = fixture();
        let mut plaintext = encode_plaintext(&keyring).unwrap();
        let count_offset = PAYLOAD_FIXED_BYTES - 4;
        plaintext[count_offset..count_offset + 4]
            .copy_from_slice(&((MAX_KEYRING_ENTRIES as u32) + 1).to_le_bytes());
        assert!(matches!(
            decode_plaintext(&plaintext),
            Err(WalletKeyringError::InvalidKeyCount)
        ));

        let anchor = keyring.anchor();
        let envelope = deterministic_envelope(&keyring, EnvelopeKind::Live);
        let mut wrong_kdf = envelope.clone();
        wrong_kdf[12] ^= 1;
        assert!(matches!(
            WalletKeyring::decode_live(&wrong_kdf, binding(), PASSPHRASE, anchor),
            Err(WalletKeyringError::NonCanonicalCryptography)
        ));

        assert!(matches!(
            WalletKeyring::decode_live(&envelope, binding(), b"short", anchor),
            Err(WalletKeyringError::InvalidPassphrase)
        ));
    }

    #[test]
    fn rollback_anchor_checksum_and_fields_fail_closed() {
        let keyring = fixture();
        let anchor = keyring.anchor();
        let mut bytes = anchor.encode().unwrap();
        bytes[20] ^= 1;
        assert!(matches!(
            KeyringAnchorV1::decode(&bytes),
            Err(WalletKeyringError::InvalidRollbackAnchor)
        ));

        let mut wrong_generation = anchor;
        wrong_generation.generation += 1;
        assert!(matches!(
            wrong_generation.verify_keyring(&keyring),
            Err(WalletKeyringError::RollbackAnchorMismatch("generation"))
        ));
    }

    #[test]
    fn backup_requires_its_exact_trusted_generation_not_merely_valid_ciphertext() {
        let keyring = fixture();
        let original_anchor = keyring.anchor();
        let old_backup = deterministic_envelope(&keyring, EnvelopeKind::Backup);
        let old_change = keyring.active_change_key();
        let next = keyring
            .transition(
                original_anchor,
                &[KeyLifecycleUpdate {
                    key_id: old_change.key_id,
                    lifecycle: KeyLifecycle::Retired,
                }],
                vec![local_entry(4, KeyRoles::CHANGE, KeyLifecycle::Active)],
            )
            .unwrap();
        assert!(matches!(
            verify_keyring_backup(&old_backup, binding(), PASSPHRASE, next.anchor()),
            Err(WalletKeyringError::RollbackAnchorMismatch("generation"))
        ));
    }
}
