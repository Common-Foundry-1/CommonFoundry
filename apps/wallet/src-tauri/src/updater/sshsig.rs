//! Strict OpenSSH SSHSIG check of a release's `SHA256SUMS.txt.sig`
//! (UPDATER-DESIGN.md section 2.4).
//!
//! It accepts exactly the shape that the release signing tool produces and
//! nothing else:
//!
//! - armor `-----BEGIN SSH SIGNATURE-----` / `-----END SSH SIGNATURE-----`,
//!   LF only, a final LF, no blank lines, canonical base64, at most 4 KiB;
//! - `SSHSIG` magic, version 1;
//! - an `ssh-ed25519` public key that is one of the keys compiled in below
//!   (keys are never taken from the network or from disk);
//! - namespace exactly `commonfoundry-release`, an empty reserved field and
//!   hash `sha512`;
//! - an `ssh-ed25519` signature of exactly 64 bytes, with no trailing bytes
//!   anywhere.
//!
//! The namespace check is load-bearing: the same key also signs producer
//! approvals under another namespace.
//!
//! The signed data is
//! `"SSHSIG" || string(namespace) || string("") || string("sha512") || string(SHA512(message))`,
//! checked with `ring`'s Ed25519.

use base64::Engine as _;
use ring::signature::{ED25519, UnparsedPublicKey};

/// The only namespace a release signature may carry.
pub(crate) const RELEASE_NAMESPACE: &str = "commonfoundry-release";

/// Largest armored signature accepted (the real ones are 318 bytes).
pub(crate) const MAX_SIGNATURE_BYTES: usize = 4 * 1024;

const ARMOR_BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----\n";
const ARMOR_END: &[u8] = b"-----END SSH SIGNATURE-----\n";
const MAGIC: &[u8] = b"SSHSIG";
const VERSION: u32 = 1;
const KEY_TYPE: &[u8] = b"ssh-ed25519";
const HASH_ALGORITHM: &[u8] = b"sha512";

/// The current release key, `commonfoundry-mainnet-owner`, fingerprint
/// `SHA256:cA1Tsf8hL/pxDV5WpOE3iPW3b4uDQosu1dOh//4a/fk`. It is the key in
/// `packaging/mainnet/MAINNET-RELEASE.allowed_signers`; a test checks that
/// the two agree.
const CURRENT_RELEASE_KEY: [u8; 32] = [
    0x5c, 0xdd, 0xae, 0xd2, 0xcb, 0x6e, 0x3b, 0x15, 0xbc, 0x83, 0x2e, 0xc6, 0x57, 0x7e, 0x13, 0x04,
    0x8c, 0x1b, 0x32, 0xdc, 0xc7, 0x37, 0xf0, 0x4e, 0xb8, 0x5c, 0x17, 0xfd, 0x35, 0x06, 0xc2, 0xd9,
];

/// The successor release key, `commonfoundry-release-successor`, fingerprint
/// `SHA256:NWNnjocqzDHbgYcTCyUvJoxw+fvmMzV2z44YEfFquRU`.
///
/// A second, offline Ed25519 release key, so releases can move
/// to it if the current key is ever lost or compromised. These are the last
/// 32 bytes of its public line's key blob; a test pins the exact line.
const SUCCESSOR_RELEASE_KEY: Option<[u8; 32]> = Some([
    0xab, 0x98, 0x06, 0x99, 0x02, 0x32, 0x09, 0x69, 0xc7, 0x66, 0x69, 0xd2, 0xd1, 0x4e, 0xb9, 0x79,
    0x09, 0x98, 0x1d, 0x0d, 0xa1, 0xe2, 0xd2, 0x00, 0x3b, 0x32, 0xa9, 0x81, 0x2d, 0xa3, 0x1f, 0x62,
]);

/// UPDATER END-TO-END TEST KEY: only in builds with the `updater-e2e`
/// feature, which must never be released. Its private seed is right here,
/// so anyone can sign with it: a wallet that trusts it trusts everyone. The
/// end-to-end tests sign their fake releases with it. A release build has
/// no such slot ([`super::BUILD_IDENTITY`] and the wallet's runtime identity
/// say which kind of build this is).
#[cfg(feature = "updater-e2e")]
const E2E_TEST_KEY_SEED: [u8; 32] = [0xe2; 32];

/// Which compiled-in key made a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseKeySlot {
    Current,
    Successor,
    /// The end-to-end test key ([`E2E_TEST_KEY_SEED`]).
    #[cfg(feature = "updater-e2e")]
    E2eTest,
}

/// Why a signature was refused. One variant per check, so callers and tests
/// can tell which rule fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SshSigError {
    TooLarge,
    CarriageReturn,
    Armor,
    Base64,
    Truncated,
    Magic,
    Version,
    PublicKeyFormat,
    Namespace,
    Reserved,
    HashAlgorithm,
    SignatureFormat,
    TrailingBytes,
    KeyNotPinned,
    SignatureInvalid,
}

impl std::fmt::Display for SshSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "the release signature file is too large",
            Self::CarriageReturn => "the release signature file contains a carriage return",
            Self::Armor => "the release signature file is not a plain SSH signature",
            Self::Base64 => "the release signature is not valid base64",
            Self::Truncated => "the release signature is cut short",
            Self::Magic => "the release signature is not an SSHSIG signature",
            Self::Version => "the release signature has an unsupported SSHSIG version",
            Self::PublicKeyFormat => "the release signature does not carry an Ed25519 key",
            Self::Namespace => "the release signature was made for another purpose",
            Self::Reserved => "the release signature has a non-empty reserved field",
            Self::HashAlgorithm => "the release signature does not use sha512",
            Self::SignatureFormat => "the release signature is not an Ed25519 signature",
            Self::TrailingBytes => "the release signature has extra bytes at the end",
            Self::KeyNotPinned => "the release was signed by a key this wallet does not trust",
            Self::SignatureInvalid => "the release signature does not match the file",
        })
    }
}

impl std::error::Error for SshSigError {}

/// The keys this wallet trusts for releases: the current key, plus the
/// successor key once its slot is filled.
fn pinned_release_keys() -> Vec<(ReleaseKeySlot, [u8; 32])> {
    let mut keys = vec![(ReleaseKeySlot::Current, CURRENT_RELEASE_KEY)];
    if let Some(key) = SUCCESSOR_RELEASE_KEY {
        keys.push((ReleaseKeySlot::Successor, key));
    }
    #[cfg(feature = "updater-e2e")]
    keys.push((ReleaseKeySlot::E2eTest, e2e_test_public_key()));
    keys
}

/// The public half of [`E2E_TEST_KEY_SEED`].
#[cfg(feature = "updater-e2e")]
fn e2e_test_public_key() -> [u8; 32] {
    use ring::signature::KeyPair;
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&E2E_TEST_KEY_SEED)
        .expect("a 32-byte Ed25519 seed");
    pair.public_key()
        .as_ref()
        .try_into()
        .expect("an Ed25519 public key is 32 bytes")
}

/// Checks that `armored` is a release signature over `message` (the exact
/// bytes of `SHA256SUMS.txt`) made by a pinned release key.
pub(crate) fn verify_release_signature(
    message: &[u8],
    armored: &[u8],
) -> Result<ReleaseKeySlot, SshSigError> {
    verify_with_keys(message, armored, &pinned_release_keys())
}

fn verify_with_keys(
    message: &[u8],
    armored: &[u8],
    keys: &[(ReleaseKeySlot, [u8; 32])],
) -> Result<ReleaseKeySlot, SshSigError> {
    let parsed = parse(armored)?;
    let slot = keys
        .iter()
        .find(|(_, key)| *key == parsed.public_key)
        .map(|(slot, _)| *slot)
        .ok_or(SshSigError::KeyNotPinned)?;
    UnparsedPublicKey::new(&ED25519, parsed.public_key)
        .verify(&signed_data(message), &parsed.signature)
        .map_err(|_| SshSigError::SignatureInvalid)?;
    Ok(slot)
}

struct ParsedSignature {
    public_key: [u8; 32],
    signature: [u8; 64],
}

fn parse(armored: &[u8]) -> Result<ParsedSignature, SshSigError> {
    if armored.len() > MAX_SIGNATURE_BYTES {
        return Err(SshSigError::TooLarge);
    }
    if armored.contains(&b'\r') {
        return Err(SshSigError::CarriageReturn);
    }
    let body = armored
        .strip_prefix(ARMOR_BEGIN)
        .and_then(|rest| rest.strip_suffix(ARMOR_END))
        .and_then(|rest| rest.strip_suffix(b"\n"))
        .ok_or(SshSigError::Armor)?;
    let mut base64_text = Vec::with_capacity(body.len());
    for line in body.split(|&byte| byte == b'\n') {
        if line.is_empty() {
            return Err(SshSigError::Armor);
        }
        base64_text.extend_from_slice(line);
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(&base64_text)
        .map_err(|_| SshSigError::Base64)?;

    let mut reader = Reader(&blob);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(SshSigError::Magic);
    }
    if reader.u32()? != VERSION {
        return Err(SshSigError::Version);
    }
    let public_key = ed25519_field::<32>(reader.string()?).ok_or(SshSigError::PublicKeyFormat)?;
    if reader.string()? != RELEASE_NAMESPACE.as_bytes() {
        return Err(SshSigError::Namespace);
    }
    if !reader.string()?.is_empty() {
        return Err(SshSigError::Reserved);
    }
    if reader.string()? != HASH_ALGORITHM {
        return Err(SshSigError::HashAlgorithm);
    }
    let signature = ed25519_field::<64>(reader.string()?).ok_or(SshSigError::SignatureFormat)?;
    if !reader.0.is_empty() {
        return Err(SshSigError::TrailingBytes);
    }
    Ok(ParsedSignature {
        public_key,
        signature,
    })
}

/// Parses `string "ssh-ed25519" || string <N bytes>` with nothing after it,
/// the shape of both the embedded public key and the signature.
fn ed25519_field<const N: usize>(field: &[u8]) -> Option<[u8; N]> {
    let mut reader = Reader(field);
    if reader.string().ok()? != KEY_TYPE {
        return None;
    }
    let bytes: [u8; N] = reader.string().ok()?.try_into().ok()?;
    reader.0.is_empty().then_some(bytes)
}

/// The exact bytes the release key signs for `message`.
fn signed_data(message: &[u8]) -> Vec<u8> {
    let digest = ring::digest::digest(&ring::digest::SHA512, message);
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(MAGIC);
    put_string(&mut out, RELEASE_NAMESPACE.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, HASH_ALGORITHM);
    put_string(&mut out, digest.as_ref());
    out
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).expect("SSH string longer than 4 GiB");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Reads SSH wire fields (big-endian `uint32` and `string`) from a byte slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], SshSigError> {
        if count > self.0.len() {
            return Err(SshSigError::Truncated);
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, SshSigError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8], SshSigError> {
        let length = self.u32()? as usize;
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    macro_rules! fixture {
        ($path:literal) => {
            include_bytes!(concat!("../../tests/fixtures/updater/", $path)).as_slice()
        };
    }

    /// (release, SHA256SUMS.txt, SHA256SUMS.txt.sig, sha256 of the signed
    /// data from the Python oracle in wallet-updater-notes.md section 3).
    const RELEASES: [(&str, &[u8], &[u8], &str); 4] = [
        (
            "v1.0.12",
            fixture!("v1.0.12/SHA256SUMS.txt"),
            fixture!("v1.0.12/SHA256SUMS.txt.sig"),
            "3d8a32ac64e68d60f2d55ba48e916afe1de6944523bee3d145e3b104a9cf720f",
        ),
        (
            "v1.0.13",
            fixture!("v1.0.13/SHA256SUMS.txt"),
            fixture!("v1.0.13/SHA256SUMS.txt.sig"),
            "94caf33e522fdc7bfc2bede47a5d402b4e0c99c181cbe0baaa8b7632100b15d3",
        ),
        (
            "v1.0.14",
            fixture!("v1.0.14/SHA256SUMS.txt"),
            fixture!("v1.0.14/SHA256SUMS.txt.sig"),
            "b4065d0a75ff9eb3e2a14750174864238257cf38c187cafab63390c049374592",
        ),
        (
            "v1.0.15",
            fixture!("v1.0.15/SHA256SUMS.txt"),
            fixture!("v1.0.15/SHA256SUMS.txt.sig"),
            "528d79789b2f7667ec6c964a56c86467767bb745db3862083b9af3f7e8f916a9",
        ),
    ];

    const V15_SUMS: &[u8] = fixture!("v1.0.15/SHA256SUMS.txt");
    const V15_SIG: &[u8] = fixture!("v1.0.15/SHA256SUMS.txt.sig");

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes))
    }

    /// The fields of an SSHSIG blob, decoded leniently so tests can change
    /// one field and re-armor the result.
    #[derive(Clone)]
    struct Fields {
        magic: Vec<u8>,
        version: u32,
        public_key: Vec<u8>,
        namespace: Vec<u8>,
        reserved: Vec<u8>,
        hash_algorithm: Vec<u8>,
        signature: Vec<u8>,
        trailing: Vec<u8>,
    }

    impl Fields {
        fn from_armor(armored: &[u8]) -> Self {
            let text = std::str::from_utf8(armored).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            let body: String = lines[1..lines.len() - 1].concat();
            let blob = base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap();
            let mut reader = Reader(&blob);
            let magic = reader.take(6).unwrap().to_vec();
            let version = reader.u32().unwrap();
            let mut string = || reader.string().unwrap().to_vec();
            let (public_key, namespace, reserved, hash_algorithm, signature) =
                (string(), string(), string(), string(), string());
            Fields {
                magic,
                version,
                public_key,
                namespace,
                reserved,
                hash_algorithm,
                signature,
                trailing: reader.0.to_vec(),
            }
        }

        fn blob(&self) -> Vec<u8> {
            let mut blob = self.magic.clone();
            blob.extend_from_slice(&self.version.to_be_bytes());
            for field in [
                &self.public_key,
                &self.namespace,
                &self.reserved,
                &self.hash_algorithm,
                &self.signature,
            ] {
                put_string(&mut blob, field);
            }
            blob.extend_from_slice(&self.trailing);
            blob
        }

        fn to_armor(&self) -> Vec<u8> {
            armor(&self.blob())
        }

        /// A signature over `message` that is cryptographically valid for
        /// this test key, whatever namespace, reserved field and hash it
        /// carries.
        fn signed_by(
            key: &Ed25519KeyPair,
            namespace: &[u8],
            reserved: &[u8],
            hash_algorithm: &[u8],
            message: &[u8],
        ) -> Self {
            let digest_algorithm = match hash_algorithm {
                b"sha256" => &ring::digest::SHA256,
                _ => &ring::digest::SHA512,
            };
            let mut data = MAGIC.to_vec();
            put_string(&mut data, namespace);
            put_string(&mut data, reserved);
            put_string(&mut data, hash_algorithm);
            put_string(
                &mut data,
                ring::digest::digest(digest_algorithm, message).as_ref(),
            );
            Fields {
                magic: MAGIC.to_vec(),
                version: VERSION,
                public_key: ed25519_blob(key.public_key().as_ref()),
                namespace: namespace.to_vec(),
                reserved: reserved.to_vec(),
                hash_algorithm: hash_algorithm.to_vec(),
                signature: ed25519_blob(key.sign(&data).as_ref()),
                trailing: Vec::new(),
            }
        }
    }

    fn ed25519_blob(bytes: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        put_string(&mut blob, KEY_TYPE);
        put_string(&mut blob, bytes);
        blob
    }

    /// Armors a blob the way the signing tool does: 76-character lines, LF.
    fn armor(blob: &[u8]) -> Vec<u8> {
        let text = base64::engine::general_purpose::STANDARD.encode(blob);
        let mut out = ARMOR_BEGIN.to_vec();
        for line in text.as_bytes().chunks(76) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        out.extend_from_slice(ARMOR_END);
        out
    }

    fn test_key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[0x42; 32]).unwrap()
    }

    fn test_key_bytes() -> [u8; 32] {
        test_key().public_key().as_ref().try_into().unwrap()
    }

    /// Checks `armored` against the test key only, so format rules can be
    /// tested with signatures that are otherwise fully valid.
    fn verify_with_test_key(message: &[u8], armored: &[u8]) -> Result<ReleaseKeySlot, SshSigError> {
        verify_with_keys(
            message,
            armored,
            &[(ReleaseKeySlot::Current, test_key_bytes())],
        )
    }

    fn valid_test_signature(message: &[u8]) -> Fields {
        Fields::signed_by(
            &test_key(),
            RELEASE_NAMESPACE.as_bytes(),
            b"",
            HASH_ALGORITHM,
            message,
        )
    }

    #[test]
    fn pinned_key_is_the_key_in_the_release_allowed_signers_file() {
        let policy =
            include_str!("../../../../../packaging/mainnet/MAINNET-RELEASE.allowed_signers");
        assert_eq!(
            sha256_hex(policy.as_bytes()),
            "9c5be92681092801d89687823837823d0966055c03a84e64551e26387da179d2"
        );
        let fields: Vec<&str> = policy.trim_end_matches('\n').split(' ').collect();
        assert_eq!(
            fields[..3],
            [
                "commonfoundry-mainnet-owner",
                "namespaces=\"commonfoundry-release\"",
                "ssh-ed25519"
            ]
        );
        let blob = base64::engine::general_purpose::STANDARD
            .decode(fields[3])
            .unwrap();
        assert_eq!(blob, ed25519_blob(&CURRENT_RELEASE_KEY));
        assert_eq!(
            hex::encode(CURRENT_RELEASE_KEY),
            "5cddaed2cb6e3b15bc832ec6577e13048c1b32dcc737f04eb85c17fd3506c2d9"
        );
        let fingerprint = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(ring::digest::digest(&ring::digest::SHA256, &blob));
        assert_eq!(fingerprint, "cA1Tsf8hL/pxDV5WpOE3iPW3b4uDQosu1dOh//4a/fk");
    }

    #[test]
    fn successor_slot_holds_the_successor_public_line() {
        const LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKuYBpkCMglpx2Zp0tFOuXkJmB0NoeLSADsyqYEtox9i commonfoundry-release-successor";
        let fields: Vec<&str> = LINE.split(' ').collect();
        assert_eq!(fields[0], "ssh-ed25519");
        let blob = base64::engine::general_purpose::STANDARD
            .decode(fields[1])
            .unwrap();
        let successor = SUCCESSOR_RELEASE_KEY.expect("the successor slot is filled");
        assert_eq!(blob, ed25519_blob(&successor));
        assert_eq!(
            hex::encode(successor),
            "ab98069902320969c76669d2d14eb97909981d0da1e2d2003b32a9812da31f62"
        );
        let fingerprint = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(ring::digest::digest(&ring::digest::SHA256, &blob));
        assert_eq!(fingerprint, "NWNnjocqzDHbgYcTCyUvJoxw+fvmMzV2z44YEfFquRU");
        assert_ne!(successor, CURRENT_RELEASE_KEY);
        assert_eq!(
            pinned_release_keys()[..2],
            [
                (ReleaseKeySlot::Current, CURRENT_RELEASE_KEY),
                (ReleaseKeySlot::Successor, successor)
            ]
        );
        // A fully valid signature from any other key is still refused.
        let armored = valid_test_signature(V15_SUMS).to_armor();
        assert_eq!(
            verify_release_signature(V15_SUMS, &armored),
            Err(SshSigError::KeyNotPinned)
        );
    }

    /// The only keys outside the `updater-e2e` feature are the release
    /// keys: no test key can ever be trusted by a build without it.
    #[test]
    fn the_e2e_test_key_is_trusted_only_with_the_updater_e2e_feature() {
        // Only the e2e slot is checked here: the successor slot has its
        // own test, and filling it must not break this one.
        let keys = pinned_release_keys();
        assert_eq!(keys[0], (ReleaseKeySlot::Current, CURRENT_RELEASE_KEY));
        let e2e = Ed25519KeyPair::from_seed_unchecked(&[0xe2; 32]).unwrap();
        // Without the feature the published e2e key is in no slot at all.
        #[cfg(not(feature = "updater-e2e"))]
        assert!(
            keys.iter()
                .all(|(_, key)| key.as_slice() != e2e.public_key().as_ref())
        );
        #[cfg(feature = "updater-e2e")]
        assert_eq!(
            keys.iter()
                .filter(|(slot, _)| *slot == ReleaseKeySlot::E2eTest)
                .collect::<Vec<_>>(),
            vec![&(ReleaseKeySlot::E2eTest, e2e_test_public_key())]
        );
        // A valid signature by the published e2e seed.
        let armored = Fields::signed_by(
            &e2e,
            RELEASE_NAMESPACE.as_bytes(),
            b"",
            HASH_ALGORITHM,
            V15_SUMS,
        )
        .to_armor();
        let verified = verify_release_signature(V15_SUMS, &armored);
        #[cfg(not(feature = "updater-e2e"))]
        assert_eq!(verified, Err(SshSigError::KeyNotPinned));
        #[cfg(feature = "updater-e2e")]
        assert_eq!(verified, Ok(ReleaseKeySlot::E2eTest));
    }

    #[test]
    fn a_filled_successor_slot_is_reported_as_the_signer() {
        let armored = valid_test_signature(V15_SUMS).to_armor();
        let keys = [
            (ReleaseKeySlot::Current, CURRENT_RELEASE_KEY),
            (ReleaseKeySlot::Successor, test_key_bytes()),
        ];
        assert_eq!(
            verify_with_keys(V15_SUMS, &armored, &keys),
            Ok(ReleaseKeySlot::Successor)
        );
        assert_eq!(
            verify_with_keys(V15_SUMS, V15_SIG, &keys),
            Ok(ReleaseKeySlot::Current)
        );
    }

    #[test]
    fn real_release_signatures_verify() {
        for (release, sums, sig, _) in RELEASES {
            assert_eq!(
                verify_release_signature(sums, sig),
                Ok(ReleaseKeySlot::Current),
                "{release}"
            );
        }
    }

    #[test]
    fn signed_data_matches_the_reference_vectors() {
        for (release, sums, _, expected) in RELEASES {
            let data = signed_data(sums);
            assert_eq!(data.len(), 113, "{release}");
            assert_eq!(sha256_hex(&data), expected, "{release}");
        }
    }

    #[test]
    fn test_signatures_are_valid_so_the_negative_cases_mean_something() {
        let armored = valid_test_signature(V15_SUMS).to_armor();
        assert_eq!(
            verify_with_test_key(V15_SUMS, &armored),
            Ok(ReleaseKeySlot::Current)
        );
        // The test helpers rebuild a real signature byte for byte.
        assert_eq!(Fields::from_armor(V15_SIG).to_armor(), V15_SIG);
    }

    #[test]
    fn a_signature_does_not_cover_another_release() {
        let (_, v14_sums, _, _) = RELEASES[2];
        assert_eq!(
            verify_release_signature(v14_sums, V15_SIG),
            Err(SshSigError::SignatureInvalid)
        );
    }

    #[test]
    fn producer_namespace_signature_by_the_same_key_is_refused() {
        let approval = fixture!("v1.0.15/MAINNET-PLAN-PRODUCER-APPROVAL.json");
        let approval_sig = fixture!("v1.0.15/MAINNET-PLAN-PRODUCER-APPROVAL.json.sig");
        assert_eq!(
            Fields::from_armor(approval_sig).public_key,
            ed25519_blob(&CURRENT_RELEASE_KEY)
        );
        assert_eq!(
            verify_release_signature(approval, approval_sig),
            Err(SshSigError::Namespace)
        );
        assert_eq!(
            verify_release_signature(V15_SUMS, approval_sig),
            Err(SshSigError::Namespace)
        );
    }

    #[test]
    fn wrong_namespace_is_refused_even_when_the_signature_is_valid() {
        for namespace in [
            &b"commonfoundry-production-v4-activation-producer-v1"[..],
            b"commonfoundry-releasE",
            b"commonfoundry-release\0",
            b"",
        ] {
            let armored =
                Fields::signed_by(&test_key(), namespace, b"", HASH_ALGORITHM, V15_SUMS).to_armor();
            assert_eq!(
                verify_with_test_key(V15_SUMS, &armored),
                Err(SshSigError::Namespace)
            );
        }
    }

    #[test]
    fn sha256_instead_of_sha512_is_refused() {
        let armored = Fields::signed_by(
            &test_key(),
            RELEASE_NAMESPACE.as_bytes(),
            b"",
            b"sha256",
            V15_SUMS,
        )
        .to_armor();
        assert_eq!(
            verify_with_test_key(V15_SUMS, &armored),
            Err(SshSigError::HashAlgorithm)
        );
        let mut real = Fields::from_armor(V15_SIG);
        real.hash_algorithm = b"sha256".to_vec();
        assert_eq!(
            verify_release_signature(V15_SUMS, &real.to_armor()),
            Err(SshSigError::HashAlgorithm)
        );
    }

    #[test]
    fn non_empty_reserved_field_is_refused() {
        let armored = Fields::signed_by(
            &test_key(),
            RELEASE_NAMESPACE.as_bytes(),
            b"x",
            HASH_ALGORITHM,
            V15_SUMS,
        )
        .to_armor();
        assert_eq!(
            verify_with_test_key(V15_SUMS, &armored),
            Err(SshSigError::Reserved)
        );
    }

    #[test]
    fn version_other_than_one_is_refused() {
        for version in [0, 2] {
            let mut fields = Fields::from_armor(V15_SIG);
            fields.version = version;
            assert_eq!(
                verify_release_signature(V15_SUMS, &fields.to_armor()),
                Err(SshSigError::Version)
            );
        }
    }

    #[test]
    fn wrong_magic_is_refused() {
        let mut fields = Fields::from_armor(V15_SIG);
        fields.magic = b"SSHSIH".to_vec();
        assert_eq!(
            verify_release_signature(V15_SUMS, &fields.to_armor()),
            Err(SshSigError::Magic)
        );
    }

    #[test]
    fn foreign_embedded_key_is_refused() {
        // A fully valid signature under the right namespace by another key.
        let armored = valid_test_signature(V15_SUMS).to_armor();
        assert_eq!(
            verify_release_signature(V15_SUMS, &armored),
            Err(SshSigError::KeyNotPinned)
        );
        // The real signature with its embedded key swapped.
        let mut fields = Fields::from_armor(V15_SIG);
        fields.public_key = ed25519_blob(&test_key_bytes());
        assert_eq!(
            verify_release_signature(V15_SUMS, &fields.to_armor()),
            Err(SshSigError::KeyNotPinned)
        );
    }

    #[test]
    fn non_ed25519_key_or_signature_shape_is_refused() {
        let real = Fields::from_armor(V15_SIG);
        let key_cases = [
            {
                let mut blob = Vec::new();
                put_string(&mut blob, b"ssh-rsa");
                put_string(&mut blob, &CURRENT_RELEASE_KEY);
                blob
            },
            ed25519_blob(&CURRENT_RELEASE_KEY[..31]),
            [ed25519_blob(&CURRENT_RELEASE_KEY), vec![0]].concat(),
            Vec::new(),
        ];
        for public_key in key_cases {
            let mut fields = real.clone();
            fields.public_key = public_key;
            assert_eq!(
                verify_release_signature(V15_SUMS, &fields.to_armor()),
                Err(SshSigError::PublicKeyFormat)
            );
        }
        let sig = &real.signature[real.signature.len() - 64..];
        let signature_cases = [
            {
                let mut blob = Vec::new();
                put_string(&mut blob, b"rsa-sha2-512");
                put_string(&mut blob, sig);
                blob
            },
            ed25519_blob(&sig[..63]),
            [ed25519_blob(sig), vec![0]].concat(),
        ];
        for signature in signature_cases {
            let mut fields = real.clone();
            fields.signature = signature;
            assert_eq!(
                verify_release_signature(V15_SUMS, &fields.to_armor()),
                Err(SshSigError::SignatureFormat)
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        for trailing in [&[0u8][..], b"\0\0\0\0", b"SSHSIG"] {
            let mut fields = Fields::from_armor(V15_SIG);
            fields.trailing = trailing.to_vec();
            assert_eq!(
                verify_release_signature(V15_SUMS, &fields.to_armor()),
                Err(SshSigError::TrailingBytes)
            );
        }
        // Text after the armor is refused too.
        for suffix in [&b"\n"[..], b"x", b"x\n"] {
            let armored = [V15_SIG, suffix].concat();
            assert_eq!(
                verify_release_signature(V15_SUMS, &armored),
                Err(SshSigError::Armor)
            );
        }
    }

    #[test]
    fn truncated_blob_is_refused() {
        let blob = Fields::from_armor(V15_SIG).blob();
        for length in [1, 5, 6, 9, 10, 60, blob.len() - 1] {
            assert_eq!(
                verify_release_signature(V15_SUMS, &armor(&blob[..length])),
                Err(SshSigError::Truncated),
                "{length}"
            );
        }
        // A length field that runs past the end of the blob.
        let mut huge = blob[..10].to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            verify_release_signature(V15_SUMS, &armor(&huge)),
            Err(SshSigError::Truncated)
        );
    }

    #[test]
    fn carriage_returns_are_refused() {
        let crlf: Vec<u8> = V15_SIG
            .iter()
            .flat_map(|&byte| {
                if byte == b'\n' {
                    vec![b'\r', b'\n']
                } else {
                    vec![byte]
                }
            })
            .collect();
        assert_eq!(
            verify_release_signature(V15_SUMS, &crlf),
            Err(SshSigError::CarriageReturn)
        );
        let mut one_cr = V15_SIG.to_vec();
        one_cr.insert(40, b'\r');
        assert_eq!(
            verify_release_signature(V15_SUMS, &one_cr),
            Err(SshSigError::CarriageReturn)
        );
        // CRLF line endings in the signed file change its bytes, so the
        // signature no longer matches.
        let crlf_sums: Vec<u8> = V15_SUMS
            .iter()
            .flat_map(|&byte| {
                if byte == b'\n' {
                    vec![b'\r', b'\n']
                } else {
                    vec![byte]
                }
            })
            .collect();
        assert_eq!(
            verify_release_signature(&crlf_sums, V15_SIG),
            Err(SshSigError::SignatureInvalid)
        );
    }

    #[test]
    fn oversize_signature_file_is_refused() {
        let mut armored = ARMOR_BEGIN.to_vec();
        while armored.len() <= MAX_SIGNATURE_BYTES {
            armored.extend_from_slice(&[b'A'; 76]);
            armored.push(b'\n');
        }
        armored.extend_from_slice(ARMOR_END);
        assert_eq!(
            verify_release_signature(V15_SUMS, &armored),
            Err(SshSigError::TooLarge)
        );
        // A real signature padded past the limit with a valid trailer.
        let mut fields = Fields::from_armor(V15_SIG);
        fields.trailing = vec![0; MAX_SIGNATURE_BYTES];
        assert_eq!(
            verify_release_signature(V15_SUMS, &fields.to_armor()),
            Err(SshSigError::TooLarge)
        );
    }

    #[test]
    fn bad_armor_is_refused() {
        let text = std::str::from_utf8(V15_SIG).unwrap();
        let cases = [
            String::new(),
            text.replace("BEGIN SSH SIGNATURE", "BEGIN SSH SIG"),
            text.replace("END SSH SIGNATURE", "END SIGNATURE"),
            text.trim_end_matches('\n').to_string(),
            text.replacen('\n', "\n\n", 2),
            format!(" {text}"),
            "-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n".to_string(),
        ];
        for case in cases {
            assert_eq!(
                verify_release_signature(V15_SUMS, case.as_bytes()),
                Err(SshSigError::Armor),
                "{case:?}"
            );
        }
    }

    #[test]
    fn bad_base64_is_refused() {
        let text = std::str::from_utf8(V15_SIG).unwrap();
        assert!(text.contains("2ww=\n"));
        let cases = [
            // A character outside the alphabet.
            text.replacen("U1NIU0lH", "U1NI!0lH", 1),
            // URL-safe alphabet.
            text.replacen('+', "-", 1),
            // Whitespace inside a line.
            text.replacen("U1NIU0lH", "U1NI U0lH", 1),
            // Missing, extra and misplaced padding.
            text.replace("2ww=\n", "2ww\n"),
            text.replace("2ww=\n", "2ww==\n"),
            text.replace("2ww=\n", "2w=w\n"),
            // Non-canonical: unused low bits set in the last character.
            text.replace("2ww=\n", "2wx=\n"),
        ];
        for case in cases {
            assert_eq!(
                verify_release_signature(V15_SUMS, case.as_bytes()),
                Err(SshSigError::Base64),
                "{case:?}"
            );
        }
    }

    #[test]
    fn flipped_bytes_are_refused() {
        let mut sums = V15_SUMS.to_vec();
        sums[0] ^= 0x01;
        assert_eq!(
            verify_release_signature(&sums, V15_SIG),
            Err(SshSigError::SignatureInvalid)
        );
        let mut extended = V15_SUMS.to_vec();
        extended.push(b'\n');
        assert_eq!(
            verify_release_signature(&extended, V15_SIG),
            Err(SshSigError::SignatureInvalid)
        );
        let real = Fields::from_armor(V15_SIG);
        for index in [real.signature.len() - 64, real.signature.len() - 1] {
            let mut fields = real.clone();
            fields.signature[index] ^= 0x80;
            assert_eq!(
                verify_release_signature(V15_SUMS, &fields.to_armor()),
                Err(SshSigError::SignatureInvalid)
            );
        }
    }
}
