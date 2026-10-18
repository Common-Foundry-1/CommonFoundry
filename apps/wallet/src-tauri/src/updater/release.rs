//! Release discovery and the checks on a release's signed metadata
//! (UPDATER-DESIGN.md sections 2.3 and 2.4, trimmed for 1.0.16).
//!
//! Discovery lists the GitHub releases of the binaries repo and takes the
//! highest plain `vX.Y.Z` release that is not a draft or prerelease and that
//! carries this platform's runtime archive. Every URL is built here from a
//! compiled repo name, a parsed version and a fixed file name; nothing is
//! ever taken from the API, and "latest" is never asked for. The API is only
//! a hint: the version that counts is the one in the signed `BUILDINFO.json`.
//!
//! Trust runs `SHA256SUMS.txt.sig` (strict SSHSIG, pinned key) →
//! `SHA256SUMS.txt` → `BUILDINFO.json` and the runtime archive's row. The
//! archive itself, and the `MAINNET-PACKAGE.json` inside it, are checked
//! after download against what this module returns.
//!
//! Everything here is pure apart from the [`Transport`] the caller passes in,
//! so tests drive it with a fake.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::sshsig::{self, ReleaseKeySlot, SshSigError};

/// Where releases are published.
pub(crate) const PRIMARY_REPO: &str = "JustAResearcher/CommonFoundry-Binaries";
/// Used only when the primary repo cannot be reached at all (see [`discover`]).
pub(crate) const MIRROR_REPO: &str = "Common-Foundry-1/CommonFoundry";

/// Pages stay small because each API entry is large. Measured 2026-10-16:
/// the anonymous `per_page=100` page 1 of the primary repo was 1,674,984
/// bytes for its 43 releases (701 assets), about 39 KB per release, the
/// largest about 124 KB. So 30 releases are about 1.2 MB, and even 30 of the
/// largest (3.7 MB) fit under [`MAX_LISTING_PAGE_BYTES`].
const RELEASES_PER_PAGE: usize = 30;
/// Releases are listed newest first; 90 is far more than will ever be
/// needed to reach the newest plain release.
const MAX_LISTING_PAGES: u32 = 3;

/// About 7x the measured size of a 30-release page.
pub(crate) const MAX_LISTING_PAGE_BYTES: u64 = 8 * 1024 * 1024;
// A page of the largest entries measured still fits twice.
const _: () = assert!(2 * RELEASES_PER_PAGE as u64 * 124_000 <= MAX_LISTING_PAGE_BYTES);
pub(crate) const MAX_SUMS_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_SIGNATURE_BYTES: u64 = sshsig::MAX_SIGNATURE_BYTES as u64;
pub(crate) const MAX_BUILDINFO_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_PACKAGE_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Hard ceiling on the runtime archive (the 1.0.15 ones are about 83 MB).
pub(crate) const MAX_RUNTIME_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) const SUMS_NAME: &str = "SHA256SUMS.txt";
pub(crate) const SIGNATURE_NAME: &str = "SHA256SUMS.txt.sig";
pub(crate) const BUILDINFO_NAME: &str = "BUILDINFO.json";

const BUILDINFO_SCHEMA: &str = "CMFD_RELEASE_BUILDINFO_V1";
const PACKAGE_SCHEMA: &str = "CMFD_MAINNET_PACKAGE_ATTESTATION_V1";
const PACKAGE_KIND_RUNTIME: &str = "runtime";

/// A plain release version `X.Y.Z`. Ordering is numeric per component, so
/// 1.0.10 is above 1.0.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl Version {
    pub(crate) const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parses exactly `X.Y.Z`: three decimal numbers without leading zeros
    /// and nothing else (no `-rc.1`, no `+build`). A `const fn`, so the
    /// build can check its own version (see [`Version::running`]).
    pub(crate) const fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let mut parts = [0u64; 3];
        let mut part = 0;
        let mut digits = 0;
        let mut index = 0;
        while index <= bytes.len() {
            if index == bytes.len() || bytes[index] == b'.' {
                if digits == 0 || part == 3 {
                    return None;
                }
                part += 1;
                digits = 0;
            } else {
                let byte = bytes[index];
                // A digit after the third number, or after a leading zero.
                if !byte.is_ascii_digit() || part == 3 || (digits == 1 && parts[part] == 0) {
                    return None;
                }
                parts[part] = match parts[part].checked_mul(10) {
                    Some(value) => match value.checked_add((byte - b'0') as u64) {
                        Some(value) => value,
                        None => return None,
                    },
                    None => return None,
                };
                digits += 1;
            }
            index += 1;
        }
        if part == 3 {
            Some(Self::new(parts[0], parts[1], parts[2]))
        } else {
            None
        }
    }

    /// Parses a release tag, which must be exactly `vX.Y.Z`.
    pub(crate) fn from_tag(tag: &str) -> Option<Self> {
        Self::parse(tag.strip_prefix('v')?)
    }

    /// The version of this wallet build, or `None` when it is not a plain
    /// `X.Y.Z` (an RC or test build), where the updater reports itself
    /// unsupported. A mainnet build with such a version does not compile.
    pub(crate) const fn running() -> Option<Self> {
        Self::parse(env!("CARGO_PKG_VERSION"))
    }

    pub(crate) fn tag(self) -> String {
        format!("v{self}")
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(feature = "production-mainnet")]
const _: () = assert!(
    Version::running().is_some(),
    "a mainnet wallet's version must be a plain X.Y.Z"
);

/// The platforms a runtime archive is published for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Platform {
    WindowsX86_64,
    LinuxX86_64,
}

impl Platform {
    /// This build's platform, or `None` where no runtime archive is published.
    pub(crate) const fn current() -> Option<Self> {
        if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
            Some(Self::WindowsX86_64)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Self::LinuxX86_64)
        } else {
            None
        }
    }

    /// The name used in asset names and in `MAINNET-PACKAGE.json`.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::WindowsX86_64 => "windows-x86_64",
            Self::LinuxX86_64 => "linux-x86_64",
        }
    }

    /// The runtime archive name for `version`, built locally so a miner,
    /// HiveOS or other-platform archive can never be picked.
    pub(crate) fn runtime_asset(self, version: Version) -> String {
        let extension = match self {
            Self::WindowsX86_64 => "zip",
            Self::LinuxX86_64 => "tar.gz",
        };
        format!(
            "commonfoundry-mainnet-runtime-{}-v{version}.{extension}",
            self.name()
        )
    }
}

/// An HTTP answer: the status code and the body (empty unless 200).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

/// Why a GET returned no [`Response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransportError {
    /// No HTTP answer at all (DNS, connect, TLS, timeout).
    NoAnswer(String),
    /// The server answered, but the body was over the cap. None of it is
    /// returned.
    TooLarge,
    /// The updater was stopped; this says nothing about the server.
    Cancelled,
}

/// One bounded HTTPS GET. The real implementation runs curl (`fetch.rs`);
/// tests use a fake.
pub(crate) trait Transport {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Response, TransportError>;
}

fn listing_url(repo: &str, page: u32) -> String {
    format!("https://api.github.com/repos/{repo}/releases?per_page={RELEASES_PER_PAGE}&page={page}")
}

/// The download URL of one file of the release tagged `v<version>`.
pub(crate) fn download_url(repo: &str, version: Version, file: &str) -> String {
    format!(
        "https://github.com/{repo}/releases/download/{}/{file}",
        version.tag()
    )
}

/// The fields read from one entry of the GitHub release list. Unknown
/// fields are ignored; a missing or mistyped one fails the whole page.
#[derive(Debug, Deserialize)]
struct ApiRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ApiAsset>,
}

#[derive(Debug, Deserialize)]
struct ApiAsset {
    name: String,
    state: String,
}

enum Listing {
    Releases(Vec<ApiRelease>),
    /// No HTTP answer, or a 5xx, for the first page: the repo cannot be
    /// reached, so the mirror may be tried.
    Unreachable(String),
    /// Anything else that is not a full listing (404, 403/429 rate limit, a
    /// bad body, a later page failing). The mirror is not tried.
    Unknown(String),
}

fn list_releases(transport: &dyn Transport, repo: &str) -> Listing {
    let mut releases = Vec::new();
    for page in 1..=MAX_LISTING_PAGES {
        let first = page == 1;
        let response = match transport.get(&listing_url(repo, page), MAX_LISTING_PAGE_BYTES) {
            Ok(response) => response,
            Err(TransportError::NoAnswer(error)) if first => return Listing::Unreachable(error),
            Err(TransportError::NoAnswer(error)) => return Listing::Unknown(error),
            // An answer, so the repo was reached: never a reason for the mirror.
            Err(TransportError::TooLarge) => {
                return Listing::Unknown("the release list is too large".into());
            }
            // Not a reason for the mirror either.
            Err(TransportError::Cancelled) => return Listing::Unknown("cancelled".into()),
        };
        match response.status {
            200 => {}
            500..=599 if first => {
                return Listing::Unreachable(format!("HTTP {}", response.status));
            }
            // GitHub's answer to too many checks from one address.
            status @ (403 | 429) => {
                return Listing::Unknown(format!(
                    "GitHub limited the check (HTTP {status}); it is tried again later"
                ));
            }
            status => return Listing::Unknown(format!("HTTP {status}")),
        }
        if response.body.len() as u64 > MAX_LISTING_PAGE_BYTES {
            return Listing::Unknown("the release list is too large".into());
        }
        let entries: Vec<ApiRelease> = match serde_json::from_slice(&response.body) {
            Ok(entries) => entries,
            Err(error) => return Listing::Unknown(format!("unreadable release list: {error}")),
        };
        let last = entries.len() < RELEASES_PER_PAGE;
        releases.extend(entries);
        if last {
            break;
        }
    }
    Listing::Releases(releases)
}

/// Every version in `releases` that may be offered on `platform`: a plain
/// `vX.Y.Z` tag, not a draft or prerelease, with this platform's runtime
/// archive and the signed `SHA256SUMS.txt`, its signature and
/// `BUILDINFO.json` uploaded. A release still being uploaded is not offered
/// yet, rather than reported as one that failed its checks.
fn candidates(releases: &[ApiRelease], platform: Platform) -> Vec<Version> {
    releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let version = Version::from_tag(&release.tag_name)?;
            let asset = platform.runtime_asset(version);
            let uploaded = |name: &str| {
                release
                    .assets
                    .iter()
                    .any(|a| a.name == name && a.state == "uploaded")
            };
            [asset.as_str(), SUMS_NAME, SIGNATURE_NAME, BUILDINFO_NAME]
                .into_iter()
                .all(uploaded)
                .then_some(version)
        })
        .collect()
}

/// A release whose signed metadata checked out. The archive still has to
/// be downloaded and matched against `asset_sha256` and `asset_size`.
///
/// `sums`, `signature` and `buildinfo` are the exact bytes that were
/// verified. Install stores these copies; it never downloads them again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedRelease {
    /// From the signed `BUILDINFO.json`.
    pub(crate) version: Version,
    /// The repo the release was found in; its files come from there too.
    pub(crate) repo: &'static str,
    pub(crate) commit: String,
    pub(crate) asset_name: String,
    pub(crate) asset_url: String,
    pub(crate) asset_sha256: [u8; 32],
    pub(crate) asset_size: u64,
    pub(crate) sums_sha256: [u8; 32],
    pub(crate) key: ReleaseKeySlot,
    pub(crate) sums: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) buildinfo: Vec<u8>,
}

/// The result of one discovery round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Discovery {
    /// The release list was read and has nothing newer than this wallet.
    UpToDate,
    /// The highest newer release, verified.
    Available(VerifiedRelease),
    /// The highest newer release failed its checks. Nothing lower is
    /// offered instead; the next round tries again.
    NotVerified {
        version: Version,
        error: ReleaseError,
    },
    /// The release list, or a signed file of the highest newer release,
    /// could not be downloaded; nothing is offered this round.
    Unknown { reason: String },
}

/// One discovery round against the real repos.
///
/// The mirror is tried only when the primary's release list cannot be
/// reached at all (no HTTP answer or a 5xx on the first page). A 404, a rate
/// limit or a bad page gives [`Discovery::Unknown`] without the mirror. Once
/// a repo has returned a list, only that repo is used: if its highest
/// release fails, the mirror is not asked either, so it can never become a
/// way to install a lower version.
pub(crate) fn discover(
    transport: &dyn Transport,
    platform: Platform,
    running: Version,
) -> Discovery {
    let (repo, releases) = match list_releases(transport, PRIMARY_REPO) {
        Listing::Releases(releases) => (PRIMARY_REPO, releases),
        Listing::Unknown(reason) => {
            return Discovery::Unknown {
                reason: format!("{PRIMARY_REPO}: {reason}"),
            };
        }
        Listing::Unreachable(primary) => match list_releases(transport, MIRROR_REPO) {
            Listing::Releases(releases) => (MIRROR_REPO, releases),
            Listing::Unreachable(mirror) | Listing::Unknown(mirror) => {
                return Discovery::Unknown {
                    reason: format!("{PRIMARY_REPO}: {primary}; {MIRROR_REPO}: {mirror}"),
                };
            }
        },
    };
    let Some(version) = candidates(&releases, platform)
        .into_iter()
        .filter(|version| *version > running)
        .max()
    else {
        return Discovery::UpToDate;
    };
    match fetch_and_verify(transport, repo, platform, version, running) {
        Ok(release) => Discovery::Available(release),
        // A file that could not be downloaded says nothing about the
        // release: the check failed, and the next one tries again.
        Err(
            error @ (ReleaseError::Fetch { .. }
            | ReleaseError::Missing { .. }
            | ReleaseError::TooLarge { .. }),
        ) => Discovery::Unknown {
            reason: format!("release {version}: {error}"),
        },
        Err(error) => Discovery::NotVerified { version, error },
    }
}

fn fetch_and_verify(
    transport: &dyn Transport,
    repo: &'static str,
    platform: Platform,
    version: Version,
    running: Version,
) -> Result<VerifiedRelease, ReleaseError> {
    let fetch = |file: &'static str, max_bytes: u64| -> Result<Vec<u8>, ReleaseError> {
        let response = transport
            .get(&download_url(repo, version, file), max_bytes)
            .map_err(|error| match error {
                TransportError::NoAnswer(detail) => ReleaseError::Fetch { file, detail },
                TransportError::TooLarge => ReleaseError::TooLarge { file },
                TransportError::Cancelled => ReleaseError::Fetch {
                    file,
                    detail: "cancelled".into(),
                },
            })?;
        match response.status {
            200 if response.body.len() as u64 <= max_bytes => Ok(response.body),
            200 => Err(ReleaseError::TooLarge { file }),
            404 => Err(ReleaseError::Missing { file }),
            status => Err(ReleaseError::Fetch {
                file,
                detail: format!("HTTP {status}"),
            }),
        }
    };
    let sums = fetch(SUMS_NAME, MAX_SUMS_BYTES)?;
    let signature = fetch(SIGNATURE_NAME, MAX_SIGNATURE_BYTES)?;
    let key =
        sshsig::verify_release_signature(&sums, &signature).map_err(ReleaseError::Signature)?;
    let buildinfo = fetch(BUILDINFO_NAME, MAX_BUILDINFO_BYTES)?;
    let signed = check_signed_contents(platform, version, running, &sums, &buildinfo)?;
    Ok(VerifiedRelease {
        version: signed.version,
        repo,
        asset_url: download_url(repo, signed.version, &signed.asset_name),
        commit: signed.commit,
        asset_name: signed.asset_name,
        asset_sha256: signed.asset_sha256,
        asset_size: signed.asset_size,
        sums_sha256: sha256(&sums),
        key,
        sums,
        signature,
        buildinfo,
    })
}

/// What a stored copy of a release's signed files says, from
/// [`verify_signed_files`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedFiles {
    /// From the signed `BUILDINFO.json`.
    pub(crate) version: Version,
    /// The source commit the signed `BUILDINFO.json` names.
    pub(crate) commit: String,
    pub(crate) asset_sha256: [u8; 32],
    pub(crate) key: ReleaseKeySlot,
}

/// Re-checks the exact `SHA256SUMS.txt`, signature and `BUILDINFO.json` an
/// installed version keeps, offline: the signature by a pinned key, and a
/// `BUILDINFO.json` that matches its row, names `version` and lists this
/// platform's runtime archive with the SUMS hash. There is no anti-rollback
/// here; the caller compares the version with its own.
pub(crate) fn verify_signed_files(
    platform: Platform,
    version: Version,
    sums: &[u8],
    signature: &[u8],
    buildinfo: &[u8],
) -> Result<SignedFiles, ReleaseError> {
    let key = sshsig::verify_release_signature(sums, signature).map_err(ReleaseError::Signature)?;
    let signed = check_signed_contents(platform, version, Version::new(0, 0, 0), sums, buildinfo)?;
    Ok(SignedFiles {
        version: signed.version,
        commit: signed.commit,
        asset_sha256: signed.asset_sha256,
        key,
    })
}

/// What the signed metadata says about the runtime archive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedContents {
    version: Version,
    commit: String,
    asset_name: String,
    asset_sha256: [u8; 32],
    asset_size: u64,
}

/// The checks after the signature: `sums` must already be verified. The
/// version comes from `BUILDINFO.json`, must equal the tag's, and must be
/// strictly above `running` (anti-rollback).
fn check_signed_contents(
    platform: Platform,
    tag_version: Version,
    running: Version,
    sums: &[u8],
    buildinfo: &[u8],
) -> Result<SignedContents, ReleaseError> {
    let rows = parse_sums(sums)?;
    let row = |name: &str| {
        rows.iter()
            .find(|(row_name, _)| row_name == name)
            .map(|(_, digest)| *digest)
            .ok_or_else(|| ReleaseError::NotInSums {
                name: name.to_owned(),
            })
    };
    let asset_name = platform.runtime_asset(tag_version);
    let buildinfo_sha256 = row(BUILDINFO_NAME)?;
    let asset_sha256 = row(&asset_name)?;
    let info = parse_buildinfo(buildinfo, buildinfo_sha256)?;
    if info.version != tag_version {
        return Err(ReleaseError::VersionMismatch {
            tag: tag_version,
            signed: info.version,
        });
    }
    if info.version <= running {
        return Err(ReleaseError::NotNewer {
            signed: info.version,
            running,
        });
    }
    let mut matches = info.artifacts.iter().filter(|a| a.name == asset_name);
    let (Some(artifact), None) = (matches.next(), matches.next()) else {
        return Err(ReleaseError::BuildInfoArtifact);
    };
    if lower_hex_32(&artifact.sha256) != Some(asset_sha256) {
        return Err(ReleaseError::AssetHashMismatch);
    }
    if artifact.size == 0 || artifact.size > MAX_RUNTIME_ARCHIVE_BYTES {
        return Err(ReleaseError::AssetSize);
    }
    Ok(SignedContents {
        version: info.version,
        commit: info.commit,
        asset_name,
        asset_sha256,
        asset_size: artifact.size,
    })
}

/// Parses a `SHA256SUMS.txt` strictly: every line is 64 lowercase hex
/// digits, two spaces and a plain file name (`[A-Za-z0-9._+-]`, so no `/`
/// and no `*` binary marker), LF only with a final LF, names unique and in
/// byte order.
fn parse_sums(sums: &[u8]) -> Result<Vec<(String, [u8; 32])>, ReleaseError> {
    if sums.len() as u64 > MAX_SUMS_BYTES {
        return Err(ReleaseError::TooLarge { file: SUMS_NAME });
    }
    if sums.contains(&b'\r') {
        return Err(ReleaseError::SumsCarriageReturn);
    }
    let body = sums
        .strip_suffix(b"\n")
        .ok_or(ReleaseError::SumsFinalNewline)?;
    let mut rows: Vec<(String, [u8; 32])> = Vec::new();
    for (index, line) in body.split(|&byte| byte == b'\n').enumerate() {
        let number = index + 1;
        let bad_line = ReleaseError::SumsLine { line: number };
        if line.len() < 67 || &line[64..66] != b"  " {
            return Err(bad_line);
        }
        let digest = std::str::from_utf8(&line[..64])
            .ok()
            .and_then(lower_hex_32)
            .ok_or(bad_line.clone())?;
        let name = &line[66..];
        if !name
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
        {
            return Err(bad_line);
        }
        let name = String::from_utf8(name.to_vec()).map_err(|_| bad_line)?;
        if let Some((previous, _)) = rows.last() {
            if *previous == name {
                return Err(ReleaseError::SumsDuplicate { name });
            }
            if previous.as_bytes() > name.as_bytes() {
                return Err(ReleaseError::SumsUnsorted { line: number });
            }
        }
        rows.push((name, digest));
    }
    Ok(rows)
}

#[derive(Debug, Deserialize)]
struct RawBuildInfo {
    schema: String,
    version: String,
    commit: String,
    artifacts: Vec<RawArtifact>,
}

#[derive(Debug, Deserialize)]
struct RawArtifact {
    name: String,
    sha256: String,
    size: u64,
}

struct BuildInfo {
    version: Version,
    commit: String,
    artifacts: Vec<RawArtifact>,
}

fn parse_buildinfo(bytes: &[u8], expected_sha256: [u8; 32]) -> Result<BuildInfo, ReleaseError> {
    if bytes.len() as u64 > MAX_BUILDINFO_BYTES {
        return Err(ReleaseError::TooLarge {
            file: BUILDINFO_NAME,
        });
    }
    if sha256(bytes) != expected_sha256 {
        return Err(ReleaseError::BuildInfoHash);
    }
    let raw: RawBuildInfo =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::BuildInfoFormat)?;
    if raw.schema != BUILDINFO_SCHEMA {
        return Err(ReleaseError::BuildInfoFormat);
    }
    let version = Version::parse(&raw.version).ok_or(ReleaseError::BuildInfoFormat)?;
    if !is_commit(&raw.commit) {
        return Err(ReleaseError::BuildInfoFormat);
    }
    Ok(BuildInfo {
        version,
        commit: raw.commit,
        artifacts: raw.artifacts,
    })
}

#[derive(Debug, Deserialize)]
struct RawPackageManifest {
    schema: String,
    kind: String,
    platform: String,
    package_version: String,
    network_id: String,
    source_commit: String,
    files: BTreeMap<String, RawPackageFile>,
}

#[derive(Debug, Deserialize)]
struct RawPackageFile {
    bytes: u64,
    sha256: String,
}

/// One file the package manifest lists, by its `/`-separated relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PackageFile {
    pub(crate) bytes: u64,
    pub(crate) sha256: [u8; 32],
}

/// A runtime package that passed [`check_package_manifest`], including the
/// same-network check. Only that function makes one, so install, which
/// takes it, cannot skip the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckedPackage {
    version: Version,
    files: BTreeMap<String, PackageFile>,
}

impl CheckedPackage {
    pub(crate) fn version(&self) -> Version {
        self.version
    }

    /// Every file the package must contain; install checks the extracted
    /// tree against this.
    pub(crate) fn files(&self) -> &BTreeMap<String, PackageFile> {
        &self.files
    }
}

/// Checks the `MAINNET-PACKAGE.json` from inside a downloaded runtime
/// archive (whose sha256 already matched the signed SUMS row) against the
/// verified release: a runtime package for this platform and version, from
/// the commit BUILDINFO names, for the network this wallet runs. A `None`
/// `network_id` (no mainnet identity compiled in) matches nothing.
///
/// Install must read these bytes from the tree extracted from that same
/// archive, never from a second download.
pub(crate) fn check_package_manifest(
    bytes: &[u8],
    platform: Platform,
    release: &VerifiedRelease,
    network_id: Option<[u8; 32]>,
) -> Result<CheckedPackage, ReleaseError> {
    check_manifest(
        bytes,
        platform,
        release.version,
        &release.commit,
        network_id,
    )
}

/// Checks the copy of `MAINNET-PACKAGE.json` an installed version keeps
/// against its re-verified signed files, with the same rules as
/// [`check_package_manifest`].
pub(crate) fn check_kept_package_manifest(
    bytes: &[u8],
    platform: Platform,
    signed: &SignedFiles,
    network_id: Option<[u8; 32]>,
) -> Result<CheckedPackage, ReleaseError> {
    check_manifest(bytes, platform, signed.version, &signed.commit, network_id)
}

fn check_manifest(
    bytes: &[u8],
    platform: Platform,
    version: Version,
    commit: &str,
    network_id: Option<[u8; 32]>,
) -> Result<CheckedPackage, ReleaseError> {
    if bytes.len() as u64 > MAX_PACKAGE_MANIFEST_BYTES {
        return Err(ReleaseError::TooLarge {
            file: "MAINNET-PACKAGE.json",
        });
    }
    let raw: RawPackageManifest =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::PackageFormat)?;
    if raw.schema != PACKAGE_SCHEMA {
        return Err(ReleaseError::PackageFormat);
    }
    if raw.kind != PACKAGE_KIND_RUNTIME || raw.platform != platform.name() {
        return Err(ReleaseError::PackageChannel);
    }
    if Version::parse(&raw.package_version) != Some(version) || raw.source_commit != commit {
        return Err(ReleaseError::PackageMismatch);
    }
    match (network_id, lower_hex_32(&raw.network_id)) {
        (Some(expected), Some(found)) if expected == found => {}
        _ => return Err(ReleaseError::NetworkMismatch),
    }
    if raw.files.is_empty() {
        return Err(ReleaseError::PackageFormat);
    }
    let mut files = BTreeMap::new();
    for (name, file) in raw.files {
        let sha256 = lower_hex_32(&file.sha256).ok_or(ReleaseError::PackageFormat)?;
        if !is_package_path(&name) {
            return Err(ReleaseError::PackageFormat);
        }
        files.insert(
            name,
            PackageFile {
                bytes: file.bytes,
                sha256,
            },
        );
    }
    Ok(CheckedPackage { version, files })
}

/// A relative path made of plain names (`[A-Za-z0-9._+-]`, not starting
/// with `.` or `-`) joined by `/`: no `..`, no root, no drive, no `\`.
pub(super) fn is_package_path(path: &str) -> bool {
    path.split('/').all(|part| {
        !part.is_empty()
            && !part.starts_with(['.', '-'])
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    })
}

/// Why a release was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReleaseError {
    Fetch { file: &'static str, detail: String },
    Missing { file: &'static str },
    TooLarge { file: &'static str },
    Signature(SshSigError),
    SumsCarriageReturn,
    SumsFinalNewline,
    SumsLine { line: usize },
    SumsDuplicate { name: String },
    SumsUnsorted { line: usize },
    NotInSums { name: String },
    BuildInfoHash,
    BuildInfoFormat,
    VersionMismatch { tag: Version, signed: Version },
    NotNewer { signed: Version, running: Version },
    BuildInfoArtifact,
    AssetHashMismatch,
    AssetSize,
    PackageFormat,
    PackageChannel,
    PackageMismatch,
    NetworkMismatch,
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch { file, detail } => write!(f, "could not download {file}: {detail}"),
            Self::Missing { file } => write!(f, "the release has no {file}"),
            Self::TooLarge { file } => write!(f, "{file} is too large"),
            Self::Signature(error) => error.fmt(f),
            Self::SumsCarriageReturn => f.write_str("SHA256SUMS.txt contains a carriage return"),
            Self::SumsFinalNewline => f.write_str("SHA256SUMS.txt does not end with a newline"),
            Self::SumsLine { line } => write!(f, "SHA256SUMS.txt line {line} is malformed"),
            Self::SumsDuplicate { name } => write!(f, "SHA256SUMS.txt lists {name} twice"),
            Self::SumsUnsorted { line } => write!(f, "SHA256SUMS.txt line {line} is out of order"),
            Self::NotInSums { name } => write!(f, "SHA256SUMS.txt does not list {name}"),
            Self::BuildInfoHash => f.write_str("BUILDINFO.json does not match SHA256SUMS.txt"),
            Self::BuildInfoFormat => f.write_str("BUILDINFO.json is not a valid release record"),
            Self::VersionMismatch { tag, signed } => {
                write!(
                    f,
                    "the release tag says {tag} but the signed version is {signed}"
                )
            }
            Self::NotNewer { signed, running } => {
                write!(f, "the signed version {signed} is not newer than {running}")
            }
            Self::BuildInfoArtifact => {
                f.write_str("BUILDINFO.json does not list the runtime archive exactly once")
            }
            Self::AssetHashMismatch => {
                f.write_str("BUILDINFO.json and SHA256SUMS.txt disagree on the runtime archive")
            }
            Self::AssetSize => f.write_str("the runtime archive size is out of range"),
            Self::PackageFormat => {
                f.write_str("MAINNET-PACKAGE.json is not a valid package record")
            }
            Self::PackageChannel => {
                f.write_str("the package is not a runtime package for this platform")
            }
            Self::PackageMismatch => {
                f.write_str("the package version or commit does not match the release")
            }
            Self::NetworkMismatch => f.write_str("the package is for a different network"),
        }
    }
}

impl std::error::Error for ReleaseError {}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

/// Decodes exactly 64 lowercase hex digits.
fn lower_hex_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

fn is_commit(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    macro_rules! fixture {
        ($path:literal) => {
            include_bytes!(concat!("../../tests/fixtures/updater/", $path)).as_slice()
        };
    }

    /// The whole real release lists (43 and 33 entries) as one array each;
    /// [`FakeTransport::listing`] serves them as API pages.
    const PRIMARY_LISTING: &[u8] = fixture!("github-releases-primary-page1.json");
    const MIRROR_LISTING: &[u8] = fixture!("github-releases-mirror-page1.json");

    /// (version, SHA256SUMS.txt, .sig, BUILDINFO.json) of a real release.
    type RealRelease = (Version, &'static [u8], &'static [u8], &'static [u8]);

    const RELEASES: [RealRelease; 4] = [
        (
            Version::new(1, 0, 12),
            fixture!("v1.0.12/SHA256SUMS.txt"),
            fixture!("v1.0.12/SHA256SUMS.txt.sig"),
            fixture!("v1.0.12/BUILDINFO.json"),
        ),
        (
            Version::new(1, 0, 13),
            fixture!("v1.0.13/SHA256SUMS.txt"),
            fixture!("v1.0.13/SHA256SUMS.txt.sig"),
            fixture!("v1.0.13/BUILDINFO.json"),
        ),
        (
            Version::new(1, 0, 14),
            fixture!("v1.0.14/SHA256SUMS.txt"),
            fixture!("v1.0.14/SHA256SUMS.txt.sig"),
            fixture!("v1.0.14/BUILDINFO.json"),
        ),
        (
            Version::new(1, 0, 15),
            fixture!("v1.0.15/SHA256SUMS.txt"),
            fixture!("v1.0.15/SHA256SUMS.txt.sig"),
            fixture!("v1.0.15/BUILDINFO.json"),
        ),
    ];

    const V15: Version = Version::new(1, 0, 15);
    const V15_COMMIT: &str = "2410f3ba780cb64b47e02bb0390459c3049d836d";
    const V15_WINDOWS_PACKAGE: &[u8] =
        fixture!("v1.0.15/runtime-windows-x86_64-MAINNET-PACKAGE.json");
    const V15_LINUX_PACKAGE: &[u8] = fixture!("v1.0.15/runtime-linux-x86_64-MAINNET-PACKAGE.json");
    const MAINNET: Option<[u8; 32]> = cmfd_consensus::mainnet_network::MAINNET_NETWORK_ID;

    const PLATFORMS: [Platform; 2] = [Platform::WindowsX86_64, Platform::LinuxX86_64];

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    /// Serves fixed answers by URL (anything else is a 404) and records
    /// every URL asked for.
    #[derive(Default)]
    struct FakeTransport {
        routes: HashMap<String, Result<Response, TransportError>>,
        requested: RefCell<Vec<String>>,
    }

    impl FakeTransport {
        fn ok(mut self, url: String, body: &[u8]) -> Self {
            let response = Response {
                status: 200,
                body: body.to_vec(),
            };
            self.routes.insert(url, Ok(response));
            self
        }

        fn status(mut self, url: String, status: u16) -> Self {
            let response = Response {
                status,
                body: Vec::new(),
            };
            self.routes.insert(url, Ok(response));
            self
        }

        fn fail(mut self, url: String) -> Self {
            let error = TransportError::NoAnswer("could not connect".into());
            self.routes.insert(url, Err(error));
            self
        }

        fn too_large(mut self, url: String) -> Self {
            self.routes.insert(url, Err(TransportError::TooLarge));
            self
        }

        fn cancelled(mut self, url: String) -> Self {
            self.routes.insert(url, Err(TransportError::Cancelled));
            self
        }

        /// Serves a whole release list from `repo`, split into API pages
        /// the way GitHub would (a full last page is followed by `[]`).
        fn listing(mut self, repo: &str, body: &[u8]) -> Self {
            let entries: Vec<serde_json::Value> = serde_json::from_slice(body).unwrap();
            let mut pages: Vec<&[serde_json::Value]> = entries.chunks(RELEASES_PER_PAGE).collect();
            if entries.len().is_multiple_of(RELEASES_PER_PAGE) {
                pages.push(&[]);
            }
            for (index, page) in pages.into_iter().enumerate() {
                self = self.ok(listing_url(repo, index as u32 + 1), &listing(page));
            }
            self
        }

        /// Serves a real release's signed files from `repo`.
        fn release(self, repo: &str, index: usize) -> Self {
            let (version, sums, sig, buildinfo) = RELEASES[index];
            self.ok(download_url(repo, version, SUMS_NAME), sums)
                .ok(download_url(repo, version, SIGNATURE_NAME), sig)
                .ok(download_url(repo, version, BUILDINFO_NAME), buildinfo)
        }

        fn requested(&self) -> Vec<String> {
            self.requested.borrow().clone()
        }

        fn asked_for(&self, needle: &str) -> bool {
            self.requested().iter().any(|url| url.contains(needle))
        }
    }

    impl Transport for FakeTransport {
        fn get(&self, url: &str, _max_bytes: u64) -> Result<Response, TransportError> {
            self.requested.borrow_mut().push(url.to_owned());
            for forbidden in ["/latest", "latest/"] {
                assert!(!url.contains(forbidden), "asked for {url}");
            }
            self.routes.get(url).cloned().unwrap_or(Ok(Response {
                status: 404,
                body: Vec::new(),
            }))
        }
    }

    fn primary_page(page: u32) -> String {
        listing_url(PRIMARY_REPO, page)
    }

    fn mirror_page(page: u32) -> String {
        listing_url(MIRROR_REPO, page)
    }

    /// A release-list entry in the GitHub API shape.
    fn entry(tag: &str, draft: bool, prerelease: bool, assets: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "tag_name": tag,
            "name": format!("Common Foundry {tag}"),
            "draft": draft,
            "prerelease": prerelease,
            "assets": assets
                .iter()
                .map(|name| serde_json::json!({"name": name, "state": "uploaded", "size": 1}))
                .collect::<Vec<_>>(),
        })
    }

    fn runtime_entry(tag: &str) -> serde_json::Value {
        let version = Version::from_tag(tag).unwrap();
        entry(
            tag,
            false,
            false,
            &[
                &Platform::WindowsX86_64.runtime_asset(version),
                &Platform::LinuxX86_64.runtime_asset(version),
                SUMS_NAME,
                SIGNATURE_NAME,
                BUILDINFO_NAME,
            ],
        )
    }

    fn listing(entries: &[serde_json::Value]) -> Vec<u8> {
        serde_json::to_vec(entries).unwrap()
    }

    fn api_releases(body: &[u8]) -> Vec<ApiRelease> {
        serde_json::from_slice(body).unwrap()
    }

    // ---- versions and tags ----

    #[test]
    fn plain_versions_parse_and_compare_numerically() {
        assert_eq!(v("1.0.15"), Version::new(1, 0, 15));
        assert_eq!(v("0.0.0"), Version::new(0, 0, 0));
        assert_eq!(v("1.10.0"), Version::new(1, 10, 0));
        assert_eq!(v("18446744073709551615.0.0"), Version::new(u64::MAX, 0, 0));
        assert_eq!(
            Version::from_tag("v10.20.30"),
            Some(Version::new(10, 20, 30))
        );
        assert!(v("1.0.10") > v("1.0.9"));
        assert!(v("1.1.0") > v("1.0.99"));
        assert!(v("2.0.0") > v("1.99.99"));
        assert_eq!(v("1.0.16").tag(), "v1.0.16");
        assert_eq!(v("1.0.16").to_string(), "1.0.16");
    }

    #[test]
    fn only_exact_plain_tags_are_versions() {
        for tag in [
            "1.0.15",
            "V1.0.15",
            "v1.0",
            "v1.0.15.1",
            "v01.0.0",
            "v1.00.0",
            "v1.0.01",
            "v1..0",
            "v1.0.",
            "v-1.0.0",
            "v+1.0.0",
            "v1.0.0 ",
            " v1.0.0",
            "v1.0.0\n",
            "v1.0.1-hotfix.2",
            "v1.0.0-sync.15",
            "v1.0.0-security.1",
            "v0.1.0-rc.5",
            "v1.0.14-test9-20261010",
            "v1.0.0+build",
            "superseded-v1.0.0-44b6388a8164",
            "chain-bootstrap-2026-10-05",
            "v99999999999999999999.0.0",
            "v18446744073709551616.0.0",
            "v",
            "",
            "v.1.0.0",
            "v1.0.0.",
            "v1.0.00",
            "v1.0.0a",
            "v١.0.0",
        ] {
            assert_eq!(Version::from_tag(tag), None, "{tag:?}");
        }
    }

    #[test]
    fn the_running_version_is_this_wallet_build() {
        assert_eq!(
            Version::running().map(|version| version.to_string()),
            Some(env!("CARGO_PKG_VERSION").to_owned())
        );
    }

    #[test]
    fn runtime_asset_names_match_the_published_ones() {
        let sums = std::str::from_utf8(RELEASES[3].1).unwrap();
        for platform in PLATFORMS {
            let name = platform.runtime_asset(V15);
            assert!(sums.contains(&format!("  {name}\n")), "{name}");
        }
        assert_eq!(
            Platform::WindowsX86_64.runtime_asset(V15),
            "commonfoundry-mainnet-runtime-windows-x86_64-v1.0.15.zip"
        );
        assert_eq!(
            Platform::LinuxX86_64.runtime_asset(V15),
            "commonfoundry-mainnet-runtime-linux-x86_64-v1.0.15.tar.gz"
        );
    }

    #[test]
    fn this_build_knows_its_platform() {
        let expected = if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
            Some(Platform::WindowsX86_64)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Platform::LinuxX86_64)
        } else {
            None
        };
        assert_eq!(Platform::current(), expected);
    }

    // ---- release list filter ----

    #[test]
    fn the_real_release_lists_offer_only_plain_releases() {
        let plain: Vec<Version> = (0..=15)
            .rev()
            .map(|patch| Version::new(1, 0, patch))
            .collect();
        for body in [PRIMARY_LISTING, MIRROR_LISTING] {
            let releases = api_releases(body);
            for platform in PLATFORMS {
                assert_eq!(candidates(&releases, platform), plain);
            }
        }
        // The lists really do hold the noise the filter has to skip.
        let primary = std::str::from_utf8(PRIMARY_LISTING).unwrap();
        for tag in [
            "\"v1.0.1-hotfix.2\"",
            "\"v1.0.0-sync.15\"",
            "\"v1.0.0-security.1\"",
            "\"v0.1.0-rc.5\"",
            "\"v0.1.0-rc.5-miner.2\"",
            "\"chain-bootstrap-2026-10-05\"",
            "\"prerelease\":true",
        ] {
            assert!(primary.contains(tag), "{tag}");
        }
        let mirror = std::str::from_utf8(MIRROR_LISTING).unwrap();
        assert!(mirror.contains("\"v1.0.14-test9-20261010\""));
    }

    #[test]
    fn drafts_prereleases_and_releases_without_this_runtime_are_skipped() {
        let v9 = v("9.9.9");
        let windows = Platform::WindowsX86_64.runtime_asset(v9);
        let linux = Platform::LinuxX86_64.runtime_asset(v9);
        // Every entry has the signed files, so only what each one tests can
        // keep it from being offered.
        let signed = |assets: &[&str]| -> Vec<String> {
            assets
                .iter()
                .copied()
                .chain([SUMS_NAME, SIGNATURE_NAME, BUILDINFO_NAME])
                .map(str::to_owned)
                .collect()
        };
        let release = |tag: &str, draft: bool, prerelease: bool, assets: &[&str]| {
            let assets = signed(assets);
            let assets: Vec<&str> = assets.iter().map(String::as_str).collect();
            entry(tag, draft, prerelease, &assets)
        };
        let mut not_uploaded = release("v9.9.9", false, false, &[&windows]);
        not_uploaded["assets"][0]["state"] = "starter".into();
        let rejected = [
            release("v9.9.9", true, false, &[&windows, &linux]),
            release("v9.9.9", false, true, &[&windows, &linux]),
            release("v9.9.9", false, false, &[]),
            release(
                "v9.9.9",
                false,
                false,
                &[
                    "commonfoundry-mainnet-miner-windows-x86_64-v9.9.9.zip",
                    "commonfoundry-mainnet-hiveos-9.9.9.tar.gz",
                    "commonfoundry-mainnet-runtime-windows-x86_64-v9.9.8.zip",
                    "commonfoundry-mainnet-runtime-windows-x86_64-v9.9.9.tar.gz",
                ],
            ),
            release("v9.9.9-hotfix.1", false, false, &[&windows]),
            not_uploaded,
        ];
        for item in rejected {
            let releases = api_releases(&listing(std::slice::from_ref(&item)));
            assert!(
                candidates(&releases, Platform::WindowsX86_64).is_empty(),
                "{item}"
            );
        }
        // A release with only the Linux archive is offered on Linux only.
        let releases = api_releases(&listing(&[release("v9.9.9", false, false, &[&linux])]));
        assert!(candidates(&releases, Platform::WindowsX86_64).is_empty());
        assert_eq!(candidates(&releases, Platform::LinuxX86_64), [v9]);
    }

    // ---- discovery ----

    #[test]
    fn discovery_verifies_the_highest_newer_real_release() {
        for platform in PLATFORMS {
            for running in ["1.0.13", "1.0.14", "1.0.0"] {
                let transport = FakeTransport::default()
                    .listing(PRIMARY_REPO, PRIMARY_LISTING)
                    .release(PRIMARY_REPO, 3);
                let Discovery::Available(release) = discover(&transport, platform, v(running))
                else {
                    panic!("{platform:?} from {running}");
                };
                assert_eq!(release.version, V15);
                assert_eq!(release.repo, PRIMARY_REPO);
                assert_eq!(release.commit, V15_COMMIT);
                assert_eq!(release.key, ReleaseKeySlot::Current);
                assert_eq!(release.asset_name, platform.runtime_asset(V15));
                assert_eq!(
                    release.asset_url,
                    format!(
                        "https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/download/v1.0.15/{}",
                        release.asset_name
                    )
                );
                assert_eq!(release.sums_sha256, sha256(RELEASES[3].1));
                // The verified bytes themselves, for install to store.
                assert_eq!(release.sums, RELEASES[3].1);
                assert_eq!(release.signature, RELEASES[3].2);
                assert_eq!(release.buildinfo, RELEASES[3].3);
                let (sha, size) = match platform {
                    Platform::WindowsX86_64 => (
                        "d9b9a20bd70de7bc78eba643ab7ba7ee8c3727094ea810733f06e287bf0d9cd8",
                        82_723_659,
                    ),
                    Platform::LinuxX86_64 => (
                        "c5ff9c5a053109ac3c6179336e7d9bb8a2fa43cdde7eb3b7c1e4fb1d1536ce5b",
                        85_446_201,
                    ),
                };
                assert_eq!(hex::encode(release.asset_sha256), sha);
                assert_eq!(release.asset_size, size);
                // Only the list and the highest release's metadata were read.
                assert_eq!(
                    transport.requested(),
                    [
                        primary_page(1),
                        primary_page(2),
                        download_url(PRIMARY_REPO, V15, SUMS_NAME),
                        download_url(PRIMARY_REPO, V15, SIGNATURE_NAME),
                        download_url(PRIMARY_REPO, V15, BUILDINFO_NAME),
                    ]
                );
            }
        }
    }

    #[test]
    fn nothing_newer_means_up_to_date() {
        for running in ["1.0.15", "1.0.16", "2.0.0"] {
            let transport = FakeTransport::default().listing(PRIMARY_REPO, PRIMARY_LISTING);
            assert_eq!(
                discover(&transport, Platform::WindowsX86_64, v(running)),
                Discovery::UpToDate
            );
            assert_eq!(transport.requested(), [primary_page(1), primary_page(2)]);
        }
        let transport = FakeTransport::default().ok(primary_page(1), b"[]");
        assert_eq!(
            discover(&transport, Platform::LinuxX86_64, v("1.0.15")),
            Discovery::UpToDate
        );
    }

    #[test]
    fn a_higher_release_that_fails_is_never_replaced_by_a_lower_one() {
        let v15_sums = download_url(PRIMARY_REPO, V15, SUMS_NAME);
        let v15_sig = download_url(PRIMARY_REPO, V15, SIGNATURE_NAME);
        let v15_buildinfo = download_url(PRIMARY_REPO, V15, BUILDINFO_NAME);
        let base = || {
            FakeTransport::default()
                .listing(PRIMARY_REPO, PRIMARY_LISTING)
                .release(PRIMARY_REPO, 2)
                .release(MIRROR_REPO, 3)
                .listing(MIRROR_REPO, MIRROR_LISTING)
        };
        // A file that cannot be downloaded is a failed check instead (the
        // next test).
        let cases: Vec<(FakeTransport, ReleaseError)> = vec![
            (
                // v1.0.15's SUMS with v1.0.14's signature.
                base()
                    .ok(v15_sums.clone(), RELEASES[3].1)
                    .ok(v15_sig.clone(), RELEASES[2].2),
                ReleaseError::Signature(SshSigError::SignatureInvalid),
            ),
            (
                // v1.0.14's signed files served under the v1.0.15 tag.
                base()
                    .ok(v15_sums.clone(), RELEASES[2].1)
                    .ok(v15_sig.clone(), RELEASES[2].2)
                    .ok(v15_buildinfo.clone(), RELEASES[2].3),
                ReleaseError::NotInSums {
                    name: Platform::WindowsX86_64.runtime_asset(V15),
                },
            ),
            (
                base()
                    .ok(v15_sums.clone(), RELEASES[3].1)
                    .ok(v15_sig.clone(), RELEASES[3].2)
                    .ok(v15_buildinfo.clone(), RELEASES[2].3),
                ReleaseError::BuildInfoHash,
            ),
        ];
        for (transport, expected) in cases {
            assert_eq!(
                discover(&transport, Platform::WindowsX86_64, v("1.0.13")),
                Discovery::NotVerified {
                    version: V15,
                    error: expected,
                }
            );
            // v1.0.14 is valid and newer than 1.0.13, but it is never even
            // fetched, and the mirror is not asked.
            assert!(!transport.asked_for("/v1.0.14/"));
            assert!(!transport.asked_for(MIRROR_REPO));
        }
    }

    #[test]
    fn a_release_file_that_cannot_be_downloaded_fails_the_check_not_the_verification() {
        let v15_sums = download_url(PRIMARY_REPO, V15, SUMS_NAME);
        let v15_sig = download_url(PRIMARY_REPO, V15, SIGNATURE_NAME);
        let v15_buildinfo = download_url(PRIMARY_REPO, V15, BUILDINFO_NAME);
        let base = || {
            FakeTransport::default()
                .listing(PRIMARY_REPO, PRIMARY_LISTING)
                .release(PRIMARY_REPO, 2)
                .release(PRIMARY_REPO, 3)
                .release(MIRROR_REPO, 3)
                .listing(MIRROR_REPO, MIRROR_LISTING)
        };
        let cases: Vec<(FakeTransport, &str)> = vec![
            (
                base().status(v15_sig.clone(), 404),
                "release 1.0.15: the release has no SHA256SUMS.txt.sig",
            ),
            (
                base().status(v15_sums.clone(), 404),
                "release 1.0.15: the release has no SHA256SUMS.txt",
            ),
            (
                base().status(v15_buildinfo.clone(), 404),
                "release 1.0.15: the release has no BUILDINFO.json",
            ),
            (
                base().status(v15_sums.clone(), 503),
                "release 1.0.15: could not download SHA256SUMS.txt: HTTP 503",
            ),
            (
                base().fail(v15_sig.clone()),
                "release 1.0.15: could not download SHA256SUMS.txt.sig: could not connect",
            ),
            (
                base().too_large(v15_sums.clone()),
                "release 1.0.15: SHA256SUMS.txt is too large",
            ),
            (
                base().cancelled(v15_buildinfo.clone()),
                "release 1.0.15: could not download BUILDINFO.json: cancelled",
            ),
        ];
        for (transport, reason) in cases {
            assert_eq!(
                discover(&transport, Platform::WindowsX86_64, v("1.0.13")),
                Discovery::Unknown {
                    reason: reason.into()
                }
            );
            // Nothing lower is offered instead, and the mirror is not asked.
            assert!(!transport.asked_for("/v1.0.14/"));
            assert!(!transport.asked_for(MIRROR_REPO));
        }
    }

    #[test]
    fn a_release_is_offered_only_once_its_signed_files_are_uploaded() {
        let v9 = v("9.9.9");
        let runtime = Platform::WindowsX86_64.runtime_asset(v9);
        let complete = [runtime.as_str(), SUMS_NAME, SIGNATURE_NAME, BUILDINFO_NAME];
        let offered = |release: serde_json::Value| {
            candidates(&api_releases(&listing(&[release])), Platform::WindowsX86_64)
        };
        assert_eq!(offered(entry("v9.9.9", false, false, &complete)), [v9]);
        for (index, file) in complete.iter().enumerate().skip(1) {
            let without: Vec<&str> = complete
                .iter()
                .copied()
                .filter(|name| name != file)
                .collect();
            assert!(
                offered(entry("v9.9.9", false, false, &without)).is_empty(),
                "{file}"
            );
            let mut uploading = entry("v9.9.9", false, false, &complete);
            uploading["assets"][index]["state"] = "starter".into();
            assert!(offered(uploading).is_empty(), "{file} still uploading");
        }
    }

    #[test]
    fn the_mirror_is_used_only_when_the_primary_cannot_be_reached() {
        for primary in [
            FakeTransport::default().fail(primary_page(1)),
            FakeTransport::default().status(primary_page(1), 500),
            FakeTransport::default().status(primary_page(1), 503),
        ] {
            let transport = primary
                .listing(MIRROR_REPO, MIRROR_LISTING)
                .release(MIRROR_REPO, 3);
            let Discovery::Available(release) =
                discover(&transport, Platform::LinuxX86_64, v("1.0.14"))
            else {
                panic!("mirror not used");
            };
            assert_eq!(release.repo, MIRROR_REPO);
            assert_eq!(release.version, V15);
            assert!(release.asset_url.starts_with(
                "https://github.com/Common-Foundry-1/CommonFoundry/releases/download/v1.0.15/"
            ));
            assert_eq!(
                transport.requested(),
                [
                    primary_page(1),
                    mirror_page(1),
                    mirror_page(2),
                    download_url(MIRROR_REPO, V15, SUMS_NAME),
                    download_url(MIRROR_REPO, V15, SIGNATURE_NAME),
                    download_url(MIRROR_REPO, V15, BUILDINFO_NAME),
                ]
            );
        }
    }

    #[test]
    fn a_primary_that_answers_badly_does_not_switch_to_the_mirror() {
        for primary in [
            FakeTransport::default().status(primary_page(1), 404),
            FakeTransport::default().status(primary_page(1), 403),
            FakeTransport::default().status(primary_page(1), 429),
            FakeTransport::default().status(primary_page(1), 302),
            FakeTransport::default().too_large(primary_page(1)),
            FakeTransport::default().cancelled(primary_page(1)),
            FakeTransport::default().ok(primary_page(1), b"<html>sign in</html>"),
            FakeTransport::default().ok(primary_page(1), b"{\"message\":\"Not Found\"}"),
            FakeTransport::default().ok(primary_page(1), b"[{\"tag_name\":\"v9.9.9\"}]"),
        ] {
            let transport = primary
                .listing(MIRROR_REPO, MIRROR_LISTING)
                .release(MIRROR_REPO, 3);
            assert!(matches!(
                discover(&transport, Platform::WindowsX86_64, v("1.0.14")),
                Discovery::Unknown { .. }
            ));
            assert_eq!(transport.requested(), [primary_page(1)]);
        }
        // A rate limit is said in words, not as a bare status code.
        let limited = FakeTransport::default().status(primary_page(1), 403);
        assert_eq!(
            discover(&limited, Platform::WindowsX86_64, v("1.0.14")),
            Discovery::Unknown {
                reason: format!(
                    "{PRIMARY_REPO}: GitHub limited the check (HTTP 403); it is tried again later"
                ),
            }
        );
    }

    #[test]
    fn both_repos_unreachable_is_unknown() {
        let transport = FakeTransport::default()
            .fail(primary_page(1))
            .status(mirror_page(1), 502);
        let Discovery::Unknown { reason } =
            discover(&transport, Platform::WindowsX86_64, v("1.0.14"))
        else {
            panic!("expected unknown");
        };
        assert!(
            reason.contains(PRIMARY_REPO) && reason.contains(MIRROR_REPO),
            "{reason}"
        );
        assert_eq!(transport.requested(), [primary_page(1), mirror_page(1)]);
    }

    /// A full page of releases that are never offered.
    fn noise_page(page: u32) -> Vec<u8> {
        let entries: Vec<_> = (0..RELEASES_PER_PAGE)
            .map(|n| entry(&format!("v1.0.0-sync.{page}{n}"), false, false, &[]))
            .collect();
        listing(&entries)
    }

    #[test]
    fn the_release_list_is_read_page_by_page() {
        // The newer release is on page 2; page 2 is short, so page 3 is
        // never asked for.
        let transport = FakeTransport::default()
            .ok(primary_page(1), &noise_page(1))
            .ok(
                primary_page(2),
                &listing(&[runtime_entry("v1.0.15"), runtime_entry("v1.0.14")]),
            )
            .release(PRIMARY_REPO, 3);
        assert!(matches!(
            discover(&transport, Platform::WindowsX86_64, v("1.0.14")),
            Discovery::Available(VerifiedRelease { version: V15, .. })
        ));
        assert!(transport.requested().contains(&primary_page(2)));
        assert!(!transport.requested().contains(&primary_page(3)));

        // A one-page list that is exactly full asks for page 2 and accepts
        // an empty answer.
        let transport = FakeTransport::default()
            .ok(primary_page(1), &noise_page(1))
            .ok(primary_page(2), b"[]");
        assert_eq!(
            discover(&transport, Platform::WindowsX86_64, v("1.0.14")),
            Discovery::UpToDate
        );
    }

    #[test]
    fn at_most_three_pages_are_read() {
        let transport = FakeTransport::default()
            .ok(primary_page(1), &noise_page(1))
            .ok(primary_page(2), &noise_page(2))
            .ok(primary_page(3), &noise_page(3))
            .ok(primary_page(4), &listing(&[runtime_entry("v1.0.15")]));
        assert_eq!(
            discover(&transport, Platform::WindowsX86_64, v("1.0.14")),
            Discovery::UpToDate
        );
        assert_eq!(
            transport.requested(),
            [primary_page(1), primary_page(2), primary_page(3)]
        );
    }

    #[test]
    fn a_later_page_failing_stops_the_round_without_the_mirror() {
        for later in [
            FakeTransport::default().fail(primary_page(2)),
            FakeTransport::default().status(primary_page(2), 503),
            FakeTransport::default().ok(primary_page(2), b"not json"),
        ] {
            let transport = later
                .ok(primary_page(1), &{
                    let mut entries: Vec<_> = (0..RELEASES_PER_PAGE - 1)
                        .map(|n| entry(&format!("v1.0.0-sync.{n}"), false, false, &[]))
                        .collect();
                    entries.push(runtime_entry("v1.0.15"));
                    listing(&entries)
                })
                .release(PRIMARY_REPO, 3)
                .listing(MIRROR_REPO, MIRROR_LISTING);
            // v1.0.15 is on page 1, but page 2 might hold a higher one, so
            // nothing is offered this round.
            assert!(matches!(
                discover(&transport, Platform::WindowsX86_64, v("1.0.14")),
                Discovery::Unknown { .. }
            ));
            assert_eq!(transport.requested(), [primary_page(1), primary_page(2)]);
        }
    }

    #[test]
    fn urls_are_built_only_from_constants_and_parsed_versions() {
        assert_eq!(
            listing_url(PRIMARY_REPO, 2),
            "https://api.github.com/repos/JustAResearcher/CommonFoundry-Binaries/releases?per_page=30&page=2"
        );
        assert_eq!(
            download_url(MIRROR_REPO, V15, SUMS_NAME),
            "https://github.com/Common-Foundry-1/CommonFoundry/releases/download/v1.0.15/SHA256SUMS.txt"
        );
        // An API entry whose tag tries to smuggle in a path is not a version.
        let releases = api_releases(&listing(&[entry(
            "v1.0.16/../../latest",
            false,
            false,
            &[&Platform::WindowsX86_64.runtime_asset(v("1.0.16"))],
        )]));
        assert!(candidates(&releases, Platform::WindowsX86_64).is_empty());
    }

    // ---- SHA256SUMS.txt ----

    #[test]
    fn the_real_sums_files_parse() {
        for (version, sums, _, _) in RELEASES {
            let rows = parse_sums(sums).unwrap();
            assert_eq!(rows.len(), 21, "{version}");
            assert_eq!(rows[0].0, BUILDINFO_NAME);
            for platform in PLATFORMS {
                let name = platform.runtime_asset(version);
                assert!(rows.iter().any(|(row, _)| *row == name), "{name}");
            }
        }
    }

    const ROW_A: &str = "acad0c81b56462539aa4ddcb6c088ffbb96f279f126c2770cd1d0ecfaef38748";
    const ROW_B: &str = "d9b9a20bd70de7bc78eba643ab7ba7ee8c3727094ea810733f06e287bf0d9cd8";

    #[test]
    fn malformed_sums_files_are_rejected() {
        let ok = format!("{ROW_A}  BUILDINFO.json\n{ROW_B}  runtime.zip\n");
        assert_eq!(parse_sums(ok.as_bytes()).unwrap().len(), 2);
        let cases: Vec<(String, ReleaseError)> = vec![
            (ok.replace('\n', "\r\n"), ReleaseError::SumsCarriageReturn),
            (ok.trim_end().to_owned(), ReleaseError::SumsFinalNewline),
            (String::new(), ReleaseError::SumsFinalNewline),
            ("\n".into(), ReleaseError::SumsLine { line: 1 }),
            (format!("{ok}\n"), ReleaseError::SumsLine { line: 3 }),
            (
                format!("{ROW_A} BUILDINFO.json\n"),
                ReleaseError::SumsLine { line: 1 },
            ),
            (
                format!("{ROW_A}   BUILDINFO.json\n"),
                ReleaseError::SumsLine { line: 1 },
            ),
            (
                format!("{ROW_A} *BUILDINFO.json\n"),
                ReleaseError::SumsLine { line: 1 },
            ),
            (
                format!("{ROW_A}\tBUILDINFO.json\n"),
                ReleaseError::SumsLine { line: 1 },
            ),
            (
                format!("{}  BUILDINFO.json\n", ROW_A.to_uppercase()),
                ReleaseError::SumsLine { line: 1 },
            ),
            (
                format!("{}  BUILDINFO.json\n", &ROW_A[..63]),
                ReleaseError::SumsLine { line: 1 },
            ),
            (format!("{ROW_A}  \n"), ReleaseError::SumsLine { line: 1 }),
            (
                format!("{ROW_A}  BUILDINFO.json\n{ROW_B}  dir/runtime.zip\n"),
                ReleaseError::SumsLine { line: 2 },
            ),
            (
                format!("{ROW_A}  BUILDINFO.json\n{ROW_B}  runtime zip\n"),
                ReleaseError::SumsLine { line: 2 },
            ),
            (
                format!("{ROW_A}  BUILDINFO.json\n{ROW_B}  runtime\\x.zip\n"),
                ReleaseError::SumsLine { line: 2 },
            ),
            (
                format!("{ROW_A}  BUILDINFO.json\n{ROW_B}  r\u{e9}.zip\n"),
                ReleaseError::SumsLine { line: 2 },
            ),
            (
                format!("{ROW_A}  a.zip\n{ROW_B}  a.zip\n"),
                ReleaseError::SumsDuplicate {
                    name: "a.zip".into(),
                },
            ),
            (
                format!("{ROW_B}  runtime.zip\n{ROW_A}  BUILDINFO.json\n"),
                ReleaseError::SumsUnsorted { line: 2 },
            ),
            (
                format!("{ROW_A}  {}\n", "a".repeat(64 * 1024)),
                ReleaseError::TooLarge { file: SUMS_NAME },
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_sums(text.as_bytes()), Err(expected), "{text:?}");
        }
    }

    // ---- BUILDINFO.json and anti-rollback ----

    #[test]
    fn the_real_releases_pass_the_signed_content_checks() {
        for (version, sums, sig, buildinfo) in RELEASES {
            assert_eq!(
                sshsig::verify_release_signature(sums, sig),
                Ok(ReleaseKeySlot::Current)
            );
            for platform in PLATFORMS {
                let signed =
                    check_signed_contents(platform, version, v("1.0.11"), sums, buildinfo).unwrap();
                assert_eq!(signed.version, version);
                assert_eq!(signed.asset_name, platform.runtime_asset(version));
                let rows = parse_sums(sums).unwrap();
                let row = rows.iter().find(|(name, _)| *name == signed.asset_name);
                assert_eq!(row.map(|(_, digest)| *digest), Some(signed.asset_sha256));
                assert!(signed.asset_size > 50_000_000 && signed.asset_size < 200_000_000);
            }
        }
    }

    /// An unsigned stand-in release: its SUMS and BUILDINFO, built so each
    /// test can break exactly one thing.
    struct Synthetic {
        tag: Version,
        buildinfo: serde_json::Value,
        asset_sha256: String,
    }

    impl Synthetic {
        fn new(version: &str) -> Self {
            let tag = v(version);
            let buildinfo = serde_json::json!({
                "schema": BUILDINFO_SCHEMA,
                "version": version,
                "commit": V15_COMMIT,
                "artifact_count": 2,
                "artifacts": [
                    {"name": Platform::LinuxX86_64.runtime_asset(tag), "sha256": ROW_A, "size": 85_000_000},
                    {"name": Platform::WindowsX86_64.runtime_asset(tag), "sha256": ROW_B, "size": 82_000_000},
                ],
            });
            Self {
                tag,
                buildinfo,
                asset_sha256: ROW_B.into(),
            }
        }

        fn check(&self, running: &str) -> Result<SignedContents, ReleaseError> {
            let buildinfo = serde_json::to_vec(&self.buildinfo).unwrap();
            let name = Platform::WindowsX86_64.runtime_asset(self.tag);
            let sums = format!(
                "{}  BUILDINFO.json\n{}  {name}\n",
                hex::encode(sha256(&buildinfo)),
                self.asset_sha256
            );
            check_signed_contents(
                Platform::WindowsX86_64,
                self.tag,
                v(running),
                sums.as_bytes(),
                &buildinfo,
            )
        }
    }

    #[test]
    fn the_synthetic_release_passes_as_built() {
        let signed = Synthetic::new("1.0.16").check("1.0.15").unwrap();
        assert_eq!(signed.version, v("1.0.16"));
        assert_eq!(signed.asset_size, 82_000_000);
        assert_eq!(hex::encode(signed.asset_sha256), ROW_B);
    }

    #[test]
    fn the_version_comes_from_buildinfo_and_must_match_the_tag() {
        let mut release = Synthetic::new("1.0.16");
        release.buildinfo["version"] = "1.0.17".into();
        assert_eq!(
            release.check("1.0.15"),
            Err(ReleaseError::VersionMismatch {
                tag: v("1.0.16"),
                signed: v("1.0.17"),
            })
        );
        for bad in ["1.0.16-rc.1", "v1.0.16", "1.0", "01.0.16", ""] {
            let mut release = Synthetic::new("1.0.16");
            release.buildinfo["version"] = bad.into();
            assert_eq!(
                release.check("1.0.15"),
                Err(ReleaseError::BuildInfoFormat),
                "{bad}"
            );
        }
    }

    #[test]
    fn anti_rollback_needs_a_strictly_newer_signed_version() {
        for running in ["1.0.16", "1.0.17", "2.0.0"] {
            assert_eq!(
                Synthetic::new("1.0.16").check(running),
                Err(ReleaseError::NotNewer {
                    signed: v("1.0.16"),
                    running: v(running),
                })
            );
        }
        // The real 1.0.15, offered to a 1.0.15 wallet.
        let (version, sums, _, buildinfo) = RELEASES[3];
        assert_eq!(
            check_signed_contents(Platform::WindowsX86_64, version, V15, sums, buildinfo),
            Err(ReleaseError::NotNewer {
                signed: V15,
                running: V15,
            })
        );
    }

    #[test]
    fn buildinfo_format_problems_are_rejected() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("schema", "CMFD_RELEASE_BUILDINFO_V2".into()),
            ("commit", "2410f3b".into()),
            ("commit", V15_COMMIT.to_uppercase().into()),
            ("version", 1016.into()),
            ("artifacts", serde_json::json!({})),
        ];
        for (field, value) in cases {
            let mut release = Synthetic::new("1.0.16");
            release.buildinfo[field] = value.clone();
            assert_eq!(
                release.check("1.0.15"),
                Err(ReleaseError::BuildInfoFormat),
                "{field} = {value}"
            );
        }
        for field in ["schema", "version", "commit", "artifacts"] {
            let mut release = Synthetic::new("1.0.16");
            release.buildinfo.as_object_mut().unwrap().remove(field);
            assert_eq!(
                release.check("1.0.15"),
                Err(ReleaseError::BuildInfoFormat),
                "{field}"
            );
        }
        // Size as a string or a negative number is not an integer size.
        for size in [serde_json::json!("82000000"), serde_json::json!(-1)] {
            let mut release = Synthetic::new("1.0.16");
            release.buildinfo["artifacts"][1]["size"] = size;
            assert_eq!(release.check("1.0.15"), Err(ReleaseError::BuildInfoFormat));
        }
    }

    #[test]
    fn buildinfo_must_be_the_one_in_sums() {
        let release = Synthetic::new("1.0.16");
        let buildinfo = serde_json::to_vec(&release.buildinfo).unwrap();
        let name = Platform::WindowsX86_64.runtime_asset(release.tag);
        let mut tampered = buildinfo.clone();
        tampered.push(b' ');
        let sums = format!(
            "{}  BUILDINFO.json\n{ROW_B}  {name}\n",
            hex::encode(sha256(&buildinfo))
        );
        assert_eq!(
            check_signed_contents(
                Platform::WindowsX86_64,
                release.tag,
                v("1.0.15"),
                sums.as_bytes(),
                &tampered,
            ),
            Err(ReleaseError::BuildInfoHash)
        );
        let oversize = vec![b' '; MAX_BUILDINFO_BYTES as usize + 1];
        let sums = format!(
            "{}  BUILDINFO.json\n{ROW_B}  {name}\n",
            hex::encode(sha256(&oversize))
        );
        assert_eq!(
            check_signed_contents(
                Platform::WindowsX86_64,
                release.tag,
                v("1.0.15"),
                sums.as_bytes(),
                &oversize,
            ),
            Err(ReleaseError::TooLarge {
                file: BUILDINFO_NAME
            })
        );
    }

    #[test]
    fn sums_must_list_buildinfo_and_the_runtime_archive() {
        let release = Synthetic::new("1.0.16");
        let buildinfo = serde_json::to_vec(&release.buildinfo).unwrap();
        let name = Platform::WindowsX86_64.runtime_asset(release.tag);
        let check = |sums: String| {
            check_signed_contents(
                Platform::WindowsX86_64,
                release.tag,
                v("1.0.15"),
                sums.as_bytes(),
                &buildinfo,
            )
        };
        assert_eq!(
            check(format!("{ROW_B}  {name}\n")),
            Err(ReleaseError::NotInSums {
                name: BUILDINFO_NAME.into()
            })
        );
        assert_eq!(
            check(format!(
                "{}  BUILDINFO.json\n{ROW_B}  commonfoundry-mainnet-miner-windows-x86_64-v1.0.16.zip\n",
                hex::encode(sha256(&buildinfo))
            )),
            Err(ReleaseError::NotInSums { name })
        );
    }

    #[test]
    fn buildinfo_and_sums_must_agree_on_the_runtime_archive() {
        let mut release = Synthetic::new("1.0.16");
        release.asset_sha256 = ROW_A.into();
        assert_eq!(
            release.check("1.0.15"),
            Err(ReleaseError::AssetHashMismatch)
        );

        let mut release = Synthetic::new("1.0.16");
        release.buildinfo["artifacts"][1]["sha256"] = ROW_B.to_uppercase().into();
        assert_eq!(
            release.check("1.0.15"),
            Err(ReleaseError::AssetHashMismatch)
        );

        let mut release = Synthetic::new("1.0.16");
        release.buildinfo["artifacts"]
            .as_array_mut()
            .unwrap()
            .remove(1);
        assert_eq!(
            release.check("1.0.15"),
            Err(ReleaseError::BuildInfoArtifact)
        );

        let mut release = Synthetic::new("1.0.16");
        let copy = release.buildinfo["artifacts"][1].clone();
        release.buildinfo["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(copy);
        assert_eq!(
            release.check("1.0.15"),
            Err(ReleaseError::BuildInfoArtifact)
        );

        for size in [0, MAX_RUNTIME_ARCHIVE_BYTES + 1] {
            let mut release = Synthetic::new("1.0.16");
            release.buildinfo["artifacts"][1]["size"] = size.into();
            assert_eq!(
                release.check("1.0.15"),
                Err(ReleaseError::AssetSize),
                "{size}"
            );
        }
        let mut release = Synthetic::new("1.0.16");
        release.buildinfo["artifacts"][1]["size"] = MAX_RUNTIME_ARCHIVE_BYTES.into();
        assert!(release.check("1.0.15").is_ok());
    }

    // ---- MAINNET-PACKAGE.json (same network) ----

    #[test]
    fn the_real_package_manifests_match_this_wallets_network() {
        assert!(MAINNET.is_some());
        for (platform, manifest, exe, count) in [
            (
                Platform::WindowsX86_64,
                V15_WINDOWS_PACKAGE,
                "common-foundry-wallet.exe",
                30,
            ),
            (
                Platform::LinuxX86_64,
                V15_LINUX_PACKAGE,
                "common-foundry-wallet",
                36,
            ),
        ] {
            let package = check_manifest(manifest, platform, V15, V15_COMMIT, MAINNET).unwrap();
            assert_eq!(package.version(), V15);
            assert_eq!(package.files().len(), count);
            let raw: serde_json::Value = serde_json::from_slice(manifest).unwrap();
            let wallet = package.files()[exe];
            assert_eq!(wallet.bytes, raw["files"][exe]["bytes"].as_u64().unwrap());
            assert_eq!(
                hex::encode(wallet.sha256),
                raw["files"][exe]["sha256"].as_str().unwrap()
            );
            assert!(
                package
                    .files()
                    .contains_key("production-mainnet/MAINNET-PLAN.json")
            );
        }
        // Through the public entry point, from a verified release.
        let transport = FakeTransport::default()
            .listing(PRIMARY_REPO, PRIMARY_LISTING)
            .release(PRIMARY_REPO, 3);
        let Discovery::Available(release) =
            discover(&transport, Platform::LinuxX86_64, v("1.0.14"))
        else {
            panic!("not verified");
        };
        assert_eq!(
            check_package_manifest(V15_LINUX_PACKAGE, Platform::LinuxX86_64, &release, MAINNET)
                .map(|package| package.version()),
            Ok(V15)
        );
        assert_eq!(
            check_package_manifest(
                V15_WINDOWS_PACKAGE,
                Platform::LinuxX86_64,
                &release,
                MAINNET
            ),
            Err(ReleaseError::PackageChannel)
        );
    }

    #[test]
    fn a_package_for_another_network_or_channel_is_rejected() {
        let check = |field: &str, value: serde_json::Value| {
            let mut manifest: serde_json::Value =
                serde_json::from_slice(V15_WINDOWS_PACKAGE).unwrap();
            manifest[field] = value;
            check_manifest(
                &serde_json::to_vec(&manifest).unwrap(),
                Platform::WindowsX86_64,
                V15,
                V15_COMMIT,
                MAINNET,
            )
        };
        let mut other_network = hex::encode(MAINNET.unwrap());
        other_network.replace_range(
            ..2,
            if other_network.starts_with("00") {
                "01"
            } else {
                "00"
            },
        );
        let cases: Vec<(&str, serde_json::Value, ReleaseError)> = vec![
            (
                "network_id",
                other_network.into(),
                ReleaseError::NetworkMismatch,
            ),
            (
                "network_id",
                hex::encode(MAINNET.unwrap()).to_uppercase().into(),
                ReleaseError::NetworkMismatch,
            ),
            ("network_id", "".into(), ReleaseError::NetworkMismatch),
            ("kind", "miner".into(), ReleaseError::PackageChannel),
            (
                "platform",
                "linux-x86_64".into(),
                ReleaseError::PackageChannel,
            ),
            (
                "package_version",
                "1.0.14".into(),
                ReleaseError::PackageMismatch,
            ),
            (
                "package_version",
                "v1.0.15".into(),
                ReleaseError::PackageMismatch,
            ),
            (
                "source_commit",
                "0000000000000000000000000000000000000000".into(),
                ReleaseError::PackageMismatch,
            ),
            (
                "schema",
                "CMFD_MAINNET_PACKAGE_ATTESTATION_V2".into(),
                ReleaseError::PackageFormat,
            ),
            (
                "network_id",
                serde_json::Value::Null,
                ReleaseError::PackageFormat,
            ),
        ];
        for (field, value, expected) in cases {
            assert_eq!(
                check(field, value.clone()),
                Err(expected),
                "{field} = {value}"
            );
        }
        // No compiled mainnet identity matches nothing, not even the real one.
        assert_eq!(
            check_manifest(
                V15_WINDOWS_PACKAGE,
                Platform::WindowsX86_64,
                V15,
                V15_COMMIT,
                None
            ),
            Err(ReleaseError::NetworkMismatch)
        );
        assert_eq!(
            check_manifest(
                b"not json",
                Platform::WindowsX86_64,
                V15,
                V15_COMMIT,
                MAINNET
            ),
            Err(ReleaseError::PackageFormat)
        );
    }

    #[test]
    fn the_package_file_list_must_be_well_formed() {
        let check = |files: serde_json::Value| {
            let mut manifest: serde_json::Value =
                serde_json::from_slice(V15_LINUX_PACKAGE).unwrap();
            manifest["files"] = files;
            check_manifest(
                &serde_json::to_vec(&manifest).unwrap(),
                Platform::LinuxX86_64,
                V15,
                V15_COMMIT,
                MAINNET,
            )
        };
        let good = "11418549e78d4f9d7d75edbc7498f000583785f11ca3953dac08093f0fa35d30";
        let entry =
            |name: &str, sha: &str| serde_json::json!({ name: {"bytes": 1, "sha256": sha} });
        assert!(check(entry("lib/libcudart.so.12", good)).is_ok());
        let mut bad: Vec<serde_json::Value> = [
            "../common-foundry-wallet",
            "lib/../../x",
            "/etc/passwd",
            "lib//x",
            "lib/",
            "./x",
            ".cmfd-updater/state.json",
            "-rf",
            "C:x",
            "lib\\x",
            "",
        ]
        .iter()
        .map(|name| entry(name, good))
        .collect();
        bad.extend([
            entry("LICENSE", &good.to_uppercase()),
            entry("LICENSE", &good[..63]),
            serde_json::json!({"LICENSE": {"bytes": 1}}),
            serde_json::json!({"LICENSE": {"bytes": -1, "sha256": good}}),
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::Value::Null,
        ]);
        for files in bad {
            assert_eq!(
                check(files.clone()),
                Err(ReleaseError::PackageFormat),
                "{files}"
            );
        }
    }
}
