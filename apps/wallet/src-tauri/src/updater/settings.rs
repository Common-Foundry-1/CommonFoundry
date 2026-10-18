//! Saved updater settings and the check schedule.
//!
//! The settings live in `<data_dir>/updates.json`, next to the wallet's other
//! saved settings (`peers.json`). A missing, unreadable or malformed file
//! means the defaults, with "Update automatically" ON.
//!
//! Deliberate deviation from design section 2.13 ("written the same way as
//! `peers.json`"): `peers.json` is written in place, so a crash mid-write can
//! leave a torn file. Here a torn file would read as the defaults and turn a
//! saved OFF back ON, so the file is written to a temporary sibling, synced,
//! and renamed over the old one instead.
//!
//! Later wallets add fields to this file (`seen`, `failed`, `opened_by_max`
//! and so on) and keep `version` 1 for good. A wallet reads only the fields it
//! knows, and a save keeps every other field of a version 1 file, so a fallback
//! to an older wallet does not erase what a newer one recorded. A file of any
//! other version cannot be merged: it reads as the defaults and a save replaces
//! it with a fresh version 1 file.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub(crate) const SETTINGS_FILE_NAME: &str = "updates.json";
const SETTINGS_TEMP_FILE_NAME: &str = "updates.json.tmp";
const SETTINGS_VERSION: u8 = 1;
const VERSION_FIELD: &str = "version";
const AUTOMATIC_FIELD: &str = "automatic";

/// The first check runs this long after the wallet window is set up.
pub(crate) const FIRST_CHECK_DELAY: Duration = Duration::from_secs(60);
/// Later checks run about this often...
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// ...give or take up to this much, so wallets do not all ask GitHub at once.
pub(crate) const CHECK_JITTER: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UpdateSettings {
    /// "Update automatically". When OFF the wallet still checks on schedule
    /// and only notifies; it downloads nothing until asked.
    pub(crate) automatic: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self { automatic: true }
    }
}

#[derive(Deserialize)]
struct SettingsFile {
    version: u8,
    #[serde(flatten)]
    settings: UpdateSettings,
}

/// What the updater may do in this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateMode {
    /// Turned off for this run by `--no-auto-update` or
    /// `CMFD_NO_AUTO_UPDATE=1`, whatever the saved setting says: no checks, no
    /// downloads, and no forwarding to a newer installed version. Callers pass
    /// the flag ORed with the environment variable.
    DisabledByLaunchOption,
    /// The switch is OFF: check on schedule, notify, download only when asked.
    NotifyOnly,
    /// The switch is ON (the default): check, download and verify in the
    /// background.
    Automatic,
}

impl UpdateMode {
    pub(crate) fn resolve(disabled_by_launch_option: bool, settings: &UpdateSettings) -> Self {
        if disabled_by_launch_option {
            Self::DisabledByLaunchOption
        } else if settings.automatic {
            Self::Automatic
        } else {
            Self::NotifyOnly
        }
    }
}

pub(crate) fn settings_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SETTINGS_FILE_NAME)
}

/// Reads the saved settings, falling back to the defaults (automatic ON).
pub(crate) fn load(data_dir: &Path) -> UpdateSettings {
    match try_load(&settings_path(data_dir)) {
        Ok(settings) => settings,
        Err(LoadIssue::Missing) => UpdateSettings::default(),
        Err(issue) => {
            eprintln!(
                "Common Foundry Wallet ignored saved update settings: {}",
                issue.message()
            );
            UpdateSettings::default()
        }
    }
}

/// Saves the settings, keeping the other fields of the current version 1
/// file. Callers serialize their own saves; one wallet process owns a data
/// directory at a time.
pub(crate) fn save(data_dir: &Path, settings: &UpdateSettings) -> io::Result<()> {
    let mut fields = fields_to_keep(&settings_path(data_dir));
    fields.insert(VERSION_FIELD.into(), SETTINGS_VERSION.into());
    fields.insert(AUTOMATIC_FIELD.into(), settings.automatic.into());
    let encoded = serde_json::to_vec_pretty(&Value::Object(fields))?;
    let temp = data_dir.join(SETTINGS_TEMP_FILE_NAME);
    // A read-only temporary file left behind would make every save fail.
    let _ = fs::remove_file(&temp);
    let result =
        write_synced(&temp, &encoded).and_then(|()| fs::rename(&temp, settings_path(data_dir)));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Every field of the current file, if it is a version 1 JSON object;
/// otherwise nothing.
fn fields_to_keep(path: &Path) -> Map<String, Value> {
    let Ok(bytes) = fs::read(path) else {
        return Map::new();
    };
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(fields))
            if fields.get(VERSION_FIELD).and_then(Value::as_u64)
                == Some(u64::from(SETTINGS_VERSION)) =>
        {
            fields
        }
        _ => Map::new(),
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadIssue {
    Missing,
    Unreadable,
    Malformed,
    UnsupportedVersion,
}

impl LoadIssue {
    fn message(self) -> &'static str {
        match self {
            Self::Missing => "no saved update settings exist yet",
            Self::Unreadable => "saved update settings could not be read",
            Self::Malformed => "saved update settings are malformed",
            Self::UnsupportedVersion => "saved update settings use an unsupported version",
        }
    }
}

fn try_load(path: &Path) -> Result<UpdateSettings, LoadIssue> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            LoadIssue::Missing
        } else {
            LoadIssue::Unreadable
        }
    })?;
    let saved: SettingsFile = serde_json::from_slice(&bytes).map_err(|_| LoadIssue::Malformed)?;
    if saved.version != SETTINGS_VERSION {
        return Err(LoadIssue::UnsupportedVersion);
    }
    Ok(saved.settings)
}

/// How long to wait after one scheduled check before the next.
pub(crate) fn next_check_interval() -> Duration {
    let mut sample = [0_u8; 8];
    let sample = SystemRandom::new()
        .fill(&mut sample)
        .ok()
        .map(|()| u64::from_le_bytes(sample));
    interval_from_sample(sample)
}

/// `CHECK_INTERVAL` ± `CHECK_JITTER`, to the second. Without a random sample
/// the plain interval is used.
fn interval_from_sample(sample: Option<u64>) -> Duration {
    let Some(sample) = sample else {
        return CHECK_INTERVAL;
    };
    let span = 2 * CHECK_JITTER.as_secs() + 1;
    CHECK_INTERVAL - CHECK_JITTER + Duration::from_secs(sample % span)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "cmfd-update-settings-{}-{unique}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, bytes: &[u8]) {
            fs::write(self.0.join(SETTINGS_FILE_NAME), bytes).unwrap();
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const OFF: UpdateSettings = UpdateSettings { automatic: false };
    const ON: UpdateSettings = UpdateSettings { automatic: true };

    #[test]
    fn settings_sit_next_to_the_other_wallet_settings() {
        let data_dir = Path::new("wallet-data");
        assert_eq!(settings_path(data_dir), data_dir.join("updates.json"));
        assert_eq!(
            settings_path(data_dir).parent(),
            data_dir.join("peers.json").parent()
        );
    }

    #[test]
    fn a_missing_file_means_automatic_on() {
        let dir = TempDir::new();
        assert_eq!(UpdateSettings::default(), ON);
        assert_eq!(try_load(&settings_path(&dir.0)), Err(LoadIssue::Missing));
        assert_eq!(load(&dir.0), ON);
        assert!(dir.entries().is_empty());
    }

    #[test]
    fn a_saved_value_reads_back_the_same() {
        let dir = TempDir::new();
        save(&dir.0, &OFF).unwrap();
        assert_eq!(load(&dir.0), OFF);
        assert_eq!(dir.entries(), ["updates.json"]);
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(settings_path(&dir.0)).unwrap()).unwrap();
        assert_eq!(saved, serde_json::json!({"version": 1, "automatic": false}));

        save(&dir.0, &ON).unwrap();
        assert_eq!(load(&dir.0), ON);
        save(&dir.0, &OFF).unwrap();
        assert_eq!(load(&dir.0), OFF);
        assert_eq!(dir.entries(), ["updates.json"]);
    }

    #[test]
    fn a_corrupt_or_unknown_file_means_automatic_on() {
        let cases: [(&[u8], LoadIssue); 8] = [
            (b"", LoadIssue::Malformed),
            (b"not json", LoadIssue::Malformed),
            (b"{\"version\":1,\"automatic\":fa", LoadIssue::Malformed),
            (b"{\"version\":1}", LoadIssue::Malformed),
            (
                b"{\"version\":1,\"automatic\":\"no\"}",
                LoadIssue::Malformed,
            ),
            (b"{\"automatic\":false}", LoadIssue::Malformed),
            (b"[false]", LoadIssue::Malformed),
            (
                b"{\"version\":2,\"automatic\":false}",
                LoadIssue::UnsupportedVersion,
            ),
        ];
        for (bytes, issue) in cases {
            let dir = TempDir::new();
            dir.write(bytes);
            assert_eq!(try_load(&settings_path(&dir.0)), Err(issue), "{bytes:?}");
            assert_eq!(load(&dir.0), ON, "{bytes:?}");
        }
    }

    #[test]
    fn fields_from_a_later_wallet_are_ignored() {
        let dir = TempDir::new();
        dir.write(
            b"{\"version\":1,\"automatic\":false,\"seen\":{\"1.0.17\":\"ab\"},\"failed\":{}}",
        );
        assert_eq!(load(&dir.0), OFF);
    }

    #[test]
    fn a_save_keeps_fields_from_a_later_wallet() {
        let dir = TempDir::new();
        dir.write(
            br#"{"version":1,"automatic":true,"seen":{"1.0.17":"ab"},
                "failed":{"1.0.18":{"kind":"start","reason":"x"}},
                "opened_by_max":"1.0.18","downgrade_override":null}"#,
        );
        save(&dir.0, &OFF).unwrap();
        assert_eq!(load(&dir.0), OFF);
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(settings_path(&dir.0)).unwrap()).unwrap();
        assert_eq!(
            saved,
            serde_json::json!({
                "version": 1,
                "automatic": false,
                "seen": {"1.0.17": "ab"},
                "failed": {"1.0.18": {"kind": "start", "reason": "x"}},
                "opened_by_max": "1.0.18",
                "downgrade_override": null,
            })
        );
        assert_eq!(dir.entries(), ["updates.json"]);
    }

    #[test]
    fn a_save_replaces_a_file_it_cannot_merge() {
        for bytes in [
            &b"not json"[..],
            b"[false]",
            b"{\"automatic\":false,\"seen\":{}}",
            b"{\"version\":\"1\",\"seen\":{}}",
            b"{\"version\":2,\"automatic\":false,\"seen\":{}}",
        ] {
            let dir = TempDir::new();
            dir.write(bytes);
            save(&dir.0, &OFF).unwrap();
            let saved: serde_json::Value =
                serde_json::from_slice(&fs::read(settings_path(&dir.0)).unwrap()).unwrap();
            assert_eq!(
                saved,
                serde_json::json!({"version": 1, "automatic": false}),
                "{bytes:?}"
            );
            assert_eq!(load(&dir.0), OFF, "{bytes:?}");
        }
    }

    #[test]
    fn a_leftover_read_only_temporary_file_does_not_block_a_save() {
        let dir = TempDir::new();
        let temp = dir.0.join(SETTINGS_TEMP_FILE_NAME);
        fs::write(&temp, b"{\"version\":1,\"automatic\":tr").unwrap();
        let mut permissions = fs::metadata(&temp).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&temp, permissions).unwrap();
        save(&dir.0, &OFF).unwrap();
        assert_eq!(load(&dir.0), OFF);
        assert_eq!(dir.entries(), ["updates.json"]);
    }

    #[test]
    fn an_unreadable_file_means_automatic_on_and_cannot_be_saved_over() {
        let dir = TempDir::new();
        fs::create_dir(settings_path(&dir.0)).unwrap();
        assert_eq!(try_load(&settings_path(&dir.0)), Err(LoadIssue::Unreadable));
        assert_eq!(load(&dir.0), ON);
        assert!(save(&dir.0, &OFF).is_err());
        assert_eq!(dir.entries(), ["updates.json"]);
        assert!(settings_path(&dir.0).is_dir());
    }

    #[test]
    fn a_failed_save_leaves_the_old_value_and_no_temporary_file() {
        let dir = TempDir::new();
        save(&dir.0, &OFF).unwrap();
        let missing = dir.0.join("missing");
        assert!(save(&missing, &ON).is_err());
        assert!(!missing.exists());
        assert_eq!(load(&dir.0), OFF);
        assert_eq!(dir.entries(), ["updates.json"]);
    }

    #[test]
    fn the_launch_option_wins_over_the_saved_switch() {
        assert_eq!(UpdateMode::resolve(false, &ON), UpdateMode::Automatic);
        assert_eq!(UpdateMode::resolve(false, &OFF), UpdateMode::NotifyOnly);
        assert_eq!(
            UpdateMode::resolve(true, &ON),
            UpdateMode::DisabledByLaunchOption
        );
        assert_eq!(
            UpdateMode::resolve(true, &OFF),
            UpdateMode::DisabledByLaunchOption
        );
    }

    #[test]
    fn checks_run_every_six_hours_give_or_take_thirty_minutes() {
        let earliest = Duration::from_secs(5 * 3600 + 30 * 60);
        let latest = Duration::from_secs(6 * 3600 + 30 * 60);
        assert_eq!(FIRST_CHECK_DELAY, Duration::from_secs(60));
        assert_eq!(interval_from_sample(None), Duration::from_secs(6 * 3600));
        assert_eq!(interval_from_sample(Some(0)), earliest);
        assert_eq!(interval_from_sample(Some(1800)), CHECK_INTERVAL);
        assert_eq!(interval_from_sample(Some(3600)), latest);
        assert_eq!(interval_from_sample(Some(3601)), earliest);
        for sample in [1, 12_345, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let interval = interval_from_sample(Some(sample));
            assert!(earliest <= interval && interval <= latest, "{sample}");
        }
        for _ in 0..16 {
            let interval = next_check_interval();
            assert!(earliest <= interval && interval <= latest);
            assert_eq!(interval.subsec_nanos(), 0);
        }
    }
}
