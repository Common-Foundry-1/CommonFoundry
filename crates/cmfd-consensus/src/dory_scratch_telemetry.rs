//! Runner-scoped accounting for Dory scratch-artifact logical file lengths.
//!
//! The qualification runner owns one new scratch directory. While its session
//! is active, every production Dory artifact writer uses [`TrackedScratchFile`].
//! A per-session lock spans each size-changing filesystem operation and the
//! corresponding ledger update, including file creation and same-file unlink.
//! The high-water marks are therefore exact for logical file lengths and live
//! tracked entries. They deliberately exclude allocation blocks, filesystem
//! metadata, RAM, and mutations through handles outside this capability.

use std::{
    collections::HashMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, IoSlice, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

use same_file::Handle;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg(any(feature = "whir-prototype", test))]
pub(crate) struct ExactScratchReservationSnapshot {
    pub(crate) peak_logical_bytes: u64,
    pub(crate) peak_live_entries: u64,
    pub(crate) file_creation_events: u64,
    pub(crate) size_mutation_events: u64,
}

#[derive(Clone, Copy)]
struct ActiveFile {
    token_id: u64,
    logical_bytes: u64,
}

#[derive(Default)]
struct ReservationState {
    active: HashMap<PathBuf, ActiveFile>,
    current_logical_bytes: u64,
    peak_logical_bytes: u64,
    peak_live_entries: u64,
    file_creation_events: u64,
    size_mutation_events: u64,
    next_token_id: u64,
    invariant_error: Option<String>,
    closed: bool,
}

type Registry = HashMap<PathBuf, Weak<Mutex<ReservationState>>>;

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_registry() -> std::sync::MutexGuard<'static, Registry> {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_state(state: &Mutex<ReservationState>) -> std::sync::MutexGuard<'_, ReservationState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn canonical_directory(path: &Path) -> io::Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_absolute() || !canonical.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scratch instrumentation root must be an existing absolute directory",
        ));
    }
    Ok(canonical)
}

fn canonical_file_key(path: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "instrumented scratch artifact has no parent",
        )
    })?;
    let root = canonical_directory(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "instrumented scratch artifact has no file name",
        )
    })?;
    Ok((root.clone(), root.join(file_name)))
}

/// One exact logical-length telemetry session for a runner-owned scratch directory.
#[cfg(any(feature = "whir-prototype", test))]
pub(crate) struct ExactScratchReservationSession {
    root: PathBuf,
    state: Arc<Mutex<ReservationState>>,
    finalization_attempted: bool,
    finished: bool,
}

#[cfg(any(feature = "whir-prototype", test))]
impl ExactScratchReservationSession {
    pub(crate) fn start(root: &Path) -> io::Result<Self> {
        let root = canonical_directory(root)?;
        let state = Arc::new(Mutex::new(ReservationState::default()));
        let mut registry = lock_registry();
        if registry
            .get(&root)
            .is_some_and(|registered| registered.strong_count() != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "scratch instrumentation session already exists for this directory",
            ));
        }
        registry.insert(root.clone(), Arc::downgrade(&state));
        Ok(Self {
            root,
            state,
            finalization_attempted: false,
            finished: false,
        })
    }

    pub(crate) fn finish_and_remove_root(&mut self) -> io::Result<ExactScratchReservationSnapshot> {
        self.finish_and_remove_root_inner(|| {})
    }

    fn finish_and_remove_root_inner(
        &mut self,
        after_close: impl FnOnce(),
    ) -> io::Result<ExactScratchReservationSnapshot> {
        if self.finalization_attempted {
            return Err(io::Error::other(
                "scratch instrumentation finalization was already attempted",
            ));
        }
        self.finalization_attempted = true;
        let snapshot = {
            let mut state = lock_state(&self.state);
            state.closed = true;
            after_close();
            if let Some(message) = &state.invariant_error {
                return Err(io::Error::other(message.clone()));
            }
            if !state.active.is_empty() || state.current_logical_bytes != 0 {
                return Err(io::Error::other(format!(
                    "scratch instrumentation retained {} live entries and {} logical bytes",
                    state.active.len(),
                    state.current_logical_bytes
                )));
            }
            let snapshot = ExactScratchReservationSnapshot {
                peak_logical_bytes: state.peak_logical_bytes,
                peak_live_entries: state.peak_live_entries,
                file_creation_events: state.file_creation_events,
                size_mutation_events: state.size_mutation_events,
            };
            let mut entries = fs::read_dir(&self.root)?;
            let retained = entries.next().transpose()?;
            drop(entries);
            if retained.is_some() {
                return Err(io::Error::other(
                    "scratch instrumentation root retained an untracked entry",
                ));
            }
            fs::remove_dir(&self.root)?;
            snapshot
        };
        self.unregister();
        self.finished = true;
        Ok(snapshot)
    }

    fn unregister(&self) {
        let mut registry = lock_registry();
        let remove = registry
            .get(&self.root)
            .and_then(Weak::upgrade)
            .is_some_and(|state| Arc::ptr_eq(&state, &self.state));
        if remove {
            registry.remove(&self.root);
        }
    }
}

#[cfg(any(feature = "whir-prototype", test))]
impl Drop for ExactScratchReservationSession {
    fn drop(&mut self) {
        if !self.finished {
            lock_state(&self.state).closed = true;
            // Leave the weak registry tombstone in place. A later explicit
            // session start may replace it, but an ordinary create must not
            // silently become untracked while the failed root still exists.
        }
    }
}

fn poison(state: &mut ReservationState, message: impl Into<String>) -> io::Error {
    let message = message.into();
    if state.invariant_error.is_none() {
        state.invariant_error = Some(message.clone());
    }
    io::Error::other(message)
}

struct ScratchFileToken {
    state: Arc<Mutex<ReservationState>>,
    key: PathBuf,
    token_id: u64,
    active: bool,
}

/// A scratch file whose logical length is serialized with the owning session's
/// accounting ledger. There is intentionally no mutable raw-file escape hatch:
/// a future rename or new size-changing operation must be added here explicitly.
pub(crate) struct TrackedScratchFile {
    file: File,
    path: PathBuf,
    token: Option<ScratchFileToken>,
}

/// Read-only duplicate of a tracked scratch handle. It intentionally exposes
/// no raw handle or size-changing operation.
pub(crate) struct TrackedScratchReader {
    file: File,
}

impl TrackedScratchReader {
    pub(crate) fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }
}

impl Read for TrackedScratchReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for TrackedScratchReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

impl TrackedScratchFile {
    /// Atomically create and register a new read/write scratch file.
    pub(crate) fn create_new(path: &Path) -> io::Result<Self> {
        let (root, key) = canonical_file_key(path)?;
        let state_and_key = {
            let registry = lock_registry();
            match registry.get(&root) {
                Some(registered) => Some((
                    registered.upgrade().ok_or_else(|| {
                        io::Error::other("scratch instrumentation closed without removing its root")
                    })?,
                    key,
                )),
                None => None,
            }
        };
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
        };
        let Some((state, key)) = state_and_key else {
            return Ok(Self {
                file: open()?,
                path: path.to_path_buf(),
                token: None,
            });
        };

        let mut ledger = lock_state(&state);
        if ledger.closed {
            return Err(io::Error::other(
                "scratch file created after instrumentation closed",
            ));
        }
        if let Some(message) = &ledger.invariant_error {
            return Err(io::Error::other(message.clone()));
        }
        if ledger.active.contains_key(&key) {
            return Err(poison(
                &mut ledger,
                format!("duplicate tracked scratch path: {}", key.display()),
            ));
        }
        let token_id = ledger.next_token_id;
        let next_token_id = token_id
            .checked_add(1)
            .ok_or_else(|| poison(&mut ledger, "tracked scratch token identifier overflow"))?;
        let next_creations = ledger
            .file_creation_events
            .checked_add(1)
            .ok_or_else(|| poison(&mut ledger, "tracked scratch creation event overflow"))?;
        let next_entries = u64::try_from(ledger.active.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| poison(&mut ledger, "tracked scratch live-entry overflow"))?;
        let file = open()?;
        let logical_bytes = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                let message = format!(
                    "could not inspect newly created tracked scratch file {}: {error}",
                    key.display()
                );
                let _ = fs::remove_file(path);
                return Err(poison(&mut ledger, message));
            }
        };
        if logical_bytes != 0 {
            let _ = fs::remove_file(path);
            return Err(poison(
                &mut ledger,
                format!(
                    "new tracked scratch file {} had nonzero length {logical_bytes}",
                    key.display()
                ),
            ));
        }
        ledger.active.insert(
            key.clone(),
            ActiveFile {
                token_id,
                logical_bytes: 0,
            },
        );
        ledger.next_token_id = next_token_id;
        ledger.file_creation_events = next_creations;
        ledger.peak_live_entries = ledger.peak_live_entries.max(next_entries);
        drop(ledger);
        Ok(Self {
            file,
            path: path.to_path_buf(),
            token: Some(ScratchFileToken {
                state,
                key,
                token_id,
                active: true,
            }),
        })
    }

    pub(crate) fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    pub(crate) fn try_clone_reader(&self) -> io::Result<TrackedScratchReader> {
        Ok(TrackedScratchReader {
            file: self.file.try_clone()?,
        })
    }

    pub(crate) fn set_len(&mut self, size: u64) -> io::Result<()> {
        self.with_size_mutation(|file| file.set_len(size))
    }

    fn with_size_mutation<T>(
        &mut self,
        operation: impl FnOnce(&mut File) -> io::Result<T>,
    ) -> io::Result<T> {
        let Some(token) = self.token.as_ref() else {
            return operation(&mut self.file);
        };
        let state = Arc::clone(&token.state);
        let key = token.key.clone();
        let token_id = token.token_id;
        let mut ledger = lock_state(&state);
        if ledger.closed {
            return Err(poison(
                &mut ledger,
                "tracked scratch mutation after instrumentation closed",
            ));
        }
        if let Some(message) = &ledger.invariant_error {
            return Err(io::Error::other(message.clone()));
        }
        let active = ledger.active.get(&key).copied().ok_or_else(|| {
            poison(
                &mut ledger,
                format!("tracked scratch token is not live: {}", key.display()),
            )
        })?;
        if active.token_id != token_id || !token.active {
            return Err(poison(
                &mut ledger,
                format!("tracked scratch token identity mismatch: {}", key.display()),
            ));
        }
        let before = self.file.metadata().map_err(|error| {
            poison(
                &mut ledger,
                format!(
                    "could not inspect tracked scratch file before mutation {}: {error}",
                    key.display()
                ),
            )
        })?;
        if before.len() != active.logical_bytes {
            return Err(poison(
                &mut ledger,
                format!(
                    "tracked scratch pre-mutation length mismatch for {}: ledger {}, file {}",
                    key.display(),
                    active.logical_bytes,
                    before.len()
                ),
            ));
        }

        let result = operation(&mut self.file);
        let after = self.file.metadata().map_err(|error| {
            poison(
                &mut ledger,
                format!(
                    "could not inspect tracked scratch file after mutation {}: {error}",
                    key.display()
                ),
            )
        })?;
        let without_file = ledger
            .current_logical_bytes
            .checked_sub(active.logical_bytes)
            .ok_or_else(|| poison(&mut ledger, "tracked scratch logical-byte underflow"))?;
        let next_current = without_file
            .checked_add(after.len())
            .ok_or_else(|| poison(&mut ledger, "tracked scratch logical-byte overflow"))?;
        let next_mutations = ledger
            .size_mutation_events
            .checked_add(1)
            .ok_or_else(|| poison(&mut ledger, "tracked scratch mutation event overflow"))?;
        let Some(entry) = ledger.active.get_mut(&key) else {
            return Err(poison(
                &mut ledger,
                format!("tracked scratch token disappeared: {}", key.display()),
            ));
        };
        if entry.token_id != token_id || entry.logical_bytes != active.logical_bytes {
            return Err(poison(
                &mut ledger,
                format!(
                    "tracked scratch ledger changed during mutation: {}",
                    key.display()
                ),
            ));
        }
        entry.logical_bytes = after.len();
        ledger.current_logical_bytes = next_current;
        ledger.peak_logical_bytes = ledger.peak_logical_bytes.max(next_current);
        ledger.size_mutation_events = next_mutations;
        result
    }

    /// Remove only the path still referring to this held file, then release its
    /// live-entry and logical-byte liability while the mutation lock is held.
    pub(crate) fn remove_if_owned(&mut self) -> io::Result<()> {
        let Some(token) = self.token.as_mut() else {
            let held = self.file.try_clone().and_then(Handle::from_file)?;
            let live = Handle::from_path(&self.path)?;
            if held != live {
                return Err(io::Error::other(
                    "scratch path no longer refers to the held file",
                ));
            }
            return fs::remove_file(&self.path);
        };
        if !token.active {
            return Ok(());
        }
        let state = Arc::clone(&token.state);
        let key = token.key.clone();
        let token_id = token.token_id;
        let mut ledger = lock_state(&state);
        let active = match ledger.active.get(&key).copied() {
            Some(active) if active.token_id == token_id => active,
            _ => {
                return Err(poison(
                    &mut ledger,
                    format!("tracked scratch cleanup token mismatch: {}", key.display()),
                ));
            }
        };
        let actual_len = match self.file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                return Err(poison(
                    &mut ledger,
                    format!(
                        "could not inspect tracked scratch file during cleanup {}: {error}",
                        key.display()
                    ),
                ));
            }
        };
        let length_mismatch = (actual_len != active.logical_bytes).then(|| {
            format!(
                "tracked scratch cleanup length mismatch for {}: ledger {}, file {}",
                key.display(),
                active.logical_bytes,
                actual_len
            )
        });
        let held = self
            .file
            .try_clone()
            .and_then(Handle::from_file)
            .map_err(|error| {
                poison(
                    &mut ledger,
                    format!(
                        "could not identify held tracked scratch file {}: {error}",
                        key.display()
                    ),
                )
            })?;
        let live = Handle::from_path(&self.path).map_err(|error| {
            poison(
                &mut ledger,
                format!(
                    "could not identify live tracked scratch path {}: {error}",
                    key.display()
                ),
            )
        })?;
        if held != live {
            return Err(poison(
                &mut ledger,
                format!(
                    "tracked scratch path was replaced before cleanup: {}",
                    key.display()
                ),
            ));
        }
        fs::remove_file(&self.path).map_err(|error| {
            poison(
                &mut ledger,
                format!(
                    "tracked scratch unlink failed for {}: {error}",
                    key.display()
                ),
            )
        })?;
        let removed = ledger.active.remove(&key).ok_or_else(|| {
            poison(
                &mut ledger,
                format!(
                    "tracked scratch token vanished during cleanup: {}",
                    key.display()
                ),
            )
        })?;
        ledger.current_logical_bytes = ledger
            .current_logical_bytes
            .checked_sub(removed.logical_bytes)
            .ok_or_else(|| poison(&mut ledger, "tracked scratch cleanup byte underflow"))?;
        token.active = false;
        if let Some(message) = length_mismatch {
            return Err(poison(&mut ledger, message));
        }
        Ok(())
    }
}

impl Read for TrackedScratchFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for TrackedScratchFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

impl Write for TrackedScratchFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.with_size_mutation(|file| file.write(buffer))
    }

    fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        self.with_size_mutation(|file| file.write_vectored(buffers))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for TrackedScratchFile {
    fn drop(&mut self) {
        let _ = self.remove_if_owned();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::BufWriter,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
    };

    use dory_pcs::primitives::arithmetic::Field;

    use super::*;
    use crate::{
        dory_bls12_381_compact_artifact::{
            BlsDoryCompactArtifactSpec, BlsDoryCompactArtifactWriter,
            BlsDoryGroupedCompactArtifactWriter,
        },
        dory_bls12_381_execution_artifact::{
            BlsDoryExecutionAccumulatorArtifactContext, BlsDoryExecutionAccumulatorArtifactWriter,
            BlsDoryExecutionAccumulatorColumn,
        },
        dory_bls12_381_fold_artifact::{BlsDoryFoldArtifactSpec, BlsDoryFoldArtifactWriter},
        dory_bls12_381_index_artifact::{BlsDoryIndexArtifactSpec, BlsDoryIndexArtifactWriter},
        dory_bls12_381_logup_artifact::{BlsDoryLogUpArtifactSpec, BlsDoryLogUpArtifactWriter},
        dory_bls12_381_prototype::BlsDoryFr,
        dory_bls12_381_transpose::BlsDoryWordTransposeWriter,
    };

    static TEST_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-scratch-telemetry-test-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn directory_logical_bytes(root: &Path) -> u64 {
        fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum()
    }

    fn fold_spec(tag: u8) -> BlsDoryFoldArtifactSpec {
        BlsDoryFoldArtifactSpec {
            context_digest: [tag; 32],
            table_index: 1,
            generation: 1,
            scalar_count: 2,
            explicit_scalar_count: 2,
            parent_digest: [tag + 1; 32],
        }
    }

    fn compact_spec(tag: u8) -> BlsDoryCompactArtifactSpec {
        BlsDoryCompactArtifactSpec {
            context_digest: [tag; 32],
            scalar_count: 32,
            explicit_scalar_count: 24,
            word_scalar_count: 16,
            word_bytes: 4,
            code_bits: 4,
            word_width_codes: 1 | (2 << 2) | (3 << 4),
            word_group_len: 4,
            signed_word_selectors: 0b0101,
        }
    }

    fn logup_spec(tag: u8) -> BlsDoryLogUpArtifactSpec {
        BlsDoryLogUpArtifactSpec {
            context_digest: [tag; 32],
            parent_digest: [tag + 1; 32],
            reconstruction_digest: [tag + 2; 32],
            generation: 1,
            selector_rows: 8,
            current_cells: 4,
            regular_selectors: 2,
            range_selectors: 3,
        }
    }

    fn seven_writer_fixture_bytes(root: &Path) -> Vec<Vec<u8>> {
        let fold_spec = fold_spec(61);
        let mut fold_writer = BlsDoryFoldArtifactWriter::create(root, fold_spec).unwrap();
        fold_writer
            .write_scalars(&[BlsDoryFr::from_u64(7), BlsDoryFr::from_u64(11)])
            .unwrap();
        let fold = fold_writer.finish().unwrap();

        let compact_spec = compact_spec(63);
        let dictionary = (0..4).map(BlsDoryFr::from_u64).collect::<Vec<_>>();
        let mut compact_writer =
            BlsDoryCompactArtifactWriter::create(root, compact_spec, dictionary.clone()).unwrap();
        compact_writer.write_words(&[0; 16]).unwrap();
        compact_writer.write_codes(&[0; 8]).unwrap();
        let compact = compact_writer.finish().unwrap();
        let mut grouped_writer =
            BlsDoryGroupedCompactArtifactWriter::create(root, compact_spec, dictionary).unwrap();
        grouped_writer
            .write_cell_chunk(0, 4, &[0; 16], &[0; 8])
            .unwrap();
        let grouped = grouped_writer.finish().unwrap();

        let execution_context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]],
            2,
            4,
            2,
            2,
            4,
        )
        .unwrap();
        let mut execution_writer =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(root, execution_context).unwrap();
        for column_index in 0..execution_context.columns() {
            let column = if column_index == 0 {
                BlsDoryExecutionAccumulatorColumn::Initialization
            } else {
                let relative = column_index - 1;
                BlsDoryExecutionAccumulatorColumn::BankLayer {
                    bank: relative / execution_context.layers_per_bank(),
                    layer: relative % execution_context.layers_per_bank(),
                }
            };
            execution_writer
                .write_column_chunk(column, &[0; 4])
                .unwrap();
            execution_writer
                .write_column_chunk(column, &[0; 4])
                .unwrap();
        }
        let execution = execution_writer.finish().unwrap();

        let mut logup_writer = BlsDoryLogUpArtifactWriter::create(root, logup_spec(65)).unwrap();
        logup_writer
            .write_regular_scalars(&vec![BlsDoryFr::one(); 8])
            .unwrap();
        logup_writer.write_range_codes(&[0; 12]).unwrap();
        let logup = logup_writer.finish().unwrap();

        let mut transpose_writer = BlsDoryWordTransposeWriter::create(root, 2, 2, 1).unwrap();
        transpose_writer.write_row(&[1, 2]).unwrap();
        transpose_writer.write_row(&[3, 4]).unwrap();
        let transpose = transpose_writer.finish().unwrap();

        let index_spec = BlsDoryIndexArtifactSpec {
            context_digest: [67; 32],
            scalar_count: 2,
            explicit_scalar_count: 2,
            literal_scalar_count: 1,
        };
        let mut index_writer = BlsDoryIndexArtifactWriter::create(
            root,
            index_spec,
            vec![BlsDoryFr::zero(), BlsDoryFr::one()],
        )
        .unwrap();
        index_writer.write_scalars(&[BlsDoryFr::one()]).unwrap();
        index_writer.write_codes(&[0]).unwrap();
        let index = index_writer.finish().unwrap();

        let bytes = [
            fold.path(),
            compact.path(),
            grouped.path(),
            execution.path(),
            logup.path(),
            transpose.path(),
            index.path(),
        ]
        .map(|path| fs::read(path).unwrap())
        .into_iter()
        .collect();
        drop((fold, compact, grouped, execution, logup, transpose, index));
        bytes
    }

    #[test]
    fn exact_logical_lengths_track_overlapping_growth_and_deletion() {
        let directory = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&directory.0).unwrap();
        let mut first = TrackedScratchFile::create_new(&directory.0.join("first")).unwrap();
        first.write_all(&[1; 100]).unwrap();
        let mut second = TrackedScratchFile::create_new(&directory.0.join("second")).unwrap();
        second.write_all(&[2; 70]).unwrap();
        first.remove_if_owned().unwrap();
        let mut third = TrackedScratchFile::create_new(&directory.0.join("third")).unwrap();
        third.write_all(&[3; 90]).unwrap();
        second.remove_if_owned().unwrap();
        third.remove_if_owned().unwrap();

        let snapshot = session.finish_and_remove_root().unwrap();
        assert_eq!(snapshot.peak_logical_bytes, 170);
        assert_eq!(snapshot.peak_live_entries, 2);
        assert_eq!(snapshot.file_creation_events, 3);
        assert!(snapshot.size_mutation_events >= 3);
        assert!(!directory.0.exists());
    }

    #[test]
    fn duplicate_paths_and_unbalanced_tokens_fail_closed() {
        let directory = TestDirectory::create();
        let mut duplicate = ExactScratchReservationSession::start(&directory.0).unwrap();
        let path = directory.0.join("duplicate");
        let mut file = TrackedScratchFile::create_new(&path).unwrap();
        assert!(TrackedScratchFile::create_new(&path).is_err());
        file.remove_if_owned().unwrap();
        assert!(duplicate.finish_and_remove_root().is_err());
        assert!(directory.0.is_dir());
        assert!(TrackedScratchFile::create_new(&directory.0.join("after-close")).is_err());
        drop(duplicate);
        assert!(TrackedScratchFile::create_new(&directory.0.join("after-drop")).is_err());
        drop(file);

        let mut unbalanced = ExactScratchReservationSession::start(&directory.0).unwrap();
        let retained = TrackedScratchFile::create_new(&directory.0.join("retained")).unwrap();
        assert!(unbalanced.finish_and_remove_root().is_err());
        drop(retained);
    }

    #[test]
    fn starting_another_root_preserves_failed_root_tombstone() {
        let first_directory = TestDirectory::create();
        let first_root = first_directory.0.clone();
        let first_session = ExactScratchReservationSession::start(&first_root).unwrap();
        drop(first_session);

        let second_directory = TestDirectory::create();
        let mut second_session =
            ExactScratchReservationSession::start(&second_directory.0).unwrap();
        assert!(TrackedScratchFile::create_new(&first_root.join("late")).is_err());
        second_session.finish_and_remove_root().unwrap();

        let mut replacement = ExactScratchReservationSession::start(&first_root).unwrap();
        replacement.finish_and_remove_root().unwrap();
    }

    #[test]
    fn preallocated_and_random_writes_report_logical_length_not_write_volume() {
        let directory = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&directory.0).unwrap();
        let mut file = TrackedScratchFile::create_new(&directory.0.join("random")).unwrap();
        file.set_len(64).unwrap();
        file.seek(SeekFrom::Start(20)).unwrap();
        file.write_all(&[9; 4]).unwrap();
        file.set_len(32).unwrap();
        file.seek(SeekFrom::Start(64)).unwrap();
        let vectored = file
            .write_vectored(&[IoSlice::new(&[1; 3]), IoSlice::new(&[2; 2])])
            .unwrap();
        assert!(vectored > 0);
        file.remove_if_owned().unwrap();

        let snapshot = session.finish_and_remove_root().unwrap();
        assert_eq!(
            snapshot.peak_logical_bytes,
            64 + u64::try_from(vectored).unwrap()
        );
        assert_eq!(snapshot.peak_live_entries, 1);
        assert_eq!(snapshot.file_creation_events, 1);
        assert!(snapshot.size_mutation_events >= 4);
    }

    #[test]
    fn bufwriter_autoflush_and_discard_are_accounted_before_unlink() {
        let directory = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&directory.0).unwrap();
        let file = TrackedScratchFile::create_new(&directory.0.join("autoflush")).unwrap();
        let mut writer = BufWriter::with_capacity(4, file);
        writer.write_all(&[5; 8]).unwrap();
        writer.flush().unwrap();
        let (mut file, buffered) = writer.into_parts();
        drop(buffered);
        assert_eq!(file.metadata().unwrap().len(), 8);
        file.remove_if_owned().unwrap();

        let file = TrackedScratchFile::create_new(&directory.0.join("discard")).unwrap();
        let mut writer = BufWriter::with_capacity(8, file);
        writer.write_all(&[7; 3]).unwrap();
        let (mut file, buffered) = writer.into_parts();
        assert_eq!(buffered.unwrap(), vec![7; 3]);
        assert_eq!(file.metadata().unwrap().len(), 0);
        file.remove_if_owned().unwrap();

        let snapshot = session.finish_and_remove_root().unwrap();
        assert_eq!(snapshot.peak_logical_bytes, 8);
        assert_eq!(snapshot.file_creation_events, 2);
    }

    #[test]
    fn all_seven_writer_classes_transfer_or_cleanup_their_live_tokens() {
        let directory = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&directory.0).unwrap();
        let fold_spec = fold_spec(3);
        let mut fold_writer = BlsDoryFoldArtifactWriter::create(&directory.0, fold_spec).unwrap();
        fold_writer
            .write_scalars(&[BlsDoryFr::from_u64(7), BlsDoryFr::from_u64(11)])
            .unwrap();
        let fold = fold_writer.finish().unwrap();

        let compact_spec = compact_spec(7);
        let dictionary = (0..4).map(BlsDoryFr::from_u64).collect::<Vec<_>>();
        let mut compact_writer =
            BlsDoryCompactArtifactWriter::create(&directory.0, compact_spec, dictionary.clone())
                .unwrap();
        compact_writer.write_words(&[0; 16]).unwrap();
        compact_writer.write_codes(&[0; 8]).unwrap();
        let compact = compact_writer.finish().unwrap();
        let mut grouped_writer = BlsDoryGroupedCompactArtifactWriter::create(
            &directory.0,
            compact_spec,
            dictionary.clone(),
        )
        .unwrap();
        grouped_writer
            .write_cell_chunk(0, 4, &[0; 16], &[0; 8])
            .unwrap();
        let grouped = grouped_writer.finish().unwrap();

        let execution_context = BlsDoryExecutionAccumulatorArtifactContext::production(
            [11; 32], [12; 32], [13; 32], [14; 32],
        )
        .unwrap();
        let execution =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(&directory.0, execution_context)
                .unwrap();

        let logup_spec = logup_spec(15);
        let mut logup_writer =
            BlsDoryLogUpArtifactWriter::create(&directory.0, logup_spec).unwrap();
        logup_writer
            .write_regular_scalars(&vec![BlsDoryFr::one(); 8])
            .unwrap();
        logup_writer.write_range_codes(&[0; 12]).unwrap();
        let logup = logup_writer.finish().unwrap();

        let mut transpose_writer =
            BlsDoryWordTransposeWriter::create(&directory.0, 2, 2, 1).unwrap();
        transpose_writer.write_row(&[1, 2]).unwrap();
        transpose_writer.write_row(&[3, 4]).unwrap();
        let transpose = transpose_writer.finish().unwrap();

        let index_spec = BlsDoryIndexArtifactSpec {
            context_digest: [19; 32],
            scalar_count: 2,
            explicit_scalar_count: 2,
            literal_scalar_count: 1,
        };
        let mut index_writer = BlsDoryIndexArtifactWriter::create(
            &directory.0,
            index_spec,
            vec![BlsDoryFr::zero(), BlsDoryFr::one()],
        )
        .unwrap();
        index_writer.write_scalars(&[BlsDoryFr::one()]).unwrap();
        index_writer.write_codes(&[0]).unwrap();
        let index = index_writer.finish().unwrap();

        let observed_live_bytes = directory_logical_bytes(&directory.0);
        drop((fold, compact, grouped, execution, logup, transpose, index));
        let snapshot = session.finish_and_remove_root().unwrap();
        assert_eq!(snapshot.peak_logical_bytes, observed_live_bytes);
        assert_eq!(snapshot.peak_live_entries, 7);
        assert_eq!(snapshot.file_creation_events, 7);
        assert!(snapshot.size_mutation_events > 0);
        assert!(!directory.0.exists());
    }

    #[test]
    fn all_seven_incomplete_writers_discard_buffers_and_cleanup() {
        let directory = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&directory.0).unwrap();
        let fold = BlsDoryFoldArtifactWriter::create(&directory.0, fold_spec(21)).unwrap();
        let compact_spec = compact_spec(23);
        let dictionary = (0..4).map(BlsDoryFr::from_u64).collect::<Vec<_>>();
        let compact =
            BlsDoryCompactArtifactWriter::create(&directory.0, compact_spec, dictionary.clone())
                .unwrap();
        let grouped =
            BlsDoryGroupedCompactArtifactWriter::create(&directory.0, compact_spec, dictionary)
                .unwrap();
        let execution_context = BlsDoryExecutionAccumulatorArtifactContext::for_test(
            [[0x31; 32], [0x32; 32], [0x33; 32], [0x34; 32]],
            2,
            4,
            2,
            2,
            4,
        )
        .unwrap();
        let execution =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(&directory.0, execution_context)
                .unwrap();
        let logup = BlsDoryLogUpArtifactWriter::create(&directory.0, logup_spec(25)).unwrap();
        let transpose = BlsDoryWordTransposeWriter::create(&directory.0, 2, 2, 1).unwrap();
        let index_spec = BlsDoryIndexArtifactSpec {
            context_digest: [27; 32],
            scalar_count: 2,
            explicit_scalar_count: 2,
            literal_scalar_count: 1,
        };
        let index = BlsDoryIndexArtifactWriter::create(
            &directory.0,
            index_spec,
            vec![BlsDoryFr::zero(), BlsDoryFr::one()],
        )
        .unwrap();

        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 7);
        drop((fold, compact, grouped, execution, logup, transpose, index));
        let snapshot = session.finish_and_remove_root().unwrap();
        assert_eq!(snapshot.peak_live_entries, 7);
        assert_eq!(snapshot.file_creation_events, 7);
        assert!(snapshot.peak_logical_bytes > 0);
        assert!(snapshot.size_mutation_events > 0);
        assert!(!directory.0.exists());
    }

    #[test]
    fn instrumentation_preserves_all_seven_writer_byte_streams() {
        let untracked = TestDirectory::create();
        let expected = seven_writer_fixture_bytes(&untracked.0);
        assert_eq!(fs::read_dir(&untracked.0).unwrap().count(), 0);

        let tracked = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&tracked.0).unwrap();
        let actual = seven_writer_fixture_bytes(&tracked.0);
        let snapshot = session.finish_and_remove_root().unwrap();
        assert_eq!(actual, expected);
        assert_eq!(snapshot.file_creation_events, 7);
        assert!(snapshot.peak_logical_bytes > 0);
        assert!(!tracked.0.exists());
    }

    #[test]
    fn concurrent_growth_records_the_real_overlap() {
        let directory = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&directory.0).unwrap();
        let first = TrackedScratchFile::create_new(&directory.0.join("first")).unwrap();
        let second = TrackedScratchFile::create_new(&directory.0.join("second")).unwrap();
        let grown = Arc::new(Barrier::new(3));
        let release = Arc::new(Barrier::new(3));
        std::thread::scope(|scope| {
            for (mut file, bytes) in [(first, 100), (second, 70)] {
                let grown = Arc::clone(&grown);
                let release = Arc::clone(&release);
                scope.spawn(move || {
                    file.set_len(bytes).unwrap();
                    grown.wait();
                    release.wait();
                    file.remove_if_owned().unwrap();
                });
            }
            grown.wait();
            assert_eq!(directory_logical_bytes(&directory.0), 170);
            release.wait();
        });
        let snapshot = session.finish_and_remove_root().unwrap();
        assert_eq!(snapshot.peak_logical_bytes, 170);
        assert_eq!(snapshot.peak_live_entries, 2);
    }

    #[test]
    fn concurrent_disjoint_sessions_keep_exact_peaks_isolated() {
        let left = TestDirectory::create();
        let right = TestDirectory::create();
        let barrier = Arc::new(Barrier::new(2));
        let (left_snapshot, right_snapshot) = std::thread::scope(|scope| {
            let left_barrier = Arc::clone(&barrier);
            let left_path = left.0.clone();
            let left_handle = scope.spawn(move || {
                let mut session = ExactScratchReservationSession::start(&left_path).unwrap();
                let mut file = TrackedScratchFile::create_new(&left_path.join("left")).unwrap();
                file.set_len(101).unwrap();
                left_barrier.wait();
                file.remove_if_owned().unwrap();
                session.finish_and_remove_root().unwrap()
            });
            let right_barrier = Arc::clone(&barrier);
            let right_path = right.0.clone();
            let right_handle = scope.spawn(move || {
                let mut session = ExactScratchReservationSession::start(&right_path).unwrap();
                let mut file = TrackedScratchFile::create_new(&right_path.join("right")).unwrap();
                file.set_len(73).unwrap();
                right_barrier.wait();
                file.remove_if_owned().unwrap();
                session.finish_and_remove_root().unwrap()
            });
            (left_handle.join().unwrap(), right_handle.join().unwrap())
        });

        assert_eq!(left_snapshot.peak_logical_bytes, 101);
        assert_eq!(right_snapshot.peak_logical_bytes, 73);
        for snapshot in [left_snapshot, right_snapshot] {
            assert_eq!(snapshot.peak_live_entries, 1);
            assert_eq!(snapshot.file_creation_events, 1);
            assert_eq!(snapshot.size_mutation_events, 1);
        }
    }

    #[test]
    fn finalization_keeps_closed_tombstone_until_root_removal_and_rejects_reentry() {
        let directory = TestDirectory::create();
        let root = directory.0.clone();
        let root_key = canonical_directory(&root).unwrap();
        let session = ExactScratchReservationSession::start(&root).unwrap();
        let closed = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let attempting = Arc::new(Barrier::new(2));

        let (snapshot, repeated, late_create) = std::thread::scope(|scope| {
            let closed_for_finish = Arc::clone(&closed);
            let release_for_finish = Arc::clone(&release);
            let finalizer = scope.spawn(move || {
                let mut session = session;
                let snapshot = session.finish_and_remove_root_inner(|| {
                    closed_for_finish.wait();
                    release_for_finish.wait();
                });
                let repeated = session.finish_and_remove_root();
                (snapshot, repeated)
            });

            closed.wait();
            assert!(root.is_dir());
            assert!(
                lock_registry()
                    .get(&root_key)
                    .and_then(Weak::upgrade)
                    .is_some()
            );
            let attempting_for_create = Arc::clone(&attempting);
            let root_for_create = root.clone();
            let creator = scope.spawn(move || {
                attempting_for_create.wait();
                TrackedScratchFile::create_new(&root_for_create.join("late"))
            });
            attempting.wait();
            release.wait();
            let (snapshot, repeated) = finalizer.join().unwrap();
            (snapshot, repeated, creator.join().unwrap())
        });

        assert!(snapshot.is_ok());
        assert!(repeated.is_err());
        assert!(late_create.is_err());
        assert!(!root.exists());
        assert!(!lock_registry().contains_key(&root_key));
    }

    #[test]
    fn writer_in_an_unrelated_directory_is_not_counted() {
        let tracked = TestDirectory::create();
        let unrelated = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&tracked.0).unwrap();
        let tracked_spec = fold_spec(41);
        let unrelated_spec = fold_spec(51);
        let tracked_writer = BlsDoryFoldArtifactWriter::create(&tracked.0, tracked_spec).unwrap();
        let unrelated_writer =
            BlsDoryFoldArtifactWriter::create(&unrelated.0, unrelated_spec).unwrap();
        drop(unrelated_writer);
        drop(tracked_writer);
        let snapshot = session.finish_and_remove_root().unwrap();
        assert_eq!(snapshot.peak_logical_bytes, 0);
        assert_eq!(snapshot.peak_live_entries, 1);
        assert_eq!(snapshot.file_creation_events, 1);
        assert!(!tracked.0.exists());
        assert_eq!(fs::read_dir(&unrelated.0).unwrap().count(), 0);
    }

    #[test]
    fn replacement_cleanup_failure_poison_and_overflow_fail_closed() {
        let replacement_directory = TestDirectory::create();
        let mut replacement_session =
            ExactScratchReservationSession::start(&replacement_directory.0).unwrap();
        let original_path = replacement_directory.0.join("original");
        let replacement_path = replacement_directory.0.join("replacement");
        fs::write(&replacement_path, b"preserve").unwrap();
        let mut file = TrackedScratchFile::create_new(&original_path).unwrap();
        file.path = replacement_path.clone();
        assert!(file.remove_if_owned().is_err());
        assert_eq!(fs::read(&replacement_path).unwrap(), b"preserve");
        file.path = original_path;
        let _ = file.remove_if_owned();
        assert!(replacement_session.finish_and_remove_root().is_err());

        let missing_directory = TestDirectory::create();
        let mut missing_session =
            ExactScratchReservationSession::start(&missing_directory.0).unwrap();
        let original_path = missing_directory.0.join("original");
        let mut file = TrackedScratchFile::create_new(&original_path).unwrap();
        file.path = missing_directory.0.join("missing");
        assert!(file.remove_if_owned().is_err());
        assert!(original_path.is_file());
        file.path = original_path;
        let _ = file.remove_if_owned();
        assert!(missing_session.finish_and_remove_root().is_err());

        let token_overflow_directory = TestDirectory::create();
        let mut token_overflow_session =
            ExactScratchReservationSession::start(&token_overflow_directory.0).unwrap();
        lock_state(&token_overflow_session.state).next_token_id = u64::MAX;
        let token_overflow_path = token_overflow_directory.0.join("token-overflow");
        assert!(TrackedScratchFile::create_new(&token_overflow_path).is_err());
        assert!(!token_overflow_path.exists());
        assert!(token_overflow_session.finish_and_remove_root().is_err());

        let overflow_directory = TestDirectory::create();
        let mut overflow_session =
            ExactScratchReservationSession::start(&overflow_directory.0).unwrap();
        let mut file =
            TrackedScratchFile::create_new(&overflow_directory.0.join("overflow")).unwrap();
        let state = Arc::clone(&file.token.as_ref().unwrap().state);
        lock_state(&state).current_logical_bytes = u64::MAX;
        assert!(file.write_all(&[1]).is_err());
        let _ = file.remove_if_owned();
        assert!(overflow_session.finish_and_remove_root().is_err());
    }

    #[test]
    fn external_length_change_makes_bufwriter_flush_and_session_fail_closed() {
        let directory = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&directory.0).unwrap();
        let path = directory.0.join("buffer-error");
        let file = TrackedScratchFile::create_new(&path).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(1)
            .unwrap();
        let mut writer = BufWriter::with_capacity(8, file);
        writer.write_all(&[4; 3]).unwrap();
        assert!(writer.flush().is_err());
        let (mut file, buffered) = writer.into_parts();
        assert_eq!(buffered.unwrap(), vec![4; 3]);
        let _ = file.remove_if_owned();
        assert!(session.finish_and_remove_root().is_err());
    }
}
