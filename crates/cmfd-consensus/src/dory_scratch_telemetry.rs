//! Runner-scoped accounting for declared Dory scratch-artifact reservations.
//!
//! The qualification runner owns one new scratch directory. While its session
//! is active, every production Dory artifact writer registers the artifact's
//! exact final logical byte count after `create_new` succeeds and releases the
//! same reservation only after same-file-identity cleanup succeeds. The high
//! water mark is therefore exact for declared live artifact reservations. It
//! is deliberately not described as physical filesystem allocation or RAM.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock, Weak},
};

#[cfg(any(feature = "whir-prototype", test))]
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg(any(feature = "whir-prototype", test))]
pub(crate) struct ExactScratchReservationSnapshot {
    pub(crate) peak_reserved_logical_bytes: u64,
    pub(crate) peak_live_artifacts: u64,
    pub(crate) reservation_events: u64,
}

#[derive(Default)]
struct ReservationState {
    active: HashMap<PathBuf, u64>,
    current_reserved_logical_bytes: u64,
    peak_reserved_logical_bytes: u64,
    peak_live_artifacts: u64,
    reservation_events: u64,
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

/// One exact-reservation session for a runner-owned scratch directory.
#[cfg(any(feature = "whir-prototype", test))]
pub(crate) struct ExactScratchReservationSession {
    root: PathBuf,
    state: Arc<Mutex<ReservationState>>,
    finished: bool,
}

#[cfg(any(feature = "whir-prototype", test))]
impl ExactScratchReservationSession {
    pub(crate) fn start(root: &Path) -> io::Result<Self> {
        let root = canonical_directory(root)?;
        let state = Arc::new(Mutex::new(ReservationState::default()));
        let mut registry = lock_registry();
        registry.retain(|_, state| state.strong_count() != 0);
        if registry.contains_key(&root) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "scratch instrumentation session already exists for this directory",
            ));
        }
        registry.insert(root.clone(), Arc::downgrade(&state));
        Ok(Self {
            root,
            state,
            finished: false,
        })
    }

    pub(crate) fn finish(&mut self) -> io::Result<ExactScratchReservationSnapshot> {
        let snapshot = {
            let mut state = lock_state(&self.state);
            state.closed = true;
            if let Some(message) = &state.invariant_error {
                return Err(io::Error::other(message.clone()));
            }
            if !state.active.is_empty() || state.current_reserved_logical_bytes != 0 {
                return Err(io::Error::other(format!(
                    "scratch instrumentation retained {} reservations and {} logical bytes",
                    state.active.len(),
                    state.current_reserved_logical_bytes
                )));
            }
            ExactScratchReservationSnapshot {
                peak_reserved_logical_bytes: state.peak_reserved_logical_bytes,
                peak_live_artifacts: state.peak_live_artifacts,
                reservation_events: state.reservation_events,
            }
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
            self.unregister();
        }
    }
}

/// Register the exact declared final logical size of one newly created file.
///
/// Outside an active qualification session this is a no-op. Inside a session,
/// overflow, duplicate paths, and registration after closure fail the writer.
pub(crate) fn register_scratch_artifact_reservation(
    path: &Path,
    reserved_logical_bytes: u64,
) -> io::Result<()> {
    if lock_registry().is_empty() {
        return Ok(());
    }
    if reserved_logical_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scratch artifact reservation must be nonzero",
        ));
    }
    let (root, key) = canonical_file_key(path)?;
    let state = {
        let registry = lock_registry();
        registry.get(&root).and_then(Weak::upgrade)
    };
    let Some(state) = state else {
        return Ok(());
    };
    let mut state = lock_state(&state);
    if state.closed {
        return Err(io::Error::other(
            "scratch artifact registered after instrumentation closed",
        ));
    }
    if let Some(message) = &state.invariant_error {
        return Err(io::Error::other(message.clone()));
    }
    if state.active.contains_key(&key) {
        let message = format!("duplicate scratch artifact reservation: {}", key.display());
        state.invariant_error = Some(message.clone());
        return Err(io::Error::other(message));
    }
    let next_bytes = state
        .current_reserved_logical_bytes
        .checked_add(reserved_logical_bytes)
        .ok_or_else(|| {
            let message = "scratch artifact reservation byte count overflow".to_owned();
            state.invariant_error = Some(message.clone());
            io::Error::other(message)
        })?;
    let next_events = state.reservation_events.checked_add(1).ok_or_else(|| {
        let message = "scratch artifact reservation event count overflow".to_owned();
        state.invariant_error = Some(message.clone());
        io::Error::other(message)
    })?;
    let next_entries = u64::try_from(state.active.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            let message = "scratch artifact live count overflow".to_owned();
            state.invariant_error = Some(message.clone());
            io::Error::other(message)
        })?;
    state.active.insert(key, reserved_logical_bytes);
    state.current_reserved_logical_bytes = next_bytes;
    state.peak_reserved_logical_bytes = state.peak_reserved_logical_bytes.max(next_bytes);
    state.peak_live_artifacts = state.peak_live_artifacts.max(next_entries);
    state.reservation_events = next_events;
    Ok(())
}

/// Release a reservation after same-file-identity removal succeeds.
///
/// Drop paths cannot return an error, so any invariant failure is retained in
/// the session and makes `finish` fail before qualification output publication.
pub(crate) fn release_scratch_artifact_reservation(path: &Path) {
    if lock_registry().is_empty() {
        return;
    }
    let Ok((root, key)) = canonical_file_key(path) else {
        return;
    };
    let state = {
        let registry = lock_registry();
        registry.get(&root).and_then(Weak::upgrade)
    };
    let Some(state) = state else {
        return;
    };
    let mut state = lock_state(&state);
    if state.invariant_error.is_some() {
        return;
    }
    let Some(bytes) = state.active.remove(&key) else {
        state.invariant_error = Some(format!(
            "released unregistered scratch artifact: {}",
            key.display()
        ));
        return;
    };
    let Some(current) = state.current_reserved_logical_bytes.checked_sub(bytes) else {
        state.invariant_error = Some("scratch artifact reservation underflow".to_owned());
        return;
    };
    state.current_reserved_logical_bytes = current;
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
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
        },
        dory_bls12_381_fold_artifact::{BlsDoryFoldArtifactSpec, BlsDoryFoldArtifactWriter},
        dory_bls12_381_logup_artifact::{BlsDoryLogUpArtifactSpec, BlsDoryLogUpArtifactWriter},
        dory_bls12_381_prototype::BlsDoryFr,
        dory_bls12_381_transpose::{
            BlsDoryWordTransposeWriter, projected_bls_dory_transpose_artifact_bytes,
        },
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

    fn create_and_register(root: &Path, name: &str, bytes: u64) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, []).unwrap();
        register_scratch_artifact_reservation(&path, bytes).unwrap();
        path
    }

    fn remove_and_release(path: &Path) {
        fs::remove_file(path).unwrap();
        release_scratch_artifact_reservation(path);
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

    #[test]
    fn exact_reservations_track_overlap_without_sampling() {
        let directory = TestDirectory::create();
        let mut session = ExactScratchReservationSession::start(&directory.0).unwrap();
        let first = create_and_register(&directory.0, "first", 100);
        let second = create_and_register(&directory.0, "second", 70);
        remove_and_release(&first);
        let third = create_and_register(&directory.0, "third", 90);
        remove_and_release(&second);
        remove_and_release(&third);

        assert_eq!(
            session.finish().unwrap(),
            ExactScratchReservationSnapshot {
                peak_reserved_logical_bytes: 170,
                peak_live_artifacts: 2,
                reservation_events: 3,
            }
        );
    }

    #[test]
    fn duplicate_and_unbalanced_reservations_fail_closed() {
        let directory = TestDirectory::create();
        let mut duplicate = ExactScratchReservationSession::start(&directory.0).unwrap();
        let path = create_and_register(&directory.0, "duplicate", 10);
        assert!(register_scratch_artifact_reservation(&path, 10).is_err());
        remove_and_release(&path);
        assert!(duplicate.finish().is_err());
        drop(duplicate);

        let mut unbalanced = ExactScratchReservationSession::start(&directory.0).unwrap();
        let retained = create_and_register(&directory.0, "retained", 20);
        assert!(unbalanced.finish().is_err());
        fs::remove_file(retained).unwrap();
    }

    #[test]
    fn all_six_writer_classes_share_one_exact_reservation_peak() {
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
        let compact =
            BlsDoryCompactArtifactWriter::create(&directory.0, compact_spec, dictionary.clone())
                .unwrap();
        let grouped = BlsDoryGroupedCompactArtifactWriter::create(
            &directory.0,
            compact_spec,
            dictionary.clone(),
        )
        .unwrap();

        let execution_context = BlsDoryExecutionAccumulatorArtifactContext::production(
            [11; 32], [12; 32], [13; 32], [14; 32],
        )
        .unwrap();
        let execution =
            BlsDoryExecutionAccumulatorArtifactWriter::create_new(&directory.0, execution_context)
                .unwrap();

        let logup_spec = logup_spec(15);
        let logup = BlsDoryLogUpArtifactWriter::create(&directory.0, logup_spec).unwrap();

        let mut transpose_writer =
            BlsDoryWordTransposeWriter::create(&directory.0, 2, 2, 1).unwrap();
        transpose_writer.write_row(&[1, 2]).unwrap();
        transpose_writer.write_row(&[3, 4]).unwrap();
        let transpose = transpose_writer.finish().unwrap();

        let expected_fold = fold_spec.encoded_bytes().unwrap();
        let expected_compact = compact_spec.encoded_bytes(dictionary.len()).unwrap();
        let expected_execution = execution_context.projected_file_bytes().unwrap();
        let expected_logup = logup_spec.encoded_bytes().unwrap();
        let expected_transpose = projected_bls_dory_transpose_artifact_bytes(2, 2).unwrap();
        drop((fold, compact, grouped, execution, logup, transpose));
        assert_eq!(
            session.finish().unwrap(),
            ExactScratchReservationSnapshot {
                peak_reserved_logical_bytes: expected_fold
                    + expected_compact * 2
                    + expected_execution
                    + expected_logup
                    + expected_transpose,
                peak_live_artifacts: 6,
                reservation_events: 6,
            }
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
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
                let spec = fold_spec(21);
                let writer = BlsDoryFoldArtifactWriter::create(&left_path, spec).unwrap();
                left_barrier.wait();
                drop(writer);
                (session.finish().unwrap(), spec.encoded_bytes().unwrap())
            });
            let right_barrier = Arc::clone(&barrier);
            let right_path = right.0.clone();
            let right_handle = scope.spawn(move || {
                let mut session = ExactScratchReservationSession::start(&right_path).unwrap();
                let spec = fold_spec(31);
                let writer = BlsDoryFoldArtifactWriter::create(&right_path, spec).unwrap();
                right_barrier.wait();
                drop(writer);
                (session.finish().unwrap(), spec.encoded_bytes().unwrap())
            });
            (left_handle.join().unwrap(), right_handle.join().unwrap())
        });
        for (snapshot, expected_bytes) in [left_snapshot, right_snapshot] {
            assert_eq!(
                snapshot,
                ExactScratchReservationSnapshot {
                    peak_reserved_logical_bytes: expected_bytes,
                    peak_live_artifacts: 1,
                    reservation_events: 1,
                }
            );
        }
        assert_eq!(fs::read_dir(&left.0).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&right.0).unwrap().count(), 0);
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
        assert_eq!(
            session.finish().unwrap(),
            ExactScratchReservationSnapshot {
                peak_reserved_logical_bytes: tracked_spec.encoded_bytes().unwrap(),
                peak_live_artifacts: 1,
                reservation_events: 1,
            }
        );
        assert_eq!(fs::read_dir(&tracked.0).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&unrelated.0).unwrap().count(), 0);
    }
}
