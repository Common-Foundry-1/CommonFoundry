use cmfd_node::NodeClientError;
use cmfd_node::startup_progress::{self, Phase, Progress};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(crate) struct StartupState(Mutex<State>);
struct State {
    progress: Progress,
    started: Instant,
    changed: Instant,
    active: bool,
    error: Option<NodeClientError>,
}

#[derive(serde::Serialize)]
pub(crate) struct StartupStatus {
    #[serde(flatten)]
    progress: Progress,
    elapsed_seconds: u64,
    seconds_since_progress: u64,
    active: bool,
    error: Option<NodeClientError>,
    available_disk_bytes: Option<u64>,
}

impl Default for StartupState {
    fn default() -> Self {
        Self(Mutex::new(State {
            progress: Progress {
                phase: Phase::WaitingForUnlock,
                completed: 0,
                total: None,
            },
            started: Instant::now(),
            changed: Instant::now(),
            active: false,
            error: None,
        }))
    }
}

impl StartupState {
    /// Independent of the node and custody locks: polling stays responsive
    /// while unlock is blocked in a long proof verification.
    pub(crate) fn snapshot(&self, data_dir: Option<&Path>) -> StartupStatus {
        let available_disk_bytes = data_dir.and_then(|path| fs2::available_space(path).ok());
        let state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        StartupStatus {
            progress: state.progress,
            elapsed_seconds: state.started.elapsed().as_secs(),
            seconds_since_progress: state.changed.elapsed().as_secs(),
            active: state.active,
            error: state.error.clone(),
            available_disk_bytes,
        }
    }

    pub(crate) fn run<T>(
        self: &Arc<Self>,
        operation: impl FnOnce() -> Result<T, NodeClientError>,
    ) -> Result<T, NodeClientError> {
        {
            let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            *state = State {
                progress: Progress {
                    phase: Phase::CheckingInputs,
                    completed: 0,
                    total: None,
                },
                started: Instant::now(),
                changed: Instant::now(),
                active: true,
                error: None,
            };
        }
        let output = Arc::clone(self);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            startup_progress::observe(Arc::new(move |progress| {
                let mut state = output.0.lock().unwrap_or_else(|error| error.into_inner());
                state.progress = progress;
                state.changed = Instant::now();
            }), operation)
        })).unwrap_or_else(|_| Err(super::startup_error("node_startup_panicked", "Wallet startup stopped unexpectedly. Keep your wallet data and backups. Reopen the wallet and check its logs if this repeats.", true)));
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.active = false;
        state.progress = Progress {
            phase: match &result {
                Ok(_) => Phase::Ready,
                Err(error) if error.code == "wallet_locked" => Phase::WaitingForUnlock,
                Err(_) => Phase::Failed,
            },
            completed: 0,
            total: None,
        };
        state.error = result
            .as_ref()
            .err()
            .filter(|error| error.code != "wallet_locked")
            .cloned();
        state.changed = Instant::now();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_can_be_read_while_startup_is_blocked() {
        let state = Arc::new(StartupState::default());
        let output = Arc::clone(&state);
        let (send, receive) = std::sync::mpsc::channel();
        let (resume, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            output.run(|| {
                startup_progress::report(Phase::CheckingProofs, 7, Some(20));
                send.send(()).unwrap();
                wait.recv().unwrap();
                Ok(())
            })
        });
        receive
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let progress = state.snapshot(None);
        assert_eq!(progress.progress.completed, 7);
        assert!(progress.active);
        resume.send(()).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(state.snapshot(None).progress.phase, Phase::Ready);
    }
    #[test]
    fn failures_are_visible_and_a_new_attempt_resets_them() {
        let state = Arc::new(StartupState::default());
        let _: Result<(), _> = state.run(|| {
            Err(super::super::startup_error(
                "disk_full",
                "Free disk space",
                true,
            ))
        });
        assert_eq!(state.snapshot(None).progress.phase, Phase::Failed);
        assert_eq!(state.snapshot(None).error.unwrap().code, "disk_full");
        state.run(|| Ok(())).unwrap();
        assert!(state.snapshot(None).error.is_none());
    }
}
