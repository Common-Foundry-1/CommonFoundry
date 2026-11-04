//! Optional, thread-scoped startup observations. They never authorize or skip
//! validation, and no observer or observer failure changes the node's result.
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    CheckingInputs,
    OpeningData,
    LoadingSnapshot,
    ScanningHistory,
    CheckingProofs,
    PreparingBalances,
    Connecting,
    Ready,
    WaitingForUnlock,
    Failed,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Progress {
    pub phase: Phase,
    pub completed: u64,
    pub total: Option<u64>,
}

pub type Observer = Arc<dyn Fn(Progress) + Send + Sync>;
thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
}

/// The observer is local to this startup thread, restored even after unwinding.
/// Concurrent nodes and later background verification do not share its state.
pub fn observe<T>(observer: Observer, operation: impl FnOnce() -> T) -> T {
    struct Restore(Option<Observer>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVER.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(OBSERVER.with(|slot| slot.replace(Some(observer))));
    operation()
}

pub fn report(phase: Phase, completed: u64, total: Option<u64>) {
    let observer = OBSERVER.with(|slot| slot.borrow().clone());
    if let Some(observer) = observer {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            observer(Progress {
                phase,
                completed,
                total,
            })
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn observations_are_scoped_and_do_not_escape_to_other_threads() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let output = Arc::clone(&seen);
        observe(
            Arc::new(move |event| output.lock().unwrap().push(event)),
            || {
                report(Phase::CheckingProofs, 1, Some(2));
                std::thread::spawn(|| report(Phase::CheckingProofs, 99, Some(99)))
                    .join()
                    .unwrap();
            },
        );
        report(Phase::Ready, 0, None);
        let events = seen.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].completed, 1);
    }

    #[test]
    fn observer_panics_do_not_change_the_operation_result() {
        assert_eq!(
            observe(Arc::new(|_| panic!("observer failed")), || {
                report(Phase::CheckingProofs, 1, Some(2));
                42
            }),
            42
        );
    }

    #[test]
    fn nested_observers_are_restored_after_an_unwind() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let output = Arc::clone(&seen);
        observe(
            Arc::new(move |event| output.lock().unwrap().push(event)),
            || {
                let _ = catch_unwind(|| observe(Arc::new(|_| {}), || panic!("startup failed")));
                report(Phase::Connecting, 0, None);
            },
        );
        assert_eq!(seen.lock().unwrap()[0].phase, Phase::Connecting);
    }
}
