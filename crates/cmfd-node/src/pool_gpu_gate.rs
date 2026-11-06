//! Pool-local scheduling only. No consensus or network protocol decisions.
//! Queued verification always precedes a new optional search batch.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

#[derive(Debug, Default)]
pub(crate) struct PoolGpuGate {
    work: Mutex<()>,
    priority: AtomicUsize,
    search_disabled: AtomicBool,
}

pub(crate) struct VerificationPermit<'a> {
    gate: &'a PoolGpuGate,
    _work: MutexGuard<'a, ()>,
}

impl PoolGpuGate {
    pub(crate) fn verification(&self) -> Result<VerificationPermit<'_>, &'static str> {
        self.priority.fetch_add(1, Ordering::SeqCst);
        match self.work.lock() {
            Ok(work) => Ok(VerificationPermit {
                gate: self,
                _work: work,
            }),
            Err(_) => {
                self.priority.fetch_sub(1, Ordering::SeqCst);
                self.disable_search();
                Err("pool GPU scheduling lock is poisoned")
            }
        }
    }

    pub(crate) fn try_search(&self) -> Result<Option<MutexGuard<'_, ()>>, &'static str> {
        if self.search_disabled.load(Ordering::SeqCst) {
            return Err("pool idle search is disabled after a worker failure; restart required");
        }
        if self.priority.load(Ordering::SeqCst) != 0 {
            return Ok(None);
        }
        let work = match self.work.try_lock() {
            Ok(work) => work,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                self.disable_search();
                return Err("pool GPU scheduling lock is poisoned");
            }
        };
        // A verifier may have queued between the first check and try_lock.
        if self.priority.load(Ordering::SeqCst) != 0 {
            return Ok(None);
        }
        Ok(Some(work))
    }

    pub(crate) fn disable_search(&self) {
        self.search_disabled.store(true, Ordering::SeqCst);
    }
}

impl Drop for VerificationPermit<'_> {
    fn drop(&mut self) {
        self.gate.priority.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    #[test]
    fn verification_excludes_search_and_search_resumes() {
        let gate = PoolGpuGate::default();
        for _ in 0..100 {
            let verify = gate.verification().unwrap();
            assert!(gate.try_search().unwrap().is_none());
            drop(verify);
            assert!(gate.try_search().unwrap().is_some());
        }
    }

    #[test]
    fn remote_verifier_waits_for_current_batch_then_blocks_new_search() {
        let gate = Arc::new(PoolGpuGate::default());
        let batch = gate.try_search().unwrap().unwrap();
        let other = Arc::clone(&gate);
        let (tx, rx) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _verify = other.verification().unwrap();
            tx.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while gate.priority.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(rx.try_recv().is_err());
        assert!(gate.try_search().unwrap().is_none());
        drop(batch);
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(gate.try_search().unwrap().is_none());
        release.send(()).unwrap();
        thread.join().unwrap();
        assert!(gate.try_search().unwrap().is_some());
    }

    #[test]
    fn worker_failure_disables_optional_search_but_not_verification() {
        let gate = PoolGpuGate::default();
        gate.disable_search();
        assert!(gate.try_search().is_err());
        assert!(gate.verification().is_ok());
        assert!(gate.try_search().is_err());
    }

    #[test]
    fn all_queued_verifications_finish_before_search_resumes() {
        let gate = Arc::new(PoolGpuGate::default());
        let batch = gate.try_search().unwrap().unwrap();
        let (acquired, events) = mpsc::channel();
        let mut threads = Vec::new();
        let mut releases = Vec::new();
        for id in 0..2 {
            let gate = Arc::clone(&gate);
            let acquired = acquired.clone();
            let (release, wait) = mpsc::channel();
            releases.push(release);
            threads.push(std::thread::spawn(move || {
                let _verify = gate.verification().unwrap();
                acquired.send(id).unwrap();
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
            }));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while gate.priority.load(Ordering::SeqCst) != 2 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        drop(batch);
        let first = events.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(gate.try_search().unwrap().is_none());
        releases[first].send(()).unwrap();
        let second = events.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_ne!(first, second);
        assert!(gate.try_search().unwrap().is_none());
        releases[second].send(()).unwrap();
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(gate.try_search().unwrap().is_some());
    }

    #[test]
    fn releasing_local_search_allows_its_own_submission() {
        let gate = PoolGpuGate::default();
        {
            let _batch = gate.try_search().unwrap().unwrap();
            assert!(gate.try_search().unwrap().is_none());
        }
        let _own_submission = gate.verification().unwrap();
        assert!(gate.try_search().unwrap().is_none());
    }

    #[test]
    fn panic_fails_closed() {
        let gate = PoolGpuGate::default();
        let _ = std::panic::catch_unwind(|| {
            let _verify = gate.verification().unwrap();
            panic!("simulated worker panic");
        });
        assert_eq!(gate.priority.load(Ordering::SeqCst), 0);
        assert!(gate.try_search().is_err());
        assert!(gate.verification().is_err());
    }
}
