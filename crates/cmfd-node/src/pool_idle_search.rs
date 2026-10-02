//! Opt-in pool-owned search, through the ordinary certificate-pinned client.
//! No separate GPU process and no bypass of share accounting or block validation.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::pool::{
    PoolClient, PoolClientConfig, PoolClientEvent, PoolError, PoolJob, PoolWorkSearchResult,
    ProductionV4PoolShareVerifier,
};

pub struct PoolIdleSearchHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for PoolIdleSearchHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn_pool_idle_search(
    verifier: Arc<dyn ProductionV4PoolShareVerifier>,
    config: PoolClientConfig,
) -> Result<PoolIdleSearchHandle, PoolError> {
    if !verifier.supports_idle_search() {
        return Err(PoolError::InvalidMessage(
            "verifier has no coordinated idle search".to_owned(),
        ));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let task_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("pool-idle-search".to_owned())
        .spawn(move || {
            // Fail only this optional worker on error. Never restart the proof
            // service, steal another process's GPU, or retry an uncertain share.
            if let Err(error) = run(verifier.as_ref(), config, &task_stop) {
                eprintln!("POOL_IDLE_SEARCH_STOPPED {error}; proof service unchanged");
            }
        })?;
    Ok(PoolIdleSearchHandle {
        stop,
        thread: Some(thread),
    })
}

fn receive_job(client: &mut PoolClient) -> Result<(), PoolError> {
    match client.receive() {
        Ok(PoolClientEvent::Job(_)) => Ok(()),
        Ok(PoolClientEvent::ShareResult(_)) => Err(PoolError::InvalidMessage(
            "unsolicited idle-search share result".to_owned(),
        )),
        Err(PoolError::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn run(
    verifier: &dyn ProductionV4PoolShareVerifier,
    config: PoolClientConfig,
    stop: &AtomicBool,
) -> Result<(), PoolError> {
    let mut client = PoolClient::connect(config)?;
    run_session(verifier, &mut client, stop)
}

trait IdleClient {
    fn job(&self) -> PoolJob;
    fn origin(&self, job: &PoolJob) -> u64;
    fn progress(&mut self, completed: u64, micros: u64) -> Result<(), PoolError>;
    fn receive_job(&mut self) -> Result<(), PoolError>;
    fn submit(&mut self, job: [u8; 32], nonce: u64, stop: &AtomicBool) -> Result<bool, PoolError>;
}

impl IdleClient for PoolClient {
    fn job(&self) -> PoolJob {
        self.current_job().clone()
    }
    fn origin(&self, job: &PoolJob) -> u64 {
        self.initial_nonce_for_job(job)
    }
    fn progress(&mut self, completed: u64, micros: u64) -> Result<(), PoolError> {
        self.report_work_progress(completed, micros)
    }
    fn receive_job(&mut self) -> Result<(), PoolError> {
        receive_job(self)
    }
    fn submit(&mut self, job: [u8; 32], nonce: u64, stop: &AtomicBool) -> Result<bool, PoolError> {
        let Some(result) = self.submit_share_interruptible(job, nonce, stop)? else {
            return Ok(false);
        };
        eprintln!(
            "POOL_IDLE_SEARCH_SHARE accepted={} block_accepted={} code={}",
            result.accepted, result.block_accepted, result.code
        );
        Ok(true)
    }
}

fn run_session(
    verifier: &dyn ProductionV4PoolShareVerifier,
    client: &mut impl IdleClient,
    stop: &AtomicBool,
) -> Result<(), PoolError> {
    let mut current_job = None;
    let mut next_nonce = 0;
    let mut completed_work = 0_u64;
    let mut search_micros = 0_u64;
    let mut paused = false;
    while !stop.load(Ordering::Acquire) {
        let job = client.job();
        if current_job != Some(job.job_id) {
            next_nonce = client.origin(&job);
            current_job = Some(job.job_id);
        }
        let started = Instant::now();
        let Some(result) = verifier.idle_search(&job, next_nonce, stop)? else {
            if !paused {
                eprintln!("POOL_IDLE_SEARCH_PAUSED verification has priority");
            }
            paused = true;
            client.receive_job()?;
            continue;
        };
        if paused {
            eprintln!("POOL_IDLE_SEARCH_RESUMED");
        }
        paused = false;
        let (completed, following) = match &result {
            PoolWorkSearchResult::Found {
                attempts_completed,
                next_nonce,
                ..
            }
            | PoolWorkSearchResult::Exhausted {
                attempts_completed,
                next_nonce,
            }
            | PoolWorkSearchResult::Cancelled {
                attempts_completed,
                next_nonce,
            } => (*attempts_completed, *next_nonce),
        };
        next_nonce = following;
        completed_work = completed_work.saturating_add(completed);
        search_micros = search_micros
            .saturating_add(started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
        if stop.load(Ordering::Acquire) {
            break;
        }
        client.progress(completed_work, search_micros)?;
        match result {
            PoolWorkSearchResult::Found { nonce, .. } => {
                // idle_search has returned and released the scheduling permit.
                // The server can now acquire it to verify our own submission.
                if !client.submit(job.job_id, nonce, stop)? {
                    break;
                }
            }
            PoolWorkSearchResult::Exhausted { .. } => client.receive_job()?,
            PoolWorkSearchResult::Cancelled { .. } => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockTemplate, pool::ProductionV4PoolShareEvaluation};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct ScriptedVerifier {
        steps: Mutex<VecDeque<Result<Option<PoolWorkSearchResult>, PoolError>>>,
        nonces: Mutex<Vec<u64>>,
    }
    impl ProductionV4PoolShareVerifier for ScriptedVerifier {
        fn evaluate(
            &self,
            _: &BlockTemplate,
            _: u64,
            _: [u8; 32],
        ) -> Result<ProductionV4PoolShareEvaluation, PoolError> {
            panic!("the client must not bypass normal server submission");
        }
        fn idle_search(
            &self,
            _: &PoolJob,
            nonce: u64,
            _: &AtomicBool,
        ) -> Result<Option<PoolWorkSearchResult>, PoolError> {
            self.nonces.lock().unwrap().push(nonce);
            self.steps
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra search")
        }
    }
    struct Client {
        job: PoolJob,
        submitted: Vec<([u8; 32], u64)>,
        completed: Vec<u64>,
        fail_submit: bool,
    }
    impl IdleClient for Client {
        fn job(&self) -> PoolJob {
            self.job.clone()
        }
        fn origin(&self, job: &PoolJob) -> u64 {
            u64::from(job.job_id[0]) * 1000
        }
        fn progress(&mut self, completed: u64, _: u64) -> Result<(), PoolError> {
            self.completed.push(completed);
            Ok(())
        }
        fn receive_job(&mut self) -> Result<(), PoolError> {
            self.job.job_id = [2; 32];
            Ok(())
        }
        fn submit(&mut self, job: [u8; 32], nonce: u64, _: &AtomicBool) -> Result<bool, PoolError> {
            self.submitted.push((job, nonce));
            if self.fail_submit {
                Err(PoolError::ConnectionClosed)
            } else {
                Ok(true)
            }
        }
    }
    fn client() -> Client {
        Client {
            job: PoolJob {
                job_id: [1; 32],
                challenge: cmfd_consensus::BlockChallenge {
                    network_id: [3; 32],
                    previous_block: [0; 32],
                    transaction_root: [0; 32],
                    height: 1,
                    timestamp: 1,
                    target: [0; 32],
                },
                share_target: [255; 32],
            },
            submitted: vec![],
            completed: vec![],
            fail_submit: false,
        }
    }
    fn found() -> Result<Option<PoolWorkSearchResult>, PoolError> {
        Ok(Some(PoolWorkSearchResult::Found {
            nonce: 2001,
            work_digest: [0; 32],
            meets_chain_target: true,
            attempts_completed: 2,
            next_nonce: 2002,
        }))
    }
    #[test]
    fn yield_refreshes_job_and_resume_preserves_nonce_progress() {
        let verifier = ScriptedVerifier {
            steps: Mutex::new(VecDeque::from([
                Ok(None),
                found(),
                Ok(Some(PoolWorkSearchResult::Cancelled {
                    attempts_completed: 0,
                    next_nonce: 2002,
                })),
            ])),
            nonces: Mutex::new(vec![]),
        };
        let mut client = client();
        run_session(&verifier, &mut client, &AtomicBool::new(false)).unwrap();
        assert_eq!(*verifier.nonces.lock().unwrap(), vec![1000, 2000, 2002]);
        assert_eq!(client.submitted, vec![([2; 32], 2001)]);
        assert_eq!(client.completed, vec![2, 2]);
    }
    #[test]
    fn uncertain_submission_stops_without_retry() {
        let verifier = ScriptedVerifier {
            steps: Mutex::new(VecDeque::from([found()])),
            nonces: Mutex::new(vec![]),
        };
        let mut client = client();
        client.fail_submit = true;
        assert!(run_session(&verifier, &mut client, &AtomicBool::new(false)).is_err());
        assert_eq!(client.submitted.len(), 1);
        assert_eq!(verifier.nonces.lock().unwrap().len(), 1);
    }
    #[test]
    fn stopped_client_does_no_work() {
        let verifier = ScriptedVerifier {
            steps: Mutex::new(VecDeque::new()),
            nonces: Mutex::new(vec![]),
        };
        let mut client = client();
        run_session(&verifier, &mut client, &AtomicBool::new(true)).unwrap();
        assert!(client.submitted.is_empty());
        assert!(verifier.nonces.lock().unwrap().is_empty());
    }
}
