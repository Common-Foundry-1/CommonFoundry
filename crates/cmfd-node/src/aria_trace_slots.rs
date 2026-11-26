use cmfd_consensus::forgematrix_v4_execution::aria_v4_cpu::trace_section::Writer;
use std::{io, sync::Mutex};

/// One trace may be proving while the other is filled by share replay.
/// Leases are retained across retries and returned on every exit path.
#[derive(Debug)]
pub(super) struct TraceSlots {
    idle: Mutex<Vec<(usize, Writer)>>,
    returned: std::sync::Condvar,
}
impl TraceSlots {
    pub(super) fn new() -> io::Result<(Self, String)> {
        let mut slots = Vec::with_capacity(2);
        let mut names = Vec::with_capacity(2);
        for index in 0..2 {
            let mut id = [0u8; 16];
            getrandom::fill(&mut id).map_err(|e| io::Error::other(e.to_string()))?;
            let writer = Writer::create(id)?;
            names.push(writer.name().to_owned());
            slots.push((index, writer));
        }
        Ok((
            Self {
                idle: Mutex::new(slots),
                returned: std::sync::Condvar::new(),
            },
            names.join(","),
        ))
    }
    pub(super) fn take(&self) -> io::Result<TraceLease<'_>> {
        let idle = self
            .idle
            .lock()
            .map_err(|_| io::Error::other("CPU trace slots poisoned"))?;
        let mut idle = self
            .returned
            .wait_while(idle, |s| s.is_empty())
            .map_err(|_| io::Error::other("CPU trace slots poisoned"))?;
        Ok(TraceLease {
            pool: self,
            slot: idle.pop(),
        })
    }
}
pub(super) struct TraceLease<'a> {
    pool: &'a TraceSlots,
    slot: Option<(usize, Writer)>,
}
impl TraceLease<'_> {
    pub(super) fn index(&self) -> usize {
        self.slot.as_ref().expect("live trace lease").0
    }
    pub(super) fn columns_mut(&mut self) -> (&mut [u32], &mut [u32]) {
        // Only a leased slot can be written. Its immutable proof command starts
        // after replay joins all writers and holds this lease until DONE.
        unsafe {
            self.slot
                .as_mut()
                .expect("live trace lease")
                .1
                .columns_mut()
        }
    }
}
impl Drop for TraceLease<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            self.pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(slot);
            self.pool.returned.notify_one();
        }
    }
}

#[cfg(test)]
#[test]
fn trace_lease_is_exclusive_and_visible_to_the_worker() {
    use cmfd_consensus::forgematrix_v4_execution::aria_v4_cpu::trace_section::Reader;
    let (pool, names) = TraceSlots::new().unwrap();
    let names: Vec<_> = names.split(',').collect();
    let mut proving = pool.take().unwrap();
    let replaying = pool.take().unwrap();
    assert_ne!(proving.index(), replaying.index());
    let reader = Reader::open(names[proving.index()]).unwrap();
    {
        let (pre, act) = proving.columns_mut();
        pre[0] = 37;
        *act.last_mut().unwrap() = 19;
    }
    // The proving lease remains live and immutable while the worker reads.
    let (pre, act) = unsafe { reader.columns() };
    assert_eq!((pre[0], *act.last().unwrap()), (37, 19));
    let returned = replaying.index();
    drop(replaying);
    assert_eq!(pool.take().unwrap().index(), returned);
}
