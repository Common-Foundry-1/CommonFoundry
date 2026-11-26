//! CPU placement for the opt-in native Windows 9950X3D pool profile.
use std::{
    io,
    os::windows::io::{AsHandle, AsRawHandle, OwnedHandle},
    process::Child,
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, WAIT_OBJECT_0},
    System::{
        SystemInformation::{GetLogicalProcessorInformation, RelationProcessorCore, SYSTEM_LOGICAL_PROCESSOR_INFORMATION},
        Threading::{GetCurrentProcess, GetCurrentThread, GetProcessAffinityMask, SetProcessAffinityMask, SetThreadAffinityMask, WaitForSingleObject},
    },
};

#[derive(Debug)]
pub(super) struct Placement {
    replay: usize,
    proving_during_replay: usize,
    all: usize,
    state: Mutex<State>,
}

#[derive(Default, Debug)]
struct State {
    child: Option<OwnedHandle>,
    replays: usize,
}

fn masks(mut cores: Vec<usize>, allowed: usize) -> io::Result<(usize, usize)> {
    cores.sort_unstable_by_key(|mask| mask.trailing_zeros());
    let mut seen = 0;
    let mut replay = 0;
    let mut proving = 0;
    if cores.len() != 16 {
        return Err(io::Error::other("9950X3D profile needs sixteen physical cores"));
    }
    for (i, core) in cores.into_iter().enumerate() {
        if core.count_ones() != 2 || seen & core != 0 {
            return Err(io::Error::other("9950X3D profile needs two distinct SMT siblings per core"));
        }
        seen |= core;
        if i < 14 { replay |= core & core.wrapping_neg(); } else { proving |= core; }
    }
    if allowed != seen {
        return Err(io::Error::other("9950X3D profile needs all 32 logical CPUs available"));
    }
    Ok((replay, proving))
}

fn process_mask(handle: HANDLE) -> io::Result<usize> {
    let (mut process, mut system) = (0, 0);
    if unsafe { GetProcessAffinityMask(handle, &mut process, &mut system) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(process)
}

fn apply(state: &mut State, mask: usize) -> io::Result<()> {
    if let Some(child) = &state.child {
        let handle = child.as_raw_handle();
        if unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0 {
            state.child = None;
            return Ok(());
        }
        if unsafe { SetProcessAffinityMask(handle, mask) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if process_mask(handle)? != mask {
            return Err(io::Error::other("CPU prover affinity readback mismatch"));
        }
    }
    Ok(())
}

impl Placement {
    pub(super) fn discover() -> io::Result<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut brand = Vec::new();
            for leaf in 0x8000_0002..=0x8000_0004 {
                let b = std::arch::x86_64::__cpuid(leaf);
                for part in [b.eax,b.ebx,b.ecx,b.edx] { brand.extend_from_slice(&part.to_le_bytes()); }
            }
            if !String::from_utf8_lossy(&brand).contains("9950X3D") {
                return Err(io::Error::other("this profile is qualified for the Ryzen 9 9950X3D"));
            }
        }
        let mut bytes = 0;
        let _ = unsafe { GetLogicalProcessorInformation(std::ptr::null_mut(), &mut bytes) };
        if bytes == 0 || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(io::Error::last_os_error());
        }
        let size = std::mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>();
        let mut info = vec![SYSTEM_LOGICAL_PROCESSOR_INFORMATION::default(); (bytes as usize).div_ceil(size)];
        if unsafe { GetLogicalProcessorInformation(info.as_mut_ptr(), &mut bytes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let cores = info[..bytes as usize / size].iter()
            .filter(|entry| entry.Relationship == RelationProcessorCore)
            .map(|entry| entry.ProcessorMask).collect();
        let all = process_mask(unsafe { GetCurrentProcess() })?;
        let (replay, proving_during_replay) = masks(cores, all)?;
        Ok(Self { replay, proving_during_replay, all, state: Mutex::default() })
    }

    pub(super) fn attach(&self, child: &Child) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| io::Error::other("CPU placement lock poisoned"))?;
        state.child = Some(child.as_handle().try_clone_to_owned()?);
        let mask = if state.replays == 0 { self.all } else { self.proving_during_replay };
        apply(&mut state, mask)
    }

    pub(super) fn begin(&self) -> io::Result<ReplayGuard<'_>> {
        let mut state = self.state.lock().map_err(|_| io::Error::other("CPU placement lock poisoned"))?;
        if state.replays == 0 { apply(&mut state, self.proving_during_replay)?; }
        state.replays += 1;
        Ok(ReplayGuard(Some(self)))
    }

    pub(super) fn place_replay_thread(&self) -> io::Result<()> {
        if unsafe { SetThreadAffinityMask(GetCurrentThread(), self.replay) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(super) struct ReplayGuard<'a>(Option<&'a Placement>);

impl ReplayGuard<'_> {
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if let Some(placement) = self.0.take() {
            let mut state = placement.state.lock().map_err(|_| io::Error::other("CPU placement lock poisoned"))?;
            state.replays -= 1;
            if state.replays == 0 { apply(&mut state, placement.all)?; }
        }
        Ok(())
    }
}

impl Drop for ReplayGuard<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.finish() { tracing::error!(%error, "restoring CPU prover affinity failed"); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_uses_one_sibling_per_replay_core_and_two_whole_prover_cores() {
        let cores: Vec<usize> = (0..16).rev().map(|i| 3usize << (2*i)).collect();
        let all = u32::MAX as usize;
        assert_eq!(masks(cores.clone(),all).unwrap(),(0x0555_5555,0xf000_0000));
        assert!(masks(cores,all ^ 1).is_err());
        assert!(masks(vec![3;16],all).is_err());
    }
}
