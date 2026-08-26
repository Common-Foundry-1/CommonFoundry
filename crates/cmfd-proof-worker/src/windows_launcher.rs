//! Atomic Windows ProductionV3 worker launch.
//!
//! The process is created as a zero-capability LPAC with an explicit Job list
//! and an explicit four-handle inheritance list. It remains suspended until the
//! parent has verified the resulting token, mitigations, Job association, and
//! exact per-launch private executable object.

use std::{
    ffi::{OsStr, OsString, c_void},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::{MaybeUninit, size_of},
    os::windows::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::OpenOptionsExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
    path::{Path, PathBuf},
    process::Command,
    ptr,
    sync::Arc,
};

use sha2::{Digest, Sha256};

use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
        GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, LocalFree,
        SetHandleInformation,
    },
    NetworkManagement::WindowsFirewall::NetworkIsolationGetAppContainerConfig,
    Security::{
        Authorization::{
            EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
            SET_ACCESS, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
            TRUSTEE_IS_USER, TRUSTEE_W,
        },
        DACL_SECURITY_INFORMATION, EqualSid, FreeSid, GetTokenInformation, IsValidSid,
        Isolation::CreateAppContainerProfile,
        NO_INHERITANCE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
        SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_DUPLICATE, TOKEN_QUERY, TokenAppContainerSid,
        TokenCapabilities, TokenIsAppContainer,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_EXECUTE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_SEQUENTIAL_SCAN, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        GetFileInformationByHandle, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
    },
    System::{
        Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
        JobObjects::IsProcessInJob,
        Memory::{
            GetProcessHeap, HeapEnableTerminationOnCorruption, HeapFree, HeapQueryInformation,
        },
        Pipes::CreatePipe,
        SystemServices::{
            PROCESS_MITIGATION_ASLR_POLICY, PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
            PROCESS_MITIGATION_DEP_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
            PROCESS_MITIGATION_IMAGE_LOAD_POLICY, PROCESS_MITIGATION_SEHOP_POLICY,
            PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
            PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
        },
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
            GetProcessMitigationPolicy, InitializeProcThreadAttributeList, OpenProcessToken,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ProcessASLRPolicy,
            ProcessChildProcessPolicy, ProcessDEPPolicy, ProcessDynamicCodePolicy,
            ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSEHOPPolicy,
            ProcessStrictHandleCheckPolicy, ProcessSystemCallDisablePolicy,
            QueryFullProcessImageNameW, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
            UpdateProcThreadAttribute,
        },
        WindowsProgramming::{
            PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
            PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
            PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE,
            PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE,
        },
    },
};

use crate::{
    ContainedChild, ProcessTerminator, ProofWorkerError, WindowsJob,
    ensure_process_cleanup_healthy,
    process::{
        ManagedProcess, Win32Child, WindowsAppContainerProfile, WindowsAppContainerProfileIntent,
        WindowsFileIdentity, WindowsPrivateRuntime, appcontainer_cleanup_healthy,
        delete_exact_runtime_handle, mark_appcontainer_cleanup_unhealthy,
        retry_pending_appcontainer_profile_cleanup, windows_file_identity,
    },
    verifier::ProductionV3VerifierRecord,
    windows_artifacts::{WindowsArtifactHandleDescriptor, WindowsArtifactHandleError},
};

pub(crate) const WINDOWS_ARTIFACT_HANDLES_ARGUMENT: &str = "--production-v3-handles";

const ATTRIBUTE_COUNT: u32 = 6;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const PROFILE_ATTEMPTS: usize = 16;
const PRIVATE_RUNTIME_ATTEMPTS: usize = 16;

// These values are the documented PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
// DWORD64 flags. windows-sys exposes the low DEP/SEHOP values but not every
// shifted constant.
const MITIGATION_HEAP_TERMINATE: u64 = 0x0000_0000_0000_1000;
const MITIGATION_BOTTOM_UP_ASLR: u64 = 0x0000_0000_0001_0000;
const MITIGATION_HIGH_ENTROPY_ASLR: u64 = 0x0000_0000_0010_0000;
const MITIGATION_STRICT_HANDLE_CHECKS: u64 = 0x0000_0000_0100_0000;
const MITIGATION_WIN32K_DISABLE: u64 = 0x0000_0000_1000_0000;
const MITIGATION_EXTENSION_POINT_DISABLE: u64 = 0x0000_0001_0000_0000;
const MITIGATION_PROHIBIT_DYNAMIC_CODE: u64 = 0x0000_0010_0000_0000;
const MITIGATION_IMAGE_LOAD_NO_REMOTE: u64 = 0x0010_0000_0000_0000;
const MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32: u64 = 0x1000_0000_0000_0000;
const MITIGATION_POLICY: u64 = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE as u64
    | PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE as u64
    | MITIGATION_HEAP_TERMINATE
    | MITIGATION_BOTTOM_UP_ASLR
    | MITIGATION_HIGH_ENTROPY_ASLR
    | MITIGATION_STRICT_HANDLE_CHECKS
    | MITIGATION_WIN32K_DISABLE
    | MITIGATION_EXTENSION_POINT_DISABLE
    | MITIGATION_PROHIBIT_DYNAMIC_CODE
    | MITIGATION_IMAGE_LOAD_NO_REMOTE
    | MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32;

fn exact_production_child_handles(
    handles: [HANDLE; 4],
    additional_handles: &[HANDLE],
) -> Result<[HANDLE; 4], ProofWorkerError> {
    if !additional_handles.is_empty() {
        return Err(ProofWorkerError::InvalidConfig(
            "ProductionV3 inherits exactly stdio and one Record V2 handle",
        ));
    }
    for (index, handle) in handles.iter().enumerate() {
        if handle.is_null() || handles[..index].contains(handle) {
            return Err(ProofWorkerError::InvalidConfig(
                "ProductionV3 inherited handles must be non-null and distinct",
            ));
        }
    }
    Ok(handles)
}

struct LoopbackExemptionEntries {
    count: u32,
    entries: *mut SID_AND_ATTRIBUTES,
}

impl Drop for LoopbackExemptionEntries {
    fn drop(&mut self) {
        if self.entries.is_null() {
            return;
        }
        // SAFETY: NetworkIsolationGetAppContainerConfig allocates every SID
        // and the containing array from the current process heap.
        let heap = unsafe { GetProcessHeap() };
        if heap.is_null() {
            return;
        }
        // SAFETY: entries has count initialized elements owned by this guard.
        let entries = unsafe { std::slice::from_raw_parts(self.entries, self.count as usize) };
        for entry in entries {
            if !entry.Sid.is_null() {
                // SAFETY: each non-null SID is one process-heap allocation.
                let _ = unsafe { HeapFree(heap, 0, entry.Sid) };
            }
        }
        // SAFETY: the array itself is one process-heap allocation.
        let _ = unsafe { HeapFree(heap, 0, self.entries.cast()) };
    }
}

fn validate_profile_has_no_loopback_exemption(profile_sid: PSID) -> io::Result<()> {
    if profile_sid.is_null() || unsafe { IsValidSid(profile_sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the AppContainer profile SID is invalid",
        ));
    }
    let mut count = 0_u32;
    let mut entries = ptr::null_mut();
    // SAFETY: both outputs point to writable values with the documented layout.
    let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries) };
    if status != ERROR_SUCCESS {
        return Err(io_context(
            "querying CheckNetIsolation loopback exemptions",
            win32_status_error(status),
        ));
    }
    let exemptions = LoopbackExemptionEntries { count, entries };
    if count != 0 && exemptions.entries.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CheckNetIsolation returned a null exemption array",
        ));
    }
    if count == 0 {
        return Ok(());
    }
    // SAFETY: the successful API call returned count initialized entries.
    let entries = unsafe { std::slice::from_raw_parts(exemptions.entries, count as usize) };
    for entry in entries {
        if entry.Sid.is_null() || unsafe { IsValidSid(entry.Sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CheckNetIsolation returned an invalid exemption SID",
            ));
        }
        if unsafe { EqualSid(entry.Sid, profile_sid) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the exact AppContainer profile SID has a loopback exemption",
            ));
        }
    }
    Ok(())
}

pub(crate) fn spawn_contained_production_windows(
    command: Command,
    record: &ProductionV3VerifierRecord,
    memory_limit_bytes: u64,
    expected_worker_sha256: [u8; 32],
) -> Result<ContainedChild, ProofWorkerError> {
    spawn_contained_production_windows_inner(
        command,
        record,
        memory_limit_bytes,
        expected_worker_sha256,
        true,
        true,
        #[cfg(test)]
        None,
    )
    .map(|(child, _)| child)
}

fn spawn_contained_production_windows_inner(
    command: Command,
    record: &ProductionV3VerifierRecord,
    memory_limit_bytes: u64,
    expected_worker_sha256: [u8; 32],
    append_artifact_arguments: bool,
    less_privileged_appcontainer: bool,
    #[cfg(test)] mut pre_resume_probe: Option<&mut dyn FnMut(HANDLE) -> io::Result<()>>,
) -> Result<(ContainedChild, String), ProofWorkerError> {
    #[cfg(test)]
    let _appcontainer_test_lock = crate::process::CrossProcessAppContainerTestLock::acquire();
    ensure_process_cleanup_healthy()?;
    if !appcontainer_cleanup_healthy() {
        return Err(containment(
            "checking prior AppContainer cleanup health",
            io::Error::other(
                "a prior AppContainer profile or private runtime cleanup exhausted its bounded retries",
            ),
        ));
    }
    if memory_limit_bytes == 0 {
        return Err(ProofWorkerError::InvalidConfig(
            "ProductionV3 worker memory limit must be nonzero",
        ));
    }
    let program = command.get_program();
    if !Path::new(program).is_absolute() {
        return Err(ProofWorkerError::InvalidConfig(
            "ProductionV3 worker executable path must be absolute",
        ));
    }
    let current_directory = command
        .get_current_dir()
        .ok_or(ProofWorkerError::InvalidConfig(
            "ProductionV3 worker current directory must be explicit",
        ))?;
    if !current_directory.is_absolute() {
        return Err(ProofWorkerError::InvalidConfig(
            "ProductionV3 worker current directory must be absolute",
        ));
    }
    if command.get_envs().next().is_some() {
        return Err(ProofWorkerError::InvalidConfig(
            "ProductionV3 Win32 launcher does not accept environment entries",
        ));
    }

    let (parent_record, observed_record) = open_artifact("Record V2", &record.record_v2)?;
    if !observed_record.matches_file_identity(&record.expected_file) {
        return Err(ProofWorkerError::HashMismatch {
            component: "production V3 Record V2",
        });
    }
    let inherited_record =
        duplicate_inheritable(parent_record.as_raw_handle().cast()).map_err(|source| {
            containment(
                "duplicating the read-only ProductionV3 Record V2 handle",
                source,
            )
        })?;
    let inherited_descriptor =
        observed_record.for_inherited_handle(inherited_record.as_raw_handle() as usize);

    let stdin = PipePair::child_reads()
        .map_err(|source| containment("creating the bounded worker stdin pipe", source))?;
    let stdout = PipePair::child_writes()
        .map_err(|source| containment("creating the bounded worker stdout pipe", source))?;
    let stderr = PipePair::child_writes()
        .map_err(|source| containment("creating the bounded worker stderr pipe", source))?;

    let job = Arc::new(
        WindowsJob::create_with_process_limit(Some(memory_limit_bytes), Some(1))
            .map_err(|source| containment("creating the atomic ProductionV3 Job Object", source))?,
    );

    let mut arguments = command.get_args().map(OsString::from).collect::<Vec<_>>();
    let transport_argument = inherited_descriptor.transport_argument();
    if append_artifact_arguments {
        arguments.push(OsString::from(WINDOWS_ARTIFACT_HANDLES_ARGUMENT));
        arguments.push(OsString::from(&transport_argument));
    }
    // The loader requires SystemRoot, but every other ambient entry is
    // deliberately absent. Passing a null pointer would inherit the parent.
    let environment = ExplicitEnvironment::create()
        .map_err(|source| containment("constructing the minimal worker environment", source))?;
    let mut profile = CreatedProfile::create()
        .map_err(|source| containment("creating a zero-capability AppContainer profile", source))?;
    if let Err(source) = validate_profile_has_no_loopback_exemption(profile.sid()) {
        return Err(profile_containment(
            "attesting the exact AppContainer profile has no loopback exemption",
            source,
            &mut profile,
        ));
    }
    let private_runtime = match PrivateLaunchRuntime::create(
        Path::new(program),
        expected_worker_sha256,
        profile.sid(),
    ) {
        Ok(runtime) => runtime,
        Err(source) => {
            return Err(profile_containment(
                "creating the verified per-launch private runtime",
                source,
                &mut profile,
            ));
        }
    };
    let private_program = private_runtime.executable_path().as_os_str();
    let mut command_line = build_command_line(private_program, &arguments).map_err(|source| {
        profile_containment(
            "encoding the exact private worker command line",
            source,
            &mut profile,
        )
    })?;
    let application_name = nul_terminated(private_program).map_err(|source| {
        profile_containment(
            "encoding the private worker executable path",
            source,
            &mut profile,
        )
    })?;
    let current_directory_utf16 = nul_terminated(private_runtime.directory_path().as_os_str())
        .map_err(|source| {
            profile_containment(
                "encoding the private worker current directory",
                source,
                &mut profile,
            )
        })?;

    let child_handles = exact_production_child_handles(
        [
            stdin.child_raw(),
            stdout.child_raw(),
            stderr.child_raw(),
            inherited_record.as_raw_handle().cast(),
        ],
        &[],
    )?;
    let job_handles = [job.raw_handle()];
    let security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid(),
        Capabilities: ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let all_application_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    let child_process_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    let mitigation_policy = MITIGATION_POLICY;
    let attribute_count = if less_privileged_appcontainer {
        ATTRIBUTE_COUNT
    } else {
        ATTRIBUTE_COUNT - 1
    };
    let mut attributes = match AttributeList::new(attribute_count) {
        Ok(attributes) => attributes,
        Err(source) => {
            return Err(profile_containment(
                "allocating the STARTUPINFOEX attribute list",
                source,
                &mut profile,
            ));
        }
    };
    let configured_security = attributes.update_value(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &security_capabilities,
    );
    let configured_appcontainer = if less_privileged_appcontainer {
        configured_security.and_then(|()| {
            attributes.update_value(
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                &all_application_packages_policy,
            )
        })
    } else {
        configured_security
    };
    if let Err(source) = configured_appcontainer
        .and_then(|()| attributes.update_slice(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &child_handles))
        .and_then(|()| attributes.update_slice(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handles))
        .and_then(|()| {
            attributes.update_value(
                PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                &child_process_policy,
            )
        })
        .and_then(|()| {
            attributes.update_value(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation_policy)
        })
    {
        return Err(profile_containment(
            "configuring the STARTUPINFOEX isolation attributes",
            source,
            &mut profile,
        ));
    }

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.child_raw();
    startup.StartupInfo.hStdOutput = stdout.child_raw();
    startup.StartupInfo.hStdError = stderr.child_raw();
    startup.lpAttributeList = attributes.as_ptr();
    let mut process_information = MaybeUninit::<PROCESS_INFORMATION>::uninit();
    let creation_flags = EXTENDED_STARTUPINFO_PRESENT
        | CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | CREATE_NO_WINDOW;

    if let Err(source) = private_runtime.verify_bound() {
        return Err(profile_containment(
            "validating the pinned private runtime objects before launch",
            source,
            &mut profile,
        ));
    }

    // SAFETY: every pointer targets a live buffer with the documented layout.
    // The mutable command line is singly NUL-terminated; the explicit handle
    // list contains only inheritable, non-pseudo handles.
    let created = unsafe {
        CreateProcessW(
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            creation_flags,
            environment.as_ptr(),
            current_directory_utf16.as_ptr(),
            &startup.StartupInfo,
            process_information.as_mut_ptr(),
        )
    };
    if created == 0 {
        let launch_error = io::Error::last_os_error();
        return Err(profile_containment(
            "creating the suspended LPAC worker",
            launch_error,
            &mut profile,
        ));
    }
    // SAFETY: successful CreateProcessW initialized both owned handles.
    let process_information = unsafe { process_information.assume_init() };
    // SAFETY: both handles are fresh owned handles returned above.
    let process = unsafe { OwnedHandle::from_raw_handle(process_information.hProcess.cast()) };
    let thread = unsafe { OwnedHandle::from_raw_handle(process_information.hThread.cast()) };

    #[cfg(test)]
    if let Some(probe) = pre_resume_probe.as_mut()
        && let Err(source) = probe(process.as_raw_handle().cast())
    {
        return Err(cleanup_failed_post_create_launch(
            "running the suspended-child inherited-handle probe",
            source,
            job,
            process,
            thread,
            profile,
            private_runtime,
        ));
    }

    if let Err(source) = validate_process_sandbox(
        process.as_raw_handle().cast(),
        job.raw_handle(),
        Some(profile.sid()),
    )
    .and_then(|()| private_runtime.verify_bound())
    .and_then(|()| private_runtime.verify_process_image(process.as_raw_handle().cast()))
    {
        return Err(cleanup_failed_post_create_launch(
            "validating the suspended LPAC worker token, mitigations, and exact image object",
            source,
            job,
            process,
            thread,
            profile,
            private_runtime,
        ));
    }

    // SAFETY: the primary thread remains live and suspended. Exactly one
    // CREATE_SUSPENDED count must be removed; any other state fails closed.
    let previous_suspend_count = unsafe { ResumeThread(thread.as_raw_handle().cast()) };
    if previous_suspend_count != 1 {
        let source = if previous_suspend_count == u32::MAX {
            io::Error::last_os_error()
        } else {
            io::Error::other(format!(
                "unexpected primary-thread suspend count {previous_suspend_count}"
            ))
        };
        return Err(cleanup_failed_post_create_launch(
            "resuming the isolated worker",
            source,
            job,
            process,
            thread,
            profile,
            private_runtime,
        ));
    }
    if process_information.dwProcessId == 0 {
        return Err(cleanup_failed_post_create_launch(
            "owning the native LPAC worker process",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CreateProcessW returned a zero process identifier",
            ),
            job,
            process,
            thread,
            profile,
            private_runtime,
        ));
    }
    drop(thread);

    let profile = profile.take_registration();
    let private_runtime = private_runtime.into_process_runtime();
    let child = Win32Child::new(
        process,
        process_information.dwProcessId,
        Some(profile),
        Some(private_runtime),
        Some(Box::new(File::from(stdin.into_parent()))),
        Some(Box::new(File::from(stdout.into_parent()))),
        Some(Box::new(File::from(stderr.into_parent()))),
    )
    .expect("the nonzero CreateProcessW process identifier was validated above");
    Ok((
        ContainedChild::new(
            ManagedProcess::from_win32(child),
            ProcessTerminator::job(job),
        ),
        transport_argument,
    ))
}

pub(crate) fn validate_current_process_sandbox() -> Result<(), String> {
    validate_heap_termination_enabled().map_err(|error| error.to_string())?;
    // SAFETY: GetCurrentProcess returns a process-local pseudo handle that must
    // not be closed. No expected SID is needed for the worker's self-check.
    validate_process_sandbox(unsafe { GetCurrentProcess() }, ptr::null_mut(), None)
        .map_err(|error| error.to_string())
}

fn validate_heap_termination_enabled() -> io::Result<()> {
    validate_heap_termination_query(|| {
        // Heap mitigation state is process-local: the parent cannot query a
        // child's heap handle. The child performs this check before reading
        // artifact contents or IPC.
        let heap = unsafe { GetProcessHeap() };
        if heap.is_null() {
            return Err(io_context(
                "querying the process heap for terminate-on-corruption",
                io::Error::last_os_error(),
            ));
        }
        let mut enabled = 0_u32;
        let mut returned = 0_usize;
        // SAFETY: `heap` is this process's live default heap and both outputs
        // have the documented ULONG/size layouts for this information class.
        if unsafe {
            HeapQueryInformation(
                heap,
                HeapEnableTerminationOnCorruption,
                ptr::from_mut(&mut enabled).cast(),
                size_of::<u32>(),
                &mut returned,
            )
        } == 0
        {
            return Err(io_context(
                "querying HeapEnableTerminationOnCorruption",
                io::Error::last_os_error(),
            ));
        }
        if returned != size_of::<u32>() {
            return Err(io::Error::other(format!(
                "HeapEnableTerminationOnCorruption returned {returned} bytes; expected {}",
                size_of::<u32>()
            )));
        }
        Ok(enabled)
    })
}

fn validate_heap_termination_query(mut query: impl FnMut() -> io::Result<u32>) -> io::Result<()> {
    let enabled = query()?;
    if enabled != 1 {
        return Err(io::Error::other(format!(
            "worker heap terminate-on-corruption state is {enabled}; expected exactly 1"
        )));
    }
    Ok(())
}

fn open_artifact(
    artifact: &'static str,
    path: &Path,
) -> Result<(File, WindowsArtifactHandleDescriptor), ProofWorkerError> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
        .map_err(|source| {
            containment("opening a retained read-only ProductionV3 artifact", source)
        })?;
    let descriptor = WindowsArtifactHandleDescriptor::observe_parent_content(artifact, &mut file)
        .map_err(|source| {
        artifact_error(
            "authenticating a retained ProductionV3 artifact handle",
            source,
        )
    })?;
    Ok((file, descriptor))
}

fn artifact_error(operation: &'static str, error: WindowsArtifactHandleError) -> ProofWorkerError {
    containment(operation, io::Error::other(error.to_string()))
}

fn containment(operation: &'static str, source: io::Error) -> ProofWorkerError {
    ProofWorkerError::Containment { operation, source }
}

fn profile_containment(
    operation: &'static str,
    source: io::Error,
    profile: &mut CreatedProfile,
) -> ProofWorkerError {
    let cleanup = profile.delete_registration();
    containment(operation, first_error(source, cleanup, Ok(())))
}

fn first_error(
    primary: io::Error,
    first_cleanup: io::Result<()>,
    second_cleanup: io::Result<()>,
) -> io::Error {
    match (first_cleanup, second_cleanup) {
        (Ok(()), Ok(())) => primary,
        (first, second) => {
            io::Error::other(format!("{primary}; cleanup results: {first:?}, {second:?}"))
        }
    }
}

fn duplicate_inheritable(source: HANDLE) -> io::Result<OwnedHandle> {
    // SAFETY: the current-process pseudo handle is valid for both source and
    // target process parameters and must not be closed.
    let current = unsafe { GetCurrentProcess() };
    let mut duplicate = ptr::null_mut();
    // SAFETY: source is an owned live artifact handle. DUPLICATE_SAME_ACCESS
    // preserves its read-only access mask and the duplicate is inheritable.
    if unsafe {
        DuplicateHandle(
            current,
            source,
            current,
            &mut duplicate,
            0,
            1,
            windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: DuplicateHandle returned one fresh owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate.cast()) })
}

struct SystemEnvironmentBlock(*mut c_void);

impl SystemEnvironmentBlock {
    fn create() -> io::Result<Self> {
        let mut token = ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut token,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
        let mut block = ptr::null_mut();
        // SAFETY: bInherit=FALSE asks Userenv for a fresh block from the
        // loaded user/system profiles, not a copy of the caller environment.
        if unsafe { CreateEnvironmentBlock(&mut block, token.as_raw_handle().cast(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if block.is_null() {
            return Err(io::Error::other(
                "CreateEnvironmentBlock returned a null block",
            ));
        }
        Ok(Self(block))
    }
}

impl Drop for SystemEnvironmentBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: CreateEnvironmentBlock returned this allocation.
            unsafe { DestroyEnvironmentBlock(self.0) };
        }
    }
}

pub(crate) const ENVIRONMENT_ALLOWLIST: [&str; 6] = [
    "LOCALAPPDATA",
    "SystemDrive",
    "SystemRoot",
    "TEMP",
    "TMP",
    "windir",
];
const ENVIRONMENT_SCAN_LIMIT: usize = 1024 * 1024;

struct ExplicitEnvironment(Vec<u16>);

impl ExplicitEnvironment {
    fn create() -> io::Result<Self> {
        let source = SystemEnvironmentBlock::create()?;
        let mut entries = Vec::with_capacity(ENVIRONMENT_ALLOWLIST.len());
        let mut found = [false; ENVIRONMENT_ALLOWLIST.len()];
        let mut offset = 0_usize;
        loop {
            if offset >= ENVIRONMENT_SCAN_LIMIT {
                return Err(io::Error::other(
                    "environment source exceeds the scan bound",
                ));
            }
            // SAFETY: CreateEnvironmentBlock returns a double-NUL-terminated
            // UTF-16 block. The scan bound prevents unbounded traversal if the
            // platform violates that contract.
            if unsafe { *source.0.cast::<u16>().add(offset) } == 0 {
                break;
            }
            let start = offset;
            while offset < ENVIRONMENT_SCAN_LIMIT
                && unsafe { *source.0.cast::<u16>().add(offset) } != 0
            {
                offset += 1;
            }
            if offset == ENVIRONMENT_SCAN_LIMIT {
                return Err(io::Error::other(
                    "environment source entry is not NUL-terminated",
                ));
            }
            // SAFETY: start..offset was bounded by the terminator scan above.
            let entry = unsafe {
                std::slice::from_raw_parts(source.0.cast::<u16>().add(start), offset - start)
            };
            offset += 1;
            let Some(separator) = entry.iter().position(|unit| *unit == b'=' as u16) else {
                return Err(io::Error::other(
                    "environment source contains an entry without a name separator",
                ));
            };
            if separator == 0 {
                continue;
            }
            let Ok(name) = String::from_utf16(&entry[..separator]) else {
                continue;
            };
            let Some(index) = ENVIRONMENT_ALLOWLIST
                .iter()
                .position(|allowed| name.eq_ignore_ascii_case(allowed))
            else {
                continue;
            };
            if found[index] {
                return Err(io::Error::other(format!(
                    "environment source contains duplicate {} entries",
                    ENVIRONMENT_ALLOWLIST[index]
                )));
            }
            found[index] = true;
            let mut filtered = ENVIRONMENT_ALLOWLIST[index]
                .encode_utf16()
                .collect::<Vec<_>>();
            filtered.push(b'=' as u16);
            filtered.extend_from_slice(&entry[separator + 1..]);
            entries.push((ENVIRONMENT_ALLOWLIST[index], filtered));
        }
        if let Some((index, _)) = found.iter().enumerate().find(|(_, present)| !**present) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "required Windows environment source {} is absent",
                    ENVIRONMENT_ALLOWLIST[index]
                ),
            ));
        }
        entries.sort_by(|left, right| {
            left.0
                .to_ascii_uppercase()
                .cmp(&right.0.to_ascii_uppercase())
        });
        let mut block = Vec::new();
        for (_, entry) in entries {
            block.extend(entry);
            block.push(0);
        }
        block.push(0);
        Ok(Self(block))
    }

    fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr().cast()
    }
}

pub(crate) fn validate_current_worker_environment() -> Result<(), String> {
    let environment = std::env::vars_os().collect::<Vec<_>>();
    if environment.len() != ENVIRONMENT_ALLOWLIST.len() {
        return Err(format!(
            "Windows ProductionV3 worker environment contains {} entries instead of {}",
            environment.len(),
            ENVIRONMENT_ALLOWLIST.len()
        ));
    }
    let mut seen = [false; ENVIRONMENT_ALLOWLIST.len()];
    for (name, value) in environment {
        let Some(name) = name.to_str() else {
            return Err("Windows ProductionV3 worker environment name is not Unicode".to_owned());
        };
        let Some(index) = ENVIRONMENT_ALLOWLIST
            .iter()
            .position(|allowed| name.eq_ignore_ascii_case(allowed))
        else {
            return Err(format!(
                "Windows ProductionV3 worker environment contains disallowed entry {name}"
            ));
        };
        if seen[index] {
            return Err(format!(
                "Windows ProductionV3 worker environment duplicates {}",
                ENVIRONMENT_ALLOWLIST[index]
            ));
        }
        if value.is_empty() {
            return Err(format!(
                "Windows ProductionV3 worker environment entry {} is empty",
                ENVIRONMENT_ALLOWLIST[index]
            ));
        }
        seen[index] = true;
    }
    if seen.iter().all(|present| *present) {
        Ok(())
    } else {
        Err("Windows ProductionV3 worker environment is missing an allowlisted entry".to_owned())
    }
}

struct PipePair {
    parent: OwnedHandle,
    child: OwnedHandle,
}

impl PipePair {
    fn child_reads() -> io::Result<Self> {
        let (read, write) = create_inheritable_pipe()?;
        clear_inherit(write.as_raw_handle().cast())?;
        Ok(Self {
            parent: write,
            child: read,
        })
    }

    fn child_writes() -> io::Result<Self> {
        let (read, write) = create_inheritable_pipe()?;
        clear_inherit(read.as_raw_handle().cast())?;
        Ok(Self {
            parent: read,
            child: write,
        })
    }

    fn child_raw(&self) -> HANDLE {
        self.child.as_raw_handle().cast()
    }

    fn into_parent(self) -> OwnedHandle {
        self.parent
    }
}

fn create_inheritable_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    // SAFETY: outputs are writable and the security attributes have the exact
    // layout. A successful call returns two fresh owned handles.
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, PIPE_BUFFER_BYTES) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read.cast()),
            OwnedHandle::from_raw_handle(write.cast()),
        )
    })
}

fn clear_inherit(handle: HANDLE) -> io::Result<()> {
    // SAFETY: handle is live and owned by the caller. The mask clears only its
    // inheritance flag, leaving all access rights unchanged.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct AttributeList {
    storage: Vec<usize>,
}

impl AttributeList {
    fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0_usize;
        // SAFETY: the first null call is the documented size query.
        let initialized =
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut bytes) };
        if initialized != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        {
            return Err(io::Error::last_os_error());
        }
        if bytes == 0 {
            return Err(io::Error::other(
                "Windows returned an empty process attribute list size",
            ));
        }
        let mut storage = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: usize storage is suitably aligned and contains at least the
        // byte count returned by the size query.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), count, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { storage })
    }

    fn as_ptr(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }

    fn update_value<T>(&mut self, attribute: u32, value: &T) -> io::Result<()> {
        self.update_raw(attribute, ptr::from_ref(value).cast(), size_of::<T>())
    }

    fn update_slice<T>(&mut self, attribute: u32, values: &[T]) -> io::Result<()> {
        let bytes = values
            .len()
            .checked_mul(size_of::<T>())
            .ok_or_else(|| io::Error::other("process attribute byte length overflow"))?;
        self.update_raw(attribute, values.as_ptr().cast(), bytes)
    }

    fn update_raw(&mut self, attribute: u32, value: *const c_void, bytes: usize) -> io::Result<()> {
        // SAFETY: the initialized list and pointed-to value both remain live
        // through CreateProcessW.
        if unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                attribute as usize,
                value,
                bytes,
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: this list was initialized successfully and has not yet been
        // deleted.
        unsafe { DeleteProcThreadAttributeList(self.storage.as_mut_ptr().cast()) };
    }
}

struct OwnedSid(PSID);

impl OwnedSid {
    fn new(sid: PSID) -> Self {
        Self(sid)
    }

    fn as_ptr(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: CreateAppContainerProfile allocated this SID and its
            // documentation requires FreeSid.
            unsafe { FreeSid(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

pub(crate) struct CreatedProfile {
    registration: Option<WindowsAppContainerProfile>,
    sid: OwnedSid,
}

impl CreatedProfile {
    fn create() -> io::Result<Self> {
        retry_pending_appcontainer_profile_cleanup()?;
        let display = nul_terminated(OsStr::new("Common Foundry verifier"))?;
        let description = nul_terminated(OsStr::new("Ephemeral ProductionV3 verifier LPAC"))?;
        for _ in 0..PROFILE_ATTEMPTS {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
            let name = format!(
                "CMFD.Verifier.{}.{}",
                std::process::id(),
                hex::encode(random)
            );
            let name = nul_terminated(OsStr::new(&name))?;
            if let Some(created) = try_create_profile(name, &display, &description)? {
                return Ok(created);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique AppContainer profile",
        ))
    }

    fn sid(&self) -> PSID {
        self.sid.as_ptr()
    }

    pub(crate) fn take_registration(&mut self) -> WindowsAppContainerProfile {
        self.registration
            .take()
            .expect("AppContainer profile guard is transferred exactly once")
    }

    pub(crate) fn delete_registration(&mut self) -> io::Result<()> {
        let Some(registration) = &mut self.registration else {
            return Ok(());
        };
        registration.delete()?;
        self.registration = None;
        Ok(())
    }
}

fn try_create_profile(
    name: Vec<u16>,
    display: &[u16],
    description: &[u16],
) -> io::Result<Option<CreatedProfile>> {
    let mut intent = WindowsAppContainerProfileIntent::begin(name.clone())?;
    let mut raw_sid = ptr::null_mut();
    // SAFETY: all strings are live, singly NUL-terminated UTF-16;
    // capabilities are explicitly empty and the SID output is writable.
    let status = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            description.as_ptr(),
            ptr::null(),
            0,
            &mut raw_sid,
        )
    };
    let sid = OwnedSid::new(raw_sid);
    if status >= 0 {
        // Successful profile creation is wrapped before any validation,
        // assertion, or fallible operation. Unwinding from every later point
        // runs bounded registration deletion and releases the returned SID.
        let mut created = CreatedProfile {
            registration: Some(intent.commit()),
            sid,
        };
        if created.sid().is_null() || unsafe { IsValidSid(created.sid()) } == 0 {
            let cleanup = created.delete_registration();
            return Err(io::Error::other(format!(
                "CreateAppContainerProfile returned an invalid SID; cleanup={cleanup:?}"
            )));
        }
        return Ok(Some(created));
    }
    if status == hresult_from_win32(ERROR_ALREADY_EXISTS) {
        // Defensive only: the documented collision path does not transfer a
        // SID. `sid` still releases any unexpected allocation, while no
        // registration guard is created or adopted.
        intent.cancel()?;
        return Ok(None);
    }
    let primary = hresult_error(status);
    let cleanup = intent.cancel();
    Err(io::Error::new(
        primary.kind(),
        format!("{primary}; profile-intent cleanup={cleanup:?}"),
    ))
}

#[cfg(test)]
pub(crate) fn try_create_owned_test_profile(
    name: Vec<u16>,
    display: &[u16],
    description: &[u16],
) -> io::Result<Option<CreatedProfile>> {
    try_create_profile(name, display, description)
}

#[cfg(test)]
pub(crate) fn try_create_untracked_test_profile(
    name: Vec<u16>,
    display: &[u16],
    description: &[u16],
) -> io::Result<Option<CreatedProfile>> {
    let mut raw_sid = ptr::null_mut();
    // SAFETY: all strings are live, singly NUL-terminated UTF-16;
    // capabilities are explicitly empty and the SID output is writable.
    let status = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            description.as_ptr(),
            ptr::null(),
            0,
            &mut raw_sid,
        )
    };
    let sid = OwnedSid::new(raw_sid);
    if status >= 0 {
        // This infallible construction is the first successful-path action.
        let mut created = CreatedProfile {
            registration: Some(WindowsAppContainerProfile::own_raw_created_for_test(name)),
            sid,
        };
        if created.sid().is_null() || unsafe { IsValidSid(created.sid()) } == 0 {
            let cleanup = created.delete_registration();
            return Err(io::Error::other(format!(
                "CreateAppContainerProfile returned an invalid test SID; cleanup={cleanup:?}"
            )));
        }
        return Ok(Some(created));
    }
    if status == hresult_from_win32(ERROR_ALREADY_EXISTS) {
        return Ok(None);
    }
    Err(hresult_error(status))
}

impl Drop for CreatedProfile {
    fn drop(&mut self) {
        if let Some(registration) = &mut self.registration
            && registration.delete().is_err()
        {
            // Drop cannot return an error. Preserve the exact registration
            // guard for its own final retry and fail closed for later launches.
            mark_appcontainer_cleanup_unhealthy();
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: security APIs allocate these buffers with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct PrivateLaunchRuntime {
    source: Option<File>,
    directory_handle: Option<File>,
    executable_handle: Option<File>,
    source_path: PathBuf,
    directory_path: PathBuf,
    executable_path: PathBuf,
    source_identity: WindowsFileIdentity,
    directory_identity: WindowsFileIdentity,
    executable_identity: WindowsFileIdentity,
    transferred: bool,
}

impl PrivateLaunchRuntime {
    fn create(source_path: &Path, expected_sha256: [u8; 32], sid: PSID) -> io::Result<Self> {
        let source = OpenOptions::new()
            .read(true)
            // No write or delete sharing: the exact configured object cannot
            // be modified or replaced from the first byte copied until the
            // contained process has exited.
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
            .open(source_path)?;
        let source_information = regular_single_link_information(&source, "source executable")?;
        let source_identity = windows_file_identity(&source)?;
        verify_runtime_path_identity(source_path, false, source_identity)?;

        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
        let extension = source_path
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or("");
        let mut directory_path = None;
        for attempt in 0..PRIVATE_RUNTIME_ATTEMPTS {
            let candidate = std::env::temp_dir().join(format!(
                "cmfd-verifier-launch-{}-{attempt}",
                hex::encode(random)
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    directory_path = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let directory_path = directory_path.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique private launch directory",
            )
        })?;
        let filename = if extension.is_empty() {
            "verifier-runtime".to_owned()
        } else {
            format!("verifier-runtime.{extension}")
        };
        let executable_path = directory_path.join(filename);
        let mut cleanup_directory_handle: Option<File> = None;
        let mut cleanup_executable_handle: Option<File> = None;
        let mut cleanup_directory_identity = None;
        let mut cleanup_executable_identity = None;

        let result = (|| {
            cleanup_directory_handle = Some(
                OpenOptions::new()
                    .access_mode(
                        DELETE | READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    )
                    .share_mode(FILE_SHARE_READ)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                    .open(&directory_path)?,
            );
            let directory_handle = cleanup_directory_handle
                .as_ref()
                .expect("the newly opened directory cleanup handle is retained");
            let directory_information = file_information(directory_handle)?;
            if directory_information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || directory_information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || directory_information.nNumberOfLinks != 1
            {
                return Err(io::Error::other(
                    "private launch directory is not a regular single-link non-reparse directory",
                ));
            }
            let directory_identity = windows_file_identity(directory_handle)?;
            cleanup_directory_identity = Some(directory_identity);

            cleanup_executable_handle = Some(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .access_mode(DELETE | GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
                    .create_new(true)
                    .share_mode(FILE_SHARE_READ)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
                    .open(&executable_path)?,
            );
            let executable_handle = cleanup_executable_handle
                .as_mut()
                .expect("the newly created executable cleanup handle is retained");
            regular_single_link_information(executable_handle, "destination executable")?;
            cleanup_executable_identity = Some(windows_file_identity(executable_handle)?);
            let mut source_reader = source.try_clone()?;
            source_reader.seek(SeekFrom::Start(0))?;
            let source_length = source_information.nFileSizeLow as u64
                | (u64::from(source_information.nFileSizeHigh) << 32);
            if source_length == 0 {
                return Err(io::Error::other("source executable is empty"));
            }
            let mut source_hash = Sha256::new();
            let mut copied = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = source_reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                source_hash.update(&buffer[..read]);
                executable_handle.write_all(&buffer[..read])?;
                copied = copied
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("private runtime length overflow"))?;
            }
            executable_handle.sync_all()?;
            if copied != source_length {
                return Err(io::Error::other(
                    "source executable length changed during private copy",
                ));
            }

            executable_handle.seek(SeekFrom::Start(0))?;
            let mut destination_hash = Sha256::new();
            let mut destination_length = 0_u64;
            loop {
                let read = executable_handle.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                destination_hash.update(&buffer[..read]);
                destination_length = destination_length
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("private runtime length overflow"))?;
            }
            let source_hash = <[u8; 32]>::from(source_hash.finalize());
            if source_hash != expected_sha256
                || destination_length != source_length
                || <[u8; 32]>::from(destination_hash.finalize()) != expected_sha256
            {
                return Err(io::Error::other(
                    "source or exact destination object failed pinned SHA-256/length verification",
                ));
            }
            grant_private_object_access(
                directory_handle,
                sid,
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE,
            )?;
            grant_private_object_access(
                executable_handle,
                sid,
                FILE_READ_DATA
                    | FILE_EXECUTE
                    | FILE_READ_ATTRIBUTES
                    | FILE_READ_EA
                    | READ_CONTROL
                    | SYNCHRONIZE,
            )?;

            // CreateProcess cannot map an image while the retained file
            // object still accounts for data-write access. Transition to a
            // read-only no-write/no-delete-share pin, then hash that exact
            // final handle again. The temporary share-write reader keeps the
            // pathname deletion-pinned across the handoff; any data race in
            // the narrow handoff is detected by the final hash.
            let transition = OpenOptions::new()
                .read(true)
                .access_mode(GENERIC_READ | READ_CONTROL)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
                .open(&executable_path)?;
            let initial_executable_handle = cleanup_executable_handle
                .take()
                .expect("the writable executable handle is transitioned once");
            drop(initial_executable_handle);
            cleanup_executable_handle = Some(
                OpenOptions::new()
                    .read(true)
                    .access_mode(DELETE | GENERIC_READ | READ_CONTROL | WRITE_DAC)
                    .share_mode(FILE_SHARE_READ)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
                    .open(&executable_path)?,
            );
            drop(transition);
            let executable_handle = cleanup_executable_handle
                .as_mut()
                .expect("the final executable cleanup handle is retained");
            executable_handle.seek(SeekFrom::Start(0))?;
            let mut final_hash = Sha256::new();
            let mut final_length = 0_u64;
            loop {
                let read = executable_handle.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                final_hash.update(&buffer[..read]);
                final_length = final_length
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("private runtime length overflow"))?;
            }
            if final_length != source_length
                || <[u8; 32]>::from(final_hash.finalize()) != expected_sha256
            {
                return Err(io::Error::other(
                    "final read-only destination pin failed SHA-256/length verification",
                ));
            }
            regular_single_link_information(executable_handle, "destination executable")?;
            let executable_identity = windows_file_identity(executable_handle)?;
            if Some(executable_identity) != cleanup_executable_identity {
                return Err(io::Error::other(
                    "private destination object identity changed during construction",
                ));
            }

            let runtime = Self {
                source: Some(source),
                directory_handle: cleanup_directory_handle.take(),
                executable_handle: cleanup_executable_handle.take(),
                source_path: source_path.to_owned(),
                directory_path: directory_path.clone(),
                executable_path: executable_path.clone(),
                source_identity,
                directory_identity,
                executable_identity,
                transferred: false,
            };
            runtime.verify_bound()?;
            Ok(runtime)
        })();
        match result {
            Ok(runtime) => Ok(runtime),
            Err(primary) => {
                let executable_cleanup = match (
                    cleanup_executable_handle.as_ref(),
                    cleanup_executable_identity,
                ) {
                    (None, _) => Ok(()),
                    (Some(handle), Some(identity)) => {
                        delete_exact_runtime_handle(handle, false, identity)
                    }
                    (Some(_), None) => Err(io::Error::other(
                        "created private executable could not be identity-bound for cleanup",
                    )),
                };
                if executable_cleanup.is_ok() {
                    cleanup_executable_handle.take();
                }
                let directory_cleanup = match (
                    executable_cleanup.as_ref(),
                    cleanup_directory_handle.as_ref(),
                    cleanup_directory_identity,
                ) {
                    (Ok(()), None, _) => Err(io::Error::other(
                        "created private directory could not be opened and identity-bound for cleanup",
                    )),
                    (Ok(()), Some(handle), Some(identity)) => {
                        delete_exact_runtime_handle(handle, true, identity)
                    }
                    (Ok(()), Some(_), None) => Err(io::Error::other(
                        "created private directory could not be identity-bound for cleanup",
                    )),
                    (Err(_), _, _) => Err(io::Error::other(
                        "private directory retained because executable cleanup was uncertain",
                    )),
                };
                if directory_cleanup.is_ok() {
                    cleanup_directory_handle.take();
                }
                if executable_cleanup.is_err() || directory_cleanup.is_err() {
                    // Do not release an exact object pin after uncertain
                    // cleanup. The process-wide health latch blocks future
                    // ProductionV3 launches until operator remediation.
                    if let Some(handle) = cleanup_executable_handle.take() {
                        std::mem::forget(handle);
                    }
                    if let Some(handle) = cleanup_directory_handle.take() {
                        std::mem::forget(handle);
                    }
                    mark_appcontainer_cleanup_unhealthy();
                    return Err(io::Error::new(
                        primary.kind(),
                        format!(
                            "{primary}; exact private-runtime construction cleanup failed: executable={executable_cleanup:?}; directory={directory_cleanup:?}"
                        ),
                    ));
                }
                Err(primary)
            }
        }
    }

    fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    fn directory_path(&self) -> &Path {
        &self.directory_path
    }

    fn verify_bound(&self) -> io::Result<()> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| io::Error::other("private runtime source handle was transferred"))?;
        let directory = self
            .directory_handle
            .as_ref()
            .ok_or_else(|| io::Error::other("private runtime directory handle was transferred"))?;
        let executable = self
            .executable_handle
            .as_ref()
            .ok_or_else(|| io::Error::other("private runtime executable handle was transferred"))?;
        regular_single_link_information(source, "source executable")?;
        regular_single_link_information(executable, "destination executable")?;
        if windows_file_identity(source)? != self.source_identity
            || windows_file_identity(executable)? != self.executable_identity
        {
            return Err(io::Error::other(
                "private runtime executable identity changed during launch",
            ));
        }
        let directory_information = file_information(directory)?;
        if windows_file_identity(directory)? != self.directory_identity
            || directory_information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || directory_information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || directory_information.nNumberOfLinks != 1
        {
            return Err(io::Error::other(
                "private runtime directory identity changed during launch",
            ));
        }
        verify_runtime_path_identity(&self.source_path, false, self.source_identity)?;
        verify_runtime_path_identity(&self.directory_path, true, self.directory_identity)?;
        verify_runtime_path_identity(&self.executable_path, false, self.executable_identity)
    }

    fn verify_process_image(&self, process: HANDLE) -> io::Result<()> {
        let mut capacity = 32_768_u32;
        let mut path = vec![0_u16; capacity as usize];
        // SAFETY: process is live and the buffer/capacity pair is writable.
        if unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut capacity) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        path.truncate(capacity as usize);
        let image_path = PathBuf::from(OsString::from_wide(&path));
        verify_runtime_path_identity(&image_path, false, self.executable_identity)
    }

    fn into_process_runtime(mut self) -> WindowsPrivateRuntime {
        self.transferred = true;
        WindowsPrivateRuntime::new(
            self.source
                .take()
                .expect("source handle is transferred once"),
            self.directory_handle
                .take()
                .expect("directory handle is transferred once"),
            self.executable_handle
                .take()
                .expect("executable handle is transferred once"),
            self.directory_path.clone(),
            self.executable_path.clone(),
            self.directory_identity,
            self.executable_identity,
        )
    }
}

impl Drop for PrivateLaunchRuntime {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        let executable_cleanup = self
            .executable_handle
            .as_ref()
            .ok_or_else(|| io::Error::other("private executable cleanup handle is unavailable"))
            .and_then(|handle| {
                delete_exact_runtime_handle(handle, false, self.executable_identity)
            });
        if executable_cleanup.is_ok() {
            self.executable_handle.take();
        }
        let directory_cleanup = if executable_cleanup.is_ok() {
            self.directory_handle
                .as_ref()
                .ok_or_else(|| io::Error::other("private directory cleanup handle is unavailable"))
                .and_then(|handle| {
                    delete_exact_runtime_handle(handle, true, self.directory_identity)
                })
        } else {
            Err(io::Error::other(
                "private directory retained because executable cleanup was uncertain",
            ))
        };
        if directory_cleanup.is_ok() {
            self.directory_handle.take();
        }
        self.source.take();
        if executable_cleanup.is_err() || directory_cleanup.is_err() {
            if let Some(handle) = self.executable_handle.take() {
                std::mem::forget(handle);
            }
            if let Some(handle) = self.directory_handle.take() {
                std::mem::forget(handle);
            }
            mark_appcontainer_cleanup_unhealthy();
        }
    }
}

fn grant_private_object_access(object: &File, sid: PSID, access: u32) -> io::Result<()> {
    let mut current_dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: outputs are writable and the retained object has READ_CONTROL.
    let status = unsafe {
        GetSecurityInfo(
            object.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut current_dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    if descriptor.is_null() || current_dacl.is_null() {
        return Err(io::Error::other("private runtime object has no DACL"));
    }
    let descriptor = LocalAllocation(descriptor);
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let mut granted_dacl = ptr::null_mut();
    // SAFETY: the SID and current DACL remain live for this call.
    let status = unsafe { SetEntriesInAclW(1, &entry, current_dacl, &mut granted_dacl) };
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    if granted_dacl.is_null() {
        return Err(io::Error::other(
            "Windows returned a null private runtime DACL",
        ));
    }
    let granted = LocalAllocation(granted_dacl.cast());
    // SAFETY: the retained object was opened with WRITE_DAC and the new ACL is
    // live. This object is unique to this launch and is never restored.
    let status = unsafe {
        SetSecurityInfo(
            object.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            granted_dacl,
            ptr::null(),
        )
    };
    drop(granted);
    drop(descriptor);
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    Ok(())
}

pub(crate) fn secure_owner_only_path(path: &Path, directory: bool) -> io::Result<()> {
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let object = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(flags)
        .open(path)?;
    secure_owner_only_handle(&object)
}

pub(crate) fn secure_owner_only_handle(object: &File) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: outputs are writable and the object grants READ_CONTROL.
    let status = unsafe {
        GetSecurityInfo(
            object.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    if descriptor.is_null() || owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(io::Error::other(
            "owner-only cleanup ledger object has no valid owner SID",
        ));
    }
    let descriptor = LocalAllocation(descriptor);
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: SET_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: owner.cast(),
        },
    };
    let mut owner_dacl = ptr::null_mut();
    // SAFETY: the owner SID remains live in descriptor for this call.
    let status = unsafe { SetEntriesInAclW(1, &entry, ptr::null_mut(), &mut owner_dacl) };
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    if owner_dacl.is_null() {
        return Err(io::Error::other("Windows returned a null owner-only DACL"));
    }
    let owner_dacl = LocalAllocation(owner_dacl.cast());
    // SAFETY: the object grants WRITE_DAC and the generated ACL is live.
    let status = unsafe {
        SetSecurityInfo(
            object.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            owner_dacl.0.cast(),
            ptr::null(),
        )
    };
    drop(owner_dacl);
    drop(descriptor);
    if status != ERROR_SUCCESS {
        return Err(win32_status_error(status));
    }
    Ok(())
}

fn runtime_object_identity(file: &File) -> io::Result<WindowsFileIdentity> {
    windows_file_identity(file)
}

fn file_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: file owns a live handle and success initializes the complete
    // documented output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { information.assume_init() })
}

fn regular_single_link_information(
    file: &File,
    description: &'static str,
) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let information = file_information(file)?;
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(io::Error::other(format!(
            "{description} must be a regular, non-reparse, single-link file"
        )));
    }
    Ok(information)
}

fn verify_runtime_path_identity(
    path: &Path,
    directory: bool,
    expected: WindowsFileIdentity,
) -> io::Result<()> {
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let reopened = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(flags)
        .open(path)?;
    if runtime_object_identity(&reopened)? != expected {
        return Err(io::Error::other(
            "private runtime path no longer resolves to the pinned object",
        ));
    }
    Ok(())
}

fn validate_process_sandbox(
    process: HANDLE,
    expected_job: HANDLE,
    expected_sid: Option<PSID>,
) -> io::Result<()> {
    let mut token = ptr::null_mut();
    // SAFETY: process is live and the token output is writable.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io_context(
            "opening the worker process token",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: OpenProcessToken returned one fresh owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    if token_u32(&token, TokenIsAppContainer).map_err(|error| {
        io_context(
            format!(
                "querying TokenIsAppContainer (class={TokenIsAppContainer}, buffer_bytes={})",
                size_of::<u32>()
            ),
            error,
        )
    })? != 1
    {
        return Err(io::Error::other(
            "worker token is not an AppContainer token",
        ));
    }
    let (capability_buffer, capability_bytes) =
        token_buffer(&token, TokenCapabilities).map_err(|error| {
            io_context(
                format!(
                    "querying TokenCapabilities (class={TokenCapabilities}, header_bytes={})",
                    size_of::<u32>()
                ),
                error,
            )
        })?;
    if capability_bytes < size_of::<u32>() {
        return Err(io::Error::other(
            "worker capability token data is truncated",
        ));
    }
    // SAFETY: the aligned allocation contains at least one initialized u32.
    let capability_count = unsafe { *capability_buffer.as_ptr().cast::<u32>() };
    if capability_count != 0 {
        return Err(io::Error::other(format!(
            "worker token unexpectedly has {capability_count} capabilities"
        )));
    }
    if let Some(expected_sid) = expected_sid {
        let (appcontainer_buffer, appcontainer_bytes) = token_buffer(&token, TokenAppContainerSid)
            .map_err(|error| {
                io_context(
                    format!(
                        "querying TokenAppContainerSid (class={TokenAppContainerSid}, minimum_bytes={})",
                        size_of::<TOKEN_APPCONTAINER_INFORMATION>()
                    ),
                    error,
                )
            })?;
        if appcontainer_bytes < size_of::<TOKEN_APPCONTAINER_INFORMATION>() {
            return Err(io::Error::other(
                "worker AppContainer SID data is truncated",
            ));
        }
        // SAFETY: the aligned buffer is at least the fixed structure size and
        // GetTokenInformation initialized it completely.
        let information = unsafe {
            &*(appcontainer_buffer
                .as_ptr()
                .cast::<TOKEN_APPCONTAINER_INFORMATION>())
        };
        if information.TokenAppContainer.is_null()
            || unsafe { EqualSid(information.TokenAppContainer, expected_sid) } == 0
        {
            return Err(io::Error::other(
                "worker token AppContainer SID does not match the created profile",
            ));
        }
    }

    let mut dep = PROCESS_MITIGATION_DEP_POLICY::default();
    query_mitigation_policy(process, ProcessDEPPolicy, "DEP", &mut dep)?;
    // Native 64-bit processes report DisableAtlThunkEmulation together with
    // Enable; 32-bit processes require only Enable.
    let expected_dep = if cfg!(target_pointer_width = "64") {
        0x3
    } else {
        0x1
    };
    require_exact_policy_bits("DEP", unsafe { dep.Anonymous.Flags }, 0x3, expected_dep)?;
    if !dep.Permanent {
        return Err(io::Error::other("worker DEP mitigation is not permanent"));
    }

    validate_requested_creation_mitigations(process)?;

    let mut aslr = PROCESS_MITIGATION_ASLR_POLICY::default();
    query_mitigation_policy(process, ProcessASLRPolicy, "ASLR", &mut aslr)?;
    // The AppContainer process reports the two explicitly requested ASLR bits
    // plus the platform-enforced force-relocate and stripped-image bans. Check
    // that complete effective policy instead of treating any single ASLR bit
    // as sufficient.
    require_exact_policy_bits("ASLR", unsafe { aslr.Anonymous.Flags }, 0xf, 0xf)?;

    let mut dynamic_code = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    query_mitigation_policy(
        process,
        ProcessDynamicCodePolicy,
        "dynamic-code",
        &mut dynamic_code,
    )?;
    // ProhibitDynamicCode is required; thread opt-out and audit/downgrade bits
    // are not accepted by this launch profile.
    require_exact_policy_bits(
        "dynamic-code",
        unsafe { dynamic_code.Anonymous.Flags },
        0xf,
        0x1,
    )?;

    let mut image_load = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    query_mitigation_policy(
        process,
        ProcessImageLoadPolicy,
        "image-load",
        &mut image_load,
    )?;
    // NoRemoteImages and PreferSystem32Images are required. The low-label
    // policy is not requested and therefore must not be reported as a silent
    // substitute for either required bit.
    require_exact_policy_bits(
        "image-load",
        unsafe { image_load.Anonymous.Flags },
        0x7,
        0x5,
    )?;

    let mut win32k = PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY::default();
    query_mitigation_policy(
        process,
        ProcessSystemCallDisablePolicy,
        "Win32k",
        &mut win32k,
    )?;
    require_exact_policy_bits("Win32k", unsafe { win32k.Anonymous.Flags }, 0x3, 0x1)?;

    let mut child_policy = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
    query_mitigation_policy(
        process,
        ProcessChildProcessPolicy,
        "child-process",
        &mut child_policy,
    )?;
    require_exact_policy_bits(
        "child-process",
        unsafe { child_policy.Anonymous.Flags },
        0x7,
        0x1,
    )?;

    let mut in_job = 0;
    // A null Job handle asks whether the process belongs to any Job and is
    // used only by the child self-check. The parent supplies the exact Job.
    if unsafe { IsProcessInJob(process, expected_job, &mut in_job) } == 0 {
        return Err(io_context(
            "querying worker Job membership",
            io::Error::last_os_error(),
        ));
    }
    if in_job == 0 {
        return Err(io::Error::other(
            "worker was not atomically associated with the required Job",
        ));
    }
    Ok(())
}

fn validate_requested_creation_mitigations(process: HANDLE) -> io::Result<()> {
    let mut sehop = PROCESS_MITIGATION_SEHOP_POLICY::default();
    query_mitigation_policy(process, ProcessSEHOPPolicy, "SEHOP", &mut sehop)?;

    let mut strict_handles = PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY::default();
    query_mitigation_policy(
        process,
        ProcessStrictHandleCheckPolicy,
        "strict-handle-check",
        &mut strict_handles,
    )?;

    let mut extension_points = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
    query_mitigation_policy(
        process,
        ProcessExtensionPointDisablePolicy,
        "extension-point-disable",
        &mut extension_points,
    )?;

    validate_requested_creation_mitigation_bits(
        unsafe { sehop.Anonymous.Flags },
        unsafe { strict_handles.Anonymous.Flags },
        unsafe { extension_points.Anonymous.Flags },
    )
}

fn validate_requested_creation_mitigation_bits(
    sehop: u32,
    strict_handles: u32,
    extension_points: u32,
) -> io::Result<()> {
    require_exact_policy_bits("SEHOP", sehop, 0x1, 0x1)?;
    // ALWAYS_ON requests both exception-on-invalid-handle and permanent
    // enforcement. Accepting only the first bit would permit a child to
    // downgrade the policy after resume.
    require_exact_policy_bits("strict-handle-check", strict_handles, 0x3, 0x3)?;
    require_exact_policy_bits("extension-point-disable", extension_points, 0x1, 0x1)
}

fn query_mitigation_policy<T>(
    process: HANDLE,
    policy: i32,
    name: &'static str,
    output: &mut T,
) -> io::Result<()> {
    // SAFETY: `process` is live and `output` has the exact structure selected
    // by the caller for this policy class.
    if unsafe {
        GetProcessMitigationPolicy(
            process,
            policy,
            ptr::from_mut(output).cast(),
            size_of::<T>(),
        )
    } == 0
    {
        Err(io_context(
            format!(
                "querying the {name} mitigation (policy={policy}, struct_bytes={})",
                size_of::<T>()
            ),
            io::Error::last_os_error(),
        ))
    } else {
        Ok(())
    }
}

fn require_exact_policy_bits(
    name: &'static str,
    observed: u32,
    relevant_mask: u32,
    expected: u32,
) -> io::Result<()> {
    if observed & relevant_mask != expected {
        Err(io::Error::other(format!(
            "worker {name} mitigation bits are 0x{observed:08x}; expected masked value 0x{expected:08x} under mask 0x{relevant_mask:08x}"
        )))
    } else {
        Ok(())
    }
}

fn token_u32(token: &OwnedHandle, class: i32) -> io::Result<u32> {
    let mut value = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: token is live and both output buffers are writable.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            class,
            ptr::from_mut(&mut value).cast(),
            size_of::<u32>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned != size_of::<u32>() as u32 {
        return Err(io::Error::other("unexpected scalar token information size"));
    }
    Ok(value)
}

fn token_buffer(token: &OwnedHandle, class: i32) -> io::Result<(Vec<usize>, usize)> {
    let mut bytes = 0_u32;
    // SAFETY: this is the documented size query with a null buffer.
    let queried = unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            class,
            ptr::null_mut(),
            0,
            &mut bytes,
        )
    };
    if queried != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || bytes == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0_usize; (bytes as usize).div_ceil(size_of::<usize>())];
    let mut returned = bytes;
    // SAFETY: aligned usize storage contains at least the queried byte count.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            class,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned > bytes {
        return Err(io::Error::other("token information grew during query"));
    }
    Ok((buffer, returned as usize))
}

#[derive(Debug)]
struct FailedLaunchTermination {
    job_termination: Result<(), String>,
    direct_fallback: Option<Result<(), String>>,
    wait: Result<bool, String>,
}

impl FailedLaunchTermination {
    fn exit_confirmed(&self) -> bool {
        self.wait.as_ref().is_ok_and(|exited| *exited)
    }

    fn clean(&self) -> bool {
        self.job_termination.is_ok()
            && self.direct_fallback.as_ref().is_none_or(Result::is_ok)
            && self.exit_confirmed()
    }
}

fn terminate_failed_launch(job: &WindowsJob, process: HANDLE) -> FailedLaunchTermination {
    use windows_sys::Win32::{
        Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{TerminateProcess, WaitForSingleObject},
    };

    terminate_failed_launch_with(
        || job.terminate(),
        || {
            // SAFETY: `process` is the fresh handle returned by CreateProcessW.
            if unsafe { TerminateProcess(process, 1) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        },
        || {
            // SAFETY: `process` remains retained throughout this bounded wait.
            match unsafe { WaitForSingleObject(process, 2_000) } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                WAIT_FAILED => Err(io::Error::last_os_error()),
                status => Err(io::Error::other(format!(
                    "unexpected process wait status {status}"
                ))),
            }
        },
    )
}

fn terminate_failed_launch_with(
    terminate_job: impl FnOnce() -> io::Result<()>,
    terminate_process: impl FnOnce() -> io::Result<()>,
    wait_process: impl FnOnce() -> io::Result<bool>,
) -> FailedLaunchTermination {
    let job_termination = terminate_job().map_err(|error| error.to_string());
    let direct_fallback = job_termination
        .as_ref()
        .err()
        .map(|_| terminate_process().map_err(|error| error.to_string()));
    let wait = wait_process().map_err(|error| error.to_string());
    FailedLaunchTermination {
        job_termination,
        direct_fallback,
        wait,
    }
}

#[allow(clippy::too_many_arguments)]
fn cleanup_failed_post_create_launch(
    operation: &'static str,
    primary: io::Error,
    job: Arc<WindowsJob>,
    process: OwnedHandle,
    thread: OwnedHandle,
    mut profile: CreatedProfile,
    private_runtime: PrivateLaunchRuntime,
) -> ProofWorkerError {
    let termination = terminate_failed_launch(&job, process.as_raw_handle().cast());
    if !termination.exit_confirmed() {
        mark_appcontainer_cleanup_unhealthy();
        // Exit is not proven. Keep every authority and identity pin alive for
        // the remainder of the parent process and block all later launches.
        std::mem::forget(thread);
        std::mem::forget(process);
        std::mem::forget(job);
        std::mem::forget(profile);
        std::mem::forget(private_runtime);
        return containment(
            operation,
            io::Error::other(format!(
                "{primary}; failed-launch termination did not confirm process exit: {termination:?}; process/job/profile/runtime resources were quarantined and ProductionV3 health was latched"
            )),
        );
    }

    drop(thread);
    drop(process);
    drop(job);
    let profile_cleanup = profile.delete_registration();
    if profile_cleanup.is_err() {
        mark_appcontainer_cleanup_unhealthy();
    }
    let mut runtime = private_runtime.into_process_runtime();
    let runtime_cleanup = runtime.cleanup();
    if runtime_cleanup.is_err() {
        mark_appcontainer_cleanup_unhealthy();
    }
    if termination.clean() && profile_cleanup.is_ok() && runtime_cleanup.is_ok() {
        containment(operation, primary)
    } else {
        containment(
            operation,
            io::Error::new(
                primary.kind(),
                format!(
                    "{primary}; failed-launch termination={termination:?}; profile_cleanup={profile_cleanup:?}; runtime_cleanup={runtime_cleanup:?}"
                ),
            ),
        )
    }
}

fn hresult_from_win32(error: u32) -> i32 {
    (0x8007_0000_u32 | error) as i32
}

fn hresult_error(status: i32) -> io::Error {
    let raw = status as u32;
    if raw & 0xffff_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((raw & 0xffff) as i32)
    } else {
        io::Error::other(format!("HRESULT 0x{raw:08x}"))
    }
}

fn win32_status_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX))
}

fn io_context(operation: impl std::fmt::Display, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

fn nul_terminated(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut encoded = value.encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows process string contains an interior NUL",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

fn build_command_line(program: &OsStr, arguments: &[OsString]) -> io::Result<Vec<u16>> {
    let mut command_line = Vec::new();
    append_quoted_argument(&mut command_line, program)?;
    for argument in arguments {
        command_line.push(b' ' as u16);
        append_quoted_argument(&mut command_line, argument)?;
    }
    command_line.push(0);
    Ok(command_line)
}

fn append_quoted_argument(output: &mut Vec<u16>, argument: &OsStr) -> io::Result<()> {
    let encoded = argument.encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows command-line argument contains an interior NUL",
        ));
    }
    let needs_quotes = encoded.is_empty()
        || encoded
            .iter()
            .any(|unit| matches!(*unit, 0x09 | 0x20 | 0x22));
    if !needs_quotes {
        output.extend_from_slice(&encoded);
        return Ok(());
    }
    output.push(b'"' as u16);
    let mut backslashes = 0_usize;
    for unit in encoded {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
        }
        backslashes = 0;
        output.push(unit);
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        io::{self, BufRead, BufReader, Read as _, Write as _},
        mem::{MaybeUninit, size_of},
        net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
        os::windows::{
            fs::OpenOptionsExt as _,
            io::{
                AsRawHandle as _, AsRawSocket as _, FromRawHandle as _, FromRawSocket as _,
                OwnedHandle, OwnedSocket,
            },
        },
        path::PathBuf,
        process::{Command, Stdio},
        ptr,
        sync::{Arc, Barrier, mpsc},
        thread,
        time::{Duration, Instant},
    };

    use sha2::{Digest as _, Sha256};

    use windows_sys::Win32::{
        Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE,
            ERROR_NO_MORE_ITEMS, HANDLE,
        },
        Networking::WinSock::{
            AF_INET, FIONBIO, IN_ADDR, IN_ADDR_0, INVALID_SOCKET, IPPROTO_TCP, POLLERR, POLLHUP,
            POLLNVAL, POLLOUT, SO_ERROR, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR,
            SOL_SOCKET, WSACleanup, WSADATA, WSAEACCES, WSAECONNREFUSED, WSAEINVAL, WSAETIMEDOUT,
            WSAEWOULDBLOCK, WSAGetLastError, WSAPOLLFD, WSAPoll, WSASYSCALLFAILURE, WSASocketW,
            WSAStartup, accept as winsock_accept, bind as winsock_bind, connect as winsock_connect,
            getsockopt, ioctlsocket, listen as winsock_listen,
        },
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
            GetFileInformationByHandleEx,
        },
        System::{
            Registry::{
                HKEY, HKEY_CURRENT_USER, KEY_READ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW,
                RegGetValueW, RegOpenKeyExW,
            },
            Threading::{GetCurrentProcess, WaitForSingleObject},
        },
    };

    use super::{
        CreatedProfile, ENVIRONMENT_ALLOWLIST, PrivateLaunchRuntime, io_context, nul_terminated,
        spawn_contained_production_windows_inner, terminate_failed_launch_with, try_create_profile,
        try_create_untracked_test_profile, validate_current_process_sandbox,
        validate_heap_termination_query, validate_requested_creation_mitigation_bits,
        validate_requested_creation_mitigations,
    };
    use crate::WindowsJob;
    use crate::process::{
        WindowsFileIdentity, isolated_appcontainer_ledger_test,
        retry_pending_appcontainer_profile_cleanup, windows_file_identity,
    };
    use crate::verifier::ProductionV3VerifierRecord;
    use cmfd_consensus::dory_v3_model_ceremony_transcript::FileIdentity;

    const CHILD_TEST: &str = "windows_launcher::tests::windows_appcontainer_probe_child";
    const INVALID_HANDLE_CHILD_TEST: &str =
        "windows_launcher::tests::windows_appcontainer_invalid_handle_probe_child";
    const NETWORK_CHILD_TEST: &str =
        "windows_launcher::tests::windows_appcontainer_network_probe_child";
    const PARENT_TEST: &str = "windows_launcher::tests::windows_appcontainer_parent_probe";
    const INVALID_HANDLE_PARENT_TEST: &str =
        "windows_launcher::tests::windows_appcontainer_invalid_handle_parent_probe";
    const PARENT_ENVIRONMENT_CANARY: &str = "CMFD_PARENT_ENVIRONMENT_CANARY";
    const PARENT_ENVIRONMENT_CANARY_VALUE: &str = "must-not-cross-the-lpac-boundary";
    const FAILED_LAUNCH_CHILD_ENV: &str = "CMFD_FAILED_LAUNCH_CHILD";
    const PANIC_CLEANUP_CHILD_ENV: &str = "CMFD_PANIC_CLEANUP_SOURCE";
    const PROBE_READY: &str = "CMFD_WINDOWS_APPCONTAINER_SENTINEL_READY";
    const PROBE_ARM: &str = "CMFD_WINDOWS_APPCONTAINER_SENTINEL_ARM";
    const PROBE_ARMED: &str = "CMFD_WINDOWS_APPCONTAINER_SENTINEL_ARMED";
    const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
    const NETWORK_PROBE_OK: &str = "CMFD_WINDOWS_APPCONTAINER_NETWORK_SENTINEL_OK";
    const CONNECT_BLOCKED_PREFIX: &str = "NETWORK_CONNECT_BLOCKED=";
    const LISTENER_BLOCKED_PREFIX: &str = "NETWORK_LISTENER_BLOCKED=";
    const IMMEDIATE_CONNECT_DENIAL_SUFFIX: &str = "|connect-error=10013";
    const BOUNDED_CONNECT_PENDING_SUFFIX: &str = "|connect-error=10035|poll=timeout";
    const DENIED_BIND_LISTEN_SUFFIX: &str = "|bind-error=10013|listen-error=10022";
    const SETUP_BIND_LISTEN_DENIAL_SUFFIX: &str = "|bind=ok|listen-error=10013";
    const SETUP_BIND_LISTEN_SUCCESS_SUFFIX: &str = "|bind=ok|listen=ok";
    const NETWORK_PARENT_CHECKED: &str = "CMFD_WINDOWS_APPCONTAINER_NETWORK_PARENT_CHECKED";
    const PARENT_CONNECT_BLOCKED_PREFIX: &str = "NETWORK_PARENT_CONNECT_BLOCKED=";
    const CHILD_ACCEPT_BLOCKED_PREFIX: &str = "NETWORK_CHILD_ACCEPT_BLOCKED=";
    const CHILD_ACCEPT_WOULD_BLOCK_SUFFIX: &str = "|accept-error=10035";
    const SUPPLIED_CONTENT: &[u8] = b"record-v2-handle-sentinel";

    fn record_identity(bytes: &[u8]) -> FileIdentity {
        FileIdentity {
            bytes: bytes.len() as u64,
            blake3: *blake3::hash(bytes).as_bytes(),
            sha256: Sha256::digest(bytes).into(),
        }
    }

    fn random_profile_name(label: &str) -> Vec<u16> {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).expect("generate a randomized test profile moniker");
        nul_terminated(OsStr::new(&format!(
            "CMFD.Verifier.{label}.{}.{}",
            std::process::id(),
            hex::encode(random)
        )))
        .expect("randomized test profile moniker is valid")
    }

    fn raw_file_identity(handle: HANDLE) -> io::Result<WindowsFileIdentity> {
        let mut identity = MaybeUninit::<FILE_ID_INFO>::zeroed();
        // SAFETY: the parent owns this duplicated handle. A successful query
        // initializes the complete output.
        if unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                identity.as_mut_ptr().cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful API call initialized the complete structure.
        let identity = unsafe { identity.assume_init() };
        Ok(WindowsFileIdentity {
            volume_serial: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        })
    }

    fn require_omitted_handle_absent_before_resume(
        child_process: HANDLE,
        omitted_handle: HANDLE,
        omitted_identity: WindowsFileIdentity,
    ) -> io::Result<()> {
        let mut duplicate = ptr::null_mut();
        // SAFETY: the child remains suspended, both process handles are live,
        // and `duplicate` is writable. The exact parent numeric value is
        // probed from the child's handle table before untrusted code can run.
        let duplicated = unsafe {
            DuplicateHandle(
                child_process,
                omitted_handle,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if duplicated != 0 {
            // SAFETY: DuplicateHandle returned one fresh owned handle.
            let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate.cast()) };
            let observed = raw_file_identity(duplicate.as_raw_handle().cast());
            let detail = match observed {
                Ok(identity) if identity == omitted_identity => {
                    "the omitted identity was inherited".to_owned()
                }
                Ok(identity) => format!(
                    "the numeric slot was reused by file identity {identity:?}; reuse is not accepted as omission proof"
                ),
                Err(error) => format!(
                    "the numeric slot was reused by a non-file or unqueryable handle ({error}); reuse is not accepted as omission proof"
                ),
            };
            return Err(io::Error::other(format!(
                "suspended-child omitted-handle attestation failed: {detail}"
            )));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INVALID_HANDLE as i32) {
            return Err(io_context(
                "duplicating the omitted numeric handle from the suspended child",
                error,
            ));
        }
        Ok(())
    }

    fn require_expected_job_close_exit(status: std::process::ExitStatus) -> io::Result<()> {
        // Exit status is only the final classifier. The caller must first
        // prove READY -> ARM -> ARMED, exact Job ActiveProcesses == 1, and a
        // nonsignaled child immediately before closing the final Job handle.
        // On the qualified Windows host, KILL_ON_JOB_CLOSE produces the Job's
        // default zero exit code. No exception or arbitrary application code
        // is accepted as equivalent evidence.
        let code = status
            .code()
            .ok_or_else(|| io::Error::other("Windows sentinel exit status had no process code"))?
            as u32;
        if code == STATUS_INVALID_HANDLE {
            return Err(io::Error::other(
                "sentinel died with STATUS_INVALID_HANDLE (0xc0000008); this is a child fault, not Job kill-on-close evidence",
            ));
        }
        if code != 0 {
            return Err(io::Error::other(format!(
                "sentinel exited with unexpected status 0x{code:08x}; only the observed Job-close status 0x00000000 is accepted"
            )));
        }
        Ok(())
    }

    fn reject_preclose_exit(status: std::process::ExitStatus) -> io::Error {
        let code = status.code().map(|code| code as u32);
        if code == Some(STATUS_INVALID_HANDLE) {
            return io::Error::other(
                "sentinel died before Job close with STATUS_INVALID_HANDLE (0xc0000008)",
            );
        }
        io::Error::other(match code {
            Some(code) => format!(
                "sentinel exited before the final Job handle close with status 0x{code:08x}"
            ),
            None => "sentinel exited before the final Job handle close without a process code"
                .to_owned(),
        })
    }

    #[test]
    fn requested_creation_mitigation_attestation_fails_closed() {
        validate_requested_creation_mitigation_bits(0x1, 0x3, 0x1)
            .expect("the exact requested mitigation bits must pass");
        for (observed, expected_name) in [
            ((0x0, 0x3, 0x1), "SEHOP"),
            ((0x1, 0x1, 0x1), "strict-handle-check"),
            ((0x1, 0x3, 0x0), "extension-point-disable"),
        ] {
            let error =
                validate_requested_creation_mitigation_bits(observed.0, observed.1, observed.2)
                    .unwrap_err();
            assert!(
                error.to_string().contains(expected_name),
                "unexpected mismatch error for {expected_name}: {error}"
            );
        }

        let error = validate_requested_creation_mitigations(ptr::null_mut()).unwrap_err();
        assert!(
            error.to_string().contains("querying the SEHOP mitigation"),
            "mitigation query failure was not propagated exactly: {error}"
        );
    }

    #[test]
    fn heap_termination_attestation_fails_closed_on_disabled_or_query_failure() {
        validate_heap_termination_query(|| Ok(1)).expect("the exact enabled heap state must pass");

        let disabled = validate_heap_termination_query(|| Ok(0)).unwrap_err();
        assert!(
            disabled.to_string().contains("expected exactly 1"),
            "unexpected disabled-state error: {disabled}"
        );

        let query_failure = validate_heap_termination_query(|| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "forced heap query failure",
            ))
        })
        .unwrap_err();
        assert_eq!(query_failure.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            query_failure
                .to_string()
                .contains("forced heap query failure")
        );
    }

    #[test]
    fn job_close_exit_classifier_rejects_invalid_handle_and_arbitrary_crashes() {
        use std::os::windows::process::ExitStatusExt as _;

        let invalid_handle = std::process::ExitStatus::from_raw(STATUS_INVALID_HANDLE);
        let error = require_expected_job_close_exit(invalid_handle).unwrap_err();
        assert!(error.to_string().contains("STATUS_INVALID_HANDLE"));

        let arbitrary_crash = std::process::ExitStatus::from_raw(0xc000_0005_u32);
        let error = require_expected_job_close_exit(arbitrary_crash).unwrap_err();
        assert!(error.to_string().contains("0xc0000005"));

        require_expected_job_close_exit(std::process::ExitStatus::from_raw(0))
            .expect("the exact observed Job-close status is accepted after the live barrier");

        let preclose_zero = reject_preclose_exit(std::process::ExitStatus::from_raw(0));
        assert!(preclose_zero.to_string().contains("before the final Job"));
    }

    #[test]
    fn production_handle_attestation_rejects_extra_socket_authority() {
        let mut winsock_data = WSADATA::default();
        assert_eq!(unsafe { WSAStartup(0x0202, &mut winsock_data) }, 0);
        let socket =
            unsafe { WSASocketW(AF_INET.into(), SOCK_STREAM, IPPROTO_TCP, ptr::null(), 0, 0) };
        assert_ne!(socket, INVALID_SOCKET);
        let socket = unsafe { OwnedSocket::from_raw_socket(socket as u64) };
        let error = super::exact_production_child_handles(
            [ptr::null_mut(); 4],
            &[socket.as_raw_socket() as HANDLE],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exactly stdio and one Record V2"),
            "unexpected inherited-handle attestation error: {error}"
        );
        drop(socket);
        assert_eq!(unsafe { WSACleanup() }, 0);
    }

    #[test]
    fn omitted_handle_probe_rejects_actual_inheritance_and_numeric_slot_reuse() {
        let _ledger = isolated_appcontainer_ledger_test();
        let files = TestDirectory::create();
        let path = files.write("omitted-probe.bin", b"omitted identity");
        let file = File::open(path).unwrap();
        let identity = windows_file_identity(&file).unwrap();
        let actual = require_omitted_handle_absent_before_resume(
            unsafe { GetCurrentProcess() },
            file.as_raw_handle().cast(),
            identity,
        )
        .unwrap_err();
        assert!(actual.to_string().contains("was inherited"));

        let reused = require_omitted_handle_absent_before_resume(
            unsafe { GetCurrentProcess() },
            file.as_raw_handle().cast(),
            WindowsFileIdentity {
                volume_serial: identity.volume_serial,
                file_id: [0xff; 16],
            },
        )
        .unwrap_err();
        assert!(reused.to_string().contains("reuse is not accepted"));
    }

    #[test]
    fn failed_launch_termination_child() {
        if std::env::var_os(FAILED_LAUNCH_CHILD_ENV).is_some() {
            thread::sleep(Duration::from_secs(30));
        }
    }

    fn failed_launch_child() -> (std::process::Child, Arc<WindowsJob>) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("windows_launcher::tests::failed_launch_termination_child")
            .arg("--nocapture")
            .env(FAILED_LAUNCH_CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().unwrap();
        let job = Arc::new(WindowsJob::create_with_process_limit(None, Some(1)).unwrap());
        job.assign(&child).unwrap();
        (child, job)
    }

    #[test]
    fn failed_launch_termination_composes_each_failure_and_leaves_no_survivor() {
        use windows_sys::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::TerminateProcess};

        let (mut direct_child, direct_job) = failed_launch_child();
        let direct_handle = direct_child.as_raw_handle();
        let direct = terminate_failed_launch_with(
            || Err(io::Error::other("forced job termination failure")),
            || {
                if unsafe { TerminateProcess(direct_handle, 1) } == 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            },
            || Ok(unsafe { WaitForSingleObject(direct_handle, 2_000) } == WAIT_OBJECT_0),
        );
        assert!(direct.exit_confirmed());
        assert!(direct.job_termination.is_err());
        assert!(direct.direct_fallback.as_ref().unwrap().is_ok());
        assert!(direct_child.try_wait().unwrap().is_some());
        drop(direct_job);

        let (mut wait_child, wait_job) = failed_launch_child();
        let wait_handle = wait_child.as_raw_handle();
        let wait_failure = terminate_failed_launch_with(
            || wait_job.terminate(),
            || panic!("direct fallback must not run after successful Job termination"),
            || Err(io::Error::other("forced wait failure")),
        );
        assert!(!wait_failure.exit_confirmed());
        assert!(
            wait_failure
                .wait
                .as_ref()
                .unwrap_err()
                .contains("forced wait")
        );
        assert_eq!(
            unsafe { WaitForSingleObject(wait_handle, 2_000) },
            WAIT_OBJECT_0
        );
        assert!(wait_child.try_wait().unwrap().is_some());
        drop(wait_job);

        let (mut uncertain_child, uncertain_job) = failed_launch_child();
        let uncertain_handle = uncertain_child.as_raw_handle();
        let uncertain = terminate_failed_launch_with(
            || Err(io::Error::other("forced job termination failure")),
            || Err(io::Error::other("forced direct termination failure")),
            || Ok(false),
        );
        assert!(!uncertain.exit_confirmed());
        assert!(uncertain.direct_fallback.as_ref().unwrap().is_err());
        assert!(uncertain_child.try_wait().unwrap().is_none());
        uncertain_job.terminate().unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(uncertain_handle, 2_000) },
            WAIT_OBJECT_0
        );
        assert!(uncertain_child.try_wait().unwrap().is_some());
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            for _ in 0..16 {
                let mut random = [0_u8; 16];
                getrandom::fill(&mut random)
                    .expect("generate a randomized Windows sentinel directory");
                let path = std::env::temp_dir().join(format!(
                    "cmfd-windows-appcontainer-{}-{}",
                    std::process::id(),
                    hex::encode(random)
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create Windows sentinel directory: {error}"),
                }
            }
            panic!("randomized Windows sentinel directory allocation was exhausted")
        }

        fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).expect("write Windows sentinel input");
            fs::canonicalize(path).expect("canonicalize Windows sentinel input")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct RegistryKey(HKEY);

    impl Drop for RegistryKey {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: RegOpenKeyExW returned this owned key handle.
                let _ = unsafe { RegCloseKey(self.0) };
            }
        }
    }

    fn cmfd_profile_mapping_snapshot() -> BTreeMap<String, String> {
        let path = nul_terminated(OsStr::new(
            "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings",
        ))
        .unwrap();
        let mut mappings = ptr::null_mut();
        // SAFETY: the key path and output pointer are live.
        let status =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut mappings) };
        assert_eq!(status, 0, "open AppContainer profile mappings: {status}");
        let mappings = RegistryKey(mappings);
        let moniker_name = nul_terminated(OsStr::new("Moniker")).unwrap();
        let mut snapshot = BTreeMap::new();
        for index in 0_u32.. {
            let mut key_name = vec![0_u16; 256];
            let mut key_units = (key_name.len() - 1) as u32;
            // SAFETY: every optional output is null and the name buffer is
            // writable for `key_units` UTF-16 units.
            let status = unsafe {
                RegEnumKeyExW(
                    mappings.0,
                    index,
                    key_name.as_mut_ptr(),
                    &mut key_units,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            assert_eq!(
                status, 0,
                "enumerate AppContainer mapping {index}: {status}"
            );
            key_name.truncate(key_units as usize);
            let key_name = String::from_utf16(&key_name).expect("mapping SID is UTF-16");
            let key_name_wide = nul_terminated(OsStr::new(&key_name)).unwrap();
            let mut subkey = ptr::null_mut();
            let status = unsafe {
                RegOpenKeyExW(mappings.0, key_name_wide.as_ptr(), 0, KEY_READ, &mut subkey)
            };
            assert_eq!(status, 0, "open AppContainer mapping {key_name}: {status}");
            let subkey = RegistryKey(subkey);
            let mut bytes = 0_u32;
            let status = unsafe {
                RegGetValueW(
                    subkey.0,
                    ptr::null(),
                    moniker_name.as_ptr(),
                    RRF_RT_REG_SZ,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut bytes,
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                continue;
            }
            assert_eq!(status, 0, "size AppContainer moniker {key_name}: {status}");
            assert_eq!(bytes as usize % size_of::<u16>(), 0);
            let mut moniker = vec![0_u16; bytes as usize / size_of::<u16>()];
            let status = unsafe {
                RegGetValueW(
                    subkey.0,
                    ptr::null(),
                    moniker_name.as_ptr(),
                    RRF_RT_REG_SZ,
                    ptr::null_mut(),
                    moniker.as_mut_ptr().cast(),
                    &mut bytes,
                )
            };
            assert_eq!(status, 0, "read AppContainer moniker {key_name}: {status}");
            while moniker.last() == Some(&0) {
                moniker.pop();
            }
            let moniker = String::from_utf16(&moniker).expect("profile moniker is UTF-16");
            if moniker.to_ascii_lowercase().starts_with("cmfd.verifier.") {
                snapshot.insert(key_name, moniker);
            }
        }
        snapshot
    }

    fn appcontainer_temp_root_snapshot() -> BTreeMap<PathBuf, WindowsFileIdentity> {
        let mut snapshot = BTreeMap::new();
        for entry in fs::read_dir(std::env::temp_dir())
            .expect("enumerate the real temporary directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read a temporary-directory entry")
        {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if ![
                "cmfd-verifier-launch-",
                "cmfd-windows-appcontainer-",
                "cmfd-appcontainer-ledger-test-",
                "cmfd-appcontainer-ledger-case-",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
            {
                continue;
            }
            let path = entry.path();
            let handle = OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(&path)
                .unwrap_or_else(|error| panic!("open temp root {}: {error}", path.display()));
            snapshot.insert(
                path,
                windows_file_identity(&handle).expect("query temp-root FILE_ID_INFO"),
            );
        }
        snapshot
    }

    fn line(reader: &mut impl BufRead) -> String {
        let mut value = String::new();
        reader
            .read_line(&mut value)
            .expect("read Windows sentinel request");
        assert!(!value.is_empty(), "Windows sentinel request ended early");
        value.trim_end_matches(['\r', '\n']).to_owned()
    }

    fn raw_handle(descriptor: &str) -> usize {
        usize::from_str_radix(
            descriptor
                .split(':')
                .next()
                .expect("descriptor contains a handle"),
            16,
        )
        .expect("descriptor handle is hexadecimal")
    }

    fn probe_stage(stage: &str) {
        eprintln!("LPAC_PROBE_STAGE={stage}");
        std::io::stderr().flush().expect("flush LPAC probe stage");
    }

    fn assert_network_stack_denied() {
        let mut data = WSADATA::default();
        // SAFETY: data is writable for the documented WSADATA layout.
        let startup = unsafe { WSAStartup(0x0202, &mut data) };
        assert_eq!(
            startup, WSASYSCALLFAILURE,
            "the zero-capability LPAC unexpectedly initialized Winsock"
        );
        // Exercise socket creation with a real AF_INET/SOCK_STREAM request,
        // not an already-invalid fabricated socket value. Because WSAStartup
        // was denied, no connect/bind/listen-capable socket may exist.
        let socket =
            unsafe { WSASocketW(AF_INET.into(), SOCK_STREAM, IPPROTO_TCP, ptr::null(), 0, 0) };
        assert_eq!(
            socket, INVALID_SOCKET,
            "the zero-capability LPAC created a socket after Winsock startup denial"
        );
        let socket_error = unsafe { WSAGetLastError() };
        assert!(
            matches!(socket_error, 10093 | WSASYSCALLFAILURE),
            "socket creation failed with unexpected Winsock error {socket_error}"
        );
    }

    fn assert_concrete_network_endpoints_denied(
        connect_socket: SOCKET,
        listen_socket: SOCKET,
        connect_address: SocketAddr,
        listen_address: SocketAddr,
    ) {
        fn socket_address(address: SocketAddr) -> SOCKADDR_IN {
            let SocketAddr::V4(address) = address else {
                panic!("the bounded LPAC sentinel requires a concrete IPv4 endpoint");
            };
            let ip = *address.ip();
            SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: address.port().to_be(),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                sin_zero: [0; 8],
            }
        }

        assert_ne!(
            connect_socket, INVALID_SOCKET,
            "the child did not create a valid connect socket"
        );
        let connect_name = socket_address(connect_address);
        let connect_result = unsafe {
            winsock_connect(
                connect_socket,
                (&raw const connect_name).cast::<SOCKADDR>(),
                size_of::<SOCKADDR_IN>() as i32,
            )
        };
        assert_eq!(
            connect_result, SOCKET_ERROR,
            "the zero-network-capability AppContainer connected to the concrete parent endpoint {connect_address}"
        );
        let mut connect_error = unsafe { WSAGetLastError() };
        let mut bounded_pending_denial = false;
        if connect_error == WSAEWOULDBLOCK {
            let mut poll = WSAPOLLFD {
                fd: connect_socket,
                events: POLLOUT,
                revents: 0,
            };
            let ready = unsafe { WSAPoll(&mut poll, 1, 5_000) };
            if ready == 0 {
                bounded_pending_denial = true;
            } else {
                assert_eq!(
                    ready, 1,
                    "the bounded connect poll failed: result={ready}, revents={}",
                    poll.revents
                );
            }
            if !bounded_pending_denial {
                assert_eq!(
                    poll.revents & POLLNVAL,
                    0,
                    "the child-created connect socket became invalid"
                );
                assert_ne!(
                    poll.revents & (POLLOUT | POLLERR | POLLHUP),
                    0,
                    "the connect probe completed without an expected poll event"
                );
                let mut option_error = 0_i32;
                let mut option_bytes = size_of::<i32>() as i32;
                assert_eq!(
                    unsafe {
                        getsockopt(
                            connect_socket,
                            SOL_SOCKET,
                            SO_ERROR,
                            (&raw mut option_error).cast(),
                            &mut option_bytes,
                        )
                    },
                    0,
                    "read the bounded connect policy result"
                );
                assert_eq!(option_bytes as usize, size_of::<i32>());
                connect_error = option_error;
            }
        }
        let connect_suffix = if bounded_pending_denial {
            BOUNDED_CONNECT_PENDING_SUFFIX
        } else {
            assert_eq!(
                connect_error, WSAEACCES,
                "the child-created socket connect attempt was not denied by AppContainer network policy"
            );
            IMMEDIATE_CONNECT_DENIAL_SUFFIX
        };
        println!("{CONNECT_BLOCKED_PREFIX}{connect_address}{connect_suffix}");

        assert_ne!(
            listen_socket, INVALID_SOCKET,
            "the child did not create a valid bind/listen socket"
        );
        let listen_name = socket_address(listen_address);
        let bind_result = unsafe {
            winsock_bind(
                listen_socket,
                (&raw const listen_name).cast::<SOCKADDR>(),
                size_of::<SOCKADDR_IN>() as i32,
            )
        };
        let bind_error = (bind_result == SOCKET_ERROR).then(|| unsafe { WSAGetLastError() });
        if let Some(bind_error) = bind_error {
            assert_eq!(
                bind_error, WSAEACCES,
                "the child-created socket bind attempt failed unexpectedly"
            );
        }
        let listen_result = unsafe { winsock_listen(listen_socket, 1) };
        let listener_suffix = if listen_result == 0 {
            assert!(bind_error.is_none(), "listen succeeded after a failed bind");
            SETUP_BIND_LISTEN_SUCCESS_SUFFIX
        } else {
            let listen_error = unsafe { WSAGetLastError() };
            if bind_error.is_some() {
                assert_eq!(
                    listen_error, WSAEINVAL,
                    "listen after the policy-denied bind returned an unexpected error"
                );
                DENIED_BIND_LISTEN_SUFFIX
            } else {
                assert_eq!(
                    listen_error, WSAEACCES,
                    "listen after the setup-only bind failed unexpectedly"
                );
                SETUP_BIND_LISTEN_DENIAL_SUFFIX
            }
        };
        println!("{LISTENER_BLOCKED_PREFIX}{listen_address}{listener_suffix}");
    }

    fn assert_path_metadata_denied(path: &PathBuf) {
        assert!(
            fs::metadata(path).is_err(),
            "the LPAC queried metadata for {}",
            path.display()
        );
        assert!(
            fs::symlink_metadata(path).is_err(),
            "the LPAC queried link metadata for {}",
            path.display()
        );
        assert!(
            OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .is_err(),
            "the LPAC opened {} for metadata-only access",
            path.display()
        );
    }

    #[test]
    fn windows_appcontainer_probe_child() {
        run_windows_appcontainer_probe_child(CHILD_TEST, false);
    }

    #[test]
    fn windows_appcontainer_invalid_handle_probe_child() {
        run_windows_appcontainer_probe_child(INVALID_HANDLE_CHILD_TEST, true);
    }

    fn run_windows_appcontainer_probe_child(child_test: &str, invalid_handle_after_arm: bool) {
        crate::configure_noninteractive_fault_reporting()
            .expect("disable interactive fault reporting in the LPAC sentinel");
        let arguments = std::env::args_os().collect::<Vec<_>>();
        let launched_as_probe = arguments
            .windows(2)
            .any(|pair| pair[0] == OsStr::new("--exact") && pair[1] == OsStr::new(child_test));
        if !launched_as_probe {
            return;
        }
        validate_current_process_sandbox().expect("validate child LPAC token and mitigations");
        probe_stage("sandbox");

        let environment = std::env::vars_os().collect::<Vec<_>>();
        assert!(
            std::env::var_os(PARENT_ENVIRONMENT_CANARY).is_none(),
            "the LPAC inherited the parent-only environment canary"
        );
        let mut names = environment
            .iter()
            .map(|(name, _)| name.to_string_lossy().to_ascii_uppercase())
            .collect::<Vec<_>>();
        names.sort();
        let mut expected = ENVIRONMENT_ALLOWLIST
            .iter()
            .map(|name| name.to_ascii_uppercase())
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            names, expected,
            "the LPAC environment was not the explicit loader allowlist: {environment:?}"
        );
        probe_stage("environment");
        let mut request = BufReader::new(std::io::stdin().lock());
        let descriptors = [line(&mut request)];
        let artifact_paths = [PathBuf::from(line(&mut request))];
        let arbitrary_path = PathBuf::from(line(&mut request));
        let child_executable = PathBuf::from(line(&mut request));

        for ((descriptor, expected), artifact_path) in descriptors
            .iter()
            .zip([SUPPLIED_CONTENT])
            .zip(&artifact_paths)
        {
            // SAFETY: each value came from the launcher's explicit handle list,
            // is distinct, and ownership transfers exactly once to this child.
            let mut inherited =
                unsafe { File::from_raw_handle(raw_handle(descriptor) as *mut std::ffi::c_void) };
            let mut observed = Vec::new();
            inherited
                .read_to_end(&mut observed)
                .expect("read the supplied artifact handle");
            assert_eq!(observed, expected);
            assert!(
                inherited.write_all(b"mutation").is_err(),
                "a supplied artifact handle unexpectedly allowed writes"
            );
            assert!(
                File::open(artifact_path).is_err(),
                "the LPAC reopened an artifact by pathname"
            );
            assert!(
                OpenOptions::new().write(true).open(artifact_path).is_err(),
                "the LPAC opened an artifact pathname for mutation"
            );
            assert_path_metadata_denied(artifact_path);
        }
        probe_stage("artifacts");

        assert!(
            File::open(&arbitrary_path).is_err(),
            "the LPAC read an arbitrary file"
        );
        assert!(
            OpenOptions::new()
                .write(true)
                .open(&arbitrary_path)
                .is_err(),
            "the LPAC mutated an arbitrary file"
        );
        assert_path_metadata_denied(&arbitrary_path);
        assert_path_metadata_denied(&child_executable);
        let private_executable = std::env::current_exe().expect("query private executable path");
        let private_directory = std::env::current_dir().expect("query private current directory");
        assert_eq!(
            private_executable.parent(),
            Some(private_directory.as_path())
        );
        assert_ne!(private_executable, child_executable);
        probe_stage("paths");
        assert_network_stack_denied();
        probe_stage("winsock-startup-and-socket-denial");
        assert!(
            Command::new(&child_executable)
                .arg("--help")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_err(),
            "the LPAC spawned an escape child"
        );
        probe_stage("child");

        println!("PRIVATE_RUNTIME={}", private_executable.display());
        println!("{PROBE_READY}");
        std::io::stdout()
            .flush()
            .expect("flush Windows sentinel READY barrier");
        assert_eq!(
            line(&mut request),
            PROBE_ARM,
            "unexpected sentinel arm command"
        );
        println!("{PROBE_ARMED}");
        std::io::stdout()
            .flush()
            .expect("flush Windows sentinel ARMED barrier");

        if invalid_handle_after_arm {
            // Reproduce the reviewer's exact post-handshake fault status as an
            // unhandled noncontinuable exception. The inherited parent error
            // mode and the child WER flag must keep it noninteractive without
            // translating or hiding STATUS_INVALID_HANDLE.
            unsafe {
                windows_sys::Win32::System::Diagnostics::Debug::RaiseException(
                    STATUS_INVALID_HANDLE,
                    windows_sys::Win32::System::SystemServices::EXCEPTION_NONCONTINUABLE,
                    0,
                    ptr::null(),
                )
            };
            panic!("noncontinuable STATUS_INVALID_HANDLE unexpectedly returned");
        }

        // Keep the child blocked on an already-authorized channel. The parent
        // retains its writer, proves this process and its Job are live, and
        // only then closes the final KILL_ON_JOB_CLOSE Job handle.
        let mut unexpected = String::new();
        match request.read_line(&mut unexpected) {
            Ok(0) => panic!("sentinel control channel closed before Job teardown"),
            Ok(_) => panic!("sentinel received data after its ARMED barrier"),
            Err(error) => panic!("sentinel control barrier failed: {error}"),
        }
    }

    #[test]
    fn windows_appcontainer_network_probe_child() {
        crate::configure_noninteractive_fault_reporting()
            .expect("disable interactive fault reporting in the network sentinel");
        let arguments = std::env::args_os().collect::<Vec<_>>();
        let launched_as_probe = arguments.windows(2).any(|pair| {
            pair[0] == OsStr::new("--exact") && pair[1] == OsStr::new(NETWORK_CHILD_TEST)
        });
        if !launched_as_probe {
            return;
        }
        validate_current_process_sandbox()
            .expect("validate zero-capability AppContainer token and mitigations");
        let mut winsock_data = WSADATA::default();
        assert_eq!(
            unsafe { WSAStartup(0x0202, &mut winsock_data) },
            0,
            "the less-restricted AppContainer must initialize Winsock for the network-policy probe"
        );

        let mut request = BufReader::new(std::io::stdin().lock());
        let connect_address = line(&mut request)
            .parse::<SocketAddr>()
            .expect("parent supplied a concrete live connect address");
        let listen_address = line(&mut request)
            .parse::<SocketAddr>()
            .expect("parent supplied a concrete listen-probe address");
        let new_nonblocking_socket = || {
            let socket =
                unsafe { WSASocketW(AF_INET.into(), SOCK_STREAM, IPPROTO_TCP, ptr::null(), 0, 0) };
            assert_ne!(
                socket, INVALID_SOCKET,
                "the zero-network-capability AppContainer could not create a probe socket"
            );
            let socket = unsafe { OwnedSocket::from_raw_socket(socket as u64) };
            let mut nonblocking = 1_u32;
            assert_eq!(
                unsafe { ioctlsocket(socket.as_raw_socket() as SOCKET, FIONBIO, &mut nonblocking) },
                0,
                "make child-created network probe socket nonblocking"
            );
            socket
        };
        let connect_socket = new_nonblocking_socket();
        let listen_socket = new_nonblocking_socket();
        assert_concrete_network_endpoints_denied(
            connect_socket.as_raw_socket() as SOCKET,
            listen_socket.as_raw_socket() as SOCKET,
            connect_address,
            listen_address,
        );
        println!(
            "PRIVATE_RUNTIME={}",
            std::env::current_exe()
                .expect("query network sentinel private executable")
                .display()
        );
        println!("{NETWORK_PROBE_OK}");
        std::io::stdout()
            .flush()
            .expect("flush AppContainer network sentinel handshake");
        let parent_result = line(&mut request);
        let parent_refused = format!("{NETWORK_PARENT_CHECKED}|connect-error={WSAECONNREFUSED}");
        let parent_timed_out = format!("{NETWORK_PARENT_CHECKED}|connect-error={WSAETIMEDOUT}");
        let parent_bounded_timeout = format!("{NETWORK_PARENT_CHECKED}|connect=timeout");
        assert!(
            parent_result == parent_refused
                || parent_result == parent_timed_out
                || parent_result == parent_bounded_timeout,
            "the parent did not attest its exact inbound-connect result"
        );
        println!(
            "{PARENT_CONNECT_BLOCKED_PREFIX}{listen_address}{}",
            parent_result
                .strip_prefix(NETWORK_PARENT_CHECKED)
                .expect("validated parent result prefix")
        );
        let accepted = unsafe {
            winsock_accept(
                listen_socket.as_raw_socket() as SOCKET,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(
            accepted, INVALID_SOCKET,
            "the zero-network-capability AppContainer accepted an inbound connection"
        );
        let accept_error = unsafe { WSAGetLastError() };
        assert_eq!(
            accept_error, WSAEWOULDBLOCK,
            "the child listener returned an unexpected bounded accept result"
        );
        println!("{CHILD_ACCEPT_BLOCKED_PREFIX}{listen_address}{CHILD_ACCEPT_WOULD_BLOCK_SUFFIX}");
        std::io::stdout()
            .flush()
            .expect("flush exact AppContainer network outcomes");
        drop(connect_socket);
        drop(listen_socket);
        assert_eq!(unsafe { WSACleanup() }, 0);
    }

    fn run_regular_appcontainer_network_sentinel(
        record: &ProductionV3VerifierRecord,
        sentinel_executable: &PathBuf,
        sentinel_sha256: [u8; 32],
    ) {
        let route_probe = UdpSocket::bind("0.0.0.0:0").expect("bind route probe");
        route_probe
            .connect("192.0.2.1:9")
            .expect("select a concrete non-loopback network interface");
        let local_ip = route_probe
            .local_addr()
            .expect("query route-probe address")
            .ip();
        assert!(
            !local_ip.is_loopback() && !local_ip.is_unspecified(),
            "the AppContainer network sentinel requires a concrete non-loopback interface"
        );
        drop(route_probe);

        let listener = TcpListener::bind("0.0.0.0:0").expect("bind parent network sentinel");
        listener
            .set_nonblocking(true)
            .expect("make parent network sentinel nonblocking");
        let connect_address = SocketAddr::new(
            local_ip,
            listener
                .local_addr()
                .expect("network sentinel address")
                .port(),
        );
        let listen_probe = TcpListener::bind(SocketAddr::new(local_ip, 0))
            .expect("reserve a concrete bind/listen sentinel address");
        let listen_address = listen_probe
            .local_addr()
            .expect("bind/listen sentinel address");
        drop(listen_probe);

        let mut command = Command::new(sentinel_executable);
        command
            .arg("--exact")
            .arg(NETWORK_CHILD_TEST)
            .arg("--nocapture")
            .env_clear()
            .current_dir(
                sentinel_executable
                    .parent()
                    .expect("network sentinel source has a parent"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (mut child, _) = spawn_contained_production_windows_inner(
            command,
            record,
            1024 * 1024 * 1024,
            sentinel_sha256,
            false,
            false,
            None,
        )
        .expect("launch the less-restricted zero-capability AppContainer network sentinel");
        let mut stdin = child.take_stdin().expect("network sentinel stdin");
        writeln!(stdin, "{connect_address}").expect("send concrete connect endpoint");
        writeln!(stdin, "{listen_address}").expect("send concrete bind/listen endpoint");

        let stdout = child.take_stdout().expect("network sentinel stdout");
        let (line_tx, line_rx) = mpsc::channel();
        let (output_tx, output_rx) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            let mut output = String::new();
            let result = loop {
                let mut line = String::new();
                match stdout.read_line(&mut line) {
                    Ok(0) => break Ok(()),
                    Ok(_) => {
                        output.push_str(&line);
                        let _ = line_tx.send(line.trim_end_matches(['\r', '\n']).to_owned());
                    }
                    Err(error) => break Err(error),
                }
            };
            let _ = output_tx.send((result, output));
        });
        let immediate_connect_result =
            format!("{CONNECT_BLOCKED_PREFIX}{connect_address}{IMMEDIATE_CONNECT_DENIAL_SUFFIX}");
        let bounded_connect_result =
            format!("{CONNECT_BLOCKED_PREFIX}{connect_address}{BOUNDED_CONNECT_PENDING_SUFFIX}");
        let denied_bind_result =
            format!("{LISTENER_BLOCKED_PREFIX}{listen_address}{DENIED_BIND_LISTEN_SUFFIX}");
        let setup_bind_result =
            format!("{LISTENER_BLOCKED_PREFIX}{listen_address}{SETUP_BIND_LISTEN_DENIAL_SUFFIX}");
        let setup_listener_result =
            format!("{LISTENER_BLOCKED_PREFIX}{listen_address}{SETUP_BIND_LISTEN_SUCCESS_SUFFIX}");
        let handshake_deadline = Instant::now() + Duration::from_secs(15);
        let mut connect_result_seen = false;
        let mut listener_result_seen = false;
        let mut handshake_seen = false;
        let mut parent_connect_result = None;
        loop {
            let remaining = handshake_deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "the bounded AppContainer network sentinel did not report its results"
            );
            let line = match line_rx.recv_timeout(remaining) {
                Ok(line) => line,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("the bounded AppContainer network sentinel timed out")
                }
            };
            connect_result_seen |=
                line == immediate_connect_result || line == bounded_connect_result;
            listener_result_seen |= line == denied_bind_result
                || line == setup_bind_result
                || line == setup_listener_result;
            if line == NETWORK_PROBE_OK {
                handshake_seen = true;
                break;
            }
        }
        if handshake_seen {
            assert!(
                connect_result_seen,
                "network sentinel did not attest an exact bounded connect result"
            );
            assert!(
                listener_result_seen,
                "network sentinel did not attest an exact listener-denial result"
            );
            let inbound_error = TcpStream::connect_timeout(&listen_address, Duration::from_secs(2))
                .expect_err(
                    "the zero-network-capability AppContainer acquired inbound listener authority",
                );
            let inbound_outcome = match inbound_error.raw_os_error() {
                Some(error @ (WSAECONNREFUSED | WSAETIMEDOUT)) => {
                    format!("connect-error={error}")
                }
                None if inbound_error.kind() == io::ErrorKind::TimedOut => "connect=timeout".into(),
                _ => {
                    panic!(
                        "the parent received an unexpected inbound-connect result {inbound_error}"
                    )
                }
            };
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
                "the zero-network-capability AppContainer reached the parent listener"
            );
            writeln!(stdin, "{NETWORK_PARENT_CHECKED}|{inbound_outcome}")
                .expect("acknowledge independent parent network checks");
            parent_connect_result = Some(format!(
                "{PARENT_CONNECT_BLOCKED_PREFIX}{listen_address}|{inbound_outcome}"
            ));
        }
        drop(stdin);

        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().expect("query network sentinel") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the bounded AppContainer network sentinel did not exit"
            );
            thread::sleep(Duration::from_millis(5));
        };
        let (read_result, output) = output_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("receive network sentinel output");
        read_result.expect("read network sentinel output");
        reader.join().expect("join network sentinel output reader");
        if !status.success() {
            let mut stderr = String::new();
            child
                .take_stderr()
                .expect("network sentinel stderr")
                .read_to_string(&mut stderr)
                .expect("read network sentinel stderr");
            panic!(
                "AppContainer network sentinel failed: status={status:?}, stdout={output:?}, stderr={stderr:?}"
            );
        }
        assert!(output.lines().any(|line| line == NETWORK_PROBE_OK));
        let parent_connect_result =
            parent_connect_result.expect("the parent completed its inbound-connect probe");
        assert!(
            output.lines().any(|line| line == parent_connect_result),
            "the child did not echo the exact parent inbound-connect result: {output:?}"
        );
        let accept_result = format!(
            "{CHILD_ACCEPT_BLOCKED_PREFIX}{listen_address}{CHILD_ACCEPT_WOULD_BLOCK_SUFFIX}"
        );
        assert!(
            output.lines().any(|line| line == accept_result),
            "the child did not attest the exact bounded accept result: {output:?}"
        );
        let private_executable = output
            .lines()
            .find_map(|line| line.strip_prefix("PRIVATE_RUNTIME="))
            .map(PathBuf::from)
            .expect("network sentinel reported its private executable");
        let private_directory = private_executable
            .parent()
            .expect("network sentinel private executable has a parent")
            .to_owned();
        drop(child);
        assert!(
            !private_executable.exists() && !private_directory.exists(),
            "the network sentinel private runtime remained after cleanup"
        );
        let rebound = TcpListener::bind(listen_address)
            .expect("the AppContainer must not occupy its requested listen endpoint");
        drop(rebound);
        drop(listener);
    }

    fn run_appcontainer_launcher_sentinel(invalid_handle_after_arm: bool) {
        crate::configure_noninteractive_fault_reporting()
            .expect("disable inherited interactive fault reporting before CreateProcessW");
        let _ledger = isolated_appcontainer_ledger_test();
        let files = TestDirectory::create();
        let artifact_paths = [files.write("record-v2.json", SUPPLIED_CONTENT)];
        let arbitrary_path = files.write("arbitrary-secret.txt", b"ambient-secret");
        let omitted_path = files.write("omitted-handle-identity.bin", b"must-not-be-inherited");
        let omitted_source = File::open(&omitted_path).expect("open omitted-handle identity file");
        let omitted_identity = windows_file_identity(&omitted_source)
            .expect("query omitted-handle 128-bit file identity");
        let omitted = super::duplicate_inheritable(omitted_source.as_raw_handle().cast())
            .expect("create omitted inheritable identity handle");

        let current_executable = std::env::current_exe().expect("locate test executable");
        let sentinel_executable = files.0.join("cmfd-windows-sentinel.exe");
        fs::copy(&current_executable, &sentinel_executable)
            .expect("copy the sentinel into a private runtime directory");
        let sentinel_executable =
            fs::canonicalize(sentinel_executable).expect("canonicalize sentinel executable");
        let sentinel_sha256 = {
            let bytes = fs::read(&sentinel_executable).expect("hash sentinel executable");
            <[u8; 32]>::from(Sha256::digest(bytes))
        };
        let mut command = Command::new(&sentinel_executable);
        command
            .arg("--exact")
            .arg(if invalid_handle_after_arm {
                INVALID_HANDLE_CHILD_TEST
            } else {
                CHILD_TEST
            })
            .arg("--nocapture")
            .env_clear()
            .current_dir(&files.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let record = ProductionV3VerifierRecord {
            record_v2: artifact_paths[0].clone(),
            expected_file: record_identity(SUPPLIED_CONTENT),
        };
        let mut omitted_probe = |process| {
            require_omitted_handle_absent_before_resume(
                process,
                omitted.as_raw_handle().cast(),
                omitted_identity,
            )
        };
        let (mut child, descriptors) = spawn_contained_production_windows_inner(
            command,
            &record,
            1024 * 1024 * 1024,
            sentinel_sha256,
            false,
            true,
            Some(&mut omitted_probe),
        )
        .expect("launch the native LPAC sentinel");
        let child_id = child.id();
        let mut stdin = child.take_stdin().expect("sentinel stdin");
        if let Err(source) = writeln!(stdin, "{descriptors}") {
            let status = child.try_wait().expect("query failed sentinel status");
            if status.is_none() {
                child.terminate_tree().expect("terminate failed sentinel");
            }
            let mut stderr = String::new();
            child
                .take_stderr()
                .expect("sentinel stderr")
                .read_to_string(&mut stderr)
                .expect("read failed sentinel stderr");
            panic!(
                "LPAC sentinel closed stdin before its request: source={source}, status={status:?}, stderr={stderr:?}"
            );
        }
        for path in &artifact_paths {
            writeln!(stdin, "{}", path.display()).expect("send artifact pathname");
        }
        writeln!(stdin, "{}", arbitrary_path.display()).expect("send arbitrary pathname");
        writeln!(stdin, "{}", sentinel_executable.display()).expect("send child pathname");
        stdin.flush().expect("flush sentinel request");

        let stdout = child.take_stdout().expect("sentinel stdout");
        let (line_tx, line_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut output = String::new();
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        output.push_str(&line);
                        if line_tx.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
            output
        });
        let mut private_executable = None;
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = ready_deadline.saturating_duration_since(Instant::now());
            let line = line_rx.recv_timeout(remaining).unwrap_or_else(|error| {
                child
                    .terminate_tree()
                    .expect("terminate sentinel missing READY");
                let status = child.try_wait().expect("query sentinel missing READY");
                panic!("LPAC sentinel did not reach READY: {error}; status={status:?}")
            });
            if let Some(path) = line.trim_end().strip_prefix("PRIVATE_RUNTIME=") {
                private_executable = Some(PathBuf::from(path));
            }
            if line.trim_end() == PROBE_READY {
                break;
            }
        }
        assert_eq!(
            child.try_wait().expect("query READY sentinel status"),
            None,
            "LPAC sentinel exited at its READY barrier"
        );
        writeln!(stdin, "{PROBE_ARM}").expect("arm LPAC sentinel teardown barrier");
        stdin.flush().expect("flush LPAC sentinel ARM command");
        let armed_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = armed_deadline.saturating_duration_since(Instant::now());
            let line = line_rx.recv_timeout(remaining).unwrap_or_else(|error| {
                child
                    .terminate_tree()
                    .expect("terminate sentinel missing ARMED");
                let status = child.try_wait().expect("query sentinel missing ARMED");
                panic!("LPAC sentinel did not reach ARMED: {error}; status={status:?}")
            });
            if line.trim_end() == PROBE_ARMED {
                break;
            }
        }
        let private_executable = private_executable
            .expect("sentinel reported its exact private executable path before READY");
        let private_directory = private_executable
            .parent()
            .expect("private executable has a directory")
            .to_owned();
        if invalid_handle_after_arm {
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = child
                    .try_wait()
                    .expect("query invalid-handle regression process")
                {
                    break status;
                }
                assert!(
                    Instant::now() < deadline,
                    "the post-ARM invalid-handle regression did not terminate"
                );
                thread::sleep(Duration::from_millis(5));
            };
            let error = require_expected_job_close_exit(status)
                .expect_err("STATUS_INVALID_HANDLE must never satisfy Job-close validation");
            assert!(
                error.to_string().contains("STATUS_INVALID_HANDLE"),
                "invalid-handle regression produced the wrong rejection: {error}; raw={status:?}"
            );
            drop(stdin);
            let output = reader.join().expect("join invalid-handle sentinel reader");
            let mut stderr = String::new();
            child
                .take_stderr()
                .expect("invalid-handle sentinel stderr")
                .read_to_string(&mut stderr)
                .expect("read invalid-handle sentinel stderr");
            panic!(
                "post-handshake invalid-handle death rejected before Job close: {error}; raw={status:?}; stdout={output:?}; stderr={stderr:?}"
            );
        }
        if let Some(status) = child.try_wait().expect("query ARMED sentinel status") {
            panic!("{}; raw={status:?}", reject_preclose_exit(status));
        }
        let active_processes = child
            .job_active_processes_for_test()
            .expect("query Job accounting before close");
        if active_processes != 1 {
            let status = child
                .try_wait()
                .expect("classify sentinel after unexpected Job accounting");
            panic!(
                "the sentinel Job reported {active_processes} active processes instead of exactly one immediately before close; status={status:?}; classification={:?}",
                status.map(reject_preclose_exit)
            );
        }
        if let Some(status) = child
            .try_wait()
            .expect("query sentinel immediately before Job close")
        {
            panic!("{}; raw={status:?}", reject_preclose_exit(status));
        }
        let close_started = Instant::now();
        assert!(
            child.close_job_handle_without_termination_for_test(),
            "sentinel did not own the final atomic-launch Job handle"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().expect("query sentinel process") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "closing the final kill-on-close Job handle did not reap sentinel PID {child_id}"
            );
            thread::sleep(Duration::from_millis(5));
        };
        assert!(
            close_started.elapsed() < Duration::from_secs(5),
            "the ARMED sentinel was not reaped promptly after the final Job handle closed"
        );
        require_expected_job_close_exit(status).unwrap_or_else(|error| {
            panic!("invalid Job-close exit classification: {error}; raw={status:?}")
        });
        drop(stdin);
        let output = reader.join().expect("join sentinel output reader");
        assert!(
            output.lines().any(|line| line == PROBE_READY)
                && output.lines().any(|line| line == PROBE_ARMED),
            "sentinel output did not retain both teardown barriers: {output:?}"
        );
        drop(child);
        assert!(
            !private_executable.exists() && !private_directory.exists(),
            "the per-launch private runtime remained after process/profile cleanup: {}",
            private_directory.display()
        );
        drop(omitted);
        drop(omitted_source);

        for (path, expected) in artifact_paths.iter().zip([SUPPLIED_CONTENT]) {
            assert_eq!(
                fs::read(path).expect("reread immutable artifact"),
                expected,
                "the LPAC mutated a supplied artifact"
            );
        }
        assert_eq!(
            fs::read(arbitrary_path).expect("reread arbitrary file"),
            b"ambient-secret"
        );
        run_regular_appcontainer_network_sentinel(&record, &sentinel_executable, sentinel_sha256);
    }

    #[test]
    fn windows_appcontainer_parent_probe() {
        crate::configure_noninteractive_fault_reporting()
            .expect("disable interactive fault reporting in the sentinel parent");
        let arguments = std::env::args_os().collect::<Vec<_>>();
        let launched_as_parent = arguments
            .windows(2)
            .any(|pair| pair[0] == OsStr::new("--exact") && pair[1] == OsStr::new(PARENT_TEST));
        if !launched_as_parent {
            return;
        }
        assert_eq!(
            std::env::var(PARENT_ENVIRONMENT_CANARY).as_deref(),
            Ok(PARENT_ENVIRONMENT_CANARY_VALUE),
            "the native sentinel parent did not receive its ambient canary"
        );
        run_appcontainer_launcher_sentinel(false);
    }

    #[test]
    fn windows_appcontainer_invalid_handle_parent_probe() {
        crate::configure_noninteractive_fault_reporting()
            .expect("disable interactive fault reporting in the invalid-handle parent");
        let arguments = std::env::args_os().collect::<Vec<_>>();
        let launched_as_parent = arguments.windows(2).any(|pair| {
            pair[0] == OsStr::new("--exact") && pair[1] == OsStr::new(INVALID_HANDLE_PARENT_TEST)
        });
        if launched_as_parent {
            run_appcontainer_launcher_sentinel(true);
        }
    }

    #[test]
    fn appcontainer_launcher_denies_ambient_authority_and_job_teardown_reaps_worker() {
        crate::configure_noninteractive_fault_reporting()
            .expect("disable inherited interactive fault reporting in the libtest parent");
        let executable = std::env::current_exe().expect("locate Windows sentinel test executable");
        for attempt in 0..3 {
            let output = Command::new(&executable)
                .arg("--exact")
                .arg(PARENT_TEST)
                .arg("--nocapture")
                .env(PARENT_ENVIRONMENT_CANARY, PARENT_ENVIRONMENT_CANARY_VALUE)
                .output()
                .expect("launch native Windows sentinel parent with an ambient canary");
            assert!(
                output.status.success(),
                "native Windows sentinel parent attempt {attempt} failed: status={:?}, stdout={:?}, stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn post_handshake_invalid_handle_death_is_rejected_without_fault_ui() {
        crate::configure_noninteractive_fault_reporting()
            .expect("disable inherited fault UI in the invalid-handle regression parent");
        let executable = std::env::current_exe().expect("locate Windows sentinel test executable");
        let started = Instant::now();
        let output = Command::new(executable)
            .arg("--exact")
            .arg(INVALID_HANDLE_PARENT_TEST)
            .arg("--nocapture")
            .output()
            .expect("launch invalid-handle sentinel regression parent");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "invalid-handle regression was not noninteractive and bounded"
        );
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("post-handshake invalid-handle death rejected before Job close")
                && stderr.contains("STATUS_INVALID_HANDLE")
                && stderr.contains("0xc0000008"),
            "invalid-handle death was not rejected with exact diagnostics: status={:?}, stdout={:?}, stderr={stderr:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn appcontainer_profile_collision_is_not_adopted_and_created_profiles_are_removed() {
        let _ledger = isolated_appcontainer_ledger_test();
        let name = random_profile_name("profile-regression");
        let display = nul_terminated(OsStr::new("Common Foundry profile regression")).unwrap();
        let description = nul_terminated(OsStr::new("Owned test profile")).unwrap();

        let mut unrelated = try_create_untracked_test_profile(name.clone(), &display, &description)
            .unwrap()
            .expect("create an RAII-owned unrelated profile registration");

        retry_pending_appcontainer_profile_cleanup().unwrap();
        assert!(
            try_create_profile(name.clone(), &display, &description)
                .unwrap()
                .is_none(),
            "an existing profile must be reported as a collision"
        );
        assert!(
            try_create_profile(name.clone(), &display, &description)
                .unwrap()
                .is_none(),
            "the collision path deleted or adopted the unrelated existing profile"
        );

        unrelated
            .delete_registration()
            .expect("delete the attested unrelated registration");

        let mut recreated = try_create_profile(name, &display, &description)
            .unwrap()
            .expect("deleted profile name is immediately reusable");
        recreated
            .registration
            .as_mut()
            .expect("recreated registration")
            .delete()
            .expect("delete recreated profile without leaving registration state");
    }

    #[test]
    fn appcontainer_profile_and_runtime_forced_panic_child() {
        let Some(source) = std::env::var_os(PANIC_CLEANUP_CHILD_ENV) else {
            return;
        };
        let source = PathBuf::from(source);
        let expected = <[u8; 32]>::from(Sha256::digest(
            fs::read(&source).expect("read forced-panic source executable"),
        ));
        let profile = CreatedProfile::create().expect("create forced-panic profile");
        let _runtime = PrivateLaunchRuntime::create(&source, expected, profile.sid())
            .expect("create forced-panic private runtime");
        let _profile = profile;
        eprintln!("CMFD_FORCED_PROFILE_PANIC_READY");
        std::io::stderr().flush().unwrap();
        panic!("forced RAII cleanup panic");
    }

    #[test]
    fn forced_panic_leaves_exact_profile_and_temp_identity_sets_unchanged() {
        let _ledger = isolated_appcontainer_ledger_test();
        let files = TestDirectory::create();
        let source = files.write("panic-source.exe", b"forced panic cleanup source");
        let executable = std::env::current_exe().expect("locate test executable");

        for attempt in 0..3 {
            let profiles_before = cmfd_profile_mapping_snapshot();
            let temp_before = appcontainer_temp_root_snapshot();
            let output = Command::new(&executable)
                .arg("--exact")
                .arg("windows_launcher::tests::appcontainer_profile_and_runtime_forced_panic_child")
                .arg("--nocapture")
                .env(PANIC_CLEANUP_CHILD_ENV, &source)
                .output()
                .expect("launch forced-panic profile cleanup child");
            assert!(
                !output.status.success(),
                "forced-panic child attempt {attempt} unexpectedly succeeded"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("CMFD_FORCED_PROFILE_PANIC_READY")
                    && stderr.contains("forced RAII cleanup panic"),
                "forced-panic child attempt {attempt} failed before the guarded panic: {stderr}"
            );

            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let profiles_after = cmfd_profile_mapping_snapshot();
                let temp_after = appcontainer_temp_root_snapshot();
                if profiles_after == profiles_before && temp_after == temp_before {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "forced-panic attempt {attempt} left profile/temp residue: profiles_before={profiles_before:?}, profiles_after={profiles_after:?}, temp_before={temp_before:?}, temp_after={temp_after:?}"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    fn dacl_snapshot(path: &std::path::Path) -> Vec<u8> {
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GetFileSecurityW};

        let path = nul_terminated(path.as_os_str()).unwrap();
        let mut needed = 0_u32;
        unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        assert_ne!(needed, 0, "query DACL descriptor size");
        let mut descriptor = vec![0_u8; needed as usize];
        assert_ne!(
            unsafe {
                GetFileSecurityW(
                    path.as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    descriptor.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            },
            0,
            "read DACL descriptor: {}",
            io::Error::last_os_error()
        );
        descriptor.truncate(needed as usize);
        descriptor
    }

    #[test]
    fn private_runtime_rejects_source_hardlinks_reparse_points_and_hash_swaps() {
        let _ledger = isolated_appcontainer_ledger_test();
        let files = TestDirectory::create();
        let source = files.write("source.exe", b"expected worker bytes");
        let expected = <[u8; 32]>::from(Sha256::digest(b"expected worker bytes"));
        let alias = files.0.join("source-alias.exe");
        fs::hard_link(&source, &alias).expect("create source hardlink ambiguity");
        let mut profile = CreatedProfile::create().expect("create private-copy profile");
        assert!(
            PrivateLaunchRuntime::create(&source, expected, profile.sid()).is_err(),
            "a multi-link source executable was accepted"
        );
        fs::remove_file(alias).expect("remove source hardlink");

        fs::write(&source, b"swapped worker bytes").expect("replace source contents");
        assert!(
            PrivateLaunchRuntime::create(&source, expected, profile.sid()).is_err(),
            "a source swap with the wrong pinned hash was accepted"
        );
        fs::write(&source, b"expected worker bytes").expect("restore source contents");

        let reparse = files.0.join("source-link.exe");
        if std::os::windows::fs::symlink_file(&source, &reparse).is_ok() {
            assert!(
                PrivateLaunchRuntime::create(&reparse, expected, profile.sid()).is_err(),
                "a reparse-point source executable was accepted"
            );
            fs::remove_file(reparse).expect("remove source symlink");
        }
        profile.delete_registration().unwrap();
    }

    #[test]
    fn private_runtime_pins_write_delete_and_detects_destination_hardlinks() {
        const PROCESS_CHILD: &str = "CMFD_PRIVATE_RUNTIME_HARDLINK_CHILD";
        const QUARANTINE_MANIFEST: &str = "CMFD_PRIVATE_RUNTIME_QUARANTINE_MANIFEST";
        if std::env::var_os(PROCESS_CHILD).is_none() {
            let _ledger = isolated_appcontainer_ledger_test();
            let manifest = std::env::temp_dir().join(format!(
                "cmfd-private-runtime-quarantine-{}-{}.txt",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(
                    "windows_launcher::tests::private_runtime_pins_write_delete_and_detects_destination_hardlinks",
                )
                .arg("--nocapture")
                .env(PROCESS_CHILD, "1")
                .env(QUARANTINE_MANIFEST, &manifest)
                .output()
                .expect("run hardlink cleanup isolation child");
            assert!(
                output.status.success(),
                "hardlink isolation child failed: stdout={:?}, stderr={:?}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let paths = fs::read_to_string(&manifest)
                .expect("read hardlink cleanup quarantine manifest")
                .lines()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            assert_eq!(paths.len(), 2);
            assert!(paths[0].is_file());
            assert!(paths[1].is_dir());
            fs::remove_file(&paths[0]).expect("remove retained exact destination after child exit");
            fs::remove_dir(&paths[1]).expect("remove retained private directory after child exit");
            fs::remove_file(manifest).expect("remove hardlink cleanup quarantine manifest");
            return;
        }

        let files = TestDirectory::create();
        let source = files.write("source.exe", b"private runtime pin test");
        let expected = <[u8; 32]>::from(Sha256::digest(b"private runtime pin test"));
        let mut profile = CreatedProfile::create().expect("create private-copy profile");
        let runtime =
            PrivateLaunchRuntime::create(&source, expected, profile.sid()).expect("private copy");
        assert!(OpenOptions::new().write(true).open(&source).is_err());
        assert!(fs::remove_file(&source).is_err());
        assert!(
            OpenOptions::new()
                .write(true)
                .open(runtime.executable_path())
                .is_err()
        );
        assert!(fs::remove_file(runtime.executable_path()).is_err());
        assert!(fs::remove_dir(runtime.directory_path()).is_err());
        let replacement = files.write("replacement.exe", b"replacement bytes");
        assert!(
            fs::rename(&replacement, runtime.executable_path()).is_err(),
            "the pinned destination path was replaced"
        );
        let moved = files.0.join("moved-destination.exe");
        assert!(
            fs::rename(runtime.executable_path(), &moved).is_err(),
            "the pinned destination object was moved out of its verified path"
        );
        let moved_directory = files.0.join("moved-runtime-directory");
        assert!(
            fs::rename(runtime.directory_path(), &moved_directory).is_err(),
            "the pinned private directory was replaced"
        );
        assert!(
            std::os::windows::fs::symlink_file(&source, runtime.executable_path()).is_err(),
            "a reparse point replaced the pinned destination"
        );
        runtime
            .verify_bound()
            .expect("pinned identities remain exact");

        let alias = files.0.join("destination-alias.exe");
        fs::hard_link(runtime.executable_path(), &alias)
            .expect("same-user hardlink race is detectable");
        assert!(
            runtime.verify_bound().is_err(),
            "destination hardlink ambiguity was not detected before resume"
        );
        let private_directory = runtime.directory_path().to_owned();
        let private_executable = runtime.executable_path().to_owned();
        profile.delete_registration().unwrap();
        drop(runtime);
        assert!(
            private_executable.exists() && private_directory.exists(),
            "ambiguous hardlink cleanup must retain rather than delete by pathname"
        );
        fs::remove_file(alias).expect("remove destination hardlink alias");
        fs::remove_file(replacement).expect("remove destination replacement candidate");
        let manifest = PathBuf::from(
            std::env::var_os(QUARANTINE_MANIFEST)
                .expect("hardlink cleanup quarantine manifest path"),
        );
        fs::write(
            manifest,
            format!(
                "{}\n{}\n",
                private_executable.display(),
                private_directory.display()
            ),
        )
        .expect("write hardlink cleanup quarantine manifest");
    }

    #[test]
    fn concurrent_private_runtimes_leave_shared_acls_exact_and_no_private_objects() {
        const PROCESS_CHILD: &str = "CMFD_PRIVATE_RUNTIME_PROCESS_CHILD";
        const PROCESS_SOURCE: &str = "CMFD_PRIVATE_RUNTIME_PROCESS_SOURCE";
        if std::env::var_os(PROCESS_CHILD).is_some() {
            let source =
                PathBuf::from(std::env::var_os(PROCESS_SOURCE).expect("cross-process source path"));
            let expected = <[u8; 32]>::from(Sha256::digest(b"concurrent private copy"));
            let mut profile = CreatedProfile::create().expect("create process-local profile");
            let runtime = PrivateLaunchRuntime::create(&source, expected, profile.sid())
                .expect("create process-local private runtime");
            let directory = runtime.directory_path().to_owned();
            let executable = runtime.executable_path().to_owned();
            runtime
                .verify_bound()
                .expect("verify process-local private runtime");
            thread::sleep(Duration::from_millis(100));
            drop(runtime);
            assert!(!directory.exists() && !executable.exists());
            profile
                .delete_registration()
                .expect("delete process-local profile");
            crate::process::shutdown_appcontainer_profile_cleanup()
                .expect("remove process-local cleanup ledger session");
            return;
        }

        let _ledger = isolated_appcontainer_ledger_test();
        let files = TestDirectory::create();
        let source = files.write("shared-worker.exe", b"concurrent private copy");
        let expected = <[u8; 32]>::from(Sha256::digest(b"concurrent private copy"));
        let directory_dacl = dacl_snapshot(&files.0);
        let source_dacl = dacl_snapshot(&source);

        let mut processes = Vec::new();
        for _ in 0..4 {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg(
                    "windows_launcher::tests::concurrent_private_runtimes_leave_shared_acls_exact_and_no_private_objects",
                )
                .arg("--nocapture")
                .env(PROCESS_CHILD, "1")
                .env(PROCESS_SOURCE, &source)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            processes.push(command.spawn().expect("spawn concurrent runtime process"));
        }
        for process in processes {
            let output = process
                .wait_with_output()
                .expect("wait for concurrent runtime process");
            assert!(
                output.status.success(),
                "concurrent runtime process failed: stdout={:?}, stderr={:?}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(dacl_snapshot(&files.0), directory_dacl);
        assert_eq!(dacl_snapshot(&source), source_dacl);

        let barrier = Arc::new(Barrier::new(4));
        let mut threads = Vec::new();
        for _ in 0..4 {
            let source = source.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                let mut profile = CreatedProfile::create().expect("create concurrent profile");
                barrier.wait();
                let runtime = PrivateLaunchRuntime::create(&source, expected, profile.sid())
                    .expect("create concurrent private runtime");
                let directory = runtime.directory_path().to_owned();
                let executable = runtime.executable_path().to_owned();
                runtime
                    .verify_bound()
                    .expect("verify concurrent private runtime");
                thread::sleep(Duration::from_millis(20));
                drop(runtime);
                assert!(!directory.exists() && !executable.exists());
                profile
                    .delete_registration()
                    .expect("delete concurrent profile");
            }));
        }
        for thread in threads {
            thread.join().expect("concurrent private runtime worker");
        }
        assert_eq!(dacl_snapshot(&files.0), directory_dacl);
        assert_eq!(dacl_snapshot(&source), source_dacl);
    }
}
