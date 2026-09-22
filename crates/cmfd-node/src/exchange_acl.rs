//! Windows access-control checks for exchange custody files.
//!
//! These checks intentionally validate the security descriptor attached to the
//! retained file handle. Path-only ACL checks are insufficient because a path
//! can be retargeted between open and validation.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
#[cfg(feature = "production-v4")]
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{addr_of, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AccessCheck, AclSizeInformation,
    DACL_SECURITY_INFORMATION, DuplicateToken, EqualSid, GENERIC_MAPPING,
    GROUP_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetTokenInformation, IsValidAcl, IsValidSecurityDescriptor,
    IsValidSid, IsWellKnownSid, LookupAccountNameW, MapGenericMask, OWNER_SECURITY_INFORMATION,
    PRIVILEGE_SET, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_MAX_SID_SIZE, SecurityImpersonation, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
    WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA, FileAttributeTagInfo, GetFileInformationByHandleEx, GetFileType, READ_CONTROL,
    WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const FILE_MAPPING: GENERIC_MAPPING = GENERIC_MAPPING {
    GenericRead: FILE_GENERIC_READ,
    GenericWrite: FILE_GENERIC_WRITE,
    GenericExecute: FILE_GENERIC_EXECUTE,
    GenericAll: FILE_ALL_ACCESS,
};

const CONTENT_READ: u32 = FILE_READ_DATA;
const MUTATING_ACCESS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;
const DIRECTORY_MUTATING_ACCESS: u32 = MUTATING_ACCESS | FILE_DELETE_CHILD;
const ANCESTOR_REPLACEMENT_ACCESS: u32 =
    FILE_DELETE_CHILD | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
const MAX_PRIVILEGE_SET_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsCustodyFilePolicy {
    JournalKey,
    ExternalReadOnly,
    ExternalSecretReadOnly,
    DurableJournal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyObjectKind {
    File,
    Directory,
    ExternalAncestorDirectory,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WindowsCustodyAclError {
    #[error("{operation} `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Windows custody ACL policy rejected `{path}`: {reason}")]
    Policy { path: PathBuf, reason: &'static str },
}

/// Validates a retained custody file and its containing directory authority.
/// Node-owned material requires its immediate parent. External controls require
/// every ancestor through the volume root so a nominally read-only subtree
/// cannot be renamed and replaced through a writable grandparent. The caller
/// must open external control files read-only.
pub(crate) fn validate_windows_custody_path_acl(
    file: &File,
    path: &Path,
    policy: WindowsCustodyFilePolicy,
) -> Result<(), WindowsCustodyAclError> {
    validate_windows_custody_path_acl_inner(file, path, policy, None)
}

/// Applies the runtime ACL policy plus an exact qualification allowlist. Any
/// owner or allow ACE carrying protected access for an unlisted SID is
/// rejected. SYSTEM, Administrators, and service identities are not implicit;
/// callers must include every intended SID explicitly.
pub(crate) fn validate_windows_custody_path_acl_with_authorities(
    file: &File,
    path: &Path,
    policy: WindowsCustodyFilePolicy,
    expected_authorities: &[String],
) -> Result<(), WindowsCustodyAclError> {
    if expected_authorities.is_empty() {
        return Err(policy_error(
            path,
            "custody ACL qualification requires an explicit authority allowlist",
        ));
    }
    validate_windows_custody_path_acl_inner(file, path, policy, Some(expected_authorities))
}

fn validate_windows_custody_path_acl_inner(
    file: &File,
    path: &Path,
    policy: WindowsCustodyFilePolicy,
    expected_authorities: Option<&[String]>,
) -> Result<(), WindowsCustodyAclError> {
    validate_windows_custody_file_acl_inner(file, path, policy, expected_authorities)?;
    match policy {
        WindowsCustodyFilePolicy::ExternalReadOnly
        | WindowsCustodyFilePolicy::ExternalSecretReadOnly => {
            validate_windows_external_ancestor_chain_inner(path, policy, None, expected_authorities)
        }
        WindowsCustodyFilePolicy::JournalKey | WindowsCustodyFilePolicy::DurableJournal => {
            let parent = path
                .parent()
                .ok_or_else(|| policy_error(path, "the custody path has no parent directory"))?;
            validate_windows_custody_directory_acl(
                parent,
                policy,
                CustodyObjectKind::Directory,
                expected_authorities,
            )
        }
    }
}

/// Returns the owner SID from the same retained file handle used by the custody
/// validator. Call this only after `validate_windows_custody_path_acl` succeeds.
pub(crate) fn windows_custody_file_owner_sid(
    file: &File,
    path: &Path,
) -> Result<String, WindowsCustodyAclError> {
    let descriptor = SecurityDescriptor::for_file(file, path)?;
    descriptor.validate(path)?;
    sid_string(descriptor.owner, path)
}

/// Validates one directory as a custody directory and returns its owner SID
/// from the retained directory handle.
pub(crate) fn validate_windows_custody_directory_path_acl(
    path: &Path,
    policy: WindowsCustodyFilePolicy,
    expected_authorities: &[String],
) -> Result<String, WindowsCustodyAclError> {
    if expected_authorities.is_empty() {
        return Err(policy_error(
            path,
            "custody ACL qualification requires an explicit authority allowlist",
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let directory = options.open(path).map_err(|source| {
        io_error(
            "open the custody directory for ACL qualification",
            path,
            source,
        )
    })?;
    validate_windows_custody_directory_handle_acl(
        &directory,
        path,
        policy,
        CustodyObjectKind::Directory,
        Some(expected_authorities),
    )
}

/// Resolves a configured Windows account and returns its stable SID string.
pub(crate) fn resolve_windows_account_sid(
    account: &str,
    path: &Path,
) -> Result<String, WindowsCustodyAclError> {
    if account.is_empty() || account.encode_utf16().count() > 512 || account.contains('\0') {
        return Err(policy_error(
            path,
            "the configured Windows identity is invalid",
        ));
    }
    let encoded = account.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut sid_bytes = 0_u32;
    let mut domain_units = 0_u32;
    let mut sid_kind = 0_i32;
    // SAFETY: this first call intentionally supplies null buffers to obtain the
    // required bounded lengths.
    let initial = unsafe {
        LookupAccountNameW(
            null_mut(),
            encoded.as_ptr(),
            null_mut(),
            &mut sid_bytes,
            null_mut(),
            &mut domain_units,
            &mut sid_kind,
        )
    };
    let source = io::Error::last_os_error();
    if initial != 0
        || source.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || sid_bytes == 0
        || sid_bytes > SECURITY_MAX_SID_SIZE
        || domain_units > 32_768
    {
        return Err(io_error(
            "resolve configured Windows identity",
            path,
            source,
        ));
    }
    let mut sid = vec![0_u8; sid_bytes as usize];
    let mut domain = vec![0_u16; domain_units.max(1) as usize];
    let mut returned_sid_bytes = sid_bytes;
    let mut returned_domain_units = domain_units;
    // SAFETY: both buffers have the exact capacities returned by the bounded
    // probe above and all length outputs are writable.
    if unsafe {
        LookupAccountNameW(
            null_mut(),
            encoded.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut returned_sid_bytes,
            domain.as_mut_ptr(),
            &mut returned_domain_units,
            &mut sid_kind,
        )
    } == 0
        || returned_sid_bytes == 0
        || returned_sid_bytes > sid_bytes
        || unsafe { IsValidSid(sid.as_mut_ptr().cast()) } == 0
    {
        return Err(last_io_error("resolve configured Windows identity", path));
    }
    sid_string(sid.as_mut_ptr().cast(), path)
}

/// Returns the current process SID and whether its primary token is elevated.
/// Qualification must use a real service process, not thread impersonation.
pub(crate) fn current_windows_process_identity(
    path: &Path,
) -> Result<(String, bool), WindowsCustodyAclError> {
    let token = ProcessToken::open(path)?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    // SAFETY: the primary token is live, and the fixed output buffer and length
    // pointer are writable.
    if unsafe {
        GetTokenInformation(
            token._primary.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
        || returned != size_of::<TOKEN_ELEVATION>() as u32
    {
        return Err(last_io_error(
            "inspect the current Windows service-token elevation",
            path,
        ));
    }
    let privileged = elevation.TokenIsElevated != 0 || sid_is(token.user_sid, WinLocalSystemSid);
    Ok((sid_string(token.user_sid, path)?, privileged))
}

#[cfg(test)]
fn validate_windows_custody_file_acl(
    file: &File,
    path: &Path,
    policy: WindowsCustodyFilePolicy,
) -> Result<(), WindowsCustodyAclError> {
    validate_windows_custody_file_acl_inner(file, path, policy, None)
}

fn validate_windows_custody_file_acl_inner(
    file: &File,
    path: &Path,
    policy: WindowsCustodyFilePolicy,
    expected_authorities: Option<&[String]>,
) -> Result<(), WindowsCustodyAclError> {
    validate_direct_disk_object(file, path, false)?;
    let descriptor = SecurityDescriptor::for_file(file, path)?;
    descriptor.validate(path)?;
    let token = ProcessToken::open(path)?;

    let owner_is_trusted = sid_is_trusted_custody_identity(descriptor.owner, token.user_sid);
    if matches!(
        policy,
        WindowsCustodyFilePolicy::JournalKey | WindowsCustodyFilePolicy::DurableJournal
    ) && !owner_is_trusted
    {
        return Err(policy_error(
            path,
            "key and journal files must be owned by the node identity, LocalSystem, or Administrators",
        ));
    }

    validate_allow_aces(
        descriptor.dacl,
        descriptor.owner,
        token.user_sid,
        policy,
        CustodyObjectKind::File,
        expected_authorities,
        path,
    )?;

    match policy {
        WindowsCustodyFilePolicy::JournalKey => {
            require_effective_access(&descriptor, &token, CONTENT_READ, path)?;
        }
        WindowsCustodyFilePolicy::DurableJournal => {
            require_effective_access(&descriptor, &token, CONTENT_READ, path)?;
            require_effective_access(&descriptor, &token, FILE_WRITE_DATA, path)?;
        }
        WindowsCustodyFilePolicy::ExternalReadOnly
        | WindowsCustodyFilePolicy::ExternalSecretReadOnly => {
            require_effective_access(&descriptor, &token, CONTENT_READ, path)?;
            for access in [
                FILE_WRITE_DATA,
                FILE_APPEND_DATA,
                FILE_WRITE_EA,
                FILE_WRITE_ATTRIBUTES,
                DELETE,
                WRITE_DAC,
                WRITE_OWNER,
            ] {
                if effective_access(&descriptor, &token, access, path)? {
                    return Err(policy_error(
                        path,
                        "the running node token can modify, delete, or take control of external authorization material",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_windows_external_ancestor_chain(
    path: &Path,
    policy: WindowsCustodyFilePolicy,
    stop_after: Option<&Path>,
) -> Result<(), WindowsCustodyAclError> {
    validate_windows_external_ancestor_chain_inner(path, policy, stop_after, None)
}

fn validate_windows_external_ancestor_chain_inner(
    path: &Path,
    policy: WindowsCustodyFilePolicy,
    stop_after: Option<&Path>,
    expected_authorities: Option<&[String]>,
) -> Result<(), WindowsCustodyAclError> {
    let parent = path
        .parent()
        .ok_or_else(|| policy_error(path, "the custody path has no parent directory"))?;
    for (index, directory) in parent.ancestors().enumerate() {
        let object_kind = if index == 0 {
            CustodyObjectKind::Directory
        } else {
            CustodyObjectKind::ExternalAncestorDirectory
        };
        validate_windows_custody_directory_acl(
            directory,
            policy,
            object_kind,
            expected_authorities,
        )?;
        if stop_after.is_some_and(|boundary| directory == boundary) {
            return Ok(());
        }
    }
    if stop_after.is_some() {
        return Err(policy_error(
            path,
            "the external-control trust boundary is not an ancestor",
        ));
    }
    Ok(())
}

fn validate_windows_custody_directory_acl(
    directory_path: &Path,
    policy: WindowsCustodyFilePolicy,
    object_kind: CustodyObjectKind,
    expected_authorities: Option<&[String]>,
) -> Result<(), WindowsCustodyAclError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let directory = options.open(directory_path).map_err(|source| {
        io_error(
            "open the custody ancestor directory for ACL validation",
            directory_path,
            source,
        )
    })?;
    validate_windows_custody_directory_handle_acl(
        &directory,
        directory_path,
        policy,
        object_kind,
        expected_authorities,
    )
    .map(|_| ())
}

fn validate_windows_custody_directory_handle_acl(
    directory: &File,
    directory_path: &Path,
    policy: WindowsCustodyFilePolicy,
    object_kind: CustodyObjectKind,
    expected_authorities: Option<&[String]>,
) -> Result<String, WindowsCustodyAclError> {
    validate_direct_disk_object(directory, directory_path, true)?;
    let descriptor = SecurityDescriptor::for_file(directory, directory_path)?;
    descriptor.validate(directory_path)?;
    let token = ProcessToken::open(directory_path)?;

    if matches!(
        policy,
        WindowsCustodyFilePolicy::JournalKey | WindowsCustodyFilePolicy::DurableJournal
    ) && !sid_is_trusted_custody_identity(descriptor.owner, token.user_sid)
    {
        return Err(policy_error(
            directory_path,
            "key and journal directories must be owned by the node identity, LocalSystem, or Administrators",
        ));
    }
    validate_allow_aces(
        descriptor.dacl,
        descriptor.owner,
        token.user_sid,
        policy,
        object_kind,
        expected_authorities,
        directory_path,
    )?;

    match policy {
        WindowsCustodyFilePolicy::JournalKey => {}
        WindowsCustodyFilePolicy::DurableJournal => {
            require_effective_access(&descriptor, &token, FILE_WRITE_DATA, directory_path)?;
            require_effective_access(&descriptor, &token, FILE_DELETE_CHILD, directory_path)?;
        }
        WindowsCustodyFilePolicy::ExternalReadOnly
        | WindowsCustodyFilePolicy::ExternalSecretReadOnly => {
            let strict_parent_access = [
                FILE_WRITE_DATA,
                FILE_APPEND_DATA,
                FILE_DELETE_CHILD,
                FILE_WRITE_EA,
                FILE_WRITE_ATTRIBUTES,
                DELETE,
                WRITE_DAC,
                WRITE_OWNER,
            ];
            let ancestor_access = [
                FILE_DELETE_CHILD,
                FILE_WRITE_EA,
                FILE_WRITE_ATTRIBUTES,
                DELETE,
                WRITE_DAC,
                WRITE_OWNER,
            ];
            let rejected_access: &[u32] =
                if object_kind == CustodyObjectKind::ExternalAncestorDirectory {
                    &ancestor_access
                } else {
                    &strict_parent_access
                };
            for &access in rejected_access {
                if effective_access(&descriptor, &token, access, directory_path)? {
                    return Err(policy_error(
                        directory_path,
                        "the running node token can replace, delete, or take control of external authorization material through an ancestor directory",
                    ));
                }
            }
        }
    }
    sid_string(descriptor.owner, directory_path)
}

/// Create a new directory with a protected owner/SYSTEM/Administrators DACL
/// from the first instant it exists. Never changes an existing directory.
#[cfg(feature = "production-v4")]
pub(crate) fn create_private_custody_directory(path: &Path) -> Result<(), WindowsCustodyAclError> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let token = ProcessToken::open(path)?;
    let current_user = sid_string(token.user_sid, path)?;
    let sddl = format!("D:P(A;OICI;FA;;;{current_user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let encoded = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut raw_descriptor = null_mut::<c_void>();
    // SAFETY: NUL-terminated SDDL and a valid output pointer. RAII frees the
    // returned LocalAlloc descriptor after CreateDirectoryW has copied it.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encoded.as_ptr(),
            SDDL_REVISION_1,
            &mut raw_descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(last_io_error("build private custody directory DACL", path));
    }
    let descriptor = LocalAllocation(raw_descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let encoded_path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if encoded_path[..encoded_path.len() - 1].contains(&0) {
        return Err(policy_error(
            path,
            "directory path contains an embedded NUL",
        ));
    }
    // SAFETY: both inputs are valid for this synchronous call. CreateDirectoryW
    // fails if the path already exists; no overwrite or ACL broadening occurs.
    if unsafe { CreateDirectoryW(encoded_path.as_ptr(), &attributes) } == 0 {
        return Err(last_io_error("create private custody directory", path));
    }
    validate_windows_custody_directory_acl(
        path,
        WindowsCustodyFilePolicy::JournalKey,
        CustodyObjectKind::Directory,
        None,
    )
}

/// Replaces the inherited DACL on a newly created, still-empty node-owned file
/// with a protected DACL granting full control only to the creating token user,
/// LocalSystem, and Administrators. The handle must include `WRITE_DAC`.
///
/// External control material is deliberately excluded: its writer identity
/// belongs to the exchange coordinator and must never be inferred by the node.
pub(crate) fn initialize_windows_node_owned_custody_file_acl(
    file: &File,
    path: &Path,
    policy: WindowsCustodyFilePolicy,
) -> Result<(), WindowsCustodyAclError> {
    if matches!(
        policy,
        WindowsCustodyFilePolicy::ExternalReadOnly
            | WindowsCustodyFilePolicy::ExternalSecretReadOnly
    ) {
        return Err(policy_error(
            path,
            "the node must not create or modify an external control-file DACL",
        ));
    }
    validate_direct_disk_object(file, path, false)?;
    let length = file
        .metadata()
        .map_err(|source| io_error("inspect new Windows custody file", path, source))?
        .len();
    if length != 0 {
        return Err(policy_error(
            path,
            "custody DACL initialization is restricted to empty new files",
        ));
    }

    let token = ProcessToken::open(path)?;
    let current_user = sid_string(token.user_sid, path)?;
    let sddl = format!("D:P(A;;FA;;;{current_user})(A;;FA;;;SY)(A;;FA;;;BA)");
    let encoded = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut raw_descriptor = null_mut::<c_void>();
    // SAFETY: `encoded` is NUL-terminated and the output pointer is writable.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encoded.as_ptr(),
            SDDL_REVISION_1,
            &mut raw_descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(last_io_error("build protected Windows custody DACL", path));
    }
    let descriptor = LocalAllocation(raw_descriptor);
    let mut present = 0_i32;
    let mut defaulted = 0_i32;
    let mut dacl = null_mut::<ACL>();
    // SAFETY: the converted security descriptor remains alive, and all output
    // pointers are writable.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(last_io_error(
            "extract protected Windows custody DACL",
            path,
        ));
    }
    // SAFETY: the retained file handle must have WRITE_DAC, and `dacl` remains
    // alive for the duration of this call.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io_error(
            "apply protected Windows custody DACL",
            path,
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    validate_windows_custody_path_acl(file, path, policy)
}

fn validate_direct_disk_object(
    file: &File,
    path: &Path,
    expect_directory: bool,
) -> Result<(), WindowsCustodyAclError> {
    let handle = file.as_raw_handle().cast();
    // SAFETY: `file` retains a valid handle for the duration of both calls and
    // `attributes` is a correctly sized writable output value.
    let file_type = unsafe { GetFileType(handle) };
    if file_type != FILE_TYPE_DISK {
        return Err(policy_error(
            path,
            "custody objects must be regular disk files",
        ));
    }
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: see the handle and output-buffer argument above.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(last_io_error(
            "inspect Windows custody file attributes",
            path,
        ));
    }
    if attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0
        || (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != expect_directory
    {
        return Err(policy_error(
            path,
            "the custody handle has the wrong object type or names a reparse/device object",
        ));
    }
    Ok(())
}

fn validate_allow_aces(
    dacl: *mut ACL,
    owner: PSID,
    current_user: PSID,
    policy: WindowsCustodyFilePolicy,
    object_kind: CustodyObjectKind,
    expected_authorities: Option<&[String]>,
    path: &Path,
) -> Result<(), WindowsCustodyAclError> {
    if let Some(expected) = expected_authorities {
        let owner_id = sid_string(owner, path)?;
        if !expected.contains(&owner_id) {
            return Err(policy_error(
                path,
                "the custody object owner is outside the configured authority allowlist",
            ));
        }
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: the DACL belongs to the live security descriptor, and the output
    // buffer has the required size and alignment.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(last_io_error("inspect Windows custody DACL", path));
    }

    for index in 0..information.AceCount {
        let mut raw_ace = null_mut::<c_void>();
        // SAFETY: the ACL is validated before this function is called and the
        // output pointer is writable.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(last_io_error("read Windows custody DACL entry", path));
        }
        // SAFETY: `GetAce` returned an ACE within a valid ACL.
        let header = unsafe { &*(raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>()) };
        match u32::from(header.AceType) {
            ACCESS_DENIED_ACE_TYPE => continue,
            ACCESS_ALLOWED_ACE_TYPE => {}
            _ => {
                return Err(policy_error(
                    path,
                    "only standard allow and deny ACEs are accepted",
                ));
            }
        }
        let inherit_only =
            header.AceFlags & (windows_sys::Win32::Security::INHERIT_ONLY_ACE as u8) != 0;
        if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(policy_error(
                path,
                "the DACL contains a malformed allow ACE",
            ));
        }
        // SAFETY: the validated ACE has at least ACCESS_ALLOWED_ACE bytes.
        let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
        let mut mask = ace.Mask;
        // SAFETY: both pointers refer to initialized values for this call.
        unsafe { MapGenericMask(&mut mask, &FILE_MAPPING) };
        let protected_access = match object_kind {
            CustodyObjectKind::File
                if matches!(
                    policy,
                    WindowsCustodyFilePolicy::JournalKey
                        | WindowsCustodyFilePolicy::ExternalSecretReadOnly
                ) =>
            {
                CONTENT_READ | MUTATING_ACCESS
            }
            CustodyObjectKind::File => MUTATING_ACCESS,
            CustodyObjectKind::Directory => DIRECTORY_MUTATING_ACCESS,
            CustodyObjectKind::ExternalAncestorDirectory => ANCESTOR_REPLACEMENT_ACCESS,
        };
        let sid_offset = addr_of!(ace.SidStart) as usize - raw_ace as usize;
        if usize::from(header.AceSize) < sid_offset + 8 {
            return Err(policy_error(path, "the DACL contains a truncated SID"));
        }
        let sid = addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
        // SAFETY: the ACE contains at least the fixed SID header, and Windows
        // validates the variable SID structure before its length is queried.
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(policy_error(path, "the DACL contains an invalid SID"));
        }
        // SAFETY: `sid` was accepted by IsValidSid.
        let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
        if sid_length > SECURITY_MAX_SID_SIZE as usize
            || sid_offset + sid_length > usize::from(header.AceSize)
        {
            return Err(policy_error(path, "the DACL SID exceeds its ACE"));
        }

        if let Some(expected) = expected_authorities {
            let qualification_access = match (policy, object_kind) {
                (
                    WindowsCustodyFilePolicy::JournalKey | WindowsCustodyFilePolicy::DurableJournal,
                    CustodyObjectKind::File | CustodyObjectKind::Directory,
                ) => protected_access | CONTENT_READ,
                _ => protected_access,
            };
            if mask & qualification_access != 0 {
                let authority = if sid_is(sid, WinCreatorOwnerRightsSid) {
                    owner
                } else {
                    sid
                };
                let authority = sid_string(authority, path)?;
                if !expected.contains(&authority) {
                    return Err(policy_error(
                        path,
                        "a protected access ACE names a SID outside the configured authority allowlist",
                    ));
                }
            }
        }

        if inherit_only {
            continue;
        }

        if mask & protected_access == 0 {
            continue;
        }

        match policy {
            WindowsCustodyFilePolicy::JournalKey | WindowsCustodyFilePolicy::DurableJournal => {
                if !(sid_is_trusted_custody_identity(sid, current_user)
                    || sid_is(sid, WinCreatorOwnerRightsSid)
                        && sid_is_trusted_custody_identity(owner, current_user))
                {
                    return Err(policy_error(
                        path,
                        "sensitive access is granted outside the node identity, LocalSystem, and Administrators",
                    ));
                }
            }
            WindowsCustodyFilePolicy::ExternalReadOnly
            | WindowsCustodyFilePolicy::ExternalSecretReadOnly => {
                if sid_is_known_broad_principal(sid) {
                    return Err(policy_error(
                        path,
                        "a broad Windows principal can modify or control external authorization material",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn require_effective_access(
    descriptor: &SecurityDescriptor,
    token: &ProcessToken,
    access: u32,
    path: &Path,
) -> Result<(), WindowsCustodyAclError> {
    if !effective_access(descriptor, token, access, path)? {
        return Err(policy_error(
            path,
            "the running node token lacks required custody-file access",
        ));
    }
    Ok(())
}

fn effective_access(
    descriptor: &SecurityDescriptor,
    token: &ProcessToken,
    mut desired_access: u32,
    path: &Path,
) -> Result<bool, WindowsCustodyAclError> {
    // SAFETY: both pointers refer to initialized values for this call.
    unsafe { MapGenericMask(&mut desired_access, &FILE_MAPPING) };
    let mut privilege_words = vec![0_usize; words_for(size_of::<PRIVILEGE_SET>())];
    loop {
        let byte_capacity = privilege_words
            .len()
            .checked_mul(size_of::<usize>())
            .ok_or_else(|| policy_error(path, "privilege-set capacity overflowed"))?;
        let mut privilege_bytes = u32::try_from(byte_capacity)
            .map_err(|_| policy_error(path, "privilege-set capacity is invalid"))?;
        let mut granted_access = 0_u32;
        let mut access_status = 0_i32;
        // SAFETY: the descriptor and impersonation token remain alive, the
        // mapping is initialized, and every output buffer has its advertised
        // size and alignment.
        let succeeded = unsafe {
            AccessCheck(
                descriptor.raw,
                token.impersonation.0,
                desired_access,
                &FILE_MAPPING,
                privilege_words.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                &mut privilege_bytes,
                &mut granted_access,
                &mut access_status,
            )
        };
        if succeeded != 0 {
            return Ok(access_status != 0 && granted_access & desired_access == desired_access);
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(io_error("evaluate Windows custody access", path, source));
        }
        let required = privilege_bytes as usize;
        if required == 0 || required > MAX_PRIVILEGE_SET_BYTES {
            return Err(policy_error(
                path,
                "Windows reported an invalid privilege-set size",
            ));
        }
        privilege_words.resize(words_for(required), 0);
    }
}

fn words_for(bytes: usize) -> usize {
    bytes.div_ceil(size_of::<usize>()).max(1)
}

fn sid_is_trusted_custody_identity(sid: PSID, current_user: PSID) -> bool {
    if sid.is_null() || current_user.is_null() {
        return false;
    }
    // SAFETY: all SIDs passed here were supplied by validated Windows token or
    // security-descriptor data.
    unsafe {
        EqualSid(sid, current_user) != 0
            || IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    }
}

fn sid_is_known_broad_principal(sid: PSID) -> bool {
    use windows_sys::Win32::Security::{
        WinAnonymousSid, WinAuthenticatedUserSid, WinBatchSid, WinBuiltinAnyPackageSid,
        WinBuiltinGuestsSid, WinBuiltinUsersSid, WinInteractiveSid,
        WinLocalAccountAndAdministratorSid, WinLocalAccountSid, WinNetworkSid,
        WinRestrictedCodeSid, WinServiceSid, WinWorldSid,
    };

    [
        WinWorldSid,
        WinAuthenticatedUserSid,
        WinBuiltinUsersSid,
        WinBuiltinGuestsSid,
        WinAnonymousSid,
        WinInteractiveSid,
        WinNetworkSid,
        WinBatchSid,
        WinServiceSid,
        WinLocalAccountSid,
        WinLocalAccountAndAdministratorSid,
        WinBuiltinAnyPackageSid,
        WinRestrictedCodeSid,
    ]
    .into_iter()
    .any(|kind| sid_is(sid, kind))
}

fn sid_is(sid: PSID, kind: i32) -> bool {
    if sid.is_null() {
        return false;
    }
    // SAFETY: callers supply a SID validated by Windows.
    unsafe { IsWellKnownSid(sid, kind) != 0 }
}

fn sid_string(sid: PSID, path: &Path) -> Result<String, WindowsCustodyAclError> {
    let mut encoded = null_mut::<u16>();
    // SAFETY: `sid` belongs to the live process-token buffer and the output
    // pointer is writable. Windows allocates the result with LocalAlloc.
    if unsafe { ConvertSidToStringSidW(sid, &mut encoded) } == 0 {
        return Err(last_io_error(
            "encode the current Windows custody identity",
            path,
        ));
    }
    let allocation = LocalAllocation(encoded.cast());
    const MAX_SID_STRING_CODE_UNITS: usize = 256;
    let length = (0..MAX_SID_STRING_CODE_UNITS)
        // SAFETY: ConvertSidToStringSidW returned a valid NUL-terminated string;
        // the explicit bound prevents an unbounded scan if that contract is
        // violated.
        .find(|offset| unsafe { *encoded.add(*offset) == 0 })
        .ok_or_else(|| policy_error(path, "the process SID string is not terminated"))?;
    // SAFETY: the preceding bounded scan established `length` initialized code
    // units before the terminator.
    let units = unsafe { std::slice::from_raw_parts(encoded, length) };
    let result = String::from_utf16(units)
        .map_err(|_| policy_error(path, "the process SID string is invalid UTF-16"));
    drop(allocation);
    result
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper owns a buffer returned by a LocalAlloc-based
            // Windows security API.
            let _ = unsafe { LocalFree(self.0) };
        }
    }
}

struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
}

impl SecurityDescriptor {
    fn for_file(file: &File, path: &Path) -> Result<Self, WindowsCustodyAclError> {
        let mut raw = null_mut::<c_void>();
        let mut owner = null_mut::<c_void>();
        let mut dacl = null_mut::<ACL>();
        // SAFETY: the retained file handle is valid, output pointers are
        // writable, and Windows allocates `raw` for LocalFree on success.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut raw,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io_error(
                "read Windows custody security descriptor",
                path,
                io::Error::from_raw_os_error(status as i32),
            ));
        }
        if raw.is_null() {
            return Err(policy_error(
                path,
                "Windows returned no security descriptor",
            ));
        }
        Ok(Self { raw, owner, dacl })
    }

    fn validate(&self, path: &Path) -> Result<(), WindowsCustodyAclError> {
        // SAFETY: `raw` owns a descriptor returned by GetSecurityInfo.
        if unsafe { IsValidSecurityDescriptor(self.raw) } == 0 {
            return Err(policy_error(path, "the security descriptor is invalid"));
        }
        if self.owner.is_null() || self.dacl.is_null() {
            return Err(policy_error(
                path,
                "custody files require an owner and a non-null DACL",
            ));
        }
        // SAFETY: `dacl` is part of the validated descriptor.
        if unsafe { IsValidAcl(self.dacl) } == 0 {
            return Err(policy_error(path, "the custody DACL is invalid"));
        }
        // SAFETY: both output values are writable and the descriptor is valid.
        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe { GetSecurityDescriptorControl(self.raw, &mut control, &mut revision) } == 0 {
            return Err(last_io_error(
                "inspect Windows custody DACL protection",
                path,
            ));
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(policy_error(
                path,
                "the custody DACL must be protected from inheritance",
            ));
        }
        Ok(())
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: GetSecurityInfo allocated the descriptor with LocalAlloc.
            let _ = unsafe { LocalFree(self.raw.cast()) };
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper exclusively owns the valid token handle.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

struct ProcessToken {
    _primary: OwnedHandle,
    impersonation: OwnedHandle,
    _user_information: Vec<usize>,
    user_sid: PSID,
}

impl ProcessToken {
    fn open(path: &Path) -> Result<Self, WindowsCustodyAclError> {
        let mut primary = null_mut::<c_void>();
        // SAFETY: the output pointer is writable and GetCurrentProcess returns
        // a valid pseudo-handle.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut primary,
            )
        } == 0
        {
            return Err(last_io_error("open the current process token", path));
        }
        let primary = OwnedHandle(primary);

        let mut impersonation = null_mut::<c_void>();
        // SAFETY: `primary` is a queryable token and the output pointer is
        // writable.
        if unsafe { DuplicateToken(primary.0, SecurityImpersonation, &mut impersonation) } == 0 {
            return Err(last_io_error("duplicate the current process token", path));
        }
        let impersonation = OwnedHandle(impersonation);

        let mut required = 0_u32;
        // SAFETY: the zero-length probe intentionally supplies no output
        // buffer; Windows reports the required length.
        let probe =
            unsafe { GetTokenInformation(primary.0, TokenUser, null_mut(), 0, &mut required) };
        let probe_error = io::Error::last_os_error();
        if probe != 0
            || probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || required < size_of::<TOKEN_USER>() as u32
        {
            return Err(io_error(
                "size the current process token identity",
                path,
                probe_error,
            ));
        }
        let mut user_information = vec![0_usize; words_for(required as usize)];
        let mut returned = required;
        // SAFETY: the word buffer is sufficiently sized and aligned for the
        // TOKEN_USER result.
        if unsafe {
            GetTokenInformation(
                primary.0,
                TokenUser,
                user_information.as_mut_ptr().cast(),
                required,
                &mut returned,
            )
        } == 0
        {
            return Err(last_io_error(
                "read the current process token identity",
                path,
            ));
        }
        if returned < size_of::<TOKEN_USER>() as u32 || returned > required {
            return Err(policy_error(
                path,
                "Windows returned an invalid token identity length",
            ));
        }
        // SAFETY: the aligned buffer contains at least TOKEN_USER bytes.
        let user_sid = unsafe { (*(user_information.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        if user_sid.is_null() {
            return Err(policy_error(path, "the process token has no user SID"));
        }
        // SAFETY: the SID pointer is returned as part of TOKEN_USER.
        if unsafe { IsValidSid(user_sid) } == 0 {
            return Err(policy_error(path, "the process token user SID is invalid"));
        }
        // SAFETY: the SID was accepted by IsValidSid.
        let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(user_sid) } as usize;
        let buffer_start = user_information.as_ptr() as usize;
        let buffer_end = buffer_start + returned as usize;
        let sid_start = user_sid as usize;
        if sid_length > SECURITY_MAX_SID_SIZE as usize
            || sid_start < buffer_start
            || sid_start
                .checked_add(sid_length)
                .is_none_or(|sid_end| sid_end > buffer_end)
        {
            return Err(policy_error(
                path,
                "the process token user SID exceeds its buffer",
            ));
        }

        Ok(Self {
            _primary: primary,
            impersonation,
            _user_information: user_information,
            user_sid,
        })
    }
}

fn last_io_error(operation: &'static str, path: &Path) -> WindowsCustodyAclError {
    io_error(operation, path, io::Error::last_os_error())
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> WindowsCustodyAclError {
    WindowsCustodyAclError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn policy_error(path: &Path, reason: &'static str) -> WindowsCustodyAclError {
    WindowsCustodyAclError::Policy {
        path: path.to_path_buf(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn key_rejects_broad_read_and_accepts_owner_system_admin() {
        let directory = test_directory("key");
        let path = directory.join("journal.key");
        set_path_dacl(
            &path,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)",
            true,
        );
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        assert!(matches!(
            validate_windows_custody_path_acl(&file, &path, WindowsCustodyFilePolicy::JournalKey),
            Err(WindowsCustodyAclError::Policy { .. })
        ));
        drop(file);

        set_existing_path_dacl(&path, "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)", true);
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        validate_windows_custody_path_acl(&file, &path, WindowsCustodyFilePolicy::JournalKey)
            .unwrap();
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn journal_rejects_broad_write() {
        let directory = test_directory("journal");
        let path = directory.join("exchange-withdrawals.0");
        set_path_dacl(
            &path,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;AU)",
            true,
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            validate_windows_custody_path_acl(
                &file,
                &path,
                WindowsCustodyFilePolicy::DurableJournal
            ),
            Err(WindowsCustodyAclError::Policy { .. })
        ));
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn journal_rejects_broad_parent_replacement_authority() {
        let directory = test_directory("journal-parent");
        let path = directory.join("exchange-withdrawals.0");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
        let file = options.open(&path).unwrap();
        initialize_windows_node_owned_custody_file_acl(
            &file,
            &path,
            WindowsCustodyFilePolicy::DurableJournal,
        )
        .unwrap();

        let directory_control = open_directory_for_acl(&directory);
        apply_dacl(
            &directory_control,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;AU)",
            true,
        );
        assert!(matches!(
            validate_windows_custody_path_acl(
                &file,
                &path,
                WindowsCustodyFilePolicy::DurableJournal
            ),
            Err(WindowsCustodyAclError::Policy { .. })
        ));
        drop(file);
        drop(directory_control);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn external_control_requires_read_without_any_effective_mutation_right() {
        let directory = test_directory("external-control");
        let path = directory.join("authorization.json");
        set_path_dacl(&path, "D:P(A;;FR;;;OW)(A;;FA;;;SY)", true);
        let writable_path = directory.join("writable-authorization.json");
        set_path_dacl(&writable_path, "D:P(A;;FA;;;OW)(A;;FA;;;SY)", true);

        // A read-only file is not external control while the node can replace
        // it through its parent directory.
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        assert!(matches!(
            validate_windows_custody_path_acl(
                &file,
                &path,
                WindowsCustodyFilePolicy::ExternalReadOnly
            ),
            Err(WindowsCustodyAclError::Policy { .. })
        ));
        drop(file);

        let directory_control = open_directory_for_acl(&directory);
        apply_dacl(&directory_control, "D:P(A;;FRFX;;;OW)(A;;FA;;;SY)", true);
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        validate_windows_custody_file_acl(&file, &path, WindowsCustodyFilePolicy::ExternalReadOnly)
            .unwrap();
        validate_windows_external_ancestor_chain(
            &path,
            WindowsCustodyFilePolicy::ExternalReadOnly,
            Some(&directory),
        )
        .unwrap();
        drop(file);

        let file = OpenOptions::new().read(true).open(&writable_path).unwrap();
        assert!(matches!(
            validate_windows_custody_path_acl(
                &file,
                &writable_path,
                WindowsCustodyFilePolicy::ExternalReadOnly
            ),
            Err(WindowsCustodyAclError::Policy { .. })
        ));
        drop(file);
        apply_dacl(
            &directory_control,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
            true,
        );
        drop(directory_control);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn external_secret_rejects_broad_read_access() {
        let directory = test_directory("external-secret");
        let path = directory.join("keyring.passphrase");
        set_path_dacl(&path, "D:P(A;;FR;;;OW)(A;;FR;;;WD)(A;;FA;;;SY)", true);
        let directory_control = open_directory_for_acl(&directory);
        apply_dacl(&directory_control, "D:P(A;;FRFX;;;OW)(A;;FA;;;SY)", true);
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        validate_windows_custody_file_acl(&file, &path, WindowsCustodyFilePolicy::ExternalReadOnly)
            .unwrap();
        validate_windows_external_ancestor_chain(
            &path,
            WindowsCustodyFilePolicy::ExternalReadOnly,
            Some(&directory),
        )
        .unwrap();
        assert!(matches!(
            validate_windows_custody_path_acl(
                &file,
                &path,
                WindowsCustodyFilePolicy::ExternalSecretReadOnly,
            ),
            Err(WindowsCustodyAclError::Policy { .. })
        ));

        drop(file);
        apply_dacl(
            &directory_control,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
            true,
        );
        drop(directory_control);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn qualification_rejects_unknown_sid_with_external_control_write_access() {
        let directory = test_directory("unknown-control-authority");
        let path = directory.join("authorization.json");
        set_path_dacl(
            &path,
            "D:P(A;;FR;;;OW)(A;;FW;;;S-1-5-21-4242424242-4242424242-4242424242-4242)(A;;FA;;;SY)",
            true,
        );
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        // This is neither a broad principal nor the running service, so the
        // runtime mutation check alone deliberately cannot infer whether the
        // SID is an approved operator. Host qualification must reject it.
        validate_windows_custody_file_acl(&file, &path, WindowsCustodyFilePolicy::ExternalReadOnly)
            .unwrap();
        assert_unknown_authority_rejected(&file, &path, WindowsCustodyFilePolicy::ExternalReadOnly);

        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn qualification_rejects_unknown_sid_with_external_secret_read_access() {
        let directory = test_directory("unknown-secret-authority");
        let path = directory.join("keyring.passphrase");
        set_path_dacl(
            &path,
            "D:P(A;;FR;;;OW)(A;;FR;;;S-1-5-21-4242424242-4242424242-4242424242-4242)(A;;FA;;;SY)",
            true,
        );
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        validate_windows_custody_file_acl(
            &file,
            &path,
            WindowsCustodyFilePolicy::ExternalSecretReadOnly,
        )
        .unwrap();
        assert_unknown_authority_rejected(
            &file,
            &path,
            WindowsCustodyFilePolicy::ExternalSecretReadOnly,
        );

        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn qualification_rejects_unknown_inherit_only_directory_authority() {
        let directory = test_directory("unknown-inherited-authority");
        let directory_control = open_directory_for_acl(&directory);
        apply_dacl(
            &directory_control,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;OICIIO;FA;;;S-1-5-21-4242424242-4242424242-4242424242-4242)",
            true,
        );
        let descriptor = SecurityDescriptor::for_file(&directory_control, &directory).unwrap();
        descriptor.validate(&directory).unwrap();
        let expected = vec![
            sid_string(descriptor.owner, &directory).unwrap(),
            "S-1-5-18".to_owned(),
            "S-1-5-32-544".to_owned(),
        ];

        assert!(matches!(
            validate_windows_custody_directory_path_acl(
                &directory,
                WindowsCustodyFilePolicy::DurableJournal,
                &expected,
            ),
            Err(WindowsCustodyAclError::Policy { reason, .. })
                if reason == "a protected access ACE names a SID outside the configured authority allowlist"
        ));

        drop(descriptor);
        drop(directory_control);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn external_control_rejects_a_safe_parent_under_a_mutable_grandparent() {
        let root = test_directory("external-mutable-grandparent");
        let controls = root.join("controls");
        fs::create_dir(&controls).unwrap();
        let controls_handle = open_directory_for_acl(&controls);
        let path = controls.join("authorization.json");
        set_path_dacl(&path, "D:P(A;;FR;;;OW)(A;;FA;;;SY)", true);
        apply_dacl(&controls_handle, "D:P(A;;FRFX;;;OW)(A;;FA;;;SY)", true);
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        assert!(matches!(
            validate_windows_custody_path_acl(
                &file,
                &path,
                WindowsCustodyFilePolicy::ExternalReadOnly,
            ),
            Err(WindowsCustodyAclError::Policy { path, .. }) if path == root
        ));

        apply_dacl(
            &controls_handle,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
            true,
        );
        drop(file);
        drop(controls_handle);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_control_accepts_each_safe_ancestor_through_a_trust_boundary() {
        let root = test_directory("external-safe-chain");
        let controls = root.join("controls");
        fs::create_dir(&controls).unwrap();
        let root_handle = open_directory_for_acl(&root);
        let controls_handle = open_directory_for_acl(&controls);
        let path = controls.join("authorization.json");
        set_path_dacl(&path, "D:P(A;;FR;;;OW)(A;;FA;;;SY)", true);
        apply_dacl(&controls_handle, "D:P(A;;FRFX;;;OW)(A;;FA;;;SY)", true);
        apply_dacl(
            &root_handle,
            "D:P(A;;FRFX;;;OW)(A;;0x00000006;;;OW)(A;;FA;;;SY)",
            true,
        );
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        validate_windows_custody_file_acl(&file, &path, WindowsCustodyFilePolicy::ExternalReadOnly)
            .unwrap();
        validate_windows_external_ancestor_chain(
            &path,
            WindowsCustodyFilePolicy::ExternalReadOnly,
            Some(&root),
        )
        .unwrap();

        apply_dacl(
            &controls_handle,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
            true,
        );
        apply_dacl(
            &root_handle,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
            true,
        );
        drop(file);
        drop(controls_handle);
        drop(root_handle);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_control_rejects_child_creation_at_the_immediate_parent() {
        let root = test_directory("external-create-at-parent");
        let controls = root.join("controls");
        fs::create_dir(&controls).unwrap();
        let controls_handle = open_directory_for_acl(&controls);
        let path = controls.join("authorization.json");
        set_path_dacl(&path, "D:P(A;;FR;;;OW)(A;;FA;;;SY)", true);
        apply_dacl(
            &controls_handle,
            "D:P(A;;FRFX;;;OW)(A;;0x00000006;;;OW)(A;;FA;;;SY)",
            true,
        );
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        validate_windows_custody_file_acl(&file, &path, WindowsCustodyFilePolicy::ExternalReadOnly)
            .unwrap();
        assert!(matches!(
            validate_windows_external_ancestor_chain(
                &path,
                WindowsCustodyFilePolicy::ExternalReadOnly,
                Some(&controls),
            ),
            Err(WindowsCustodyAclError::Policy { path, .. }) if path == controls
        ));

        apply_dacl(
            &controls_handle,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
            true,
        );
        drop(file);
        drop(controls_handle);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inherited_dacl_is_rejected() {
        let directory = test_directory("inheritance");
        let path = directory.join("journal.key");
        set_path_dacl(&path, "D:(A;;FA;;;OW)(A;;FA;;;SY)", false);
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        assert!(matches!(
            validate_windows_custody_path_acl(&file, &path, WindowsCustodyFilePolicy::JournalKey),
            Err(WindowsCustodyAclError::Policy { .. })
        ));
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn initializer_replaces_inheritance_before_new_journal_use() {
        let directory = test_directory("initializer");
        let path = directory.join("exchange-withdrawals.0");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
        let file = options.open(&path).unwrap();
        initialize_windows_node_owned_custody_file_acl(
            &file,
            &path,
            WindowsCustodyFilePolicy::DurableJournal,
        )
        .unwrap();
        drop(file);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        validate_windows_custody_path_acl(&file, &path, WindowsCustodyFilePolicy::DurableJournal)
            .unwrap();
        drop(file);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn initializer_rejects_a_protected_file_in_a_broadly_writable_parent() {
        let directory = test_directory("initializer-parent");
        let directory_control = open_directory_for_acl(&directory);
        apply_dacl(
            &directory_control,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;AU)",
            true,
        );
        let path = directory.join("exchange-withdrawals.0");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
        let file = options.open(&path).unwrap();

        assert!(matches!(
            initialize_windows_node_owned_custody_file_acl(
                &file,
                &path,
                WindowsCustodyFilePolicy::DurableJournal,
            ),
            Err(WindowsCustodyAclError::Policy { .. })
        ));

        apply_dacl(
            &directory_control,
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
            true,
        );
        drop(file);
        drop(directory_control);
        fs::remove_dir_all(directory).unwrap();
    }

    fn test_directory(label: &str) -> PathBuf {
        let nonce = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-exchange-acl-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        let directory = open_directory_for_acl(&path);
        apply_dacl(&directory, "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)", true);
        drop(directory);
        path
    }

    fn assert_unknown_authority_rejected(
        file: &File,
        path: &Path,
        policy: WindowsCustodyFilePolicy,
    ) {
        let descriptor = SecurityDescriptor::for_file(file, path).unwrap();
        descriptor.validate(path).unwrap();
        let expected = vec![
            sid_string(descriptor.owner, path).unwrap(),
            "S-1-5-18".to_owned(),
        ];
        assert!(matches!(
            validate_windows_custody_path_acl_with_authorities(file, path, policy, &expected),
            Err(WindowsCustodyAclError::Policy { reason, .. })
                if reason == "a protected access ACE names a SID outside the configured authority allowlist"
        ));
    }

    fn open_directory_for_acl(path: &Path) -> File {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        options.open(path).unwrap()
    }

    fn set_path_dacl(path: &Path, sddl: &str, protected: bool) {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
        let file = options.open(path).unwrap();
        apply_dacl(&file, sddl, protected);
    }

    fn set_existing_path_dacl(path: &Path, sddl: &str, protected: bool) {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
        let file = options.open(path).unwrap();
        apply_dacl(&file, sddl, protected);
    }

    fn apply_dacl(file: &File, sddl: &str, protected: bool) {
        let encoded = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut descriptor = null_mut::<c_void>();
        // SAFETY: `encoded` is NUL-terminated and the output pointer is
        // writable. The descriptor is freed below.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    encoded.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let owned = TestDescriptor(descriptor);
        let mut present = 0_i32;
        let mut defaulted = 0_i32;
        let mut dacl = null_mut::<ACL>();
        // SAFETY: the converted descriptor is valid and all outputs are
        // writable.
        assert_ne!(
            unsafe { GetSecurityDescriptorDacl(owned.0, &mut present, &mut dacl, &mut defaulted,) },
            0
        );
        assert_ne!(present, 0);
        assert!(!dacl.is_null());
        let inheritance = if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // SAFETY: the file was opened with WRITE_DAC and the DACL remains
        // alive through this call.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | inheritance,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
    }

    struct TestDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for TestDescriptor {
        fn drop(&mut self) {
            // SAFETY: the SDDL conversion allocated this descriptor with
            // LocalAlloc.
            let _ = unsafe { LocalFree(self.0.cast()) };
        }
    }
}
