//! util.rs – Windows ACL + helpers (+ no-op stubs for non-Windows).
//! Applies a protected DACL allowing Owner, Administrators, and SYSTEM full control.
//!
//! We convert SDDL → security descriptor via a direct FFI declaration to avoid
//! depending on `winapi::um::sddl` feature/module (not always enabled).
//!
//! Also exposes a cross-platform `paths_same_file` helper:
//!   - Windows: robust identity via GetFileInformationByHandle (vol serial + file index)
//!   - Unix:    (dev, ino)
//!   - Others:  path equality fallback

/// ---------------- Windows implementation ---------------------------------
#[cfg(windows)]
#[allow(unsafe_code)]
mod win_acl {
    use std::fs::OpenOptions;
    use std::io;
    use std::path::Path;
    use std::ptr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;

    use winapi::shared::minwindef::{BOOL, FALSE};
    use winapi::shared::ntdef::LPCWSTR;
    use winapi::shared::winerror::ERROR_SUCCESS;
    use winapi::um::accctrl::SE_FILE_OBJECT;
    use winapi::um::aclapi::SetNamedSecurityInfoW;
    use winapi::um::fileapi::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    use winapi::um::securitybaseapi::GetSecurityDescriptorDacl;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PACL, PSECURITY_DESCRIPTOR,
    };

    // FFI declaration (normally in sddl.h). Linked from advapi32.
    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: LPCWSTR,
            StringSDRevision: u32, // SDDL_REVISION_1 = 1
            SecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
            SecurityDescriptorSize: *mut u32,
        ) -> BOOL;
    }

    /// Apply a protected DACL from SDDL:
    /// D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)
    pub(crate) fn tighten(path: &Path) -> io::Result<()> {
        let wpath: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        const SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)";

        let (sd, dacl) = sddl_to_dacl(SDDL)?;

        let status = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr() as *mut _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        unsafe { LocalFree(sd as *mut _); }

        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn sddl_to_dacl(sddl: &str) -> io::Result<(PSECURITY_DESCRIPTOR, PACL)> {
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let mut present: BOOL = FALSE;
        let mut defaulted: BOOL = FALSE;
        let mut pdacl: PACL = ptr::null_mut();

        let wides: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wides.as_ptr(),
                1, // SDDL_REVISION_1
                &mut psd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let ok2 = unsafe { GetSecurityDescriptorDacl(psd, &mut present, &mut pdacl, &mut defaulted) };
        if ok2 == 0 {
            unsafe { LocalFree(psd as *mut _) };
            return Err(io::Error::last_os_error());
        }
        if present == 0 {
            unsafe { LocalFree(psd as *mut _) };
            return Err(io::Error::new(io::ErrorKind::Other, "No DACL present"));
        }
        Ok((psd, pdacl))
    }

    /// Robust Windows same-file check (volume serial + file index)
    pub(crate) fn same_file(a: &Path, b: &Path) -> io::Result<bool> {
        let fa = match OpenOptions::new().read(true).open(a) {
            Ok(f) => f,
            Err(_) => return Ok(false),
        };
        let fb = match OpenOptions::new().read(true).open(b) {
            Ok(f) => f,
            Err(_) => return Ok(false),
        };

        unsafe {
            let mut ia: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
            let mut ib: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();

            if GetFileInformationByHandle(fa.as_raw_handle(), &mut ia) == 0 {
                return Ok(false);
            }
            if GetFileInformationByHandle(fb.as_raw_handle(), &mut ib) == 0 {
                return Ok(false);
            }

            let same_vol = ia.dwVolumeSerialNumber == ib.dwVolumeSerialNumber;
            let same_idx =
                ia.nFileIndexHigh == ib.nFileIndexHigh && ia.nFileIndexLow == ib.nFileIndexLow;
            Ok(same_vol && same_idx)
        }
    }
}

// Re-export for callers in the rest of the code-base.
#[cfg(windows)]
pub(crate) use win_acl::same_file as paths_same_file;
#[cfg(windows)]
pub(crate) use win_acl::tighten as tighten_dacl;

/// ---------------- Non-Windows stubs & helpers ---------------------------
#[cfg(not(windows))]
#[allow(dead_code)]
pub(crate) fn tighten_dacl(_path: &std::path::Path) -> std::io::Result<()> {
    // POSIX platforms already use chmod(0o600) elsewhere.
    Ok(())
}

#[cfg(unix)]
pub(crate) fn paths_same_file(a: &std::path::Path, b: &std::path::Path) -> std::io::Result<bool> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    let ma = fs::metadata(a)?;
    let mb = fs::metadata(b)?;
    Ok(ma.dev() == mb.dev() && ma.ino() == mb.ino())
}

#[cfg(all(not(windows), not(unix)))]
pub(crate) fn paths_same_file(a: &std::path::Path, b: &std::path::Path) -> std::io::Result<bool> {
    Ok(a == b)
}
