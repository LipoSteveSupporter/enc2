///// key (single-file) – deterministic high-strength key material generator /////
// New UX: two-password mode (no base64). The second password (“pepper”)
// is hashed into a *secret* salt (not stored), making this deterministic,
// stronger (when the pepper is independent/high-entropy), and friendlier.
//
// Usage examples:
//   key 10485760 -o key.key
//   key 1073741824 --algo chacha
//
// Notes:
// • SIZE is BYTES only (min 1, max 20 GiB).
// • This is NOT a perfect OTP: reusing a key or using a key shorter than data loses OTP guarantees.
// • Keys are raw bytes written with 0600 (Unix) or a protected DACL (Windows).
//
// Security notes (summarized):
// • Deterministic: same (password, pepper, params, algo) -> same stream.
// • Pepper becomes a *secret* salt via BLAKE3 derive_key (domain-separated).
// • Argon2id parameters are enforced and lanes are clamped to maintain m ≥ 8p.
// • On Unix you can optionally disable core dumps / mark process non-dumpable.
//
// Build: Rust 1.78+, edition 2021

#![deny(unsafe_code)]

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use argon2::{Algorithm, Argon2, Params, Version};
use argon2::Block; // 1 KiB block for with_memory API
use clap::{Parser, ValueEnum};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/*───────────────────────────── Compile‑time “config” ─────────────────────────────*/

#[derive(Copy, Clone, ValueEnum, Debug)]
pub enum StreamAlgo {
    Blake3,
    Chacha,
}
impl std::fmt::Display for StreamAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamAlgo::Blake3 => write!(f, "blake3"),
            StreamAlgo::Chacha => write!(f, "chacha"),
        }
    }
}

/// Change these constants to tweak defaults at compile time.
mod config {
    use super::StreamAlgo;
    /// Default stream algorithm
    pub const DEFAULT_STREAM_ALGO: StreamAlgo = StreamAlgo::Blake3;

    /// Argon2 defaults
    pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024; // 64 MiB
    pub const DEFAULT_ARGON2_TIME: u32 = 3;
    /// 0 = auto (use available_parallelism)
    pub const DEFAULT_ARGON2_PAR: u32 = 0;

    /// Maximum key size in bytes (20 GiB)
    pub const KEY_MAX_BYTES: u128 = 20 * 1024 * 1024 * 1024;

    /// I/O buffer size for streaming to file (1 MiB)
    pub const IO_BUF_SIZE: usize = 1 << 20;

    /// Seed domain separation version
    pub const SEED_CTX_VERSION: &str = "v1";

    /// Minimum pepper length (usability + basic strength)
    pub const PEPPER_MIN_CHARS: usize = 8;
}

/*────────────────────────────────── Unix hardening ──────────────────────────────────*/

#[cfg(unix)]
#[allow(unsafe_code)]
mod unix_sec {
    pub fn harden_process() {
        unsafe {
            // 1) Disable core dumps
            let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            let _ = libc::setrlimit(libc::RLIMIT_CORE, &rlim as *const _);

            // 2) Mark process non-dumpable on Linux/Android
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            }
        }
    }

    use std::fs::File;
    use std::io;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    pub fn open_secure_unix(path: &Path, no_clobber: bool) -> io::Result<File> {
        use libc::{fcntl, F_SETFD, FD_CLOEXEC, O_NOFOLLOW, O_CLOEXEC};

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true)
            .mode(0o600)
            // Avoid following symlinks; fail if path is a symlink.
            .custom_flags(O_NOFOLLOW | O_CLOEXEC);

        if no_clobber {
            // Fail if file exists.
            opts.create_new(true);
        } else {
            opts.create(true).truncate(true);
        }

        let f = opts.open(path)?;

        // Belt-and-suspenders: ensure CLOEXEC even if O_CLOEXEC was ignored.
        unsafe {
            let _ = fcntl(f.as_raw_fd(), F_SETFD, FD_CLOEXEC);
        }

        Ok(f)
    }

    /// Crash-consistency: fsync the parent directory so the directory entry is durable.
    pub fn fsync_parent_dir(path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            // On Unix, opening a directory for reading is enough to call sync_all.
            let dir = std::fs::File::open(parent)?;
            dir.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(unix)]
use unix_sec::{harden_process, open_secure_unix, fsync_parent_dir};

/*────────────────────────────────── Windows ACL ──────────────────────────────────*/

/// Applies a protected DACL allowing Owner, Administrators, and SYSTEM full control.
/// Implemented here to avoid extra modules/files.
#[cfg(windows)]
#[allow(unsafe_code)]
mod win_acl {
    use std::{io, path::Path};
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::minwindef::{BOOL, FALSE};
    use winapi::um::accctrl::SE_FILE_OBJECT;
    use winapi::um::aclapi::SetNamedSecurityInfoW;
    use winapi::um::securitybaseapi::GetSecurityDescriptorDacl;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PACL, PSECURITY_DESCRIPTOR,
    };
    use winapi::shared::ntdef::LPCWSTR;

    // FFI declaration (normally in sddl.h). Linked from advapi32.
    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: LPCWSTR,
            StringSDRevision: u32, // SDDL_REVISION_1 = 1
            SecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
            SecurityDescriptorSize: *mut u32,
        ) -> winapi::shared::minwindef::BOOL;
    }

    /// Apply a protected DACL from SDDL:
    /// D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)
    pub fn tighten(path: &Path) -> io::Result<()> {
        let wpath: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        const SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)";
        let (sd, dacl) = sddl_to_dacl(SDDL)?;
        let status = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr() as *mut _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        unsafe { LocalFree(sd as *mut _) };
        // Avoid needing the winerror feature: 0 == ERROR_SUCCESS
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn sddl_to_dacl(sddl: &str) -> io::Result<(PSECURITY_DESCRIPTOR, PACL)> {
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut present: BOOL = FALSE;
        let mut defaulted: BOOL = FALSE;
        let mut pdacl: PACL = std::ptr::null_mut();
        let wides: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wides.as_ptr(),
                1, // SDDL_REVISION_1
                &mut psd,
                std::ptr::null_mut(),
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
}
#[cfg(windows)]
use win_acl::tighten as tighten_dacl;

/*───────────────────────────────── CLI definition ─────────────────────────────────*/

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Deterministic cryptographic key generator (NOT a perfect OTP)",
    after_help =
"SIZE is in BYTES only (1..=20 GiB).
You will be prompted for two passwords. The second becomes a *secret salt* \
(derived with BLAKE3; not stored), making the tool deterministic by design.

Security notes:
  • Do not reuse the same (password, pepper) pair across unrelated contexts.
  • Strength relies on the combined entropy of BOTH secrets.
  • Suggested Argon2id presets:
      - interactive:  mem=64–128 MiB, t=3–4, p=auto
      - batch/high:   mem=256–1024 MiB, t=3–6, p=auto
"
)]
struct Cli {
    /// Key size in BYTES (e.g. 32, 1048576). Allowed range: 1..=20 GiB.
    #[arg(value_name = "SIZE_BYTES")]
    size_bytes: u128,

    /// Output file path
    #[arg(short, long, default_value = "key.key")]
    output: PathBuf,

    /// Output stream algorithm
    #[arg(short = 'a', long = "algo", value_enum, default_value_t = config::DEFAULT_STREAM_ALGO)]
    algo: StreamAlgo,

    /// Argon2 memory in KiB
    #[arg(long, default_value_t = config::DEFAULT_ARGON2_MEMORY_KIB)]
    argon2_memory: u32,

    /// Argon2 time cost (iterations)
    #[arg(long, default_value_t = config::DEFAULT_ARGON2_TIME)]
    argon2_time: u32,

    /// Argon2 parallelism (lanes); 0 = auto
    #[arg(long, default_value_t = config::DEFAULT_ARGON2_PAR)]
    argon2_par: u32,

    /// Refuse to overwrite an existing file (create-new semantics).
    #[arg(long = "no-clobber", default_value_t = false)]
    no_clobber: bool,

    /// Print the first N bytes as hex to stdout (probe for reproducibility).
    /// This does not alter the written file; the stream is re-initialized.
    #[arg(long = "print-first")]
    print_first: Option<usize>,
}

/*─────────────────────────────────── main / run ───────────────────────────────────*/

fn main() -> io::Result<()> {
    // NOTE: returning Err from main() preserves zeroization paths and still exits non-zero.
    if let Err(e) = run() {
        eprintln!("❌ {e}");
        return Err(e);
    }
    Ok(())
}

fn run() -> io::Result<()> {
    let k = Cli::parse();

    // Optional Unix hardening early: disable core dumps / mark non-dumpable
    #[cfg(unix)]
    harden_process();

    // Validate size: BYTES only
    if k.size_bytes == 0 || k.size_bytes > config::KEY_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "SIZE_BYTES out of range: {} (allowed 1..={} bytes)",
                k.size_bytes, config::KEY_MAX_BYTES
            ),
        ));
    }

    // Password (confirm with constant-time compare); forbid empty
    let pwd1 = read_password("🔐 Enter password: ")?;
    let pwd2 = read_password("🔐 Confirm password: ")?;
    if pwd1.as_bytes().ct_eq(pwd2.as_bytes()).unwrap_u8() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Passwords do not match."));
    }

    // Second password (pepper → secret salt)
    let pepper1 = read_password("🔐 Enter second password (salt/pepper): ")?;
    let pepper2 = read_password("🔐 Confirm second password: ")?;
    if pepper1.as_bytes().ct_eq(pepper2.as_bytes()).unwrap_u8() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Second passwords do not match."));
    }
    // Basic strength/quality checks
    if pepper1.chars().count() < config::PEPPER_MIN_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Second password too short – need ≥{} characters.", config::PEPPER_MIN_CHARS),
        ));
    }
    if !pepper1.chars().any(|c| !c.is_whitespace()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Second password must contain at least one non‑whitespace character.",
        ));
    }

    // Derive a 32‑byte secret salt from the pepper (domain-separated, versioned)
    let mut salt = Zeroizing::new(derive_salt_from_pepper(&pepper1));

    // Derive 32-byte seed with Argon2id (with lane clamp)
    let mut par_eff = effective_parallelism(k.argon2_par);
    let max_par = (k.argon2_memory / 8).max(1);
    if par_eff > max_par {
        eprintln!(
            "ℹ️ Reducing Argon2 lanes from {par_eff} to {max_par} to satisfy m ≥ 8p (m={} KiB).",
            k.argon2_memory
        );
        par_eff = max_par;
    }

    println!(
        "📦 Generating {} bytes with {} / Argon2id(mem={} KiB, t={}, p={})",
        k.size_bytes, k.algo, k.argon2_memory, k.argon2_time, par_eff
    );
    let start = Instant::now();

    // Raw Argon2 seed
    let mut seed_raw = derive_seed(&pwd1, &salt, k.argon2_memory, k.argon2_time, par_eff)?;

    // Domain-separate the stream seed so algo/params can't collide with other tools.
    let mut seed = derive_stream_seed(&seed_raw, k.algo, k.argon2_memory, k.argon2_time, par_eff);

    // Optional probe: print first N bytes in hex (does not affect file stream)
    if let Some(n) = k.print_first {
        if n > 0 {
            let first = first_n_bytes(&seed, k.algo, n)?;
            println!("— first {n} bytes (hex) —");
            println!("{}", hex_with_rows(&first, 16));
        }
    }

    // Stream out key material
    match k.algo {
        StreamAlgo::Blake3 => write_blake3(&k.output, &seed, k.size_bytes, k.no_clobber)?,
        StreamAlgo::Chacha => write_chacha(&k.output, &seed, k.size_bytes, k.no_clobber)?,
    }

    // Wipe seeds and pepper copies ASAP
    seed_raw.zeroize();
    seed.zeroize();
    salt.zeroize();

    println!("✅ Key written to '{}' in {:.2?}", k.output.display(), start.elapsed());
    Ok(())
}

/*──────────────────────────────── Helpers ────────────────────────────────*/

/// Read a password without echoing; forbid empty strings.
fn read_password(prompt: &str) -> io::Result<Zeroizing<String>> {
    match prompt_password(prompt) {
        Ok(s) if !s.is_empty() => Ok(Zeroizing::new(s)),
        Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty password not allowed")),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("Failed to read password: {e}"))),
    }
}

/// Parallelism helper (0 = auto).
fn effective_parallelism(user: u32) -> u32 {
    if user != 0 {
        return user.max(1);
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// Derive the Argon2 seed (32 bytes) using the provided working memory.
fn derive_seed(
    password: &Zeroizing<String>,
    salt_bytes: &[u8; 32],
    mem: u32,
    time: u32,
    par: u32,
) -> io::Result<[u8; 32]> {
    if mem > 4 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("argon2-memory ({mem} KiB) exceeds 4 GiB limit."),
        ));
    }
    let params = Params::new(mem, time, par, None).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid Argon2 parameters: {e}"))
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Use the "no-alloc" API: provide our own memory blocks (1 KiB each)
    let mut seed = [0u8; 32];
    let blocks_len = mem as usize; // mem is in KiB; Block::SIZE == 1024 bytes
    let mut blocks = vec![Block::new(); blocks_len];

    argon2
        .hash_password_into_with_memory(password.as_bytes(), salt_bytes, &mut seed, &mut blocks)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2id hashing failed: {e}")))?;

    // Wipe Argon2 working memory before drop.
    for b in &mut blocks {
        *b = Block::new();
    }
    Ok(seed)
}

/// Derive a secret salt (32 bytes) from the second password (pepper).
fn derive_salt_from_pepper(pepper: &Zeroizing<String>) -> [u8; 32] {
    let context = format!("key/salt/pepper/{}", config::SEED_CTX_VERSION);
    blake3::derive_key(&context, pepper.as_bytes())
}

/// Domain-separate the final stream seed from the raw Argon2 seed.
/// Context is stable across program versions: "key/seed/v1".
fn derive_stream_seed(
    raw_seed: &[u8; 32],
    algo: StreamAlgo,
    mem: u32,
    time: u32,
    par: u32,
) -> [u8; 32] {
    let context = format!(
        "key/seed/{}|algo={}|argon2(m={},t={},p={})",
        config::SEED_CTX_VERSION, algo, mem, time, par
    );
    blake3::derive_key(&context, raw_seed)
}

/// Produce the first N bytes for reproducibility probing (does not alter file stream).
fn first_n_bytes(seed: &[u8; 32], algo: StreamAlgo, n: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    match algo {
        StreamAlgo::Blake3 => {
            let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
            xof.fill(&mut out);
        }
        StreamAlgo::Chacha => {
            let mut rng = ChaCha20Rng::from_seed(*seed);
            rng.fill_bytes(&mut out);
        }
    }
    Ok(out)
}

/// Hex dump with rows of `cols` bytes.
fn hex_with_rows(bytes: &[u8], cols: usize) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            if i % cols == 0 {
                s.push('\n');
            } else {
                s.push(' ');
            }
        }
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/*─────────────────────────────── Streaming I/O ───────────────────────────────*/

fn write_blake3(path: &Path, seed: &[u8; 32], size_bytes: u128, no_clobber: bool) -> io::Result<()> {
    let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
    stream_to_file(path, size_bytes, no_clobber, |buf| xof.fill(buf))
}

fn write_chacha(path: &Path, seed: &[u8; 32], size_bytes: u128, no_clobber: bool) -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    stream_to_file(path, size_bytes, no_clobber, |buf| rng.fill_bytes(buf))
}

fn stream_to_file<F>(path: &Path, mut remaining: u128, no_clobber: bool, mut fill: F) -> io::Result<()>
where
    F: FnMut(&mut [u8]),
{
    /* ---- open with tight permissions -------------------------------- */

    #[cfg(unix)]
    let mut f = open_secure_unix(path, no_clobber)?;

    #[cfg(windows)]
    let mut f = {
        // Respect no_clobber if requested.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true);
        if no_clobber {
            opts.create_new(true);
        } else {
            opts.create(true).truncate(true);
        }
        let file = opts.open(path)?;

        // Tighten ACLs immediately after creation *before* any writes.
        tighten_dacl(path)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        file
    };

    // Heap buffer so we don't blow stack; zeroized on drop.
    let mut buf = Zeroizing::new(vec![0u8; config::IO_BUF_SIZE]);
    while remaining != 0 {
        let n = remaining.min(config::IO_BUF_SIZE as u128) as usize;
        fill(&mut buf[..n]);
        f.write_all(&buf[..n])?;
        remaining -= n as u128;
    }
    f.sync_all()?; // flush file contents/metadata

    #[cfg(unix)]
    fsync_parent_dir(path)?; // ensure directory entry is durable

    Ok(())
}
