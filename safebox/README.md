# Safebox v2 (pure Rust, hard‑coded key)
A single‑command, streaming file encryptor/decryptor with **atomic in‑place updates** and built‑in **self‑verification** — simplified to use a **hard‑coded master key only** (no environment variables).

> **Key properties:** one command (`safebox <file>`), no double‑encrypt, crash‑safe atomic replace, authenticated streaming encryption (XChaCha20‑Poly1305), per‑file subkeys, integrity self‑check before commit, pure Rust dependencies, **hard‑coded master key with a default value**.

---

## Overview
**Safebox** focuses on **data safety** and **operational simplicity**. Run it with exactly one argument — the file path. Safebox auto‑detects whether the file is plaintext or already encrypted (via magic header) and performs the correct action, preventing accidental double‑encryption.

- **Single command:** `safebox <path>`; mode auto‑detected by header (`SBX2`).
- **Atomic & crash‑safe:** write to temp file in the same directory → `fsync` → atomic rename over original.
- **Self‑verification:** after encrypting, Safebox decrypts its own temp output and compares a BLAKE3 hash of plaintext before replacing the original.
- **Authenticated streaming AEAD:** XChaCha20‑Poly1305 (pure Rust via the `chacha20poly1305` crate).
- **Per‑file subkeys:** derived from a **hard‑coded** 32‑byte master key + random salt stored in the header.
- **No double‑encrypt:** `SBX2` magic triggers decrypt; refuses legacy `SBX1` to prevent data loss.
- **Metadata preservation:** permissions and timestamps are restored after replacement.
- **Concurrency guard:** advisory sidecar lock `<file>.sbx.lock` avoids concurrent clobbering and is auto‑cleaned via RAII even on error.
- **Pure Rust:** no C libraries; minimal dependencies.

---

## Security model & caveats
> **Hard‑coded master key:** This build *only* uses a compiled‑in key. A **default key** is provided for convenience and **must be replaced** before real use. If the binary or its memory dumps leak, an attacker can extract the key. This matches the stated threat model (attacker does not have access to the machine running Safebox), but you should still protect distribution of the binary.

- **Confidentiality & integrity:** Every frame is AEAD‑authenticated with AAD binding the file header, frame type, and counter; a final authenticated frame guarantees truncation detection.
- **Data safety:** Original file is untouched until the new content is fully written, synced, verified, and atomically renamed into place.
- **Key hygiene:** Key material is zeroized in memory on drop (via `Zeroizing`), but hard‑coding means the key can be recovered from the binary itself if it leaks.

---

## Build
Requires Rust (stable). No external libraries.

```bash
cargo build --release
# Binaries:
# - Unix:  target/release/safebox
# - Win:   target\release\safebox.exe
```

---

## Configure the hard‑coded master key (required)
Open `src/main.rs` and locate:

```rust
const MASTER_KEY_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
```

> **Replace the default value** with your own **64‑hex‑character** string (32 bytes). Keep the old key somewhere safe if you need to decrypt old files later.

Generate a random key:

- **PowerShell**
  ```powershell
  $b = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
  ($b | ForEach-Object { $_.ToString('x2') }) -join ''
  ```

- **bash**
  ```bash
  openssl rand -hex 32
  ```

Paste the hex into `MASTER_KEY_HEX`, rebuild, and use that binary for both encryption and decryption. **If you change the key later, you will not be able to decrypt files written with the old key unless you keep a copy of the old binary/key.**

---

## Quick start
1) Edit `MASTER_KEY_HEX` in `src/main.rs` and rebuild (`cargo build --release`).  
2) Run with exactly one argument: the file path.

**Examples**

```bash
# Encrypt (auto-detected)
safebox ./notes.txt

# Decrypt (auto-detected)
safebox ./notes.txt
```

**Windows (PowerShell)**

```powershell
.\target\release\safebox.exe ".\My Documents\photo.jpg"
```

Running without an argument prints usage and exits with a non‑zero status.

---

## Usage notes
- **Same directory temp:** A temporary file is created in the *same directory* to ensure cross‑device renames are not attempted (atomic within a single filesystem).
- **Do not change the key between runs:** Decryption requires the same master key used for encryption.
- **No double‑encrypt:** Files starting with the `SBX2` magic will be decrypted instead of encrypted.
- **Legacy format guard:** Files with `SBX1` (v1/libsodium) are refused; decrypt with a v1 binary first, then re‑encrypt with v2.
- **Locks:** A best‑effort advisory lock `<file>.sbx.lock` prevents two Safebox processes from touching the same file at once; it is automatically removed on all exit paths (RAII).

---

## Data safety & atomicity
1. Open source file for reading.  
2. Create a temporary file in the same directory (`.safebox.*.tmp`).  
3. Stream‑encrypt (or decrypt) into the temp file.  
4. **fsync** the temp file to push data to storage.  
5. **Self‑verification (encrypt only):** reopen the temp file, decrypt it back, and compare a BLAKE3 hash of plaintext with the original.  
6. **Atomic replace:** rename the temp file over the original in one step.  
7. Restore timestamps and permissions; perform a best‑effort directory durability call.

> On Windows, directory syncing is best‑effort; the temp file itself is always `fsync`’d before rename.

---

## Cryptography details
- **Algorithm:** XChaCha20‑Poly1305 (24‑byte nonce, 16‑byte tag) via `chacha20poly1305` (pure Rust).  
- **Key derivation:** Per‑file subkey = `BLAKE3.keyed_hash(master_key, salt)`, where `salt` is 16 random bytes stored in the header.  
- **Nonces:** 16‑byte per‑file random nonce base + 8‑byte big‑endian frame counter → 24‑byte XNonce.  
- **AAD:** Fixed header bytes + frame type + frame counter for each frame; binds ciphertext to file identity and position.  
- **Final frame:** Zero‑length payload with its own nonce/AAD; guarantees truncation detection at chunk boundaries.  
- **Chunk size:** 64 KiB plaintext per Data frame (tune by changing `CHUNK_SIZE` in `main.rs`).

---

## File format (SBX2)

### Header (fixed)

| Field        | Bytes | Description                                              |
|--------------|:-----:|----------------------------------------------------------|
| `MAGIC`      |   4   | ASCII `SBX2`.                                           |
| `ALGO_ID`    |   1   | `0x02` (XChaCha20‑Poly1305 stream framing).             |
| `SALT_LEN`   |   1   | `0x10` (16 bytes).                                      |
| `SALT`       |  16   | Random per‑file salt used for subkey derivation.        |
| `NB_LEN`     |   1   | `0x10` (16 bytes).                                      |
| `NONCE_BASE` |  16   | Random per‑file nonce base.                             |

### Frames (streaming)

| Field         | Type/Bytes | Description                                                         |
|---------------|------------|---------------------------------------------------------------------|
| `FRAME_TYPE`  |     1      | `0x00`=Data, `0xFF`=Final.                                         |
| `COUNTER`     |     8      | Big‑endian u64, starts at 0 and increments by 1 per frame.         |
| `CT_LEN`      |     4      | Big‑endian u32; length of ciphertext for this frame.               |
| `CIPHERTEXT`  |  CT_LEN    | AEAD output: encrypted chunk + 16‑byte tag.                        |

**AAD per frame:** fixed header + frame type + counter. Exactly one Final frame must appear, carrying an empty plaintext. Any trailing bytes after Final cause decryption failure.

---

## Appendix — Executables, Streaming/Chunking, Overhead & Key Format

### Can Safebox safely process executable files?
- **Yes.** Safebox operates on raw bytes and is **binary‑safe**. It works with `.exe`, `.dll`, `.so`, `.dylib`, Mach‑O, ELF—anything. After decryption you get a **byte‑for‑byte identical** file (verified by decrypting the temp file and comparing a BLAKE3 hash before the atomic rename).
- **Permissions preserved:** POSIX execute bits and timestamps are preserved. On Windows, basic attributes are preserved via the replacement file’s permissions.
- **While in use:** If another process holds the destination file open (e.g., a running EXE), Windows may block the replace; Safebox **aborts before rename** so the original remains intact.
- **Special metadata caveat:** Extended attributes, POSIX ACLs beyond mode bits, and Windows Alternate Data Streams (ADS) are not currently preserved. Most executables don’t rely on these, but if yours do, see “Metadata preservation options.”

### Does it process in chunks or load the whole file?
- **Streaming, not whole‑file.** Safebox works in **64 KiB chunks** (configurable via `CHUNK_SIZE`). Memory remains small and constant even for very large files.
- **Framing & integrity:** Each chunk is an AEAD‑authenticated frame with AAD that binds the file header, frame type, and counter. A **Final** zero‑length frame guarantees truncation detection.

### How much on‑disk overhead does the format add?
- **Fixed header:** 39 bytes per file.  
- **Per frame (each data chunk & the final frame):** 13‑byte frame header + 16‑byte AEAD tag = **29 bytes**.  
- **Total overhead:** `39 + (N_data + 1) × 29`, where `N_data = ceil(plaintext_bytes / CHUNK_SIZE)`.  
- **Example (100 MiB, 64 KiB chunks):** `N_data = 1600` → overhead `= 39 + (1600+1)×29 = 46,468 bytes ≈ 45.4 KiB`.

### Metadata preservation options (advanced)
If you need to preserve extra metadata, extend the implementation:
- **POSIX xattrs/ACLs:** read extended attributes before processing; write them to the temp file before the atomic rename.
- **Windows ADS:** enumerate named streams on the original and copy them to the temp file before rename.
- **Where to hook:** In code, capture metadata right after `fs::metadata` in `encrypt_in_place`/`decrypt_in_place`; restore it just before the final `rename`.

> These extensions don’t affect the file’s bytes or cryptography; they only mirror metadata around the atomic replace.

### Does hex limit the number of keys compared to a “binary” key?
- **No.** A **64‑hex‑character** string encodes exactly **32 bytes (256 bits)** → the same **2²⁵⁶** key space as a raw 32‑byte key.
- Entropy loss happens only if keys are chosen from a smaller character set or human‑memorable strings. Random 64‑hex‑char keys preserve full strength.
- **Alternative representation (identical strength):** store the key as a raw byte array to skip the tiny decode step.

### Safety recap
- **Atomic replace:** original file is untouched until the new file is fully written, `fsync`’d, verified (encrypt path), and atomically renamed into place.
- **Authentication everywhere:** Any corruption, reordering, or missing final frame causes decryption to fail (fail‑closed).
- **Locking:** a sidecar lock file (`.sbx.lock`) prevents two concurrent runs on the same target; it is automatically removed even on error paths (RAII).

---

## License & warranty
© 2025 Safebox v2 (pure Rust, hard‑coded key). Replace the default key before real use. **No warranty; test in your environment.**
