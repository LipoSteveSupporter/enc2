# sivcrypt-pro

A fast, chunked, **AES‑256‑GCM‑SIV** file encryption CLI with robust operations: file locking, symlink refusal, metadata preservation, progress reporting, and **atomic output replace**. It supports **Argon2id passphrase** derivation **or** 32‑byte **key files**, uses a safer chunk layout that binds every chunk to its position (prevents cut‑and‑paste reordering), and decrypts legacy **v2** files while writing safer **v3**.

> **Why this tool?**  
> Each chunk’s nonce is derived from `base_nonce8 || u32_be(index)` and the **entire header is AAD**, so tampering with parameters or reordering chunks breaks authentication.

---

## Features

- **AES‑256‑GCM‑SIV** AEAD (misuse‑resistant to nonce reuse; still uses unique nonces per chunk)
- **Chunked encryption/decryption** for bounded memory; great for huge files
- **Order integrity**: per‑chunk nonce derived from `base_nonce8 || u32_be(index)` (**not stored**)
- **Header‑as‑AAD**: algorithm, version, sizes, salt, KDF params are authenticated
- **Two keying modes**:
  - 32‑byte **key file** (strict permission checks on Unix)
  - **Argon2id** passphrase (`AES_PASSWORD` env or interactive prompt) with strong defaults
- **Atomic replace** of the destination path using `atomic-write-file`
  - **Unix:** in‑place overwrite supported (default when `--out` is omitted)
  - **Windows:** **require `--out`** (in‑place overwrite is not performed due to OS handle semantics)
- **Operational hardening**: exclusive file locks, symlink refusal, progress bar, restore original permissions & mtime
- **Backward compatible**: decrypts older **v2** files; writes **v3** format

> **What’s *not* implemented (yet):** `--verify` (read‑only check), `--stdout` streaming, `--wipe-input`, tunable Argon2 CLI flags. (See “Roadmap”.)

---

## Install / Build

Prerequisites: recent Rust toolchain (stable).

```bash
git clone <your-repo-or-local-path> sivcrypt-pro
cd sivcrypt-pro
cargo build --release

# optional: install to cargo bin dir
cargo install --path .
```

Binary: `target/release/sivcrypt-pro` (Windows: `target\release\sivcrypt-pro.exe`).

---

## Quick Start

Encrypt a file in place (interactive password prompt, Argon2id KDF):
```bash
sivcrypt-pro --password --encrypt ./data.bin
```

Decrypt to a new path:
```bash
sivcrypt-pro --decrypt --out ./plain.bin ./data.bin.siv
```

Encrypt using a 32‑byte key file:
```bash
sivcrypt-pro --keyfile ./secret.key --encrypt ./movie.mkv
```

> **Windows note:** for both encrypt and decrypt, if input == output path, the tool will error. Pass `--out <PATH>`.

---

## Usage

```
USAGE:
    sivcrypt-pro [--encrypt | --decrypt] [OPTIONS] <FILE>

MODES (choose one or auto-detected if omitted):
    --encrypt               Encrypt the input file
    --decrypt               Decrypt the input file

I/O:
    --out <PATH>            Write output to this path (default: overwrite input)
    --chunk-size <N>        Chunk size (e.g., 4M, 8M, 1M). Max 64M. Default: 4M
    --quiet                 Suppress progress output
    --yes                   Assume “yes” for overwriting outputs

KEYING:
    --keyfile <PATH>        Use a 32-byte key file (encryption & decryption). Enforces strict perms on Unix
    --password              Derive key from passphrase (Argon2id) for ENCRYPTION.
                            For decryption the tool auto-detects and will prompt if needed.

ENVIRONMENT:
    AES_PASSWORD            If set, used as the passphrase instead of prompting
```

Exit status is non‑zero on error.

---

## Security Design

- **Cipher**: AES‑256‑GCM‑SIV (AEAD). We use 96‑bit nonces, unique per chunk.
- **Header‑as‑AAD**: The full 64‑byte header is Associated Data for every chunk, binding algorithm, version, salt, Argon2 params, chunk size, file size, and `base_nonce8`.
- **Nonce derivation (v3)**: For chunk index *i* (0‑based), `nonce = base_nonce8 || u32_be(i)`. Nonces are **not stored** in the body; chunk reordering/splicing fails authentication.
- **Body layout (v3)**: `ciphertext_i || tag_i(16)`.  
  **Legacy v2**: `nonce(12) || ciphertext_i || tag(16)` per chunk.
- **Strict parsing**: Decryption rejects truncated files, **trailing bytes**, unreasonable header values, and wrong keys/passwords.
- **KDF**: With `--password`, keys are derived via **Argon2id** using strong defaults (256 MiB, 3 iters, 1 lane). The file header stores the Argon2 params and per‑file random salt.
- **Atomic replace**: Output is written to a temp file in the same directory, fsynced, then atomically replaced over the destination to avoid torn writes.
- **Key hygiene**: Passphrases are read without echo; derived keys and temporaries are zeroized when possible.

> **Not covered**: metadata secrecy (filenames, sizes, timestamps), deniability, or forensic‑grade deletion. Pair with full‑disk encryption if those matter.

---

## File Format (v3)

**Header** (64 bytes; used as AAD for all chunks):

| Field            | Bytes | Format | Notes                                   |
|------------------|------:|--------|-----------------------------------------|
| Magic            | 10    | ASCII  | `AESGCM-SIV`                            |
| Version          | 1     | u8     | `3` for v3                              |
| Algorithm        | 1     | u8     | `1` = AES‑256‑GCM‑SIV                   |
| Flags            | 2     | u16LE  | bit 0: key from Argon2                  |
| Chunk size       | 4     | u32LE  | plaintext chunk size                    |
| File size        | 8     | u64LE  | total plaintext size                    |
| base_nonce8      | 8     | bytes  | random per file                         |
| salt16           | 16    | bytes  | Argon2 only; zero otherwise             |
| Argon2 m_cost    | 4     | u32LE  | in KiB (Argon2 only; else zero)         |
| Argon2 t_cost    | 4     | u32LE  | iterations (Argon2 only; else zero)     |
| Argon2 lanes     | 4     | u32LE  | parallelism (Argon2 only; else zero)    |
| Reserved         | 2     | zero   | padding to 64 bytes                     |

**Body** (per chunk *i*):  
`ciphertext_i (len = min(chunk_size, remaining_plain)) || tag_i (16 bytes)`  
`nonce_i = base_nonce8 || u32_be(i)`; AAD = 64‑byte header.

---

## Performance & Tuning

- **Chunk size** (`--chunk-size`): default 4 MiB. Larger chunks can improve throughput; smaller chunks reduce memory. Max 64 MiB.
- **Argon2 defaults** (when `--password`): 256 MiB memory, 3 iterations, 1 lane. These are strong defaults for modern desktops.

---

## Operational Notes

- **Key files on Unix**: The tool refuses world/group‑accessible key files (recommend `chmod 600 secret.key`).
- **Environment variables**: `AES_PASSWORD` is convenient but can leak via env inspection. Prefer prompting for high‑value secrets.
- **Windows output path**: Use `--out` to avoid in‑place replace; the tool will refuse input==output on Windows.

---

## Troubleshooting

- **“authentication failed / wrong key”**: Wrong passphrase/key file or file corruption. For password‑based files, ensure `AES_PASSWORD` isn’t set unintentionally.
- **“file already appears encrypted”**: You tried to encrypt an already encrypted file; pass `--encrypt` explicitly to force (not generally recommended).
- **“key file must be exactly 32 bytes”**: The key file must contain 32 raw bytes. Generate with:  
  `head -c 32 /dev/urandom > key.key && chmod 600 key.key` (Unix).

---

## Roadmap (nice‑to‑have)

Planned but not in the current codebase:
- `--verify` (read‑only integrity check)
- `--stdout` streaming for pipelines
- `--wipe-input` (best‑effort overwrite + delete)
- Tunable Argon2 flags (`--kdf-mem-mib`, `--kdf-iters`, `--kdf-lanes`)

---

## License

MIT. See `LICENSE`.
