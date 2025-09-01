# votp 2.2

**Versatile, hardened one-time-pad XOR transformer**  
+ **Deterministic key generator** (built in by default)

---

## Features

- **OTP XOR**: Encrypts or decrypts data with a key file (stream XOR).
- **Deterministic keygen**: Derives high‑strength key material from a password & salt (Argon2id → seed → BLAKE3‑XOF or ChaCha stream).
- **Secure file handling**:
  - Unix: restrictive `chmod(0600)` + `O_NOFOLLOW` (refuse to follow symlinks) for input/output.
  - Windows: restrictive ACLs (Owner/Admins/System) + refusal to follow symlinks/junctions for input/output.
  - Exclusive file locks, atomic in‑place updates (temp + rename, with cross‑device fallback), timestamp restore on Unix.
  - **Alias safety**: refuses dangerous cases where `{input, output, key}` refer to the same file.
- **Optional SHA‑256** (feature `verify`)
  - `--expect <sha256>` to verify output in constant‑time.
  - If `--expect` is omitted and stderr is a TTY, prints the SHA‑256 of the output.
- **Optional progress bar** (feature `progress`)
- **Optional Unix xattrs preservation** (feature `xattrs`)

---

## Installation

```sh
# Default build (includes the key generator)
cargo build --release

# Build with extras
cargo build --release --features verify,progress,xattrs

# Small build without keygen
cargo build --release --no-default-features
```

Binary will be at:
```
target/release/votp
```

---

## Key Size Format

When generating keys, size uses the format:

```
<n><B|KB|MB|GB>
```

- `B`  = bytes
- `KB` = kibibytes (×1024)
- `MB` = mebibytes (×1024²)
- `GB` = gibibytes (×1024³)
- **Maximum key size:** 20 GiB

Examples:
```
32B   → 32 bytes
1KB   → 1024 bytes
10MB  → 10 × 1024² bytes
2GB   → 2 × 1024³ bytes
```

---

## Key Generation (deterministic)

Generate cryptographic key material from a password & **unique random salt**.  
This is not a perfect OTP, but a strong deterministic key stream derived via Argon2id.

```
votp keygen <size> [OPTIONS]
```

### Options

| Option                | Description                                                | Default          |
|-----------------------|------------------------------------------------------------|------------------|
| `<size>`              | Key size (`B|KB|MB|GB` format)                             | — (required)     |
| `-o`, `--output`      | Output file path                                           | `key.key`        |
| `-a`, `--algo`        | Stream algorithm: `blake3` or `chacha`                     | `blake3`         |
| `-s`, `--salt`        | **Base64 salt, ≥ 24 chars (≥ 16 random bytes)**            | — (required)     |
| `--argon2-memory`     | Argon2 memory in KiB (max 4,194,304 KiB = 4 GiB)           | `65536` (64 MiB) |
| `--argon2-time`       | Argon2 iterations/time cost                                | `3`              |
| `--argon2-par`        | Argon2 parallelism (0 = auto)                              | `0`              |
| `--gen-salt <n>`      | Generate and print a new random salt of **N bytes**, then exit | —            |

> **Notes**
> - Salts must be **random** and **unique per key**. They **do not need to be secret**; you may store them alongside the key or ciphertext if desired.
> - The generator preflights Argon2 memory and will fail early if the requested work memory can’t be allocated.

### Examples

**1) Generate a salt (16 bytes)**
```sh
votp keygen 1KB --gen-salt 16
```

**2) Generate a 1 MB BLAKE3 key**
```sh
votp keygen 1MB --salt "BASE64_SALT_FROM_STEP1"
```

**3) Generate a 32 B ChaCha key with custom output**
```sh
votp keygen 32B -a chacha -o my.key --salt "BASE64_SALT"
```

**4) Generate a 10 MB key with custom Argon2 parameters**
```sh
votp keygen 10MB --argon2-memory 131072 --argon2-time 5 --argon2-par 4 --salt "BASE64_SALT"
```

---

## OTP XOR

Encrypts or decrypts data with a key file by XORing the streams.

```
votp xor [OPTIONS]
```

Or, without the explicit subcommand:
```
votp [OPTIONS]
```

### Options

| Option              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `-i`, `--input`     | Input file (`-` for stdin)                                                  |
| `-k`, `--key`       | Key file path (or use `$OTP_KEY` env var)                                   |
| `-o`, `--output`    | Output file (`-` for stdout)                                                |
| `--in-place`        | Modify the input file in place (not allowed with `-`/stdin)                 |
| `--min-len`         | Require key length ≥ data length                                            |
| `--strict-len`      | Require key length == data length                                           |
| `--expect <sha256>` | (feature `verify`) Verify output SHA-256 (hex) in constant time             |
| `--progress`        | (feature `progress`) Show a progress bar                                    |

### Safety checks & behavior

- **Alias safety:** tool refuses if:
  - `input == key`, or `output == key`, or `output == input` (unless `--in-place`).
- **Symlinks/junctions:** refuses input symlinks and output symlinks/junctions.
- **stdin + `--in-place`:** not allowed.
- **Empty key file:** refused.
- **Key length warning:** if key length ≠ data length and you didn’t use `--min-len`/`--strict-len`, the key repeats and you’ll get a warning (not OTP‑strong).

### Examples

**1) Encrypt file with key**
```sh
votp xor -i secret.txt -k key.key -o secret.enc
```

**2) Decrypt back**
```sh
votp xor -i secret.enc -k key.key -o secret.txt
```

**3) Encrypt in-place**
```sh
votp xor -i secret.txt -k key.key --in-place
```

**4) Enforce exact key length (OTP semantics)**
```sh
votp xor -i file.bin -k key.bin --strict-len
```

**5) Require at least file length (no short key)**
```sh
votp xor -i file.bin -k key.bin --min-len
```

**6) With SHA‑256 verification**
```sh
# Build with: --features verify
votp xor -i file.bin -k key.bin -o out.bin --expect deadbeef...cafebabe
```

**7) With progress bar**
```sh
# Build with: --features progress
votp xor -i bigfile.iso -k bigkey.key -o out.iso --progress
```

---

## Security Notes

- One‑time‑pad security **requires all of**:
  - Truly random, secret key
  - Key used only once
  - Key length exactly equals data length
- The deterministic `keygen` mode is **not a true OTP**, but produces strong key material from a password and salt.
- Salts should be **random** and **unique**; **they do not need to be secret**.
- If the key is shorter than the data, it will repeat (you’ll see a warning). Repeating keys **break OTP security**.

---

## Limits

- **Keygen size cap:** 20 GiB
- **Argon2 memory cap:** 4 GiB (`--argon2-memory` in KiB)
- **Parallelism:** `--argon2-par 0` auto‑detects logical cores

---

## License

MIT OR Apache-2.0
