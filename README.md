# Encrypted ZIP Manager — Documentation

**AES-256-CBC + HMAC-SHA256**

---

## Table of Contents

1. [Overview](#1-overview)
2. [File Format (.enczip)](#2-file-format-enczip)
3. [Encryption in Detail](#3-encryption-in-detail)
4. [Key Derivation](#4-key-derivation)
5. [Encryption Modes](#5-encryption-modes)
6. [Data Integrity (HMAC)](#6-data-integrity-hmac)
7. [Application Architecture](#7-application-architecture)
8. [User Interface Guide](#8-user-interface-guide)
9. [Editor Associations](#9-editor-associations)
10. [Security Considerations](#10-security-considerations)
11. [Command-Line Usage](#11-command-line-usage)
12. [Threat Model](#12-threat-model)

---

## 1. Overview

Encrypted ZIP Manager is a desktop application for creating and managing encrypted archives. It combines standard ZIP
compression (LZMA) with AES-256-CBC encryption and HMAC-SHA256 authentication, providing a secure container for
sensitive files.

Files are stored in a custom **.enczip** format. Unlike standard ZIP encryption (which encrypts individual files and
leaves filenames visible), this format encrypts the **entire** ZIP archive as a single binary blob. An attacker who
obtains the file cannot see the number of files, their names, sizes, or any metadata.

Two encryption modes are supported: passphrase-based (with PBKDF2 key derivation) and raw key mode (where you provide
the AES key and IV directly).

### Dependencies

```bash
pip install cryptography

# tkinter (usually included with Python)
# Ubuntu/Debian:  sudo apt install python3-tk
# Fedora:         sudo dnf install python3-tkinter
# Conda:          conda install tk
```

---

## 2. File Format (.enczip)

The .enczip file has a fixed 89-byte header followed by the ciphertext:

```
┌──────────────────────────────────────────────┐
│ magic       8 bytes   "ENCZIP01"             │
│ mode        1 byte    0x00=pass, 0x01=key    │
│ salt       32 bytes   PBKDF2 salt            │
│ iv         16 bytes   AES-CBC IV             │
│ hmac       32 bytes   HMAC-SHA256(ciphertext)│
│ ciphertext  …         AES-256-CBC(ZIP)       │
└──────────────────────────────────────────────┘
```

| Field      | Offset | Size     | Description                            |
|------------|--------|----------|----------------------------------------|
| magic      | 0      | 8 bytes  | ASCII `"ENCZIP01"` — format identifier |
| mode       | 8      | 1 byte   | `0x00` = passphrase, `0x01` = raw key  |
| salt       | 9      | 32 bytes | PBKDF2 salt (zeroed in raw-key mode)   |
| iv         | 41     | 16 bytes | Initialization Vector for AES-CBC      |
| hmac       | 57     | 32 bytes | HMAC-SHA256 over the ciphertext        |
| ciphertext | 89     | variable | AES-256-CBC encrypted ZIP data         |

**magic** — allows quick identification of whether a file is an ENCZIP container without attempting decryption.

**mode** — tells the decryptor which key derivation method was used, so it can prompt for the correct input (passphrase
vs. raw key).

---

## 3. Encryption in Detail

### 3.1 Encryption Pipeline

When you save or modify the archive, the following steps occur:

| Step | Operation           | Details                                                               |
|------|---------------------|-----------------------------------------------------------------------|
| 1    | ZIP compress        | All files are packed into a standard ZIP with LZMA compression        |
| 2    | PKCS7 pad           | ZIP bytes are padded to a multiple of 16 bytes (AES block size)       |
| 3    | AES-256-CBC encrypt | Padded data is encrypted using the 32-byte key and 16-byte IV         |
| 4    | HMAC-SHA256         | A MAC is computed over the ciphertext (encrypt-then-MAC)              |
| 5    | Write container     | Header (magic + mode + salt + IV + HMAC) + ciphertext written to disk |

### 3.2 Decryption Pipeline

| Step | Operation           | Details                                                         |
|------|---------------------|-----------------------------------------------------------------|
| 1    | Read header         | Parse magic, mode, salt, IV, HMAC from the first 89 bytes       |
| 2    | Derive keys         | Compute AES key + HMAC key from passphrase or raw_key           |
| 3    | Verify HMAC         | Recompute HMAC-SHA256 over ciphertext; compare with stored HMAC |
| 4    | AES-256-CBC decrypt | Decrypt ciphertext using key + IV from header                   |
| 5    | PKCS7 unpad         | Remove padding to obtain original ZIP bytes                     |
| 6    | ZIP decompress      | Parse ZIP to access individual files                            |

> **Encrypt-then-MAC**: The HMAC is computed over the *ciphertext*, not the plaintext. This is the cryptographically
> preferred order because it allows rejecting tampered data *before* any decryption occurs, preventing padding oracle
> attacks.

---

## 4. Key Derivation

### 4.1 Passphrase Mode (PBKDF2)

When you enter a passphrase, the application derives two 32-byte keys using PBKDF2-HMAC-SHA256:

```
derived = PBKDF2-HMAC-SHA256(
    password   = passphrase (UTF-8 encoded),
    salt       = 32 random bytes (stored in header),
    iterations = 300,000,
    dklen      = 64 bytes
)
aes_key  = derived[0:32]    # first 32 bytes
hmac_key = derived[32:64]   # last 32 bytes
```

The 32-byte random salt is generated fresh for each encryption and stored in the file header. This ensures that the same
passphrase produces different keys for different files (or different saves of the same file), preventing rainbow table
attacks.

> **300,000 iterations** is chosen as a balance between security and usability. On modern hardware (2024), this takes
> approximately 0.2–0.5 seconds, making brute-force attacks expensive while keeping the UI responsive.

### 4.2 Raw Key Mode

When you provide a raw 32-byte key (as 64 hex characters), it is used directly as the AES encryption key. The HMAC key
is derived deterministically:

```
aes_key  = raw_key                        # your 32 bytes
hmac_key = SHA-256("hmac-" || raw_key)     # derived
```

In this mode, the salt field in the header is zeroed out (unused). The IV can be provided by the user (32 hex
characters = 16 bytes) or generated randomly if omitted.

> **Warning**: In raw key mode, if you specify a fixed IV, re-encrypting the same data with the same key and IV will
> produce identical ciphertext. For maximum security, leave the IV field empty (auto-random).

---

## 5. Encryption Modes

| Property               | Passphrase Mode          | Raw Key Mode               |
|------------------------|--------------------------|----------------------------|
| Mode byte              | `0x00`                   | `0x01`                     |
| Key source             | PBKDF2(passphrase, salt) | User-provided 32 bytes     |
| HMAC key               | PBKDF2 second half       | SHA-256("hmac-" + key)     |
| Salt                   | 32 random bytes          | Zeroed (unused)            |
| IV                     | Always random            | User-provided or random    |
| Use case               | Normal users             | Interoperability / HW keys |
| Brute-force resistance | PBKDF2 (300k rounds)     | Depends on key entropy     |

---

## 6. Data Integrity (HMAC)

Every .enczip file includes an HMAC-SHA256 authentication tag computed over the ciphertext. This provides two critical
guarantees:

**1. Tamper Detection**

If any byte of the ciphertext is modified (by disk corruption, malicious tampering, or transmission errors), the HMAC
check will fail and decryption will be refused with a clear error message.

**2. Wrong Password Detection**

If you enter the wrong passphrase, the derived HMAC key will be different, and the HMAC check will fail. This gives you
a clear "wrong password" error instead of silently producing garbage data.

> The HMAC uses a *separate key* from the AES encryption key. In passphrase mode, both keys are derived from the same
> PBKDF2 output but are cryptographically independent (first 32 bytes vs. last 32 bytes of a 64-byte derivation).

---

## 7. Application Architecture

### 7.1 Layers

The application has three distinct layers:

**EncryptedContainer** — handles all cryptographic operations: key derivation, AES-256-CBC encryption/decryption, HMAC
computation/verification, and file I/O. This class has no GUI dependencies and can be used as a standalone library.

**ZIP helpers** — a set of pure functions (`zip_create_empty`, `zip_add_files`, `zip_delete_files`, `zip_read_file`,
`zip_extract_file`, `zip_extract_all`, `zip_list`) that operate on in-memory ZIP bytes. They use Python's standard
`zipfile` module with LZMA compression.

**EncryptedZipManager** — the tkinter GUI that ties everything together. For every operation (add, delete, edit,
extract), it: (1) decrypts the container to get ZIP bytes, (2) modifies the ZIP in memory, (3) re-encrypts and writes
back.

### 7.2 Edit-in-Place Flow

When you double-click a file to edit it:

| Step | Action                                                                  |
|------|-------------------------------------------------------------------------|
| 1    | Decrypt the .enczip container to get ZIP bytes                          |
| 2    | Extract the selected file from ZIP to a temp directory                  |
| 3    | Look up the editor for the file's extension (EditorRegistry)            |
| 4    | Launch the external editor with the temp file path                      |
| 5    | Start a background watcher thread (polls file mtime every 1 second)     |
| 6    | When the editor saves: read the modified temp file                      |
| 7    | Decrypt the current archive, replace the file in ZIP, re-encrypt, write |
| 8    | Refresh the file list in the GUI                                        |
| 9    | Watcher continues until 30 minutes of inactivity or file deletion       |

---

## 8. User Interface Guide

### 8.1 Toolbar

| Button       | Description                                                            |
|--------------|------------------------------------------------------------------------|
| **New**      | Create a new .enczip archive. Prompts for location and credentials     |
| **Open**     | Open an existing .enczip file. Unlock dialog shows encryption metadata |
| **Settings** | Configure editor associations and encryption credentials               |

### 8.2 Action Bar

| Button             | Description                                                             |
|--------------------|-------------------------------------------------------------------------|
| **New File**       | Create an empty file inside the archive (with extension-based template) |
| **Add Files**      | Add one or more files from disk into the archive                        |
| **Add Folder**     | Recursively add an entire folder (preserving directory structure)       |
| **Extract**        | Extract selected files to a chosen directory                            |
| **Edit in Editor** | Open the selected file in the appropriate editor (by extension)         |
| **Delete**         | Remove selected files from the archive                                  |
| **Extract All**    | Extract all files to a chosen directory                                 |

### 8.3 Crypto Info Bar

Below the toolbar, a status line shows the current encryption parameters: algorithm (AES-256-CBC + HMAC-SHA256), key
derivation mode (Passphrase/PBKDF2 or Raw Key), and IV status (specific hex value or "auto/random").

### 8.4 Unlock Dialog

When opening a file, the dialog shows metadata from the header: encryption mode (passphrase/raw_key), IV, and ciphertext
size. This helps identify how the file was encrypted before entering credentials.

---

## 9. Editor Associations

The application maintains a mapping from file extensions to editor commands. On first launch, it auto-detects system
defaults:

| OS      | Detection Method              | Examples                               |
|---------|-------------------------------|----------------------------------------|
| macOS   | `duti -x <ext>` or `open`     | `.docx` → `open -a Microsoft Word`     |
| Windows | `assoc` + `ftype` (registry)  | `.xlsx` → `C:\...\EXCEL.EXE`           |
| Linux   | `xdg-mime` → `.desktop` files | `.pdf` → evince, `.docx` → libreoffice |

### Configuration

Settings are persisted in `~/.enczip_editors.json`:

```json
{
  "fallback": "code",
  "ext_map": {
    ".txt": "code",
    ".docx": "open -a \"Microsoft Word\"",
    ".pdf": "open",
    ".py": "/usr/local/bin/code",
    ".jpg": "open -a Preview"
  }
}
```

**fallback** — the editor used for any extension not listed in `ext_map`. On macOS, `open` is usually the best default (
it delegates to Launch Services).

### GUI Management

In the **Settings** dialog:

- **Add…** — add a new extension association
- **Edit…** — change the editor for an extension (or double-click)
- **Delete** — remove an association (fallback editor will be used)
- **Re-detect from OS** — re-query system defaults

### Editor Path Handling

| Format                                 | How It Is Handled                 |
|----------------------------------------|-----------------------------------|
| `code`                                 | Name looked up in PATH            |
| `/usr/bin/code`                        | Absolute path                     |
| `code --wait`                          | Command with flags (shlex.split)  |
| `/Applications/Visual Studio Code.app` | macOS .app → `open -a "..." file` |
| `open -a "Microsoft Word"`             | macOS open with app specification |
| `libreoffice --writer`                 | Command with subcommand           |

---

## 10. Security Considerations

### 10.1 What Is Protected

The entire ZIP archive (including filenames, directory structure, file sizes, and metadata) is encrypted. An attacker
with access to the .enczip file can only see the total ciphertext size and the encryption mode (passphrase vs. raw key).
The IV is visible in the header but this is by design — IVs are not secrets.

### 10.2 Temporary Files

When editing a file, the decrypted content is written to a temp directory. The application deletes the temp directory on
close. However, the data may persist on disk (deleted files can be recovered with forensic tools).

> **Recommendation**: For maximum security, use an encrypted filesystem for your temp directory, or a RAM disk (`tmpfs`
> on Linux, `diskutil` on macOS).

### 10.3 Memory

The passphrase and derived keys are stored in Python variables during the session. Python does not support secure memory
erasure (the garbage collector may leave copies in memory). For highly sensitive applications, consider a C/Rust
implementation with `mlock()` and explicit memory wiping.

### 10.4 Atomic Writes

The application writes to a `.tmp` file first, then atomically replaces the original via `os.replace()`. This prevents
corruption if the process is killed during a write operation.

### 10.5 Password Strength

PBKDF2 with 300,000 iterations slows down brute-force attacks, but security ultimately depends on passphrase entropy.
Recommendations:

- At least 15 characters with mixed case, digits, and symbols
- A random 4-word passphrase (e.g. "correct horse battery staple") provides approximately 44 bits of entropy — adequate
  for most use cases
- For critical data, use 6+ random words or 32+ random characters

### 10.6 Comparison with Standard ZIP Encryption

| Property               | Standard ZIP (WZ_AES)    | This format (.enczip)        |
|------------------------|--------------------------|------------------------------|
| Filenames              | **Visible** in plaintext | Encrypted                    |
| File count             | **Visible**              | Encrypted                    |
| File sizes             | **Visible**              | Encrypted                    |
| Directory structure    | **Visible**              | Encrypted                    |
| Authentication         | Per-file CRC             | HMAC-SHA256 (full container) |
| Padding oracle defense | None                     | Encrypt-then-MAC             |

---

## 11. Command-Line Usage

```bash
# Launch the GUI
python encrypted_zip_manager.py

# Open a specific archive
python encrypted_zip_manager.py --archive secrets.enczip
python encrypted_zip_manager.py -a secrets.enczip

# Specify the default editor
python encrypted_zip_manager.py --editor /usr/bin/code
python encrypted_zip_manager.py -e "code --wait"

# Both
python encrypted_zip_manager.py -a vault.enczip -e "code --wait"
```

---

## 12. Threat Model

| Threat                      | Protection                                          | Status        |
|-----------------------------|-----------------------------------------------------|---------------|
| Stolen disk / USB drive     | AES-256-CBC encryption; data unreadable without key | ✅ Protected   |
| Passphrase brute-force      | PBKDF2 with 300k iterations slows attacks           | ✅ Protected   |
| Ciphertext tampering        | HMAC-SHA256 detects any modification                | ✅ Protected   |
| Filename / metadata leakage | Entire ZIP is encrypted, not just file contents     | ✅ Protected   |
| Replay attacks              | Random salt + IV per encryption                     | ✅ Protected   |
| Padding oracle attacks      | Encrypt-then-MAC (HMAC verified before decryption)  | ✅ Protected   |
| Memory forensics            | Keys in Python memory (no secure erasure)           | ⚠️ Partial    |
| Temp file forensics         | Files deleted on close but not securely wiped       | ⚠️ Partial    |
| Keylogger / screen capture  | Out of scope (OS-level threat)                      | ❌ Not covered |
| Rubber-hose cryptanalysis   | Out of scope (physical coercion)                    | ❌ Not covered |

---

This application is designed for protecting files on external drives, USB sticks, and cloud storage against unauthorized
access. It provides strong confidentiality and integrity guarantees for data at rest.