# File Encryption and Decryption Tool

This is a Rust-based command-line application that allows users to securely encrypt and decrypt files using the AES-GCM encryption algorithm. The tool provides a simple interface to choose between encryption and decryption, ensuring data confidentiality and integrity.

---

## Features

- **AES-GCM Encryption**: Uses the AES-GCM algorithm for authenticated encryption.
- **File Encryption**: Encrypts files and saves the encrypted data along with a unique nonce.
- **File Decryption**: Decrypts previously encrypted files using the same passphrase and nonce.
- **User-Friendly Interface**: Provides a menu to choose between encryption and decryption.
- **Secure Key Derivation**: Derives encryption keys from user-provided passphrases using a secure key derivation function.

---

## Requirements

- **Rust**: Ensure you have Rust installed. You can install it from [rust-lang.org](https://www.rust-lang.org/).
- **Dependencies**: The following crates are used in the project:
  - `aes-gcm`
  - `rfd`
  - `sha2`
  - `generic-array`
  - `concat-kdf`
  - `base64`

To install dependencies, run:
```bash
cargo build