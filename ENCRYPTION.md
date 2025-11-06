### KeyRex Encryption Design & Implementation

---

## Overview

This document describes the technical design, cryptographic primitives, and implementation details that ensure the confidentiality and integrity of all vault entries.

Encryption and decryption are handled by the module [`crypto.rs`](./src/crypto.rs), implemented in Rust with a focus on simplicity, auditability, and security.

---

## 1. Cryptographic Algorithms

| Purpose               | Algorithm           | Details                                                                |
| --------------------- | ------------------- | ---------------------------------------------------------------------- |
| **Encryption**        | AES-256-GCM         | Authenticated encryption (provides both confidentiality and integrity) |
| **Key Derivation**    | PBKDF2-HMAC-SHA256  | Derives a 256-bit key from a user-supplied password                    |
| **Randomness Source** | `rand::rngs::OsRng` | Cryptographically secure system RNG                                    |
| **Encoding**          | Base64              | Encodes the combined output for storage in vault.dat                   |

---

## 2. Encryption Process

The encryption workflow in `crypto.rs` proceeds as follows:

1. **Generate a random salt** (32 bytes) using a secure RNG.
   The salt ensures that the same password never derives the same key twice.

2. **Derive a 256-bit key** using PBKDF2-HMAC-SHA256:

   * Password: user-supplied
   * Salt: random 32 bytes
   * Iterations: `600,000`
   * Output: 32-byte derived key

3. **Generate a random nonce** (12 bytes) for AES-GCM.
   Each encryption operation uses a fresh nonce.

4. **Encrypt the plaintext** using AES-256-GCM with the derived key and generated nonce.
   The algorithm produces both ciphertext and an integrity authentication tag.

5. **Concatenate and encode** the following into a Base64 string:

   ```
   [salt || nonce || ciphertext+tag]
   ```

6. **Zeroize** key material from memory immediately after use to minimize exposure.

---

## 3. Decryption Process

To decrypt an encrypted entry:

1. **Decode** the Base64-encoded string.
2. **Extract** the salt (32 bytes) and nonce (12 bytes).
3. **Derive** the same AES key from the password and salt (using PBKDF2-HMAC-SHA256, 600k iterations).
4. **Decrypt** the ciphertext using AES-256-GCM with the derived key and extracted nonce.
5. **Return** the decrypted plaintext if authentication succeeds, otherwise return a `DecryptionFailed` error.

If an incorrect password is provided or the data has been tampered with, decryption fails cleanly with a clear error message.

---

## 4. Data Format

Encrypted entries are stored as Base64 strings representing the concatenation:

```
salt (32 bytes) + nonce (12 bytes) + ciphertext+tag (variable length)
```

Example (shortened):

```
U2FsdGVkX1+xKz...AAQp8n3pJ+VbZho0I1g==
```

This design keeps the vault portable and self-contained, requiring no external metadata.

---

## 5. Parameters

| Parameter         | Value              | Notes                            |
| ----------------- | ------------------ | -------------------------------- |
| **KDF algorithm** | PBKDF2-HMAC-SHA256 | Standard, well-supported         |
| **Iterations**    | 600,000            | Increases brute-force resistance |
| **Key length**    | 256 bits           | AES-256 compatible               |
| **Salt length**   | 32 bytes           | Unique per entry                 |
| **Nonce length**  | 12 bytes           | Unique per encryption            |
| **Tag length**    | 16 bytes           | Implicit in AES-GCM output       |
| **Encoding**      | Base64             | Safe for text-based vault files  |

---

## 6. Error Handling

All cryptographic operations are wrapped in structured error types:

* `CryptoError::EncryptionFailed`
* `CryptoError::DecryptionFailed`
* `CryptoError::InvalidFormat`
* `CryptoError::KeyDerivationError`

Descriptive messages are returned to the CLI layer for user-friendly error output.

---

## 7. Security Considerations

| Area                         | Practice                            | Status                        |
| ---------------------------- | ----------------------------------- | ----------------------------- |
| **Key Derivation Hardening** | PBKDF2 with 600k iterations         | ✅ Implemented                 |
| **Authenticated Encryption** | AES-GCM tag verification            | ✅ Implemented                 |
| **Key Zeroization**          | Sensitive data wiped post-use       | ✅ Implemented                 |
| **Password Caching**         | Managed externally by the CLI layer | ✅ Implemented                 |
| **Tamper Detection**         | GCM authentication tag              | ✅ Implemented                 |
| **Randomness Source**        | OS CSPRNG via `OsRng`               | ✅ Implemented                 |

> ⚠️ The password caching behavior mentioned in the README is implemented at the CLI level, not inside `crypto.rs`.
> This design choice keeps the crypto layer stateless and secure.

---

## 9. Future Improvements

* Optional **Argon2id** support for stronger, memory-hard key derivation.
* Configurable iteration count via environment or CLI flag.
* Secure memory handling (via `zeroize` or `secrecy` crates) for all buffers.
* Hardware-backed key support (TPM or YubiKey integration).

---

## 10. Summary

KeyRex provides **AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation**,
ensuring that vault contents remain confidential and tamper-evident, even if the data file is exposed.

All encryption happens locally — no keys, salts, or passwords are ever transmitted or stored remotely.

> **In short:**
> KeyRex offers a transparent, auditable, and standards-based encryption design that prioritizes user privacy and practical security over complexity.
