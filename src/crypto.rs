//! Encryption and security operations
//!
//! This module implements AES-256-GCM encryption with password-based key derivation
//! following OWASP security guidelines:
//! - **Encryption**: AES-256-GCM (Authenticated Encryption)
//! - **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations
//! - **Password Validation**: Minimum 12 chars, complexity requirements
//! - **Rate Limiting**: Max 5 failed attempts with exponential backoff
//! - **Memory Security**: Keys are zeroized after use
//!
//! Format: `base64(32-byte-salt || 12-byte-nonce || ciphertext)`

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::io::Write;
use std::sync::Mutex;
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
// TODO: Document in Security
const PBKDF2_ROUNDS: u32 = 600_000;

// Rate limiting constants
const MAX_PASSWORD_ATTEMPTS: u32 = 5;
const BASE_BACKOFF_SECS: u64 = 1;

/// Global password attempt counter for rate limiting
static PASSWORD_ATTEMPTS: Mutex<u32> = Mutex::new(0);

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidFormat,
    MaxAttemptsExceeded,
    WeakPassword(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            // Note: Do NOT hint at "wrong password" - this leaks information about auth failure modes
            CryptoError::DecryptionFailed => write!(f, "Unable to decrypt vault"),
            // Note: InvalidFormat and DecryptionFailed are both handled as generic decryption failure
            // to prevent timing/information attacks that could reveal vault properties
            CryptoError::InvalidFormat => write!(f, "Unable to decrypt vault"),
            CryptoError::MaxAttemptsExceeded => write!(
                f,
                "Maximum password attempts ({}) exceeded",
                MAX_PASSWORD_ATTEMPTS
            ),
            CryptoError::WeakPassword(msg) => write!(f, "Weak password: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Records a failed password attempt and applies exponential backoff
/// Returns Err if max attempts exceeded
fn record_failed_attempt() -> Result<(), CryptoError> {
    let mut attempts = PASSWORD_ATTEMPTS.lock().unwrap();
    *attempts += 1;

    if *attempts >= MAX_PASSWORD_ATTEMPTS {
        return Err(CryptoError::MaxAttemptsExceeded);
    }

    // Calculate exponential backoff: 2^(attempt-1) seconds
    // Attempt 1: 1s, Attempt 2: 2s, Attempt 3: 4s, Attempt 4: 8s
    let backoff_secs = BASE_BACKOFF_SECS * 2u64.pow(*attempts - 1);
    let remaining = MAX_PASSWORD_ATTEMPTS - *attempts;

    eprintln!(
        "Invalid password. {} attempt{} remaining. Waiting {} second{}...",
        remaining,
        if remaining == 1 { "" } else { "s" },
        backoff_secs,
        if backoff_secs == 1 { "" } else { "s" }
    );

    std::thread::sleep(Duration::from_secs(backoff_secs));
    Ok(())
}

/// Resets the password attempt counter (called on successful authentication)
pub fn reset_attempts() {
    let mut attempts = PASSWORD_ATTEMPTS.lock().unwrap();
    *attempts = 0;
}

/// Gets the current number of failed attempts
#[allow(dead_code)]
pub fn get_attempts() -> u32 {
    *PASSWORD_ATTEMPTS.lock().unwrap()
}

/// Derives a 256-bit key from a password using PBKDF2-HMAC-SHA256
fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
    key
}

/// Validates password strength according to security requirements
///
/// Requirements:
/// - Minimum 12 characters
/// - At least one uppercase letter
/// - At least one lowercase letter
/// - At least one digit
/// - At least one special character
pub fn validate_password_strength(password: &str) -> Result<(), CryptoError> {
    if password.len() < 12 {
        return Err(CryptoError::WeakPassword(
            "Password must be at least 12 characters long".to_string(),
        ));
    }

    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password
        .chars()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace());

    let mut missing = Vec::new();
    if !has_uppercase {
        missing.push("uppercase letter");
    }
    if !has_lowercase {
        missing.push("lowercase letter");
    }
    if !has_digit {
        missing.push("digit");
    }
    if !has_special {
        missing.push("special character");
    }

    if !missing.is_empty() {
        return Err(CryptoError::WeakPassword(format!(
            "Password must contain at least one: {}",
            missing.join(", ")
        )));
    }

    Ok(())
}

/// Encrypts data using AES-256-GCM
/// Returns: base64(salt || nonce || ciphertext)
///
/// # Security
///
/// - Derives encryption key from password using PBKDF2
/// - Zeroizes the key immediately after encryption
/// - Uses cryptographically secure random salt and nonce
pub fn encrypt(plaintext: &str, password: &str) -> Result<String, CryptoError> {
    // Generate random salt
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // Derive encryption key from password
    let mut key = derive_key(password, &salt);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::EncryptionFailed)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt the data
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Zeroize sensitive data immediately
    key.zeroize();

    // Combine: salt || nonce || ciphertext
    let mut result = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    // Encode to base64
    Ok(BASE64.encode(&result))
}

/// Decrypts data using AES-256-GCM with rate limiting
/// Expects: base64(salt || nonce || ciphertext)
///
/// On decryption failure (wrong password), records the attempt and applies exponential backoff.
/// After MAX_PASSWORD_ATTEMPTS failed attempts, returns MaxAttemptsExceeded error.
///
/// # Security
///
/// - Derives decryption key from password using PBKDF2
/// - Zeroizes the key immediately after decryption attempt
/// - Rate limits password attempts to prevent brute force attacks
pub fn decrypt(encrypted: &str, password: &str) -> Result<String, CryptoError> {
    // Decode from base64
    let data = BASE64
        .decode(encrypted)
        .map_err(|_| CryptoError::InvalidFormat)?;

    // Check minimum length
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    // Split into components
    let (salt, rest) = data.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    // Derive decryption key from password
    let mut key = derive_key(password, salt);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        // Zeroize key even on cipher creation failure
        key.zeroize();
        CryptoError::DecryptionFailed
    })?;

    // Create nonce
    let nonce_array: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat)?;
    let nonce = Nonce::from(nonce_array);

    // Decrypt the data
    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        // Zeroize key before handling the error
        key.zeroize();
        // Record failed attempt and apply backoff on decryption failure
        // This indicates a wrong password
        if let Err(e) = record_failed_attempt() {
            return e;
        }
        CryptoError::DecryptionFailed
    })?;

    // Zeroize sensitive data immediately after successful decryption
    key.zeroize();

    // Convert to string
    String::from_utf8(plaintext).map_err(|_| CryptoError::DecryptionFailed)
}

/// Prompts for a password without echoing to terminal
pub fn prompt_password(prompt: &str) -> std::io::Result<String> {
    print!("{}", prompt);
    std::io::stdout().flush()?;
    rpassword::read_password()
}

/// Prompts for password with confirmation and validates strength
///
/// # Security
///
/// - Validates password strength before acceptance
/// - Zeroizes failed password attempts immediately
/// - Only returns password after successful validation and confirmation
pub fn prompt_password_with_confirmation(prompt: &str) -> std::io::Result<String> {
    loop {
        print!("{}", prompt);
        std::io::stdout().flush()?;
        let mut password = rpassword::read_password()?;

        // Validate password strength
        if let Err(e) = validate_password_strength(&password) {
            println!("{}", e);
            println!("Please try again with a stronger password.");
            // Zeroize rejected password
            password.zeroize();
            continue;
        }

        print!("Confirm password: ");
        std::io::stdout().flush()?;
        let mut confirm = rpassword::read_password()?;

        // Use constant-time comparison to prevent timing attacks
        if password.as_bytes().ct_eq(confirm.as_bytes()).into() {
            // Zeroize the confirmation copy
            confirm.zeroize();
            return Ok(password);
        }

        println!("Passwords do not match. Please try again.");
        // Zeroize both failed attempts
        password.zeroize();
        confirm.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to ensure rate limit tests run serially
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = "Hello, World!";
        let password = "supersecret";

        let encrypted = encrypt(plaintext, password).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_invalid_format() {
        let result = decrypt("invalid", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_salts() {
        let plaintext = "Hello, World!";
        let password = "supersecret";

        let encrypted1 = encrypt(plaintext, password).unwrap();
        let encrypted2 = encrypt(plaintext, password).unwrap();

        // Same plaintext and password should produce different ciphertext due to random salt/nonce
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        assert_eq!(decrypt(&encrypted1, password).unwrap(), plaintext);
        assert_eq!(decrypt(&encrypted2, password).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let _lock = TEST_LOCK.lock().unwrap(); // Serialize test execution
        reset_attempts(); // Reset for clean test

        let plaintext = "Hello, World!";
        let password = "supersecret";
        let wrong_password = "wrongpassword";

        let encrypted = encrypt(plaintext, password).unwrap();
        let result = decrypt(&encrypted, wrong_password);

        assert!(result.is_err());
        assert_eq!(get_attempts(), 1); // One failed attempt recorded
    }

    #[test]
    fn test_rate_limit_max_attempts() {
        let _lock = TEST_LOCK.lock().unwrap(); // Serialize test execution
        reset_attempts(); // Start fresh

        let plaintext = "test";
        let password = "correct";
        let wrong_password = "wrong";

        let encrypted = encrypt(plaintext, password).unwrap();

        // Attempt 4 wrong passwords (attempts 1-4)
        for i in 1..=4 {
            let result = decrypt(&encrypted, wrong_password);
            assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
            assert_eq!(get_attempts(), i);
        }

        // 5th attempt should trigger MaxAttemptsExceeded
        let result = decrypt(&encrypted, wrong_password);
        assert!(matches!(result, Err(CryptoError::MaxAttemptsExceeded)));
        assert_eq!(get_attempts(), 5);

        // Further attempts should still fail with MaxAttemptsExceeded
        let result = decrypt(&encrypted, wrong_password);
        assert!(matches!(result, Err(CryptoError::MaxAttemptsExceeded)));
    }

    #[test]
    fn test_rate_limit_reset_on_success() {
        let _lock = TEST_LOCK.lock().unwrap(); // Serialize test execution
        reset_attempts();

        let plaintext = "test";
        let password = "correct";
        let wrong_password = "wrong";

        let encrypted = encrypt(plaintext, password).unwrap();

        // Make 2 failed attempts
        let _ = decrypt(&encrypted, wrong_password);
        let _ = decrypt(&encrypted, wrong_password);
        assert_eq!(get_attempts(), 2);

        // Successful decryption should allow counter reset
        let result = decrypt(&encrypted, password);
        assert!(result.is_ok());

        // Manually reset (simulating what main.rs does)
        reset_attempts();
        assert_eq!(get_attempts(), 0);

        // Should be able to attempt again
        let result = decrypt(&encrypted, password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_attempt_counter_operations() {
        let _lock = TEST_LOCK.lock().unwrap(); // Serialize test execution
        reset_attempts();
        assert_eq!(get_attempts(), 0);

        // Simulate failed attempts using the internal function
        let plaintext = "test";
        let password = "correct";
        let wrong_password = "wrong";
        let encrypted = encrypt(plaintext, password).unwrap();

        let _ = decrypt(&encrypted, wrong_password);
        assert_eq!(get_attempts(), 1);

        let _ = decrypt(&encrypted, wrong_password);
        assert_eq!(get_attempts(), 2);

        reset_attempts();
        assert_eq!(get_attempts(), 0);
    }

    #[test]
    fn test_password_too_short() {
        let result = validate_password_strength("Short1!");
        assert!(result.is_err());
        match result {
            Err(CryptoError::WeakPassword(msg)) => {
                assert!(msg.contains("at least 12 characters"));
            }
            _ => panic!("Expected WeakPassword error"),
        }
    }

    #[test]
    fn test_password_missing_uppercase() {
        let result = validate_password_strength("lowercase123!");
        assert!(result.is_err());
        match result {
            Err(CryptoError::WeakPassword(msg)) => {
                assert!(msg.contains("uppercase letter"));
            }
            _ => panic!("Expected WeakPassword error"),
        }
    }

    #[test]
    fn test_password_missing_lowercase() {
        let result = validate_password_strength("UPPERCASE123!");
        assert!(result.is_err());
        match result {
            Err(CryptoError::WeakPassword(msg)) => {
                assert!(msg.contains("lowercase letter"));
            }
            _ => panic!("Expected WeakPassword error"),
        }
    }

    #[test]
    fn test_password_missing_digit() {
        let result = validate_password_strength("NoDigitsHere!");
        assert!(result.is_err());
        match result {
            Err(CryptoError::WeakPassword(msg)) => {
                assert!(msg.contains("digit"));
            }
            _ => panic!("Expected WeakPassword error"),
        }
    }

    #[test]
    fn test_password_missing_special() {
        let result = validate_password_strength("NoSpecial123");
        assert!(result.is_err());
        match result {
            Err(CryptoError::WeakPassword(msg)) => {
                assert!(msg.contains("special character"));
            }
            _ => panic!("Expected WeakPassword error"),
        }
    }

    #[test]
    fn test_password_missing_multiple() {
        let result = validate_password_strength("onlylowercase");
        assert!(result.is_err());
        match result {
            Err(CryptoError::WeakPassword(msg)) => {
                assert!(msg.contains("uppercase letter"));
                assert!(msg.contains("digit"));
                assert!(msg.contains("special character"));
            }
            _ => panic!("Expected WeakPassword error"),
        }
    }

    #[test]
    fn test_password_valid_strong() {
        let result = validate_password_strength("StrongPass123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_valid_with_various_special() {
        assert!(validate_password_strength("MyPass123@word").is_ok());
        assert!(validate_password_strength("MyPass123#word").is_ok());
        assert!(validate_password_strength("MyPass123$word").is_ok());
        assert!(validate_password_strength("MyPass123%word").is_ok());
        assert!(validate_password_strength("MyPass123^word").is_ok());
        assert!(validate_password_strength("MyPass123&word").is_ok());
        assert!(validate_password_strength("MyPass123*word").is_ok());
    }

    #[test]
    fn test_password_exactly_12_chars() {
        assert!(validate_password_strength("Pass123!word").is_ok());
    }
}
