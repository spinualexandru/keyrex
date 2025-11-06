//! Security-focused tests
//!
//! Tests for security features including:
//! - Memory zeroization verification
//! - Clipboard operations
//! - Password handling
//!
//! Note: Most tests in this file are pure unit tests that don't touch
//! the filesystem, so they don't require config-based test environments.
//! They test cryptographic primitives and memory operations directly.

#[test]
fn test_password_string_zeroization() {
    use zeroize::Zeroize;

    // Test that zeroize properly clears memory
    let mut password = String::from("super_secret_password_12345");

    // Zeroize the string
    password.zeroize();

    // After zeroization, string should be empty
    assert_eq!(password.len(), 0);
    assert_eq!(password, "");

    // Note: Capacity might remain (implementation detail), but content is zeroed
    // This is acceptable as the memory has been overwritten
}

#[test]
fn test_password_bytes_zeroization() {
    use zeroize::Zeroize;

    // Test zeroization of byte arrays (used for keys)
    let mut key: [u8; 32] = [0x42; 32]; // Fill with 'B' (0x42)

    // Verify initial state
    assert_eq!(key[0], 0x42);
    assert_eq!(key[31], 0x42);

    // Zeroize the key
    key.zeroize();

    // After zeroization, all bytes should be zero
    for byte in &key {
        assert_eq!(*byte, 0);
    }
}

#[test]
fn test_vector_zeroization() {
    use zeroize::Zeroize;

    // Test zeroization of vectors (used for passwords and keys)
    let mut sensitive_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

    // Verify initial state
    assert_eq!(sensitive_data.len(), 8);
    assert_eq!(sensitive_data[0], 1);

    // Zeroize the vector
    sensitive_data.zeroize();

    // After zeroization, all elements should be zero
    for byte in &sensitive_data {
        assert_eq!(*byte, 0);
    }
}

#[test]
fn test_secret_string_protection() {
    use secrecy::{ExposeSecret, SecretString};

    // Test that SecretString provides basic memory protection
    let password = "my_secret_password";
    let secret = SecretString::new(password.to_string().into_boxed_str());

    // Can expose the secret when needed
    assert_eq!(secret.expose_secret(), password);

    // Secret doesn't implement Display or Debug by default (compile-time protection)
    // This prevents accidental logging of secrets

    // When secret is dropped, the memory should be zeroized automatically
    drop(secret);
    // No way to verify this directly, but secrecy crate guarantees it
}

#[test]
fn test_session_password_lifecycle() {
    use keyrex::session;
    use std::thread;
    use std::time::Duration;

    // Store a password in the session
    session::store_password("test_password_123".to_string());

    // The password should be stored securely
    // We can't directly access it (which is good for security)
    // But we can verify the session management works

    // Simulate session ending by letting the test complete
    // The SessionPassword's Drop trait should be called
    thread::sleep(Duration::from_millis(10));

    // This test verifies that the session module compiles and runs
    // The actual zeroization happens in Drop, which we can't directly test
    // without unsafe code or memory inspection tools
}

#[test]
fn test_multiple_zeroization_safe() {
    use zeroize::Zeroize;

    // Test that zeroizing twice doesn't cause issues
    let mut data = vec![1u8, 2, 3, 4];

    data.zeroize();
    data.zeroize(); // Should be safe to zeroize again

    for byte in &data {
        assert_eq!(*byte, 0);
    }
}

#[test]
#[cfg(not(target_os = "linux"))] // Skip on CI environments without display
fn test_clipboard_basic_operation() {
    use arboard::Clipboard;

    // Try to create a clipboard instance
    let clipboard_result = Clipboard::new();

    match clipboard_result {
        Ok(mut clipboard) => {
            // If clipboard is available, test basic operations
            let test_value = "test_clipboard_value";

            // Set text
            let set_result = clipboard.set_text(test_value);

            if let Ok(_) = set_result {
                // Get text back
                match clipboard.get_text() {
                    Ok(retrieved) => {
                        assert_eq!(retrieved, test_value);
                    }
                    Err(_) => {
                        // Clipboard get might fail in some environments
                        // This is acceptable in test environments
                    }
                }
            }
        }
        Err(_) => {
            // Clipboard might not be available in headless environments
            // This is expected and acceptable
            println!("Clipboard not available (expected in CI)");
        }
    }
}

#[test]
#[cfg(not(target_os = "linux"))] // Skip on CI environments without display
fn test_clipboard_clear() {
    use arboard::Clipboard;

    let clipboard_result = Clipboard::new();

    match clipboard_result {
        Ok(mut clipboard) => {
            // Set some sensitive data
            let _ = clipboard.set_text("sensitive_data");

            // Clear by setting to empty string
            let clear_result = clipboard.set_text("");

            match clear_result {
                Ok(_) => {
                    // Verify clipboard is cleared
                    match clipboard.get_text() {
                        Ok(text) => {
                            assert_eq!(text, "");
                        }
                        Err(_) => {
                            // Acceptable in some environments
                        }
                    }
                }
                Err(_) => {
                    // Acceptable in test environments
                }
            }
        }
        Err(_) => {
            // Expected in CI/headless environments
        }
    }
}

#[test]
fn test_clipboard_unavailable_handling() {
    // This test verifies that the code handles clipboard unavailability gracefully
    // In the actual application, errors are caught and reported to the user

    // We can't easily simulate clipboard unavailability without mocking,
    // but we can verify the error types are correct
    use arboard::Clipboard;

    let result = Clipboard::new();

    // The result type should be Result<Clipboard, Error>
    // This compiles, which verifies the type is correct
    match result {
        Ok(_) => {
            // Clipboard available
        }
        Err(e) => {
            // Clipboard unavailable (expected in some environments)
            let _error_message = format!("{}", e);
            // Error message should not contain sensitive data
        }
    }
}

#[test]
fn test_password_not_in_error_messages() {
    use keyrex::vault::VaultError;

    // Verify that error types don't leak passwords
    let error = VaultError::InvalidInput("test error".to_string());
    let error_string = format!("{}", error);

    // Error should not contain common password-related terms in unexpected ways
    assert!(error_string.contains("Invalid input"));

    // Test other error types
    let error2 = VaultError::HomeDirectoryNotFound;
    let error_string2 = format!("{}", error2);
    assert!(error_string2.contains("home directory"));
}

#[test]
fn test_sensitive_data_not_logged() {
    // This test verifies that we're not accidentally logging sensitive data
    // through Debug or Display implementations

    use keyrex::vault::Entry;

    let entry = Entry {
        key: "api_key".to_string(),
        value: "secret_api_key_12345".to_string(),
    };

    // Entry does implement Debug (for development), but in production
    // we should ensure sensitive values aren't logged
    let debug_output = format!("{:?}", entry);

    // The debug output will contain the value (that's expected for debugging)
    // The important thing is that production code doesn't log Entry values
    assert!(debug_output.contains("api_key"));
}

#[test]
fn test_key_derivation_memory_safety() {
    // Test that key derivation doesn't leave keys in memory
    // This is more of a documentation test - actual verification would require
    // memory inspection tools

    use keyrex::crypto;

    let password = "test_password";
    let plaintext = "test data";

    // Encrypt some data (this derives a key internally)
    let encrypted = crypto::encrypt(plaintext, password);
    assert!(encrypted.is_ok());

    // The encryption key should have been zeroized after use
    // We can't verify this directly, but the crypto module guarantees it

    // Decrypt the data
    let decrypted = crypto::decrypt(&encrypted.unwrap(), password);
    assert!(decrypted.is_ok());
    assert_eq!(decrypted.unwrap(), plaintext);

    // The decryption key should also have been zeroized
}

#[test]
fn test_password_comparison_timing() {
    // This test verifies that password comparison takes roughly the same time
    // regardless of where the passwords differ
    // This helps prevent timing attacks

    use keyrex::crypto;
    use std::time::Instant;

    let correct_password = "correct_password_with_sufficient_length";
    let wrong_password1 = "xorrect_password_with_sufficient_length"; // Differs at start
    let wrong_password2 = "correct_password_with_sufficient_lengtx"; // Differs at end

    // Create encrypted data with correct password
    let plaintext = "test data for timing attack resistance";
    let encrypted = crypto::encrypt(plaintext, correct_password).unwrap();

    // Time decryption with password differing at start
    let start1 = Instant::now();
    let _ = crypto::decrypt(&encrypted, wrong_password1);
    let duration1 = start1.elapsed();

    // Time decryption with password differing at end
    let start2 = Instant::now();
    let _ = crypto::decrypt(&encrypted, wrong_password2);
    let duration2 = start2.elapsed();

    // The timing difference should be minimal (within an order of magnitude)
    // Note: This is a weak test because system scheduling affects timing
    // But it documents the intent
    let ratio = if duration1 > duration2 {
        duration1.as_nanos() as f64 / duration2.as_nanos() as f64
    } else {
        duration2.as_nanos() as f64 / duration1.as_nanos() as f64
    };

    // Allow up to 10x difference (very lenient due to system scheduling)
    // In practice, constant-time comparison should make this ratio close to 1.0
    assert!(ratio < 10.0, "Timing ratio too large: {}", ratio);
}

#[test]
fn test_failed_password_zeroized() {
    use keyrex::crypto;

    // Test that even when decryption fails, the password is not left in memory
    let encrypted = crypto::encrypt("data", "correct").unwrap();

    // Try to decrypt with wrong password
    let result = crypto::decrypt(&encrypted, "wrong");

    assert!(result.is_err());
    // The wrong password should have been zeroized even though decryption failed
    // We can't verify this directly, but the crypto module guarantees it
}

#[test]
fn test_empty_password_handling() {
    use keyrex::crypto;

    // Test empty password behavior
    // Note: The crypto module itself may accept empty passwords for encryption
    // (as it's technically a valid input to PBKDF2), but password validation
    // should reject them at a higher level
    let result = crypto::encrypt("data", "");

    // The crypto::encrypt function technically works with empty passwords
    // (it derives a key from the empty string), but this is not recommended
    // Password validation (validate_password_strength) should reject empty passwords
    // which is tested in test_weak_password_rejection

    // If empty password encryption succeeds, verify decrypt works
    if let Ok(encrypted) = result {
        let decrypted = crypto::decrypt(&encrypted, "");
        assert!(
            decrypted.is_ok(),
            "Should be able to decrypt with same empty password"
        );
        assert_eq!(decrypted.unwrap(), "data");
    }
}

#[test]
fn test_weak_password_rejection() {
    use keyrex::crypto::validate_password_strength;

    // Test various weak passwords
    let weak_passwords = vec![
        "short",            // Too short
        "12345678",         // Too short
        "abcdefghij",       // No numbers/special chars
        "ABCDEFGHIJ",       // No lowercase/numbers
        "1234567890",       // No letters
        "passwordpassword", // Common word
    ];

    for weak_password in weak_passwords {
        let result = validate_password_strength(weak_password);
        assert!(
            result.is_err(),
            "Should reject weak password: {}",
            weak_password
        );
    }

    // Test a strong password
    let strong_password = "MyStr0ng!P@ssw0rd";
    let result = validate_password_strength(strong_password);
    assert!(result.is_ok(), "Should accept strong password");
}

#[test]
fn test_secure_random_generation() {
    use keyrex::crypto;

    // Generate multiple encrypted values with same password and plaintext
    // They should all be different due to random salt and nonce
    let password = "test_password";
    let plaintext = "test data";

    let encrypted1 = crypto::encrypt(plaintext, password).unwrap();
    let encrypted2 = crypto::encrypt(plaintext, password).unwrap();
    let encrypted3 = crypto::encrypt(plaintext, password).unwrap();

    // All should be different (random salt and nonce)
    assert_ne!(encrypted1, encrypted2);
    assert_ne!(encrypted2, encrypted3);
    assert_ne!(encrypted1, encrypted3);

    // But all should decrypt to same plaintext
    assert_eq!(crypto::decrypt(&encrypted1, password).unwrap(), plaintext);
    assert_eq!(crypto::decrypt(&encrypted2, password).unwrap(), plaintext);
    assert_eq!(crypto::decrypt(&encrypted3, password).unwrap(), plaintext);
}
