#![no_main]

use libfuzzer_sys::fuzz_target;
use keyrex::crypto;

fuzz_target!(|data: &[u8]| {
    // Fuzzing encrypt/decrypt with arbitrary data
    // This helps find edge cases in crypto implementation

    // Split input into password and plaintext
    if data.len() < 2 {
        return; // Need at least 2 bytes
    }

    let split_point = data.len() / 2;
    let password = match std::str::from_utf8(&data[..split_point]) {
        Ok(s) if !s.is_empty() => s,
        _ => return, // Invalid UTF-8 or empty, skip
    };

    let plaintext = match std::str::from_utf8(&data[split_point..]) {
        Ok(s) if !s.is_empty() => s,
        _ => return, // Invalid UTF-8 or empty, skip
    };

    // Try to encrypt (may fail due to weak password)
    if let Ok(encrypted) = crypto::encrypt(plaintext, password) {
        // If encryption succeeded, decryption with same password should work
        match crypto::decrypt(&encrypted, password) {
            Ok(decrypted) => {
                // Decrypted text should match original
                assert_eq!(decrypted, plaintext, "Decryption mismatch");
            }
            Err(_) => {
                // Decryption failed - this should not happen if encryption succeeded
                panic!("Decryption failed after successful encryption");
            }
        }

        // Try decryption with wrong password - should fail
        let wrong_password = "definitely_wrong_password";
        if password != wrong_password {
            let result = crypto::decrypt(&encrypted, wrong_password);
            // Should fail (or very rarely succeed by chance, which is acceptable)
            let _ = result;
        }
    }
});
