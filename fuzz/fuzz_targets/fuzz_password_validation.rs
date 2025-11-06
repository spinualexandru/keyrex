#![no_main]

use libfuzzer_sys::fuzz_target;
use keyrex::crypto::validate_password_strength;

fuzz_target!(|data: &[u8]| {
    // Fuzzing password validation with arbitrary input
    // This helps find edge cases and crashes in password validation logic

    // Convert bytes to string
    let password = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return, // Invalid UTF-8, skip
    };

    // Try to validate the password
    // This should never panic, regardless of input
    let result = validate_password_strength(password);

    // Verify result consistency
    match result {
        Ok(_) => {
            // If validation passed, password should meet minimum requirements
            // At minimum: >= 12 characters
            assert!(
                password.len() >= 12,
                "Password shorter than 12 chars should not pass validation"
            );
        }
        Err(_) => {
            // Validation failed - this is expected for most random inputs
        }
    }

    // Try multiple times with same password (should give consistent results)
    let result2 = validate_password_strength(password);
    assert_eq!(
        result.is_ok(),
        result2.is_ok(),
        "Validation should be deterministic"
    );
});
