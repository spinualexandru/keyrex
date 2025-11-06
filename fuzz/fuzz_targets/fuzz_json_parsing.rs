#![no_main]

use libfuzzer_sys::fuzz_target;
use keyrex::vault::Vault;

fuzz_target!(|data: &[u8]| {
    // Fuzzing JSON parsing with arbitrary input
    // This helps find edge cases in deserialization and validation

    // Try to parse as UTF-8 string
    let json_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return, // Invalid UTF-8, skip
    };

    // Try to parse as Vault
    // This should never panic, even with malformed JSON
    let result: Result<Vault, _> = serde_json::from_str(json_str);

    match result {
        Ok(mut vault) => {
            // If parsing succeeded, verify basic operations don't panic
            let _ = vault.entry_count();
            let _ = vault.list_entries();

            // Try to access entries
            for entry in vault.list_entries() {
                let _ = vault.get_entry(&entry.key);
            }

            // Verify HMAC checking doesn't panic
            // Note: HMAC verification happens in load(), not during parsing
            // But we can trigger it by trying vault operations

            // Try to search (should not panic even with weird entries)
            let _ = vault.search_entries("test");

            // Verify timestamps are valid
            let now = chrono::Utc::now();
            // Timestamps should be reasonable (not far in future)
            assert!(
                vault.created_at <= now + chrono::Duration::days(1),
                "Created timestamp too far in future"
            );
        }
        Err(_) => {
            // Parsing failed - this is expected for most random inputs
            // The important thing is that it didn't panic
        }
    }
});
