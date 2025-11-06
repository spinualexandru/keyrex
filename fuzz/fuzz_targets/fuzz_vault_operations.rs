#![no_main]

use libfuzzer_sys::fuzz_target;
use keyrex::vault::Vault;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    // Fuzzing vault operations with arbitrary key-value pairs
    // This helps find edge cases in vault entry handling

    // Set an isolated vault path to prevent polluting developer's vault
    // Use a unique path for this fuzz run
    let mut fuzz_vault_path = std::env::temp_dir();
    fuzz_vault_path.push("keyrex_fuzz");
    fuzz_vault_path.push(format!("vault_ops_{}.dat", std::process::id()));
    let _ = Vault::set_vault_path(fuzz_vault_path);

    if data.len() < 4 {
        return; // Need at least 4 bytes for key and value lengths
    }

    // Parse input as: [key_len (2 bytes)][key][value]
    let key_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if key_len == 0 || key_len + 2 >= data.len() {
        return; // Invalid key length
    }

    let key = match std::str::from_utf8(&data[2..2 + key_len]) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => return, // Invalid UTF-8 or empty
    };

    let value = match std::str::from_utf8(&data[2 + key_len..]) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => return, // Invalid UTF-8 or empty
    };

    // Create a vault and try to add the entry
    let mut vault = Vault::new();

    // Try to add entry - may fail due to validation
    match vault.add_entry(key.clone(), value.clone()) {
        Ok(()) => {
            // If add succeeded, verify we can get it back
            let retrieved = vault.get_entry(&key);
            assert!(retrieved.is_some(), "Entry should exist after adding");
            assert_eq!(retrieved.unwrap().value, value, "Value mismatch");

            // Try to update the entry
            let new_value = format!("{}_updated", value);
            if let Ok(()) = vault.update_entry(&key, new_value.clone()) {
                let updated = vault.get_entry(&key);
                assert_eq!(
                    updated.unwrap().value,
                    new_value,
                    "Updated value mismatch"
                );
            }

            // Try to remove the entry
            let removed = vault.remove_entry(&key);
            assert!(removed.is_some(), "Remove should return the entry");
            assert!(vault.get_entry(&key).is_none(), "Entry should not exist after removal");
        }
        Err(_) => {
            // Add failed due to validation (e.g., too long, null bytes)
            // This is expected and acceptable
        }
    }

    // Try search operation
    let _ = vault.search_entries(&key);

    // Try list operation
    let _ = vault.list_entries();

    // Verify entry count is consistent
    let _ = vault.entry_count();
});
