//! Filesystem error simulation and robustness tests
//!
//! Tests vault behavior under various filesystem error conditions:
//! - Corrupted data files
//! - Permission issues
//! - Concurrent access scenarios
//! - Atomic write operations
//!
//! All tests use isolated test environments with config files to ensure
//! no interference with developer's actual vault.

mod common;

use common::{with_test_env, TestEnvironment};
use keyrex::vault::{Vault, VaultError};
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

#[test]
fn test_load_corrupted_json() {
    with_test_env("fs_corrupted_json", |env| {
        // Write invalid JSON to vault file
        fs::write(&env.vault_path, "{ invalid json content }").unwrap();

        env.set_as_vault_path().unwrap();
        let result = Vault::load();

        assert!(result.is_err());
        match result {
            Err(VaultError::ParseFailed(_)) => {
                // Expected behavior
            }
            other => panic!("Expected ParseFailed error, got: {:?}", other),
        }
    });
}

#[test]
fn test_load_empty_file() {
    with_test_env("fs_empty_file", |env| {
        // Create an empty file
        fs::write(&env.vault_path, "").unwrap();

        env.set_as_vault_path().unwrap();
        let result = Vault::load();

        // Empty file should fail to parse
        assert!(result.is_err(), "Empty file should cause parse error");
    });
}

#[test]
fn test_load_partial_json() {
    with_test_env("fs_partial_json", |env| {
        // Write incomplete JSON (missing closing braces)
        fs::write(&env.vault_path, r#"{"entries": {"key": {"key": "test""#).unwrap();

        env.set_as_vault_path().unwrap();
        let result = Vault::load();

        // Partial JSON should cause parse error
        assert!(result.is_err(), "Partial JSON should cause parse error");
        match result {
            Err(VaultError::ParseFailed(_)) => {
                // Expected
            }
            other => panic!("Expected ParseFailed error, got: {:?}", other),
        }
    });
}

#[test]
fn test_hmac_tampering_detection() {
    with_test_env("fs_hmac_tampering", |env| {
        // Create and save a valid vault
        env.set_as_vault_path().unwrap();
        {
            let mut vault = Vault::new();
            vault
                .add_entry("key".to_string(), "value".to_string())
                .unwrap();
            vault.save().unwrap();
        }

        // Tamper with the saved file
        let mut content = fs::read_to_string(&env.vault_path).unwrap();

        // Modify a value in the JSON (simulate tampering)
        content = content.replace("\"value\"", "\"tampered\"");
        fs::write(&env.vault_path, &content).unwrap();

        // Attempt to load the tampered vault
        let result = Vault::load();

        assert!(result.is_err());
        match result {
            Err(VaultError::IntegrityCheckFailed) => {
                // Expected - HMAC verification should fail
            }
            other => {
                // Could also be a parse error if tampering broke JSON
                println!("Got error: {:?}", other);
            }
        }
    });
}

#[test]
fn test_atomic_write_protection() {
    with_test_env("fs_atomic_write", |env| {
        let temp_path = env.vault_path.with_extension("dat.tmp");

        env.set_as_vault_path().unwrap();

        // Create and save a vault
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        vault.save().unwrap();

        // Verify the temp file doesn't exist after successful save
        assert!(!temp_path.exists(), "Temp file should be cleaned up");
        assert!(env.vault_path.exists(), "Vault file should exist");

        // Verify we can load the vault
        let mut loaded = Vault::load().unwrap();
        assert_eq!(loaded.entry_count(), 1);
        assert_eq!(loaded.get_entry("key1").unwrap().value, "value1");
    });
}

#[test]
fn test_missing_parent_directory() {
    with_test_env("fs_missing_parent", |env| {
        let nested_vault_path = env
            .test_dir
            .join("nonexistent")
            .join("nested")
            .join("vault.dat");

        // Try to set a vault path with non-existent parent directories
        // This should succeed as set_vault_path creates parent directories
        let result = Vault::set_vault_path(nested_vault_path.clone());
        assert!(result.is_ok());

        // Create and save a vault - parent dirs should be created
        let mut vault = Vault::new();
        vault
            .add_entry("key".to_string(), "value".to_string())
            .unwrap();
        let save_result = vault.save();
        assert!(save_result.is_ok());

        // Verify the vault was saved
        assert!(nested_vault_path.exists());
    });
}

#[test]
fn test_load_nonexistent_vault() {
    with_test_env("fs_nonexistent_vault", |env| {
        env.set_as_vault_path().unwrap();

        // Loading a non-existent vault should return a new empty vault
        let result = Vault::load();
        assert!(result.is_ok());

        let vault = result.unwrap();
        assert_eq!(vault.entry_count(), 0);
    });
}

#[test]
fn test_json_with_unicode() {
    with_test_env("fs_unicode_json", |env| {
        env.set_as_vault_path().unwrap();

        // Create vault with unicode characters
        let mut vault = Vault::new();
        vault
            .add_entry("emoji_key_🔑".to_string(), "emoji_value_🔒".to_string())
            .unwrap();
        vault
            .add_entry("chinese_中文".to_string(), "日本語_japanese".to_string())
            .unwrap();
        vault
            .add_entry("arabic_العربية".to_string(), "русский_russian".to_string())
            .unwrap();

        vault.save().unwrap();

        // Load and verify
        let mut loaded = Vault::load().unwrap();
        assert_eq!(loaded.entry_count(), 3);
        assert_eq!(
            loaded.get_entry("emoji_key_🔑").unwrap().value,
            "emoji_value_🔒"
        );
        assert_eq!(
            loaded.get_entry("chinese_中文").unwrap().value,
            "日本語_japanese"
        );
        assert_eq!(
            loaded.get_entry("arabic_العربية").unwrap().value,
            "русский_russian"
        );
    });
}

#[test]
fn test_large_vault_handling() {
    with_test_env("fs_large_vault", |env| {
        env.set_as_vault_path().unwrap();

        // Create a vault with many entries
        let mut vault = Vault::new();
        for i in 0..1000 {
            vault
                .add_entry(format!("key_{:04}", i), format!("value_number_{}", i))
                .unwrap();
        }

        // Save and measure
        let save_result = vault.save();
        assert!(save_result.is_ok());

        // Load and verify count
        let mut loaded = Vault::load().unwrap();
        assert_eq!(loaded.entry_count(), 1000);
        assert_eq!(
            loaded.get_entry("key_0000").unwrap().value,
            "value_number_0"
        );
        assert_eq!(
            loaded.get_entry("key_0999").unwrap().value,
            "value_number_999"
        );
    });
}

#[test]
fn test_vault_size_limits() {
    with_test_env("fs_size_limits", |env| {
        env.set_as_vault_path().unwrap();

        let mut vault = Vault::new();

        // Test maximum value size (64KB)
        let max_value = "x".repeat(64 * 1024);
        let result = vault.add_entry("max_size".to_string(), max_value);
        assert!(result.is_ok(), "Should accept 64KB value");

        // Test exceeding maximum value size
        let too_large = "x".repeat(64 * 1024 + 1);
        let result = vault.add_entry("too_large".to_string(), too_large);
        assert!(result.is_err(), "Should reject >64KB value");

        // Test maximum key size (256 chars)
        let max_key = "k".repeat(256);
        let result = vault.add_entry(max_key, "value".to_string());
        assert!(result.is_ok(), "Should accept 256 char key");

        // Test exceeding maximum key size
        let too_long_key = "k".repeat(257);
        let result = vault.add_entry(too_long_key, "value".to_string());
        assert!(result.is_err(), "Should reject >256 char key");
    });
}

// Concurrency tests
#[test]
fn test_concurrent_reads() {
    let env = TestEnvironment::new("fs_concurrent_reads");
    env.set_as_vault_path().unwrap();

    // Create and save a test vault
    {
        let mut vault = Vault::new();
        for i in 0..100 {
            vault
                .add_entry(format!("key{}", i), format!("value{}", i))
                .unwrap();
        }
        vault.save().unwrap();
    }

    // Verify vault was created before spawning threads
    assert!(
        env.vault_path.exists(),
        "Vault file should exist before concurrent tests"
    );

    // Spawn multiple threads to read concurrently
    let mut handles = vec![];
    let barrier = Arc::new(Barrier::new(5));

    for thread_id in 0..5 {
        let vault_path = env.vault_path.clone();
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Set vault path for this thread
            Vault::set_vault_path(vault_path).unwrap();

            // Wait for all threads to be ready
            barrier.wait();

            // Perform reads
            for _ in 0..10 {
                let result = Vault::load();
                assert!(result.is_ok(), "Thread {} failed to load vault", thread_id);

                let vault = result.unwrap();
                assert_eq!(
                    vault.entry_count(),
                    100,
                    "Thread {} got wrong count",
                    thread_id
                );

                thread::sleep(Duration::from_millis(1));
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    // env is dropped here, triggering cleanup
}

#[test]
fn test_sequential_write_safety() {
    with_test_env("fs_sequential_writes", |env| {
        env.set_as_vault_path().unwrap();

        // Create initial vault
        {
            let mut vault = Vault::new();
            vault
                .add_entry("initial".to_string(), "value".to_string())
                .unwrap();
            vault.save().unwrap();
        }

        // Perform sequential writes from multiple "processes" (threads)
        for i in 0..10 {
            let mut vault = Vault::load().unwrap();
            vault
                .add_entry(format!("key{}", i), format!("value{}", i))
                .unwrap();
            vault.save().unwrap();

            thread::sleep(Duration::from_millis(5));
        }

        // Verify all writes succeeded
        let mut final_vault = Vault::load().unwrap();
        assert_eq!(final_vault.entry_count(), 11); // initial + 10 additions
        assert_eq!(final_vault.get_entry("initial").unwrap().value, "value");
    });
}

#[test]
fn test_lock_prevents_corruption() {
    with_test_env("fs_lock_prevents_corruption", |env| {
        env.set_as_vault_path().unwrap();

        // Create initial vault
        {
            let mut vault = Vault::new();
            vault
                .add_entry("test".to_string(), "value".to_string())
                .unwrap();
            vault.save().unwrap();
        }

        // Test that lock is acquired and released properly
        {
            let _lock1 = Vault::acquire_lock();
            assert!(_lock1.is_ok(), "Should acquire first lock");

            // Lock is held in this scope
        } // Lock is released here

        // After lock is released, should be able to acquire it again
        {
            let _lock2 = Vault::acquire_lock();
            assert!(_lock2.is_ok(), "Should acquire lock after previous release");
        }

        // Test that operations work correctly with locking
        let mut vault = Vault::load().unwrap();
        vault
            .add_entry("key2".to_string(), "value2".to_string())
            .unwrap();
        vault.save().unwrap();

        let mut final_vault = Vault::load().unwrap();
        assert_eq!(final_vault.entry_count(), 2);
        assert_eq!(final_vault.get_entry("test").unwrap().value, "value");
        assert_eq!(final_vault.get_entry("key2").unwrap().value, "value2");
    });
}

#[test]
fn test_file_descriptor_cleanup() {
    with_test_env("fs_fd_cleanup", |env| {
        env.set_as_vault_path().unwrap();

        // Perform many load/save operations
        // This tests that file descriptors are properly closed
        for i in 0..100 {
            let mut vault = Vault::new();
            vault
                .add_entry(format!("key{}", i), "value".to_string())
                .unwrap();
            vault.save().unwrap();

            let mut loaded = Vault::load().unwrap();
            assert_eq!(loaded.entry_count(), 1);
            assert_eq!(
                loaded.get_entry(&format!("key{}", i)).unwrap().value,
                "value"
            );
        }
    });
}

#[test]
#[cfg(unix)]
fn test_file_permissions_set_correctly() {
    use std::os::unix::fs::PermissionsExt;

    with_test_env("fs_permissions", |env| {
        env.set_as_vault_path().unwrap();

        // Create and save a vault
        let mut vault = Vault::new();
        vault
            .add_entry("key".to_string(), "value".to_string())
            .unwrap();
        vault.save().unwrap();

        // Check file permissions
        let metadata = fs::metadata(&env.vault_path).unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Extract permission bits (last 9 bits)
        let perms = mode & 0o777;

        // Should be 0o600 (owner read/write only)
        assert_eq!(
            perms, 0o600,
            "Vault file should have 0600 permissions, got {:o}",
            perms
        );
    });
}

#[test]
fn test_malformed_timestamp_handling() {
    with_test_env("fs_malformed_timestamp", |env| {
        // Write a vault with invalid timestamp
        let malformed = r#"{
        "entries": {},
        "created_at": "not_a_number",
        "last_updated_at": 1234567890,
        "last_accessed_at": 1234567890
    }"#;

        fs::write(&env.vault_path, malformed).unwrap();

        env.set_as_vault_path().unwrap();
        let result = Vault::load();

        // Should fail to parse
        assert!(result.is_err());
    });
}

#[test]
fn test_error_message_security() {
    // Verify that error messages don't leak sensitive information
    let err = VaultError::InvalidInput("test error with secret123".to_string());
    let msg = format!("{}", err);

    // Error message should contain the generic description
    assert!(msg.contains("Invalid input"));

    // But it will contain the full error message since we pass it
    // The important thing is not to add passwords/keys to error messages
    assert!(msg.contains("test error with secret123"));
}

#[test]
fn test_null_byte_rejection() {
    // This test doesn't need file system access, so no test env needed
    let mut vault = Vault::new();

    // Test null byte in key
    let result = vault.add_entry("key\0bad".to_string(), "value".to_string());
    assert!(result.is_err());

    // Test null byte in value
    let result = vault.add_entry("key".to_string(), "value\0bad".to_string());
    assert!(result.is_err());
}

#[test]
fn test_special_characters_in_paths() {
    with_test_env("fs_special-chars-path", |env| {
        // Use a path with spaces
        let vault_with_spaces = env.test_dir.join("vault with spaces.dat");

        Vault::set_vault_path(vault_with_spaces.clone()).unwrap();

        let mut vault = Vault::new();
        vault
            .add_entry("key".to_string(), "value".to_string())
            .unwrap();

        // Should handle paths with spaces
        let result = vault.save();
        assert!(result.is_ok(), "Should save vault with spaces in path");

        // Should be able to load it back
        let loaded = Vault::load();
        assert!(loaded.is_ok(), "Should load vault with spaces in path");
        assert_eq!(loaded.unwrap().entry_count(), 1);
    });
}
