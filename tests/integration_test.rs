//! Integration tests for KeyRex
//!
//! These tests use isolated test environments with config files to ensure
//! no interference with user's actual vault data.

mod common;

use common::{with_test_env, TestEnvironment};

#[test]
fn test_vault_creation_with_config() {
    with_test_env("vault_creation", |env| {
        // Vault should not exist initially
        assert!(!env.vault_exists(), "Vault should not exist initially");

        // Set vault path for programmatic access
        env.set_as_vault_path().expect("Failed to set vault path");

        // Create a vault by adding an entry
        let mut vault = keyrex::vault::Vault::new();
        vault
            .add_entry("test_key".to_string(), "test_value".to_string())
            .expect("Failed to add entry");

        // Save the vault
        vault.save().expect("Failed to save vault");

        // Now vault should exist
        assert!(env.vault_exists(), "Vault should exist after save");

        // Verify config file is still intact
        assert!(env.config_exists(), "Config should still exist");
    });
}

#[test]
fn test_multiple_tests_dont_interfere() {
    let env1 = TestEnvironment::new("test_isolation_1");
    let env2 = TestEnvironment::new("test_isolation_2");

    // Each test should have its own isolated config and vault
    assert_ne!(env1.config_path, env2.config_path);
    assert_ne!(env1.vault_path, env2.vault_path);

    // Both configs should exist
    assert!(env1.config_exists());
    assert!(env2.config_exists());

    // Create vault in env1
    env1.set_as_vault_path().unwrap();
    let mut vault1 = keyrex::vault::Vault::new();
    vault1
        .add_entry("key1".to_string(), "value1".to_string())
        .unwrap();
    vault1.save().unwrap();
    assert!(env1.vault_exists(), "Vault 1 should exist after save");

    // Create vault in env2 (this will change the global path)
    env2.set_as_vault_path().unwrap();
    let mut vault2 = keyrex::vault::Vault::new();
    vault2
        .add_entry("key2".to_string(), "value2".to_string())
        .unwrap();
    vault2.save().unwrap();
    assert!(env2.vault_exists(), "Vault 2 should exist after save");

    // Verify env1 vault still exists (independent files)
    assert!(
        env1.vault_exists(),
        "Vault 1 should still exist independently"
    );

    // Cleanup happens automatically when env1 and env2 are dropped
}

#[test]
fn test_config_file_contains_correct_path() {
    with_test_env("config_path_check", |env| {
        // Read config file content
        let config_content =
            std::fs::read_to_string(&env.config_path).expect("Failed to read config file");

        // Verify it contains the correct vault path
        assert!(
            config_content.contains("[default]"),
            "Config should have [default] section"
        );
        assert!(
            config_content.contains("path ="),
            "Config should have path setting"
        );

        let vault_path_str = env.vault_str();
        assert!(
            config_content.contains(&vault_path_str) || config_content.contains("vault.dat"),
            "Config should contain vault path"
        );

        // Verify config is in isolated test directory
        assert!(
            env.config_path.to_string_lossy().contains("keyrex_tests"),
            "Config should be in keyrex_tests directory"
        );
    });
}

#[test]
fn test_vault_operations_with_config_isolation() {
    with_test_env("vault_operations", |env| {
        env.set_as_vault_path().unwrap();

        // Create a new vault
        let mut vault = keyrex::vault::Vault::new();

        // Add multiple entries
        vault
            .add_entry("user".to_string(), "admin".to_string())
            .unwrap();
        vault
            .add_entry("password".to_string(), "secret123".to_string())
            .unwrap();
        vault
            .add_entry("api_key".to_string(), "abc-123-xyz".to_string())
            .unwrap();

        // Save vault
        vault.save().unwrap();

        // Load vault from disk to verify persistence
        let mut loaded_vault = keyrex::vault::Vault::load().expect("Failed to load vault");

        // Verify all entries are present
        assert_eq!(loaded_vault.entry_count(), 3);
        assert!(loaded_vault.get_entry("user").is_some());
        assert!(loaded_vault.get_entry("password").is_some());
        assert!(loaded_vault.get_entry("api_key").is_some());

        // Verify values
        assert_eq!(loaded_vault.get_entry("user").unwrap().value, "admin");
        assert_eq!(
            loaded_vault.get_entry("password").unwrap().value,
            "secret123"
        );

        // Verify vault is in isolated location
        assert!(env.vault_exists());
        assert!(env
            .vault_path
            .to_string_lossy()
            .contains("keyrex_tests/vault_operations"));
    });
}

#[test]
fn test_automatic_cleanup_after_test() {
    let vault_path;
    let config_path;

    {
        let env = TestEnvironment::new("cleanup_verification");
        vault_path = env.vault_path.clone();
        config_path = env.config_path.clone();

        // Create a vault
        env.set_as_vault_path().unwrap();
        let mut vault = keyrex::vault::Vault::new();
        vault
            .add_entry("temp".to_string(), "data".to_string())
            .unwrap();
        vault.save().unwrap();

        // Verify files exist
        assert!(vault_path.exists(), "Vault should exist");
        assert!(config_path.exists(), "Config should exist");
    } // env dropped here, triggering cleanup

    // After env is dropped, files should be cleaned up
    assert!(
        !vault_path.exists(),
        "Vault should be cleaned up after test"
    );
    assert!(
        !config_path.exists(),
        "Config should be cleaned up after test"
    );
}
