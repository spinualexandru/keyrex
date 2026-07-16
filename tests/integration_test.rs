//! Integration tests for KeyRex
//!
//! These tests use isolated test environments with config files to ensure
//! no interference with user's actual vault data.

mod common;

use common::{cleanup_temp_test_dir, create_temp_test_dir, with_test_env, TestEnvironment};
use std::fs;
use std::process::Command;

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
fn test_keys_command_lists_plain_vault_keys() {
    with_test_env("keys_command_plain_vault", |env| {
        let mut vault = keyrex::vault::Vault::new();
        vault
            .add_entry("alpha_secret".to_string(), "value".to_string())
            .unwrap();
        vault
            .add_entry("beta_token".to_string(), "value".to_string())
            .unwrap();
        vault
            .add_entry("spaced key".to_string(), "secret_value".to_string())
            .unwrap();
        vault
            .add_entry("unicode_🔑".to_string(), "secret_value".to_string())
            .unwrap();
        vault
            .add_entry("line\nbreak".to_string(), "secret_value".to_string())
            .unwrap();
        vault
            .add_entry("tab\tkey".to_string(), "secret_value".to_string())
            .unwrap();
        fs::write(&env.vault_path, serde_json::to_string(&vault).unwrap()).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_keyrex"))
            .args(["--config", &env.config_str(), "keys"])
            .output()
            .expect("Failed to run keyrex keys");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout.lines().collect::<Vec<_>>(),
            vec!["alpha_secret", "beta_token", "spaced key", "unicode_🔑"]
        );
        assert!(!stdout.contains("secret_value"));
        assert!(!stdout.contains("line"));
        assert!(!stdout.contains("tab"));
        assert!(!stdout.contains("Initialized new vault"));
    });
}

#[test]
fn test_completions_bypass_invalid_vault_configuration() {
    let missing_config = std::env::temp_dir().join("keyrex_missing_completion_config.toml");
    let _ = fs::remove_file(&missing_config);

    let output = Command::new(env!("CARGO_BIN_EXE_keyrex"))
        .args([
            "--config",
            &missing_config.to_string_lossy(),
            "completions",
            "bash",
        ])
        .output()
        .expect("Failed to generate Bash completions");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Generated by KeyRex"));
    assert!(stdout.contains("Dynamic KeyRex key completion"));
    assert!(!missing_config.exists());
}

#[test]
fn test_completion_install_detects_shell_and_is_idempotent() {
    let root = create_temp_test_dir("completion_install_detection");
    let missing_config = root.join("missing-config.toml");
    let target = root.join("fish/completions/keyrex.fish");

    let run_install = || {
        Command::new(env!("CARGO_BIN_EXE_keyrex"))
            .env("SHELL", "/usr/bin/fish")
            .env("XDG_CONFIG_HOME", &root)
            .args([
                "--config",
                &missing_config.to_string_lossy(),
                "completions",
                "install",
            ])
            .output()
            .expect("Failed to install detected Fish completions")
    };

    let first = run_install();
    assert!(first.status.success());
    assert!(target.is_file());
    assert!(String::from_utf8(first.stderr)
        .unwrap()
        .contains("Installed fish completions"));

    let second = run_install();
    assert!(second.status.success());
    assert!(String::from_utf8(second.stderr)
        .unwrap()
        .contains("Updated fish completions"));
    assert!(!missing_config.exists());

    cleanup_temp_test_dir(&root);
}

#[test]
fn test_completion_install_uses_per_shell_user_paths() {
    let root = create_temp_test_dir("completion_install_paths");
    let config_home = root.join("config");
    let data_home = root.join("data");
    let bash_home = root.join("bash-completion");
    let cases = [
        ("bash", bash_home.join("completions/keyrex.bash")),
        ("fish", config_home.join("fish/completions/keyrex.fish")),
        ("zsh", data_home.join("zsh/site-functions/_keyrex")),
        (
            "powershell",
            data_home.join("keyrex/completions/_keyrex.ps1"),
        ),
        ("elvish", config_home.join("elvish/lib/keyrex.elv")),
    ];

    for (shell, target) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_keyrex"))
            .env("XDG_CONFIG_HOME", &config_home)
            .env("XDG_DATA_HOME", &data_home)
            .env("BASH_COMPLETION_USER_DIR", &bash_home)
            .args(["completions", "install", "--shell", shell])
            .output()
            .expect("Failed to install shell completions");

        assert!(output.status.success(), "installation failed for {shell}");
        assert!(target.is_file(), "missing completion file for {shell}");
        assert!(fs::read_to_string(target)
            .unwrap()
            .contains("Generated by KeyRex"));
    }

    cleanup_temp_test_dir(&root);
}

#[test]
fn test_keys_command_is_quiet_for_encrypted_vault() {
    with_test_env("keys_command_encrypted_vault", |env| {
        let mut vault = keyrex::vault::Vault::new();
        vault
            .add_entry("alpha_secret".to_string(), "value".to_string())
            .unwrap();
        let encrypted =
            keyrex::crypto::encrypt(&serde_json::to_string(&vault).unwrap(), "StrongPass123!")
                .unwrap();
        fs::write(&env.vault_path, encrypted).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_keyrex"))
            .args(["--config", &env.config_str(), "keys"])
            .output()
            .expect("Failed to run keyrex keys");

        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
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
