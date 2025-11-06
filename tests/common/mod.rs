//! Common test utilities for KeyRex tests
//!
//! Provides isolated test environments using config files to ensure tests
//! never pollute the developer's actual vault.

use std::fs;
use std::path::{Path, PathBuf};

/// TestEnvironment provides an isolated test setup with its own config and vault
pub struct TestEnvironment {
    /// Root directory for this test (contains config and vault)
    pub test_dir: PathBuf,
    /// Path to the test config file
    pub config_path: PathBuf,
    /// Path to the test vault file
    pub vault_path: PathBuf,
}

impl TestEnvironment {
    /// Create a new isolated test environment
    ///
    /// Creates a directory structure:
    /// ```text
    /// /tmp/keyrex_tests/{test_name}/
    ///   ├── config.toml
    ///   └── vault.dat
    /// ```
    pub fn new(test_name: &str) -> Self {
        let mut test_dir = std::env::temp_dir();
        test_dir.push("keyrex_tests");
        test_dir.push(test_name);

        // Clean up any existing test data
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).expect("Failed to create test directory");

        let config_path = test_dir.join("config.toml");
        let vault_path = test_dir.join("vault.dat");

        // Create the config file pointing to the test vault
        let config_content = format!(
            r#"[default]
path = "{}"
"#,
            vault_path.display()
        );

        fs::write(&config_path, config_content).expect("Failed to write test config");

        Self {
            test_dir,
            config_path,
            vault_path,
        }
    }

    /// Get the config path as a string (for use with --config flag)
    #[allow(dead_code)]
    pub fn config_str(&self) -> String {
        self.config_path.to_string_lossy().to_string()
    }

    /// Get the vault path as a string
    #[allow(dead_code)]
    pub fn vault_str(&self) -> String {
        self.vault_path.to_string_lossy().to_string()
    }

    /// Set the vault path for programmatic access (for tests that don't use CLI)
    pub fn set_as_vault_path(&self) -> Result<(), Box<dyn std::error::Error>> {
        keyrex::vault::Vault::set_vault_path(self.vault_path.clone())?;
        Ok(())
    }

    /// Check if vault file exists
    #[allow(dead_code)]
    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Check if config file exists
    pub fn config_exists(&self) -> bool {
        self.config_path.exists()
    }

    /// Clean up the test environment (called automatically on drop)
    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.test_dir);
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Helper function to create a test environment with automatic cleanup
///
/// # Example
/// ```no_run
/// use tests::common::with_test_env;
///
/// with_test_env("my_test", |env| {
///     // Use env.config_path, env.vault_path
///     // Cleanup happens automatically
/// });
/// ```
pub fn with_test_env<F>(test_name: &str, test_fn: F)
where
    F: FnOnce(&TestEnvironment),
{
    let env = TestEnvironment::new(test_name);
    test_fn(&env);
    // env is dropped here, triggering cleanup
}

/// Create a temporary directory for tests that need custom setups
#[allow(dead_code)]
pub fn create_temp_test_dir(test_name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("keyrex_tests");
    path.push(test_name);

    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("Failed to create temp test directory");

    path
}

/// Clean up a temporary test directory
#[allow(dead_code)]
pub fn cleanup_temp_test_dir(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_creation() {
        let env = TestEnvironment::new("test_env_creation");

        // Verify directory structure
        assert!(env.test_dir.exists(), "Test directory should exist");
        assert!(env.config_exists(), "Config file should exist");
        assert!(
            env.test_dir
                .to_string_lossy()
                .contains("keyrex_tests/test_env_creation"),
            "Test dir should be in keyrex_tests"
        );

        // Verify config content
        let config_content = fs::read_to_string(&env.config_path).unwrap();
        assert!(
            config_content.contains("[default]"),
            "Config should have [default] section"
        );
        assert!(
            config_content.contains("path ="),
            "Config should have path setting"
        );
        assert!(
            config_content.contains("vault.dat"),
            "Config should point to vault.dat"
        );
    }

    #[test]
    fn test_environment_isolation() {
        let env1 = TestEnvironment::new("isolation_test_1");
        let env2 = TestEnvironment::new("isolation_test_2");

        // Each environment should have its own isolated paths
        assert_ne!(env1.test_dir, env2.test_dir);
        assert_ne!(env1.config_path, env2.config_path);
        assert_ne!(env1.vault_path, env2.vault_path);

        // Both should exist
        assert!(env1.config_exists());
        assert!(env2.config_exists());
    }

    #[test]
    fn test_environment_cleanup() {
        let test_dir;
        let config_path;

        {
            let env = TestEnvironment::new("cleanup_test");
            test_dir = env.test_dir.clone();
            config_path = env.config_path.clone();

            // Should exist while in scope
            assert!(test_dir.exists());
            assert!(config_path.exists());
        } // env dropped here

        // Should be cleaned up after drop
        assert!(
            !test_dir.exists(),
            "Test directory should be cleaned up after drop"
        );
        assert!(
            !config_path.exists(),
            "Config file should be cleaned up after drop"
        );
    }

    #[test]
    fn test_with_test_env_helper() {
        let mut vault_path_captured = PathBuf::new();

        with_test_env("helper_test", |env| {
            assert!(env.config_exists());
            vault_path_captured = env.vault_path.clone();
        });

        // After closure, environment should be cleaned up
        assert!(
            !vault_path_captured.exists(),
            "Vault path should be cleaned up"
        );
    }
}
