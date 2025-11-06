//! Test utilities for isolated testing
//!
//! This module provides utilities to ensure tests run in isolation
//! without affecting user's actual vault data.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Mutex;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Get a temporary test vault path that won't interfere with user data
pub fn get_test_vault_path(test_name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("keyrex_tests");
    path.push(test_name);
    path.push("test_vault.dat");
    path
}

/// Set up a test environment with isolated vault path
/// Returns a guard that must be held for the duration of the test
pub fn setup_test_env(test_name: &str) -> (std::sync::MutexGuard<'static, ()>, PathBuf) {
    let guard = TEST_MUTEX.lock().unwrap();

    let test_path = get_test_vault_path(test_name);

    // Clean up any existing test data
    if let Some(parent) = test_path.parent() {
        let _ = std::fs::remove_dir_all(parent);
        let _ = std::fs::create_dir_all(parent);
    }

    // Set the test vault path
    std::env::set_var("KEYREX_VAULT_PATH", test_path.to_string_lossy().to_string());

    (guard, test_path)
}

/// Clean up test environment
pub fn cleanup_test_env(test_path: &std::path::Path) {
    // Remove test vault and directory
    if let Some(parent) = test_path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }

    // Clear the environment variable
    std::env::remove_var("KEYREX_VAULT_PATH");
}

/// A test vault that automatically sets up and tears down an isolated test environment
pub struct TestVault {
    path: PathBuf,
    _guard: Option<std::sync::MutexGuard<'static, ()>>,
}

impl Default for TestVault {
    fn default() -> Self {
        Self::new()
    }
}

impl TestVault {
    /// Create a new test vault with an isolated path
    pub fn new() -> Self {
        // Get a unique name based on the test that's running
        let test_name = std::thread::current()
            .name()
            .unwrap_or("unknown_test")
            .to_string();

        let (_guard, path) = setup_test_env(&test_name);
        TestVault {
            path,
            _guard: Some(_guard),
        }
    }

    /// Get the path to the test vault
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }
}

impl Drop for TestVault {
    fn drop(&mut self) {
        cleanup_test_env(&self.path);
    }
}
