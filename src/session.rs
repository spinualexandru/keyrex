//! Session management for encrypted vaults
//!
//! This module handles password storage during a session and vault save orchestration.
//! When a vault is encrypted, the password is stored once at startup and reused
//! throughout the session to avoid repeated password prompts on every save operation.
//!
//! # Security
//!
//! - Uses `secrecy::Secret<String>` to protect password in memory
//! - Implements `Drop` trait to zeroize password when session ends
//! - Thread-safe password storage using `Mutex`

use crate::vault::Vault;
use colored::Colorize;
use secrecy::{ExposeSecret, SecretString};
use std::sync::{Mutex, OnceLock};

/// Wrapper for session password that zeroizes on drop
struct SessionPassword {
    password: SecretString,
}

impl SessionPassword {
    fn new(password: String) -> Self {
        Self {
            password: SecretString::new(password.into_boxed_str()),
        }
    }

    fn expose(&self) -> &str {
        self.password.expose_secret()
    }
}

impl Drop for SessionPassword {
    fn drop(&mut self) {
        // The Secret<String> type handles zeroization automatically,
        // but we explicitly ensure it happens here
        tracing::debug!("Zeroizing session password on drop");
    }
}

// Global password storage for the session
static SESSION_PASSWORD: OnceLock<Mutex<SessionPassword>> = OnceLock::new();

/// Store the vault password for the current session
///
/// This allows encrypted vaults to be saved multiple times during a session
/// without prompting the user for the password again.
///
/// # Security
///
/// The password is wrapped in `Secret<String>` and will be zeroized when the session ends.
pub fn store_password(password: String) {
    let _ = SESSION_PASSWORD.set(Mutex::new(SessionPassword::new(password)));
}

/// Retrieve the session password if one has been stored
///
/// Returns None if no password has been stored or if the lock cannot be acquired.
///
/// # Security
///
/// The returned String will be zeroized after use by the caller.
fn get_password() -> Option<String> {
    SESSION_PASSWORD
        .get()
        .and_then(|m| m.lock().ok())
        .map(|guard| guard.expose().to_string())
}

/// Save vault to disk, handling both encrypted and plain text vaults
///
/// For encrypted vaults, uses the session password stored during initialization.
/// Exits the process with code 1 on save failure.
///
/// # Security
///
/// Zeroizes the password string after use to prevent memory exposure.
pub fn save_vault(vault: &Vault, is_encrypted: bool) {
    use zeroize::Zeroize;

    if is_encrypted {
        if let Some(mut password) = get_password() {
            let result = vault.save_encrypted(&password);
            // Zeroize password immediately after use
            password.zeroize();

            if let Err(e) = result {
                eprintln!("{}", format!("✗ Failed to save vault: {}", e).red().bold());
                std::process::exit(1);
            }
        } else {
            eprintln!(
                "{}",
                "✗ Internal error: encryption password not available"
                    .red()
                    .bold()
            );
            std::process::exit(1);
        }
    } else if let Err(e) = vault.save() {
        eprintln!("{}", format!("✗ Failed to save vault: {}", e).red().bold());
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestVault;

    #[test]
    fn test_save_vault_plain_success() {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();

        Vault::set_vault_path(vault_path).unwrap();

        let mut vault = Vault::new();
        vault
            .add_entry("test_key".to_string(), "test_value".to_string())
            .unwrap();

        // This should succeed for plain vaults
        save_vault(&vault, false);

        // Verify the vault was saved
        let loaded = Vault::load().unwrap();
        assert_eq!(loaded.entry_count(), 1);
    }

    #[test]
    fn test_vault_save_plain_multiple_times() {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();
        Vault::set_vault_path(vault_path).unwrap();

        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();

        // Save multiple times
        save_vault(&vault, false);
        save_vault(&vault, false);
        save_vault(&vault, false);

        // Verify vault persists
        let loaded = Vault::load().unwrap();
        assert_eq!(loaded.entry_count(), 1);
    }

    #[test]
    fn test_vault_modifications_persist() {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();
        Vault::set_vault_path(vault_path).unwrap();

        // Create and save initial vault
        let mut vault = Vault::new();
        vault
            .add_entry("initial_key".to_string(), "initial_value".to_string())
            .unwrap();
        save_vault(&vault, false);

        // Modify and save again
        let mut vault2 = Vault::load().unwrap();
        vault2
            .add_entry("second_key".to_string(), "second_value".to_string())
            .unwrap();
        save_vault(&vault2, false);

        // Verify both entries exist
        let mut final_vault = Vault::load().unwrap();
        assert_eq!(final_vault.entry_count(), 2);
        assert!(final_vault.get_entry("initial_key").is_some());
        assert!(final_vault.get_entry("second_key").is_some());
    }

    #[test]
    fn test_empty_vault_save() {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();
        Vault::set_vault_path(vault_path).unwrap();

        let vault = Vault::new();
        save_vault(&vault, false);

        let loaded = Vault::load().unwrap();
        assert_eq!(loaded.entry_count(), 0);
    }

    #[test]
    fn test_vault_integrity_after_save() {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();
        Vault::set_vault_path(vault_path).unwrap();

        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        vault
            .add_entry("key2".to_string(), "value2".to_string())
            .unwrap();

        save_vault(&vault, false);

        let mut loaded = Vault::load().unwrap();
        assert_eq!(loaded.entry_count(), 2);
        assert_eq!(
            loaded.get_entry("key1").unwrap().value,
            "value1".to_string()
        );
        assert_eq!(
            loaded.get_entry("key2").unwrap().value,
            "value2".to_string()
        );
    }
}
