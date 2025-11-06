//! Vault data model and persistence layer
//!
//! This module defines the core `Vault` and `Entry` data structures and handles
//! all file operations including:
//! - Loading and saving vaults (both encrypted and plain JSON)
//! - CRUD operations on vault entries
//! - File locking for concurrent access safety
//! - Encryption detection
//! - Timestamp tracking (created, updated, accessed)

use crate::crypto;
use crate::security;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use fslock::LockFile;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use tracing::debug;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Could not find home directory")]
    HomeDirectoryNotFound,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to acquire vault lock: {0}")]
    LockAcquisitionFailed(String),

    #[error("Failed to parse vault data: {0}")]
    ParseFailed(#[from] serde_json::Error),

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] crate::crypto::CryptoError),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Integrity check failed: vault may have been tampered with")]
    IntegrityCheckFailed,
}

/// Maximum allowed length for a key (256 characters)
const MAX_KEY_LENGTH: usize = 256;

/// Maximum allowed length for a value (64KB)
const MAX_VALUE_LENGTH: usize = 64 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub key: String,
    pub value: String,
}

impl Entry {
    /// Validates that the key and value meet security requirements
    ///
    /// Checks:
    /// - Key is not empty and <= 256 characters
    /// - Value is not empty and <= 64KB
    /// - Neither contains null bytes (security risk for C interop)
    pub fn validate(&self) -> Result<(), VaultError> {
        // Validate key
        if self.key.is_empty() {
            return Err(VaultError::InvalidInput("Key cannot be empty".to_string()));
        }

        if self.key.len() > MAX_KEY_LENGTH {
            return Err(VaultError::InvalidInput(format!(
                "Key exceeds maximum length of {} characters",
                MAX_KEY_LENGTH
            )));
        }

        if self.key.contains('\0') {
            return Err(VaultError::InvalidInput(
                "Key contains null bytes (not allowed)".to_string(),
            ));
        }

        // Validate value
        if self.value.is_empty() {
            return Err(VaultError::InvalidInput(
                "Value cannot be empty".to_string(),
            ));
        }

        if self.value.len() > MAX_VALUE_LENGTH {
            return Err(VaultError::InvalidInput(format!(
                "Value exceeds maximum length of {} bytes",
                MAX_VALUE_LENGTH
            )));
        }

        if self.value.contains('\0') {
            return Err(VaultError::InvalidInput(
                "Value contains null bytes (not allowed)".to_string(),
            ));
        }

        Ok(())
    }

    /// Sanitizes the entry by removing or replacing dangerous control characters
    /// Preserves common whitespace like newlines and tabs for readability
    #[allow(dead_code)]
    pub fn sanitize(&mut self) {
        // Keep only printable characters and common whitespace
        self.key = self
            .key
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .collect();

        self.value = self
            .value
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t' || *c == '\r')
            .collect();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub entries: HashMap<String, Entry>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub last_updated_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub last_accessed_at: DateTime<Utc>,
    /// Optional HMAC for integrity checking of plaintext vaults
    /// Used to detect tampering or accidental corruption
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

impl Vault {
    pub fn new() -> Self {
        Vault {
            entries: HashMap::new(),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
            last_accessed_at: Utc::now(),
            hmac: None,
        }
    }

    /// Computes HMAC-SHA256 of the vault entries for integrity checking
    /// Returns base64-encoded HMAC
    fn compute_hmac(&self) -> String {
        type HmacSha256 = Hmac<Sha256>;

        // Serialize entries without HMAC for hash computation
        let entries_json = serde_json::json!({
            "entries": self.entries,
            "created_at": self.created_at.timestamp(),
            "last_updated_at": self.last_updated_at.timestamp(),
            "last_accessed_at": self.last_accessed_at.timestamp(),
        });

        let data = serde_json::to_string(&entries_json).unwrap_or_default();

        // Use a fixed key for plaintext vault integrity (not for security, just corruption detection)
        // This is different from encryption - it's purely for detecting accidental data corruption
        let key = b"keyrex-plaintext-integrity-v1";
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data.as_bytes());

        BASE64.encode(mac.finalize().into_bytes())
    }

    /// Verifies the HMAC of the vault
    /// Returns true if HMAC is valid or not present, false if tampering is detected
    fn verify_hmac(&self) -> Result<(), VaultError> {
        match &self.hmac {
            None => {
                // HMAC not present - this is fine for legacy vaults
                debug!("No HMAC present in vault (legacy vault or encrypted)");
                Ok(())
            }
            Some(stored_hmac) => {
                let computed = self.compute_hmac();
                if computed == *stored_hmac {
                    debug!("HMAC verification successful");
                    Ok(())
                } else {
                    debug!(
                        stored = stored_hmac,
                        computed = computed,
                        "HMAC verification failed - vault may have been tampered with"
                    );
                    Err(VaultError::IntegrityCheckFailed)
                }
            }
        }
    }

    /// Get the vault path (can be overridden by configuration)
    pub fn get_user_vault_path() -> Result<PathBuf, VaultError> {
        // Check if a custom path was set via environment/config
        // This will be called from main after config is loaded
        if let Ok(custom_path) = std::env::var("KEYREX_VAULT_PATH") {
            debug!(path = %custom_path, "Using custom vault path from environment");
            return Ok(PathBuf::from(custom_path));
        }

        // Default path
        let mut path = dirs::home_dir().ok_or(VaultError::HomeDirectoryNotFound)?;
        path.push(".keyrex");
        fs::create_dir_all(&path)?;
        path.push("vault.dat");
        Ok(path)
    }

    /// Set a custom vault path for this process
    /// This is used when loading configuration
    pub fn set_vault_path(path: PathBuf) -> Result<(), VaultError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Store in environment variable for this process
        std::env::set_var("KEYREX_VAULT_PATH", path.to_string_lossy().to_string());
        debug!(path = %path.display(), "Set custom vault path");
        Ok(())
    }

    /// Gets the path to the lock file
    /// The lock file is placed in the same directory as the vault file
    fn get_lock_path() -> Result<PathBuf, VaultError> {
        let vault_path = Self::get_user_vault_path()?;
        let lock_path = vault_path.with_extension("lock");

        // Ensure parent directory exists
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(lock_path)
    }

    /// Acquires an exclusive lock on the vault file
    /// Returns a LockFile that should be held for the duration of the operation
    pub fn acquire_lock() -> Result<LockFile, VaultError> {
        let lock_path = Self::get_lock_path()?;
        let mut lockfile = LockFile::open(&lock_path).map_err(|e| {
            VaultError::LockAcquisitionFailed(format!("Failed to open lock file: {}", e))
        })?;

        // Try to acquire lock with timeout
        lockfile.try_lock().map_err(|e| {
            VaultError::LockAcquisitionFailed(format!(
                "Vault is currently locked by another process: {}",
                e
            ))
        })?;

        Ok(lockfile)
    }

    pub fn check_vault_exists() -> Result<bool, VaultError> {
        let path = Self::get_user_vault_path()?;
        Ok(path.exists())
    }

    pub fn load() -> Result<Self, VaultError> {
        let _lock = Self::acquire_lock()?;
        let path = Self::get_user_vault_path()?;
        if path.exists() {
            let data = fs::read_to_string(&path)?;
            let vault: Vault = serde_json::from_str(&data)?;
            // Verify HMAC if present (integrity check for plaintext vaults)
            vault.verify_hmac()?;
            Ok(vault)
        } else {
            Ok(Vault::new())
        }
        // Lock is automatically released when _lock goes out of scope
    }

    pub fn save(&self) -> Result<(), VaultError> {
        let _lock = Self::acquire_lock()?;
        let path = Self::get_user_vault_path()?;

        // Create a modified copy with HMAC for saving
        let mut vault_to_save = serde_json::to_value(self)?;
        let hmac = self.compute_hmac();
        vault_to_save["hmac"] = serde_json::Value::String(hmac);

        let data = serde_json::to_string(&vault_to_save)?;

        // Atomic write: write to temp file, then rename
        // This prevents corruption if the process crashes mid-write
        let temp_path = path.with_extension("dat.tmp");
        debug!(temp_path = %temp_path.display(), "Writing to temporary file");
        fs::write(&temp_path, &data)?;
        debug!(from = %temp_path.display(), to = %path.display(), "Atomic rename");
        fs::rename(&temp_path, &path)?;
        debug!(path = %path.display(), "Vault saved successfully (atomic)");

        // Set file permissions to 0600 (owner read/write only)
        security::set_file_permissions_secure(&path)?;

        Ok(())
        // Lock is automatically released when _lock goes out of scope
    }

    pub fn save_encrypted(&self, password: &str) -> Result<(), VaultError> {
        let _lock = Self::acquire_lock()?;
        let path = Self::get_user_vault_path()?;
        let data = serde_json::to_string(self)?;
        let encrypted = crypto::encrypt(&data, password)?;

        // Atomic write: write to temp file, then rename
        // This prevents corruption if the process crashes mid-write
        let temp_path = path.with_extension("dat.tmp");
        debug!(temp_path = %temp_path.display(), "Writing encrypted data to temporary file");
        fs::write(&temp_path, &encrypted)?;
        debug!(from = %temp_path.display(), to = %path.display(), "Atomic rename");
        fs::rename(&temp_path, &path)?;
        debug!(path = %path.display(), "Encrypted vault saved successfully (atomic)");

        // Set file permissions to 0600 (owner read/write only)
        security::set_file_permissions_secure(&path)?;

        Ok(())
        // Lock is automatically released when _lock goes out of scope
    }

    pub fn load_encrypted(password: &str) -> Result<Self, VaultError> {
        let _lock = Self::acquire_lock()?;
        let path = Self::get_user_vault_path()?;
        let encrypted_data = fs::read_to_string(&path)?;
        let decrypted = crypto::decrypt(&encrypted_data, password)?;
        let vault: Vault = serde_json::from_str(&decrypted)?;
        Ok(vault)
        // Lock is automatically released when _lock goes out of scope
    }

    pub fn is_encrypted() -> Result<bool, VaultError> {
        let path = Self::get_user_vault_path()?;
        if !path.exists() {
            return Ok(false);
        }

        // Try to parse as JSON - if it fails, it's likely encrypted
        let data = fs::read_to_string(&path)?;
        Ok(serde_json::from_str::<Vault>(&data).is_err())
    }

    pub fn add_entry(&mut self, key: String, value: String) -> Result<(), VaultError> {
        let entry = Entry {
            key: key.clone(),
            value,
        };
        entry.validate()?;
        self.entries.insert(key, entry);
        self.last_updated_at = Utc::now();
        Ok(())
    }

    pub fn get_entry(&mut self, key: &str) -> Option<&Entry> {
        self.last_accessed_at = Utc::now();
        self.entries.get(key)
    }

    pub fn remove_entry(&mut self, key: &str) -> Option<Entry> {
        let removed = self.entries.remove(key);
        if removed.is_some() {
            self.last_updated_at = Utc::now();
        }
        removed
    }

    pub fn list_entries(&self) -> Vec<&Entry> {
        self.entries.values().collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn search_entries(&self, pattern: &str) -> Vec<&Entry> {
        self.entries
            .values()
            .filter(|entry| {
                entry.key.to_lowercase().contains(&pattern.to_lowercase())
                    || entry.value.to_lowercase().contains(&pattern.to_lowercase())
            })
            .collect()
    }

    pub fn update_entry(&mut self, key: &str, value: String) -> Result<(), VaultError> {
        if let Some(entry) = self.entries.get_mut(key) {
            // Validate new value
            let temp_entry = Entry {
                key: key.to_string(),
                value: value.clone(),
            };
            temp_entry.validate()?;

            entry.value = value;
            self.last_updated_at = Utc::now();
            Ok(())
        } else {
            Err(VaultError::InvalidInput(format!(
                "Entry with key '{}' not found",
                key
            )))
        }
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestVault;

    // Entry validation tests
    #[test]
    fn test_entry_empty_key() {
        let entry = Entry {
            key: String::new(),
            value: "value".to_string(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_empty_value() {
        let entry = Entry {
            key: "key".to_string(),
            value: String::new(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_key_with_null_bytes() {
        let entry = Entry {
            key: "key\0bad".to_string(),
            value: "value".to_string(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_value_with_null_bytes() {
        let entry = Entry {
            key: "key".to_string(),
            value: "value\0bad".to_string(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_key_exceeds_max_length() {
        let entry = Entry {
            key: "k".repeat(257),
            value: "value".to_string(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_value_exceeds_max_length() {
        let entry = Entry {
            key: "key".to_string(),
            value: "v".repeat(65 * 1024 + 1),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_valid() {
        let entry = Entry {
            key: "mykey".to_string(),
            value: "myvalue".to_string(),
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_entry_max_length_keys() {
        let entry = Entry {
            key: "k".repeat(256),
            value: "v".repeat(64 * 1024),
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_entry_sanitize() {
        let mut entry = Entry {
            key: "key\x01\x02".to_string(),
            value: "value\x03\n".to_string(),
        };
        entry.sanitize();
        assert!(!entry.key.contains('\x01'));
        assert!(!entry.key.contains('\x02'));
        // Newline should be preserved
        assert!(entry.value.contains('\n'));
    }

    // Vault creation and basic operations
    #[test]
    fn test_vault_new() {
        let vault = Vault::new();
        assert_eq!(vault.entry_count(), 0);
        assert!(vault.created_at <= Utc::now());
        assert!(vault.last_updated_at <= Utc::now());
    }

    #[test]
    fn test_vault_add_entry() {
        let mut vault = Vault::new();
        assert!(vault
            .add_entry("key1".to_string(), "value1".to_string())
            .is_ok());
        assert_eq!(vault.entry_count(), 1);
    }

    #[test]
    fn test_vault_add_duplicate_entry() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        // Adding same key overwrites
        vault
            .add_entry("key1".to_string(), "value2".to_string())
            .unwrap();
        assert_eq!(vault.entry_count(), 1);
        assert_eq!(vault.get_entry("key1").unwrap().value, "value2".to_string());
    }

    #[test]
    fn test_vault_add_invalid_entry() {
        let mut vault = Vault::new();
        let result = vault.add_entry("".to_string(), "value".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_get_entry() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        assert_eq!(vault.get_entry("key1").unwrap().value, "value1".to_string());
    }

    #[test]
    fn test_vault_get_nonexistent_entry() {
        let mut vault = Vault::new();
        assert!(vault.get_entry("nonexistent").is_none());
    }

    #[test]
    fn test_vault_remove_entry() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        let removed = vault.remove_entry("key1");
        assert!(removed.is_some());
        assert_eq!(vault.entry_count(), 0);
    }

    #[test]
    fn test_vault_remove_nonexistent_entry() {
        let mut vault = Vault::new();
        let removed = vault.remove_entry("nonexistent");
        assert!(removed.is_none());
    }

    #[test]
    fn test_vault_update_entry() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        let old_timestamp = vault.last_updated_at;

        // Wait a bit to ensure timestamp difference
        std::thread::sleep(std::time::Duration::from_millis(10));

        vault.update_entry("key1", "value2".to_string()).unwrap();
        assert_eq!(vault.get_entry("key1").unwrap().value, "value2".to_string());
        assert!(vault.last_updated_at > old_timestamp);
    }

    #[test]
    fn test_vault_update_nonexistent_entry() {
        let mut vault = Vault::new();
        let result = vault.update_entry("nonexistent", "value".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_update_invalid_value() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        let result = vault.update_entry("key1", String::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_list_entries() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        vault
            .add_entry("key2".to_string(), "value2".to_string())
            .unwrap();
        let entries = vault.list_entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_vault_search_entries_by_key() {
        let mut vault = Vault::new();
        vault
            .add_entry("password_gmail".to_string(), "secret".to_string())
            .unwrap();
        vault
            .add_entry("password_github".to_string(), "secret2".to_string())
            .unwrap();
        vault
            .add_entry("api_key".to_string(), "secret3".to_string())
            .unwrap();

        let results = vault.search_entries("password");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_vault_search_entries_by_value() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "mysecret_value".to_string())
            .unwrap();
        vault
            .add_entry("key2".to_string(), "other_value".to_string())
            .unwrap();

        let results = vault.search_entries("mysecret");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_vault_search_case_insensitive() {
        let mut vault = Vault::new();
        vault
            .add_entry("MyKey".to_string(), "value".to_string())
            .unwrap();

        let results = vault.search_entries("mykey");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_vault_hmac_computation() {
        let vault = Vault::new();
        let hmac1 = vault.compute_hmac();
        let hmac2 = vault.compute_hmac();
        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn test_vault_hmac_changes_on_modification() {
        let mut vault = Vault::new();
        let hmac1 = vault.compute_hmac();

        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        let hmac2 = vault.compute_hmac();

        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_vault_hmac_verification() {
        let vault = Vault::new();
        assert!(vault.verify_hmac().is_ok());
    }

    #[test]
    fn test_vault_entry_count() {
        let mut vault = Vault::new();
        assert_eq!(vault.entry_count(), 0);

        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        assert_eq!(vault.entry_count(), 1);

        vault
            .add_entry("key2".to_string(), "value2".to_string())
            .unwrap();
        assert_eq!(vault.entry_count(), 2);

        vault.remove_entry("key1");
        assert_eq!(vault.entry_count(), 1);
    }

    #[test]
    fn test_vault_timestamps() {
        let vault = Vault::new();
        let now = Utc::now();

        assert!(vault.created_at <= now);
        assert!(vault.last_updated_at <= now);
        assert!(vault.last_accessed_at <= now);
    }

    #[test]
    fn test_vault_get_updates_access_time() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        let old_access_time = vault.last_accessed_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        vault.get_entry("key1");

        assert!(vault.last_accessed_at > old_access_time);
    }

    #[test]
    fn test_vault_add_updates_timestamp() {
        let mut vault = Vault::new();
        let old_updated = vault.last_updated_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();

        assert!(vault.last_updated_at > old_updated);
    }

    #[test]
    fn test_vault_remove_updates_timestamp() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        let old_updated = vault.last_updated_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        vault.remove_entry("key1");

        assert!(vault.last_updated_at > old_updated);
    }

    #[test]
    fn test_vault_default() {
        let vault1 = Vault::new();
        let vault2 = Vault::default();

        assert_eq!(vault1.entry_count(), vault2.entry_count());
    }

    #[test]
    fn test_vault_serialization() {
        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();

        let json = serde_json::to_string(&vault).unwrap();
        let mut deserialized: Vault = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.entry_count(), 1);
        assert_eq!(
            deserialized.get_entry("key1").unwrap().value,
            "value1".to_string()
        );
    }

    // File I/O tests using test utilities
    #[test]
    fn test_vault_save_and_load() {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();

        {
            let mut vault = Vault::new();
            vault
                .add_entry("key1".to_string(), "value1".to_string())
                .unwrap();

            Vault::set_vault_path(vault_path.clone()).unwrap();
            vault.save().unwrap();
        }

        Vault::set_vault_path(vault_path).unwrap();
        let mut loaded = Vault::load().unwrap();

        assert_eq!(loaded.entry_count(), 1);
        assert_eq!(
            loaded.get_entry("key1").unwrap().value,
            "value1".to_string()
        );
    }

    #[test]
    fn test_vault_check_exists() {
        let test_vault = TestVault::new();
        Vault::set_vault_path(test_vault.path()).unwrap();

        assert!(!Vault::check_vault_exists().unwrap());

        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();
        vault.save().unwrap();

        assert!(Vault::check_vault_exists().unwrap());
    }

    #[test]
    fn test_vault_is_encrypted_plain() {
        let test_vault = TestVault::new();
        let vault_path = test_vault.path();

        let mut vault = Vault::new();
        vault
            .add_entry("key1".to_string(), "value1".to_string())
            .unwrap();

        Vault::set_vault_path(vault_path).unwrap();
        vault.save().unwrap();

        let is_encrypted = Vault::is_encrypted().unwrap();
        assert!(!is_encrypted);
    }

    #[test]
    fn test_vault_multiple_entries_serialization() {
        let mut vault = Vault::new();
        for i in 0..10 {
            vault
                .add_entry(format!("key{}", i), format!("value{}", i))
                .unwrap();
        }

        let json = serde_json::to_string(&vault).unwrap();
        let mut deserialized: Vault = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.entry_count(), 10);
        for i in 0..10 {
            assert_eq!(
                deserialized.get_entry(&format!("key{}", i)).unwrap().value,
                format!("value{}", i)
            );
        }
    }

    #[test]
    fn test_vault_special_characters() {
        let mut vault = Vault::new();
        vault
            .add_entry(
                "key-with-special_chars.123".to_string(),
                "value!@#$%^&*()".to_string(),
            )
            .unwrap();
        vault
            .add_entry(
                "key/with\\slashes".to_string(),
                "value/with\\paths".to_string(),
            )
            .unwrap();
        vault
            .add_entry(
                "key-with-emoji-🔒".to_string(),
                "value-with-emoji-🔑".to_string(),
            )
            .unwrap();

        assert_eq!(vault.entry_count(), 3);
        assert!(vault.get_entry("key-with-special_chars.123").is_some());
        assert!(vault.get_entry("key/with\\slashes").is_some());
        assert!(vault.get_entry("key-with-emoji-🔒").is_some());
    }

    #[test]
    fn test_vault_whitespace_preservation() {
        let mut vault = Vault::new();
        let value_with_spaces = "  value with   spaces  \n\t  ";
        vault
            .add_entry("key".to_string(), value_with_spaces.to_string())
            .unwrap();

        assert_eq!(
            vault.get_entry("key").unwrap().value,
            value_with_spaces.to_string()
        );
    }

    // Filesystem error simulation tests
    // Note: These tests create temp files to simulate filesystem errors
    #[test]
    #[ignore] // Run with: cargo test test_vault_load_corrupted_json -- --ignored --test-threads=1
    fn test_vault_load_corrupted_json() {
        let temp_file = "/tmp/keyrex_test_corrupted.dat";

        // Write invalid JSON to the file
        fs::write(temp_file, "{ invalid json content }").unwrap();

        // Attempting to load corrupted JSON should return an error
        Vault::set_vault_path(PathBuf::from(temp_file)).unwrap();
        let result = Vault::load();
        assert!(result.is_err());

        // Clean up
        let _ = fs::remove_file(temp_file);

        match result {
            Err(VaultError::ParseFailed(_)) => {
                // Expected behavior
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    #[ignore] // Run with: cargo test test_vault_load_empty_file -- --ignored --test-threads=1
    fn test_vault_load_empty_file() {
        let temp_file = "/tmp/keyrex_test_empty.dat";

        // Create an empty file
        fs::write(temp_file, "").unwrap();

        // Attempting to load an empty file should return an error
        Vault::set_vault_path(PathBuf::from(temp_file)).unwrap();
        let result = Vault::load();

        // Clean up
        let _ = fs::remove_file(temp_file);

        assert!(result.is_err());
    }

    #[test]
    #[ignore] // Run with: cargo test test_vault_load_partial_json -- --ignored --test-threads=1
    fn test_vault_load_partial_json() {
        let temp_file = "/tmp/keyrex_test_partial.dat";

        // Write incomplete JSON
        fs::write(temp_file, r#"{"entries": {"key": {"key": "test""#).unwrap();

        Vault::set_vault_path(PathBuf::from(temp_file)).unwrap();
        let result = Vault::load();

        // Clean up
        let _ = fs::remove_file(temp_file);

        assert!(result.is_err());
    }

    #[test]
    #[ignore] // Run with: cargo test test_vault_hmac_mismatch_detection -- --ignored --test-threads=1
    fn test_vault_hmac_mismatch_detection() {
        let temp_file = "/tmp/keyrex_test_tampered.dat";

        // Create a valid vault and save it
        Vault::set_vault_path(PathBuf::from(temp_file)).unwrap();
        {
            let mut vault = Vault::new();
            vault
                .add_entry("key".to_string(), "value".to_string())
                .unwrap();
            vault.save().unwrap();
        }

        // Load the saved data and tamper with it
        let mut content = fs::read_to_string(temp_file).unwrap();

        // Modify the content slightly (simulate tampering)
        if let Some(pos) = content.find("\"value\"") {
            let mut chars = content.chars().collect::<Vec<_>>();
            if pos + 8 < chars.len() {
                chars[pos + 8] = 'X'; // Change one character
                content = chars.into_iter().collect();
                fs::write(temp_file, &content).unwrap();
            }
        }

        // Attempting to load tampered vault should fail HMAC check
        Vault::set_vault_path(PathBuf::from(temp_file)).unwrap();
        let result = Vault::load();

        // Clean up
        let _ = fs::remove_file(temp_file);

        assert!(result.is_err());

        match result {
            Err(VaultError::IntegrityCheckFailed) => {
                // Expected - HMAC mismatch
            }
            _ => {
                // Could also be a parse error if tampering broke JSON structure
                // Both are acceptable for this test
            }
        }
    }

    #[test]
    fn test_vault_corrupted_json_error_type() {
        // Test that parsing errors are properly categorized
        let vault_data = "{ invalid json }";
        let result = serde_json::from_str::<Vault>(vault_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_error_messages() {
        // Verify that error messages don't leak sensitive information
        let err = VaultError::InvalidInput("test error".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid input"));
        assert!(!msg.contains("password"));
        assert!(!msg.contains("secret"));
    }
}
