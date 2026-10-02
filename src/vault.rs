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
use crate::storage;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use fslock::LockFile;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::debug;
use zeroize::Zeroizing;

thread_local! {
    static VAULT_PATH_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

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

    #[error("Vault was changed by another process after it was loaded; nothing was saved, so run the command again")]
    ConcurrentModification,
}

/// How long to wait for another keyrex process to release the vault lock.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum allowed length for a key (256 characters)
const MAX_KEY_LENGTH: usize = 256;

/// Maximum allowed length for a value (64KB)
const MAX_VALUE_LENGTH: usize = 64 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: String,
    /// Stored with the entry so deleting it cannot leave dangling tag links.
    /// Omit empty tags to preserve the integrity checksum of older vaults.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<String>,
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

        for tag in &self.tags {
            validate_tag(tag)?;
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

/// Encrypted vaults are base64 text and plaintext vaults are JSON objects. Empty files
/// count as plaintext, so they fail to parse instead of prompting for a password.
pub(crate) fn is_encrypted_data(data: &[u8]) -> bool {
    data.iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|&byte| byte != b'{')
}

fn validate_tag(tag: &str) -> Result<(), VaultError> {
    if tag.trim().is_empty() || tag.len() > MAX_KEY_LENGTH || tag.chars().any(char::is_control) {
        return Err(VaultError::InvalidInput(
            "Tags must be nonblank, at most 256 bytes, and contain no control characters".into(),
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    /// The file this vault was read from, updated by each save.
    #[serde(skip)]
    origin: OriginCell,
}

/// What the vault file held when this vault was read, so saves never overwrite newer data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Origin {
    /// Built in memory; saving writes unconditionally.
    #[default]
    Memory,
    /// Read when no vault file existed.
    Missing,
    /// Read from a file with this SHA-256 digest.
    File([u8; 32]),
}

impl Origin {
    fn of(data: Option<&[u8]>) -> Self {
        data.map_or(Self::Missing, |data| {
            Self::File(Sha256::digest(data).into())
        })
    }
}

/// Vault file contents, or `None` when no vault file exists.
type VaultBytes = Option<Zeroizing<Vec<u8>>>;

/// Lets `save(&self)` record its write while `Vault` stays `Send + Sync`.
#[derive(Debug, Default)]
struct OriginCell(Mutex<Origin>);

impl OriginCell {
    fn get(&self) -> Origin {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, origin: Origin) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = origin;
    }
}

impl Clone for OriginCell {
    fn clone(&self) -> Self {
        Self(Mutex::new(self.get()))
    }
}

/// Borrowed form of a saved vault, so encoding does not copy every secret. Fields and
/// entries are in sorted order, matching the sorted `serde_json::Value` layout earlier
/// versions wrote, so a vault kept under version control gets stable diffs.
#[derive(Serialize)]
struct StoredVault<'a> {
    #[serde(with = "chrono::serde::ts_seconds")]
    created_at: DateTime<Utc>,
    entries: BTreeMap<&'a str, StoredEntry<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_accessed_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct StoredEntry<'a> {
    key: &'a str,
    #[serde(skip_serializing_if = "no_tags")]
    tags: &'a BTreeSet<String>,
    value: &'a str,
}

fn no_tags(tags: &&BTreeSet<String>) -> bool {
    tags.is_empty()
}

/// `<vault stem>.<extension>` beside the vault, or `<vault name>.<extension>` when the
/// vault itself already has that extension.
fn sibling_path(vault_path: &Path, extension: &str) -> PathBuf {
    let path = vault_path.with_extension(extension);
    if path != vault_path {
        return path;
    }
    let mut name = vault_path.as_os_str().to_os_string();
    name.push(".");
    name.push(extension);
    PathBuf::from(name)
}

/// `get` records access times in this file instead of rewriting the vault, so reading
/// never makes a concurrent writer's save fail. It holds Unix seconds.
pub(crate) fn access_path(vault_path: &Path) -> PathBuf {
    sibling_path(vault_path, "access")
}

/// Read while holding the vault lock. A missing or unreadable record adds nothing.
pub(crate) fn read_access_time(vault_path: &Path) -> Option<DateTime<Utc>> {
    let data = storage::read_regular(&access_path(vault_path)).ok()?;
    DateTime::from_timestamp(data.trim().parse().ok()?, 0)
}

impl Vault {
    pub fn new() -> Self {
        Vault {
            entries: HashMap::new(),
            created_at: Utc::now(),
            last_updated_at: Utc::now(),
            last_accessed_at: Utc::now(),
            hmac: None,
            origin: OriginCell::default(),
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
        if let Some(custom_path) = VAULT_PATH_OVERRIDE.with(|path| path.borrow().clone()) {
            debug!(path = %custom_path.display(), "Using custom vault path override");
            return Ok(custom_path);
        }

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

        VAULT_PATH_OVERRIDE.with(|override_path| {
            *override_path.borrow_mut() = Some(path.clone());
        });
        debug!(path = %path.display(), "Set custom vault path");
        Ok(())
    }

    /// Clear the thread-local vault path override.
    ///
    /// This is primarily useful for tests and long-lived embedding contexts that need to
    /// restore default path resolution after calling `set_vault_path`.
    pub fn clear_vault_path_override() {
        VAULT_PATH_OVERRIDE.with(|override_path| {
            *override_path.borrow_mut() = None;
        });
    }

    /// Acquires an exclusive lock, waiting while another keyrex process holds it.
    pub fn acquire_lock() -> Result<LockFile, VaultError> {
        Self::acquire_lock_at(&Self::get_user_vault_path()?)
    }

    /// Like `acquire_lock`, but gives up after `timeout` instead of the default wait.
    pub fn acquire_lock_with_timeout(timeout: Duration) -> Result<LockFile, VaultError> {
        Self::lock_at(&Self::get_user_vault_path()?, timeout)
    }

    pub(crate) fn acquire_lock_at(vault_path: &Path) -> Result<LockFile, VaultError> {
        Self::lock_at(vault_path, LOCK_TIMEOUT)
    }

    /// A lock still busy at the deadline is an error, never an unlocked success.
    fn lock_at(vault_path: &Path, timeout: Duration) -> Result<LockFile, VaultError> {
        let lock_path = sibling_path(vault_path, "lock");
        if let Some(parent) = lock_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let mut lockfile = LockFile::open(&lock_path).map_err(|e| {
            VaultError::LockAcquisitionFailed(format!("Failed to open lock file: {}", e))
        })?;
        // A timeout too large to represent as a deadline waits indefinitely.
        let deadline = Instant::now().checked_add(timeout);
        let mut delay = Duration::from_millis(1);
        while !lockfile
            .try_lock()
            .map_err(|e| VaultError::LockAcquisitionFailed(e.to_string()))?
        {
            let remaining =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            if remaining.is_some_and(|remaining| remaining.is_zero()) {
                return Err(VaultError::LockAcquisitionFailed(format!(
                    "Vault is still locked by another process after {:?}",
                    timeout
                )));
            }
            thread::sleep(remaining.map_or(delay, |remaining| delay.min(remaining)));
            delay = (delay * 2).min(Duration::from_millis(50));
        }
        Ok(lockfile)
    }

    pub fn check_vault_exists() -> Result<bool, VaultError> {
        let path = Self::get_user_vault_path()?;
        Ok(path.exists())
    }

    pub fn load() -> Result<Self, VaultError> {
        let (data, accessed) = Self::read_locked()?;
        let mut vault = match &data {
            Some(data) => Self::decode(data, None)?,
            None => Vault::new(),
        };
        vault.merge_access_time(accessed);
        vault
            .origin
            .set(Origin::of(data.as_deref().map(Vec::as_slice)));
        Ok(vault)
    }

    pub fn load_encrypted(password: &str) -> Result<Self, VaultError> {
        let (data, accessed) = Self::read_locked()?;
        let data = data
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "vault file does not exist"))?;
        let mut vault = Self::decode(&data, Some(password))?;
        vault.merge_access_time(accessed);
        vault.origin.set(Origin::of(Some(&data)));
        Ok(vault)
    }

    /// Hold the lock only while reading; parsing and decryption happen after release.
    fn read_locked() -> Result<(VaultBytes, Option<DateTime<Utc>>), VaultError> {
        let path = Self::get_user_vault_path()?;
        let _lock = Self::acquire_lock_at(&path)?;
        let (_, data) = storage::read_through_link(&path)?;
        Ok((data, read_access_time(&path)))
    }

    /// Adopt a newer access time recorded beside the vault.
    pub(crate) fn merge_access_time(&mut self, recorded: Option<DateTime<Utc>>) {
        if let Some(recorded) = recorded {
            self.last_accessed_at = self.last_accessed_at.max(recorded);
        }
    }

    /// Persist `last_accessed_at` beside the vault rather than rewriting the vault itself.
    pub fn record_access(&self) -> Result<(), VaultError> {
        let path = Self::get_user_vault_path()?;
        let _lock = Self::acquire_lock_at(&path)?;
        let accessed = read_access_time(&path).map_or(self.last_accessed_at, |recorded| {
            recorded.max(self.last_accessed_at)
        });
        storage::write_bookkeeping(
            &access_path(&path),
            accessed.timestamp().to_string().as_bytes(),
        )?;
        Ok(())
    }

    pub fn save(&self) -> Result<(), VaultError> {
        let data = self.encode(None)?;
        self.write(data.as_bytes())
    }

    pub fn save_encrypted(&self, password: &str) -> Result<(), VaultError> {
        // Key derivation is slow, so it runs before taking the lock.
        let encrypted = self.encode(Some(password))?;
        self.write(encrypted.as_bytes())
    }

    /// Replace the vault file unless another process changed it after this vault was read.
    fn write(&self, data: &[u8]) -> Result<(), VaultError> {
        let path = Self::get_user_vault_path()?;
        let _lock = Self::acquire_lock_at(&path)?;
        let origin = self.origin.get();
        let target = if origin == Origin::Memory {
            storage::resolve_link(&path)?
        } else {
            let (target, current) = storage::read_through_link(&path)?;
            if Origin::of(current.as_deref().map(Vec::as_slice)) != origin {
                return Err(VaultError::ConcurrentModification);
            }
            target
        };
        storage::atomic_write(&target, data, true, storage::Access::Private)?;
        self.origin.set(Origin::of(Some(data)));
        Ok(())
    }

    /// Encode without acquiring a lock so import can commit under one existing lock.
    pub(crate) fn encode(&self, password: Option<&str>) -> Result<Zeroizing<String>, VaultError> {
        let stored = StoredVault {
            created_at: self.created_at,
            entries: self
                .entries
                .iter()
                .map(|(key, entry)| {
                    let stored = StoredEntry {
                        key: &entry.key,
                        tags: &entry.tags,
                        value: &entry.value,
                    };
                    (key.as_str(), stored)
                })
                .collect(),
            hmac: password.is_none().then(|| self.compute_hmac()),
            last_accessed_at: self.last_accessed_at,
            last_updated_at: self.last_updated_at,
        };
        let data = Zeroizing::new(serde_json::to_string(&stored)?);
        match password {
            Some(password) => Ok(Zeroizing::new(crypto::encrypt(&data, password)?)),
            None => Ok(data),
        }
    }

    /// Parse vault file bytes, as every command reads them. Entries are not validated, so
    /// a vault holding an entry that breaks today's rules still opens and can be fixed.
    pub(crate) fn decode(data: &[u8], password: Option<&str>) -> Result<Self, VaultError> {
        match password {
            Some(password) => {
                let encrypted =
                    std::str::from_utf8(data).map_err(|_| crypto::CryptoError::InvalidFormat)?;
                let plaintext = Zeroizing::new(crypto::decrypt(encrypted, password)?);
                Ok(serde_json::from_str(&plaintext)?)
            }
            None => {
                let vault: Self = serde_json::from_slice(data)?;
                // Verify HMAC if present (integrity check for plaintext vaults)
                vault.verify_hmac()?;
                Ok(vault)
            }
        }
    }

    /// Names the offending entry, so it can be fixed with `update`, `tag`, or `remove`.
    pub(crate) fn validate(&self) -> Result<(), VaultError> {
        for (key, entry) in &self.entries {
            let invalid =
                |reason: String| VaultError::InvalidInput(format!("entry {key:?}: {reason}"));
            if key != &entry.key {
                return Err(invalid("key does not match the stored entry key".into()));
            }
            entry.validate().map_err(|error| match error {
                VaultError::InvalidInput(reason) => invalid(reason),
                other => other,
            })?;
        }
        Ok(())
    }

    pub fn is_encrypted() -> Result<bool, VaultError> {
        let path = Self::get_user_vault_path()?;
        let (_, data) = storage::read_through_link(&path)?;
        Ok(data.is_some_and(|data| is_encrypted_data(&data)))
    }

    pub fn add_entry(&mut self, key: String, value: String) -> Result<(), VaultError> {
        let entry = Entry {
            key: key.clone(),
            value,
            tags: self
                .entries
                .get(&key)
                .map(|e| e.tags.clone())
                .unwrap_or_default(),
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
                tags: BTreeSet::new(),
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

    /// Add a tag, or replace every tag on one entry. Duplicate additions are a no-op.
    pub fn tag_entry(&mut self, key: &str, tag: &str, replace: bool) -> Result<bool, VaultError> {
        validate_tag(tag)?;
        let entry = self.entries.get_mut(key).ok_or_else(|| {
            VaultError::InvalidInput(format!("Entry with key '{}' not found", key))
        })?;
        let changed = if replace {
            let tags = BTreeSet::from([tag.to_string()]);
            let changed = entry.tags != tags;
            entry.tags = tags;
            changed
        } else {
            entry.tags.insert(tag.to_string())
        };
        if changed {
            self.last_updated_at = Utc::now();
        }
        Ok(changed)
    }

    /// Detach a tag, or all tags, from one entry without changing its value.
    pub fn untag_entry(&mut self, key: &str, tag: Option<&str>) -> Result<bool, VaultError> {
        if let Some(tag) = tag {
            validate_tag(tag)?;
        }
        let entry = self.entries.get_mut(key).ok_or_else(|| {
            VaultError::InvalidInput(format!("Entry with key '{}' not found", key))
        })?;
        let changed = if let Some(tag) = tag {
            entry.tags.remove(tag)
        } else {
            let changed = !entry.tags.is_empty();
            entry.tags.clear();
            changed
        };
        if changed {
            self.last_updated_at = Utc::now();
        }
        Ok(changed)
    }

    /// Return the distinct tags still attached to entries, in alphabetical order.
    pub fn list_tags(&self) -> BTreeSet<&str> {
        self.entries
            .values()
            .flat_map(|e| e.tags.iter().map(String::as_str))
            .collect()
    }

    /// Return entries with this exact, case-sensitive tag, ordered by entry name.
    pub fn entries_with_tag(&self, tag: &str) -> Result<Vec<&Entry>, VaultError> {
        validate_tag(tag)?;
        let mut entries: Vec<_> = self
            .entries
            .values()
            .filter(|e| e.tags.contains(tag))
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(entries)
    }

    /// Rename all memberships, merging them if the destination tag already exists.
    pub fn rename_tag(&mut self, old: &str, new: &str) -> Result<usize, VaultError> {
        validate_tag(old)?;
        validate_tag(new)?;
        if !self.entries.values().any(|e| e.tags.contains(old)) {
            return Err(VaultError::InvalidInput(format!("Tag '{}' not found", old)));
        }
        if old == new {
            return Ok(0);
        }
        let mut changed = 0;
        for entry in self.entries.values_mut() {
            if entry.tags.remove(old) {
                entry.tags.insert(new.to_string());
                changed += 1;
            }
        }
        self.last_updated_at = Utc::now();
        Ok(changed)
    }

    /// Remove a tag from every entry without deleting any entries.
    pub fn remove_tag(&mut self, tag: &str) -> Result<usize, VaultError> {
        validate_tag(tag)?;
        let mut changed = 0;
        for entry in self.entries.values_mut() {
            if entry.tags.remove(tag) {
                changed += 1;
            }
        }
        if changed > 0 {
            self.last_updated_at = Utc::now();
        }
        Ok(changed)
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
            tags: BTreeSet::new(),
            key: String::new(),
            value: "value".to_string(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_empty_value() {
        let entry = Entry {
            tags: BTreeSet::new(),
            key: "key".to_string(),
            value: String::new(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_key_with_null_bytes() {
        let entry = Entry {
            tags: BTreeSet::new(),
            key: "key\0bad".to_string(),
            value: "value".to_string(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_value_with_null_bytes() {
        let entry = Entry {
            tags: BTreeSet::new(),
            key: "key".to_string(),
            value: "value\0bad".to_string(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_key_exceeds_max_length() {
        let entry = Entry {
            tags: BTreeSet::new(),
            key: "k".repeat(257),
            value: "value".to_string(),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_value_exceeds_max_length() {
        let entry = Entry {
            tags: BTreeSet::new(),
            key: "key".to_string(),
            value: "v".repeat(65 * 1024 + 1),
        };
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_valid() {
        let entry = Entry {
            tags: BTreeSet::new(),
            key: "mykey".to_string(),
            value: "myvalue".to_string(),
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_entry_max_length_keys() {
        let entry = Entry {
            tags: BTreeSet::new(),
            key: "k".repeat(256),
            value: "v".repeat(64 * 1024),
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_entry_sanitize() {
        let mut entry = Entry {
            tags: BTreeSet::new(),
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
    fn test_encode_writes_the_sorted_layout_of_earlier_versions() {
        let mut vault = Vault::new();
        for key in ["zeta", "alpha", "middle"] {
            vault
                .add_entry(key.to_string(), format!("{key}-value"))
                .unwrap();
        }
        vault.tag_entry("alpha", "work", false).unwrap();
        let encoded = vault.encode(None).unwrap();
        // Earlier versions saved through a sorted `serde_json::Value`.
        let mut expected = serde_json::to_value(&vault).unwrap();
        expected["hmac"] = serde_json::json!(vault.compute_hmac());
        assert_eq!(*encoded, serde_json::to_string(&expected).unwrap());
        let decoded: Vault = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.verify_hmac().is_ok());
    }

    #[test]
    fn test_vault_can_be_shared_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Vault>();
    }

    #[test]
    fn test_unrepresentable_lock_timeout_waits_instead_of_panicking() {
        let test_vault = TestVault::new();
        Vault::set_vault_path(test_vault.path()).unwrap();
        assert!(Vault::acquire_lock_with_timeout(Duration::MAX).is_ok());
    }

    #[test]
    fn test_encryption_detection_treats_empty_and_json_as_plaintext() {
        assert!(!is_encrypted_data(b""));
        assert!(!is_encrypted_data(b" \n\t"));
        assert!(!is_encrypted_data(b"\n{broken"));
        let encrypted = crypto::encrypt("{}", "Test-Password-123!").unwrap();
        assert!(is_encrypted_data(encrypted.as_bytes()));
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
