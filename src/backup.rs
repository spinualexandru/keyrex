//! Versioned logical backups and transactional restore/merge operations.
//!
//! A backup stores sorted entries (including tags) and vault timestamps. Encrypted
//! payloads record their KDF rounds so they remain independent of native defaults.

use crate::crypto::{self, CryptoError};
use crate::storage::{self, Access};
use crate::vault::{self, Entry, Vault, VaultError};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

const FORMAT: &str = "keyrex-backup";
const VERSION: u32 = 1;
const MAX_KDF_ROUNDS: u32 = 2_000_000;
/// Recovery copies are named `<vault file name>.pre-import-<UTC timestamp>.bak`.
const RECOVERY_MARKER: &str = ".pre-import-";
const RECOVERY_SUFFIX: &str = ".bak";

#[derive(Error, Debug)]
pub enum BackupError {
    #[error("{0}")]
    Vault(#[from] VaultError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid backup JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid backup: {0}")]
    InvalidFormat(String),
    #[error("A password is required to decrypt this file")]
    PasswordRequired,
    #[error("Unable to decrypt backup")]
    DecryptionFailed,
    #[error("Import cancelled; the vault was not changed")]
    Cancelled,
    #[error("No vault exists to export")]
    SourceMissing,
    #[error("Vault already exists; use --replace to restore or --merge to combine entries")]
    DestinationExists,
    #[error("Vault changed during this operation; retry the import")]
    DestinationChanged,
    #[error("{0} conflicting entry key(s); use --on-conflict skip or --on-conflict overwrite")]
    Conflicts(usize),
    #[error("Failed to install vault: {source}; recovery copy saved at {recovery_path}")]
    CommitFailed {
        source: io::Error,
        recovery_path: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ConflictPolicy {
    #[default]
    Error,
    Skip,
    Overwrite,
}

#[derive(Clone, Copy, Debug)]
pub enum ImportMode {
    Restore { replace: bool },
    Merge { on_conflict: ConflictPolicy },
}

#[derive(Debug)]
pub struct ImportOutcome {
    pub added: usize,
    pub overwritten: usize,
    /// Conflicting entries identical to the local entry, under `--on-conflict overwrite`.
    pub unchanged: usize,
    pub skipped: usize,
    pub changed: bool,
    pub encrypted: bool,
    pub recovery_path: Option<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    #[serde(with = "chrono::serde::ts_seconds")]
    exported_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_updated_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_accessed_at: DateTime<Utc>,
    #[serde(deserialize_with = "strict_entries")]
    entries: Vec<Entry>,
}

/// Backups are hand-editable, so a misspelled entry field must fail instead of being
/// dropped. Native vaults keep `Entry`'s lenient parsing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictEntry {
    key: String,
    value: String,
    #[serde(default)]
    tags: BTreeSet<String>,
}

fn strict_entries<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Entry>, D::Error> {
    Ok(Vec::<StrictEntry>::deserialize(deserializer)?
        .into_iter()
        .map(|entry| Entry {
            key: entry.key,
            value: entry.value,
            tags: entry.tags,
        })
        .collect())
}

impl Snapshot {
    fn from_vault(vault: &Vault) -> Result<Self, BackupError> {
        vault.validate()?;
        let mut entries: Vec<_> = vault.entries.values().cloned().collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(Self {
            exported_at: Utc::now(),
            created_at: vault.created_at,
            last_updated_at: vault.last_updated_at,
            last_accessed_at: vault.last_accessed_at,
            entries,
        })
    }

    fn validate(&self) -> Result<(), BackupError> {
        let mut keys = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            if !keys.insert(entry.key.as_str()) {
                return Err(BackupError::InvalidFormat("duplicate entry key".into()));
            }
        }
        Ok(())
    }

    fn into_vault(self) -> Result<Vault, BackupError> {
        self.validate()?;
        let mut vault = Vault::new();
        vault.entries = self
            .entries
            .into_iter()
            .map(|entry| (entry.key.clone(), entry))
            .collect();
        vault.created_at = self.created_at;
        vault.last_updated_at = self.last_updated_at;
        vault.last_accessed_at = self.last_accessed_at;
        Ok(vault)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Payload {
    Plaintext {
        snapshot: Snapshot,
    },
    Encrypted {
        cipher: String,
        kdf: String,
        iterations: u32,
        data: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupDocument {
    format: String,
    version: u32,
    payload: Payload,
}

impl BackupDocument {
    /// `None` explicitly requests plaintext. The CLI requires --plaintext for this.
    pub fn from_vault(vault: &Vault, password: Option<&str>) -> Result<Self, BackupError> {
        let snapshot = Snapshot::from_vault(vault)?;
        let payload = match password {
            Some(password) => {
                crypto::validate_password_strength(password).map_err(VaultError::from)?;
                let plaintext = Zeroizing::new(serde_json::to_string(&snapshot)?);
                let iterations = crypto::pbkdf2_rounds();
                Payload::Encrypted {
                    cipher: "aes-256-gcm".into(),
                    kdf: "pbkdf2-hmac-sha256".into(),
                    iterations,
                    data: crypto::encrypt_with_rounds(&plaintext, password, iterations)
                        .map_err(VaultError::from)?,
                }
            }
            None => Payload::Plaintext { snapshot },
        };
        Ok(Self {
            format: FORMAT.into(),
            version: VERSION,
            payload,
        })
    }

    pub fn parse(data: &str) -> Result<Self, BackupError> {
        let document: Self = serde_json::from_str(data)?;
        document.validate()?;
        Ok(document)
    }

    fn validate(&self) -> Result<(), BackupError> {
        self.validate_header()?;
        if let Payload::Plaintext { snapshot } = &self.payload {
            snapshot.validate()?;
        }
        Ok(())
    }

    fn validate_header(&self) -> Result<(), BackupError> {
        if self.format != FORMAT || self.version != VERSION {
            return Err(BackupError::InvalidFormat(
                "unsupported format or version".into(),
            ));
        }
        match &self.payload {
            Payload::Plaintext { .. } => {}
            Payload::Encrypted {
                cipher,
                kdf,
                iterations,
                data,
            } => {
                if cipher != "aes-256-gcm"
                    || kdf != "pbkdf2-hmac-sha256"
                    || !(1..=MAX_KDF_ROUNDS).contains(iterations)
                {
                    return Err(BackupError::InvalidFormat(
                        "unsupported encryption parameters".into(),
                    ));
                }
                // Check the shape only; decryption decodes the payload once.
                let padding = data.bytes().rev().take_while(|&byte| byte == b'=').count();
                if data.len() % 4 != 0
                    || padding > 2
                    || !data
                        .bytes()
                        .rev()
                        .skip(padding)
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
                {
                    return Err(BackupError::InvalidFormat(
                        "invalid encrypted payload".into(),
                    ));
                }
                if data.len() / 4 * 3 - padding < crypto::MIN_ENCRYPTED_LEN {
                    return Err(BackupError::InvalidFormat(
                        "truncated encrypted payload".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self, BackupError> {
        let data = Zeroizing::new(storage::read_regular(path)?);
        Self::parse(&data)
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self.payload, Payload::Encrypted { .. })
    }

    pub fn decode(&self, password: Option<&str>) -> Result<Vault, BackupError> {
        self.validate_header()?;
        match &self.payload {
            Payload::Plaintext { snapshot } => snapshot.clone().into_vault(),
            Payload::Encrypted {
                iterations, data, ..
            } => {
                let password = password.ok_or(BackupError::PasswordRequired)?;
                let plaintext = Zeroizing::new(
                    crypto::decrypt_with_rounds(data, password, *iterations).map_err(|error| {
                        match error {
                            CryptoError::DecryptionFailed | CryptoError::InvalidFormat => {
                                BackupError::DecryptionFailed
                            }
                            other => VaultError::from(other).into(),
                        }
                    })?,
                );
                let snapshot: Snapshot = serde_json::from_str(&plaintext)?;
                let vault = snapshot.into_vault()?;
                crypto::reset_attempts();
                Ok(vault)
            }
        }
    }

    /// Write a new backup; existing files are never replaced.
    pub fn write_new(&self, path: &Path) -> Result<(), BackupError> {
        self.validate()?;
        let data = Zeroizing::new(serde_json::to_string_pretty(self)?);
        storage::atomic_write(path, data.as_bytes(), false, Access::Private)?;
        Ok(())
    }
}

/// Capture the destination before prompts, and reject concurrent changes at commit.
pub struct VaultFile {
    /// The configured vault path; its lock and recovery copies live beside it.
    path: PathBuf,
    /// Where the vault bytes live: `path`, or the file a symlinked vault points to.
    target: PathBuf,
    data: Option<Zeroizing<Vec<u8>>>,
    /// Access time recorded beside the vault, which may be newer than the vault's own.
    accessed: Option<DateTime<Utc>>,
}

fn directory_of(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

impl VaultFile {
    pub fn read(path: &Path) -> Result<Self, BackupError> {
        let _lock = Vault::acquire_lock_at(path)?;
        let (target, data) = storage::read_through_link(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            target,
            data,
            accessed: vault::read_access_time(path),
        })
    }

    pub fn exists(&self) -> bool {
        self.data.is_some()
    }

    pub fn is_encrypted(&self) -> bool {
        self.data
            .as_ref()
            .is_some_and(|data| vault::is_encrypted_data(data))
    }

    /// Whether this import would store secrets unencrypted that are encrypted today: an
    /// encrypted vault restored from a plaintext backup, or an encrypted backup merged
    /// into a plaintext vault.
    pub fn exposes_encrypted_secrets(&self, document: &BackupDocument, mode: ImportMode) -> bool {
        if !self.exists() {
            return false;
        }
        match mode {
            ImportMode::Restore { .. } => self.is_encrypted() && !document.is_encrypted(),
            ImportMode::Merge { .. } => document.is_encrypted() && !self.is_encrypted(),
        }
    }

    pub fn decode(&self, password: Option<&str>) -> Result<Vault, BackupError> {
        let data = self.data.as_ref().ok_or(BackupError::SourceMissing)?;
        let password = if self.is_encrypted() {
            Some(password.ok_or(BackupError::PasswordRequired)?)
        } else {
            None
        };
        let mut vault = Vault::decode(data, password)?;
        if password.is_some() {
            crypto::reset_attempts();
        }
        vault.merge_access_time(self.accessed);
        Ok(vault)
    }

    /// The no-clobber write already refuses the vault itself and any alias of it.
    pub fn export(&self, destination: &Path, document: &BackupDocument) -> Result<(), BackupError> {
        if !self.exists() {
            return Err(BackupError::SourceMissing);
        }
        document.write_new(destination)
    }

    /// Full restores adopt backup protection/password. Merges preserve local protection.
    pub fn import(
        &self,
        source: &Path,
        document: &BackupDocument,
        backup_password: Option<&str>,
        mode: ImportMode,
        vault_password: Option<&str>,
    ) -> Result<ImportOutcome, BackupError> {
        storage::reject_same_file(source, &self.path)?;
        if matches!(mode, ImportMode::Restore { replace: false }) && self.exists() {
            return Err(BackupError::DestinationExists);
        }
        let incoming = document.decode(backup_password)?;
        let merging = matches!(mode, ImportMode::Merge { .. }) && self.exists();
        let mut outcome = ImportOutcome {
            added: incoming.entry_count(),
            overwritten: 0,
            unchanged: 0,
            skipped: 0,
            changed: true,
            encrypted: document.is_encrypted(),
            recovery_path: None,
        };
        let (vault, password) = match mode {
            ImportMode::Merge { on_conflict } if merging => {
                let mut vault = self.decode(vault_password)?;
                outcome.encrypted = self.is_encrypted();
                let conflicts = incoming
                    .entries
                    .keys()
                    .filter(|key| vault.entries.contains_key(*key))
                    .count();
                if on_conflict == ConflictPolicy::Error && conflicts > 0 {
                    return Err(BackupError::Conflicts(conflicts));
                }
                outcome.added = 0;
                outcome.changed = false;
                for (key, entry) in incoming.entries {
                    match vault.entries.get(&key) {
                        Some(_) if on_conflict == ConflictPolicy::Skip => {
                            outcome.skipped += 1;
                            continue;
                        }
                        Some(existing) if existing == &entry => {
                            outcome.unchanged += 1;
                            continue;
                        }
                        Some(_) => outcome.overwritten += 1,
                        None => outcome.added += 1,
                    }
                    outcome.changed = true;
                    vault.entries.insert(key, entry);
                }
                if outcome.changed {
                    vault.last_updated_at = Utc::now();
                }
                (
                    vault,
                    if outcome.encrypted {
                        vault_password
                    } else {
                        None
                    },
                )
            }
            _ => (
                incoming,
                if document.is_encrypted() {
                    backup_password
                } else {
                    None
                },
            ),
        };
        let encoded = if outcome.changed {
            Some(vault.encode(password)?)
        } else {
            None
        };
        // Check even no-op merges so the reported result reflects the captured destination.
        let _lock = Vault::acquire_lock_at(&self.path)?;
        let (target, current) = storage::read_through_link(&self.path)?;
        if target != self.target || current != self.data {
            return Err(BackupError::DestinationChanged);
        }
        storage::reject_same_file(source, &self.path)?;
        if !outcome.changed {
            return Ok(outcome);
        }
        let encoded = encoded.expect("changed imports have encoded vault data");
        if let Some(original) = &self.data {
            // Recovery copies are only written under this lock, so leftovers are stale.
            let prefix = recovery_prefix(&self.path)?;
            storage::remove_stale_temps(directory_of(&self.path), |destination| {
                destination.starts_with(prefix.as_encoded_bytes())
                    && destination.ends_with(RECOVERY_SUFFIX.as_bytes())
            });
            let recovery_path = recovery_path(&self.path)?;
            storage::atomic_write(&recovery_path, original, false, Access::Private)?;
            outcome.recovery_path = Some(recovery_path);
        }
        if let Err(source) =
            storage::atomic_write(&target, encoded.as_bytes(), self.exists(), Access::Private)
        {
            return Err(match outcome.recovery_path {
                Some(recovery_path) => BackupError::CommitFailed {
                    source,
                    recovery_path,
                },
                None => BackupError::Io(source),
            });
        }
        if !merging {
            // A restore keeps the snapshot's access time, not one recorded since.
            let _ = fs::remove_file(vault::access_path(&self.path));
        }
        Ok(outcome)
    }
}

fn recovery_prefix(vault_path: &Path) -> Result<OsString, BackupError> {
    let mut prefix = OsString::from(
        vault_path
            .file_name()
            .ok_or_else(|| BackupError::InvalidFormat("invalid destination path".into()))?,
    );
    prefix.push(RECOVERY_MARKER);
    Ok(prefix)
}

fn recovery_path(vault_path: &Path) -> Result<PathBuf, BackupError> {
    let mut name = recovery_prefix(vault_path)?;
    name.push(format!(
        "{}{}",
        Utc::now().format("%Y%m%dT%H%M%S%.9fZ"),
        RECOVERY_SUFFIX
    ));
    Ok(vault_path.with_file_name(name))
}

/// Recovery copies that earlier imports left beside the vault and that are not encrypted.
pub fn plaintext_recovery_copies(vault_path: &Path) -> Result<Vec<PathBuf>, BackupError> {
    let prefix = recovery_prefix(vault_path)?;
    let mut copies = Vec::new();
    for entry in fs::read_dir(directory_of(vault_path))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.as_encoded_bytes();
        if !name.starts_with(prefix.as_encoded_bytes())
            || !name.ends_with(RECOVERY_SUFFIX.as_bytes())
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        let path = entry.path();
        if is_plaintext_file(&path) {
            copies.push(path);
        }
    }
    copies.sort();
    Ok(copies)
}

/// Only the first non-whitespace byte matters, so a short prefix is enough.
fn is_plaintext_file(path: &Path) -> bool {
    const PREFIX_LEN: usize = 4096;
    let mut prefix = Zeroizing::new(Vec::with_capacity(PREFIX_LEN));
    File::open(path)
        .and_then(|file| file.take(PREFIX_LEN as u64).read_to_end(&mut prefix))
        .is_ok()
        && !vault::is_encrypted_data(&prefix)
}

pub fn default_export_path() -> PathBuf {
    PathBuf::from(format!(
        "keyrex-vault-{}.json",
        Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
    ))
}
