//! Backup codec and real CLI tests use independent temporary configurations.

use chrono::{TimeZone, Utc};
use keyrex::backup::{
    plaintext_recovery_copies, BackupDocument, BackupError, ConflictPolicy, ImportMode, VaultFile,
};
use keyrex::vault::{Vault, VaultError};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const BACKUP_PASSWORD: &str = "Backup-Password-123!";
const LOCAL_PASSWORD: &str = "Local-Vault-Password-456!";

struct Environment {
    root: TempDir,
    config: PathBuf,
    vault: PathBuf,
}

impl Environment {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config.toml");
        let vault = root.path().join("vault.dat");
        fs::write(
            &config,
            format!(
                "[default]\npath = {}\n",
                serde_json::to_string(vault.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        Self {
            root,
            config,
            vault,
        }
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_keyrex"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .current_dir(self.root.path())
            .output()
            .unwrap()
    }

    fn write_vault(&self, vault: &Vault, password: Option<&str>) {
        Vault::set_vault_path(self.vault.clone()).unwrap();
        match password {
            Some(password) => vault.save_encrypted(password),
            None => vault.save(),
        }
        .unwrap();
        Vault::clear_vault_path_override();
    }
}

fn sample_vault() -> Vault {
    let mut vault = Vault::new();
    vault
        .add_entry("zeta".into(), "unicode-🔑\nsecond line".into())
        .unwrap();
    vault
        .add_entry("alpha".into(), "alpha-secret".into())
        .unwrap();
    vault.tag_entry("alpha", "work", false).unwrap();
    vault.tag_entry("alpha", "ai", false).unwrap();
    vault.created_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    vault.last_updated_at = Utc.timestamp_opt(1_700_000_100, 0).unwrap();
    vault.last_accessed_at = Utc.timestamp_opt(1_700_000_200, 0).unwrap();
    vault
}

fn backup(env: &Environment, vault: &Vault, password: Option<&str>) -> (PathBuf, BackupDocument) {
    let path = env.root.path().join("backup.json");
    let document = BackupDocument::from_vault(vault, password).unwrap();
    document.write_new(&path).unwrap();
    (path, document)
}

fn restore() -> ImportMode {
    ImportMode::Restore { replace: false }
}
fn merge(on_conflict: ConflictPolicy) -> ImportMode {
    ImportMode::Merge { on_conflict }
}

fn assert_snapshot(actual: &Vault, expected: &Vault) {
    assert_eq!(actual.entries, expected.entries);
    assert_eq!(actual.created_at, expected.created_at);
    assert_eq!(actual.last_updated_at, expected.last_updated_at);
    assert_eq!(actual.last_accessed_at, expected.last_accessed_at);
}

#[test]
fn plaintext_backup_is_sorted_and_preserves_all_metadata() {
    let env = Environment::new();
    let vault = sample_vault();
    let (path, _) = backup(&env, &vault, None);
    let data: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(data["format"], "keyrex-backup");
    assert_eq!(data["version"], 1);
    assert_eq!(data["payload"]["snapshot"]["entries"][0]["key"], "alpha");
    let restored = BackupDocument::read(&path).unwrap().decode(None).unwrap();
    assert_snapshot(&restored, &vault);
}

#[test]
fn encrypted_backup_hides_values_and_records_portable_kdf_rounds() {
    let env = Environment::new();
    let vault = sample_vault();
    let (path, _) = backup(&env, &vault, Some(BACKUP_PASSWORD));
    let raw = fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("alpha-secret"));
    assert!(!raw.contains("zeta"));
    let data: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(data["payload"]["iterations"].as_u64().unwrap() > 0);
    let document = BackupDocument::read(&path).unwrap();
    assert!(document.is_encrypted());
    assert_snapshot(&document.decode(Some(BACKUP_PASSWORD)).unwrap(), &vault);
    assert!(matches!(
        document.decode(None),
        Err(BackupError::PasswordRequired)
    ));
    let wrong = document.decode(Some("Wrong-Password-123!")).unwrap_err();
    assert!(matches!(wrong, BackupError::DecryptionFailed));
    assert_eq!(wrong.to_string(), "Unable to decrypt backup");
}

#[test]
fn tampered_ciphertext_is_rejected() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let env = Environment::new();
    let (path, _) = backup(&env, &sample_vault(), Some(BACKUP_PASSWORD));
    let mut data: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mut encrypted = STANDARD
        .decode(data["payload"]["data"].as_str().unwrap())
        .unwrap();
    *encrypted.last_mut().unwrap() ^= 1;
    data["payload"]["data"] = serde_json::json!(STANDARD.encode(encrypted));
    let document = BackupDocument::parse(&data.to_string()).unwrap();
    assert!(document.decode(Some(BACKUP_PASSWORD)).is_err());
}

#[test]
fn malformed_schema_duplicate_keys_and_invalid_entries_are_rejected() {
    let env = Environment::new();
    let (path, _) = backup(&env, &sample_vault(), None);
    let valid: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    for field in ["version", "format"] {
        let mut data = valid.clone();
        data[field] = serde_json::json!(99);
        assert!(BackupDocument::parse(&data.to_string()).is_err());
    }
    let mut duplicate = valid.clone();
    let entries = duplicate["payload"]["snapshot"]["entries"]
        .as_array_mut()
        .unwrap();
    entries.push(entries[0].clone());
    assert!(BackupDocument::parse(&duplicate.to_string()).is_err());
    for (field, value) in [
        ("key", serde_json::json!("")),
        ("value", serde_json::json!("")),
        ("tags", serde_json::json!(["\ninvalid"])),
        ("value", serde_json::json!("x".repeat(65_537))),
    ] {
        let mut data = valid.clone();
        data["payload"]["snapshot"]["entries"][0][field] = value;
        assert!(BackupDocument::parse(&data.to_string()).is_err());
    }
    // A misspelled field in a hand-edited entry must not silently drop data.
    let mut misspelled = valid.clone();
    misspelled["payload"]["snapshot"]["entries"][0]["tag"] = serde_json::json!(["work"]);
    assert!(BackupDocument::parse(&misspelled.to_string()).is_err());
    let mut data = valid;
    data["payload"]["snapshot"]["created_at"] = serde_json::json!(i64::MAX);
    assert!(BackupDocument::parse(&data.to_string()).is_err());
}

#[test]
fn unsupported_kdf_parameters_fail_before_decryption() {
    let env = Environment::new();
    let (path, _) = backup(&env, &sample_vault(), Some(BACKUP_PASSWORD));
    let valid: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    for rounds in [0, 2_000_001, u32::MAX] {
        let mut data = valid.clone();
        data["payload"]["iterations"] = serde_json::json!(rounds);
        assert!(BackupDocument::parse(&data.to_string()).is_err());
        // Deserializing through serde directly must not bypass the public decoder's bounds.
        let document: BackupDocument = serde_json::from_value(data).unwrap();
        assert!(matches!(
            document.decode(Some(BACKUP_PASSWORD)),
            Err(BackupError::InvalidFormat(_))
        ));
    }
    for payload in ["not base64!", "AAAA", "AAA=="] {
        let mut data = valid.clone();
        data["payload"]["data"] = serde_json::json!(payload);
        assert!(matches!(
            BackupDocument::parse(&data.to_string()),
            Err(BackupError::InvalidFormat(_))
        ));
    }
    let mut data = valid;
    data["payload"]["cipher"] = serde_json::json!("unsupported");
    assert!(BackupDocument::parse(&data.to_string()).is_err());
}

#[test]
fn restores_into_missing_vault_and_recomputes_plaintext_integrity() {
    let env = Environment::new();
    let vault = sample_vault();
    let (path, document) = backup(&env, &vault, None);
    let destination = VaultFile::read(&env.vault).unwrap();
    assert!(!env.vault.exists());
    let result = destination
        .import(&path, &document, None, restore(), None)
        .unwrap();
    assert_eq!(result.added, 2);
    assert!(result.recovery_path.is_none());
    assert_snapshot(
        &VaultFile::read(&env.vault).unwrap().decode(None).unwrap(),
        &vault,
    );
    let data: serde_json::Value = serde_json::from_slice(&fs::read(&env.vault).unwrap()).unwrap();
    assert!(data["hmac"].is_string());
}

#[test]
fn encrypted_restore_adopts_backup_password() {
    let env = Environment::new();
    let vault = sample_vault();
    let (path, document) = backup(&env, &vault, Some(BACKUP_PASSWORD));
    let result = VaultFile::read(&env.vault)
        .unwrap()
        .import(&path, &document, Some(BACKUP_PASSWORD), restore(), None)
        .unwrap();
    assert!(result.encrypted);
    let destination = VaultFile::read(&env.vault).unwrap();
    assert!(destination.is_encrypted());
    assert_snapshot(&destination.decode(Some(BACKUP_PASSWORD)).unwrap(), &vault);
    assert!(!fs::read_to_string(&env.vault)
        .unwrap()
        .contains("alpha-secret"));
}

#[test]
fn replacing_damaged_binary_vault_saves_exact_recovery_copy() {
    let env = Environment::new();
    let original = [0xff, 0, 0x80, 0x7f];
    fs::write(&env.vault, original).unwrap();
    let vault = sample_vault();
    let (path, document) = backup(&env, &vault, None);
    let destination = VaultFile::read(&env.vault).unwrap();
    assert!(matches!(
        destination.import(&path, &document, None, restore(), None),
        Err(BackupError::DestinationExists)
    ));
    assert_eq!(fs::read(&env.vault).unwrap(), original);
    let result = destination
        .import(
            &path,
            &document,
            None,
            ImportMode::Restore { replace: true },
            None,
        )
        .unwrap();
    assert_eq!(fs::read(result.recovery_path.unwrap()).unwrap(), original);
    assert_snapshot(
        &VaultFile::read(&env.vault).unwrap().decode(None).unwrap(),
        &vault,
    );
}

#[test]
fn merge_conflict_failure_is_atomic() {
    let env = Environment::new();
    env.write_vault(&sample_vault(), None);
    let before = fs::read(&env.vault).unwrap();
    let mut incoming = sample_vault();
    incoming
        .add_entry("brand-new".into(), "new-secret".into())
        .unwrap();
    let (path, document) = backup(&env, &incoming, None);
    assert!(matches!(
        VaultFile::read(&env.vault).unwrap().import(
            &path,
            &document,
            None,
            merge(ConflictPolicy::Error),
            None
        ),
        Err(BackupError::Conflicts(2))
    ));
    assert_eq!(fs::read(&env.vault).unwrap(), before);
    assert_eq!(
        fs::read_dir(env.root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("pre-import"))
            .count(),
        0
    );
}

#[test]
fn merge_skip_and_overwrite_apply_complete_entries_including_tags() {
    for policy in [ConflictPolicy::Skip, ConflictPolicy::Overwrite] {
        let env = Environment::new();
        let local = sample_vault();
        env.write_vault(&local, None);
        let before = fs::read(&env.vault).unwrap();
        let mut incoming = Vault::new();
        incoming
            .add_entry("alpha".into(), "incoming-secret".into())
            .unwrap();
        incoming.tag_entry("alpha", "personal", false).unwrap();
        incoming
            .add_entry("new".into(), "new-value".into())
            .unwrap();
        let (path, document) = backup(&env, &incoming, None);
        let result = VaultFile::read(&env.vault)
            .unwrap()
            .import(&path, &document, None, merge(policy), None)
            .unwrap();
        assert_eq!(result.added, 1);
        assert_eq!(fs::read(result.recovery_path.unwrap()).unwrap(), before);
        let merged = VaultFile::read(&env.vault).unwrap().decode(None).unwrap();
        assert_eq!(merged.entries.len(), 3);
        assert_eq!(merged.created_at, local.created_at);
        assert_eq!(merged.last_accessed_at, local.last_accessed_at);
        assert!(merged.last_updated_at > local.last_updated_at);
        let expected = if policy == ConflictPolicy::Skip {
            &local.entries["alpha"]
        } else {
            &incoming.entries["alpha"]
        };
        assert_eq!(&merged.entries["alpha"], expected);
        assert_eq!(result.skipped, usize::from(policy == ConflictPolicy::Skip));
        assert_eq!(
            result.overwritten,
            usize::from(policy == ConflictPolicy::Overwrite)
        );
    }
}

#[test]
fn no_op_merge_keeps_bytes_timestamps_and_creates_no_recovery_copy() {
    for policy in [ConflictPolicy::Skip, ConflictPolicy::Overwrite] {
        let env = Environment::new();
        let vault = sample_vault();
        env.write_vault(&vault, None);
        let before = fs::read(&env.vault).unwrap();
        let (path, document) = backup(&env, &vault, None);
        let result = VaultFile::read(&env.vault)
            .unwrap()
            .import(&path, &document, None, merge(policy), None)
            .unwrap();
        assert!(!result.changed);
        assert!(result.recovery_path.is_none());
        assert_eq!(fs::read(&env.vault).unwrap(), before);
        // Identical entries are never reported as overwritten.
        assert_eq!(result.overwritten, 0);
        let (skipped, unchanged) = if policy == ConflictPolicy::Skip {
            (2, 0)
        } else {
            (0, 2)
        };
        assert_eq!((result.skipped, result.unchanged), (skipped, unchanged));
    }
}

#[test]
fn merge_keeps_local_encryption_even_with_different_backup_password() {
    let env = Environment::new();
    let local = sample_vault();
    env.write_vault(&local, Some(LOCAL_PASSWORD));
    let mut incoming = Vault::new();
    incoming
        .add_entry("new".into(), "incoming-secret".into())
        .unwrap();
    let (path, document) = backup(&env, &incoming, Some(BACKUP_PASSWORD));
    let result = VaultFile::read(&env.vault)
        .unwrap()
        .import(
            &path,
            &document,
            Some(BACKUP_PASSWORD),
            merge(ConflictPolicy::Error),
            Some(LOCAL_PASSWORD),
        )
        .unwrap();
    assert!(result.encrypted);
    let merged = VaultFile::read(&env.vault)
        .unwrap()
        .decode(Some(LOCAL_PASSWORD))
        .unwrap();
    assert_eq!(merged.entries.len(), 3);
    assert_eq!(merged.created_at, local.created_at);
    assert!(!fs::read_to_string(&env.vault)
        .unwrap()
        .contains("incoming-secret"));
}

#[test]
fn stale_destination_is_not_overwritten() {
    let env = Environment::new();
    env.write_vault(&sample_vault(), None);
    let captured = VaultFile::read(&env.vault).unwrap();
    let (path, document) = backup(&env, &sample_vault(), None);
    fs::write(&env.vault, "changed-after-capture").unwrap();
    assert!(matches!(
        captured.import(
            &path,
            &document,
            None,
            ImportMode::Restore { replace: true },
            None
        ),
        Err(BackupError::DestinationChanged)
    ));
    assert_eq!(
        fs::read_to_string(&env.vault).unwrap(),
        "changed-after-capture"
    );
}

#[test]
fn backup_output_is_never_clobbered_and_aliases_are_rejected() {
    let env = Environment::new();
    let vault = sample_vault();
    env.write_vault(&vault, None);
    let (path, document) = backup(&env, &vault, None);
    let before = fs::read(&path).unwrap();
    assert!(document.write_new(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    let source = VaultFile::read(&env.vault).unwrap();
    assert!(source.export(&env.vault, &document).is_err());
    assert!(source
        .import(
            &env.vault,
            &document,
            None,
            ImportMode::Restore { replace: true },
            None
        )
        .is_err());
    let alias = env.root.path().join("hardlink.dat");
    fs::hard_link(&env.vault, &alias).unwrap();
    assert!(source.export(&alias, &document).is_err());
}

#[test]
fn busy_lock_is_awaited_and_times_out_without_an_unlocked_success() {
    let env = Environment::new();
    Vault::set_vault_path(env.vault.clone()).unwrap();
    let lock = Vault::acquire_lock().unwrap();
    assert!(matches!(
        Vault::acquire_lock_with_timeout(Duration::from_millis(50)),
        Err(VaultError::LockAcquisitionFailed(_))
    ));
    let holder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(lock);
    });
    let started = Instant::now();
    VaultFile::read(&env.vault).unwrap();
    assert!(started.elapsed() >= Duration::from_millis(100));
    holder.join().unwrap();
    Vault::clear_vault_path_override();
}

#[test]
fn saves_from_a_vault_loaded_before_an_import_are_rejected() {
    let env = Environment::new();
    env.write_vault(&sample_vault(), None);
    Vault::set_vault_path(env.vault.clone()).unwrap();
    let mut stale = Vault::load().unwrap();
    let mut incoming = Vault::new();
    incoming
        .add_entry("restored".into(), "restored-value".into())
        .unwrap();
    let (path, document) = backup(&env, &incoming, None);
    VaultFile::read(&env.vault)
        .unwrap()
        .import(
            &path,
            &document,
            None,
            ImportMode::Restore { replace: true },
            None,
        )
        .unwrap();
    let restored = fs::read(&env.vault).unwrap();
    stale.remove_entry("alpha");
    assert!(matches!(
        stale.save(),
        Err(VaultError::ConcurrentModification)
    ));
    assert_eq!(fs::read(&env.vault).unwrap(), restored);
    Vault::clear_vault_path_override();
}

#[test]
fn empty_vault_file_is_damaged_plaintext_for_every_command() {
    let env = Environment::new();
    fs::write(&env.vault, " \n").unwrap();
    let destination = VaultFile::read(&env.vault).unwrap();
    assert!(!destination.is_encrypted());
    Vault::set_vault_path(env.vault.clone()).unwrap();
    assert!(!Vault::is_encrypted().unwrap());
    Vault::clear_vault_path_override();
    let (path, document) = backup(&env, &sample_vault(), None);
    assert!(matches!(
        destination.import(&path, &document, None, merge(ConflictPolicy::Error), None),
        Err(BackupError::Vault(VaultError::ParseFailed(_)))
    ));
}

#[test]
fn imports_that_would_store_encrypted_secrets_unencrypted_are_detected() {
    let env = Environment::new();
    let plain_document = BackupDocument::from_vault(&sample_vault(), None).unwrap();
    let encrypted_document =
        BackupDocument::from_vault(&sample_vault(), Some(BACKUP_PASSWORD)).unwrap();
    let replace = ImportMode::Restore { replace: true };
    let combine = merge(ConflictPolicy::Skip);

    let missing = VaultFile::read(&env.vault).unwrap();
    for mode in [replace, combine] {
        assert!(!missing.exposes_encrypted_secrets(&plain_document, mode));
        assert!(!missing.exposes_encrypted_secrets(&encrypted_document, mode));
    }

    env.write_vault(&sample_vault(), Some(LOCAL_PASSWORD));
    let local_encrypted = VaultFile::read(&env.vault).unwrap();
    assert!(local_encrypted.exposes_encrypted_secrets(&plain_document, replace));
    assert!(!local_encrypted.exposes_encrypted_secrets(&plain_document, combine));
    assert!(!local_encrypted.exposes_encrypted_secrets(&encrypted_document, replace));

    env.write_vault(&sample_vault(), None);
    let local_plain = VaultFile::read(&env.vault).unwrap();
    assert!(local_plain.exposes_encrypted_secrets(&encrypted_document, combine));
    assert!(!local_plain.exposes_encrypted_secrets(&encrypted_document, replace));
    assert!(!local_plain.exposes_encrypted_secrets(&plain_document, combine));
}

#[test]
fn plaintext_recovery_copies_are_listed_for_cleanup() {
    let env = Environment::new();
    env.write_vault(&sample_vault(), None);
    let (path, document) = backup(&env, &sample_vault(), Some(BACKUP_PASSWORD));
    let replace = ImportMode::Restore { replace: true };
    let first = VaultFile::read(&env.vault)
        .unwrap()
        .import(&path, &document, Some(BACKUP_PASSWORD), replace, None)
        .unwrap();
    // The vault is encrypted now, so this recovery copy is encrypted too.
    let second = VaultFile::read(&env.vault)
        .unwrap()
        .import(&path, &document, Some(BACKUP_PASSWORD), replace, None)
        .unwrap();
    assert!(second.recovery_path.unwrap().exists());
    assert_eq!(
        plaintext_recovery_copies(&env.vault).unwrap(),
        vec![first.recovery_path.unwrap()]
    );
}

#[test]
fn vault_with_lock_extension_can_be_restored_without_lock_file_alias() {
    let env = Environment::new();
    let path = env.root.path().join("vault.lock");
    let (source, document) = backup(&env, &sample_vault(), None);
    let captured = VaultFile::read(&path).unwrap();
    assert!(!path.exists());
    captured
        .import(&source, &document, None, restore(), None)
        .unwrap();
    assert_eq!(
        VaultFile::read(&path)
            .unwrap()
            .decode(None)
            .unwrap()
            .entry_count(),
        2
    );
}

#[test]
fn cli_plaintext_round_trip_with_default_export_path() {
    let source = Environment::new();
    let vault = sample_vault();
    source.write_vault(&vault, None);
    let before = fs::read(&source.vault).unwrap();
    let exported = source.cli(&["vault", "export", "--plaintext"]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_eq!(fs::read(&source.vault).unwrap(), before);
    let path = fs::read_dir(source.root.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("keyrex-vault-")
        })
        .unwrap();
    let target = Environment::new();
    let imported = target.cli(&["vault", "import", path.to_str().unwrap()]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    assert!(!String::from_utf8_lossy(&imported.stdout).contains("Initialized new vault"));
    assert_snapshot(
        &VaultFile::read(&target.vault)
            .unwrap()
            .decode(None)
            .unwrap(),
        &vault,
    );
    let existing = target.cli(&["vault", "import", path.to_str().unwrap()]);
    assert!(!existing.status.success());
    assert!(String::from_utf8_lossy(&existing.stderr).contains("--replace"));
}

#[test]
fn cli_failed_export_and_import_do_not_initialize_missing_vault() {
    let env = Environment::new();
    assert!(!env
        .cli(&["vault", "export", "--plaintext"])
        .status
        .success());
    assert!(!env.vault.exists());
    let bad = env.root.path().join("invalid.json");
    fs::write(&bad, "not a backup").unwrap();
    assert!(!env
        .cli(&["vault", "import", bad.to_str().unwrap()])
        .status
        .success());
    assert!(!env.vault.exists());
}

#[test]
fn cli_replaces_corrupted_vault_and_merge_conflicts_exit_with_failure() {
    let env = Environment::new();
    fs::write(&env.vault, "{broken JSON").unwrap();
    let (path, _) = backup(&env, &sample_vault(), None);
    let restored = env.cli(&["vault", "import", path.to_str().unwrap(), "--replace"]);
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert!(String::from_utf8_lossy(&restored.stdout).contains("Recovery copy:"));
    let before = fs::read(&env.vault).unwrap();
    let merged = env.cli(&["vault", "import", path.to_str().unwrap(), "--merge"]);
    assert!(!merged.status.success());
    assert_eq!(fs::read(&env.vault).unwrap(), before);
    let skipped = env.cli(&[
        "vault",
        "import",
        path.to_str().unwrap(),
        "--merge",
        "--on-conflict",
        "skip",
    ]);
    assert!(skipped.status.success());
    assert!(String::from_utf8_lossy(&skipped.stdout).contains("2 skipped"));
}

#[test]
fn cli_confirms_before_restoring_plaintext_over_an_encrypted_vault() {
    let env = Environment::new();
    env.write_vault(&sample_vault(), Some(LOCAL_PASSWORD));
    let before = fs::read(&env.vault).unwrap();
    let (path, _) = backup(&env, &sample_vault(), None);
    let path = path.to_str().unwrap();
    // Stdin is closed, so the confirmation prompt reads no answer and declines.
    let declined = env.cli(&["vault", "import", path, "--replace"]);
    assert!(!declined.status.success());
    let stderr = String::from_utf8_lossy(&declined.stderr);
    assert!(stderr.contains("stored unencrypted"));
    assert!(stderr.contains("Import cancelled"));
    assert_eq!(fs::read(&env.vault).unwrap(), before);
    let confirmed = env.cli(&["vault", "import", path, "--replace", "--yes"]);
    assert!(
        confirmed.status.success(),
        "{}",
        String::from_utf8_lossy(&confirmed.stderr)
    );
    assert!(!VaultFile::read(&env.vault).unwrap().is_encrypted());
}

#[test]
fn cli_confirms_before_merging_an_encrypted_backup_into_a_plaintext_vault() {
    let env = Environment::new();
    env.write_vault(&sample_vault(), None);
    let before = fs::read(&env.vault).unwrap();
    let (path, _) = backup(&env, &Vault::new(), Some(BACKUP_PASSWORD));
    let declined = env.cli(&["vault", "import", path.to_str().unwrap(), "--merge"]);
    assert!(!declined.status.success());
    let stderr = String::from_utf8_lossy(&declined.stderr);
    assert!(stderr.contains("stored unencrypted"));
    assert!(stderr.contains("Import cancelled"));
    assert_eq!(fs::read(&env.vault).unwrap(), before);
}

#[test]
fn recorded_access_time_is_exported_and_replaced_by_a_restore() {
    let env = Environment::new();
    env.write_vault(&sample_vault(), None);
    Vault::set_vault_path(env.vault.clone()).unwrap();
    let mut accessed = Vault::load().unwrap();
    let recorded = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    accessed.last_accessed_at = recorded;
    accessed.record_access().unwrap();
    assert_eq!(
        VaultFile::read(&env.vault)
            .unwrap()
            .decode(None)
            .unwrap()
            .last_accessed_at,
        recorded
    );
    let interrupted = env
        .root
        .path()
        .join(".vault.dat.pre-import-20250101T000000.000000000Z.bak.keyrex-tmp-abc123");
    fs::write(&interrupted, "interrupted recovery copy").unwrap();
    let (path, document) = backup(&env, &sample_vault(), None);
    VaultFile::read(&env.vault)
        .unwrap()
        .import(
            &path,
            &document,
            None,
            ImportMode::Restore { replace: true },
            None,
        )
        .unwrap();
    assert!(!interrupted.exists());
    assert_eq!(
        Vault::load().unwrap().last_accessed_at,
        sample_vault().last_accessed_at
    );
    Vault::clear_vault_path_override();
}

#[test]
fn vault_with_an_invalid_legacy_entry_opens_and_export_names_the_entry() {
    let env = Environment::new();
    let legacy = r#"{"entries":{"blank":{"key":"blank","value":""}},"created_at":1700000000,"last_updated_at":1700000000,"last_accessed_at":1700000000}"#;
    fs::write(&env.vault, legacy).unwrap();
    let listed = env.cli(&["list"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let exported = env.cli(&["vault", "export", "out.json", "--plaintext"]);
    assert!(!exported.status.success());
    assert!(String::from_utf8_lossy(&exported.stderr).contains("entry \"blank\""));
    assert!(!env.root.path().join("out.json").exists());
}

#[cfg(unix)]
#[test]
fn backup_vault_and_recovery_files_have_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let env = Environment::new();
    env.write_vault(&sample_vault(), None);
    let (path, document) = backup(&env, &sample_vault(), None);
    let result = VaultFile::read(&env.vault)
        .unwrap()
        .import(
            &path,
            &document,
            None,
            ImportMode::Restore { replace: true },
            None,
        )
        .unwrap();
    for path in [path, env.vault, result.recovery_path.unwrap()] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_inputs_and_outputs_are_rejected_without_following_them() {
    use std::os::unix::fs::symlink;
    let env = Environment::new();
    let (path, document) = backup(&env, &sample_vault(), None);
    let alias = env.root.path().join("symlink.json");
    symlink(&path, &alias).unwrap();
    assert!(BackupDocument::read(&alias).is_err());
    assert!(document.write_new(&alias).is_err());
    assert!(BackupDocument::read(&path).is_ok());
}

#[cfg(unix)]
#[test]
fn symlinked_vault_is_restored_through_the_link() {
    use std::os::unix::fs::symlink;
    let env = Environment::new();
    let real = env.root.path().join("synced/vault.dat");
    fs::create_dir(env.root.path().join("synced")).unwrap();
    Vault::set_vault_path(real.clone()).unwrap();
    sample_vault().save().unwrap();
    Vault::clear_vault_path_override();
    symlink(&real, &env.vault).unwrap();
    let mut incoming = Vault::new();
    incoming
        .add_entry("restored".into(), "restored-value".into())
        .unwrap();
    let (path, document) = backup(&env, &incoming, None);
    let outcome = VaultFile::read(&env.vault)
        .unwrap()
        .import(
            &path,
            &document,
            None,
            ImportMode::Restore { replace: true },
            None,
        )
        .unwrap();
    assert!(fs::symlink_metadata(&env.vault)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        VaultFile::read(&real)
            .unwrap()
            .decode(None)
            .unwrap()
            .entries,
        incoming.entries
    );
    assert_eq!(
        outcome.recovery_path.unwrap().parent(),
        Some(env.root.path())
    );
}

#[test]
fn missing_parent_output_directory_is_created() {
    let env = Environment::new();
    let document = BackupDocument::from_vault(&sample_vault(), None).unwrap();
    let path = env.root.path().join("new/directory/backup.json");
    document.write_new(&path).unwrap();
    assert_snapshot(
        &BackupDocument::read(&path).unwrap().decode(None).unwrap(),
        &sample_vault(),
    );
}

#[test]
fn empty_backup_and_merge_into_missing_vault_are_supported() {
    let env = Environment::new();
    let (path, document) = backup(&env, &Vault::new(), None);
    let outcome = VaultFile::read(&env.vault)
        .unwrap()
        .import(&path, &document, None, merge(ConflictPolicy::Error), None)
        .unwrap();
    assert_eq!(outcome.added, 0);
    assert!(env.vault.exists());
    assert_eq!(
        VaultFile::read(&env.vault)
            .unwrap()
            .decode(None)
            .unwrap()
            .entry_count(),
        0
    );
}

#[test]
fn invalid_backup_password_does_not_modify_destination_or_create_recovery_copy() {
    let env = Environment::new();
    env.write_vault(&sample_vault(), None);
    let before = fs::read(&env.vault).unwrap();
    let (path, document) = backup(&env, &sample_vault(), Some(BACKUP_PASSWORD));
    assert!(VaultFile::read(&env.vault)
        .unwrap()
        .import(
            &path,
            &document,
            Some("Wrong-Password-123!"),
            ImportMode::Restore { replace: true },
            None
        )
        .is_err());
    assert_eq!(fs::read(&env.vault).unwrap(), before);
    assert!(!fs::read_dir(env.root.path())
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().contains("pre-import")));
}

#[test]
fn plaintext_export_accepts_legacy_entries_without_tags_and_checks_integrity() {
    let env = Environment::new();
    let legacy = r#"{"entries":{"legacy":{"key":"legacy","value":"legacy-secret"}},"created_at":1700000000,"last_updated_at":1700000000,"last_accessed_at":1700000000,"hmac":"6MKjC8aT2vmhUa5sr6SHgZegOdlnj3qsAkm1yG8EXYQ="}"#;
    fs::write(&env.vault, legacy).unwrap();
    let output = env.cli(&["vault", "export", "legacy.json", "--plaintext"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let restored = BackupDocument::read(&env.root.path().join("legacy.json"))
        .unwrap()
        .decode(None)
        .unwrap();
    assert!(restored.entries["legacy"].tags.is_empty());
    fs::write(
        &env.vault,
        legacy.replace("legacy-secret", "tampered-value"),
    )
    .unwrap();
    assert!(!env
        .cli(&["vault", "export", "tampered.json", "--plaintext"])
        .status
        .success());
    assert!(!env.root.path().join("tampered.json").exists());
}

#[cfg(unix)]
#[test]
fn failed_recovery_write_preserves_original_vault() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let env = Environment::new();
    // Root bypasses Unix mode bits; exercise this failure where permissions are enforced.
    if fs::metadata(env.root.path()).unwrap().uid() == 0 {
        return;
    }
    env.write_vault(&sample_vault(), None);
    let before = fs::read(&env.vault).unwrap();
    let (path, document) = backup(&env, &sample_vault(), None);
    let captured = VaultFile::read(&env.vault).unwrap();
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let result = captured.import(
        &path,
        &document,
        None,
        ImportMode::Restore { replace: true },
        None,
    );
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert_eq!(fs::read(&env.vault).unwrap(), before);
}
