//! Tag lifecycle coverage using isolated vaults and real CLI subprocesses.

mod common;

use clap::Parser;
use common::TestEnvironment;
use keyrex::cli::Cli;
use keyrex::vault::{Vault, VaultError};
use std::fs;
use std::process::Command;

fn run(env: &TestEnvironment, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_keyrex"))
        .arg("--config")
        .arg(&env.config_path)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn loaded(env: &TestEnvironment) -> Vault {
    env.set_as_vault_path().unwrap();
    Vault::load().unwrap()
}

#[test]
fn tag_cli_lifecycle_and_secret_visibility() {
    let env = TestEnvironment::new("tag_cli_lifecycle");
    run(&env, &["add", "mistral", "mistral-secret"]);
    run(&env, &["add", "anthropic", "anthropic-secret"]);
    run(&env, &["tag", "mistral", "ai"]);
    let before = fs::read(&env.vault_path).unwrap();
    run(&env, &["tag", "mistral", "ai"]);
    assert_eq!(
        fs::read(&env.vault_path).unwrap(),
        before,
        "Duplicate tags must be a no-op"
    );
    run(&env, &["tag", "mistral", "europe"]);
    run(&env, &["tag", "anthropic", "ai"]);
    assert_eq!(run(&env, &["tag", "--list"]), "ai\neurope\n");
    assert_eq!(run(&env, &["tag", "ai"]), "anthropic\nmistral\n");
    assert_eq!(
        run(&env, &["tag", "ai", "--include-keys"]),
        "anthropic => anthropic-secret\nmistral => mistral-secret\n"
    );
    assert_eq!(loaded(&env).entries["mistral"].tags.len(), 2);

    run(&env, &["tag", "mistral", "europe", "--replace"]);
    assert_eq!(run(&env, &["tag", "ai"]), "anthropic\n");
    assert_eq!(loaded(&env).entries["mistral"].tags.len(), 1);
    run(&env, &["tag", "mistral", "ai"]);
    run(&env, &["tag", "mistral", "ai", "--remove"]);
    assert_eq!(run(&env, &["tag", "ai"]), "anthropic\n");
    assert_eq!(run(&env, &["tag", "europe"]), "mistral\n");
    run(&env, &["tag", "mistral", "--remove"]);
    assert!(loaded(&env).entries["mistral"].tags.is_empty());
    assert_eq!(run(&env, &["tag", "--list"]), "ai\n");

    run(&env, &["tag", "mistral", "aii"]);
    run(&env, &["tag", "anthropic", "aii"]);
    run(&env, &["tag", "rename", "aii", "ai"]);
    let vault = loaded(&env);
    assert_eq!(vault.list_tags().into_iter().collect::<Vec<_>>(), ["ai"]);
    assert!(vault.entries.values().all(|e| e.tags.len() == 1));
    run(&env, &["update", "mistral", "rotated-secret"]);
    assert_eq!(
        run(&env, &["tag", "ai", "--include-keys"]),
        "anthropic => anthropic-secret\nmistral => rotated-secret\n"
    );
    run(&env, &["tag", "remove", "ai"]);
    let vault = loaded(&env);
    assert!(vault.entries.values().all(|e| e.tags.is_empty()));
    assert_eq!(vault.entry_count(), 2);
    assert_eq!(vault.entries["mistral"].value, "rotated-secret");
    assert_eq!(run(&env, &["tag", "--list"]), "No tags found.\n");

    run(&env, &["tag", "mistral", "europe"]);
    run(&env, &["remove", "mistral", "--yes"]);
    assert!(loaded(&env).list_tags().is_empty());
    run(&env, &["tag", "anthropic", "ai"]);
    run(&env, &["clear", "--yes"]);
    assert!(loaded(&env).list_tags().is_empty());
}

#[test]
fn tag_names_with_spaces_unicode_and_reserved_commands() {
    let env = TestEnvironment::new("tag_names");
    run(&env, &["add", "rename", "hidden-secret"]);
    run(&env, &["tag", "--", "rename", "équipe europe"]);
    assert_eq!(run(&env, &["tag", "équipe europe"]), "rename\n");
    run(&env, &["tag", "rename", "équipe europe", "remove"]);
    assert_eq!(run(&env, &["tag", "--", "remove"]), "rename\n");
    assert!(run(&env, &["tag", "REMOVE"]).contains("No entries found"));
    run(&env, &["tag", "--remove", "--", "rename", "remove"]);
    assert!(loaded(&env).list_tags().is_empty());
}

#[test]
fn tag_failures_leave_vault_unchanged() {
    let env = TestEnvironment::new("tag_failures");
    run(&env, &["add", "mistral", "hidden-secret"]);
    run(&env, &["tag", "mistral", "ai"]);
    let before = fs::read(&env.vault_path).unwrap();
    for args in [
        vec!["tag", "missing", "ai"],
        vec!["tag", "missing", "--remove"],
        vec!["tag", "mistral", "", "--replace"],
        vec!["tag", "mistral", "   "],
        vec!["tag", "mistral", "bad\ntag"],
        vec!["tag", "rename", "ai", "\t"],
        vec!["tag", "rename", "missing", "ai"],
        vec!["tag", "--list", "ai"],
        vec!["tag", "mistral", "--replace"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_keyrex"))
            .arg("--config")
            .arg(&env.config_path)
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("hidden-secret"));
        assert_eq!(fs::read(&env.vault_path).unwrap(), before, "{args:?}");
    }
}

#[test]
fn tag_validation_and_noop_timestamps() {
    let mut vault = Vault::new();
    vault.add_entry("mistral".into(), "secret".into()).unwrap();
    vault.tag_entry("mistral", "ai", false).unwrap();
    let timestamp = vault.last_updated_at;
    assert!(!vault.tag_entry("mistral", "ai", false).unwrap());
    assert!(!vault.tag_entry("mistral", "ai", true).unwrap());
    assert!(!vault.untag_entry("mistral", Some("missing")).unwrap());
    assert_eq!(vault.rename_tag("ai", "ai").unwrap(), 0);
    assert_eq!(vault.remove_tag("missing").unwrap(), 0);
    assert_eq!(vault.last_updated_at, timestamp);
    for tag in [
        "".to_string(),
        " ".into(),
        "bad\0tag".into(),
        "x".repeat(257),
    ] {
        assert!(vault.tag_entry("mistral", &tag, true).is_err());
        assert!(vault.rename_tag("ai", &tag).is_err());
        assert!(vault.remove_tag(&tag).is_err());
        assert!(vault.untag_entry("mistral", Some(&tag)).is_err());
        assert!(vault.entries_with_tag(&tag).is_err());
    }
    assert_eq!(vault.last_updated_at, timestamp);
    assert_eq!(vault.entries_with_tag("ai").unwrap().len(), 1);
    vault.add_entry("mistral".into(), "updated".into()).unwrap();
    assert_eq!(vault.entries_with_tag("ai").unwrap()[0].value, "updated");
    vault.tag_entry("mistral", &"x".repeat(256), false).unwrap();
}

#[test]
fn legacy_vault_checksum_and_tag_integrity() {
    let env = TestEnvironment::new("tag_legacy_checksum");
    // Fixture from the original key/value-only format, including its v1 checksum.
    let legacy = r#"{"entries":{"legacy":{"key":"legacy","value":"legacy-secret"}},"created_at":1700000000,"last_updated_at":1700000000,"last_accessed_at":1700000000,"hmac":"6MKjC8aT2vmhUa5sr6SHgZegOdlnj3qsAkm1yG8EXYQ="}"#;
    fs::write(&env.vault_path, legacy).unwrap();
    let mut vault = loaded(&env);
    assert!(vault.entries["legacy"].tags.is_empty());
    vault.tag_entry("legacy", "ai", false).unwrap();
    vault.save().unwrap();
    assert_eq!(loaded(&env).entries_with_tag("ai").unwrap().len(), 1);
    let mut data: serde_json::Value =
        serde_json::from_slice(&fs::read(&env.vault_path).unwrap()).unwrap();
    data["entries"]["legacy"]["tags"] = serde_json::json!(["tampered"]);
    fs::write(&env.vault_path, serde_json::to_vec(&data).unwrap()).unwrap();
    assert!(matches!(
        Vault::load(),
        Err(VaultError::IntegrityCheckFailed)
    ));
}

#[test]
fn encrypted_vault_from_previous_dependencies_remains_readable() {
    let env = TestEnvironment::new("tag_legacy_encryption");
    env.set_as_vault_path().unwrap();
    // Generated before the upgrade with aes-gcm 0.10.3, base64 0.22.1,
    // a random salt/nonce, and the test harness's 1,000 PBKDF2 rounds.
    fs::write(
        &env.vault_path,
        include_str!("fixtures/aes-gcm-0.10.3-vault.enc"),
    )
    .unwrap();
    let password = "Legacy-Vault-Password-123!";
    let mut vault = Vault::load_encrypted(password).unwrap();
    assert_eq!(vault.entries["legacy"].value, "legacy-secret");
    assert!(vault.entries["legacy"].tags.is_empty());
    vault.tag_entry("legacy", "ai", false).unwrap();
    vault.save_encrypted(password).unwrap();
    let loaded = Vault::load_encrypted(password).unwrap();
    assert_eq!(
        loaded.entries_with_tag("ai").unwrap()[0].value,
        "legacy-secret"
    );
}

#[test]
fn encrypted_tag_commands_preserve_encryption_and_memberships() {
    let env = TestEnvironment::new("tag_encrypted");
    env.set_as_vault_path().unwrap();
    let password = "TagTest-Password-123!";
    keyrex::session::store_password(password.into());
    let mut vault = Vault::new();
    vault
        .add_entry("mistral".into(), "hidden-secret".into())
        .unwrap();
    vault.save_encrypted(password).unwrap();
    for (args, expected) in [
        (vec!["tag", "mistral", "aii"], vec!["aii"]),
        (vec!["tag", "mistral", "europe"], vec!["aii", "europe"]),
        (vec!["tag", "rename", "aii", "ai"], vec!["ai", "europe"]),
        (vec!["tag", "mistral", "ai", "--replace"], vec!["ai"]),
        (vec!["tag", "remove", "ai"], vec![]),
    ] {
        let mut vault = Vault::load_encrypted(password).unwrap();
        let cli = Cli::parse_from(std::iter::once("keyrex").chain(args));
        keyrex::commands::handle_command(cli.command, &mut vault, true);
        assert!(Vault::is_encrypted().unwrap());
        assert!(!fs::read_to_string(&env.vault_path)
            .unwrap()
            .contains("hidden-secret"));
        let loaded = Vault::load_encrypted(password).unwrap();
        assert_eq!(loaded.list_tags().into_iter().collect::<Vec<_>>(), expected);
        assert_eq!(loaded.entries["mistral"].value, "hidden-secret");
    }
}
