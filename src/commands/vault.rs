//! Vault transfer commands run before normal vault loading or initialization.

use crate::backup::{self, BackupDocument, BackupError, ImportMode, VaultFile};
use crate::cli::VaultCommand;
use crate::crypto;
use crate::output;
use crate::vault::Vault;
use colored::Colorize;
use secrecy::{ExposeSecret, SecretString};

fn password(prompt: &str, confirm: bool) -> Result<SecretString, BackupError> {
    let password = if confirm {
        crypto::prompt_password_with_confirmation(prompt)?
    } else {
        crypto::prompt_password(prompt)?
    };
    Ok(SecretString::new(password.into_boxed_str()))
}

pub fn handle_vault_command(command: VaultCommand) -> Result<(), BackupError> {
    let vault_path = Vault::get_user_vault_path()?;
    match command {
        VaultCommand::Export { path, plaintext } => {
            let source = VaultFile::read(&vault_path)?;
            if !source.exists() {
                return Err(BackupError::SourceMissing);
            }
            let source_password = if source.is_encrypted() {
                Some(password("Enter vault password: ", false)?)
            } else {
                None
            };
            let vault = source.decode(source_password.as_ref().map(ExposeSecret::expose_secret))?;
            let backup_password = if plaintext {
                None
            } else {
                Some(password("Enter backup password: ", true)?)
            };
            let document = BackupDocument::from_vault(
                &vault,
                backup_password.as_ref().map(ExposeSecret::expose_secret),
            )?;
            let path = path.unwrap_or_else(backup::default_export_path);
            source.export(&path, &document)?;
            let protection = if plaintext { "plaintext" } else { "encrypted" };
            println!(
                "{}",
                format!(
                    "✓ Exported {} entries to {} ({})",
                    vault.entry_count(),
                    path.display(),
                    protection
                )
                .green()
                .bold()
            );
            if plaintext {
                eprintln!(
                    "{}",
                    "This backup contains readable secret values.".yellow()
                );
            }
        }
        VaultCommand::Import {
            path,
            replace,
            merge,
            on_conflict,
            yes,
        } => {
            let document = BackupDocument::read(&path)?;
            let destination = VaultFile::read(&vault_path)?;
            if destination.exists() && !merge && !replace {
                return Err(BackupError::DestinationExists);
            }
            let mode = if merge {
                ImportMode::Merge { on_conflict }
            } else {
                ImportMode::Restore { replace }
            };
            if destination.exposes_encrypted_secrets(&document, mode) && !yes {
                let warning = if merge {
                    "⚠ The backup is encrypted but the local vault is not: merged secrets will be stored unencrypted."
                } else {
                    "⚠ The current vault is encrypted but this backup is not: the restored vault will be stored unencrypted."
                };
                eprintln!("{}", warning.yellow().bold());
                // Fail rather than exit 0, so a script never mistakes this for a restore.
                if !output::confirm("Continue? [y/N]")? {
                    return Err(BackupError::Cancelled);
                }
            }
            let previous_plaintext = destination.exists() && !destination.is_encrypted();
            let backup_password = if document.is_encrypted() {
                Some(password("Enter backup password: ", false)?)
            } else {
                None
            };
            let vault_password = if merge && destination.is_encrypted() {
                Some(password("Enter local vault password: ", false)?)
            } else {
                None
            };
            let outcome = destination.import(
                &path,
                &document,
                backup_password.as_ref().map(ExposeSecret::expose_secret),
                mode,
                vault_password.as_ref().map(ExposeSecret::expose_secret),
            )?;
            if merge {
                println!(
                    "{}",
                    format!(
                        "✓ Merge complete: {} added, {} overwritten, {} unchanged, {} skipped",
                        outcome.added, outcome.overwritten, outcome.unchanged, outcome.skipped
                    )
                    .green()
                    .bold()
                );
                if !outcome.changed {
                    println!("Vault unchanged.");
                }
            } else {
                let protection = if outcome.encrypted {
                    "encrypted; uses the backup password"
                } else {
                    "plaintext"
                };
                println!(
                    "{}",
                    format!(
                        "✓ Restored {} entries to {} ({})",
                        outcome.added,
                        vault_path.display(),
                        protection
                    )
                    .green()
                    .bold()
                );
            }
            if let Some(path) = outcome.recovery_path {
                println!("Recovery copy: {}", path.display());
                if previous_plaintext && outcome.encrypted {
                    eprintln!(
                        "{}",
                        "⚠ The recovery copy holds your previous vault unencrypted. Delete it once you have checked the import."
                            .yellow()
                            .bold()
                    );
                } else {
                    println!("It holds the previous vault; delete it once you no longer need it.");
                }
            }
        }
    }
    Ok(())
}
