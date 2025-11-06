//! CRUD (Create, Read, Update, Delete) operations for vault entries

use crate::output;
use crate::security;
use crate::session;
use crate::vault::Vault;
use arboard::Clipboard;
use colored::Colorize;

pub fn handle_add(vault: &mut Vault, key: String, value: String, is_encrypted: bool) {
    // Check file permissions before CRUD operation
    if let Ok(path) = Vault::get_user_vault_path() {
        security::check_file_permissions_warn(&path);
    }
    if vault.entries.contains_key(&key) {
        eprintln!(
            "{}",
            format!(
                "✗ Entry '{}' already exists. Use 'update' to modify it.",
                key
            )
            .red()
            .bold()
        );
        std::process::exit(1);
    }

    match vault.add_entry(key.clone(), value) {
        Ok(()) => {
            session::save_vault(vault, is_encrypted);
            println!("{}", format!("✓ Added entry '{}'", key).green().bold());
        }
        Err(e) => {
            eprintln!("{}", format!("✗ Failed to add entry: {}", e).red().bold());
            std::process::exit(1);
        }
    }
}

pub fn handle_get(vault: &mut Vault, key: String, copy: bool, is_encrypted: bool) {
    // Check file permissions before CRUD operation
    if let Ok(path) = Vault::get_user_vault_path() {
        security::check_file_permissions_warn(&path);
    }
    if let Some(entry) = vault.get_entry(&key) {
        if copy {
            match Clipboard::new() {
                Ok(mut clipboard) => {
                    match clipboard.set_text(entry.value.clone()) {
                        Ok(_) => {
                            println!("{}", "✓ Value copied to clipboard".green().bold());
                            session::save_vault(vault, is_encrypted); // Save to update last_accessed_at
                            return; // Exit without printing value (secure)
                        }
                        Err(e) => {
                            eprintln!(
                                "{}",
                                format!("✗ Failed to copy to clipboard: {}", e).red().bold()
                            );
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("✗ Clipboard not available: {}", e).red().bold()
                    );
                    std::process::exit(1);
                }
            }
        }
        println!("{}", entry.value);
        session::save_vault(vault, is_encrypted); // Save to update last_accessed_at
    } else {
        eprintln!("{}", format!("✗ Entry '{}' not found", key).red().bold());
        std::process::exit(1);
    }
}

pub fn handle_update(vault: &mut Vault, key: String, value: String, is_encrypted: bool) {
    // Check file permissions before CRUD operation
    if let Ok(path) = Vault::get_user_vault_path() {
        security::check_file_permissions_warn(&path);
    }

    match vault.update_entry(&key, value) {
        Ok(()) => {
            session::save_vault(vault, is_encrypted);
            println!("{}", format!("✓ Updated entry '{}'", key).green().bold());
        }
        Err(e) => {
            eprintln!("{}", format!("✗ {}", e).red().bold());
            std::process::exit(1);
        }
    }
}

pub fn handle_remove(vault: &mut Vault, key: String, yes: bool, is_encrypted: bool) {
    // Check file permissions before CRUD operation
    if let Ok(path) = Vault::get_user_vault_path() {
        security::check_file_permissions_warn(&path);
    }
    if !vault.entries.contains_key(&key) {
        eprintln!("{}", format!("✗ Entry '{}' not found", key).red().bold());
        std::process::exit(1);
    }

    if !yes {
        match output::confirm(&format!("Remove entry '{}'? [y/N]", key)) {
            Ok(true) => {}
            Ok(false) => {
                println!("{}", "Cancelled.".yellow());
                return;
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    format!("✗ Failed to read confirmation: {}", e).red().bold()
                );
                std::process::exit(1);
            }
        }
    }

    vault.remove_entry(&key);
    session::save_vault(vault, is_encrypted);
    println!("{}", format!("✓ Removed entry '{}'", key).green().bold());
}
