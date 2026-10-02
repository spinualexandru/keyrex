//! Security operations for vault encryption and decryption

use crate::backup;
use crate::crypto;
use crate::output;
use crate::vault::Vault;
use colored::Colorize;

pub fn handle_encrypt(vault: &Vault, is_encrypted: bool) {
    if is_encrypted {
        println!("{}", "✓ Vault is already encrypted".green().bold());
        return;
    }

    println!(
        "{}",
        "Enabling encryption on vault with AES-256-GCM"
            .cyan()
            .bold()
    );
    println!();

    match crypto::prompt_password_with_confirmation("Enter new password: ") {
        Ok(mut password) => {
            if password.is_empty() {
                eprintln!("{}", "✗ Password cannot be empty".red().bold());
                // Zeroize empty password before exiting
                use zeroize::Zeroize;
                password.zeroize();
                std::process::exit(1);
            }

            let result = vault.save_encrypted(&password);
            // Zeroize password immediately after use
            use zeroize::Zeroize;
            password.zeroize();

            if let Err(e) = result {
                eprintln!(
                    "{}",
                    format!("✗ Failed to encrypt vault: {}", e).red().bold()
                );
                std::process::exit(1);
            }

            println!("{}", "✓ Vault encrypted successfully".green().bold());
            println!(
                "{}",
                "⚠ Remember your password! There is no way to recover it if lost."
                    .yellow()
                    .bold()
            );
            warn_plaintext_recovery_copies();
        }
        Err(e) => {
            eprintln!(
                "{}",
                format!("✗ Failed to read password: {}", e).red().bold()
            );
            std::process::exit(1);
        }
    }
}

pub fn handle_decrypt(vault: &Vault, is_encrypted: bool) {
    if !is_encrypted {
        println!("{}", "✓ Vault is already decrypted".green().bold());
        return;
    }

    println!(
        "{}",
        "Disabling encryption on vault (storing as plain JSON)"
            .cyan()
            .bold()
    );
    println!();

    match output::confirm("Are you sure you want to disable encryption? [y/N]") {
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

    match vault.save() {
        Ok(_) => {
            println!("{}", "✓ Vault decrypted successfully".green().bold());
        }
        Err(e) => {
            eprintln!("{}", format!("✗ Failed to save vault: {}", e).red().bold());
            std::process::exit(1);
        }
    }
    println!(
        "{}",
        "⚠ KeyRex Vault is now stored as plain text JSON"
            .yellow()
            .bold()
    );
}

/// Earlier imports may have left unencrypted copies of the vault beside it.
fn warn_plaintext_recovery_copies() {
    let copies = Vault::get_user_vault_path()
        .ok()
        .and_then(|path| backup::plaintext_recovery_copies(&path).ok())
        .unwrap_or_default();
    if copies.is_empty() {
        return;
    }
    eprintln!(
        "{}",
        "⚠ These import recovery copies still hold unencrypted secrets; delete them once you no longer need them:"
            .yellow()
            .bold()
    );
    for copy in copies {
        eprintln!("  {}", copy.display());
    }
}
