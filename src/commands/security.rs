//! Security operations for vault encryption and decryption

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
