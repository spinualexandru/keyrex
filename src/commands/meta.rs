//! Meta operations for vault management (clear, etc.)

use crate::output;
use crate::session;
use crate::vault::Vault;
use chrono::Utc;
use colored::Colorize;

pub fn handle_clear(vault: &mut Vault, yes: bool, is_encrypted: bool) {
    let count = vault.entry_count();
    if count == 0 {
        println!("{}", "Vault is already empty.".yellow());
        return;
    }

    if !yes {
        match output::confirm(&format!("Clear all {} entries? [y/N]", count)) {
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

    vault.entries.clear();
    vault.last_updated_at = Utc::now();
    session::save_vault(vault, is_encrypted);
    println!("{}", format!("✓ Cleared {} entries", count).green().bold());
}
