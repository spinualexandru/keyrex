//! Query operations for searching and displaying vault information

use crate::vault::Vault;
use colored::Colorize;

pub fn handle_list(vault: &Vault, values: bool, sort: bool) {
    let count = vault.entry_count();
    if count == 0 {
        println!("{}", "The KeyRex vault is empty.".yellow());
        return;
    }

    let mut entries = vault.list_entries();
    if sort {
        entries.sort_by(|a, b| a.key.cmp(&b.key));
    }

    for entry in entries {
        if values {
            println!(
                "{} => {}",
                entry.key.to_string().cyan().bold(),
                entry.value.green().bold()
            );
        } else {
            println!("  {}", entry.key.cyan());
        }
    }
}

pub fn handle_search(vault: &Vault, pattern: String, values: bool) {
    let results = vault.search_entries(&pattern);

    if results.is_empty() {
        println!(
            "{}",
            format!("No entries found matching '{}'", pattern).yellow()
        );
        return;
    }

    println!(
        "{}",
        format!("Found {} matching entries:", results.len())
            .cyan()
            .bold()
    );
    println!();

    for entry in results {
        if values {
            println!(
                "  {} {}",
                format!("{}:", entry.key).cyan().bold(),
                entry.value.bright_white()
            );
        } else {
            println!("  {}", entry.key.cyan());
        }
    }
}

pub fn handle_info(vault: &Vault, is_encrypted: bool) {
    let count = vault.entry_count();
    println!("{}", "Vault Information".cyan().bold().underline());
    println!();

    let vault_path = match Vault::get_user_vault_path() {
        Ok(path) => path.display().to_string(),
        Err(e) => format!("Error: {}", e),
    };

    println!(
        "  {} {}",
        "Location:".bright_white().bold(),
        vault_path.bright_black()
    );
    println!(
        "  {} {}",
        "Encrypted:".bright_white().bold(),
        if is_encrypted {
            "Yes (AES-256-GCM)".green().bold()
        } else {
            "No".yellow()
        }
    );
    println!(
        "  {} {}",
        "Entries:".bright_white().bold(),
        count.to_string().cyan().bold()
    );
    println!(
        "  {} {}",
        "Created:".bright_white().bold(),
        vault
            .created_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string()
            .bright_black()
    );
    println!(
        "  {} {}",
        "Last Updated:".bright_white().bold(),
        vault
            .last_updated_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string()
            .bright_black()
    );
    println!(
        "  {} {}",
        "Last Accessed:".bright_white().bold(),
        vault
            .last_accessed_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string()
            .bright_black()
    );
}

pub fn handle_keys(vault: &Vault) {
    // Output keys only, one per line, for shell completion
    for key in vault.entries.keys() {
        println!("{}", key);
    }
}
