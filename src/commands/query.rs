//! Query operations for searching and displaying vault information

use crate::vault::Vault;
use chrono::{DateTime, Local, Utc};
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
        format_local_timestamp(vault.created_at).bright_black()
    );
    println!(
        "  {} {}",
        "Last Updated:".bright_white().bold(),
        format_local_timestamp(vault.last_updated_at).bright_black()
    );
    println!(
        "  {} {}",
        "Last Accessed:".bright_white().bold(),
        format_local_timestamp(vault.last_accessed_at).bright_black()
    );
}

fn format_local_timestamp(timestamp: DateTime<Utc>) -> String {
    timestamp
        .with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

pub fn handle_keys(vault: &Vault) {
    // Output keys only, one per line, for shell completion
    for key in vault.entries.keys() {
        println!("{}", key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn format_local_timestamp_uses_system_timezone() {
        let timestamp = Utc.with_ymd_and_hms(2026, 5, 6, 12, 34, 56).unwrap();
        let expected = timestamp
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S %:z")
            .to_string();

        assert_eq!(format_local_timestamp(timestamp), expected);
    }

    #[test]
    fn format_local_timestamp_does_not_label_output_as_utc() {
        let timestamp = Utc.with_ymd_and_hms(2026, 5, 6, 12, 34, 56).unwrap();

        assert!(!format_local_timestamp(timestamp).ends_with(" UTC"));
    }
}
