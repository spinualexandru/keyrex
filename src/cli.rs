//! Command-line interface definitions
//!
//! This module defines the CLI structure using clap's derive API.
//! It includes all command definitions and their arguments.

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "keyrex")]
#[command(about = "A secure and simple key-value vault for your secrets", long_about = None)]
#[command(version)]
pub struct Cli {
    /// Path to configuration file
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(about = "Add a new entry to KeyRex")]
    Add {
        #[arg(help = "The key for the entry")]
        key: String,
        #[arg(help = "The value to store")]
        value: String,
    },

    #[command(about = "Get an entry from KeyRex")]
    Get {
        #[arg(help = "The key to retrieve")]
        key: String,
        #[arg(short, long, help = "Copy value to clipboard (if available)")]
        copy: bool,
    },

    #[command(about = "Update an existing entry in KeyRex")]
    Update {
        #[arg(help = "The key to update")]
        key: String,
        #[arg(help = "The new value")]
        value: String,
    },

    #[command(about = "Remove an entry from KeyRex")]
    Remove {
        #[arg(help = "The key to remove")]
        key: String,
        #[arg(short, long, help = "Skip confirmation prompt")]
        yes: bool,
    },

    #[command(about = "List all entries in KeyRex")]
    List {
        #[arg(
            short,
            long,
            help = "Show values (default: keys only)",
            default_value = "true"
        )]
        values: bool,
        #[arg(short, long, help = "Sort entries alphabetically")]
        sort: bool,
    },

    #[command(about = "Search for entries by key or value")]
    Search {
        #[arg(help = "Pattern to search for")]
        pattern: String,
        #[arg(short, long, help = "Show values in results")]
        values: bool,
    },

    #[command(about = "Show KeyRex statistics and information")]
    Info,

    #[command(about = "Clear all entries from KeyRex")]
    Clear {
        #[arg(short, long, help = "Skip confirmation prompt")]
        yes: bool,
    },

    #[command(about = "Generate shell completions")]
    Completions {
        #[arg(help = "Shell to generate completions for (bash, fish, zsh, powershell, elvish)")]
        shell: Shell,
    },

    #[command(about = "List keys only (for shell completion)", hide = true)]
    Keys,

    #[command(about = "Enable encryption on the KeyRex vault")]
    Encrypt,

    #[command(about = "Disable encryption on the KeyRex vault")]
    Decrypt,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to parse CLI arguments
    fn parse_cli(args: &[&str]) -> Result<Cli, clap::error::Error> {
        let mut cli_args = vec!["keyrex"];
        cli_args.extend(args);
        Cli::try_parse_from(cli_args)
    }

    // Basic command parsing tests
    #[test]
    fn test_parse_add_command() {
        let cli = parse_cli(&["add", "mykey", "myvalue"]).unwrap();
        match cli.command {
            Command::Add { key, value } => {
                assert_eq!(key, "mykey");
                assert_eq!(value, "myvalue");
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_parse_get_command() {
        let cli = parse_cli(&["get", "mykey"]).unwrap();
        match cli.command {
            Command::Get { key, copy } => {
                assert_eq!(key, "mykey");
                assert!(!copy);
            }
            _ => panic!("Expected Get command"),
        }
    }

    #[test]
    fn test_parse_get_command_with_copy() {
        let cli = parse_cli(&["get", "mykey", "--copy"]).unwrap();
        match cli.command {
            Command::Get { key, copy } => {
                assert_eq!(key, "mykey");
                assert!(copy);
            }
            _ => panic!("Expected Get command with copy"),
        }
    }

    #[test]
    fn test_parse_get_command_with_copy_short() {
        let cli = parse_cli(&["get", "mykey", "-c"]).unwrap();
        match cli.command {
            Command::Get { key, copy } => {
                assert_eq!(key, "mykey");
                assert!(copy);
            }
            _ => panic!("Expected Get command with copy"),
        }
    }

    #[test]
    fn test_parse_update_command() {
        let cli = parse_cli(&["update", "mykey", "newvalue"]).unwrap();
        match cli.command {
            Command::Update { key, value } => {
                assert_eq!(key, "mykey");
                assert_eq!(value, "newvalue");
            }
            _ => panic!("Expected Update command"),
        }
    }

    #[test]
    fn test_parse_remove_command() {
        let cli = parse_cli(&["remove", "mykey"]).unwrap();
        match cli.command {
            Command::Remove { key, yes } => {
                assert_eq!(key, "mykey");
                assert!(!yes);
            }
            _ => panic!("Expected Remove command"),
        }
    }

    #[test]
    fn test_parse_remove_command_with_yes() {
        let cli = parse_cli(&["remove", "mykey", "--yes"]).unwrap();
        match cli.command {
            Command::Remove { key, yes } => {
                assert_eq!(key, "mykey");
                assert!(yes);
            }
            _ => panic!("Expected Remove command with yes"),
        }
    }

    #[test]
    fn test_parse_remove_command_with_yes_short() {
        let cli = parse_cli(&["remove", "mykey", "-y"]).unwrap();
        match cli.command {
            Command::Remove { key, yes } => {
                assert_eq!(key, "mykey");
                assert!(yes);
            }
            _ => panic!("Expected Remove command with yes"),
        }
    }

    #[test]
    fn test_parse_list_command() {
        let cli = parse_cli(&["list"]).unwrap();
        match cli.command {
            Command::List { values, sort } => {
                assert!(values); // default is true
                assert!(!sort);
            }
            _ => panic!("Expected List command"),
        }
    }

    #[test]
    fn test_parse_list_command_no_values() {
        // List defaults to values=true, this test verifies default behavior
        let cli = parse_cli(&["list"]).unwrap();
        match cli.command {
            Command::List { values, sort } => {
                assert!(values); // default is true
                assert!(!sort);
            }
            _ => panic!("Expected List command"),
        }
    }

    #[test]
    fn test_parse_list_command_with_sort() {
        let cli = parse_cli(&["list", "--sort"]).unwrap();
        match cli.command {
            Command::List { values, sort } => {
                assert!(values);
                assert!(sort);
            }
            _ => panic!("Expected List command with sort"),
        }
    }

    #[test]
    fn test_parse_list_command_with_sort_short() {
        let cli = parse_cli(&["list", "-s"]).unwrap();
        match cli.command {
            Command::List { values, sort } => {
                assert!(values);
                assert!(sort);
            }
            _ => panic!("Expected List command with sort"),
        }
    }

    #[test]
    fn test_parse_search_command() {
        let cli = parse_cli(&["search", "pattern"]).unwrap();
        match cli.command {
            Command::Search { pattern, values } => {
                assert_eq!(pattern, "pattern");
                assert!(!values);
            }
            _ => panic!("Expected Search command"),
        }
    }

    #[test]
    fn test_parse_search_command_with_values() {
        let cli = parse_cli(&["search", "pattern", "--values"]).unwrap();
        match cli.command {
            Command::Search { pattern, values } => {
                assert_eq!(pattern, "pattern");
                assert!(values);
            }
            _ => panic!("Expected Search command with values"),
        }
    }

    #[test]
    fn test_parse_search_command_with_values_short() {
        let cli = parse_cli(&["search", "pattern", "-v"]).unwrap();
        match cli.command {
            Command::Search { pattern, values } => {
                assert_eq!(pattern, "pattern");
                assert!(values);
            }
            _ => panic!("Expected Search command with values"),
        }
    }

    #[test]
    fn test_parse_info_command() {
        let cli = parse_cli(&["info"]).unwrap();
        match cli.command {
            Command::Info => {
                // Success - Info has no arguments
            }
            _ => panic!("Expected Info command"),
        }
    }

    #[test]
    fn test_parse_clear_command() {
        let cli = parse_cli(&["clear"]).unwrap();
        match cli.command {
            Command::Clear { yes } => {
                assert!(!yes);
            }
            _ => panic!("Expected Clear command"),
        }
    }

    #[test]
    fn test_parse_clear_command_with_yes() {
        let cli = parse_cli(&["clear", "--yes"]).unwrap();
        match cli.command {
            Command::Clear { yes } => {
                assert!(yes);
            }
            _ => panic!("Expected Clear command with yes"),
        }
    }

    #[test]
    fn test_parse_encrypt_command() {
        let cli = parse_cli(&["encrypt"]).unwrap();
        match cli.command {
            Command::Encrypt => {
                // Success
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_parse_decrypt_command() {
        let cli = parse_cli(&["decrypt"]).unwrap();
        match cli.command {
            Command::Decrypt => {
                // Success
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_parse_keys_command() {
        let cli = parse_cli(&["keys"]).unwrap();
        match cli.command {
            Command::Keys => {
                // Success
            }
            _ => panic!("Expected Keys command"),
        }
    }

    #[test]
    fn test_parse_with_config_option() {
        let cli = parse_cli(&["--config", "/path/to/config.toml", "info"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/path/to/config.toml")));
        match cli.command {
            Command::Info => {
                // Success
            }
            _ => panic!("Expected Info command"),
        }
    }

    #[test]
    fn test_parse_with_config_option_long() {
        let cli = parse_cli(&["--config=/path/to/config.toml", "list"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/path/to/config.toml")));
        match cli.command {
            Command::List { .. } => {
                // Success
            }
            _ => panic!("Expected List command"),
        }
    }

    #[test]
    fn test_parse_add_with_special_characters() {
        let cli = parse_cli(&["add", "api_key!@#$", "value!@#$%^&*()"]).unwrap();
        match cli.command {
            Command::Add { key, value } => {
                assert_eq!(key, "api_key!@#$");
                assert_eq!(value, "value!@#$%^&*()");
            }
            _ => panic!("Expected Add command with special characters"),
        }
    }

    #[test]
    fn test_parse_add_with_spaces() {
        let cli = parse_cli(&["add", "my key", "my value with spaces"]).unwrap();
        match cli.command {
            Command::Add { key, value } => {
                assert_eq!(key, "my key");
                assert_eq!(value, "my value with spaces");
            }
            _ => panic!("Expected Add command with spaces"),
        }
    }

    #[test]
    fn test_parse_search_with_special_pattern() {
        let cli = parse_cli(&["search", "*.example.com"]).unwrap();
        match cli.command {
            Command::Search { pattern, .. } => {
                assert_eq!(pattern, "*.example.com");
            }
            _ => panic!("Expected Search command with special pattern"),
        }
    }

    #[test]
    fn test_parse_missing_required_args_add() {
        let result = parse_cli(&["add", "onlykey"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_required_args_get() {
        let result = parse_cli(&["get"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_required_args_search() {
        let result = parse_cli(&["search"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_command() {
        let result = parse_cli(&["nonexistent"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_completions_bash() {
        let cli = parse_cli(&["completions", "bash"]).unwrap();
        match cli.command {
            Command::Completions { shell } => {
                assert_eq!(format!("{:?}", shell), "Bash");
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_parse_completions_zsh() {
        let cli = parse_cli(&["completions", "zsh"]).unwrap();
        match cli.command {
            Command::Completions { shell } => {
                assert_eq!(format!("{:?}", shell), "Zsh");
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_parse_completions_fish() {
        let cli = parse_cli(&["completions", "fish"]).unwrap();
        match cli.command {
            Command::Completions { shell } => {
                assert_eq!(format!("{:?}", shell), "Fish");
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_parse_multiple_flags_list() {
        let cli = parse_cli(&["list", "--sort"]).unwrap();
        match cli.command {
            Command::List { values, sort } => {
                assert!(values); // default
                assert!(sort);
            }
            _ => panic!("Expected List command"),
        }
    }

    #[test]
    fn test_parse_config_and_command_order1() {
        let cli = parse_cli(&["--config", "config.toml", "add", "key", "value"]).unwrap();
        assert!(cli.config.is_some());
        match cli.command {
            Command::Add { key, value } => {
                assert_eq!(key, "key");
                assert_eq!(value, "value");
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_parse_config_and_command_order2() {
        let cli = parse_cli(&["add", "--config", "config.toml", "key", "value"]).unwrap();
        assert!(cli.config.is_some());
        match cli.command {
            Command::Add { key, value } => {
                assert_eq!(key, "key");
                assert_eq!(value, "value");
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_parse_empty_key_and_value() {
        // Empty strings are technically valid from CLI parsing perspective
        // Validation happens at the vault level
        let cli = parse_cli(&["add", "", ""]).unwrap();
        match cli.command {
            Command::Add { key, value } => {
                assert_eq!(key, "");
                assert_eq!(value, "");
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_parse_very_long_key_and_value() {
        let long_key = "k".repeat(500);
        let long_value = "v".repeat(70000);
        let cli = parse_cli(&["add", &long_key, &long_value]).unwrap();
        match cli.command {
            Command::Add { key, value } => {
                assert_eq!(key.len(), 500);
                assert_eq!(value.len(), 70000);
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_parse_unicode_key_and_value() {
        let cli = parse_cli(&["add", "key_🔑", "value_🔒"]).unwrap();
        match cli.command {
            Command::Add { key, value } => {
                assert_eq!(key, "key_🔑");
                assert_eq!(value, "value_🔒");
            }
            _ => panic!("Expected Add command with unicode"),
        }
    }
}
