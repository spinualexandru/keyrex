use clap::Parser;
use colored::Colorize;
use keyrex::cli::Cli;
use keyrex::commands::handle_command;
use keyrex::config;
use keyrex::crypto::{prompt_password, reset_attempts};
use keyrex::logging;
use keyrex::session;
use keyrex::vault::Vault;
use tracing::{debug, error, info};

fn main() {
    // Initialize structured logging
    logging::init();

    debug!("Starting KeyRex");
    let cli = Cli::parse();
    debug!(?cli, "Parsed CLI arguments");

    // Load configuration and set vault path
    match config::Config::load(cli.config.clone()) {
        Ok(vault_path) => {
            info!(path = %vault_path.display(), "Loaded vault configuration");
            if let Err(e) = Vault::set_vault_path(vault_path) {
                error!(error = %e, "Failed to set vault path");
                eprintln!(
                    "{}",
                    format!("✗ Failed to set vault path: {}", e).red().bold()
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to load configuration");
            eprintln!(
                "{}",
                format!("✗ Failed to load configuration: {}", e)
                    .red()
                    .bold()
            );
            std::process::exit(1);
        }
    }

    let vault_exists = match Vault::check_vault_exists() {
        Ok(exists) => {
            debug!(exists, "Checked vault existence");
            exists
        }
        Err(e) => {
            error!(error = %e, "Failed to check vault existence");
            eprintln!("{}", format!("✗ Failed to check vault: {}", e).red().bold());
            std::process::exit(1);
        }
    };

    let is_encrypted = vault_exists
        && match Vault::is_encrypted() {
            Ok(encrypted) => {
                debug!(encrypted, "Checked encryption status");
                encrypted
            }
            Err(e) => {
                error!(error = %e, "Failed to check encryption status");
                eprintln!(
                    "{}",
                    format!("✗ Failed to check encryption status: {}", e)
                        .red()
                        .bold()
                );
                std::process::exit(1);
            }
        };

    let mut vault = if is_encrypted {
        info!("Loading encrypted vault");
        match prompt_password("Enter vault password: ") {
            Ok(mut password) => {
                // Try to load and decrypt vault
                let result = Vault::load_encrypted(&password);

                match result {
                    Ok(v) => {
                        info!("Successfully decrypted vault");
                        // Reset attempt counter on successful decryption
                        reset_attempts();
                        // Store password for this session (password is moved, no need to zeroize)
                        session::store_password(password);
                        v
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to decrypt vault");
                        // Zeroize password on failure
                        use zeroize::Zeroize;
                        password.zeroize();
                        eprintln!(
                            "{}",
                            format!("✗ Failed to decrypt vault: {}", e).red().bold()
                        );
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to read password");
                eprintln!(
                    "{}",
                    format!("✗ Failed to read password: {}", e).red().bold()
                );
                std::process::exit(1);
            }
        }
    } else {
        debug!("Loading unencrypted vault");
        match Vault::load() {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "Failed to load vault");
                eprintln!("{}", format!("✗ Failed to load vault: {}", e).red().bold());
                std::process::exit(1);
            }
        }
    };

    if !vault_exists {
        info!("Initializing new vault");
        println!("{}", "✓ Initialized new vault".green().bold());
        match vault.save() {
            Ok(_) => debug!("New vault saved successfully"),
            Err(e) => {
                error!(error = %e, "Failed to save new vault");
                eprintln!("{}", format!("✗ Failed to save vault: {}", e).red().bold());
                std::process::exit(1);
            }
        }
    }

    debug!("Dispatching command");
    handle_command(cli.command, &mut vault, is_encrypted);
    debug!("Command completed successfully");
}
