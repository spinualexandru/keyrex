//! Tag membership and tag query commands.

use crate::cli::{TagArgs, TagCommand};
use crate::session;
use crate::vault::{Vault, VaultError};
use colored::Colorize;

pub fn handle_tag(vault: &mut Vault, args: TagArgs, is_encrypted: bool) {
    match run_tag(vault, args) {
        Ok(Some((changed, message))) => {
            if changed {
                session::save_vault(vault, is_encrypted);
            }
            println!("{}", format!("✓ {}", message).green().bold());
        }
        Ok(None) => {}
        Err(error) => {
            eprintln!("{}", format!("✗ {}", error).red().bold());
            std::process::exit(1);
        }
    }
}

fn run_tag(vault: &mut Vault, args: TagArgs) -> Result<Option<(bool, String)>, VaultError> {
    if let Some(command) = args.command {
        let (changed, message) = match command {
            TagCommand::Rename { old, new } => {
                let count = vault.rename_tag(&old, &new)?;
                (
                    count > 0,
                    format!("Renamed tag '{}' to '{}' on {} entries", old, new, count),
                )
            }
            TagCommand::Remove { tag } => {
                let count = vault.remove_tag(&tag)?;
                (
                    count > 0,
                    format!("Removed tag '{}' from {} entries", tag, count),
                )
            }
        };
        return Ok(Some((changed, message)));
    }

    if args.list {
        let tags = vault.list_tags();
        if tags.is_empty() {
            println!("No tags found.");
        }
        for tag in tags {
            println!("{}", tag);
        }
        return Ok(None);
    }

    let name = args
        .name
        .expect("clap requires a name unless listing tags or using a subcommand");
    if args.remove {
        let changed = vault.untag_entry(&name, args.tag.as_deref())?;
        let message = match args.tag {
            Some(tag) => format!("Removed tag '{}' from '{}'", tag, name),
            None => format!("Removed all tags from '{}'", name),
        };
        return Ok(Some((changed, message)));
    }
    if let Some(tag) = args.tag {
        let changed = vault.tag_entry(&name, &tag, args.replace)?;
        let message = if args.replace {
            format!("Replaced tags on '{}' with '{}'", name, tag)
        } else {
            format!("Tagged '{}' with '{}'", name, tag)
        };
        return Ok(Some((changed, message)));
    }

    let entries = vault.entries_with_tag(&name)?;
    if entries.is_empty() {
        println!("No entries found with tag '{}'.", name);
    }
    for entry in entries {
        if args.include_keys {
            println!(
                "{} => {}",
                entry.key.cyan().bold(),
                entry.value.green().bold()
            );
        } else {
            println!("{}", entry.key);
        }
    }
    Ok(None)
}
