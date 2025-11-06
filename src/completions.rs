//! Shell completion generation and installation instructions
//!
//! This module handles generating shell completion scripts and providing
//! shell-specific installation instructions for bash, fish, zsh, PowerShell, and elvish.

use crate::cli::Cli;
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use colored::Colorize;
use std::io;

/// Generate shell completions and print installation instructions
pub fn handle_completions(shell: Shell) {
    let mut cmd = Cli::command();
    let bin_name = "keyrex";

    eprintln!(
        "{}",
        format!("Generating {} completions for '{}'...", shell, bin_name)
            .cyan()
            .bold()
    );

    generate(shell, &mut cmd, bin_name, &mut io::stdout());

    eprintln!();
    eprintln!("{}", "Installation instructions:".green().bold());

    print_completion_instructions(shell);
}

fn print_completion_instructions(shell: Shell) {
    match shell {
        Shell::Bash => print_bash_instructions(),
        Shell::Fish => print_fish_instructions(),
        Shell::Zsh => print_zsh_instructions(),
        Shell::PowerShell => print_powershell_instructions(),
        Shell::Elvish => print_elvish_instructions(),
        _ => {}
    }
}

fn print_bash_instructions() {
    eprintln!("  Add this to your {}:", "~/.bashrc".cyan());
    eprintln!(
        "    {}",
        "eval \"$(keyrex completions bash)\"".bright_black()
    );
    eprintln!("  Or save to file:");
    eprintln!(
        "    {}",
        "keyrex completions bash > ~/.local/share/bash-completion/completions/keyrex"
            .bright_black()
    );
    eprintln!();
    eprintln!(
        "{}",
        "For dynamic key completion, also add:".yellow().bold()
    );
    eprintln!("    {}", "_keyrex_complete_keys() {".bright_black());
    eprintln!(
        "    {}",
        "        COMPREPLY=($(compgen -W \"$(keyrex keys 2>/dev/null)\" -- \"${COMP_WORDS[COMP_CWORD]}\"))"
            .bright_black()
    );
    eprintln!("    {}", "    }".bright_black());
    eprintln!(
        "    {}",
        "    complete -F _keyrex_complete_keys -o default keyrex".bright_black()
    );
}

fn print_fish_instructions() {
    eprintln!("  Save to fish completions directory:");
    eprintln!(
        "    {}",
        "keyrex completions fish > ~/.config/fish/completions/keyrex.fish".bright_black()
    );
    eprintln!();
    eprintln!(
        "{}",
        "For dynamic key completion, create this file:"
            .yellow()
            .bold()
    );
    eprintln!("  {}:", "~/.config/fish/completions/keyrex.fish".cyan());
    eprintln!();
    eprintln!(
        "    {}",
        "# Complete keyrex keys for get, update, and remove commands".bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from get' -a '(keyrex keys 2>/dev/null)'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from update' -a '(keyrex keys 2>/dev/null)'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from remove' -a '(keyrex keys 2>/dev/null)'"
            .bright_black()
    );
    eprintln!();
    eprintln!("    {}", "# Standard completions".bright_black());
    eprintln!("    {}", "complete -c keyrex -f".bright_black());
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_use_subcommand' -a 'add' -d 'Add a new entry to the vault'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_use_subcommand' -a 'get' -d 'Get an entry from the vault'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_use_subcommand' -a 'update' -d 'Update an existing entry'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_use_subcommand' -a 'remove' -d 'Remove an entry from the vault'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_use_subcommand' -a 'list' -d 'List all entries'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_use_subcommand' -a 'search' -d 'Search for entries'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_use_subcommand' -a 'info' -d 'Show vault information'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_use_subcommand' -a 'clear' -d 'Clear all entries'"
            .bright_black()
    );
    eprintln!();
    eprintln!("    {}", "# Options for specific commands".bright_black());
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from get' -s c -l copy -d 'Copy value to clipboard'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from remove' -s y -l yes -d 'Skip confirmation'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from list' -s v -l values -d 'Show values'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from list' -s s -l sort -d 'Sort alphabetically'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from search' -s v -l values -d 'Show values'"
            .bright_black()
    );
    eprintln!(
        "    {}",
        "complete -c keyrex -n '__fish_seen_subcommand_from clear' -s y -l yes -d 'Skip confirmation'"
            .bright_black()
    );
}

fn print_zsh_instructions() {
    eprintln!("  Add this to your {}:", "~/.zshrc".cyan());
    eprintln!(
        "    {}",
        "eval \"$(keyrex completions zsh)\"".bright_black()
    );
    eprintln!("  Or save to a directory in your $fpath:");
    eprintln!(
        "    {}",
        "keyrex completions zsh > /usr/local/share/zsh/site-functions/_keyrex".bright_black()
    );
    eprintln!();
    eprintln!(
        "{}",
        "For dynamic key completion, also add:".yellow().bold()
    );
    eprintln!(
        "    {}",
        "_keyrex_keys() { _values 'keys' $(keyrex keys 2>/dev/null) }".bright_black()
    );
    eprintln!(
        "    {}",
        "    compdef _keyrex_keys keyrex get update remove".bright_black()
    );
}

fn print_powershell_instructions() {
    eprintln!("  Add this to your PowerShell profile:");
    eprintln!(
        "    {}",
        "keyrex completions powershell | Out-String | Invoke-Expression".bright_black()
    );
}

fn print_elvish_instructions() {
    eprintln!("  Save to elvish completions directory:");
    eprintln!(
        "    {}",
        "keyrex completions elvish > ~/.config/elvish/lib/keyrex.elv".bright_black()
    );
}
