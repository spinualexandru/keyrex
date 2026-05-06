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
    print_dynamic_key_completion(shell);

    eprintln!();
    eprintln!("{}", "Installation instructions:".green().bold());

    print_completion_instructions(shell);
}

fn print_dynamic_key_completion(shell: Shell) {
    match shell {
        Shell::Bash => print_bash_dynamic_key_completion(),
        Shell::Fish => print_fish_dynamic_key_completion(),
        Shell::Zsh => print_zsh_dynamic_key_completion(),
        _ => {}
    }
}

fn print_bash_dynamic_key_completion() {
    println!(
        "{}",
        r#"

# Dynamic KeyRex key completion for get, update, and remove.
_keyrex_complete_keys_command() {
    local -a keyrex_args=()
    local i=1

    while [[ $i -lt $COMP_CWORD ]]; do
        case "${COMP_WORDS[$i]}" in
            --config)
                if [[ $((i + 1)) -lt $COMP_CWORD ]]; then
                    keyrex_args+=("--config" "${COMP_WORDS[$((i + 1))]}")
                    i=$((i + 2))
                    continue
                fi
                ;;
            --config=*)
                keyrex_args+=("${COMP_WORDS[$i]}")
                ;;
        esac
        i=$((i + 1))
    done

    command keyrex "${keyrex_args[@]}" keys 2>/dev/null
}

_keyrex_complete_with_keys() {
    local cur subcommand key
    local subcommand_index=0
    local i=1
    cur="${COMP_WORDS[COMP_CWORD]}"

    while [[ $i -lt $COMP_CWORD ]]; do
        case "${COMP_WORDS[$i]}" in
            --config)
                i=$((i + 2))
                continue
                ;;
            --config=*)
                i=$((i + 1))
                continue
                ;;
            -*)
                i=$((i + 1))
                continue
                ;;
            *)
                subcommand="${COMP_WORDS[$i]}"
                subcommand_index=$i
                break
                ;;
        esac
    done

    case "$subcommand" in
        get|update|remove)
            if [[ $COMP_CWORD -eq $((subcommand_index + 1)) ]]; then
                COMPREPLY=()
                while IFS= read -r key; do
                    [[ "$key" == "$cur"* ]] && COMPREPLY+=("$key")
                done < <(_keyrex_complete_keys_command)
                return 0
            fi
            ;;
    esac

    _keyrex "$@"
}

complete -F _keyrex_complete_with_keys -o bashdefault -o default keyrex
"#
    );
}

fn print_fish_dynamic_key_completion() {
    println!(
        "{}",
        r#"

# Dynamic KeyRex key completion for get, update, and remove.
function __keyrex_complete_keys
    set -l tokens (commandline -opc)
    set -l keyrex_args
    set -l i 1

    while test $i -le (count $tokens)
        switch $tokens[$i]
            case --config
                set -l next (math $i + 1)
                if test $next -le (count $tokens)
                    set -a keyrex_args --config $tokens[$next]
                    set i (math $i + 2)
                    continue
                end
            case '--config=*'
                set -a keyrex_args $tokens[$i]
        end
        set i (math $i + 1)
    end

    command keyrex $keyrex_args keys 2>/dev/null
end

complete -c keyrex -n '__fish_seen_subcommand_from get update remove' -f -a '(__keyrex_complete_keys)'
"#
    );
}

fn print_zsh_dynamic_key_completion() {
    println!(
        "{}",
        r#"

# Dynamic KeyRex key completion for get, update, and remove.
_keyrex_complete_keys_command() {
    local -a keyrex_args keys
    local -i i=2

    while (( i < CURRENT )); do
        case "${words[$i]}" in
            --config)
                if (( i + 1 < CURRENT )); then
                    keyrex_args+=(--config "${words[$((i + 1))]}")
                    (( i += 2 ))
                    continue
                fi
                ;;
            --config=*)
                keyrex_args+=("${words[$i]}")
                ;;
        esac
        (( i++ ))
    done

    keys=("${(@f)$(command keyrex "${keyrex_args[@]}" keys 2>/dev/null)}")
    compadd -a keys
}

_keyrex_complete_with_keys() {
    local subcommand
    local -i subcommand_index=0
    local -i i=2

    while (( i < CURRENT )); do
        case "${words[$i]}" in
            --config)
                (( i += 2 ))
                continue
                ;;
            --config=*)
                (( i++ ))
                continue
                ;;
            -*)
                (( i++ ))
                continue
                ;;
            *)
                subcommand="${words[$i]}"
                subcommand_index=$i
                break
                ;;
        esac
    done

    case "$subcommand" in
        get|update|remove)
            if (( CURRENT == subcommand_index + 1 )); then
                _keyrex_complete_keys_command
                return
            fi
            ;;
    esac

    _keyrex "$@"
}

compdef _keyrex_complete_with_keys keyrex
"#
    );
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
        "Dynamic key completion is included for get, update, and remove.".yellow()
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
        "Dynamic key completion is included for get, update, and remove.".yellow()
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
        "Dynamic key completion is included for get, update, and remove.".yellow()
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
