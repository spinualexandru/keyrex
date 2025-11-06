# Bash completion for keyrex
# Source this file or add to ~/.bashrc

_keyrex_complete() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main commands
    local commands="add get update remove list search info clear encrypt decrypt completions help"

    # If we're completing the first argument (subcommand)
    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    # Get the subcommand
    local subcommand="${COMP_WORDS[1]}"

    # For get, update, and remove commands, complete with vault keys
    case "${subcommand}" in
        get|update|remove)
            if [ $COMP_CWORD -eq 2 ]; then
                local keys=$(keyrex keys 2>/dev/null)
                COMPREPLY=( $(compgen -W "${keys}" -- ${cur}) )
                return 0
            fi
            ;;
        list)
            local opts="--values --sort -v -s --help -h"
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
        search)
            local opts="--values -v --help -h"
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
        clear|remove)
            local opts="--yes -y --help -h"
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
        completions)
            if [ $COMP_CWORD -eq 2 ]; then
                local shells="bash fish zsh powershell elvish"
                COMPREPLY=( $(compgen -W "${shells}" -- ${cur}) )
                return 0
            fi
            ;;
    esac
}

complete -F _keyrex_complete keyrex
