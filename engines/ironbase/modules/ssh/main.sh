#!/bin/bash
# modules/ssh/main.sh
# Integration Entrypoint

module_meta() {
    echo "Name: SSH Hardening"
    echo "Description: Hardens SSH configuration interactively with wizard."
    echo "Version: 2.0.0"
}

module_scan() {
    local script_dir="$(dirname "${BASH_SOURCE[0]}")"
    
    # Load module dependencies (constants and functions)
    export MODULE_ROOT="$script_dir"
    source "$script_dir/lib/common.sh"
    
    # Initialize log file
    init_log_file
    
    # Load and run scanner
    source "$script_dir/scanners/ssh.sh"
    scan_ssh
    
    # Print summary and determine exit code
    print_summary
    return $?
}

module_apply() {
    local script_dir="$(dirname "${BASH_SOURCE[0]}")"
    
    # Load module dependencies (constants and colors for wizard)
    export MODULE_ROOT="$script_dir"
    source "$script_dir/lib/common.sh"
    
    # Re-use wizard
    source "$script_dir/lib/wizard.sh"
    
    # We assume IronBase core provides helpers (log_apply/backup_file) or wizard falls back
    # But usually core/engine.sh sets up environment.
    # The SSH wizard expects 'apply_fix_ssh_root' to be called.
    
    echo -e "${C_BOLD}Running SSH Hardening Module${C_RESET}"
    apply_fix_ssh_root
}
