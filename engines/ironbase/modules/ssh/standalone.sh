#!/bin/bash
# modules/ssh/standalone.sh
# Standalone runner for SSH Hardening

# Resolve strictly absolute path to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export MODULE_ROOT="$SCRIPT_DIR"

# Colors
export C_RED='\033[0;31m'
export C_GREEN='\033[0;32m'
export C_YELLOW='\033[0;33m'
export C_BLUE='\033[0;34m'
export C_BOLD='\033[1m'
export C_RESET='\033[0m'

# Helpers
export LOG_FILE="ssh-scan.log"
vps_log() {
    echo "[$1] $2" >> "$LOG_FILE"
}

add_vps_finding() {
    local id="$1"
    local sev="$2"
    local type="$3"
    local origin="$4"
    local cat="$5"
    local title="$6"
    local desc="$7"
    local evidence="$8"
    local rec="$9"
    
    echo -e "${C_RED}[$sev] $title ($id)${C_RESET}"
    echo "  $desc"
    echo "  Rec: $rec"
    echo ""
}

# --- Parse Args ---
MODE="scan"
for arg in "$@"; do
    case $arg in
        --force)
            export IRONBASE_FORCE="true"
            ;;
        apply)
            MODE="apply"
            ;;
    esac
done

if [[ "$MODE" == "scan" ]]; then
    # Load and run Scanner
    source "$SCRIPT_DIR/scanners/ssh.sh"
    echo "Starting SSH Scan..."
    scan_ssh
    echo "Scan complete. Log: $LOG_FILE"
    echo "To remediate, run: $0 apply"

elif [[ "$MODE" == "apply" ]]; then
    # Run Apply Wizard
    export VPS_APPLY_LOG="ssh-apply.log"
    
    # We need wizard.sh and basic helpers (log_apply, backup_file are in wizard.sh fallback or defined here)
    # Define helpers here to be safe and consistent with IronBase style
    log_apply() {
        local status="$1"
        local msg="$2"
        echo "[$status] $msg" >> "$VPS_APPLY_LOG"
    }

    backup_file() {
        local file="$1"
        local backup="${file}.bak.$(date +%s)"
        if [[ -f "$file" ]]; then
            cp "$file" "$backup"
            log_apply "INFO" "Backed up $file to $backup"
            echo -e "${C_BLUE}Backed up $file to $backup${C_RESET}"
        fi
    }
    
    # Init Log
    echo "IronBase SSH Hardening" > "$VPS_APPLY_LOG"
    
    # Header
    if [[ "$IRONBASE_FORCE" == "true" ]]; then
         echo -e "${C_RED}${C_BOLD}FORCE MODE ACTIVE${C_RESET}"
    else
         echo -e "${C_BOLD}Starting Interactive SSH Hardening${C_RESET}"
    fi

    # Load Wizard
    source "$SCRIPT_DIR/lib/wizard.sh"
    
    # Verify INT-SSH-001 status first? Or just run wizard?
    # Wizard internally checks state. But usually we only run fix if finding exists.
    # For standalone wizard tool, we just run the wizard.
    apply_fix_ssh_root

    echo -e "\n${C_BOLD}Done.${C_RESET}"
fi
