#!/bin/bash

# modules/secure-vps/lib/apply.sh
# Handles interactive remediation

# Use run directory if available, otherwise fallback to current directory
# Defensive: ensure IRONBASE_RUN_DIR is a valid directory before using it
if [[ -n "$IRONBASE_RUN_DIR" ]] && [[ -d "$IRONBASE_RUN_DIR" ]] && [[ "$IRONBASE_RUN_DIR" != "/" ]]; then
    APPLY_LOG="${VPS_APPLY_LOG:-$IRONBASE_RUN_DIR/secure-vps-apply.log}"
else
    # Fallback to legacy paths or current directory (standalone mode)
    APPLY_LOG="${VPS_APPLY_LOG:-secure-vps-apply.log}"
fi

# --- Utility Functions ---

init_apply_log() {
    echo "IronBase - Secure VPS Remediation Log" > "$APPLY_LOG"
    echo "Date: $(date)" >> "$APPLY_LOG"
    echo "Hostname: $(hostname)" >> "$APPLY_LOG"
    echo "-------------------------------------" >> "$APPLY_LOG"
}

log_apply() {
    local status="$1" # [INFO], [SUCCESS], [SKIP], [ERROR]
    local msg="$2"
    echo "[$status] $msg" >> "$APPLY_LOG"
}

# Prompt user with Yes/No/Skip
# Returns 0 for Yes, 1 for No/Skip
confirm_action() {
    local prompt="$1"
    local default="${2:-N}" # Default to N for safety

    local options="[y/N]"
    if [[ "$default" == "Y" ]]; then options="[Y/n]"; fi

    read -p "$(echo -e "${C_YELLOW}$prompt $options${C_RESET} "): " response < /dev/tty
    response=${response:-$default}

    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Backup a file before modifying
backup_file() {
    local file="$1"
    local backup="${file}.bak.$(date +%s)"
    if [[ -f "$file" ]]; then
        cp "$file" "$backup"
        log_apply "INFO" "Backed up $file to $backup"
        echo -e "${C_BLUE}Backed up $file to $backup${C_RESET}"
    fi
}

# --- Specific Remediations ---

# --- Specific Remediations ---

echo -e "\n${C_BOLD}>>> Finding: SSH Root Login Enabled (INT-SSH-001)${C_RESET}"

# --- Shared Logic ---
SOURCE_DIR="$(dirname "${BASH_SOURCE[0]}")/../../ssh/lib"
if [[ -f "$SOURCE_DIR/wizard.sh" ]]; then
    source "$SOURCE_DIR/wizard.sh"
else
    log_apply "ERROR" "CRITICAL: Shared SSH wizard not found at $SOURCE_DIR/wizard.sh"
    echo -e "${C_RED}Error: Shared SSH wizard not found.${C_RESET}"
    # Define dummy to prevent crash if file missing
    apply_fix_ssh_root() { echo "Error: SSH Wizard missing."; }
fi

apply_fix_critical_ports() {
    echo -e "\n${C_BOLD}>>> Finding: Critical Internal Services Exposed (INT-NET-002)${C_RESET}"
    # Re-scan to find them alive
    if ! command -v ss &> /dev/null; then echo "Warning: 'ss' not found. Skipping."; return; fi
    
    # This regex must match the one in internal.sh/baseline.sh
    # Redis, Postgres, MySQL, Mongo, Elastic, Docker
    local ports_crit="^(6379|543[0-9]|3306|27017|9200|237[0-9])$"
    local raw_all=$(ss -lntu | awk '$5 !~ /^127\.0\.0\.1/ && $5 !~ /^\[::1\]/ && NR>1 {print $0}')
    local raw_critical=""
    local raw_unclassified=""

    # Split Critical vs Other
    while read -r line; do
        local port=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}')
        if [[ "$port" =~ $ports_crit ]]; then
            raw_critical+="${line}\n"
        else
            # Filter out Expected ports (Web/VoIP) to just find "Unclassified"
            local ports_expected="^(80|443|3478|7880|7881|22)$"
            if [[ ! "$port" =~ $ports_expected ]]; then
                raw_unclassified+="${line}\n"
            fi
        fi
    done <<< "$raw_all"

    # Split Critical vs Other
    # Collect Critical RAW lines only first
    while read -r line; do
        local port=$(echo "$line" | awk '{print $5}' | awk -F: '{print $NF}')
        if [[ "$port" =~ $ports_crit ]]; then
            raw_critical+="${line}\n"
        else
            # Filter out Expected ports (Web/VoIP) to just find "Unclassified"
            local ports_expected="^(80|443|3478|7880|7881|22)$"
            if [[ ! "$port" =~ $ports_expected ]]; then
                raw_unclassified+="${line}\n"
            fi
        fi
    done <<< "$raw_all"

    # Handle Critical (Deduplicated Logic)
    if [[ -n "$raw_critical" && "$raw_critical" != "\n" ]]; then
        # 1. Extract Unique Ports
        local ports_unique=$(echo -e "$raw_critical" | awk '{print $5}' | awk -F: '{print $NF}' | sort -u)
        
        # 2. Iterate per Logic Port
        for port in $ports_unique; do
            [[ -z "$port" ]] && continue
            
            echo -e "\n${C_RED}${C_BOLD}>>> Critical Exposure Detected: Port $port${C_RESET}"
            
            # Show all evidence for this port
            local evidence=$(echo -e "$raw_critical" | grep ":$port")
            echo "Evidence:"
            echo "$evidence"

            # Try to identify process (just once per port, usually sufficient context)
            local proc_info=""
            if [[ $EUID -eq 0 ]]; then
                proc_info=$(ss -lntp | grep ":$port" | head -n 1 | awk '{print $6}')
                echo "Process (Primary): $proc_info"
            else
                echo "(Process name hidden: Run as root to see)"
            fi

            # Context-aware messaging
            case "$port" in
                6379)
                    echo -e "\n${C_YELLOW}Context: Redis (likely Coolify/Docker)${C_RESET}"
                    echo " Recommendation: Block public access via firewall."
                    ;;
                5432|5433)
                    echo -e "\n${C_YELLOW}Context: PostgreSQL Database${C_RESET}"
                    echo " Recommendation: Block public access via firewall."
                    ;;
                2377)
                    echo -e "\n${C_RED}${C_BOLD}CRITICAL CONTEXT: Docker Swarm Management${C_RESET}"
                    echo " Recommendation: Block public access via firewall IMMEDIATELY."
                    ;;
                *)
                    echo -e "\n${C_YELLOW}Context: Critical Service${C_RESET}"
                    ;;
            esac

            # Action Prompt
            if [[ "$IRONBASE_FORCE" == "true" ]]; then
                 echo -e "\n${C_RED}${C_BOLD}FORCE MODE: Applying UFW Block Automatically${C_RESET}"
                 choice="1"
            else
                 echo -e "\n${C_BOLD}Options:${C_RESET}"
                 echo "1) Block public access via UFW (Recommended - Safe)"
                 echo "2) Skip"
                 read -p "Choose action [1/2]: " choice < /dev/tty
            fi
            
            case "$choice" in
                1)
                    if command -v ufw &> /dev/null; then
                        echo "Executing: ufw deny $port"
                        ufw deny "$port" >/dev/null
                        log_apply "SUCCESS" "UFW denied port $port (Force=$IRONBASE_FORCE)"
                        echo -e "${C_GREEN}Port $port blocked via UFW.${C_RESET}"
                    else
                        echo -e "${C_RED}Error: UFW not found.${C_RESET}"
                        log_apply "ERROR" "UFW not found for port $port"
                    fi
                    ;;
                *)
                    log_apply "SKIP" "Skipped port $port"
                    echo "Skipping."
                    ;;
            esac
        done
    else
        echo "No Critical internal services exposed."
    fi

    # Handle Unclassified (INT-NET-001) - NO AUTO FIX EVEN IN FORCE MODE (As per rule: "NO aplicar fixes a findings sin remedicion definida")
    if [[ -n "$raw_unclassified" && "$raw_unclassified" != "\n" ]]; then
        echo -e "\n${C_YELLOW}${C_BOLD}>>> Unclassified Services (INT-NET-001)${C_RESET}"
        echo "The following services are exposed but unclassified:"
        echo -e "$raw_unclassified"
        echo -e "${C_BOLD}Action: Manual Review Required.${C_RESET}"
        echo "These services require manual verification. No auto-fixes will be applied."
        log_apply "INFO" "Unclassified services listed for manual review."
    fi
}

# apply_fix_writable_path Removed as per policy.

# --- Main Apply Loop ---

run_apply() {
    init_apply_log
    
    if [[ "$IRONBASE_FORCE" == "true" ]]; then
        echo -e "\n${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!                  EMERGENCY HARDENING MODE (FORCE)                  !${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
        echo -e "${C_RED}WARNING: You have requested to FORCE apply all security fixes.${C_RESET}"
        echo -e "${C_RED}This will:${C_RESET}"
        echo -e "${C_RED}  - DISABLE internal safety locks (SSH root login check, etc.)${C_RESET}"
        echo -e "${C_RED}  - MODIFY critical configurations.${C_RESET}"
        echo -e "${C_RED}  - POTENTIALLY disrupt production services or SSH access.${C_RESET}"
        echo -e ""
        echo -e "This action is potentially disruptive and should only be used in emergencies"
        echo -e "or if you have console access/recovery options."
        echo -e ""
        echo -e "This will APPLY ALL security fixes without further confirmation."
        echo -e "Do you want to continue? (y/N): "
        
        read -p "Confirm FORCE execution (y/N): " force_confirm < /dev/tty
        if [[ ! "$force_confirm" =~ ^[Yy]$ ]]; then
            echo "Aborting Force Mode."
            log_apply "ABORT" "User aborted Force Mode at warning screen."
            return 1
        fi
        
        log_apply "FORCE_START" "User confirmed Force Mode execution."
        echo -e "${C_BOLD}>>> STARTING FORCED HARDENING <<<${C_RESET}"
    else
        # Normal Mode Header
        echo -e "${C_BOLD}Starting Interactive Remediation${C_RESET}"
        echo -e "${C_YELLOW}WARNING: You are about to modify system configurations.${C_RESET}"
        echo -e "This tool will prompt for confirmation before every action."
    fi

    echo -e "A log will be saved to: $APPLY_LOG"
    echo ""

    # 1. Critical Ports Fix (Highest Priority)
    # Order changed as requested: Firewall/Network first.
    apply_fix_critical_ports

    # 2. SSH Root Fix
    apply_fix_ssh_root

    # 3. (Removed) Writable Path Fix
    # Users check manual report for INT-SYS-003

    echo ""
    echo "-------------------------------------"
    if [[ "$IRONBASE_FORCE" == "true" ]]; then
        echo -e "${C_RED}${C_BOLD}Forced Hardening Complete.${C_RESET}"
        echo "Mode: FORCE | Log saved at: $APPLY_LOG"
    else
        echo -e "${C_BOLD}Remediation Complete.${C_RESET}"
        echo "Please review $APPLY_LOG"
    fi
}
