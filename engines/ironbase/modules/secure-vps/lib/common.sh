#!/bin/bash

# modules/secure-vps/lib/common.sh
# Shared logic and data models for secure-vps module

# --- Colors & Styles ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_BOLD='\033[1m'

# --- Enums ---
TYPE_MISCONFIG="Misconfiguration"
TYPE_RISK="Risk Exposure"
TYPE_VULN="Vulnerability"

ORIGIN_INTERNAL="Internal"
ORIGIN_EXTERNAL="External"

SEV_INFO="INFO"
SEV_LOW="LOW"
SEV_MEDIUM="MEDIUM"
SEV_HIGH="HIGH"
SEV_CRITICAL="CRITICAL"

# --- Load Dependencies ---
# Determine module root if not set, or assume relative sourcing
# NOTE: Callers (main.sh/standalone.sh) should set MODULE_ROOT ideally.
if [[ -z "$MODULE_ROOT" ]]; then
    # Fallback for direct sourcing
    MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

# Source Output Logic and Baseline
source "$MODULE_ROOT/lib/output.sh"
source "$MODULE_ROOT/lib/baseline.sh"

# --- Functions ---

# Function: vps_log
# Usage: vps_log "INFO|ERROR" "Message"
vps_log() {
    local level="$1"
    local msg="$2"
    # Optional: Log to file too? For now console debug.
    # echo "[$level] $msg" >> "$LOG_FILE"
    echo -e "${C_BLUE}[${level}]${C_RESET} ${msg}" >&2
}

# Function: add_vps_finding
# Wrapper that calls the output printer
add_vps_finding() {
    print_finding "$@"
}
