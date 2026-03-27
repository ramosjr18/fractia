#!/bin/bash

# modules/ssh/lib/common.sh
# Shared logic and data models for ssh module

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
# MODULE_ROOT should be set by caller (main.sh), but provide fallback
if [[ -z "$MODULE_ROOT" ]]; then
    # Fallback: calculate from common.sh location
    MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    export MODULE_ROOT
fi

# Source Output Logic
if [[ -f "$MODULE_ROOT/lib/output.sh" ]]; then
    source "$MODULE_ROOT/lib/output.sh"
else
    echo "Error: output.sh not found at $MODULE_ROOT/lib/output.sh" >&2
    return 1
fi

# --- Functions ---

# Function: vps_log
# Usage: vps_log "INFO|ERROR" "Message"
vps_log() {
    local level="$1"
    local msg="$2"
    echo -e "${C_BLUE}[${level}]${C_RESET} ${msg}" >&2
}

# Function: add_vps_finding
# Wrapper that calls the output printer
add_vps_finding() {
    print_finding "$@"
}
