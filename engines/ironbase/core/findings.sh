#!/bin/bash

# core/findings.sh
# Defines the finding model and output functions.

# Severities
SEV_INFO="INFO"
SEV_LOW="LOW"
SEV_MEDIUM="MEDIUM"
SEV_HIGH="HIGH"
SEV_CRITICAL="CRITICAL"

# Statuses
STATUS_PASS="PASS"
STATUS_WARN="WARN"
STATUS_FAIL="FAIL"

# Colors (re-defined here or reuse from utils, but let's make sure they match)
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_BOLD='\033[1m'

# Function: add_finding
# Usage: add_finding "ID" "SEVERITY" "STATUS" "TITLE" "DESCRIPTION" "EVIDENCE" "REMEDIATION"
add_finding() {
    local id="$1"
    local severity="$2"
    local status="$3"
    local title="$4"
    local description="$5"
    local evidence="$6"
    local remediation="$7"

    # Register to global report if reporting system is initialized
    if [[ -n "$IRONBASE_RUN_DIR" ]] && declare -f register_finding > /dev/null 2>&1; then
        register_finding "$id" "$severity" "$status" "$title" "$description" "$evidence" "$remediation" "" "" ""
    fi

    # Colorize based on status
    local color="$C_RESET"
    if [[ "$status" == "$STATUS_FAIL" ]]; then
        color="$C_RED"
    elif [[ "$status" == "$STATUS_WARN" ]]; then
        color="$C_YELLOW"
    elif [[ "$status" == "$STATUS_PASS" ]]; then
        color="$C_GREEN"
    fi

    # Human-readable output
    echo -e "${color}[${status}]${C_RESET} ${C_BOLD}[${severity}]${C_RESET} ${title} (${id})"
    
    # Indent details for readability if not PASS (keep PASS brief)
    if [[ "$status" != "$STATUS_PASS" ]]; then
        echo -e "      ${C_BOLD}Description:${C_RESET} $description"
        if [[ -n "$evidence" ]]; then
            echo -e "      ${C_BOLD}Evidence:${C_RESET}    $evidence"
        fi
        if [[ -n "$remediation" ]]; then
            echo -e "      ${C_BOLD}Remediation:${C_RESET} $remediation"
        fi
        echo "" 
    fi
}
