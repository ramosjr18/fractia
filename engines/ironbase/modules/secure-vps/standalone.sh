#!/bin/bash

# modules/secure-vps/standalone.sh
# Runnable entrypoint for standalone usage

# Resolve absolute path to module root
MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load Libraries
source "$MODULE_ROOT/lib/common.sh"
source "$MODULE_ROOT/lib/network.sh"

# Load Scanners
source "$MODULE_ROOT/scanners/internal.sh"
source "$MODULE_ROOT/scanners/external.sh"

# Load Apply Logic
source "$MODULE_ROOT/lib/apply.sh"

# Argument Parsing
ACTION="scan"
for arg in "$@"; do
    case "$arg" in
        apply|--apply) ACTION="apply" ;;
        --force) export IRONBASE_FORCE="true" ;;
    esac
done

# Header
echo -e "${C_BOLD}Secure-VPS Standalone${C_RESET}"
echo "======================================"

if [[ "$ACTION" == "apply" ]]; then
    run_apply
    exit $?
else
    # Initialize Log
    init_log_file

    # Run Scans
    scan_internal
    scan_external

    # Summary
    print_summary
    exit $?
fi
