#!/bin/bash

# modules/secure-vps/main.sh
# Integrated entrypoint for IronBase

MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load Module Libraries
# Sources common.sh, which sources output.sh AND baseline.sh
source "$MODULE_ROOT/lib/common.sh"
source "$MODULE_ROOT/lib/network.sh"

# Load Scanners
source "$MODULE_ROOT/scanners/internal.sh"
source "$MODULE_ROOT/scanners/external.sh"

module_meta() {
    echo "Name: Secure VPS"
    echo "Description: Comprehensive threat exposure assessment for public VPS."
    echo "Version: 1.0.0"
}

# Override add_vps_finding isn't needed here if we rely on common.sh's implementation
# BUT we need to support IronBase `add_finding` potentially?
# The user wants THIS module to behave differently.
# So `module_scan` will print directly.
# IronBase `engine.sh` logs "Module X: PASSED" based on exit code.
# The internal module output will happen in-stream.

module_scan() {
    # Initialize Log
    init_log_file

    # Run the scans
    scan_internal
    scan_external
    
    # Print Summary and determine exit code
    print_summary
    return $?
}

source "$MODULE_ROOT/lib/apply.sh"

module_apply() {
    # Call the interactive remediation logic
    run_apply
}
