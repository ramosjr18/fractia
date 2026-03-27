#!/bin/bash

# tests/test_writable_path.sh
# Tests INT-SYS-003 logic with symlinks

MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../modules/secure-vps" && pwd)"
source "$MODULE_ROOT/lib/common.sh"
source "$MODULE_ROOT/scanners/internal.sh"

# Mock Environment
mkdir -p /tmp/test_env/secure
mkdir -p /tmp/test_env/vulnerable
mkdir -p /tmp/test_env/symlinks

# 1. Secure Dir (755)
chmod 755 /tmp/test_env/secure

# 2. Vulnerable Dir (777)
chmod 777 /tmp/test_env/vulnerable

# 3. Symlink to Secure (Link itself is 777 usually, target 755)
ln -sf /tmp/test_env/secure /tmp/test_env/symlinks/link_to_secure

# 4. Symlink to Vulnerable
ln -sf /tmp/test_env/vulnerable /tmp/test_env/symlinks/link_to_vuln

# Override add_vps_finding to verify output
add_vps_finding() {
    echo "FINDING: $1 $6"
    echo "EVIDENCE: $8"
}

# Run Scan with modified PATH
echo "Testing Secure Symlink..."
export PATH="/tmp/test_env/symlinks/link_to_secure:$PATH"
scan_internal | grep "INT-SYS-003" || echo "No finding (Correct)"

echo "Testing Vulnerable Target..."
export PATH="/tmp/test_env/symlinks/link_to_vuln:$PATH"
scan_internal | grep "INT-SYS-003" && echo "Finding detected (Correct)" || echo "No finding (Incorrect)"

# Cleanup
rm -rf /tmp/test_env
