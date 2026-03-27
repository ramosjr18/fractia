#!/bin/bash

# tests/test_service_classification.sh

# Mock Environment
MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../modules/secure-vps" && pwd)"
source "$MODULE_ROOT/lib/common.sh"

# Mock ss command
ss() {
    # Output simulated listening ports
    echo "Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port"
    echo "tcp    LISTEN  0       128      0.0.0.0:6379         0.0.0.0:*"   # Redis (Critical)
    echo "tcp    LISTEN  0       128      0.0.0.0:80           0.0.0.0:*"   # Web (Expected)
    echo "tcp    LISTEN  0       128      *:2222               *:*"         # Unknown (Medium)
    echo "tcp    LISTEN  0       128      127.0.0.1:27017      0.0.0.0:*"   # Localhost (Ignored)
}
export -f ss

# Load Internal Scanner
# We need to modify internal scanner to NOT check for `command -v ss` strictly, 
# or we assume the test env has a function override which bash respects.
# But `command -v ss` might fail if ss is a function? No, command -v finds functions too.

source "$MODULE_ROOT/scanners/internal.sh"

# Run Scan
echo "Running Internal Scan with Mocked ss..."
scan_internal
