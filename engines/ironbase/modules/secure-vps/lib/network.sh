#!/bin/bash

# modules/secure-vps/lib/network.sh
# Network helper functions

# Function: get_public_ip
# Purpose: Detect public IP using external service (with fallback)
get_public_ip() {
    # Try various services
    local ip=""
    ip=$(curl -s --max-time 3 https://ifconfig.me/ip)
    if [[ -z "$ip" ]]; then
        ip=$(curl -s --max-time 3 https://api.ipify.org)
    fi
    echo "$ip"
}

# Function: is_port_listening_globally
# Purpose: Check if a port is bound to 0.0.0.0 or [::]
# detailed logic using ss
is_port_listening_globally() {
    local port="$1"
    local protocol="$2" # tcp or udp
    
    # Check for *:$port or 0.0.0.0:$port or [::]:$port
    if ! command -v ss &> /dev/null; then
        return 1
    fi
    ss -ln"${protocol:0:1}" | grep -E ":$port " | grep -E "(\*|0\.0\.0\.0|\[::\])" > /dev/null
    return $?
}

# Function: get_listening_services
# Purpose: Return list of listening services (process name, port, bind addr)
get_listening_services() {
    ss -lntuHp | awk '{print $1, $4, $5, $6}'
}
