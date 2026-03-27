#!/bin/bash

# modules/secure-vps/scanners/external.sh
# External (Network-based) Security Checks (Simulated)

scan_external() {
    vps_log "INFO" "Starting External Scan (Network Exposure Simulation)..."

    # 1. Public IP Detection
    local public_ip=$(get_public_ip)
    if [[ -z "$public_ip" ]]; then
        add_vps_finding "EXT-NET-000" "$SEV_INFO" "$TYPE_RISK" "$ORIGIN_EXTERNAL" "Network" \
            "Public IP Not Detected" \
            "Could not determine public IP via external APIs." \
            "" \
            "Check internet connectivity."
    else
        add_vps_finding "EXT-NET-001" "$SEV_INFO" "$TYPE_RISK" "$ORIGIN_EXTERNAL" "Network" \
            "Public IP Detected" \
            "VPS is exposed on Public IP: $public_ip" \
            "" \
            "Ensure firewall rules specifically filter traffic to this IP."
    fi

    # 2. Exposed Ports (Simulated)
    # Checks what is listening on 0.0.0.0 or the public IP
    if command -v ss &> /dev/null; then
        local listening_ports=$(ss -lntu | awk -v pip="$public_ip" '$4 ~ /0\.0\.0\.0/ || $4 ~ /\*/ || $4 ~ pip {print $1, $4, $5}')
        
        if [[ -n "$listening_ports" ]]; then
             add_vps_finding "EXT-NET-002" "$SEV_HIGH" "$TYPE_RISK" "$ORIGIN_EXTERNAL" "Network" \
                "Ports Exposed to Internet" \
                "Services are listening on public interfaces or all interfaces." \
                "$listening_ports" \
                "Verify that firewall (UFW/IPTables) restricts access to these ports."
        fi
    fi

    # 3. ICMP Response
    local icmp_echo=$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null)
    if [[ "$icmp_echo" == "0" ]]; then
        add_vps_finding "EXT-NET-003" "$SEV_LOW" "$TYPE_RISK" "$ORIGIN_EXTERNAL" "Network" \
            "ICMP Echo Reply Enabled" \
            "Server responds to Ping request." \
            "sysctl net.ipv4.icmp_echo_ignore_all = 0" \
            "Consider disabling if stealth is priority (sysctl net.ipv4.icmp_echo_ignore_all=1)."
    fi

    # 4. SSH Exposure Check
    # If SSH is on default port 22 and exposed
    if is_port_listening_globally "22" "tcp"; then
         add_vps_finding "EXT-SSH-001" "$SEV_MEDIUM" "$TYPE_RISK" "$ORIGIN_EXTERNAL" "Auth" \
            "SSH on Default Port 22" \
            "SSH service detected on standard port 22 exposed globally. Note: Changing port is not a security control by itself, but reduces automated scanning noise." \
            "ss -lnt | grep :22" \
            "Consider changing SSH port (noise reduction) or strictly limiting access via Firewall/VPN (security control)."
    fi
}
