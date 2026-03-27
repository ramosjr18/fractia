#!/bin/bash
# modules/ssh/scanners/ssh.sh
# SSH Configuration Checks

scan_ssh() {
    vps_log "INFO" "Starting SSH Configuration Scan..."

    local sshd_config="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_config" ]]; then
        vps_log "ERROR" "sshd_config not found at $sshd_config"
        return
    fi

    # INT-SSH-001: Root Login
    if grep -E "^PermitRootLogin yes" "$sshd_config" > /dev/null; then
         add_vps_finding "INT-SSH-001" "$SEV_HIGH" "$TYPE_MISCONFIG" "$ORIGIN_INTERNAL" "Auth" \
            "SSH Root Login Enabled" \
            "PermitRootLogin is set to yes" \
            "" \
            "Set PermitRootLogin no"
    fi
    
    # INT-SSH-002: Password Auth
    if grep -E "^PasswordAuthentication yes" "$sshd_config" > /dev/null; then
         add_vps_finding "INT-SSH-002" "$SEV_MEDIUM" "$TYPE_MISCONFIG" "$ORIGIN_INTERNAL" "Auth" \
            "SSH Password Auth Enabled" \
            "PasswordAuthentication is set to yes" \
            "" \
            "Disable PasswordAuthentication, use keys only."
    fi
    
    # INT-SSH-003: Empty Passwords
    if grep -E "^PermitEmptyPasswords yes" "$sshd_config" > /dev/null; then
         add_vps_finding "INT-SSH-003" "$SEV_CRITICAL" "$TYPE_VULN" "$ORIGIN_INTERNAL" "Auth" \
            "SSH Empty Passwords Enabled" \
            "PermitEmptyPasswords is set to yes (CRITICAL SECURITY RISK)" \
            "grep PermitEmptyPasswords $sshd_config" \
            "Set 'PermitEmptyPasswords no' immediately. This allows authentication without passwords."
    fi
}
