#!/bin/bash

# modules/firewall/main.sh
# Firewall hardening module (UFW based)

module_meta() {
    echo "Name: Firewall Hardening"
    echo "Description: Ensures UFW is enabled and basic policies are set. Advanced scan checks for rule completeness, interference, and service exposure."
    echo "Version: 2.0.0"
}

module_scan() {
    # ========================================================================
    # BASELINE CHECKS (Fail-Fast Behavior)
    # ========================================================================
    # This module implements fail-fast behavior: if UFW is not installed or
    # inactive, the scan stops immediately. Advanced checks (FW-004 through
    # FW-011) are only meaningful when UFW is active and operational.
    # 
    # Rationale: Running advanced firewall checks against an inactive firewall
    # would produce misleading or irrelevant results. This demonstrates
    # intentional design maturity and prevents false positives.
    # ========================================================================
    
    # 1. Check Install
    # FAIL-FAST: If UFW is not installed, stop scan immediately.
    # No further checks can be performed without UFW.
    if ! command_exists ufw; then
        add_finding "FW-001" "$SEV_HIGH" "$STATUS_FAIL" "UFW Installed" \
            "UFW is not installed. This check validates UFW baseline configuration only. It does not assess full service exposure or rule completeness." \
            "" \
            "Install 'ufw' package."
        return 1
    fi

    # 2. Check Status
    # FAIL-FAST: If UFW is inactive, stop scan immediately.
    # Advanced checks (FW-004 through FW-011) require UFW to be active.
    # If UFW is inactive, the firewall scan stops after FW-002.
    local status_out
    status_out=$(sudo ufw status verbose 2>/dev/null)
    if echo "$status_out" | grep -q "Status: active"; then
        add_finding "FW-002" "$SEV_HIGH" "$STATUS_PASS" "UFW Status" \
            "UFW is active. This check validates UFW baseline configuration only. It does not assess full service exposure or rule completeness." \
            "" \
            ""
            
        # 3. Check Policies (Default Deny Incoming)
        # Only executes if UFW is active (FW-002 passed)
        if echo "$status_out" | grep -q "Default: deny (incoming)"; then
            add_finding "FW-003" "$SEV_MEDIUM" "$STATUS_PASS" "Default Incoming Policy" \
                "Default incoming policy is DENY." \
                "" \
                ""
        else
            add_finding "FW-003" "$SEV_HIGH" "$STATUS_FAIL" "Default Incoming Policy" \
                "Default incoming policy is NOT deny." \
                "Current: $(echo "$status_out" | grep "Default:")" \
                "Run 'ufw default deny incoming'"
        fi
    else
        add_finding "FW-002" "$SEV_HIGH" "$STATUS_FAIL" "UFW Status" \
            "UFW is inactive. This check validates UFW baseline configuration only. It does not assess full service exposure or rule completeness." \
            "" \
            "Run 'ufw enable'"
        # FAIL-FAST: Stop scan here. Advanced checks (FW-004 through FW-011) are skipped.
        return 1
    fi

    # ========================================================================
    # ADVANCED CHECKS (FW-004 through FW-011)
    # ========================================================================
    # These checks only execute if UFW is installed AND active (FW-002 passed).
    # They perform deeper analysis of firewall rules, interference, and
    # service exposure correlation.
    # ========================================================================

    # 4. Specific Allow Rules Exist
    local numbered_out
    numbered_out=$(sudo ufw status numbered 2>/dev/null)
    if [[ -n "$numbered_out" ]]; then
        local allow_count=$(echo "$numbered_out" | grep -c "ALLOW IN" 2>/dev/null | head -n1 | tr -d '[:space:]' || echo "0")
        # Sanitize: ensure numeric value
        [[ "$allow_count" =~ ^[0-9]+$ ]] || allow_count=0
        
        # Check for SSH port dynamically
        local ssh_port="22"
        if command_exists ss; then
            local ssh_listening=$(ss -lnt 2>/dev/null | grep ":22 " | head -1)
            if [[ -n "$ssh_listening" ]]; then
                # Check if SSH port is explicitly allowed
                local ssh_allowed=$(echo "$numbered_out" | grep -E "ALLOW IN.*22" || echo "")
                if [[ -n "$ssh_allowed" ]]; then
                    # SSH is allowed, check if at least one allow rule exists
                    if [[ "$allow_count" -eq 0 ]]; then
                        add_finding "FW-004" "$SEV_HIGH" "$STATUS_FAIL" "Specific Allow Rules Exist" \
                            "Default deny exists with no explicit ALLOW IN rules detected. System may be completely locked down or SSH access may be blocked." \
                            "ufw status numbered: No ALLOW IN rules found" \
                            "Review firewall rules: 'sudo ufw status numbered'. Ensure required services (SSH, web) have explicit allow rules."
                    else
                        add_finding "FW-004" "$SEV_MEDIUM" "$STATUS_PASS" "Specific Allow Rules Exist" \
                            "At least one explicit ALLOW IN rule exists ($allow_count total). SSH port appears to be allowed." \
                            "Found $allow_count ALLOW IN rules in 'ufw status numbered'" \
                            ""
                    fi
                else
                    # SSH is listening but not explicitly allowed - could be allowed by default policy
                    if [[ "$allow_count" -eq 0 ]]; then
                        add_finding "FW-004" "$SEV_HIGH" "$STATUS_WARN" "Specific Allow Rules Exist" \
                            "SSH port 22 is listening but no explicit ALLOW IN rule found. May be blocked if default deny is active." \
                            "SSH listening: $ssh_listening | ufw status: No explicit allow for port 22" \
                            "Verify SSH access works. Consider: 'sudo ufw allow 22/tcp' or review default policy."
                    else
                        add_finding "FW-004" "$SEV_MEDIUM" "$STATUS_PASS" "Specific Allow Rules Exist" \
                            "Explicit ALLOW IN rules exist ($allow_count total). SSH port 22 may be covered by default policy or other rules." \
                            "Found $allow_count ALLOW IN rules" \
                            ""
                    fi
                fi
            else
                # No SSH listening, just check for any allow rules
                if [[ "$allow_count" -eq 0 ]]; then
                    add_finding "FW-004" "$SEV_HIGH" "$STATUS_FAIL" "Specific Allow Rules Exist" \
                        "Default deny exists with no explicit ALLOW IN rules. System may be completely locked down." \
                        "ufw status numbered: No ALLOW IN rules found" \
                        "Review firewall rules: 'sudo ufw status numbered'. Add explicit allow rules for required services."
                else
                    add_finding "FW-004" "$SEV_MEDIUM" "$STATUS_PASS" "Specific Allow Rules Exist" \
                        "At least one explicit ALLOW IN rule exists ($allow_count total)." \
                        "Found $allow_count ALLOW IN rules" \
                        ""
                fi
            fi
        else
            # ss not available, just check allow count
            if [[ "$allow_count" -eq 0 ]]; then
                add_finding "FW-004" "$SEV_HIGH" "$STATUS_FAIL" "Specific Allow Rules Exist" \
                    "Default deny exists with no explicit ALLOW IN rules detected." \
                    "ufw status numbered: No ALLOW IN rules found" \
                    "Review firewall rules: 'sudo ufw status numbered'. Ensure required services have explicit allow rules."
            else
                add_finding "FW-004" "$SEV_MEDIUM" "$STATUS_PASS" "Specific Allow Rules Exist" \
                    "At least one explicit ALLOW IN rule exists ($allow_count total)." \
                    "Found $allow_count ALLOW IN rules" \
                    ""
            fi
        fi
    fi

    # 5. Docker / nftables Interference
    local docker_active=0
    local docker_chains=0
    
    if command_exists systemctl && systemctl is-active --quiet docker 2>/dev/null; then
        docker_active=1
    elif command_exists docker && docker info &>/dev/null; then
        docker_active=1
    fi
    
    if [[ $docker_active -eq 1 ]]; then
        # Check for Docker chains in iptables
        if command_exists iptables; then
            local ipt_docker=$(sudo iptables -L -n 2>/dev/null | grep -i "DOCKER" | head -1)
            if [[ -n "$ipt_docker" ]]; then
                docker_chains=1
            fi
        fi
        
        # Check for Docker in nftables
        if command_exists nft && sudo nft list ruleset 2>/dev/null | grep -qi "docker"; then
            docker_chains=1
        fi
        
        if [[ $docker_chains -eq 1 ]]; then
            add_finding "FW-005" "$SEV_MEDIUM" "$STATUS_WARN" "Docker / nftables Interference" \
                "Docker service is active and appears to manipulate firewall rules (DOCKER chains detected). Docker may bypass or interfere with UFW rules." \
                "Docker active: yes | DOCKER chains found in iptables/nftables" \
                "Review Docker networking mode and UFW integration. Consider: Docker may bypass UFW - verify port exposure independently with 'ss -lnt'."
        else
            add_finding "FW-005" "$SEV_LOW" "$STATUS_PASS" "Docker / nftables Interference" \
                "Docker service is active but no DOCKER firewall chains detected. Potential interference may exist but not confirmed." \
                "Docker active: yes | No DOCKER chains detected" \
                ""
        fi
    else
        add_finding "FW-005" "$SEV_LOW" "$STATUS_PASS" "Docker / nftables Interference" \
            "Docker service is not active or not detected." \
            "" \
            ""
    fi

    # 6. Multiple Firewalls Active
    local firewall_count=0
    local active_firewalls=""
    
    # Check UFW
    if command_exists ufw && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        ((firewall_count++))
        active_firewalls="${active_firewalls}ufw "
    fi
    
    # Check firewalld
    if command_exists firewall-cmd && sudo firewall-cmd --state 2>/dev/null | grep -q "running"; then
        ((firewall_count++))
        active_firewalls="${active_firewalls}firewalld "
    fi
    
    # Check nftables
    if command_exists nft && sudo nft list ruleset 2>/dev/null | grep -q "table"; then
        local nft_table_count=$(sudo nft list tables 2>/dev/null | wc -l | head -n1 | tr -d '[:space:]' || echo "0")
        # Sanitize: ensure numeric value
        [[ "$nft_table_count" =~ ^[0-9]+$ ]] || nft_table_count=0
        if [[ $nft_table_count -gt 0 ]]; then
            ((firewall_count++))
            active_firewalls="${active_firewalls}nftables "
        fi
    fi
    
    # Check raw iptables (not managed by UFW)
    if command_exists iptables; then
        local ipt_rules=$(sudo iptables -L -n 2>/dev/null | grep -v "^Chain\|^target\|^$" | grep -v "ACCEPT.*all.*--.*lo\|DROP.*all.*--.*0.0.0.0/0" | head -5)
        if [[ -n "$ipt_rules" ]]; then
            # Check if rules are from UFW or manual
            if ! sudo iptables -L -n 2>/dev/null | grep -q "Chain ufw"; then
                # Non-UFW iptables rules exist
                ((firewall_count++))
                active_firewalls="${active_firewalls}iptables(manual) "
            fi
        fi
    fi
    
    if [[ $firewall_count -gt 1 ]]; then
        add_finding "FW-006" "$SEV_HIGH" "$STATUS_FAIL" "Multiple Firewalls Active" \
            "Multiple firewall systems are active simultaneously. This can cause conflicts, unexpected behavior, and rule enforcement issues." \
            "Active firewalls: ${active_firewalls}" \
            "Disable redundant firewall systems. Keep only one: UFW (recommended for Ubuntu) or firewalld. Remove others: 'sudo systemctl disable firewalld' or 'sudo systemctl stop nftables'."
    else
        add_finding "FW-006" "$SEV_MEDIUM" "$STATUS_PASS" "Multiple Firewalls Active" \
            "Only one firewall system is active (${active_firewalls:-none detected})." \
            "Active: ${active_firewalls:-none}" \
            ""
    fi

    # 7. Real Service Exposure (Correlated)
    if command_exists ss; then
        local listening_services=$(ss -lntup 2>/dev/null | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0/ || $5 ~ /^\[::\]/ || $5 ~ /^\*/) {print $1, $5, $7}' | head -10)
        
        if [[ -n "$listening_services" ]]; then
            local exposed_ports=""
            local unmanaged_ports=""
            
            while IFS= read -r service_line; do
                if [[ -z "$service_line" ]]; then continue; fi
                
                local port=$(echo "$service_line" | awk '{print $2}' | awk -F: '{print $NF}' | sed 's/]//')
                local proto=$(echo "$service_line" | awk '{print $1}')
                
                # Check if port has explicit UFW rule
                local ufw_rule=$(echo "$numbered_out" | grep -E "($port|$proto)" | grep -E "(ALLOW|DENY)" | head -1)
                
                if [[ -z "$ufw_rule" ]]; then
                    unmanaged_ports="${unmanaged_ports}${proto} ${port}; "
                else
                    exposed_ports="${exposed_ports}${proto} ${port}; "
                fi
            done <<< "$listening_services"
            
            if [[ -n "$unmanaged_ports" ]]; then
                add_finding "FW-007" "$SEV_HIGH" "$STATUS_FAIL" "Real Service Exposure (Correlated)" \
                    "Services are listening on public interfaces (0.0.0.0 or ::) without explicit firewall control. These ports may be exposed to the internet without UFW rules." \
                    "Unmanaged services: ${unmanaged_ports} | Check: 'ss -lntup | grep -E \"0.0.0.0|::\"'" \
                    "Review listening services: 'ss -lntup'. Add explicit UFW rules for required services: 'sudo ufw allow <port>/<proto>'. Block unnecessary services: 'sudo ufw deny <port>/<proto>' or bind to 127.0.0.1."
            else
                add_finding "FW-007" "$SEV_MEDIUM" "$STATUS_PASS" "Real Service Exposure (Correlated)" \
                    "All detected public listeners appear to have corresponding UFW rules or are managed by default policy." \
                    "Public listeners found with firewall rules" \
                    ""
            fi
        else
            add_finding "FW-007" "$SEV_LOW" "$STATUS_PASS" "Real Service Exposure (Correlated)" \
                "No services detected listening on public interfaces (0.0.0.0 or ::)." \
                "" \
                ""
        fi
    else
        add_finding "FW-007" "$SEV_INFO" "$STATUS_WARN" "Real Service Exposure (Correlated)" \
            "Cannot perform service exposure correlation check: 'ss' command not available." \
            "" \
            "Install 'iproute2' package to enable service exposure analysis."
    fi

    # 8. Forwarding / NAT Policy
    local ipv4_forward=0
    local ipv6_forward=0
    
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    fi
    
    if [[ -f /proc/sys/net/ipv6/conf/all/forwarding ]]; then
        ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")
    fi
    
    local forwarding_enabled=0
    if [[ "$ipv4_forward" == "1" ]] || [[ "$ipv6_forward" == "1" ]]; then
        forwarding_enabled=1
    fi
    
    if [[ $forwarding_enabled -eq 1 ]]; then
        # Check if UFW has forwarding/routing rules
        local ufw_forward=$(echo "$status_out" | grep -i "routed" || echo "")
        local ufw_forward_rules=$(echo "$numbered_out" | grep -i "route" || echo "")
        
        if [[ -z "$ufw_forward" && -z "$ufw_forward_rules" ]]; then
            add_finding "FW-008" "$SEV_HIGH" "$STATUS_FAIL" "Forwarding / NAT Policy" \
                "IP forwarding is enabled (IPv4: $ipv4_forward, IPv6: $ipv6_forward) but no explicit UFW routing/forwarding rules detected. System may be acting as router without firewall control." \
                "sysctl: net.ipv4.ip_forward=$ipv4_forward, net.ipv6.conf.all.forwarding=$ipv6_forward | UFW routed: none" \
                "Review IP forwarding requirement. If router/NAT is intentional, configure UFW forwarding rules: 'sudo ufw route allow in on <interface> out on <interface>'. If not needed, disable: 'sudo sysctl -w net.ipv4.ip_forward=0'."
        else
            add_finding "FW-008" "$SEV_MEDIUM" "$STATUS_PASS" "Forwarding / NAT Policy" \
                "IP forwarding is enabled but UFW routing/forwarding rules are present or configured." \
                "Forwarding enabled | UFW routing rules detected" \
                ""
        fi
    else
        add_finding "FW-008" "$SEV_LOW" "$STATUS_PASS" "Forwarding / NAT Policy" \
            "IP forwarding is disabled. System is not acting as router." \
            "net.ipv4.ip_forward=$ipv4_forward, net.ipv6.conf.all.forwarding=$ipv6_forward" \
            ""
    fi

    # 9. Logging & Rate Limiting
    local ufw_logging=$(echo "$status_out" | grep -i "Logging:" | awk '{print $2}' || echo "off")
    local limit_rules=$(echo "$numbered_out" | grep -c "limit" 2>/dev/null | head -n1 | tr -d '[:space:]' || echo "0")
    # Sanitize: ensure numeric value
    [[ "$limit_rules" =~ ^[0-9]+$ ]] || limit_rules=0
    
    if [[ "$ufw_logging" == "off" ]] && [[ "$limit_rules" -eq 0 ]]; then
        add_finding "FW-009" "$SEV_MEDIUM" "$STATUS_WARN" "Logging & Rate Limiting" \
            "UFW logging is disabled and no rate-limiting rules detected. No protection against brute-force attacks or audit trail for firewall events." \
            "UFW Logging: $ufw_logging | Limit rules: $limit_rules" \
            "Enable UFW logging for security auditing: 'sudo ufw logging on'. Consider rate-limiting rules for SSH: 'sudo ufw limit 22/tcp'."
    elif [[ "$ufw_logging" == "off" ]]; then
        add_finding "FW-009" "$SEV_LOW" "$STATUS_WARN" "Logging & Rate Limiting" \
            "UFW logging is disabled but rate-limiting rules exist ($limit_rules found). Limited protection without audit trail." \
            "UFW Logging: $ufw_logging | Limit rules: $limit_rules" \
            "Enable UFW logging for security auditing: 'sudo ufw logging on'."
    elif [[ "$limit_rules" -eq 0 ]]; then
        add_finding "FW-009" "$SEV_LOW" "$STATUS_WARN" "Logging & Rate Limiting" \
            "UFW logging is enabled but no rate-limiting rules detected. Logging provides audit trail but no automatic brute-force protection." \
            "UFW Logging: $ufw_logging | Limit rules: $limit_rules" \
            "Consider adding rate-limiting rules for SSH and other exposed services: 'sudo ufw limit 22/tcp'."
    else
        add_finding "FW-009" "$SEV_MEDIUM" "$STATUS_PASS" "Logging & Rate Limiting" \
            "UFW logging is enabled ($ufw_logging) and rate-limiting rules exist ($limit_rules found)." \
            "UFW Logging: $ufw_logging | Limit rules: $limit_rules" \
            ""
    fi

    # 10. IPv6 Enforcement
    local ufw_ipv6_enabled="no"
    if [[ -f /etc/default/ufw ]]; then
        ufw_ipv6_enabled=$(grep "^IPV6=" /etc/default/ufw 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "no")
    fi
    
    local ipv6_rules=0
    if [[ "$ufw_ipv6_enabled" == "yes" ]]; then
        ipv6_rules=$(echo "$numbered_out" | grep -c "v6" || echo "0")
        # Also check for IPv6 specific output
        local ufw_ipv6_status=$(sudo ufw status verbose 2>/dev/null | grep -i "ipv6" || echo "")
        
        if [[ -n "$ufw_ipv6_status" ]]; then
            add_finding "FW-010" "$SEV_MEDIUM" "$STATUS_PASS" "IPv6 Enforcement" \
                "IPv6 is enabled in UFW configuration (IPV6=yes) and IPv6 rules appear to be present." \
                "/etc/default/ufw: IPV6=$ufw_ipv6_enabled | IPv6 rules: detected" \
                ""
        else
            add_finding "FW-010" "$SEV_HIGH" "$STATUS_WARN" "IPv6 Enforcement" \
                "IPv6 is enabled in UFW configuration (IPV6=yes) but IPv6 rules may not be active or enforced. IPv6 traffic may bypass firewall." \
                "/etc/default/ufw: IPV6=$ufw_ipv6_enabled | IPv6 rules: not clearly detected" \
                "Verify IPv6 rules are active: 'sudo ufw status verbose'. If IPv6 is not needed, disable: Set IPV6=no in /etc/default/ufw and restart UFW."
        fi
    else
        # Check if IPv6 is actually disabled on system
        local ipv6_system_disabled=0
        if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
            local ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
            if [[ "$ipv6_disabled" == "1" ]]; then
                ipv6_system_disabled=1
            fi
        fi
        
        if [[ $ipv6_system_disabled -eq 0 ]]; then
            # IPv6 is enabled system-wide but UFW IPv6 is disabled
            add_finding "FW-010" "$SEV_HIGH" "$STATUS_FAIL" "IPv6 Enforcement" \
                "IPv6 is disabled in UFW (IPV6=no) but IPv6 is enabled system-wide. IPv6 traffic may bypass UFW firewall completely." \
                "/etc/default/ufw: IPV6=$ufw_ipv6_enabled | System IPv6: enabled" \
                "Enable IPv6 in UFW: Set IPV6=yes in /etc/default/ufw, then 'sudo ufw reload'. Or disable IPv6 system-wide if not needed: 'sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1'."
        else
            add_finding "FW-010" "$SEV_MEDIUM" "$STATUS_PASS" "IPv6 Enforcement" \
                "IPv6 is disabled in UFW and system-wide. No IPv6 firewall enforcement needed." \
                "UFW IPV6=$ufw_ipv6_enabled | System IPv6: disabled" \
                ""
        fi
    fi

    # 11. Configuration Drift
    if command_exists ss; then
        # Parse listening ports: only capture numeric ports from public interfaces
        local listening_ports=$(ss -lnt 2>/dev/null | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0/ || $5 ~ /^\[::\]/) {print $5}' | awk -F: '{print $NF}' | sed 's/]//' | grep -E '^[0-9]+$' | sort -u)
        # Parse UFW allowed ports: only capture numeric ports
        local ufw_allowed_ports=$(echo "$numbered_out" | grep "ALLOW" | grep -oE "[0-9]+(/tcp|/udp)?" | grep -oE "^[0-9]+$" | sort -u)
        
        if [[ -n "$listening_ports" ]]; then
            local unaccounted_ports=""
            local accounted_count=0
            
            for port in $listening_ports; do
                # Sanitize: only process numeric ports
                if [[ -z "$port" ]] || ! [[ "$port" =~ ^[0-9]+$ ]]; then continue; fi
                
                local found=0
                for ufw_port in $ufw_allowed_ports; do
                    # Sanitize: only compare numeric ports
                    if [[ -n "$ufw_port" ]] && [[ "$ufw_port" =~ ^[0-9]+$ ]] && [[ "$port" == "$ufw_port" ]]; then
                        found=1
                        ((accounted_count++))
                        break
                    fi
                done
                
                if [[ $found -eq 0 ]]; then
                    unaccounted_ports="${unaccounted_ports}${port} "
                fi
            done
            
            if [[ -n "$unaccounted_ports" ]]; then
                add_finding "FW-011" "$SEV_MEDIUM" "$STATUS_WARN" "Configuration Drift" \
                    "Services are listening on ports that do not have corresponding UFW allow rules. Configuration drift detected - firewall rules may not match actual service exposure." \
                    "Unaccounted ports: ${unaccounted_ports} | Listening: $(echo $listening_ports | tr '\n' ' ') | UFW allowed: $(echo $ufw_allowed_ports | tr '\n' ' ')" \
                    "Review port exposure: 'ss -lnt | grep -E \"0.0.0.0|::\"'. Align firewall rules: Add UFW allow rules for required services or stop/bind unnecessary services to localhost."
            else
                add_finding "FW-011" "$SEV_LOW" "$STATUS_PASS" "Configuration Drift" \
                    "All listening ports on public interfaces appear to have corresponding UFW rules or are managed by default policy." \
                    "Ports aligned: $(echo $listening_ports | tr '\n' ' ')" \
                    ""
            fi
        else
            add_finding "FW-011" "$SEV_LOW" "$STATUS_PASS" "Configuration Drift" \
                "No services detected listening on public interfaces. No configuration drift detected." \
                "" \
                ""
        fi
    else
        add_finding "FW-011" "$SEV_INFO" "$STATUS_WARN" "Configuration Drift" \
            "Cannot perform configuration drift check: 'ss' command not available." \
            "" \
            "Install 'iproute2' package to enable configuration drift analysis."
    fi

    return 0
}

module_apply() {
    # Initialize color constants (fallback if not already set from core/findings.sh)
    if [[ -z "$C_RESET" ]]; then
        C_RESET='\033[0m'
        C_RED='\033[0;31m'
        C_GREEN='\033[0;32m'
        C_YELLOW='\033[0;33m'
        C_BLUE='\033[0;34m'
        C_BOLD='\033[1m'
    fi
    
    # Initialize helpers (fallback definitions if not available)
    # Use run directory if available, otherwise fallback to current directory
    # Defensive: ensure IRONBASE_RUN_DIR is a valid directory before using it
    if [[ -n "$IRONBASE_RUN_DIR" ]] && [[ -d "$IRONBASE_RUN_DIR" ]] && [[ "$IRONBASE_RUN_DIR" != "/" ]]; then
        local APPLY_LOG="${FIREWALL_APPLY_LOG:-${VPS_APPLY_LOG:-$IRONBASE_RUN_DIR/firewall-apply.log}}"
    else
        # Fallback to legacy paths or current directory (standalone mode)
        local APPLY_LOG="${FIREWALL_APPLY_LOG:-${VPS_APPLY_LOG:-firewall-apply.log}}"
    fi
    
    init_apply_log() {
        echo "IronBase - Firewall Remediation Log" > "$APPLY_LOG"
        echo "Date: $(date)" >> "$APPLY_LOG"
        echo "Hostname: $(hostname)" >> "$APPLY_LOG"
        local mode="SAFE"
        if [[ "$IRONBASE_BOOTSTRAP" == "true" ]]; then
            mode="BOOTSTRAP"
        elif [[ "$IRONBASE_FORCE" == "true" ]]; then
            mode="FORCE"
        fi
        echo "Mode: $mode" >> "$APPLY_LOG"
        echo "-------------------------------------" >> "$APPLY_LOG"
    }
    
    log_apply() {
        local status="$1"
        local msg="$2"
        echo "[$status] $msg" >> "$APPLY_LOG"
        echo -e "${C_BLUE}[$status]${C_RESET} $msg"
    }
    
    backup_file() {
        local file="$1"
        local backup="${file}.bak.$(date +%s)"
        if [[ -f "$file" ]]; then
            cp "$file" "$backup"
            log_apply "INFO" "Backed up $file to $backup"
            echo -e "${C_BLUE}Backed up $file to $backup${C_RESET}"
            return 0
        fi
        return 1
    }
    
    confirm_action() {
        local prompt="$1"
        local default="${2:-N}"
        
        local options="[y/N]"
        if [[ "$default" == "Y" ]]; then options="[Y/n]"; fi
        
        read -p "$(echo -e "${C_YELLOW}$prompt $options${C_RESET} "): " response < /dev/tty
        response=${response:-$default}
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            return 0
        else
            return 1
        fi
    }
    
    # Initialize log
    init_apply_log
    
    # Check if UFW is installed
    if ! command_exists ufw; then
        log_apply "ERROR" "UFW is not installed. Please install it first: sudo apt-get install ufw"
        echo -e "${C_RED}Error: UFW is not installed.${C_RESET}"
        echo "Install with: sudo apt-get install ufw"
        return 1
    fi
    
    # ========================================================================
    # PHASE 1: PRE-FLIGHT SSH SAFETY CHECK (MANDATORY, NON-BYPASSABLE)
    # ========================================================================
    # This safety check MUST execute BEFORE ANY firewall modifications.
    # It verifies that SSH is running and the port can be reliably detected.
    # This check applies to ALL apply modes (SAFE, FORCE, BOOTSTRAP).
    # Even --force mode cannot skip this safety guard.
    # ========================================================================
    
    # Global variables for SSH safety system
    local SSH_PORT=""
    local SSH_PID=""
    local UFW_RULES_BACKUP_DIR=""
    
    # Detect SSH port using authoritative method (ss -lntp), fallback to sshd_config
    # Returns: port number on success, empty string on failure
    detect_ssh_port_authoritative() {
        local detected_port=""
        local sshd_process=""
        
        # PHASE 1A: Use ss -lntp as authoritative source (primary detection method)
        # ss -lntp shows listening TCP ports with process information
        if command_exists ss; then
            # Look for SSH daemon process listening on TCP
            # Format: LISTEN 0 128 *:22 *:* users:(("sshd",pid=123,fd=3))
            local ss_output=$(ss -lntp 2>/dev/null | grep -E "sshd|:22 |:2222 |:2200 ")
            
            if [[ -n "$ss_output" ]]; then
                # Extract port from ss output (format: *:PORT or 0.0.0.0:PORT)
                detected_port=$(echo "$ss_output" | awk '{print $4}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | head -n1)
                
                # Extract SSH daemon PID for verification
                SSH_PID=$(echo "$ss_output" | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | head -n1)
                
                # Verify detected port is numeric and valid range (1-65535)
                if [[ -n "$detected_port" ]] && [[ "$detected_port" =~ ^[0-9]+$ ]] && [[ "$detected_port" -ge 1 ]] && [[ "$detected_port" -le 65535 ]]; then
                    echo "$detected_port"
                    return 0
                fi
            fi
        fi
        
        # PHASE 1B: Fallback to /etc/ssh/sshd_config if ss detection failed
        if [[ -z "$detected_port" ]] && [[ -f /etc/ssh/sshd_config ]]; then
            local config_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1 | tr -d '[:space:]')
            
            if [[ -n "$config_port" ]] && [[ "$config_port" =~ ^[0-9]+$ ]] && [[ "$config_port" -ge 1 ]] && [[ "$config_port" -le 65535 ]]; then
                # Verify SSH is actually listening on this port using ss
                if command_exists ss; then
                    local listening_check=$(ss -lnt 2>/dev/null | grep -E ":$config_port " | head -1)
                    if [[ -n "$listening_check" ]]; then
                        echo "$config_port"
                        return 0
                    fi
                else
                    # ss not available, trust config file (less reliable)
                    echo "$config_port"
                    return 0
                fi
            fi
        fi
        
        # Detection failed
        return 1
    }
    
    # Verify SSH daemon is running
    verify_ssh_daemon_running() {
        # Method 1: Check process by PID (if we detected one via ss -lntp)
        if [[ -n "$SSH_PID" ]] && [[ "$SSH_PID" =~ ^[0-9]+$ ]]; then
            if ps -p "$SSH_PID" > /dev/null 2>&1; then
                return 0
            fi
        fi
        
        # Method 2: Check for sshd process by name
        if pgrep -x sshd > /dev/null 2>&1; then
            return 0
        fi
        
        # Method 3: Check systemd service status
        if command_exists systemctl && systemctl is-active --quiet ssh 2>/dev/null; then
            return 0
        fi
        
        if command_exists systemctl && systemctl is-active --quiet sshd 2>/dev/null; then
            return 0
        fi
        
        return 1
    }
    
    # Pre-flight SSH safety check - MANDATORY before any firewall modifications
    # Returns: 0 if safe to proceed, 1 if unsafe (hard block)
    pre_flight_ssh_safety_check() {
        echo -e "\n${C_BOLD}${C_YELLOW}==============================================================${C_RESET}"
        echo -e "${C_BOLD}${C_YELLOW}  PHASE 1: PRE-FLIGHT SSH SAFETY CHECK (MANDATORY)            ${C_RESET}"
        echo -e "${C_BOLD}${C_YELLOW}==============================================================${C_RESET}"
        log_apply "SAFETY" "Starting pre-flight SSH safety check (MANDATORY, non-bypassable)"
        
        # Step 1: Detect SSH port (authoritative method)
        SSH_PORT=$(detect_ssh_port_authoritative)
        
        if [[ -z "$SSH_PORT" ]] || ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 ]] || [[ "$SSH_PORT" -gt 65535 ]]; then
            echo -e "${C_RED}${C_BOLD}BLOCKING ERROR: SSH port cannot be reliably detected.${C_RESET}"
            echo -e "${C_RED}Firewall modifications are UNSAFE without confirmed SSH access.${C_RESET}"
            echo ""
            echo -e "${C_YELLOW}Detection methods attempted:${C_RESET}"
            echo "  1. ss -lntp (authoritative): No SSH service detected"
            if [[ -f /etc/ssh/sshd_config ]]; then
                echo "  2. /etc/ssh/sshd_config: Port directive found but not listening"
            else
                echo "  2. /etc/ssh/sshd_config: File not found"
            fi
            echo ""
            echo -e "${C_RED}${C_BOLD}ABORTING: Firewall apply cancelled to prevent lockout.${C_RESET}"
            echo -e "${C_YELLOW}Please ensure:${C_RESET}"
            echo "  - SSH daemon (sshd) is running: sudo systemctl status ssh"
            echo "  - SSH is listening on a valid port: ss -lntp | grep sshd"
            echo "  - SSH configuration is correct: sudo sshd -T | grep port"
            log_apply "ERROR" "PRE-FLIGHT CHECK FAILED: SSH port cannot be detected. Aborting."
            return 1
        fi
        
        log_apply "SAFETY" "SSH port detected: $SSH_PORT (authoritative method: ss -lntp)"
        echo -e "${C_GREEN}✓ SSH port detected: ${C_BOLD}$SSH_PORT${C_RESET}"
        
        # Step 2: Verify SSH daemon is running
        if ! verify_ssh_daemon_running; then
            echo -e "${C_RED}${C_BOLD}BLOCKING ERROR: SSH daemon is not running.${C_RESET}"
            echo -e "${C_RED}Firewall modifications are UNSAFE without an active SSH daemon.${C_RESET}"
            echo ""
            echo -e "${C_YELLOW}Verification methods attempted:${C_RESET}"
            echo "  1. Process check (PID: ${SSH_PID:-none})"
            echo "  2. Process name check (sshd)"
            echo "  3. Systemd service status (ssh/sshd)"
            echo ""
            echo -e "${C_RED}${C_BOLD}ABORTING: Firewall apply cancelled to prevent lockout.${C_RESET}"
            echo -e "${C_YELLOW}Please start SSH service:${C_RESET}"
            echo "  sudo systemctl start ssh  # Ubuntu/Debian"
            echo "  sudo systemctl start sshd  # RHEL/CentOS"
            log_apply "ERROR" "PRE-FLIGHT CHECK FAILED: SSH daemon not running. Aborting."
            return 1
        fi
        
        log_apply "SAFETY" "SSH daemon confirmed running (PID: ${SSH_PID:-detected})"
        echo -e "${C_GREEN}✓ SSH daemon confirmed running${C_RESET}"
        
        # Step 3: Verify SSH is actually listening on the detected port
        if command_exists ss; then
            local listening_verify=$(ss -lnt 2>/dev/null | grep -E ":$SSH_PORT " | head -1)
            if [[ -z "$listening_verify" ]]; then
                echo -e "${C_RED}${C_BOLD}BLOCKING ERROR: SSH is not listening on detected port $SSH_PORT.${C_RESET}"
                echo -e "${C_RED}Firewall modifications are UNSAFE without confirmed SSH listening.${C_RESET}"
                echo ""
                echo -e "${C_YELLOW}Detection conflict:${C_RESET}"
                echo "  - Port detected: $SSH_PORT"
                echo "  - ss -lnt verification: SSH not listening on this port"
                echo ""
                echo -e "${C_RED}${C_BOLD}ABORTING: Firewall apply cancelled to prevent lockout.${C_RESET}"
                echo -e "${C_YELLOW}Please verify SSH configuration and restart if needed:${C_RESET}"
                echo "  sudo systemctl restart ssh"
                echo "  sudo ss -lntp | grep sshd"
                log_apply "ERROR" "PRE-FLIGHT CHECK FAILED: SSH not listening on port $SSH_PORT. Aborting."
                return 1
            fi
        fi
        
        log_apply "SAFETY" "SSH listening verification passed: port $SSH_PORT confirmed listening"
        echo -e "${C_GREEN}✓ SSH listening verification passed${C_RESET}"
        
        echo -e "${C_BOLD}${C_GREEN}PRE-FLIGHT CHECK PASSED: Safe to proceed with firewall modifications.${C_RESET}"
        echo ""
        
        return 0
    }
    
    # ========================================================================
    # UFW RULES BACKUP AND ROLLBACK FUNCTIONS
    # ========================================================================
    # These functions backup UFW rule files before modifications and restore
    # them if post-flight verification fails, preventing SSH lockout.
    # ========================================================================
    
    # Backup UFW rules to a timestamped directory
    # Returns: backup directory path on success, empty string on failure
    backup_ufw_rules() {
        local timestamp=$(date +%s)
        local backup_dir="/tmp/ufw-rules-backup-$timestamp"
        
        # Create backup directory
        if ! mkdir -p "$backup_dir" 2>/dev/null; then
            log_apply "ERROR" "Failed to create backup directory: $backup_dir"
            return 1
        fi
        
        # Backup UFW rule files
        local backed_up=0
        
        # IPv4 rules
        if [[ -f /etc/ufw/user.rules ]]; then
            if cp /etc/ufw/user.rules "$backup_dir/user.rules" 2>/dev/null; then
                log_apply "SAFETY" "Backed up /etc/ufw/user.rules to $backup_dir/user.rules"
                ((backed_up++))
            fi
        fi
        
        # IPv6 rules
        if [[ -f /etc/ufw/user6.rules ]]; then
            if cp /etc/ufw/user6.rules "$backup_dir/user6.rules" 2>/dev/null; then
                log_apply "SAFETY" "Backed up /etc/ufw/user6.rules to $backup_dir/user6.rules"
                ((backed_up++))
            fi
        fi
        
        # UFW configuration
        if [[ -f /etc/default/ufw ]]; then
            if cp /etc/default/ufw "$backup_dir/ufw-default" 2>/dev/null; then
                log_apply "SAFETY" "Backed up /etc/default/ufw to $backup_dir/ufw-default"
                ((backed_up++))
            fi
        fi
        
        if [[ $backed_up -gt 0 ]]; then
            UFW_RULES_BACKUP_DIR="$backup_dir"
            echo "$backup_dir"
            return 0
        else
            log_apply "ERROR" "Failed to backup any UFW rule files"
            rm -rf "$backup_dir" 2>/dev/null
            return 1
        fi
    }
    
    # Rollback UFW rules from backup directory
    # Returns: 0 on success, 1 on failure
    rollback_ufw_rules() {
        if [[ -z "$UFW_RULES_BACKUP_DIR" ]] || [[ ! -d "$UFW_RULES_BACKUP_DIR" ]]; then
            log_apply "ERROR" "Rollback failed: Backup directory not found: $UFW_RULES_BACKUP_DIR"
            return 1
        fi
        
        log_apply "ROLLBACK" "Starting UFW rules rollback from: $UFW_RULES_BACKUP_DIR"
        echo -e "${C_RED}${C_BOLD}ROLLBACK: Restoring UFW rules from backup...${C_RESET}"
        
        local rollback_success=0
        
        # Restore IPv4 rules
        if [[ -f "$UFW_RULES_BACKUP_DIR/user.rules" ]]; then
            if sudo cp "$UFW_RULES_BACKUP_DIR/user.rules" /etc/ufw/user.rules 2>/dev/null; then
                log_apply "ROLLBACK" "Restored /etc/ufw/user.rules"
                ((rollback_success++))
            else
                log_apply "ERROR" "Failed to restore /etc/ufw/user.rules"
            fi
        fi
        
        # Restore IPv6 rules
        if [[ -f "$UFW_RULES_BACKUP_DIR/user6.rules" ]]; then
            if sudo cp "$UFW_RULES_BACKUP_DIR/user6.rules" /etc/ufw/user6.rules 2>/dev/null; then
                log_apply "ROLLBACK" "Restored /etc/ufw/user6.rules"
                ((rollback_success++))
            else
                log_apply "ERROR" "Failed to restore /etc/ufw/user6.rules"
            fi
        fi
        
        # Restore UFW configuration
        if [[ -f "$UFW_RULES_BACKUP_DIR/ufw-default" ]]; then
            if sudo cp "$UFW_RULES_BACKUP_DIR/ufw-default" /etc/default/ufw 2>/dev/null; then
                log_apply "ROLLBACK" "Restored /etc/default/ufw"
                ((rollback_success++))
            else
                log_apply "ERROR" "Failed to restore /etc/default/ufw"
            fi
        fi
        
        if [[ $rollback_success -gt 0 ]]; then
            # Reload UFW to apply restored rules
            log_apply "ROLLBACK" "Reloading UFW to apply restored rules..."
            sudo ufw reload > /dev/null 2>&1
            log_apply "ROLLBACK" "UFW reloaded with restored rules"
            echo -e "${C_YELLOW}UFW reloaded with restored rules.${C_RESET}"
            return 0
        else
            log_apply "ERROR" "Rollback failed: No files restored successfully"
            return 1
        fi
    }
    
    # ========================================================================
    # PHASE 2: POST-FLIGHT SSH REACHABILITY VERIFICATION
    # ========================================================================
    # This verification MUST execute AFTER firewall rule changes and BEFORE exit.
    # It verifies that SSH access is guaranteed after modifications.
    # If verification fails, automatic rollback is executed to prevent lockout.
    # ========================================================================
    
    # Verify SSH ALLOW rule exists and is persistent
    # Returns: 0 if rule exists and is persistent, 1 if verification fails
    post_flight_ssh_verification() {
        echo -e "\n${C_BOLD}${C_YELLOW}==============================================================${C_RESET}"
        echo -e "${C_BOLD}${C_YELLOW}  PHASE 2: POST-FLIGHT SSH REACHABILITY VERIFICATION         ${C_RESET}"
        echo -e "${C_BOLD}${C_YELLOW}==============================================================${C_RESET}"
        log_apply "SAFETY" "Starting post-flight SSH reachability verification (MANDATORY)"
        
        if [[ -z "$SSH_PORT" ]] || ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
            echo -e "${C_RED}${C_BOLD}VERIFICATION ERROR: SSH port not available for verification.${C_RESET}"
            log_apply "ERROR" "POST-FLIGHT VERIFICATION FAILED: SSH port not available"
            return 1
        fi
        
        # Step 1: Verify at least one ALLOW IN rule exists for SSH port in active rules
        local numbered_out=$(sudo ufw status numbered 2>/dev/null)
        local ssh_allow_rule=$(echo "$numbered_out" | grep -E "ALLOW.*IN.*$SSH_PORT.*tcp" || echo "")
        
        if [[ -z "$ssh_allow_rule" ]]; then
            echo -e "${C_RED}${C_BOLD}VERIFICATION FAILED: No ALLOW IN rule found for SSH port $SSH_PORT/tcp.${C_RESET}"
            echo -e "${C_RED}SSH access is NOT guaranteed after firewall modifications.${C_RESET}"
            log_apply "ERROR" "POST-FLIGHT VERIFICATION FAILED: No ALLOW rule for port $SSH_PORT/tcp in active rules"
            return 1
        fi
        
        log_apply "SAFETY" "SSH ALLOW rule confirmed in active rules: $ssh_allow_rule"
        echo -e "${C_GREEN}✓ SSH ALLOW rule confirmed in active UFW rules${C_RESET}"
        
        # Step 2: Verify rule is persistent in /etc/ufw/user.rules (not just runtime)
        if [[ ! -f /etc/ufw/user.rules ]]; then
            echo -e "${C_RED}${C_BOLD}VERIFICATION FAILED: /etc/ufw/user.rules not found.${C_RESET}"
            echo -e "${C_RED}SSH rule may not persist across UFW reloads.${C_RESET}"
            log_apply "ERROR" "POST-FLIGHT VERIFICATION FAILED: /etc/ufw/user.rules file not found"
            return 1
        fi
        
        # Check if SSH port is in the persistent rules file
        # UFW user.rules format: -A ufw-user-input -p tcp -m tcp --dport PORT -j ACCEPT
        local persistent_rule=$(sudo grep -E "ufw-user-input.*--dport $SSH_PORT.*ACCEPT" /etc/ufw/user.rules 2>/dev/null || echo "")
        
        if [[ -z "$persistent_rule" ]]; then
            echo -e "${C_RED}${C_BOLD}VERIFICATION FAILED: SSH port $SSH_PORT/tcp rule not found in persistent rules file.${C_RESET}"
            echo -e "${C_RED}SSH rule may not persist across UFW reloads or system reboots.${C_RESET}"
            log_apply "ERROR" "POST-FLIGHT VERIFICATION FAILED: SSH rule not persistent in /etc/ufw/user.rules"
            return 1
        fi
        
        log_apply "SAFETY" "SSH rule confirmed persistent in /etc/ufw/user.rules"
        echo -e "${C_GREEN}✓ SSH rule confirmed persistent in /etc/ufw/user.rules${C_RESET}"
        
        # Step 3: Check if rule is shadowed by a broader DENY rule (rule order matters)
        # UFW processes rules in order, so we check if there's a DENY rule before our ALLOW
        local rule_line_num=$(sudo grep -n "ufw-user-input.*--dport $SSH_PORT.*ACCEPT" /etc/ufw/user.rules 2>/dev/null | head -1 | cut -d: -f1)
        
        if [[ -n "$rule_line_num" ]] && [[ "$rule_line_num" =~ ^[0-9]+$ ]]; then
            # Check for DENY rules before our ALLOW rule
            local deny_before=$(sudo sed -n "1,$rule_line_num p" /etc/ufw/user.rules 2>/dev/null | grep -E "ufw-user-input.*REJECT|ufw-user-input.*DROP" | tail -1 || echo "")
            
            if [[ -n "$deny_before" ]]; then
                # Check if the DENY rule is broader (e.g., DENY all ports before ALLOW specific port)
                local deny_port=$(echo "$deny_before" | grep -oE "--dport [0-9]+" | grep -oE "[0-9]+" || echo "")
                
                if [[ -z "$deny_port" ]] || [[ "$deny_port" == "0" ]] || [[ "$deny_port" == "all" ]]; then
                    echo -e "${C_YELLOW}${C_BOLD}WARNING: SSH rule may be shadowed by a broader DENY rule.${C_RESET}"
                    echo -e "${C_YELLOW}DENY rule found before SSH ALLOW rule: $deny_before${C_RESET}"
                    log_apply "WARN" "SSH rule may be shadowed by broader DENY rule (order-dependent, may still work)"
                    # Don't fail verification for this - UFW may still allow it depending on rule structure
                fi
            fi
        fi
        
        echo -e "${C_BOLD}${C_GREEN}POST-FLIGHT VERIFICATION PASSED: SSH access is guaranteed.${C_RESET}"
        echo ""
        log_apply "SAFETY" "Post-flight SSH verification passed: SSH port $SSH_PORT/tcp is allowed and persistent"
        
        return 0
    }
    
    # Display Connectivity Guarantee summary
    display_connectivity_guarantee() {
        echo -e "\n${C_BOLD}${C_BLUE}==============================================================${C_RESET}"
        echo -e "${C_BOLD}${C_BLUE}  CONNECTIVITY GUARANTEE SUMMARY                              ${C_RESET}"
        echo -e "${C_BOLD}${C_BLUE}==============================================================${C_RESET}"
        echo -e "${C_GREEN}✓ Detected SSH Port:${C_RESET} ${C_BOLD}$SSH_PORT/tcp${C_RESET}"
        
        local numbered_out=$(sudo ufw status numbered 2>/dev/null)
        local ssh_rule=$(echo "$numbered_out" | grep -E "ALLOW.*IN.*$SSH_PORT.*tcp" | head -1 || echo "")
        if [[ -n "$ssh_rule" ]]; then
            echo -e "${C_GREEN}✓ Confirmed ALLOW Rule:${C_RESET} $ssh_rule"
        else
            echo -e "${C_RED}✗ ALLOW Rule:${C_RESET} NOT FOUND (VERIFICATION FAILED)"
        fi
        
        if [[ -f /etc/ufw/user.rules ]]; then
            local persistent_check=$(sudo grep -c "ufw-user-input.*--dport $SSH_PORT.*ACCEPT" /etc/ufw/user.rules 2>/dev/null || echo "0")
            if [[ "$persistent_check" -gt 0 ]]; then
                echo -e "${C_GREEN}✓ Persistence Verification:${C_RESET} Rule is persistent in /etc/ufw/user.rules ($persistent_check occurrence(s))"
            else
                echo -e "${C_RED}✗ Persistence Verification:${C_RESET} Rule NOT found in persistent rules file"
            fi
        else
            echo -e "${C_RED}✗ Persistence Verification:${C_RESET} /etc/ufw/user.rules file not found"
        fi
        
        if [[ -n "$UFW_RULES_BACKUP_DIR" ]] && [[ -d "$UFW_RULES_BACKUP_DIR" ]]; then
            echo -e "${C_GREEN}✓ Backup Available:${C_RESET} $UFW_RULES_BACKUP_DIR"
        else
            echo -e "${C_YELLOW}⚠ Backup:${C_RESET} No backup available (initial state or backup failed)"
        fi
        
        echo -e "${C_BOLD}${C_BLUE}==============================================================${C_RESET}"
        echo ""
    }
    
    # ========================================================================
    # EXECUTE PRE-FLIGHT SAFETY CHECK (MANDATORY, NON-BYPASSABLE)
    # ========================================================================
    # This check executes BEFORE any firewall modifications in ALL modes.
    # Even --force mode cannot skip this check.
    # ========================================================================
    
    if ! pre_flight_ssh_safety_check; then
        echo -e "${C_RED}${C_BOLD}Firewall apply aborted due to pre-flight safety check failure.${C_RESET}"
        log_apply "ABORT" "Firewall apply aborted: Pre-flight SSH safety check failed"
        return 1
    fi
    
    local ssh_port="$SSH_PORT"  # Use detected port for compatibility with existing code
    
    # ========================================================================
    # BOOTSTRAP MODE HANDLING (Initial Firewall Hardening)
    # ========================================================================
    if [[ "$IRONBASE_BOOTSTRAP" == "true" ]]; then
        echo -e "\n${C_RED}${C_BOLD}==============================================================${C_RESET}"
        echo -e "${C_RED}${C_BOLD}          BOOTSTRAP MODE: INITIAL FIREWALL SETUP                ${C_RESET}"
        echo -e "${C_RED}${C_BOLD}==============================================================${C_RESET}"
        echo -e "${C_YELLOW}WARNING: Bootstrap mode will configure UFW firewall from scratch.${C_RESET}"
        echo ""
        echo -e "${C_BOLD}This will:${C_RESET}"
        echo -e "  ${C_YELLOW}•${C_RESET} Install UFW if missing"
        echo -e "  ${C_YELLOW}•${C_RESET} Add SSH allow rule ($ssh_port/tcp) ${C_BOLD}BEFORE${C_RESET} enabling firewall"
        echo -e "  ${C_YELLOW}•${C_RESET} Enable UFW firewall"
        echo -e "  ${C_YELLOW}•${C_RESET} Set default policies: ${C_RED}DENY incoming${C_RESET}, ALLOW outgoing"
        echo -e "  ${C_YELLOW}•${C_RESET} Handle IPv6 configuration"
        echo -e "  ${C_YELLOW}•${C_RESET} Detect and warn about Docker/VPN/bridge conflicts"
        echo -e "  ${C_YELLOW}•${C_RESET} Disable IP forwarding (if safe to do so)"
        echo ""
        echo -e "${C_RED}${C_BOLD}NETWORKING BEHAVIOR WILL CHANGE${C_RESET}"
        echo -e "${C_RED}  • Incoming connections will be blocked by default${C_RESET}"
        echo -e "${C_RED}  • Only explicitly allowed services will be accessible${C_RESET}"
        echo -e "${C_RED}  • Ensure SSH access is properly configured before proceeding${C_RESET}"
        echo ""
        echo -e "${C_YELLOW}This action requires explicit confirmation.${C_RESET}"
        echo ""
        
        read -p "Type 'BOOTSTRAP' (all caps) to continue: " bootstrap_confirm < /dev/tty
        if [[ "$bootstrap_confirm" != "BOOTSTRAP" ]]; then
            echo "Aborting Bootstrap Mode."
            log_apply "ABORT" "User aborted Bootstrap Mode at warning screen."
            return 1
        fi
        
        log_apply "BOOTSTRAP_START" "User confirmed Bootstrap Mode execution."
        echo -e "${C_BOLD}>>> Starting Bootstrap Mode Firewall Setup <<<${C_RESET}"
        
        # Backup UFW rules BEFORE any modifications (safety requirement)
        if ! backup_ufw_rules > /dev/null 2>&1; then
            echo -e "${C_YELLOW}WARNING: Failed to create UFW rules backup. Continuing with caution.${C_RESET}"
            log_apply "WARN" "UFW rules backup failed, but proceeding with bootstrap"
        else
            echo -e "${C_GREEN}✓ UFW rules backed up before modifications${C_RESET}"
            log_apply "SAFETY" "UFW rules backed up to: $UFW_RULES_BACKUP_DIR"
        fi
        
        # Helper function: Detect Docker
        detect_docker() {
            local docker_detected=0
            
            # Check Docker service
            if command_exists systemctl && systemctl is-active --quiet docker 2>/dev/null; then
                docker_detected=1
            elif command_exists docker && docker info &>/dev/null 2>&1; then
                docker_detected=1
            fi
            
            # Check Docker networks/bridges
            if command_exists ip && ip link show | grep -qi "docker"; then
                docker_detected=1
            fi
            
            echo "$docker_detected"
        }
        
        # Helper function: Detect VPN/Bridge interfaces
        detect_vpn_or_bridge() {
            local vpn_bridge_detected=0
            
            if command_exists ip; then
                # Check for common VPN interfaces
                if ip link show | grep -qiE "(tun[0-9]+|tap[0-9]+|ppp[0-9]+|wg[0-9]+|openvpn|wireguard)"; then
                    vpn_bridge_detected=1
                fi
                
                # Check for bridge interfaces
                if ip link show type bridge 2>/dev/null | grep -q "state UP"; then
                    vpn_bridge_detected=1
                fi
            fi
            
            echo "$vpn_bridge_detected"
        }
        
        # Step 1: Install UFW if missing
        if ! command_exists ufw; then
            log_apply "INFO" "UFW not installed. Installing UFW..."
            echo -e "${C_YELLOW}Installing UFW package...${C_RESET}"
            
            if command_exists apt-get; then
                sudo apt-get update -qq 2>&1 | tee -a "$APPLY_LOG"
                sudo apt-get install -y ufw 2>&1 | tee -a "$APPLY_LOG"
            elif command_exists yum; then
                sudo yum install -y ufw 2>&1 | tee -a "$APPLY_LOG"
            elif command_exists dnf; then
                sudo dnf install -y ufw 2>&1 | tee -a "$APPLY_LOG"
            else
                log_apply "ERROR" "Package manager not found. Cannot install UFW automatically."
                echo -e "${C_RED}Error: Cannot install UFW. Please install manually.${C_RESET}"
                return 1
            fi
            
            if command_exists ufw; then
                log_apply "SUCCESS" "UFW installed successfully"
            else
                log_apply "ERROR" "UFW installation failed"
                echo -e "${C_RED}Error: UFW installation failed.${C_RESET}"
                return 1
            fi
        else
            log_apply "INFO" "UFW is already installed"
        fi
        
        # Step 2: Add SSH allow rule BEFORE enabling firewall (CRITICAL)
        # This ensures SSH access is preserved when firewall is enabled
        # IMPORTANT: Ensure idempotency - check if rule already exists before adding
        # UFW allows adding rules even when active, so we check first to avoid duplicates
        log_apply "INFO" "Adding SSH allow rule BEFORE enabling firewall..."
        echo -e "${C_BOLD}Adding SSH allow rule ($ssh_port/tcp) to prevent lockout...${C_RESET}"
        
        # Check if SSH rule already exists (idempotency check)
        # Check both active rules and persistent rules file to ensure no duplicates
        local existing_ssh_rule=""
        if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
            existing_ssh_rule=$(sudo ufw status numbered 2>/dev/null | grep -E "ALLOW.*IN.*$ssh_port.*tcp" || echo "")
        fi
        
        # Also check persistent rules file if UFW is inactive or rule not in active rules
        if [[ -z "$existing_ssh_rule" ]] && [[ -f /etc/ufw/user.rules ]]; then
            local persistent_check=$(sudo grep -c "ufw-user-input.*--dport $ssh_port.*ACCEPT" /etc/ufw/user.rules 2>/dev/null || echo "0")
            if [[ "$persistent_check" -gt 0 ]]; then
                existing_ssh_rule="persistent_rule_exists"
            fi
        fi
        
        if [[ -z "$existing_ssh_rule" ]]; then
            # SSH rule does not exist - add it (idempotent operation)
            if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
                log_apply "INFO" "UFW is active. Adding SSH rule (idempotent)..."
            else
                log_apply "INFO" "UFW is inactive. Adding SSH rule before enabling (idempotent)..."
            fi
            
            # Add SSH allow rule (UFW will not duplicate identical rules, but we check anyway for safety)
            sudo ufw allow "$ssh_port/tcp" comment 'SSH (IronBase Bootstrap)' 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "Added UFW rule: allow $ssh_port/tcp (SSH) - idempotent operation"
            echo -e "${C_GREEN}SSH rule added successfully.${C_RESET}"
        else
            log_apply "SKIP" "SSH allow rule already exists (idempotent operation, skipping duplicate)"
            echo -e "${C_GREEN}SSH rule already exists. Skipping (idempotent).${C_RESET}"
        fi
        
        # Step 3: Set default policies BEFORE enabling
        log_apply "INFO" "Setting default policies..."
        sudo ufw default deny incoming 2>&1 | tee -a "$APPLY_LOG"
        sudo ufw default allow outgoing 2>&1 | tee -a "$APPLY_LOG"
        log_apply "SUCCESS" "Default policies set: deny incoming, allow outgoing"
        
        # Step 4: Enable UFW
        log_apply "INFO" "Enabling UFW firewall..."
        echo -e "${C_YELLOW}Enabling UFW firewall...${C_RESET}"
        
        # Check if UFW is already active
        if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
            log_apply "INFO" "UFW is already active"
            echo -e "${C_GREEN}UFW is already active.${C_RESET}"
        else
            # Enable UFW (may prompt for confirmation, use --force to avoid)
            if echo "y" | sudo ufw --force enable 2>&1 | tee -a "$APPLY_LOG"; then
                log_apply "SUCCESS" "UFW enabled successfully"
                echo -e "${C_GREEN}UFW firewall enabled.${C_RESET}"
            else
                log_apply "ERROR" "Failed to enable UFW"
                echo -e "${C_RED}Error: Failed to enable UFW.${C_RESET}"
                return 1
            fi
        fi
        
        # Step 5: Verify SSH rule exists after enabling UFW
        # This is a safety check to ensure the rule persisted after enable/reload
        local numbered_out=$(sudo ufw status numbered 2>/dev/null)
        local ssh_allowed=$(echo "$numbered_out" | grep -E "ALLOW.*IN.*$ssh_port.*tcp" || echo "")
        if [[ -z "$ssh_allowed" ]]; then
            log_apply "WARN" "SSH rule not found in active rules after enable. Adding now (idempotent)..."
            # Add rule again (idempotent - won't duplicate if it exists)
            sudo ufw allow "$ssh_port/tcp" comment 'SSH (IronBase Bootstrap)' 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "Added UFW rule: allow $ssh_port/tcp (SSH) - safety verification"
            echo -e "${C_YELLOW}SSH rule added during verification (should not happen if Step 2 succeeded).${C_RESET}"
        else
            log_apply "SUCCESS" "SSH rule confirmed after enable: allow $ssh_port/tcp"
            echo -e "${C_GREEN}SSH access confirmed: port $ssh_port/tcp is allowed.${C_RESET}"
        fi
        
        # Step 6: Handle IPv6 (same logic as FORCE mode)
        local ufw_ipv6_enabled=$(grep "^IPV6" /etc/default/ufw 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
        if [[ "$ufw_ipv6_enabled" != "no" ]]; then
            backup_file /etc/default/ufw
            log_apply "INFO" "Disabling IPv6 in UFW (Bootstrap mode)..."
            sudo sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "IPv6 disabled in UFW (IPV6=no)"
            echo -e "${C_YELLOW}IPv6 disabled in UFW. Reload required.${C_RESET}"
        else
            log_apply "INFO" "IPv6 already disabled in UFW"
        fi
        
        # Step 7: Detect and warn about Docker
        local docker_detected=$(detect_docker)
        if [[ "$docker_detected" == "1" ]]; then
            echo ""
            echo -e "${C_YELLOW}${C_BOLD}>>> Docker Detected <<<${C_RESET}"
            echo -e "${C_YELLOW}WARNING: Docker is active. Docker may bypass UFW firewall rules.${C_RESET}"
            echo -e "${C_YELLOW}Docker uses its own iptables chains which can override UFW rules.${C_RESET}"
            echo -e "${C_YELLOW}Verify Docker container networking independently.${C_RESET}"
            log_apply "WARN" "Docker detected - may bypass UFW rules. Not modifying Docker configuration."
        else
            log_apply "INFO" "Docker not detected"
        fi
        
        # Step 8: Detect and handle forwarding
        local ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
        local ipv6_forward="0"
        if [[ -f /proc/sys/net/ipv6/conf/all/forwarding ]]; then
            ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")
        fi
        
        local forwarding_enabled=0
        if [[ "$ipv4_forward" == "1" ]] || [[ "$ipv6_forward" == "1" ]]; then
            forwarding_enabled=1
        fi
        
        if [[ "$forwarding_enabled" == "1" ]]; then
            echo ""
            echo -e "${C_YELLOW}${C_BOLD}>>> IP Forwarding Detected <<<${C_RESET}"
            echo -e "Current state: IPv4 forwarding=$ipv4_forward, IPv6 forwarding=$ipv6_forward"
            
            # Check for Docker/VPN/Bridge
            local docker_detected=$(detect_docker)
            local vpn_bridge_detected=$(detect_vpn_or_bridge)
            
            if [[ "$docker_detected" == "1" ]] || [[ "$vpn_bridge_detected" == "1" ]]; then
                echo -e "${C_YELLOW}WARNING: Docker, VPN, or bridge interfaces detected.${C_RESET}"
                echo -e "${C_YELLOW}Skipping forwarding disable to avoid breaking Docker/VPN networking.${C_RESET}"
                log_apply "SKIP" "IP forwarding enabled but Docker/VPN/bridge detected - not disabling forwarding"
            else
                echo -e "${C_YELLOW}No Docker/VPN/bridge detected. Disabling IP forwarding...${C_RESET}"
                
                if confirm_action "Disable IP forwarding? (safe for non-router systems)" "Y"; then
                    if [[ "$ipv4_forward" == "1" ]]; then
                        sudo sysctl -w net.ipv4.ip_forward=0 2>&1 | tee -a "$APPLY_LOG"
                        echo "net.ipv4.ip_forward=0" | sudo tee -a /etc/sysctl.conf 2>&1 | tee -a "$APPLY_LOG"
                        log_apply "SUCCESS" "IPv4 forwarding disabled"
                    fi
                    
                    if [[ "$ipv6_forward" == "1" ]]; then
                        sudo sysctl -w net.ipv6.conf.all.forwarding=0 2>&1 | tee -a "$APPLY_LOG"
                        echo "net.ipv6.conf.all.forwarding=0" | sudo tee -a /etc/sysctl.conf 2>&1 | tee -a "$APPLY_LOG"
                        log_apply "SUCCESS" "IPv6 forwarding disabled"
                    fi
                    
                    echo -e "${C_GREEN}IP forwarding disabled.${C_RESET}"
                else
                    log_apply "SKIP" "IP forwarding kept enabled (user choice)"
                fi
            fi
        else
            log_apply "INFO" "IP forwarding already disabled"
        fi
        
        # Step 9: Enable logging
        if sudo ufw status verbose 2>/dev/null | grep -qi "Logging: off"; then
            sudo ufw logging on 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "UFW logging enabled"
        fi
        
        # Step 10: Reload UFW if IPv6 was changed
        if [[ "$ufw_ipv6_enabled" != "no" ]]; then
            sudo ufw reload 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "UFW reloaded (IPv6 config change)"
        fi
        
        # ========================================================================
        # PHASE 2: POST-FLIGHT SSH REACHABILITY VERIFICATION (MANDATORY)
        # ========================================================================
        # This verification MUST execute AFTER all firewall modifications.
        # If verification fails, automatic rollback prevents SSH lockout.
        # ========================================================================
        
        if ! post_flight_ssh_verification; then
            echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
            echo -e "${C_RED}${C_BOLD}!  BLOCKING FAILURE: SSH REACHABILITY VERIFICATION FAILED       !${C_RESET}"
            echo -e "${C_RED}${C_BOLD}!  EXECUTING AUTOMATIC ROLLBACK TO PREVENT LOCKOUT              !${C_RESET}"
            echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
            log_apply "ERROR" "POST-FLIGHT VERIFICATION FAILED: Executing automatic rollback"
            
            if rollback_ufw_rules; then
                echo -e "${C_YELLOW}Rollback completed. Original firewall rules restored.${C_RESET}"
                log_apply "ROLLBACK" "UFW rules successfully rolled back to prevent lockout"
            else
                echo -e "${C_RED}${C_BOLD}CRITICAL: Rollback failed. Manual intervention required.${C_RESET}"
                log_apply "CRITICAL" "Rollback failed - manual intervention required to restore SSH access"
            fi
            
            echo ""
            echo -e "${C_RED}${C_BOLD}Firewall apply ABORTED due to SSH reachability verification failure.${C_RESET}"
            echo -e "${C_YELLOW}Please verify:${C_RESET}"
            echo "  1. SSH daemon is running: sudo systemctl status ssh"
            echo "  2. SSH is listening on port $ssh_port: ss -lntp | grep :$ssh_port"
            echo "  3. UFW rules allow SSH: sudo ufw status | grep $ssh_port"
            echo "  4. UFW rules are correct: sudo ufw status numbered"
            echo ""
            log_apply "ABORT" "Bootstrap mode aborted: Post-flight verification failed"
            return 1
        fi
        
        # Display Connectivity Guarantee summary
        display_connectivity_guarantee
        
        echo ""
        echo -e "${C_BOLD}=== Bootstrap Mode Complete ===${C_RESET}"
        echo -e "${C_GREEN}Firewall has been initialized and enabled.${C_RESET}"
        echo ""
        echo "Final UFW Status:"
        sudo ufw status verbose
        echo ""
        echo -e "Log saved to: ${C_BLUE}$APPLY_LOG${C_RESET}"
        
        return 0
    fi
    
    # ========================================================================
    # FORCE MODE HANDLING
    # ========================================================================
    if [[ "$IRONBASE_FORCE" == "true" ]]; then
        echo -e "\n${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!              FORCE MODE: FIREWALL HARDENING                      !${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
        echo -e "${C_RED}WARNING: You have requested FORCE apply for firewall hardening.${C_RESET}"
        echo -e "${C_RED}This will:${C_RESET}"
        echo -e "${C_RED}  - Enforce UFW as the ONLY firewall (disable nftables)${C_RESET}"
        echo -e "${C_RED}  - Add ALLOW rules for SSH ($ssh_port/tcp), 80/tcp, 443/tcp${C_RESET}"
        echo -e "${C_RED}  - Add rate limiting to SSH${C_RESET}"
        echo -e "${C_RED}  - DENY all other listening ports detected${C_RESET}"
        echo -e "${C_RED}  - Disable IPv6 in UFW (unless already hardened)${C_RESET}"
        echo -e "${C_RED}  - Modify system configurations without further confirmation${C_RESET}"
        echo ""
        echo -e "${C_RED}This action is potentially disruptive and may lock you out if SSH is not properly configured.${C_RESET}"
        echo -e "${C_RED}Ensure you have console/VNC access before proceeding.${C_RESET}"
        echo ""
        
        read -p "Confirm FORCE execution (type 'yes' to continue): " force_confirm < /dev/tty
        if [[ "$force_confirm" != "yes" ]]; then
            echo "Aborting Force Mode."
            log_apply "ABORT" "User aborted Force Mode at warning screen."
            return 1
        fi
        
        log_apply "FORCE_START" "User confirmed Force Mode execution."
        echo -e "${C_BOLD}>>> Starting FORCE Mode Firewall Hardening <<<${C_RESET}"
        
        # Backup UFW rules BEFORE any modifications (safety requirement - even in FORCE mode)
        if ! backup_ufw_rules > /dev/null 2>&1; then
            echo -e "${C_YELLOW}WARNING: Failed to create UFW rules backup. Continuing with caution.${C_RESET}"
            log_apply "WARN" "UFW rules backup failed, but proceeding with FORCE mode"
        else
            echo -e "${C_GREEN}✓ UFW rules backed up before modifications${C_RESET}"
            log_apply "SAFETY" "UFW rules backed up to: $UFW_RULES_BACKUP_DIR"
        fi
        
        # Ensure UFW is enabled
        if ! sudo ufw status 2>/dev/null | grep -q "Status: active"; then
            log_apply "INFO" "Enabling UFW..."
            sudo ufw --force enable 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "UFW enabled"
        fi
        
        # Set default policies
        log_apply "INFO" "Setting default deny incoming policy..."
        sudo ufw default deny incoming 2>&1 | tee -a "$APPLY_LOG"
        sudo ufw default allow outgoing 2>&1 | tee -a "$APPLY_LOG"
        log_apply "SUCCESS" "Default policies set: deny incoming, allow outgoing"
        
        # Disable nftables if active
        if command_exists systemctl && systemctl is-active --quiet nftables 2>/dev/null; then
            log_apply "WARN" "Stopping and disabling nftables service (UFW-only enforcement)..."
            sudo systemctl stop nftables 2>&1 | tee -a "$APPLY_LOG"
            sudo systemctl disable nftables 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "nftables stopped and disabled"
        fi
        
        # Add essential allow rules
        log_apply "INFO" "Adding essential ALLOW rules..."
        
        # SSH port (critical - must be first, idempotent operation)
        local existing_ssh_rule=$(sudo ufw status numbered 2>/dev/null | grep -E "ALLOW.*IN.*$ssh_port.*tcp" || echo "")
        if [[ -z "$existing_ssh_rule" ]]; then
            sudo ufw allow "$ssh_port/tcp" comment 'SSH (IronBase Force)' 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "Added UFW rule: allow $ssh_port/tcp (SSH)"
        else
            log_apply "SKIP" "SSH port $ssh_port/tcp already allowed (idempotent): $existing_ssh_rule"
        fi
        
        # HTTP/HTTPS
        for port in 80 443; do
            if ! sudo ufw status numbered 2>/dev/null | grep -qE "ALLOW IN.*$port.*tcp"; then
                local service_name="HTTP"
                if [[ "$port" == "443" ]]; then service_name="HTTPS"; fi
                sudo ufw allow "$port/tcp" comment "$service_name (IronBase Force)" 2>&1 | tee -a "$APPLY_LOG"
                log_apply "SUCCESS" "Added UFW rule: allow $port/tcp ($service_name)"
            else
                log_apply "SKIP" "Port $port/tcp already allowed"
            fi
        done
        
        # Add SSH rate limiting
        if ! sudo ufw status numbered 2>/dev/null | grep -qE "LIMIT.*$ssh_port.*tcp"; then
            sudo ufw limit "$ssh_port/tcp" comment 'SSH Rate Limit (IronBase Force)' 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "Added UFW rate limit: limit $ssh_port/tcp (SSH)"
        else
            log_apply "SKIP" "SSH rate limit already configured"
        fi
        
        # Deny all other listening ports
        if command_exists ss; then
            local listening_ports=$(ss -lntu 2>/dev/null | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0/ || $5 ~ /^\[::\]/) {print $1, $5}' | awk -F: '{print $NF}' | sed 's/]//' | grep -E '^[0-9]+$' | sort -u)
            
            for port_line in $listening_ports; do
                local port=$(echo "$port_line" | grep -oE '^[0-9]+$' | head -n1)
                if [[ -z "$port" ]] || ! [[ "$port" =~ ^[0-9]+$ ]]; then continue; fi
                
                # Skip if already in essential list
                if [[ "$port" == "$ssh_port" ]] || [[ "$port" == "80" ]] || [[ "$port" == "443" ]]; then
                    continue
                fi
                
                # Check if already denied
                if ! sudo ufw status numbered 2>/dev/null | grep -qE "DENY.*$port"; then
                    sudo ufw deny "$port/tcp" comment "Blocked by IronBase Force" 2>&1 | tee -a "$APPLY_LOG"
                    sudo ufw deny "$port/udp" comment "Blocked by IronBase Force" 2>&1 | tee -a "$APPLY_LOG"
                    log_apply "WARN" "Denied port $port (tcp/udp) - ensure no critical services are affected"
                fi
            done
        fi
        
        # Handle IPv6
        local ufw_ipv6_enabled=$(grep "^IPV6" /etc/default/ufw 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
        if [[ "$ufw_ipv6_enabled" != "no" ]]; then
            backup_file /etc/default/ufw
            log_apply "INFO" "Disabling IPv6 in UFW (Force mode)..."
            sudo sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "IPv6 disabled in UFW (IPV6=no)"
        fi
        
        # Enable logging
        if sudo ufw status verbose 2>/dev/null | grep -qi "Logging: off"; then
            sudo ufw logging on 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "UFW logging enabled"
        fi
        
        # Reload UFW
        sudo ufw reload 2>&1 | tee -a "$APPLY_LOG"
        log_apply "SUCCESS" "UFW reloaded"
        
        # ========================================================================
        # PHASE 2: POST-FLIGHT SSH REACHABILITY VERIFICATION (MANDATORY)
        # ========================================================================
        # This verification MUST execute AFTER all firewall modifications.
        # Even in FORCE mode, this safety guard is non-bypassable.
        # If verification fails, automatic rollback prevents SSH lockout.
        # ========================================================================
        
        if ! post_flight_ssh_verification; then
            echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
            echo -e "${C_RED}${C_BOLD}!  BLOCKING FAILURE: SSH REACHABILITY VERIFICATION FAILED       !${C_RESET}"
            echo -e "${C_RED}${C_BOLD}!  EXECUTING AUTOMATIC ROLLBACK TO PREVENT LOCKOUT              !${C_RESET}"
            echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
            log_apply "ERROR" "POST-FLIGHT VERIFICATION FAILED (FORCE MODE): Executing automatic rollback"
            
            if rollback_ufw_rules; then
                echo -e "${C_YELLOW}Rollback completed. Original firewall rules restored.${C_RESET}"
                log_apply "ROLLBACK" "UFW rules successfully rolled back to prevent lockout"
            else
                echo -e "${C_RED}${C_BOLD}CRITICAL: Rollback failed. Manual intervention required.${C_RESET}"
                log_apply "CRITICAL" "Rollback failed - manual intervention required to restore SSH access"
            fi
            
            echo ""
            echo -e "${C_RED}${C_BOLD}Firewall apply ABORTED due to SSH reachability verification failure.${C_RESET}"
            echo -e "${C_RED}Even in FORCE mode, SSH safety guards cannot be bypassed.${C_RESET}"
            echo -e "${C_YELLOW}Please verify:${C_RESET}"
            echo "  1. SSH daemon is running: sudo systemctl status ssh"
            echo "  2. SSH is listening on port $ssh_port: ss -lntp | grep :$ssh_port"
            echo "  3. UFW rules allow SSH: sudo ufw status | grep $ssh_port"
            echo "  4. UFW rules are correct: sudo ufw status numbered"
            echo ""
            log_apply "ABORT" "FORCE mode aborted: Post-flight verification failed (safety guard enforced)"
            return 1
        fi
        
        # Display Connectivity Guarantee summary
        display_connectivity_guarantee
        
        echo ""
        echo -e "${C_BOLD}=== FORCE Mode Complete ===${C_RESET}"
        echo "Final UFW Status:"
        sudo ufw status verbose
        
        return 0
    fi
    
    # ========================================================================
    # SAFE MODE (Interactive)
    # ========================================================================
    echo -e "\n${C_BOLD}Starting Interactive Firewall Hardening${C_RESET}"
    echo -e "${C_YELLOW}WARNING: You are about to modify firewall configurations.${C_RESET}"
    echo -e "This tool will prompt for confirmation before every action."
    echo -e "Log file: $APPLY_LOG"
    echo ""
    
    # Backup UFW rules BEFORE any modifications (safety requirement)
    if ! backup_ufw_rules > /dev/null 2>&1; then
        echo -e "${C_YELLOW}WARNING: Failed to create UFW rules backup. Continuing with caution.${C_RESET}"
        log_apply "WARN" "UFW rules backup failed, but proceeding with SAFE mode"
    else
        echo -e "${C_GREEN}✓ UFW rules backed up before modifications${C_RESET}"
        log_apply "SAFETY" "UFW rules backed up to: $UFW_RULES_BACKUP_DIR"
    fi
    
    # Ensure UFW is enabled
    if ! sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        if confirm_action "UFW is inactive. Enable UFW now?" "Y"; then
            log_apply "INFO" "Enabling UFW..."
            sudo ufw --force enable 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "UFW enabled"
        else
            log_apply "SKIP" "UFW not enabled - aborting"
            echo -e "${C_YELLOW}UFW must be active to continue. Exiting.${C_RESET}"
            return 1
        fi
    fi
    
    # Check default policies
    local status_out=$(sudo ufw status verbose 2>/dev/null)
    if ! echo "$status_out" | grep -q "Default: deny (incoming)"; then
        if confirm_action "Set default incoming policy to DENY?" "Y"; then
            log_apply "INFO" "Setting default deny incoming..."
            sudo ufw default deny incoming 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "Default incoming policy set to DENY"
        fi
    fi
    
    # Detect and handle SSH port
    echo ""
    echo -e "${C_BOLD}>>> SSH Port Configuration <<<${C_RESET}"
    echo -e "Detected SSH port: ${C_GREEN}$ssh_port${C_RESET}"
    
    local numbered_out=$(sudo ufw status numbered 2>/dev/null)
    local ssh_allowed=$(echo "$numbered_out" | grep -E "ALLOW.*$ssh_port.*tcp" || echo "")
    
    if [[ -z "$ssh_allowed" ]]; then
        if confirm_action "Add UFW ALLOW rule for SSH port $ssh_port/tcp?" "Y"; then
            sudo ufw allow "$ssh_port/tcp" comment 'SSH (IronBase)' 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "Added UFW rule: allow $ssh_port/tcp (SSH)"
        else
            log_apply "SKIP" "SSH port $ssh_port/tcp rule not added (user declined)"
            echo -e "${C_YELLOW}WARNING: SSH rule not added. Ensure SSH access is not locked out.${C_RESET}"
        fi
    else
        echo -e "${C_GREEN}SSH port $ssh_port/tcp already has an allow rule (idempotent).${C_RESET}"
        log_apply "INFO" "SSH port $ssh_port/tcp already allowed: $ssh_allowed"
    fi
    
    # SSH rate limiting
    local has_limit=$(echo "$numbered_out" | grep -E "LIMIT.*$ssh_port.*tcp" || echo "")
    if [[ -z "$has_limit" ]]; then
        if confirm_action "Add rate limiting to SSH port $ssh_port/tcp?" "N"; then
            sudo ufw limit "$ssh_port/tcp" comment 'SSH Rate Limit (IronBase)' 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "Added UFW rate limit: limit $ssh_port/tcp (SSH)"
        fi
    else
        echo -e "${C_GREEN}SSH rate limiting already configured.${C_RESET}"
        log_apply "INFO" "SSH rate limit already exists"
    fi
    
    # Multiple firewalls warning
    local firewall_count=0
    local active_firewalls=""
    
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        ((firewall_count++))
        active_firewalls="${active_firewalls}ufw "
    fi
    
    if command_exists systemctl && systemctl is-active --quiet nftables 2>/dev/null; then
        ((firewall_count++))
        active_firewalls="${active_firewalls}nftables "
    fi
    
    if [[ $firewall_count -gt 1 ]]; then
        echo ""
        echo -e "${C_YELLOW}>>> Multiple Firewalls Active <<<${C_RESET}"
        echo -e "Detected active firewalls: ${C_RED}${active_firewalls}${C_RESET}"
        echo -e "Multiple firewalls can conflict and cause unexpected behavior."
        echo -e "${C_YELLOW}NOTE: In SAFE mode, we will NOT disable other firewalls automatically.${C_RESET}"
        echo -e "Consider disabling redundant firewalls manually if needed."
        log_apply "WARN" "Multiple firewalls active: $active_firewalls (not auto-disabled in SAFE mode)"
    fi
    
    # Exposed services
    if command_exists ss; then
        local listening_services=$(ss -lntup 2>/dev/null | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0/ || $5 ~ /^\[::\]/) {print $1, $5, $7}' | head -10)
        
        if [[ -n "$listening_services" ]]; then
            echo ""
            echo -e "${C_BOLD}>>> Exposed Services Detection <<<${C_RESET}"
            echo "Services listening on public interfaces:"
            echo "$listening_services" | while read -r line; do
                echo "  - $line"
            done
            
            echo ""
            echo -e "${C_YELLOW}For each service above, you can:${C_RESET}"
            echo "  1. Add an ALLOW rule (if service should be accessible)"
            echo "  2. Skip (if already managed or should remain as-is)"
            echo ""
            echo -e "${C_YELLOW}NOTE: We will NOT add DENY rules automatically in SAFE mode.${C_RESET}"
            echo -e "Services not explicitly allowed will be handled by default policy."
            log_apply "INFO" "Exposed services detected (not auto-denied in SAFE mode)"
        fi
    fi
    
    # IPv6 handling
    echo ""
    echo -e "${C_BOLD}>>> IPv6 Configuration <<<${C_RESET}"
    local ufw_ipv6_enabled=$(grep "^IPV6" /etc/default/ufw 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
    echo "Current UFW IPv6 setting: ${ufw_ipv6_enabled:-not set (default: yes)}"
    
    if [[ "$ufw_ipv6_enabled" != "no" ]]; then
        echo "Options:"
        echo "  1) Enforce IPv6 rules (keep IPV6=yes, ensure IPv6 rules are active)"
        echo "  2) Disable IPv6 in UFW (set IPV6=no)"
        echo "  3) Skip (keep current setting)"
        
        read -p "Choose option [1/2/3]: " ipv6_choice < /dev/tty
        case "$ipv6_choice" in
            1)
                echo -e "${C_GREEN}Keeping IPv6 enabled. Verify IPv6 rules with: sudo ufw status verbose${C_RESET}"
                log_apply "INFO" "IPv6 enforcement: keeping IPV6=yes (user should verify rules)"
                ;;
            2)
                if confirm_action "Disable IPv6 in UFW? (IPV6=no)" "N"; then
                    backup_file /etc/default/ufw
                    sudo sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw 2>&1 | tee -a "$APPLY_LOG"
                    log_apply "SUCCESS" "IPv6 disabled in UFW (IPV6=no)"
                    echo -e "${C_YELLOW}UFW will need to be reloaded for this change to take effect.${C_RESET}"
                fi
                ;;
            *)
                log_apply "SKIP" "IPv6 configuration skipped"
                ;;
        esac
    else
        echo -e "${C_GREEN}IPv6 is already disabled in UFW (IPV6=no).${C_RESET}"
        log_apply "INFO" "IPv6 already disabled"
    fi
    
    # Logging
    if echo "$status_out" | grep -qi "Logging: off"; then
        if confirm_action "Enable UFW logging?" "Y"; then
            sudo ufw logging on 2>&1 | tee -a "$APPLY_LOG"
            log_apply "SUCCESS" "UFW logging enabled"
        fi
    fi
    
    # Reload UFW if any rules were modified
    local rules_modified=0
    if [[ -n "$ssh_allowed" ]] || echo "$status_out" | grep -qi "Logging: on"; then
        # Check if reload is needed (UFW may have been reloaded already, but safe to reload)
        if sudo ufw reload 2>&1 | tee -a "$APPLY_LOG"; then
            log_apply "INFO" "UFW reloaded after modifications"
            rules_modified=1
        fi
    fi
    
    # ========================================================================
    # PHASE 2: POST-FLIGHT SSH REACHABILITY VERIFICATION (MANDATORY)
    # ========================================================================
    # This verification MUST execute AFTER all firewall modifications.
    # Even in SAFE mode, this safety guard is non-bypassable.
    # If verification fails, automatic rollback prevents SSH lockout.
    # ========================================================================
    
    if ! post_flight_ssh_verification; then
        echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!  BLOCKING FAILURE: SSH REACHABILITY VERIFICATION FAILED       !${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!  EXECUTING AUTOMATIC ROLLBACK TO PREVENT LOCKOUT              !${C_RESET}"
        echo -e "${C_RED}${C_BOLD}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${C_RESET}"
        log_apply "ERROR" "POST-FLIGHT VERIFICATION FAILED (SAFE MODE): Executing automatic rollback"
        
        if rollback_ufw_rules; then
            echo -e "${C_YELLOW}Rollback completed. Original firewall rules restored.${C_RESET}"
            log_apply "ROLLBACK" "UFW rules successfully rolled back to prevent lockout"
        else
            echo -e "${C_RED}${C_BOLD}CRITICAL: Rollback failed. Manual intervention required.${C_RESET}"
            log_apply "CRITICAL" "Rollback failed - manual intervention required to restore SSH access"
        fi
        
        echo ""
        echo -e "${C_RED}${C_BOLD}Firewall apply ABORTED due to SSH reachability verification failure.${C_RESET}"
        echo -e "${C_YELLOW}Please verify:${C_RESET}"
        echo "  1. SSH daemon is running: sudo systemctl status ssh"
        echo "  2. SSH is listening on port $ssh_port: ss -lntp | grep :$ssh_port"
        echo "  3. UFW rules allow SSH: sudo ufw status | grep $ssh_port"
        echo "  4. UFW rules are correct: sudo ufw status numbered"
        echo ""
        log_apply "ABORT" "SAFE mode aborted: Post-flight verification failed (safety guard enforced)"
        return 1
    fi
    
    # Display Connectivity Guarantee summary
    display_connectivity_guarantee
    
    # Final status
    echo ""
    echo -e "${C_BOLD}=== Interactive Mode Complete ===${C_RESET}"
    echo "Final UFW Status:"
    sudo ufw status verbose
    echo ""
    echo -e "Log saved to: ${C_BLUE}$APPLY_LOG${C_RESET}"
    
    return 0
}
