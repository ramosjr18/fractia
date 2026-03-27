#!/bin/bash

# modules/network/main.sh
# Network Exposure Checks

module_meta() {
    echo "Name: Network Exposure"
    echo "Description: Checks for listening ports and bound addresses."
    echo "Version: 1.0.0"
}

module_scan() {
    # 1. Listening Ports (requires ss or netstat)
    if command_exists ss; then
        local listening
        listening=$(ss -tuln)
        
        # Check for 0.0.0.0 listeners
        local global_listeners
        global_listeners=$(echo "$listening" | grep "0.0.0.0")
        
        if [[ -n "$global_listeners" ]]; then
             add_finding "NET-001" "$SEV_MEDIUM" "$STATUS_WARN" "Global Listeners (IPv4)" \
                "Services are listening on 0.0.0.0 (all interfaces)." \
                "$(echo "$global_listeners" | head -n 3)..." \
                "Bind services to localhost (127.0.0.1) if remote access is not needed."
        else
             add_finding "NET-001" "$SEV_MEDIUM" "$STATUS_PASS" "Global Listeners (IPv4)" \
                "No services found listening on 0.0.0.0." \
                "" \
                ""
        fi

        # Check for [::] listeners
        local ipv6_global_listeners
        ipv6_global_listeners=$(echo "$listening" | grep "\[::\]")
        if [[ -n "$ipv6_global_listeners" ]]; then
             add_finding "NET-002" "$SEV_MEDIUM" "$STATUS_WARN" "Global Listeners (IPv6)" \
                "Services are listening on [::] (all IPv6 interfaces)." \
                "$(echo "$ipv6_global_listeners" | head -n 3)..." \
                "Review IPv6 exposure."
        fi
    else
        add_finding "NET-000" "$SEV_INFO" "$STATUS_WARN" "Net Tools Missing" \
            "Cannot run 'ss' command." \
            "" \
            "Install iproute2 package."
    fi
    
    # 2. IPv6 Enabled?
    if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
        local ipv6_disabled
        ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
        if [[ "$ipv6_disabled" -eq 1 ]]; then
             add_finding "NET-003" "$SEV_LOW" "$STATUS_PASS" "IPv6 Status" \
                "IPv6 it disabled system-wide." \
                "" \
                ""
        else
            add_finding "NET-003" "$SEV_LOW" "$STATUS_WARN" "IPv6 Status" \
                "IPv6 is enabled." \
                "" \
                "Disable via sysctl if not needed."
        fi
    fi
    
    return 0
}

module_apply() {
    :
}
