#!/bin/bash

# modules/system/main.sh
# General System Hardening (Updates, etc)

module_meta() {
    echo "Name: System Updates & Config"
    echo "Description: Checks OS version, updates, and core configurations."
    echo "Version: 1.1.0"
}

module_scan() {
    # 1. OS Version & EOL (Mock check for Ubuntu)
    local os_name
    os_name=$(grep "^NAME=" /etc/os-release | cut -d= -f2 | tr -d '"')
    local os_ver
    os_ver=$(grep "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    
    add_finding "SYS-001" "$SEV_INFO" "$STATUS_PASS" "OS Detection" \
        "Detected Operating System version." \
        "$os_name $os_ver" \
        ""

    # 2. Kernel Version
    local kernel
    kernel=$(uname -r)
    add_finding "SYS-002" "$SEV_INFO" "$STATUS_PASS" "Kernel Version" \
        "Current running kernel." \
        "$kernel" \
        ""

    # 3. Time Sync
    if command_exists timedatectl; then
        if timedatectl status | grep -q "System clock synchronized: yes"; then
            add_finding "SYS-003" "$SEV_MEDIUM" "$STATUS_PASS" "Time Synchronized" \
                "System clock is synchronized." \
                "timedatectl status: yes" \
                ""
        else
             add_finding "SYS-003" "$SEV_MEDIUM" "$STATUS_WARN" "Time Synchronized" \
                "System clock is NOT synchronized. Investigate NTP config." \
                "timedatectl status: no" \
                "Ensure chrony or systemd-timesyncd is active."
        fi
    else
         add_finding "SYS-003" "$SEV_MEDIUM" "$STATUS_WARN" "Time Synchronized" \
            "Cannot determine time sync status (timedatectl not found)." \
            "" \
            "Install systemd-timesyncd or chrony."
    fi

    # 4. Updates Available
    # Check for update-notifier
    local updates_file="/var/lib/update-notifier/updates-available"
    if [[ -f "$updates_file" ]] && [[ -s "$updates_file" ]]; then
         # Check content
         local content
         content=$(cat "$updates_file")
         add_finding "SYS-004" "$SEV_HIGH" "$STATUS_WARN" "System Updates" \
            "Pending updates detected." \
            "$content" \
            "Run 'apt-get update && apt-get upgrade'"
    else
         add_finding "SYS-004" "$SEV_HIGH" "$STATUS_PASS" "System Updates" \
            "No pending updates detected via update-notifier." \
            "" \
            ""
    fi
    
    # 5. Automatic Updates
    if [[ -f "/etc/apt/apt.conf.d/20auto-upgrades" ]]; then
        if grep -q "APT::Periodic::Update-Package-Lists \"1\"" "/etc/apt/apt.conf.d/20auto-upgrades"; then
             add_finding "SYS-005" "$SEV_MEDIUM" "$STATUS_PASS" "Automatic Updates" \
                "Automatic updates seem enabled." \
                "Config found in /etc/apt/apt.conf.d/20auto-upgrades" \
                ""
        else
             add_finding "SYS-005" "$SEV_MEDIUM" "$STATUS_WARN" "Automatic Updates" \
                "Automatic updates config found but might be disabled." \
                "Check /etc/apt/apt.conf.d/20auto-upgrades" \
                "Enable unattended-upgrades."
        fi
    else
         add_finding "SYS-005" "$SEV_MEDIUM" "$STATUS_WARN" "Automatic Updates" \
            "Automatic updates configuration not found." \
            "Missing /etc/apt/apt.conf.d/20auto-upgrades" \
            "Install and configure unattended-upgrades."
    fi

    return 0
}

module_apply() {
    # Scan only expansion for now, preserving old apply mock for updates
    echo "APPLY: Running system updates..."
    # sudo apt-get update && sudo apt-get upgrade -y
}
