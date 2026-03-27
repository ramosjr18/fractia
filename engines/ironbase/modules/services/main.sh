#!/bin/bash

# modules/services/main.sh
# Services, Containers, and Logging

module_meta() {
    echo "Name: Services & Logging"
    echo "Description: Checks active services, docker, and audit components."
    echo "Version: 1.0.0"
}

module_scan() {
    # 1. Docker
    if command_exists docker; then
        add_finding "SVC-001" "$SEV_INFO" "$STATUS_PASS" "Docker Installed" \
            "Docker is present on the system." \
            "" \
            ""
        
        # Check permissions on socket (usually root:docker)
        if [[ -S /var/run/docker.sock ]]; then
            local perms
            perms=$(ls -l /var/run/docker.sock)
            add_finding "SVC-002" "$SEV_LOW" "$STATUS_WARN" "Docker Socket" \
                "Docker socket available." \
                "$perms" \
                "Ensure only trusted users are in docker group."
        fi
    else
        add_finding "SVC-001" "$SEV_INFO" "$STATUS_PASS" "Docker Installed" \
            "Docker is not installed." \
            "" \
            ""
    fi

    # 2. Auditd
    if command_exists auditd; then
         # Check if running
         if pgrep auditd > /dev/null; then
             add_finding "SVC-003" "$SEV_MEDIUM" "$STATUS_PASS" "Auditd" \
                "Auditd is installed and running." \
                "" \
                ""
         else
             add_finding "SVC-003" "$SEV_MEDIUM" "$STATUS_WARN" "Auditd" \
                "Auditd is installed but NOT running." \
                "" \
                "Start auditd service."
         fi
    else
         add_finding "SVC-003" "$SEV_MEDIUM" "$STATUS_WARN" "Auditd" \
            "Auditd not detected." \
            "" \
            "Install 'auditd' for system accounting."
    fi

    # 3. Journald Logging
    if [[ -d /var/log/journal ]]; then
        add_finding "SVC-004" "$SEV_LOW" "$STATUS_PASS" "Journald Persistence" \
            "Persistent journald logging enabled (/var/log/journal exists)." \
            "" \
            ""
    else
         add_finding "SVC-004" "$SEV_LOW" "$STATUS_WARN" "Journald Persistence" \
            "Journald persistence might not be enabled (memory only?)." \
            "Check /etc/systemd/journald.conf" \
            ""
    fi

    return 0
}

module_apply() {
    :
}
