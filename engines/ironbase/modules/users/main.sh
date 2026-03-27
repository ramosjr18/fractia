#!/bin/bash

# modules/users/main.sh
# User and Privilege Checks

module_meta() {
    echo "Name: Users & Privileges"
    echo "Description: Checks UIDs, Sudoers, and Password policies."
    echo "Version: 1.0.0"
}

module_scan() {
    # 1. UID 0 Duplicates
    if [[ -f /etc/passwd ]]; then
        local uid0_users
        uid0_users=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
        local count
        count=$(echo "$uid0_users" | wc -l | xargs)
        
        if [[ "$count" -eq 1 ]]; then
             add_finding "USR-001" "$SEV_CRITICAL" "$STATUS_PASS" "UID 0 Users" \
                "Only one user with UID 0 found (root)." \
                "$uid0_users" \
                ""
        else
             add_finding "USR-001" "$SEV_CRITICAL" "$STATUS_FAIL" "UID 0 Users" \
                "Multiple users with UID 0 detected!" \
                "Users: $uid0_users" \
                "Remove unnecessary UID 0 accounts immediately."
        fi
    else
         add_finding "USR-001" "$SEV_CRITICAL" "$STATUS_WARN" "UID 0 Users" \
            "Cannot read /etc/passwd." \
            "" \
            "Check usage permissions."
    fi

    # 2. Users with Empty Passwords
    if [[ -f /etc/shadow ]] && [[ -r /etc/shadow ]]; then
        local empty_pw
        empty_pw=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow)
        if [[ -n "$empty_pw" ]]; then
            add_finding "USR-002" "$SEV_HIGH" "$STATUS_FAIL" "Empty Passwords" \
                "Users found with empty passwords." \
                "Users: $empty_pw" \
                "Lock accounts or set passwords."
        else
            add_finding "USR-002" "$SEV_HIGH" "$STATUS_PASS" "Empty Passwords" \
                "No users with empty passwords found." \
                "" \
                ""
        fi
    else
         # Often we can't read shadow as non-root user, so careful with WARN vs INFO
         if [ "$EUID" -ne 0 ]; then
            add_finding "USR-002" "$SEV_HIGH" "$STATUS_WARN" "Empty Passwords" \
                "Cannot read /etc/shadow (permission denied)." \
                "Run as root for full check." \
                ""
         fi
    fi

    # 3. Sudoers
    if [[ -f /etc/sudoers ]]; then
        if grep -q "NOPASSWD" /etc/sudoers; then
             add_finding "USR-003" "$SEV_HIGH" "$STATUS_WARN" "Sudoers NOPASSWD" \
                "Sudoers file contains NOPASSWD directives." \
                "grep NOPASSWD /etc/sudoers" \
                "Review sudoers file to ensure NOPASSWD is strictly limited."
        else
             add_finding "USR-003" "$SEV_HIGH" "$STATUS_PASS" "Sudoers NOPASSWD" \
                "No NOPASSWD directives found in /etc/sudoers." \
                "" \
                ""
        fi
    fi

    # 4. Check Root Password Integrity (is it locked?)
    # Typically root should be locked on Ubuntu (passwd -l root) which sets shell to nologin or pw to '!' or '*'
    if [[ -f /etc/shadow ]] && [[ -r /etc/shadow ]]; then
        local root_hash
        root_hash=$(grep "^root:" /etc/shadow | cut -d: -f2)
        if [[ "$root_hash" == "*" ]] || [[ "$root_hash" == "!"* ]]; then
            add_finding "USR-004" "$SEV_MEDIUM" "$STATUS_PASS" "Root Account Locked" \
                "Root account password is locked (standard for Ubuntu)." \
                "" \
                ""
        else
             add_finding "USR-004" "$SEV_MEDIUM" "$STATUS_WARN" "Root Account Locked" \
                "Root account has a valid password hash or is not strictly locked." \
                "" \
                "Ensure this is intentional."
        fi
    fi

    return 0
}

module_list() {
    echo ""
    echo "=== System Users and Privileges ==="
    echo ""
    
    # Header
    printf "%-16s %-8s %-8s %-12s %-20s %-20s %-10s\n" \
        "USERNAME" "UID" "GID" "PRIVILEGE" "SHELL" "HOME" "STATUS"
    printf "%-16s %-8s %-8s %-12s %-20s %-20s %-10s\n" \
        "--------" "---" "---" "---------" "-----" "----" "------"
    
    # Read /etc/passwd
    while IFS=: read -r username _ uid gid _ home shell; do
        # Determine privilege level
        local privilege="USER"
        local status="ACTIVE"
        
        # Check if UID 0 (root)
        if [[ "$uid" -eq 0 ]]; then
            privilege="ROOT"
        else
            # Check if user is in sudo/admin groups
            if groups "$username" 2>/dev/null | grep -qE '\b(sudo|admin|wheel)\b'; then
                privilege="SUDO"
            fi
        fi
        
        # Check account status from /etc/shadow if readable
        if [[ -r /etc/shadow ]]; then
            local shadow_entry
            shadow_entry=$(grep "^${username}:" /etc/shadow 2>/dev/null)
            if [[ -n "$shadow_entry" ]]; then
                local password_field
                password_field=$(echo "$shadow_entry" | cut -d: -f2)
                if [[ "$password_field" == "!"* ]] || [[ "$password_field" == "*" ]] || [[ "$password_field" == "!!" ]]; then
                    status="LOCKED"
                fi
            fi
        fi
        
        # Truncate long paths for display
        local display_shell="${shell##*/}"
        local display_home="$home"
        if [[ ${#display_home} -gt 20 ]]; then
            display_home="...${display_home: -17}"
        fi
        
        # Print user info
        printf "%-16s %-8s %-8s %-12s %-20s %-20s %-10s\n" \
            "$username" "$uid" "$gid" "$privilege" "$display_shell" "$display_home" "$status"
            
    done < /etc/passwd
    
    echo ""
    echo "Legend:"
    echo "  ROOT  - User with UID 0 (superuser)"
    echo "  SUDO  - User in sudo/admin/wheel group"
    echo "  USER  - Regular user without elevated privileges"
    echo ""
    
    if [[ ! -r /etc/shadow ]]; then
        echo "Note: Run with sudo to see account lock status"
        echo ""
    fi
}

module_apply() {
    # No apply logic for this module check
    :
}
