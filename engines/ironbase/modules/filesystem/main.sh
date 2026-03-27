#!/bin/bash

# modules/filesystem/main.sh
# Filesystem Permissions Checks

module_meta() {
    echo "Name: Filesystem Permissions"
    echo "Description: Checks /etc, /boot, /root permissions, SUID binaries, and sensitive directory permissions."
    echo "Version: 2.0.0"
}

module_scan() {
    # ========================================================================
    # SENSITIVE DIRECTORY OWNERSHIP CHECKS
    # ========================================================================
    
    # Helper function: Check directory ownership (cross-platform)
    check_dir_ownership() {
        local dir_path="$1"
        local finding_id="$2"
        local dir_name="$3"
        
        if [[ ! -d "$dir_path" ]]; then
            return 0  # Directory doesn't exist, skip
        fi
        
        local dir_owner
        if [[ "$(uname)" == "Darwin" ]]; then
            dir_owner=$(stat -f '%Su' "$dir_path" 2>/dev/null)
        else
            dir_owner=$(stat -c '%U' "$dir_path" 2>/dev/null)
        fi
        
        if [[ -z "$dir_owner" ]]; then
            add_finding "$finding_id" "$SEV_HIGH" "$STATUS_WARN" "$dir_name Ownership" \
                "Cannot determine ownership of $dir_path (permission denied or inaccessible)." \
                "" \
                "Check permissions: ls -ld $dir_path"
            return 1
        fi
        
        if [[ "$dir_owner" == "root" ]]; then
            add_finding "$finding_id" "$SEV_HIGH" "$STATUS_PASS" "$dir_name Ownership" \
                "$dir_path is owned by root." \
                "Owner: $dir_owner" \
                ""
        else
            add_finding "$finding_id" "$SEV_HIGH" "$STATUS_FAIL" "$dir_name Ownership" \
                "$dir_path is NOT owned by root." \
                "Owner: $dir_owner" \
                "chown root:root $dir_path"
        fi
    }
    
    # FS-001: /etc Ownership
    check_dir_ownership "/etc" "FS-001" "/etc"
    
    # FS-003: /boot Ownership (if exists)
    if [[ -d "/boot" ]]; then
        check_dir_ownership "/boot" "FS-003" "/boot"
    fi
    
    # FS-004: /root Ownership (if exists)
    if [[ -d "/root" ]]; then
        check_dir_ownership "/root" "FS-004" "/root"
    fi
    
    # FS-005: /var/log Ownership
    if [[ -d "/var/log" ]]; then
        check_dir_ownership "/var/log" "FS-005" "/var/log"
    fi
    
    # FS-006: /usr/bin Ownership (critical system binaries)
    if [[ -d "/usr/bin" ]]; then
        check_dir_ownership "/usr/bin" "FS-006" "/usr/bin"
    fi
    
    # FS-007: /usr/sbin Ownership (critical system binaries)
    if [[ -d "/usr/sbin" ]]; then
        check_dir_ownership "/usr/sbin" "FS-007" "/usr/sbin"
    fi
    
    # ========================================================================
    # WORLD WRITABLE FILES IN SENSITIVE DIRECTORIES (RECURSIVE)
    # ========================================================================
    
    # Helper function: Check world-writable files (recursive, configurable depth)
    check_world_writable() {
        local dir_path="$1"
        local finding_id="$2"
        local dir_name="$3"
        local max_depth="${4:-3}"  # Default depth 3
        
        if [[ ! -d "$dir_path" ]]; then
            return 0  # Directory doesn't exist, skip
        fi
        
        local ww_files
        ww_files=$(find "$dir_path" -maxdepth "$max_depth" -type f -perm -0002 2>/dev/null | head -n 10)
        
        # Sanitize count: ensure single-line integer
        local count=$(echo "$ww_files" | grep -v "^$" | wc -l | head -n1 | tr -d '[:space:]')
        [[ "$count" =~ ^[0-9]+$ ]] || count=0
        
        if [[ "$count" -gt 0 ]]; then
            local sample=$(echo "$ww_files" | head -n 5)
            add_finding "$finding_id" "$SEV_HIGH" "$STATUS_FAIL" "World Writable $dir_name" \
                "Found $count world writable file(s) in $dir_path (depth $max_depth)." \
                "$(echo "$sample" | head -n 5)" \
                "Review and remove write permission for others: chmod o-w <file>"
        else
            add_finding "$finding_id" "$SEV_HIGH" "$STATUS_PASS" "World Writable $dir_name" \
                "No world writable files found in $dir_path (depth $max_depth)." \
                "" \
                ""
        fi
    }
    
    # FS-002: World Writable /etc (recursive, depth 3)
    check_world_writable "/etc" "FS-002" "/etc" "3"
    
    # FS-008: World Writable /boot (if exists, depth 2)
    if [[ -d "/boot" ]]; then
        check_world_writable "/boot" "FS-008" "/boot" "2"
    fi
    
    # FS-009: World Writable /root (if exists, depth 2)
    if [[ -d "/root" ]]; then
        check_world_writable "/root" "FS-009" "/root" "2"
    fi
    
    # FS-010: World Writable /var/log (depth 2)
    if [[ -d "/var/log" ]]; then
        check_world_writable "/var/log" "FS-010" "/var/log" "2"
    fi
    
    # ========================================================================
    # FULL PERMISSION MODE ANALYSIS
    # ========================================================================
    
    # Helper function: Check directory permissions (full mode analysis)
    check_dir_permissions() {
        local dir_path="$1"
        local finding_id="$2"
        local dir_name="$3"
        local expected_perm="$4"  # Expected permissions (e.g., "755" or "700")
        
        if [[ ! -d "$dir_path" ]]; then
            return 0
        fi
        
        local current_perm
        if [[ "$(uname)" == "Darwin" ]]; then
            current_perm=$(stat -f '%A' "$dir_path" 2>/dev/null)
        else
            current_perm=$(stat -c '%a' "$dir_path" 2>/dev/null)
        fi
        
        if [[ -z "$current_perm" ]]; then
            return 1
        fi
        
        # Sanitize: ensure numeric
        [[ "$current_perm" =~ ^[0-9]+$ ]] || return 1
        
        # Extract last 3 digits (permissions for owner/group/other)
        local perm_octal="${current_perm: -3}"
        
        # Check if world (other) has write permission
        # Permission digits: 2=write, 3=write+execute, 6=read+write, 7=all (all have write)
        # 4=read, 5=read+execute (no write)
        local other_perm="${perm_octal: -1}"
        if [[ "$other_perm" =~ ^[2367]$ ]]; then
            add_finding "$finding_id" "$SEV_HIGH" "$STATUS_FAIL" "$dir_name Permissions" \
                "$dir_path has permissive permissions ($perm_octal). World/other has write access (permission digit: $other_perm)." \
                "Current permissions: $perm_octal (stat -c '%a' $dir_path)" \
                "Restrict permissions: chmod $expected_perm $dir_path"
        elif [[ -n "$expected_perm" ]] && [[ "$perm_octal" != "$expected_perm" ]]; then
            add_finding "$finding_id" "$SEV_MEDIUM" "$STATUS_WARN" "$dir_name Permissions" \
                "$dir_path permissions ($perm_octal) differ from expected ($expected_perm)." \
                "Current: $perm_octal | Expected: $expected_perm" \
                "Set expected permissions: chmod $expected_perm $dir_path"
        else
            add_finding "$finding_id" "$SEV_MEDIUM" "$STATUS_PASS" "$dir_name Permissions" \
                "$dir_path has acceptable permissions ($perm_octal)." \
                "" \
                ""
        fi
    }
    
    # FS-011: /etc permissions (should be 755 or stricter)
    check_dir_permissions "/etc" "FS-011" "/etc" "755"
    
    # FS-012: /root permissions (should be 700)
    if [[ -d "/root" ]]; then
        check_dir_permissions "/root" "FS-012" "/root" "700"
    fi
    
    # FS-013: /boot permissions (should be 755)
    if [[ -d "/boot" ]]; then
        check_dir_permissions "/boot" "FS-013" "/boot" "755"
    fi
    
    # ========================================================================
    # SUID BINARY SCANNING
    # ========================================================================
    
    # FS-014: SUID binaries scan
    if command_exists find; then
        # Find SUID binaries in common system directories
        local suid_binaries
        suid_binaries=$(find /usr/bin /usr/sbin /bin /sbin -type f -perm -4000 2>/dev/null | head -n 20)
        
        # Sanitize count
        local suid_count=$(echo "$suid_binaries" | grep -v "^$" | wc -l | head -n1 | tr -d '[:space:]')
        [[ "$suid_count" =~ ^[0-9]+$ ]] || suid_count=0
        
        if [[ "$suid_count" -gt 0 ]]; then
            # Common expected SUID binaries (whitelist)
            local expected_suid="passwd mount umount su sudo ping chfn chsh gpasswd newgrp"
            local unexpected_suid=""
            local expected_found=""
            
            while IFS= read -r suid_file; do
                [[ -z "$suid_file" ]] && continue
                local basename_file=$(basename "$suid_file")
                if echo "$expected_suid" | grep -qw "$basename_file"; then
                    expected_found="$expected_found\n$suid_file"
                else
                    unexpected_suid="$unexpected_suid\n$suid_file"
                fi
            done <<< "$suid_binaries"
            
            # Sanitize unexpected count
            local unexpected_count=$(echo -e "$unexpected_suid" | grep -v "^$" | wc -l | head -n1 | tr -d '[:space:]')
            [[ "$unexpected_count" =~ ^[0-9]+$ ]] || unexpected_count=0
            
            if [[ "$unexpected_count" -gt 0 ]]; then
                local sample_unexpected=$(echo -e "$unexpected_suid" | grep -v "^$" | head -n 10)
                add_finding "FS-014" "$SEV_HIGH" "$STATUS_WARN" "Unexpected SUID Binaries" \
                    "Found $unexpected_count unexpected SUID binary(ies) out of $suid_count total. SUID binaries run with owner privileges and pose privilege escalation risk if compromised." \
                    "$(echo -e "$sample_unexpected" | head -n 10)" \
                    "Review SUID binaries: ls -l <file> | grep '^-..s' | head -20. Remove SUID bit if not needed: chmod u-s <file>"
            else
                add_finding "FS-014" "$SEV_MEDIUM" "$STATUS_PASS" "SUID Binaries" \
                    "Found $suid_count SUID binary(ies), all appear to be expected system binaries." \
                    "$(echo -e "$suid_binaries" | head -n 10)" \
                    "Periodically review SUID binaries for unauthorized additions."
            fi
        else
            add_finding "FS-014" "$SEV_INFO" "$STATUS_PASS" "SUID Binaries" \
                "No SUID binaries found in common system directories." \
                "" \
                ""
        fi
    else
        add_finding "FS-014" "$SEV_MEDIUM" "$STATUS_WARN" "SUID Binaries" \
            "Cannot scan for SUID binaries: 'find' command not found." \
            "" \
            "Install findutils package."
    fi
    
    # FS-015: SGID binaries scan
    if command_exists find; then
        local sgid_binaries
        sgid_binaries=$(find /usr/bin /usr/sbin /bin /sbin -type f -perm -2000 2>/dev/null | head -n 20)
        
        local sgid_count=$(echo "$sgid_binaries" | grep -v "^$" | wc -l | head -n1 | tr -d '[:space:]')
        [[ "$sgid_count" =~ ^[0-9]+$ ]] || sgid_count=0
        
        if [[ "$sgid_count" -gt 0 ]]; then
            local sample_sgid=$(echo "$sgid_binaries" | head -n 10)
            add_finding "FS-015" "$SEV_MEDIUM" "$STATUS_WARN" "SGID Binaries" \
                "Found $sgid_count SGID binary(ies). SGID binaries run with group privileges." \
                "$(echo "$sample_sgid" | head -n 10)" \
                "Review SGID binaries: ls -l <file> | grep '^-....s'. Remove SGID bit if not needed: chmod g-s <file>"
        fi
    fi
    
    # FS-016: World-writable directories in PATH (security risk)
    if [[ -n "$PATH" ]]; then
        local writable_path_dirs=""
        IFS=':' read -ra PATH_DIRS <<< "$PATH"
        for dir in "${PATH_DIRS[@]}"; do
            [[ -z "$dir" ]] && continue
            # Resolve symlinks
            local real_path=$(readlink -f "$dir" 2>/dev/null || echo "$dir")
            if [[ -d "$real_path" ]]; then
                # Check if world-writable (other has write permission)
                local perms
                if [[ "$(uname)" == "Darwin" ]]; then
                    perms=$(stat -f '%A' "$real_path" 2>/dev/null)
                else
                    perms=$(stat -c '%a' "$real_path" 2>/dev/null)
                fi
                
                if [[ -n "$perms" ]] && [[ "$perms" =~ ^[0-9]+$ ]]; then
                    local perm_octal="${perms: -3}"
                    local other_perm="${perm_octal: -1}"
                    # Check if other has write (2, 3, 6, 7)
                    if [[ "$other_perm" =~ [2367] ]]; then
                        if [[ -z "$writable_path_dirs" ]]; then
                            writable_path_dirs="$dir (-> $real_path, perms: $perm_octal)"
                        else
                            writable_path_dirs="$writable_path_dirs, $dir (-> $real_path, perms: $perm_octal)"
                        fi
                    fi
                fi
            fi
        done
        
        if [[ -n "$writable_path_dirs" ]]; then
            add_finding "FS-016" "$SEV_HIGH" "$STATUS_FAIL" "World Writable PATH Directory" \
                "Found world-writable directory(ies) in PATH. This allows privilege escalation if an attacker can write to these directories." \
                "$writable_path_dirs" \
                "Remove write permission for others: chmod o-w <directory>"
        else
            add_finding "FS-016" "$SEV_HIGH" "$STATUS_PASS" "PATH Directory Permissions" \
                "No world-writable directories found in PATH." \
                "" \
                ""
        fi
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
    
    # Initialize apply log
    local apply_log="filesystem-apply.log"
    if [[ -n "$IRONBASE_RUN_DIR" ]] && [[ -d "$IRONBASE_RUN_DIR" ]] && [[ "$IRONBASE_RUN_DIR" != "/" ]]; then
        apply_log="$IRONBASE_RUN_DIR/filesystem-apply.log"
    fi
    
    init_apply_log() {
        echo "IronBase - Filesystem Remediation Log" > "$apply_log"
        echo "Date: $(date)" >> "$apply_log"
        echo "Hostname: $(hostname)" >> "$apply_log"
        local mode="SAFE"
        if [[ "$IRONBASE_FORCE" == "true" ]]; then
            mode="FORCE"
        fi
        echo "Mode: $mode" >> "$apply_log"
        echo "-------------------------------------" >> "$apply_log"
    }
    
    log_apply() {
        local status="$1"
        local msg="$2"
        echo "[$status] $msg" >> "$apply_log"
        echo -e "${C_BLUE}[$status]${C_RESET} $msg"
    }
    
    backup_file() {
        local file="$1"
        local backup="${file}.bak.$(date +%s)"
        if [[ -f "$file" ]]; then
            cp "$file" "$backup" 2>/dev/null || return 1
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
        
        if [[ "$IRONBASE_FORCE" == "true" ]]; then
            log_apply "FORCE" "Auto-confirming: $prompt (FORCE mode)"
            return 0
        fi
        
        read -p "$(echo -e "${C_YELLOW}$prompt $options${C_RESET} "): " response < /dev/tty
        response=${response:-$default}
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            return 0
        else
            return 1
        fi
    }
    
    # Helper function: Fix directory ownership
    fix_dir_ownership() {
        local dir_path="$1"
        local finding_id="$2"
        
        if [[ ! -d "$dir_path" ]]; then
            log_apply "SKIP" "Directory $dir_path does not exist"
            return 0
        fi
        
        local current_owner
        if [[ "$(uname)" == "Darwin" ]]; then
            current_owner=$(stat -f '%Su' "$dir_path" 2>/dev/null)
        else
            current_owner=$(stat -c '%U' "$dir_path" 2>/dev/null)
        fi
        
        if [[ "$current_owner" != "root" ]]; then
            if confirm_action "Fix ownership of $dir_path (current: $current_owner -> root:root)?" "Y"; then
                if sudo chown root:root "$dir_path" 2>&1 | tee -a "$apply_log"; then
                    log_apply "SUCCESS" "Fixed ownership of $dir_path to root:root"
                    echo -e "${C_GREEN}✓ Fixed ownership of $dir_path${C_RESET}"
                else
                    log_apply "ERROR" "Failed to fix ownership of $dir_path"
                    echo -e "${C_RED}✗ Failed to fix ownership of $dir_path${C_RESET}"
                    return 1
                fi
            else
                log_apply "SKIP" "User skipped fixing ownership of $dir_path"
            fi
        else
            log_apply "SKIP" "$dir_path already owned by root"
        fi
    }
    
    # Helper function: Fix world-writable files
    fix_world_writable() {
        local dir_path="$1"
        local max_depth="${2:-3}"
        
        if [[ ! -d "$dir_path" ]]; then
            return 0
        fi
        
        local ww_files
        ww_files=$(find "$dir_path" -maxdepth "$max_depth" -type f -perm -0002 2>/dev/null | head -n 20)
        
        if [[ -z "$ww_files" ]]; then
            log_apply "SKIP" "No world-writable files found in $dir_path"
            return 0
        fi
        
        local count=$(echo "$ww_files" | grep -v "^$" | wc -l | head -n1 | tr -d '[:space:]')
        [[ "$count" =~ ^[0-9]+$ ]] || count=0
        
        if [[ "$count" -gt 0 ]]; then
            echo -e "\n${C_YELLOW}Found $count world-writable file(s) in $dir_path${C_RESET}"
            echo "$ww_files" | head -n 10
            
            if confirm_action "Remove world-writable permission from these files?" "Y"; then
                local fixed=0
                local failed=0
                while IFS= read -r file; do
                    [[ -z "$file" ]] && continue
                    if sudo chmod o-w "$file" 2>&1 | tee -a "$apply_log"; then
                        log_apply "SUCCESS" "Removed world-writable from $file"
                        ((fixed++))
                    else
                        log_apply "ERROR" "Failed to fix $file"
                        ((failed++))
                    fi
                done <<< "$ww_files"
                
                echo -e "${C_GREEN}✓ Fixed $fixed file(s)${C_RESET}"
                if [[ "$failed" -gt 0 ]]; then
                    echo -e "${C_RED}✗ Failed to fix $failed file(s)${C_RESET}"
                fi
            else
                log_apply "SKIP" "User skipped fixing world-writable files in $dir_path"
            fi
        fi
    }
    
    # Helper function: Fix directory permissions
    fix_dir_permissions() {
        local dir_path="$1"
        local expected_perm="$2"
        
        if [[ ! -d "$dir_path" ]]; then
            return 0
        fi
        
        local current_perm
        if [[ "$(uname)" == "Darwin" ]]; then
            current_perm=$(stat -f '%A' "$dir_path" 2>/dev/null)
        else
            current_perm=$(stat -c '%a' "$dir_path" 2>/dev/null)
        fi
        
        if [[ -z "$current_perm" ]]; then
            return 1
        fi
        
        [[ "$current_perm" =~ ^[0-9]+$ ]] || return 1
        local perm_octal="${current_perm: -3}"
        
        if [[ "$perm_octal" != "$expected_perm" ]]; then
            if confirm_action "Fix permissions of $dir_path (current: $perm_octal -> expected: $expected_perm)?" "Y"; then
                if sudo chmod "$expected_perm" "$dir_path" 2>&1 | tee -a "$apply_log"; then
                    log_apply "SUCCESS" "Fixed permissions of $dir_path to $expected_perm"
                    echo -e "${C_GREEN}✓ Fixed permissions of $dir_path to $expected_perm${C_RESET}"
                else
                    log_apply "ERROR" "Failed to fix permissions of $dir_path"
                    echo -e "${C_RED}✗ Failed to fix permissions of $dir_path${C_RESET}"
                    return 1
                fi
            else
                log_apply "SKIP" "User skipped fixing permissions of $dir_path"
            fi
        else
            log_apply "SKIP" "$dir_path already has expected permissions ($expected_perm)"
        fi
    }
    
    # Helper function: Remove SUID bit from unexpected binaries
    fix_suid_binary() {
        local suid_file="$1"
        
        if [[ ! -f "$suid_file" ]]; then
            return 1
        fi
        
        local basename_file=$(basename "$suid_file")
        if confirm_action "Remove SUID bit from $suid_file?" "N"; then
            if sudo chmod u-s "$suid_file" 2>&1 | tee -a "$apply_log"; then
                log_apply "SUCCESS" "Removed SUID bit from $suid_file"
                echo -e "${C_GREEN}✓ Removed SUID bit from $suid_file${C_RESET}"
                return 0
            else
                log_apply "ERROR" "Failed to remove SUID bit from $suid_file"
                echo -e "${C_RED}✗ Failed to remove SUID bit from $suid_file${C_RESET}"
                return 1
            fi
        else
            log_apply "SKIP" "User skipped removing SUID bit from $suid_file"
            return 1
        fi
    }
    
    # Helper function: Fix world-writable PATH directories
    fix_writable_path() {
        local dir_path="$1"
        
        if [[ ! -d "$dir_path" ]]; then
            return 0
        fi
        
        local perms
        if [[ "$(uname)" == "Darwin" ]]; then
            perms=$(stat -f '%A' "$dir_path" 2>/dev/null)
        else
            perms=$(stat -c '%a' "$dir_path" 2>/dev/null)
        fi
        
        if [[ -z "$perms" ]] || ! [[ "$perms" =~ ^[0-9]+$ ]]; then
            return 1
        fi
        
        local perm_octal="${perms: -3}"
        local other_perm="${perm_octal: -1}"
        
        if [[ "$other_perm" =~ [2367] ]]; then
            # Calculate new permissions (remove write from other)
            local owner_perm="${perm_octal:0:1}"
            local group_perm="${perm_octal:1:1}"
            local new_other_perm="4"  # read only
            local new_perm="${owner_perm}${group_perm}${new_other_perm}"
            
            if confirm_action "Fix world-writable PATH directory $dir_path (current: $perm_octal -> new: $new_perm)?" "Y"; then
                if sudo chmod "$new_perm" "$dir_path" 2>&1 | tee -a "$apply_log"; then
                    log_apply "SUCCESS" "Fixed permissions of PATH directory $dir_path to $new_perm"
                    echo -e "${C_GREEN}✓ Fixed permissions of $dir_path to $new_perm${C_RESET}"
                    return 0
                else
                    log_apply "ERROR" "Failed to fix permissions of $dir_path"
                    echo -e "${C_RED}✗ Failed to fix permissions of $dir_path${C_RESET}"
                    return 1
                fi
            else
                log_apply "SKIP" "User skipped fixing PATH directory $dir_path"
                return 1
            fi
        fi
        return 0
    }
    
    # Initialize log
    init_apply_log
    
    echo -e "${C_BOLD}Starting Filesystem Remediation${C_RESET}"
    echo -e "${C_YELLOW}WARNING: You are about to modify filesystem permissions and ownership.${C_RESET}"
    echo "This tool will prompt for confirmation before every action."
    echo "Log will be saved to: $apply_log"
    echo ""
    
    # Step 1: Fix directory ownership
    echo -e "${C_BOLD}>>> Step 1: Fixing Directory Ownership <<<${C_RESET}"
    fix_dir_ownership "/etc" "FS-001"
    [[ -d "/boot" ]] && fix_dir_ownership "/boot" "FS-003"
    [[ -d "/root" ]] && fix_dir_ownership "/root" "FS-004"
    [[ -d "/var/log" ]] && fix_dir_ownership "/var/log" "FS-005"
    [[ -d "/usr/bin" ]] && fix_dir_ownership "/usr/bin" "FS-006"
    [[ -d "/usr/sbin" ]] && fix_dir_ownership "/usr/sbin" "FS-007"
    
    # Step 2: Fix world-writable files
    echo ""
    echo -e "${C_BOLD}>>> Step 2: Fixing World-Writable Files <<<${C_RESET}"
    fix_world_writable "/etc" 3
    [[ -d "/boot" ]] && fix_world_writable "/boot" 2
    [[ -d "/root" ]] && fix_world_writable "/root" 2
    [[ -d "/var/log" ]] && fix_world_writable "/var/log" 2
    
    # Step 3: Fix directory permissions
    echo ""
    echo -e "${C_BOLD}>>> Step 3: Fixing Directory Permissions <<<${C_RESET}"
    fix_dir_permissions "/etc" "755"
    [[ -d "/root" ]] && fix_dir_permissions "/root" "700"
    [[ -d "/boot" ]] && fix_dir_permissions "/boot" "755"
    
    # Step 4: Review and fix unexpected SUID binaries
    echo ""
    echo -e "${C_BOLD}>>> Step 4: Reviewing SUID Binaries <<<${C_RESET}"
    if command_exists find; then
        local suid_binaries
        suid_binaries=$(find /usr/bin /usr/sbin /bin /sbin -type f -perm -4000 2>/dev/null | head -n 20)
        
        if [[ -n "$suid_binaries" ]]; then
            local expected_suid="passwd mount umount su sudo ping chfn chsh gpasswd newgrp"
            local unexpected_found=0
            
            while IFS= read -r suid_file; do
                [[ -z "$suid_file" ]] && continue
                local basename_file=$(basename "$suid_file")
                if ! echo "$expected_suid" | grep -qw "$basename_file"; then
                    echo -e "${C_YELLOW}Unexpected SUID binary: $suid_file${C_RESET}"
                    fix_suid_binary "$suid_file"
                    unexpected_found=1
                fi
            done <<< "$suid_binaries"
            
            if [[ "$unexpected_found" -eq 0 ]]; then
                log_apply "INFO" "All SUID binaries appear to be expected system binaries"
                echo -e "${C_GREEN}✓ All SUID binaries are expected${C_RESET}"
            fi
        fi
    else
        log_apply "WARN" "Cannot scan SUID binaries: 'find' command not found"
        echo -e "${C_YELLOW}Warning: 'find' command not found. Cannot scan SUID binaries.${C_RESET}"
    fi
    
    # Step 5: Fix world-writable PATH directories
    echo ""
    echo -e "${C_BOLD}>>> Step 5: Fixing World-Writable PATH Directories <<<${C_RESET}"
    if [[ -n "$PATH" ]]; then
        IFS=':' read -ra PATH_DIRS <<< "$PATH"
        for dir in "${PATH_DIRS[@]}"; do
            [[ -z "$dir" ]] && continue
            local real_path=$(readlink -f "$dir" 2>/dev/null || echo "$dir")
            if [[ -d "$real_path" ]]; then
                fix_writable_path "$real_path"
            fi
        done
    fi
    
    echo ""
    echo "-------------------------------------"
    echo -e "${C_BOLD}Filesystem Remediation Complete${C_RESET}"
    echo "Please review $apply_log"
    log_apply "COMPLETE" "Filesystem remediation completed"
    
    return 0
}
