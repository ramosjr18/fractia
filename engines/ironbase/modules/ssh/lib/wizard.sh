#!/bin/bash
# modules/ssh/lib/wizard.sh
# Shared SSH Hardening Logic

# Ensure dependencies are available or mock them if running standalone without common lib
if ! command -v log_apply &> /dev/null; then
    # Fallback logger if not provided by parent
    log_apply() {
        local status="$1"
        local msg="$2"
        echo "[$status] $msg"
    }
fi

if ! command -v backup_file &> /dev/null; then
    backup_file() {
        local file="$1"
        local backup="${file}.bak.$(date +%s)"
        if [[ -f "$file" ]]; then
            cp "$file" "$backup"
            log_apply "INFO" "Backed up $file to $backup"
            echo -e "Backed up $file to $backup"
        fi
    }
fi

create_ssh_user() {
    local disable_root_intent="$1"

    echo -e "\n${C_BOLD}>>> User Creation Wizard${C_RESET}"
    read -p "Enter new username: " new_user < /dev/tty
    
    # Validation
    if id "$new_user" &>/dev/null; then
        echo -e "${C_RED}Error: User '$new_user' already exists.${C_RESET}"
        return 1
    fi
    if [[ -z "$new_user" || "$new_user" == "root" ]]; then
        echo -e "${C_RED}Error: Invalid username.${C_RESET}"
        return 1
    fi

    echo -e "\nSelect Privileges:"
    echo "1) Sudo / Admin (Recommended for replacement)"
    echo "2) Limited User"
    read -p "Choice [1/2]: " priv_choice < /dev/tty
    
    # Create user
    useradd -m -s /bin/bash "$new_user"
    if [[ $? -ne 0 ]]; then
        log_apply "ERROR" "Failed to create user $new_user"
        return 1
    fi

    # Password
    echo -e "\n${C_YELLOW}Set password for $new_user:${C_RESET}"
    passwd "$new_user" < /dev/tty
    if [[ $? -ne 0 ]]; then
        echo -e "${C_RED}Password set failed. Deleting user...${C_RESET}"
        userdel -r "$new_user"
        return 1
    fi

    # Sudo
    if [[ "$priv_choice" == "1" ]]; then
        usermod -aG sudo "$new_user" 2>/dev/null || usermod -aG wheel "$new_user" 2>/dev/null
        echo -e "${C_GREEN}User $new_user added to sudoers.${C_RESET}"
    fi

    # Safety Verification
    echo -e "\n${C_BOLD}Verifying New User...${C_RESET}"
    if ! id "$new_user" &>/dev/null; then
         echo -e "${C_RED}CRITICAL: User creation failed check.${C_RESET}"
         return 1
    fi
    # Check sudo if requested
    if [[ "$priv_choice" == "1" ]]; then
        if ! groups "$new_user" | grep -E "sudo|wheel" &>/dev/null; then
             echo -e "${C_RED}WARNING: User $new_user NOT found in sudo group!${C_RESET}"
        fi
    fi
    
    echo -e "${C_GREEN}User $new_user created successfully.${C_RESET}"
    log_apply "SUCCESS" "Created user $new_user (Sudo: $priv_choice)"

    # Disable Root Prompt (Path 1 only)
    if [[ "$disable_root_intent" == "true" ]]; then
        echo -e "\n${C_RED}${C_BOLD}FINAL CONFIRMATION${C_RESET}"
        echo -e "Do you want to disable SSH login for root now?"
        echo -e "WARNING: Ensure you have tested login with $new_user first."
        read -p "Disable root SSH login? (y/N): " confirm < /dev/tty
        
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            local ssh_config="/etc/ssh/sshd_config"
            backup_file "$ssh_config"
             if grep -q "^PermitRootLogin" "$ssh_config"; then
                sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
            else
                echo "PermitRootLogin no" >> "$ssh_config"
            fi
            log_apply "SUCCESS" "Disabled root login via Wizard."
            echo -e "${C_GREEN}Root login disabled. Restart SSH manually.${C_RESET}"
        else
            echo "Root login kept enabled."
            log_apply "INFO" "User chose to keep root login enabled."
        fi
    fi
}

apply_fix_ssh_root() {
    echo -e "\n${C_BOLD}>>> Finding: SSH Root Login Enabled (INT-SSH-001)${C_RESET}"
    echo -e "Risk: High. Root login allows direct brute-force attacks on superuser."
    
    # --- Context Gathering ---
    local sudoers=$(grep -E '^(sudo|wheel):' /etc/group | cut -d: -f4)
    local has_sudoer=0
    local sudo_user_list=""
    for user in ${sudoers//,/ }; do
        if [[ "$user" != "root" ]]; then
            has_sudoer=1
            sudo_user_list="$sudo_user_list $user"
        fi
    done
    
    local ssh_config="/etc/ssh/sshd_config"
    local current_permit=$(grep "^PermitRootLogin" "$ssh_config" | awk '{print $2}')
    local current_pwauth=$(grep "^PasswordAuthentication" "$ssh_config" | awk '{print $2}')
    local current_port=$(grep "^Port" "$ssh_config" | awk '{print $2}')

    # --- Force Mode (Bypass Wizard) ---
    if [[ "$IRONBASE_FORCE" == "true" ]]; then
        echo -e "${C_RED}${C_BOLD}FORCE MODE ACTIVE: Disabling Root Login (Ignoring Safety Locks)${C_RESET}"
        if [[ $has_sudoer -eq 0 ]]; then
            echo -e "${C_RED}WARNING: Check for sudo users FAILED. You may be LOCKED OUT after this.${C_RESET}"
        else
            echo -e "Confirmed sudo users:${C_GREEN}$sudo_user_list${C_RESET}"
        fi
        
        backup_file "$ssh_config"
        if grep -q "^PermitRootLogin" "$ssh_config"; then
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
        else
            echo "PermitRootLogin no" >> "$ssh_config"
        fi
        log_apply "SUCCESS" "Set PermitRootLogin no in $ssh_config (Force=$IRONBASE_FORCE)"
        echo -e "${C_GREEN}Applied. Restart SSH service manually.${C_RESET}"
        return
    fi
    
    # --- Wizard Mode (Assignments) ---
    echo -e "\n${C_BLUE}--- Current SSH Configuration ---${C_RESET}"
    echo -e "PermitRootLogin:      ${current_permit:-Computed (Default)}"
    echo -e "PasswordAuthentication: ${current_pwauth:-Computed (Default)}"
    echo -e "SSH Port:             ${current_port:-22}"
    echo -e "\n${C_BLUE}--- Privilege Overview ---${C_RESET}"
    if [[ $has_sudoer -eq 1 ]]; then
        echo -e "Existing Sudo Users: ${C_GREEN}$sudo_user_list${C_RESET}"
    else
        echo -e "Existing Sudo Users: ${C_RED}NONE (Root only)${C_RESET}"
    fi

    echo -e "\n${C_BOLD}Select Hardening Strategy:${C_RESET}"
    echo "1) Replace root SSH access with a NEW user (Recommended)"
    echo "2) Add a new SSH user (Keep root enabled)"
    echo "3) Review only (No changes)"
    
    read -p "Choose option [1-3]: " wizard_choice < /dev/tty
    
    case "$wizard_choice" in
        1)
            create_ssh_user "true" # "true" means prompt to disable root at the end
            ;;
        2)
            create_ssh_user "false" # "false" means do not prompt to disable root
            echo -e "\n${C_YELLOW}NOTE: Root login remains enabled (INT-SSH-001 active).${C_RESET}"
            log_apply "INFO" "User added regular user but kept root login."
            ;;
        *)
            echo "Skipping SSH hardening."
            log_apply "SKIP" "User selected Review Only."
            ;;
    esac
}
