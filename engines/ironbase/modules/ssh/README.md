# SSH Hardening Module

## Overview

This module provides focused, robust hardening for OpenSSH configuration. It performs diagnostic scans of SSH configuration and provides an interactive wizard to safely harden SSH access by creating sudo users and disabling root login without risk of lockout.

**Context**: Use this module to audit and harden SSH configuration on any Linux system. This is a critical security module that should run early in any security assessment, especially for systems with remote access.

## What This Module Does (Current Capabilities)

### Scan Behavior

Performs diagnostic scan of SSH configuration:

- **INT-SSH-001**: Detects if `PermitRootLogin yes` is enabled in `/etc/ssh/sshd_config`
- **INT-SSH-002**: Detects if `PasswordAuthentication yes` is enabled (recommends key-based auth)
- **INT-SSH-003**: Detects if `PermitEmptyPasswords yes` is enabled (CRITICAL security risk)

### Apply Behavior

Implements interactive wizard for safe SSH hardening:

1. **Context Analysis**: Checks if root login is enabled and if other sudo users exist
2. **Strategy Selection**:
   - **Option 1: Replace Root**: Creates new sudo user, validates it, and prompts to disable root login
   - **Option 2: Add User**: Creates new user but keeps root login enabled (for gradual migration)
   - **Option 3: Review**: Exits without changes
3. **User Creation Wizard**:
   - Creates new user with home directory and shell
   - Option to grant sudo/admin privileges
   - Sets password for new user
   - Validates user creation before proceeding
4. **Verification**: Before disabling root, verifies the new user exists and has sudo rights
5. **Safe Application**: Only disables root login after explicit confirmation AND successful user verification
6. **Backup Creation**: Creates backups of `/etc/ssh/sshd_config` before modifications
7. **Logging**: All actions logged to `ssh-apply.log` (or `output/runs/<run-id>/ssh.log` in engine mode)

### Findings Generated

| ID | Severity | Type | Status | Description |
|:---|:---------|:-----|:------|:------------|
| **INT-SSH-001** | HIGH | Misconfiguration | WARN | SSH Root Login Enabled |
| **INT-SSH-002** | MEDIUM | Misconfiguration | WARN | SSH Password Auth Enabled |
| **INT-SSH-003** | CRITICAL | Vulnerability | FAIL | SSH Empty Passwords Enabled |

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT check SSH key configurations** (does not verify authorized_keys, key permissions, or key types)
- **Does NOT verify SSH cipher/protocol settings** (does not check for weak ciphers or deprecated protocols)
- **Does NOT check SSH port configuration** (does not verify if SSH is on standard port 22 or custom port)
- **Does NOT verify SSH rate limiting** (does not check fail2ban or similar protection)
- **Does NOT check SSH access controls** (does not verify AllowUsers, DenyUsers, or IP restrictions)
- **Does NOT verify SSH host keys** (does not check host key permissions or known_hosts configuration)
- **Does NOT check SSH agent forwarding** (does not verify AllowAgentForwarding settings)
- **Does NOT check SSH X11 forwarding** (does not verify X11Forwarding settings)
- **Does NOT check SSH compression** (does not verify Compression settings)
- **Does NOT verify SSH log configuration** (does not check logging levels or destinations)
- **Does NOT automatically disable password auth** (only detects it, does not disable without wizard)
- **Does NOT configure SSH keys** (does not generate or install SSH keys)
- **Does NOT verify existing user configurations** (does not check if existing users have proper SSH access)

## Scan Behavior

When executing `ironbase scan --module ssh`:

1. Reads `/etc/ssh/sshd_config` for SSH configuration
2. Checks for `PermitRootLogin yes` (reports INT-SSH-001 if found)
3. Checks for `PasswordAuthentication yes` (reports INT-SSH-002 if found)
4. Checks for `PermitEmptyPasswords yes` (reports INT-SSH-003 if found, CRITICAL)
5. Reports findings with evidence (configuration file paths, grep commands)
6. Generates summary with counts by severity

**Output**: Findings displayed on console and registered to global report. Logs written to `ssh.log` (or `output/runs/<run-id>/ssh.log` in engine mode).

**Exit Code**: 
- Returns 0 if no critical/high findings
- Returns 1 if critical/high findings detected

**Dependencies**: Requires `/etc/ssh/sshd_config` file to exist. Will log error if file not found.

## Apply Behavior

When executing `ironbase apply --module ssh`:

### Interactive Wizard Flow

1. **Initial Check**: Verifies if root login is enabled and checks for existing sudo users
2. **Strategy Selection**: User chooses between:
   - Replace Root (creates sudo user, validates, disables root)
   - Add User (creates user, keeps root enabled)
   - Review (exits without changes)
3. **User Creation**:
   - Prompts for username
   - Validates username (checks if exists, not root)
   - Prompts for privilege level (sudo/admin or limited)
   - Creates user with `useradd -m -s /bin/bash`
   - Sets password for new user
   - Validates user creation before proceeding
4. **Root Disable Verification**:
   - Verifies new user exists
   - Verifies new user has sudo rights (if selected)
   - Prompts for explicit confirmation before disabling root
   - Creates backup of `/etc/ssh/sshd_config`
   - Adds `PermitRootLogin no` to configuration
   - Restarts SSH service (if service restart confirmed)
5. **Logging**: All actions logged with timestamps and status

### Safety Mechanisms

- **Never disables root without confirmation**: Requires explicit user confirmation
- **User verification required**: Verifies new user exists and has sudo rights before disabling root
- **Backup creation**: Always creates backup before modifying `/etc/ssh/sshd_config`
- **Service restart confirmation**: Prompts before restarting SSH service
- **Lockout prevention**: Ensures alternative access method (new sudo user) exists before disabling root

**Output**: Wizard provides interactive prompts with colored output. All actions logged to apply log file.

**Exit Code**: Returns 0 on success, 1 on failure or cancellation.

**Dependencies**: 
- Requires `useradd` command (usually available on Linux)
- Requires `passwd` command for password setting
- Requires `systemctl` or `service` for SSH service restart
- Requires root access for user creation and SSH configuration changes

## Safety Notes

### General Safety

- **Read-only in scan mode**: Only queries SSH configuration. No modifications performed.
- **Safe-by-default in apply mode**: Never disables root login without explicit confirmation AND successful user verification
- **Backup creation**: Always creates backup of `/etc/ssh/sshd_config` before modifications
- **User verification**: Verifies new user exists and has sudo rights before disabling root
- **Lockout prevention**: Ensures alternative access method exists before disabling root

### Apply Mode Safety

- **High safety**: Interactive wizard requires explicit confirmation for all actions
- **No automatic changes**: Never disables root login without user confirmation
- **User validation**: Verifies user creation before proceeding
- **Service restart confirmation**: Prompts before restarting SSH service
- **Graceful failure**: Fails gracefully if user creation fails

### Known Limitations

- **Root access required**: Apply mode requires root access for user creation and SSH configuration changes
- **Service restart required**: SSH configuration changes require service restart to take effect
- **Password-based user creation**: Creates users with password authentication (does not set up SSH keys)
- **Limited user validation**: Only checks if user exists and has sudo rights, does not verify SSH key access

**⚠️ Always ensure console/VNC access before using apply mode** (though module is designed to prevent lockout)

**When NOT to use**:
- Systems without console access and no alternative access method
- Systems with complex user management requirements
- Systems with non-standard SSH configuration (custom paths, containers)

### Integration with secure-vps

This module is shared by the `secure-vps` module, which uses the same wizard logic. Both modules use the same SSH hardening code to ensure consistent behavior.

## Usage Examples

### Scan

```bash
# Basic scan
./cmd/ironbase scan --module ssh

# Standalone mode
./modules/ssh/standalone.sh
```

### Apply (Interactive Wizard)

```bash
# Interactive wizard (default)
./cmd/ironbase apply --module ssh

# Standalone mode
./modules/ssh/standalone.sh apply
```

### Expected Scan Output

```
[INFO] Starting SSH Configuration Scan...
[WARN] [HIGH] SSH Root Login Enabled (INT-SSH-001)
      Category: Auth | Type: Misconfiguration | Scope: Internal
      Description: PermitRootLogin is set to yes
      Rec: Set PermitRootLogin no

[WARN] [MEDIUM] SSH Password Auth Enabled (INT-SSH-002)
      Category: Auth | Type: Misconfiguration | Scope: Internal
      Description: PasswordAuthentication is set to yes
      Rec: Disable PasswordAuthentication, use keys only.

======================================
SSH Scan Summary:
Critical: 0
High:     1
Medium:   1
Low:      0
Info:     0
======================================
Result: PASSED WITH FINDINGS (Medium findings detected)
```

### Expected Apply Output (Wizard)

```
>>> User Creation Wizard
Enter new username: admin

Select Privileges:
1) Sudo / Admin (Recommended for replacement)
2) Limited User
Choice [1/2]: 1

Creating user 'admin'...
Setting password for 'admin'...
User 'admin' created successfully.

>>> Finding: SSH Root Login Enabled (INT-SSH-001)
Disable root login now? (new sudo user 'admin' verified) [y/N]: y

Backing up /etc/ssh/sshd_config...
Adding 'PermitRootLogin no' to /etc/ssh/sshd_config...
Restart SSH service? [y/N]: y

SSH hardening complete.
```

## Special Considerations: Coolify with Root Hardening

### Problem Context

When blocking root access via SSH hardening, Coolify (a self-hosted PaaS) has certain limitations because it's designed for quick configuration with root access. After hardening and blocking root, Coolify may encounter permission issues, particularly with SSH key storage.

### Solution: Permissions and Ownership Configuration

If you encounter the error **"SSH keys storage directory is not writable"** after hardening SSH and blocking root, apply the following permissions and ownership configuration:

#### 1. Base Data Directory
```bash
sudo chmod 755 /data
```
**Motivo**: Permitir traversal (ejecución) desde contenedores sin exponer escritura global.

#### 2. Coolify Root Directory
```bash
sudo chown -R 9999:9999 /data/coolify
sudo chmod 755 /data/coolify
```
**Motivo**: 
- UID 9999 = www-data dentro del contenedor Coolify
- Permite lectura y escritura controlada por Coolify

#### 3. General Internal Permissions
```bash
sudo chmod -R 775 /data/coolify
```
**Motivo**: Permitir escritura a Coolify y a procesos internos (apps, db, builds).

#### 4. Critical SSH Directories (Main Fix)
```bash
sudo mkdir -p /data/coolify/ssh/keys
sudo mkdir -p /data/coolify/ssh/tmp

sudo chown -R 9999:9999 /data/coolify/ssh
sudo chmod -R 700 /data/coolify/ssh
```
**Motivo**:
- Coolify guarda keys privadas SSH aquí
- Requiere permiso estricto (700) por seguridad
- **Error "SSH keys storage directory is not writable" resuelto aquí**

#### 5. Verification Inside Container
```bash
sudo docker exec -it coolify sh -c '
id &&
touch /var/www/html/storage/app/ssh/keys/test &&
rm /var/www/html/storage/app/ssh/keys/test
'
```

**Expected Result**:
```
uid=9999(www-data) gid=9999(www-data)
OK
```
✔ Confirmado: Coolify sí puede escribir en su storage interno

### Final State Summary

| Ruta | Owner | Permisos |
|:-----|:------|:---------|
| `/data` | root | 755 |
| `/data/coolify` | 9999:9999 | 755 |
| `/data/coolify/**` | 9999:9999 | 775 |
| `/data/coolify/ssh/**` | 9999:9999 | 700 |

### Technical Conclusion

❌ El error NO era la app  
❌ NO era la base de datos  
❌ NO era Docker  
✅ Era ownership + permisos incorrectos tras reinstalar / borrar volúmenes  
✅ Coolify no puede operar sin escritura en `/storage/app/ssh`

**Note**: This configuration is required after reinstalling Coolify or deleting volumes when root SSH access has been blocked. The issue occurs because Coolify expects root-level permissions but operates with UID 9999 (www-data) inside containers.

## Status

**State**: Stable (Scan Complete, Apply Fully Functional)

**Features Implemented**:
- 3 comprehensive SSH configuration checks
- Interactive wizard for safe user creation
- Root login disable with verification
- Backup creation for SSH configuration
- Logging of all actions
- Lockout prevention mechanisms
- Integration with secure-vps module
- Standalone execution capability

**Features Pending**:
- SSH key configuration and installation
- SSH cipher/protocol verification
- SSH port configuration checks
- SSH rate limiting configuration
- SSH access control verification (AllowUsers, DenyUsers)
- SSH host key verification
- SSH forwarding configuration checks (X11, agent)
- SSH compression configuration
- SSH log configuration verification
- Automatic password auth disable (currently only detects)
- Service restart verification (currently prompts, does not verify success)
