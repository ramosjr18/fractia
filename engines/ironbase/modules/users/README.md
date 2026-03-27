# Users & Privileges Module

## Overview

**⚠️ DEVELOPMENT STATUS: This module is currently in development and should be used at your own risk.**

This module audits user accounts, privileges, and authentication configuration. It checks for multiple UID 0 accounts, empty passwords, sudoer configurations, and root account lock status. These checks help identify privilege escalation risks and authentication weaknesses.

**Context**: Use this module to audit user account security before applying hardening changes. This is a critical baseline check that should run early in any security assessment.

**⚠️ WARNING**: This module is incomplete. The `apply` functionality is not implemented. Only `scan` mode and `--list` mode are currently functional. Use with caution.

## What This Module Does (Current Capabilities)

- **USR-001**: Detects multiple users with UID 0 (superuser privilege check)
- **USR-002**: Identifies users with empty passwords (requires root to read `/etc/shadow`)
- **USR-003**: Checks for `NOPASSWD` directives in `/etc/sudoers`
- **USR-004**: Verifies root account password lock status (checks if root password is locked)

### Findings Generated

| ID | Severity | Status | Description |
|:---|:---------|:------|:------------|
| **USR-001** | CRITICAL | PASS/FAIL/WARN | Multiple UID 0 users detected |
| **USR-002** | HIGH | PASS/FAIL/WARN | Users with empty passwords |
| **USR-003** | HIGH | PASS/WARN | NOPASSWD directives in sudoers |
| **USR-004** | MEDIUM | PASS/INFO | Root account lock status |

### Additional Capabilities

- **module_list()**: Provides detailed user listing with privileges, UIDs, shells, and account status
  - Shows ROOT, SUDO, or USER privilege levels
  - Indicates LOCKED or ACTIVE account status
  - Requires root access to read `/etc/shadow` for lock status

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT check password complexity** (only checks for empty passwords, not weak passwords)
- **Does NOT verify password aging** (does not check password expiration or max age)
- **Does NOT check sudoer file syntax** (only checks for `NOPASSWD` presence, not validity)
- **Does NOT verify sudoer file includes** (does not check `/etc/sudoers.d/*` files)
- **Does NOT detect inactive accounts** (does not check last login or account inactivity)
- **Does NOT verify home directory permissions** (does not check home directory security)
- **Does NOT check for default accounts** (does not verify if default users were changed)
- **Does NOT detect privilege escalation exploits** (only checks configuration, not active exploits)
- **Does NOT provide remediation** (scan-only, no apply functionality)
- **Does NOT create or modify users** (does not create sudo users or lock accounts)
- **Does NOT integrate with SSH module** (does not coordinate with SSH hardening for root disable)

## Scan Behavior

When executing `ironbase scan --module users`:

1. Reads `/etc/passwd` to find users with UID 0
2. Attempts to read `/etc/shadow` to find empty passwords (requires root access)
3. Reads `/etc/sudoers` to check for `NOPASSWD` directives
4. Checks root account password hash in `/etc/shadow` to verify lock status
5. Reports findings with evidence (user names, sudoer content, password hash status)

**Output**: Findings displayed on console and registered to global report. No files are modified.

**Exit Code**: Always returns 0 (scan completes successfully even if issues found)

**Permissions Required**: 
- Root access recommended for full checks (reading `/etc/shadow`)
- Non-root scans will report warnings when `/etc/shadow` cannot be read

### List Mode

When executing `ironbase scan --module users --list`:

- Displays formatted table of all users with UIDs, GIDs, privilege levels, shells, home directories, and account status
- Shows ROOT, SUDO, or USER privilege classification
- Indicates LOCKED or ACTIVE account status (requires root for shadow file access)
- Provides legend explaining privilege levels

## Apply Behavior

**⚠️ NOT IMPLEMENTED**: This module does not implement `module_apply()`. The function exists but is a no-op (`:`) and will not perform any actions.

**⚠️ DO NOT USE APPLY MODE**: This is a **scan-only diagnostic module**. Remediation must be performed manually or using other modules:
- Remove UID 0 users: `sudo usermod -u <new_uid> <username>` or delete account
- Set passwords: `sudo passwd <username>`
- Lock accounts: `sudo passwd -l <username>`
- Review sudoers: `sudo visudo` to edit `/etc/sudoers`
- Use `ssh` module to safely disable root login and create sudo users

## Safety Notes

- **Read-only operation**: Only queries user database files. No modifications performed.
- **May require root**: Full checks require root access to read `/etc/shadow`. Non-root scans will report warnings for inaccessible checks.
- **No lockout risk**: Scanning user accounts cannot cause authentication issues.
- **Does not expose passwords**: Only checks for empty passwords, never reads password hashes for analysis

**When NOT to use**: This module provides basic user account auditing. For comprehensive SSH hardening with safe user creation, use the `ssh` module. For detailed user management, use system tools like `usermod`, `passwd`, `visudo`.

## Usage Examples

### Basic Scan

```bash
# Run as root for full checks
sudo ./cmd/ironbase scan --module users

# Run as regular user (will report warnings for inaccessible checks)
./cmd/ironbase scan --module users
```

### List Mode (User Listing)

```bash
# Display formatted user table
./cmd/ironbase scan --module users --list

# With root for full lock status
sudo ./cmd/ironbase scan --module users --list
```

### Integrated with Profile

```bash
./cmd/ironbase scan --profile profiles/ubuntu-baseline.yaml
```

### Expected Output

```
[PASS] [CRITICAL] UID 0 Users (USR-001)
      Description: Only one user with UID 0 found (root).
      Evidence: root
[WARN] [HIGH] Empty Passwords (USR-002)
      Description: Cannot read /etc/shadow (permission denied).
      Evidence: Run as root for full check.
[PASS] [HIGH] Sudoers NOPASSWD (USR-003)
      Description: No NOPASSWD directives found in /etc/sudoers.
[PASS] [MEDIUM] Root Account Locked (USR-004)
      Description: Root account password is locked (standard for Ubuntu).
```

## Status

**State**: ⚠️ **IN DEVELOPMENT** - Use at your own risk

**⚠️ IMPORTANT**: This module is currently in development. Scan functionality and `--list` mode are complete and stable, but `apply` mode is not implemented and will not perform any actions.

**Features Implemented**:
- UID 0 duplicate detection
- Empty password detection (requires root)
- NOPASSWD directive check
- Root account lock status verification
- User listing with privileges (`--list` mode)

**Features Pending**:
- Password complexity verification
- Password aging checks
- Sudoer file syntax validation
- Sudoer include file checks (`/etc/sudoers.d/*`)
- Inactive account detection
- Home directory permission checks
- Default account detection
- Apply/remediation functionality (NOT IMPLEMENTED - no-op only)
- Integration with SSH module for coordinated hardening

**⚠️ DISCLAIMER**: This module is provided as-is for experimental use. The scan and list functionality are stable and functional, but apply mode is completely non-functional. Use in production environments at your own risk.
