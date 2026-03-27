# Filesystem Permissions Module

## Overview

This module checks critical filesystem permission configurations on Linux systems. It verifies ownership, world-writable permissions, SUID/SGID binaries, and permission modes for sensitive directories (`/etc`, `/boot`, `/root`, `/var/log`, `/usr/bin`, `/usr/sbin`) and files. These checks are fundamental for preventing unauthorized modifications to system configuration files and privilege escalation attacks.

**Context**: Use this module to audit filesystem security posture before deploying hardening changes. This is a baseline check that should run early in any security assessment. The module supports both scan-only assessment and interactive remediation.

## What This Module Does (Current Capabilities)

### Scan Behavior

Performs comprehensive filesystem permission checks:

**Sensitive Directory Ownership Checks**:
- **FS-001**: Verifies `/etc` directory ownership (must be `root`)
- **FS-003**: Verifies `/boot` directory ownership (if exists)
- **FS-004**: Verifies `/root` directory ownership (if exists)
- **FS-005**: Verifies `/var/log` directory ownership
- **FS-006**: Verifies `/usr/bin` directory ownership (critical system binaries)
- **FS-007**: Verifies `/usr/sbin` directory ownership (critical system binaries)

**World-Writable Files Detection (Recursive)**:
- **FS-002**: Detects world-writable files in `/etc` (recursive, depth 3)
- **FS-008**: Detects world-writable files in `/boot` (if exists, depth 2)
- **FS-009**: Detects world-writable files in `/root` (if exists, depth 2)
- **FS-010**: Detects world-writable files in `/var/log` (depth 2)

**Full Permission Mode Analysis**:
- **FS-011**: Verifies `/etc` permissions (should be 755 or stricter)
- **FS-012**: Verifies `/root` permissions (should be 700)
- **FS-013**: Verifies `/boot` permissions (should be 755)

**SUID/SGID Binary Scanning**:
- **FS-014**: Scans for SUID binaries in system directories (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`)
  - Identifies unexpected SUID binaries (not in expected whitelist)
  - Whitelist: `passwd`, `mount`, `umount`, `su`, `sudo`, `ping`, `chfn`, `chsh`, `gpasswd`, `newgrp`
- **FS-015**: Scans for SGID binaries in system directories

**PATH Security Checks**:
- **FS-016**: Detects world-writable directories in PATH (privilege escalation risk)

### Findings Generated

| ID | Severity | Status | Description |
|:---|:---------|:------|:------------|
| **FS-001** | HIGH | PASS/FAIL/WARN | `/etc` ownership check (must be root) |
| **FS-002** | HIGH | PASS/FAIL | World-writable files in `/etc` (recursive, depth 3) |
| **FS-003** | HIGH | PASS/FAIL/WARN | `/boot` ownership check (if exists) |
| **FS-004** | HIGH | PASS/FAIL/WARN | `/root` ownership check (if exists) |
| **FS-005** | HIGH | PASS/FAIL/WARN | `/var/log` ownership check |
| **FS-006** | HIGH | PASS/FAIL/WARN | `/usr/bin` ownership check |
| **FS-007** | HIGH | PASS/FAIL/WARN | `/usr/sbin` ownership check |
| **FS-008** | HIGH | PASS/FAIL | World-writable files in `/boot` (if exists, depth 2) |
| **FS-009** | HIGH | PASS/FAIL | World-writable files in `/root` (if exists, depth 2) |
| **FS-010** | HIGH | PASS/FAIL | World-writable files in `/var/log` (depth 2) |
| **FS-011** | MEDIUM | PASS/WARN/FAIL | `/etc` permissions analysis (expected: 755) |
| **FS-012** | MEDIUM | PASS/WARN/FAIL | `/root` permissions analysis (expected: 700) |
| **FS-013** | MEDIUM | PASS/WARN/FAIL | `/boot` permissions analysis (expected: 755) |
| **FS-014** | HIGH/MEDIUM/INFO | WARN/PASS | SUID binaries scan (unexpected vs expected) |
| **FS-015** | MEDIUM | INFO | SGID binaries scan |
| **FS-016** | HIGH | PASS/FAIL | World-writable PATH directory detection |

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT check sticky bits** (does not verify `/tmp` sticky bit or similar)
- **Does NOT verify home directory permissions** (does not check `/home` or user home directories)
- **Does NOT check for misconfigured sudo executables** (does not verify `/usr/bin/sudo` permissions beyond ownership)
- **Does NOT verify `/tmp` and `/var/tmp` permissions** (does not check temporary directory security)
- **Does NOT check file ACLs** (Access Control Lists) (only checks standard Unix permissions)
- **Does NOT verify extended attributes** (does not check SELinux or AppArmor context)
- **Does NOT scan all system directories** (focuses on critical directories, not exhaustive)
- **Does NOT verify package file integrity** (does not check if files have been modified from package defaults)

## Scan Behavior

When executing `ironbase scan --module filesystem`:

1. **Sensitive Directory Ownership Checks**: Verifies ownership of `/etc`, `/boot`, `/root`, `/var/log`, `/usr/bin`, `/usr/sbin` (cross-platform: supports both Linux and macOS stat syntax)
2. **World-Writable Files Detection (Recursive)**: Scans sensitive directories recursively for world-writable files:
   - `/etc` (depth 3)
   - `/boot` (depth 2, if exists)
   - `/root` (depth 2, if exists)
   - `/var/log` (depth 2)
3. **Full Permission Mode Analysis**: Analyzes permission modes (octal) for critical directories:
   - `/etc` (expected: 755)
   - `/root` (expected: 700)
   - `/boot` (expected: 755)
4. **SUID Binary Scanning**: Scans system directories (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`) for SUID binaries:
   - Compares against expected whitelist
   - Flags unexpected SUID binaries as security risk
5. **SGID Binary Scanning**: Scans system directories for SGID binaries (informational)
6. **PATH Security Check**: Detects world-writable directories in PATH (privilege escalation risk)
7. Reports findings with evidence (owner names, file paths, permission modes, binary lists)
8. Returns exit code based on findings severity (0=pass, 1=high/critical findings)

**Output**: Findings are displayed on console and registered to global report. No files are modified.

**Exit Code**: 
- Returns 0 if no critical/high findings
- Returns 1 if critical/high findings detected

## Apply Behavior

When executing `ironbase apply --module filesystem`:

The module implements **interactive remediation** with the following steps:

**Step 1: Fix Directory Ownership**
- Fixes ownership of `/etc`, `/boot`, `/root`, `/var/log`, `/usr/bin`, `/usr/sbin` to `root:root`
- Prompts for confirmation before each change (unless `--force` mode)

**Step 2: Fix World-Writable Files**
- Removes world-writable permission (`chmod o-w`) from files found in sensitive directories
- Processes files recursively in `/etc` (depth 3), `/boot` (depth 2), `/root` (depth 2), `/var/log` (depth 2)
- Lists files before prompting for confirmation

**Step 3: Fix Directory Permissions**
- Sets expected permissions:
  - `/etc` → 755
  - `/root` → 700
  - `/boot` → 755
- Prompts for confirmation before each change

**Step 4: Review and Fix Unexpected SUID Binaries**
- Lists unexpected SUID binaries (not in expected whitelist)
- Prompts to remove SUID bit (`chmod u-s`) from each unexpected binary
- **Conservative by default**: Only removes SUID from confirmed unexpected binaries

**Step 5: Fix World-Writable PATH Directories**
- Fixes world-writable directories found in PATH
- Removes write permission from "other" (sets to read-only for other)
- Calculates safe permissions before applying

**Safety Features**:
- **Interactive by default**: Prompts for confirmation before every action
- **Logging**: All actions logged to `filesystem-apply.log` (or `output/runs/<run-id>/filesystem-apply.log`)
- **No automatic changes**: Never modifies filesystem without explicit confirmation
- **FORCE mode support**: `--force` flag auto-confirms all prompts (use with caution)

**Output**: Interactive prompts with colored output. All actions logged to apply log file.

**Exit Code**: Returns 0 on success, 1 on failure or cancellation.

**Dependencies**: 
- Requires `find` command for SUID/SGID binary scanning
- Requires `stat` command for permission checking (usually available on Linux/macOS)
- Requires `chmod`, `chown` commands for remediation (requires root access)
- Requires root access for ownership and permission changes

## Safety Notes

### Scan Mode Safety

- **Read-only operation**: Scan mode only reads filesystem metadata. No modifications are performed.
- **No lockout risk**: Scanning filesystem permissions cannot cause system lockout or access issues.
- **May require root**: Some checks (scanning `/root`, `/boot`, system binaries) may require root for full visibility, but module handles gracefully without root
- **Cross-platform**: Supports both Linux and macOS (handles different `stat` command syntax)

### Apply Mode Safety

- **Interactive by default**: Requires explicit confirmation before every action
- **Conservative SUID handling**: Only removes SUID from confirmed unexpected binaries (whitelist-based)
- **Permission changes are reversible**: All changes use standard Unix permissions (can be reverted)
- **No automatic bulk operations**: Processes files one by one or with explicit batch confirmation
- **Logging**: All actions logged with timestamps for audit trail

**FORCE Mode Risks** (`--force` flag):
- **Auto-confirms all prompts**: No interactive confirmation required
- **May remove SUID from necessary binaries**: If whitelist is incomplete, may break system functionality
- **May change permissions on critical directories**: Could affect system services or applications

**⚠️ Always review changes before applying in production environments**

**When NOT to use**:
- Systems with custom permission schemes (containers, special applications)
- Production systems without testing apply changes first
- Systems with non-standard directory structures

## Usage Examples

### Basic Scan

```bash
./cmd/ironbase scan --module filesystem
```

### Apply (Interactive Remediation)

```bash
# Interactive mode (default)
./cmd/ironbase apply --module filesystem

# Force mode (auto-confirms all prompts)
./cmd/ironbase apply --module filesystem --force
```

### Integrated with Profile

```bash
# Run all modules in profile (includes filesystem if enabled)
./cmd/ironbase scan --profile profiles/ubuntu-baseline.yaml
```

### Expected Scan Output

```
[PASS] [HIGH] /etc Ownership (FS-001)
      Description: /etc is owned by root.
[PASS] [HIGH] World Writable /etc (FS-002)
      Description: No world writable files found in /etc (depth 3).
[PASS] [MEDIUM] /etc Permissions (FS-011)
      Description: /etc has acceptable permissions (755).
[WARN] [HIGH] Unexpected SUID Binaries (FS-014)
      Description: Found 2 unexpected SUID binary(ies) out of 15 total. SUID binaries run with owner privileges and pose privilege escalation risk if compromised.
      Evidence: /usr/bin/custom-suid
      Remediation: Review SUID binaries: ls -l <file> | grep '^-..s' | head -20. Remove SUID bit if not needed: chmod u-s <file>
[PASS] [HIGH] PATH Directory Permissions (FS-016)
      Description: No world-writable directories found in PATH.
```

### Expected Apply Output (Interactive)

```
Starting Filesystem Remediation
WARNING: You are about to modify filesystem permissions and ownership.
This tool will prompt for confirmation before every action.
Log will be saved to: filesystem-apply.log

>>> Step 1: Fixing Directory Ownership <<<
Fix ownership of /etc (current: root -> root:root)? [Y/n]: y
✓ Fixed ownership of /etc

>>> Step 2: Fixing World-Writable Files <<<
Found 3 world-writable file(s) in /etc
/etc/file1
/etc/file2
/etc/file3
Remove world-writable permission from these files? [Y/n]: y
✓ Fixed 3 file(s)

>>> Step 3: Fixing Directory Permissions <<<
Fix permissions of /root (current: 755 -> expected: 700)? [Y/n]: y
✓ Fixed permissions of /root to 700

>>> Step 4: Reviewing SUID Binaries <<<
Unexpected SUID binary: /usr/bin/custom-suid
Remove SUID bit from /usr/bin/custom-suid? [y/N]: n
Skipping.

>>> Step 5: Fixing World-Writable PATH Directories <<<
No world-writable PATH directories found.

-------------------------------------
Filesystem Remediation Complete
Please review filesystem-apply.log
```

## Status

**State**: Stable (Scan Complete, Apply Functional)

**Features Implemented**:
- **16 comprehensive scan checks** covering ownership, permissions, SUID/SGID binaries, and PATH security
- **Sensitive directory ownership checks** (`/etc`, `/boot`, `/root`, `/var/log`, `/usr/bin`, `/usr/sbin`)
- **Recursive world-writable file detection** (configurable depth per directory)
- **Full permission mode analysis** (octal permission comparison)
- **SUID binary scanning** with expected whitelist comparison
- **SGID binary scanning** (informational)
- **World-writable PATH directory detection** (privilege escalation risk)
- **Interactive apply/remediation functionality** with 5-step process:
  1. Fix directory ownership
  2. Fix world-writable files
  3. Fix directory permissions
  4. Review and fix unexpected SUID binaries
  5. Fix world-writable PATH directories
- **FORCE mode support** (`--force` flag for auto-confirmation)
- **Comprehensive logging** to apply log file

**Features Pending**:
- Sticky bit verification (`/tmp`, `/var/tmp`)
- Home directory permission checks (`/home/*`)
- File ACL verification (Access Control Lists)
- Extended attributes checking (SELinux, AppArmor)
- Package file integrity verification (compare against package database)
- Bulk permission restoration from backup/configuration
