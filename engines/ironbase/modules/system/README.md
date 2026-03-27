# System Updates & Config Module

## Overview

**⚠️ DEVELOPMENT STATUS: This module is currently in development and should be used at your own risk.**

This module checks system-level configuration for updates, time synchronization, and OS version information. It verifies pending updates, automatic update configuration, time sync status, and collects basic system metadata (OS version, kernel version). These checks ensure the system is current and properly configured for security maintenance.

**Context**: Use this module to audit system maintenance configuration before applying other hardening changes. This should run early in any security assessment to verify system currency.

**⚠️ WARNING**: This module is incomplete. The `apply` functionality is a placeholder and will NOT perform any actions. Only `scan` mode is currently functional. Use with caution.

## What This Module Does (Current Capabilities)

- **SYS-001**: Detects OS name and version from `/etc/os-release`
- **SYS-002**: Reports current kernel version (`uname -r`)
- **SYS-003**: Verifies system time synchronization status (`timedatectl`)
- **SYS-004**: Checks for pending system updates (reads `/var/lib/update-notifier/updates-available`)
- **SYS-005**: Verifies automatic update configuration (checks `/etc/apt/apt.conf.d/20auto-upgrades`)

### Findings Generated

| ID | Severity | Status | Description |
|:---|:---------|:------|:------------|
| **SYS-001** | INFO | PASS | OS name and version detection |
| **SYS-002** | INFO | PASS | Kernel version information |
| **SYS-003** | MEDIUM | PASS/WARN | System time synchronization status |
| **SYS-004** | HIGH | PASS/WARN | Pending system updates detection |
| **SYS-005** | MEDIUM | PASS/WARN | Automatic updates configuration |

### Tools Used

- `/etc/os-release`: OS identification
- `uname -r`: Kernel version
- `timedatectl`: Time synchronization status (requires `systemd`)
- `/var/lib/update-notifier/updates-available`: Update status (Ubuntu-specific)
- `/etc/apt/apt.conf.d/20auto-upgrades`: Automatic update config (Debian/Ubuntu)

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT install updates** (scan-only, does not apply patches)
- **Does NOT configure automatic updates** (only checks if configured, does not set it up)
- **Does NOT check specific package vulnerabilities** (use `vulnerability` module for that)
- **Does NOT verify update source integrity** (does not check GPG keys or repository configuration)
- **Does NOT check EOL/EOS status** (does not verify if OS version is end-of-life)
- **Does NOT verify kernel-specific vulnerabilities** (does not match kernel version against CVE database)
- **Does NOT check NTP configuration** (only checks if time is synchronized, not how)
- **Does NOT verify update frequency** (only checks if auto-updates enabled, not schedule)
- **Does NOT work on non-Debian systems** (update checks are Ubuntu/Debian-specific)
- **Does NOT provide comprehensive remediation** (apply function exists but only prints message)

## Scan Behavior

When executing `ironbase scan --module system`:

1. Reads `/etc/os-release` to detect OS name and version
2. Executes `uname -r` to get kernel version
3. Runs `timedatectl status` to check time synchronization
4. Reads `/var/lib/update-notifier/updates-available` (Ubuntu-specific) to detect pending updates
5. Checks `/etc/apt/apt.conf.d/20auto-upgrades` for automatic update configuration
6. Reports findings with evidence (OS version, kernel, time status, update content)

**Output**: Findings displayed on console and registered to global report. No files are modified.

**Exit Code**: Always returns 0 (scan completes successfully even if issues found)

**Dependencies**: 
- Requires `timedatectl` for time sync check (usually available on systemd-based systems)
- Update detection requires Ubuntu/Debian-specific files (will not work on other distributions)
- Automatic update check requires Debian/Ubuntu APT configuration

## Apply Behavior

**⚠️ NOT IMPLEMENTED**: `module_apply()` exists but is **completely non-functional**. It currently only prints a message and has a commented-out update command:

```bash
module_apply() {
    echo "APPLY: Running system updates..."
    # sudo apt-get update && sudo apt-get upgrade -y
}
```

**Current State**: The apply function is a **placeholder**. It does not execute updates or modify system configuration.

**⚠️ DO NOT USE APPLY MODE**: The apply function will not perform any actions. All remediation must be performed manually:
- Install updates: `sudo apt-get update && sudo apt-get upgrade`
- Configure auto-updates: `sudo apt-get install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`
- Fix time sync: `sudo systemctl enable systemd-timesyncd && sudo systemctl start systemd-timesyncd`

**Future Implementation** (not currently implemented):
- Update package lists
- Apply security updates
- Configure automatic updates
- Set up time synchronization

## Safety Notes

- **Read-only in scan mode**: Only queries system state. No modifications performed.
- **Apply mode is non-functional**: `module_apply()` does not execute updates. No risk in scan mode.
- **Distribution-specific**: Update checks only work on Ubuntu/Debian systems. Other distributions will report missing files as expected.
- **May require root**: Some checks (reading `/var/lib/update-notifier/updates-available`) may require root access
- **Time sync check requires systemd**: Systems without `timedatectl` will report warning

**When NOT to use**: This module is designed for Ubuntu/Debian systems. On other distributions, only OS/kernel detection will function. For comprehensive vulnerability assessment, use the `vulnerability` module.

## Usage Examples

### Basic Scan

```bash
./cmd/ironbase scan --module system
```

### Integrated with Profile

```bash
./cmd/ironbase scan --profile profiles/ubuntu-baseline.yaml
```

### Attempt Apply (Non-Functional)

```bash
./cmd/ironbase apply --module system
# This will print a message but not perform any actions
```

### Expected Output

```
[PASS] [INFO] OS Detection (SYS-001)
      Description: Detected Operating System version.
      Evidence: Ubuntu 22.04
[PASS] [INFO] Kernel Version (SYS-002)
      Description: Current running kernel.
      Evidence: 5.15.0-72-generic
[WARN] [HIGH] System Updates (SYS-004)
      Description: Pending updates detected.
      Remediation: Run 'apt-get update && apt-get upgrade'
```

## Status

**State**: ⚠️ **IN DEVELOPMENT** - Use at your own risk

**⚠️ IMPORTANT**: This module is currently in development. Scan functionality is complete and stable, but `apply` mode is a placeholder and will NOT perform any actions. Use with caution.

**Features Implemented**:
- OS and kernel version detection
- Time synchronization status check
- Pending updates detection (Ubuntu/Debian)
- Automatic updates configuration check (Ubuntu/Debian)

**Features Pending**:
- Functional apply/remediation (NOT IMPLEMENTED - placeholder only)
- EOL/EOS status verification
- Kernel-specific vulnerability matching
- Update source integrity verification
- NTP configuration verification
- Update frequency scheduling
- Cross-distribution support (currently Ubuntu/Debian only)

**⚠️ DISCLAIMER**: This module is provided as-is for experimental use. The scan functionality is stable and functional, but apply mode is completely non-functional. Do not rely on this module's apply functionality. Use in production environments at your own risk.
