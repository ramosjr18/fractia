# Services & Logging Module

## Overview

**⚠️ DEVELOPMENT STATUS: This module is currently in development and should be used at your own risk.**

This module performs basic service detection and logging configuration checks. It identifies Docker installation and socket permissions, verifies auditd service status, and checks journald persistence configuration. These checks help ensure proper system accounting and service isolation.

**Context**: Use this module to audit service presence and logging configuration before applying hardening changes. This is a diagnostic scan that complements other security modules.

**⚠️ WARNING**: This module is incomplete. The `apply` functionality is not implemented. Only `scan` mode is currently functional. Use with caution.

## What This Module Does (Current Capabilities)

- **SVC-001**: Detects Docker installation (reports presence or absence)
- **SVC-002**: Checks Docker socket permissions (`/var/run/docker.sock`)
- **SVC-003**: Verifies auditd installation and running status
- **SVC-004**: Checks journald persistence configuration (detects `/var/log/journal` directory)

### Findings Generated

| ID | Severity | Status | Description |
|:---|:---------|:------|:------------|
| **SVC-001** | INFO | PASS | Docker installation status |
| **SVC-002** | LOW | INFO | Docker socket permissions |
| **SVC-003** | MEDIUM | PASS/WARN | auditd installation and running status |
| **SVC-004** | LOW | PASS/INFO | journald persistence enabled/disabled |

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT check Docker container security** (does not scan running containers or images)
- **Does NOT verify Docker networking configuration** (does not check firewall bypass or network isolation)
- **Does NOT check auditd rules** (only verifies service is running, not rule configuration)
- **Does NOT verify journald configuration** (only checks if persistence directory exists, not `/etc/systemd/journald.conf` content)
- **Does NOT scan other services** (does not check SSH, web servers, databases, etc.)
- **Does NOT verify service hardening** (does not check service-specific security configurations)
- **Does NOT check container runtime alternatives** (does not detect podman, containerd, etc.)
- **Does NOT provide remediation** (scan-only, no apply functionality)
- **Does NOT integrate with firewall module** (does not check if Docker bypasses firewall rules like `firewall` module does)

## Scan Behavior

When executing `ironbase scan --module services`:

1. Checks for `docker` command availability (reports presence or absence)
2. If Docker installed, checks `/var/run/docker.sock` socket permissions
3. Checks for `auditd` command availability
4. If auditd installed, checks if `auditd` process is running via `pgrep`
5. Checks if `/var/log/journal` directory exists (indicates journald persistence)
6. Reports findings with evidence (socket permissions, process status)

**Output**: Findings displayed on console and registered to global report. No files are modified.

**Exit Code**: Always returns 0 (scan completes successfully even if issues found)

**Dependencies**: Requires `pgrep` command (usually available via `procps` package). No external dependencies for Docker/auditd checks.

## Apply Behavior

**Not Applicable**: This module does not implement `module_apply()`. The function exists but is a no-op (`:`).

This is a **scan-only diagnostic module**. Remediation must be performed manually or using other modules:
- Start auditd: `sudo systemctl start auditd && sudo systemctl enable auditd`
- Install auditd: `sudo apt-get install auditd`
- Configure journald persistence: edit `/etc/systemd/journald.conf`
- Review Docker socket permissions: ensure only trusted users in `docker` group

## Safety Notes

- **Read-only operation**: Only queries service status and file metadata. No modifications performed.
- **No service disruption**: Scanning service status cannot cause service failures.
- **No lockout risk**: Service detection checks cannot cause connectivity issues.
- **Limited scope**: Only checks presence and basic status, not security configuration

**When NOT to use**: This module provides basic service detection. For comprehensive service exposure analysis, use the `secure-vps` module. For Docker-specific firewall interference checks, use the `firewall` module.

## Usage Examples

### Basic Scan

```bash
./cmd/ironbase scan --module services
```

### Integrated with Profile

```bash
./cmd/ironbase scan --profile profiles/ubuntu-baseline.yaml
```

### Expected Output

```
[PASS] [INFO] Docker Installed (SVC-001)
      Description: Docker is present on the system.
[INFO] [LOW] Docker Socket (SVC-002)
      Description: Docker socket available.
      Evidence: srw-rw---- 1 root docker ...
      Remediation: Ensure only trusted users are in docker group.
[PASS] [MEDIUM] auditd (SVC-003)
      Description: auditd is installed and running.
```

## Status

**State**: ⚠️ **IN DEVELOPMENT** - Use at your own risk

**⚠️ IMPORTANT**: This module is currently in development. Only scan functionality is implemented. Apply mode is not available and will not perform any actions.

**Features Implemented**:
- Docker installation detection
- Docker socket permission check
- auditd installation and status check
- journald persistence detection

**Features Pending**:
- Docker container/image security scanning
- Docker networking configuration verification
- auditd rule configuration verification
- journald configuration file analysis
- Additional service scanning (SSH, web servers, databases)
- Service hardening verification
- Container runtime alternatives (podman, containerd)
- Apply/remediation functionality (NOT IMPLEMENTED)
- Integration with firewall module for Docker bypass detection

**⚠️ DISCLAIMER**: This module is provided as-is for experimental use. The scan functionality is stable, but the module is incomplete and should not be used in production environments without thorough testing.
