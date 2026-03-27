# Secure VPS Module

## Overview

This module provides comprehensive security assessment for public Linux VPS environments. It evaluates security posture from both **Internal** (host-based) and **External** (network-based simulation) perspectives. The module performs dual-perspective scanning, correlates findings with firewall rules, and provides interactive remediation with safety mechanisms to prevent lockout.

**Context**: Use this module to audit and harden public-facing Linux VPS systems. This is an integrated assessment module that combines multiple security checks into a unified view, suitable for initial security assessment and ongoing hardening.

## What This Module Does (Current Capabilities)

### Scan Behavior

Performs comprehensive dual-perspective scanning:

#### Internal Scanner (Host-based)

**System Checks**:
- **INT-SYS-001**: Kernel version assessment (EOL, Legacy, or Modern)
- **INT-SYS-002**: ASLR (Address Space Layout Randomization) status verification
- **INT-SYS-003**: World-writable directories in PATH detection (privilege escalation risk)

**User Checks**:
- **INT-USR-001**: Multiple UID 0 users detection
- **INT-USR-002**: Empty password fields in `/etc/shadow`

**Network Checks**:
- **INT-NET-001**: Unclassified services exposed (services not in allow-list)
- **INT-NET-002**: Critical internal services exposed (databases, management interfaces) **without** firewall protection
- **INT-NET-002-M**: Critical internal services exposed but **mitigated** by UFW (blocked)
- **INT-NET-003**: Known public services detected (web, VoIP)

**SSH Checks** (uses `ssh` module scanner):
- **INT-SSH-001**: SSH root login enabled
- **INT-SSH-002**: SSH password authentication enabled

#### External Scanner (Network-based Simulation)

- **EXT-NET-000**: Public IP not detected (connectivity check)
- **EXT-NET-001**: Public IP detected (VPS exposure confirmation)
- **EXT-NET-002**: Ports exposed to internet (services listening on public interfaces)
- **EXT-NET-003**: ICMP response enabled (ping allowed)
- **EXT-SSH-001**: SSH default port (22) exposed externally

### Apply Behavior

Implements interactive remediation with two modes:

#### Interactive Mode (Default)

- **Critical Port Blocking**: Prompts to block critical exposed ports via UFW (`apply_fix_critical_ports`)
  - Identifies ports: Redis (6379), PostgreSQL (5432/5433), MySQL (3306), MongoDB (27017), Elasticsearch (9200), Docker (2375-2379)
  - Verifies UFW is active before applying blocks
  - Prompts for confirmation before each block (never auto-blocks in interactive mode)
  - Lists unclassified services but does NOT auto-fix them (manual review required)

- **SSH Hardening**: Uses SSH wizard from `ssh` module (`apply_fix_ssh_root`)
  - Creates new sudo user with verification
  - Disables root login only after confirmation and user validation
  - Prevents lockout by ensuring alternative access method exists

- **Logging**: All actions logged to `secure-vps-apply.log` (or `output/runs/<run-id>/secure-vps-apply.log` in engine mode)

#### FORCE Mode (`--force` flag)

- **Blocking Warning**: Displays emergency hardening warning requiring explicit confirmation ("y")
- **Auto-blocks Critical Ports**: Automatically blocks critical exposed ports via UFW without prompts
- **Bypasses SSH Safety Checks**: May disable SSH root login even without alternative user verification
- **Potentially Disruptive**: May lock out services or SSH access

**⚠️ Always ensure console/VNC access before using FORCE mode**

### Service Classification

The module automatically classifies listening ports:

- **Critical**: Databases and management interfaces (Redis 6379, PostgreSQL 5432-5439, MySQL 3306, MongoDB 27017, Elasticsearch 9200, Docker 2375-2379)
- **Expected**: Public services (Web 80/443, VoIP 3478/7880/7881, SSH 22)
- **Unclassified**: Any other service listening on public interfaces (requires manual review)

### Findings Generated

| ID | Severity | Type | Origin | Category | Description |
|:---|:---------|:-----|:-------|:---------|:------------|
| **INT-SYS-001** | HIGH/LOW/INFO | Vuln/Risk/Misconfig | Internal | System | Kernel EOL/Legacy/OK |
| **INT-SYS-002** | HIGH | Misconfiguration | Internal | System | ASLR Disabled or Weak |
| **INT-SYS-003** | HIGH | Vulnerability | Internal | System | World Writable Directory in PATH |
| **INT-USR-001** | CRITICAL | Vulnerability | Internal | Users | Multiple UID 0 users found |
| **INT-USR-002** | CRITICAL | Vulnerability | Internal | Users | Accounts with empty passwords found |
| **INT-NET-001** | MEDIUM | Risk | Internal | Network | Unclassified Services Exposed |
| **INT-NET-002** | CRITICAL | Risk | Internal | Network | Critical Internal Services Exposed (Verified, NOT blocked) |
| **INT-NET-002-M** | INFO | Info | Internal | Network | Critical Internal Services (Mitigated by UFW) |
| **INT-NET-003** | INFO | Risk | Internal | Network | Known Public Services Detected |
| **INT-SSH-001** | HIGH | Misconfiguration | Internal | Auth | SSH Root Login Enabled |
| **INT-SSH-002** | MEDIUM | Misconfiguration | Internal | Auth | SSH Password Auth Enabled |
| **EXT-NET-000** | INFO | Risk | External | Network | Public IP Not Detected |
| **EXT-NET-001** | INFO | Risk | External | Network | Public IP Detected |
| **EXT-NET-002** | HIGH | Risk | External | Network | Ports Exposed to Internet |
| **EXT-NET-003** | LOW | Risk | External | Network | ICMP Response Enabled |
| **EXT-SSH-001** | MEDIUM | Risk | External | Auth | SSH Default Port (22) Exposed |

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT check for specific CVEs** (use `vulnerability` module for package-level vulnerabilities)
- **Does NOT verify firewall rule effectiveness** (only checks if UFW blocks ports, does not test if rules actually work)
- **Does NOT scan external accessibility** (does not test if ports are reachable from outside, only simulates)
- **Does NOT check SSH key configurations** (only checks basic SSH config, detailed checks in `ssh` module)
- **Does NOT verify SSH cipher/protocol settings** (does not check for weak ciphers or deprecated protocols)
- **Does NOT fix writable PATH directories** (INT-SYS-003 is detected but not automatically fixed, manual remediation required)
- **Does NOT automatically fix unclassified services** (INT-NET-001 is listed but never auto-fixed, even in FORCE mode)
- **Does NOT configure SSH keys** (does not generate or install SSH keys, only disables password auth)
- **Does NOT verify service configurations** (does not check if services are properly configured, only detects exposure)
- **Does NOT check for service vulnerabilities** (does not verify if exposed services have known vulnerabilities)
- **Does NOT integrate with firewall module** (does not use firewall module's apply logic, uses UFW directly)
- **Does NOT verify external exposure** (does not test if ports are actually reachable from internet, only detects listening state)
- **Does NOT handle complex firewall rules** (only uses simple `ufw deny` commands, does not handle complex iptables rules)

## Scan Behavior

When executing `ironbase scan --module secure-vps`:

1. **Initializes log file** (`secure-vps.log` or `output/runs/<run-id>/secure-vps.log`)
2. **Runs internal scanner** (`scan_internal`):
   - Checks kernel version and ASLR
   - Scans for multiple UID 0 users and empty passwords
   - Detects exposed services and classifies them (critical/expected/unclassified)
   - Correlates exposed services with UFW rules (detects mitigated services)
   - Checks SSH configuration
   - Detects world-writable PATH directories
3. **Runs external scanner** (`scan_external`):
   - Detects public IP via external APIs (`ifconfig.me/ip`, `api.ipify.org`)
   - Lists services listening on public interfaces
   - Checks ICMP response status
   - Detects SSH default port exposure
4. **Generates summary** with counts by severity
5. **Determines exit code** (0 if no critical/high, 1 if critical/high found)

**Output**: Findings displayed on console (truncated evidence >200 chars) and registered to global report. Full details logged to module log file.

**Exit Code**: 
- Returns 0 if no critical/high findings
- Returns 1 if critical/high findings detected

**Dependencies**: 
- Requires `ss` command for network scanning
- Requires `sysctl` for ASLR check
- Requires `/etc/shadow` read access for empty password check (root recommended)
- Requires internet connectivity for public IP detection (optional, graceful failure)

## Apply Behavior

When executing `ironbase apply --module secure-vps`:

### Interactive Mode (Default)

1. **Initializes apply log** (`secure-vps-apply.log` or `output/runs/<run-id>/secure-vps-apply.log`)
2. **Displays warning** about configuration modifications
3. **Fixes critical ports** (`apply_fix_critical_ports`):
   - Rescans for exposed critical services
   - Identifies unique ports (Redis, PostgreSQL, MySQL, MongoDB, Elasticsearch, Docker)
   - For each critical port:
     - Shows evidence (listening service details)
     - Identifies process if root access available
     - Provides context-aware messaging (Redis/Coolify, PostgreSQL, Docker Swarm)
     - Prompts to block via UFW (Option 1) or Skip (Option 2)
     - If confirmed, executes `ufw deny <port>` (requires UFW active)
   - Lists unclassified services but does NOT auto-fix them (manual review required)
4. **Fixes SSH root login** (`apply_fix_ssh_root`):
   - Uses SSH wizard from `ssh` module
   - Creates new sudo user with verification
   - Disables root login only after confirmation and user validation
5. **Logs all actions** with timestamps and status

### FORCE Mode (`--force` flag)

1. **Displays blocking warning** requiring explicit confirmation ("y")
2. **Auto-blocks critical ports** without prompts (bypasses confirmation)
3. **Bypasses SSH safety checks** (may disable root login without alternative user verification)
4. **Potentially disruptive** (may lock out services or SSH access)

**⚠️ FORCE mode may disable SSH root login even if no alternative user is found, potentially locking you out. Always ensure you have VNC/Console access before using this mode.**

**Output**: Wizard provides interactive prompts with colored output. All actions logged to apply log file.

**Exit Code**: Returns 0 on success, 1 on failure or cancellation.

**Dependencies**: 
- Requires `ss` command for port rescanning
- Requires `ufw` command for port blocking
- Requires root access for UFW rule changes and SSH configuration modifications
- Requires `useradd`, `passwd` commands for SSH wizard (from `ssh` module)

## Safety Notes

### General Safety

- **Read-only in scan mode**: Only queries system state. No modifications performed.
- **Interactive by default**: Apply mode requires explicit confirmation for all actions.
- **Backup creation**: SSH wizard creates backups of `/etc/ssh/sshd_config` before modifications.
- **Lockout prevention**: SSH wizard verifies new user exists and has sudo rights before disabling root.
- **Service correlation**: Verifies UFW is active before attempting port blocks.

### Interactive Mode Safety

- **High safety**: Requires explicit confirmation for all actions.
- **No automatic port blocking**: Never blocks ports without confirmation.
- **No automatic SSH changes**: Never disables root login without confirmation and user verification.
- **Unclassified services safe**: Never auto-fixes unclassified services, even in FORCE mode.

### FORCE Mode Risks

- **Low safety**: Applies fixes without further confirmation after initial warning.
- **May lock out services**: Auto-blocks critical ports without verification.
- **May lock out SSH**: May disable root login without alternative user verification.
- **Potential disruption**: May affect production services without warning.

**⚠️ Always ensure console/VNC access before using FORCE mode**

### Known Limitations

- **UFW dependency**: Port blocking requires UFW to be active. Module will report error if UFW not active.
- **Root access required**: UFW rule changes and SSH configuration modifications require root access.
- **Service identification**: Port blocking relies on port numbers, not service names (may block wrong services if ports are misidentified).
- **External exposure simulation**: Does not actually test if ports are reachable from internet, only detects listening state.

**When NOT to use**:
- Systems without console access and no alternative access method (especially FORCE mode)
- Systems with complex firewall rules (does not handle advanced iptables rules)
- Systems with services on non-standard ports (may misidentify services)
- Production systems with critical services (interactive mode still requires caution)

### Integration with Other Modules

- **Uses `ssh` module**: Imports SSH wizard logic from `ssh` module for consistent behavior
- **Correlates with UFW**: Checks UFW status to verify if exposed services are already blocked
- **Complements `firewall` module**: Detects exposure, firewall module provides comprehensive firewall management
- **Complements `vulnerability` module**: Detects exposure, vulnerability module checks for CVEs in exposed services

## Usage Examples

### Scan

```bash
# Basic scan
./cmd/ironbase scan --module secure-vps

# Standalone mode
./modules/secure-vps/standalone.sh
```

### Apply (Interactive Mode - Default)

```bash
# Interactive mode (default)
./cmd/ironbase apply --module secure-vps

# Standalone mode
./modules/secure-vps/standalone.sh apply
```

### Apply (FORCE Mode)

```bash
# Force mode with explicit confirmation
./cmd/ironbase apply --module secure-vps --force

# Standalone mode
./modules/secure-vps/standalone.sh --force
```

### Expected Scan Output

```
[INFO] Starting Internal Scan (Host-based)...
[INFO] Starting External Scan (Network Exposure Simulation)...
[HIGH] Kernel EOL Detected (INT-SSH-001)
      Category: System | Type: Vulnerability | Scope: Internal
      Description: Running Kernel: 4.15.0-generic (Older than 4.19)
      Evidence: uname -r
      Rec: Upgrade to a supported LTS kernel immediately (5.15+ recommended).

[CRITICAL] Critical Internal Services Exposed (Verified) (INT-NET-002)
      Category: Network | Type: Risk | Scope: Internal
      Description: Services usually meant for internal use are listening externally AND NOT blocked by firewall.
      Evidence: tcp  0.0.0.0:6379  ... (Redis)
      Rec: IMMEDIATE ACTION: Bind these services to 127.0.0.1 or block via UFW ('ufw deny <port>').

[INFO] Public IP Detected (EXT-NET-001)
      Category: Network | Type: Risk | Scope: External
      Description: VPS is exposed on Public IP: 192.0.2.1
      Rec: Ensure firewall rules specifically filter traffic to this IP.

======================================
Scan Summary:
Critical: 2
High:     3
Medium:   1
Low:      0
Info:     3
======================================
Result: FAILED (Critical/High findings detected)
```

### Expected Apply Output (Interactive)

```
Starting Interactive Remediation
WARNING: You are about to modify system configurations.
This tool will prompt for confirmation before every action.
A log will be saved to: secure-vps-apply.log

>>> Finding: Critical Internal Services Exposed (INT-NET-002)

>>> Critical Exposure Detected: Port 6379
Evidence:
tcp  0.0.0.0:6379  ...
Process (Primary): users:(("redis-server",pid=1234,...))

Context: Redis (likely Coolify/Docker)
 Recommendation: Block public access via firewall.

Options:
1) Block public access via UFW (Recommended - Safe)
2) Skip
Choose action [1/2]: 1
Executing: ufw deny 6379
Port 6379 blocked via UFW.

>>> User Creation Wizard
Enter new username: admin
...
SSH hardening complete.

Remediation Complete.
Please review secure-vps-apply.log
```

### Expected Apply Output (FORCE Mode)

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!                  EMERGENCY HARDENING MODE (FORCE)                  !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
WARNING: You have requested to FORCE apply all security fixes.
This will:
  - DISABLE internal safety locks (SSH root login check, etc.)
  - MODIFY critical configurations.
  - POTENTIALLY disrupt production services or SSH access.

Confirm FORCE execution (y/N): y

>>> STARTING FORCED HARDENING <<<

>>> Critical Exposure Detected: Port 6379
FORCE MODE: Applying UFW Block Automatically
Port 6379 blocked via UFW.

Forced Hardening Complete.
Mode: FORCE | Log saved at: secure-vps-apply.log
```

## Status

**State**: Stable (Scan Complete, Apply Functional)

**Features Implemented**:
- 16 comprehensive findings across internal and external scanners
- Dual-perspective scanning (host-based and network-based)
- Service classification (critical/expected/unclassified)
- UFW correlation (detects mitigated services)
- Interactive port blocking with confirmation
- SSH hardening via shared wizard (from `ssh` module)
- FORCE mode for emergency hardening
- Standalone execution capability
- Comprehensive logging

**Features Pending**:
- External accessibility testing (actual port scanning from outside)
- Service vulnerability checking (CVE matching for exposed services)
- SSH key configuration and installation
- Writable PATH directory auto-fix (currently manual remediation)
- Unclassified service auto-fix (currently manual review required)
- Complex firewall rule handling (advanced iptables rules)
- Service name identification (currently relies on port numbers)
- Integration with firewall module's apply logic
